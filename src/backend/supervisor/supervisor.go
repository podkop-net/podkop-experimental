// Package supervisor is the backend as a running thing: it brings the router from its
// settings to a working state, keeps it there when the settings change, and takes it back.
//
// One goroutine does everything, one step after another, so no two changes of the router
// meet. A change of the settings is applied by comparing what it would write with what
// runs: sing-box is replaced only for another configuration, a list that changed is a
// file sing-box reads again, a firewall set that changed is refilled in place.
package supervisor

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
	"github.com/podkop-net/podkop-experimental/src/backend/lists"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/probe"
	"github.com/podkop-net/podkop-experimental/src/backend/render"
	"github.com/podkop-net/podkop-experimental/src/backend/sockets"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	"github.com/podkop-net/podkop-experimental/src/backend/yacd"
	E "github.com/sagernet/sing/common/exceptions"
)

// System is the router outside sing-box as the supervisor changes it. The real one is
// Router; a test has its own and sees the order of the calls.
type System interface {
	// LANAddress is the IPv4 address of the LAN, empty when it is not known.
	LANAddress() string
	// Devices are the devices of layer 3 interface names stand for now, those that
	// stand for another device than their own name (netcfg.Devices).
	Devices(names []string) map[string]string
	// Listening are the sockets of the system that listen (sockets.Bound); nil when they
	// cannot be read, and then they are not looked at.
	Listening() []sockets.Listener
	ApplyRouting() error
	RemoveRouting() error
	// AllowBridgedTraffic keeps bridged packets out of the IP firewall hooks and names
	// the switches it had to turn off (netcfg.AllowBridgedTraffic).
	AllowBridgedTraffic() []string
	// RoutingPresent tells whether the rule and the route of ApplyRouting are both there,
	// FirewallPresent whether the table is.
	RoutingPresent() (bool, error)
	FirewallPresent() (bool, error)
	// RouteUplinks keeps the rules that route the sockets of sing-box bound to an uplink by
	// the main table, and tells the devices it added a rule for (netcfg.RouteUplinks);
	// RemoveRouting removes them.
	RouteUplinks() ([]string, error)
	// SetClashSecret writes the key of the Clash API into the settings.
	SetClashSecret(key string) error
	// UpdateFirewall brings the firewall table from the previous plan to the next; with
	// no previous plan the table is made anew.
	UpdateFirewall(previous *firewall.Plan, next *firewall.Plan) error
	RemoveFirewall() error
	// TakeOverDNS points the resolver of the LAN at the backend, RestoreDNS gives it back
	// what it had. Each tells whether it changed anything.
	TakeOverDNS() (bool, error)
	RestoreDNS() (bool, error)
	// NTPServerNames are the names of the NTP servers of the router (clock.ServerNames).
	NTPServerNames() []string
}

// Clock is the help the router's NTP service gets (clock.Keeper): kicked when sing-box has
// started and when an interface comes up, it runs in the background.
type Clock interface {
	Kick()
}

// Engine is sing-box as the supervisor uses it. The real one is the package engine's
// (Options.Engine nil); a test has its own and runs the supervisor without sing-box.
type Engine interface {
	// Check builds a configuration as it will run, the rule-set files it names included,
	// and tells why sing-box refuses it (render.Check).
	Check(config []byte, links []plan.Link) error
	// Build makes an instance of a configuration; nothing runs yet (engine.BuildLogged).
	Build(config []byte, sink engine.LogSink, hooks ...engine.ConnectionHook) (Instance, error)
	// Ready asks the DNS inbound of a started instance for the readiness name until an
	// answer from FakeIP comes or the context ends (engine.Probe).
	Ready(ctx context.Context) error
	// Notes returns what sing-box noted that was not returned before (engine.Notes).
	Notes() []string
	// CheckServers finds the servers of a list sing-box cannot build, those of known taking
	// the verdicts they had, and returns the verdicts of the list (subscription.Check).
	CheckServers(servers []subscription.Server, known map[string]string) map[string]string
	// Delays are what the URL tests last found for outbounds, by tag (engine.Delays).
	Delays(tags []string) map[string]uint16
}

// Instance is a sing-box of one configuration (engine.Instance).
type Instance interface {
	OnRuleSetUpdate(tags []string, updated func(tag string))
	Start() error
	// Close returns engine.ErrStuck when the instance does not close in time.
	Close(patience time.Duration) error
	RuleSetContent(tag string) ([]byte, bool)
	RuleSetHasAddresses(tag string) (bool, bool)
	RuleSetUpdated(tag string) (time.Time, bool)
	UpdateRuleSets(ctx context.Context) (engine.RuleSetUpdate, error)
	FakeIPAddress(name string) (netip.Addr, bool, error)
	Traffic() (engine.Traffic, error)
	Dial(ctx context.Context, tag string, address string) (net.Conn, error)
	// Swap replaces outbounds while the instance runs (hot.go).
	Swap(configuration []byte, swap engine.Swap, limit int) (engine.Swapped, error)
}

var _ Instance = (*engine.Instance)(nil)

// realEngine is the Engine of the package engine.
type realEngine struct{}

func (realEngine) Check(config []byte, links []plan.Link) error {
	_, err := render.Check(config, links)
	return err
}

func (realEngine) Build(config []byte, sink engine.LogSink, hooks ...engine.ConnectionHook) (Instance, error) {
	instance, err := engine.BuildLogged(config, sink, hooks...)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (realEngine) Ready(ctx context.Context) error {
	return engine.Probe(ctx, dataplane.DNSServer.String(), dataplane.ReadinessName, dataplane.FakeIPPrefix)
}

func (realEngine) Notes() []string { return engine.Notes() }

func (realEngine) CheckServers(servers []subscription.Server, known map[string]string) map[string]string {
	checkAll := func(configuration []byte) error {
		_, err := engine.Check(configuration)
		return err
	}
	return subscription.Check(servers, known, checkAll, engine.CheckLink)
}

func (realEngine) Delays(tags []string) map[string]uint16 { return engine.Delays(tags) }

// Options say where the supervisor finds and puts things.
type Options struct {
	// SettingsPath is the UCI file of the backend.
	SettingsPath string
	// RuleSetDir is where the rule-set files go; the usual place when empty.
	RuleSetDir string
	// StagingDir is where a candidate's files are put to be checked before anything of
	// the running state is touched.
	StagingDir string
	// StatePath is the file that tells a guard outside the process what the backend is
	// doing (see writeState); none when empty.
	StatePath string
	// ConfigDir is where the configuration that runs and the last one that was refused
	// are kept for the user interface (RunningConfig, RejectedConfig); in RAM; none when
	// empty.
	ConfigDir string
	// DownloadURL is the download test URL of urltest groups whose section does not set
	// one; none when empty.
	DownloadURL string
	// YACDBuiltinDir holds the dashboard YACD of the package, YACDServedDir is where
	// sing-box serves it (yacd.Ensure); none: the dashboard is left to sing-box.
	YACDBuiltinDir, YACDServedDir string
	// ReadyTimeout is how long a started sing-box has to answer the probe.
	ReadyTimeout time.Duration
	System       System
	// Log is told what happens: a level (info, warn, error) and a message.
	Log func(level string, message string)
	// EngineLog, when set, is given the lines sing-box logs.
	EngineLog engine.LogSink
	// Engine is sing-box; the real one when nil.
	Engine Engine
	// Watcher, when set, makes the checks with made-up names possible: the configuration
	// gets their rules, and sing-box shows the watcher the connections it routes. Who
	// sets it serves the dead end of those connections (probe.ServeDeadEnd).
	Watcher *probe.Watcher
	// Clock, when set, is kicked after a start of sing-box and when an interface comes up.
	Clock Clock
	// SubscriptionDir is where the lists of the subscriptions are kept over a reboot; none:
	// in memory only.
	SubscriptionDir string
	// Device is what a provider is told of the router, Version the version of the backend
	// it is told as the client (subscription.Device.Headers).
	Device  subscription.Device
	Version string
	// Download downloads a list in place of subscription.Download (a test).
	Download func(ctx context.Context, address string, header http.Header, routes []subscription.Route, plan subscription.Plan, report func([]subscription.Try)) (*subscription.Answer, []subscription.Try, error)
}

// The files of Options.ConfigDir (api.RunningConfig, api.LastConfig, api.RejectedConfig).
// The configuration that runs is there while it runs, written after every start that came
// up, the start of the previous configuration included; at the stop and when the router is
// given back it becomes the last one, shown while nothing runs. The last configuration
// sing-box refused is there until the next settings are read, so a message that names a
// place in it (outbounds[2]) can be read beside it; it goes at the stop.
const (
	RunningConfig  = api.RunningConfig
	LastConfig     = api.LastConfig
	RejectedConfig = api.RejectedConfig
)

// Result, Status, ListsUpdate, ListState and ProbeResult are what the supervisor answers
// those who ask from outside, the types of the socket.
type (
	Result      = api.Result
	Status      = api.Status
	ListsUpdate = api.ListsUpdate
	ListState   = api.ListState
	ProbeResult = api.ProbeResult
)

// Supervisor holds what runs now.
type Supervisor struct {
	options Options
	// current is nil when nothing runs: before the boot, after a boot or a change that
	// could not bring anything up, after the stop.
	current *running
	// derive is signalled when sing-box has loaded new content into a rule set
	derive chan struct{}
	// requests are changes asked for from another goroutine, each with where to answer
	requests chan chan Result
	// updates are updates of the lists asked for from another goroutine
	updates chan chan ListsUpdate
	// probes are questions about a check name asked from another goroutine
	probes chan probeRequest
	// statuses are questions about the state of the lists from another goroutine
	statuses chan chan []ListState
	// firewallTold is what the log last said of the sets of the firewall
	firewallTold string
	// restores are asks to put back what the network took, from another goroutine
	restores chan chan string
	// failed tells that the last start of sing-box failed, or the start of the settings
	// around it (not settings that cannot be used, nor a stop): the router is given back
	// and the start is tried again at the next change of the network and when the guard
	// of the package asks (restoreRouting)
	failed bool
	// failures are the starts that failed in a row, the last at failedAt: after the first
	// few, a try waits longer each time (retryPause)
	failures int
	failedAt time.Time
	// unapplied is the change of the network the settings were last applied again for
	// without taking: the same change is not tried again at every event of the network
	unapplied string
	// stuck tells that an instance of sing-box did not close: nothing more can run in
	// this process (see close)
	stuck bool
	// clashSecret is the key of the Clash API the settings had last, or the one this
	// process made when they had none (see clashKey)
	clashSecret string
	// listChecks are what the checks of local lists found, by format and content: a list
	// that did not change is not read again. checkedLists are the
	// lists the configuration that runs was checked with.
	listChecks   map[listKey]listCheck
	checkedLists map[listKey]bool
	// derived is what the firewall sets were made of last, read what was read of each
	// rule set for them, known what each rule set held when it was read last
	derived *derivation
	read    map[derivationKey]readRules
	known   map[string]knownSource
	// loads are the loads of rule sets sing-box reported, by instance
	loads ruleSetLoads

	statusAccess sync.Mutex
	status       Status
	facts        api.Facts
	// live is the instance that runs, for the goroutines that ask what goes through it, and
	// liveLinks the proxy links of its configuration
	live      Instance
	liveLinks []plan.Link

	// subscriptions are the lists of the subscriptions and what is known of them;
	// downloads bring what a download in the background came to, subscriptionRequests
	// the downloads asked for from another goroutine
	subscriptions        subscriptions
	downloads            chan downloaded
	subscriptionRequests chan subscriptionRequest
}

// running is a state of the router that was brought up.
type running struct {
	settings *model.Config
	result   *plan.Result
	instance Instance
	// firewall is the plan the table was last brought to
	firewall *firewall.Plan
}

// what an update of the lists asked for from outside may take
const listsUpdateTimeout = 5 * time.Minute

type probeRequest struct {
	// label is the label of the name; empty when the backend is to open the connection
	// itself, as a program of the router
	label string
	wait  time.Duration
	reply chan ProbeResult
}

// how long a question about a check name may wait for the connection, at the most and
// when the caller does not say
const (
	probeWaitLimit   = 10 * time.Second
	probeWaitDefault = 3 * time.Second
)

// New makes a supervisor; nothing is touched yet.
func New(options Options) *Supervisor {
	if options.RuleSetDir == "" {
		options.RuleSetDir = plan.DefaultRuleSetDir
	}
	if options.StagingDir == "" {
		options.StagingDir = "/tmp/podkop/candidate"
	}
	if options.ReadyTimeout == 0 {
		options.ReadyTimeout = 15 * time.Second
	}
	if options.Log == nil {
		options.Log = func(string, string) {}
	}
	if options.Engine == nil {
		options.Engine = realEngine{}
	}
	return &Supervisor{options: options, derive: make(chan struct{}, 1), requests: make(chan chan Result), updates: make(chan chan ListsUpdate), probes: make(chan probeRequest), statuses: make(chan chan []ListState), restores: make(chan chan string),
		downloads: make(chan downloaded), subscriptionRequests: make(chan subscriptionRequest)}
}

func (s *Supervisor) log(level string, message ...any) {
	s.options.Log(level, oneLine(E.New(message...).Error()))
}

// Running tells whether a state is up.
func (s *Supervisor) Running() bool {
	return s.current != nil
}

// Status returns the state of the backend. It may be called from any goroutine.
func (s *Supervisor) Status() Status {
	s.statusAccess.Lock()
	defer s.statusAccess.Unlock()
	return s.status
}

// Facts tells what the commands need to know of what runs. It may be called from any
// goroutine.
func (s *Supervisor) Facts() api.Facts {
	s.statusAccess.Lock()
	defer s.statusAccess.Unlock()
	return s.facts
}

// Traffic tells what went through the sing-box that runs (engine.Instance.Traffic); false
// when nothing runs, or for the moment one instance gives way to another. It may be called
// from any goroutine.
func (s *Supervisor) Traffic() (engine.Traffic, bool) {
	s.statusAccess.Lock()
	live := s.live
	s.statusAccess.Unlock()
	if live == nil {
		return engine.Traffic{}, false
	}
	traffic, err := live.Traffic()
	return traffic, err == nil
}

// factsOf are the facts of a state that runs.
func factsOf(current *running) api.Facts {
	if current == nil {
		return api.Facts{}
	}
	return api.Facts{ClashAPI: current.result.Dataplane.ClashAPI, ClashSecret: current.result.Dataplane.ClashSecret}
}

// done records what a boot or a change came to and returns it.
func (s *Supervisor) done(ok bool, replaced bool, message ...any) Result {
	result := Result{OK: ok, Message: oneLine(E.New(message...).Error())}
	s.statusAccess.Lock()
	defer s.statusAccess.Unlock()
	now := time.Now()
	if s.current == nil {
		s.status.Running = false
	} else if !s.status.Running || replaced {
		s.status.Running, s.status.Since = true, now
	}
	s.status.Last, s.status.LastAt = result, now
	s.facts = factsOf(s.current)
	s.live, s.liveLinks = nil, nil
	if s.current != nil {
		s.live, s.liveLinks = s.current.instance, s.current.result.Links
	}
	switch {
	case s.current != nil:
		s.failed, s.failures = false, 0
		s.writeState(stateRunning)
	case s.failed:
		s.writeState(stateFailed)
	default:
		s.writeState(stateReleased)
	}
	return result
}

// What the backend is doing, for a guard outside the process (the liveness probe of the
// package): it judges the silence of the DNS inbound only of a backend that runs, and of
// one that has been starting or applying for too long. Released: there is no sing-box, and
// the DNS of the LAN is the router's own, on purpose. Failed: released after a start that
// failed, which the guard asks to be tried again (Supervisor.failed).
const (
	stateBooting  = "booting"
	stateApplying = "applying"
	stateRunning  = "running"
	stateReleased = "released"
	stateFailed   = "failed"
	stateStopped  = "stopped"
)

// writeState records what the backend is doing: the word, the process and the time, one
// line. The file is in RAM; a failure to write it is no failure of the backend.
func (s *Supervisor) writeState(state string) {
	if s.options.StatePath == "" {
		return
	}
	line := state + " " + strconv.Itoa(os.Getpid()) + " " + strconv.FormatInt(time.Now().Unix(), 10) + "\n"
	_ = render.WriteFile(s.options.StatePath, []byte(line))
}

// Request asks the goroutine of Run to apply the settings and waits for what it came
// to. It is for callers outside that goroutine.
func (s *Supervisor) Request(ctx context.Context) Result {
	reply := make(chan Result, 1)
	select {
	case s.requests <- reply:
	case <-ctx.Done():
		return Result{Message: "the backend is busy"}
	}
	select {
	case result := <-reply:
		return result
	case <-ctx.Done():
		return Result{Message: "the backend did not finish in time; its log tells how it went"}
	}
}

// UpdateLists downloads every list now instead of at the update interval and waits for
// what it came to: the rule sets sing-box downloads, and the plain lists the backend
// downloads itself. It is for callers outside the goroutine of Run.
func (s *Supervisor) UpdateLists(ctx context.Context) ListsUpdate {
	reply := make(chan ListsUpdate, 1)
	select {
	case s.updates <- reply:
	case <-ctx.Done():
		return ListsUpdate{Lines: []string{"the backend is busy"}}
	}
	select {
	case result := <-reply:
		return result
	case <-ctx.Done():
		return ListsUpdate{Lines: []string{"the update did not finish in time; the log of the backend tells how it went"}}
	}
}

// updateLists starts an update of the lists of the state that runs and answers when it
// is over. The goroutine of Run is not held: the settings can be applied meanwhile, and
// an update of a state that was replaced ends with that state.
func (s *Supervisor) updateLists(reply chan<- ListsUpdate) {
	current := s.current
	if current == nil {
		reply <- ListsUpdate{Lines: []string{"nothing runs: there are no lists to update"}}
		return
	}
	instance := current.instance
	go func() {
		defer s.survive("the update of the lists asked for", func() {
			// the answer may have gone already
			select {
			case reply <- ListsUpdate{Lines: []string{"the update ended with a fault of the backend; its log has it"}}:
			default:
			}
		})
		deadline := time.Now().Add(listsUpdateTimeout)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		result := ListsUpdate{OK: true}
		summary, err := instance.UpdateRuleSets(ctx)
		switch {
		case err != nil:
			result.OK = false
			result.Lines = append(result.Lines, "rule sets: "+oneLine(err.Error()))
		case summary.Total > 0:
			result.OK = summary.Failed == 0
			result.Lines = append(result.Lines, E.New("rule sets: ", summary.Total, " asked, ", summary.Loaded, " with a new list, ", summary.Failed, " failed").Error())
		}
		if len(result.Lines) == 0 {
			result.Lines = []string{"the settings have no list that is downloaded"}
		}
		level := "info"
		if !result.OK {
			level = "warn"
		}
		s.log(level, "lists updated on request: ", strings.Join(result.Lines, "; "))
		reply <- result
	}()
}

// ListStatus tells what is known of the rule sets of the configuration that runs: none
// when nothing runs. It is for callers outside the goroutine of Run.
func (s *Supervisor) ListStatus(ctx context.Context) []ListState {
	reply := make(chan []ListState, 1)
	select {
	case s.statuses <- reply:
	case <-ctx.Done():
		return nil
	}
	select {
	case states := <-reply:
		return states
	case <-ctx.Done():
		return nil
	}
}

// listStatus collects the state of the lists of what runs. A remote rule set's last
// error and next try are sing-box's own and not told here; its log has them (the first
// failure as an error, then a count every ten minutes).
func (s *Supervisor) listStatus() []ListState {
	current := s.current
	states := []ListState{}
	if current == nil {
		return states
	}
	for _, ruleSet := range current.result.RuleSets {
		state := ListState{Tag: ruleSet.Tag}
		switch {
		case ruleSet.Path == "":
			state.Kind, state.URL, state.Format = "remote", ruleSet.URL, ruleSet.Format
			if updated, known := current.instance.RuleSetUpdated(ruleSet.Tag); known {
				state.LastUpdated = &updated
			}
		default:
			state.Kind, state.Path = "file", ruleSet.Path
		}
		states = append(states, state)
	}
	return states
}

// RestoreRouting puts back what something of the router took from the backend, as at
// "/etc/init.d/network restart": netifd, restarted, flushes the rules it does not own,
// and the loopback that goes down takes the route of the table with it. The firewall
// table and the DNS of the LAN are put back too when they are gone. Nothing is rebuilt;
// with nothing running nothing is done. It tells what it did; it is for callers outside
// the goroutine of Run (the hotplug script of the package asks at every ifup).
func (s *Supervisor) RestoreRouting(ctx context.Context) string {
	reply := make(chan string, 1)
	select {
	case s.restores <- reply:
	case <-ctx.Done():
		return "the backend is busy"
	}
	select {
	case result := <-reply:
		return result
	case <-ctx.Done():
		return "the backend is busy"
	}
}

func (s *Supervisor) restoreRouting() string {
	current := s.current
	if current == nil {
		if !s.failed {
			return "nothing runs"
		}
		if wait := retryPause(s.failures) - time.Since(s.failedAt); wait > 0 {
			return "the start failed " + strconv.Itoa(s.failures) + " times in a row: it is tried again from " + time.Now().Add(wait).Format(time.TimeOnly)
		}
		// an address that was not there (the loopback while the network restarted), a
		// port another program held: what kept sing-box from starting may be gone
		s.log("info", "the start failed before (", s.failures, " in a row): it is tried again")
		result := s.Boot()
		return "the start that had failed was tried again: " + result.Message
	}
	// an uplink that came up: sysntpd learns of it only at its next try
	s.kickClock()
	var restored []string
	if s.allowBridged() {
		restored = append(restored, "bridged packets out of the IP firewall (br_netfilter)")
	}
	present, err := s.options.System.RoutingPresent()
	if err != nil {
		s.log("warn", "look at the routing: ", err)
	} else if !present {
		err = s.options.System.ApplyRouting()
		if err != nil {
			s.log("error", "put the routing back: ", err)
		} else {
			restored = append(restored, "the rule and the route of the routing table")
		}
	}
	// an uplink that came up, or the rules a restart of the network flushed
	routed := s.routeUplinks()
	present, err = s.options.System.FirewallPresent()
	if err != nil {
		s.log("warn", "look at the firewall table: ", err)
	} else if !present {
		// the plan of the table, or one made now when setting it up had failed
		plan := current.firewall
		if plan == nil {
			plan = s.firewallPlan(current)
		}
		err = s.options.System.UpdateFirewall(nil, plan)
		if err != nil {
			s.log("error", "put the firewall table back: ", err)
		} else {
			current.firewall = plan
			restored = append(restored, "the firewall table")
		}
	}
	if current.result.Dataplane.TakeDNS {
		changed, err := s.options.System.TakeOverDNS()
		if err != nil {
			s.log("error", "point the DNS of the LAN at the backend: ", err)
		} else if changed {
			restored = append(restored, "the DNS of the LAN")
		}
	}
	var message string
	if len(restored) > 0 {
		message = strings.Join(restored, ", ") + " had gone and are back"
		s.log("warn", "the network changed: ", message)
	}
	if routed != "" {
		if message != "" {
			message += "; "
		}
		message += routed
	}
	if changes, lost := s.drift(current); len(changes) > 0 {
		// The router has changed under the configuration: an interface came up after
		// podkop or got another device, the LAN got its address or another one (the
		// mixed proxies listen on it). The firewall takes the new devices, and a
		// configuration that is the same leaves sing-box running. A socket sing-box
		// listened on and has lost is listened on again by a new instance.
		change := strings.Join(changes, "; ")
		if message != "" {
			message += "; "
		}
		if !lost && change == s.unapplied {
			// the settings did not take for it before; a change of the settings or another
			// one of the network tries again
			message += "the settings did not take for " + change + " before: not applied again"
		} else {
			s.log("info", "the network changed under the settings (", change, "): they are applied again")
			result := s.apply(lost)
			s.unapplied = ""
			if !result.OK {
				s.unapplied = change
			}
			message += "the settings applied again for " + change + ": " + result.Message
		}
	}
	if message == "" {
		return "nothing was missing"
	}
	return message
}

// routeUplinks keeps the rules for the sockets of sing-box bound to an uplink
// (System.RouteUplinks) and tells the uplinks it added a rule for; a failure is only
// logged: sockets that are not bound do not need the rules.
func (s *Supervisor) routeUplinks() string {
	added, err := s.options.System.RouteUplinks()
	if err != nil {
		s.log("warn", "route the sockets bound to an uplink: ", err)
	}
	if len(added) == 0 {
		return ""
	}
	message := "what sing-box sends bound to " + strings.Join(added, ", ") + " goes by the main routing table"
	s.log("info", message)
	return message
}

// drift tells what of the router the running configuration no longer matches: the
// interface names that stand for another device now than when it was built ("wan:
// pppoe-wan"), the address of the LAN, and the sockets of its inbounds that nothing
// listens on any more; lost tells there is one of these.
func (s *Supervisor) drift(current *running) (changes []string, lost bool) {
	built := current.result.Facts
	// netifd that does not answer (busy while the network restarts) tells nothing
	if names := plan.InterfaceNames(current.settings); len(names) > 0 {
		now := s.options.System.Devices(names)
		for _, name := range names {
			if now == nil {
				break
			}
			if now[name] != built.Devices[name] {
				device := now[name]
				if device == "" {
					device = name
				}
				changes = append(changes, name+": "+device)
			}
		}
	}
	// an address that went away is no change: the sockets bound to it listen again when
	// it is back, and one that is not there cannot be listened on
	if address := s.options.System.LANAddress(); address != "" && address != built.LANAddress {
		changes = append(changes, "the address of the LAN: "+address+" (was "+cmp.Or(built.LANAddress, "none")+")")
	}
	if listening := s.options.System.Listening(); listening != nil {
		for _, inbound := range inboundSockets(current.result.Config) {
			if !listensOn(listening, inbound.protocol, inbound.address) {
				changes = append(changes, "nothing listens on "+inbound.protocol+" "+inbound.address.String()+" ("+inbound.tag+")")
				lost = true
			}
		}
	}
	return changes, lost
}

// listensOn tells whether a socket listens on exactly this address: sing-box binds the
// address of an inbound as it is, and a wildcard socket of another program (dnsmasq on
// [::]:53) is not one of its own.
func listensOn(listening []sockets.Listener, protocol string, at netip.AddrPort) bool {
	return slices.ContainsFunc(listening, func(listener sockets.Listener) bool {
		return listener.Protocol == protocol && listener.Address.Port() == at.Port() && listener.Address.Addr().Unmap() == at.Addr().Unmap()
	})
}

type inboundSocket struct {
	tag      string
	protocol string
	address  netip.AddrPort
}

// inboundSockets are the sockets the inbounds of a configuration listen on: TCP, and UDP
// too for the transparent proxy and the DNS inbound (types tproxy and direct) unless their
// network says otherwise.
func inboundSockets(config []byte) []inboundSocket {
	var document struct {
		Inbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Listen     string `json:"listen"`
			ListenPort uint16 `json:"listen_port"`
			Network    string `json:"network"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(config, &document) != nil {
		return nil
	}
	var result []inboundSocket
	for _, inbound := range document.Inbounds {
		address, err := netip.ParseAddr(inbound.Listen)
		if err != nil || inbound.ListenPort == 0 {
			continue
		}
		at := netip.AddrPortFrom(address, inbound.ListenPort)
		if inbound.Network != "udp" {
			result = append(result, inboundSocket{tag: inbound.Tag, protocol: "tcp", address: at})
		}
		if (inbound.Type == "tproxy" || inbound.Type == "direct") && inbound.Network != "tcp" {
			result = append(result, inboundSocket{tag: inbound.Tag, protocol: "udp", address: at})
		}
	}
	return result
}

// Probe tells what the backend saw of the check name of a label: whether its DNS question
// came, and whether a connection to it came in through the transparent proxy inbound. It
// waits for the connection for the given time, the usual one when that is zero. A
// device of the LAN is checked this way: it opens a connection to the name and asks.
func (s *Supervisor) Probe(ctx context.Context, label string, wait time.Duration) ProbeResult {
	if !probe.ValidLabel(label) {
		return ProbeResult{}
	}
	return s.probe(ctx, probeRequest{label: label, wait: wait})
}

// ProbeSelf checks the router itself: the backend opens a connection to a fresh check
// name with the resolver and the routing a program of the router has, and tells what
// came of it.
func (s *Supervisor) ProbeSelf(ctx context.Context) ProbeResult {
	return s.probe(ctx, probeRequest{})
}

func (s *Supervisor) probe(ctx context.Context, request probeRequest) ProbeResult {
	if request.wait <= 0 {
		request.wait = probeWaitDefault
	}
	request.wait = min(request.wait, probeWaitLimit)
	request.reply = make(chan ProbeResult, 1)
	select {
	case s.probes <- request:
	case <-ctx.Done():
		return ProbeResult{}
	}
	select {
	case result := <-request.reply:
		return result
	case <-ctx.Done():
		return ProbeResult{}
	}
}

// answerProbe answers a question about a check name without holding the goroutine of Run.
func (s *Supervisor) answerProbe(request probeRequest) {
	current, watcher := s.current, s.options.Watcher
	if current == nil || watcher == nil {
		request.reply <- ProbeResult{}
		return
	}
	instance := current.instance
	go func() {
		defer s.survive("a check name", func() {
			select {
			case request.reply <- ProbeResult{}:
			default:
			}
		})
		ctx, cancel := context.WithTimeout(context.Background(), request.wait)
		defer cancel()
		label := request.label
		if label == "" {
			label = probe.NewLabel()
			go func() {
				defer s.survive("a knock at a check name", nil)
				_, _ = probe.Knock(ctx, label)
			}()
		}
		arrival, arrived := watcher.Wait(ctx, label)
		var result ProbeResult
		address, known, err := instance.FakeIPAddress(probe.Name(label))
		if err != nil {
			s.log("error", "a check name: ", err)
		} else if known {
			result.DNS, result.Address = true, address.String()
		}
		// through another inbound a connection proves nothing of the firewall and the
		// routing: a proxy inbound of a section is reached without them
		if arrived && arrival.Inbound == plan.TProxyInboundTag {
			result.Connection, result.Client = true, arrival.Source.String()
		}
		request.reply <- result
	}()
}

// Run boots, then serves until the context ends: reload applies the settings again, a
// rule set that sing-box reloaded refills the firewall sets. At the end everything is
// taken back.
func (s *Supervisor) Run(ctx context.Context, reload <-chan struct{}) error {
	s.Boot()
	// a download brings several rule sets one after another: the firewall is refilled
	// once, deriveMerge after the last of them (deriveMergeLimit after the first at the
	// latest), and nothing else waits meanwhile
	var merge <-chan time.Time
	var mergeFirst time.Time
	bridged := time.NewTicker(bridgedCheckInterval)
	defer bridged.Stop()
	subscriptionTicker := time.NewTicker(subscriptionTick)
	defer subscriptionTicker.Stop()
	for !s.stuck {
		select {
		case <-ctx.Done():
			s.Stop()
			return s.stuckError()
		case <-bridged.C:
			if s.current != nil {
				s.allowBridged()
			}
		case now := <-subscriptionTicker.C:
			s.downloadDue(now, "")
		case result := <-s.downloads:
			s.takeList(result)
		case request := <-s.subscriptionRequests:
			s.askDownload(request)
		case <-reload:
			s.Apply()
		case reply := <-s.requests:
			reply <- s.Apply()
		case reply := <-s.updates:
			s.updateLists(reply)
		case request := <-s.probes:
			s.answerProbe(request)
		case reply := <-s.statuses:
			reply <- s.listStatus()
		case reply := <-s.restores:
			if ctx.Err() != nil {
				// a start tried again would hold up the stop
				reply <- "the backend stops"
				continue
			}
			reply <- s.restoreRouting()
		case <-s.derive:
			now := time.Now()
			if merge == nil {
				mergeFirst = now
			}
			if now.Sub(mergeFirst) < deriveMergeLimit {
				merge = time.After(deriveMerge)
			}
		case <-merge:
			merge = nil
			s.refreshFirewall()
		}
	}
	return s.stuckError()
}

// how long the refill of the firewall sets waits for more rule sets to load, after the
// last load and after the first at the most
const (
	deriveMerge      = 500 * time.Millisecond
	deriveMergeLimit = 5 * time.Second
)

// bridgedCheckInterval is how often a running backend looks whether another program has
// let bridged packets through the IP firewall hooks again (dockerd does at its start).
const bridgedCheckInterval = 30 * time.Second

// allowBridged keeps bridged packets out of the IP firewall hooks (System.
// AllowBridgedTraffic) and logs each switch that had to be turned off: another program
// turned it on, and it breaks the transparent proxy for the devices behind the LAN bridge.
// It tells whether anything was turned off.
func (s *Supervisor) allowBridged() bool {
	changed := s.options.System.AllowBridgedTraffic()
	for _, name := range changed {
		s.log("warn", name, " was 1 (br_netfilter): set to 0")
	}
	return len(changed) > 0
}

// stuckError is what ends Run when sing-box did not close: nil when it did.
func (s *Supervisor) stuckError() error {
	if s.stuck {
		return engine.ErrStuck
	}
	return nil
}

// listKey is a local list as its check knows it: its format and the hash of its content.
type listKey struct {
	format string
	sum    [sha256.Size]byte
}

type listCheck struct {
	skipped int
	first   string
	err     error
}

// checkList is plan.Options.CheckList with what the checks found remembered: a list is
// read once an apply however many times the plan is built, and not at all when it is as
// it was. The lists of this apply are noted in used.
func (s *Supervisor) checkList(used map[listKey]bool) func(format string, content []byte) (int, string, error) {
	return func(format string, content []byte) (int, string, error) {
		key := listKey{format, sha256.Sum256(content)}
		used[key] = true
		if found, known := s.listChecks[key]; known {
			return found.skipped, found.first, found.err
		}
		skipped, first, err := engine.CheckRuleSet(format, content)
		s.listChecks[key] = listCheck{skipped, first, err}
		return skipped, first, err
	}
}

func sameKeys(left map[listKey]bool, right map[listKey]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if !right[key] {
			return false
		}
	}
	return true
}

// candidate is settings that were read and checked, not yet running.
type candidate struct {
	settings *model.Config
	result   *plan.Result
	// hot is set when sing-box can take the configuration while it runs (hotPlan)
	hot *hotSwap
}

// prepare reads the settings and makes the configuration and the files of them. The
// configuration is built by sing-box with its files in a place of their own: settings
// that cannot run are found out here, with nothing of the running state touched.
// faultWhileReading lets a test fault where the settings are read.
var faultWhileReading func()

func (s *Supervisor) prepare() (next *candidate, err error) {
	// A fault while the settings are read (the UCI file, a link, a list) must not end the
	// process: procd would start it again, the same settings would fault again, and the
	// DNS of the LAN would point at a backend that is never there. The settings are
	// refused instead, as unusable ones are.
	defer func() {
		if fault := recover(); fault != nil {
			os.Stderr.Write(debug.Stack())
			next, err = nil, E.New("a fault of the backend while the settings were read: ", fault)
		}
	}()
	s.keepConfig(RejectedConfig, nil)
	content, err := os.ReadFile(s.options.SettingsPath)
	if err != nil {
		return nil, E.Cause(err, "read the settings")
	}
	if faultWhileReading != nil {
		faultWhileReading()
	}
	parsed, err := uci.Parse(content)
	if err != nil {
		return nil, E.Cause(err, "read the settings")
	}
	settings, err := model.Load(parsed)
	if err != nil {
		return nil, E.Cause(err, "read the settings")
	}
	s.clashKey(settings)
	s.syncSubscriptions(settings)
	servers := s.servers()
	facts := plan.Facts{LANAddress: s.options.System.LANAddress(), Devices: s.options.System.Devices(plan.InterfaceNames(settings)), NTPServerNames: s.options.System.NTPServerNames()}
	if facts.Devices == nil && s.current != nil {
		// netifd did not answer: the devices the names stood for so far, not the names
		facts.Devices = s.current.result.Facts.Devices
	}
	if s.listChecks == nil {
		s.listChecks = make(map[listKey]listCheck)
	}
	used := make(map[listKey]bool)
	noExternalUI := s.noDashboard(settings)
	if noExternalUI {
		s.log("warn", "there is no dashboard YACD to serve: the Clash API runs without it")
	}
	build := func(ruleSetDir string) (*plan.Result, error) {
		options := plan.Options{RuleSetDir: ruleSetDir, DecodeLink: engine.DecodeLink, CheckList: s.checkList(used), DownloadURL: s.options.DownloadURL,
			ExternalUI: s.options.YACDServedDir, NoExternalUI: noExternalUI, Servers: servers}
		if s.options.Watcher != nil {
			options.CheckNames = plan.CheckNames{Suffix: probe.Suffix, DeadEndAddress: probe.DeadEndAddress, DeadEndPort: probe.DeadEndPort}
		}
		return plan.Build(settings, facts, options)
	}
	result, err := build(s.options.RuleSetDir)
	if err != nil {
		return nil, err
	}
	// what was left out or cannot be honoured is told on every apply: who made a typo
	// looks at the log after the change
	for _, warning := range result.Warnings {
		s.log("warn", warning)
	}
	// The configuration that runs, with the same local lists, was built by sing-box
	// already: it is not built again, a big list read again for it
	// and the memory of a second copy beside the one that runs. A local list that
	// changed is checked by sing-box as before, with what it holds against the DNS rules.
	if s.current != nil && bytes.Equal(result.Config, s.current.result.Config) && sameKeys(used, s.checkedLists) {
		s.forgetLists(used)
		return &candidate{settings: settings, result: result}, nil
	}
	// Nor is a configuration whose only change are servers of the groups, which sing-box takes
	// while it runs: it built each server when the list was taken (subscription.Check).
	if s.current != nil && sameKeys(used, s.checkedLists) {
		if hot, _ := hotPlan(s.current.result, result); hot != nil {
			s.forgetLists(used)
			return &candidate{settings: settings, result: result, hot: hot}, nil
		}
	}
	staged, err := build(filepath.Join(s.options.StagingDir, "rulesets"))
	if err != nil {
		return nil, err
	}
	// the files of the check are not needed after it, and they are in RAM
	defer os.RemoveAll(s.options.StagingDir)
	for _, path := range staged.FileOrder {
		err = render.WriteFile(path, staged.Files[path])
		if err != nil {
			return nil, E.Cause(err, "write a rule-set file to check")
		}
	}
	err = s.options.Engine.Check(staged.Config, staged.Links)
	s.tellNotes()
	s.forgetLists(used)
	// what the check built is given back before an instance reads the lists again
	debug.FreeOSMemory()
	if err != nil {
		// kept as it would have run: the same but for where the rule-set files are
		s.keepConfig(RejectedConfig, result.Config)
		return nil, err
	}
	s.checkedLists = used
	return &candidate{settings: settings, result: result}, nil
}

// noDashboard puts the dashboard YACD of the package in place for settings that turn it on
// (yacd.Ensure): sing-box serves what is there, and downloads one within its start into an
// empty directory. It tells whether there is none to serve.
func (s *Supervisor) noDashboard(settings *model.Config) bool {
	if !settings.Settings.EnableYACD || s.options.YACDServedDir == "" {
		return false
	}
	served, err := yacd.Ensure(s.options.YACDBuiltinDir, s.options.YACDServedDir)
	if err != nil {
		s.log("warn", "put the dashboard YACD in place: ", err)
	}
	return !served
}

// forgetLists keeps what the checks found only of the lists of this apply.
func (s *Supervisor) forgetLists(used map[listKey]bool) {
	for key := range s.listChecks {
		if !used[key] {
			delete(s.listChecks, key)
		}
	}
}

// writeFiles stores the rule-set files that differ from what the previous state wrote.
func (s *Supervisor) writeFiles(result *plan.Result, previous *plan.Result) error {
	for _, path := range result.FileOrder {
		if previous != nil && bytes.Equal(previous.Files[path], result.Files[path]) {
			continue
		}
		err := render.WriteFile(path, result.Files[path])
		if err != nil {
			return E.Cause(err, "write the rule-set file ", path)
		}
	}
	return nil
}

// start builds and starts sing-box of a candidate and waits until it answers.
func (s *Supervisor) start(next *candidate, previous *plan.Result) (Instance, error) {
	err := s.writeFiles(next.result, previous)
	if err != nil {
		return nil, err
	}
	// sing-box opens the cache file but does not make its directory, and after a reboot
	// settings whose lists are all downloaded or local write no rule-set file that would
	// have made it
	if path := next.settings.Settings.CachePath; path != "" {
		err = os.MkdirAll(filepath.Dir(path), 0o755)
		if err != nil {
			s.log("warn", "make the directory of the cache file: ", err)
		}
	}
	// what the instance before and the check left is given back before this one reads its
	// lists
	debug.FreeOSMemory()
	var hooks []engine.ConnectionHook
	if s.options.Watcher != nil {
		hooks = append(hooks, s.options.Watcher.Note)
	}
	instance, err := s.options.Engine.Build(next.result.Config, s.options.EngineLog, hooks...)
	if err != nil {
		return nil, E.Cause(err, "build sing-box")
	}
	// a rule set that sing-box loads refills the firewall sets: told from before the
	// start, so that a load during the start or right after it is not missed, and once an
	// instance, so that applies with the same configuration do not add more callbacks
	tags := make([]string, len(next.result.RuleSets))
	sources := make(map[string]string, len(next.result.RuleSets))
	for index, ruleSet := range next.result.RuleSets {
		tags[index] = ruleSet.Tag
		sources[ruleSet.Tag] = ruleSet.URL
		if ruleSet.URL == "" {
			sources[ruleSet.Tag] = "file " + ruleSet.Path
		}
	}
	instance.OnRuleSetUpdate(tags, func(tag string) {
		// counted before the firewall is told: a refill that reads the count after this
		// reads the content of this load
		s.loads.add(instance, tag)
		s.log("info", "list ", tag, " updated (", sources[tag], ")")
		select {
		case s.derive <- struct{}{}:
		default:
		}
	})
	err = instance.Start()
	if err != nil {
		s.loads.forget(instance)
		if taken := takenBy(err); taken != "" {
			s.log("error", taken)
		}
		if errors.Is(err, engine.ErrStuck) {
			// what it holds is let go only by the end of the process, as in close
			s.log("error", "sing-box does not close after its start failed: giving the router back; the process has to end")
			s.current = nil
			s.release()
			s.stuck = true
		}
		return nil, E.Cause(err, "start sing-box")
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.options.ReadyTimeout)
	defer cancel()
	err = s.options.Engine.Ready(ctx)
	if err != nil {
		s.close(instance)
		return nil, err
	}
	s.tellNotes()
	s.storeConfig(next)
	s.log("info", describeConfig(next))
	for _, tag := range tags {
		s.log("info", "list ", tag, ": ", sources[tag])
	}
	return instance, nil
}

// tellNotes logs what sing-box noted as deprecated and the log does not have yet: each
// note once in the life of the process, those of the start included.
func (s *Supervisor) tellNotes() {
	for _, note := range s.options.Engine.Notes() {
		s.log("warn", note)
	}
}

// storeConfig keeps the configuration that runs in ConfigDir, which the user interface
// shows. sing-box here is given the configuration in memory; nothing is written anywhere
// else (no file of a sing-box package).
func (s *Supervisor) storeConfig(running *candidate) {
	s.keepConfig(RunningConfig, running.result.Config)
}

// retireConfig keeps the configuration that ran, if one did, as the last one: it is
// shown while nothing runs, until the next one runs or a reboot (ConfigDir is in RAM).
func (s *Supervisor) retireConfig() {
	if s.options.ConfigDir == "" {
		return
	}
	_ = os.Rename(filepath.Join(s.options.ConfigDir, RunningConfig), filepath.Join(s.options.ConfigDir, LastConfig))
}

// keepConfig writes a file of ConfigDir, or removes it when content is nil.
func (s *Supervisor) keepConfig(name string, content []byte) {
	if s.options.ConfigDir == "" {
		return
	}
	path := filepath.Join(s.options.ConfigDir, name)
	if content == nil {
		_ = os.Remove(path)
		return
	}
	current, err := os.ReadFile(path)
	if err == nil && bytes.Equal(current, content) {
		return
	}
	err = render.WriteFile(path, content)
	if err != nil {
		s.log("warn", "keep the configuration at ", path, ": ", err)
	}
}

// close stops an instance. One that does not stop leaves the process no way to go on:
// its sockets are still bound. What the router was given is taken back, and the
// supervisor is stuck: Run returns engine.ErrStuck, and the process that runs it ends,
// so that the service manager starts another. It tells whether the instance closed.
func (s *Supervisor) close(instance Instance) bool {
	// sing-box sets the memory limit of Go for the process while it runs and lifts it when
	// it closes; the next one sets it again only when it starts. The limit it had stays
	// meanwhile: the build of the next one reads its local lists, the biggest allocation
	// of an apply. A negative value only reads the limit.
	limit := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(limit)
	defer s.loads.forget(instance)
	err := instance.Close(engine.StopTimeout)
	if err == engine.ErrStuck {
		s.log("error", "sing-box does not close: giving the router back; the process has to end")
		s.current = nil
		s.release()
		s.stuck = true
		return false
	}
	if err != nil {
		s.log("warn", "sing-box closed with an error: ", err)
	}
	return true
}

// Boot brings the router up from the settings. When that cannot be done the router is
// left as it is without the backend, with its own DNS working, and the supervisor stays
// to try again when the settings change.
func (s *Supervisor) Boot() Result {
	started := time.Now()
	s.writeState(stateBooting)
	// what a backend before this one kept is what ran last, not what runs
	s.retireConfig()
	next, err := s.prepare()
	if err != nil {
		s.log("error", "the settings cannot be used: ", err)
		s.failed, s.failures = false, 0
		s.release()
		return s.done(false, false, "the settings cannot be used: ", err)
	}
	instance, err := s.start(next, nil)
	if err != nil {
		s.log("error", err)
		s.keepConfig(RejectedConfig, next.result.Config)
		s.release()
		s.startFailed()
		return s.done(false, false, err)
	}
	s.current = &running{settings: next.settings, result: next.result, instance: instance}
	err = s.surround(nil)
	if err != nil {
		s.log("error", err)
		s.Stop()
		s.startFailed()
		return s.done(false, false, err)
	}
	s.log("info", "running, ", time.Since(started).Milliseconds(), " ms after the start")
	s.kickClock()
	return s.done(true, true, "started in ", time.Since(started).Milliseconds(), " ms")
}

// kickClock asks the help of the router's NTP service to look at the clock (Options.Clock).
func (s *Supervisor) kickClock() {
	if s.options.Clock != nil {
		s.options.Clock.Kick()
	}
}

// startFailed records a start of sing-box, or of the settings around it, that failed: the
// router is given back, and the start is tried again (restoreRouting).
func (s *Supervisor) startFailed() {
	s.failed = true
	s.failures++
	s.failedAt = time.Now()
}

// retryPause is how long after the last of the starts that failed in a row the next try
// waits: the first few at once (an address that comes back with the network: a restart
// of the network brings several events), then a minute, doubled each time up to an hour
// (a port another program holds for good). The events of the network and the guard ask
// as they come; a start that is not due is not tried.
func retryPause(failures int) time.Duration {
	const atOnce = 3
	if failures <= atOnce {
		return 0
	}
	return min(time.Minute<<min(failures-atOnce-1, 6), time.Hour)
}

// surround does what a running sing-box needs around it, in the order that never leaves
// the LAN asking a resolver that is not there: the routing and the firewall first, the
// DNS of the LAN last.
func (s *Supervisor) surround(previousFirewall *firewall.Plan) error {
	current := s.current
	s.allowBridged()
	err := s.options.System.ApplyRouting()
	if err != nil {
		return E.Cause(err, "set up the routing")
	}
	s.routeUplinks()
	// the plan is kept once the kernel has it: one that failed leaves none, and the next
	// update sets the whole table up
	plan := s.firewallPlan(current)
	err = s.options.System.UpdateFirewall(previousFirewall, plan)
	if err != nil {
		return E.Cause(err, "set up the firewall")
	}
	current.firewall = plan
	s.tellFirewall(plan)
	if current.result.Dataplane.TakeDNS {
		changed, err := s.options.System.TakeOverDNS()
		if err != nil {
			return E.Cause(err, "point the DNS of the LAN at the backend")
		}
		if changed {
			s.log("info", "the DNS of the LAN asks the backend now")
		}
	} else {
		// dont_touch_dhcp turned on while the backend had dnsmasq: it is given back now,
		// not at the stop; a dnsmasq set by hand is not touched (dnsmasq.Restore)
		changed, err := s.options.System.RestoreDNS()
		if err != nil {
			s.log("error", "give the DNS of the LAN back: ", err)
		} else if changed {
			s.log("info", "the DNS of the LAN is as it was before the backend: dont_touch_dhcp is on")
		}
	}
	return nil
}

// firewallPlan makes the firewall table of a state: the rules from the settings, the
// sets from what the rule sets hold now.
func (s *Supervisor) firewallPlan(current *running) *firewall.Plan {
	wanted := &current.result.Dataplane
	result := &firewall.Plan{Interfaces: wanted.Interfaces, ExcludeNTP: wanted.ExcludeNTP, Sources: wanted.Sources, ClashAPIInterfaces: wanted.ClashAPIInterfaces}
	var sources []keyedSource
	known := make(map[string]knownSource, len(current.result.RuleSets))
	for _, ruleSet := range current.result.RuleSets {
		// a rule set without a rule of addresses gives the firewall nothing: its content,
		// often the biggest list of names, is not read
		if has, told := current.instance.RuleSetHasAddresses(ruleSet.Tag); told && !has {
			continue
		}
		source, stamp, found := s.ruleSetSource(current.instance, ruleSet)
		if found {
			sources = append(sources, source)
			known[ruleSet.Tag] = stamp
		}
	}
	s.known = known
	destinations, problems := s.deriveSets(sources)
	for _, problem := range problems {
		s.log("warn", "firewall sets: ", problem)
	}
	result.Subnets, result.Groups = destinations.Subnets, destinations.Groups
	return result
}

// ruleSetLoads counts the loads of rule sets sing-box reported, by instance and tag. The
// counts are added from sing-box's goroutines; the firewall reads a list again only when
// it was loaded after it was read last.
type ruleSetLoads struct {
	access sync.Mutex
	counts map[ruleSetLoad]uint64
}

type ruleSetLoad struct {
	instance Instance
	tag      string
}

func (l *ruleSetLoads) add(instance Instance, tag string) {
	l.access.Lock()
	defer l.access.Unlock()
	if l.counts == nil {
		l.counts = make(map[ruleSetLoad]uint64)
	}
	l.counts[ruleSetLoad{instance, tag}]++
}

func (l *ruleSetLoads) count(instance Instance, tag string) uint64 {
	l.access.Lock()
	defer l.access.Unlock()
	return l.counts[ruleSetLoad{instance, tag}]
}

// forget drops the counts of an instance that closed.
func (l *ruleSetLoads) forget(instance Instance) {
	l.access.Lock()
	defer l.access.Unlock()
	for key := range l.counts {
		if key.instance == instance {
			delete(l.counts, key)
		}
	}
}

// derivation is what the firewall sets were made of: the rule sets by tag, format and
// content, and what came of them.
type derivation struct {
	keys         []derivationKey
	destinations *lists.Destinations
	problems     []error
}

type derivationKey struct {
	tag    string
	format string
	sum    [sha256.Size]byte
}

type readRules struct {
	rules []engine.AddressRule
	err   error
}

// keyedSource is a rule set for the firewall with the key of its content. Content is nil
// when what was read of that content is kept (Supervisor.read).
type keyedSource struct {
	lists.Source
	key derivationKey
}

// knownSource is the key of what a rule set held when the firewall read it last, and what
// tells that it has not changed since: the instance and its count of loads of the rule set
// for one sing-box downloads (it tells every load), the size and time of the file for a
// local one.
type knownSource struct {
	instance Instance
	loads    uint64
	path     string
	size     int64
	modified time.Time
	key      derivationKey
}

func (k knownSource) same(other knownSource) bool {
	return k.instance == other.instance && k.loads == other.loads && k.path == other.path && k.size == other.size && k.modified.Equal(other.modified)
}

// ruleSetSource is a rule set as the firewall reads it: its content is read only when it
// may have changed since the last read, or when what was read of it is not kept. A big
// list that did not change is not copied from the cache file and hashed at every refill.
func (s *Supervisor) ruleSetSource(instance Instance, ruleSet plan.RuleSet) (keyedSource, knownSource, bool) {
	source := lists.Source{Tag: ruleSet.Tag, Format: ruleSet.Format}
	var stamp knownSource
	if ruleSet.Path != "" {
		info, err := os.Stat(ruleSet.Path)
		if err != nil {
			return keyedSource{}, knownSource{}, false
		}
		stamp = knownSource{path: ruleSet.Path, size: info.Size(), modified: info.ModTime()}
	} else {
		// taken before the content: a load meanwhile has the content read again
		stamp = knownSource{instance: instance, loads: s.loads.count(instance, ruleSet.Tag)}
	}
	if previous, seen := s.known[ruleSet.Tag]; seen && previous.same(stamp) && previous.key.format == ruleSet.Format {
		if _, kept := s.read[previous.key]; kept {
			return keyedSource{source, previous.key}, previous, true
		}
	}
	if ruleSet.Path != "" {
		content, err := os.ReadFile(ruleSet.Path)
		if err != nil {
			return keyedSource{}, knownSource{}, false
		}
		source.Content = content
	} else {
		content, found := instance.RuleSetContent(ruleSet.Tag)
		if !found {
			return keyedSource{}, knownSource{}, false
		}
		source.Content = content
	}
	stamp.key = derivationKey{ruleSet.Tag, ruleSet.Format, sha256.Sum256(source.Content)}
	return keyedSource{source, stamp.key}, stamp, true
}

// deriveSets is lists.Derive of rule sets with what was read of each kept: the sets of the
// firewall are made at every apply and at every load of a rule set, and a big list read
// for them again is a big list read once more. Only a rule set whose
// content changed is read; when none did, the sets are those made last.
func (s *Supervisor) deriveSets(sources []keyedSource) (*lists.Destinations, []error) {
	keys := make([]derivationKey, len(sources))
	plain := make([]lists.Source, len(sources))
	for index, source := range sources {
		keys[index], plain[index] = source.key, source.Source
	}
	if s.derived != nil && slices.Equal(keys, s.derived.keys) {
		return s.derived.destinations, s.derived.problems
	}
	if s.read == nil {
		s.read = make(map[derivationKey]readRules)
	}
	// the tags of the rule sets of a configuration are its own each
	keyOf := make(map[string]derivationKey, len(keys))
	for _, key := range keys {
		keyOf[key.tag] = key
	}
	used := make(map[derivationKey]bool, len(keys))
	destinations, problems := lists.DeriveWith(plain, func(source lists.Source) ([]engine.AddressRule, error) {
		key := keyOf[source.Tag]
		used[key] = true
		if found, known := s.read[key]; known {
			return found.rules, found.err
		}
		rules, err := engine.RuleSetAddresses(source.Format, source.Content)
		s.read[key] = readRules{rules, err}
		return rules, err
	})
	for key := range s.read {
		if !used[key] {
			delete(s.read, key)
		}
	}
	s.derived = &derivation{keys: keys, destinations: destinations, problems: problems}
	return destinations, problems
}

// refreshFirewall brings the firewall to what the rule sets hold now.
func (s *Supervisor) refreshFirewall() {
	current := s.current
	if current == nil {
		return
	}
	next := s.firewallPlan(current)
	err := s.options.System.UpdateFirewall(current.firewall, next)
	if err != nil {
		s.log("error", "update the firewall sets: ", err)
		// a set may be half filled: the next update sets the whole table up
		current.firewall = nil
		return
	}
	current.firewall = next
	s.tellFirewall(next)
}

// Apply brings the router to the settings as they are now. Settings that cannot be used
// change nothing: what runs keeps running. A configuration that is the same leaves
// sing-box alone. Another configuration replaces it, and when the new one does not come
// up the previous one is started again.
func (s *Supervisor) Apply() Result {
	// the settings may have changed: a start that failed is tried at once, and a change of
	// the network they did not take for is tried again
	s.failures, s.unapplied = 0, ""
	return s.apply(false)
}

// apply is Apply; with force a configuration that is the same replaces sing-box too, as
// one that is not: the instance that runs has lost a socket it listened on. Then settings
// that cannot be used start the configuration that runs again.
func (s *Supervisor) apply(force bool) Result {
	if s.current == nil {
		return s.Boot()
	}
	started := time.Now()
	s.writeState(stateApplying)
	current := s.current
	next, err := s.prepare()
	if err != nil {
		if !force {
			s.log("error", "the settings cannot be used, nothing is changed: ", err)
			return s.done(false, false, "the settings cannot be used, nothing is changed: ", err)
		}
		s.log("error", "the settings cannot be used: ", err, "; the configuration that runs is started again for the socket it lost")
		next = &candidate{settings: current.settings, result: current.result}
	}
	previousFirewall := current.firewall
	if !force && bytes.Equal(next.result.Config, current.result.Config) {
		err = s.writeFiles(next.result, current.result)
		if err != nil {
			s.log("error", err)
		}
		// the path of the export may be what changed
		s.storeConfig(next)
		s.current = &running{settings: next.settings, result: next.result, instance: current.instance}
		err = s.surround(previousFirewall)
		if err != nil {
			s.log("error", err)
		}
		s.log("info", "the settings are applied in ", time.Since(started).Milliseconds(), " ms, sing-box keeps running")
		return s.done(true, false, "applied in ", time.Since(started).Milliseconds(), " ms, sing-box keeps running")
	}
	if !force && next.hot != nil {
		result, swapped := s.swap(current, next, started)
		if swapped {
			return result
		}
	}
	// another configuration. The cache file belongs to one instance at a time, so the
	// running one is closed before the next is started.
	closing := time.Now()
	if !s.close(current.instance) {
		return s.done(false, false, "sing-box does not close: the router is given back, the process has to end")
	}
	closed := time.Since(closing)
	instance, err := s.start(next, current.result)
	if err == nil {
		s.current = &running{settings: next.settings, result: next.result, instance: instance}
		err = s.surround(previousFirewall)
		if err != nil {
			s.log("error", err)
		}
		s.log("info", "the settings are applied in ", time.Since(started).Milliseconds(), " ms, sing-box runs the new configuration (it did not answer for ",
			time.Since(closing).Milliseconds(), " ms, of which the previous one took ", closed.Milliseconds(), " ms to close)")
		return s.done(true, true, "applied in ", time.Since(started).Milliseconds(), " ms, sing-box runs the new configuration")
	}
	if s.stuck {
		return s.done(false, false, "the new configuration does not come up, and sing-box does not close: the router is given back, the process has to end")
	}
	s.log("error", "the new configuration does not come up, going back to the previous one: ", err)
	s.keepConfig(RejectedConfig, next.result.Config)
	failure := err
	instance, err = s.start(&candidate{settings: current.settings, result: current.result}, next.result)
	if err != nil {
		s.log("error", "the previous configuration does not come up either: ", err)
		s.current = nil
		s.release()
		s.startFailed()
		return s.done(false, false, "the new configuration does not come up: ", failure, "; the previous one does not either: ", err)
	}
	s.current = &running{settings: current.settings, result: current.result, instance: instance}
	err = s.surround(previousFirewall)
	if err != nil {
		s.log("error", err)
	}
	return s.done(false, true, "the new configuration does not come up, the previous one runs again: ", failure)
}

// Stop takes everything back. The DNS of the LAN first: whatever happens after, the
// devices ask a resolver that answers.
func (s *Supervisor) Stop() {
	current := s.current
	s.current = nil
	s.failed = false
	s.release()
	if current != nil {
		s.close(current.instance)
	}
	s.removeFiles()
	s.keepConfig(RejectedConfig, nil)
	s.statusAccess.Lock()
	s.status.Running = false
	s.facts = api.Facts{}
	s.live = nil
	s.statusAccess.Unlock()
	s.writeState(stateStopped)
}

// compat: rule-set-files
// removeFiles deletes the rule-set files. The shell backend, which may run after this
// one, takes a rule-set file that is there for one it has already put into its
// configuration, and writes a configuration without the lists.
func (s *Supervisor) removeFiles() {
	entries, err := os.ReadDir(s.options.RuleSetDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			_ = os.Remove(filepath.Join(s.options.RuleSetDir, entry.Name()))
		}
	}
}

// Release gives the router back what a backend that is gone left taken: one that was
// killed, or one that ended before it could clean up. Nothing must run while it is
// called. What is not there is no error.
func (s *Supervisor) Release() {
	s.release()
	s.removeFiles()
	s.keepConfig(RejectedConfig, nil)
}

// release gives the router back what the backend took: the DNS of the LAN, the firewall
// table, the routing. Each is no error when it is not there. Nothing runs after it.
func (s *Supervisor) release() {
	s.retireConfig()
	// what was read of the lists for the firewall goes with the firewall table: with
	// nothing running it would hold the addresses of every list until the next start
	s.derived, s.read, s.known = nil, nil, nil
	changed, err := s.options.System.RestoreDNS()
	if err != nil {
		s.log("error", "give the DNS of the LAN back: ", err)
	} else if changed {
		s.log("info", "the DNS of the LAN is as it was before the backend")
	}
	err = s.options.System.RemoveFirewall()
	if err != nil {
		s.log("error", "remove the firewall table: ", err)
	}
	err = s.options.System.RemoveRouting()
	if err != nil {
		s.log("error", "remove the routing: ", err)
	}
}

// clashKey gives the Clash API a key when the settings have none: without one any device
// of the LAN reads the connections and switches the outbounds. The key
// is written into the settings, where the page reads it to send as its token. Settings
// saved without it (the page drops the field while WAN access to YACD is off) get back
// the key they had last, the one written before this process started included: the key
// changes only when someone sets another. A key is made only when the settings had none
// since the process started.
func (s *Supervisor) clashKey(settings *model.Config) {
	if settings.Settings.YACDSecretKey != "" {
		s.clashSecret = settings.Settings.YACDSecretKey
		return
	}
	made := false
	if s.clashSecret == "" {
		var random [16]byte
		_, _ = rand.Read(random[:])
		s.clashSecret = hex.EncodeToString(random[:])
		made = true
	}
	settings.Settings.YACDSecretKey = s.clashSecret
	err := s.options.System.SetClashSecret(s.clashSecret)
	if err != nil {
		s.log("warn", "write the key of the Clash API into the settings: ", err)
		return
	}
	if made {
		s.log("info", "the Clash API has a key now (podkop.settings.yacd_secret_key): a device of the LAN without it is refused")
	}
}

// survive, deferred by a goroutine of a worker, turns a fault of it into a line of the log
// (the stack goes to the standard error) and answers for it with answer: the backend
// and the router stay up.
func (s *Supervisor) survive(what string, answer func()) {
	fault := recover()
	if fault == nil {
		return
	}
	os.Stderr.Write(debug.Stack())
	s.log("error", "a fault of the backend in ", what, ": ", fault)
	if answer != nil {
		answer()
	}
}

// oneLine keeps a message on one line of the log.
func oneLine(message string) string {
	return strings.Join(strings.Fields(message), " ")
}
