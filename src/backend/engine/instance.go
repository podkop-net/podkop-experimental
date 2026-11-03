package engine

import (
	"context"
	"net"
	"net/netip"
	"regexp"
	"runtime/debug"
	"sync"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/detect"
	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// Instance is a sing-box of one configuration, inside this process. It is built, started
// once and closed once; another configuration is another instance.
type Instance struct {
	ctx    context.Context
	cancel context.CancelFunc
	box    *box.Box
	// dialers are the outbounds and the endpoints of the configuration, for the history
	dialers map[string]dialer
	// use is held for reading by the calls of other goroutines (a worker of the backend
	// may still hold an instance that was replaced); Close takes it for writing, and the
	// calls after it find the instance closed and do not touch what sing-box let go
	use    sync.RWMutex
	closed bool
	// started is when Start was called; set once, before others have the instance
	started time.Time
	// detectForgotten is when a swap replaced the outbound of a tag: its connections opened before
	// are of the old one (forgetDetect)
	detectAccess    sync.Mutex
	detectForgotten map[string]time.Time
}

// ErrClosed is what a call to an instance that was closed returns.
var ErrClosed = E.New("the configuration of this sing-box was replaced or stopped")

// enter begins a call of another goroutine; it tells false when the instance is closed.
// A call that entered ends with leave.
func (i *Instance) enter() bool {
	i.use.RLock()
	if i.closed {
		i.use.RUnlock()
		return false
	}
	return true
}

func (i *Instance) leave() {
	i.use.RUnlock()
}

// ErrStuck is returned by Close when sing-box does not close in the time it is given.
// Its sockets and its goroutines are then still there: the process has to end.
var ErrStuck = E.New("sing-box does not close")

// Build makes an instance of a configuration and does not start it: nothing is listened
// on and no file is opened, so it can be built while another instance runs. A
// configuration that cannot be built is refused here, with the words of sing-box.
func Build(configuration []byte) (*Instance, error) {
	return BuildLogged(configuration, nil)
}

// LogSink takes the lines sing-box logs: the level by its name and the message.
type LogSink func(level string, message string)

// sinkWriter gives a sink the lines of the level the configuration asks for, without
// colours (log.PlatformWriterLevel, log.PlatformWriterColors): sing-box formats a line
// for it only at that level. A sink that took every line would hold little besides the
// debug lines of the last connections.
type sinkWriter struct {
	sink  LogSink
	level log.Level
}

// what sing-box puts before a message: the level with the seconds since the start
var levelPrefix = regexp.MustCompile(`^[A-Z]+\[[0-9]+\] `)

func (w sinkWriter) WriteMessage(level log.Level, message string) {
	w.sink(log.FormatLevel(level), levelPrefix.ReplaceAllString(message, ""))
}

func (w sinkWriter) Level() log.Level { return w.level }

func (sinkWriter) DisableColors() bool { return true }

// sinkLevel is the level of the log a configuration asks for: the one sing-box writes
// its own output at.
func sinkLevel(options *option.LogOptions) log.Level {
	if options == nil {
		return log.LevelInfo
	}
	if options.Disabled {
		return log.LevelPanic
	}
	level, err := log.ParseLevel(options.Level)
	if err != nil {
		return log.LevelInfo
	}
	return level
}

// BuildLogged is Build with the log of the instance also given to a sink, besides where
// the configuration sends it, and with hooks that are told of every connection the
// instance routes. The instances share the urltest history of the process (history).
func BuildLogged(configuration []byte, sink LogSink, hooks ...ConnectionHook) (*Instance, error) {
	collected := &notes{tell: true}
	ctx, cancel := context.WithCancel(withHistory(service.ExtendContext(include.Context(service.ContextWith[deprecated.Manager](context.Background(), collected)))))
	type built struct {
		box *box.Box
		err error
	}
	done := make(chan built, 1)
	go func() {
		var result built
		defer func() {
			if recover() != nil {
				result = built{nil, E.New("this sing-box cannot build the configuration")}
			}
			done <- result
		}()
		options, err := json.UnmarshalExtendedContext[option.Options](ctx, configuration)
		if err != nil {
			result.err = err
			return
		}
		// the lines sing-box writes itself go to the system log, where colours are escape codes
		if options.Log != nil {
			options.Log.DisableColor = true
		}
		boxOptions := box.Options{Context: ctx, Options: options}
		if sink != nil {
			boxOptions.PlatformLogWriter = sinkWriter{sink, sinkLevel(options.Log)}
		}
		result.box, result.err = box.New(boxOptions)
		if result.err == nil {
			// before the start: the router takes trackers only while nothing runs
			router := service.FromContext[adapter.Router](ctx)
			for _, hook := range hooks {
				router.AppendTracker(hookTracker{hook})
			}
		}
	}()
	select {
	case result := <-done:
		if result.err != nil {
			cancel()
			return nil, result.err
		}
		return &Instance{ctx: ctx, cancel: cancel, box: result.box, dialers: dialersOf(configuration)}, nil
	case <-time.After(buildTimeout):
		cancel()
		return nil, E.New("this sing-box takes too long to build the configuration")
	}
}

// Start starts the instance: the inbounds listen, the cache file is opened, remote rule
// sets begin to load. An instance that failed to start is closed here.
func (i *Instance) Start() error {
	// late: a test of the instance before may still end and write its result while that
	// one closes
	history.forgetChanged(i.dialers)
	i.started = time.Now()
	// a start that failed is closed here, within a bound: box.Start would close it itself,
	// for as long as a component takes, and the caller would never learn it is stuck
	err := i.box.StartWithoutClose()
	if err != nil {
		closeErr := i.Close(C.FatalStopTimeout)
		if closeErr == ErrStuck {
			return E.Errors(err, closeErr)
		}
		return err
	}
	// what the start needed and the run does not goes back to the system
	debug.FreeOSMemory()
	return nil
}

// Close stops the instance and waits for it for the given time. Calls of other
// goroutines are cut first (their context is the instance's) and waited for.
func (i *Instance) Close(patience time.Duration) error {
	i.cancel()
	done := make(chan error, 1)
	go func() {
		i.use.Lock()
		i.closed = true
		i.use.Unlock()
		done <- i.box.Close()
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(patience):
		return ErrStuck
	}
}

// Probe asks the DNS inbound of the instance for a name the configuration answers from
// FakeIP, again and again until an address of that range comes or the context ends. An
// instance that answers has its DNS inbound, its DNS rules and its FakeIP store working,
// which is what the LAN needs before its DNS is pointed here.
func Probe(ctx context.Context, address string, name string, fakeRange netip.Prefix) error {
	message := new(mDNS.Msg)
	message.SetQuestion(mDNS.Fqdn(name), mDNS.TypeA)
	client := &mDNS.Client{Net: "udp", Timeout: time.Second}
	var last error
	for {
		response, _, err := client.ExchangeContext(ctx, message, address)
		if err == nil {
			for _, record := range response.Answer {
				if answer, isAddress := record.(*mDNS.A); isAddress {
					if parsed, valid := netip.AddrFromSlice(answer.A.To4()); valid && fakeRange.Contains(parsed) {
						return nil
					}
					last = E.New("the answer for ", name, " is ", answer.A.String(), ", not an address of ", fakeRange.String())
				}
			}
			if last == nil {
				last = E.New("no address in the answer for ", name)
			}
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return E.Cause(last, "the DNS inbound at ", address, " does not answer as it should")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// RuleSetContent returns a rule set as sing-box last downloaded it: the bytes of the
// file, binary or source. Nothing is returned for a rule set that was never downloaded
// and for a configuration without a cache file.
func (i *Instance) RuleSetContent(tag string) ([]byte, bool) {
	if !i.enter() {
		return nil, false
	}
	defer i.leave()
	cacheFile := service.FromContext[adapter.CacheFile](i.ctx)
	if cacheFile == nil {
		return nil, false
	}
	saved := cacheFile.LoadRuleSet(tag)
	if saved == nil || len(saved.Content) == 0 {
		return nil, false
	}
	return saved.Content, true
}

// RuleSetHasAddresses tells whether the content sing-box loaded into a rule set has a rule
// with destination addresses (its metadata, ContainsIPCIDRRule; while the content of a
// remote one is not known yet, it says yes); told is false when there is no such rule set.
// A list of names only gives the firewall nothing, and need not be read for it.
func (i *Instance) RuleSetHasAddresses(tag string) (has bool, told bool) {
	if !i.enter() {
		return false, false
	}
	defer i.leave()
	router := service.FromContext[adapter.Router](i.ctx)
	if router == nil {
		return false, false
	}
	ruleSet, found := router.RuleSet(tag)
	if !found {
		return false, false
	}
	return ruleSet.Metadata().ContainsIPCIDRRule, true
}

// RuleSetUpdated tells when sing-box last downloaded a rule set, or found it unchanged at
// its server; nothing for a rule set never downloaded and without a cache file.
func (i *Instance) RuleSetUpdated(tag string) (time.Time, bool) {
	if !i.enter() {
		return time.Time{}, false
	}
	defer i.leave()
	cacheFile := service.FromContext[adapter.CacheFile](i.ctx)
	if cacheFile == nil {
		return time.Time{}, false
	}
	saved := cacheFile.LoadRuleSet(tag)
	if saved == nil || saved.LastUpdated.IsZero() {
		return time.Time{}, false
	}
	return saved.LastUpdated, true
}

// OnRuleSetUpdate calls back whenever sing-box loads new content into a rule set of the
// configuration: a download that brought a change, after it is saved to the cache file,
// or a local file that was rewritten. Registered before Start, it also hears the loads of
// the start. The call comes from sing-box's goroutine and must not block; it tells the
// tag only. Tags the configuration does not have are left out.
func (i *Instance) OnRuleSetUpdate(tags []string, updated func(tag string)) {
	router := service.FromContext[adapter.Router](i.ctx)
	if router == nil {
		return
	}
	for _, tag := range tags {
		ruleSet, found := router.RuleSet(tag)
		if !found {
			continue
		}
		ruleSet.RegisterCallback(func(adapter.RuleSet) { updated(tag) })
	}
}

// RuleSetUpdate is what an update of the remote rule sets came to.
type RuleSetUpdate struct {
	// Total is the number of rule sets sing-box downloads.
	Total int
	// Loaded is how many of them got new content.
	Loaded int
	// Failed is how many could not be downloaded or read.
	Failed int
}

// UpdateRuleSets makes sing-box download its remote rule sets now instead of at their
// update interval, and returns what that came to. A rule set that got new content is
// reported through OnRuleSetUpdate as after any other download.
func (i *Instance) UpdateRuleSets(ctx context.Context) (RuleSetUpdate, error) {
	if !i.enter() {
		return RuleSetUpdate{}, ErrClosed
	}
	defer i.leave()
	// ends with the instance as well
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(i.ctx, cancel)
	defer stop()
	updater, can := service.FromContext[adapter.Router](i.ctx).(ruleSetUpdater)
	if !can {
		// the router of this sing-box has UpdateRuleSets (fork.go): another one is not its own
		return RuleSetUpdate{}, E.New("the router of this sing-box is not its own and does not update its rule sets on request")
	}
	summary, err := updater.UpdateRuleSets(ctx)
	if err != nil {
		return RuleSetUpdate{}, err
	}
	return RuleSetUpdate{Total: summary.Total, Loaded: summary.Loaded, Failed: summary.Failed}, nil
}

// FakeIPAddress returns the FakeIP address a name has, if a DNS question for it was ever
// answered from FakeIP by this instance or by one that kept the cache file before it. It
// gives the name no address. A configuration without FakeIP has none.
func (i *Instance) FakeIPAddress(name string) (netip.Addr, bool, error) {
	if !i.enter() {
		return netip.Addr{}, false, nil
	}
	defer i.leave()
	manager := service.FromContext[adapter.DNSTransportManager](i.ctx)
	if manager == nil || manager.FakeIP() == nil {
		return netip.Addr{}, false, nil
	}
	store, can := manager.FakeIP().Store().(peeker)
	if !can {
		// the store of this sing-box has Peek (fork.go): another one is not its own
		return netip.Addr{}, false, E.New("the FakeIP store of this sing-box is not its own and cannot be asked without giving an address")
	}
	address, found := store.Peek(name, false)
	return address, found, nil
}

// Traffic is what went through an instance: the bytes of its connections up and down since
// it started, those still open and those closed, and the connections open now.
type Traffic struct {
	Up          int64
	Down        int64
	Connections int
}

// Traffic tells what went through the instance, from the tracker sing-box keeps for the Clash
// API and for a log writer of its own (which the instances of the backend all have).
func (i *Instance) Traffic() (Traffic, error) {
	if !i.enter() {
		return Traffic{}, ErrClosed
	}
	defer i.leave()
	manager := service.PtrFromContext[trafficcontrol.Manager](i.ctx)
	if manager == nil {
		return Traffic{}, E.New("this sing-box keeps no count of its traffic")
	}
	up, down := manager.Total()
	return Traffic{Up: up, Down: down, Connections: manager.ConnectionsLen()}, nil
}

// Connections returns the open TCP connections the tracker keeps, read in process (no Clash HTTP
// API): a big one counts as a flow that goes past a limit before it closes, and one whose client
// has long waited for the server as a cut. What the closed ones came to is in DetectFlows. Those of
// an outbound a swap replaced are left out: they say nothing of the link that has its tag now.
func (i *Instance) Connections() ([]detect.Conn, error) {
	if !i.enter() {
		return nil, ErrClosed
	}
	defer i.leave()
	manager := service.PtrFromContext[trafficcontrol.Manager](i.ctx)
	if manager == nil {
		return nil, E.New("this sing-box keeps no count of its traffic")
	}
	open := manager.Connections()
	conns := make([]detect.Conn, 0, len(open))
	i.detectAccess.Lock()
	defer i.detectAccess.Unlock()
	for _, m := range open {
		if m.Metadata.Network != N.NetworkTCP {
			continue
		}
		if forgotten, found := i.detectForgotten[m.Outbound]; found && m.CreatedAt.Before(forgotten) {
			continue
		}
		conns = append(conns, detect.Conn{Outbound: m.Outbound, Down: m.Download.Load(), Up: m.Upload.Load(), CreatedAt: m.CreatedAt, PendingSince: m.PendingSince()})
	}
	return conns, nil
}

// DetectFlows returns what the engine keeps for the block detector of the closed TCP connections
// of the proxy outbounds, by tag: possible cuts and when flows last carried anything. Unlike the
// closed connections of the Clash API, the cleanup at every GC does not wipe it.
func (i *Instance) DetectFlows() (map[string]detect.FlowSample, error) {
	if !i.enter() {
		return nil, ErrClosed
	}
	defer i.leave()
	manager := service.PtrFromContext[trafficcontrol.Manager](i.ctx)
	if manager == nil {
		return nil, E.New("this sing-box keeps no count of its traffic")
	}
	samples := manager.DetectFlows()
	flows := make(map[string]detect.FlowSample, len(samples))
	for tag, sample := range samples {
		cuts := make([]detect.Flow, len(sample.Cuts))
		for index, cut := range sample.Cuts {
			cuts[index] = detect.Flow{Download: cut.Download, Upload: cut.Upload, CreatedAt: cut.CreatedAt, ClosedAt: cut.ClosedAt, PendingSince: cut.PendingSince}
		}
		flows[tag] = detect.FlowSample{Cuts: cuts, LastBigAt: sample.LastBigAt, LastDataAt: sample.LastDataAt}
	}
	return flows, nil
}

// DetectOutcome returns what the engine recorded of the handshakes with a server, from the cache
// file; false when the configuration has no cache file or no record for the key. The caller
// decides whether a record is still fresh. The key is the fallback's: the configured fingerprint,
// the TLS server name and the server (host:port), as ServersOf reads them.
func (i *Instance) DetectOutcome(fingerprint string, serverName string, destination string) (detect.Outcome, bool) {
	if !i.enter() {
		return detect.Outcome{}, false
	}
	defer i.leave()
	cache := service.FromContext[adapter.CacheFile](i.ctx)
	if cache == nil {
		return detect.Outcome{}, false
	}
	flags, fp, at, loaded := cache.LoadDetectOutcome(fingerprint + " " + serverName + " " + destination)
	if !loaded {
		return detect.Outcome{}, false
	}
	return detect.Outcome{
		NoAnswer:    flags&adapter.DetectNoAnswer != 0,
		Refused:     flags&adapter.DetectRefused != 0,
		Failed:      flags&adapter.DetectFailed != 0,
		Fingerprint: fp,
		At:          at,
	}, true
}

// StartedAt is when the instance was asked to start: what it recorded since is of this run.
func (i *Instance) StartedAt() time.Time {
	return i.started
}

// Dial opens a TCP connection to an address (host:port) through an outbound of the instance,
// by its tag: a name is resolved the way the outbound resolves names, by the DNS of the
// configuration for direct-out, by the server for a proxy. The connection ends with the
// context, and with the instance.
func (i *Instance) Dial(ctx context.Context, tag string, address string) (net.Conn, error) {
	if !i.enter() {
		return nil, ErrClosed
	}
	defer i.leave()
	manager := service.FromContext[adapter.OutboundManager](i.ctx)
	if manager == nil {
		return nil, E.New("this sing-box has no outbounds")
	}
	outbound, found := manager.Outbound(tag)
	if !found {
		return nil, E.New("there is no outbound ", tag)
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(i.ctx, cancel)
	conn, err := outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(address))
	if err != nil {
		stop()
		cancel()
		return nil, err
	}
	return &dialed{Conn: conn, stop: stop, cancel: cancel}, nil
}

// dialed is a connection of Dial: closed, it lets go of the context it was opened with.
type dialed struct {
	net.Conn
	stop   func() bool
	cancel context.CancelFunc
}

func (c *dialed) Close() error {
	c.stop()
	c.cancel()
	return c.Conn.Close()
}
