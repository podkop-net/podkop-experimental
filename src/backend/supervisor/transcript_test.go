package supervisor

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/btstats"
	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/sockets"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"

	"github.com/stretchr/testify/require"
)

// The transcripts of the supervisor: each scenario of transcriptScenarios is a list of steps (the
// settings written, Boot, Apply, a change of the network, a list sing-box loads, a download of a
// subscription that ends, Stop, Release, and what the engine or the router does wrong from a step
// on), run on the fake engine of fake_test.go and a System of this file, both recording. What they
// were asked, in order and with the arguments (the configurations and the firewall plans by number,
// each described where it first appears), the log with its levels, the results, the answers to the
// callers that wait for downloads, the subscriptions and the state after each step are
// testdata/transcripts/<name>.txt, byte for byte. No time, no process number: durations are "N ms",
// clock times "HH:MM:SS", the directory of the test "$DIR".
//
// Not recorded: the calls of the engine and of the instances that only read for the page, the
// detector and the downloads (Notes, Delays, Traffic, CheckServers, DownloadWays, RecordDownload,
// Dial...), which the downloads make from their own goroutines; and RuleSetHasAddresses, asked of
// every rule set at every firewall plan. Each step is run in the goroutine of the test, as the
// goroutine of Run would: downloads are held at the provider until a step lets one answer, so the
// order is the test's.
//
// They are for the bug classes of a rearranged apply and takeList: a success tail of apply that
// skips a call (the review of 2026-11-14, finding 1: excludeDownloads of the same configuration;
// scenario skip-downloads), a branch of takeList that skips downloadDue (a subscription that waited
// for a place stays not busy), applyTaken (the lists taken are not applied at the end of a round)
// or answerWaiting (a caller stays waiting): the takelist-* scenarios go through each branch with
// a subscription waiting and as the last of a round (lab/v0822/kern/mutants.sh deleted each of
// those calls in turn while each branch had its own: all were caught but the applyTaken of the
// branch of a changed request, which can apply nothing there). The tails and the branches now
// share nowRunning and the end of takeList; lab/v0823/sup/sup.sh NAME mutants deletes each of
// their calls in turn, and those that tell the parts (subscriptionRuntime, bitTorrentRuntime) what
// the supervisor does.
//
//	go test -count=1 -run TestTranscripts -update ./supervisor/   (with the tags of the package's tests)
//
// rewrites them (on nexus: lab/v0822/kern/kern.sh NAME transcripts). A diff of them in a commit that
// only rearranges the code is a failure.
var updateTranscripts = flag.Bool("update", false, "rewrite the transcripts of testdata/transcripts")

func TestTranscripts(t *testing.T) {
	for _, scenario := range transcriptScenarios() {
		t.Run(scenario.name, func(t *testing.T) {
			got := runScenario(t, scenario)
			path := filepath.Join("testdata", "transcripts", scenario.name+".txt")
			if *updateTranscripts {
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
				require.NoError(t, os.WriteFile(path, []byte(got), 0o644))
				return
			}
			want, err := os.ReadFile(path)
			require.NoError(t, err, "-update writes it")
			if string(want) != got {
				t.Errorf("%s is not what the scenario makes now (-update rewrites it, for a change that is meant):\n%s", path, transcriptDifference(string(want), got))
			}
		})
	}
}

// transcriptDifference shows where two transcripts part: the step and the lines before, then the
// first differing lines of each.
func transcriptDifference(want string, got string) string {
	wantLines, gotLines := strings.Split(want, "\n"), strings.Split(got, "\n")
	line := 0
	for line < len(wantLines) && line < len(gotLines) && wantLines[line] == gotLines[line] {
		line++
	}
	var text strings.Builder
	for index := line - 1; index >= 0; index-- {
		if strings.HasPrefix(wantLines[index], "== ") {
			text.WriteString("in the step " + wantLines[index] + ", after line " + strconv.Itoa(line) + ":\n")
			break
		}
	}
	for _, item := range wantLines[max(0, line-3):line] {
		text.WriteString("    " + item + "\n")
	}
	part := func(name string, lines []string) {
		text.WriteString("--- " + name + "\n")
		if line >= len(lines) {
			text.WriteString("  (the end)\n")
		}
		for _, item := range lines[min(line, len(lines)):min(line+8, len(lines))] {
			text.WriteString("  " + item + "\n")
		}
	}
	part("the transcript", wantLines)
	part("now", gotLines)
	return text.String()
}

// tape is what a scenario recorded.
type tape struct {
	access sync.Mutex
	lines  []string
	// notes go after the next line: what a configuration or a plan named in it is
	notes    []string
	replacer *strings.Replacer
	configs  []string
	plans    []string
}

var (
	milliseconds = regexp.MustCompile(`\b\d+ ms\b`)
	clockTimes   = regexp.MustCompile(`\b\d{2}:\d{2}:\d{2}\b`)
)

func (p *tape) normal(text string) string {
	text = p.replacer.Replace(text)
	text = milliseconds.ReplaceAllString(text, "N ms")
	return clockTimes.ReplaceAllString(text, "HH:MM:SS")
}

func (p *tape) add(format string, arguments ...any) {
	p.access.Lock()
	defer p.access.Unlock()
	p.lines = append(p.lines, p.normal(fmt.Sprintf(format, arguments...)))
	p.lines = append(p.lines, p.notes...)
	p.notes = nil
}

// config names a configuration by its number, the same text the same number; a new one is
// described after the line that names it.
func (p *tape) config(config []byte) string {
	p.access.Lock()
	defer p.access.Unlock()
	text := p.replacer.Replace(string(config))
	for index, known := range p.configs {
		if known == text {
			return "C" + strconv.Itoa(index+1)
		}
	}
	p.configs = append(p.configs, text)
	name := "C" + strconv.Itoa(len(p.configs))
	p.notes = append(p.notes, "    "+name+" = "+p.normal(configSummary(config)))
	return name
}

// plan names a firewall plan as config names a configuration.
func (p *tape) plan(next *firewall.Plan) string {
	if next == nil {
		return "none"
	}
	p.access.Lock()
	defer p.access.Unlock()
	lines := planText(next)
	text := strings.Join(lines, "\n")
	for index, known := range p.plans {
		if known == text {
			return "P" + strconv.Itoa(index+1)
		}
	}
	p.plans = append(p.plans, text)
	name := "P" + strconv.Itoa(len(p.plans))
	for index, line := range lines {
		lead := "      "
		if index == 0 {
			lead = "    " + name + " = "
		}
		p.notes = append(p.notes, lead+line)
	}
	return name
}

// configSummary is what a configuration is for a reader of a transcript: its inbounds and its
// outbounds.
func configSummary(config []byte) string {
	var document struct {
		Inbounds []struct {
			Type, Tag, Listen string
			Port              int `json:"listen_port"`
		}
		Outbounds []struct{ Type, Tag string }
		Route     struct {
			RuleSets []struct{ Tag string } `json:"rule_set"`
		}
	}
	if json.Unmarshal(config, &document) != nil {
		return "(not JSON)"
	}
	var inbounds, outbounds []string
	for _, inbound := range document.Inbounds {
		text := inbound.Tag + " " + inbound.Type
		if inbound.Listen != "" {
			text += " " + net.JoinHostPort(inbound.Listen, strconv.Itoa(inbound.Port))
		}
		inbounds = append(inbounds, text)
	}
	for _, outbound := range document.Outbounds {
		outbounds = append(outbounds, outbound.Tag+" "+outbound.Type)
	}
	return "inbounds: " + strings.Join(inbounds, ", ") + "; outbounds: " + strings.Join(outbounds, ", ") + "; rule sets: " + strconv.Itoa(len(document.Route.RuleSets))
}

// planText is a firewall plan, a field a line, the empty ones left out.
func planText(next *firewall.Plan) []string {
	var lines []string
	add := func(name string, values ...string) {
		if len(values) > 0 {
			lines = append(lines, name+" "+strings.Join(values, " "))
		}
	}
	prefixes := func(list []netip.Prefix) []string {
		texts := make([]string, len(list))
		for index, prefix := range list {
			texts[index] = prefix.String()
		}
		return texts
	}
	add("interfaces", next.Interfaces...)
	if next.ExcludeNTP {
		lines = append(lines, "NTP of the LAN left alone")
	}
	add("devices routed whole", prefixes(next.Sources)...)
	add("subnets", firewall.RangeStrings(next.Subnets)...)
	for _, group := range next.Groups {
		var ports []string
		for _, item := range group.Ports {
			ports = append(ports, strconv.Itoa(int(item.From))+"-"+strconv.Itoa(int(item.To)))
		}
		var ranges6 []string
		for _, item := range group.Ranges6 {
			ranges6 = append(ranges6, item.String())
		}
		lines = append(lines, "group "+group.Set+" protocol "+strconv.Itoa(int(group.Protocol))+" ports "+strings.Join(ports, ",")+
			" subnets "+strings.Join(firewall.RangeStrings(group.Ranges), " ")+" subnets6 "+strings.Join(ranges6, " "))
	}
	add("the Clash API from", next.ClashAPIInterfaces...)
	// (off, the rest of the detector is not used: its devices are the plan's own then)
	if detector := next.BitTorrent; detector.Mode != "" {
		var users []string
		for _, user := range detector.RouterUsers {
			users = append(users, strconv.Itoa(int(user)))
		}
		lines = append(lines, fmt.Sprintf("bittorrent %q lan %v devices %v fan %v router users %v", detector.Mode, detector.LAN, prefixes(next.Sources), fmt.Sprintf("%+v", detector.Fan), users))
	}
	for _, mark := range next.OwnMarks {
		lines = append(lines, fmt.Sprintf("own mark 0x%08x", mark))
	}
	if next.IPv6 {
		lines = append(lines, "IPv6 through podkop")
		var subnets6 []string
		for _, item := range next.Subnets6 {
			subnets6 = append(subnets6, item.String())
		}
		add("subnets6", subnets6...)
	}
	if len(lines) == 0 {
		return []string{"(nothing)"}
	}
	return lines
}

func outcome(err error) string {
	if err != nil {
		return " -> error: " + err.Error()
	}
	return " -> ok"
}

func listText(values []string) string {
	return "[" + strings.Join(values, ", ") + "]"
}

func mapText(values map[string]string) string {
	if values == nil {
		return "none"
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	texts := make([]string, len(keys))
	for index, key := range keys {
		texts[index] = key + "=" + values[key]
	}
	return "{" + strings.Join(texts, ", ") + "}"
}

// tapeSystem is a System that records what it is asked and does what the steps make of the
// router.
type tapeSystem struct {
	tape *tape
	// lan is the address of the LAN, "" none; devices what netifd says the interface names stand
	// for; listening the sockets that listen (nil: not known); ipv6 whether the router has ::1
	lan       string
	devices   map[string]string
	listening []sockets.Listener
	ipv6      bool
	// routingGone, firewallGone: taken away by the router (netifd flushed them); dnsOurs: dnsmasq
	// asks the backend
	routingGone, firewallGone, dnsOurs bool
	// routingError, routingErrorIPv6: what setting up the routing (of IPv6) fails with;
	// firewallErrorIPv6 what an update of a plan with IPv6 fails with
	routingError, routingErrorIPv6, firewallErrorIPv6 error
	// uplinks: the devices RouteUplinks adds rules for, once; bridged: br_netfilter is on
	uplinks []string
	bridged bool
}

func (r *tapeSystem) LANAddress() string {
	r.tape.add("system LANAddress -> %q", r.lan)
	return r.lan
}

func (r *tapeSystem) Devices(names []string) map[string]string {
	r.tape.add("system Devices %s -> %s", listText(names), mapText(r.devices))
	return r.devices
}

func (r *tapeSystem) Listening() []sockets.Listener {
	if r.listening == nil {
		r.tape.add("system Listening -> not known")
		return nil
	}
	r.tape.add("system Listening -> %d sockets", len(r.listening))
	return r.listening
}

func (r *tapeSystem) ApplyRouting(ipv6 bool) error {
	err := r.routingError
	if ipv6 && r.routingErrorIPv6 != nil {
		err = r.routingErrorIPv6
	}
	if err == nil {
		r.routingGone = false
	}
	r.tape.add("system ApplyRouting ipv6=%v%s", ipv6, outcome(err))
	return err
}

func (r *tapeSystem) RemoveRouting() error {
	r.tape.add("system RemoveRouting")
	return nil
}

func (r *tapeSystem) AllowBridgedTraffic() []string {
	var turned []string
	if r.bridged {
		r.bridged = false
		turned = []string{"net.bridge.bridge-nf-call-iptables"}
	}
	r.tape.add("system AllowBridgedTraffic -> %s", listText(turned))
	return turned
}

func (r *tapeSystem) RoutingPresent(ipv6 bool) (bool, error) {
	r.tape.add("system RoutingPresent ipv6=%v -> %v", ipv6, !r.routingGone)
	return !r.routingGone, nil
}

func (r *tapeSystem) IPv6() bool {
	r.tape.add("system IPv6 -> %v", r.ipv6)
	return r.ipv6
}

func (r *tapeSystem) FirewallPresent() (bool, error) {
	r.tape.add("system FirewallPresent -> %v", !r.firewallGone)
	return !r.firewallGone, nil
}

func (r *tapeSystem) RouteUplinks() ([]string, error) {
	added := r.uplinks
	r.uplinks = nil
	r.tape.add("system RouteUplinks -> %s", listText(added))
	return added, nil
}

func (r *tapeSystem) SetClashSecret(key string) error {
	r.tape.add("system SetClashSecret (a key of %d characters)", len(key))
	return nil
}

func (r *tapeSystem) UpdateFirewall(previous *firewall.Plan, next *firewall.Plan) error {
	var err error
	if next.IPv6 && r.firewallErrorIPv6 != nil {
		err = r.firewallErrorIPv6
	}
	r.tape.add("system UpdateFirewall %s to %s%s", r.tape.plan(previous), r.tape.plan(next), outcome(err))
	if err == nil {
		r.firewallGone = false
	}
	return err
}

func (r *tapeSystem) ForgetBitTorrentFlows(which firewall.Forget) error {
	r.tape.add("system ForgetBitTorrentFlows %s", which.String())
	return nil
}

func (r *tapeSystem) BitTorrentFlows() ([]btstats.Flow, error) { return nil, nil }
func (r *tapeSystem) BitTorrentDrops() (btstats.Drops, error)  { return btstats.Drops{}, nil }

func (r *tapeSystem) RemoveFirewall() error {
	r.tape.add("system RemoveFirewall")
	return nil
}

func (r *tapeSystem) TakeOverDNS() (bool, error) {
	changed := !r.dnsOurs
	r.dnsOurs = true
	r.tape.add("system TakeOverDNS -> changed %v", changed)
	return changed, nil
}

func (r *tapeSystem) RestoreDNS() (bool, error) {
	changed := r.dnsOurs
	r.dnsOurs = false
	r.tape.add("system RestoreDNS -> changed %v", changed)
	return changed, nil
}

func (r *tapeSystem) NTPServerNames() []string {
	r.tape.add("system NTPServerNames -> []")
	return nil
}

func (r *tapeSystem) EndCause(int) string {
	r.tape.add("system EndCause")
	return ""
}

// tapeEngine is the fake engine, recording.
type tapeEngine struct {
	*fakeEngine
	tape      *tape
	instances int
}

func (e *tapeEngine) Check(config []byte, links []plan.Link) error {
	err := e.fakeEngine.Check(config, links)
	e.tape.add("engine Check %s%s", e.tape.config(config), outcome(err))
	return err
}

func (e *tapeEngine) Build(config []byte, sink engine.LogSink, hooks ...engine.ConnectionHook) (Instance, error) {
	built, err := e.fakeEngine.Build(config, sink, hooks...)
	name := e.tape.config(config)
	if err != nil {
		e.tape.add("engine Build %s%s", name, outcome(err))
		return nil, err
	}
	e.instances++
	instance := &tapeInstance{fakeInstance: built.(*fakeInstance), tape: e.tape, number: e.instances}
	e.tape.add("engine Build %s -> instance %d", name, instance.number)
	return instance, nil
}

func (e *tapeEngine) Ready(ctx context.Context) error {
	err := e.fakeEngine.Ready(ctx)
	e.tape.add("engine Ready%s", outcome(err))
	return err
}

func (e *tapeEngine) ExcludeDownloads(tags []string) {
	e.tape.add("engine ExcludeDownloads %s", listText(tags))
	e.fakeEngine.ExcludeDownloads(tags)
}

// tapeInstance is an instance of the fake engine, recording.
type tapeInstance struct {
	*fakeInstance
	tape   *tape
	number int
}

func (i *tapeInstance) OnRuleSetUpdate(tags []string, updated func(tag string)) {
	i.tape.add("instance %d OnRuleSetUpdate %s", i.number, listText(tags))
	i.fakeInstance.OnRuleSetUpdate(tags, updated)
}

func (i *tapeInstance) Start() error {
	err := i.fakeInstance.Start()
	i.tape.add("instance %d Start%s", i.number, outcome(err))
	return err
}

func (i *tapeInstance) Close(patience time.Duration) error {
	err := i.fakeInstance.Close(patience)
	i.tape.add("instance %d Close%s", i.number, outcome(err))
	return err
}

func (i *tapeInstance) RuleSetContent(tag string) ([]byte, bool) {
	content, found := i.fakeInstance.RuleSetContent(tag)
	if found {
		i.tape.add("instance %d RuleSetContent %s -> %d bytes", i.number, tag, len(content))
	} else {
		i.tape.add("instance %d RuleSetContent %s -> none", i.number, tag)
	}
	return content, found
}

func (i *tapeInstance) Swap(configuration []byte, swap engine.Swap, limit int) (engine.Swapped, error) {
	swapped, err := i.fakeInstance.Swap(configuration, swap, limit)
	var put []string
	for _, outbound := range swap.Put {
		var tagged struct{ Tag string }
		_ = json.Unmarshal(outbound, &tagged)
		put = append(put, tagged.Tag)
	}
	i.tape.add("instance %d Swap %s put %s remove %s limit %d%s", i.number, i.tape.config(configuration), listText(put), listText(swap.Remove), limit, outcome(err))
	return swapped, err
}

func (i *tapeInstance) CarrySelections(configuration []byte) map[string]string {
	carried := i.fakeInstance.CarrySelections(configuration)
	i.tape.add("instance %d CarrySelections %s -> %s", i.number, i.tape.config(configuration), mapText(carried))
	return carried
}

func (i *tapeInstance) AdoptSelections(selectors map[string]string, members map[string]string) {
	i.tape.add("instance %d AdoptSelections %s members %s", i.number, mapText(selectors), mapText(members))
	i.fakeInstance.AdoptSelections(selectors, members)
}

func (i *tapeInstance) Select(choices map[string]string) {
	i.tape.add("instance %d Select %s", i.number, mapText(choices))
	i.fakeInstance.Select(choices)
}

type tapeDnsmasq struct{ tape *tape }

func (w tapeDnsmasq) Kick(after time.Duration)    { w.tape.add("dnsmasq Kick after %s", after) }
func (w tapeDnsmasq) Settle(budget time.Duration) { w.tape.add("dnsmasq Settle within %s", budget) }

type tapeClock struct{ tape *tape }

func (c tapeClock) Kick() { c.tape.add("clock Kick") }

// feeds are the providers of the subscriptions of a scenario, by address: a download waits at its
// provider until a step lets it answer (feed.gate), or the scenario ends.
type feeds struct {
	access    sync.Mutex
	byAddress map[string]*feed
	quit      chan struct{}
}

type feed struct {
	gate chan struct{}
	body string
	fail bool
}

func (f *feeds) of(address string) *feed {
	f.access.Lock()
	defer f.access.Unlock()
	if f.byAddress[address] == nil {
		f.byAddress[address] = &feed{gate: make(chan struct{})}
	}
	return f.byAddress[address]
}

func (f *feeds) download(ctx context.Context, address string, header http.Header, routes []subscription.Route, way subscription.Plan, report func([]subscription.Try)) (*subscription.Answer, []subscription.Try, error) {
	source := f.of(address)
	select {
	case <-source.gate:
	case <-ctx.Done():
		return nil, nil, &subscription.Failure{Code: "canceled", Text: "canceled"}
	case <-f.quit:
		return nil, nil, &subscription.Failure{Code: "canceled", Text: "the test ended"}
	}
	f.access.Lock()
	body, fail := source.body, source.fail
	f.access.Unlock()
	route := "direct"
	if len(routes) > 0 {
		route = routes[0].Name
	}
	if fail {
		tries := []subscription.Try{{Route: route, Phase: subscription.PhaseFailed, Took: 5 * time.Second, Failure: &subscription.Failure{Code: "timeout", Args: []string{"5"}, Text: "no answer in 5 s"}}}
		return nil, tries, &subscription.Failure{Code: "unreachable", Text: "the provider could not be reached"}
	}
	tries := []subscription.Try{{Route: route, Phase: subscription.PhaseDone, Took: 800 * time.Millisecond, FirstByte: 700 * time.Millisecond, Bytes: int64(len(body))}}
	return &subscription.Answer{Body: []byte(body), Header: http.Header{}, Route: route}, tries, nil
}

// run is a scenario under way.
type run struct {
	t       *testing.T
	tape    *tape
	s       *Supervisor
	engine  *tapeEngine
	system  *tapeSystem
	dir     string
	feeds   *feeds
	waiting []waiter
}

// waiter is a caller of UpdateSubscriptions ("" for all) waiting for its answer.
type waiter struct {
	name  string
	reply chan []SubscriptionState
}

type step struct {
	title string
	do    func(r *run)
}

type scenario struct {
	name, about string
	steps       []step
}

func runScenario(t *testing.T, scenario scenario) string {
	dir := t.TempDir()
	recorded := &tape{replacer: strings.NewReplacer(filepath.Join(dir, "candidate", "rulesets"), "$DIR/rulesets", dir, "$DIR")}
	system := &tapeSystem{tape: recorded, lan: "192.168.1.1"}
	fake := &fakeEngine{refuse: map[string]error{}, lists: map[string][]byte{}, noAddresses: map[string]bool{}}
	providers := &feeds{byAddress: map[string]*feed{}, quit: make(chan struct{})}
	r := &run{t: t, tape: recorded, engine: &tapeEngine{fakeEngine: fake, tape: recorded}, system: system, dir: dir, feeds: providers}
	r.s = New(Options{
		SettingsPath: filepath.Join(dir, "podkop"), RuleSetDir: filepath.Join(dir, "rulesets"),
		StagingDir: filepath.Join(dir, "candidate"), StatePath: filepath.Join(dir, "state"),
		ConfigDir: filepath.Join(dir, "run"), ReadyTimeout: time.Second, System: system, Engine: r.engine,
		Log:     func(level string, message string) { recorded.add("log %s: %s", level, message) },
		Dnsmasq: tapeDnsmasq{recorded}, Clock: tapeClock{recorded}, Version: "0.8.22", Download: providers.download,
	})
	t.Cleanup(func() {
		// the downloads still held end, and what they came to is taken by nobody
		close(providers.quit)
		go func() {
			for range r.s.subscriptions.downloads {
			}
		}()
	})
	recorded.lines = []string{"# " + scenario.name + ": " + scenario.about,
		"# (supervisor/transcript_test.go; go test -run TestTranscripts -update ./supervisor/ writes it anew)"}
	for _, item := range scenario.steps {
		recorded.add("")
		recorded.add("== %s", item.title)
		item.do(r)
		r.after()
	}
	for _, waiting := range r.waiting {
		recorded.add("still waiting: the caller of %s", waitName(waiting.name))
	}
	return strings.Join(recorded.lines, "\n") + "\n"
}

func waitName(name string) string {
	if name == "" {
		return "all"
	}
	return name
}

// after records what a step left: the answers to the callers that waited, the subscriptions,
// the state.
func (r *run) after() {
	var still []waiter
	for _, waiting := range r.waiting {
		select {
		case states := <-waiting.reply:
			r.tape.add("answered the caller of %s: %s", waitName(waiting.name), statesText(states))
		default:
			still = append(still, waiting)
		}
	}
	r.waiting = still
	if states := r.s.subscriptionStates(); len(states) > 0 {
		r.tape.add("subscriptions: %s", statesText(states))
	}
	word := "none"
	if content, err := os.ReadFile(r.s.options.StatePath); err == nil {
		if fields := strings.Fields(string(content)); len(fields) > 0 {
			word = fields[0]
		}
	}
	r.tape.add("state: %s, running %v", word, r.s.Running())
}

// statesText is what the subscriptions are: busy or the servers of the list taken, the error, when
// the next download is due (to 10 s).
func statesText(states []SubscriptionState) string {
	texts := make([]string, len(states))
	now := time.Now()
	for index, state := range states {
		text := state.Name
		if state.Busy {
			text += " busy"
		} else {
			text += " " + strconv.Itoa(state.Servers) + " servers"
			if state.ErrorCode != "" {
				text += ", error " + state.ErrorCode
			}
			switch {
			case state.Next == nil:
				text += ", nothing planned"
			case !state.Next.After(now):
				text += ", due"
			default:
				text += ", next in " + state.Next.Sub(now).Round(10*time.Second).String()
			}
		}
		texts[index] = text
	}
	return strings.Join(texts, "; ")
}

// fatal ends the scenario, with the end of what it recorded so far.
func (r *run) fatal(format string, arguments ...any) {
	r.t.Helper()
	r.tape.access.Lock()
	lines := r.tape.lines[max(0, len(r.tape.lines)-60):]
	r.tape.access.Unlock()
	r.t.Fatalf(format+"; the end of the transcript:\n%s", append(arguments, strings.Join(lines, "\n"))...)
}

func (r *run) result(result Result) {
	word := "failed"
	if result.OK {
		word = "ok"
	}
	r.tape.add("result %s: %s", word, result.Message)
}

// the steps

func writeSettings(label string, text func(dir string) string) step {
	return step{"write the settings: " + label, func(r *run) {
		require.NoError(r.t, os.WriteFile(r.s.options.SettingsPath, []byte(text(r.dir)), 0o644))
	}}
}

func boot() step  { return step{"Boot", func(r *run) { r.result(r.s.Boot()) }} }
func apply() step { return step{"Apply", func(r *run) { r.result(r.s.Apply()) }} }
func stop() step  { return step{"Stop", func(r *run) { r.s.Stop() }} }

func release() step { return step{"Release", func(r *run) { r.s.Release() }} }

// networkChange is an interface that came up: the hotplug script asks the backend to put back what
// the router took (RestoreRouting).
func networkChange() step {
	return step{"the network changes (RestoreRouting)", func(r *run) { r.tape.add("answer: %s", r.s.restoreRouting()) }}
}

// meanwhile is what the router or the engine does from now on.
func meanwhile(title string, do func(r *run)) step {
	return step{"meanwhile: " + title, do}
}

// listeningAll: everything the running configuration listens on is there, but what drop names (a
// tag, or a tag and a protocol).
func listeningAll(r *run, drop string) []sockets.Listener {
	result := []sockets.Listener{}
	for _, inbound := range inboundSockets(r.s.current.result.Config) {
		if inbound.tag+" "+inbound.protocol != drop && inbound.tag != drop {
			result = append(result, sockets.Listener{Protocol: inbound.protocol, Address: inbound.address})
		}
	}
	return result
}

// ruleSetTag is the tag of the rule set of the running configuration whose address ends so.
func ruleSetTag(r *run, suffix string) string {
	for _, ruleSet := range r.s.current.result.RuleSets {
		if strings.HasSuffix(ruleSet.URL, suffix) {
			return ruleSet.Tag
		}
	}
	r.fatal("no rule set of %s", suffix)
	return ""
}

// loadList is sing-box loading a list it downloaded: the instance tells the backend, and the
// firewall is brought to it, as Run does after the pause that merges loads.
func loadList(suffix string, content string) step {
	return step{"sing-box loads the list " + suffix + ": " + strings.Join(strings.Fields(content), " "), func(r *run) {
		tag := ruleSetTag(r, suffix)
		r.engine.lists[tag] = []byte(content)
		r.s.current.instance.(*tapeInstance).loaded(tag)
		r.s.refreshFirewall()
	}}
}

// due makes every subscription due at the same time, as those an apply adds are, and starts the
// downloads that have a place, as the ticker of Run does: downloadDue takes them by name.
func due() step {
	return step{"every subscription is due: the downloads start", func(r *run) {
		r.s.subscriptions.access.Lock()
		past := time.Now().Add(-time.Second)
		for _, state := range r.s.subscriptions.states {
			state.Next = &past
		}
		r.s.subscriptions.access.Unlock()
		r.s.downloadDue(time.Now(), "")
	}}
}

// waitFor is a caller of UpdateSubscriptions for a subscription ("" all), taken by Run.
func waitFor(name string) step {
	return step{"a caller asks for the download of " + waitName(name) + " and waits", func(r *run) {
		reply := make(chan []SubscriptionState, 1)
		r.s.askDownload(subscriptionRequest{name: name, reply: reply})
		r.waiting = append(r.waiting, waiter{name: name, reply: reply})
	}}
}

// provide lets the download of address end with the list body (fail: unreachable), and Run takes
// what it came to.
func provide(address string, body string, fail bool) step {
	title := "the provider " + address + " answers with " + strconv.Itoa(strings.Count(body, "\n")) + " servers"
	if fail {
		title = "the provider " + address + " cannot be reached"
	}
	return step{title, func(r *run) {
		source := r.feeds.of(address)
		r.feeds.access.Lock()
		source.body, source.fail = body, fail
		r.feeds.access.Unlock()
		select {
		case source.gate <- struct{}{}:
		case <-time.After(10 * time.Second):
			r.fatal("no download of %s is under way", address)
		}
		select {
		case result := <-r.s.subscriptions.downloads:
			r.s.takeList(result)
		case <-time.After(10 * time.Second):
			r.fatal("the download of %s did not come back", address)
		}
	}}
}

// the settings of the scenarios

// plainSettings: a rule of names through a SOCKS5 proxy, the TTL of the DNS ttl; more goes into
// the settings, rule into the rule (podkop 0.7's format, converted by the backend).
func plainSettings(ttl string, more string, rule string) func(dir string) string {
	return func(dir string) string {
		return "config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '127.0.0.1:9'\n\toption dns_rewrite_ttl '" + ttl + "'\n" +
			"\toption cache_path '" + filepath.Join(dir, "cache.db") + "'\n\toption yacd_secret_key 'k'\n" + more +
			"\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n" +
			"\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'one.lab.example'\n" + rule
	}
}

func brokenSettings(dir string) string {
	return strings.Replace(plainSettings("60", "", "")(dir), "socks5://203.0.113.15:1080", "vless://broken", 1)
}

// sourceSettings: format 2, a rule of names whose source has link (none: nothing to route).
func sourceSettings(link string) func(dir string) string {
	return func(dir string) string {
		source := ""
		if link != "" {
			source = "\toption type 'links'\n\tlist link '" + link + "'\n"
		}
		return "config settings 'settings'\n\toption config_version '2'\n\toption dns_type 'udp'\n\toption dns_server '127.0.0.1:9'\n" +
			"\toption cache_path '" + filepath.Join(dir, "cache.db") + "'\n\toption yacd_secret_key 'k'\n" +
			"\nconfig source 'src1'\n" + source +
			"\nconfig section 'main'\n\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'one.lab.example'\n" +
			"\nconfig member\n\toption section 'main'\n\toption role 'server'\n\toption source 'src1'\n"
	}
}

// subscriptionAddress is the address of the subscription provN.
func subscriptionAddress(number int) string {
	return "https://sub" + strconv.Itoa(number) + ".example/s"
}

// subscriptionsSettings: the subscriptions prov1..provN (provN's address addresses[N-1] when given,
// its section more[N-1] added), in one group of their servers named NL, which a rule uses.
func subscriptionsSettings(count int, addresses map[int]string, more map[int]string) func(dir string) string {
	return func(dir string) string {
		text := plainSettings("60", "", "")(dir)
		group := "\nconfig group 'nl'\n"
		for number := 1; number <= count; number++ {
			name := "prov" + strconv.Itoa(number)
			address := subscriptionAddress(number)
			if other, found := addresses[number]; found {
				address = other
			}
			text += "\nconfig subscription '" + name + "'\n\toption url '" + address + "'\n\toption update_interval '1h'\n" + more[number]
			group += "\tlist subscription '" + name + "'\n"
		}
		return text + group + "\tlist include 'NL'\n\toption empty 'block'\n" +
			"\nconfig section 'youtube'\n\toption connection_type 'group'\n\toption group 'nl'\n" +
			"\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'youtube.lab.example'\n"
	}
}

// servers is a list of a provider: a VLESS server for each name, its host and user of the name
// before a bracket ("NL 1 (29 days)" is NL 1 renamed).
func servers(names ...string) string {
	var text strings.Builder
	for _, name := range names {
		base, _, _ := strings.Cut(name, " (")
		host := strings.ToLower(strings.ReplaceAll(base, " ", ""))
		text.WriteString("vless://u-" + host + "@" + host + ".example:443?security=tls&sni=" + host + ".example#" + strings.ReplaceAll(name, " ", "%20") + "\n")
	}
	return text.String()
}

// roundOne downloads a first list of each of three subscriptions: two at once, the third when one
// of them ended.
func roundOne() []step {
	return []step{
		due(),
		provide(subscriptionAddress(1), servers("NL 11"), false),
		provide(subscriptionAddress(2), servers("NL 21"), false),
		provide(subscriptionAddress(3), servers("NL 31"), false),
	}
}

func concat(parts ...[]step) []step { return slices.Concat(parts...) }

func transcriptScenarios() []scenario {
	ttl := func(value string) []string { return []string{`"rewrite_ttl": ` + value} }
	mixed := "\toption mixed_proxy_enabled '1'\n\toption mixed_proxy_port '2080'\n"
	lists := "\tlist remote_subnet_lists 'http://192.0.2.80/subnets.lst'\n\tlist remote_domain_lists 'http://192.0.2.80/domains.lst'\n"
	return []scenario{
		{"same-configuration", "an apply of the settings that run leaves sing-box running; the stop and the release give the router back", []step{
			writeSettings("a rule of names through a SOCKS5 proxy", plainSettings("60", "", "")),
			boot(),
			apply(),
			stop(),
			release(),
		}},
		{"restart", "an inbound that changes starts a new sing-box", []step{
			writeSettings("a rule of names through a SOCKS5 proxy", plainSettings("60", "", "")),
			boot(),
			writeSettings("the same with a mixed proxy on port 2080", plainSettings("60", "", mixed)),
			apply(),
			writeSettings("the mixed proxy off again, another TTL", plainSettings("61", "", "")),
			apply(),
			stop(),
		}},
		{"rollback", "a configuration that does not come up gives way to the previous one; when that does not either, the router is given back and the start tried again", []step{
			writeSettings("the TTL 60", plainSettings("60", "", "")),
			boot(),
			meanwhile("a start of the configuration of the TTL 61 fails", func(r *run) { r.engine.failing = ttl("61") }),
			writeSettings("the TTL 61", plainSettings("61", "", "")),
			apply(),
			meanwhile("sing-box of the TTL 62 does not answer", func(r *run) { r.engine.silent = ttl("62") }),
			writeSettings("the TTL 62", plainSettings("62", "", "")),
			apply(),
			meanwhile("the starts of the TTL 61 and 60 both fail", func(r *run) { r.engine.failing = append(ttl("61"), ttl("60")...) }),
			writeSettings("the TTL 61", plainSettings("61", "", "")),
			apply(),
			networkChange(),
			meanwhile("sing-box starts again", func(r *run) { r.engine.failing = nil }),
			networkChange(),
			stop(),
		}},
		{"unusable-settings", "settings that cannot be used change nothing; good ones again are the configuration that runs", []step{
			writeSettings("a rule of names through a SOCKS5 proxy", plainSettings("60", "", "")),
			boot(),
			writeSettings("a link that cannot be read", brokenSettings),
			apply(),
			writeSettings("the good settings again", plainSettings("60", "", "")),
			apply(),
			stop(),
		}},
		{"boot-fails", "a boot whose sing-box does not start is tried again at a change of the network; a boot of settings sing-box refuses is not", []step{
			meanwhile("a start of the TTL 60 fails", func(r *run) { r.engine.failing = ttl("60") }),
			writeSettings("the TTL 60", plainSettings("60", "", "")),
			boot(),
			networkChange(),
			meanwhile("sing-box starts", func(r *run) { r.engine.failing = nil }),
			networkChange(),
			stop(),
			meanwhile("sing-box refuses the configuration of the TTL 60", func(r *run) { r.engine.refuse[ttl("60")[0]] = os.ErrInvalid }),
			boot(),
			networkChange(),
		}},
		{"network-change", "what the router took is put back; an uplink gets its rule; a LAN of another address and a lost socket are applied again", []step{
			writeSettings("a rule with a mixed proxy", plainSettings("60", "", mixed)),
			boot(),
			meanwhile("every socket of sing-box listens", func(r *run) { r.system.listening = listeningAll(r, "") }),
			networkChange(),
			meanwhile("netifd flushed the rules, the table is gone, dnsmasq has its own DNS again, br_netfilter is on", func(r *run) {
				r.system.routingGone, r.system.firewallGone, r.system.dnsOurs, r.system.bridged = true, true, false, true
			}),
			networkChange(),
			meanwhile("the uplink wwan0 comes up", func(r *run) { r.system.uplinks = []string{"wwan0"} }),
			networkChange(),
			meanwhile("the LAN has the address 192.168.2.1", func(r *run) { r.system.lan = "192.168.2.1" }),
			networkChange(),
			meanwhile("nothing listens on the UDP socket of the transparent proxy", func(r *run) { r.system.listening = listeningAll(r, "tproxy-in udp") }),
			networkChange(),
			stop(),
		}},
		{"rule-set-loads", "a list sing-box loads fills the firewall sets; one without addresses is not read; one not loaded again is not read again", []step{
			writeSettings("a rule with a list of subnets and a list of names", plainSettings("60", "", lists)),
			boot(),
			meanwhile("the list of names has no rule of addresses", func(r *run) { r.engine.noAddresses[ruleSetTag(r, "/domains.lst")] = true }),
			loadList("/subnets.lst", "11.0.0.0/24\n"),
			loadList("/domains.lst", "one.lab.example\n"),
			loadList("/subnets.lst", "11.0.0.0/24\n11.0.2.0/24\n"),
			apply(),
			stop(),
		}},
		{"idle", "settings with nothing to route leave the router alone; a source filled starts sing-box; emptied again it is closed", []step{
			writeSettings("a rule whose source is empty", sourceSettings("")),
			boot(),
			writeSettings("the source has a SOCKS5 link", sourceSettings("socks5://u:p@203.0.113.15:1080#s5")),
			apply(),
			writeSettings("the source empty again", sourceSettings("")),
			apply(),
			stop(),
		}},
		{"hot-swap", "the servers of a subscription that change are swapped into the sing-box that runs; a list in another order changes nothing; a swap sing-box refuses starts it anew", []step{
			writeSettings("a subscription in a group of NL", subscriptionsSettings(1, nil, nil)),
			boot(),
			due(),
			provide(subscriptionAddress(1), servers("NL 1", "DE 1"), false),
			due(),
			provide(subscriptionAddress(1), servers("DE 1", "NL 1"), false),
			due(),
			provide(subscriptionAddress(1), servers("NL 1 (29 days)", "DE 1"), false),
			meanwhile("sing-box refuses to take a configuration with NL 2 while it runs", func(r *run) { r.engine.swapRefused = []string{"NL 2"} }),
			due(),
			provide(subscriptionAddress(1), servers("NL 1 (29 days)", "NL 2"), false),
			stop(),
		}},
		{"skip-downloads", "a source kept off the downloads, alone, is told to the engine though the configuration is the same (the review of 2026-11-14, finding 1)", []step{
			writeSettings("a subscription in a group of NL", subscriptionsSettings(1, nil, nil)),
			boot(),
			due(),
			provide(subscriptionAddress(1), servers("NL 1"), false),
			writeSettings("the subscription kept off the downloads", subscriptionsSettings(1, nil, map[int]string{1: "\toption skip_downloads '1'\n"})),
			apply(),
			writeSettings("the subscription for the downloads again", subscriptionsSettings(1, nil, nil)),
			apply(),
			stop(),
		}},
		{"takelist-new-lists", "three subscriptions, two downloads at once: a list taken starts the one that waited, the last one applies the lists and answers the callers", []step{
			writeSettings("three subscriptions in a group of NL", subscriptionsSettings(3, nil, nil)),
			boot(),
			due(),
			waitFor("prov3"),
			waitFor(""),
			provide(subscriptionAddress(1), servers("NL 11"), false),
			provide(subscriptionAddress(2), servers("NL 21"), false),
			provide(subscriptionAddress(3), servers("NL 31"), false),
			stop(),
		}},
		{"takelist-same-lists", "a list that has not changed starts the download that waited, and, the last of a round, applies the lists taken and answers the callers", concat(
			[]step{writeSettings("three subscriptions in a group of NL", subscriptionsSettings(3, nil, nil)), boot()},
			roundOne(),
			[]step{
				due(),
				waitFor("prov3"),
				waitFor(""),
				provide(subscriptionAddress(1), servers("NL 11"), false),
				provide(subscriptionAddress(2), servers("NL 21", "NL 22"), false),
				provide(subscriptionAddress(3), servers("NL 31"), false),
				stop(),
			})},
		{"takelist-failures", "a download that fails starts the one that waited, and, the last of a round, applies the lists taken and answers the callers", concat(
			[]step{writeSettings("three subscriptions in a group of NL", subscriptionsSettings(3, nil, nil)), boot()},
			roundOne(),
			[]step{
				due(),
				waitFor("prov3"),
				waitFor(""),
				provide(subscriptionAddress(1), "", true),
				provide(subscriptionAddress(2), servers("NL 21", "NL 22"), false),
				provide(subscriptionAddress(3), "", true),
				due(),
				provide(subscriptionAddress(1), "", true),
				stop(),
			})},
		{"takelist-request-changed", "the answer to a User-Agent the settings no longer have is not taken: the list is downloaded again, the one that waited starts first", []step{
			writeSettings("three subscriptions in a group of NL", subscriptionsSettings(3, nil, nil)),
			boot(),
			due(),
			waitFor(""),
			writeSettings("prov1 asks with another User-Agent", subscriptionsSettings(3, nil, map[int]string{1: "\toption user_agent 'Happ/1.0'\n"})),
			apply(),
			provide(subscriptionAddress(1), servers("NL 11"), false),
			provide(subscriptionAddress(2), servers("NL 21"), false),
			provide(subscriptionAddress(3), servers("NL 31"), false),
			provide(subscriptionAddress(1), servers("NL 11"), false),
			stop(),
		}},
		{"takelist-address-changed", "the answer of an address the settings no longer have is not taken: it applies the lists taken, starts the one that waited and answers the callers (those of all: none is busy)", []step{
			writeSettings("three subscriptions in a group of NL", subscriptionsSettings(3, nil, nil)),
			boot(),
			due(),
			waitFor(""),
			provide(subscriptionAddress(2), servers("NL 21"), false),
			provide(subscriptionAddress(3), servers("NL 31"), false),
			writeSettings("prov1 has another address", subscriptionsSettings(3, map[int]string{1: "https://sub1b.example/s"}, nil)),
			apply(),
			provide(subscriptionAddress(1), servers("NL 11"), false),
			due(),
			writeSettings("prov1 has its first address again", subscriptionsSettings(3, nil, nil)),
			apply(),
			provide("https://sub1b.example/s", servers("NL 12"), false),
			stop(),
		}},
		{"takelist-removed", "the answer of a subscription the settings no longer have is not taken: the callers that waited for it are answered, those of all once none is busy (prov1 too, which they asked for)", []step{
			writeSettings("three subscriptions in a group of NL", subscriptionsSettings(3, nil, nil)),
			boot(),
			due(),
			provide(subscriptionAddress(1), servers("NL 11"), false),
			waitFor("prov3"),
			waitFor(""),
			writeSettings("prov3 is gone", subscriptionsSettings(2, nil, nil)),
			apply(),
			provide(subscriptionAddress(3), servers("NL 31"), false),
			provide(subscriptionAddress(2), servers("NL 21"), false),
			provide(subscriptionAddress(1), servers("NL 11"), false),
			stop(),
		}},
		{"bittorrent-modes", "the modes of the BitTorrent detector: the firewall plan follows them, and the connections past podkop a new mode takes otherwise are ended", []step{
			writeSettings("BitTorrent past podkop", plainSettings("60", "\toption bittorrent 'bypass'\n", "")),
			boot(),
			writeSettings("BitTorrent blocked", plainSettings("60", "\toption bittorrent 'block'\n", "")),
			apply(),
			writeSettings("BitTorrent blocked for the whole LAN", plainSettings("60", "\toption bittorrent 'block'\n\toption bittorrent_block_scope 'lan'\n", "")),
			apply(),
			writeSettings("BitTorrent off", plainSettings("60", "", "")),
			apply(),
			stop(),
		}},
		{"ipv6", "IPv6 through podkop: its routing and firewall; what fails of IPv6 alone leaves IPv4 working", []step{
			meanwhile("the router has IPv6", func(r *run) { r.system.ipv6 = true }),
			writeSettings("IPv6 through podkop, devices routed whole, the NTP of the LAN left alone", plainSettings("60",
				"\toption ipv6_routing 'podkop'\n\toption exclude_ntp '1'\n", "\tlist fully_routed_ips '192.168.1.60'\n")),
			boot(),
			meanwhile("the routing of IPv6 fails", func(r *run) { r.system.routingErrorIPv6 = os.ErrPermission }),
			writeSettings("another TTL", plainSettings("61", "\toption ipv6_routing 'podkop'\n\toption exclude_ntp '1'\n", "\tlist fully_routed_ips '192.168.1.60'\n")),
			apply(),
			meanwhile("the routing of IPv6 works, the firewall of IPv6 fails", func(r *run) {
				r.system.routingErrorIPv6, r.system.firewallErrorIPv6 = nil, os.ErrPermission
			}),
			writeSettings("another TTL", plainSettings("62", "\toption ipv6_routing 'podkop'\n\toption exclude_ntp '1'\n", "\tlist fully_routed_ips '192.168.1.60'\n")),
			apply(),
			meanwhile("netifd flushed the rules", func(r *run) { r.system.routingGone = true }),
			networkChange(),
			stop(),
		}},
	}
}
