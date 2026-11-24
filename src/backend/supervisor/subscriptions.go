package supervisor

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
)

// SubscriptionState, SubscriptionPreview, GroupCheck and GroupPreview are the types of the
// socket for the subscriptions.
type (
	SubscriptionState   = api.SubscriptionState
	SubscriptionPreview = api.SubscriptionPreview
	GroupCheck          = api.GroupCheck
	GroupPreview        = api.GroupPreview
)

// How the lists of the subscriptions are downloaded: the ways to the provider start as the
// history of the address plans them (subscription.Plan); these bound the whole. A download in
// the background has 2 minutes, nobody waits for it; Load of the page a minute, as a job the
// page asks about (LuCI waits for a call 20 s); Check of a group, a call itself, what LuCI
// waits less the rest of the call. The ways are those the downloader of the lists orders
// (routes); without it, directly and then the fastest few servers the URL tests found
// (downloadProxies).
const (
	downloadBudget     = 2 * time.Minute
	downloadProxies    = 8
	loadBudget         = time.Minute
	previewBudget      = 17 * time.Second
	previewProxies     = 3
	subscriptionTick   = 15 * time.Second
	firstDownloadDelay = 10 * time.Second
	// a list that could not be downloaded is tried again sooner than at its interval; a
	// subscription with no list at all after 1, 2, 4 and 8 minutes (downloadBackoff)
	downloadRetry = 10 * time.Minute
	// how long a list downloaded for the page is used again by the page
	previewKept = 10 * time.Minute
	// at most this many downloads in the background and for the page at once: all the
	// subscriptions are due in one tick at the start, and would go through one server
	mostDownloads = 2
	mostLoads     = 2
	// the downloads that brought a list a history keeps
	historyKept = 8
	// how long UpdateSubscriptions waits for the downloads it asked: less than its callers
	// wait (api.Client.UpdateSubscriptions)
	updateWait = 170 * time.Second
)

// subscriptionRuntime is the subscriptions of the settings while the backend runs: the lists taken
// and what is known of each, the downloads in the background (downloads.go), the callers that wait
// for them, the lists the page asks for (loads.go). It is a part of the supervisor, which has one
// and hands on to it what Run does and what is asked from outside (the methods of Supervisor at
// the end of this file).
//
// Who comes here:
//   - the goroutine of Run, as for all of the supervisor: syncSubscriptions and servers when settings
//     are read (prepare), downloadDue at every subscriptionTick, takeList of what comes on downloads,
//     askDownload of what comes on requests. Only it changes what the configuration is made of, and
//     only it has the settings applied again (applyTaken).
//   - a goroutine of each download in the background (downloadDue, mostDownloads at most), which
//     hands what it came to over on downloads, and of each list downloaded for the page (startLoad,
//     mostLoads at most).
//   - the callers from outside, the page's: what they ask is answered in their goroutines;
//     updateSubscriptions hands its request over to Run on requests.
type subscriptionRuntime struct {
	options *Options
	host    subscriptionHost
	// downloads bring what a download in the background came to, requests the downloads asked
	// for from another goroutine, both to the goroutine of Run
	downloads chan downloaded
	requests  chan subscriptionRequest

	// access guards all that follows. Only the goroutine of Run changes it, except for verdicts,
	// previews, histories and jobs, which the downloads and the callers change too. Nothing is
	// downloaded or applied with access held. The lock of the status is taken within it (liveInstance,
	// in takeResult), never the other way round.
	access sync.Mutex
	// addresses are those of the subscriptions of the settings read last, by name
	addresses map[string]string
	// intervals are their update intervals
	intervals map[string]time.Duration
	// lists are the lists taken, by name: of the address the settings have
	lists map[string]*subscription.Saved
	// states are what the status tells, by name
	states map[string]*SubscriptionState
	// verdicts are the reasons of the servers built so far by their ID, whichever list
	// or preview they came in (subscription.Check)
	verdicts map[string]string
	// customs are what the settings add to the requests of each subscription (the User-Agent
	// and the extra headers), by name
	customs map[string]subscription.Custom
	// waiting are the callers of UpdateSubscriptions, by name ("*" for all)
	waiting map[string][]chan []SubscriptionState
	// previews are the lists downloaded for the page (LoadSubscription, CheckGroup), by the
	// key of their address, for a while: Check of a group takes the list Load just got. An
	// address keeps the newest only, whatever it was asked with: a list may have 4 MiB
	previews map[string]*preview
	// changed tells that a list was taken since the settings were last applied: they are
	// applied again once no download is under way, once for all the lists of a round, and
	// no download loses the sing-box it goes through to a new configuration meanwhile
	changed bool
	// histories are how the downloads of each address went, by the key of the address
	histories map[string]*history
	// jobs are the downloads for the page (Load), by their ID, for a while after they end
	jobs map[string]*loadJob
	// forced are the subscriptions asked to be downloaded now that wait for a place
	forced map[string]bool
	// failures are how many downloads of each subscription failed in a row
	failures map[string]int
}

// subscriptionHost is what the subscriptions use of the supervisor.
type subscriptionHost interface {
	log(level string, message ...any)
	// survive is deferred by the goroutines of the downloads
	survive(what string, answer func())
	// routes are the ways to a provider, liveInstance the sing-box that runs; from any goroutine
	routes(proxies int, first string, host string) ([]subscription.Route, Instance, bool)
	liveInstance() Instance
	// Running and apply are for the goroutine of Run: with a state up the settings are applied again
	// with the lists taken
	Running() bool
	apply(force bool) Result
}

func newSubscriptionRuntime(options *Options, host subscriptionHost) *subscriptionRuntime {
	return &subscriptionRuntime{options: options, host: host, downloads: make(chan downloaded), requests: make(chan subscriptionRequest)}
}

func (t *subscriptionRuntime) log(level string, message ...any) {
	t.host.log(level, message...)
}

// preview is a list downloaded for the page, and the key of the request it was asked with
// (subscription.Custom.Key): a list asked with one User-Agent is not the answer to another.
type preview struct {
	list    *subscription.Saved
	request string
}

// downloaded is what a download in the background came to.
type downloaded struct {
	name    string
	address string
	// request is the key of the User-Agent and the headers it was asked with: an answer to
	// those the settings no longer have is not taken
	request string
	list    *subscription.Saved
	tries   []subscription.Try
	err     error
	// through is the instance whose outbounds the download went through; none directly
	through Instance
	// planned is when the next download was due before one was asked for now (forced): a
	// download asked for by hand that fails leaves that time as it was
	planned *time.Time
}

type subscriptionRequest struct {
	name  string
	reply chan []SubscriptionState
}

func (t *subscriptionRuntime) store() subscription.Store {
	return subscription.Store{Dir: t.options.SubscriptionDir}
}

// syncSubscriptions takes the subscriptions of settings that were read: the list of each is
// the one kept for its address, a new one is downloaded soon after, and what the settings
// no longer have is forgotten, its file included. Another User-Agent or other headers of the
// same address keep the list in use (it is of the same account) and download it again soon. tell
// logs what the settings add to a request and cannot be sent: once an apply, not again for a
// configuration built again after a swap.
func (t *subscriptionRuntime) syncSubscriptions(settings *model.Config, tell bool) {
	t.access.Lock()
	defer t.access.Unlock()
	if t.lists == nil {
		t.addresses, t.intervals, t.lists = make(map[string]string), make(map[string]time.Duration), make(map[string]*subscription.Saved)
		t.states, t.verdicts, t.waiting = make(map[string]*SubscriptionState), make(map[string]string), make(map[string][]chan []SubscriptionState)
	}
	if t.customs == nil {
		t.customs = make(map[string]subscription.Custom)
	}
	var names []string
	now := time.Now()
	for _, item := range settings.Sources {
		if item.Type != "subscription" || item.URL == "" {
			continue
		}
		names = append(names, item.Name)
		custom, problems := subscription.ParseRequest(item.UserAgentPreset, item.UserAgent, item.Headers, t.options.SingBoxVersion)
		if tell {
			for _, problem := range problems {
				line := problem.Describe()
				if problem.Line == 0 {
					line += ": podkop/" + t.options.Version + " is sent"
				}
				t.log("warn", "subscription ", item.Name, ": ", line)
			}
		}
		before := t.interval(item.Name)
		t.intervals[item.Name] = parseInterval(item.UpdateInterval)
		if t.addresses[item.Name] == item.URL && t.states[item.Name] != nil {
			t.reschedule(item.Name, before)
			state := t.states[item.Name]
			if t.customs[item.Name].Key() != custom.Key() {
				// the list in use stays: it is a list of the same account (a placeholder is never
				// taken). A download under way asked the old way: its answer is not taken
				// (takeList), and the list is downloaded again when it ends
				delete(t.failures, item.Name)
				if state.Busy {
					t.log("info", "subscription ", item.Name, ": the User-Agent or the headers changed during a download: its answer is not taken, ",
						"the list is downloaded again as soon as it ends, the one in use stays until then")
				} else {
					next := now.Add(firstDownloadDelay)
					state.Next = &next
					// the download waits for the first tick of the scheduler after the delay
					t.log("info", "subscription ", item.Name, ": the User-Agent or the headers changed: the list is downloaded again in ",
						int(firstDownloadDelay/time.Second), " to ", int((firstDownloadDelay+subscriptionTick)/time.Second),
						" s, the one in use stays until then")
				}
			}
			t.customs[item.Name] = custom
			state.Agent, state.Preset, state.Headers, state.Problems = custom.UserAgent, custom.Preset, custom.Names(), problemsOf(problems)
			continue
		}
		t.addresses[item.Name] = item.URL
		t.customs[item.Name] = custom
		delete(t.lists, item.Name)
		delete(t.failures, item.Name)
		next := now.Add(firstDownloadDelay)
		state := &SubscriptionState{Name: item.Name, Next: &next, Agent: custom.UserAgent, Preset: custom.Preset, Headers: custom.Names(), Problems: problemsOf(problems)}
		t.states[item.Name] = state
		var saved *subscription.Saved
		found := false
		if t.options.SubscriptionDir != "" {
			saved, found = t.store().Load(item.Name, item.URL)
		}
		if kept := t.previews[subscription.AddressKey(item.URL)]; !found && kept != nil && kept.request == custom.Key() && now.Sub(kept.list.Changed) < previewKept {
			// the list the page got for the address a while ago (Load, Check of a group), asked
			// as the settings ask it: a subscription just added has its servers at the apply that
			// adds it; it is downloaded soon all the same, as the provider may have changed the
			// list since
			saved, found = kept.list, true
			checked := kept.list.Changed
			state.Checked = &checked
			if t.options.SubscriptionDir != "" {
				if err := t.store().Save(item.Name, kept.list); err != nil {
					t.log("warn", "subscription ", item.Name, ": ", err)
				}
			}
		}
		if found {
			t.lists[item.Name] = saved
			for id, reason := range saved.Verdicts() {
				t.verdicts[id] = reason
			}
			state.Servers, state.Usable = len(saved.Servers), usable(saved.Servers)
			state.Format, state.Configs = saved.Format, saved.Configs
			changed := saved.Changed
			state.Changed, state.Route = &changed, saved.Route
			state.Provider = subscription.ReadInfo(saved.Info)
		}
	}
	for name := range t.addresses {
		if !slices.Contains(names, name) {
			delete(t.addresses, name)
			delete(t.intervals, name)
			delete(t.lists, name)
			delete(t.states, name)
			delete(t.forced, name)
			delete(t.failures, name)
			delete(t.customs, name)
		}
	}
	if t.options.SubscriptionDir != "" {
		t.store().Keep(names)
	}
}

// problemsOf are the problems of a request as the state tells them.
func problemsOf(problems []subscription.Problem) []api.RequestProblem {
	var told []api.RequestProblem
	for _, problem := range problems {
		told = append(told, api.RequestProblem{Line: problem.Line, Name: problem.Name, Code: problem.Code, Args: problem.Args, Text: problem.Text})
	}
	return told
}

// servers are what plan.Options.Servers takes: the servers of each list sing-box can use.
func (t *subscriptionRuntime) servers() map[string][]plan.SubscriptionServer {
	t.access.Lock()
	defer t.access.Unlock()
	result := make(map[string][]plan.SubscriptionServer)
	for name, list := range t.lists {
		for _, server := range list.Servers {
			if server.Usable() {
				result[name] = append(result[name], plan.SubscriptionServer{Name: server.Name, Link: server.Link})
			}
		}
	}
	return result
}

func usable(servers []subscription.Server) int {
	count := 0
	for index := range servers {
		if servers[index].Usable() {
			count++
		}
	}
	return count
}

// interval is how often the list of a subscription is downloaded again: as the settings say,
// or for auto as the provider asks in its header profile-update-interval (hours), a day when
// it asks nothing. The caller holds access.
func (t *subscriptionRuntime) interval(name string) time.Duration {
	if interval := t.intervals[name]; interval > 0 {
		return interval
	}
	if state := t.states[name]; state != nil && state.Provider != nil && state.Provider.UpdateHours > 0 {
		return time.Duration(state.Provider.UpdateHours) * time.Hour
	}
	return 24 * time.Hour
}

// reschedule counts the next download from the last one by the interval of the settings when
// that changed: the time set by the old interval could be a day away. A download under way
// sets the time when it ends, and a retry after a failure is not put off. The caller holds
// access.
func (t *subscriptionRuntime) reschedule(name string, before time.Duration) {
	state := t.states[name]
	interval := t.interval(name)
	if interval == before || state.Busy || state.Attempted == nil || state.Next == nil {
		return
	}
	next := state.Attempted.Add(interval)
	if t.failures[name] > 0 && next.After(*state.Next) {
		return
	}
	state.Next = &next
}

// parseInterval reads an update interval of the settings: a number of minutes, hours or
// days (20m, 12h, 1d), or auto, which is 0 (see interval). What cannot be read is 12 hours;
// less than ten minutes is ten.
func parseInterval(text string) time.Duration {
	text = strings.TrimSpace(text)
	if text == "auto" {
		return 0
	}
	units := map[byte]time.Duration{'m': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour}
	if len(text) < 2 || units[text[len(text)-1]] == 0 {
		return 12 * time.Hour
	}
	number, err := strconv.Atoi(text[:len(text)-1])
	if err != nil || number <= 0 {
		return 12 * time.Hour
	}
	return max(time.Duration(number)*units[text[len(text)-1]], 10*time.Minute)
}

// subscriptionStates is what the status tells of the subscriptions, in the order of their
// names.
func (t *subscriptionRuntime) subscriptionStates() []SubscriptionState {
	t.access.Lock()
	defer t.access.Unlock()
	states := []SubscriptionState{}
	now := time.Now()
	for _, state := range t.states {
		told := *state
		told.Now = &now
		states = append(states, told)
	}
	slices.SortFunc(states, func(left SubscriptionState, right SubscriptionState) int {
		return strings.Compare(left.Name, right.Name)
	})
	return states
}

// The subscriptions as the supervisor has them: what Run and prepare do, then what is asked from
// outside the goroutine of Run (api.Backend).

func (s *Supervisor) syncSubscriptions(settings *model.Config, tell bool) {
	s.subscriptions.syncSubscriptions(settings, tell)
}

func (s *Supervisor) servers() map[string][]plan.SubscriptionServer {
	return s.subscriptions.servers()
}

func (s *Supervisor) downloadDue(now time.Time, force string) {
	s.subscriptions.downloadDue(now, force)
}

func (s *Supervisor) takeList(result downloaded) {
	s.subscriptions.takeList(result)
}

func (s *Supervisor) askDownload(request subscriptionRequest) {
	s.subscriptions.askDownload(request)
}

func (s *Supervisor) subscriptionStates() []SubscriptionState {
	return s.subscriptions.subscriptionStates()
}

// Subscriptions tells what is known of each subscription. It is for callers outside the
// goroutine of Run.
func (s *Supervisor) Subscriptions(context.Context) []SubscriptionState {
	return s.subscriptionStates()
}

// UpdateSubscriptions downloads the list of a subscription now (of all of them with no name)
// and waits for what it came to. It is for callers outside the goroutine of Run.
func (s *Supervisor) UpdateSubscriptions(ctx context.Context, name string) []SubscriptionState {
	return s.subscriptions.updateSubscriptions(ctx, name)
}

// LoadSubscription downloads a list to be shown, asked with the request of the form of the page;
// nothing is taken. It is for callers outside the goroutine of Run.
func (s *Supervisor) LoadSubscription(ctx context.Context, address string, request api.ListRequest) SubscriptionPreview {
	return s.subscriptions.loadSubscription(ctx, address, request)
}

// CheckGroup tells which servers a group would choose. It is for callers outside the goroutine of
// Run.
func (s *Supervisor) CheckGroup(ctx context.Context, check GroupCheck) GroupPreview {
	return s.subscriptions.checkGroup(ctx, check)
}

// StartLoad starts a download of a list for the page, which asks how it goes (LoadState). It is
// for callers outside the goroutine of Run.
func (s *Supervisor) StartLoad(ctx context.Context, address string, request api.ListRequest) LoadJob {
	return s.subscriptions.startLoad(ctx, address, request)
}

// LoadState tells how a download for the page goes. It is for callers outside the goroutine
// of Run.
func (s *Supervisor) LoadState(ctx context.Context, id string) (LoadJob, bool) {
	return s.subscriptions.loadState(ctx, id)
}

// CancelLoad stops a download for the page. It is for callers outside the goroutine of Run.
func (s *Supervisor) CancelLoad(ctx context.Context, id string) (LoadJob, bool) {
	return s.subscriptions.cancelLoad(ctx, id)
}
