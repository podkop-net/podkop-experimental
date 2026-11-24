package supervisor

import (
	"context"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
	E "github.com/sagernet/sing/common/exceptions"
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

// downloadBackoff is when a subscription with no list is tried again after its failures.
func downloadBackoff(failures int) time.Duration {
	failures = min(max(failures, 1), 5)
	return min(time.Minute<<(failures-1), downloadRetry)
}

// subscriptions is what the supervisor knows of the subscriptions of the settings. The
// goroutine of Run changes it; the previews of other goroutines read it under access.
type subscriptions struct {
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
	// waiting are the callers of UpdateSubscriptions, by name ("" for all)
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

func (s *Supervisor) store() subscription.Store {
	return subscription.Store{Dir: s.options.SubscriptionDir}
}

// syncSubscriptions takes the subscriptions of settings that were read: the list of each is
// the one kept for its address, a new one is downloaded soon after, and what the settings
// no longer have is forgotten, its file included. Another User-Agent or other headers of the
// same address keep the list in use (it is of the same account) and download it again soon. tell
// logs what the settings add to a request and cannot be sent: once an apply, not again for a
// configuration built again after a swap.
func (s *Supervisor) syncSubscriptions(settings *model.Config, tell bool) {
	t := &s.subscriptions
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
		custom, problems := subscription.ParseRequest(item.UserAgentPreset, item.UserAgent, item.Headers, s.options.SingBoxVersion)
		if tell {
			for _, problem := range problems {
				line := problem.Describe()
				if problem.Line == 0 {
					line += ": podkop/" + s.options.Version + " is sent"
				}
				s.log("warn", "subscription ", item.Name, ": ", line)
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
				if !state.Busy {
					next := now.Add(firstDownloadDelay)
					state.Next = &next
				}
				// the download waits for the first tick of the scheduler after the delay
				s.log("info", "subscription ", item.Name, ": the User-Agent or the headers changed: the list is downloaded again in ",
					int(firstDownloadDelay/time.Second), " to ", int((firstDownloadDelay+subscriptionTick)/time.Second),
					" s, the one in use stays until then")
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
		if s.options.SubscriptionDir != "" {
			saved, found = s.store().Load(item.Name, item.URL)
		}
		if kept := t.previews[subscription.AddressKey(item.URL)]; !found && kept != nil && kept.request == custom.Key() && now.Sub(kept.list.Changed) < previewKept {
			// the list the page got for the address a while ago (Load, Check of a group), asked
			// as the settings ask it: a subscription just added has its servers at the apply that
			// adds it; it is downloaded soon all the same, as the provider may have changed the
			// list since
			saved, found = kept.list, true
			checked := kept.list.Changed
			state.Checked = &checked
			if s.options.SubscriptionDir != "" {
				if err := s.store().Save(item.Name, kept.list); err != nil {
					s.log("warn", "subscription ", item.Name, ": ", err)
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
	if s.options.SubscriptionDir != "" {
		s.store().Keep(names)
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
func (s *Supervisor) servers() map[string][]plan.SubscriptionServer {
	t := &s.subscriptions
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
func (t *subscriptions) interval(name string) time.Duration {
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
func (t *subscriptions) reschedule(name string, before time.Duration) {
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

// routes are the ways to a provider at host, in the order they are tried. While sing-box runs
// with the HTTP client of the lists (http_client.outbounds, engine r26), its downloader orders
// them as it orders the ways of the lists: directly and the servers of the rules that download
// the lists, by what the downloads from the host found (downloadWays); together then tells that
// the first way failed for the host the last time. Else directly, then through the servers of
// the configuration that runs, the fastest first as the URL tests found them, those not tested
// after, at most proxies of them. Directly is through direct-out of sing-box while it runs: the
// resolver of the system answers the names of the lists from FakeIP then.
func (s *Supervisor) routes(proxies int, first string, host string) ([]subscription.Route, Instance, bool) {
	s.statusAccess.Lock()
	live, links := s.live, s.liveLinks
	s.statusAccess.Unlock()
	if live == nil {
		return []subscription.Route{subscription.DirectRoute()}, nil, false
	}
	through := func(tag string) func(ctx context.Context, network string, address string) (net.Conn, error) {
		return func(ctx context.Context, network string, address string) (net.Conn, error) {
			return live.Dial(ctx, tag, address)
		}
	}
	// a way is named as the page names the outbound: the name of the server of a subscription,
	// the section and number of a link
	var tags []string
	names := make(map[string]string)
	for _, link := range links {
		if !slices.Contains(tags, link.Tag) {
			tags = append(tags, link.Tag)
			names[link.Tag] = link.Name
		}
	}
	if ways, together := live.DownloadWays(plan.ListsHTTPClient, host); len(ways) > 0 {
		routes := make([]subscription.Route, 0, len(ways))
		for _, tag := range ways {
			route := subscription.Route{Name: names[tag], Tag: tag, Dial: through(tag)}
			switch {
			case tag == plan.DirectOutbound:
				route.Name, route.Direct = "direct", true
			case route.Name == "":
				route.Name = tag
			}
			routes = append(routes, route)
		}
		return routes, live, together
	}
	routes := []subscription.Route{{Name: "direct", Tag: plan.DirectOutbound, Direct: true, Dial: through(plan.DirectOutbound)}}
	delays := s.options.Engine.Delays(tags)
	slices.SortStableFunc(tags, func(left string, right string) int {
		// the way of the last download first: it brought the list then
		switch {
		case names[left] == first && names[right] != first:
			return -1
		case names[right] == first && names[left] != first:
			return 1
		}
		leftDelay, leftTested := delays[left]
		rightDelay, rightTested := delays[right]
		switch {
		case leftTested && rightTested:
			return int(leftDelay) - int(rightDelay)
		case leftTested:
			return -1
		case rightTested:
			return 1
		}
		return 0
	})
	for _, tag := range tags[:min(len(tags), proxies)] {
		routes = append(routes, subscription.Route{Name: names[tag], Tag: tag, Dial: through(tag)})
	}
	return routes, live, false
}

// recordTries tells the downloader of the lists what the tries of a download from host came to:
// a way that brought the list, and one that failed for a fault of its own (not one another way
// made needless, nor one the end of the download's context cut — a search that found its mask,
// a page that gave up, a budget spent —, nor an answer of the provider itself).
func recordTries(live Instance, host string, routes []subscription.Route, tries []subscription.Try) {
	if live == nil {
		return
	}
	tags := make(map[string]string, len(routes))
	for _, route := range routes {
		tags[route.Name] = route.Tag
	}
	for _, item := range tries {
		tag := tags[item.Route]
		if tag == "" {
			continue
		}
		switch {
		case item.Phase == subscription.PhaseDone:
			live.RecordDownload(plan.ListsHTTPClient, host, tag, nil, item.Took, item.Bytes)
		case item.Phase == subscription.PhaseFailed && item.Failure != nil && !item.Failure.Final() && item.Failure.Code != "canceled" && !item.Cut:
			live.RecordDownload(plan.ListsHTTPClient, host, tag, item.Failure, item.Took, item.Bytes)
		}
	}
}

// hostOf is the host of an address, "" for an address that has none.
func hostOf(address string) string {
	parsed, err := url.Parse(address)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// secureAddress tells an address of HTTPS.
func secureAddress(address string) bool {
	parsed, err := url.Parse(address)
	return err == nil && parsed.Scheme == "https"
}

// fetch downloads and reads a list, asked with what the settings or the page add to the request:
// the servers with their reasons, those built before taking the verdicts they had. The ways start
// as the history of the address plans them, and what the download came to goes into it: the
// history is of the way to the address, whatever it was asked with. It tells the instance it went
// through and the tries.
func (s *Supervisor) fetch(ctx context.Context, address string, custom subscription.Custom, proxies int, report func([]subscription.Try)) (*subscription.Saved, Instance, []subscription.Try, error) {
	header := s.options.Device.Headers(s.options.Version, custom)
	download := s.options.Download
	if download == nil {
		download = subscription.Download
	}
	key := subscription.AddressKey(address)
	way, first := s.planOf(key)
	host := hostOf(address)
	routes, through, together := s.routes(proxies, first, host)
	way.Together = way.Together || together
	// a web page to the User-Agent of another app over TLS is the provider's answer to it: two
	// ways at most get it, and none is held at fault for it
	way.PageIsAnswer = custom.UserAgent != "" && secureAddress(address)
	answer, tries, err := download(ctx, address, header, routes, way, report)
	s.remember(key, tries)
	recordTries(through, host, routes, tries)
	if err != nil {
		return nil, through, tries, subscription.ForAgent(err, custom, address)
	}
	read, err := subscription.ParseList(ctx, answer.Body, subscription.Codec{Decode: engine.DecodeLink, Normalize: engine.NormalizeOutbound})
	if err != nil {
		return nil, through, tries, subscription.ForAgent(err, custom, address)
	}
	servers := read.Servers
	t := &s.subscriptions
	known := func() map[string]string {
		t.access.Lock()
		defer t.access.Unlock()
		known := make(map[string]string, len(t.verdicts))
		for id, reason := range t.verdicts {
			known[id] = reason
		}
		return known
	}()
	verdicts := s.options.Engine.CheckServers(servers, known)
	func() {
		t.access.Lock()
		defer t.access.Unlock()
		if t.verdicts == nil || len(t.verdicts) > 10000 {
			t.verdicts = make(map[string]string)
		}
		for id, reason := range verdicts {
			t.verdicts[id] = reason
		}
	}()
	list := subscription.SavedList(read)
	list.Address, list.Changed, list.Route, list.Info = key, time.Now().UTC(), answer.Route, answer.Info()
	return list, through, tries, nil
}

// downloadDue starts the downloads that are due, at most mostDownloads at once, each in a
// goroutine of its own; what they come to comes back to the goroutine of Run (takeList),
// which starts those that waited for a place. A subscription asked to be downloaded now
// waits for its place too.
func (s *Supervisor) downloadDue(now time.Time, force string) {
	t := &s.subscriptions
	t.access.Lock()
	defer t.access.Unlock()
	if t.forced == nil {
		t.forced = make(map[string]bool)
	}
	busy := 0
	var names []string
	for name, state := range t.states {
		if (force == name || force == "*") && !state.Busy {
			t.forced[name] = true
		}
		if state.Busy {
			busy++
		}
		names = append(names, name)
	}
	// the asked ones first, then the longest due
	slices.SortFunc(names, func(left string, right string) int {
		switch {
		case t.forced[left] != t.forced[right] && t.forced[left]:
			return -1
		case t.forced[left] != t.forced[right]:
			return 1
		}
		leftNext, rightNext := t.states[left].Next, t.states[right].Next
		if leftNext != nil && rightNext != nil {
			return leftNext.Compare(*rightNext)
		}
		return strings.Compare(left, right)
	})
	for _, name := range names {
		state := t.states[name]
		due := state.Next != nil && !now.Before(*state.Next)
		if state.Busy || !(due || t.forced[name]) || busy >= mostDownloads {
			continue
		}
		busy++
		var planned *time.Time
		if t.forced[name] && !due && state.Next != nil {
			at := *state.Next
			planned = &at
		}
		delete(t.forced, name)
		state.Busy = true
		address, custom := t.addresses[name], t.customs[name]
		// the fault carries the request too: an answer to the request of now is taken as a
		// failure, with its backoff, not as one of an old request
		request := custom.Key()
		go func() {
			defer s.survive("the download of subscription "+name, func() {
				s.downloads <- downloaded{name: name, address: address, request: request, err: &subscription.Failure{Code: "fault", Text: "the download stopped on a fault of podkop: see the log"}}
			})
			ctx, cancel := context.WithTimeout(context.Background(), downloadBudget)
			defer cancel()
			list, through, tries, err := s.fetch(ctx, address, custom, downloadProxies, nil)
			s.downloads <- downloaded{name: name, address: address, request: request, list: list, tries: tries, err: err, through: through, planned: planned}
		}()
	}
}

// takeList takes a list downloaded in the background: a list with other servers is kept, and
// the settings are applied again with it once no other download is under way; one that has
// the same servers, under other names or in another order, is not, and nothing changes, unless
// the new names change what a group chooses (a server the provider calls DE now, not NL).
// Whatever the download came to, the downloads that waited for a place start, the lists of a
// round that ended are applied, and the callers that waited for it are answered when it was
// taken (takeResult).
func (s *Supervisor) takeList(result downloaded) {
	tell, answer := s.takeResult(result)
	// the log and the file of the list after the lock: the previews of other goroutines wait
	// on it
	if tell != nil {
		tell()
	}
	s.downloadDue(time.Now(), "")
	s.applyTaken()
	if answer {
		s.answerWaiting(result.name)
	}
}

// takeResult is what takeList does under the lock of the subscriptions. tell is what is logged
// and written of it after the lock, none when nothing is; answer tells that the callers waiting
// for the subscription are answered.
func (s *Supervisor) takeResult(result downloaded) (tell func(), answer bool) {
	t := &s.subscriptions
	t.access.Lock()
	defer t.access.Unlock()
	state := t.states[result.name]
	if state == nil || t.addresses[result.name] != result.address {
		// the settings changed meanwhile: the list of another address is not taken
		return nil, false
	}
	state.Busy = false
	now := time.Now()
	if t.customs[result.name].Key() != result.request {
		// the User-Agent or the headers changed meanwhile: the answer to the old ones is not
		// taken, and the list is downloaded again with the new ones now
		state.Next = &now
		return nil, false
	}
	if result.err == nil {
		// what the provider tells in this answer counts at once: under auto the next download
		// is as often as it asks now, the first list of a subscription included
		state.Provider = subscription.ReadInfo(result.list.Info)
	}
	next := now.Add(t.interval(result.name))
	state.Attempted, state.Attempts = &now, attempts(result.tries)
	if result.err != nil {
		replaced := result.through != nil && result.through != s.liveInstance()
		if result.planned != nil && result.planned.After(now) && t.lists[result.name] != nil && !replaced {
			// asked for by hand and failed, with a list in use: the download that was planned
			// stays when it was, and the failure does not count towards the backoff
			next = *result.planned
		} else {
			if t.failures == nil {
				t.failures = make(map[string]int)
			}
			t.failures[result.name]++
			next = now.Add(min(downloadRetry, t.interval(result.name)))
			if t.lists[result.name] == nil {
				// no list at all: the groups of the subscription go by their rule for no server
				next = now.Add(min(downloadBackoff(t.failures[result.name]), t.interval(result.name)))
			}
			if replaced {
				// the sing-box it went through was replaced meanwhile: again at the next tick
				next = now
			}
		}
		state.Next = &next
		// the same failure again is told at the info level, shortly: the first of a run was
		// told at the warning level with its reasons
		repeated := state.Error != ""
		previousCode := state.ErrorCode
		state.Error, state.ErrorCode, state.ErrorArgs = failureOf(result.err)
		repeated = repeated && state.ErrorCode == previousCode
		failures := t.failures[result.name]
		code, text := state.ErrorCode, state.Error
		return func() {
			if repeated {
				again := "again"
				if failures > 1 {
					again = strconv.Itoa(failures) + " times in a row"
				}
				s.log("info", "subscription ", result.name, ": not downloaded ", again, " (", code, "), the next try at ", next.Format(time.TimeOnly))
			} else {
				s.log("warn", "subscription ", result.name, ": ", text)
			}
		}, true
	}
	failed := t.failures[result.name]
	delete(t.failures, result.name)
	state.Error, state.ErrorCode, state.ErrorArgs = "", "", nil
	state.Next, state.Checked, state.Route, state.Took = &next, &now, result.list.Route, tookOf(result.tries)
	way := waysLine(result.tries)
	if failed > 0 {
		way += "; downloaded again after " + strconv.Itoa(failed) + " failed " + plural(failed, "try", "tries")
	}
	custom := t.customs[result.name]
	if asked := subscription.AskedAs(custom.Preset, custom.UserAgent); asked != "" {
		way += "; " + asked
	}
	old := t.lists[result.name]
	formatLine := formatLine(old, result.list)
	state.Format, state.Configs = result.list.Format, result.list.Configs
	if old != nil && subscription.SameList(old.Servers, result.list.Servers) {
		// the traffic and the end the provider tells change with every list: kept in memory,
		// the file is written only when the servers or their names change, or the format they
		// came in (the same servers as links of the provider or of podkop: the configuration
		// stays as it is)
		old.Info = result.list.Info
		reformatted := old.Format != result.list.Format || old.Configs != result.list.Configs
		if reformatted {
			// the servers did not change: when they did is when they last did
			result.list.Info, result.list.Changed = old.Info, old.Changed
			t.lists[result.name] = result.list
		}
		return func() {
			for _, line := range formatLine {
				s.log("info", "subscription ", result.name, ": ", line)
			}
			s.log("info", "subscription ", result.name, ": the list has not changed (", way, ")")
			if reformatted {
				s.saveList(result.name, result.list)
			}
		}, true
	}
	t.lists[result.name] = result.list
	changed := result.list.Changed
	state.Changed, state.Servers, state.Usable = &changed, len(result.list.Servers), usable(result.list.Servers)
	state.Changes = nil
	if old != nil {
		changes := subscription.Compare(old.Servers, result.list.Servers, engine.DecodeLink)
		state.Changes = &changes
	}
	t.changed = true
	changes, count, canUse := state.Changes, state.Servers, state.Usable
	return func() {
		for _, line := range formatLine {
			s.log("info", "subscription ", result.name, ": ", line)
		}
		if changes != nil {
			s.log("info", "subscription ", result.name, ": ", changesLine(changes), "; ", count, " servers, ", canUse, " can be used (", way, ")")
		} else {
			s.log("info", "subscription ", result.name, ": ", count, " servers, ", canUse, " can be used (", way, ")")
		}
		s.saveList(result.name, result.list)
	}, true
}

// saveList keeps the list taken of a subscription on flash, when there is a directory for them.
func (s *Supervisor) saveList(name string, list *subscription.Saved) {
	if s.options.SubscriptionDir == "" {
		return
	}
	if err := s.store().Save(name, list); err != nil {
		s.log("warn", "subscription ", name, ": ", err)
	}
}

// formatLine tells the log what a list came as, when it is a configuration (its counts, never a
// value), and that the format changed since the list before: "Xray JSON of 11 configurations: 31
// server outbounds, 12 servers taken; their routing, DNS and balancers are left out", "the
// provider now sends Xray JSON instead of a list of links".
func formatLine(old *subscription.Saved, fresh *subscription.Saved) []string {
	var lines []string
	if old != nil && old.Format != fresh.Format {
		lines = append(lines, "the provider now sends "+subscription.FormatText(fresh.Format)+" instead of "+subscription.FormatText(old.Format))
	}
	taken := strconv.Itoa(fresh.Outbounds()) + " server " + plural(fresh.Outbounds(), "outbound", "outbounds") + ", " +
		strconv.Itoa(len(fresh.Servers)) + " " + plural(len(fresh.Servers), "server", "servers") + " taken"
	switch fresh.Format {
	case subscription.FormatXray:
		lines = append(lines, "Xray JSON of "+strconv.Itoa(fresh.Configs)+" "+plural(fresh.Configs, "configuration", "configurations")+": "+taken+
			"; their routing, DNS and balancers are left out")
	case subscription.FormatSingBox:
		lines = append(lines, "sing-box JSON: "+taken+"; its groups, routing and DNS are left out")
	}
	return lines
}

// changesLine tells how a list differs from the one before, for the log: "renamed 2, changed
// 1 (tls.reality.short_id), removed 0, added 3".
func changesLine(changes *subscription.ListChanges) string {
	line := "renamed " + strconv.Itoa(changes.Renamed) + ", changed " + strconv.Itoa(changes.Changed)
	if len(changes.Fields) > 0 {
		line += " (" + strings.Join(changes.Fields, ", ") + ")"
	}
	return line + ", removed " + strconv.Itoa(changes.Removed) + ", added " + strconv.Itoa(changes.Added)
}

// waysLine tells how a list came for the log: the way and the time, and why the ways tried
// before or beside it did not bring it, each reason once ("through main-2 in 6.4 s; 2 other ways
// failed: the transfer stopped at 16 KB ×2").
func waysLine(tries []subscription.Try) string {
	var won string
	failed := 0
	for _, item := range tries {
		switch {
		case item.Phase == subscription.PhaseDone:
			won = item.Route + " in " + strconv.FormatFloat(item.Took.Seconds(), 'f', 1, 64) + " s"
			if item.Route != "direct" {
				won = "through " + won
			}
		case item.Failure != nil && item.Failure.Code != "canceled":
			failed++
		}
	}
	if failed == 0 {
		return won
	}
	return won + "; " + strconv.Itoa(failed) + " other " + plural(failed, "way", "ways") + " failed: " + subscription.Reasons(tries)
}

// plural is the word for a number.
func plural(count int, one string, many string) string {
	if count == 1 {
		return one
	}
	return many
}

// applyTaken applies the settings again with the lists taken, once no download is under way.
func (s *Supervisor) applyTaken() {
	t := &s.subscriptions
	t.access.Lock()
	busy := false
	for _, state := range t.states {
		busy = busy || state.Busy
	}
	due := t.changed && !busy
	if due {
		t.changed = false
	}
	t.access.Unlock()
	if due && s.current != nil {
		s.apply(false)
	}
}

// liveInstance is the instance that runs now.
func (s *Supervisor) liveInstance() Instance {
	s.statusAccess.Lock()
	defer s.statusAccess.Unlock()
	return s.live
}

// subscriptionStates is what the status tells of the subscriptions, in the order of their
// names.
func (s *Supervisor) subscriptionStates() []SubscriptionState {
	t := &s.subscriptions
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

// answerWaiting answers the callers of UpdateSubscriptions waiting for a subscription, and
// those waiting for all once none is busy.
func (s *Supervisor) answerWaiting(name string) {
	states := s.subscriptionStates()
	t := &s.subscriptions
	t.access.Lock()
	defer t.access.Unlock()
	var replies []chan []SubscriptionState
	replies, t.waiting[name] = t.waiting[name], nil
	busy := false
	for _, state := range t.states {
		busy = busy || state.Busy
	}
	if !busy {
		replies = append(replies, t.waiting["*"]...)
		t.waiting["*"] = nil
	}
	for _, reply := range replies {
		reply <- states
	}
}

// Subscriptions tells what is known of each subscription. It is for callers outside the
// goroutine of Run.
func (s *Supervisor) Subscriptions(context.Context) []SubscriptionState {
	return s.subscriptionStates()
}

// UpdateSubscriptions downloads the list of a subscription now (of all of them with no name)
// and waits for what it came to. It is for callers outside the goroutine of Run.
func (s *Supervisor) UpdateSubscriptions(ctx context.Context, name string) []SubscriptionState {
	// the caller waits 3 minutes; two rounds of downloads of a provider that never answers
	// take longer: the states are told before, those under way still busy
	ctx, cancel := context.WithTimeout(ctx, updateWait)
	defer cancel()
	reply := make(chan []SubscriptionState, 1)
	// the request waits for the goroutine of Run as long as a caller that waits would, even
	// when this one does not (the page, which asks for the states at once): Run applies
	// settings and replaces sing-box in its own goroutine, which may take longer than the
	// caller is told to wait, and a download asked for is still made once Run takes it
	taken := make(chan struct{})
	go func() {
		timer := time.NewTimer(updateWait)
		defer timer.Stop()
		select {
		case s.subscriptionRequests <- subscriptionRequest{name: name, reply: reply}:
			close(taken)
		case <-timer.C:
		}
	}()
	select {
	case <-taken:
	case <-ctx.Done():
		return s.subscriptionStates()
	}
	select {
	case states := <-reply:
		return states
	case <-ctx.Done():
		return s.subscriptionStates()
	}
}

// askDownload is UpdateSubscriptions in the goroutine of Run.
func (s *Supervisor) askDownload(request subscriptionRequest) {
	key := request.name
	if key == "" {
		key = "*"
	}
	t := &s.subscriptions
	t.access.Lock()
	known := key == "*" || t.states[key] != nil
	if known {
		t.waiting[key] = append(t.waiting[key], request.reply)
	}
	empty := len(t.states) == 0
	t.access.Unlock()
	if !known || empty {
		request.reply <- s.subscriptionStates()
		return
	}
	s.downloadDue(time.Now(), key)
}

// LoadSubscription downloads a list to be shown: the page asks with the address, the User-Agent
// and the headers of its form, saved or not. Nothing is taken. It is for callers outside the
// goroutine of Run.
func (s *Supervisor) LoadSubscription(ctx context.Context, address string, request api.ListRequest) SubscriptionPreview {
	custom, problems := subscription.ParseRequest(request.Preset, request.UserAgent, request.Headers, s.options.SingBoxVersion)
	if len(problems) > 0 {
		return refusedRequest(problems[0])
	}
	ctx, cancel := context.WithTimeout(ctx, loadBudget)
	defer cancel()
	return s.loadPreview(ctx, address, custom, nil)
}

// CheckGroup tells which servers a group would choose. A subscription's list is the one
// taken when the form has the address and the request the settings that run have, else the one
// Load got for the address and the request of the form a while ago, else one downloaded for
// them; none of these is taken. It is for callers outside the goroutine of Run.
func (s *Supervisor) CheckGroup(ctx context.Context, check GroupCheck) GroupPreview {
	ctx, cancel := context.WithTimeout(ctx, previewBudget)
	defer cancel()
	row := model.Member{Include: check.Include, Exclude: check.Exclude}
	preview := GroupPreview{Chosen: []string{}}
	var seen []string
	for _, name := range check.Subscriptions {
		if slices.Contains(seen, name) {
			continue
		}
		seen = append(seen, name)
		var request *api.ListRequest
		if asked, found := check.Requests[name]; found {
			request = &asked
		}
		list, err := s.groupList(ctx, name, strings.TrimSpace(check.Addresses[name]), request)
		if err != nil {
			preview.Missing = append(preview.Missing, name+": "+model.OneLine(err.Error()))
			continue
		}
		for _, server := range list.Servers {
			if !server.Usable() {
				continue
			}
			preview.Total++
			if row.Takes(server.Name) {
				preview.Chosen = append(preview.Chosen, server.Name)
			}
		}
	}
	return preview
}

// groupList is the list of a subscription for CheckGroup, by the address of the form (none:
// that of the settings) and its request (none: that of the settings). The request of the form
// is read as the settings are (subscription.ParseRequest): a line they leave out is left out here
// too, so the same raw lines are the same request, and the list taken is used.
func (s *Supervisor) groupList(ctx context.Context, name string, address string, request *api.ListRequest) (*subscription.Saved, error) {
	t := &s.subscriptions
	t.access.Lock()
	saved, list, running := t.addresses[name], t.lists[name], t.customs[name]
	custom := running
	if request != nil {
		custom, _ = subscription.ParseRequest(request.Preset, request.UserAgent, request.Headers, s.options.SingBoxVersion)
	}
	if address == "" {
		address = saved
	}
	if list != nil && address == saved && custom.Key() == running.Key() {
		t.access.Unlock()
		return list, nil
	}
	kept := t.previews[subscription.AddressKey(address)]
	t.access.Unlock()
	if address == "" {
		return nil, E.New("the address is not set")
	}
	if kept != nil && kept.request == custom.Key() && time.Since(kept.list.Changed) < previewKept {
		return kept.list, nil
	}
	list, _, _, err := s.fetch(ctx, address, custom, previewProxies, nil)
	if err != nil {
		return nil, err
	}
	s.keepPreview(list, custom.Key())
	return list, nil
}

// keepPreview keeps a list downloaded for the page for a while, the newest of its address only,
// with the key of the request it was asked with, and forgets those older.
func (s *Supervisor) keepPreview(list *subscription.Saved, request string) {
	t := &s.subscriptions
	t.access.Lock()
	defer t.access.Unlock()
	if t.previews == nil {
		t.previews = make(map[string]*preview)
	}
	for key, kept := range t.previews {
		if time.Since(kept.list.Changed) >= previewKept {
			delete(t.previews, key)
		}
	}
	t.previews[list.Address] = &preview{list: list, request: request}
}
