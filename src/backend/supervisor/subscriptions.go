package supervisor

import (
	"context"
	"net"
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
// waits less the rest of the call. The ways through proxies are the fastest few the URL tests
// found.
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
	// waiting are the callers of UpdateSubscriptions, by name ("" for all)
	waiting map[string][]chan []SubscriptionState
	// previews are the lists downloaded for the page (LoadSubscription, CheckGroup), by the
	// key of their address, for a while: Check of a group takes the list Load just got
	previews map[string]*subscription.Saved
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

// downloaded is what a download in the background came to.
type downloaded struct {
	name    string
	address string
	list    *subscription.Saved
	tries   []subscription.Try
	err     error
	// through is the instance whose outbounds the download went through; none directly
	through Instance
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
// no longer have is forgotten, its file included.
func (s *Supervisor) syncSubscriptions(settings *model.Config) {
	t := &s.subscriptions
	t.access.Lock()
	defer t.access.Unlock()
	if t.lists == nil {
		t.addresses, t.intervals, t.lists = make(map[string]string), make(map[string]time.Duration), make(map[string]*subscription.Saved)
		t.states, t.verdicts, t.waiting = make(map[string]*SubscriptionState), make(map[string]string), make(map[string][]chan []SubscriptionState)
		t.previews = make(map[string]*subscription.Saved)
	}
	var names []string
	now := time.Now()
	for _, item := range settings.Subscriptions {
		names = append(names, item.Name)
		t.intervals[item.Name] = parseInterval(item.UpdateInterval)
		if t.addresses[item.Name] == item.URL && t.states[item.Name] != nil {
			continue
		}
		t.addresses[item.Name] = item.URL
		delete(t.lists, item.Name)
		delete(t.failures, item.Name)
		next := now.Add(firstDownloadDelay)
		state := &SubscriptionState{Name: item.Name, Next: &next}
		t.states[item.Name] = state
		var saved *subscription.Saved
		found := false
		if s.options.SubscriptionDir != "" {
			saved, found = s.store().Load(item.Name, item.URL)
		}
		if kept := t.previews[subscription.AddressKey(item.URL)]; !found && kept != nil && now.Sub(kept.Changed) < previewKept {
			// the list the page got for the address a while ago (Load, Check of a group): a
			// subscription just added has its servers at the apply that adds it; it is
			// downloaded soon all the same, as the provider may have changed the list since
			saved, found = kept, true
			checked := kept.Changed
			state.Checked = &checked
			if s.options.SubscriptionDir != "" {
				if err := s.store().Save(item.Name, kept); err != nil {
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
		}
	}
	if s.options.SubscriptionDir != "" {
		s.store().Keep(names)
	}
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

// parseInterval reads an update interval of the settings: a number of minutes, hours or
// days (30m, 12h, 1d). What cannot be read is 12 hours; less than ten minutes is ten.
func parseInterval(text string) time.Duration {
	text = strings.TrimSpace(text)
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

// routes are the ways to a provider, in the order they are tried: directly, then through the
// servers of the configuration that runs, the fastest first as the URL tests found them,
// those not tested after. Directly is through direct-out of sing-box while it runs: the
// resolver of the system answers the names of the lists from FakeIP then.
func (s *Supervisor) routes(proxies int, first string) ([]subscription.Route, Instance) {
	s.statusAccess.Lock()
	live, links := s.live, s.liveLinks
	s.statusAccess.Unlock()
	if live == nil {
		return []subscription.Route{subscription.DirectRoute()}, nil
	}
	through := func(tag string) func(ctx context.Context, network string, address string) (net.Conn, error) {
		return func(ctx context.Context, network string, address string) (net.Conn, error) {
			return live.Dial(ctx, tag, address)
		}
	}
	routes := []subscription.Route{{Name: "direct", Direct: true, Dial: through("direct-out")}}
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
		routes = append(routes, subscription.Route{Name: names[tag], Dial: through(tag)})
	}
	return routes, live
}

// fetch downloads and reads a list: the servers with their reasons, those built before taking
// the verdicts they had. The ways start as the history of the address plans them, and what
// the download came to goes into it. It tells the instance it went through and the tries.
func (s *Supervisor) fetch(ctx context.Context, address string, proxies int, report func([]subscription.Try)) (*subscription.Saved, Instance, []subscription.Try, error) {
	header := s.options.Device.Headers(s.options.Version)
	download := s.options.Download
	if download == nil {
		download = subscription.Download
	}
	key := subscription.AddressKey(address)
	plan, first := s.planOf(key)
	routes, through := s.routes(proxies, first)
	answer, tries, err := download(ctx, address, header, routes, plan, report)
	s.remember(key, tries)
	if err != nil {
		return nil, through, tries, err
	}
	servers, err := subscription.Parse(answer.Body, engine.DecodeLink)
	if err != nil {
		return nil, through, tries, err
	}
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
	return &subscription.Saved{Address: key, Changed: time.Now().UTC(), Route: answer.Route, Servers: servers, Info: answer.Info()}, through, tries, nil
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
		delete(t.forced, name)
		state.Busy = true
		address := t.addresses[name]
		go func() {
			defer s.survive("the download of subscription "+name, func() {
				s.downloads <- downloaded{name: name, address: address, err: &subscription.Failure{Code: "fault", Text: "the download stopped on a fault of podkop: see the log"}}
			})
			ctx, cancel := context.WithTimeout(context.Background(), downloadBudget)
			defer cancel()
			list, through, tries, err := s.fetch(ctx, address, downloadProxies, nil)
			s.downloads <- downloaded{name: name, address: address, list: list, tries: tries, err: err, through: through}
		}()
	}
}

// takeList takes a list downloaded in the background: a list with other servers is kept, and
// the settings are applied again with it once no other download is under way; one that has
// the same servers, under other names or in another order, is not, and nothing changes, unless
// the new names change what a group chooses (a server the provider calls DE now, not NL).
func (s *Supervisor) takeList(result downloaded) {
	t := &s.subscriptions
	t.access.Lock()
	state := t.states[result.name]
	if state == nil || t.addresses[result.name] != result.address {
		// the settings changed meanwhile: the list of another address is not taken
		t.access.Unlock()
		s.downloadDue(time.Now(), "")
		s.applyTaken()
		return
	}
	state.Busy = false
	now := time.Now()
	next := now.Add(t.intervals[result.name])
	state.Attempted, state.Attempts = &now, attempts(result.tries)
	if result.err != nil {
		if t.failures == nil {
			t.failures = make(map[string]int)
		}
		t.failures[result.name]++
		next = now.Add(min(downloadRetry, t.intervals[result.name]))
		if t.lists[result.name] == nil {
			// no list at all: the groups of the subscription go by their rule for no server
			next = now.Add(min(downloadBackoff(t.failures[result.name]), t.intervals[result.name]))
		}
		if result.through != nil && result.through != s.liveInstance() {
			// the sing-box it went through was replaced meanwhile: again at the next tick
			next = now
		}
		state.Next = &next
		state.Error, state.ErrorCode, state.ErrorArgs = failureOf(result.err)
		t.access.Unlock()
		s.log("warn", "subscription ", result.name, ": ", state.Error)
		s.downloadDue(time.Now(), "")
		s.applyTaken()
		s.answerWaiting(result.name)
		return
	}
	delete(t.failures, result.name)
	state.Error, state.ErrorCode, state.ErrorArgs = "", "", nil
	state.Next, state.Checked, state.Route, state.Took = &next, &now, result.list.Route, tookOf(result.tries)
	state.Provider = subscription.ReadInfo(result.list.Info)
	way := waysLine(result.tries)
	old := t.lists[result.name]
	if old != nil && subscription.SameServers(old.Servers, result.list.Servers) && !s.choiceChanged(result.name, old.Servers, result.list.Servers) {
		// the traffic and the end the provider tells change with every list: kept in memory,
		// the file is written only when the servers change
		old.Info = result.list.Info
		t.access.Unlock()
		s.log("info", "subscription ", result.name, ": the list has not changed (", way, ")")
		s.downloadDue(time.Now(), "")
		s.applyTaken()
		s.answerWaiting(result.name)
		return
	}
	t.lists[result.name] = result.list
	changed := result.list.Changed
	state.Changed, state.Servers, state.Usable = &changed, len(result.list.Servers), usable(result.list.Servers)
	t.changed = true
	t.access.Unlock()
	s.log("info", "subscription ", result.name, ": ", state.Servers, " servers, ", state.Usable, " can be used (", way, ")")
	if s.options.SubscriptionDir != "" {
		err := s.store().Save(result.name, result.list)
		if err != nil {
			s.log("warn", "subscription ", result.name, ": ", err)
		}
	}
	s.downloadDue(time.Now(), "")
	s.applyTaken()
	s.answerWaiting(result.name)
}

// waysLine tells how a list came for the log: the way and the time, and why the ways tried
// before or beside it did not bring it ("through main-2 in 6.4 s; direct: the transfer stopped
// at 16 KB").
func waysLine(tries []subscription.Try) string {
	var won string
	var others []string
	for _, item := range tries {
		switch {
		case item.Phase == subscription.PhaseDone:
			won = item.Route + " in " + strconv.FormatFloat(item.Took.Seconds(), 'f', 1, 64) + " s"
			if item.Route != "direct" {
				won = "through " + won
			}
		case item.Failure != nil && item.Failure.Code != "canceled":
			others = append(others, item.Route+": "+item.Failure.Text)
		}
	}
	return strings.Join(append([]string{won}, others...), "; ")
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
	select {
	case s.subscriptionRequests <- subscriptionRequest{name: name, reply: reply}:
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

// LoadSubscription downloads a list to be shown: the page asks with the address of its form,
// saved or not. Nothing is taken. It is for callers outside the goroutine of Run.
func (s *Supervisor) LoadSubscription(ctx context.Context, address string) SubscriptionPreview {
	ctx, cancel := context.WithTimeout(ctx, loadBudget)
	defer cancel()
	return s.loadPreview(ctx, address, nil)
}

// CheckGroup tells which servers a group would choose. A subscription's list is the one
// taken when the form has the address the settings have, else the one Load got for the address
// of the form a while ago, else one downloaded for it; none of these is taken. It is for
// callers outside the goroutine of Run.
func (s *Supervisor) CheckGroup(ctx context.Context, check GroupCheck) GroupPreview {
	ctx, cancel := context.WithTimeout(ctx, previewBudget)
	defer cancel()
	group := model.Group{Include: check.Include, Exclude: check.Exclude}
	preview := GroupPreview{Chosen: []string{}}
	var seen []string
	for _, name := range check.Subscriptions {
		if slices.Contains(seen, name) {
			continue
		}
		seen = append(seen, name)
		list, err := s.groupList(ctx, name, strings.TrimSpace(check.Addresses[name]))
		if err != nil {
			preview.Missing = append(preview.Missing, name+": "+oneLine(err.Error()))
			continue
		}
		for _, server := range list.Servers {
			if !server.Usable() {
				continue
			}
			preview.Total++
			if group.Takes(server.Name) {
				preview.Chosen = append(preview.Chosen, server.Name)
			}
		}
	}
	return preview
}

// groupList is the list of a subscription for CheckGroup, by the address of the form (none:
// that of the settings).
func (s *Supervisor) groupList(ctx context.Context, name string, address string) (*subscription.Saved, error) {
	t := &s.subscriptions
	t.access.Lock()
	saved, list := t.addresses[name], t.lists[name]
	if address == "" {
		address = saved
	}
	if list != nil && address == saved {
		t.access.Unlock()
		return list, nil
	}
	kept := t.previews[subscription.AddressKey(address)]
	t.access.Unlock()
	if address == "" {
		return nil, E.New("the address is not set")
	}
	if kept != nil && time.Since(kept.Changed) < previewKept {
		return kept, nil
	}
	list, _, _, err := s.fetch(ctx, address, previewProxies, nil)
	if err != nil {
		return nil, err
	}
	s.keepPreview(list)
	return list, nil
}

// keepPreview keeps a list downloaded for the page for a while, and forgets those older.
func (s *Supervisor) keepPreview(list *subscription.Saved) {
	t := &s.subscriptions
	t.access.Lock()
	defer t.access.Unlock()
	if t.previews == nil {
		t.previews = make(map[string]*subscription.Saved)
	}
	for key, kept := range t.previews {
		if time.Since(kept.Changed) >= previewKept {
			delete(t.previews, key)
		}
	}
	t.previews[list.Address] = list
}

// choiceChanged tells whether the groups of the settings that run would choose other servers
// of a subscription by the names of its new list than by those of the old one.
func (s *Supervisor) choiceChanged(name string, old []subscription.Server, fresh []subscription.Server) bool {
	if s.current == nil {
		return false
	}
	chosen := func(group *model.Group, servers []subscription.Server) []string {
		var ids []string
		for index := range servers {
			if servers[index].Usable() && group.Takes(servers[index].Name) {
				ids = append(ids, servers[index].ID)
			}
		}
		slices.Sort(ids)
		return ids
	}
	for index := range s.current.settings.Groups {
		group := &s.current.settings.Groups[index]
		if slices.Contains(group.Subscriptions, name) && !slices.Equal(chosen(group, old), chosen(group, fresh)) {
			return true
		}
	}
	return false
}
