package supervisor

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
)

// The downloads of the lists of the subscriptions (subscriptions.go): when each is due, what its
// ways came to before, and what is taken of it.

// downloadBackoff is when a subscription with no list is tried again after its failures.
func downloadBackoff(failures int) time.Duration {
	failures = min(max(failures, 1), 5)
	return min(time.Minute<<(failures-1), downloadRetry)
}

// history is how the downloads of an address went: the last of them that brought a list, the
// way of the last one, and whether its direct way brought the list. The next download plans
// its ways by it (subscription.Plan): a provider that takes 8 s is waited for, a way that
// stopped before is not.
type history struct {
	samples      []sample
	route        string
	directFailed bool
}

// sample is a download that brought a list, by the try that brought it: the time to the
// first byte of the answer, the longest pause in the body, the whole time.
type sample struct {
	firstByte, pause, total time.Duration
}

// plan is the plan of the next download of the address: twice the worst of the last downloads
// that brought a list, within 2-15 s (the whole try 5-30 s); with none, the default plan.
func (h *history) plan() subscription.Plan {
	plan := subscription.DefaultPlan
	if h == nil {
		return plan
	}
	plan.Together = h.directFailed
	if len(h.samples) == 0 {
		return plan
	}
	var firstByte, pause, total time.Duration
	for _, item := range h.samples {
		firstByte, pause, total = max(firstByte, item.firstByte), max(pause, item.pause), max(total, item.total)
	}
	plan.Wait = min(max(2*firstByte, 2*time.Second), 15*time.Second)
	plan.Body = min(max(2*pause, 2*time.Second), 15*time.Second)
	plan.Total = min(max(2*total, 5*time.Second), 30*time.Second)
	return plan
}

// remember takes what a download of an address came to into its history.
func (t *subscriptionRuntime) remember(key string, tries []subscription.Try) {
	t.access.Lock()
	defer t.access.Unlock()
	record := t.histories[key]
	if record == nil {
		record = &history{}
		t.histories[key] = record
	}
	for _, item := range tries {
		switch {
		case item.Route == "direct" && !item.Cut && (item.Failure == nil || !item.Failure.Final()):
			// a try the end of the download's context cut says nothing of the way, nor does an
			// answer of the provider itself (a web page to the User-Agent of the settings too)
			record.directFailed = item.Phase != subscription.PhaseDone
		}
		if item.Phase == subscription.PhaseDone {
			record.route = item.Route
			record.samples = append(record.samples, sample{firstByte: item.FirstByte, pause: item.Pause, total: item.Took})
			if len(record.samples) > historyKept {
				record.samples = record.samples[len(record.samples)-historyKept:]
			}
		}
	}
}

// planOf is the plan of the next download of an address and the way of its last one.
func (t *subscriptionRuntime) planOf(key string) (subscription.Plan, string) {
	t.access.Lock()
	defer t.access.Unlock()
	record := t.histories[key]
	if record == nil {
		return subscription.DefaultPlan, ""
	}
	return record.plan(), record.route
}

// fetch downloads and reads a list, asked with what the settings or the page add to the request:
// the servers with their reasons, those built before taking the verdicts they had. The ways start
// as the history of the address plans them, and what the download came to goes into it: the
// history is of the way to the address, whatever it was asked with. It tells the instance it went
// through and the tries.
func (t *subscriptionRuntime) fetch(ctx context.Context, address string, custom subscription.Custom, proxies int, report func([]subscription.Try)) (*subscription.Saved, Instance, []subscription.Try, error) {
	header := t.options.Device.Headers(t.options.Version, custom)
	download := t.options.Download
	if download == nil {
		download = subscription.Download
	}
	key := subscription.AddressKey(address)
	way, first := t.planOf(key)
	host := hostOf(address)
	routes, through, together := t.host.routes(proxies, first, host)
	way.Together = way.Together || together
	// a web page to the User-Agent of another app over TLS is the provider's answer to it: two
	// ways at most get it, and none is held at fault for it
	way.PageIsAnswer = custom.UserAgent != "" && secureAddress(address)
	answer, tries, err := download(ctx, address, header, routes, way, report)
	t.remember(key, tries)
	recordTries(through, host, routes, tries)
	if err != nil {
		return nil, through, tries, subscription.ForAgent(err, custom, address)
	}
	read, err := subscription.ParseList(ctx, answer.Body, subscription.Codec{Decode: engine.DecodeLink, Normalize: engine.NormalizeOutbound})
	if err != nil {
		return nil, through, tries, subscription.ForAgent(err, custom, address)
	}
	servers := read.Servers
	known := func() map[string]string {
		t.access.Lock()
		defer t.access.Unlock()
		known := make(map[string]string, len(t.verdicts))
		for id, reason := range t.verdicts {
			known[id] = reason
		}
		return known
	}()
	verdicts := t.options.Engine.CheckServers(servers, known)
	func() {
		t.access.Lock()
		defer t.access.Unlock()
		if len(t.verdicts) > 10000 {
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
func (t *subscriptionRuntime) downloadDue(now time.Time, force string) {
	t.access.Lock()
	defer t.access.Unlock()
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
	// the asked ones first, then the longest due, then by name: the subscriptions an apply adds
	// are all due at the same time, and the names come in the order of a map
	slices.SortFunc(names, func(left string, right string) int {
		switch {
		case t.forced[left] != t.forced[right] && t.forced[left]:
			return -1
		case t.forced[left] != t.forced[right]:
			return 1
		}
		leftNext, rightNext := t.states[left].Next, t.states[right].Next
		switch {
		case leftNext != nil && rightNext != nil:
			if order := leftNext.Compare(*rightNext); order != 0 {
				return order
			}
		case leftNext != nil:
			// nothing planned is never due: after what is, for one order whatever the names
			return -1
		case rightNext != nil:
			return 1
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
			defer t.host.survive("the download of subscription "+name, func() {
				t.downloads <- downloaded{name: name, address: address, request: request, err: &subscription.Failure{Code: "fault", Text: "the download stopped on a fault of podkop: see the log"}}
			})
			ctx, cancel := context.WithTimeout(context.Background(), downloadBudget)
			defer cancel()
			list, through, tries, err := t.fetch(ctx, address, custom, downloadProxies, nil)
			t.downloads <- downloaded{name: name, address: address, request: request, list: list, tries: tries, err: err, through: through, planned: planned}
		}()
	}
}

// takeList takes a list downloaded in the background: a list with other servers is kept, and
// the settings are applied again with it once no other download is under way; one that has
// the same servers, under other names or in another order, is not, and nothing changes, unless
// the new names change what a group chooses (a server the provider calls DE now, not NL).
// Whatever the download came to, the downloads that waited for a place start, the lists of a
// round that ended are applied, and the callers that waited for it are answered, unless the list
// is downloaded again at once (takeResult).
func (t *subscriptionRuntime) takeList(result downloaded) {
	tell, answer := t.takeResult(result)
	// the log and the file of the list after the lock: the previews of other goroutines wait
	// on it
	if tell != nil {
		tell()
	}
	t.downloadDue(time.Now(), "")
	t.applyTaken()
	if answer {
		t.answerWaiting(result.name)
	}
}

// takeResult is what takeList does under the lock of the subscriptions. tell is what is logged
// and written of it after the lock, none when nothing is; answer tells that the callers waiting
// for the subscription are answered, and those waiting for all if none is busy then
// (answerWaiting).
func (t *subscriptionRuntime) takeResult(result downloaded) (tell func(), answer bool) {
	t.access.Lock()
	defer t.access.Unlock()
	state := t.states[result.name]
	if state == nil || t.addresses[result.name] != result.address {
		// the settings changed meanwhile: the list of another address is not taken. The callers
		// that waited for it are answered all the same: nothing else answers those of a
		// subscription that is gone, nor those of all while no other download is under way, and
		// the next download of another address is the scheduler's, not one they asked for
		return nil, true
	}
	state.Busy = false
	now := time.Now()
	if t.customs[result.name].Key() != result.request {
		// the User-Agent or the headers changed meanwhile: the answer to the old ones is not
		// taken, and the list is downloaded again with the new ones now. The callers that waited
		// for it wait for that download, whose end answers them: answered now, they would be told
		// it is busy, and those of all could not be (it is, or the downloads it waits for are)
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
		replaced := result.through != nil && result.through != t.host.liveInstance()
		if result.planned != nil && result.planned.After(now) && t.lists[result.name] != nil && !replaced {
			// asked for by hand and failed, with a list in use: the download that was planned
			// stays when it was, and the failure does not count towards the backoff
			next = *result.planned
		} else {
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
				t.log("info", "subscription ", result.name, ": not downloaded ", again, " (", code, "), the next try at ", next.Format(time.TimeOnly))
			} else {
				t.log("warn", "subscription ", result.name, ": ", text)
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
				t.log("info", "subscription ", result.name, ": ", line)
			}
			t.log("info", "subscription ", result.name, ": the list has not changed (", way, ")")
			if reformatted {
				t.saveList(result.name, result.list)
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
			t.log("info", "subscription ", result.name, ": ", line)
		}
		if changes != nil {
			t.log("info", "subscription ", result.name, ": ", changesLine(changes), "; ", count, " servers, ", canUse, " can be used (", way, ")")
		} else {
			t.log("info", "subscription ", result.name, ": ", count, " servers, ", canUse, " can be used (", way, ")")
		}
		t.saveList(result.name, result.list)
	}, true
}

// saveList keeps the list taken of a subscription on flash, when there is a directory for them.
func (t *subscriptionRuntime) saveList(name string, list *subscription.Saved) {
	if t.options.SubscriptionDir == "" {
		return
	}
	if err := t.store().Save(name, list); err != nil {
		t.log("warn", "subscription ", name, ": ", err)
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
func (t *subscriptionRuntime) applyTaken() {
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
	if due && t.host.Running() {
		t.host.apply(false)
	}
}

// answerWaiting answers the callers of UpdateSubscriptions waiting for a subscription, and
// those waiting for all once none is busy.
func (t *subscriptionRuntime) answerWaiting(name string) {
	states := t.subscriptionStates()
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

// updateSubscriptions downloads the list of a subscription now (of all of them with no name)
// and waits for what it came to. It is for callers outside the goroutine of Run.
func (t *subscriptionRuntime) updateSubscriptions(ctx context.Context, name string) []SubscriptionState {
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
		case t.requests <- subscriptionRequest{name: name, reply: reply}:
			close(taken)
		case <-timer.C:
		}
	}()
	select {
	case <-taken:
	case <-ctx.Done():
		return t.subscriptionStates()
	}
	select {
	case states := <-reply:
		return states
	case <-ctx.Done():
		return t.subscriptionStates()
	}
}

// askDownload is updateSubscriptions in the goroutine of Run.
func (t *subscriptionRuntime) askDownload(request subscriptionRequest) {
	key := request.name
	if key == "" {
		key = "*"
	}
	t.access.Lock()
	known := key == "*" || t.states[key] != nil
	if known {
		t.waiting[key] = append(t.waiting[key], request.reply)
	}
	empty := len(t.states) == 0
	t.access.Unlock()
	if !known || empty {
		request.reply <- t.subscriptionStates()
		return
	}
	t.downloadDue(time.Now(), key)
}
