package supervisor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
)

// LoadJob is the type of the socket for a download of a list for the page.
type LoadJob = api.LoadJob

// The states of a download for the page.
const (
	loadRunning  = "running"
	loadDone     = "done"
	loadFailed   = "failed"
	loadCanceled = "canceled"
)

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
func (s *Supervisor) remember(key string, tries []subscription.Try) {
	t := &s.subscriptions
	t.access.Lock()
	defer t.access.Unlock()
	if t.histories == nil {
		t.histories = make(map[string]*history)
	}
	record := t.histories[key]
	if record == nil {
		record = &history{}
		t.histories[key] = record
	}
	for _, item := range tries {
		switch {
		case item.Route == "direct":
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
func (s *Supervisor) planOf(key string) (subscription.Plan, string) {
	t := &s.subscriptions
	t.access.Lock()
	defer t.access.Unlock()
	record := t.histories[key]
	if record == nil {
		return subscription.DefaultPlan, ""
	}
	return record.plan(), record.route
}

// loadJob is a download of a list for the page.
type loadJob struct {
	id       string
	key      string
	started  time.Time
	cancel   context.CancelFunc
	state    string
	tries    []subscription.Try
	preview  *SubscriptionPreview
	finished time.Time
}

func (j *loadJob) view() LoadJob {
	elapsed := time.Since(j.started)
	if !j.finished.IsZero() {
		elapsed = j.finished.Sub(j.started)
	}
	view := LoadJob{ID: j.id, State: j.state, Elapsed: elapsed.Milliseconds(), Attempts: attempts(j.tries), Preview: j.preview}
	if view.Attempts == nil {
		view.Attempts = []api.Attempt{}
	}
	return view
}

// StartLoad starts a download of a list from an address for the page; the same address under
// way already is that download. The page asks how it goes (LoadState): LuCI waits for a call
// 20 s, a download has a minute. It is for callers outside the goroutine of Run.
func (s *Supervisor) StartLoad(ctx context.Context, address string) LoadJob {
	address = strings.TrimSpace(address)
	key := subscription.AddressKey(address)
	t := &s.subscriptions
	t.access.Lock()
	now := time.Now()
	if t.jobs == nil {
		t.jobs = make(map[string]*loadJob)
	}
	running := 0
	for id, job := range t.jobs {
		switch {
		case job.state == loadRunning && job.key == key:
			view := job.view()
			t.access.Unlock()
			return view
		case job.finished.IsZero():
			// under way, or canceled with its goroutine still at work
			running++
		case now.Sub(job.finished) > previewKept:
			delete(t.jobs, id)
		}
	}
	if running >= mostLoads {
		t.access.Unlock()
		text := "two lists are downloaded for the page now: wait for them"
		return LoadJob{State: loadFailed, Attempts: []api.Attempt{}, Preview: &SubscriptionPreview{Servers: []api.PreviewServer{}, Error: text, ErrorCode: "busy"}}
	}
	jobContext, cancel := context.WithTimeout(context.Background(), loadBudget)
	job := &loadJob{id: newJobID(), key: key, started: now, cancel: cancel, state: loadRunning}
	t.jobs[job.id] = job
	view := job.view()
	t.access.Unlock()
	go func() {
		defer cancel()
		var preview SubscriptionPreview
		defer s.survive("the download of a list for the page", func() {
			t.access.Lock()
			defer t.access.Unlock()
			job.state, job.finished = loadFailed, time.Now()
			job.preview = &SubscriptionPreview{Servers: []api.PreviewServer{}, Error: "the download stopped on a fault of podkop: see the log", ErrorCode: "fault"}
		})
		preview = s.loadPreview(jobContext, address, func(tries []subscription.Try) {
			t.access.Lock()
			job.tries = tries
			t.access.Unlock()
		})
		t.access.Lock()
		defer t.access.Unlock()
		job.finished = time.Now()
		switch {
		case job.state == loadCanceled:
			// the preview of the cancel stays: the user asked for no list
		case preview.Error != "":
			job.state, job.preview = loadFailed, &preview
		default:
			job.state, job.preview = loadDone, &preview
		}
	}()
	return view
}

// LoadState tells how a download for the page goes. It is for callers outside the goroutine
// of Run.
func (s *Supervisor) LoadState(ctx context.Context, id string) (LoadJob, bool) {
	t := &s.subscriptions
	t.access.Lock()
	defer t.access.Unlock()
	job := t.jobs[id]
	if job == nil {
		return LoadJob{}, false
	}
	return job.view(), true
}

// CancelLoad stops a download for the page. It is for callers outside the goroutine of Run.
func (s *Supervisor) CancelLoad(ctx context.Context, id string) (LoadJob, bool) {
	t := &s.subscriptions
	t.access.Lock()
	defer t.access.Unlock()
	job := t.jobs[id]
	if job == nil {
		return LoadJob{}, false
	}
	if job.state == loadRunning {
		job.state = loadCanceled
		job.preview = &SubscriptionPreview{Servers: []api.PreviewServer{}, Error: "the download was canceled", ErrorCode: "canceled"}
		job.cancel()
	}
	return job.view(), true
}

// loadPreview downloads a list to be shown: nothing is taken; the list is kept a while for
// Check of a group and for a subscription added with its address.
func (s *Supervisor) loadPreview(ctx context.Context, address string, report func([]subscription.Try)) SubscriptionPreview {
	preview := SubscriptionPreview{Servers: []api.PreviewServer{}}
	address = strings.TrimSpace(address)
	list, _, tries, err := s.fetch(ctx, address, downloadProxies, report)
	preview.Attempts = attempts(tries)
	if err != nil {
		preview.Error, preview.ErrorCode, preview.ErrorArgs = failureOf(err)
		if errors.Is(ctx.Err(), context.Canceled) {
			preview.Error, preview.ErrorCode, preview.ErrorArgs = "the download was canceled", "canceled", nil
		}
		return preview
	}
	s.keepPreview(list)
	preview.Route, preview.Took = list.Route, tookOf(tries)
	preview.Provider = subscription.ReadInfo(list.Info)
	for _, server := range list.Servers {
		scheme, endpoint := server.Endpoint()
		preview.Servers = append(preview.Servers, api.PreviewServer{Name: server.Name, Scheme: scheme, Address: endpoint, Link: server.Link, Reason: server.Reason, Notes: server.Notes})
	}
	return preview
}

// attempts are the tries of a download as the page is told them.
func attempts(tries []subscription.Try) []api.Attempt {
	var list []api.Attempt
	for _, item := range tries {
		attempt := api.Attempt{Route: item.Route, Phase: item.Phase, Took: item.Took.Milliseconds(), FirstByte: item.FirstByte.Milliseconds(), Bytes: item.Bytes}
		if item.Failure != nil {
			attempt.Error, attempt.Code, attempt.Args = item.Failure.Text, item.Failure.Code, item.Failure.Args
		}
		list = append(list, attempt)
	}
	return list
}

// tookOf is how long the try that brought the list took, in milliseconds.
func tookOf(tries []subscription.Try) int64 {
	for _, item := range tries {
		if item.Phase == subscription.PhaseDone {
			return item.Took.Milliseconds()
		}
	}
	return 0
}

// failureOf is what the page is told of a failure: its text, and its code with its
// arguments when it has one.
func failureOf(err error) (string, string, []string) {
	var failure *subscription.Failure
	if errors.As(err, &failure) {
		return oneLine(failure.Text), failure.Code, failure.Args
	}
	return oneLine(err.Error()), "", nil
}

func newJobID() string {
	random := make([]byte, 8)
	_, _ = rand.Read(random)
	return hex.EncodeToString(random)
}
