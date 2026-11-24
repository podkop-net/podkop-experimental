package supervisor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
	E "github.com/sagernet/sing/common/exceptions"
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

// startLoad starts a download of a list from an address, asked with the request of the form, for
// the page; the same address and request under way already is that download. A request that
// cannot be sent as it is fails at once: the form asks for what it shows. The page asks how it
// goes (loadState): LuCI waits for a call 20 s, a download has a minute. It is for callers outside
// the goroutine of Run.
func (t *subscriptionRuntime) startLoad(ctx context.Context, address string, request api.ListRequest) LoadJob {
	address = strings.TrimSpace(address)
	custom, problems := subscription.ParseRequest(request.Preset, request.UserAgent, request.Headers, t.options.SingBoxVersion)
	if len(problems) > 0 {
		refused := refusedRequest(problems[0])
		return LoadJob{State: loadFailed, Attempts: []api.Attempt{}, Preview: &refused}
	}
	key := subscription.RequestKey(address, custom)
	t.access.Lock()
	now := time.Now()
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
		defer t.host.survive("the download of a list for the page", func() {
			t.access.Lock()
			defer t.access.Unlock()
			job.state, job.finished = loadFailed, time.Now()
			job.preview = &SubscriptionPreview{Servers: []api.PreviewServer{}, Error: "the download stopped on a fault of podkop: see the log", ErrorCode: "fault"}
		})
		preview = t.loadPreview(jobContext, address, custom, func(tries []subscription.Try) {
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

// loadState tells how a download for the page goes. It is for callers outside the goroutine
// of Run.
func (t *subscriptionRuntime) loadState(ctx context.Context, id string) (LoadJob, bool) {
	t.access.Lock()
	defer t.access.Unlock()
	job := t.jobs[id]
	if job == nil {
		return LoadJob{}, false
	}
	return job.view(), true
}

// cancelLoad stops a download for the page. It is for callers outside the goroutine of Run.
func (t *subscriptionRuntime) cancelLoad(ctx context.Context, id string) (LoadJob, bool) {
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

// refusedRequest is the preview of a request of the page that cannot be sent: the first line
// left out, by its code for the page (the code, the line, the name, the arguments), never its
// value.
func refusedRequest(problem subscription.Problem) SubscriptionPreview {
	args := append([]string{problem.Code, strconv.Itoa(problem.Line), problem.Name}, problem.Args...)
	return SubscriptionPreview{Servers: []api.PreviewServer{}, Error: "the User-Agent or a header cannot be sent: " + problem.Where() + ": " + problem.Text, ErrorCode: "request", ErrorArgs: args}
}

// loadSubscription downloads a list to be shown: the page asks with the address, the User-Agent
// and the headers of its form, saved or not. Nothing is taken. It is for callers outside the
// goroutine of Run.
func (t *subscriptionRuntime) loadSubscription(ctx context.Context, address string, request api.ListRequest) SubscriptionPreview {
	custom, problems := subscription.ParseRequest(request.Preset, request.UserAgent, request.Headers, t.options.SingBoxVersion)
	if len(problems) > 0 {
		return refusedRequest(problems[0])
	}
	ctx, cancel := context.WithTimeout(ctx, loadBudget)
	defer cancel()
	return t.loadPreview(ctx, address, custom, nil)
}

// loadPreview downloads a list to be shown: nothing is taken; the list is kept a while for
// Check of a group and for a subscription added with its address and request.
func (t *subscriptionRuntime) loadPreview(ctx context.Context, address string, custom subscription.Custom, report func([]subscription.Try)) SubscriptionPreview {
	preview := SubscriptionPreview{Servers: []api.PreviewServer{}, Agent: custom.UserAgent, Preset: custom.Preset}
	address = strings.TrimSpace(address)
	list, _, tries, err := t.fetch(ctx, address, custom, downloadProxies, report)
	preview.Attempts = attempts(tries)
	if err != nil {
		preview.Error, preview.ErrorCode, preview.ErrorArgs = failureOf(err)
		if errors.Is(ctx.Err(), context.Canceled) {
			preview.Error, preview.ErrorCode, preview.ErrorArgs = "the download was canceled", "canceled", nil
		}
		return preview
	}
	t.keepPreview(list, custom.Key())
	preview.Route, preview.Took = list.Route, tookOf(tries)
	preview.Provider = subscription.ReadInfo(list.Info)
	preview.Format, preview.Configs = list.Format, list.Configs
	for _, server := range list.Servers {
		scheme, endpoint := server.Endpoint()
		preview.Servers = append(preview.Servers, api.PreviewServer{Name: server.Name, Scheme: scheme, Address: endpoint, Link: server.Link, Reason: server.Reason, Notes: server.Notes,
			Made: list.Format != ""})
	}
	return preview
}

// checkGroup tells which servers a group would choose. A subscription's list is the one
// taken when the form has the address and the request the settings that run have, else the one
// Load got for the address and the request of the form a while ago, else one downloaded for
// them; none of these is taken. It is for callers outside the goroutine of Run.
func (t *subscriptionRuntime) checkGroup(ctx context.Context, check GroupCheck) GroupPreview {
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
		list, err := t.groupList(ctx, name, strings.TrimSpace(check.Addresses[name]), request)
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

// groupList is the list of a subscription for checkGroup, by the address of the form (none:
// that of the settings) and its request (none: that of the settings). The request of the form
// is read as the settings are (subscription.ParseRequest): a line they leave out is left out here
// too, so the same raw lines are the same request, and the list taken is used.
func (t *subscriptionRuntime) groupList(ctx context.Context, name string, address string, request *api.ListRequest) (*subscription.Saved, error) {
	t.access.Lock()
	saved, list, running := t.addresses[name], t.lists[name], t.customs[name]
	custom := running
	if request != nil {
		custom, _ = subscription.ParseRequest(request.Preset, request.UserAgent, request.Headers, t.options.SingBoxVersion)
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
	list, _, _, err := t.fetch(ctx, address, custom, previewProxies, nil)
	if err != nil {
		return nil, err
	}
	t.keepPreview(list, custom.Key())
	return list, nil
}

// keepPreview keeps a list downloaded for the page for a while, the newest of its address only,
// with the key of the request it was asked with, and forgets those older.
func (t *subscriptionRuntime) keepPreview(list *subscription.Saved, request string) {
	t.access.Lock()
	defer t.access.Unlock()
	for key, kept := range t.previews {
		if time.Since(kept.list.Changed) >= previewKept {
			delete(t.previews, key)
		}
	}
	t.previews[list.Address] = &preview{list: list, request: request}
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
		return model.OneLine(failure.Text), failure.Code, failure.Args
	}
	return model.OneLine(err.Error()), "", nil
}

func newJobID() string {
	random := make([]byte, 8)
	_, _ = rand.Read(random)
	return hex.EncodeToString(random)
}
