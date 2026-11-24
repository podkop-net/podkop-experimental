package api

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/btstats"
	"github.com/podkop-net/podkop-experimental/src/backend/logbuf"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"

	"github.com/stretchr/testify/require"
)

// fixed is a Backend of fixed answers that notes what it is asked.
type fixed struct {
	Backend
	access sync.Mutex
	asked  []string
	// empty: every answer is empty
	empty bool
	// block holds Probe until its context ends
	block bool
	// now is the time of the answers
	now time.Time
}

func (f *fixed) note(question string) {
	f.access.Lock()
	defer f.access.Unlock()
	f.asked = append(f.asked, question)
}

// told are the questions asked since the last time it told.
func (f *fixed) told() string {
	f.access.Lock()
	defer f.access.Unlock()
	text := strings.Join(f.asked, "; ")
	f.asked = nil
	return text
}

func (f *fixed) Status() Status {
	f.note("status")
	if f.empty {
		return Status{}
	}
	return Status{Running: true, Since: f.now, Last: Result{OK: true, Message: "applied <1> & \"2\""}, LastAt: time.Date(2026, 11, 24, 12, 0, 0, 123456789, time.FixedZone("MSK", 3*60*60))}
}

func (f *fixed) Facts() Facts {
	f.note("facts")
	if f.empty {
		return Facts{}
	}
	// as the supervisor makes the tags: json.Marshal, the text escaped for HTML
	tags, _ := json.Marshal(map[string]string{"a": "<b> & c"})
	return Facts{ClashAPI: "127.0.0.1:1", ClashSecret: "k&<>", Tags: tags}
}

func (f *fixed) Request(context.Context) Result {
	f.note("apply")
	return Result{Message: "refused"}
}

func (f *fixed) UpdateLists(context.Context) ListsUpdate {
	f.note("update lists")
	if f.empty {
		return ListsUpdate{}
	}
	return ListsUpdate{OK: true, Lines: []string{}}
}

func (f *fixed) ListStatus(context.Context) []ListState {
	f.note("lists")
	if f.empty {
		return nil
	}
	return []ListState{{Tag: "t", Kind: "remote", URL: "https://l.example/?a=1&b=<2>", LastUpdated: &f.now}}
}

func (f *fixed) RestoreRouting(context.Context) string {
	f.note("restore")
	if f.empty {
		return ""
	}
	return "nothing was missing"
}

func (f *fixed) Probe(ctx context.Context, label string, wait time.Duration) ProbeResult {
	f.note("probe " + label + " " + wait.String())
	if f.block {
		<-ctx.Done()
		f.note("probe ended")
		return ProbeResult{DNS: true}
	}
	return ProbeResult{DNS: !f.empty}
}

func (f *fixed) ProbeSelf(context.Context) ProbeResult {
	f.note("probe self")
	return ProbeResult{Connection: !f.empty, Client: "192.168.1.2"}
}

func (f *fixed) Subscriptions(context.Context) []SubscriptionState {
	f.note("subscriptions")
	return f.states()
}

func (f *fixed) states() []SubscriptionState {
	if f.empty {
		return []SubscriptionState{}
	}
	return []SubscriptionState{{Name: "s", Attempts: []Attempt{}, Headers: []string{}, Changed: &f.now, Now: &f.now, Error: "a \u2028 <b>",
		Provider: &subscription.ProviderInfo{Title: "T", Expire: &f.now}, Changes: &subscription.ListChanges{}}}
}

func (f *fixed) UpdateSubscriptions(ctx context.Context, name string) []SubscriptionState {
	deadline, limited := ctx.Deadline()
	f.note("update " + name)
	if limited && time.Until(deadline) <= startWait {
		f.note("no longer than a start")
	}
	return f.states()
}

func (f *fixed) StartLoad(_ context.Context, address string, request ListRequest) LoadJob {
	encoded, _ := json.Marshal(request)
	f.note("load " + address + " " + string(encoded))
	return LoadJob{ID: "1", State: "running"}
}

func (f *fixed) LoadState(_ context.Context, id string) (LoadJob, bool) {
	f.note("state of " + id)
	return LoadJob{ID: id, State: "done", Attempts: []Attempt{}, Preview: &SubscriptionPreview{}}, id == "1"
}

func (f *fixed) CancelLoad(_ context.Context, id string) (LoadJob, bool) {
	f.note("cancel " + id)
	return LoadJob{ID: id, State: "canceled"}, id == "1"
}

func (f *fixed) CheckGroup(_ context.Context, check GroupCheck) GroupPreview {
	encoded, _ := json.Marshal(check)
	f.note("group " + string(encoded))
	if f.empty {
		return GroupPreview{}
	}
	return GroupPreview{Chosen: []string{}, Total: 3, Missing: []string{"m"}}
}

func (f *fixed) BitTorrent() map[string]int64 {
	f.note("counters")
	if f.empty {
		return nil
	}
	return map[string]int64{"b": 2, "a": 1 << 60}
}

func (f *fixed) BitTorrentStats() btstats.Report {
	f.note("stats")
	if f.empty {
		return btstats.Report{Rows: []btstats.Row{}}
	}
	return btstats.Report{Mode: "bypass", Module: map[string]int64{}}
}

func (f *fixed) ResetBitTorrentStats() btstats.Report {
	f.note("reset")
	return btstats.Report{ResetAt: 1}
}

// Direct answers what Client answers, as JSON, and asks the backend the same: the commands print
// the same inside the backend and in a program of their own.
func TestDirectAsClient(t *testing.T) {
	type client interface {
		Status() (*Status, error)
		Facts() (*Facts, error)
		Logs(uint64) (*LogPage, error)
		Apply() (*Result, error)
		UpdateLists() (*ListsUpdate, error)
		RestoreRouting() (string, error)
		Lists() ([]ListState, error)
		Probe(string, time.Duration) (*ProbeResult, error)
		ProbeSelf() (*ProbeResult, error)
		BitTorrentStats() (btstats.Report, error)
		ResetBitTorrentStats() (btstats.Report, error)
		BitTorrent() (map[string]int64, error)
		Subscriptions() ([]SubscriptionState, error)
		StartSubscriptionUpdate(string) ([]SubscriptionState, error)
		UpdateSubscriptions(string) ([]SubscriptionState, error)
		StartLoad(string, ListRequest) (*LoadJob, error)
		LoadState(string) (*LoadJob, error)
		CancelLoad(string) (*LoadJob, error)
		CheckGroup(GroupCheck, time.Duration) (*GroupPreview, error)
	}
	request := ListRequest{Preset: "custom", UserAgent: "A & <B>", Headers: []string{"X: 1"}}
	questions := map[string]func(c client) (any, error){
		"Status":                  func(c client) (any, error) { return c.Status() },
		"Facts":                   func(c client) (any, error) { return c.Facts() },
		"Logs 0":                  func(c client) (any, error) { return c.Logs(0) },
		"Logs 1":                  func(c client) (any, error) { return c.Logs(1) },
		"Logs 2":                  func(c client) (any, error) { return c.Logs(2) },
		"Apply":                   func(c client) (any, error) { return c.Apply() },
		"UpdateLists":             func(c client) (any, error) { return c.UpdateLists() },
		"RestoreRouting":          func(c client) (any, error) { return c.RestoreRouting() },
		"Lists":                   func(c client) (any, error) { return c.Lists() },
		"Probe":                   func(c client) (any, error) { return c.Probe("0a1b2c3d4e5f", 1500*time.Millisecond) },
		"Probe at once":           func(c client) (any, error) { return c.Probe("0a1b2c3d4e5f", 0) },
		"Probe of no time":        func(c client) (any, error) { return c.Probe("0a1b2c3d4e5f", -time.Minute) },
		"ProbeSelf":               func(c client) (any, error) { return c.ProbeSelf() },
		"BitTorrentStats":         func(c client) (any, error) { return c.BitTorrentStats() },
		"ResetBitTorrentStats":    func(c client) (any, error) { return c.ResetBitTorrentStats() },
		"BitTorrent":              func(c client) (any, error) { return c.BitTorrent() },
		"Subscriptions":           func(c client) (any, error) { return c.Subscriptions() },
		"StartSubscriptionUpdate": func(c client) (any, error) { return c.StartSubscriptionUpdate("s & 1") },
		"UpdateSubscriptions":     func(c client) (any, error) { return c.UpdateSubscriptions("") },
		"StartLoad":               func(c client) (any, error) { return c.StartLoad("https://s.example/?a=<1>&b", request) },
		"LoadState":               func(c client) (any, error) { return c.LoadState("1") },
		"LoadState unknown":       func(c client) (any, error) { return c.LoadState("2") },
		"CancelLoad":              func(c client) (any, error) { return c.CancelLoad("1") },
		"CancelLoad unknown":      func(c client) (any, error) { return c.CancelLoad("2&3") },
		"CheckGroup": func(c client) (any, error) {
			return c.CheckGroup(GroupCheck{Subscriptions: []string{"s"}, Requests: map[string]ListRequest{"s": request}}, time.Minute)
		},
		"CheckGroup of nothing": func(c client) (any, error) { return c.CheckGroup(GroupCheck{}, time.Minute) },
	}
	logs := logbuf.New(1 << 12)
	logs.Write("backend", "info", "one <1>")
	logs.Write("sing-box", "error", "two \xff\xfe")
	backend := &fixed{now: time.Now()}
	path := filepath.Join(t.TempDir(), "ctl.sock")
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, path, backend, logs) }()
	require.Eventually(t, func() bool { _, err := os.Stat(path); return err == nil }, 5*time.Second, 10*time.Millisecond)
	for _, empty := range []bool{false, true} {
		backend.empty = empty
		for name, question := range questions {
			want, wantErr := question(Client{Path: path})
			wantAsked := backend.told()
			got, gotErr := question(Direct{Backend: backend, Log: logs})
			require.Equal(t, wantErr != nil, gotErr != nil, "%s (empty %v): Client %v, Direct %v", name, empty, wantErr, gotErr)
			require.Equal(t, encode(t, want), encode(t, got), "%s (empty %v)", name, empty)
			require.Equal(t, wantAsked, backend.told(), "%s (empty %v)", name, empty)
		}
	}
	// both tell the version of the protocol
	status, err := Direct{Backend: backend}.Status()
	require.NoError(t, err)
	require.Equal(t, ProtocolVersion, status.Protocol)
	cancel()
	require.NoError(t, <-served)
}

func encode(t *testing.T, value any) string {
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return string(encoded)
}

// An answer is waited for as long as Client waits, and no longer than its context: the backend is
// told that no one waits for it, and what it answers then is none.
func TestDirectWaits(t *testing.T) {
	backend := &fixed{block: true}
	// the time of the question: probeSlack longer than its wait
	started := time.Now()
	result, err := Direct{Backend: backend}.Probe("0a1b2c3d4e5f", 100*time.Millisecond-probeSlack)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, result)
	require.Less(t, time.Since(started), probeSlack)
	require.Eventually(t, func() bool { return strings.HasSuffix(backend.told(), "probe ended") }, 5*time.Second, 10*time.Millisecond)
	// the time is up, whether the backend answers or not
	for range 20 {
		answer, err := ask(Direct{}, time.Millisecond, func(ctx context.Context) (int, error) { <-ctx.Done(); return 1, nil })
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Zero(t, answer)
	}
	// the end of what the question is asked for
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = Direct{Backend: backend, Context: ctx}.Probe("0a1b2c3d4e5f", 0)
	require.ErrorIs(t, err, context.Canceled)
}

// A fault of the backend is an error, as it is for Client: it does not end the backend.
func TestDirectSurvives(t *testing.T) {
	_, err := ask(Direct{}, time.Minute, func(context.Context) (int, error) { panic("a fault") })
	require.ErrorContains(t, err, "a fault")
	_, err = ask(Direct{}, time.Minute, func(context.Context) (int, error) { panic(errors.New("a fault")) })
	require.ErrorContains(t, err, "a fault")
	// no Backend at all
	_, err = Direct{}.Status()
	require.Error(t, err)
}
