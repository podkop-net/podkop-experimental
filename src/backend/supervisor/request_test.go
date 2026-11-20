package supervisor

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"

	"github.com/stretchr/testify/require"
)

const twoServers = "vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\nvless://u2@nl2.example:443?security=tls&sni=nl2.example#NL%202\n"

// requestSettings are the settings of the tests with what the subscription prov1 is asked with.
func requestSettings(directory string, lines string) string {
	return strings.Replace(subscriptionSettings(directory, "all"), "\toption update_interval '1h'\n", "\toption update_interval '1h'\n"+lines, 1)
}

// logged keeps the lines of the log of a subscription.
type logged struct {
	access sync.Mutex
	lines  []string
}

func (l *logged) log(level string, message string) {
	if strings.HasPrefix(message, "subscription prov1: ") {
		l.access.Lock()
		l.lines = append(l.lines, "["+level+"] "+message)
		l.access.Unlock()
	}
}

func (l *logged) count(part string) int {
	l.access.Lock()
	defer l.access.Unlock()
	count := 0
	for _, line := range l.lines {
		if strings.Contains(line, part) {
			count++
		}
	}
	return count
}

func requestOptions(directory string, source *provider, fake *fakeEngine, lines *logged) Options {
	return Options{
		SettingsPath: filepath.Join(directory, "podkop"), RuleSetDir: filepath.Join(directory, "rulesets"),
		StagingDir: filepath.Join(directory, "candidate"), StatePath: filepath.Join(directory, "state"),
		ConfigDir: filepath.Join(directory, "run"), ReadyTimeout: time.Second, System: new(recorder), Engine: fake,
		SubscriptionDir: filepath.Join(directory, "subscriptions"), Version: "0.8.5",
		Device: subscription.Device{HWID: "0123456789abcdef0123456789abcdef"}, Download: source.download, Log: lines.log,
	}
}

// The provider is asked with the User-Agent and the headers of the settings and the router's own
// HWID; a line that cannot be sent is left out, told once an apply (not again for the
// configuration checked after a swap sing-box refused), and shown in the state.
func TestSubscriptionRequestOfTheSettings(t *testing.T) {
	directory := t.TempDir()
	fake := &fakeEngine{refuse: map[string]error{}}
	source := &provider{body: "vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\n"}
	lines := new(logged)
	options := requestOptions(directory, source, fake, lines)
	settings := requestSettings(directory, "\toption user_agent 'INCY'\n\tlist header 'Authorization: Bearer t'\n\tlist header 'x-hwid: fake'\n")
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(settings), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	defer s.Stop()
	warning := "[warn] subscription prov1: header 2 (x-hwid) of the settings is left out: podkop sends the device identifier itself"
	require.Equal(t, 1, lines.count(warning))
	// the list taken applies the settings again, and tells it again, as the warnings of the plan
	downloadNow(t, s)
	require.Equal(t, 2, lines.count(warning))
	header := source.headers[0]
	require.Equal(t, "INCY", header.Get("User-Agent"))
	require.Equal(t, "Bearer t", header.Get("Authorization"))
	require.Equal(t, "0123456789abcdef0123456789abcdef", header.Get("x-hwid"))
	state := s.subscriptionStates()[0]
	require.Equal(t, "INCY", state.Agent)
	require.Equal(t, []string{"Authorization"}, state.Headers)
	require.Equal(t, []api.RequestProblem{{Line: 2, Name: "x-hwid", Code: "device", Text: "podkop sends the device identifier itself"}}, state.Problems)
	require.Equal(t, 1, lines.count("1 servers, 1 can be used (direct in 0.8 s; User-Agent INCY)"))

	// another apply tells it again
	require.True(t, s.Apply().OK)
	require.Equal(t, 3, lines.count(warning))
	// a new server sing-box does not take while it runs: the configuration checked after it is
	// built of the same settings, and tells nothing again
	fake.access.Lock()
	fake.swapRefused = []string{"NL 2"}
	built := len(fake.built)
	fake.access.Unlock()
	source.serve(twoServers)
	downloadNow(t, s)
	require.Greater(t, len(fake.built), built, "checked and started anew")
	require.Equal(t, 4, lines.count(warning))
	require.Zero(t, lines.count("Bearer"))
	require.Zero(t, lines.count("fake"))
}

// Another User-Agent for the same address keeps the list in use and downloads it again soon; the
// answer to the new one that podkop cannot read is told as such, and the list stays. Another
// address drops the list, as before.
func TestSubscriptionRequestChanged(t *testing.T) {
	directory := t.TempDir()
	fake := &fakeEngine{refuse: map[string]error{}}
	source := &provider{body: twoServers}
	lines := new(logged)
	options := requestOptions(directory, source, fake, lines)
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(requestSettings(directory, "\toption user_agent 'INCY'\n")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	defer s.Stop()
	downloadNow(t, s)
	require.Len(t, s.servers()["prov1"], 2)
	s.subscriptions.access.Lock()
	s.subscriptions.failures = map[string]int{"prov1": 2}
	s.subscriptions.access.Unlock()

	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(requestSettings(directory, "\toption user_agent 'SFA/1.11'\n")), 0o644))
	require.True(t, s.Apply().OK)
	require.Len(t, s.servers()["prov1"], 2, "the list in use stays")
	state := s.subscriptionStates()[0]
	require.Equal(t, "SFA/1.11", state.Agent)
	require.WithinDuration(t, time.Now().Add(firstDownloadDelay), *state.Next, 3*time.Second)
	require.Zero(t, s.subscriptions.failures["prov1"])
	require.Equal(t, 1, lines.count("[info] subscription prov1: the User-Agent or the headers changed: the list is downloaded again in 10 s, the one in use stays until then"))
	// the same again changes nothing
	require.True(t, s.Apply().OK)
	require.Equal(t, 1, lines.count("the User-Agent or the headers changed"))

	source.serve(`{"outbounds":[{"type":"vless"}]}`)
	downloadNow(t, s)
	state = s.subscriptionStates()[0]
	require.Equal(t, "json-agent", state.ErrorCode)
	require.Contains(t, state.Error, `"SFA/1.11"`)
	require.Equal(t, 2, state.Servers)
	require.Len(t, s.servers()["prov1"], 2)
	require.Equal(t, "SFA/1.11", source.headers[len(source.headers)-1].Get("User-Agent"))

	// the control: another address drops the list
	moved := strings.Replace(requestSettings(directory, "\toption user_agent 'SFA/1.11'\n"), "https://sub.example/api/sub/TOKEN", "https://sub.example/api/sub/OTHER", 1)
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(moved), 0o644))
	s.Apply()
	require.Empty(t, s.servers()["prov1"])
}

// A download under way when the User-Agent changes: its answer is not taken, and the list is
// downloaded again with the new one at once.
func TestSubscriptionRequestChangedWhileBusy(t *testing.T) {
	directory := t.TempDir()
	fake := &fakeEngine{refuse: map[string]error{}}
	source := &provider{body: "vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\n"}
	lines := new(logged)
	options := requestOptions(directory, source, fake, lines)
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(requestSettings(directory, "\toption user_agent 'INCY'\n")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	defer s.Stop()
	downloadNow(t, s)
	require.Len(t, s.servers()["prov1"], 1)

	source.access.Lock()
	source.block = make(chan struct{})
	source.body = twoServers
	source.access.Unlock()
	s.downloadDue(time.Now(), "prov1")
	require.True(t, s.subscriptionStates()[0].Busy)
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(requestSettings(directory, "\toption user_agent 'Happ'\n")), 0o644))
	require.True(t, s.Apply().OK)
	close(source.block)
	old := <-s.downloads
	s.takeList(old)
	require.Len(t, s.servers()["prov1"], 1, "the answer to the old User-Agent is not taken")
	require.True(t, s.subscriptionStates()[0].Busy, "downloaded again at once")
	fresh := <-s.downloads
	require.NotEqual(t, old.request, fresh.request)
	s.takeList(fresh)
	require.Len(t, s.servers()["prov1"], 2)
	require.Equal(t, "Happ", source.headers[len(source.headers)-1].Get("User-Agent"))
	require.Equal(t, "INCY", source.headers[len(source.headers)-2].Get("User-Agent"))
}

// A download that stops on a fault of podkop, with a User-Agent of the settings, is a failure of
// the request of now: it backs off, it is not tried again at every tick.
func TestSubscriptionRequestFaultBacksOff(t *testing.T) {
	directory := t.TempDir()
	fake := &fakeEngine{refuse: map[string]error{}}
	source := &provider{body: twoServers}
	lines := new(logged)
	options := requestOptions(directory, source, fake, lines)
	options.Download = func(context.Context, string, http.Header, []subscription.Route, subscription.Plan, func([]subscription.Try)) (*subscription.Answer, []subscription.Try, error) {
		panic("a fault of the test")
	}
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(requestSettings(directory, "\toption user_agent 'INCY'\n")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	defer s.Stop()
	downloadNow(t, s)
	state := s.subscriptionStates()[0]
	require.Equal(t, "fault", state.ErrorCode)
	require.WithinDuration(t, time.Now().Add(time.Minute), *state.Next, 5*time.Second, "the backoff of a subscription with no list")
}

// Load asks with the request of the form: a list asked with one User-Agent is not that of
// another, an address keeps the newest list only, and a request that cannot be sent fails at
// once with what cannot be.
func TestSubscriptionRequestPreviews(t *testing.T) {
	directory := t.TempDir()
	fake := &fakeEngine{refuse: map[string]error{}}
	source := &provider{body: twoServers}
	lines := new(logged)
	options := requestOptions(directory, source, fake, lines)
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(subscriptionSettings(directory, "all")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	defer s.Stop()
	const address = "https://other.example/sub/X"
	incy, sfa := api.ListRequest{UserAgent: "INCY"}, api.ListRequest{UserAgent: "SFA/1.11"}
	preview := s.LoadSubscription(context.Background(), address, incy)
	require.Empty(t, preview.Error)
	require.Equal(t, "INCY", preview.Agent)
	require.Equal(t, "INCY", source.headers[len(source.headers)-1].Get("User-Agent"))

	group := func(request api.ListRequest) GroupPreview {
		return s.CheckGroup(context.Background(), GroupCheck{Subscriptions: []string{"fresh"}, Addresses: map[string]string{"fresh": address}, Requests: map[string]api.ListRequest{"fresh": request}})
	}
	asked := len(source.headers)
	require.Equal(t, 2, group(incy).Total)
	require.Equal(t, asked, len(source.headers), "the list Load got with the same request")
	require.Equal(t, 2, group(sfa).Total)
	require.Equal(t, asked+1, len(source.headers), "another User-Agent is downloaded")
	require.Equal(t, "SFA/1.11", source.headers[len(source.headers)-1].Get("User-Agent"))
	require.Equal(t, 2, group(incy).Total)
	require.Equal(t, asked+2, len(source.headers), "the address keeps the newest list only")
	s.subscriptions.access.Lock()
	require.Len(t, s.subscriptions.previews, 1)
	s.subscriptions.access.Unlock()

	// a subscription added with the address and the request of the last Load has its servers at
	// the apply; one added with another User-Agent has none until it is downloaded
	s.LoadSubscription(context.Background(), address, sfa)
	s.LoadSubscription(context.Background(), "https://third.example/sub/Y", incy)
	settings, err := os.ReadFile(options.SettingsPath)
	require.NoError(t, err)
	settings = append(settings, []byte("\nconfig source 'fresh'\n\toption type 'subscription'\n\toption url '"+address+"'\n\toption user_agent 'SFA/1.11'\n"+
		"\nconfig source 'other'\n\toption type 'subscription'\n\toption url 'https://third.example/sub/Y'\n\toption user_agent 'Happ'\n")...)
	require.NoError(t, os.WriteFile(options.SettingsPath, settings, 0o644))
	asked = len(source.headers)
	require.True(t, s.Apply().OK)
	require.Equal(t, asked, len(source.headers))
	for _, state := range s.subscriptionStates() {
		switch state.Name {
		case "fresh":
			require.Equal(t, 2, state.Servers)
		case "other":
			require.Nil(t, state.Changed, "Load asked with another User-Agent")
		}
	}

	// a request that cannot be sent: at once, by its code, without the value
	refused := s.StartLoad(context.Background(), address, api.ListRequest{UserAgent: "INCY", Headers: []string{"X-Kept: 1", "x-hwid: s3cret"}})
	require.Equal(t, "failed", refused.State)
	require.Equal(t, "request", refused.Preview.ErrorCode)
	require.Equal(t, []string{"device", "2", "x-hwid"}, refused.Preview.ErrorArgs)
	require.NotContains(t, refused.Preview.Error, "s3cret")
	require.Equal(t, "request", s.LoadSubscription(context.Background(), address, api.ListRequest{UserAgent: "a\nb"}).ErrorCode)
}

// Two Loads of one address with other requests are two jobs; the same request is the same job.
func TestSubscriptionRequestLoadJobs(t *testing.T) {
	directory := t.TempDir()
	fake := &fakeEngine{refuse: map[string]error{}}
	source := &provider{body: twoServers, block: make(chan struct{})}
	lines := new(logged)
	options := requestOptions(directory, source, fake, lines)
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(subscriptionSettings(directory, "all")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	defer s.Stop()
	ctx := context.Background()
	first := s.StartLoad(ctx, "https://one.example/sub/A", api.ListRequest{UserAgent: "INCY"})
	second := s.StartLoad(ctx, "https://one.example/sub/A", api.ListRequest{UserAgent: "Happ"})
	require.NotEqual(t, first.ID, second.ID)
	require.Equal(t, first.ID, s.StartLoad(ctx, "https://one.example/sub/A", api.ListRequest{UserAgent: " INCY "}).ID)
	close(source.block)
	require.Eventually(t, func() bool {
		job, _ := s.LoadState(ctx, second.ID)
		return job.State == "done"
	}, 5*time.Second, 20*time.Millisecond)
	job, _ := s.LoadState(ctx, second.ID)
	require.Equal(t, "Happ", job.Preview.Agent)
}

// The group check takes the request of the form as the settings take it: the same raw lines, an
// invalid one among them, are the request that runs, and its list is used without a download;
// another User-Agent is downloaded with it.
func TestSubscriptionRequestGroupCheck(t *testing.T) {
	directory := t.TempDir()
	fake := &fakeEngine{refuse: map[string]error{}}
	source := &provider{body: twoServers}
	lines := new(logged)
	options := requestOptions(directory, source, fake, lines)
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(requestSettings(directory, "\toption user_agent 'INCY'\n\tlist header 'x-hwid: fake'\n")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	defer s.Stop()
	downloadNow(t, s)
	asked := len(source.headers)
	check := func(requests map[string]api.ListRequest) GroupPreview {
		return s.CheckGroup(context.Background(), GroupCheck{Subscriptions: []string{"prov1"}, Include: []string{"nl"}, Addresses: map[string]string{"prov1": "https://sub.example/api/sub/TOKEN"}, Requests: requests})
	}
	require.Equal(t, 2, check(map[string]api.ListRequest{"prov1": {UserAgent: "INCY", Headers: []string{"x-hwid: fake"}}}).Total)
	require.Equal(t, 2, check(nil).Total)
	require.Equal(t, asked, len(source.headers), "the list taken")
	require.Equal(t, 2, check(map[string]api.ListRequest{"prov1": {UserAgent: "SFA/1.11"}}).Total)
	require.Equal(t, asked+1, len(source.headers))
	require.Equal(t, "SFA/1.11", source.headers[len(source.headers)-1].Get("User-Agent"))
	require.Equal(t, "0123456789abcdef0123456789abcdef", source.headers[len(source.headers)-1].Get("x-hwid"))
}
