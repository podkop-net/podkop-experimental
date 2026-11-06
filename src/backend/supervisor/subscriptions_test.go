package supervisor

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"

	"github.com/stretchr/testify/require"
)

// provider is a subscription of a test: the list it serves now, and the routes it was asked
// by.
type provider struct {
	access sync.Mutex
	body   string
	// block, when set, holds every download until it is closed or the download ends
	block chan struct{}
	// refused are the routes that do not reach it; with refuseAll none does
	refused   []string
	refuseAll bool
	asked     []string
	headers   []http.Header
	plans     []subscription.Plan
	// answer are the headers it answers with
	answer http.Header
}

func (p *provider) answerWith(header http.Header) {
	p.access.Lock()
	p.answer = header
	p.access.Unlock()
}

func (p *provider) serve(body string) {
	p.access.Lock()
	p.body = body
	p.access.Unlock()
}

func (p *provider) download(ctx context.Context, address string, header http.Header, routes []subscription.Route, plan subscription.Plan, report func([]subscription.Try)) (*subscription.Answer, []subscription.Try, error) {
	if p.block != nil {
		select {
		case <-p.block:
		case <-ctx.Done():
			return nil, nil, &subscription.Failure{Code: "unreachable", Text: "the provider could not be reached"}
		}
	}
	p.access.Lock()
	defer p.access.Unlock()
	p.headers = append(p.headers, header)
	p.plans = append(p.plans, plan)
	var tries []subscription.Try
	for _, route := range routes {
		p.asked = append(p.asked, route.Name)
		refused := p.refuseAll
		for _, name := range p.refused {
			refused = refused || name == route.Name
		}
		if !refused {
			tries = append(tries, subscription.Try{Route: route.Name, Phase: subscription.PhaseDone, Took: 800 * time.Millisecond, FirstByte: 700 * time.Millisecond, Pause: 10 * time.Millisecond, Bytes: int64(len(p.body))})
			header := http.Header{}
			for key, values := range p.answer {
				header[key] = values
			}
			return &subscription.Answer{Body: []byte(p.body), Header: header, Route: route.Name}, tries, nil
		}
		tries = append(tries, subscription.Try{Route: route.Name, Phase: subscription.PhaseFailed, Took: 5 * time.Second, Failure: &subscription.Failure{Code: "timeout", Args: []string{"5"}, Text: "no answer in 5 s"}})
	}
	return nil, tries, &subscription.Failure{Code: "unreachable", Text: "the provider could not be reached"}
}

func subscriptionSettings(directory string, empty string) string {
	return "config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '127.0.0.1:9'\n" +
		"\toption cache_path '" + filepath.Join(directory, "cache.db") + "'\n\toption yacd_secret_key 'k'\n" +
		"\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n" +
		"\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'main.lab.example'\n" +
		"\nconfig subscription 'prov1'\n\toption url 'https://sub.example/api/sub/TOKEN'\n\toption update_interval '1h'\n" +
		"\nconfig group 'nl'\n\tlist subscription 'prov1'\n\tlist include 'NL'\n\toption empty '" + empty + "'\n" +
		"\nconfig section 'youtube'\n\toption connection_type 'group'\n\toption group 'nl'\n" +
		"\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'youtube.lab.example'\n"
}

// download runs a download of every subscription now, as Run would, and takes what it came to:
// each is made due, not asked for (a download asked for by hand that fails keeps the time
// planned before).
func downloadNow(t *testing.T, s *Supervisor) {
	t.Helper()
	s.subscriptions.access.Lock()
	past := time.Now().Add(-time.Second)
	for _, state := range s.subscriptions.states {
		state.Next = &past
	}
	s.subscriptions.access.Unlock()
	s.downloadDue(time.Now(), "")
	select {
	case result := <-s.downloads:
		s.takeList(result)
	case <-time.After(10 * time.Second):
		t.Fatal("no download came back")
	}
}

// The list of a subscription is taken, kept on flash and used at the next start; sing-box
// takes the servers while it runs, renamed ones too; a list the provider only reordered changes
// nothing; when sing-box does not take the servers, the configuration starts anew.
func TestSubscriptionLists(t *testing.T) {
	directory := t.TempDir()
	fake, system := &fakeEngine{refuse: map[string]error{}}, new(recorder)
	source := &provider{body: "vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\nvless://u2@de1.example:443?security=tls&sni=de1.example#DE%201\n"}
	options := Options{
		SettingsPath: filepath.Join(directory, "podkop"), RuleSetDir: filepath.Join(directory, "rulesets"),
		StagingDir: filepath.Join(directory, "candidate"), StatePath: filepath.Join(directory, "state"),
		ConfigDir: filepath.Join(directory, "run"), ReadyTimeout: time.Second, System: system, Engine: fake,
		SubscriptionDir: filepath.Join(directory, "subscriptions"), Version: "0.8.5",
		Device: subscription.Device{HWID: "0123456789abcdef0123456789abcdef"}, Download: source.download,
	}
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(subscriptionSettings(directory, "block")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	// no list yet: the group refuses
	require.NotContains(t, string(s.current.result.Config), "prov1: NL 1")
	require.Equal(t, 1, len(fake.built))

	downloadNow(t, s)
	require.Len(t, fake.built, 1, "sing-box takes the servers while it runs")
	require.Len(t, fake.swaps, 1)
	require.Equal(t, string(s.current.result.Config), string(fake.built[0].config))
	config := string(s.current.result.Config)
	require.Contains(t, config, `"prov1: NL 1"`)
	require.NotContains(t, config, `"prov1: DE 1"`, "a server the group does not choose has no outbound")
	require.Equal(t, "0123456789abcdef0123456789abcdef", source.headers[0].Get("x-hwid"))
	require.Equal(t, "podkop/0.8.5", source.headers[0].Get("User-Agent"))
	states := s.subscriptionStates()
	require.Len(t, states, 1)
	require.Equal(t, 2, states[0].Servers)
	require.Equal(t, "direct", states[0].Route)
	file, err := os.Stat(filepath.Join(directory, "subscriptions", "prov1.json"))
	require.NoError(t, err)
	written := file.ModTime()

	// only the order changed: nothing is written, nothing changes
	source.serve("vless://u2@de1.example:443?security=tls&sni=de1.example#DE%201\nvless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\n")
	time.Sleep(10 * time.Millisecond)
	downloadNow(t, s)
	require.Len(t, fake.swaps, 1)
	file, err = os.Stat(filepath.Join(directory, "subscriptions", "prov1.json"))
	require.NoError(t, err)
	require.Equal(t, written, file.ModTime())

	// only the names changed: the list is taken and its names shown, sing-box keeps running
	source.serve("vless://u2@de1.example:443?security=tls&sni=de1.example#DE%201%20(29%20days)\nvless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201%20(29%20days)\n")
	downloadNow(t, s)
	require.Len(t, fake.built, 1)
	require.Len(t, fake.swaps, 2)
	require.Equal(t, []string{"prov1: NL 1"}, fake.swaps[1].Remove)
	file, err = os.Stat(filepath.Join(directory, "subscriptions", "prov1.json"))
	require.NoError(t, err)
	require.NotEqual(t, written, file.ModTime())
	require.Contains(t, string(s.current.result.Config), `"prov1: NL 1 (29 days)"`)
	require.Equal(t, &api.ListChanges{Renamed: 2}, s.subscriptionStates()[0].Changes)

	// the same servers, the names swapped: what the group chooses changes
	source.serve("vless://u1@nl1.example:443?security=tls&sni=nl1.example#DE%201\nvless://u2@de1.example:443?security=tls&sni=de1.example#NL%201\n")
	downloadNow(t, s)
	require.Len(t, fake.built, 1)
	require.Contains(t, string(s.current.result.Config), `"server": "de1.example"`)
	require.NotContains(t, string(s.current.result.Config), `"server": "nl1.example"`)

	// another server, which sing-box does not take while it runs: the configuration is checked
	// and started anew
	fake.swapRefused = []string{"NL 2"}
	checked := fake.checked
	source.serve("vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\nvless://u3@nl2.example:443?security=tls&sni=nl2.example#NL%202\n")
	downloadNow(t, s)
	require.Len(t, fake.built, 2)
	require.Equal(t, checked+1, fake.checked, "checked before it replaces the one that runs")
	require.Equal(t, 1, fake.carried, "the choices of the dashboard go with the servers renamed")
	require.Empty(t, fake.selected)
	require.Contains(t, string(s.current.result.Config), `"prov1: NL 2"`)
	require.Equal(t, &api.ListChanges{Renamed: 1, Removed: 1, Added: 1}, s.subscriptionStates()[0].Changes)
	s.Stop()

	// the next start has the list before any download
	again := New(options)
	require.True(t, again.Boot().OK)
	require.Contains(t, string(again.current.result.Config), `"prov1: NL 2"`)

	// another server, and a configuration that does not come up: the previous one runs again,
	// with the choices of the dashboard it had
	fake.swapRefused = []string{"NL 3"}
	fake.failing = []string{"NL 3"}
	fake.carry = map[string]string{"g-out": "prov1: NL 2"}
	built := len(fake.built)
	source.serve("vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\nvless://u4@nl3.example:443?security=tls&sni=nl3.example#NL%203\n")
	downloadNow(t, again)
	require.Len(t, fake.built, built+2, "the new one, and the previous one again")
	require.Contains(t, string(again.current.result.Config), `"prov1: NL 2"`)
	require.Equal(t, []map[string]string{{"g-out": "prov1: NL 2"}}, fake.selected)
	again.Stop()

	// a subscription the settings no longer have is forgotten, its file too
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(strings.Split(subscriptionSettings(directory, "block"), "\nconfig subscription")[0]), 0o644))
	third := New(options)
	require.True(t, third.Boot().OK)
	_, err = os.Stat(filepath.Join(directory, "subscriptions", "prov1.json"))
	require.True(t, os.IsNotExist(err))
	third.Stop()
}

// linkRoute is the way through the proxy link of the settings of the tests: the source main_link
// (podkop migrate) has no label, and its tag is the name the page gives it.
const linkRoute = "socks5 203.0.113.15:1080"

// The provider is asked directly first, then through the servers of the configuration, the
// fastest first; a list that cannot be downloaded keeps the one there was.
func TestSubscriptionRoutes(t *testing.T) {
	directory := t.TempDir()
	fake, system := &fakeEngine{refuse: map[string]error{}, delays: map[string]uint16{"prov1: NL 2": 90, "prov1: NL 1": 300}}, new(recorder)
	source := &provider{body: "vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\nvless://u2@nl2.example:443?security=tls&sni=nl2.example#NL%202\n"}
	options := Options{
		SettingsPath: filepath.Join(directory, "podkop"), RuleSetDir: filepath.Join(directory, "rulesets"),
		StagingDir: filepath.Join(directory, "candidate"), StatePath: filepath.Join(directory, "state"),
		ConfigDir: filepath.Join(directory, "run"), ReadyTimeout: time.Second, System: system, Engine: fake,
		SubscriptionDir: filepath.Join(directory, "subscriptions"), Download: source.download,
	}
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(subscriptionSettings(directory, "all")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	downloadNow(t, s)
	require.Equal(t, []string{"direct"}, source.asked)
	routes, _ := s.routes(3, "")
	var names []string
	for _, route := range routes {
		names = append(names, route.Name)
	}
	// a way is named as the page names the outbound: the server, or the section of a link
	require.Equal(t, []string{"direct", "prov1: NL 2", "prov1: NL 1", linkRoute}, names)
	// the way that brought the list the last time first among the servers
	routes, _ = s.routes(3, linkRoute)
	require.Equal(t, linkRoute, routes[1].Name)
	// direct goes through direct-out of sing-box while it runs
	fake.dial = func(ctx context.Context, tag string, address string) (net.Conn, error) { return nil, os.ErrClosed }
	_, _ = routes[0].Dial(context.Background(), "tcp", "sub.example:443")
	require.Equal(t, []string{"direct-out"}, fake.dialed)

	// blocked directly: through the fastest server
	source.asked = nil
	source.refused = []string{"direct"}
	source.serve("vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\n")
	downloadNow(t, s)
	require.Equal(t, []string{"direct", "prov1: NL 2"}, source.asked)
	state := s.subscriptionStates()[0]
	require.Equal(t, "prov1: NL 2", state.Route)
	require.Equal(t, int64(800), state.Took)
	require.Len(t, state.Attempts, 2)
	require.Equal(t, "timeout", state.Attempts[0].Code)
	require.NotNil(t, state.Attempted)
	require.NotNil(t, state.Now)
	// the plan of the next download: by the downloads that brought a list (0.7 s to the first
	// byte, 0.8 s in all: the floors), the direct way beside the server that brought it now
	plan, first := s.planOf(subscription.AddressKey("https://sub.example/api/sub/TOKEN"))
	require.Equal(t, subscription.Plan{Wait: 2 * time.Second, Body: 2 * time.Second, Total: 5 * time.Second, Together: true}, plan)
	require.Equal(t, "prov1: NL 2", first)

	// nothing reaches it: the list there was stays, the error is told with its code (the
	// server that brought the list is gone with it: the order of the delays)
	source.asked = nil
	source.refused = []string{"direct", "prov1: NL 1", "prov1: NL 2", linkRoute}
	downloadNow(t, s)
	require.Equal(t, []string{"direct", "prov1: NL 1", linkRoute}, source.asked)
	require.True(t, source.plans[len(source.plans)-1].Together)
	state = s.subscriptionStates()[0]
	require.NotEmpty(t, state.Error)
	require.Equal(t, "unreachable", state.ErrorCode)
	require.Equal(t, 1, state.Servers)
	require.WithinDuration(t, time.Now().Add(10*time.Minute), *state.Next, 5*time.Second, "a list there was: again in 10 minutes")
	require.Contains(t, string(s.current.result.Config), `"prov1: NL 1"`)
	s.Stop()
}

// A subscription with no list is tried again after 1, 2, 4, 8 and then every 10 minutes; at
// most two downloads run at once, the others wait for a place.
func TestSubscriptionRetriesAndPlaces(t *testing.T) {
	require.Equal(t, []time.Duration{time.Minute, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 10 * time.Minute, 10 * time.Minute},
		[]time.Duration{downloadBackoff(0), downloadBackoff(1), downloadBackoff(2), downloadBackoff(3), downloadBackoff(4), downloadBackoff(5), downloadBackoff(9)})
	// a subscription that never brings a list: the shift would overflow after 28 failures
	for _, failures := range []int{29, 54, 64, 1000} {
		require.Equal(t, downloadRetry, downloadBackoff(failures), failures)
	}

	directory := t.TempDir()
	fake, system := &fakeEngine{refuse: map[string]error{}}, new(recorder)
	source := &provider{body: "vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\n", refused: []string{"direct", linkRoute}}
	options := Options{
		SettingsPath: filepath.Join(directory, "podkop"), RuleSetDir: filepath.Join(directory, "rulesets"),
		StagingDir: filepath.Join(directory, "candidate"), StatePath: filepath.Join(directory, "state"),
		ConfigDir: filepath.Join(directory, "run"), ReadyTimeout: time.Second, System: system, Engine: fake,
		Download: source.download,
	}
	settings := subscriptionSettings(directory, "block")
	for _, name := range []string{"prov2", "prov3"} {
		settings += "\nconfig subscription '" + name + "'\n\toption url 'https://other.example/sub/" + name + "'\n"
	}
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(settings), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	s.downloadDue(time.Now(), "*")
	busy := 0
	for _, state := range s.subscriptionStates() {
		if state.Busy {
			busy++
		}
	}
	require.Equal(t, 2, busy, "two at once")
	first := <-s.downloads
	s.takeList(first)
	state := s.subscriptions.states[first.name]
	require.Equal(t, "unreachable", state.ErrorCode)
	require.WithinDuration(t, time.Now().Add(time.Minute), *state.Next, 5*time.Second, "no list: again in a minute")
	busy = 0
	for _, state := range s.subscriptionStates() {
		if state.Busy {
			busy++
		}
	}
	require.Equal(t, 2, busy, "the third took the place that came free")
	s.takeList(<-s.downloads)
	s.takeList(<-s.downloads)
	s.downloadDue(time.Now(), first.name)
	s.takeList(<-s.downloads)
	require.WithinDuration(t, time.Now().Add(2*time.Minute), *s.subscriptions.states[first.name].Next, 5*time.Second, "the second failure: 2 minutes")
	s.Stop()
}

// The page sees a list without taking it, and the servers a group of its form would choose.
func TestSubscriptionPreviews(t *testing.T) {
	directory := t.TempDir()
	fake, system := &fakeEngine{refuse: map[string]error{}, unusable: []string{"vmess://"}}, new(recorder)
	source := &provider{body: "vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\nvmess://eyJhZGQiOiJ4In0=#VM\nvless://u2@de1.example:443?security=tls&sni=de1.example#DE%201\n"}
	options := Options{
		SettingsPath: filepath.Join(directory, "podkop"), RuleSetDir: filepath.Join(directory, "rulesets"),
		StagingDir: filepath.Join(directory, "candidate"), StatePath: filepath.Join(directory, "state"),
		ConfigDir: filepath.Join(directory, "run"), ReadyTimeout: time.Second, System: system, Engine: fake,
		SubscriptionDir: filepath.Join(directory, "subscriptions"), Download: source.download,
	}
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(subscriptionSettings(directory, "all")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	preview := s.LoadSubscription(context.Background(), "https://other.example/sub/X")
	require.Empty(t, preview.Error)
	require.Len(t, preview.Servers, 3)
	require.Equal(t, "NL 1", preview.Servers[0].Name)
	require.Equal(t, "vless", preview.Servers[0].Scheme)
	require.Equal(t, "nl1.example:443", preview.Servers[0].Address)
	require.NotEmpty(t, preview.Servers[1].Reason)
	require.Len(t, fake.built, 1, "a preview takes nothing")
	_, err := os.Stat(filepath.Join(directory, "subscriptions"))
	require.True(t, os.IsNotExist(err), "a preview writes nothing")

	// a subscription of the settings without a list is downloaded for the check, not taken
	check := s.CheckGroup(context.Background(), GroupCheck{Subscriptions: []string{"prov1", "prov1", "gone"}, Include: []string{"nl", "de"}, Exclude: []string{"de 1"}})
	require.Equal(t, []string{"NL 1"}, check.Chosen)
	require.Equal(t, 2, check.Total)
	require.Equal(t, []string{"gone: the address is not set"}, check.Missing)
	require.Len(t, fake.built, 1)

	// a subscription not saved yet: the address of the form; the list Load got is used again
	asked := len(source.asked)
	check = s.CheckGroup(context.Background(), GroupCheck{Subscriptions: []string{"fresh"}, Include: []string{"nl"}, Addresses: map[string]string{"fresh": "https://other.example/sub/X"}})
	require.Equal(t, []string{"NL 1"}, check.Chosen)
	require.Empty(t, check.Missing)
	require.Equal(t, asked, len(source.asked), "the list Load got for the address")
	check = s.CheckGroup(context.Background(), GroupCheck{Subscriptions: []string{"fresh"}, Addresses: map[string]string{"fresh": "https://third.example/sub/Y"}})
	require.Equal(t, 2, check.Total)
	require.Greater(t, len(source.asked), asked, "another address is downloaded")
	require.Len(t, fake.built, 1)

	// a subscription added with the address Load just got: its servers are there at the apply
	// that adds it, before any download, and kept on flash
	asked = len(source.asked)
	settings, err := os.ReadFile(options.SettingsPath)
	require.NoError(t, err)
	// the daemon converted the file at the boot: what the page adds is of the format 2
	settings = append(settings, []byte("\nconfig source 'fresh'\n\toption type 'subscription'\n\toption url 'https://other.example/sub/X'\n"+
		"\nconfig section 'third'\n\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'third.lab.example'\n"+
		"\nconfig member\n\toption section 'third'\n\toption role 'server'\n\toption source 'fresh'\n")...)
	require.NoError(t, os.WriteFile(options.SettingsPath, settings, 0o644))
	require.True(t, s.Apply().OK)
	require.Contains(t, string(s.current.result.Config), `"other.example: NL 1"`)
	require.Equal(t, asked, len(source.asked))
	for _, state := range s.subscriptionStates() {
		if state.Name == "fresh" {
			require.WithinDuration(t, time.Now().Add(firstDownloadDelay), *state.Next, 5*time.Second, "downloaded soon all the same")
		}
	}
	_, err = os.Stat(filepath.Join(directory, "subscriptions", "fresh.json"))
	require.NoError(t, err)
	s.Stop()
}

// Two lists that come in the same round make one new configuration, after the last of them:
// no download loses the sing-box it goes through to a new configuration.
func TestSubscriptionRoundAppliesOnce(t *testing.T) {
	directory := t.TempDir()
	fake, system := &fakeEngine{refuse: map[string]error{}}, new(recorder)
	source := &provider{body: "vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\n"}
	options := Options{
		SettingsPath: filepath.Join(directory, "podkop"), RuleSetDir: filepath.Join(directory, "rulesets"),
		StagingDir: filepath.Join(directory, "candidate"), StatePath: filepath.Join(directory, "state"),
		ConfigDir: filepath.Join(directory, "run"), ReadyTimeout: time.Second, System: system, Engine: fake,
		Download: source.download,
	}
	settings := subscriptionSettings(directory, "block") + "\nconfig subscription 'prov2'\n\toption url 'https://other.example/sub/2'\n" +
		"\nconfig group 'two'\n\tlist subscription 'prov2'\n" +
		"\nconfig section 'second'\n\toption connection_type 'group'\n\toption group 'two'\n\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'second.lab.example'\n"
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(settings), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	require.Len(t, fake.built, 1)
	s.downloadDue(time.Now(), "*")
	first := <-s.downloads
	s.takeList(first)
	require.Len(t, fake.built, 1, "the other download is under way")
	second := <-s.downloads
	s.takeList(second)
	require.Len(t, fake.built, 1)
	require.Len(t, fake.swaps, 1, "one change for both lists")
	config := string(s.current.result.Config)
	require.Contains(t, config, `"prov1: NL 1"`)
	require.Contains(t, config, `"prov2: NL 1"`)

	// a download whose sing-box was replaced meanwhile is tried again at the next tick
	before := s.current.instance
	s.takeList(downloaded{name: "prov1", address: "https://sub.example/api/sub/TOKEN", err: os.ErrDeadlineExceeded, through: &fakeInstance{}})
	state := s.subscriptionStates()[0]
	require.Equal(t, "prov1", state.Name)
	require.False(t, state.Next.After(time.Now()))
	require.Same(t, before, s.current.instance)
	s.Stop()
}

// A changed interval moves the next download: it counts from the last one by the new interval,
// and when that is past the download is due now. A retry after a failure is not put off.
func TestSubscriptionIntervalChange(t *testing.T) {
	const name, address = "prov1", "https://sub.example/api/sub/TOKEN"
	last := time.Now().Add(-5 * time.Minute)
	day := last.Add(24 * time.Hour)
	s := New(Options{})
	apply := func(interval string) {
		s.syncSubscriptions(&model.Config{Sources: []model.Source{{Name: name, Type: "subscription", URL: address, UpdateInterval: interval}}})
	}
	apply("auto")
	state := s.subscriptions.states[name]
	state.Attempted, state.Next = &last, &day
	apply("auto")
	require.Equal(t, day, *state.Next, "the same interval moves nothing")
	apply("24h")
	require.Equal(t, day, *state.Next, "another way to write it moves nothing")
	apply("1h")
	require.Equal(t, last.Add(time.Hour), *state.Next)
	apply("1d")
	require.Equal(t, day, *state.Next, "a longer one moves it later")
	long := last.Add(-time.Hour)
	state.Attempted = &long
	apply("20m")
	require.False(t, time.Now().Before(*state.Next), "past: due now")

	state.Attempted = &last
	state.Busy = true
	held := *state.Next
	apply("3h")
	require.Equal(t, held, *state.Next, "a download under way sets it when it ends")
	state.Busy = false

	retry := last.Add(downloadRetry)
	state.Next = &retry
	s.subscriptions.failures = map[string]int{name: 1}
	apply("6h")
	require.Equal(t, retry, *state.Next, "a retry is not put off")
	apply("20m")
	require.False(t, state.Next.After(retry), "a shorter interval may bring it nearer")
}

// Under auto the next download is as often as the answer just taken asks: the first list of a
// subscription too (it used to wait a day, the interval of a provider that had told nothing yet),
// and a provider that changes its interval is followed at once. A failed download keeps what
// the provider told before.
func TestSubscriptionAutoIntervalOfAnswer(t *testing.T) {
	directory := t.TempDir()
	fake, system := &fakeEngine{refuse: map[string]error{}}, new(recorder)
	source := &provider{body: "vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\n", answer: http.Header{"Profile-Update-Interval": {"2"}}}
	options := Options{
		SettingsPath: filepath.Join(directory, "podkop"), RuleSetDir: filepath.Join(directory, "rulesets"),
		StagingDir: filepath.Join(directory, "candidate"), StatePath: filepath.Join(directory, "state"),
		ConfigDir: filepath.Join(directory, "run"), ReadyTimeout: time.Second, System: system, Engine: fake,
		Download: source.download,
	}
	settings := strings.Replace(subscriptionSettings(directory, "block"), "option update_interval '1h'", "option update_interval 'auto'", 1)
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(settings), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	next := func(want time.Duration, why string) {
		t.Helper()
		state := s.subscriptionStates()[0]
		require.Equal(t, "prov1", state.Name)
		require.WithinDuration(t, time.Now().Add(want), *state.Next, time.Minute, why)
	}
	downloadNow(t, s)
	next(2*time.Hour, "the first list: as the provider asks in it")
	source.answerWith(http.Header{"Profile-Update-Interval": {"5"}})
	downloadNow(t, s)
	next(5*time.Hour, "the interval the provider asks now")
	source.answerWith(nil)
	downloadNow(t, s)
	next(24*time.Hour, "a provider that asks nothing: a day")

	source.answerWith(http.Header{"Profile-Update-Interval": {"3"}})
	downloadNow(t, s)
	source.access.Lock()
	source.refuseAll = true
	source.access.Unlock()
	downloadNow(t, s)
	require.NotNil(t, s.subscriptionStates()[0].Provider)
	require.Equal(t, 3, s.subscriptionStates()[0].Provider.UpdateHours, "a failure keeps what the provider told")
	s.Stop()
}

func TestParseInterval(t *testing.T) {
	for text, want := range map[string]time.Duration{"1h": time.Hour, "12h": 12 * time.Hour, "1d": 24 * time.Hour, "30m": 30 * time.Minute, "1m": 10 * time.Minute, "": 12 * time.Hour, "x": 12 * time.Hour, "-1h": 12 * time.Hour} {
		require.Equal(t, want, parseInterval(text), text)
	}
}

// Load is a job: the same address under way is that job, at most two run at once, a canceled
// one tells the cancel (whatever its download comes to after), and a done one its list.
func TestSubscriptionLoadJobs(t *testing.T) {
	directory := t.TempDir()
	fake, system := &fakeEngine{refuse: map[string]error{}}, new(recorder)
	source := &provider{body: "vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\n", block: make(chan struct{})}
	options := Options{
		SettingsPath: filepath.Join(directory, "podkop"), RuleSetDir: filepath.Join(directory, "rulesets"),
		StagingDir: filepath.Join(directory, "candidate"), StatePath: filepath.Join(directory, "state"),
		ConfigDir: filepath.Join(directory, "run"), ReadyTimeout: time.Second, System: system, Engine: fake,
		Download: source.download,
	}
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(subscriptionSettings(directory, "all")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	ctx := context.Background()
	first := s.StartLoad(ctx, "https://one.example/sub/A")
	require.Equal(t, "running", first.State)
	require.NotEmpty(t, first.ID)
	require.Equal(t, first.ID, s.StartLoad(ctx, " https://one.example/sub/A ").ID, "the same address: the same job")
	second := s.StartLoad(ctx, "https://two.example/sub/B")
	require.NotEqual(t, first.ID, second.ID)
	busy := s.StartLoad(ctx, "https://three.example/sub/C")
	require.Equal(t, "failed", busy.State)
	require.Equal(t, "busy", busy.Preview.ErrorCode)

	canceled, known := s.CancelLoad(ctx, first.ID)
	require.True(t, known)
	require.Equal(t, "canceled", canceled.State)
	require.Equal(t, "canceled", canceled.Preview.ErrorCode, "told at once")
	close(source.block)
	require.Eventually(t, func() bool {
		job, _ := s.LoadState(ctx, second.ID)
		return job.State == "done"
	}, 5*time.Second, 20*time.Millisecond)
	job, _ := s.LoadState(ctx, second.ID)
	require.Equal(t, "NL 1", job.Preview.Servers[0].Name)
	job, _ = s.LoadState(ctx, first.ID)
	require.Equal(t, "canceled", job.State)
	require.Equal(t, "canceled", job.Preview.ErrorCode)
	_, known = s.LoadState(ctx, "nosuchjob")
	require.False(t, known)
	s.Stop()
}

// A download asked for by hand: one that brings a list counts the next download from it; one
// that fails, with a list in use, leaves the next download when it was planned and does not
// count towards the backoff.
func TestSubscriptionUpdateByHand(t *testing.T) {
	directory := t.TempDir()
	fake, system := &fakeEngine{refuse: map[string]error{}}, new(recorder)
	source := &provider{body: "vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\n"}
	options := Options{
		SettingsPath: filepath.Join(directory, "podkop"), RuleSetDir: filepath.Join(directory, "rulesets"),
		StagingDir: filepath.Join(directory, "candidate"), StatePath: filepath.Join(directory, "state"),
		ConfigDir: filepath.Join(directory, "run"), ReadyTimeout: time.Second, System: system, Engine: fake,
		Download: source.download,
	}
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(subscriptionSettings(directory, "block")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	downloadNow(t, s)
	state := s.subscriptions.states["prov1"]
	require.Empty(t, state.ErrorCode)
	require.WithinDuration(t, time.Now().Add(time.Hour), *state.Next, 5*time.Second, "the interval of the settings")

	// planned in 40 minutes; asked for now, it fails on every way
	planned := time.Now().Add(40 * time.Minute)
	state.Next = &planned
	source.access.Lock()
	source.refuseAll = true
	source.access.Unlock()
	s.downloadDue(time.Now(), "prov1")
	s.takeList(<-s.downloads)
	require.Equal(t, "unreachable", state.ErrorCode)
	require.Equal(t, planned, *state.Next, "the planned download stays")
	require.Zero(t, s.subscriptions.failures["prov1"])

	// asked for now again, it brings a list: the next one in an interval from now
	source.access.Lock()
	source.refuseAll = false
	source.access.Unlock()
	s.downloadDue(time.Now(), "prov1")
	s.takeList(<-s.downloads)
	require.Empty(t, state.ErrorCode)
	require.WithinDuration(t, time.Now().Add(time.Hour), *state.Next, 5*time.Second)

	// a failure of a planned download (not asked for) is retried soon, as before
	source.access.Lock()
	source.refuseAll = true
	source.access.Unlock()
	past := time.Now().Add(-time.Second)
	state.Next = &past
	s.downloadDue(time.Now(), "")
	s.takeList(<-s.downloads)
	require.True(t, state.Next.Before(time.Now().Add(downloadRetry+5*time.Second)))
	require.Equal(t, 1, s.subscriptions.failures["prov1"])
	s.Stop()
}

// A label changed on the page renames the outbounds of its source: they are replaced while
// sing-box runs, and the log tells the configuration by the new name.
func TestLabelRenamesWhileRunning(t *testing.T) {
	directory := t.TempDir()
	fake := &fakeEngine{refuse: map[string]error{}}
	source := &provider{body: "vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\n"}
	var access sync.Mutex
	var lines []string
	options := Options{
		SettingsPath: filepath.Join(directory, "podkop"), RuleSetDir: filepath.Join(directory, "rulesets"),
		StagingDir: filepath.Join(directory, "candidate"), StatePath: filepath.Join(directory, "state"),
		ConfigDir: filepath.Join(directory, "run"), ReadyTimeout: time.Second, System: new(recorder), Engine: fake,
		SubscriptionDir: filepath.Join(directory, "subscriptions"), Download: source.download,
		Log: func(_ string, text string) {
			access.Lock()
			defer access.Unlock()
			lines = append(lines, text)
		},
	}
	told := func(part string) bool {
		access.Lock()
		defer access.Unlock()
		for _, line := range lines {
			if strings.HasPrefix(line, "configuration: rules") && strings.Contains(line, part) {
				return true
			}
		}
		return false
	}
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(subscriptionSettings(directory, "block")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	defer s.Stop()
	downloadNow(t, s)
	require.Contains(t, string(s.current.result.Config), `"prov1: NL 1"`)
	require.True(t, told("youtube (prov1 with NL"))

	settings, err := os.ReadFile(options.SettingsPath)
	require.NoError(t, err)
	require.Contains(t, string(settings), "option label 'prov1'", "podkop migrate labels the subscription")
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(strings.Replace(string(settings), "option label 'prov1'", "option label 'Lab'", 1)), 0o644))
	result := s.Apply()
	require.True(t, result.OK, result.Message)
	require.Len(t, fake.built, 1, "the outbounds renamed are replaced while sing-box runs")
	require.Contains(t, string(s.current.result.Config), `"Lab: NL 1"`)
	require.NotContains(t, string(s.current.result.Config), `"prov1: NL 1"`)
	require.True(t, told("youtube (Lab with NL"), "the configuration told again by the new name")
}
