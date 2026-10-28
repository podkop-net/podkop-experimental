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

	"github.com/podkop-net/podkop-experimental/src/backend/subscription"

	"github.com/stretchr/testify/require"
)

// provider is a subscription of a test: the list it serves now, and the routes it was asked
// by.
type provider struct {
	access sync.Mutex
	body   string
	// refused are the routes that do not reach it
	refused []string
	asked   []string
	headers []http.Header
	plans   []subscription.Plan
}

func (p *provider) serve(body string) {
	p.access.Lock()
	p.body = body
	p.access.Unlock()
}

func (p *provider) download(ctx context.Context, address string, header http.Header, routes []subscription.Route, plan subscription.Plan, report func([]subscription.Try)) (*subscription.Answer, []subscription.Try, error) {
	p.access.Lock()
	defer p.access.Unlock()
	p.headers = append(p.headers, header)
	p.plans = append(p.plans, plan)
	var tries []subscription.Try
	for _, route := range routes {
		p.asked = append(p.asked, route.Name)
		refused := false
		for _, name := range p.refused {
			refused = refused || name == route.Name
		}
		if !refused {
			tries = append(tries, subscription.Try{Route: route.Name, Phase: subscription.PhaseDone, Took: 800 * time.Millisecond, FirstByte: 700 * time.Millisecond, Pause: 10 * time.Millisecond, Bytes: int64(len(p.body))})
			return &subscription.Answer{Body: []byte(p.body), Header: http.Header{}, Route: route.Name}, tries, nil
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

// download runs a download of every subscription now, as Run would, and takes what it came to.
func downloadNow(t *testing.T, s *Supervisor) {
	t.Helper()
	s.downloadDue(time.Now(), "*")
	select {
	case result := <-s.downloads:
		s.takeList(result)
	case <-time.After(10 * time.Second):
		t.Fatal("no download came back")
	}
}

// The list of a subscription is taken, kept on flash and used at the next start; a list
// that only renamed its servers changes nothing; one with another server makes a new
// configuration.
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
	require.Len(t, fake.built, 2, "the list makes a new configuration")
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

	// only the names changed: nothing is written, nothing restarts
	source.serve("vless://u2@de1.example:443?security=tls&sni=de1.example#DE%201%20(29%20days)\nvless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201%20(29%20days)\n")
	time.Sleep(10 * time.Millisecond)
	downloadNow(t, s)
	require.Len(t, fake.built, 2)
	file, err = os.Stat(filepath.Join(directory, "subscriptions", "prov1.json"))
	require.NoError(t, err)
	require.Equal(t, written, file.ModTime())
	require.Contains(t, string(s.current.result.Config), `"prov1: NL 1"`)

	// the same servers, the names swapped: what the group chooses changes, and the list is taken
	source.serve("vless://u1@nl1.example:443?security=tls&sni=nl1.example#DE%201\nvless://u2@de1.example:443?security=tls&sni=de1.example#NL%201\n")
	downloadNow(t, s)
	require.Len(t, fake.built, 3)
	require.Contains(t, string(s.current.result.Config), `"server": "de1.example"`)
	require.NotContains(t, string(s.current.result.Config), `"server": "nl1.example"`)

	// another server: a new configuration
	source.serve("vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\nvless://u3@nl2.example:443?security=tls&sni=nl2.example#NL%202\n")
	downloadNow(t, s)
	require.Len(t, fake.built, 4)
	require.Contains(t, string(s.current.result.Config), `"prov1: NL 2"`)
	s.Stop()

	// the next start has the list before any download
	again := New(options)
	require.True(t, again.Boot().OK)
	require.Contains(t, string(again.current.result.Config), `"prov1: NL 2"`)
	again.Stop()

	// a subscription the settings no longer have is forgotten, its file too
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(strings.Split(subscriptionSettings(directory, "block"), "\nconfig subscription")[0]), 0o644))
	third := New(options)
	require.True(t, third.Boot().OK)
	_, err = os.Stat(filepath.Join(directory, "subscriptions", "prov1.json"))
	require.True(t, os.IsNotExist(err))
	third.Stop()
}

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
	require.Equal(t, []string{"direct", "prov1: NL 2", "prov1: NL 1", "main"}, names)
	// the way that brought the list the last time first among the servers
	routes, _ = s.routes(3, "main")
	require.Equal(t, "main", routes[1].Name)
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
	source.refused = []string{"direct", "prov1: NL 1", "prov1: NL 2", "main"}
	downloadNow(t, s)
	require.Equal(t, []string{"direct", "prov1: NL 1", "main"}, source.asked)
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

	directory := t.TempDir()
	fake, system := &fakeEngine{refuse: map[string]error{}}, new(recorder)
	source := &provider{body: "vless://u1@nl1.example:443?security=tls&sni=nl1.example#NL%201\n", refused: []string{"direct", "main"}}
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
	settings = append(settings, []byte("\nconfig subscription 'fresh'\n\toption url 'https://other.example/sub/X'\n"+
		"\nconfig group 'fresh_all'\n\tlist subscription 'fresh'\n"+
		"\nconfig section 'third'\n\toption connection_type 'group'\n\toption group 'fresh_all'\n\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'third.lab.example'\n")...)
	require.NoError(t, os.WriteFile(options.SettingsPath, settings, 0o644))
	require.True(t, s.Apply().OK)
	require.Contains(t, string(s.current.result.Config), `"fresh: NL 1"`)
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
	require.Len(t, fake.built, 2)
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

func TestParseInterval(t *testing.T) {
	for text, want := range map[string]time.Duration{"1h": time.Hour, "12h": 12 * time.Hour, "1d": 24 * time.Hour, "30m": 30 * time.Minute, "1m": 10 * time.Minute, "": 12 * time.Hour, "x": 12 * time.Hour, "-1h": 12 * time.Hour} {
		require.Equal(t, want, parseInterval(text), text)
	}
}
