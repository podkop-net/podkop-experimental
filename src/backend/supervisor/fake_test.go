package supervisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/sockets"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
	"github.com/podkop-net/podkop-experimental/src/backend/yacd"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/stretchr/testify/require"
)

// fakeEngine is an Engine without sing-box: what it builds is told by the test, and it
// remembers what it was asked. The tests with it bind no port and touch no network.
type fakeEngine struct {
	// refuse is the error of Check for a configuration that has it in its text
	refuse map[string]error
	// broken are the texts of configurations whose build fails, failing those whose start
	// fails, silent those whose instance never answers, stuck those whose instance does not
	// close
	broken, failing, silent, stuck []string
	built                          []*fakeInstance
	// checked counts the checks of whole configurations
	checked int
	// lists are what the downloaded rule sets hold, by tag, in the cache file of every
	// instance; noAddresses are the tags of those without a rule of addresses
	lists       map[string][]byte
	noAddresses map[string]bool
	// delays are what the URL tests found, by tag; unusable are texts of links sing-box
	// cannot build; dial, when set, opens a connection through an outbound, dialed are the
	// tags dialed through
	delays   map[string]uint16
	unusable []string
	dial     func(ctx context.Context, tag string, address string) (net.Conn, error)
	dialed   []string
	access   sync.Mutex
	// swaps are what the instances were asked to replace while they run; swapRefused texts of
	// configurations they refuse to take so
	swaps       []engine.Swap
	swapRefused []string
	// carried counts the calls of CarrySelections
	carried int
}

type fakeInstance struct {
	engine                 *fakeEngine
	config                 []byte
	started, closed        bool
	failing, silent, stuck bool
	// loaded is what OnRuleSetUpdate was given; reads counts RuleSetContent by tag
	loaded func(tag string)
	reads  map[string]int
}

func has(config []byte, texts []string) bool {
	for _, text := range texts {
		if strings.Contains(string(config), text) {
			return true
		}
	}
	return false
}

func (e *fakeEngine) Check(config []byte, links []plan.Link) error {
	e.checked++
	for text, err := range e.refuse {
		if strings.Contains(string(config), text) {
			return err
		}
	}
	return nil
}

func (e *fakeEngine) Build(config []byte, sink engine.LogSink, hooks ...engine.ConnectionHook) (Instance, error) {
	if has(config, e.broken) {
		return nil, os.ErrInvalid
	}
	instance := &fakeInstance{engine: e, config: config, failing: has(config, e.failing), silent: has(config, e.silent), stuck: has(config, e.stuck), reads: map[string]int{}}
	e.built = append(e.built, instance)
	return instance, nil
}

func (e *fakeEngine) Ready(ctx context.Context) error {
	last := e.built[len(e.built)-1]
	if last.silent {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func (e *fakeEngine) Notes() []string { return nil }

func (e *fakeEngine) CheckServers(servers []subscription.Server, known map[string]string) map[string]string {
	verdicts := make(map[string]string)
	for index := range servers {
		if servers[index].Usable() && has([]byte(servers[index].Link), e.unusable) {
			servers[index].Reason = "this sing-box cannot build it"
		}
		if servers[index].ID != "" {
			verdicts[servers[index].ID] = servers[index].Reason
		}
	}
	return verdicts
}

func (e *fakeEngine) Delays(tags []string) map[string]uint16 {
	result := make(map[string]uint16)
	for _, tag := range tags {
		if delay, found := e.delays[tag]; found {
			result[tag] = delay
		}
	}
	return result
}

func (i *fakeInstance) OnRuleSetUpdate(tags []string, updated func(tag string)) {
	i.loaded = updated
}

// Start fails as engine.Instance.Start does: it closes the instance, and tells when that
// does not end.
func (i *fakeInstance) Start() error {
	if !i.failing {
		i.started = true
		return nil
	}
	if i.stuck {
		return E.Errors(os.ErrPermission, engine.ErrStuck)
	}
	i.closed = true
	return os.ErrPermission
}
func (i *fakeInstance) Close(time.Duration) error {
	if i.stuck {
		return engine.ErrStuck
	}
	i.closed = true
	return nil
}
func (i *fakeInstance) RuleSetContent(tag string) ([]byte, bool) {
	content, found := i.engine.lists[tag]
	if found {
		i.reads[tag]++
	}
	return bytes.Clone(content), found
}
func (i *fakeInstance) RuleSetHasAddresses(tag string) (bool, bool) {
	_, found := i.engine.lists[tag]
	return found && !i.engine.noAddresses[tag], found
}
func (i *fakeInstance) RuleSetUpdated(string) (time.Time, bool) {
	return time.Time{}, false
}
func (i *fakeInstance) FakeIPAddress(string) (netip.Addr, bool, error) {
	return netip.Addr{}, false, nil
}
func (i *fakeInstance) UpdateRuleSets(context.Context) (engine.RuleSetUpdate, error) {
	return engine.RuleSetUpdate{}, nil
}
func (i *fakeInstance) Dial(ctx context.Context, tag string, address string) (net.Conn, error) {
	i.engine.access.Lock()
	i.engine.dialed = append(i.engine.dialed, tag)
	dial := i.engine.dial
	i.engine.access.Unlock()
	if dial == nil {
		return nil, E.New("no way through ", tag)
	}
	return dial(ctx, tag, address)
}

// Swap takes the configuration when it has none of the texts of swapRefused: the instance
// runs it from then on.
func (i *fakeInstance) Swap(configuration []byte, swap engine.Swap, limit int) (engine.Swapped, error) {
	i.engine.access.Lock()
	defer i.engine.access.Unlock()
	i.engine.swaps = append(i.engine.swaps, swap)
	if has(configuration, i.engine.swapRefused) {
		return engine.Swapped{}, os.ErrInvalid
	}
	i.config = configuration
	return engine.Swapped{Added: len(swap.Put), Removed: len(swap.Remove)}, nil
}

func (i *fakeInstance) CarrySelections(configuration []byte) {
	i.engine.access.Lock()
	defer i.engine.access.Unlock()
	i.engine.carried++
}

func (i *fakeInstance) Traffic() (engine.Traffic, error) {
	if !i.started || i.closed {
		return engine.Traffic{}, engine.ErrClosed
	}
	return engine.Traffic{Up: int64(len(i.config)), Down: 2, Connections: 3}, nil
}

// fakeFixture is a supervisor of a fake engine and a recorder: no root is needed.
func fakeFixture(t *testing.T) (*Supervisor, *fakeEngine, *recorder, func(name string, ttl string)) {
	directory := t.TempDir()
	fake, system := &fakeEngine{refuse: map[string]error{}}, new(recorder)
	s := New(Options{
		SettingsPath: filepath.Join(directory, "podkop"), RuleSetDir: filepath.Join(directory, "rulesets"),
		StagingDir: filepath.Join(directory, "candidate"), StatePath: filepath.Join(directory, "state"),
		ConfigDir: filepath.Join(directory, "run"), ReadyTimeout: time.Second, System: system, Engine: fake,
	})
	settings := func(name string, ttl string) {
		text := "config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '127.0.0.1:9'\n\toption dns_rewrite_ttl '" + ttl + "'\n" +
			"\toption cache_path '" + filepath.Join(directory, "cache.db") + "'\n" +
			"\toption yacd_secret_key 'k'\n" +
			"\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n" +
			"\toption user_domain_list_type 'dynamic'\n\tlist user_domains '" + name + "'\n"
		require.NoError(t, os.WriteFile(filepath.Join(directory, "podkop"), []byte(text), 0o644))
	}
	return s, fake, system, settings
}

func state(t *testing.T, s *Supervisor) string {
	content, err := os.ReadFile(s.options.StatePath)
	require.NoError(t, err)
	return strings.Fields(string(content))[0]
}

// Settings sing-box refuses at boot: the router keeps its own DNS, nothing is taken.
func TestFakeBootRefused(t *testing.T) {
	s, fake, system, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	// the names of a list are in a rule-set file: a configuration is told by its TTL
	fake.refuse[`"rewrite_ttl": 60`] = os.ErrInvalid
	result := s.Boot()
	require.False(t, result.OK)
	require.False(t, s.Running())
	require.Empty(t, fake.built)
	require.Equal(t, []string{"no dns", "no firewall", "no routing"}, system.take())
	require.Equal(t, stateReleased, state(t, s))
}

// A boot whose sing-box does not answer is closed, and the router given back.
func TestFakeBootSilent(t *testing.T) {
	s, fake, system, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	fake.silent = []string{`"rewrite_ttl": 60`}
	result := s.Boot()
	require.False(t, result.OK)
	require.False(t, s.Running())
	require.Len(t, fake.built, 1)
	require.True(t, fake.built[0].closed)
	require.Equal(t, []string{"no dns", "no firewall", "no routing"}, system.take())
}

// The routing and the firewall come before the DNS of the LAN; the same configuration
// again leaves sing-box alone; another one replaces it; one that does not come up gives
// way to the previous one, started again.
func TestFakeApply(t *testing.T) {
	s, fake, system, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	require.True(t, s.Boot().OK)
	require.Equal(t, []string{"routing", "firewall", "dns"}, system.take())
	first := s.current.instance
	traffic, running := s.Traffic()
	require.True(t, running)
	require.Equal(t, engine.Traffic{Up: int64(len(fake.built[0].config)), Down: 2, Connections: 3}, traffic)

	result := s.Apply()
	require.True(t, result.OK, result.Message)
	require.Same(t, first, s.current.instance)
	require.Len(t, fake.built, 1)

	settings("one.lab.example", "61")
	result = s.Apply()
	require.True(t, result.OK, result.Message)
	require.Len(t, fake.built, 2)
	require.True(t, fake.built[0].closed)
	require.True(t, fake.built[1].started)

	settings("two.lab.example", "62")
	fake.silent = []string{`"rewrite_ttl": 62`}
	result = s.Apply()
	require.False(t, result.OK)
	require.Contains(t, result.Message, "the previous one runs again")
	require.Len(t, fake.built, 4)
	require.True(t, fake.built[2].closed, "the one that did not come up is closed")
	require.Equal(t, string(fake.built[1].config), string(fake.built[3].config), "the previous configuration is started again")
	require.Same(t, fake.built[3], s.current.instance)
	require.Equal(t, stateRunning, state(t, s))
	// what goes through the instance that runs now, not one closed before
	traffic, running = s.Traffic()
	require.True(t, running)
	require.Equal(t, int64(len(fake.built[3].config)), traffic.Up)
	s.Stop()
	_, running = s.Traffic()
	require.False(t, running)
}

// An instance that does not close leaves the process nothing to go on with: the router is
// given back, and Run would end with engine.ErrStuck.
func TestFakeStuck(t *testing.T) {
	s, fake, system, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	fake.stuck = []string{`"rewrite_ttl": 60`}
	require.True(t, s.Boot().OK)
	system.take()
	settings("one.lab.example", "61")
	result := s.Apply()
	require.False(t, result.OK)
	require.False(t, s.Running())
	require.Equal(t, []string{"no dns", "no firewall", "no routing"}, system.take())
	require.ErrorIs(t, s.stuckError(), engine.ErrStuck)
}

// A start that fails and whose instance does not close then is stuck too: the router is
// given back, and Run ends with engine.ErrStuck; at the boot and at an apply.
func TestFakeStartStuck(t *testing.T) {
	s, fake, system, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	fake.failing = []string{`"rewrite_ttl": 60`}
	fake.stuck = []string{`"rewrite_ttl": 60`}
	require.False(t, s.Boot().OK)
	require.False(t, s.Running())
	require.ErrorIs(t, s.stuckError(), engine.ErrStuck)
	require.Contains(t, system.take(), "no dns")

	s, fake, system, settings = fakeFixture(t)
	settings("one.lab.example", "60")
	fake.failing = []string{`"rewrite_ttl": 61`}
	fake.stuck = []string{`"rewrite_ttl": 61`}
	require.True(t, s.Boot().OK)
	system.take()
	settings("one.lab.example", "61")
	require.False(t, s.Apply().OK)
	require.False(t, s.Running())
	require.Equal(t, []string{"no dns", "no firewall", "no routing"}, system.take())
	require.ErrorIs(t, s.stuckError(), engine.ErrStuck)
}

// An apply of the settings and the local lists the running configuration was checked
// with does not build that configuration again; a local list that changed, or another
// configuration, is checked. A list is read once an apply.
func TestFakeCheckOnce(t *testing.T) {
	s, fake, _, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	local := filepath.Join(t.TempDir(), "local.lst")
	require.NoError(t, os.WriteFile(local, []byte("local-one.lab.example\n"), 0o644))
	withLocal := func() {
		content, err := os.ReadFile(s.options.SettingsPath)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(s.options.SettingsPath, append(content, "\tlist local_domain_lists '"+local+"'\n"...), 0o644))
	}
	withLocal()
	require.True(t, s.Boot().OK)
	require.Equal(t, 1, fake.checked)
	require.Len(t, s.listChecks, 1)

	require.True(t, s.Apply().OK)
	require.Equal(t, 1, fake.checked, "the same settings and lists: no check")
	require.Len(t, fake.built, 1)

	require.NoError(t, os.WriteFile(local, []byte("local-one.lab.example\nlocal-two.lab.example\n"), 0o644))
	require.True(t, s.Apply().OK)
	require.Equal(t, 2, fake.checked, "a local list that changed")
	require.Len(t, s.listChecks, 1, "what the check of the list before found is forgotten")
	require.True(t, s.Apply().OK)
	require.Equal(t, 2, fake.checked)

	settings("one.lab.example", "61")
	withLocal()
	require.True(t, s.Apply().OK)
	require.Equal(t, 3, fake.checked, "another configuration")
	require.Len(t, fake.built, 2)
	s.Stop()
}

// A change of one list reads only that list again for the firewall sets: a big local list
// that did not change is not read again.
func TestFakeDeriveOnce(t *testing.T) {
	s, _, system, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	local := filepath.Join(t.TempDir(), "subnets.lst")
	require.NoError(t, os.WriteFile(local, []byte("11.0.0.0/24\n11.0.2.0/24\n"), 0o644))
	withLocal := func(extra string) {
		content, err := os.ReadFile(s.options.SettingsPath)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(s.options.SettingsPath, append(content, "\tlist local_subnet_lists '"+local+"'\n"+extra...), 0o644))
	}
	withLocal("")
	require.True(t, s.Boot().OK)
	content, err := os.ReadFile(local)
	require.NoError(t, err)
	sum := sha256.Sum256(content)
	var before *engine.AddressRule
	for key, found := range s.read {
		if key.sum == sum {
			require.NoError(t, found.err)
			before = &found.rules[0]
		}
	}
	require.NotNil(t, before, "the local list was read for the firewall")
	// another subnet in the user list
	settings("one.lab.example", "60")
	withLocal("\toption user_subnet_list_type 'dynamic'\n\tlist user_subnets '100.71.99.8'\n")
	require.True(t, s.Apply().OK)
	last := system.plans[len(system.plans)-1]
	require.Contains(t, firewall.RangeStrings(last.Subnets), "100.71.99.8/32")
	require.Contains(t, firewall.RangeStrings(last.Subnets), "11.0.2.0/24")
	found := false
	for key, read := range s.read {
		if key.sum == sum {
			found = true
			require.Same(t, before, &read.rules[0], "the local list was read again")
		}
	}
	require.True(t, found)
	s.Stop()
}

// The firewall reads a downloaded list again only after sing-box loaded it again, and a
// list without a rule of addresses not at all. A new instance reads its lists once, and
// one with the same content is not parsed again.
func TestFakeReadLoadedOnly(t *testing.T) {
	s, fake, system, settings := fakeFixture(t)
	withLists := func(ttl string) {
		settings("one.lab.example", ttl)
		content, err := os.ReadFile(s.options.SettingsPath)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(s.options.SettingsPath, append(content, "\tlist remote_subnet_lists 'http://192.0.2.80/subnets.lst'\n"+
			"\tlist remote_domain_lists 'http://192.0.2.80/domains.lst'\n"...), 0o644))
	}
	withLists("60")
	require.True(t, s.Boot().OK)
	var subnets, domains string
	for _, ruleSet := range s.current.result.RuleSets {
		switch {
		case strings.HasSuffix(ruleSet.URL, "/subnets.lst"):
			subnets = ruleSet.Tag
		case strings.HasSuffix(ruleSet.URL, "/domains.lst"):
			domains = ruleSet.Tag
		}
	}
	require.NotEmpty(t, subnets)
	require.NotEmpty(t, domains)
	fake.lists = map[string][]byte{subnets: []byte("11.0.0.0/24\n"), domains: []byte("one.lab.example\n")}
	fake.noAddresses = map[string]bool{domains: true}
	first := fake.built[0]
	lastSubnets := func() []string {
		return firewall.RangeStrings(system.plans[len(system.plans)-1].Subnets)
	}

	first.loaded(subnets)
	first.loaded(domains)
	s.refreshFirewall()
	require.Equal(t, []string{"11.0.0.0/24"}, lastSubnets())
	require.Equal(t, 1, first.reads[subnets])
	require.Zero(t, first.reads[domains], "a list without addresses is not read")

	s.refreshFirewall()
	require.Equal(t, 1, first.reads[subnets], "a list not loaded again is not read again")

	fake.lists[subnets] = []byte("11.0.0.0/24\n11.0.2.0/24\n")
	first.loaded(subnets)
	s.refreshFirewall()
	require.Equal(t, 2, first.reads[subnets])
	require.Equal(t, []string{"11.0.0.0/24", "11.0.2.0/24"}, lastSubnets())
	var parsed *engine.AddressRule
	for key, read := range s.read {
		if key.tag == subnets {
			parsed = &read.rules[0]
		}
	}
	require.NotNil(t, parsed)

	// another configuration: its instance reads the list once, the same content, which is
	// not parsed again
	withLists("61")
	require.True(t, s.Apply().OK)
	second := fake.built[1]
	require.NotSame(t, first, second)
	require.Equal(t, 1, second.reads[subnets])
	require.Equal(t, []string{"11.0.0.0/24", "11.0.2.0/24"}, lastSubnets())
	for key, read := range s.read {
		if key.tag == subnets {
			require.Same(t, parsed, &read.rules[0], "the same content was parsed again")
		}
	}
	s.refreshFirewall()
	require.Equal(t, 1, second.reads[subnets])
	s.Stop()
}

// A start that fails says "failed" and is tried again at the next change of the network
// (and when the guard of the package asks): it runs once what kept it down is gone.
// Settings that cannot be used, and a stop, are not tried again.
func TestFakeRetryFailedStart(t *testing.T) {
	s, fake, system, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	fake.silent = []string{`"rewrite_ttl": 60`}
	require.False(t, s.Boot().OK)
	require.Equal(t, stateFailed, state(t, s))
	system.take()
	// still down: the first few tried at once, failed again
	for range 3 {
		require.Contains(t, s.restoreRouting(), "the start that had failed was tried again")
	}
	require.Equal(t, stateFailed, state(t, s))
	require.Len(t, fake.built, 4)
	// then a try waits
	require.Contains(t, s.restoreRouting(), "the start failed 4 times in a row: it is tried again from ")
	require.Len(t, fake.built, 4)
	// a change of the settings is tried at once
	require.False(t, s.Apply().OK)
	require.Len(t, fake.built, 5)
	system.take()
	// what kept it down is gone
	fake.silent = nil
	require.Contains(t, s.restoreRouting(), "the start that had failed was tried again: started")
	require.True(t, s.Running())
	require.Equal(t, stateRunning, state(t, s))
	require.Equal(t, []string{"routing", "firewall", "dns"}, system.take())
	// a stop is not undone by the network
	s.Stop()
	require.Equal(t, "nothing runs", s.restoreRouting())
	// nor are settings that cannot be used
	fake.refuse[`"rewrite_ttl": 60`] = os.ErrInvalid
	require.False(t, s.Boot().OK)
	require.Equal(t, stateReleased, state(t, s))
	require.Equal(t, "nothing runs", s.restoreRouting())
}

// A start whose routing cannot be set up is a start that failed too: it is tried again,
// and the stop that gives the router back keeps the count of the failures.
func TestFakeSurroundFailed(t *testing.T) {
	s, fake, system, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	system.routingError = os.ErrPermission
	require.False(t, s.Boot().OK)
	require.Equal(t, stateFailed, state(t, s))
	for range 3 {
		require.Contains(t, s.restoreRouting(), "the start that had failed was tried again: set up the routing")
	}
	require.Contains(t, s.restoreRouting(), "the start failed 4 times in a row")
	require.Len(t, fake.built, 4)
	require.True(t, fake.built[3].closed)
	system.routingError = nil
	s.failedAt = time.Now().Add(-time.Minute)
	require.Contains(t, s.restoreRouting(), "the start that had failed was tried again: started")
	require.Equal(t, stateRunning, state(t, s))
	s.Stop()
}

// With YACD on, the dashboard of the package is put where sing-box serves it before it starts,
// and the configuration names that directory by its path.
func TestFakeDashboardServed(t *testing.T) {
	s, _, _, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	path := s.options.SettingsPath
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	content = bytes.Replace(content, []byte("config settings 'settings'\n"), []byte("config settings 'settings'\n\toption enable_yacd '1'\n\tlist yacd_interfaces 'br-lan'\n"), 1)
	require.NoError(t, os.WriteFile(path, content, 0o644))
	root := t.TempDir()
	builtin, served := filepath.Join(root, "yacd"), filepath.Join(root, "ui")
	require.NoError(t, os.MkdirAll(builtin, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(builtin, yacd.Marker), []byte("build 1\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(builtin, "index.html"), []byte("<html>1</html>"), 0o644))
	s.options.YACDBuiltinDir, s.options.YACDServedDir = builtin, served
	require.True(t, s.Boot().OK)
	require.Contains(t, string(s.current.result.Config), `"external_ui": "`+served+`"`)
	index, err := os.ReadFile(filepath.Join(served, "index.html"))
	require.NoError(t, err)
	require.Equal(t, "<html>1</html>", string(index))
	s.Stop()
}

// At a change of the network the running configuration is held to the router: a LAN that
// got another address is applied again (its mixed proxies listen on it), one that lost it
// is not; a socket of an inbound nothing listens on any more is listened on again by a new
// instance, though the configuration is the same.
func TestFakeDrift(t *testing.T) {
	s, fake, system, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	require.True(t, s.Boot().OK)
	all := func(drop string) []sockets.Listener {
		var result []sockets.Listener
		for _, inbound := range inboundSockets(s.current.result.Config) {
			if inbound.tag+" "+inbound.protocol != drop && inbound.tag != drop {
				result = append(result, sockets.Listener{Protocol: inbound.protocol, Address: inbound.address})
			}
		}
		return result
	}
	require.NotEmpty(t, all(""))
	system.listening = all("")
	require.Equal(t, "nothing was missing", s.restoreRouting())
	// an uplink that came up gets its rule, and sing-box keeps running
	system.uplinks = []string{"wwan0"}
	require.Equal(t, "what sing-box sends bound to wwan0 goes by the main routing table", s.restoreRouting())
	require.Len(t, fake.built, 1)
	require.Equal(t, "nothing was missing", s.restoreRouting())

	system.lan = "192.168.2.1"
	message := s.restoreRouting()
	require.Contains(t, message, "the address of the LAN: 192.168.2.1 (was 127.0.0.1)")
	require.Contains(t, message, "sing-box keeps running")
	require.Len(t, fake.built, 1)
	require.Equal(t, "nothing was missing", s.restoreRouting())
	system.noLAN = true
	require.Equal(t, "nothing was missing", s.restoreRouting(), "an address that went away is no change")
	system.noLAN = false

	// a wildcard socket of another program is none of its own
	system.listening = append(all("dns-in"), sockets.Listener{Protocol: "udp", Address: netip.MustParseAddrPort("[::]:53")},
		sockets.Listener{Protocol: "tcp", Address: netip.MustParseAddrPort("0.0.0.0:53")})
	message = s.restoreRouting()
	require.Contains(t, message, "nothing listens on tcp 127.0.0.42:53 (dns-in); nothing listens on udp 127.0.0.42:53 (dns-in)")
	require.Len(t, fake.built, 2, "a new instance listens again")
	require.True(t, fake.built[0].closed)
	require.Equal(t, string(fake.built[0].config), string(fake.built[1].config))
	system.listening = all("")
	require.Equal(t, "nothing was missing", s.restoreRouting())
	// the UDP socket of the transparent proxy alone
	system.listening = all("tproxy-in udp")
	require.Contains(t, s.restoreRouting(), "the settings applied again for nothing listens on udp 127.0.0.1:1602 (tproxy-in): ")
	require.Len(t, fake.built, 3)
	system.listening = all("")

	// settings that cannot be used now: a change of the network is applied again once
	path := s.options.SettingsPath
	good, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, bytes.Replace(good, []byte("socks5://203.0.113.15:1080"), []byte("vless://broken"), 1), 0o644))
	system.lan = "192.168.3.1"
	require.Contains(t, s.restoreRouting(), "nothing is changed")
	require.Contains(t, s.restoreRouting(), "the settings did not take for the address of the LAN: 192.168.3.1 (was 192.168.2.1) before: not applied again")
	require.Len(t, fake.built, 3)
	// a lost socket all the same: the configuration that runs is started again
	system.listening = all("tproxy-in")
	message = s.restoreRouting()
	require.Contains(t, message, "nothing listens on tcp 127.0.0.1:1602 (tproxy-in)")
	require.Contains(t, message, "sing-box runs the new configuration")
	require.Len(t, fake.built, 4)
	require.Equal(t, string(fake.built[2].config), string(fake.built[3].config))
	require.True(t, s.Running())
	system.listening = all("")
	// a change of the settings tries the change of the network again
	require.NoError(t, os.WriteFile(path, good, 0o644))
	require.True(t, s.Apply().OK)
	require.Equal(t, "nothing was missing", s.restoreRouting())
	s.Stop()
}

func TestRetryPause(t *testing.T) {
	var pauses []time.Duration
	for failures := 1; failures <= 11; failures++ {
		pauses = append(pauses, retryPause(failures))
	}
	require.Equal(t, []time.Duration{0, 0, 0, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour}, pauses)
}
