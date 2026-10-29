//go:build with_quic && with_utls

package supervisor

import (
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/probe"
	"github.com/podkop-net/podkop-experimental/src/backend/sockets"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// The tests run a real sing-box of generated configurations: the DNS inbound at
// 127.0.0.42:53 and a transparent proxy inbound need root and the right to administer
// the network, as a container run with NET_ADMIN has them. What is outside
// sing-box, the firewall, the routing and dnsmasq, is a recorder here.

// recorder is a System that remembers what it was asked to do.
type recorder struct {
	calls     []string
	plans     []*firewall.Plan
	firewalls int
	// dnsOurs is whether dnsmasq asks the backend; routingGone and firewallGone make the
	// routing and the table look taken away
	dnsOurs                   bool
	routingGone, firewallGone bool
	// secrets are the keys of the Clash API written into the settings
	secrets []string
	// bridged is whether bridged packets pass the IP firewall hooks (br_netfilter)
	bridged bool
	// devices are what netifd says the interface names stand for
	devices map[string]string
	// lan is the address of the LAN when it is not 127.0.0.1, noLAN that there is none
	lan   string
	noLAN bool
	// listening are the sockets that listen; nil: not known
	listening []sockets.Listener
	// ntpNames are the names of the NTP servers of the router
	ntpNames []string
	// routingError is what setting up the routing fails with
	routingError error
	// uplinks are the devices RouteUplinks adds a rule for, once
	uplinks []string
}

func (r *recorder) Devices(names []string) map[string]string { return r.devices }
func (r *recorder) Listening() []sockets.Listener            { return r.listening }

func (r *recorder) AllowBridgedTraffic() []string {
	if !r.bridged {
		return nil
	}
	r.bridged = false
	return []string{"net.bridge.bridge-nf-call-iptables"}
}

func (r *recorder) SetClashSecret(key string) error { r.secrets = append(r.secrets, key); return nil }
func (r *recorder) RoutingPresent() (bool, error)   { return !r.routingGone, nil }
func (r *recorder) FirewallPresent() (bool, error)  { return !r.firewallGone, nil }

func (r *recorder) RouteUplinks() ([]string, error) {
	added := r.uplinks
	r.uplinks = nil
	return added, nil
}

func (r *recorder) NTPServerNames() []string { return r.ntpNames }

func (r *recorder) LANAddress() string {
	if r.noLAN {
		return ""
	}
	return cmp.Or(r.lan, "127.0.0.1")
}
func (r *recorder) ApplyRouting() error   { r.calls = append(r.calls, "routing"); return r.routingError }
func (r *recorder) RemoveRouting() error  { r.calls = append(r.calls, "no routing"); return nil }
func (r *recorder) RemoveFirewall() error { r.calls = append(r.calls, "no firewall"); return nil }
func (r *recorder) TakeOverDNS() (bool, error) {
	r.calls = append(r.calls, "dns")
	changed := !r.dnsOurs
	r.dnsOurs = true
	return changed, nil
}

func (r *recorder) RestoreDNS() (bool, error) {
	r.calls = append(r.calls, "no dns")
	changed := r.dnsOurs
	r.dnsOurs = false
	return changed, nil
}

func (r *recorder) UpdateFirewall(previous *firewall.Plan, next *firewall.Plan) error {
	if previous == nil {
		r.calls = append(r.calls, "firewall")
	} else {
		r.calls = append(r.calls, "firewall update")
	}
	r.plans = append(r.plans, next)
	return nil
}

func (r *recorder) take() []string {
	calls := r.calls
	r.calls = nil
	return calls
}

type fixture struct {
	t          *testing.T
	directory  string
	system     *recorder
	supervisor *Supervisor
	// the log is written from the goroutines of the backend as well
	logAccess sync.Mutex
	log       []string
}

func newFixture(t *testing.T) *fixture {
	if os.Getuid() != 0 {
		t.Skip("not root")
	}
	f := &fixture{t: t, directory: t.TempDir(), system: new(recorder)}
	f.supervisor = New(Options{
		SettingsPath: filepath.Join(f.directory, "podkop"),
		RuleSetDir:   filepath.Join(f.directory, "rulesets"),
		StagingDir:   filepath.Join(f.directory, "candidate"),
		StatePath:    filepath.Join(f.directory, "state"),
		ConfigDir:    filepath.Join(f.directory, "run"),
		ReadyTimeout: 10 * time.Second,
		System:       f.system,
		Log: func(level string, message string) {
			f.logAccess.Lock()
			defer f.logAccess.Unlock()
			f.log = append(f.log, "["+level+"] "+message)
		},
	})
	return f
}

// settings writes the settings file: one section with a list of names, and what a test adds.
func (f *fixture) settings(settings string, section string) {
	text := "config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '127.0.0.1:9'\n\toption update_interval '1d'\n" +
		// podkop 0.7 wrote the configuration where config_path named: the backend does not
		"\toption config_path '" + filepath.Join(f.directory, "config.json") + "'\n" +
		"\toption cache_path '" + filepath.Join(f.directory, "cache.db") + "'\n" + settings +
		"\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://u:p@203.0.113.15:1080#s5'\n" + section
	require.NoError(f.t, os.WriteFile(f.supervisor.options.SettingsPath, []byte(text), 0o644))
}

const oneName = "\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'one.lab.example'\n"

// answer asks the DNS inbound for a name and tells whether a FakeIP address came.
func answer(name string) bool {
	message := new(mDNS.Msg)
	message.SetQuestion(mDNS.Fqdn(name), mDNS.TypeA)
	response, _, err := (&mDNS.Client{Net: "udp", Timeout: time.Second}).Exchange(message, dataplane.DNSServer.String())
	if err != nil {
		return false
	}
	for _, record := range response.Answer {
		if address, isAddress := record.(*mDNS.A); isAddress && strings.HasPrefix(address.A.String(), "198.18.") {
			return true
		}
	}
	return false
}

// lines returns what was logged so far.
func (f *fixture) lines() []string {
	f.logAccess.Lock()
	defer f.logAccess.Unlock()
	return append([]string{}, f.log...)
}

func (f *fixture) logged(part string) bool {
	for _, line := range f.lines() {
		if strings.Contains(line, part) {
			return true
		}
	}
	return false
}

// kept is the content of a file of ConfigDir, "" when it is not there.
func (f *fixture) kept(name string) string {
	content, _ := os.ReadFile(filepath.Join(f.directory, "run", name))
	return string(content)
}

// state is the first word of the state file the guard reads, after checking the process.
func (f *fixture) state() string {
	content, err := os.ReadFile(filepath.Join(f.directory, "state"))
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(content))
	if len(fields) != 3 || fields[1] != strconv.Itoa(os.Getpid()) {
		return "malformed: " + string(content)
	}
	return fields[0]
}

func TestBootApplyStop(t *testing.T) {
	f := newFixture(t)
	s := f.supervisor
	f.settings("", oneName)
	s.Boot()
	require.True(t, s.Running(), "%v", f.lines())
	// sing-box first, then the routing and the firewall, the DNS of the LAN last
	require.Equal(t, []string{"routing", "firewall", "dns"}, f.system.take())
	require.True(t, answer("one.lab.example"))
	require.False(t, answer("two.lab.example"))
	first := s.current.instance
	require.Equal(t, string(s.current.result.Config), f.kept(RunningConfig), "the configuration that runs is kept for the user interface")

	// the same settings again: sing-box is left alone
	s.Apply()
	require.Same(t, first, s.current.instance)
	require.Equal(t, []string{"routing", "firewall update", "dns"}, f.system.take())

	// a name added to a list: the configuration is the same, a file changes, and
	// sing-box reads it again by itself
	f.settings("", oneName+"\tlist user_domains 'two.lab.example'\n")
	s.Apply()
	require.Same(t, first, s.current.instance)
	require.Eventually(t, func() bool { return answer("two.lab.example") }, 10*time.Second, 100*time.Millisecond, "the new name of the list is not answered from FakeIP")
	require.True(t, answer("one.lab.example"))
	f.system.take()

	// another configuration: sing-box is replaced
	f.settings("\toption dns_rewrite_ttl '120'\n", oneName+"\tlist user_domains 'two.lab.example'\n")
	s.Apply()
	require.NotSame(t, first, s.current.instance)
	require.True(t, answer("two.lab.example"))
	require.Equal(t, []string{"routing", "firewall update", "dns"}, f.system.take())
	second := s.current.instance

	// settings that cannot be used change nothing
	f.settings("\toption dns_rewrite_ttl '120'\n", strings.Replace(oneName, "one.lab.example", "three.lab.example", 1)+"\toption proxy_string 'vless://broken'\n")
	s.Apply()
	require.Same(t, second, s.current.instance)
	require.True(t, f.logged("nothing is changed"), "%v", f.lines())
	require.Empty(t, f.system.take())
	require.True(t, answer("two.lab.example"))
	require.False(t, answer("three.lab.example"))

	// a configuration sing-box builds and cannot start: a port of it is taken. The
	// previous configuration is started again.
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer taken.Close()
	port := taken.Addr().(*net.TCPAddr).Port
	f.settings("\toption dns_rewrite_ttl '120'\n", strings.Replace(oneName, "one.lab.example", "four.lab.example", 1)+fmt.Sprintf("\toption mixed_proxy_enabled '1'\n\toption mixed_proxy_port '%d'\n", port))
	s.Apply()
	require.True(t, s.Running(), "%v", f.lines())
	require.True(t, f.logged("going back to the previous one"), "%v", f.lines())
	// who holds the port is told: this test, which listens there
	require.True(t, f.logged(fmt.Sprintf("127.0.0.1:%d (tcp) is taken: ", port)), "%v", f.lines())
	require.True(t, f.logged(fmt.Sprintf("(pid %d) on 127.0.0.1:%d", os.Getpid(), port)), "%v", f.lines())
	require.NotSame(t, second, s.current.instance)
	require.True(t, answer("two.lab.example"), "the previous configuration does not answer after the way back")
	require.False(t, answer("four.lab.example"))
	f.system.take()
	// what is shown is what runs: the previous configuration; the refused one, with the
	// mixed proxy at the port that is taken, is beside it
	require.Equal(t, string(s.current.result.Config), f.kept(RunningConfig))
	takenPort := fmt.Sprintf(`"listen_port": %d`, port)
	require.Contains(t, f.kept(RejectedConfig), takenPort)
	require.NotContains(t, f.kept(RunningConfig), takenPort)

	// the configuration that runs is in the directory of the copies only: nothing is
	// written where the settings of podkop 0.7 named (config_path)
	_, err = os.Stat(filepath.Join(f.directory, "config.json"))
	require.True(t, os.IsNotExist(err), "a configuration outside the directory of the copies: %v", err)
	ran := string(s.current.result.Config)
	files, err := os.ReadDir(s.options.RuleSetDir)
	require.NoError(t, err)
	require.NotEmpty(t, files)

	// the stop gives the DNS of the LAN back before anything else, and leaves no rule-set
	// file; the configuration that ran is kept as the last one, nothing as running or
	// refused
	s.Stop()
	require.False(t, s.Running())
	require.Equal(t, []string{"no dns", "no firewall", "no routing"}, f.system.take())
	require.Empty(t, f.kept(RunningConfig))
	require.Empty(t, f.kept(RejectedConfig))
	require.Equal(t, ran, f.kept(LastConfig))
	require.False(t, answer("one.lab.example"))
	files, err = os.ReadDir(s.options.RuleSetDir)
	require.NoError(t, err)
	require.Empty(t, files)
}

// Settings without a key of the Clash API get one, written into them; settings saved
// without it again get the same one back, and sing-box keeps running.
func TestClashKey(t *testing.T) {
	f := newFixture(t)
	s := f.supervisor
	f.settings("", oneName)
	s.Boot()
	require.True(t, s.Running(), "%v", f.lines())
	defer s.Stop()
	require.Len(t, f.system.secrets, 1)
	key := f.system.secrets[0]
	require.Len(t, key, 32)
	require.Contains(t, string(s.current.result.Config), `"secret": "`+key+`"`)
	// the commands ask the API where it listens, with the key
	require.Equal(t, api.Facts{ClashAPI: "127.0.0.1:9090", ClashSecret: key}, s.Facts())
	first := s.current.instance
	s.Apply()
	require.Equal(t, []string{key, key}, f.system.secrets)
	require.Same(t, first, s.current.instance)
	// a key of the settings is the key, and none is written
	f.settings("\toption yacd_secret_key 'mine'\n", oneName)
	s.Apply()
	require.Len(t, f.system.secrets, 2)
	require.Contains(t, string(s.current.result.Config), `"secret": "mine"`)
	require.Equal(t, "mine", s.Facts().ClashSecret)
	s.Stop()
	require.Equal(t, api.Facts{}, s.Facts(), "nothing runs")

	// the next process finds the key in the settings; a save without it gets that key
	// back, and sing-box keeps running
	next := New(s.options)
	next.Boot()
	require.True(t, next.Running(), "%v", f.lines())
	defer next.Stop()
	running := next.current.instance
	f.settings("", oneName)
	next.Apply()
	require.Equal(t, "mine", f.system.secrets[len(f.system.secrets)-1])
	require.Len(t, f.system.secrets, 3)
	require.Same(t, running, next.current.instance)
}

// After a reboot /tmp is empty: settings whose lists sing-box downloads or reads itself
// write no rule-set file, and the directory of the cache file is made by the backend.
func TestCacheDirectoryIsMade(t *testing.T) {
	f := newFixture(t)
	s := f.supervisor
	cache := filepath.Join(f.directory, "after-reboot", "sing-box", "cache.db")
	text := "config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '127.0.0.1:9'\n" +
		"\toption cache_path '" + cache + "'\n" +
		"\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n"
	require.NoError(t, os.WriteFile(s.options.SettingsPath, []byte(text), 0o644))
	s.Boot()
	require.True(t, s.Running(), "%v", f.lines())
	defer s.Stop()
	_, err := os.Stat(cache)
	require.NoError(t, err)
}

// The facts of a state are those of its plan; nothing runs, nothing is told.
func TestFactsOf(t *testing.T) {
	require.Equal(t, api.Facts{}, factsOf(nil))
	require.Equal(t, api.Facts{ClashAPI: "192.168.1.1:9090", ClashSecret: "k"}, factsOf(&running{result: &plan.Result{Dataplane: plan.Dataplane{ClashAPI: "192.168.1.1:9090", ClashSecret: "k"}}}))
}

// dont_touch_dhcp turned on gives back, at the apply, the dnsmasq the backend took.
func TestDontTouchDHCP(t *testing.T) {
	f := newFixture(t)
	s := f.supervisor
	f.settings("", oneName)
	s.Boot()
	require.True(t, s.Running(), "%v", f.lines())
	defer s.Stop()
	f.system.take()
	f.settings("\toption dont_touch_dhcp '1'\n", oneName)
	s.Apply()
	require.Equal(t, []string{"routing", "firewall update", "no dns"}, f.system.take())
	require.True(t, f.logged("dont_touch_dhcp is on"), "%v", f.lines())
}

// What the network took (a restart of netifd flushes the rule, the loopback going down
// takes the route) is put back, and only that.
func TestRestoreRouting(t *testing.T) {
	f := newFixture(t)
	s := f.supervisor
	require.Equal(t, "nothing runs", s.restoreRouting())
	f.settings("", oneName)
	s.Boot()
	require.True(t, s.Running(), "%v", f.lines())
	defer s.Stop()
	f.system.take()
	require.Equal(t, "nothing was missing", s.restoreRouting())
	require.Equal(t, []string{"dns"}, f.system.take())
	f.system.routingGone, f.system.firewallGone = true, true
	message := s.restoreRouting()
	require.Contains(t, message, "the rule and the route of the routing table")
	require.Contains(t, message, "the firewall table")
	require.Equal(t, []string{"routing", "firewall", "dns"}, f.system.take())
	require.True(t, f.logged("the network changed"), "%v", f.lines())
	// another program let bridged packets through the IP firewall hooks (dockerd does):
	// turned off again, told, and the rest left as it is
	f.system.routingGone, f.system.firewallGone = false, false
	f.system.bridged = true
	require.Contains(t, s.restoreRouting(), "br_netfilter")
	require.True(t, f.logged("net.bridge.bridge-nf-call-iptables was 1 (br_netfilter): set to 0"), "%v", f.lines())
	require.Equal(t, []string{"dns"}, f.system.take())
}

// An interface of the settings that comes up after the backend, or gets another device, is
// taken at the next ifup: the firewall gets the device, and sing-box keeps running when its
// configuration stays the same.
func TestDevicesMoved(t *testing.T) {
	f := newFixture(t)
	s := f.supervisor
	f.settings("\tlist source_network_interfaces 'lan'\n", oneName)
	s.Boot()
	require.True(t, s.Running(), "%v", f.lines())
	defer s.Stop()
	require.Equal(t, []string{"lan"}, f.system.plans[len(f.system.plans)-1].Interfaces)
	require.Equal(t, "nothing was missing", s.restoreRouting())
	f.system.take()
	f.system.devices = map[string]string{"lan": "br-lan"}
	message := s.restoreRouting()
	require.Contains(t, message, "lan: br-lan")
	require.Contains(t, message, "sing-box keeps running")
	require.Equal(t, []string{"br-lan"}, f.system.plans[len(f.system.plans)-1].Interfaces)
	require.Contains(t, f.system.take(), "firewall update")
	require.True(t, f.logged("the network changed under the settings (lan: br-lan): they are applied again"), "%v", f.lines())
	// the same devices at the next ifup: nothing is applied
	require.Equal(t, "nothing was missing", s.restoreRouting())
	// netifd that does not answer: an apply keeps the devices the names stood for, and no
	// name moves
	f.system.devices = nil
	require.True(t, s.Apply().OK, "%v", f.lines())
	require.Equal(t, []string{"br-lan"}, f.system.plans[len(f.system.plans)-1].Interfaces)
	require.Equal(t, "nothing was missing", s.restoreRouting())
}

// Settings that cannot be used at the boot leave the router without the backend and with
// its own DNS; settings that can be used later bring it up.
func TestBootWithUnusableSettings(t *testing.T) {
	f := newFixture(t)
	s := f.supervisor
	f.settings("", oneName+"\toption proxy_string 'vless://broken'\n")
	s.Boot()
	require.False(t, s.Running())
	require.Equal(t, []string{"no dns", "no firewall", "no routing"}, f.system.take())
	require.True(t, f.logged("[error]"))
	require.Equal(t, "released", f.state(), "the guard must not judge a backend that has given the router back")
	f.settings("", oneName)
	s.Apply()
	require.True(t, s.Running(), "%v", f.lines())
	require.Equal(t, []string{"routing", "firewall", "dns"}, f.system.take())
	require.True(t, answer("one.lab.example"))
	require.Equal(t, "running", f.state())
	s.Stop()
	require.Equal(t, "stopped", f.state())
}

// Settings whose rules name no filled source (those of a fresh install) leave the router alone
// without an error; a source filled brings the backend up, and emptied again gives the router
// back.
func TestNothingToRoute(t *testing.T) {
	f := newFixture(t)
	s := f.supervisor
	write := func(link string) {
		text := "config settings 'settings'\n\toption config_version '2'\n\toption dns_type 'udp'\n\toption dns_server '127.0.0.1:9'\n" +
			"\toption cache_path '" + filepath.Join(f.directory, "cache.db") + "'\n" +
			"\nconfig source 'src1'\n" + link +
			"\nconfig section 'main'\n" + oneName +
			"\nconfig member\n\toption section 'main'\n\toption role 'server'\n\toption source 'src1'\n"
		require.NoError(t, os.WriteFile(s.options.SettingsPath, []byte(text), 0o644))
	}
	write("")
	result := s.Boot()
	require.True(t, result.OK, result.Message)
	require.False(t, s.Running())
	require.Equal(t, []string{"no dns", "no firewall", "no routing"}, f.system.take())
	require.Equal(t, "released", f.state())
	require.False(t, f.logged("[error]"), "%v", f.lines())
	require.True(t, f.logged("no rule has a server yet"), "%v", f.lines())
	write("\toption type 'links'\n\tlist link 'socks5://u:p@203.0.113.15:1080#s5'\n")
	require.True(t, s.Apply().OK, "%v", f.lines())
	require.True(t, s.Running())
	require.Equal(t, []string{"routing", "firewall", "dns"}, f.system.take())
	require.True(t, answer("one.lab.example"))
	write("")
	result = s.Apply()
	require.True(t, result.OK, result.Message)
	require.False(t, s.Running())
	require.Equal(t, []string{"no dns", "no firewall", "no routing"}, f.system.take())
	require.Equal(t, "released", f.state())
	require.False(t, answer("one.lab.example"))
	s.Stop()
}

// A fault while the settings are read refuses them as unusable settings are refused: the
// process stays, and procd does not start it again and again on the same settings.
func TestBootSurvivesAFault(t *testing.T) {
	f := newFixture(t)
	s := f.supervisor
	f.settings("", oneName)
	faultWhileReading = func() { panic("a fault for the test") }
	defer func() { faultWhileReading = nil }()
	result := s.Boot()
	require.False(t, s.Running())
	require.Contains(t, result.Message, "a fault for the test")
	require.Equal(t, "released", f.state())
	faultWhileReading = nil
	s.Apply()
	require.True(t, s.Running(), "%v", f.lines())
	require.True(t, answer("one.lab.example"))
	s.Stop()
}

// The firewall sets are what the rule sets hold: the settings give the first content,
// and a rule set sing-box reads again gives the next.
func TestFirewallFollowsTheRuleSets(t *testing.T) {
	f := newFixture(t)
	s := f.supervisor
	subnets := "\toption user_subnet_list_type 'dynamic'\n\tlist user_subnets '198.51.100.8/30'\n\tlist fully_routed_ips '192.168.1.60'\n"
	f.settings("\tlist source_network_interfaces 'br-lan'\n\tlist source_network_interfaces 'eth1'\n\toption exclude_ntp '1'\n", oneName+subnets)
	s.Boot()
	require.True(t, s.Running(), "%v", f.lines())
	defer s.Stop()
	first := f.system.plans[len(f.system.plans)-1]
	require.Equal(t, []string{"br-lan", "eth1"}, first.Interfaces)
	require.True(t, first.ExcludeNTP)
	require.Equal(t, "[192.168.1.60/32]", fmt.Sprint(first.Sources))
	require.Equal(t, "[198.51.100.8/30]", fmt.Sprint(firewall.RangeStrings(first.Subnets)))

	// the list changes: the settings are applied, and sing-box tells of the file it read again
	f.settings("\tlist source_network_interfaces 'br-lan'\n\tlist source_network_interfaces 'eth1'\n\toption exclude_ntp '1'\n",
		oneName+strings.Replace(subnets, "198.51.100.8/30", "203.0.113.0/24", 1))
	instance := s.current.instance
	s.Apply()
	require.Same(t, instance, s.current.instance)
	require.Equal(t, "[203.0.113.0/24]", fmt.Sprint(firewall.RangeStrings(f.system.plans[len(f.system.plans)-1].Subnets)))
	select {
	case <-s.derive:
	case <-time.After(10 * time.Second):
		t.Fatal("sing-box did not tell of the rule set it read again")
	}
	before := len(f.system.plans)
	s.refreshFirewall()
	require.Len(t, f.system.plans, before+1)
	require.Equal(t, "[203.0.113.0/24]", fmt.Sprint(firewall.RangeStrings(f.system.plans[len(f.system.plans)-1].Subnets)))
}

// An update asked for from outside downloads again every list: the rule set files and the
// lists written as plain text alike, all of them rule sets sing-box downloads. None waits
// for its interval.
func TestUpdateListsOnRequest(t *testing.T) {
	var ruleSetName, plainName atomic.Value
	ruleSetName.Store("first.lab.example")
	plainName.Store("plain-one.lab.example")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/names.json":
			io.WriteString(writer, `{"version":3,"rules":[{"domain_suffix":["`+ruleSetName.Load().(string)+`"]}]}`)
		case "/plain.lst":
			io.WriteString(writer, plainName.Load().(string)+"\n")
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	f := newFixture(t)
	s := f.supervisor
	f.settings("", oneName+"\tlist remote_domain_lists '"+server.URL+"/names.json'\n\tlist remote_domain_lists '"+server.URL+"/plain.lst'\n")
	s.Boot()
	require.True(t, s.Running(), "%v", f.lines())
	defer s.Stop()
	require.Eventually(t, func() bool { return answer("first.lab.example") && answer("plain-one.lab.example") },
		20*time.Second, 100*time.Millisecond, "the lists of the start did not come: %v", f.lines())

	// both lists change where they are published; the next download of each is a day away
	ruleSetName.Store("second.lab.example")
	plainName.Store("plain-two.lab.example")
	reply := make(chan ListsUpdate, 1)
	s.updateLists(reply)
	var result ListsUpdate
	select {
	case result = <-reply:
	case <-time.After(30 * time.Second):
		t.Fatal("the update did not end")
	}
	require.True(t, result.OK, "%v", result.Lines)
	require.Equal(t, []string{"rule sets: 2 asked, 2 with a new list, 0 failed"}, result.Lines)
	require.Eventually(t, func() bool { return answer("second.lab.example") && answer("plain-two.lab.example") },
		20*time.Second, 100*time.Millisecond, "the new lists are not used: %v", f.lines())
	require.False(t, answer("first.lab.example"), "a name the list no longer has is still answered from FakeIP")

	// a list that cannot be downloaded is told, and the update is not a success
	server.Close()
	s.updateLists(reply)
	select {
	case result = <-reply:
	case <-time.After(60 * time.Second):
		t.Fatal("the update did not end")
	}
	require.False(t, result.OK, "%v", result.Lines)
	require.Contains(t, result.Lines[0], "rule sets: 2 asked, 0 with a new list, 2 failed")
	require.True(t, answer("second.lab.example") && answer("plain-two.lab.example"), "a failed update took away the lists that were there")

	// the state of the lists: each downloaded one in its format, with the time of its
	// last download; the user list is a file of the backend
	formats := make(map[string]ListState)
	for _, state := range s.listStatus() {
		formats[state.Kind+" "+state.Format] = state
	}
	require.Equal(t, server.URL+"/names.json", formats["remote source"].URL, "%+v", formats)
	require.NotNil(t, formats["remote source"].LastUpdated)
	require.Equal(t, server.URL+"/plain.lst", formats["remote text"].URL, "%+v", formats)
	require.NotNil(t, formats["remote text"].LastUpdated)
	require.Contains(t, formats, "file ", "%+v", formats)

	// nothing runs: nothing to update
	s.Stop()
	s.updateLists(reply)
	require.Equal(t, ListsUpdate{Lines: []string{"nothing runs: there are no lists to update"}}, <-reply)
}

// A check name: its DNS question is answered from FakeIP, a connection to it through the
// transparent proxy inbound is seen and ends on this host, and the backend tells both.
// The firewall that would bring a connection of the LAN to the inbound is not here: the
// test connects to the inbound itself, and sing-box learns the name from the TLS hello.
func TestProbe(t *testing.T) {
	f := newFixture(t)
	watcher := probe.NewWatcher()
	f.supervisor.options.Watcher = watcher
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go probe.ServeDeadEnd(ctx, func(string, string) {})
	s := f.supervisor
	f.settings("", oneName)
	done := make(chan struct{})
	go func() {
		s.Run(ctx, nil)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	require.Eventually(t, func() bool { return answer("one.lab.example") }, 20*time.Second, 100*time.Millisecond, "%v", f.lines())

	// nothing was asked and nothing came: the answer waits its time and says so
	label := probe.NewLabel()
	began := time.Now()
	require.Equal(t, ProbeResult{}, s.Probe(ctx, label, 300*time.Millisecond))
	require.GreaterOrEqual(t, time.Since(began), 300*time.Millisecond)

	// the DNS question alone
	require.True(t, answer(probe.Name(label)), "a check name is not answered from FakeIP: %v", f.lines())
	result := s.Probe(ctx, label, 300*time.Millisecond)
	require.True(t, result.DNS)
	require.False(t, result.Connection)
	require.True(t, strings.HasPrefix(result.Address, "198.18."), result.Address)

	// and the connection: the question is asked first and answered when it comes
	answered := make(chan ProbeResult, 1)
	go func() { answered <- s.Probe(ctx, label, 10*time.Second) }()
	time.Sleep(200 * time.Millisecond)
	connection, err := net.DialTimeout("tcp", "127.0.0.1:1602", 5*time.Second)
	require.NoError(t, err)
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	// the hello is all that matters; the handshake ends when the dead end closes
	require.Error(t, tls.Client(connection, &tls.Config{ServerName: probe.Name(label), InsecureSkipVerify: true}).Handshake())
	select {
	case result = <-answered:
	case <-time.After(15 * time.Second):
		t.Fatal("the question about the check name was not answered")
	}
	require.Equal(t, ProbeResult{DNS: true, Connection: true, Client: "127.0.0.1", Address: result.Address}, result, "%v", f.lines())
	require.Less(t, time.Since(began), 8*time.Second, "the answer waited for its whole time")

	// what is no label is not asked about
	require.Equal(t, ProbeResult{}, s.Probe(ctx, "NO SUCH", time.Second))
	// the configuration that runs has the rules of the check names, after the service ones
	config := f.kept(RunningConfig)
	require.Contains(t, config, `"domain_suffix": "fakeipchecker.podkop.net"`)
	require.Contains(t, config, `"override_address": "127.0.0.1"`)
}
