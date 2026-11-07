package dnsmasq

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// router is a System that keeps what was done to it.
type router struct {
	settings   string
	scripts    []string
	applies    int
	resolvFile bool
}

func (r *router) ReadSettings() ([]byte, error) { return []byte(r.settings), nil }
func (r *router) Batch(script string) error     { r.scripts = append(r.scripts, script); return nil }
func (r *router) Apply() error                  { r.applies++; return nil }
func (r *router) Exists(string) bool            { return r.resolvFile }

func lines(script string) []string {
	return strings.Split(strings.TrimSpace(script), "\n")
}

func TestTakeOver(t *testing.T) {
	t.Parallel()
	system := &router{settings: "config dnsmasq\n\toption cachesize '1000'\n\tlist server '8.8.8.8'\n\tlist server '/lan/192.168.1.1'\n\toption noresolv '0'\n"}
	changed, err := TakeOver(system)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, 1, system.applies)
	require.Equal(t, []string{
		"add_list dhcp.@dnsmasq[0].podkop_server='8.8.8.8'",
		"del_list dhcp.@dnsmasq[0].server='8.8.8.8'",
		"set dhcp.@dnsmasq[0].podkop_noresolv='0'",
		"set dhcp.@dnsmasq[0].podkop_cachesize='1000'",
		"add_list dhcp.@dnsmasq[0].server='127.0.0.42'",
		"set dhcp.@dnsmasq[0].noresolv='1'",
		"set dhcp.@dnsmasq[0].cachesize='0'",
		"set dhcp.@dnsmasq[0].podkop_taken='1'",
		"commit dhcp",
	}, lines(system.scripts[0]))

	// a dnsmasq with nothing set: nothing to keep
	system = &router{settings: "config dnsmasq\n\toption domain 'lan'\n"}
	_, err = TakeOver(system)
	require.NoError(t, err)
	require.Equal(t, []string{"add_list dhcp.@dnsmasq[0].server='127.0.0.42'", "set dhcp.@dnsmasq[0].noresolv='1'", "set dhcp.@dnsmasq[0].cachesize='0'",
		"set dhcp.@dnsmasq[0].podkop_taken='1'", "commit dhcp"}, lines(system.scripts[0]))

	// it asks the backend already: nothing is done, dnsmasq is not started again
	system = &router{settings: "config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n\tlist podkop_server '8.8.8.8'\n"}
	changed, err = TakeOver(system)
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, system.scripts)
	require.Zero(t, system.applies)

	// it asks the backend with nothing kept and no marker: marked, not started again
	system = &router{settings: "config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n"}
	changed, err = TakeOver(system)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, []string{"set dhcp.@dnsmasq[0].podkop_taken='1'", "commit dhcp"}, lines(system.scripts[0]))
	require.Zero(t, system.applies)

	// marked and kept, but given back by hand since (no 127.0.0.42): what was kept is
	// stale, what it has now is kept
	system = &router{settings: "config dnsmasq\n\tlist server '1.1.1.1'\n\toption cachesize '500'\n\tlist podkop_server '8.8.8.8'\n\toption podkop_cachesize '1000'\n\toption podkop_taken '1'\n"}
	_, err = TakeOver(system)
	require.NoError(t, err)
	require.Equal(t, []string{
		"delete dhcp.@dnsmasq[0].podkop_server",
		"delete dhcp.@dnsmasq[0].podkop_noresolv",
		"delete dhcp.@dnsmasq[0].podkop_cachesize",
		"add_list dhcp.@dnsmasq[0].podkop_server='1.1.1.1'",
		"del_list dhcp.@dnsmasq[0].server='1.1.1.1'",
		"set dhcp.@dnsmasq[0].podkop_cachesize='500'",
		"add_list dhcp.@dnsmasq[0].server='127.0.0.42'",
		"set dhcp.@dnsmasq[0].noresolv='1'",
		"set dhcp.@dnsmasq[0].cachesize='0'",
		"set dhcp.@dnsmasq[0].podkop_taken='1'",
		"commit dhcp",
	}, lines(system.scripts[0]))

	_, err = TakeOver(&router{settings: "config dhcp 'lan'\n"})
	require.Error(t, err)

	// taken over before, then a forwarding for the names of a domain added while the backend
	// ran (another package, the user): it stays, and nothing is done; a server for every name
	// added is kept with the others, the forwarding stays where it is
	system = &router{settings: "config dnsmasq\n\tlist server '127.0.0.42'\n\tlist server '/corp.lan/192.168.1.5'\n\toption noresolv '1'\n\toption cachesize '0'\n" +
		"\tlist podkop_server '8.8.8.8'\n\toption podkop_cachesize '1000'\n\toption podkop_taken '1'\n"}
	changed, err = TakeOver(system)
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, system.scripts)
	require.Zero(t, system.applies)
	system = &router{settings: "config dnsmasq\n\tlist server '127.0.0.42'\n\tlist server '/corp.lan/192.168.1.5'\n\tlist server '9.9.9.9'\n\toption noresolv '1'\n\toption cachesize '0'\n" +
		"\tlist podkop_server '8.8.8.8'\n\toption podkop_cachesize '1000'\n\toption podkop_taken '1'\n"}
	changed, err = TakeOver(system)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, []string{
		"add_list dhcp.@dnsmasq[0].podkop_server='9.9.9.9'",
		"del_list dhcp.@dnsmasq[0].server='9.9.9.9'",
		"set dhcp.@dnsmasq[0].noresolv='1'",
		"set dhcp.@dnsmasq[0].cachesize='0'",
		"set dhcp.@dnsmasq[0].podkop_taken='1'",
		"commit dhcp",
	}, lines(system.scripts[0]))
}

// At boot dnsmasq is set before it starts: the same settings as TakeOver, no start.
func TestPrepare(t *testing.T) {
	t.Parallel()
	settings := "config dnsmasq\n\toption cachesize '1000'\n\tlist server '8.8.8.8'\n"
	prepared := &router{settings: settings}
	changed, err := Prepare(prepared)
	require.NoError(t, err)
	require.True(t, changed)
	require.Zero(t, prepared.applies)
	taken := &router{settings: settings}
	_, err = TakeOver(taken)
	require.NoError(t, err)
	require.Equal(t, taken.scripts, prepared.scripts)

	// set already (a boot after a lost power, when the stop that gives it back never ran)
	prepared = &router{settings: "config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n\toption podkop_taken '1'\n"}
	changed, err = Prepare(prepared)
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, prepared.scripts)
	require.Zero(t, prepared.applies)
}

func TestRestore(t *testing.T) {
	t.Parallel()
	system := &router{settings: "config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n\tlist podkop_server '8.8.8.8'\n\tlist podkop_server '9.9.9.9'\n\toption podkop_noresolv '1'\n\toption podkop_cachesize '1000'\n"}
	changed, err := Restore(system)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, 1, system.applies)
	require.Equal(t, []string{
		"set dhcp.@dnsmasq[0].cachesize='1000'",
		"delete dhcp.@dnsmasq[0].podkop_cachesize",
		"set dhcp.@dnsmasq[0].noresolv='1'",
		"delete dhcp.@dnsmasq[0].podkop_noresolv",
		"del_list dhcp.@dnsmasq[0].server='127.0.0.42'",
		"add_list dhcp.@dnsmasq[0].server='8.8.8.8'",
		"add_list dhcp.@dnsmasq[0].server='9.9.9.9'",
		"delete dhcp.@dnsmasq[0].podkop_server",
		"commit dhcp",
	}, lines(system.scripts[0]))

	// taken over with nothing to keep: the resolvers netifd collects, and dnsmasq told to
	// read them
	system = &router{resolvFile: true, settings: "config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n\toption podkop_taken '1'\n"}
	_, err = Restore(system)
	require.NoError(t, err)
	require.Equal(t, []string{"delete dhcp.@dnsmasq[0].podkop_taken", "set dhcp.@dnsmasq[0].cachesize='150'", "set dhcp.@dnsmasq[0].noresolv='0'", "del_list dhcp.@dnsmasq[0].server='127.0.0.42'",
		"set dhcp.@dnsmasq[0].resolvfile='/tmp/resolv.conf.d/resolv.conf.auto'", "commit dhcp"}, lines(system.scripts[0]))

	// set by hand to ask the backend (dont_touch_dhcp), with nothing kept and no marker:
	// it is the user's setting, and it stays
	system = &router{resolvFile: true, settings: "config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n"}
	changed, err = Restore(system)
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, system.scripts)

	// it was told not to read the resolvers and has no servers kept
	system = &router{resolvFile: true, settings: "config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n\toption podkop_noresolv '1'\n"}
	_, err = Restore(system)
	require.NoError(t, err)
	require.Contains(t, lines(system.scripts[0]), "set dhcp.@dnsmasq[0].noresolv='0'")

	// a forwarding added by hand while the backend ran stays; with no server for every
	// name kept, the resolvers are read, and a resolv file set by hand stays
	system = &router{resolvFile: true, settings: "config dnsmasq\n\tlist server '127.0.0.42'\n\tlist server '/corp.lan/192.168.1.5'\n\toption noresolv '1'\n\toption cachesize '0'\n" +
		"\toption podkop_cachesize '1000'\n\toption podkop_taken '1'\n\toption resolvfile '/etc/resolv.mine'\n"}
	_, err = Restore(system)
	require.NoError(t, err)
	require.Equal(t, []string{"delete dhcp.@dnsmasq[0].podkop_taken", "set dhcp.@dnsmasq[0].cachesize='1000'", "delete dhcp.@dnsmasq[0].podkop_cachesize",
		"set dhcp.@dnsmasq[0].noresolv='0'", "del_list dhcp.@dnsmasq[0].server='127.0.0.42'", "commit dhcp"}, lines(system.scripts[0]))

	// a dnsmasq the backend never touched is left alone
	system = &router{settings: "config dnsmasq\n\tlist server '8.8.8.8'\n\toption cachesize '1000'\n"}
	changed, err = Restore(system)
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, system.scripts)
	require.Zero(t, system.applies)
}

func TestQuote(t *testing.T) {
	t.Parallel()
	require.Equal(t, `'/it'\''s/1.2.3.4'`, Quote("/it's/1.2.3.4"))
}

// Which lines of dnsmasq are asked for every name, as dnsmasq 2.93 reads them (measured with
// rs-lab/rb/guest-fwd.sh): a line without a domain, and one with the domain "#" or "*".
func TestForEveryName(t *testing.T) {
	t.Parallel()
	for _, server := range []string{"8.8.8.8", "127.0.0.1#5053", "1.1.1.1@wan", "2001:db8::1", "fe80::1%br-lan#53", "dns.example",
		"/#/1.1.1.1", "/*/1.1.1.1", "/#/", "/example.com/#/1.1.1.1", "/", "/1.1.1.1", "127.0.0.42"} {
		require.True(t, ForEveryName(server), server)
	}
	for _, server := range []string{"/example.com/1.1.1.1", "/.ts.net/100.100.100.100", "/*.example.com/1.1.1.1", "/*google.com/1.1.1.1",
		"/a.lan/b.lan/192.168.1.5", "//192.168.1.1", "/example.com/", "/lan/", "/example.com/#", "/example.com/192.168.1.5#5353@br-lan",
		"/example.com/fe80::1%br-lan#53", "/1.168.192.in-addr.arpa/192.168.1.1", "/example.com/127.0.0.42", "/example.com//1.1.1.1"} {
		require.False(t, ForEveryName(server), server)
	}
	require.True(t, AsksBackend([]string{"127.0.0.42", "/.ts.net/100.100.100.100", "/lan/"}))
	require.False(t, AsksBackend([]string{"127.0.0.42", "/#/1.1.1.1"}))
	require.False(t, AsksBackend([]string{"127.0.0.42", "8.8.8.8"}))
	require.False(t, AsksBackend([]string{"/.ts.net/100.100.100.100"}))
	require.False(t, AsksBackend(nil))
	domains, upstream := Split("/a.lan/b.lan/192.168.1.5#5353")
	require.Equal(t, []string{"a.lan", "b.lan"}, domains)
	require.Equal(t, "192.168.1.5#5353", upstream)
	domains, upstream = Split("//192.168.1.1")
	require.Equal(t, []string{""}, domains)
	require.Equal(t, "192.168.1.1", upstream)
	domains, upstream = Split("/lan/")
	require.Equal(t, []string{"lan"}, domains)
	require.Empty(t, upstream)
	domains, upstream = Split("8.8.8.8")
	require.Empty(t, domains)
	require.Equal(t, "8.8.8.8", upstream)
}

// The forms of the forwarding for the names of a domain stay where they are when dnsmasq is
// taken over and when it is given back; those for every name go and come back; a stop
// leaves the same servers as before the start.
func TestTakeOverForwardings(t *testing.T) {
	t.Parallel()
	forwardings := []string{"/.ts.net/100.100.100.100", "/*.corp.example/10.8.0.1", "/*google.example/192.168.1.5#5353@br-lan", "/a.lan/b.lan/192.168.1.5",
		"//192.168.1.1", "/local.example/", "/www.example/#", "/1.168.192.in-addr.arpa/192.168.1.1", "/v6.example/fe80::1%br-lan#53"}
	every := []string{"8.8.8.8", "/#/1.1.1.1", "/*/9.9.9.9", "127.0.0.1#5053"}
	var settings strings.Builder
	settings.WriteString("config dnsmasq\n\toption cachesize '1000'\n")
	for i := range max(len(forwardings), len(every)) {
		if i < len(every) {
			settings.WriteString("\tlist server '" + every[i] + "'\n")
		}
		if i < len(forwardings) {
			settings.WriteString("\tlist server '" + forwardings[i] + "'\n")
		}
	}
	system := &router{settings: settings.String()}
	changed, err := TakeOver(system)
	require.NoError(t, err)
	require.True(t, changed)
	taken := applied(t, settings.String(), system.scripts[0])
	require.Equal(t, append(forwardings, "127.0.0.42"), taken.servers)
	require.Equal(t, every, taken.keptServers)
	require.True(t, taken.ours())

	// taken: nothing more to do, also at boot
	system = &router{settings: render(taken)}
	changed, err = TakeOver(system)
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, system.scripts)
	changed, err = Prepare(system)
	require.NoError(t, err)
	require.False(t, changed)

	// given back: the same servers as before, those for every name after the forwardings
	system = &router{settings: render(taken)}
	changed, err = Restore(system)
	require.NoError(t, err)
	require.True(t, changed)
	given := applied(t, render(taken), system.scripts[0])
	require.ElementsMatch(t, append(append([]string{}, forwardings...), every...), given.servers)
	require.Empty(t, given.keptServers)
	require.False(t, given.taken())

	// nothing but forwardings: given back with the resolvers netifd collects
	system = &router{resolvFile: true, settings: "config dnsmasq\n\tlist server '/.ts.net/100.100.100.100'\n"}
	_, err = TakeOver(system)
	require.NoError(t, err)
	taken = applied(t, system.settings, system.scripts[0])
	require.Equal(t, []string{"/.ts.net/100.100.100.100", "127.0.0.42"}, taken.servers)
	system = &router{resolvFile: true, settings: render(taken)}
	_, err = Restore(system)
	require.NoError(t, err)
	require.Contains(t, lines(system.scripts[0]), "set dhcp.@dnsmasq[0].resolvfile='/tmp/resolv.conf.d/resolv.conf.auto'")
}

// A dnsmasq the shell backend or a release before this one took over keeps its forwardings
// with the servers it kept: they go back to work, once, and dnsmasq takes them.
func TestTakeOverForwardingsKeptBefore(t *testing.T) {
	t.Parallel()
	before := "config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n" +
		"\tlist podkop_server '8.8.8.8'\n\tlist podkop_server '/.ts.net/100.100.100.100'\n\tlist podkop_server '/#/1.1.1.1'\n\toption podkop_cachesize '150'\n\toption podkop_taken '1'\n"
	system := &router{settings: before}
	changed, err := TakeOver(system)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, 1, system.applies)
	require.Equal(t, []string{
		"delete dhcp.@dnsmasq[0].podkop_server",
		"add_list dhcp.@dnsmasq[0].podkop_server='8.8.8.8'",
		"add_list dhcp.@dnsmasq[0].podkop_server='/#/1.1.1.1'",
		"add_list dhcp.@dnsmasq[0].server='/.ts.net/100.100.100.100'",
		"commit dhcp",
	}, lines(system.scripts[0]))
	taken := applied(t, before, system.scripts[0])
	system = &router{settings: render(taken)}
	changed, err = TakeOver(system)
	require.NoError(t, err)
	require.False(t, changed)

	// the same with a server for every name added meanwhile: both in one go
	system = &router{settings: strings.Replace(before, "\toption noresolv", "\tlist server '9.9.9.9'\n\toption noresolv", 1)}
	_, err = TakeOver(system)
	require.NoError(t, err)
	taken = applied(t, system.settings, system.scripts[0])
	require.Equal(t, []string{"127.0.0.42", "/.ts.net/100.100.100.100"}, taken.servers)
	require.Equal(t, []string{"8.8.8.8", "/#/1.1.1.1", "9.9.9.9"}, taken.keptServers)

	// given back without being taken over again: the forwarding kept comes back too
	system = &router{settings: before}
	_, err = Restore(system)
	require.NoError(t, err)
	given := applied(t, before, system.scripts[0])
	require.Equal(t, []string{"8.8.8.8", "/.ts.net/100.100.100.100", "/#/1.1.1.1"}, given.servers)
}

// applied runs a script of "uci batch" on the first dnsmasq of settings, as far as the
// commands of this package go, and reads the result.
func applied(t *testing.T, settings string, script string) *state {
	t.Helper()
	parsed, err := read(&router{settings: settings})
	require.NoError(t, err)
	options := map[string]string{"noresolv": parsed.noResolv, "cachesize": parsed.cacheSize, "resolvfile": parsed.resolvFile,
		"podkop_noresolv": parsed.keptNoResolv, "podkop_cachesize": parsed.keptCacheSize}
	if parsed.marked {
		options[marker] = "1"
	}
	lists := map[string][]string{"server": parsed.servers, "podkop_server": parsed.keptServers}
	unquote := func(value string) string {
		require.True(t, strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'"), value)
		return strings.ReplaceAll(value[1:len(value)-1], `'\''`, "'")
	}
	for _, line := range lines(script) {
		command, rest, _ := strings.Cut(line, " ")
		if command == "commit" {
			continue
		}
		path, value, _ := strings.Cut(rest, "=")
		option := strings.TrimPrefix(path, section+".")
		switch command {
		case "set":
			options[option] = unquote(value)
		case "delete":
			delete(options, option)
			delete(lists, option)
		case "add_list":
			lists[option] = append(lists[option], unquote(value))
		case "del_list":
			var left []string
			for _, item := range lists[option] {
				if item != unquote(value) {
					left = append(left, item)
				}
			}
			lists[option] = left
		default:
			t.Fatalf("a command this test does not know: %s", line)
		}
	}
	return &state{servers: lists["server"], keptServers: lists["podkop_server"], noResolv: options["noresolv"], cacheSize: options["cachesize"],
		resolvFile: options["resolvfile"], keptNoResolv: options["podkop_noresolv"], keptCacheSize: options["podkop_cachesize"], marked: options[marker] == "1"}
}

// render writes a state as the settings of dnsmasq.
func render(s *state) string {
	var text strings.Builder
	text.WriteString("config dnsmasq\n")
	option := func(name string, value string) {
		if value != "" {
			text.WriteString("\toption " + name + " '" + value + "'\n")
		}
	}
	option("noresolv", s.noResolv)
	option("cachesize", s.cacheSize)
	option("resolvfile", s.resolvFile)
	option("podkop_noresolv", s.keptNoResolv)
	option("podkop_cachesize", s.keptCacheSize)
	if s.marked {
		option(marker, "1")
	}
	for _, server := range s.servers {
		text.WriteString("\tlist server '" + server + "'\n")
	}
	for _, server := range s.keptServers {
		text.WriteString("\tlist podkop_server '" + server + "'\n")
	}
	return text.String()
}
