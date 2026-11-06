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
	reloads    int
	resolvFile bool
}

func (r *router) ReadSettings() ([]byte, error) { return []byte(r.settings), nil }
func (r *router) Batch(script string) error     { r.scripts = append(r.scripts, script); return nil }
func (r *router) Reload() error                 { r.reloads++; return nil }
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
	require.Equal(t, 1, system.reloads)
	require.Equal(t, []string{
		"add_list dhcp.@dnsmasq[0].podkop_server='8.8.8.8'",
		"add_list dhcp.@dnsmasq[0].podkop_server='/lan/192.168.1.1'",
		"delete dhcp.@dnsmasq[0].server",
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

	// it asks the backend already: nothing is done, dnsmasq is not reloaded
	system = &router{settings: "config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n\tlist podkop_server '8.8.8.8'\n"}
	changed, err = TakeOver(system)
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, system.scripts)
	require.Zero(t, system.reloads)

	// it asks the backend with nothing kept and no marker: marked, not reloaded
	system = &router{settings: "config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n"}
	changed, err = TakeOver(system)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, []string{"set dhcp.@dnsmasq[0].podkop_taken='1'", "commit dhcp"}, lines(system.scripts[0]))
	require.Zero(t, system.reloads)

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
		"delete dhcp.@dnsmasq[0].server",
		"set dhcp.@dnsmasq[0].podkop_cachesize='500'",
		"add_list dhcp.@dnsmasq[0].server='127.0.0.42'",
		"set dhcp.@dnsmasq[0].noresolv='1'",
		"set dhcp.@dnsmasq[0].cachesize='0'",
		"set dhcp.@dnsmasq[0].podkop_taken='1'",
		"commit dhcp",
	}, lines(system.scripts[0]))

	_, err = TakeOver(&router{settings: "config dhcp 'lan'\n"})
	require.Error(t, err)

	// taken over before, then a forwarding added by hand while the backend ran: what was
	// kept the first time stays (not the backend's own noresolv and cache size), the
	// forwarding is kept beside the servers kept
	system = &router{settings: "config dnsmasq\n\tlist server '127.0.0.42'\n\tlist server '/corp.lan/192.168.1.5'\n\toption noresolv '1'\n\toption cachesize '0'\n" +
		"\tlist podkop_server '8.8.8.8'\n\toption podkop_cachesize '1000'\n\toption podkop_taken '1'\n"}
	changed, err = TakeOver(system)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, []string{
		"add_list dhcp.@dnsmasq[0].podkop_server='/corp.lan/192.168.1.5'",
		"delete dhcp.@dnsmasq[0].server",
		"add_list dhcp.@dnsmasq[0].server='127.0.0.42'",
		"set dhcp.@dnsmasq[0].noresolv='1'",
		"set dhcp.@dnsmasq[0].cachesize='0'",
		"set dhcp.@dnsmasq[0].podkop_taken='1'",
		"commit dhcp",
	}, lines(system.scripts[0]))
}

// At boot dnsmasq is set before it starts: the same settings as TakeOver, no reload.
func TestPrepare(t *testing.T) {
	t.Parallel()
	settings := "config dnsmasq\n\toption cachesize '1000'\n\tlist server '8.8.8.8'\n"
	prepared := &router{settings: settings}
	changed, err := Prepare(prepared)
	require.NoError(t, err)
	require.True(t, changed)
	require.Zero(t, prepared.reloads)
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
	require.Zero(t, prepared.reloads)
}

func TestRestore(t *testing.T) {
	t.Parallel()
	system := &router{settings: "config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n\tlist podkop_server '8.8.8.8'\n\tlist podkop_server '9.9.9.9'\n\toption podkop_noresolv '1'\n\toption podkop_cachesize '1000'\n"}
	changed, err := Restore(system)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, 1, system.reloads)
	require.Equal(t, []string{
		"set dhcp.@dnsmasq[0].cachesize='1000'",
		"delete dhcp.@dnsmasq[0].podkop_cachesize",
		"set dhcp.@dnsmasq[0].noresolv='1'",
		"delete dhcp.@dnsmasq[0].podkop_noresolv",
		"delete dhcp.@dnsmasq[0].server",
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
	require.Equal(t, []string{"delete dhcp.@dnsmasq[0].podkop_taken", "set dhcp.@dnsmasq[0].cachesize='150'", "set dhcp.@dnsmasq[0].noresolv='0'", "delete dhcp.@dnsmasq[0].server",
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
		"set dhcp.@dnsmasq[0].noresolv='0'", "delete dhcp.@dnsmasq[0].server", "add_list dhcp.@dnsmasq[0].server='/corp.lan/192.168.1.5'", "commit dhcp"}, lines(system.scripts[0]))

	// a dnsmasq the backend never touched is left alone
	system = &router{settings: "config dnsmasq\n\tlist server '8.8.8.8'\n\toption cachesize '1000'\n"}
	changed, err = Restore(system)
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, system.scripts)
	require.Zero(t, system.reloads)
}

func TestQuote(t *testing.T) {
	t.Parallel()
	require.Equal(t, `'/it'\''s/1.2.3.4'`, Quote("/it's/1.2.3.4"))
}
