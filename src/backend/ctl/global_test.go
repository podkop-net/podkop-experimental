package ctl

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/diag"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/sockets"
	"github.com/stretchr/testify/require"
)

func TestWANBlock(t *testing.T) {
	t.Parallel()
	network := `config interface 'lan'
	option proto 'static'
	option ipaddr '192.168.1.1'

config interface 'wan'
	option device 'eth1'
	option proto 'pppoe'
	option username 'me'
	option password 'secret'
	option ipaddr '10.0.0.2'

config interface 'wan6'
	option proto 'dhcpv6'
`
	require.Equal(t, []string{"config interface 'wan'", "\toption device 'eth1'", "\toption proto 'pppoe'", "        option username '******'", "        option password '******'", "\toption ipaddr '10.0.0.2'", ""}, wanBlock(network))
	static := "config interface 'wan'\n\toption proto 'static'\n\toption ipaddr '198.51.100.2'\n\toption netmask '255.255.255.0'\n\toption gateway '198.51.100.1'\n\toption dns '1.1.1.1'\n"
	require.Equal(t, []string{"config interface 'wan'", "\toption proto 'static'", "        option ipaddr '******'", "        option netmask '******'", "        option gateway '******'", "\toption dns '1.1.1.1'"}, wanBlock(static))
	require.Equal(t, []string{"config dnsmasq", "\toption noresolv '1'"}, blocks("config dnsmasq\n\toption noresolv '1'\nconfig dhcp 'lan'\n\toption start '100'\n", func(fields []string) bool { return fields[1] == "dnsmasq" }))
}

func TestLANDNSLines(t *testing.T) {
	t.Parallel()
	addresses := []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fd00::1")}
	dnsmasq := []sockets.Listener{
		{Protocol: "udp", Address: netip.MustParseAddrPort("192.168.1.1:53"), PID: 7600, Program: "dnsmasq"},
		{Protocol: "udp", Address: netip.MustParseAddrPort("[fd00::1]:53"), PID: 7600, Program: "dnsmasq"},
	}
	// one line a process, with every address it listens on
	require.Equal(t, []string{"✅ DNS on br-lan: dnsmasq (pid 7600) on 192.168.1.1:53 and [fd00::1]:53, forwards to 127.0.0.42, no-resolv"},
		lanDNSLines(diag.LANDNS{Interface: "br-lan", Addresses: addresses, Holders: dnsmasq, Dnsmasq: true, Servers: []string{"127.0.0.42"}, NoResolv: true}, true))
	require.Equal(t, []string{"❌ DNS on br-lan: dnsmasq (pid 7600) on 192.168.1.1:53 and [fd00::1]:53, forwards to 127.0.0.1#5053 and to the servers of its resolv file"},
		lanDNSLines(diag.LANDNS{Interface: "br-lan", Addresses: addresses, Holders: dnsmasq, Dnsmasq: true, Servers: []string{"127.0.0.1#5053"}}, true))
	// while the backend is stopped, dnsmasq is the router's own: nothing is wrong
	require.Equal(t, []string{"⚠️ DNS on br-lan: dnsmasq (pid 7600) on 192.168.1.1:53 and [fd00::1]:53, forwards to the servers of its resolv file only"},
		lanDNSLines(diag.LANDNS{Interface: "br-lan", Addresses: addresses, Holders: dnsmasq, Dnsmasq: true}, false))
	other := []sockets.Listener{{Protocol: "udp", Address: netip.MustParseAddrPort("0.0.0.0:53"), PID: 900, Program: "AdGuardHome"}}
	require.Equal(t, []string{"⚠️ DNS on br-lan: AdGuardHome (pid 900) on 0.0.0.0:53"},
		lanDNSLines(diag.LANDNS{Interface: "br-lan", Addresses: addresses, Holders: other}, true))
	require.Equal(t, []string{"❌ DNS on br-lan (192.168.1.1, fd00::1): nobody listens on port 53"},
		lanDNSLines(diag.LANDNS{Interface: "br-lan", Addresses: addresses}, true))
	require.Equal(t, []string{"❌ DNS on wg0: the interface has no address"}, lanDNSLines(diag.LANDNS{Interface: "wg0"}, true))
}

func TestCutSettings(t *testing.T) {
	t.Parallel()
	require.Equal(t, "config settings 'settings'", cutSettings("config settings 'settings'"))
	long := "config settings 'settings'\n\toption user_domains_text '" + strings.Repeat("name.example\n", 20000) + "'"
	cut := cutSettings(long)
	require.Less(t, len(cut), settingsShown+100)
	require.True(t, strings.HasPrefix(cut, "config settings 'settings'\n"))
	require.Contains(t, cut, "bytes more of the settings are left out")
}

func TestInterfaceLines(t *testing.T) {
	t.Parallel()
	settings := &model.Settings{SourceNetworkInterfaces: []string{"lan", "lan1", "guest"}, EnableYACD: true, YACDInterfaces: []string{"wan6only"}, OutputNetworkInterface: "wan"}
	sources := []model.Source{{Name: "torrents", Type: "interface", Interface: "wan"}, {Name: "tunnel", Type: "interface", Interface: "awg0"}, {Name: "main", Type: "links", Interface: "ignored"}}
	devices := map[string]string{"lan": "br-lan", "wan": "pppoe-wan"}
	addresses := map[string][]netip.Addr{
		"br-lan":    {netip.MustParseAddr("192.168.1.1")},
		"lan1":      nil,
		"pppoe-wan": {netip.MustParseAddr("203.0.113.7")},
		"wan6only":  {netip.MustParseAddr("2001:db8::1")},
		"awg0":      {netip.MustParseAddr("169.254.0.2")},
	}
	lookup := func(device string) ([]netip.Addr, bool) {
		found, exists := addresses[device]
		return found, exists
	}
	uses := interfaceUses(settings, sources)
	require.Equal(t, []string{
		"✅ Source: lan → br-lan",
		"⚠️ Source: lan1: no IPv4 address (a port of a bridge, a network that is down, or a wrong name): podkop sees no traffic from it",
		"⚠️ Source: guest: no such device now (a network that is down, or a wrong name): podkop sees no traffic from it",
		"✅ YACD: wan6only",
		"✅ Output: wan → pppoe-wan",
		"✅ Interface source torrents: wan → pppoe-wan",
		"⚠️ Interface source tunnel: awg0: no IPv4 address (a port of a bridge, a network that is down, or a wrong name)",
	}, interfaceLines(uses, devices, lookup))

	// the output down: an error; none chosen: the routing of the router
	addresses["pppoe-wan"] = nil
	require.Contains(t, interfaceLines(uses, devices, lookup), "❌ Output: wan → pppoe-wan: no IPv4 address (a port of a bridge, a network that is down, or a wrong name): sing-box cannot go out through it")
	require.Equal(t, []string{"✅ Output: where the routing of the router sends it"}, interfaceLines(nil, nil, lookup))

	require.Equal(t, []string{"br-lan", "lan1", "guest"}, sourceDevices(&model.Settings{SourceNetworkInterfaces: []string{"lan", "br-lan", "lan1", "guest"}}, devices))
}
