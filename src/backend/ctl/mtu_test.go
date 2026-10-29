package ctl

import (
	"net/netip"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

func testMTUFacts(mtus map[string]int, routes map[netip.Addr]string) mtuFacts {
	return mtuFacts{
		mtu: func(device string) (int, bool) {
			mtu, found := mtus[device]
			return mtu, found
		},
		routeDevice: func(destination netip.Addr) (string, bool) {
			device, found := routes[destination]
			return device, found
		},
	}
}

// The hint of a VPN section that did not pass its test: a full packet of the tunnel against
// the MTU of the way out. The numbers are those measured on the stand of AmneziaWG: with
// the padding S4 32 and MTU 1420 the largest packet that went through was 1408; S4 12 fits
// the 1492 of PPPoE, S4 16 does not.
func TestVPNMTUHints(t *testing.T) {
	const network = `config interface 'awg'
	option proto 'amneziawg'
	option awg_s4 '32'

config amneziawg_awg
	option endpoint_host 'vpn.example.org'

config interface 'wg'
	option proto 'wireguard'

config wireguard_wg
	option endpoint_host '2001:db8::5'

config interface 'pppawg'
	option proto 'amneziawg'
	option awg_s4 '16'

config interface 'lan'
	option proto 'static'
`
	parsed, err := uci.Parse([]byte(network))
	require.NoError(t, err)
	facts := testMTUFacts(
		map[string]int{"awg": 1420, "wg": 1420, "pppawg": 1420, "eth0": 1500, "pppoe-wan": 1492, "br-lan": 1500},
		map[netip.Addr]string{somewhereOutside: "eth0", netip.MustParseAddr("2001:db8::5"): "eth0"},
	)
	config := mtuConfig([][2]string{{"a", "awg"}, {"w", "wg"}, {"ok", "awg"}, {"p", ""}, {"l", "lan"}}...)
	results := []string{"❌ a: does not work (timeout)", "❌ w: does not work (timeout)", "✅ ok: 120 ms", "❌ p: does not work", "❌ l: does not work"}
	hints := vpnMTUHints(config, results, parsed, nil, facts)
	require.Len(t, hints, 2, "a passed section, a proxy section and an interface of another protocol get none")
	require.Contains(t, hints[0], "awg has 1420 (and the padding S4 of AmneziaWG, 32 bytes): a full packet of the tunnel leaves as 1512 bytes, more than the 1500 of eth0. Lower the MTU of the interface awg to 1408 or less")
	// plain WireGuard to an IPv6 endpoint: 1420 + 40 + 40 = 1500, it fits
	require.Contains(t, hints[1], "wg has 1420: a full packet of the tunnel leaves as 1500 bytes, within the 1500 of eth0. If the way to the server carries less")

	// PPPoE: S4 16 does not fit 1492, S4 12 does
	facts = testMTUFacts(map[string]int{"pppawg": 1420, "pppoe-wan": 1492}, map[netip.Addr]string{somewhereOutside: "pppoe-wan"})
	hints = vpnMTUHints(mtuConfig([][2]string{{"p", "pppawg"}}...), []string{"❌ p: does not work"}, parsed, nil, facts)
	require.Len(t, hints, 1)
	require.Contains(t, hints[0], "leaves as 1496 bytes, more than the 1492 of pppoe-wan. Lower the MTU of the interface pppawg to 1416 or less")
	twelve, err := uci.Parse([]byte("config interface 'pppawg'\n\toption proto 'amneziawg'\n\toption awg_s4 '12'\n"))
	require.NoError(t, err)
	hints = vpnMTUHints(mtuConfig([][2]string{{"p", "pppawg"}}...), []string{"❌ p: does not work"}, twelve, nil, facts)
	require.Contains(t, hints[0], "leaves as 1492 bytes, within the 1492 of pppoe-wan")

	// the device of layer 3 the interface stands for is the one read
	facts = testMTUFacts(map[string]int{"awg0": 1376, "eth0": 1500}, map[netip.Addr]string{somewhereOutside: "eth0"})
	hints = vpnMTUHints(mtuConfig([][2]string{{"a", "awg"}}...), []string{"❌ a: does not work"}, parsed, map[string]string{"awg": "awg0"}, facts)
	require.Contains(t, hints[0], "awg0 has 1376 (and the padding S4 of AmneziaWG, 32 bytes): a full packet of the tunnel leaves as 1468 bytes, within the 1500 of eth0")
	// nothing known of the device: no hint
	require.Empty(t, vpnMTUHints(mtuConfig([][2]string{{"a", "awg"}}...), []string{"❌ a: does not work"}, parsed, nil, facts))
	require.Empty(t, vpnMTUHints(config, results, nil, nil, facts))
}

// mtuConfig makes the rules of the names, each with one row of a source of its own: an
// interface source of the interface, or links for none.
func mtuConfig(rules ...[2]string) *model.Config {
	config := new(model.Config)
	for _, rule := range rules {
		source := model.Source{Name: rule[0] + "_source", Type: "interface", Interface: rule[1]}
		if rule[1] == "" {
			source.Type, source.Links = "links", []string{"vless://x"}
		}
		config.Sources = append(config.Sources, source)
		config.Sections = append(config.Sections, model.Section{Name: rule[0], Enabled: true, Servers: []model.Member{{Source: source.Name}}})
	}
	return config
}
