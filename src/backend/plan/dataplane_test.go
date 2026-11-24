package plan

import (
	"net/netip"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

func buildText(t *testing.T, settings string, facts Facts) *Result {
	parsed, err := uci.Parse([]byte(settings))
	require.NoError(t, err)
	config, err := model.Load(parsed)
	require.NoError(t, err)
	result, err := Build(config, facts, Options{DecodeLink: func(string) ([]byte, []string, error) {
		return []byte(`{"type": "socks", "server": "203.0.113.15", "server_port": 1080}`), nil, nil
	}})
	require.NoError(t, err)
	return result
}

// What the router needs around the configuration comes with it: the rules of the
// firewall, the DNS of the LAN, the Clash API.
func TestDataplane(t *testing.T) {
	const head = "config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '8.8.8.8'\n"
	const proxy = "\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n"

	// the defaults: the bridge of the LAN, NTP through, the DNS of the LAN taken, the API
	// on this host only, whatever the address of the LAN
	result := buildText(t, head+proxy, Facts{LANAddress: "192.168.1.1"})
	require.Equal(t, dataplane.Intent{Interfaces: []string{"br-lan"}, TakeDNS: true, ClashAPI: "127.0.0.1:9090"}, result.Dataplane)
	require.Contains(t, string(result.Config), `"external_controller": "127.0.0.1:9090"`)

	// what the settings say; devices routed whole are IPv4 prefixes, a word is left out
	result = buildText(t, head+"\tlist source_network_interfaces 'br-guest'\n\tlist source_network_interfaces 'eth2'\n\toption exclude_ntp '1'\n\toption dont_touch_dhcp '1'\n"+
		"\toption enable_yacd '1'\n\tlist yacd_interfaces 'br-guest'\n\tlist yacd_interfaces 'wan'\n\toption yacd_secret_key 'k'\n"+
		proxy+"\tlist fully_routed_ips '192.168.1.23'\n\tlist fully_routed_ips '192.168.2.0/24'\n\tlist fully_routed_ips '2001:db8::1'\n\tlist fully_routed_ips 'word'\n",
		Facts{LANAddress: "192.168.1.1"})
	require.Equal(t, dataplane.Intent{
		Interfaces: []string{"br-guest", "eth2"}, ExcludeNTP: true,
		Sources: []netip.Prefix{netip.MustParsePrefix("192.168.1.23/32"), netip.MustParsePrefix("192.168.2.0/24")},
		// with YACD the API listens on every address, kept by the firewall to the devices
		// of YACD, and is asked on this host
		ClashAPI: "127.0.0.1:9090", ClashSecret: "k", ClashAPIInterfaces: []string{"br-guest", "wan"},
	}, result.Dataplane)
	require.Contains(t, string(result.Config), `"external_controller": "0.0.0.0:9090"`)

	// YACD without devices of its own: those the traffic is taken from
	result = buildText(t, head+"\tlist source_network_interfaces 'br-guest'\n\toption enable_yacd '1'\n"+proxy, Facts{})
	require.Equal(t, []string{"br-guest"}, result.Dataplane.ClashAPIInterfaces)
}

// The interface names of the settings become the devices of layer 3 netifd says they
// stand for, in the firewall and in sing-box alike; what sing-box opens carries the mark
// mangle_output lets go by, and is bound only to an interface the settings name.
func TestDevices(t *testing.T) {
	const head = "config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '8.8.8.8'\n"
	const proxy = "\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n"
	const vpn = "\nconfig section 'torrents'\n\toption connection_type 'vpn'\n\toption interface 'wan'\n"
	settings := head + "\tlist source_network_interfaces 'lan'\n\tlist source_network_interfaces 'br-lan'\n\tlist source_network_interfaces 'guest'\n" +
		"\toption enable_yacd '1'\n\tlist yacd_interfaces 'lan'\n\toption yacd_secret_key 'k'\n" + proxy + vpn

	// nothing known of the names: they are used as they are, sing-box goes where the
	// routing sends it
	result := buildText(t, settings, Facts{})
	require.Equal(t, []string{"lan", "br-lan", "guest"}, result.Dataplane.Interfaces)
	config := string(result.Config)
	require.Contains(t, config, `"bind_interface": "wan"`)
	require.Contains(t, config, `"default_mark": 2097152`)
	require.NotContains(t, config, "auto_detect_interface")
	require.NotContains(t, config, "default_interface")

	// the devices of layer 3: one device once, in the order of the settings
	facts := Facts{Devices: map[string]string{"lan": "br-lan", "guest": "phy0-ap1", "wan": "pppoe-wan"}}
	result = buildText(t, settings, facts)
	require.Equal(t, []string{"br-lan", "phy0-ap1"}, result.Dataplane.Interfaces)
	require.Equal(t, []string{"br-lan"}, result.Dataplane.ClashAPIInterfaces)
	require.Contains(t, string(result.Config), `"bind_interface": "pppoe-wan"`)
	require.Equal(t, facts, result.Facts)

	// an output interface binds what sing-box opens, the mark stays
	result = buildText(t, head+"\toption enable_output_network_interface '1'\n\toption output_network_interface 'wan'\n"+proxy, facts)
	config = string(result.Config)
	require.Contains(t, config, `"default_interface": "pppoe-wan"`)
	require.Contains(t, config, `"default_mark": 2097152`)

	// the names netifd is asked about: each once; the interface of a section that is no
	// VPN section is none
	parsed, err := uci.Parse([]byte(head + "\toption output_network_interface 'wwan'\n\tlist source_network_interfaces 'lan'\n\toption enable_yacd '1'\n\tlist yacd_interfaces 'lan'\n\tlist yacd_interfaces 'wan'\n" +
		proxy + "\toption interface 'ignored'\n" + vpn))
	require.NoError(t, err)
	loaded, err := model.Load(parsed)
	require.NoError(t, err)
	require.Equal(t, []string{"lan", "wan", "wwan"}, InterfaceNames(loaded))
}
