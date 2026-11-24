package ctl

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

func devicesConfig() *model.Config {
	servers := []model.Member{{Source: "own"}}
	return &model.Config{
		Sources: []model.Source{{Name: "own", Label: "Own", Type: "links", Links: []string{"vless://x"}}},
		Sections: []model.Section{
			{Name: "bank", Enabled: true, Servers: []model.Member{{Source: model.SourceDirect}}, UserDomainListType: "dynamic", OnlyDevices: []string{"192.168.78.30"}},
			{Name: "tv", Label: "TV", Enabled: true, Servers: servers, CommunityLists: []string{"youtube"}, UserDomainListType: "disabled", UserSubnetListType: "disabled",
				OnlyDevices: []string{"192.168.78.10", "192.168.79.0/24", "2001:db8:1::50"}},
			{Name: "bad", Enabled: true, Servers: []model.Member{{Source: model.SourceBlock}}, CommunityLists: []string{"porn"}, UserDomainListType: "disabled", UserSubnetListType: "disabled", OnlyDevices: []string{"word"}},
			{Name: "pc", Enabled: true, Servers: servers, UserDomainListType: "disabled", UserSubnetListType: "disabled", FullyRoutedIPs: []string{"192.168.78.60", "2001:db8:1::60"}},
			{Name: "noyt", Enabled: true, Servers: []model.Member{{Source: model.SourceBlock}}, CommunityLists: []string{"youtube"}, UserDomainListType: "disabled", UserSubnetListType: "disabled"},
			{Name: "off", Enabled: false, Servers: servers, CommunityLists: []string{"discord"}, OnlyDevices: []string{"192.168.78.10"}},
		},
		Settings: model.Settings{RoutingExcludedIPs: []string{"192.168.78.70"}, IPv6Routing: model.IPv6Podkop},
	}
}

// devicesSettings are the settings of devicesConfig as a file (bank with a domain, and a link the
// engine takes): the report of a device builds them (plan.BuildDeviceRoutes), which needs the
// defaults model.Load gives.
const devicesSettings = `config settings 'settings'
	option config_version '2'
	option dns_type 'udp'
	option dns_server '8.8.8.8'
	option ipv6_routing 'podkop'
	list routing_excluded_ips '192.168.78.70'

config source 'own'
	option type 'links'
	option label 'Own'
	list link 'socks5://192.0.2.1:1080'

config section 'bank'
	option user_domain_list_type 'dynamic'
	list user_domains 'bank.example'
	list only_devices '192.168.78.30'

config member
	option section 'bank'
	option role 'server'
	option source 'direct'

config section 'tv'
	option label 'TV'
	list community_lists 'youtube'
	option user_domain_list_type 'disabled'
	option user_subnet_list_type 'disabled'
	list only_devices '192.168.78.10'
	list only_devices '192.168.79.0/24'
	list only_devices '2001:db8:1::50'

config member
	option section 'tv'
	option role 'server'
	option source 'own'

config section 'bad'
	list community_lists 'porn'
	option user_domain_list_type 'disabled'
	option user_subnet_list_type 'disabled'
	list only_devices 'word'

config member
	option section 'bad'
	option role 'server'
	option source 'block'

config section 'pc'
	option user_domain_list_type 'disabled'
	option user_subnet_list_type 'disabled'
	list fully_routed_ips '192.168.78.60'
	list fully_routed_ips '2001:db8:1::60'

config member
	option section 'pc'
	option role 'server'
	option source 'own'

config section 'noyt'
	list community_lists 'youtube'
	option user_domain_list_type 'disabled'
	option user_subnet_list_type 'disabled'

config member
	option section 'noyt'
	option role 'server'
	option source 'block'

config section 'off'
	option enabled '0'
	list community_lists 'discord'
	list only_devices '192.168.78.10'

config member
	option section 'off'
	option role 'server'
	option source 'own'
`

// The status of podkop names the devices of each rule only for some devices, the IPv6 ones counted,
// and warns of a rule that takes no device; a rule that is off or not limited is not there.
func TestRuleDeviceLines(t *testing.T) {
	t.Parallel()
	require.Equal(t, []string{
		"ℹ️ Rule bank takes only the devices 192.168.78.30",
		"ℹ️ Rule TV (tv) takes only the devices 192.168.78.10, 192.168.79.0/24, IPv6 items: 1",
		`⚠️ Rule bad: no item of "only for devices" is an address or a subnet: the rule blocks nobody`,
	}, ruleDeviceLines(devicesConfig()))
	require.Empty(t, ruleDeviceLines(&model.Config{}))
}

// "This device" tells whether the IPv4 address the check found is among the devices of each rule
// only for some devices; nothing without an address.
func TestDeviceRuleLines(t *testing.T) {
	t.Parallel()
	config := devicesConfig()
	require.Equal(t, []string{
		"ℹ️ This device's IPv4 address 192.168.79.5 is not among the devices of the rule bank: that rule does not take its traffic",
		"✅ This device's IPv4 address 192.168.79.5 is among the devices of the rule TV (tv); IPv6 addresses are not checked",
	}, deviceRuleLines(config, netip.MustParseAddr("192.168.79.5")))
	require.Equal(t, []string{
		"ℹ️ This device's IPv4 address 192.168.78.20 is not among the devices of the rule bank: that rule does not take its traffic",
		"ℹ️ This device's IPv4 address 192.168.78.20 is not among the devices of the rule TV (tv): that rule does not take its traffic; IPv6 addresses are not checked",
	}, deviceRuleLines(config, netip.MustParseAddr("::ffff:192.168.78.20")))
	require.Nil(t, deviceRuleLines(config, netip.Addr{}))
}

// "podkop device" lists the rules in the order sing-box matches them for the device: the leading
// rules, the devices excluded, the devices routed whole, the rules of lists.
func TestDeviceReport(t *testing.T) {
	t.Parallel()
	parsed, err := uci.Parse([]byte(devicesSettings))
	require.NoError(t, err)
	config, err := model.Load(parsed)
	require.NoError(t, err)
	routerIPv6 := plan.Facts{IPv6: true}
	report := func(address string) string {
		lines, ok := deviceReport(config, routerIPv6, address)
		require.True(t, ok, "%s: %v", address, lines)
		return strings.Join(lines, "\n")
	}
	require.Equal(t, strings.Join([]string{
		"ℹ️ The rules for 192.168.78.10, in the order they are matched:",
		"➖ Rule bank does not take it: only for 192.168.78.30",
		"✅ Rule TV (tv) takes its connections to the lists of the rule, as one of its devices: through its servers",
		`❌ Rule bad takes no device: no item of "only for devices" is an address or a subnet`,
		"✅ Rule noyt takes its connections to the lists of the rule, as those of every device: blocked",
		"➡️ What no rule takes goes directly",
	}, "\n"), report("192.168.78.10"))
	require.Contains(t, report("192.168.78.20"), "➖ Rule TV (tv) does not take it: only for 192.168.78.10, 192.168.79.0/24, 2001:db8:1::50")
	// an IPv6 device of a rule: the names of the lists get IPv4 addresses, so only its connections
	// to the IPv6 subnets of the lists reach the rule
	require.Contains(t, report("2001:db8:1::50"), "✅ Rule TV (tv) takes its connections to the lists of the rule that reach sing-box, "+
		"those to the IPv6 subnets of the lists (the names of the lists get FakeIP IPv4 addresses only), as one of its devices: through its servers")
	// the leading rule comes before the devices excluded, which end the list
	require.Equal(t, strings.Join([]string{
		"ℹ️ The rules for 192.168.78.70, in the order they are matched:",
		"➖ Rule bank does not take it: only for 192.168.78.30",
		"↪️ It is among the Routing Excluded IPs (192.168.78.70): the rules below do not take its traffic, it goes directly",
	}, "\n"), report("192.168.78.70"))
	require.Contains(t, report("192.168.78.30"), "✅ Rule bank takes its connections to the lists of the rule, as one of its devices: directly")
	// routed whole by a rule below: before every rule of lists
	pc := report("192.168.78.60")
	require.Contains(t, pc, "✅ Rule pc takes all its traffic (Fully Routed IPs, 192.168.78.60): through its servers")
	require.NotContains(t, pc, "Rule TV")
	// an IPv6 device routed whole: the route rule holds it, but only its connections to the IPv6
	// subnets of the lists reach sing-box
	require.Equal(t, strings.Join([]string{
		"ℹ️ The rules for 2001:db8:1::60, in the order they are matched:",
		"➖ Rule bank does not take it: only for 192.168.78.30",
		"✅ Rule pc takes its connections that reach sing-box, those to the IPv6 subnets of the lists, not all its traffic (Fully Routed IPs, 2001:db8:1::60): through its servers",
	}, "\n"), report("2001:db8:1::60"))

	// IPv6 past podkop
	config.Settings.IPv6Routing = model.IPv6Bypass
	require.Contains(t, report("2001:db8:1::50"), "IPv6 traffic goes past podkop")
	_, ok := deviceReport(config, routerIPv6, "word")
	require.False(t, ok)
}
