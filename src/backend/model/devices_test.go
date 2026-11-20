package model

import (
	"net/netip"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

func prefixes(devices []Device) []string {
	var result []string
	for _, device := range devices {
		result = append(result, device.Prefix.String())
	}
	return result
}

// The devices of a rule: addresses and subnets of both families, masked, each once, in their
// order; a value of several items written by hand is as many items, as the page shows it.
func TestParseDevices(t *testing.T) {
	t.Parallel()
	devices, dropped := ParseDevices([]string{
		"192.168.1.50", "192.168.1.0/24", "192.168.1.7/24", "2001:db8:1::50", "2001:db8:2::1/64",
		" 192.168.2.10, 192.168.2.11\t192.168.1.50 ", "", "10.0.0.0/8",
	})
	require.Empty(t, dropped)
	require.Equal(t, []string{"192.168.1.50", "192.168.1.0/24", "2001:db8:1::50", "2001:db8:2::1/64", "192.168.2.10", "192.168.2.11", "10.0.0.0/8"}, Texts(devices))
	require.Equal(t, []string{"192.168.1.50/32", "192.168.1.0/24", "2001:db8:1::50/128", "2001:db8:2::/64", "192.168.2.10/32", "192.168.2.11/32", "10.0.0.0/8"}, prefixes(devices))

	// what is no device: a word, leading zeros (in an octet and in the length of an IPv4
	// prefix, as the page refuses them), a subnet of the whole internet, a zone, the unspecified
	// addresses, a link-local address of IPv6, an IPv4 address in IPv6 form
	devices, dropped = ParseDevices([]string{
		"word", "192.168.1.050", "192.168.1.0/08", "10.0.0.0/0", "::/0", "fe80::1%eth0", "0.0.0.0", "::",
		"0.0.0.0/24", "fe80::1", "fe80::/64", "::ffff:192.168.1.50", "::ffff:c0a8:132", "192.168.1.0/33", "2001:db8::/129",
		"192.168.1.60",
	})
	require.Equal(t, []string{"192.168.1.60"}, Texts(devices))
	require.Equal(t, []string{"word", "192.168.1.050", "192.168.1.0/08", "10.0.0.0/0", "::/0", "fe80::1%eth0", "0.0.0.0", "::",
		"0.0.0.0/24", "fe80::1", "fe80::/64", "::ffff:192.168.1.50", "::ffff:c0a8:132", "192.168.1.0/33", "2001:db8::/129"}, dropped)

	// a unique local address of IPv6 is a device's (with NAT66 it is its source to the internet)
	devices, dropped = ParseDevices([]string{"fd00::50", "fd12:3456::/64"})
	require.Empty(t, dropped)
	require.Len(t, devices, 2)
}

// The devices routed whole are taken as sing-box reads them, a /0 and a zone too; what it cannot
// read is dropped: it refused the whole configuration for it.
func TestParseRouted(t *testing.T) {
	t.Parallel()
	routed, dropped := ParseRouted([]string{"192.168.1.23", "192.168.2.7/24", "1.2.3.4/0", "2001:db8::1", "word", "192.168.1.23", "192.168.3.1 192.168.3.2", "192.168.1.050"})
	require.Equal(t, []string{"192.168.1.23", "192.168.2.7/24", "1.2.3.4/0", "2001:db8::1", "192.168.1.23", "192.168.3.1", "192.168.3.2"}, Texts(routed))
	require.Equal(t, []string{"192.168.1.23/32", "192.168.2.0/24", "0.0.0.0/0", "2001:db8::1/128", "192.168.1.23/32", "192.168.3.1/32", "192.168.3.2/32"}, prefixes(routed))
	require.Equal(t, []string{"word", "192.168.1.050"}, dropped)
}

func TestPrefixWithin(t *testing.T) {
	t.Parallel()
	within := func(inner string, outer string) bool {
		return PrefixWithin(netip.MustParsePrefix(inner), netip.MustParsePrefix(outer))
	}
	require.True(t, within("192.168.1.50/32", "192.168.1.50/32"))
	require.True(t, within("192.168.1.50/32", "192.168.1.0/24"))
	require.True(t, within("192.168.1.128/25", "192.168.1.0/24"))
	require.False(t, within("192.168.1.0/24", "192.168.1.128/25"))
	require.False(t, within("192.168.1.0/23", "192.168.1.0/24"))
	require.False(t, within("192.168.2.1/32", "192.168.1.0/24"))
	require.True(t, within("2001:db8:1::50/128", "2001:db8:1::/64"))
	require.False(t, within("2001:db8:2::50/128", "2001:db8:1::/64"))
	// across the families: never, an IPv4 address in IPv6 form neither
	require.False(t, within("192.168.1.50/32", "::/0"))
	require.False(t, within("::ffff:192.168.1.50/128", "192.168.1.0/24"))
	require.False(t, within("2001:db8::1/128", "0.0.0.0/0"))
}

// A rule only for some devices routes whole only the devices within them (strict AND); one with
// no device routes none and tells none as outside; one without the field routes every device it
// names, as before.
func TestRuleDevices(t *testing.T) {
	t.Parallel()
	section := Section{OnlyDevices: []string{"192.168.1.0/28", "2001:db8:1::50"}, FullyRoutedIPs: []string{"192.168.1.5", "192.168.1.60", "word", "192.168.1.8/30", "192.168.1.0/24"}}
	devices := section.Devices()
	require.True(t, devices.Limited)
	require.Equal(t, []string{"192.168.1.5", "192.168.1.8/30"}, Texts(devices.Routed))
	require.Equal(t, []string{"192.168.1.60", "192.168.1.0/24"}, Texts(devices.Outside))
	require.Equal(t, []string{"word"}, devices.RoutedDropped)
	require.True(t, devices.Takes(netip.MustParseAddr("192.168.1.15")))
	require.True(t, devices.Takes(netip.MustParseAddr("::ffff:192.168.1.15")))
	require.False(t, devices.Takes(netip.MustParseAddr("192.168.1.16")))
	require.True(t, devices.Takes(netip.MustParseAddr("2001:db8:1::50")))
	require.False(t, devices.Takes(netip.MustParseAddr("2001:db8:1::51")))
	require.Equal(t, "192.168.1.0/28, IPv6 items: 1", DevicesText(devices.Devices))

	section.OnlyDevices = []string{"word", "0.0.0.0"}
	devices = section.Devices()
	require.True(t, devices.Limited)
	require.Empty(t, devices.Devices)
	require.Equal(t, []string{"word", "0.0.0.0"}, devices.Dropped)
	require.Empty(t, devices.Routed)
	require.Empty(t, devices.Outside)
	require.False(t, devices.Takes(netip.MustParseAddr("192.168.1.5")))

	// without the field (or with spaces only): every device, every device routed whole
	for _, only := range [][]string{nil, {" "}} {
		section.OnlyDevices = only
		devices = section.Devices()
		require.False(t, devices.Limited)
		require.Equal(t, []string{"192.168.1.5", "192.168.1.60", "192.168.1.8/30", "192.168.1.0/24"}, Texts(devices.Routed))
		require.True(t, devices.Takes(netip.MustParseAddr("10.1.1.1")))
	}
}

func TestLoadOnlyDevices(t *testing.T) {
	t.Parallel()
	parsed, err := uci.Parse([]byte("config settings 'settings'\n\toption config_version '2'\n\nconfig section 'tv'\n\tlist only_devices '192.168.1.50'\n\tlist only_devices '2001:db8:1::50'\n\nconfig section 'pc'\n\toption only_devices '192.168.1.60 192.168.1.61'\n\nconfig section 'all'\n"))
	require.NoError(t, err)
	config, err := Load(parsed)
	require.NoError(t, err)
	require.Equal(t, []string{"192.168.1.50", "2001:db8:1::50"}, config.Section("tv").OnlyDevices)
	pc := config.Section("pc").Devices()
	require.Equal(t, []string{"192.168.1.60", "192.168.1.61"}, Texts(pc.Devices))
	require.Nil(t, config.Section("all").OnlyDevices)
	require.False(t, config.Section("all").Devices().Limited)
}
