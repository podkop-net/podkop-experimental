package model

import (
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

// Device is an item of the devices of a rule ("only_devices") or of the devices it routes whole
// ("fully_routed_ips"): its text as the settings have it, which is what sing-box is given, and the
// prefix it stands for, masked (an address is the prefix of that one address).
type Device struct {
	Text   string
	Prefix netip.Prefix
}

// linkLocal6 are the link-local addresses of IPv6: no connection of a device to an address of a
// list comes from one.
var linkLocal6 = netip.MustParsePrefix("fe80::/10")

// splitItems are the items of a list option, a value that holds several at spaces or commas (a
// file edited by hand) taken as as many items: the page (L.toArray) shows such a value so.
func splitItems(values []string) []string {
	var items []string
	for _, value := range values {
		items = append(items, strings.FieldsFunc(value, func(character rune) bool {
			return character == ',' || unicode.IsSpace(character)
		})...)
	}
	return items
}

// ParseDevices reads the items of "only_devices": IPv4 and IPv6 addresses (IsIP) and subnets
// (IsCIDR), split as splitItems does, each prefix once, in their order. Dropped is what is no
// address or subnet, an IPv4 address in IPv6 form and one with a zone (IsIPv6 refuses both), an
// unspecified address (0.0.0.0, ::), a subnet of the whole internet (/0), and a link-local
// address of IPv6 (fe80::/10).
func ParseDevices(items []string) (devices []Device, dropped []string) {
	seen := make(map[netip.Prefix]bool)
	for _, item := range splitItems(items) {
		prefix, ok := devicePrefix(item)
		if !ok {
			dropped = append(dropped, item)
			continue
		}
		if !seen[prefix] {
			seen[prefix] = true
			devices = append(devices, Device{Text: item, Prefix: prefix})
		}
	}
	return devices, dropped
}

func devicePrefix(text string) (netip.Prefix, bool) {
	if !IsIP(text) && !IsCIDR(text) {
		return netip.Prefix{}, false
	}
	address, length, isSubnet := strings.Cut(text, "/")
	parsed, err := netip.ParseAddr(address)
	if err != nil || parsed.IsUnspecified() || parsed.Is6() && linkLocal6.Contains(parsed) {
		return netip.Prefix{}, false
	}
	prefix := netip.PrefixFrom(parsed, parsed.BitLen())
	if isSubnet {
		bits, err := strconv.Atoi(length)
		if err != nil || bits == 0 {
			return netip.Prefix{}, false
		}
		prefix, err = parsed.Prefix(bits)
		if err != nil {
			return netip.Prefix{}, false
		}
	}
	return prefix, true
}

// ParseRouted reads the items of "fully_routed_ips" as the releases before 0.8.21 gave them to
// sing-box and to the firewall: any address or subnet sing-box reads, of IPv4 or of IPv6, split as
// splitItems does, in their order, the same one twice too. Dropped is what sing-box cannot read: it
// refused the whole configuration for it.
func ParseRouted(items []string) (routed []Device, dropped []string) {
	for _, item := range splitItems(items) {
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			address, addressErr := netip.ParseAddr(item)
			if addressErr != nil {
				dropped = append(dropped, item)
				continue
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		routed = append(routed, Device{Text: item, Prefix: prefix.Masked()})
	}
	return routed, dropped
}

// PrefixWithin tells whether the prefix inner lies within outer: of the same family, no shorter,
// its address inside outer.
func PrefixWithin(inner netip.Prefix, outer netip.Prefix) bool {
	return inner.Addr().Is4() == outer.Addr().Is4() && outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// RuleDevices are the devices whose traffic a rule takes, as its settings name them.
type RuleDevices struct {
	// Limited tells that the rule is only for some devices ("only_devices" has an item): it takes
	// the traffic of Devices alone, and of none when no item is a device
	Limited bool
	Devices []Device
	// Dropped are the items of "only_devices" that are no device (ParseDevices)
	Dropped []string
	// Routed are the devices the rule routes whole: the items of "fully_routed_ips" sing-box
	// reads, of a rule that is limited those within its devices (each must lie within one)
	Routed []Device
	// Outside are the devices routed whole left out for lying outside the devices of the rule;
	// none when it has no device, which leaves out every one of them
	Outside []Device
	// RoutedDropped are the items of "fully_routed_ips" sing-box cannot read (ParseRouted)
	RoutedDropped []string
}

// Devices reads the devices of the rule and the devices it routes whole.
func (s *Section) Devices() RuleDevices {
	var result RuleDevices
	result.Devices, result.Dropped = ParseDevices(s.OnlyDevices)
	result.Limited = len(result.Devices) > 0 || len(result.Dropped) > 0
	routed, dropped := ParseRouted(s.FullyRoutedIPs)
	result.RoutedDropped = dropped
	for _, device := range routed {
		switch {
		case !result.Limited || result.Within(device.Prefix):
			result.Routed = append(result.Routed, device)
		case len(result.Devices) > 0:
			result.Outside = append(result.Outside, device)
		}
	}
	return result
}

// Within tells whether the prefix lies within one of the devices.
func (d *RuleDevices) Within(prefix netip.Prefix) bool {
	for _, device := range d.Devices {
		if PrefixWithin(prefix, device.Prefix) {
			return true
		}
	}
	return false
}

// HasIPv6 tells whether one of the devices is of IPv6.
func (d *RuleDevices) HasIPv6() bool {
	for _, device := range d.Devices {
		if device.Prefix.Addr().Is6() {
			return true
		}
	}
	return false
}

// Takes tells whether the rule takes the traffic of a device of the address: of every device when
// it is not limited.
func (d *RuleDevices) Takes(address netip.Addr) bool {
	address = address.Unmap().WithZone("")
	return !d.Limited || d.Within(netip.PrefixFrom(address, address.BitLen()))
}

// NoDevice says what becomes of a rule only for some devices of which no item is a device, by
// where it sends its traffic (Config.Exit): it takes no connection, of any device.
func NoDevice(exit string) string {
	switch exit {
	case ExitBlock:
		return "the rule blocks nobody"
	case ExitServers:
		return "the rule takes no traffic: its devices go past its servers, by the rules below or directly"
	}
	return "the rule takes no traffic"
}

// Texts are the texts of the devices, which sing-box is given.
func Texts(devices []Device) []string {
	texts := make([]string, len(devices))
	for index, device := range devices {
		texts[index] = device.Text
	}
	return texts
}

// DevicesText names devices in a text people paste where others read it (the global check, the
// log): the IPv4 items in full, the IPv6 ones counted, since their prefix is the user's own.
func DevicesText(devices []Device) string {
	var shown []string
	ipv6 := 0
	for _, device := range devices {
		if device.Prefix.Addr().Is4() {
			shown = append(shown, device.Text)
		} else {
			ipv6++
		}
	}
	if ipv6 > 0 {
		shown = append(shown, "IPv6 items: "+strconv.Itoa(ipv6))
	}
	return strings.Join(shown, ", ")
}
