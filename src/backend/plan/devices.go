package plan

import (
	"net/netip"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
)

// A rule only for some devices ("only_devices") takes the connections of those devices alone: its
// route rule (and its resolve rule) has their addresses as source_ip_cidr, beside the rule sets of
// its lists, which sing-box matches together with them. A device that is not one of them goes on to
// the rules below, and directly when none takes it. Nothing else depends on the field: the DNS
// cannot tell the devices apart (dnsmasq asks sing-box for all of them, and its cache answers any of
// them), so the names of the lists get FakeIP addresses for every device; the firewall marks what
// it marked; the mixed proxy, BitTorrent and the devices left out stay as they were. The devices
// the rule routes whole must lie within its devices.

// readDevices reads the devices of each rule and those it routes whole (model.Section.Devices),
// and tells the log what a rule that routes cannot use of them. A rule that does not route is not
// told about: the settings are read again at every reload.
func (b *builder) readDevices() {
	b.devicesOf = make(map[string]model.RuleDevices, len(b.config.Sections))
	for index := range b.config.Sections {
		section := &b.config.Sections[index]
		devices := section.Devices()
		b.devicesOf[section.Name] = devices
		if !b.routes(section) {
			continue
		}
		name := b.names.RuleText(section.Name)
		b.warnLeftOut(leftOutOf(devices.Dropped), "no address or subnet of a device", "rule ", name, ", only for devices")
		if devices.Limited && len(devices.Devices) == 0 {
			b.warn("rule ", name, `: no item of "only for devices" is an address or a subnet: `, model.NoDevice(b.config.Exit(section)))
		}
		b.warnLeftOut(leftOutOf(devices.RoutedDropped), "no address or subnet", "rule ", name, ", fully routed IPs")
		for _, device := range devices.Outside {
			b.warn("rule ", name, ": the fully routed IP ", device.Text, " is not among its devices (only for devices): left out")
		}
		// a rule with neither has a warning of its own (buildSectionLists) unless its mixed proxy
		// or BitTorrent gives it a route rule, which the field does not limit
		if devices.Limited && !section.HasEnabledLists() && len(section.FullyRoutedIPs) == 0 && (section.MixedProxyEnabled || b.bitTorrentSection == section) {
			b.warn("rule ", name, `: "only for devices" limits the lists and the fully routed IPs of the rule, and it has neither: the field does nothing`)
		}
	}
}

func leftOutOf(items []string) leftOut {
	var result leftOut
	for _, item := range items {
		result.add(item)
	}
	return result
}

// legacySources are the IPv4 prefixes of the devices routed whole as 0.8.20 gave them to the
// firewall: each item netip reads, masked.
func legacySources(items []string) []netip.Prefix {
	var sources []netip.Prefix
	for _, text := range items {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			address, addressErr := netip.ParseAddr(text)
			if addressErr != nil {
				continue
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if prefix.Addr().Is4() {
			sources = append(sources, prefix.Masked())
		}
	}
	return sources
}
