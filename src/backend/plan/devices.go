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

// DeviceRoute is a route rule of the configuration that takes connections by the device they
// come from, or the route rule of the lists of a rule, which goes by it too (only_devices): what a
// report of the rules that take the traffic of a device reads ("podkop device").
type DeviceRoute struct {
	// Kind is what the route rule is: RouteLists, RouteExcluded or RouteFullyRouted.
	Kind string
	// Section is the rule of the settings it is of; none for RouteExcluded.
	Section string
	// Exit is where it sends what it takes (model.Config.Exit): ExitDirect for RouteExcluded.
	Exit string
	// Limited tells that it takes the connections of Devices alone; the route rule of the lists of a
	// rule that is not only for some devices takes those of every device. A rule of lists limited
	// to no device takes nothing: it has no route rule in the configuration, only this place.
	Limited bool
	// Devices are its devices (source_ip_cidr), as the settings write them.
	Devices []model.Device
}

// The kinds of DeviceRoute.
const (
	// RouteLists is the route rule of the lists of a rule: it takes the connections to them.
	RouteLists = "lists"
	// RouteExcluded is the route rule of the devices excluded from routing (Routing Excluded IPs):
	// directly, whatever the rules below.
	RouteExcluded = "excluded"
	// RouteFullyRouted is the route rule of the devices a rule routes whole (Fully Routed IPs).
	RouteFullyRouted = "fully_routed"
)

// DeviceRoutes are the route rules of the configuration of the settings that take connections by
// their device or by the lists of a rule (DeviceRoute), in the order sing-box matches them.
type DeviceRoutes struct {
	// IPv6 tells that IPv6 goes through podkop, as the settings ask and the router has it
	// (Facts.IPv6): without it no route rule takes a connection from an IPv6 address, which goes
	// past podkop.
	IPv6   bool
	Routes []DeviceRoute
}

// BuildDeviceRoutes builds the configuration of the settings as Build does, and gives its
// DeviceRoutes: the rules the configuration has, not a copy of their order.
func BuildDeviceRoutes(config *model.Config, facts Facts, options Options) (*DeviceRoutes, error) {
	_, b, err := build(config, facts, options)
	if err != nil {
		return nil, err
	}
	routes := &DeviceRoutes{IPv6: b.ipv6}
	for _, entry := range b.routeRules {
		if entry.device != nil {
			routes.Routes = append(routes.Routes, *entry.device)
		}
	}
	return routes, nil
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
