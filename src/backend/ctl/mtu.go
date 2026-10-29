package ctl

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/netcfg"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
)

// wireGuardOverhead is what WireGuard puts around a packet of the tunnel: its header (16
// bytes) and the tag of its cipher (16), then UDP (8).
const wireGuardOverhead = 16 + 16 + 8

// mtuFacts are what the hints read of the router; a test has its own.
type mtuFacts struct {
	// mtu is the MTU of a device, and whether there is one of the name
	mtu func(device string) (int, bool)
	// routeDevice is the device the routing sends a packet to an address through
	routeDevice func(destination netip.Addr) (string, bool)
}

var routerMTUFacts = mtuFacts{
	mtu: func(device string) (int, bool) {
		found, err := net.InterfaceByName(device)
		if err != nil {
			return 0, false
		}
		return found.MTU, true
	},
	routeDevice: func(destination netip.Addr) (string, bool) {
		device, err := netcfg.RouteDevice(destination)
		return device, err == nil
	},
}

// somewhereOutside stands for a server whose endpoint is a name: the way out is that of
// the default route (TEST-NET-1, only looked up, never sent to).
var somewhereOutside = netip.MustParseAddr("192.0.2.1")

// vpnMTUHints tells, for each VPN section on a WireGuard or AmneziaWG interface whose test
// did not pass (its line in results begins "❌ <name>:"), how large a full packet of the
// tunnel leaves against the MTU of the device it leaves through. A tunnel whose MTU is too
// large for that loses every full-size packet once the way drops fragments: small requests
// pass, a TLS handshake does not (AmneziaWG 2.0 adds the padding S4 to every packet, and
// the interface keeps the MTU of 1420 that WireGuard has). Nothing is changed: the hint
// names the MTU to set.
func vpnMTUHints(config *model.Config, results []string, network *uci.Package, devices map[string]string, facts mtuFacts) []string {
	if network == nil {
		return nil
	}
	var hints []string
	seen := make(map[string]bool)
	for _, section := range config.Sections {
		if !failed(results, section.Name) {
			continue
		}
		for _, row := range section.Servers {
			source := config.Source(row.Source)
			if source == nil || source.Type != "interface" || source.Interface == "" || seen[source.Interface] {
				continue
			}
			seen[source.Interface] = true
			if hint := vpnMTUHint(source.Interface, network, devices, facts); hint != "" {
				hints = append(hints, hint)
			}
		}
	}
	return hints
}

func failed(results []string, name string) bool {
	for _, line := range results {
		if strings.HasPrefix(line, "❌ "+name+":") || strings.HasPrefix(line, "❌ "+name+" (") {
			return true
		}
	}
	return false
}

func vpnMTUHint(name string, network *uci.Package, devices map[string]string, facts mtuFacts) string {
	settings := network.Section(name)
	if settings == nil {
		return ""
	}
	proto := settings.Get("proto")
	if proto != "wireguard" && proto != "amneziawg" {
		return ""
	}
	device := name
	if resolved := devices[name]; resolved != "" {
		device = resolved
	}
	tunnel, found := facts.mtu(device)
	if !found {
		return ""
	}
	padding := 0
	if proto == "amneziawg" {
		padding, _ = strconv.Atoi(strings.TrimSpace(settings.Get("awg_s4")))
	}
	// the peer: an address of IPv6 makes the outer header 40 bytes, and its way out is the
	// one to it
	header, destination := 20, somewhereOutside
	for _, peer := range network.SectionsOfType(proto + "_" + name) {
		endpoint, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(peer.Get("endpoint_host")), "[]"))
		if err != nil {
			continue
		}
		destination = endpoint.Unmap()
		if destination.Is6() {
			header = 40
		}
		break
	}
	way, found := facts.routeDevice(destination)
	if !found {
		return ""
	}
	wayMTU, found := facts.mtu(way)
	if !found {
		return ""
	}
	leaves := tunnel + wireGuardOverhead + padding + header
	has := "⚠️ MTU: " + device + " has " + strconv.Itoa(tunnel)
	if padding > 0 {
		has += " (and the padding S4 of AmneziaWG, " + strconv.Itoa(padding) + " bytes)"
	}
	where := " (Network → Interfaces → " + name + " → Advanced Settings → Override MTU)"
	if leaves > wayMTU {
		fit := wayMTU - wireGuardOverhead - padding - header
		return has + ": a full packet of the tunnel leaves as " + strconv.Itoa(leaves) + " bytes, more than the " +
			strconv.Itoa(wayMTU) + " of " + way + ". Lower the MTU of the interface " + name + " to " + strconv.Itoa(fit) + " or less" + where
	}
	return has + ": a full packet of the tunnel leaves as " + strconv.Itoa(leaves) + " bytes, within the " +
		strconv.Itoa(wayMTU) + " of " + way + ". If the way to the server carries less (PPPoE or a tunnel of the provider), lower the MTU of the interface " +
		name + ", down to 1280" + where
}
