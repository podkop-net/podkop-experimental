package ctl

import (
	"net/netip"
	"slices"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/netcfg"
)

// interfaceUse is a name of an interface in the settings and what it is for.
type interfaceUse struct {
	// role is what the report calls it: "Source", "YACD", "Output", "VPN section <name>"
	role string
	name string
}

// interfaceUses are the interface names of the settings, by role, in the order of the form.
func interfaceUses(settings *model.Settings, sources []model.Source) []interfaceUse {
	var uses []interfaceUse
	for _, name := range settings.SourceNetworkInterfaces {
		uses = append(uses, interfaceUse{"Source", name})
	}
	if settings.EnableYACD {
		for _, name := range settings.YACDInterfaces {
			uses = append(uses, interfaceUse{"YACD", name})
		}
	}
	if settings.OutputNetworkInterface != "" {
		uses = append(uses, interfaceUse{"Output", settings.OutputNetworkInterface})
	}
	for index := range sources {
		if sources[index].Type == "interface" && sources[index].Interface != "" {
			uses = append(uses, interfaceUse{"Interface source " + sources[index].Name, sources[index].Interface})
		}
	}
	return uses
}

// interfaceLines tells, for each interface name of the settings, the device of layer 3 it
// stands for now (devices, netcfg.Devices) and whether that device has an address the use
// needs: an IPv4 one for the LAN, the output and a VPN section (podkop takes and sends
// IPv4), any for YACD. addresses gives the addresses of a device, the link-local ones of
// IPv6 aside, and whether there is such a device. Without an output interface, what
// sing-box opens goes where the routing of the router sends it.
func interfaceLines(uses []interfaceUse, devices map[string]string, addresses func(device string) ([]netip.Addr, bool)) []string {
	var lines []string
	output := false
	for _, use := range uses {
		device := use.name
		shown := use.name
		if resolved := devices[use.name]; resolved != "" {
			device = resolved
			shown = use.name + " → " + resolved
		}
		found, exists := addresses(device)
		var ipv4, any bool
		for _, address := range found {
			if netcfg.UsableAddress(address) {
				ipv4 = true
			}
			if !address.IsLoopback() && !address.IsLinkLocalUnicast() {
				any = true
			}
		}
		head := use.role + ": " + shown
		var problem string
		switch {
		case !exists:
			problem = "no such device now (a network that is down, or a wrong name)"
		case use.role == "YACD" && !any:
			problem = "no address: YACD cannot be opened through it"
		case use.role != "YACD" && !ipv4:
			problem = "no IPv4 address (a port of a bridge, a network that is down, or a wrong name)"
		}
		switch {
		case problem == "":
			lines = append(lines, "✅ "+head)
		case use.role == "Output":
			lines = append(lines, "❌ "+head+": "+problem+": sing-box cannot go out through it")
		case use.role == "Source":
			lines = append(lines, "⚠️ "+head+": "+problem+": podkop sees no traffic from it")
		default:
			lines = append(lines, "⚠️ "+head+": "+problem)
		}
		if use.role == "Output" {
			output = true
		}
	}
	if !output {
		lines = append(lines, "✅ Output: where the routing of the router sends it")
	}
	return lines
}

// sourceDevices are the devices the interface names of the LAN stand for.
func sourceDevices(settings *model.Settings, devices map[string]string) []string {
	result := make([]string, 0, len(settings.SourceNetworkInterfaces))
	for _, name := range settings.SourceNetworkInterfaces {
		if device := devices[name]; device != "" {
			name = device
		}
		if !slices.Contains(result, name) {
			result = append(result, name)
		}
	}
	return result
}
