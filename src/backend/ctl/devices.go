package ctl

import (
	"net/netip"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
)

// limitedRules are the rules that route and are only for some devices ("only_devices"), in their
// order, with their devices.
func limitedRules(config *model.Config) ([]*model.Section, []model.RuleDevices) {
	var sections []*model.Section
	var devices []model.RuleDevices
	for index := range config.Sections {
		section := &config.Sections[index]
		if !section.Enabled || config.Exit(section) == model.ExitNone {
			continue
		}
		if read := section.Devices(); read.Limited {
			sections = append(sections, section)
			devices = append(devices, read)
		}
	}
	return sections, devices
}

// ruleDeviceLines tell, in the status of podkop, the devices of each rule only for some devices: the
// IPv4 ones in full and the IPv6 ones counted, since people paste the report where others read it
// and an IPv6 address carries the user's own prefix. A rule none of whose items is a device is
// warned of: it takes nothing.
func ruleDeviceLines(config *model.Config) []string {
	names := config.Names()
	sections, devices := limitedRules(config)
	var lines []string
	for index, section := range sections {
		rule := names.RuleText(section.Name)
		if len(devices[index].Devices) == 0 {
			lines = append(lines, "⚠️ Rule "+rule+`: no item of "only for devices" is an address or a subnet: `+model.NoDevice(config.Exit(section)))
			continue
		}
		lines = append(lines, "ℹ️ Rule "+rule+" takes only the devices "+model.DevicesText(devices[index].Devices))
	}
	return lines
}

// deviceRuleLines tell whether the device that asked for the check is among the devices of each rule
// only for some devices. Its address is the one its connection to a check name came from (FakeIP,
// so IPv4); its IPv6 addresses are not known here.
func deviceRuleLines(config *model.Config, client netip.Addr) []string {
	if !client.IsValid() {
		return nil
	}
	client = client.Unmap()
	address := "This device's IPv4 address " + client.String()
	if client.Is6() {
		address = "This device's address " + client.String()
	}
	names := config.Names()
	sections, devices := limitedRules(config)
	var lines []string
	for index, section := range sections {
		read := devices[index]
		if len(read.Devices) == 0 {
			// told in the status of podkop: the rule takes no device
			continue
		}
		var unchecked string
		if client.Is4() && read.HasIPv6() {
			unchecked = "; IPv6 addresses are not checked"
		}
		rule := names.RuleText(section.Name)
		if read.Takes(client) {
			lines = append(lines, "✅ "+address+" is among the devices of the rule "+rule+unchecked)
		} else {
			lines = append(lines, "ℹ️ "+address+" is not among the devices of the rule "+rule+": that rule does not take its traffic"+unchecked)
		}
	}
	return lines
}

// deviceReport tells which rules take the traffic of a device of the address, in the order sing-box
// matches them (plan.Build): the leading rules of direct and block, the devices excluded from
// routing, the devices routed whole, the rules of lists. It is the check of a device that cannot
// open the page (a TV): "podkop device 192.168.1.50" on the router. false: the text is no address.
func deviceReport(config *model.Config, text string) ([]string, bool) {
	address, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil || address.Zone() != "" {
		return []string{"❌ " + text + " is not an IPv4 or an IPv6 address"}, false
	}
	address = address.Unmap()
	if address.Is6() && config.Settings.IPv6Routing != model.IPv6Podkop {
		return []string{"ℹ️ IPv6 traffic goes past podkop (IPv6 traffic: Past podkop): no rule takes the traffic of " + address.String()}, true
	}
	names := config.Names()
	exit := func(section *model.Section) string {
		switch config.Exit(section) {
		case model.ExitBlock:
			return "blocked"
		case model.ExitDirect:
			return "directly"
		}
		return "through its servers"
	}
	lines := []string{"ℹ️ The rules for " + address.String() + ", in the order they are matched:"}
	lists := func(section *model.Section) {
		if !section.Enabled || config.Exit(section) == model.ExitNone || !section.HasEnabledLists() {
			return
		}
		devices := section.Devices()
		rule := names.RuleText(section.Name)
		switch {
		case devices.Limited && len(devices.Devices) == 0:
			lines = append(lines, "❌ Rule "+rule+` takes no device: no item of "only for devices" is an address or a subnet`)
		case !devices.Limited:
			lines = append(lines, "✅ Rule "+rule+" takes its connections to the lists of the rule, as those of every device: "+exit(section))
		case devices.Takes(address):
			lines = append(lines, "✅ Rule "+rule+" takes its connections to the lists of the rule, as one of its devices: "+exit(section))
		default:
			lines = append(lines, "➖ Rule "+rule+" does not take it: only for "+strings.Join(model.Texts(devices.Devices), ", "))
		}
	}
	lead := plan.LeadingRules(config)
	for index := range lead {
		lists(&config.Sections[index])
	}
	excluded, _ := model.ParseRouted(config.Settings.RoutingExcludedIPs)
	for _, device := range excluded {
		if device.Prefix.Contains(address) {
			return append(lines, "↪️ It is among the Routing Excluded IPs ("+device.Text+"): the rules below do not take its traffic, it goes directly"), true
		}
	}
	// The route rule of the devices routed whole holds both families (plan.Build); the firewall
	// sends all the traffic of such a device to sing-box by its IPv4 address only, and of an IPv6
	// address only what goes to the IPv6 subnets of the lists, as of every device.
	for index := range config.Sections {
		section := &config.Sections[index]
		if !section.Enabled || config.Exit(section) == model.ExitNone {
			continue
		}
		for _, device := range section.Devices().Routed {
			if !device.Prefix.Contains(address) {
				continue
			}
			what := "all its traffic"
			if address.Is6() {
				what = "its connections that reach sing-box, those to the IPv6 subnets of the lists, not all its traffic"
			}
			return append(lines, "✅ Rule "+names.RuleText(section.Name)+" takes "+what+" (Fully Routed IPs, "+device.Text+"): "+exit(section)), true
		}
	}
	for index := lead; index < len(config.Sections); index++ {
		lists(&config.Sections[index])
	}
	return append(lines, "➡️ What no rule takes goes directly"), true
}
