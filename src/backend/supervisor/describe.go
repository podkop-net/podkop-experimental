package supervisor

import (
	"strconv"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
)

// describeConfig tells in a line what a configuration that starts is: its rules with where
// each sends traffic, its sources, its lists, its DNS and the interfaces the LAN comes in on.
func describeConfig(next *candidate) string {
	config := next.settings
	var sections []string
	for index := range config.Sections {
		section := &config.Sections[index]
		what := config.Exit(section)
		switch {
		case !section.Enabled:
			what = "off"
		case what == model.ExitNone:
			what = "no source filled"
		case what == model.ExitServers:
			what = rowsText(section.Servers)
			if len(section.Fallbacks) > 0 {
				what += "; fallbacks " + rowsText(section.Fallbacks)
			}
		}
		sections = append(sections, section.Name+" ("+what+")")
	}
	var sources []string
	for _, source := range config.Sources {
		what := source.Type
		switch source.Type {
		case "":
			what = "not filled"
		case "links":
			what = strconv.Itoa(len(source.Links)) + " links"
		case "interface":
			what = "interface " + source.Interface
			if source.Interface == "" {
				what = "the main route"
			}
		}
		sources = append(sources, source.Name+" ("+what+")")
	}
	downloaded, files := 0, 0
	for _, ruleSet := range next.result.RuleSets {
		if ruleSet.URL != "" {
			downloaded++
		} else {
			files++
		}
	}
	settings := &next.settings.Settings
	return "configuration: rules " + strings.Join(sections, ", ") +
		"; sources " + strings.Join(sources, ", ") +
		"; " + strconv.Itoa(len(next.result.RuleSets)) + " lists (" + strconv.Itoa(downloaded) + " downloaded, " + strconv.Itoa(files) + " from files)" +
		"; DNS " + settings.DNSType + " " + settings.DNSServer +
		"; the LAN on " + strings.Join(settings.SourceNetworkInterfaces, ", ")
}

// rowsText names the rows of a rule: their sources, with the filter and the source they
// connect through.
func rowsText(rows []model.Member) string {
	var names []string
	for _, row := range rows {
		name := row.Source
		if len(row.Include) > 0 {
			name += " with " + strings.Join(row.Include, "/")
		}
		if len(row.Exclude) > 0 {
			name += " without " + strings.Join(row.Exclude, "/")
		}
		if row.Via != "" {
			name += " via " + row.Via
		}
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

// describeFirewall tells what the sets of the firewall send to the proxy by address.
func describeFirewall(plan *firewall.Plan) string {
	text := "firewall: " + strconv.Itoa(len(plan.Subnets)) + " address ranges of the lists go to the proxy by address"
	if len(plan.Groups) > 0 {
		count := 0
		for _, group := range plan.Groups {
			count += len(group.Ranges)
		}
		text += ", " + strconv.Itoa(count) + " more for some ports only (" + strconv.Itoa(len(plan.Groups)) + " groups of ports)"
	}
	return text
}

// tellFirewall logs what the sets of the firewall hold when that changed.
func (s *Supervisor) tellFirewall(plan *firewall.Plan) {
	if plan == nil {
		return
	}
	text := describeFirewall(plan)
	if text != s.firewallTold {
		s.firewallTold = text
		s.log("info", text)
	}
}
