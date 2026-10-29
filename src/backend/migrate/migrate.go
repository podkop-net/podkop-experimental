// Package migrate turns the settings of podkop 0.7 and of podkop-exp 0.8 into the format of
// podkop-exp 0.9. The servers move out of the sections: a link, a set of links, an
// outbound JSON or a network interface becomes a source (the tab Servers), and what a
// section takes becomes its members, rows of servers and of fallbacks in order. A
// subscription is a source of its own name, so its cached list stays; a group becomes the
// members of the sections that used it. A section keeps its name, lists and DNS: the rules
// of the route and the outbound tag "<section>-out" do not change.
package migrate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/uci"
)

// Version is the format of the settings the backend reads: settings.config_version.
const Version = "2"

// checkOptions are the options of the server check: a section of the type urltest had its
// own, there is one for every section now, in the settings.
var checkOptions = []string{"urltest_check_interval", "urltest_tolerance", "urltest_testing_url", "urltest_download_check", "urltest_download_url"}

// exitOptions are the options of a section that described its servers.
var exitOptions = []string{
	"connection_type", "proxy_config_type", "proxy_string", "outbound_json", "selector_proxy_links",
	"urltest_proxy_links", "urltest_fallback_links", "enable_udp_over_tcp", "detour", "interface",
	"domain_resolver_enabled", "domain_resolver_dns_type", "domain_resolver_dns_server", "group",
}

// Needed tells whether the settings are of an older format than Version.
func Needed(parsed *uci.Package) bool {
	settings := parsed.Section("settings")
	return settings != nil && settings.Type == "settings" && settings.Get("config_version") != Version
}

// Convert turns the settings into the format Version in place. The notes are for the
// journal: what was decided where the old settings had no equal. Settings of the format
// already are left alone and give no notes.
func Convert(parsed *uci.Package) []string {
	if !Needed(parsed) {
		return nil
	}
	c := &converter{
		parsed:  parsed,
		names:   make(map[string]bool),
		rows:    make(map[string][]*uci.Section),
		primary: make(map[string]string),
		ofGroup: make(map[string]bool),
		empty:   make(map[string]string),
	}
	for _, section := range parsed.Sections {
		c.names[section.Name] = true
	}
	settings := parsed.Section("settings")
	var subscriptions, sections, kept []*uci.Section
	for _, section := range parsed.Sections {
		switch section.Type {
		case "settings":
		case "subscription":
			subscriptions = append(subscriptions, section)
		case "section":
			sections = append(sections, section)
		case "group":
			// its sections take its servers as members
		default:
			kept = append(kept, section)
		}
	}
	c.check(settings, sections)
	for _, subscription := range subscriptions {
		if subscription.Name == "direct" || subscription.Name == "block" {
			c.rename(subscription)
		}
	}
	for _, subscription := range subscriptions {
		subscription.Type = "source"
		subscription.Set("type", "subscription")
		if subscription.Get("label") == "" {
			// the user named a subscription of 0.8 by its section; the page shows the label
			subscription.Set("label", subscription.Name)
		}
		if subscription.Get("update_interval") == "" {
			// what the backend of 0.8 took for a subscription without one
			subscription.Set("update_interval", "12h")
		}
	}
	for _, section := range sections {
		c.section(section)
	}
	for _, section := range sections {
		c.emptySection(section)
	}
	for _, section := range sections {
		c.detour(section)
	}
	// the backend of 0.8 put the rules of the block and exclusion sections before those of
	// every other section; the order of the sections decides now
	before := sectionNames(sections)
	sort.SliceStable(sections, func(i, j int) bool { return rank(sections[i]) < rank(sections[j]) })
	if after := sectionNames(sections); after != before {
		c.note("the sections of the types block and exclusion went first, as their rules did: %s", after)
	}
	for _, section := range sections {
		for _, name := range exitOptions {
			section.Delete(name)
		}
		for _, name := range checkOptions {
			section.Delete(name)
		}
	}
	settings.Set("config_version", Version)
	ordered := []*uci.Section{settings}
	ordered = append(ordered, kept...)
	ordered = append(ordered, subscriptions...)
	ordered = append(ordered, c.sources...)
	ordered = append(ordered, sections...)
	ordered = append(ordered, c.members...)
	parsed.Sections = ordered
	return c.notes
}

type converter struct {
	parsed  *uci.Package
	names   map[string]bool
	sources []*uci.Section
	members []*uci.Section
	// rows are the members of each section, in order
	rows map[string][]*uci.Section
	// primary is the source a section's connections go through: what a detour to the
	// section goes through now
	primary map[string]string
	// ofGroup marks a section whose primary is the first subscription of its group
	ofGroup map[string]bool
	// empty is the section an empty group sent its sections to
	empty map[string]string
	made  int
	notes []string
}

// rename gives a subscription named as a reserved source (direct, block) another name, in the
// groups that name it too; its list is downloaded again under the new name.
func (c *converter) rename(subscription *uci.Section) {
	old := subscription.Name
	subscription.Name = c.name(old + "_sub")
	for _, group := range c.parsed.Sections {
		if group.Type != "group" {
			continue
		}
		words := listWords(group, "subscription")
		for index, word := range words {
			if word == old {
				words[index] = subscription.Name
			}
		}
		group.SetList("subscription", words)
	}
	if subscription.Get("label") == "" {
		subscription.Set("label", old)
	}
	c.note("the subscription %s is the source %s now: %s names the outbound of the same name", old, subscription.Name, old)
}

func (c *converter) note(format string, arguments ...any) {
	c.notes = append(c.notes, fmt.Sprintf(format, arguments...))
}

// name returns a section name not taken: sections, sources and the rest share one name
// space in UCI.
func (c *converter) name(base string) string {
	name := base
	for number := 2; c.names[name]; number++ {
		name = fmt.Sprintf("%s_%d", base, number)
	}
	c.names[name] = true
	return name
}

func (c *converter) source(base string, kind string) *uci.Section {
	source := uci.NewSection("source", c.name(base), false)
	source.Set("type", kind)
	c.sources = append(c.sources, source)
	return source
}

func (c *converter) member(section string, role string, source string) *uci.Section {
	c.made++
	// an anonymous section: the name only tells it apart until the file is read again
	member := uci.NewSection("member", fmt.Sprintf("@member%d", c.made), true)
	member.Set("section", section)
	member.Set("role", role)
	member.Set("source", source)
	c.members = append(c.members, member)
	c.rows[section] = append(c.rows[section], member)
	return member
}

// check takes the server check of the first section of the type urltest into the
// settings: there is one check for every section now.
func (c *converter) check(settings *uci.Section, sections []*uci.Section) {
	var first *uci.Section
	for _, section := range sections {
		if section.Get("proxy_config_type") != "urltest" || !isProxy(section) {
			continue
		}
		if first == nil {
			first = section
			for _, name := range checkOptions {
				if value := section.Get(name); value != "" && settings.Get(name) == "" {
					settings.Set(name, value)
				}
			}
			continue
		}
		for _, name := range checkOptions {
			if section.Get(name) != first.Get(name) {
				c.note("the sections %s and %s checked their servers differently: the one check of the settings takes the values of %s", first.Name, section.Name, first.Name)
				break
			}
		}
	}
}

func isProxy(section *uci.Section) bool {
	kind := section.Get("connection_type")
	return kind == "proxy" || kind == ""
}

func (c *converter) section(section *uci.Section) {
	name := section.Name
	switch kind := section.Get("connection_type"); kind {
	case "block":
		c.member(name, "server", "block")
	case "exclusion":
		c.member(name, "server", "direct")
	case "vpn":
		source := c.source(name+"_if", "interface")
		source.Set("interface", section.Get("interface"))
		if isOne(section.Get("domain_resolver_enabled")) {
			source.Set("domain_resolver_enabled", "1")
			for _, option := range []string{"domain_resolver_dns_type", "domain_resolver_dns_server"} {
				if value := section.Get(option); value != "" {
					source.Set(option, value)
				}
			}
		}
		c.member(name, "server", source.Name)
		c.primary[name] = source.Name
	case "group":
		c.group(section)
	case "proxy", "":
		if kind == "" && !section.Has("proxy_config_type") && !section.Has("proxy_string") {
			// no servers before either: a section of lists only
			return
		}
		c.proxy(section)
	default:
		c.note("the section %s had the connection type %q, which podkop does not know: it got no servers", name, kind)
	}
}

func (c *converter) proxy(section *uci.Section) {
	name := section.Name
	var source *uci.Section
	var fallbacks []string
	switch kind := section.Get("proxy_config_type"); kind {
	case "", "url":
		source = c.source(name+"_link", "links")
		if link := strings.TrimSpace(section.Get("proxy_string")); link != "" {
			source.SetList("link", []string{link})
		}
	case "selector":
		source = c.source(name+"_links", "links")
		source.SetList("link", strings.Fields(section.Get("selector_proxy_links")))
		c.note("the section %s had its server chosen by hand (selector): it takes the fastest now, and a server can be pinned on the dashboard", name)
	case "urltest":
		source = c.source(name+"_links", "links")
		source.SetList("link", strings.Fields(section.Get("urltest_proxy_links")))
		fallbacks = strings.Fields(section.Get("urltest_fallback_links"))
	case "outbound":
		source = c.source(name+"_json", "json")
		source.Set("outbound_json", section.Get("outbound_json"))
	default:
		c.note("the section %s had the proxy type %q, which podkop does not know: it got no servers", name, kind)
		return
	}
	udpOverTCP(source, section)
	c.member(name, "server", source.Name)
	c.primary[name] = source.Name
	// the fallback links were used in their order: a source and a fallback row each
	for index, link := range fallbacks {
		fallback := c.source(fmt.Sprintf("%s_fallback%d", name, index+1), "links")
		fallback.SetList("link", []string{link})
		udpOverTCP(fallback, section)
		c.member(name, "fallback", fallback.Name)
	}
}

func udpOverTCP(source *uci.Section, section *uci.Section) {
	if section.Get("enable_udp_over_tcp") == "1" {
		source.Set("udp_over_tcp", "1")
	}
}

func (c *converter) group(section *uci.Section) {
	name := section.Name
	words := listWords(section, "group")
	if len(words) == 0 {
		c.note("the section %s of the type group had no group: it got no servers", name)
		return
	}
	group := c.parsed.Section(words[0])
	if group == nil || group.Type != "group" {
		c.note("the section %s used the group %s, which is not there: it got no servers", name, words[0])
		return
	}
	var subscriptions []string
	for _, subscription := range listWords(group, "subscription") {
		if found := c.parsed.Section(subscription); found != nil && (found.Type == "subscription" || found.Type == "source") {
			subscriptions = append(subscriptions, subscription)
		}
	}
	if empty := group.Get("empty"); len(subscriptions) == 0 && (empty == "" || empty == "all") {
		// a group of no subscription that is there had no server: 0.8 refused the connections
		c.note("the group %s of the section %s names no subscription that is there: the connections of %s are refused, as they were", words[0], name, name)
		c.member(name, "server", "block")
		return
	}
	include, exclude := listWords(group, "include"), listWords(group, "exclude")
	for _, subscription := range subscriptions {
		member := c.member(name, "server", subscription)
		member.SetList("include", include)
		member.SetList("exclude", exclude)
	}
	if len(subscriptions) > 0 {
		c.primary[name] = subscriptions[0]
		c.ofGroup[name] = true
	}
	switch empty := group.Get("empty"); empty {
	case "", "all":
		if len(include) == 0 && len(exclude) == 0 {
			// the rows take every server already
			return
		}
		for _, subscription := range subscriptions {
			c.member(name, "fallback", subscription)
		}
	case "direct", "block":
		c.member(name, "fallback", empty)
	case "section":
		c.empty[name] = group.Get("empty_section")
	default:
		c.note("the group %s of the section %s had the empty rule %q, which podkop does not know: the section has no fallback", group.Name, name, empty)
	}
}

// emptySection gives a section whose group went to another section when empty the server
// rows of that section as its fallbacks.
func (c *converter) emptySection(section *uci.Section) {
	target, found := c.empty[section.Name]
	if !found {
		return
	}
	var copied int
	for _, row := range c.rows[target] {
		if row.Get("role") != "server" {
			continue
		}
		member := c.member(section.Name, "fallback", row.Get("source"))
		member.SetList("include", row.List("include"))
		member.SetList("exclude", row.List("exclude"))
		copied++
	}
	if copied == 0 {
		c.note("the section %s went to the section %s when its group was empty, and %s has no servers: the fallback of %s is to block", section.Name, target, target, section.Name)
		c.member(section.Name, "fallback", "block")
	}
}

// detour makes "connect through" of a section the via of its rows: the source the section
// it named connects through.
func (c *converter) detour(section *uci.Section) {
	target := section.Get("detour")
	if target == "" || target == section.Name {
		return
	}
	if !isProxy(section) {
		// the backend of 0.8 left it out as well
		c.note("the section %s connected through the section %s, which only a proxy section could: it is not carried over", section.Name, target)
		return
	}
	via := c.primary[target]
	if next := c.parsed.Section(target); via != "" && next != nil && next.Get("detour") != "" && next.Get("detour") != target {
		c.note("the section %s connected through %s, which connected through %s: a row goes through one source now, %s connects through the server of %s directly", section.Name, target, next.Get("detour"), section.Name, target)
	}
	if via == "" {
		c.note("the section %s connected through the section %s, which has no server now: %s connects directly", section.Name, target, section.Name)
		return
	}
	if c.ofGroup[target] {
		c.note("the section %s connected through the group of %s: it connects through the best server of the subscription %s now", section.Name, target, via)
	}
	for _, row := range c.rows[section.Name] {
		if source := row.Get("source"); source == "direct" || source == "block" || source == via {
			continue
		}
		row.Set("via", via)
	}
}

func rank(section *uci.Section) int {
	switch section.Get("connection_type") {
	case "block":
		return 0
	case "exclusion":
		return 1
	}
	return 2
}

func sectionNames(sections []*uci.Section) string {
	names := make([]string, 0, len(sections))
	for _, section := range sections {
		names = append(names, section.Name)
	}
	return strings.Join(names, ", ")
}

// listWords returns the items of a list option without the empty ones and the spaces
// around them.
func listWords(section *uci.Section, name string) []string {
	var result []string
	for _, item := range section.List(name) {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

// isOne reads a switch as the shell backend's "-eq 1" did.
func isOne(text string) bool {
	text = strings.TrimPrefix(strings.Trim(text, " \t\n"), "+")
	if text == "" {
		return false
	}
	return strings.TrimLeft(text[:len(text)-1], "0") == "" && text[len(text)-1] == '1'
}
