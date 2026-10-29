package plan

import (
	neturl "net/url"
	pathpkg "path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	E "github.com/sagernet/sing/common/exceptions"
)

func ruleSetTag(section string, name string, kind string) string {
	return section + "-" + name + "-" + kind + "-ruleset"
}

// buildSectionLists makes the rule sets of a section and the route rule they belong to.
func (b *builder) buildSectionLists(section *model.Section) error {
	if !b.routes(section) {
		return nil
	}
	if !section.HasEnabledLists() {
		if len(section.FullyRoutedIPs) == 0 && !section.MixedProxyEnabled {
			b.warn("rule ", section.Name, " has no list: no route rule for it")
		}
		return nil
	}
	target := b.addRouteRule("section "+section.Name, b.sectionRoute(section, tagTProxyInbound))

	for _, list := range section.CommunityLists {
		if !slices.Contains(communityLists, list) {
			// as the shell backend: a name of no list would be retried for ever
			return E.New("section ", section.Name, ": no community list is named \"", list, "\"")
		}
		tag := ruleSetTag(section.Name, list, "community")
		b.addRemoteRuleSet(tag, "binary", urlCommunityLists+"/"+list+".srs")
		patch(target.fields, "rule_set", argument(tag))
		patch(b.fakeIPRule.fields, "rule_set", argument(tag))
	}
	if section.UserDomainListType != "disabled" {
		file := b.addSourceRuleSet(section.Name, "user", "domains", target)
		var items string
		switch section.UserDomainListType {
		case "dynamic":
			items = section.UserDomains
		case "text":
			items = section.UserDomainsText
		}
		var dropped leftOut
		patchRuleSetFile(file, "domain_suffix", parseItems(items, model.IsDomainSuffix, &dropped))
		b.warnLeftOut(dropped, "no domain", "section ", section.Name, ", the user domain list")
	}
	if section.UserSubnetListType != "disabled" {
		file := b.addSourceRuleSet(section.Name, "user", "subnets", target)
		var items string
		switch section.UserSubnetListType {
		case "dynamic":
			items = section.UserSubnets
		case "text":
			items = section.UserSubnetsText
		}
		var dropped leftOut
		patchRuleSetFile(file, "ip_cidr", parseItems(items, isSubnet, &dropped))
		b.warnLeftOut(dropped, "no subnet", "section ", section.Name, ", the user subnet list")
	}
	b.addLocalLists(section, "domains", target)
	b.addLocalLists(section, "subnets", target)
	b.addRemoteLists(section, "domains", target)
	b.addRemoteLists(section, "subnets", target)

	if section.ResolveRealIPForRouting {
		// before the rule of the section, with the rule sets it has by now: names of the
		// lists are resolved, and the rule is then matched by the address as well
		ruleSet, found := target.fields.get("rule_set")
		if !found {
			ruleSet = []any{}
		}
		resolve := &rule{fields: newObject("action", "resolve", "rule_set", ruleSet, "server", tagDNSServer)}
		for index, entry := range b.routeRules {
			if entry == target {
				b.routeRules = append(b.routeRules[:index], append([]*rule{resolve}, b.routeRules[index:]...)...)
				break
			}
		}
	}
	return nil
}

func isSubnet(text string) bool {
	return model.IsIPv4(text) || model.IsIPv4CIDR(text)
}

func (b *builder) downloadDetour() string {
	if !b.config.Settings.DownloadListsViaProxy {
		return ""
	}
	name := b.config.Settings.DownloadListsViaProxySection
	if section := b.config.Section(name); section != nil && (!b.config.HasOutbound(section) || b.isRefused(section)) {
		b.warnOnce("the lists are downloaded directly: rule ", name, " has no servers now")
		return ""
	}
	return outboundTag(name)
}

// addRemoteRuleSet names a rule set sing-box downloads. It downloads with the HTTP
// client of the lists (see listsHTTPClient), not with download_detour, which sing-box
// 1.14 deprecates and 1.16 removes, and not with the implicit default client either.
func (b *builder) addRemoteRuleSet(tag string, format string, url string) {
	ruleSet := newObject("type", "remote", "tag", tag, "format", format, "url", url)
	ruleSet.set("update_interval", b.config.Settings.UpdateInterval)
	b.ruleSets = append(b.ruleSets, ruleSet)
	b.remoteRuleSets = true
}

// listsHTTPClient is the HTTP client the remote rule sets download with: through the
// outbound of the section the settings name for the lists, or directly.
func (b *builder) listsHTTPClient() *object {
	client := newObject("tag", tagListsHTTPClient)
	if detour := b.downloadDetour(); detour != "" {
		client.set("detour", detour)
	}
	return client
}

// addSourceRuleSet makes a rule-set file the backend fills itself, names it in the
// configuration and in the rule of the section, and, for names, in the FakeIP rule. A
// section has one such file of a kind; asked again, it returns the file there is.
func (b *builder) addSourceRuleSet(section string, name string, kind string, target *rule) *object {
	tag := ruleSetTag(section, name, kind)
	path := b.options.RuleSetDir + "/" + tag + ".json"
	if file, exists := b.files[path]; exists {
		return file
	}
	file := newObject("version", versionSourceRuleSet, "rules", []any{})
	b.files[path] = file
	b.fileOrder = append(b.fileOrder, path)
	b.ruleSets = append(b.ruleSets, newObject("type", "local", "tag", tag, "format", "source", "path", path))
	patch(target.fields, "rule_set", argument(tag))
	if kind == "domains" {
		patch(b.fakeIPRule.fields, "rule_set", argument(tag))
	}
	return file
}

// A list the user gave, by URL or by the path of a file, is a rule set of sing-box: a rule
// set file (.json, .srs) of its format, any other a list written as plain text (format
// text, common/ruletext). The extension is the one of the path, whatever its case; the
// query of a URL does not count.
func listFormat(location string) string {
	if parsed, err := neturl.Parse(location); err == nil && parsed.Scheme != "" {
		location = parsed.Path
	}
	switch strings.ToLower(pathpkg.Ext(location)) {
	case ".json":
		return "source"
	case ".srs":
		return "binary"
	}
	return "text"
}

// listName is the part of the file name of a list before its first dot; "list" when the
// location names no file.
func listName(location string) string {
	if parsed, err := neturl.Parse(location); err == nil && parsed.Scheme != "" {
		location = parsed.Path
	}
	fileName := location[strings.LastIndexByte(location, '/')+1:]
	name, _, _ := strings.Cut(fileName, ".")
	if name == "" {
		return "list"
	}
	return name
}

// listEntry is the rule set of one list the user gave.
type listEntry struct {
	location string
	format   string
	tag      string
}

// listEntries names the rule sets of lists of a section and kind, in their order: by the
// name of the file, with "text" for lists written as text (their rule sets come together,
// see addRemoteLists) and "local" for files of the router, and by a number when two lists
// of one sort have one name.
func listEntries(section string, kind string, locations []string, local bool) []listEntry {
	entries := make([]listEntry, len(locations))
	taken := make(map[string]bool)
	for index, location := range locations {
		format := listFormat(location)
		group := "remote-" + kind
		switch {
		case local:
			group = "local-" + kind
		case format == "text":
			group = "text-" + kind
		}
		base := listName(location)
		name := base
		for number := 2; taken[group+" "+name]; number++ {
			name = base + "-" + strconv.Itoa(number)
		}
		taken[group+" "+name] = true
		entries[index] = listEntry{location: location, format: format, tag: ruleSetTag(section, name, group)}
	}
	return entries
}

// remoteLocations and localLocations are the lists of a kind of a section.
func remoteLocations(section *model.Section, kind string) []string {
	if kind == "subnets" {
		return section.RemoteSubnetLists
	}
	return section.RemoteDomainLists
}

func localLocations(section *model.Section, kind string) []string {
	if kind == "subnets" {
		return section.LocalSubnetLists
	}
	return section.LocalDomainLists
}

// remoteOrder is the order the rule sets of the remote lists of a section and kind come
// in: each rule set file where it is, the lists written as text together, where the first
// of them is.
func remoteOrder(entries []listEntry) []listEntry {
	var ordered []listEntry
	textAdded := false
	for _, entry := range entries {
		if entry.format != "text" {
			ordered = append(ordered, entry)
			continue
		}
		if textAdded {
			continue
		}
		textAdded = true
		for _, text := range entries {
			if text.format == "text" {
				ordered = append(ordered, text)
			}
		}
	}
	return ordered
}

// addRemoteLists names the lists of a section and kind the user gave by URL; sing-box
// downloads every one of them.
func (b *builder) addRemoteLists(section *model.Section, kind string, target *rule) {
	for _, entry := range remoteOrder(listEntries(section.Name, kind, remoteLocations(section, kind), false)) {
		b.addRemoteRuleSet(entry.tag, entry.format, entry.location)
		b.refer(target, kind, entry.tag)
	}
}

// addLocalLists names the lists of a section and kind that are files of the router:
// sing-box reads each and reads it again when it changes. A file sing-box cannot read
// would stop the whole configuration: it is told in the log and stands as an empty rule
// set file of the backend until the settings are applied again.
func (b *builder) addLocalLists(section *model.Section, kind string, target *rule) {
	for _, entry := range listEntries(section.Name, kind, localLocations(section, kind), true) {
		if problem := b.checkLocalList(entry); problem != "" {
			b.warn("local list ", entry.location, " ", problem, ": it is left empty until the settings are applied again")
			b.addEmptyRuleSet(entry.tag)
		} else {
			b.ruleSets = append(b.ruleSets, newObject("type", "local", "tag", entry.tag, "format", entry.format, "path", b.localPath(entry.location)))
		}
		b.refer(target, kind, entry.tag)
	}
}

// checkLocalList tells what is wrong with a local list for sing-box, nothing when sing-box
// takes it; lines a text list leaves out go to the log.
func (b *builder) checkLocalList(entry listEntry) string {
	content, err := b.options.ReadFile(entry.location)
	if err != nil {
		return "is not found"
	}
	if b.options.CheckList == nil {
		return ""
	}
	skipped, first, err := b.options.CheckList(entry.format, content)
	if err != nil {
		return "cannot be read as a list (" + err.Error() + ")"
	}
	if skipped > 0 {
		what := "neither a domain nor an IP CIDR"
		b.warnLeftOut(leftOut{count: skipped, first: first}, what, "local list ", entry.location)
	}
	return ""
}

func (b *builder) localPath(path string) string {
	if b.options.LocalPath == nil {
		return path
	}
	return b.options.LocalPath(path)
}

// addEmptyRuleSet names a rule set file of the backend with no rule in it.
func (b *builder) addEmptyRuleSet(tag string) {
	path := b.options.RuleSetDir + "/" + tag + ".json"
	b.files[path] = newObject("version", versionSourceRuleSet, "rules", []any{})
	b.fileOrder = append(b.fileOrder, path)
	b.ruleSets = append(b.ruleSets, newObject("type", "local", "tag", tag, "format", "source", "path", path))
}

// refer names a rule set in the rule of the section and, for names, in the FakeIP rule.
func (b *builder) refer(target *rule, kind string, tag string) {
	patch(target.fields, "rule_set", argument(tag))
	if kind == "domains" {
		patch(b.fakeIPRule.fields, "rule_set", argument(tag))
	}
}

// leftOut counts what a list has that is no item, and keeps the first of it.
type leftOut struct {
	count int
	first string
}

func (l *leftOut) add(item string) {
	if l == nil {
		return
	}
	if l.count == 0 {
		l.first = item
	}
	l.count++
}

// warnLeftOut tells the log what a list had that is no item and was left out: a typo
// otherwise only shows as a name that does not go where it should.
// what the items are not (no domain, no subnet), list which list it is.
func (b *builder) warnLeftOut(dropped leftOut, what string, list ...any) {
	if dropped.count == 0 {
		return
	}
	first := dropped.first
	if len(first) > 64 {
		first = first[:64] + "…"
	}
	b.warn(append(list, ": ", dropped.count, " item(s) are ", what, " and are left out, the first: ", strconv.Quote(first))...)
}

// parseItems takes the items of a list written as text: comments from "//" to the end of
// a line, items separated by commas, spaces and line ends. What is no item is left out
// and counted in dropped.
func parseItems(text string, valid func(string) bool, dropped *leftOut) []string {
	items := []string{}
	for _, line := range strings.Split(text, "\n") {
		if comment := strings.Index(line, "//"); comment >= 0 {
			line = line[:comment]
		}
		for _, item := range strings.FieldsFunc(line, func(character rune) bool { return character == ',' || character == ' ' }) {
			item = trimSpace(item)
			if item == "" {
				continue
			}
			if valid(item) {
				items = append(items, item)
			} else {
				dropped.add(item)
			}
		}
	}
	return items
}

// trimSpace removes what the shell backend's [[:space:]] removes at both ends.
func trimSpace(text string) string {
	return strings.Trim(text, " \t\n\v\f\r")
}

// patchRuleSetFile adds items to the rule of a rule-set file that has the key, or makes
// the rule.
func patchRuleSetFile(file *object, key string, items []string) {
	rules, _ := file.get("rules")
	list := rules.([]any)
	for _, entry := range list {
		fields := entry.(*object)
		current, found := fields.get(key)
		if !found {
			continue
		}
		merged := append(append([]string{}, anyToStrings(current.([]any))...), items...)
		sort.Strings(merged)
		unique := merged[:0]
		for index, item := range merged {
			if index == 0 || item != merged[index-1] {
				unique = append(unique, item)
			}
		}
		fields.set(key, stringsToAny(unique))
		return
	}
	file.set("rules", append(list, newObject(key, stringsToAny(items))))
}

func anyToStrings(items []any) []string {
	result := make([]string, len(items))
	for index, item := range items {
		result[index] = item.(string)
	}
	return result
}
