package plan

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	E "github.com/sagernet/sing/common/exceptions"
)

// The generator wrote what the shell backend of podkop 0.7.24 writes, byte for byte, and
// the cases of render/testdata hold what the shell backend wrote. Where the generator
// differs on purpose, the difference is listed here, and
// FromShell brings a configuration of the shell backend to what the generator writes
// instead, so that every case still checks the rest byte for byte:
//
//  1. Remote rule sets download with one named HTTP client, "lists", with a detour to the
//     outbound of the section the settings name for the lists, or without one, and
//     route.default_http_client names it. The shell backend gives each rule set
//     download_detour, or nothing (the implicit default client): sing-box 1.14 notes
//     both as deprecated, and 1.16 removes them.
//  2. A list given by URL that is no rule set file is a remote rule set of the format
//     text, a URL each, downloaded by sing-box (common/ruletext); those of a section and
//     kind come together, where the first of them is. The shell backend downloads such
//     lists itself into one local rule set file of the section and kind.
//  3. No inbound service-mixed-in (port 4534) and no route rule of it: it was the proxy
//     the backend's own downloads went through, and the backend downloads nothing now.
//  4. What a list is, is told by the extension of the path of its URL, whatever its case
//     and without the query (list.json?raw=1 and LIST.SRS are rule set files; the shell
//     backend took both for plain lists), and two lists of one name in a section and kind
//     get numbers (the shell backend gives them one tag, and sing-box refuses the
//     configuration).
//  5. A list that is a file of the router is a local rule set of sing-box, a file each, in
//     the format of its extension: sing-box reads the file and reads it again when it
//     changes. The shell backend copies the files of a section and kind into one rule set
//     file at its start, its own way (the last line without a line end lost, a thousand
//     items at a time). A file sing-box cannot read stands as an empty rule set file.
//  6. No dns.independent_cache: the cache of sing-box 1.14 keeps the answers of each server
//     apart anyway, the option is deprecated and 1.16 removes it.
//  7. The Clash API has the key of the settings whenever there is one, YACD on or not;
//     the shell backend gives it only with YACD.
//  8. The files are in the backend's own directories, none in those of the sing-box
//     package: the rule-set files in /var/run/podkop/rulesets (the shell backend:
//     /tmp/sing-box/rulesets), and a cache file the settings name in /tmp/sing-box or
//     /usr/share/sing-box under the same name in /var/run/podkop or /usr/share/podkop
//     (model.CachePath); without cache_path it is /var/run/podkop/cache.db (the shell
//     backend: /tmp/sing-box/cache.db).
//  9. No rules for the names the checks of podkop 0.7's page ask an outside server with:
//     the shell backend routes ip.podkop.fyi to the first section and sends
//     fakeip.podkop.fyi to port 8443, and its DNS rule answers both from FakeIP. The page
//     of this backend asks the backend instead. That DNS rule answers the readiness name
//     (dataplane.ReadinessName) alone.
// 10. The Clash API listens on 127.0.0.1, or on every address with YACD on, where the
//     firewall lets only the devices of yacd_interfaces reach it (firewall.Plan); the shell
//     backend listens on the address of the LAN, or on every address with YACD's WAN
//     access, which this backend does not have.
// 11. The connections sing-box opens itself are not bound to the interface of the default
//     route (route.auto_detect_interface of the shell backend): they go where the routing
//     of the router sends them, mwan3 and the routes of hosts and tunnels included, with
//     route.default_mark (dataplane.OutboundMark), which mangle_output lets go by. An
//     interface of the settings still binds them (route.default_interface), as the
//     interface of a VPN section binds its outbound; the device of layer 3 a name stands
//     for (Facts.Devices) goes there. What is bound to the device of an uplink goes by the
//     main table (netcfg.RouteUplinks), not into the table of another uplink that the
//     policy of mwan3 chose.
// 12. Settings with two mixed proxies on one port are refused: sing-box would fail to start
//     on the second socket, and so would every try of the start again. The shell backend
//     wrote the configuration.
// 13. A proxy section connected through another section (option detour) in 0.8; since 0.9
//     a row of a rule connects through a source (item 17).
// 14. The uTLS fingerprint fallback of the engine (experimental.utls_fallback) is told
//     always: on without the option utls_fallback and with 'enabled', off with 'disabled'.
//     The shell backend wrote it only with enable_utls_fallback on, with a list of
//     fingerprints the engine reads no more since podkop-engine r17.
// 15. A name without an IPv4 address gets its IPv6 addresses (dns.ipv6_if_no_ipv4 of
//     podkop-engine r17): the strategy stays ipv4_only, and an AAAA question goes out only
//     when the A question of its name is answered without an A record. FakeIP answers no
//     AAAA question, so a name of a list is not affected. The shell backend answered every
//     AAAA question empty.
// 16. The names of the NTP servers of the router's NTP service (Facts.NTPServerNames) have
//     a DNS rule of their own before the lists: they get their own addresses, never FakeIP
//     ones, and the NTP of the router goes past the proxy (firewall). The shell backend had
//     neither: a name of a list sent sysntpd through the proxy, which a wrong clock breaks.
//     Without such names (the cases of render/testdata) there is no rule.
// 17. Since podkop-exp 0.9 the servers are sources and rows of rules (exits.go): a server
//     is an outbound once, and once more for each source its rows connect through; a rule
//     goes through the selector "<rule>-out" over a URL test of the servers of its rows with
//     its fallback rows in order, the server check one for every rule; a rule whose rows of
//     the servers are all direct or all block is a route rule of its own at its place in the
//     order of the rules, and those at the top go before the devices left out and routed
//     whole, as the block and exclusion sections did. The shell backend built the outbounds
//     of each section from its own links, and put the rules of the block and exclusion
//     sections before all others: the cases are not compared since (render.TestCases).

// Shell is what FromShell has to know besides the configuration: the settings it was made
// of, and how the generator reads and names the local lists (Options: RuleSetDir,
// ReadFile, CheckList, LocalPath).
type Shell struct {
	Settings *model.Config
	Options  Options
}

// Converted is a configuration of the shell backend as the generator writes it.
type Converted struct {
	Config []byte
	// Dropped are rule-set files of the shell backend the generator does not write, by
	// name; Added are those it writes and the shell backend does not, by name.
	Dropped []string
	Added   map[string][]byte
}

// FromShell returns a configuration the shell backend wrote as the generator writes it,
// the differences above applied.
func FromShell(content []byte, shell Shell) (*Converted, error) {
	value, err := parseValue(content)
	if err != nil {
		return nil, err
	}
	document, isObject := value.(*object)
	if !isObject {
		return &Converted{Config: content}, nil
	}
	options := shell.Options
	if options.RuleSetDir == "" {
		options.RuleSetDir = DefaultRuleSetDir
	}
	converted := &Converted{Added: make(map[string][]byte)}
	removeServiceProxy(document)
	replaceCheckNames(document)
	if dns, _ := document.get("dns"); dns != nil {
		if dnsObject, isObject := dns.(*object); isObject {
			dnsObject.remove("independent_cache")
			if _, found := dnsObject.get("strategy"); found {
				dnsObject.insertAfter("strategy", "ipv6_if_no_ipv4", true)
			}
		}
	}
	route, _ := document.get("route")
	routeObject, _ := route.(*object)
	if routeObject != nil {
		if _, found := routeObject.get("auto_detect_interface"); found {
			routeObject.insertAfter("auto_detect_interface", "default_mark", dataplane.OutboundMark)
			routeObject.remove("auto_detect_interface")
		}
	}
	if routeObject != nil && shell.Settings != nil {
		ruleSets, _ := routeObject.get("rule_set")
		list, _ := ruleSets.([]any)
		var detour any
		for _, entry := range list {
			if ruleSet, isObject := entry.(*object); isObject {
				if value, found := ruleSet.get("download_detour"); found {
					detour = value
					ruleSet.remove("download_detour")
				}
			}
		}
		for index := range shell.Settings.Sections {
			section := &shell.Settings.Sections[index]
			for _, kind := range []string{"domains", "subnets"} {
				// the files of the router
				locals := listEntries(section.Name, kind, localLocations(section, kind), true)
				if len(locals) > 0 {
					oldTag := ruleSetTag(section.Name, "local", kind)
					var replacement []any
					var newTags []string
					for _, entry := range locals {
						newTags = append(newTags, entry.tag)
						if usableLocalList(entry, options) {
							replacement = append(replacement, newObject("type", "local", "tag", entry.tag, "format", entry.format, "path", localPathOf(entry.location, options)))
							continue
						}
						path := options.RuleSetDir + "/" + entry.tag + ".json"
						replacement = append(replacement, newObject("type", "local", "tag", entry.tag, "format", "source", "path", path))
						empty, err := indented(newObject("version", versionSourceRuleSet, "rules", []any{}))
						if err != nil {
							return nil, err
						}
						converted.Added[entry.tag+".json"] = empty
					}
					list, err = replaceSpan(list, []string{oldTag}, replacement)
					if err != nil {
						return nil, E.Cause(err, "section ", section.Name, ", local ", kind)
					}
					converted.Dropped = append(converted.Dropped, oldTag+".json")
					replaceReferences(document, []string{oldTag}, newTags)
				}
				// the lists given by URL
				locations := remoteLocations(section, kind)
				if len(locations) > 0 {
					oldTags, plain := shellRemoteTags(section.Name, kind, locations)
					var replacement []any
					var newTags []string
					for _, entry := range remoteOrder(listEntries(section.Name, kind, locations, false)) {
						newTags = append(newTags, entry.tag)
						replacement = append(replacement, newObject("type", "remote", "tag", entry.tag, "format", entry.format, "url", entry.location,
							"update_interval", shell.Settings.Settings.UpdateInterval))
					}
					list, err = replaceSpan(list, oldTags, replacement)
					if err != nil {
						return nil, E.Cause(err, "section ", section.Name, ", remote ", kind)
					}
					if plain {
						converted.Dropped = append(converted.Dropped, ruleSetTag(section.Name, "remote", kind)+".json")
					}
					replaceReferences(document, oldTags, newTags)
				}
			}
		}
		routeObject.set("rule_set", list)
		remote := false
		for _, entry := range list {
			if ruleSet, isObject := entry.(*object); isObject {
				if kind, _ := ruleSet.get("type"); kind == "remote" {
					remote = true
				}
			}
		}
		if remote {
			if detour == nil && shell.Settings.Settings.DownloadListsViaProxy {
				// a configuration whose only downloaded lists were plain ones had no
				// download_detour to take the section from
				detour = outboundTag(shell.Settings.Settings.DownloadListsViaProxySection)
			}
			client := newObject("tag", tagListsHTTPClient)
			if detour != nil {
				client.set("detour", detour)
			}
			document.insertAfter("certificate", "http_clients", []any{client})
			routeObject.set("default_http_client", tagListsHTTPClient)
		}
	}
	if experimental, _ := document.get("experimental"); experimental != nil && shell.Settings != nil {
		if experimentalObject, isObject := experimental.(*object); isObject {
			if clashAPI, _ := experimentalObject.get("clash_api"); clashAPI != nil {
				if clashAPIObject, isObject := clashAPI.(*object); isObject {
					if shell.Settings.Settings.YACDSecretKey != "" {
						clashAPIObject.set("secret", shell.Settings.Settings.YACDSecretKey)
					}
					address := "127.0.0.1"
					if shell.Settings.Settings.EnableYACD {
						address = "0.0.0.0"
					}
					clashAPIObject.set("external_controller", address+":"+strconv.Itoa(dataplane.ClashAPIPort))
				}
			}
			experimentalObject.set("utls_fallback", newObject("enabled", shell.Settings.Settings.UTLSFallback))
		}
	}
	movePaths(document, options.RuleSetDir)
	converted.Config, err = indented(document)
	if err != nil {
		return nil, err
	}
	return converted, nil
}

// shellRuleSetDir is where the shell backend keeps the rule-set files it makes.
const shellRuleSetDir = "/tmp/sing-box/rulesets"

// movePaths takes the paths of the shell backend's files to the backend's own directories
// (item 8): the rule-set files it makes and the cache file of sing-box.
func movePaths(document *object, ruleSetDir string) {
	if route, _ := document.get("route"); route != nil {
		if routeObject, isObject := route.(*object); isObject {
			ruleSets, _ := routeObject.get("rule_set")
			list, _ := ruleSets.([]any)
			for _, entry := range list {
				ruleSet, isObject := entry.(*object)
				if !isObject {
					continue
				}
				path, _ := ruleSet.get("path")
				if text, isText := path.(string); isText {
					if rest, found := strings.CutPrefix(text, shellRuleSetDir+"/"); found {
						ruleSet.set("path", ruleSetDir+"/"+rest)
					}
				}
			}
		}
	}
	if experimental, _ := document.get("experimental"); experimental != nil {
		if experimentalObject, isObject := experimental.(*object); isObject {
			if cacheFile, _ := experimentalObject.get("cache_file"); cacheFile != nil {
				if cacheObject, isObject := cacheFile.(*object); isObject {
					path, _ := cacheObject.get("path")
					if text, isText := path.(string); isText {
						cacheObject.set("path", model.CachePath(text))
					}
				}
			}
		}
	}
}

// shellRemoteTags are the tags the shell backend gives the remote lists of a section and
// kind, in their order: a list is a rule set file when the text after the last dot of the
// URL is "json" or "srs" exactly, query and all; the others go into one file of the
// section and kind, which is told too.
func shellRemoteTags(section string, kind string, locations []string) ([]string, bool) {
	var tags []string
	plain := false
	for _, location := range locations {
		fileName := location[strings.LastIndexByte(location, '/')+1:]
		var extension string
		if dot := strings.LastIndexByte(fileName, '.'); dot >= 0 {
			extension = fileName[dot+1:]
		}
		if extension == "json" || extension == "srs" {
			baseName, _, _ := strings.Cut(fileName, ".")
			tags = append(tags, ruleSetTag(section, baseName, "remote-"+kind))
			continue
		}
		if !plain {
			plain = true
			tags = append(tags, ruleSetTag(section, "remote", kind))
		}
	}
	return tags, plain
}

func usableLocalList(entry listEntry, options Options) bool {
	if options.ReadFile == nil {
		return false
	}
	content, err := options.ReadFile(entry.location)
	if err != nil {
		return false
	}
	if options.CheckList == nil {
		return true
	}
	_, _, err = options.CheckList(entry.format, content)
	return err == nil
}

func localPathOf(path string, options Options) string {
	if options.LocalPath == nil {
		return path
	}
	return options.LocalPath(path)
}

// removeServiceProxy removes the proxy inbound of the shell backend's downloads, told by
// its port (a section named "service" has a mixed inbound of that tag too), and the
// route rule of it.
func removeServiceProxy(document *object) {
	inbounds, _ := document.get("inbounds")
	list, _ := inbounds.([]any)
	removed := false
	kept := list[:0:0]
	for _, entry := range list {
		if inbound, isObject := entry.(*object); isObject {
			tag, _ := inbound.get("tag")
			port, _ := inbound.get("listen_port")
			if tag == "service-mixed-in" && fmt.Sprint(port) == "4534" {
				removed = true
				continue
			}
		}
		kept = append(kept, entry)
	}
	if !removed {
		return
	}
	document.set("inbounds", kept)
	route, _ := document.get("route")
	routeObject, _ := route.(*object)
	if routeObject == nil {
		return
	}
	rules, _ := routeObject.get("rules")
	ruleList, _ := rules.([]any)
	keptRules := ruleList[:0:0]
	for _, entry := range ruleList {
		if rule, isObject := entry.(*object); isObject {
			if inbound, _ := rule.get("inbound"); inbound == "service-mixed-in" {
				continue
			}
		}
		keptRules = append(keptRules, entry)
	}
	routeObject.set("rules", keptRules)
}

// shellCheckNames are the names of the checks of podkop 0.7's page (item 9).
var shellCheckNames = []string{"fakeip.podkop.fyi", "ip.podkop.fyi"}

// textList returns a list of texts, nil for anything else.
func textList(value any) []string {
	list, _ := value.([]any)
	var texts []string
	for _, item := range list {
		text, isText := item.(string)
		if !isText {
			return nil
		}
		texts = append(texts, text)
	}
	return texts
}

// replaceCheckNames removes the route rules of the names of the checks of podkop 0.7's
// page, and has their DNS rule answer the readiness name (item 9).
func replaceCheckNames(document *object) {
	if dns, _ := document.get("dns"); dns != nil {
		if dnsObject, isObject := dns.(*object); isObject {
			rules, _ := dnsObject.get("rules")
			list, _ := rules.([]any)
			for _, entry := range list {
				if rule, isObject := entry.(*object); isObject {
					if domains, _ := rule.get("domain"); slices.Equal(textList(domains), shellCheckNames) {
						rule.set("domain", []any{dataplane.ReadinessName})
					}
				}
			}
		}
	}
	route, _ := document.get("route")
	routeObject, _ := route.(*object)
	if routeObject == nil {
		return
	}
	rules, _ := routeObject.get("rules")
	list, isList := rules.([]any)
	if !isList {
		return
	}
	kept := list[:0:0]
	for _, entry := range list {
		if rule, isObject := entry.(*object); isObject {
			if domain, _ := rule.get("domain"); slices.Contains(shellCheckNames, fmt.Sprint(domain)) {
				continue
			}
		}
		kept = append(kept, entry)
	}
	routeObject.set("rules", kept)
}

// replaceSpan puts entries in place of the rule sets of the tags, which stand one after
// another in the list.
func replaceSpan(list []any, tags []string, entries []any) ([]any, error) {
	if len(tags) == 0 {
		return list, nil
	}
	start := -1
	for index, entry := range list {
		if ruleSet, isObject := entry.(*object); isObject {
			if tag, _ := ruleSet.get("tag"); tag == tags[0] {
				start = index
				break
			}
		}
	}
	if start < 0 || start+len(tags) > len(list) {
		return nil, E.New("the rule sets ", strings.Join(tags, ", "), " are not in the configuration")
	}
	for offset, want := range tags {
		ruleSet, _ := list[start+offset].(*object)
		if ruleSet == nil {
			return nil, E.New("the rule sets ", strings.Join(tags, ", "), " do not stand together")
		}
		if tag, _ := ruleSet.get("tag"); tag != want {
			return nil, E.New("the rule sets ", strings.Join(tags, ", "), " do not stand together")
		}
	}
	result := append(append(append([]any{}, list[:start]...), entries...), list[start+len(tags):]...)
	return result, nil
}

// replaceReferences puts tags in place of others in the rule_set of the route and DNS
// rules: where the old ones stand one after another, a name alone when one is left, a
// list otherwise, as patch makes it.
func replaceReferences(document *object, oldTags []string, newTags []string) {
	if len(oldTags) == 0 {
		return
	}
	for _, key := range []string{"route", "dns"} {
		holder, _ := document.get(key)
		holderObject, _ := holder.(*object)
		if holderObject == nil {
			continue
		}
		rules, _ := holderObject.get("rules")
		ruleList, _ := rules.([]any)
		for _, entry := range ruleList {
			rule, isObject := entry.(*object)
			if !isObject {
				continue
			}
			value, found := rule.get("rule_set")
			if !found {
				continue
			}
			var current []any
			switch typed := value.(type) {
			case string:
				current = []any{typed}
			case []any:
				current = typed
			default:
				continue
			}
			start := -1
			for index := 0; index+len(oldTags) <= len(current); index++ {
				matches := true
				for offset, tag := range oldTags {
					if current[index+offset] != tag {
						matches = false
						break
					}
				}
				if matches {
					start = index
					break
				}
			}
			if start < 0 {
				continue
			}
			replaced := append(append(append([]any{}, current[:start]...), stringsToAny(newTags)...), current[start+len(oldTags):]...)
			if len(replaced) == 1 {
				rule.set("rule_set", replaced[0])
			} else {
				rule.set("rule_set", replaced)
			}
		}
	}
}
