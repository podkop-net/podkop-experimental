// Package plan turns the settings of the backend into a sing-box configuration and the
// rule-set files it names. It is a function of its input: nothing is read but the local
// list files the settings name, and nothing is written; the caller stores the result.
//
// The configuration is the one the shell backend of podkop 0.7 writes for the same
// settings, rule by rule and in the same order: route rules are matched in order, and
// the dashboard finds outbounds by their tags.
package plan

import (
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	tagDirectOutbound     = "direct-out"
	tagBlockOutbound      = "block" // no "-out": the outbound of a section is "<name>-out", and a section may be named block
	tagListsHTTPClient    = "lists"
	tagTProxyInbound      = "tproxy-in"
	tagDNSInbound         = "dns-in"
	tagDNSServer          = "dns-server"
	tagBootstrapDNSServer = "bootstrap-dns-server"
	tagFakeIPServer       = "fakeip-server"

	urlCommunityLists = "https://github.com/itdoginfo/allow-domains/releases/latest/download"
	// DefaultRuleSetDir is where the backend keeps the rule-set files it makes (the
	// shell backend: /tmp/sing-box/rulesets).
	DefaultRuleSetDir    = dataplane.RunDir + "/rulesets"
	versionSourceRuleSet = 3
	versionUDPOverTCP    = 2
)

// communityLists are the names of the community lists, as the shell backend of podkop
// 0.7.24 knows them (COMMUNITY_SERVICES of its constants.sh): it refuses any other name.
var communityLists = []string{
	"russia_inside", "russia_outside", "ukraine_inside", "geoblock", "block", "porn", "news", "anime", "youtube",
	"hdrezka", "tiktok", "google_ai", "google_play", "hodca", "discord", "meta", "twitter", "cloudflare",
	"cloudfront", "digitalocean", "hetzner", "ovh", "telegram", "roblox",
}

// What a caller that runs the configuration has to know of it besides the values of
// dataplane.
const (
	// TProxyInboundTag is the inbound the traffic the firewall marks comes in through.
	TProxyInboundTag = tagTProxyInbound
	// DirectOutboundTag is the outbound of what goes without a proxy.
	DirectOutboundTag = tagDirectOutbound
	// BlockOutboundTag is the outbound a section of the type group whose group has no server
	// refuses its connections with.
	BlockOutboundTag = tagBlockOutbound
)

// Facts is what the builder needs to know of the router besides the settings.
type Facts struct {
	// LANAddress is the IPv4 address of the interface "lan" as netifd reports it, or
	// empty when there is none: the address the Clash API and the mixed proxies listen on.
	LANAddress string
	// Devices are the devices the interface names of the settings stand for now
	// (netcfg.Devices): the device of layer 3 of a logical interface of netifd for its
	// name ("wan": "pppoe-wan"), the same for a device of layer 2 under it. A name that is
	// not in it is used as it is.
	Devices map[string]string
	// NTPServerNames are the names of the NTP servers of the router's NTP service
	// (clock.ServerNames): sing-box answers them with their own addresses, never from FakeIP
	// (ledger item 16).
	NTPServerNames []string
}

// Options are the builder's ways to the outside.
type Options struct {
	// RuleSetDir is where the rule-set files the builder makes will be stored.
	RuleSetDir string
	// ReadFile reads a local list. os.ReadFile when nil.
	ReadFile func(path string) ([]byte, error)
	// CheckList tells whether sing-box takes the content of a local list in a format
	// (engine.CheckRuleSet), and how many lines of a list written as text it leaves out; when
	// nil, a local list that can be read is taken.
	CheckList func(format string, content []byte) (skipped int, first string, err error)
	// LocalPath is the path a local list has in the configuration; the path the settings
	// give when nil. A check of the configuration under a root of a test sets it.
	LocalPath func(path string) string
	// DecodeLink turns a proxy link into an outbound (a JSON object) and the warnings
	// about what the link asks for and the outbound cannot do. Whether sing-box builds the
	// outbound is for the check of the whole configuration (Result.Links).
	DecodeLink func(link string) (outbound []byte, warnings []string, err error)
	// CheckNames, with a suffix, adds what checks with made-up names need. The shell
	// backend has nothing of the kind: without a suffix the configuration is the one it
	// makes.
	CheckNames CheckNames
	// DownloadURL, when set, is the download test URL of the urltest groups whose section
	// leaves the test at its default. The shell backend leaves that to an environment
	// variable of the sing-box service: without it the configuration is the one it makes.
	DownloadURL string
	// ExternalUI is the directory the Clash API serves the dashboard YACD from (yacd.
	// ServedDir); none: "ui" of the working directory, as the shell backend has it.
	// NoExternalUI leaves the dashboard out: there is none to serve, and sing-box would
	// download one within its start (supervisor, yacd).
	ExternalUI   string
	NoExternalUI bool
	// Servers are the servers of the subscriptions by the name of the subscription, those
	// sing-box can use, in the order of the list of the provider; a subscription whose list
	// was never taken has none.
	Servers map[string][]SubscriptionServer
}

// CheckNames is a domain of names made up for checks: none of them exists, every one is
// answered from FakeIP, and a connection to one ends at a port of this host.
type CheckNames struct {
	// Suffix is the domain the names are under.
	Suffix string
	// DeadEndAddress and DeadEndPort are where the connections to the names are sent.
	DeadEndAddress string
	DeadEndPort    int
}

// Result is what a start of the backend writes.
type Result struct {
	// Config is the sing-box configuration.
	Config []byte
	// Files are the rule-set files the configuration names, by path.
	Files map[string][]byte
	// FileOrder is the paths of Files in the order they were made.
	FileOrder []string
	// Warnings are for the log: what was skipped or could not be honoured.
	Warnings []string
	// RuleSets are the rule sets of the configuration, in its order.
	RuleSets []RuleSet
	// Links are the proxy links the outbounds were decoded from, in the order of the
	// outbounds: a check of the configuration that sing-box refused builds them one by one
	// to name the one it cannot use.
	Links []Link
	// Dataplane is what the router needs around the configuration.
	Dataplane Dataplane
	// Facts are those the configuration was built of: a later look tells by them whether
	// the router has changed under it (the address of the LAN, the device a name stands for).
	Facts Facts
	// Swappable are the tags of the outbounds sing-box may replace while it runs: the servers
	// of the subscriptions, the URL tests of the groups and the selectors of the sections of
	// the type group. A configuration that differs from another only by these is applied
	// without a new sing-box.
	Swappable map[string]bool
	// Tags tell what the outbounds are, by the sections of the settings.
	Tags Tags
	// Legacy maps the tags the outbounds had while tags were made of the sections (v0.8.10
	// and before: "main-out", "src3: NL 1") to their tags of now: the cache file keeps the
	// choices of the dashboard by those (Adoptions).
	Legacy map[string]string
}

// legacyTags is Result.Legacy.
func (b *builder) legacyTags() map[string]string {
	legacy := make(map[string]string)
	for section, rule := range b.tags.Rules {
		legacy[section+"-out"] = rule.Selector
		if rule.Test != "" {
			legacy[section+"-urltest-out"] = rule.Test
		}
	}
	for tag, owner := range b.tags.Outbounds {
		switch {
		case owner.Rule != "" && owner.Fallback > 0:
			legacy[owner.Rule+"-fallback-"+strconv.Itoa(owner.Fallback)+"-out"] = tag
		case owner.Source != "":
			old := owner.Source
			if b.groups[tag] {
				old += "-best"
			} else if owner.Server != "" {
				old += ": " + owner.Server
			}
			if owner.Via != "" {
				old += " via " + owner.Via
			}
			legacy[old] = tag
		}
	}
	for old, now := range legacy {
		if old == now {
			delete(legacy, old)
		}
	}
	return legacy
}

// Adoptions are the choices of the dashboard the cache file keeps under tags the outbounds
// had before next: the selectors, old tag → new (the same when it did not change; a rule
// renamed, or the tags of the sections of v0.8.10 at the first start of this release), and the
// outbounds a choice may name, old tag → new. previous is the configuration that ran before,
// nil at a start.
func Adoptions(next *Result, previous *Result) (selectors map[string]string, members map[string]string) {
	selectors = make(map[string]string)
	members = make(map[string]string)
	if previous != nil {
		for section, rule := range next.Tags.Rules {
			if old := previous.Tags.Rules[section]; old.Selector != "" {
				selectors[old.Selector] = rule.Selector
				if old.Test != "" && rule.Test != "" && old.Test != rule.Test {
					members[old.Test] = rule.Test
				}
			}
		}
		// a server of the same source, server and way under another tag; a rule's selector
		// and URL test share their owner and are taken above
		owned := make(map[TagOf]string)
		shared := make(map[TagOf]bool)
		for tag, owner := range next.Tags.Outbounds {
			if owner.Rule != "" && owner.Fallback == 0 {
				continue
			}
			if _, seen := owned[owner]; seen {
				shared[owner] = true
			}
			owned[owner] = tag
		}
		for tag, owner := range previous.Tags.Outbounds {
			if now, found := owned[owner]; found && !shared[owner] && now != tag {
				members[tag] = now
			}
		}
	}
	for old, now := range next.Legacy {
		if _, taken := members[old]; !taken {
			members[old] = now
		}
	}
	// the selector of a rule under the tag of v0.8.10, which may be its tag of now (a rule
	// without a label): its choice may name a server by its old tag
	for section, rule := range next.Tags.Rules {
		if _, taken := selectors[section+"-out"]; !taken {
			selectors[section+"-out"] = rule.Selector
		}
	}
	return selectors, members
}

// Tags tell the user interface what the outbounds of a configuration are, by the section names
// the settings refer by: the tags are made of the names of the rules and the sources
// (model.Names), which a label changes, and are not to be taken apart.
type Tags struct {
	// Rules are the outbounds of each rule that goes through servers, by its section.
	Rules map[string]RuleTags `json:"rules"`
	// Outbounds tell what the outbound of each tag of a server or a group is.
	Outbounds map[string]TagOf `json:"outbounds"`
}

// RuleTags are the outbounds of a rule.
type RuleTags struct {
	// Name is the name of the rule in the tags.
	Name string `json:"name"`
	// Selector is the outbound its route rule goes to; Test the URL test of its servers, ""
	// for a rule of one server.
	Selector string `json:"selector"`
	Test     string `json:"test,omitempty"`
}

// TagOf is what an outbound is: a group of a rule, a server of a source, or the URL test of the
// servers of a source that rows connect through.
type TagOf struct {
	// Rule is the rule of a selector or a URL test; Fallback the fallback row (from 1) a URL
	// test is of.
	Rule     string `json:"rule,omitempty"`
	Fallback int    `json:"fallback,omitempty"`
	// Source is the source of a server, or of the URL test of its servers.
	Source string `json:"source,omitempty"`
	// Server is the name of the server in its source as the tag has it (a name the list has
	// more than once numbered); "" for a source of one server.
	Server string `json:"server,omitempty"`
	// Via is the source the server connects through.
	Via string `json:"via,omitempty"`
}

// Dataplane is what the router needs around a configuration, made of the settings: the
// rules of the firewall (its sets come from what the rule sets hold), whether the resolver
// of the LAN asks the DNS inbound, where the Clash API is reached. The values that do not
// depend on the settings are those of dataplane.
type Dataplane struct {
	// Interfaces are the interfaces the firewall takes traffic from: those the settings
	// name, br-lan when they name none.
	Interfaces []string
	// ExcludeNTP leaves UDP port 123 alone.
	ExcludeNTP bool
	// Sources are the devices of the LAN routed whole (fully_routed_ips), IPv4.
	Sources []netip.Prefix
	// TakeDNS tells that the resolver of the LAN is pointed at the DNS inbound; off with
	// dont_touch_dhcp, and then a resolver the backend took is given back.
	TakeDNS bool
	// ClashAPI is where the Clash API of the configuration is reached from the router
	// (host:port: an API open on every address is asked on this host), and ClashSecret
	// its key; the commands of the user interface ask it.
	ClashAPI    string
	ClashSecret string
	// ClashAPIInterfaces are the devices the firewall lets reach the Clash API, which
	// listens on every address with YACD on (firewall.Plan.ClashAPIInterfaces): those of
	// yacd_interfaces, or Interfaces. None with YACD off.
	ClashAPIInterfaces []string
}

// defaultInterface is the interface the firewall takes traffic from when the settings
// name none: the bridge of the LAN of OpenWrt.
const defaultInterface = "br-lan"

// InterfaceNames are the names of interfaces the settings use, each once: those of the LAN,
// of YACD, of the output and of the VPN sections. Facts.Devices is asked about them.
func InterfaceNames(config *model.Config) []string {
	settings := &config.Settings
	names := slices.Clone(settings.SourceNetworkInterfaces)
	if settings.EnableYACD {
		names = append(names, settings.YACDInterfaces...)
	}
	names = append(names, settings.OutputNetworkInterface)
	for index := range config.Sources {
		if config.Sources[index].Type == "interface" {
			names = append(names, config.Sources[index].Interface)
		}
	}
	result := names[:0]
	for _, name := range names {
		if name != "" && !slices.Contains(result, name) {
			result = append(result, name)
		}
	}
	return result
}

// device is the device an interface name of the settings stands for now (Facts.Devices).
func (b *builder) device(name string) string {
	if device := b.facts.Devices[name]; device != "" {
		return device
	}
	return name
}

func (b *builder) devices(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	result := make([]string, 0, len(names))
	for _, name := range names {
		device := b.device(name)
		if !slices.Contains(result, device) {
			result = append(result, device)
		}
	}
	return result
}

func (b *builder) dataplane() Dataplane {
	settings := &b.config.Settings
	result := Dataplane{Interfaces: b.devices(settings.SourceNetworkInterfaces), ExcludeNTP: settings.ExcludeNTP, TakeDNS: !settings.DontTouchDHCP, ClashAPI: b.clashAPI, ClashSecret: b.clashSecret}
	if len(result.Interfaces) == 0 {
		result.Interfaces = []string{defaultInterface}
	}
	if settings.EnableYACD {
		result.ClashAPIInterfaces = b.devices(settings.YACDInterfaces)
		if len(result.ClashAPIInterfaces) == 0 {
			result.ClashAPIInterfaces = result.Interfaces
		}
	}
	for index := range b.config.Sections {
		for _, text := range b.config.Sections[index].FullyRoutedIPs {
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				address, addressErr := netip.ParseAddr(text)
				if addressErr != nil {
					continue
				}
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
			if prefix.Addr().Is4() {
				result.Sources = append(result.Sources, prefix.Masked())
			}
		}
	}
	if host, port, err := net.SplitHostPort(result.ClashAPI); err == nil {
		if address, err := netip.ParseAddr(host); err == nil && address.IsUnspecified() {
			result.ClashAPI = net.JoinHostPort("127.0.0.1", port)
		}
	}
	return result
}

// Link is a proxy link of the settings and the outbound it became.
type Link struct {
	// Section is the section of the settings the link is in.
	Section string
	// Name is the name of the outbound: the section's, or with the number of the link in
	// a group ("main-2", "main-fallback-1"); the tag of a server of a subscription.
	Name string
	// Tag is the tag of the outbound.
	Tag string
	// Text is the link as the settings hold it, a secret.
	Text string
}

// RuleSet names a rule set of the configuration for the code that reads its content.
type RuleSet struct {
	Tag string
	// Path is the file of a rule set the backend writes; empty for one sing-box downloads.
	Path string
	// URL is where sing-box downloads a rule set from; empty for a file.
	URL string
	// Format is the format of a downloaded rule set: binary, source or text.
	Format string
}

type builder struct {
	config  *model.Config
	facts   Facts
	options Options

	inbounds   []any
	outbounds  []any
	dnsServers []any
	dnsRules   []*rule
	routeRules []*rule
	ruleSets   []any
	// remoteRuleSets tells that sing-box downloads some of them
	remoteRuleSets bool
	experimental   *object

	files     map[string]*object
	fileOrder []string
	warnings  []string
	links     []Link

	clashAPI    string
	clashSecret string

	// the DNS rule that sends the names of the lists to FakeIP
	fakeIPRule *rule

	// what the rules were given (exits.go): the tags of the servers of each subscription,
	// the outbounds of the servers decoded so far, the servers of each source, the servers
	// and the URL tests made, what sing-box may replace while it runs, and the rules whose
	// connections are refused for want of a server
	subscriptionTags map[string][]string
	decoded          map[string]*object
	sourceCache      map[string][]sourceServer
	servers          map[string]bool
	groups           map[string]bool
	swappable        map[string]bool
	refused          map[string]bool

	// the names of the rules and the sources the tags are made of; the owner of each tag and
	// the tag of each owner (claim); what the tags are, for the user interface
	names  model.Names
	owners map[string]string
	tagOf  map[string]string
	tags   Tags
	// the outbounds of outbound JSONs, which may name others (renameOldTags)
	jsonOutbounds []*object
}

// rule is a route or a DNS rule while it is built: later steps find it by its name to add
// conditions to it. The name is not written.
type rule struct {
	name   string
	fields *object
}

// Build makes the configuration.
func Build(config *model.Config, facts Facts, options Options) (*Result, error) {
	if options.RuleSetDir == "" {
		options.RuleSetDir = DefaultRuleSetDir
	}
	if options.ReadFile == nil {
		options.ReadFile = os.ReadFile
	}
	if options.DecodeLink == nil {
		return nil, E.New("no decoder of proxy links")
	}
	b := &builder{config: config, facts: facts, options: options, experimental: new(object), files: make(map[string]*object),
		subscriptionTags: make(map[string][]string), decoded: make(map[string]*object), sourceCache: make(map[string][]sourceServer), servers: make(map[string]bool), groups: make(map[string]bool),
		swappable: make(map[string]bool), refused: make(map[string]bool),
		names: config.Names(), owners: make(map[string]string), tagOf: make(map[string]string),
		tags: Tags{Rules: make(map[string]RuleTags), Outbounds: make(map[string]TagOf)}}
	b.claimRuleTags()
	b.buildInbounds()
	err := b.buildOutbounds()
	if err != nil {
		return nil, err
	}
	dns, err := b.buildDNS()
	if err != nil {
		return nil, err
	}
	route, err := b.buildRoute()
	if err != nil {
		return nil, err
	}
	b.buildExperimental()
	err = b.buildAdditionalInbounds()
	if err != nil {
		return nil, err
	}

	// a DNS rule that sends to a server and was given no condition would take every query
	var dnsRules []any
	for _, entry := range b.dnsRules {
		action, _ := entry.fields.get("action")
		if action == "route" && onlyKeys(entry.fields, "action", "server", "rewrite_ttl") {
			continue
		}
		dnsRules = append(dnsRules, entry.fields)
	}
	dns.set("rules", listOrEmpty(dnsRules))
	var routeRules []any
	for _, entry := range b.routeRules {
		routeRules = append(routeRules, entry.fields)
	}
	route.set("rules", listOrEmpty(routeRules))
	route.set("rule_set", listOrEmpty(b.ruleSets))

	document := newObject(
		"log", newObject("disabled", false, "level", config.Settings.LogLevel, "timestamp", false),
		"dns", dns,
		"ntp", new(object),
		"certificate", new(object),
	)
	if b.remoteRuleSets {
		document.set("http_clients", []any{b.listsHTTPClient()})
		route.set("default_http_client", tagListsHTTPClient)
	}
	document.append(
		"endpoints", []any{},
		"inbounds", listOrEmpty(b.inbounds),
		"outbounds", listOrEmpty(b.outbounds),
		"route", route,
		"services", []any{},
		"experimental", b.experimental,
	)
	content, err := indented(document)
	if err != nil {
		return nil, E.Cause(err, "encode the configuration")
	}
	result := &Result{Config: content, Files: make(map[string][]byte), FileOrder: b.fileOrder, Warnings: b.warnings, Links: b.links, Dataplane: b.dataplane(), Facts: b.facts,
		Swappable: b.swappable, Tags: b.tags, Legacy: b.legacyTags()}
	for _, entry := range b.ruleSets {
		fields := entry.(*object)
		tag, _ := fields.get("tag")
		path, _ := fields.get("path")
		format, _ := fields.get("format")
		address, _ := fields.get("url")
		info := RuleSet{Tag: tag.(string), Format: format.(string)}
		if path != nil {
			info.Path = path.(string)
		}
		if address != nil {
			info.URL = address.(string)
		}
		result.RuleSets = append(result.RuleSets, info)
	}
	for path, file := range b.files {
		result.Files[path], err = indented(file)
		if err != nil {
			return nil, E.Cause(err, "encode the rule-set ", path)
		}
	}
	return result, nil
}

func (b *builder) warn(message ...any) {
	b.warnings = append(b.warnings, E.New(message...).Error())
}

func (b *builder) buildInbounds() {
	b.inbounds = append(b.inbounds,
		newObject("type", "tproxy", "tag", tagTProxyInbound, "listen", dataplane.TProxyAddress, "listen_port", dataplane.TProxyPort, "tcp_fast_open", true, "udp_fragment", true),
		newObject("type", "direct", "tag", tagDNSInbound, "listen", dataplane.DNSAddress, "listen_port", dataplane.DNSPort),
	)
}

// ruleTag is the tag of an outbound of a rule of the name: its selector (kind ""), the URL
// test of its servers ("urltest") or of a fallback row of several servers ("fallback-N").
func ruleTag(name string, kind string) string {
	if kind == "" {
		return name + "-out"
	}
	return name + "-" + kind + "-out"
}

// RuleOutbound is the tag of the selector of a rule, which its route rule goes to.
func RuleOutbound(config *model.Config, section string) string {
	return ruleTag(config.Names().Rule(section), "")
}

// ruleOutbound is the tag of the selector of a rule.
func (b *builder) ruleOutbound(section string) string {
	return b.claim(ruleTag(b.names.Rule(section), ""), "rule\x00"+section)
}

// claimRuleTags gives the outbounds of the rules their tags before any other: the tags of
// the rules are a matter of the settings alone (RuleOutbound), and a source of the same name
// yields.
func (b *builder) claimRuleTags() {
	b.claim(tagDirectOutbound, "podkop\x00direct")
	b.claim(tagBlockOutbound, "podkop\x00block")
	for index := range b.config.Sections {
		section := &b.config.Sections[index]
		name := b.names.Rule(section.Name)
		b.ruleOutbound(section.Name)
		b.claim(ruleTag(name, "urltest"), "rule\x00"+section.Name+"\x00urltest")
		for row := range section.Fallbacks {
			kind := "fallback-" + strconv.Itoa(row+1)
			b.claim(ruleTag(name, kind), "rule\x00"+section.Name+"\x00"+kind)
		}
	}
}

// claim gives the owner the tag, or the tag numbered when another owner has it: two outbounds
// of one tag would be taken for one (addServer puts a tag in once). An owner keeps the tag it
// got first.
func (b *builder) claim(tag string, owner string) string {
	if got, found := b.tagOf[owner]; found {
		return got
	}
	candidate := tag
	for number := 2; b.owners[candidate] != ""; number++ {
		candidate = tag + " #" + strconv.Itoa(number)
	}
	b.owners[candidate] = owner
	b.tagOf[owner] = candidate
	return candidate
}

func (b *builder) buildOutbounds() error {
	if err := b.buildExits(); err != nil {
		return err
	}
	b.renameOldTags()
	return nil
}

// dnsServer makes a DNS server of the settings "type" and "host[:port][/path]".
func dnsServer(serverType string, tag string, server string, resolver string, detour string) (*object, error) {
	host, portText, path := splitServer(server)
	var transport string
	var defaultPort int
	switch serverType {
	case "udp":
		transport, defaultPort = "udp", 53
	case "dot":
		transport, defaultPort = "tls", 853
	case "doh":
		transport, defaultPort = "https", 443
	default:
		return nil, E.New("unsupported DNS server type \"", serverType, "\"")
	}
	port := defaultPort
	if portText != "" {
		var err error
		port, err = strconv.Atoi(portText)
		if err != nil {
			return nil, E.New("the port of the DNS server ", server, " is not a number")
		}
	}
	result := newObject("type", transport, "tag", tag, "server", host, "server_port", port)
	if transport == "https" && path != "" {
		result.set("path", path)
	}
	if detour != "" {
		result.set("detour", detour)
	}
	if resolver != "" {
		result.set("domain_resolver", resolver)
	}
	return result, nil
}

// SplitServer takes the setting of a DNS server apart: the host, the port and the path,
// each empty when the setting has none.
func SplitServer(server string) (host string, port string, path string) {
	return splitServer(server)
}

// splitServer takes "scheme://user@host:port/path?query" apart the way the shell backend
// does: the host ends at the first colon, the path at the first question mark.
func splitServer(server string) (host string, port string, path string) {
	rest := server
	if _, after, found := strings.Cut(rest, "://"); found {
		rest = after
	}
	authority := rest
	if _, after, found := strings.Cut(authority, "@"); found {
		authority = after
	}
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	host, port, _ = strings.Cut(authority, ":")
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		path = rest[slash:]
		if question := strings.IndexByte(path, '?'); question >= 0 {
			path = path[:question]
		}
	}
	return
}

// upstreamServer makes the DNS server of a row of the list: the servers of the internet
// provider (podkop-engine's "provider", the servers netifd knows), or a server of its own,
// whose name the bootstrap server resolves.
func upstreamServer(upstream model.DNSUpstream, tag string) (*object, error) {
	if upstream.Type == model.DNSTypeProvider {
		return newObject("type", "provider", "tag", tag), nil
	}
	host, _, _ := splitServer(upstream.Server)
	if host == "" {
		return nil, E.New("a DNS server of the list has no address")
	}
	var resolver string
	if !model.IsIPv4(host) {
		resolver = tagBootstrapDNSServer
	}
	return dnsServer(upstream.Type, tag, upstream.Server, resolver, "")
}

// buildDNSServers puts in the DNS servers of the list under the tag every rule goes to: the one
// server itself, or podkop-engine's group of the servers "dns-server-N", asked in their order
// or the fastest first. A row given twice is used once.
func (b *builder) buildDNSServers() error {
	settings := &b.config.Settings
	if settings.EmptyDNSRows > 0 {
		b.warnOnce(settings.EmptyDNSRows, " row(s) of the DNS server list have neither a type nor an address (added on the page and never filled in): left out")
	}
	var upstreams []model.DNSUpstream
	for _, upstream := range settings.DNSUpstreams {
		if slices.Contains(upstreams, upstream) {
			b.warnOnce("the DNS server ", upstream.Type, " ", upstream.Server, " is in the list twice: it is asked once")
			continue
		}
		upstreams = append(upstreams, upstream)
	}
	if len(upstreams) == 1 {
		server, err := upstreamServer(upstreams[0], tagDNSServer)
		if err != nil {
			return err
		}
		b.dnsServers = append(b.dnsServers, server)
		return nil
	}
	strategy := settings.DNSMode
	if strategy != model.DNSModeFastest {
		strategy = model.DNSModeOrder
	}
	var members []string
	for index, upstream := range upstreams {
		tag := tagDNSServer + "-" + strconv.Itoa(index+1)
		server, err := upstreamServer(upstream, tag)
		if err != nil {
			return E.Cause(err, "DNS server ", index+1)
		}
		b.dnsServers = append(b.dnsServers, server)
		members = append(members, tag)
	}
	b.dnsServers = append(b.dnsServers, newObject("type", "group", "tag", tagDNSServer, "servers", stringsToAny(members), "strategy", strategy))
	return nil
}

func (b *builder) buildDNS() (*object, error) {
	settings := &b.config.Settings
	b.dnsServers = append(b.dnsServers, newObject("type", "udp", "tag", tagBootstrapDNSServer, "server", settings.BootstrapDNSServer, "server_port", 53))
	if err := b.buildDNSServers(); err != nil {
		return nil, err
	}
	b.dnsServers = append(b.dnsServers, newObject("type", "fakeip", "tag", tagFakeIPServer, "inet4_range", dataplane.FakeIPRange))

	ttl := argument(settings.DNSRewriteTTL)
	b.fakeIPRule = &rule{fields: newObject("action", "route", "server", tagFakeIPServer, "rewrite_ttl", ttl)}
	b.dnsRules = append(b.dnsRules,
		&rule{fields: newObject("action", "reject", "query_type", "HTTPS")},
		&rule{fields: newObject("action", "reject", "domain_suffix", "use-application-dns.net")},
	)
	if names := b.facts.NTPServerNames; len(names) > 0 {
		// the NTP of the router goes past the proxy (firewall): a name of a list would have
		// it sent to a FakeIP address, and through the proxy, which the clock may break
		b.dnsRules = append(b.dnsRules, &rule{fields: newObject("action", "route", "server", tagDNSServer, "domain", stringsToAny(names))})
	}
	b.dnsRules = append(b.dnsRules,
		b.fakeIPRule,
		// The name the backend checks itself with has a rule apart from the lists: since
		// sing-box 1.14 a rule set of several rules next to "domain" matches only together
		// with it. The supervisor tells by it that sing-box is up
		// (dataplane.ReadinessName), with check names or without them.
		&rule{fields: newObject("action", "route", "server", tagFakeIPServer, "rewrite_ttl", ttl, "domain", []any{dataplane.ReadinessName})},
	)
	if suffix := b.options.CheckNames.Suffix; suffix != "" {
		b.dnsRules = append(b.dnsRules, &rule{fields: newObject("action", "route", "server", tagFakeIPServer, "rewrite_ttl", ttl, "domain_suffix", suffix)})
	}
	// IPv4 only, as FakeIP and the firewall are; a name without an IPv4 address gets its
	// IPv6 addresses, which go past the proxy (ledger item 15)
	return newObject("servers", listOrEmpty(b.dnsServers), "rules", nil, "final", tagDNSServer, "strategy", "ipv4_only", "ipv6_if_no_ipv4", true), nil
}

func (b *builder) addRouteRule(name string, fields *object) *rule {
	entry := &rule{name: name, fields: fields}
	b.routeRules = append(b.routeRules, entry)
	return entry
}

func (b *builder) routeRule(name string) *rule {
	for _, entry := range b.routeRules {
		if entry.name != "" && entry.name == name {
			return entry
		}
	}
	return nil
}

func (b *builder) buildRoute() (*object, error) {
	settings := &b.config.Settings
	// What sing-box opens goes where the routing of the router sends it (mwan3, a route
	// of a host, a tunnel's included), with the mark that keeps it out of the proxy
	// (ledger item 11). The interface of the settings binds it.
	route := newObject("rules", nil, "rule_set", nil, "final", tagDirectOutbound,
		"default_mark", dataplane.OutboundMark, "default_domain_resolver", tagDNSServer)
	if settings.OutputNetworkInterface != "" {
		route.set("default_interface", b.device(settings.OutputNetworkInterface))
	}

	b.addRouteRule("", newObject("action", "sniff", "inbound", []any{tagTProxyInbound, tagDNSInbound}))
	b.addRouteRule("", newObject("action", "hijack-dns", "protocol", "dns"))
	if settings.DisableQUIC {
		b.addRouteRule("", newObject("action", "reject", "inbound", tagTProxyInbound, "protocol", "quic"))
	}
	if names := b.options.CheckNames; names.Suffix != "" {
		// Before every rule of a section and of a proxy inbound: a connection to a check
		// name ends on this host whatever the lists say and whichever way it came in. It is
		// routed, not rejected: a connection tracker sees only what is routed. The second
		// rule goes by the address the first one has put in place of the name: by then the
		// name is known only where it was sniffed.
		b.addRouteRule("", newObject("action", "route-options", "domain_suffix", names.Suffix, "override_address", names.DeadEndAddress, "override_port", names.DeadEndPort))
		b.addRouteRule("", newObject("action", "route", "ip_cidr", names.DeadEndAddress, "port", names.DeadEndPort, "outbound", tagDirectOutbound))
	}

	// The rules of direct and block at the top go before the devices left out and the devices
	// routed whole, as the block and exclusion sections of 0.8 did (the conversion puts those
	// sections first): a bank stays direct and ads stay blocked for every device. Below them
	// the order of the rules decides for the lists only.
	lead := 0
	for lead < len(b.config.Sections) {
		section := &b.config.Sections[lead]
		if exit := b.config.Exit(section); section.Enabled && exit != model.ExitDirect && exit != model.ExitBlock {
			break
		}
		lead++
	}
	for index := range lead {
		err := b.buildSectionLists(&b.config.Sections[index])
		if err != nil {
			return nil, E.Cause(err, "section ", b.config.Sections[index].Name)
		}
	}
	if len(settings.RoutingExcludedIPs) > 0 {
		entry := b.addRouteRule("", newObject("action", "route", "inbound", tagTProxyInbound, "outbound", tagDirectOutbound))
		for _, address := range settings.RoutingExcludedIPs {
			patch(entry.fields, "source_ip_cidr", argument(address))
		}
	}
	for index := range b.config.Sections {
		section := &b.config.Sections[index]
		if len(section.FullyRoutedIPs) == 0 || !b.routes(section) {
			continue
		}
		entry := b.addRouteRule("", b.sectionRoute(section, tagTProxyInbound))
		for _, address := range section.FullyRoutedIPs {
			patch(entry.fields, "source_ip_cidr", argument(address))
		}
	}
	for index := lead; index < len(b.config.Sections); index++ {
		err := b.buildSectionLists(&b.config.Sections[index])
		if err != nil {
			return nil, E.Cause(err, "section ", b.config.Sections[index].Name)
		}
	}
	return route, nil
}

// routes tells whether a rule has route rules: it is on and goes somewhere.
func (b *builder) routes(section *model.Section) bool {
	return section.Enabled && b.config.Exit(section) != model.ExitNone
}

func (b *builder) buildExperimental() {
	settings := &b.config.Settings
	b.experimental.set("cache_file", newObject("enabled", true, "path", settings.CachePath, "store_fakeip", true))
	// The Clash API is for the router itself (the commands of the page ask it on this host)
	// unless YACD is on: then it listens on every address, and the firewall lets in only
	// the devices of YACD (Dataplane.ClashAPIInterfaces). The address of the LAN it used to
	// follow is not known at a start before the LAN has one, nor is it that of every device.
	address := "127.0.0.1"
	if settings.EnableYACD {
		address = "0.0.0.0"
	}
	b.clashAPI = address + ":" + strconv.Itoa(dataplane.ClashAPIPort)
	clashAPI := newObject("external_controller", b.clashAPI)
	if settings.EnableYACD && !b.options.NoExternalUI {
		clashAPI.set("external_ui", cmp.Or(b.options.ExternalUI, "ui"))
	}
	// the API has the key of the settings whether YACD is on or not: a device of the LAN
	// that has no key reads no connection and switches no outbound. The backend makes a
	// key when the settings have none (supervisor); the page sends it as the token.
	if settings.YACDSecretKey != "" {
		clashAPI.set("secret", settings.YACDSecretKey)
		b.clashSecret = settings.YACDSecretKey
	}
	b.experimental.set("clash_api", clashAPI)
	// the fallback is told either way: the environment of the engine
	// (SING_BOX_UTLS_FALLBACK) is not read then
	b.experimental.set("utls_fallback", newObject("enabled", settings.UTLSFallback))
}

// listenAddress is where the services for the LAN listen: what the settings say, or the
// address of the LAN.
func (b *builder) listenAddress() string {
	if b.config.Settings.ServiceListenAddress != "" {
		return b.config.Settings.ServiceListenAddress
	}
	return b.facts.LANAddress
}

func (b *builder) buildAdditionalInbounds() error {
	address := b.listenAddress()
	if address == "" {
		for index := range b.config.Sections {
			if b.config.Sections[index].MixedProxyEnabled {
				b.warn("the address for the mixed proxy of ", b.config.Sections[index].Name, " is not known: it is not created")
			}
		}
		return nil
	}
	ports := make(map[string]string)
	for index := range b.config.Sections {
		section := &b.config.Sections[index]
		if !section.MixedProxyEnabled || !b.routes(section) {
			continue
		}
		port := argument(section.MixedProxyPort)
		if _, isText := port.(string); isText {
			return E.New("rule ", b.names.RuleText(section.Name), ": the port of the mixed proxy is not a number")
		}
		// sing-box would fail to start on the second socket, and so would every try again
		if other, taken := ports[fmt.Sprint(port)]; taken {
			return E.New("rules ", other, " and ", b.names.RuleText(section.Name), ": the mixed proxies have the same port ", port)
		}
		ports[fmt.Sprint(port)] = b.names.RuleText(section.Name)
		tag := b.names.Rule(section.Name) + "-mixed-in"
		b.inbounds = append(b.inbounds, newObject("type", "mixed", "tag", tag, "listen", address, "listen_port", port))
		b.addRouteRule("", b.sectionRoute(section, tag))
	}
	return nil
}

func onlyKeys(fields *object, allowed ...string) bool {
	for _, key := range fields.keys() {
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func listOrEmpty(items []any) []any {
	if items == nil {
		return []any{}
	}
	return items
}
