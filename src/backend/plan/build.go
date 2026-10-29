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
	for index := range config.Sections {
		if config.Sections[index].ConnectionType == "vpn" {
			names = append(names, config.Sections[index].Interface)
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

	// detours are the sections the servers of a proxy section are reached through, by the
	// name of the section (checkDetours)
	detours map[string]string

	// what the sections of the type group were given (groups.go): where each section goes,
	// the tags of the servers of each subscription, the outbounds of the servers decoded so
	// far, and the servers and the groups made
	exits            map[string]groupExit
	subscriptionTags map[string][]string
	decoded          map[string]*object
	servers          map[string]bool
	groups           map[string]bool
	swappable        map[string]bool
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
		exits: make(map[string]groupExit), subscriptionTags: make(map[string][]string), decoded: make(map[string]*object), servers: make(map[string]bool), groups: make(map[string]bool),
		swappable: make(map[string]bool)}
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
		Swappable: b.swappable}
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

func outboundTag(section string) string {
	return section + "-out"
}

func (b *builder) buildOutbounds() error {
	err := b.checkDetours()
	if err != nil {
		return err
	}
	b.outbounds = append(b.outbounds, newObject("type", "direct", "tag", tagDirectOutbound))
	// what a section of the type group whose group has no server refuses its connections
	// with: the selector of the section changes while sing-box runs, a rule does not. There
	// whenever a section is of the type group, so that it does not come and go with it.
	if slices.ContainsFunc(b.config.Sections, func(section model.Section) bool { return section.ConnectionType == "group" }) {
		b.outbounds = append(b.outbounds, newObject("type", "block", "tag", tagBlockOutbound))
	}
	for index := range b.config.Sections {
		section := &b.config.Sections[index]
		var err error
		switch section.ConnectionType {
		case "proxy":
			err = b.buildProxyOutbounds(section)
		case "vpn":
			err = b.buildInterfaceOutbound(section)
		case "group":
			err = b.buildGroupSection(section)
		case "block", "exclusion":
			// no outbound: such a section is a route rule
		default:
			err = E.New("unknown connection type \"", section.ConnectionType, "\"")
		}
		if err != nil {
			return E.Cause(err, "section ", section.Name)
		}
	}
	return nil
}

// checkDetours takes the section each proxy section connects through (its option detour):
// the servers of the section are reached through the outbound of that one, a proxy or a VPN
// section, a group of either kind included. A detour to a section that is not there, has no
// outbound or leads back round is refused here, in the words of the settings: sing-box would
// refuse the configuration in terms of outbounds.
func (b *builder) checkDetours() error {
	sections := make(map[string]*model.Section, len(b.config.Sections))
	for index := range b.config.Sections {
		sections[b.config.Sections[index].Name] = &b.config.Sections[index]
	}
	b.detours = make(map[string]string)
	for index := range b.config.Sections {
		section := &b.config.Sections[index]
		if section.Detour == "" {
			continue
		}
		if section.ConnectionType != "proxy" {
			b.warn("section ", section.Name, ": the connection through ", section.Detour, " is left out: only a proxy section connects through another")
			continue
		}
		target := sections[section.Detour]
		switch {
		case section.Detour == section.Name:
			return E.New("section ", section.Name, " connects through itself")
		case target == nil:
			return E.New("section ", section.Name, " connects through ", section.Detour, ", and there is no such section")
		case target.ConnectionType == "group":
			return E.New("section ", section.Name, " connects through ", section.Detour, ", a section of the type group: a group cannot be connected through yet")
		case target.ConnectionType != "proxy" && target.ConnectionType != "vpn":
			return E.New("section ", section.Name, " connects through ", section.Detour, ", a section of the type ", target.ConnectionType, " that has no outbound")
		}
		b.detours[section.Name] = section.Detour
	}
	for name := range b.detours {
		path := []string{name}
		for next := b.detours[name]; next != ""; next = b.detours[next] {
			if slices.Contains(path, next) {
				return E.New("section ", name, " connects round in a loop: ", strings.Join(append(path, next), " → "))
			}
			path = append(path, next)
		}
	}
	return nil
}

// isTransit tells whether another section connects through this one, or goes as it does
// when its group chooses no server.
func (b *builder) isTransit(name string) bool {
	for _, detour := range b.detours {
		if detour == name {
			return true
		}
	}
	for _, group := range b.config.Groups {
		if group.Empty == "section" && group.EmptySection == name {
			return true
		}
	}
	return false
}

// setDetour makes an outbound of a section reach its server through the section it connects
// through. tls.spoof needs the socket of its own connection: through a proxy it is refused at
// every connection (common/tls of the engine), so it is said once here.
func (b *builder) setDetour(section *model.Section, name string, outbound *object) {
	detour := b.detours[section.Name]
	if detour == "" {
		return
	}
	if _, has := outbound.get("detour"); !has {
		outbound.set("detour", outboundTag(detour))
	}
	value, _ := outbound.get("tls")
	tls, isObject := value.(*object)
	if !isObject {
		return
	}
	if spoof, _ := tls.get("spoof"); spoof == nil || spoof == "" {
		return
	}
	for _, other := range b.config.Sections {
		if other.Name == detour && other.ConnectionType == "proxy" {
			b.warn("proxy link of ", name, ": tls.spoof does not work through the proxy section ", detour, ": its connections will fail; it works through a VPN section")
		}
	}
}

func (b *builder) buildProxyOutbounds(section *model.Section) error {
	switch section.ProxyConfigType {
	case "url":
		if section.ProxyString == "" {
			return E.New("the proxy link is not set")
		}
		return b.addLinkOutbound(section, section.Name, section.ProxyString)
	case "outbound":
		// a byte order mark comes with text copied out of a file
		parsed, err := parseValue([]byte(strings.TrimPrefix(section.OutboundJSON, "\ufeff")))
		if err != nil {
			return E.Cause(err, "the outbound is not JSON")
		}
		outbound, isObject := parsed.(*object)
		if !isObject {
			return E.New("the outbound is not a JSON object")
		}
		outbound.set("tag", outboundTag(section.Name))
		if outboundType, _ := outbound.get("type"); b.detours[section.Name] != "" && (outboundType == "selector" || outboundType == "urltest") {
			// a group dials nothing itself: its members connect through another outbound
			return E.New("the outbound JSON is a ", outboundType, ", which connects through nothing: set detour in the outbounds it chooses from")
		}
		b.setDetour(section, section.Name, outbound)
		b.outbounds = append(b.outbounds, outbound)
	case "selector":
		if len(section.SelectorProxyLinks) == 0 {
			return E.New("the proxy links of the selector are not set")
		}
		var members []string
		for index, link := range section.SelectorProxyLinks {
			name := section.Name + "-" + strconv.Itoa(index+1)
			err := b.addLinkOutbound(section, name, link)
			if err != nil {
				return err
			}
			members = append(members, outboundTag(name))
		}
		b.outbounds = append(b.outbounds, newObject("type", "selector", "tag", outboundTag(section.Name), "outbounds", stringsToAny(members), "default", members[0]))
	case "urltest":
		if len(section.URLTestProxyLinks) == 0 {
			return E.New("the proxy links of the URL test are not set")
		}
		var members, fallbacks []string
		for index, link := range section.URLTestProxyLinks {
			name := section.Name + "-" + strconv.Itoa(index+1)
			err := b.addLinkOutbound(section, name, link)
			if err != nil {
				return err
			}
			members = append(members, outboundTag(name))
		}
		for index, link := range section.URLTestFallbackLinks {
			name := section.Name + "-fallback-" + strconv.Itoa(index+1)
			err := b.addLinkOutbound(section, name, link)
			if err != nil {
				return err
			}
			fallbacks = append(fallbacks, outboundTag(name))
		}
		tolerance, isNumber := numberOf(section.URLTestTolerance)
		if !isNumber {
			return E.New("the tolerance of the URL test is not a number")
		}
		groupTag := outboundTag(section.Name + "-urltest")
		group := newObject("type", "urltest", "tag", groupTag, "outbounds", stringsToAny(members),
			"url", section.URLTestTestingURL, "interval", section.URLTestCheckInterval, "tolerance", tolerance)
		if len(fallbacks) > 0 {
			group.set("fallbacks", stringsToAny(fallbacks))
		}
		switch {
		case section.URLTestDownloadCheck == "off":
			group.set("download_url", "")
		case section.URLTestDownloadCheck == "custom" && section.URLTestDownloadURL != "":
			group.set("download_url", section.URLTestDownloadURL)
		case b.options.DownloadURL != "":
			group.set("download_url", b.options.DownloadURL)
		}
		b.outbounds = append(b.outbounds, group)
		all := append(append(append([]string{}, members...), fallbacks...), groupTag)
		b.outbounds = append(b.outbounds, newObject("type", "selector", "tag", outboundTag(section.Name), "outbounds", stringsToAny(all), "default", groupTag))
	default:
		return E.New("unknown proxy configuration type \"", section.ProxyConfigType, "\"")
	}
	return nil
}

// addLinkOutbound decodes a link into the outbound of the given name.
func (b *builder) addLinkOutbound(section *model.Section, name string, link string) error {
	content, warnings, err := b.options.DecodeLink(link)
	if err != nil {
		return E.Cause(err, "cannot use the proxy link of ", name)
	}
	for _, warning := range warnings {
		b.warn("proxy link of ", name, ": ", warning)
	}
	parsed, err := parseValue(content)
	if err != nil {
		return E.Cause(err, "the outbound of the proxy link of ", name)
	}
	outbound, isObject := parsed.(*object)
	if !isObject {
		return E.New("the outbound of the proxy link of ", name, " is not an object")
	}
	outbound.set("tag", outboundTag(name))
	outboundType, _ := outbound.get("type")
	if section.EnableUDPOverTCP && (outboundType == "socks" || outboundType == "shadowsocks") {
		outbound.set("udp_over_tcp", newObject("enabled", true, "version", versionUDPOverTCP))
	}
	b.setDetour(section, name, outbound)
	b.outbounds = append(b.outbounds, outbound)
	b.links = append(b.links, Link{Section: section.Name, Name: name, Tag: outboundTag(name), Text: link})
	return nil
}

func (b *builder) buildInterfaceOutbound(section *model.Section) error {
	if section.Interface == "" {
		return E.New("the VPN interface is not set")
	}
	outbound := newObject("type", "direct", "tag", outboundTag(section.Name), "bind_interface", b.device(section.Interface))
	if section.DomainResolverEnabled {
		resolverTag := section.Name + "-domain-resolver"
		// The shell backend asks the bootstrap server for the address of this resolver
		// whatever it is, an address included: it tests a variable of another function.
		server, err := dnsServer(section.DomainResolverDNSType, resolverTag, section.DomainResolverDNSServer, tagBootstrapDNSServer, outboundTag(section.Name))
		if err != nil {
			return err
		}
		b.dnsServers = append(b.dnsServers, server)
		outbound.set("domain_resolver", resolverTag)
	}
	b.outbounds = append(b.outbounds, outbound)
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

func (b *builder) buildDNS() (*object, error) {
	settings := &b.config.Settings
	host, _, _ := splitServer(settings.DNSServer)
	var resolver string
	if !model.IsIPv4(host) {
		resolver = tagBootstrapDNSServer
	}
	b.dnsServers = append(b.dnsServers, newObject("type", "udp", "tag", tagBootstrapDNSServer, "server", settings.BootstrapDNSServer, "server_port", 53))
	server, err := dnsServer(settings.DNSType, tagDNSServer, settings.DNSServer, resolver, "")
	if err != nil {
		return nil, err
	}
	b.dnsServers = append(b.dnsServers, server, newObject("type", "fakeip", "tag", tagFakeIPServer, "inet4_range", dataplane.FakeIPRange))

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
		// with it. The supervisor and the guard of the package tell by it that sing-box is
		// up (dataplane.ReadinessName), with check names or without them.
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

const (
	nameRejectRule    = "reject"
	nameExclusionRule = "exclusion"
)

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

	// one rule for all the sections that block, and one for all that exclude
	if b.anySectionWithLists("block") {
		b.addRouteRule(nameRejectRule, newObject("action", "reject", "inbound", tagTProxyInbound))
	}
	if b.anySectionWithLists("exclusion") {
		b.addRouteRule(nameExclusionRule, newObject("action", "route", "inbound", tagTProxyInbound, "outbound", tagDirectOutbound))
	}
	if len(settings.RoutingExcludedIPs) > 0 {
		entry := b.addRouteRule("", newObject("action", "route", "inbound", tagTProxyInbound, "outbound", tagDirectOutbound))
		for _, address := range settings.RoutingExcludedIPs {
			patch(entry.fields, "source_ip_cidr", argument(address))
		}
	}
	for index := range b.config.Sections {
		section := &b.config.Sections[index]
		if len(section.FullyRoutedIPs) == 0 {
			continue
		}
		entry := b.addRouteRule("", b.sectionRoute(section, tagTProxyInbound))
		for _, address := range section.FullyRoutedIPs {
			patch(entry.fields, "source_ip_cidr", argument(address))
		}
	}
	for index := range b.config.Sections {
		err := b.buildSectionLists(&b.config.Sections[index])
		if err != nil {
			return nil, E.Cause(err, "section ", b.config.Sections[index].Name)
		}
	}
	return route, nil
}

func (b *builder) anySectionWithLists(connectionType string) bool {
	found := false
	for index := range b.config.Sections {
		section := &b.config.Sections[index]
		if section.ConnectionType != connectionType {
			continue
		}
		found = true
		if section.HasEnabledLists() {
			return true
		}
	}
	if found {
		b.warn("sections of the type ", connectionType, " have no list: a rule for them is not needed")
	}
	return false
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
		if !section.MixedProxyEnabled {
			continue
		}
		port := argument(section.MixedProxyPort)
		if _, isText := port.(string); isText {
			return E.New("section ", section.Name, ": the port of the mixed proxy is not a number")
		}
		// sing-box would fail to start on the second socket, and so would every try again
		if other, taken := ports[fmt.Sprint(port)]; taken {
			return E.New("sections ", other, " and ", section.Name, ": the mixed proxies have the same port ", port)
		}
		ports[fmt.Sprint(port)] = section.Name
		tag := section.Name + "-mixed-in"
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
