package plan

import (
	"slices"
	"strconv"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	E "github.com/sagernet/sing/common/exceptions"
)

// SubscriptionServer is a server of a subscription as the builder takes it: its name in the
// list of the provider and its proxy link.
type SubscriptionServer struct {
	Name string
	Link string
}

// sourceServer is a server a source names: its outbound without a detour, decoded once.
type sourceServer struct {
	// name is the name of the server in the list of a subscription or the link (filters
	// go by it), tag the tag of its outbound
	name     string
	tag      string
	outbound *object
	// link is the proxy link it came from; "" for an outbound JSON or an interface
	link string
}

// buildExits makes the outbounds of the rules (ledger item 17). A server is there once for
// itself and once for each source its rows connect through ("<tag> via <source>"). A rule
// that goes through servers gets a URL test of the servers of its rows, with its fallback
// rows in their order (a fallback row of several servers is a URL test of its own), and the
// selector "<rule>-out" of the test and the servers, which its route rule goes to and the
// dashboard pins a server on. A rule whose rows name no server now refuses its connections
// through a selector of the block outbound: when servers come, sing-box replaces it while it
// runs (Result.Swappable), as it replaces every outbound made here.
func (b *builder) buildExits() error {
	b.outbounds = append(b.outbounds, newObject("type", "direct", "tag", tagDirectOutbound), newObject("type", "block", "tag", tagBlockOutbound))
	if _, isNumber := numberOf(b.config.Settings.Check.Tolerance); !isNumber {
		return E.New("the tolerance of the server check is not a number")
	}
	for index := range b.config.Sections {
		section := &b.config.Sections[index]
		if !section.Enabled {
			continue
		}
		switch b.config.Exit(section) {
		case model.ExitServers:
			if err := b.buildExit(section); err != nil {
				return E.Cause(err, "rule ", section.Name)
			}
		case model.ExitNone:
			if len(section.Servers)+len(section.Fallbacks) > 0 {
				b.warn("rule ", section.Name, ": its sources are not filled yet: the rule does nothing")
			} else {
				b.warn("rule ", section.Name, " has no servers: the rule does nothing")
			}
		}
	}
	return nil
}

func (b *builder) buildExit(section *model.Section) error {
	var members []string
	for _, row := range section.Servers {
		if row.Source == model.SourceDirect || row.Source == model.SourceBlock {
			b.warn("rule ", section.Name, ": ", row.Source, " among the servers counts only as the one row of the servers: the row is left out; as a fallback it is used")
			continue
		}
		tags, err := b.rowServers(section, row)
		if err != nil {
			return err
		}
		for _, tag := range tags {
			if !slices.Contains(members, tag) {
				members = append(members, tag)
			}
		}
	}
	// a fallback that is a server of the rule or a fallback before it is there once: sing-box
	// refuses a URL test that lists an outbound twice
	var tiers []string
	addTier := func(tag string) {
		if !slices.Contains(members, tag) && !slices.Contains(tiers, tag) {
			tiers = append(tiers, tag)
		}
	}
	for index, row := range section.Fallbacks {
		switch row.Source {
		case model.SourceDirect:
			addTier(tagDirectOutbound)
			continue
		case model.SourceBlock:
			addTier(tagBlockOutbound)
			continue
		}
		tags, err := b.rowServers(section, row)
		if err != nil {
			return err
		}
		switch len(tags) {
		case 0:
		case 1:
			addTier(tags[0])
		default:
			tag := outboundTag(section.Name + "-fallback-" + strconv.Itoa(index+1))
			b.addURLTest(tag, tags, nil)
			addTier(tag)
		}
	}
	var choices []string
	if len(members) == 0 && len(tiers) == 0 {
		b.warn("rule ", section.Name, ": its sources name no server now: its connections are refused")
		choices = []string{tagBlockOutbound}
		b.refused[section.Name] = true
	} else {
		test := outboundTag(section.Name + "-urltest")
		b.addURLTest(test, members, tiers)
		choices = append([]string{test}, members...)
		for _, tier := range tiers {
			if tier != tagDirectOutbound && tier != tagBlockOutbound && !slices.Contains(choices, tier) {
				choices = append(choices, tier)
			}
		}
	}
	tag := outboundTag(section.Name)
	b.outbounds = append(b.outbounds, newObject("type", "selector", "tag", tag, "outbounds", stringsToAny(choices), "default", choices[0]))
	b.swappable[tag] = true
	return nil
}

// addURLTest makes a URL test of the outbounds with the server check of the settings.
func (b *builder) addURLTest(tag string, members []string, fallbacks []string) {
	check := &b.config.Settings.Check
	tolerance, _ := numberOf(check.Tolerance)
	group := newObject("type", "urltest", "tag", tag, "outbounds", listOrEmpty(stringsToAny(members)),
		"url", check.TestingURL, "interval", check.Interval, "tolerance", tolerance)
	if len(fallbacks) > 0 {
		group.set("fallbacks", stringsToAny(fallbacks))
	}
	switch {
	case check.DownloadCheck == "off":
		group.set("download_url", "")
	case check.DownloadCheck == "custom" && check.DownloadURL != "":
		group.set("download_url", check.DownloadURL)
	case b.options.DownloadURL != "":
		group.set("download_url", b.options.DownloadURL)
	}
	b.outbounds = append(b.outbounds, group)
	b.swappable[tag] = true
}

// rowServers puts in the servers a row takes and returns their tags, in the order of the
// source.
func (b *builder) rowServers(section *model.Section, row model.Member) ([]string, error) {
	source := b.config.Source(row.Source)
	if source == nil {
		b.warnOnce("rule ", section.Name, ": there is no source ", row.Source)
		return nil, nil
	}
	if !source.Filled() {
		return nil, nil
	}
	servers, err := b.sourceServers(source)
	if err != nil {
		return nil, err
	}
	var via string
	if row.Via != "" {
		if source.Type == "interface" {
			return nil, E.New("the interface of the source ", source.Name, " does not connect through another source")
		}
		via, err = b.viaTag(row.Via, source.Name)
		if err != nil {
			return nil, err
		}
		if via == "" {
			// the source it goes through has no servers yet: the row has none now
			return nil, nil
		}
	}
	filtered := source.Type == "subscription" || len(servers) > 1
	var tags []string
	for _, server := range servers {
		if filtered && !row.Takes(server.name) {
			continue
		}
		if via == "" {
			b.addServer(section, server, server.tag, "")
			tags = append(tags, server.tag)
			continue
		}
		tag := server.tag + " via " + row.Via
		if kind, _ := server.outbound.get("type"); kind == "selector" || kind == "urltest" {
			return nil, E.New("the outbound JSON of the source ", source.Name, " is a ", kind, ", which connects through nothing: set detour in the outbounds it chooses from")
		}
		b.addServer(section, server, tag, via)
		tags = append(tags, tag)
	}
	return tags, nil
}

// addServer puts the outbound of a server in once, under the tag, connecting through the
// outbound via ("": directly).
func (b *builder) addServer(section *model.Section, server sourceServer, tag string, via string) {
	if b.servers[tag] {
		return
	}
	b.servers[tag] = true
	b.swappable[tag] = true
	outbound := server.outbound
	if via != "" || tag != server.tag {
		outbound = cloneObject(server.outbound)
	}
	outbound.set("tag", tag)
	if via != "" {
		if _, has := outbound.get("detour"); !has {
			outbound.set("detour", via)
		}
		b.warnSpoofThrough(tag, outbound, via)
	}
	b.outbounds = append(b.outbounds, outbound)
	if server.link != "" {
		b.links = append(b.links, Link{Section: section.Name, Name: tag, Tag: tag, Text: server.link})
	}
}

// viaTag is the outbound the servers of a row connect through: the one server of the
// source, or a URL test of its servers ("<source>-best").
func (b *builder) viaTag(name string, rowSource string) (string, error) {
	if name == rowSource {
		return "", E.New("a row of the source ", name, " connects through the same source")
	}
	source := b.config.Source(name)
	if source == nil {
		return "", E.New("there is no source ", name, " to connect through")
	}
	if !source.Filled() {
		return "", E.New("the source ", name, " to connect through is not filled")
	}
	servers, err := b.sourceServers(source)
	if err != nil {
		return "", err
	}
	if len(servers) == 0 {
		// a subscription not downloaded yet: the rows through it take no server for now, and
		// the rule goes by its fallbacks, as when a filter takes none
		b.warnOnce("the source ", name, " to connect through has no servers yet: the rows through it take none for now")
		return "", nil
	}
	var tags []string
	for _, server := range servers {
		b.addServer(&model.Section{Name: name}, server, server.tag, "")
		tags = append(tags, server.tag)
	}
	if len(tags) == 1 {
		return tags[0], nil
	}
	tag := name + "-best"
	if !b.groups[tag] {
		b.groups[tag] = true
		b.addURLTest(tag, tags, nil)
	}
	return tag, nil
}

// warnSpoofThrough says once that tls.spoof fails through a proxy: it needs the socket of its
// own connection (common/tls of the engine), which an interface gives and a proxy does not.
func (b *builder) warnSpoofThrough(tag string, outbound *object, via string) {
	value, _ := outbound.get("tls")
	tls, isObject := value.(*object)
	if !isObject {
		return
	}
	if spoof, _ := tls.get("spoof"); spoof == nil || spoof == "" {
		return
	}
	if source := b.config.Source(strings.TrimSuffix(via, "-best")); source != nil && source.Type == "interface" {
		return
	}
	b.warnOnce("server ", tag, ": tls.spoof does not work through a proxy: its connections will fail; it works through an interface")
}

// sourceServers are the servers of a source in its order, decoded once.
func (b *builder) sourceServers(source *model.Source) ([]sourceServer, error) {
	if servers, done := b.sourceCache[source.Name]; done {
		return servers, nil
	}
	var servers []sourceServer
	var err error
	switch source.Type {
	case "subscription":
		servers = b.subscriptionServers(source)
	case "links":
		servers, err = b.linkServers(source)
	case "json":
		servers, err = b.jsonServers(source)
	case "interface":
		servers, err = b.interfaceServers(source)
	default:
		err = E.New("the source ", source.Name, " is of an unknown type \"", source.Type, "\"")
	}
	if err != nil {
		return nil, err
	}
	b.sourceCache[source.Name] = servers
	return servers, nil
}

// subscriptionServers are the servers of the list of a subscription taken last. Their tags
// are the name of the source and the name of the server, numbered when the list has the
// name more than once; a server whose link is not decoded any more is left out.
func (b *builder) subscriptionServers(source *model.Source) []sourceServer {
	list := b.options.Servers[source.Name]
	if len(list) == 0 {
		b.warnOnce("source ", source.Name, " has no servers yet")
		return nil
	}
	var servers []sourceServer
	for index, server := range list {
		tag := b.serverTags(source.Name)[index]
		if outbound := b.serverOutbound(source.Name, index); outbound != nil {
			servers = append(servers, sourceServer{name: server.Name, tag: tag, outbound: outbound, link: server.Link})
		}
	}
	return servers
}

// serverTags are the tags of the servers of a subscription, in the order of its list. The
// dashboard and YACD show them.
func (b *builder) serverTags(subscription string) []string {
	if tags, done := b.subscriptionTags[subscription]; done {
		return tags
	}
	servers := b.options.Servers[subscription]
	names := make([]string, len(servers))
	for index, server := range servers {
		names[index] = server.Name
	}
	tags := numberedTags(subscription+": ", names)
	b.subscriptionTags[subscription] = tags
	return tags
}

// numberedTags are the tags of servers of the names after the prefix: a name the list has
// more than once numbered, a server without a name "server N".
func numberedTags(prefix string, names []string) []string {
	tags := make([]string, len(names))
	seen := make(map[string]int)
	for index, name := range names {
		if name == "" {
			name = "server " + strconv.Itoa(index+1)
		}
		seen[name]++
		if seen[name] > 1 {
			name += " #" + strconv.Itoa(seen[name])
		}
		tags[index] = prefix + name
	}
	return tags
}

// serverOutbound is the outbound of a server of a subscription, decoded once; nil when its
// link cannot be decoded. The servers were decoded and built by sing-box when their list was
// taken (subscription.Check): a link this one decodes no longer is of a list taken by
// another version.
func (b *builder) serverOutbound(subscription string, index int) *object {
	tag := b.serverTags(subscription)[index]
	if outbound, done := b.decoded[tag]; done {
		return outbound
	}
	content, _, err := b.options.DecodeLink(b.options.Servers[subscription][index].Link)
	var outbound *object
	if err == nil {
		parsed, parseErr := parseValue(content)
		outbound, _ = parsed.(*object)
		err = parseErr
	}
	if err != nil || outbound == nil {
		b.warn("server ", tag, " is left out: its link is not decoded any more")
		outbound = nil
	} else {
		outbound.set("tag", tag)
	}
	b.decoded[tag] = outbound
	return outbound
}

// linkServers decodes the links of a source. One link is the source: its tag is the name of
// the source; of several, each is named by its name after #, as a server of a subscription.
func (b *builder) linkServers(source *model.Source) ([]sourceServer, error) {
	var outbounds []*object
	var names []string
	for index, link := range source.Links {
		content, warnings, err := b.options.DecodeLink(link)
		if err != nil {
			return nil, E.Cause(err, "cannot use the proxy link ", index+1, " of the source ", source.Name)
		}
		for _, warning := range warnings {
			b.warn("proxy link ", index+1, " of the source ", source.Name, ": ", warning)
		}
		parsed, err := parseValue(content)
		if err != nil {
			return nil, E.Cause(err, "the outbound of the proxy link ", index+1, " of the source ", source.Name)
		}
		outbound, isObject := parsed.(*object)
		if !isObject {
			return nil, E.New("the outbound of the proxy link ", index+1, " of the source ", source.Name, " is not an object")
		}
		if kind, _ := outbound.get("type"); source.UDPOverTCP && (kind == "socks" || kind == "shadowsocks") {
			outbound.set("udp_over_tcp", newObject("enabled", true, "version", versionUDPOverTCP))
		}
		name, _ := outbound.get("tag")
		text, _ := name.(string)
		outbounds = append(outbounds, outbound)
		names = append(names, text)
	}
	tags := []string{source.Name}
	if len(outbounds) > 1 {
		tags = numberedTags(source.Name+": ", names)
	}
	servers := make([]sourceServer, len(outbounds))
	for index, outbound := range outbounds {
		outbound.set("tag", tags[index])
		servers[index] = sourceServer{name: names[index], tag: tags[index], outbound: outbound, link: source.Links[index]}
	}
	return servers, nil
}

func (b *builder) jsonServers(source *model.Source) ([]sourceServer, error) {
	// a byte order mark comes with text copied out of a file
	parsed, err := parseValue([]byte(strings.TrimPrefix(source.OutboundJSON, "\ufeff")))
	if err != nil {
		return nil, E.Cause(err, "the outbound of the source ", source.Name, " is not JSON")
	}
	outbound, isObject := parsed.(*object)
	if !isObject {
		return nil, E.New("the outbound of the source ", source.Name, " is not a JSON object")
	}
	outbound.set("tag", source.Name)
	return []sourceServer{{name: source.Name, tag: source.Name, outbound: outbound}}, nil
}

// interfaceServers is the outbound of a network interface: a direct one bound to its device
// (none: the main route) and given its routing mark. With a domain resolver, the names of
// the connections through it are resolved by a DNS server reached through it.
func (b *builder) interfaceServers(source *model.Source) ([]sourceServer, error) {
	outbound := newObject("type", "direct", "tag", source.Name)
	if source.Interface != "" {
		outbound.set("bind_interface", b.device(source.Interface))
	}
	if source.RoutingMark != "" {
		mark, err := strconv.ParseUint(source.RoutingMark, 0, 32)
		if err != nil {
			return nil, E.New("the routing mark of the source ", source.Name, " is not a number")
		}
		outbound.set("routing_mark", mark)
	}
	if source.DomainResolverEnabled {
		if source.DomainResolverDNSServer == "" {
			return nil, E.New("the domain resolver of the source ", source.Name, " has no DNS server")
		}
		resolverTag := source.Name + "-domain-resolver"
		server, err := dnsServer(source.DomainResolverDNSType, resolverTag, source.DomainResolverDNSServer, tagBootstrapDNSServer, source.Name)
		if err != nil {
			return nil, E.Cause(err, "the domain resolver of the source ", source.Name)
		}
		b.dnsServers = append(b.dnsServers, server)
		outbound.set("domain_resolver", resolverTag)
	}
	return []sourceServer{{name: source.Name, tag: source.Name, outbound: outbound}}, nil
}

// warnOnce warns of what every rule of a source would repeat.
func (b *builder) warnOnce(message ...any) {
	text := E.New(message...).Error()
	if !slices.Contains(b.warnings, text) {
		b.warnings = append(b.warnings, text)
	}
}

// isRefused tells whether the connections of a rule are refused because its sources name no
// server now: its outbound is a selector of the block outbound, and the lists are not
// downloaded through it.
func (b *builder) isRefused(section *model.Section) bool {
	return b.refused[section.Name]
}

// sectionRoute is the route rule of a rule from the inbound: to its outbound, or the route
// of a rule whose one row is direct or block.
func (b *builder) sectionRoute(section *model.Section, inbound string) *object {
	switch b.config.Exit(section) {
	case model.ExitBlock:
		return newObject("action", "reject", "inbound", inbound)
	case model.ExitDirect:
		return newObject("action", "route", "inbound", inbound, "outbound", tagDirectOutbound)
	}
	return newObject("action", "route", "inbound", inbound, "outbound", outboundTag(section.Name))
}

// cloneObject is a deep copy of an object: a server reached directly and through a source is
// two outbounds.
func cloneObject(original *object) *object {
	content, err := indented(original)
	if err != nil {
		panic(err)
	}
	parsed, err := parseValue(content)
	if err != nil {
		panic(err)
	}
	return parsed.(*object)
}
