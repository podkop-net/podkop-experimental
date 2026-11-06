package plan

import (
	"encoding/json"
	"net/url"
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
	// source is the section of its source and index its place there; shown is its name in
	// the tag after the name of the source, "" for a source of one server
	source string
	index  int
	shown  string
}

// buildExits makes the outbounds of the rules (ledger item 17). A server is there once for
// itself and once for each source its rows connect through ("<tag> via <source>"). A rule
// that goes through servers gets a URL test of the servers of its rows, with its fallback
// rows in their order (a fallback row of several servers is a URL test of its own), and the
// selector "<rule>-out" of the test and all the servers, those of its fallbacks too, which its
// route rule goes to and the dashboard pins a server on. A rule of one server and no fallback has nothing to choose from
// and its selector takes the server alone, unless a subscription can bring more at any time.
// A rule whose rows name no server now refuses its connections
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
				return E.Cause(err, "rule ", b.names.RuleText(section.Name))
			}
		case model.ExitNone:
			if len(section.Servers)+len(section.Fallbacks) > 0 {
				b.warn("rule ", b.names.RuleText(section.Name), ": its sources are not filled yet: the rule does nothing")
			} else {
				b.warn("rule ", b.names.RuleText(section.Name), " has no servers: the rule does nothing")
			}
		}
	}
	return nil
}

func (b *builder) buildExit(section *model.Section) error {
	var members []string
	changing := false
	for _, row := range section.Servers {
		if row.Source == model.SourceDirect || row.Source == model.SourceBlock {
			b.warn("rule ", b.names.RuleText(section.Name), ": ", row.Source, " among the servers counts only as the one row of the servers: the row is left out; as a fallback it is used")
			continue
		}
		if source := b.config.Source(row.Source); source != nil && source.Type == "subscription" {
			changing = true
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
	// the servers of a fallback of several servers, by the tag of its URL test
	groups := make(map[string][]string)
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
			kind := "fallback-" + strconv.Itoa(index+1)
			tag := b.claim(ruleTag(b.names.Rule(section.Name), kind), "rule\x00"+section.Name+"\x00"+kind)
			b.addURLTest(tag, tags, nil)
			b.tags.Outbounds[tag] = TagOf{Rule: section.Name, Fallback: index + 1}
			addTier(tag)
			groups[tag] = tags
		}
	}
	var choices []string
	tags := RuleTags{Name: b.names.Rule(section.Name), Selector: b.ruleOutbound(section.Name)}
	switch {
	case len(members) == 0 && len(tiers) == 0:
		b.warn("rule ", b.names.RuleText(section.Name), ": its sources name no server now: its connections are refused")
		choices = []string{tagBlockOutbound}
		b.refused[section.Name] = true
	case len(members) == 1 && len(tiers) == 0 && !changing:
		choices = members
	default:
		test := b.claim(ruleTag(tags.Name, "urltest"), "rule\x00"+section.Name+"\x00urltest")
		b.setChoice(b.addURLTest(test, members, tiers), section)
		tags.Test = test
		b.tags.Outbounds[test] = TagOf{Rule: section.Name}
		choices = append([]string{test}, members...)
		for _, tier := range tiers {
			// a fallback of several servers is offered by its servers, so that the dashboard
			// pins any server it shows; direct and block are only fallbacks
			servers, isGroup := groups[tier]
			if !isGroup && tier != tagDirectOutbound && tier != tagBlockOutbound {
				servers = []string{tier}
			}
			for _, server := range servers {
				if !slices.Contains(choices, server) {
					choices = append(choices, server)
				}
			}
		}
	}
	b.outbounds = append(b.outbounds, newObject("type", "selector", "tag", tags.Selector, "outbounds", stringsToAny(choices), "default", choices[0]))
	b.swappable[tags.Selector] = true
	b.tags.Rules[section.Name] = tags
	b.tags.Outbounds[tags.Selector] = TagOf{Rule: section.Name}
	return nil
}

// addURLTest makes a URL test of the outbounds with the server check of the settings.
func (b *builder) addURLTest(tag string, members []string, fallbacks []string) *object {
	check := &b.config.Settings.Check
	tolerance, _ := numberOf(check.Tolerance)
	group := newObject("type", "urltest", "tag", tag, "outbounds", listOrEmpty(stringsToAny(members)),
		"urls", stringsToAny(check.TestingURLs), "interval", check.Interval, "tolerance", tolerance)
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
	return group
}

// setChoice gives the URL test of a rule's servers the rule's server choice: fastest goes
// as before; loss and balance probe the servers for loss through the loss URL. The fallback
// groups of a rule go by the fastest: they carry its connections only while its servers
// are down.
func (b *builder) setChoice(group *object, section *model.Section) {
	rule := b.names.RuleText(section.Name)
	switch section.Choice {
	case "", model.ChoiceFastest:
		return
	case model.ChoiceLoss, model.ChoiceBalance:
	default:
		b.warnOnce("rule ", rule, ": the server choice ", strconv.Quote(section.Choice), " is not known: the fastest server is used")
		return
	}
	group.set("mode", section.Choice)
	group.set("loss_url", b.lossURL())
	if section.LossInterval != "" {
		minutes, err := strconv.Atoi(section.LossInterval)
		if err != nil || minutes < model.MinLossInterval || minutes > 1440 {
			b.warnOnce("rule ", rule, ": the loss check interval ", strconv.Quote(section.LossInterval), " is not a number of minutes from ", model.MinLossInterval, " to 1440: 30 minutes are used")
		} else {
			group.set("loss_interval", strconv.Itoa(minutes)+"m")
		}
	}
	if section.Choice == model.ChoiceBalance && section.LossThreshold != "" {
		percent, err := strconv.ParseFloat(section.LossThreshold, 64)
		// written as it is, so that NaN, which no comparison holds, is refused too
		if err != nil || !(percent > 0 && percent <= 50) {
			b.warnOnce("rule ", rule, ": the loss threshold ", strconv.Quote(section.LossThreshold), " is not a percentage above 0 and up to 50: 1 % is used")
		} else {
			group.set("loss_threshold", json.Number(strconv.FormatFloat(percent, 'f', -1, 64)))
		}
	}
}

// lossURL is the loss URL of the settings, the default one when it is not an http or https
// URL with a host (the engine would refuse the whole configuration).
func (b *builder) lossURL() string {
	link := b.config.Settings.Check.LossURL
	if parsed, err := url.Parse(link); err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		b.warnOnce("the loss URL ", strconv.Quote(link), " is not an http or https URL with a host: ", model.DefaultLossURL, " is used")
		return model.DefaultLossURL
	}
	return link
}

// rowServers puts in the servers a row takes and returns their tags, in the order of the
// source.
func (b *builder) rowServers(section *model.Section, row model.Member) ([]string, error) {
	source := b.config.Source(row.Source)
	rule := b.names.RuleText(section.Name)
	if source == nil {
		b.warnOnce("rule ", rule, ": there is no source ", row.Source)
		return nil, nil
	}
	if !source.Filled() {
		if source.Type != "" && !slices.Contains(model.SourceTypes, source.Type) {
			b.warnOnce("rule ", rule, ": the source ", b.names.SourceText(source.Name), " is of a type podkop does not know (", source.Type, "): its row takes no server")
		}
		return nil, nil
	}
	servers, err := b.sourceServers(source)
	if err != nil {
		return nil, err
	}
	// The outbound JSON of a source may name its own way (detour). With the "Through" of the
	// row set, the row's way is taken and replaces it: the tag tells it ("… via <source>"), and
	// the log and the dashboard show the way the connections go. Without, a detour that names
	// another source is taken as a "Through" is (its server, or the best of its servers), with
	// the tag telling it; a detour that names no source (an outbound the JSON brings along, one
	// of podkop) stays as it is.
	throughName := row.Via
	if detour := jsonDetour(source, servers); detour != "" {
		switch {
		case row.Via != "" && detour != row.Via:
			b.warnOnce("rule ", rule, ": the outbound JSON of the source ", b.names.SourceText(source.Name), " connects through ", detour,
				"; the row connects it through ", b.names.SourceText(row.Via), " instead, as its tag tells")
		case row.Via == "" && b.config.Source(detour) != nil:
			throughName = detour
		}
	}
	var via string
	if throughName != "" {
		// a row that cannot go the way it names takes no server: the rule goes by its other
		// rows and its fallbacks, and the rest of the settings run
		if source.Type == "interface" {
			b.warnOnce("rule ", rule, ": the interface of the source ", b.names.SourceText(source.Name), " does not connect through another source: the row takes no server")
			return nil, nil
		}
		via, err = b.viaTag(section.Name, throughName, source.Name)
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
			tags = append(tags, b.addServer(section, server, "", ""))
			continue
		}
		if kind, _ := server.outbound.get("type"); kind == "selector" || kind == "urltest" {
			return nil, E.New("the outbound JSON of the source ", b.names.SourceText(source.Name), " is a ", kind, ", which connects through nothing: set detour in the outbounds it chooses from")
		}
		tags = append(tags, b.addServer(section, server, via, throughName))
	}
	return tags, nil
}

// addServer puts the outbound of a server in once and returns its tag: "<tag of the server>",
// or "<tag of the server> via <name of the source>" connecting through the outbound via of the
// source through.
func (b *builder) addServer(section *model.Section, server sourceServer, via string, through string) string {
	owner := "server\x00" + server.source + "\x00" + strconv.Itoa(server.index)
	tag := server.tag
	if via != "" {
		owner += "\x00" + through
		tag += " via " + b.names.Source(through)
	}
	tag = b.claim(tag, owner)
	if b.servers[tag] {
		return tag
	}
	b.servers[tag] = true
	b.swappable[tag] = true
	b.tags.Outbounds[tag] = TagOf{Source: server.source, Server: server.shown, Via: through}
	outbound := server.outbound
	if via != "" || tag != server.tag {
		outbound = cloneObject(server.outbound)
	}
	outbound.set("tag", tag)
	if via != "" {
		// the way of the tag, also over a detour of an outbound JSON (rowServers)
		outbound.set("detour", via)
		b.warnSpoofThrough(tag, outbound, through)
	}
	b.outbounds = append(b.outbounds, outbound)
	if server.link != "" {
		b.links = append(b.links, Link{Section: section.Name, Name: tag, Tag: tag, Text: server.link})
	}
	if source := b.config.Source(server.source); source != nil && source.Type == "json" {
		b.jsonOutbounds = append(b.jsonOutbounds, outbound)
	}
	return tag
}

// oldServerOwner is the owner of a server by the tag it had while tags were made of sections:
// "src2" (a source of one server) or "src3: NL 1" (a server of a source of several, its name
// numbered as then).
func (b *builder) oldServerOwner(name string) (string, bool) {
	if b.config.Source(name) != nil {
		return "server\x00" + name + "\x000", true
	}
	section, shown, found := strings.Cut(name, ": ")
	source := b.config.Source(section)
	if !found || source == nil || !source.Filled() {
		return "", false
	}
	servers, err := b.sourceServers(source)
	if err != nil {
		return "", false
	}
	for _, server := range servers {
		if server.shown == shown {
			return "server\x00" + section + "\x00" + strconv.Itoa(server.index), true
		}
	}
	return "", false
}

// renameOldTags puts the tags of now in an outbound JSON that names outbounds of podkop by the
// tags they had while tags were made of sections: "src2" (a source of one server), "src3: NL 1"
// (a server of a source of several), "src3: NL 1 via src2", "src2-best", "main-out",
// "main-urltest-out", "main-fallback-1-out". A selector or a URL test of the JSON chooses from
// them, a detour names one. A name that is a tag of now stays.
func (b *builder) renameOldTags() {
	rename := func(name string) string {
		if b.owners[name] != "" {
			return name
		}
		var owners []string
		if owner, found := b.oldServerOwner(name); found {
			owners = append(owners, owner)
		}
		if at := strings.LastIndex(name, " via "); at > 0 {
			through := name[at+len(" via "):]
			if owner, found := b.oldServerOwner(name[:at]); found && b.config.Source(through) != nil {
				owners = append(owners, owner+"\x00"+through)
			}
		}
		if source, found := strings.CutSuffix(name, "-best"); found {
			owners = append(owners, "best\x00"+source)
		}
		if base, found := strings.CutSuffix(name, "-out"); found {
			if rule, found := strings.CutSuffix(base, "-urltest"); found {
				owners = append(owners, "rule\x00"+rule+"\x00urltest")
			}
			if at := strings.LastIndex(base, "-fallback-"); at > 0 {
				owners = append(owners, "rule\x00"+base[:at]+"\x00"+base[at+1:])
			}
			owners = append(owners, "rule\x00"+base)
		}
		for _, owner := range owners {
			if tag, found := b.tagOf[owner]; found {
				return tag
			}
		}
		return name
	}
	for _, outbound := range b.jsonOutbounds {
		if detour, _ := outbound.get("detour"); detour != nil {
			if name, isText := detour.(string); isText {
				outbound.set("detour", rename(name))
			}
		}
		if list, _ := outbound.get("outbounds"); list != nil {
			if items, isItems := list.([]any); isItems {
				for index, item := range items {
					if name, isText := item.(string); isText {
						items[index] = rename(name)
					}
				}
			}
		}
	}
}

// jsonDetour is the detour the outbound JSON of a source names; "" for a source of another
// type, or one without.
func jsonDetour(source *model.Source, servers []sourceServer) string {
	if source.Type != "json" || len(servers) != 1 {
		return ""
	}
	detour, _ := servers[0].outbound.get("detour")
	name, _ := detour.(string)
	return strings.TrimSpace(name)
}

// viaTag is the outbound the servers of a row connect through: the one server of the
// source, or a URL test of its servers ("<source>-best").
func (b *builder) viaTag(rule string, name string, rowSource string) (string, error) {
	rule = b.names.RuleText(rule)
	if name == rowSource {
		b.warnOnce("rule ", rule, ": a row of the source ", b.names.SourceText(name), " connects through the same source: the row takes no server")
		return "", nil
	}
	source := b.config.Source(name)
	if source == nil {
		b.warnOnce("rule ", rule, ": there is no source ", name, " to connect through: the row takes no server")
		return "", nil
	}
	if !source.Filled() {
		b.warnOnce("rule ", rule, ": the source ", b.names.SourceText(name), " to connect through is not filled: the row takes no server")
		return "", nil
	}
	servers, err := b.sourceServers(source)
	if err != nil {
		return "", err
	}
	if len(servers) == 0 {
		// a subscription not downloaded yet: the rows through it take no server for now, and
		// the rule goes by its fallbacks, as when a filter takes none
		b.warnOnce("the source ", b.names.SourceText(name), " to connect through has no servers yet: the rows through it take none for now")
		return "", nil
	}
	var tags []string
	for _, server := range servers {
		tags = append(tags, b.addServer(&model.Section{Name: name}, server, "", ""))
	}
	if len(tags) == 1 {
		return tags[0], nil
	}
	tag := b.claim(b.names.Source(name)+"-best", "best\x00"+name)
	if !b.groups[tag] {
		b.groups[tag] = true
		b.addURLTest(tag, tags, nil)
		b.tags.Outbounds[tag] = TagOf{Source: name}
	}
	return tag, nil
}

// warnSpoofThrough says once that tls.spoof fails through a proxy: it needs the socket of its
// own connection (common/tls of the engine), which an interface gives and a proxy does not.
// through is the source the outbound connects through.
func (b *builder) warnSpoofThrough(tag string, outbound *object, through string) {
	value, _ := outbound.get("tls")
	tls, isObject := value.(*object)
	if !isObject {
		return
	}
	if spoof, _ := tls.get("spoof"); spoof == nil || spoof == "" {
		return
	}
	if source := b.config.Source(through); source != nil && source.Type == "interface" {
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
		err = E.New("the source ", b.names.SourceText(source.Name), " is of an unknown type \"", source.Type, "\"")
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
		b.warnOnce("source ", b.names.SourceText(source.Name), " has no servers yet")
		return nil
	}
	prefix := b.names.Source(source.Name) + ": "
	var servers []sourceServer
	for index, server := range list {
		tag := b.serverTags(source.Name)[index]
		if outbound := b.serverOutbound(source.Name, index); outbound != nil {
			servers = append(servers, sourceServer{name: server.Name, tag: tag, outbound: outbound, link: server.Link,
				source: source.Name, index: index, shown: strings.TrimPrefix(tag, prefix)})
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
	tags := numberedTags(b.names.Source(subscription)+": ", names)
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
	key := subscription + "\x00" + strconv.Itoa(index)
	if outbound, done := b.decoded[key]; done {
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
	b.decoded[key] = outbound
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
			return nil, E.Cause(err, "cannot use the proxy link ", index+1, " of the source ", b.names.SourceText(source.Name))
		}
		for _, warning := range warnings {
			b.warn("proxy link ", index+1, " of the source ", b.names.SourceText(source.Name), ": ", warning)
		}
		parsed, err := parseValue(content)
		if err != nil {
			return nil, E.Cause(err, "the outbound of the proxy link ", index+1, " of the source ", b.names.SourceText(source.Name))
		}
		outbound, isObject := parsed.(*object)
		if !isObject {
			return nil, E.New("the outbound of the proxy link ", index+1, " of the source ", b.names.SourceText(source.Name), " is not an object")
		}
		if kind, _ := outbound.get("type"); source.UDPOverTCP && (kind == "socks" || kind == "shadowsocks") {
			outbound.set("udp_over_tcp", newObject("enabled", true, "version", versionUDPOverTCP))
		}
		name, _ := outbound.get("tag")
		text, _ := name.(string)
		outbounds = append(outbounds, outbound)
		names = append(names, text)
	}
	name := b.names.Source(source.Name)
	tags := []string{name}
	if len(outbounds) > 1 {
		tags = numberedTags(name+": ", names)
	}
	servers := make([]sourceServer, len(outbounds))
	for index, outbound := range outbounds {
		outbound.set("tag", tags[index])
		servers[index] = sourceServer{name: names[index], tag: tags[index], outbound: outbound, link: source.Links[index], source: source.Name, index: index}
		if len(outbounds) > 1 {
			servers[index].shown = strings.TrimPrefix(tags[index], name+": ")
		}
	}
	return servers, nil
}

func (b *builder) jsonServers(source *model.Source) ([]sourceServer, error) {
	// a byte order mark comes with text copied out of a file
	parsed, err := parseValue([]byte(strings.TrimPrefix(source.OutboundJSON, "\ufeff")))
	if err != nil {
		return nil, E.Cause(err, "the outbound of the source ", b.names.SourceText(source.Name), " is not JSON")
	}
	outbound, isObject := parsed.(*object)
	if !isObject {
		return nil, E.New("the outbound of the source ", b.names.SourceText(source.Name), " is not a JSON object")
	}
	name := b.names.Source(source.Name)
	outbound.set("tag", name)
	return []sourceServer{{name: source.Name, tag: name, outbound: outbound, source: source.Name}}, nil
}

// interfaceServers is the outbound of a network interface: a direct one bound to its device
// (none: the main route) and given its routing mark. With a domain resolver, the names of
// the connections through it are resolved by a DNS server reached through it.
func (b *builder) interfaceServers(source *model.Source) ([]sourceServer, error) {
	// the tag the outbound gets (addServer claims it for the same owner, numbered when
	// another has the name): the DNS server of the domain resolver goes through it by it
	name := b.claim(b.names.Source(source.Name), "server\x00"+source.Name+"\x000")
	outbound := newObject("type", "direct", "tag", name)
	if source.Interface != "" {
		outbound.set("bind_interface", b.device(source.Interface))
	}
	if source.RoutingMark != "" {
		mark, err := strconv.ParseUint(source.RoutingMark, 0, 32)
		if err != nil {
			return nil, E.New("the routing mark of the source ", b.names.SourceText(source.Name), " is not a number")
		}
		outbound.set("routing_mark", mark)
	}
	if source.DomainResolverEnabled {
		if source.DomainResolverDNSServer == "" {
			return nil, E.New("the domain resolver of the source ", b.names.SourceText(source.Name), " has no DNS server")
		}
		resolverTag := name + "-domain-resolver"
		server, err := dnsServer(source.DomainResolverDNSType, resolverTag, source.DomainResolverDNSServer, tagBootstrapDNSServer, name)
		if err != nil {
			return nil, E.Cause(err, "the domain resolver of the source ", b.names.SourceText(source.Name))
		}
		b.dnsServers = append(b.dnsServers, server)
		outbound.set("domain_resolver", resolverTag)
	}
	return []sourceServer{{name: source.Name, tag: name, outbound: outbound, source: source.Name}}, nil
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
	return newObject("action", "route", "inbound", inbound, "outbound", b.ruleOutbound(section.Name))
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
