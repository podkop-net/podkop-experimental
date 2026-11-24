package plan

import (
	"encoding/json"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/serverid"
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
// rows in their order (a fallback row of several servers is a URL test of its own; with a fallback
// choice the servers of all of them are one, fallbackTiers), and the selector "<rule>-out" of the
// test and all the servers, those of its fallbacks too, which its route rule goes to and the
// dashboard pins a server on. A rule of one server and no fallback has nothing to choose from
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
	tags := RuleTags{Name: b.names.Rule(section.Name), Selector: b.ruleOutbound(section.Name)}
	tiers, groups, err := b.fallbackTiers(section, members, &tags)
	if err != nil {
		return err
	}
	var choices []string
	switch {
	case len(members) == 0 && len(tiers) == 0:
		b.warn("rule ", b.names.RuleText(section.Name), ": its sources name no server now: its connections are refused")
		choices = []string{tagBlockOutbound}
		b.refused[section.Name] = true
	case len(members) == 1 && len(tiers) == 0 && !changing:
		choices = members
	default:
		test := b.claim(ruleTag(tags.Name, "urltest"), "rule\x00"+section.Name+"\x00urltest")
		b.setChoice(b.addURLTest(test, members, tiers), section, section.Choice)
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

// fallbackTiers makes the fallbacks of a rule whose servers are members: the tiers of its URL test,
// and the servers of each tier that is a URL test of its own, by its tag.
//
// By default each row is a tier, in the order of the rows. With another fallback choice the servers
// of all the rows are one tier, a URL test of that choice, and direct and block come after it,
// whatever their place among the rows: direct answers the server check before any server does, and
// block refuses, so that a choice among them and servers would be no choice. The loss of the servers
// of a tier is probed only while the rule goes through it (the engine: a group not in use probes
// nothing).
func (b *builder) fallbackTiers(section *model.Section, members []string, rule *RuleTags) (tiers []string, groups map[string][]string, err error) {
	groups = make(map[string][]string)
	// a fallback that is a server of the rule or a fallback before it is there once: sing-box
	// refuses a URL test that lists an outbound twice
	addTier := func(tag string) {
		if !slices.Contains(members, tag) && !slices.Contains(tiers, tag) {
			tiers = append(tiers, tag)
		}
	}
	addGroup := func(kind string, owner TagOf, servers []string) string {
		tag := b.claim(ruleTag(rule.Name, kind), "rule\x00"+section.Name+"\x00"+kind)
		group := b.addURLTest(tag, servers, nil)
		if kind == poolKind {
			b.setChoice(group, section, section.FallbackChoice)
			if section.FallbackChoice != model.ChoiceFastest {
				// the probes stop this long after the last connection through the group: the
				// least the engine takes, so that they end with the use of the fallbacks
				group.set("idle_timeout", b.config.Settings.Check.Interval)
			}
		}
		b.tags.Outbounds[tag] = owner
		addTier(tag)
		groups[tag] = servers
		return tag
	}
	pooled := poolsFallbacks(section)
	if !pooled && section.FallbackChoice != "" && section.FallbackChoice != model.ChoiceOrder {
		b.warnOnce("rule ", b.names.RuleText(section.Name), ": the fallback choice ", strconv.Quote(section.FallbackChoice), " is not known: the fallbacks are used in their order")
	}
	var pool, last []string
	for index, row := range section.Fallbacks {
		resort := map[string]string{model.SourceDirect: tagDirectOutbound, model.SourceBlock: tagBlockOutbound}[row.Source]
		switch {
		case resort != "" && pooled:
			last = append(last, resort)
			continue
		case resort != "":
			addTier(resort)
			continue
		}
		servers, err := b.rowServers(section, row)
		if err != nil {
			return nil, nil, err
		}
		switch {
		case pooled:
			for _, tag := range servers {
				if !slices.Contains(members, tag) && !slices.Contains(pool, tag) {
					pool = append(pool, tag)
				}
			}
		case len(servers) == 1:
			addTier(servers[0])
		case len(servers) > 1:
			addGroup("fallback-"+strconv.Itoa(index+1), TagOf{Rule: section.Name, Fallback: index + 1}, servers)
		}
	}
	switch {
	case len(pool) == 1:
		addTier(pool[0])
	case len(pool) > 1:
		rule.Pool = addGroup(poolKind, TagOf{Rule: section.Name}, pool)
	}
	for _, tag := range last {
		addTier(tag)
	}
	return tiers, groups, nil
}

// poolKind is the kind of the tag of the URL test of the servers of all the fallbacks of a rule.
const poolKind = "fallback"

// poolsFallbacks tells whether the servers of the fallbacks of a rule are chosen among as one.
func poolsFallbacks(section *model.Section) bool {
	switch section.FallbackChoice {
	case model.ChoiceFastest, model.ChoiceLoss, model.ChoiceBalance:
		return true
	}
	return false
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

// setChoice gives a URL test of a rule its choice: of the test of its servers the server choice, of
// the one of the servers of all its fallbacks the fallback choice. Fastest goes as before; loss and
// balance probe the servers for loss through the loss URL. The URL test of one fallback row (in
// order) goes by the fastest.
func (b *builder) setChoice(group *object, section *model.Section, choice string) {
	rule := b.names.RuleText(section.Name)
	switch choice {
	case "", model.ChoiceFastest:
		return
	case model.ChoiceLoss, model.ChoiceBalance:
	default:
		b.warnOnce("rule ", rule, ": the server choice ", strconv.Quote(choice), " is not known: the fastest server is used")
		return
	}
	group.set("mode", choice)
	group.set("loss_url", b.lossURL())
	if section.LossInterval != "" {
		minutes, err := strconv.Atoi(section.LossInterval)
		if err != nil || minutes < model.MinLossInterval || minutes > 1440 {
			b.warnOnce("rule ", rule, ": the loss check interval ", strconv.Quote(section.LossInterval), " is not a number of minutes from ", model.MinLossInterval, " to 1440: 30 minutes are used")
		} else {
			group.set("loss_interval", strconv.Itoa(minutes)+"m")
		}
	}
	if choice == model.ChoiceBalance && section.LossThreshold != "" {
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
	// an interface has no server and no protocol: the row of one takes it whatever its protocols
	ofProtocols := source.Type != "interface" && len(row.Protocols) > 0
	if ofProtocols {
		b.checkProtocols(rule, source, row, servers)
	}
	var tags []string
	for _, server := range servers {
		if filtered && !row.Takes(server.name) {
			continue
		}
		if ofProtocols && !row.TakesProtocol(server.protocol()) {
			continue
		}
		if via == "" {
			tag, err := b.addServer(section, server, "", "")
			if err != nil {
				return nil, err
			}
			tags = append(tags, tag)
			continue
		}
		if kind, _ := server.outbound.get("type"); kind == "selector" || kind == "urltest" {
			return nil, E.New("the outbound JSON of the source ", b.names.SourceText(source.Name), " is a ", kind, ", which connects through nothing: set detour in the outbounds it chooses from")
		}
		tag, err := b.addServer(section, server, via, throughName)
		if err != nil {
			return nil, err
		}
		tags = append(tags, tag)
	}
	return tags, nil
}

// protocol is the protocol of the server a row chooses it by: the type of its outbound.
func (s *sourceServer) protocol() string {
	kind, _ := s.outbound.get("type")
	name, _ := kind.(string)
	return name
}

// checkProtocols warns of the protocols of a row that are none: no link makes a server of it, and
// no server of the source is of it (an outbound JSON may be of any type of sing-box). The row takes
// no server by it; its other protocols work.
func (b *builder) checkProtocols(rule string, source *model.Source, row model.Member, servers []sourceServer) {
	for _, protocol := range row.Protocols {
		if slices.Contains(model.Protocols, protocol) || slices.ContainsFunc(servers, func(server sourceServer) bool { return server.protocol() == protocol }) {
			continue
		}
		b.warnOnce("rule ", rule, ": ", strconv.Quote(protocol), " among the protocols of the row of the source ", b.names.SourceText(source.Name),
			" is not known (", strings.Join(model.Protocols, ", "), "): no server is of it")
	}
}

// addServer puts the outbound of a server in once and returns its tag: "<tag of the server>",
// or "<tag of the server> via <name of the source>" connecting through the outbound via of the
// source through.
func (b *builder) addServer(section *model.Section, server sourceServer, via string, through string) (string, error) {
	owner := "server\x00" + server.source + "\x00" + strconv.Itoa(server.index)
	tag := server.tag
	if via != "" {
		owner += "\x00" + through
		tag += " via " + b.names.Source(through)
	}
	tag = b.claim(tag, owner)
	if b.servers[tag] {
		return tag, nil
	}
	b.servers[tag] = true
	b.swappable[tag] = true
	// the stable identity of the server: its key in the cure store and the id the page joins the
	// tag to. Taken from the outbound before the tag and the detour are set on it, so it is the
	// same across a rebuild and whatever way the server is reached.
	raw, _ := json.Marshal(server.outbound)
	stableHash := serverid.Canonical(raw)
	b.tags.Outbounds[tag] = TagOf{Source: server.source, Server: server.shown, Via: through, StableHash: stableHash}
	cure := b.config.Cure(stableHash, through)
	outbound := server.outbound
	if via != "" || tag != server.tag || cure != nil {
		outbound = cloneObject(server.outbound)
	}
	outbound.set("tag", tag)
	if via != "" {
		// the way of the tag, also over a detour of an outbound JSON (rowServers)
		outbound.set("detour", via)
	}
	if cure != nil && cure.Kind == model.CureDetour {
		if err := b.applyDetour(section, tag, server, outbound, cure); err != nil {
			return "", err
		}
	} else if cure != nil {
		if err := b.applyCure(tag, outbound, cure, through); err != nil {
			return "", err
		}
	}
	// a server whose link or JSON already carries spoof, or a cure that slipped through, reaches a
	// proxy detour without it: the engine would fail every connection of it (it needs its own socket)
	b.dropSpoofThrough(tag, outbound, through)
	b.outbounds = append(b.outbounds, outbound)
	if server.link != "" {
		b.links = append(b.links, Link{Section: section.Name, Name: tag, Tag: tag, Text: server.link})
	}
	if source := b.config.Source(server.source); source != nil && source.Type == "json" {
		b.jsonOutbounds = append(b.jsonOutbounds, outbound)
	}
	return tag, nil
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

// detoursItself tells a server of a source whose own treatment (of its direct use) connects it
// through another server.
func (b *builder) detoursItself(server sourceServer) bool {
	raw, _ := json.Marshal(server.outbound)
	cure := b.config.Cure(serverid.Canonical(raw), "")
	return cure != nil && cure.Kind == model.CureDetour
}

// viaTag is the outbound the servers of a row connect through: the one server of the
// source, or a URL test of its servers ("<source>-best"). Inside a treatment of 0.8.13
// (detouring), the servers of the source that are treated to go through another server
// themselves are left out ("<source>-relays" when some are).
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
	left := 0
	for _, server := range servers {
		if b.detouring && b.detoursItself(server) {
			// the way of a treatment written by 0.8.13 (it names no relay, only this source) is
			// never a server its own treatment connects through another one: that would be a
			// chain or a loop, and building it here without its treatment would take the
			// treatment from its other uses too (they share its tag)
			left++
			continue
		}
		tag, err := b.addServer(&model.Section{Name: name}, server, "", "")
		if err != nil {
			return "", err
		}
		tags = append(tags, tag)
	}
	if len(tags) == 0 {
		b.warnOnce("rule ", rule, ": every server of the source ", b.names.SourceText(name), " is connected through another one by a treatment of its own: a treatment through it is left off")
		return "", nil
	}
	if len(tags) == 1 {
		return tags[0], nil
	}
	label, owner := b.names.Source(name)+"-best", "best\x00"+name
	if left > 0 {
		// not all the servers of the source: a group of its own, the rows through the source keep theirs
		label, owner = b.names.Source(name)+"-relays", "relays\x00"+name
	}
	tag := b.claim(label, owner)
	if !b.groups[tag] {
		b.groups[tag] = true
		b.addURLTest(tag, tags, nil)
		b.tags.Outbounds[tag] = TagOf{Source: name}
	}
	return tag, nil
}

// applyCure sets the treatment of a cure on the server's TLS; dropSpoofThrough (called next)
// leaves a spoof off a proxy detour. A server with no TLS gets a warning and no change — a cure
// needs a TLS handshake to act on.
func (b *builder) applyCure(tag string, outbound *object, cure *model.Cure, through string) error {
	value, _ := outbound.get("tls")
	tls, isObject := value.(*object)
	if !isObject {
		b.warnOnce("server ", tag, ": a treatment needs TLS, which this server has none of; it is left off")
		return nil
	}
	switch cure.Kind {
	case model.CureSpoof:
		// a row written by hand may hold a name the engine refuses (not a host name, or the
		// server's own name): the build must not fail for it
		value, _ := tls.get("server_name")
		serverName, _ := value.(string)
		if !model.ValidMaskName(cure.SNI) || strings.EqualFold(cure.SNI, serverName) {
			b.warnOnce("server ", tag, ": the mask ", strconv.Quote(cure.SNI), " is not a host name other than the server's; the treatment is left off")
			return nil
		}
		tls.set("spoof", cure.SNI)
	case model.CureRecordFragment:
		tls.set("record_fragment", true)
	}
	return nil
}

// applyDetour connects a server whose path from here is cut and which answers through another one
// (a detour cure) through that other server: the outbound of the relay the cure names, reached
// directly, becomes the detour of the server's outbound (applyRelay), the server's tag and identity
// unchanged. A cure written by 0.8.13 names no relay, only its source: the server goes through the
// best server of that source, as a row with "via" would, of those of its servers that are not
// treated to go through another server themselves (viaTag: a chain or a loop otherwise, whatever
// the order of the build); a detour of 0.8.13 through the server's own source is left off. The
// cure is keyed by the direct use, so a detoured use never takes it.
func (b *builder) applyDetour(section *model.Section, tag string, server sourceServer, outbound *object, cure *model.Cure) error {
	if b.detouring {
		b.warnOnce("server ", tag, ": its treatment connects it through another source, but it is itself the way of a treated server: left off here, so no loop is made")
		return nil
	}
	if cure.Relay != "" {
		return b.applyRelay(tag, outbound, cure)
	}
	b.detouring = true
	through, err := b.viaTag(section.Name, cure.Through, server.source)
	b.detouring = false
	if err != nil {
		return err
	}
	if through == "" {
		// viaTag told why
		return nil
	}
	outbound.set("detour", through)
	return nil
}

// applyRelay sets the detour of a server to the one server its cure names: the server of the
// source cure.Through whose stable identity is cure.Relay, reached directly, the same outbound a
// rule has of it (or put in once for the treatment). The relay may be of the server's own source:
// it is another server, which connects directly, so no loop is made. A relay that is the server
// itself, is gone from its source (the subscription dropped or changed it), or is connected
// through another server by a treatment of its own (a chain) leaves the treatment off, with a
// warning; the dashboard counts such a treatment as stale.
func (b *builder) applyRelay(tag string, outbound *object, cure *model.Cure) error {
	if cure.Relay == cure.Hash {
		b.warnOnce("server ", tag, ": its treatment connects it through itself: left off")
		return nil
	}
	if relayCure := b.config.Cure(cure.Relay, ""); relayCure != nil && relayCure.Kind == model.CureDetour {
		b.warnOnce("server ", tag, ": the server its treatment connects it through is connected through another one itself: left off, so no chain is made")
		return nil
	}
	source := b.config.Source(cure.Through)
	if source != nil && source.Filled() {
		servers, err := b.sourceServers(source)
		if err != nil {
			return err
		}
		for _, candidate := range servers {
			raw, _ := json.Marshal(candidate.outbound)
			if serverid.Canonical(raw) != cure.Relay {
				continue
			}
			relayTag, err := b.addServer(&model.Section{Name: cure.Through}, candidate, "", "")
			if err != nil {
				return err
			}
			outbound.set("detour", relayTag)
			return nil
		}
	}
	b.warnOnce("server ", tag, ": the server its treatment connects it through is not in the source ", b.names.SourceText(cure.Through), " now: the treatment is left off")
	return nil
}

// dropSpoofThrough leaves tls.spoof off a server reached through a proxy, with a warning: it
// forges the first ClientHello on the server's own socket (common/tls of the engine), which a
// proxy detour does not give, so every connection of the outbound would fail. An interface gives
// a real socket and keeps it; a direct server (through == "") keeps it; record_fragment is
// carried through a detour and is not touched. Only that use goes without it (the outbound
// reached through a proxy is a copy), so spoof is never on a proxy detour and one server does not
// stop the whole configuration: set_cure refuses such a cure, so this meets a link or an outbound
// JSON that carries spoof by hand, or a cure stored for a way that has become a proxy since.
func (b *builder) dropSpoofThrough(tag string, outbound *object, through string) {
	if through == "" {
		return
	}
	if source := b.config.Source(through); source != nil && source.Type == "interface" {
		return
	}
	value, _ := outbound.get("tls")
	tls, isObject := value.(*object)
	if !isObject {
		return
	}
	if spoof, _ := tls.get("spoof"); spoof != nil && spoof != "" {
		tls.remove("spoof")
		b.warnOnce("server ", tag, ": tls.spoof does not work through a proxy, only directly or through an interface (it needs the server's own connection): it is left off here")
	}
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
		// the marks of podkop: what has ProxyMark or RouterMark goes to the transparent proxy by
		// the rules of the routing table, its own connections included
		if mark&(dataplane.ProxyMark|dataplane.RouterMark) != 0 {
			return nil, E.New("the routing mark of the source ", b.names.SourceText(source.Name), " has the bits of podkop's marks (0x100000, 0x400000): its connections would come back into sing-box")
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
func (b *builder) sectionRoute(section *model.Section, inbound any) *object {
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
