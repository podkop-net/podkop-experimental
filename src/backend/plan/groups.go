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

// what a group that chooses servers tests them with: the values a URL test section has by
// default
const (
	groupTestURL      = "https://www.gstatic.com/generate_204"
	groupTestInterval = "3m"
	groupTolerance    = 50
)

// exitKind is where the traffic of a section of the type group goes.
type exitKind int

const (
	exitServers exitKind = iota
	exitSection
	exitDirect
	exitBlock
)

type groupExit struct {
	kind exitKind
	// group is the group whose servers it goes through (exitServers), section the section
	// it goes as (exitSection)
	group   string
	section string
	// servers are the servers of the group
	servers []groupServer
}

// serverTags are the tags of the servers of a subscription, in the order of its list: the
// name of the subscription and the name of the server, numbered when the list has the name
// more than once. The dashboard and YACD show them.
func (b *builder) serverTags(subscription string) []string {
	if tags, done := b.subscriptionTags[subscription]; done {
		return tags
	}
	servers := b.options.Servers[subscription]
	tags := make([]string, len(servers))
	seen := make(map[string]int)
	for index, server := range servers {
		name := server.Name
		if name == "" {
			name = "server " + strconv.Itoa(index+1)
		}
		seen[name]++
		if seen[name] > 1 {
			name += " #" + strconv.Itoa(seen[name])
		}
		tags[index] = subscription + ": " + name
	}
	b.subscriptionTags[subscription] = tags
	return tags
}

// groupServers are the servers a group chooses: those of its subscriptions whose names it
// takes, or all of them (all false: only those it takes). Each server is there once, in the
// order of the subscriptions of the group and of their lists. A server whose link cannot be
// decoded is not there.
func (b *builder) groupServers(group *model.Group, all bool) []groupServer {
	var result []groupServer
	var subscriptions []string
	for _, name := range group.Subscriptions {
		if slices.Contains(subscriptions, name) {
			continue
		}
		subscriptions = append(subscriptions, name)
		if b.config.Subscription(name) == nil {
			b.warnOnce("group ", group.Name, ": there is no subscription ", name)
			continue
		}
		if len(b.options.Servers[name]) == 0 {
			b.warnOnce("subscription ", name, " has no servers yet")
			continue
		}
		tags := b.serverTags(name)
		for index, server := range b.options.Servers[name] {
			if (all || group.Takes(server.Name)) && b.serverOutbound(name, index) != nil {
				result = append(result, groupServer{subscription: name, index: index, tag: tags[index]})
			}
		}
	}
	return result
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

type groupServer struct {
	subscription string
	index        int
	tag          string
}

// warnOnce warns of what every section of a group would repeat.
func (b *builder) warnOnce(message ...any) {
	text := E.New(message...).Error()
	if !slices.Contains(b.warnings, text) {
		b.warnings = append(b.warnings, text)
	}
}

// sectionExit finds where the traffic of a section of the type group goes. A group that
// chooses no server does what its option "empty" says; a section it sends the traffic to
// instead may be one of the type group as well, and the way is followed to its end: path
// are the sections on the way so far.
func (b *builder) sectionExit(section *model.Section, path []string) (groupExit, error) {
	if exit, found := b.exits[section.Name]; found {
		return exit, nil
	}
	path = append(path, section.Name)
	// the build names the section it starts from (buildSections); a section reached through a
	// group with no server is named here
	where := ""
	if len(path) > 1 {
		where = "section " + section.Name + ": "
	}
	switch {
	case len(section.Groups) == 0:
		return groupExit{}, E.New(where, "the group is not set")
	case len(section.Groups) > 1:
		return groupExit{}, E.New(where, "a section takes one group so far")
	}
	group := b.config.Group(section.Groups[0])
	if group == nil {
		return groupExit{}, E.New(where, "there is no group ", section.Groups[0])
	}
	exit := groupExit{kind: exitServers, group: group.Name, servers: b.groupServers(group, false)}
	if len(exit.servers) == 0 {
		var err error
		exit, err = b.emptyExit(section, group, path)
		if err != nil {
			return groupExit{}, err
		}
	}
	b.exits[section.Name] = exit
	return exit, nil
}

// emptyExit is where a section goes when its group chooses no server.
func (b *builder) emptyExit(section *model.Section, group *model.Group, path []string) (groupExit, error) {
	switch group.Empty {
	case "all":
		exit := groupExit{kind: exitServers, group: group.Name, servers: b.groupServers(group, true)}
		if len(exit.servers) > 0 {
			b.warnOnce("group ", group.Name, ": no server of its subscriptions has a name it takes: all ", len(exit.servers), " are used")
			return exit, nil
		}
		b.warnOnce("group ", group.Name, ": its subscriptions have no servers: the connections of section ", section.Name, " are refused")
		return groupExit{kind: exitBlock}, nil
	case "section":
		name := group.EmptySection
		target := b.config.Section(name)
		switch {
		case name == "":
			return groupExit{}, E.New("group ", group.Name, ": the section for no server is not set")
		case target == nil:
			return groupExit{}, E.New("group ", group.Name, ": there is no section ", name, " for no server")
		case slices.Contains(path, name):
			return groupExit{}, E.New("the groups with no server lead round in a loop: ", strings.Join(append(path, name), " → "))
		case target.ConnectionType == "block":
			// the section may have been turned so after the group was set: it is followed
			b.warnOnce("group ", group.Name, " chooses no server, and section ", name, " refuses its connections: so does section ", section.Name)
			return groupExit{kind: exitBlock}, nil
		case target.ConnectionType == "exclusion":
			b.warnOnce("group ", group.Name, " chooses no server, and section ", name, " is an exclusion: the connections of section ", section.Name, " go directly")
			return groupExit{kind: exitDirect}, nil
		case !target.HasOutbound():
			return groupExit{}, E.New("group ", group.Name, ": the section ", name, " for no server is of the type ", target.ConnectionType, ", which has no outbound")
		}
		if target.ConnectionType == "group" {
			further, err := b.sectionExit(target, path)
			if err != nil {
				return groupExit{}, err
			}
			if further.kind == exitBlock {
				b.warnOnce("group ", group.Name, " chooses no server, and section ", name, " refuses its connections: so does section ", section.Name)
				return groupExit{kind: exitBlock}, nil
			}
		}
		b.warnOnce("group ", group.Name, " chooses no server: section ", section.Name, " goes as section ", name, " does")
		return groupExit{kind: exitSection, section: name}, nil
	case "direct":
		b.warnOnce("group ", group.Name, " chooses no server: the connections of section ", section.Name, " go directly")
		return groupExit{kind: exitDirect}, nil
	case "block":
		b.warnOnce("group ", group.Name, " chooses no server: the connections of section ", section.Name, " are refused")
		return groupExit{kind: exitBlock}, nil
	default:
		return groupExit{}, E.New("group ", group.Name, ": unknown choice for no server \"", group.Empty, "\"")
	}
}

// buildGroupSection makes the outbound of a section of the type group: a selector of its
// group and the servers of the group, the group first and chosen, as a section of URL tests
// has it; the dashboard switches it. The servers and the group are made once, whichever
// sections use them. A section whose connections are refused has a selector of the block
// outbound (isRefused). sing-box replaces these while it runs (Result.Swappable).
func (b *builder) buildGroupSection(section *model.Section) error {
	exit, err := b.sectionExit(section, nil)
	if err != nil {
		return err
	}
	var members []string
	switch exit.kind {
	case exitBlock:
		members = []string{tagBlockOutbound}
	case exitDirect:
		members = []string{tagDirectOutbound}
	case exitSection:
		members = []string{outboundTag(exit.section)}
	case exitServers:
		members = []string{b.addGroup(section, exit)}
		for _, server := range exit.servers {
			members = append(members, server.tag)
		}
	}
	b.outbounds = append(b.outbounds, newObject("type", "selector", "tag", outboundTag(section.Name), "outbounds", stringsToAny(members), "default", members[0]))
	b.swappable[outboundTag(section.Name)] = true
	return nil
}

// addGroup makes the servers of a group and the URL test of them once, and returns the tag
// of the test.
func (b *builder) addGroup(section *model.Section, exit groupExit) string {
	tag := exit.group + "-group"
	if b.groups[tag] {
		return tag
	}
	b.groups[tag] = true
	var members []string
	for _, server := range exit.servers {
		b.addServer(section, server)
		members = append(members, server.tag)
	}
	group := newObject("type", "urltest", "tag", tag, "outbounds", stringsToAny(members), "url", groupTestURL, "interval", groupTestInterval, "tolerance", groupTolerance)
	if b.options.DownloadURL != "" {
		group.set("download_url", b.options.DownloadURL)
	}
	b.outbounds = append(b.outbounds, group)
	b.swappable[tag] = true
	return tag
}

// addServer puts the outbound of a server of a subscription in once. The warnings about its
// link are told in the list of the subscription, not at every apply.
func (b *builder) addServer(section *model.Section, server groupServer) {
	if b.servers[server.tag] {
		return
	}
	b.servers[server.tag] = true
	b.swappable[server.tag] = true
	b.outbounds = append(b.outbounds, b.serverOutbound(server.subscription, server.index))
	b.links = append(b.links, Link{Section: section.Name, Name: server.tag, Tag: server.tag, Text: b.options.Servers[server.subscription][server.index].Link})
}

// isRefused tells whether the connections of a section are refused: a section of the type
// group whose group chose no server and says so. Its outbound is a selector of the block
// outbound: the lists are not downloaded through it.
func (b *builder) isRefused(section *model.Section) bool {
	return section.ConnectionType == "group" && b.exits[section.Name].kind == exitBlock
}

// sectionRoute is the route rule of a section: to its outbound.
func (b *builder) sectionRoute(section *model.Section, inbound string) *object {
	return newObject("action", "route", "inbound", inbound, "outbound", outboundTag(section.Name))
}
