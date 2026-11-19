// Package lists is what the backend does about lists besides writing them into the
// configuration: it tells the firewall which destinations the rule sets name. sing-box
// downloads every list given by URL, those written as plain text too (format text).
package lists

import (
	"fmt"
	"sort"

	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
	E "github.com/sagernet/sing/common/exceptions"

	"go4.org/netipx"
	"golang.org/x/sys/unix"
)

// Source is the content of one rule set: the bytes of its file, in its format
// (engine.RuleSetFormat*; the source format when empty).
type Source struct {
	Tag     string
	Format  string
	Content []byte
}

// Destinations is what the firewall has to send to the proxy by address, merged
// (firewall.Merge).
type Destinations struct {
	// Subnets go there whatever the port is; Subnets6 are those of IPv6 (firewall.Merge6).
	Subnets  []firewall.Range
	Subnets6 []netipx.IPRange
	// Groups go there for some ports of one protocol.
	Groups []firewall.Group
}

// Derive reads the rule sets and collects the addresses their rules name. sing-box
// matches a connection against the rules only when the firewall hands the connection to
// it, so every address a rule could match has to be in the firewall's sets.
//
// A rule that names addresses together with one protocol and ports, and nothing else,
// makes a group of its own: Discord's voice servers are a /12 of a CDN on UDP ports
// 19000 to 20000, and without the ports the whole /12 would go to the proxy. Any other
// rule gives its addresses to the common set, also when it has more conditions: more
// goes through sing-box than its rules take, and what they do not take leaves directly.
// Rules that are inverted name no addresses.
//
// It returns the tags of the rule sets that could not be read, with the reasons.
func Derive(sources []Source) (*Destinations, []error) {
	return DeriveWith(sources, func(source Source) ([]engine.AddressRule, error) {
		return engine.RuleSetAddresses(source.Format, source.Content)
	})
}

// DeriveWith is Derive with the rules of a rule set read by read: a caller that keeps what
// it read of a rule set that did not change reads only the ones that did.
func DeriveWith(sources []Source, read func(Source) ([]engine.AddressRule, error)) (*Destinations, []error) {
	var problems []error
	var subnets []firewall.Range
	var subnets6 []netipx.IPRange
	groups := make(map[string]*firewall.Group)
	for _, source := range sources {
		rules, err := read(source)
		if err != nil {
			problems = append(problems, E.Cause(err, "rule set ", source.Tag))
			continue
		}
		for _, rule := range rules {
			// the parts of a logical rule are not told apart: all their addresses are
			// for the common set
			if rule.Nested || !rule.Narrow {
				subnets = append(subnets, rule.Ranges...)
				subnets6 = append(subnets6, rule.Ranges6...)
				continue
			}
			protocol := byte(unix.IPPROTO_TCP)
			if rule.Network == "udp" {
				protocol = unix.IPPROTO_UDP
			}
			ports := make([]firewall.PortRange, len(rule.Ports))
			for index, port := range rule.Ports {
				ports[index] = firewall.PortRange{From: port.From, To: port.To}
			}
			key := fmt.Sprint(protocol, ports)
			group := groups[key]
			if group == nil {
				group = &firewall.Group{Protocol: protocol, Ports: ports}
				groups[key] = group
			}
			group.Ranges = append(group.Ranges, rule.Ranges...)
			group.Ranges6 = append(group.Ranges6, rule.Ranges6...)
		}
	}
	// merged here, in the copies collected above: the firewall takes them as they are, and
	// the plans of the firewall and what is kept of this derivation share one list
	result := &Destinations{Subnets: firewall.Merge(subnets), Subnets6: firewall.Merge6(subnets6)}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for index, key := range keys {
		group := groups[key]
		// the name tells the protocol; the ports are in the rule
		group.Set = fmt.Sprintf("podkop_subnets_%s_%d", protocolName(group.Protocol), index+1)
		group.Ranges = firewall.Merge(group.Ranges)
		group.Ranges6 = firewall.Merge6(group.Ranges6)
		result.Groups = append(result.Groups, *group)
	}
	return result, problems
}

func protocolName(protocol byte) string {
	if protocol == unix.IPPROTO_UDP {
		return "udp"
	}
	return "tcp"
}
