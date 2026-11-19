package engine

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/domainset"
	"github.com/sagernet/sing-box/common/ruletext"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"go4.org/netipx"
)

// The formats of a rule-set file: sing-box's binary and source formats, and a list
// written as plain text (common/ruletext). A format left empty is the source format.
const (
	RuleSetFormatBinary = C.RuleSetFormatBinary
	RuleSetFormatSource = C.RuleSetFormatSource
	RuleSetFormatText   = C.RuleSetFormatText
)

// CheckRuleSet reads the content of a rule-set file as sing-box will read it, in its
// format, and tells whether sing-box takes it: a local rule set it cannot read stops the
// whole configuration. For a list written as text it also tells how many lines are left
// out, and the first of them.
func CheckRuleSet(format string, content []byte) (int, string, error) {
	if format == RuleSetFormatText {
		compat, skipped, err := ruletext.ReadAddresses(content)
		if err == nil {
			_, err = compat.Upgrade()
		}
		return skipped.Count, skipped.First, err
	}
	_, err := readRuleSet(format, content, false)
	return 0, "", err
}

// AddressRule is a rule of a rule set that names IPv4 destinations, as a firewall that
// hands sing-box what its rules could match sees it. Inverted rules name none.
type AddressRule struct {
	// Ranges are the IPv4 destinations the rule names, packed as the sets of sing-box keep
	// them (cidrset.Set.Ranges4): the first address in the high 32 bits, the last in the
	// low ones. They may be the slice of the set they were read from: not to be changed.
	Ranges []uint64
	// Ranges6 are the IPv6 destinations the rule names, in order.
	Ranges6 []netipx.IPRange
	// Nested tells that the rule is a part of a logical rule.
	Nested bool
	// Narrow tells that the rule has, besides its addresses, exactly one protocol and
	// destination ports and nothing else: Network ("tcp" or "udp") and Ports.
	Narrow  bool
	Network string
	Ports   []PortRange
}

// PortRange is a range of ports, both ends included.
type PortRange struct {
	From uint16
	To   uint16
}

// RuleSetAddresses reads the content of a rule-set file in its format and returns its
// rules that name addresses, in their order. The names of domains are not built: a rule
// keeps the first of them, which tell that it has some.
func RuleSetAddresses(format string, content []byte) ([]AddressRule, error) {
	rules, err := readRuleSet(format, content, true)
	if err != nil {
		return nil, err
	}
	var result []AddressRule
	collectAddresses(rules, false, &result)
	return result, nil
}

// readRuleSet reads a rule-set file as sing-box reads it; addresses: without building the
// names of its domains (the trie a list of the source format makes), for its addresses.
// The addresses come as sets of ranges (cidrset), as sing-box keeps them.
func readRuleSet(format string, content []byte, addresses bool) ([]option.HeadlessRule, error) {
	var compat option.PlainRuleSetCompat
	var err error
	switch {
	case format == RuleSetFormatBinary:
		compat, err = srs.ReadSets(bytes.NewReader(content))
	case format == RuleSetFormatText:
		// the domains are checked and counted, not built
		compat, _, err = ruletext.ReadAddresses(content)
	case addresses:
		compat, err = domainset.ReadSourceAddresses(content)
	default:
		compat, err = domainset.ReadSource(content)
	}
	if err != nil {
		return nil, err
	}
	ruleSet, err := compat.Upgrade()
	if err != nil {
		return nil, err
	}
	return ruleSet.Rules, nil
}

func collectAddresses(rules []option.HeadlessRule, nested bool, result *[]AddressRule) {
	for index := range rules {
		rule := &rules[index]
		if rule.Type == C.RuleTypeLogical {
			if !rule.LogicalOptions.Invert {
				collectAddresses(rule.LogicalOptions.Rules, true, result)
			}
			continue
		}
		fields := &rule.DefaultOptions
		if fields.Invert {
			continue
		}
		ranges, ranges6 := addresses(fields)
		if len(ranges) == 0 && len(ranges6) == 0 {
			continue
		}
		entry := AddressRule{Ranges: ranges, Ranges6: ranges6, Nested: nested}
		entry.Network, entry.Ports, entry.Narrow = portsOnly(fields)
		*result = append(*result, entry)
	}
}

// addresses returns the IPv4 destinations of a rule, packed (AddressRule.Ranges): the ranges
// of its set as the set keeps them, when that is all it has; written as text, they are read.
// And its IPv6 destinations (AddressRule.Ranges6), which only a set that has some copies.
func addresses(fields *option.DefaultHeadlessRule) (ranges []uint64, ranges6 []netipx.IPRange) {
	for _, text := range fields.IPCIDR {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			address, addressErr := netip.ParseAddr(text)
			if addressErr != nil {
				continue
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if prefix.Addr().Is4() {
			ranges = append(ranges, packRange(netipx.RangeOfPrefix(prefix.Masked())))
		} else if !prefix.Addr().Is4In6() {
			ranges6 = append(ranges6, netipx.RangeOfPrefix(prefix.Masked()))
		}
	}
	if fields.IPSet != nil {
		for _, item := range fields.IPSet.Ranges() {
			if item.From().Is4() {
				ranges = append(ranges, packRange(item))
			} else if !item.From().Is4In6() {
				ranges6 = append(ranges6, item)
			}
		}
	}
	if fields.IPRanges != nil {
		// the set keeps IPv4 first: what follows its IPv4 ranges is IPv6
		if four := fields.IPRanges.Ranges4(); fields.IPRanges.Len() > len(four) {
			ranges6 = append(ranges6, fields.IPRanges.Ranges()[len(four):]...)
		}
		if len(ranges) == 0 {
			return fields.IPRanges.Ranges4(), ranges6
		}
		ranges = append(ranges, fields.IPRanges.Ranges4()...)
	}
	return ranges, ranges6
}

func packRange(item netipx.IPRange) uint64 {
	from, to := item.From().As4(), item.To().As4()
	return uint64(binary.BigEndian.Uint32(from[:]))<<32 | uint64(binary.BigEndian.Uint32(to[:]))
}

// portsOnly tells whether the conditions of a rule besides its addresses are exactly one
// protocol and destination ports, and returns them.
func portsOnly(fields *option.DefaultHeadlessRule) (string, []PortRange, bool) {
	if len(fields.Network) != 1 || len(fields.Port) == 0 && len(fields.PortRange) == 0 {
		return "", nil, false
	}
	network := fields.Network[0]
	if network != "tcp" && network != "udp" {
		return "", nil, false
	}
	// anything else narrows the rule in a way the firewall does not express
	if len(fields.QueryType)+len(fields.Domain)+len(fields.DomainSuffix)+len(fields.DomainKeyword)+len(fields.DomainRegex)+
		len(fields.SourceIPCIDR)+len(fields.SourcePort)+len(fields.SourcePortRange)+len(fields.ProcessName)+len(fields.ProcessPath)+
		len(fields.ProcessPathRegex)+len(fields.PackageName)+len(fields.PackageNameRegex)+len(fields.NetworkType)+len(fields.WIFISSID)+len(fields.WIFIBSSID)+
		len(fields.DefaultInterfaceAddress) > 0 || fields.SourceIPSet != nil || fields.SourceIPRanges != nil || fields.DomainMatcher != nil || fields.DomainSet != nil || fields.AdGuardDomainMatcher != nil ||
		fields.NetworkIsExpensive || fields.NetworkIsConstrained || fields.NetworkInterfaceAddress != nil {
		return "", nil, false
	}
	var ports []PortRange
	for _, port := range fields.Port {
		ports = append(ports, PortRange{From: port, To: port})
	}
	for _, text := range fields.PortRange {
		// "from:to", either end may be left out
		fromText, toText, isRange := strings.Cut(text, ":")
		if !isRange {
			return "", nil, false
		}
		from, to := uint64(0), uint64(65535)
		var err error
		if fromText != "" {
			from, err = strconv.ParseUint(fromText, 10, 16)
			if err != nil {
				return "", nil, false
			}
		}
		if toText != "" {
			to, err = strconv.ParseUint(toText, 10, 16)
			if err != nil {
				return "", nil, false
			}
		}
		if from > to {
			return "", nil, false
		}
		ports = append(ports, PortRange{From: uint16(from), To: uint16(to)})
	}
	sort.Slice(ports, func(left int, right int) bool { return ports[left].From < ports[right].From })
	// ports that overlap or touch are one range: the interval set of nftables refuses
	// elements that overlap, and with them the whole update of the table
	merged := ports[:1]
	for _, next := range ports[1:] {
		last := &merged[len(merged)-1]
		if uint32(next.From) <= uint32(last.To)+1 {
			last.To = max(last.To, next.To)
			continue
		}
		merged = append(merged, next)
	}
	return network, merged, true
}
