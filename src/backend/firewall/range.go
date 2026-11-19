package firewall

import (
	"encoding/binary"
	"math"
	"net/netip"
	"slices"

	"go4.org/netipx"
)

// Range is a range of IPv4 destinations, both ends included: the first address in the high
// 32 bits, the last in the low ones, as the address sets of sing-box keep them
// (cidrset.Set.Ranges4), so that the ranges of a list come here without a copy. Eight bytes
// and no pointer: a plan keeps those of every list for the life of a run, where a
// netip.Prefix took 32 bytes with a pointer the collector scans.
type Range = uint64

// RangeOf is the range of an IPv4 prefix; there is none of an IPv6 one.
func RangeOf(prefix netip.Prefix) (Range, bool) {
	if !prefix.Addr().Is4() {
		return 0, false
	}
	prefix = prefix.Masked()
	address := prefix.Addr().As4()
	from := binary.BigEndian.Uint32(address[:])
	return Range(from)<<32 | Range(from|uint32(uint64(1)<<(32-prefix.Bits())-1)), true
}

// RangesOf are the ranges of the IPv4 prefixes.
func RangesOf(prefixes []netip.Prefix) []Range {
	ranges := make([]Range, 0, len(prefixes))
	for _, prefix := range prefixes {
		if item, ok := RangeOf(prefix); ok {
			ranges = append(ranges, item)
		}
	}
	return ranges
}

// RangeString writes a range as a prefix when it is one, as "first-last" otherwise.
func RangeString(item Range) string {
	from, to := uint32(item>>32), uint32(item)
	size := uint64(to) - uint64(from) + 1
	if size&(size-1) == 0 && from&uint32(size-1) == 0 {
		bits := 32
		for value := size; value > 1; value >>= 1 {
			bits--
		}
		return netip.PrefixFrom(address4(from), bits).String()
	}
	return address4(from).String() + "-" + address4(to).String()
}

// RangeStrings writes ranges as RangeString does.
func RangeStrings(ranges []Range) []string {
	texts := make([]string, len(ranges))
	for index, item := range ranges {
		texts[index] = RangeString(item)
	}
	return texts
}

func address4(value uint32) netip.Addr {
	var address [4]byte
	binary.BigEndian.PutUint32(address[:], value)
	return netip.AddrFrom4(address)
}

// Merge makes the ranges one list in order: overlapping and adjacent ones become one range.
// The kernel takes ranges that do not overlap, and the merging the nft program offers
// ("auto-merge") is done by that program, not by the kernel. The ranges are sorted and
// merged where they are, so the slice is the caller's no more; a list that merges into far
// fewer ranges (many /32s) is copied, so that the long one can be let go.
func Merge(ranges []Range) []Range {
	// by the first address, then by the last: the high half, then the low one
	slices.Sort(ranges)
	kept := ranges[:0]
	for _, item := range ranges {
		if last := len(kept) - 1; last >= 0 {
			lastTo := uint32(kept[last])
			if lastTo == math.MaxUint32 || uint32(item>>32) <= lastTo+1 {
				if uint32(item) > lastTo {
					kept[last] = kept[last]&^math.MaxUint32 | Range(uint32(item))
				}
				continue
			}
		}
		kept = append(kept, item)
	}
	if len(kept) == 0 {
		return nil
	}
	if len(kept) < cap(ranges)/2 {
		return slices.Clone(kept)
	}
	return kept
}

// IsMerged tells whether ranges are as Merge leaves them: in order, and none overlaps or
// touches the next.
func IsMerged(ranges []Range) bool {
	for index, item := range ranges {
		if uint32(item>>32) > uint32(item) {
			return false
		}
		if index > 0 {
			previousTo := uint32(ranges[index-1])
			if previousTo == math.MaxUint32 || uint32(item>>32) <= previousTo+1 {
				return false
			}
		}
	}
	return true
}

// Merge6 makes IPv6 ranges one list in order, as Merge does IPv4 ones: overlapping and
// adjacent ones become one range. Ranges of IPv4 among them are left out.
func Merge6(ranges []netipx.IPRange) []netipx.IPRange {
	var builder netipx.IPSetBuilder
	for _, item := range ranges {
		if item.IsValid() && item.From().Is6() {
			builder.AddRange(item)
		}
	}
	set, err := builder.IPSet()
	if err != nil {
		return nil
	}
	if merged := set.Ranges(); len(merged) > 0 {
		return merged
	}
	return nil
}
