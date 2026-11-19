// Package firewall keeps the nftables table of the backend over netlink, without the nft
// program: the table, the sets, the chains and the rules the shell backend of podkop
// makes with some forty runs of nft, and the filling of the set of subnets.
//
// The table is the one that backend makes, rule by rule: `nft list table` prints the same
// text for both (the test compares them).
package firewall

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
	E "github.com/sagernet/sing/common/exceptions"

	"go4.org/netipx"
	"golang.org/x/sys/unix"
)

const (
	tableName     = dataplane.FirewallTable
	SetLocal      = "localv4"
	SetSubnets    = "podkop_subnets"
	SetInterfaces = "interfaces"
	// the sets of IPv6, there while IPv6 goes through podkop (Plan.IPv6); the set of IPv6 of a
	// group is named as the group's with suffix6
	SetLocal6   = "localv6"
	SetSubnets6 = "podkop_subnets_v6"
	suffix6     = "_v6"

	markProxy    = dataplane.ProxyMark
	markRouter   = dataplane.RouterMark
	markOutbound = dataplane.OutboundMark
	portTProxy   = dataplane.TProxyPort
	// the bit of a connection's status that says its destination was rewritten
	// (IPS_DST_NAT of the kernel's nf_conntrack_common.h)
	statusDNAT = 1 << 5
	// the direction of a packet that answers the one that began its connection, and of one that
	// goes the way of the packet that began it (IP_CT_DIR_REPLY and IP_CT_DIR_ORIGINAL of the
	// kernel's nf_conntrack_tuple_common.h)
	ctDirectionReply    = 1
	ctDirectionOriginal = 0
)

// clashAPIPriority is that of the chain clash_api: before fw4's input chain (filter, 0)
const clashAPIPriority = -1

// the numbers the sets go by inside the transaction that makes them
const (
	idLocal = iota + 1
	idSubnets
	idInterfaces
	// the sets of the groups take the numbers after these
)

var (
	rangeFakeIP   = dataplane.FakeIPPrefix
	addressProxy  = netip.MustParseAddr(dataplane.TProxyAddress)
	addressProxy6 = netip.MustParseAddr(dataplane.TProxyAddress6)
	// what of IPv6 never goes to the proxy, from the LAN or from the router itself: the
	// unspecified address and the loopback, IPv4 in IPv6 forms, NAT64's prefix, the prefix
	// of discards, documentation, the unique local addresses, the link-local ones, multicast
	localRanges6 = []netipx.IPRange{
		netipx.RangeOfPrefix(netip.MustParsePrefix("::/127")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("::ffff:0:0/96")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("64:ff9b::/96")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("64:ff9b:1::/48")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("100::/64")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("2001:db8::/32")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("fc00::/7")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("fe80::/10")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("ff00::/8")),
	}
	// what never goes to the proxy from the router itself
	localRanges = []netipx.IPRange{
		netipx.RangeOfPrefix(netip.MustParsePrefix("0.0.0.0/8")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("10.0.0.0/8")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("127.0.0.0/8")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("169.254.0.0/16")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("172.16.0.0/12")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("192.0.0.0/24")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("192.0.2.0/24")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("192.88.99.0/24")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("192.168.0.0/16")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("198.51.100.0/24")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("203.0.113.0/24")),
		netipx.RangeOfPrefix(netip.MustParsePrefix("224.0.0.0/4")),
		netipx.IPRangeFrom(netip.MustParseAddr("240.0.0.0"), netip.MustParseAddr("255.255.255.255")),
	}
)

// netlinkDeadline bounds how long a transaction of the table waits for the kernel's
// answers. A refill of the sets of a million subnets never ended twice in 37 runs of the
// stand, holding the goroutine of the backend for good: no apply, no update, no answer to
// the page. With the bound the refill fails and is logged, and the next one sets the whole
// table up.
const netlinkDeadline = time.Minute

// netlinkReadBuffer is the receive buffer asked for a netlink connection of the firewall (the
// kernel gives twice what is asked). The kernel answers a transaction once it has taken all of
// it: an acknowledgement of every message, and every rule back (the library asks for the echo, to
// learn the rule's handle), all queued on the socket before the first is read. The default buffer
// (212992 bytes on nexus) held the answers to the table up to 0.8.18, and not to the table with
// the detector's limits of 0.8.19: "netlink receive: recvmsg: no buffer space available", and no
// table. A table with more rules for any other reason would have met the same. 2 MiB asked: twenty
// times the default; only what is queued takes memory. (A variable for the test that measures
// what the table needs.)
var netlinkReadBuffer = 2 << 20

// newConn is a netlink connection of nftables whose reads end at netlinkDeadline and whose
// receive buffer is netlinkReadBuffer; a connection that is not lasting dials anew at every
// flush, and both with it.
func newConn() (*nftables.Conn, error) {
	return nftables.New(nftables.WithSockOptions(func(conn *netlink.Conn) error {
		readBuffer(conn)
		return conn.SetReadDeadline(time.Now().Add(netlinkDeadline))
	}))
}

// readBuffer gives a connection netlinkReadBuffer: past the system's limit when the process may
// (the backend runs as root), else as much of it as the limit allows.
func readBuffer(conn *netlink.Conn) {
	if raw, err := conn.SyscallConn(); err == nil {
		forced := false
		_ = raw.Control(func(fd uintptr) {
			forced = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, netlinkReadBuffer) == nil
		})
		if forced {
			return
		}
	}
	_ = conn.SetReadBuffer(netlinkReadBuffer)
}

// Plan is the whole table: what its rules depend on and what its sets hold.
type Plan struct {
	// Interfaces are the interfaces traffic is taken from.
	Interfaces []string
	// ExcludeNTP leaves UDP port 123 alone.
	ExcludeNTP bool
	// Sources are devices of the LAN whose traffic goes to the proxy whatever its
	// destination is, the local networks excepted.
	Sources []netip.Prefix
	// Subnets are the destinations that go to the proxy by address.
	Subnets []Range
	// Groups are destinations that go to the proxy only for some ports.
	Groups []Group
	// ClashAPIInterfaces are the devices that reach the Clash API, which listens on every
	// address while YACD is on: a chain of the input lets their connections to its port in,
	// and those of the router itself (lo), and drops the others. None: no such chain, the
	// API listens on this host only.
	ClashAPIInterfaces []string
	// BitTorrent is what becomes of the traffic of BitTorrent clients (bittorrent_linux.go).
	BitTorrent BitTorrent
	// IPv6 sends the IPv6 traffic to Subnets6 (and to the IPv6 ranges of the groups) to the
	// proxy, from the LAN and from the router itself, as IPv4 to Subnets. Without it the table
	// has nothing of IPv6, and IPv6 goes past the proxy.
	IPv6     bool
	Subnets6 []netipx.IPRange

	// the ranges of Subnets, merged once
	subnets merged
}

// merged keeps the ranges a list of ranges merged into: a plan that is the previous one of
// an update has them from when it was the next one.
type merged struct {
	done   bool
	ranges []Range
}

func rangesOfIPRanges(ranges []netipx.IPRange) []Range {
	result := make([]Range, 0, len(ranges))
	for _, item := range ranges {
		if item.From().Is4() {
			from, to := item.From().As4(), item.To().As4()
			result = append(result, Range(binary.BigEndian.Uint32(from[:]))<<32|Range(binary.BigEndian.Uint32(to[:])))
		}
	}
	return result
}

// of returns the ranges merged: those of a plan made from lists.Derive are merged already
// and are taken as they are, any others are merged in a copy (the plan's are not changed).
func (m *merged) of(ranges []Range) []Range {
	if !m.done {
		m.ranges = ranges
		if !IsMerged(ranges) {
			m.ranges = Merge(slices.Clone(ranges))
		}
		m.done = true
	}
	return m.ranges
}

// Group is a set of destinations with a condition of its own.
type Group struct {
	// Set is the name of the nftables set.
	Set string
	// Protocol is unix.IPPROTO_UDP or unix.IPPROTO_TCP.
	Protocol byte
	// Ports are the destination ports the group is about.
	Ports  []PortRange
	Ranges []Range
	// Ranges6 are the IPv6 destinations of the group (Plan.IPv6), merged (Merge6).
	Ranges6 []netipx.IPRange

	spans merged
}

// PortRange is a range of ports, both ends included.
type PortRange struct {
	From uint16
	To   uint16
}

// structure tells the rules of two plans apart: everything but what the sets hold.
func (p *Plan) structure() string {
	var text strings.Builder
	fmt.Fprint(&text, p.Interfaces, p.ExcludeNTP, p.Sources, p.ClashAPIInterfaces, p.BitTorrent, p.IPv6)
	for _, group := range p.Groups {
		fmt.Fprint(&text, group.Set, group.Protocol, group.Ports)
	}
	return text.String()
}

// Update brings the table from what a previous call made to the plan. Rules that changed
// replace the table whole; a set that changed is brought to its new content by what
// differs (updateSet), with the rules left as they are, counters included. With no
// previous plan the table is made anew, whatever is there.
func Update(previous *Plan, next *Plan) error {
	if previous == nil || previous.structure() != next.structure() {
		return Apply(next)
	}
	err := updateSet(SetSubnets, previous.subnets.of(previous.Subnets), next.subnets.of(next.Subnets))
	if err != nil {
		return err
	}
	for index := range next.Groups {
		before, after := &previous.Groups[index], &next.Groups[index]
		err = updateSet(after.Set, before.spans.of(before.Ranges), after.spans.of(after.Ranges))
		if err != nil {
			return err
		}
	}
	if !next.IPv6 {
		return nil
	}
	// the sets of IPv6 are small (the lists name few IPv6 subnets): one that changed is filled
	// anew, in one transaction
	if !slices.Equal(previous.Subnets6, next.Subnets6) {
		err = replaceRanges6(SetSubnets6, next.Subnets6)
		if err != nil {
			return err
		}
	}
	for index := range next.Groups {
		before, after := &previous.Groups[index], &next.Groups[index]
		if !slices.Equal(before.Ranges6, after.Ranges6) {
			err = replaceRanges6(after.Set+suffix6, after.Ranges6)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// fillLot is the most ranges a set takes in one transaction when it is filled whole. The
// kernel holds a transaction until it is committed, and the netlink library holds the
// messages of one until it is sent: a set of a hundred thousand ranges filled at once
// took a router with 128 MB to the OOM killer. A set of no more
// ranges than this is filled at once, a packet seeing it whole or not at all; a bigger
// one is half filled for a moment.
const fillLot = 10000

// updateSet brings a set from the ranges it was filled with to the next ones by what
// differs: the ranges that went are deleted and the ranges that came are added, in one
// transaction, so that a change of a few items is a few elements however big the set
// is, and a packet sees the old set or the new one. A change of more than fillLot ranges,
// or a set the kernel does not have as the previous ranges say, is filled anew.
func updateSet(name string, before []Range, after []Range) error {
	if slices.Equal(before, after) {
		return nil
	}
	gone, came, few := rangesDifferUpTo(before, after, fillLot)
	if few {
		conn, err := newConn()
		if err != nil {
			return E.Cause(err, "open netlink")
		}
		set := &nftables.Set{Table: &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}, Name: name, Interval: true, AutoMerge: true, KeyType: nftables.TypeIPAddr}
		err = deleteElements(conn, set, intervals(gone))
		if err == nil {
			err = addElements(conn, set, intervals(came))
		}
		if err == nil {
			err = conn.Flush()
		}
		if err == nil {
			return nil
		}
	}
	return replaceRanges(name, after, fillLot)
}

// rangesDiffer returns the ranges of before that after does not have, and those of
// after that before does not have. Both are in order and do not overlap, as Merge makes
// them: one walk through the two.
func rangesDiffer(before []Range, after []Range) (gone []Range, came []Range) {
	gone, came, _ = rangesDifferUpTo(before, after, -1)
	return gone, came
}

// rangesDifferUpTo is rangesDiffer that gives up once more than limit ranges differ (a
// negative limit: never), and then returns none: the set is filled anew, and a big list
// changed whole is not held a third time meanwhile.
func rangesDifferUpTo(before []Range, after []Range, limit int) (gone []Range, came []Range, few bool) {
	for i, j := 0, 0; i < len(before) || j < len(after); {
		if limit >= 0 && len(gone)+len(came) > limit {
			return nil, nil, false
		}
		switch {
		case j == len(after):
			gone = append(gone, before[i])
			i++
		case i == len(before):
			came = append(came, after[j])
			j++
		case before[i] == after[j]:
			i++
			j++
		default:
			// by the first address, the high half
			order := cmp.Compare(before[i]>>32, after[j]>>32)
			if order <= 0 {
				gone = append(gone, before[i])
				i++
			}
			if order >= 0 {
				came = append(came, after[j])
				j++
			}
		}
	}
	if limit >= 0 && len(gone)+len(came) > limit {
		return nil, nil, false
	}
	return gone, came, true
}

// Apply makes the table anew, in one transaction: what a previous run left is replaced
// whole, and the kernel never has a half of it.
func Apply(plan *Plan) error {
	// what the detector of BitTorrent learned goes into the new table (bitTorrentKept), read
	// before the transaction that replaces the old one
	var kept map[string][]nftables.SetElement
	if plan.BitTorrent.Mode != "" {
		kept = bitTorrentKept()
		// no table (a start): what the last stop saved
		if len(kept) == 0 {
			kept = loadBitTorrentSets(time.Now())
		}
	}
	conn, err := newConn()
	if err != nil {
		return E.Cause(err, "open netlink")
	}
	table := &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}
	// a table that is added and deleted in the same transaction: deleting one that is
	// not there would fail the whole of it
	conn.AddTable(table)
	conn.DelTable(table)
	conn.AddTable(table)

	var builder netipx.IPSetBuilder
	for _, item := range localRanges {
		builder.AddRange(item)
	}
	local, err := builder.IPSet()
	if err != nil {
		return err
	}
	localRangesMerged := rangesOfIPRanges(local.Ranges())
	nextID := uint32(idInterfaces)
	// what a set of more than fillLot ranges holds beyond them, added after the table is
	// there
	type rest struct {
		set    *nftables.Set
		ranges []Range
	}
	var later []rest
	addSet := func(name string, id uint32, ranges []Range) error {
		set := &nftables.Set{Table: table, ID: id, Name: name, Interval: true, AutoMerge: true, KeyType: nftables.TypeIPAddr}
		err := conn.AddSet(set, nil)
		if err != nil {
			return E.Cause(err, "add the set ", name)
		}
		if len(ranges) > fillLot {
			later = append(later, rest{&nftables.Set{Table: table, Name: name, Interval: true, AutoMerge: true, KeyType: nftables.TypeIPAddr}, ranges[fillLot:]})
			ranges = ranges[:fillLot]
		}
		return addElements(conn, set, intervals(ranges))
	}
	err = addSet(SetLocal, idLocal, localRangesMerged)
	if err != nil {
		return err
	}
	err = addSet(SetSubnets, idSubnets, plan.subnets.of(plan.Subnets))
	if err != nil {
		return err
	}
	var names []nftables.SetElement
	for _, name := range plan.Interfaces {
		// an interval set of names, as the shell backend has it: a name is the range
		// from itself to the next value
		names = append(names, nftables.SetElement{Key: interfaceName(name, 0)}, nftables.SetElement{Key: interfaceName(name, 1), IntervalEnd: true})
	}
	interfaceSet := &nftables.Set{Table: table, ID: idInterfaces, Name: SetInterfaces, Interval: true, KeyType: nftables.TypeIFName}
	err = conn.AddSet(interfaceSet, names)
	if err != nil {
		return E.Cause(err, "add the set ", SetInterfaces)
	}
	// the sets of IPv6, small: filled at once
	addSet6 := func(name string, ranges []netipx.IPRange) (uint32, error) {
		nextID++
		set := &nftables.Set{Table: table, ID: nextID, Name: name, Interval: true, AutoMerge: true, KeyType: nftables.TypeIP6Addr}
		err := conn.AddSet(set, nil)
		if err != nil {
			return 0, E.Cause(err, "add the set ", name)
		}
		return nextID, addElements(conn, set, intervals6(ranges))
	}
	var idLocal6, idSubnets6 uint32
	if plan.IPv6 {
		idLocal6, err = addSet6(SetLocal6, Merge6(slices.Clone(localRanges6)))
		if err == nil {
			idSubnets6, err = addSet6(SetSubnets6, plan.Subnets6)
		}
		if err != nil {
			return err
		}
	}

	accept := nftables.ChainPolicyAccept
	mangle := conn.AddChain(&nftables.Chain{Name: "mangle", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityMangle, Policy: &accept})
	mangleOutput := conn.AddChain(&nftables.Chain{Name: "mangle_output", Table: table, Type: nftables.ChainTypeRoute, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityMangle, Policy: &accept})
	proxy := conn.AddChain(&nftables.Chain{Name: "proxy", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Policy: &accept})
	add := func(chain *nftables.Chain, parts ...[]expr.Any) {
		var all []expr.Any
		for _, part := range parts {
			all = append(all, part...)
		}
		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: all})
	}
	fromInterfaces := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: SetInterfaces, SetID: idInterfaces},
	}
	toSubnets := append(ipv4(), addressIn(offsetDestination, SetSubnets, idSubnets)...)
	toFakeIP := append(ipv4(), addressWithin(offsetDestination, rangeFakeIP)...)
	markWith := func(value uint32) []expr.Any {
		return []expr.Any{
			&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(value)},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
			&expr.Counter{},
		}
	}
	mark := markWith(markProxy)
	returns := []expr.Any{&expr.Verdict{Kind: expr.VerdictReturn}}
	transports := []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP}

	// mangle: what comes from the LAN. First the replies of a connection that did not begin on
	// the LAN (a port forward, UPnP: one the router forwards to a device): no traffic of the
	// device's own, and the proxy cannot take a connection on the run. The shell backend had only
	// the return of DNAT, below the rules of the devices routed whole, so the reply of such a device
	// was marked for the proxy, and a forwarded TCP connection to it never came up (the stand of
	// lab/bt16/fwd.sh, 2026-11-15: a timeout with the device routed whole, an answer without). By
	// the direction, not the DNAT: a connection of the device itself that a rule of fw4 redirects
	// (DNAT) has it from its second packet on, after its first went to the proxy.
	add(mangle, []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{ctDirectionReply}},
	}, returns)
	// The shell backend puts the rules of a device on top of the chain one device after another,
	// so the last device comes first.
	for index := len(plan.Sources) - 1; index >= 0; index-- {
		fromDevice := append(ipv4(), addressWithin(offsetSource, plan.Sources[index])...)
		add(mangle, fromDevice, addressIn(offsetDestination, SetLocal, idLocal), returns)
		add(mangle, fromInterfaces, fromDevice, protocol(unix.IPPROTO_UDP), mark)
		add(mangle, fromInterfaces, fromDevice, protocol(unix.IPPROTO_TCP), mark)
	}
	if plan.ExcludeNTP {
		add(mangle, protocol(unix.IPPROTO_UDP), destinationPort(123), returns)
	}
	add(mangle, []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATUS},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(statusDNAT), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
	}, returns)
	for _, destination := range [][]expr.Any{toSubnets, toFakeIP} {
		for _, transport := range transports {
			add(mangle, fromInterfaces, destination, protocol(transport), mark)
		}
	}
	// IPv6 to the subnets of the lists, as IPv4 (FakeIP has no IPv6 range)
	toSubnets6 := append(ipv6(), address6In(offset6Destination, SetSubnets6, idSubnets6)...)
	if plan.IPv6 {
		for _, transport := range transports {
			add(mangle, fromInterfaces, toSubnets6, protocol(transport), mark)
		}
	}
	// proxy: what is marked goes to the transparent proxy inbound (BitTorrent to its own inbounds
	// first, by the conntrack mark of the detector); what the router sent comes here through the
	// loopback with its own mark
	if plan.BitTorrent.Mode != "" {
		addBitTorrentProxy(add, proxy, plan.BitTorrent)
	}
	for _, value := range []uint32{markProxy, markRouter} {
		for _, transport := range transports {
			add(proxy, []expr.Any{
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(value), Xor: binaryutil.NativeEndian.PutUint32(0)},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(value)},
			}, protocol(transport), []expr.Any{
				&expr.Immediate{Register: 1, Data: addressProxy.AsSlice()},
				&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(portTProxy)},
				&expr.TProxy{Family: byte(nftables.TableFamilyIPv4), TableFamily: byte(nftables.TableFamilyINet), RegAddr: 1, RegPort: 2},
				&expr.Counter{},
			})
		}
	}
	// IPv6 to the inbound of IPv6 (a socket of 127.0.0.1 takes no IPv6 packet: the rules above
	// do not act on one)
	if plan.IPv6 {
		for _, value := range []uint32{markProxy, markRouter} {
			for _, transport := range transports {
				add(proxy, []expr.Any{
					&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
					&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(value), Xor: binaryutil.NativeEndian.PutUint32(0)},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(value)},
				}, protocol(transport), []expr.Any{
					&expr.Immediate{Register: 1, Data: addressProxy6.AsSlice()},
					&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(portTProxy)},
					&expr.TProxy{Family: byte(nftables.TableFamilyIPv6), TableFamily: byte(nftables.TableFamilyINet), RegAddr: 1, RegPort: 2},
					&expr.Counter{},
				})
			}
		}
	}
	// mangle_output: the same marking for what the router itself sends, with the mark of
	// the router (dataplane.RouterMark)
	add(mangleOutput, ipv4(), addressIn(offsetDestination, SetLocal, idLocal), returns)
	// what sing-box opens itself, and a tunnel of the router with the mark as its own
	// (dataplane.OutboundMark), under the mask: mwan3 adds its bits to the mark
	add(mangleOutput, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(markOutbound), Xor: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(markOutbound)},
		&expr.Counter{},
	}, returns)
	// the programs of the router that run as a user the settings name for BitTorrent (bt_router)
	if plan.BitTorrent.Mode != "" && len(plan.BitTorrent.RouterUsers) > 0 {
		router := addBitTorrentRouter(conn, table, add, plan.BitTorrent)
		for _, user := range plan.BitTorrent.RouterUsers {
			// (IPv4 alone, as the detector: the addresses that are local were told above for it)
			add(mangleOutput, ipv4(), []expr.Any{
				&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(user)},
				&expr.Verdict{Kind: expr.VerdictJump, Chain: router.Name},
			})
		}
		// and by the connection: what the kernel still sends for a socket the client has closed
		// (the last ACK, a FIN again, data left in the queue) has no owner to tell it by, and left
		// directly, from the router's own address, where the connection went through the rule
		// (TCP and UDP only: an ICMP error the router sends about a device's flow is related to that
		// flow and carries its mark); and the answers of a connection from outside to the client
		// (bt_router's mark of it), whose socket is closed
		if plan.BitTorrent.Mode != BitTorrentBlock {
			for _, transport := range transports {
				add(mangleOutput, ipv4(), protocol(transport), []expr.Any{
					&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{ctDirectionOriginal}},
				}, ctMarkTest(ctBitTorrent, expr.CmpOpNeq), []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: router.Name}})
			}
			add(mangleOutput, ipv4(), []expr.Any{
				&expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{ctDirectionReply}},
			}, ctMarkAll(dataplane.BitTorrentInboundCt), []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: router.Name}})
		}
	}
	// the NTP of the router itself (sysntpd, the clock check of the backend) never goes to
	// the proxy, whose TLS or REALITY a wrong clock breaks: through it the clock would never
	// be set. A FakeIP address has no other way than sing-box; the DNS gives the names of
	// the NTP servers their own addresses (plan, ledger item 16).
	add(mangleOutput, ipv4(), addressNotWithin(offsetDestination, rangeFakeIP), protocol(unix.IPPROTO_UDP), destinationPort(123), returns)
	for _, destination := range [][]expr.Any{toSubnets, toFakeIP} {
		for _, transport := range transports {
			add(mangleOutput, destination, protocol(transport), markWith(markRouter))
		}
	}
	// the router's own IPv6, as its IPv4: nothing local, nothing of sing-box (the return of
	// the mark above has no family), not its NTP
	if plan.IPv6 {
		add(mangleOutput, ipv6(), address6In(offset6Destination, SetLocal6, idLocal6), returns)
		add(mangleOutput, ipv6(), protocol(unix.IPPROTO_UDP), destinationPort(123), returns)
		for _, transport := range transports {
			add(mangleOutput, toSubnets6, protocol(transport), markWith(markRouter))
		}
	}
	// the groups: a set each, and a rule of the LAN chain with the ports of the group
	for index := range plan.Groups {
		group := &plan.Groups[index]
		nextID++
		groupID := nextID
		err = addSet(group.Set, groupID, group.spans.of(group.Ranges))
		if err != nil {
			return err
		}
		var ports []nftables.SetElement
		for _, item := range group.Ports {
			ports = append(ports, nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(item.From)})
			// nothing follows port 65535: such a range has no end element
			if item.To < 65535 {
				ports = append(ports, nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(item.To + 1), IntervalEnd: true})
			}
		}
		nextID++
		portSet := &nftables.Set{Table: table, ID: nextID, Name: "__set%d", Anonymous: true, Constant: true, Interval: true, KeyType: nftables.TypeInetService}
		err = conn.AddSet(portSet, ports)
		if err != nil {
			return E.Cause(err, "add the ports of the set ", group.Set)
		}
		add(mangle, fromInterfaces, ipv4(), addressIn(offsetDestination, group.Set, groupID), protocol(group.Protocol), []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Lookup{SourceRegister: 1, SetName: portSet.Name, SetID: portSet.ID},
		}, mark)
		if !plan.IPv6 {
			continue
		}
		// the IPv6 of the group: a set of its own, and an anonymous set of the ports of its own
		// (one belongs to one rule)
		groupID6, err := addSet6(group.Set+suffix6, group.Ranges6)
		if err != nil {
			return err
		}
		nextID++
		portSet6 := &nftables.Set{Table: table, ID: nextID, Name: "__set%d", Anonymous: true, Constant: true, Interval: true, KeyType: nftables.TypeInetService}
		err = conn.AddSet(portSet6, ports)
		if err != nil {
			return E.Cause(err, "add the ports of the set ", group.Set+suffix6)
		}
		add(mangle, fromInterfaces, ipv6(), address6In(offset6Destination, group.Set+suffix6, groupID6), protocol(group.Protocol), []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Lookup{SourceRegister: 1, SetName: portSet6.Name, SetID: portSet6.ID},
		}, mark)
	}
	// the BitTorrent detector, after the sets of the groups
	if plan.BitTorrent.Mode != "" {
		err = addBitTorrent(conn, table, plan, add, &nextID, kept)
		if err != nil {
			return E.Cause(err, "add the BitTorrent detector")
		}
	}
	// clash_api: the port of the Clash API from the devices of YACD and from the router
	// itself; before the input chain of fw4, whose rules then go on as they would
	if len(plan.ClashAPIInterfaces) > 0 {
		guard := conn.AddChain(&nftables.Chain{Name: "clash_api", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityRef(clashAPIPriority), Policy: &accept})
		toAPI := func() []expr.Any {
			return append(protocol(unix.IPPROTO_TCP), destinationPort(dataplane.ClashAPIPort)...)
		}
		for _, name := range append([]string{"lo"}, plan.ClashAPIInterfaces...) {
			add(guard, toAPI(), []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: interfaceName(name, 0)},
			}, returns)
		}
		add(guard, toAPI(), []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}})
	}
	err = conn.Flush()
	if err != nil {
		return E.Cause(err, "apply the table")
	}
	for _, item := range later {
		for len(item.ranges) > 0 {
			count := min(fillLot, len(item.ranges))
			err = addElements(conn, item.set, intervals(item.ranges[:count]))
			if err == nil {
				err = conn.Flush()
			}
			if err != nil {
				return E.Cause(err, "fill the set ", item.set.Name)
			}
			item.ranges = item.ranges[count:]
		}
	}
	return nil
}

// Remove deletes the table; one that is not there is no error. What the sets of the detector of
// BitTorrent hold is saved first (saveBitTorrentSets), for the next start.
func Remove() error {
	saveBitTorrentSets(time.Now())
	conn, err := newConn()
	if err != nil {
		return E.Cause(err, "open netlink")
	}
	table := &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}
	conn.AddTable(table)
	conn.DelTable(table)
	return conn.Flush()
}

// ReplaceSet makes a set of the table hold exactly these ranges.
//
// With lot zero the set is emptied and filled in one transaction: a packet sees the old
// set or the new one. A positive lot sends that many ranges a transaction, which bounds
// what the kernel holds at once at the price of a set that is half filled for a moment.
// It returns the number of ranges the set holds.
func ReplaceSet(name string, ranges []Range, lot int) (int, error) {
	ranges = Merge(slices.Clone(ranges))
	return len(ranges), replaceRanges(name, ranges, lot)
}

func replaceRanges(name string, ranges []Range, lot int) error {
	conn, err := newConn()
	if err != nil {
		return E.Cause(err, "open netlink")
	}
	set := &nftables.Set{Table: &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}, Name: name, Interval: true, AutoMerge: true, KeyType: nftables.TypeIPAddr}
	conn.FlushSet(set)
	// the elements of a lot are made as it is sent: those of a whole list at once take a
	// few hundred bytes a range, tens of megabytes for a big list
	for len(ranges) > 0 {
		count := len(ranges)
		if lot > 0 {
			count = min(lot, count)
		}
		err = addElements(conn, set, intervals(ranges[:count]))
		if err != nil {
			return err
		}
		ranges = ranges[count:]
		if len(ranges) > 0 {
			err = conn.Flush()
			if err != nil {
				return E.Cause(err, "fill the set ", name)
			}
		}
	}
	err = conn.Flush()
	if err != nil {
		return E.Cause(err, "fill the set ", name)
	}
	return nil
}

// addElements queues the elements of a set. The library puts the elements of a call into
// one netlink message, and a message holds 64 KiB of them at most: the list is cut here.
// The messages still belong to one transaction.
func addElements(conn *nftables.Conn, set *nftables.Set, elements []nftables.SetElement) error {
	for len(elements) > 0 {
		count := min(elementsPerMessage, len(elements))
		err := conn.SetAddElements(set, elements[:count])
		if err != nil {
			return E.Cause(err, "add to the set ", set.Name)
		}
		elements = elements[count:]
	}
	return nil
}

// deleteElements queues the deletion of elements of a set, as addElements their addition.
func deleteElements(conn *nftables.Conn, set *nftables.Set, elements []nftables.SetElement) error {
	for len(elements) > 0 {
		count := min(elementsPerMessage, len(elements))
		err := conn.SetDeleteElements(set, elements[:count])
		if err != nil {
			return E.Cause(err, "delete from the set ", set.Name)
		}
		elements = elements[count:]
	}
	return nil
}

// elementsPerMessage keeps a message of set elements well under the 64 KiB a netlink
// attribute can be: an element of an IPv4 set takes about twenty bytes.
const elementsPerMessage = 1000

// intervals writes ranges the way the kernel keeps an interval set: the first address of
// a range, and the address after its last one marked as an end.
func intervals(ranges []Range) []nftables.SetElement {
	elements := make([]nftables.SetElement, 0, 2*len(ranges))
	for _, item := range ranges {
		from, to := uint32(item>>32), uint32(item)
		elements = append(elements, nftables.SetElement{Key: binaryutil.BigEndian.PutUint32(from)})
		// nothing follows 255.255.255.255: such a range has no end element
		if to != math.MaxUint32 {
			elements = append(elements, nftables.SetElement{Key: binaryutil.BigEndian.PutUint32(to + 1), IntervalEnd: true})
		}
	}
	return elements
}

// interfaceName is the key of a name in a set of interface names, sixteen bytes, with a
// number added to it as to one big number.
func interfaceName(name string, add byte) []byte {
	key := make([]byte, unix.IFNAMSIZ)
	copy(key, name)
	key[len(key)-1] += add
	return key
}

func protocol(number byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{number}},
	}
}

// where the addresses are in an IPv4 header
const (
	offsetSource      = 12
	offsetDestination = 16
)

// ipv4 tells the packet is IPv4: the table is of the family inet, and a rule that reads
// an IPv4 address says so first, once.
func ipv4() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
	}
}

// where the addresses are in an IPv6 header
const (
	offset6Source      = 8
	offset6Destination = 24
)

// ipv6 tells the packet is IPv6, as ipv4 tells IPv4.
func ipv6() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
	}
}

// address6In matches an IPv6 address of the header against a set.
func address6In(offset uint32, setName string, setID uint32) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 16},
		&expr.Lookup{SourceRegister: 1, SetName: setName, SetID: setID},
	}
}

// intervals6 writes IPv6 ranges as intervals does IPv4 ones.
func intervals6(ranges []netipx.IPRange) []nftables.SetElement {
	elements := make([]nftables.SetElement, 0, 2*len(ranges))
	for _, item := range ranges {
		elements = append(elements, nftables.SetElement{Key: item.From().AsSlice()})
		// nothing follows ffff:...:ffff: such a range has no end element
		if next := item.To().Next(); next.IsValid() {
			elements = append(elements, nftables.SetElement{Key: next.AsSlice(), IntervalEnd: true})
		}
	}
	return elements
}

// replaceRanges6 makes a set of IPv6 hold exactly these ranges, in one transaction.
func replaceRanges6(name string, ranges []netipx.IPRange) error {
	conn, err := newConn()
	if err != nil {
		return E.Cause(err, "open netlink")
	}
	set := &nftables.Set{Table: &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}, Name: name, Interval: true, AutoMerge: true, KeyType: nftables.TypeIP6Addr}
	conn.FlushSet(set)
	err = addElements(conn, set, intervals6(ranges))
	if err != nil {
		return err
	}
	err = conn.Flush()
	if err != nil {
		return E.Cause(err, "fill the set ", name)
	}
	return nil
}

func addressLoad(offset uint32) expr.Any {
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4}
}

func addressIn(offset uint32, setName string, setID uint32) []expr.Any {
	return []expr.Any{addressLoad(offset), &expr.Lookup{SourceRegister: 1, SetName: setName, SetID: setID}}
}

// addressWithin matches an address against a prefix; a whole address needs no mask.
func addressWithin(offset uint32, prefix netip.Prefix) []expr.Any {
	return addressCompared(offset, prefix, expr.CmpOpEq)
}

// addressNotWithin matches an address outside a prefix.
func addressNotWithin(offset uint32, prefix netip.Prefix) []expr.Any {
	return addressCompared(offset, prefix, expr.CmpOpNeq)
}

func addressCompared(offset uint32, prefix netip.Prefix, op expr.CmpOp) []expr.Any {
	if prefix.Bits() == 32 {
		return []expr.Any{addressLoad(offset), &expr.Cmp{Op: op, Register: 1, Data: prefix.Addr().AsSlice()}}
	}
	mask := netipx.RangeOfPrefix(netip.PrefixFrom(netip.MustParseAddr("255.255.255.255"), prefix.Bits())).From().AsSlice()
	return []expr.Any{
		addressLoad(offset),
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: op, Register: 1, Data: prefix.Masked().Addr().AsSlice()},
	}
}

func destinationPort(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
	}
}

// ChainState is what a check wants to know of a chain of the table.
type ChainState struct {
	// Exists tells whether the chain is there and has rules that count packets.
	Exists bool
	// Counted tells whether any of them has counted a packet.
	Counted bool
}

// State is what the kernel has of the table, and what else marks packets.
type State struct {
	Table        bool
	Mangle       ChainState
	MangleOutput ChainState
	Proxy        ChainState
	// ForeignMarks names the chains of other tables that set a packet mark: the place
	// to look when another program's rules and the backend's get in each other's way.
	ForeignMarks []string
}

// Exists tells whether the table is there.
func Exists() (bool, error) {
	conn, err := newConn()
	if err != nil {
		return false, E.Cause(err, "open netlink")
	}
	tables, err := conn.ListTables()
	if err != nil {
		return false, E.Cause(err, "list the tables")
	}
	for _, table := range tables {
		if table.Family == nftables.TableFamilyINet && table.Name == tableName {
			return true, nil
		}
	}
	return false, nil
}

// Inspect reads the state of the table and of the counters of its rules.
func Inspect() (*State, error) {
	conn, err := newConn()
	if err != nil {
		return nil, E.Cause(err, "open netlink")
	}
	tables, err := conn.ListTables()
	if err != nil {
		return nil, E.Cause(err, "list the tables")
	}
	state := new(State)
	for _, table := range tables {
		if table.Family == nftables.TableFamilyINet && table.Name == tableName {
			state.Table = true
			state.Mangle = chainState(conn, table, "mangle")
			state.MangleOutput = chainState(conn, table, "mangle_output")
			state.Proxy = chainState(conn, table, "proxy")
		}
	}
	chains, err := conn.ListChains()
	if err != nil {
		return state, E.Cause(err, "list the chains")
	}
	for _, chain := range chains {
		if chain.Table.Family == nftables.TableFamilyINet && chain.Table.Name == tableName {
			continue
		}
		rules, err := conn.GetRules(chain.Table, chain)
		if err != nil {
			continue
		}
		for _, rule := range rules {
			if setsMark(rule) {
				state.ForeignMarks = append(state.ForeignMarks, familyName(chain.Table.Family)+" "+chain.Table.Name+" "+chain.Name)
				break
			}
		}
	}
	return state, nil
}

func chainState(conn *nftables.Conn, table *nftables.Table, name string) ChainState {
	var state ChainState
	rules, err := conn.GetRules(table, &nftables.Chain{Name: name, Table: table})
	if err != nil {
		return state
	}
	for _, rule := range rules {
		for _, expression := range rule.Exprs {
			if counter, isCounter := expression.(*expr.Counter); isCounter {
				state.Exists = true
				if counter.Packets > 0 || counter.Bytes > 0 {
					state.Counted = true
				}
			}
		}
	}
	return state
}

func setsMark(rule *nftables.Rule) bool {
	for _, expression := range rule.Exprs {
		if meta, isMeta := expression.(*expr.Meta); isMeta && meta.SourceRegister && meta.Key == expr.MetaKeyMARK {
			return true
		}
	}
	return false
}

func familyName(family nftables.TableFamily) string {
	switch family {
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyBridge:
		return "bridge"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyNetdev:
		return "netdev"
	}
	return "family " + strconv.Itoa(int(family))
}
