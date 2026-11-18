package firewall

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/mdlayher/netlink"
	"github.com/podkop-net/podkop-experimental/src/backend/btstats"
	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/expr"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

// What ctnetlink takes and gives (linux/netfilter/nfnetlink.h, nfnetlink_conntrack.h): the
// subsystem, the messages, the attributes of an entry.
const (
	nfnlSubsysCtnetlink = 1
	ipctnlMsgCtGet      = 1
	ipctnlMsgCtDelete   = 2
	nfnetlinkV0         = 0
	ctaTupleOrig        = 1
	ctaStatus           = 3
	ctaMark             = 8
	ctaCountersOrig     = 9
	ctaCountersReply    = 10
	ctaID               = 12
	ctaMarkMask         = 21
	ctaTupleProto       = 2
	ctaProtoNum         = 1
	ctaCountersPackets  = 1
	ctaCountersBytes    = 2
)

// Forget is which connections of BitTorrent a change of the mode ends (ForgetFor).
type Forget int

const (
	// ForgetNone: every connection of BitTorrent goes on the way it had, or the new mode takes
	// its next packet by its mark
	ForgetNone Forget = iota
	// ForgetIntercepted: those podkop takes, which the mode bypass let past it
	ForgetIntercepted
	// ForgetAll: every one, which the block of the whole LAN drops and the section of the whole LAN
	// sends to the section; those podkop does not take went past it in every other mode
	ForgetAll
)

func (f Forget) String() string {
	switch f {
	case ForgetIntercepted:
		return "intercepted"
	case ForgetAll:
		return "all"
	}
	return "none"
}

// ForgetFor tells which connections of BitTorrent a change of the mode from previous (the
// detector of the table the backend put in the kernel last) to next ends. The router forwards a
// connection of BitTorrent podkop does not take in every mode but those of the whole LAN, and one
// podkop takes in the mode bypass; it may offload what it forwards, and an offloaded
// connection passes no rule of nftables: the new mode reaches it only once ForgetBitTorrentFlows
// ended its entry. A detector made when there was none leaves the connections alone: its sets are
// empty, the new entries of the connections it ended could not be told, and the marks of those
// entries tell them as they are (bt_decided).
func ForgetFor(previous, next BitTorrent) Forget {
	switch {
	case previous.Mode == "":
		return ForgetNone
	case next.Mode != "" && next.LAN && (next.Mode != previous.Mode || !previous.LAN):
		// the block or the section of the whole LAN takes what the router forwarded past podkop
		return ForgetAll
	case previous.Mode == BitTorrentBypass && next.Mode != BitTorrentBypass:
		return ForgetIntercepted
	}
	return ForgetNone
}

// ForgetBitTorrentFlows ends the conntrack entries the detector marked as BitTorrent, those podkop
// takes or all of them (ctnetlink: a delete without a tuple ends the entries the mark and its mask
// match; the module nf_conntrack_netlink, kmod-nf-conntrack-netlink of OpenWrt). The next packet
// of such a connection makes a new entry, which the detector tells again by its sets and the mode
// of now takes: the router offloads a connection by its entry, so the offloading ends with it.
func ForgetBitTorrentFlows(which Forget) error {
	var mark uint32
	switch which {
	case ForgetIntercepted:
		mark = ctBitTorrent | ctIntercepted
	case ForgetAll:
		mark = ctBitTorrent
	default:
		return nil
	}
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return E.Cause(err, "open netlink of netfilter")
	}
	defer conn.Close()
	encoder := netlink.NewAttributeEncoder()
	encoder.ByteOrder = binary.BigEndian
	encoder.Uint32(ctaMark, mark)
	encoder.Uint32(ctaMarkMask, mark)
	attributes, err := encoder.Encode()
	if err != nil {
		return err
	}
	// nfgenmsg: the family (of the entries of IPv4; the version 0 does not hold the kernel to
	// it), the version, the resource id
	header := []byte{unix.AF_INET, nfnetlinkV0, 0, 0}
	_, err = conn.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(nfnlSubsysCtnetlink<<8 | ipctnlMsgCtDelete), Flags: netlink.Request | netlink.Acknowledge},
		Data:   append(header, attributes...),
	})
	if err != nil {
		return E.Cause(err, "end the conntrack entries of BitTorrent")
	}
	return nil
}

// BitTorrentFlows reads the conntrack entries of IPv4 that carry a mark of the detector (told as
// BitTorrent, inspected, told late), each once, with what the kernel counted of them
// (btstats.Flow). A dump that the mark and its mask filter in the kernel: the entries of the other
// traffic are not sent.
func BitTorrentFlows() ([]btstats.Flow, error) {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, E.Cause(err, "open netlink of netfilter")
	}
	defer conn.Close()
	type key struct {
		id    uint32
		tuple string
	}
	seen := make(map[key]bool)
	var flows []btstats.Flow
	for _, mark := range []uint32{ctBitTorrent, ctInspect, ctLate} {
		encoder := netlink.NewAttributeEncoder()
		encoder.ByteOrder = binary.BigEndian
		encoder.Uint32(ctaMark, mark)
		encoder.Uint32(ctaMarkMask, mark)
		attributes, err := encoder.Encode()
		if err != nil {
			return flows, err
		}
		messages, err := conn.Execute(netlink.Message{
			Header: netlink.Header{Type: netlink.HeaderType(nfnlSubsysCtnetlink<<8 | ipctnlMsgCtGet), Flags: netlink.Request | netlink.Dump},
			Data:   append([]byte{unix.AF_INET, nfnetlinkV0, 0, 0}, attributes...),
		})
		if err != nil {
			return flows, E.Cause(err, "read the conntrack entries of BitTorrent")
		}
		for _, message := range messages {
			flow, ok := parseFlow(message.Data)
			if !ok || seen[key{flow.ID, flow.Key}] {
				continue
			}
			seen[key{flow.ID, flow.Key}] = true
			flows = append(flows, flow)
		}
	}
	return flows, nil
}

// parseFlow reads an entry of a dump of ctnetlink: the nfgenmsg header, then the attributes.
func parseFlow(data []byte) (btstats.Flow, bool) {
	var flow btstats.Flow
	if len(data) < 4 {
		return flow, false
	}
	decoder, err := netlink.NewAttributeDecoder(data[4:])
	if err != nil {
		return flow, false
	}
	decoder.ByteOrder = binary.BigEndian
	var status uint32
	counts := func(count *btstats.Count) func(*netlink.AttributeDecoder) error {
		return func(nested *netlink.AttributeDecoder) error {
			for nested.Next() {
				switch nested.Type() {
				case ctaCountersPackets:
					count.Packets = nested.Uint64()
				case ctaCountersBytes:
					count.Bytes = nested.Uint64()
				}
			}
			return nil
		}
	}
	for decoder.Next() {
		switch decoder.Type() {
		case ctaTupleOrig:
			flow.Key = string(decoder.Bytes())
			decoder.Nested(func(tuple *netlink.AttributeDecoder) error {
				for tuple.Next() {
					if tuple.Type() != ctaTupleProto {
						continue
					}
					tuple.Nested(func(proto *netlink.AttributeDecoder) error {
						for proto.Next() {
							if proto.Type() == ctaProtoNum {
								flow.UDP = proto.Uint8() == unix.IPPROTO_UDP
							}
						}
						return nil
					})
				}
				return nil
			})
		case ctaStatus:
			status = decoder.Uint32()
		case ctaMark:
			flow.Mark = decoder.Uint32()
		case ctaID:
			flow.ID = decoder.Uint32()
		case ctaCountersOrig:
			flow.Counted = true
			decoder.Nested(counts(&flow.Original))
		case ctaCountersReply:
			flow.Counted = true
			decoder.Nested(counts(&flow.Reply))
		}
	}
	// from outside: its destination was rewritten (a port forward to a device), or it came to a
	// client on the router itself (bt_router's mark of it)
	flow.Incoming = status&statusDNAT != 0 || flow.Mark&dataplane.BitTorrentInboundCt == dataplane.BitTorrentInboundCt
	return flow, decoder.Err() == nil && flow.Key != ""
}

// BitTorrentDrops reads the counters of the rules of the detector that drop BitTorrent: bt_block's
// by kind (in the mode block), bt_incoming's (a new connection from outside to a client's socket),
// and bt_decided's drop of a uTP SYN on a flow of discovery; and the counters of what the detector
// could not take (the sets that are full, the sources that are not of their interface). A chain
// that is not there counts 0; a
// chain that could not be read is an error, and the counters are none (a read that failed must
// not pass for counters at 0: the statistics take those for a table made anew, and count what the
// rules had once more at the next read).
func BitTorrentDrops() (btstats.Drops, error) {
	var drops btstats.Drops
	conn, err := newConn()
	if err != nil {
		return drops, err
	}
	table := &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}
	var failed error
	dropped := func(chain string) []btstats.Count {
		counts, err := dropCounts(conn, table, chain)
		if err != nil && failed == nil {
			failed = E.Cause(err, "read the rules of ", chain)
		}
		return counts
	}
	if block := dropped(ChainBitTorrentBlock); len(block) == 3 {
		drops.Discovery, drops.UTP, drops.TCP = block[0], block[1], block[2]
	}
	for _, count := range dropped(ChainBitTorrentIncoming) {
		drops.Incoming.Packets += count.Packets
		drops.Incoming.Bytes += count.Bytes
	}
	// of the router's own programs (bt_router, in block): UDP, then the rest
	if router := dropped(ChainBitTorrentRouter); len(router) == 2 {
		drops.UTP.Packets += router[0].Packets
		drops.UTP.Bytes += router[0].Bytes
		drops.TCP.Packets += router[1].Packets
		drops.TCP.Bytes += router[1].Bytes
	}
	for _, count := range dropped(ChainBitTorrentDecided) {
		drops.UTPToTCP.Packets += count.Packets
		drops.UTPToTCP.Bytes += count.Bytes
	}
	// what the detector could not take: the packets a full set took nothing of, and those whose
	// source address is not of the interface they came in on
	last := func(chain string) btstats.Count {
		counts, err := ruleCounts(conn, table, chain, func(rule *nftables.Rule) bool { return len(rule.Exprs) == 1 })
		if err != nil && failed == nil {
			failed = E.Cause(err, "read the rules of ", chain)
		}
		if len(counts) == 0 {
			return btstats.Count{}
		}
		return counts[len(counts)-1]
	}
	drops.FullHosts, drops.FullSockets, drops.FullPeers, drops.FullUTP = last(chainBitTorrentAddHosts), last(chainBitTorrentAddSockets),
		last(chainBitTorrentAddPeers), last(chainBitTorrentFullUTP)
	foreign, err := ruleCounts(conn, table, chainBitTorrentDetect, func(rule *nftables.Rule) bool {
		for _, expression := range rule.Exprs {
			if fib, ok := expression.(*expr.Fib); ok && fib.FlagSADDR {
				return true
			}
		}
		return false
	})
	if err != nil && failed == nil {
		failed = E.Cause(err, "read the rules of ", chainBitTorrentDetect)
	}
	if len(foreign) > 0 {
		drops.Foreign = foreign[0]
	}
	if failed != nil {
		return btstats.Drops{}, failed
	}
	return drops, nil
}

// ruleCounts are the counters of the rules of a chain that which chooses, in their order; none
// when the chain (or the table) is not there.
func ruleCounts(conn *nftables.Conn, table *nftables.Table, chain string, which func(*nftables.Rule) bool) ([]btstats.Count, error) {
	rules, err := conn.GetRules(table, &nftables.Chain{Name: chain, Table: table})
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		return nil, err
	}
	var counts []btstats.Count
	for _, rule := range rules {
		if !which(rule) {
			continue
		}
		for _, expression := range rule.Exprs {
			if counter, ok := expression.(*expr.Counter); ok {
				counts = append(counts, btstats.Count{Packets: counter.Packets, Bytes: counter.Bytes})
				break
			}
		}
	}
	return counts, nil
}

// dropCounts are the counters of the rules of a chain that count and drop, in their order; none
// when the chain (or the table) is not there.
func dropCounts(conn *nftables.Conn, table *nftables.Table, chain string) ([]btstats.Count, error) {
	rules, err := conn.GetRules(table, &nftables.Chain{Name: chain, Table: table})
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		return nil, err
	}
	var counts []btstats.Count
	for _, rule := range rules {
		var count *btstats.Count
		drop := false
		for _, expression := range rule.Exprs {
			switch e := expression.(type) {
			case *expr.Counter:
				count = &btstats.Count{Packets: e.Packets, Bytes: e.Bytes}
			case *expr.Verdict:
				drop = e.Kind == expr.VerdictDrop
			}
		}
		if count != nil && drop {
			counts = append(counts, *count)
		}
	}
	return counts, nil
}

// The attributes of a tuple (nfnetlink_conntrack.h).
const (
	ctaTupleIP      = 1
	ctaIPv4Src      = 1
	ctaIPv4Dst      = 2
	ctaProtoDstPort = 3
)

// undecided is a conntrack entry EndUndecidedFlows looks at: the raw tuple of its original
// direction (given back to the kernel to end it), its source, protocol, destination port and mark.
type undecided struct {
	tuple  []byte
	source [4]byte
	far    [4]byte
	tcp    bool
	port   uint16
	mark   uint32
}

// parseUndecided reads an entry of a conntrack dump.
func parseUndecided(data []byte) (undecided, bool) {
	var entry undecided
	if len(data) < 4 {
		return entry, false
	}
	decoder, err := netlink.NewAttributeDecoder(data[4:])
	if err != nil {
		return entry, false
	}
	decoder.ByteOrder = binary.BigEndian
	for decoder.Next() {
		switch decoder.Type() {
		case ctaTupleOrig:
			entry.tuple = append([]byte(nil), decoder.Bytes()...)
			decoder.Nested(func(tuple *netlink.AttributeDecoder) error {
				for tuple.Next() {
					switch tuple.Type() {
					case ctaTupleIP:
						tuple.Nested(func(ip *netlink.AttributeDecoder) error {
							for ip.Next() {
								switch {
								case ip.Type() == ctaIPv4Src && len(ip.Bytes()) == 4:
									copy(entry.source[:], ip.Bytes())
								case ip.Type() == ctaIPv4Dst && len(ip.Bytes()) == 4:
									copy(entry.far[:], ip.Bytes())
								}
							}
							return nil
						})
					case ctaTupleProto:
						tuple.Nested(func(proto *netlink.AttributeDecoder) error {
							for proto.Next() {
								switch proto.Type() {
								case ctaProtoNum:
									entry.tcp = proto.Uint8() == unix.IPPROTO_TCP
								case ctaProtoDstPort:
									entry.port = proto.Uint16()
								}
							}
							return nil
						})
					}
				}
				return nil
			})
		case ctaMark:
			entry.mark = decoder.Uint32()
		}
	}
	return entry, decoder.Err() == nil && len(entry.tuple) > 0
}

// isUndecided tells whether an entry is a TCP connection of device to an uncommon port that the
// detector did not tell as BitTorrent, does not inspect and podkop did not take: one that goes on
// as forwarded, whatever it carries.
func (u undecided) isUndecided(device [4]byte) bool {
	if !u.tcp || u.source != device || u.port < firstFreePort || u.mark&(ctBitTorrent|ctLate|ctInspect|ctIntercepted) != 0 {
		return false
	}
	// (to the router or to a network of its own: no peer's, and the detector does not look there)
	if far := netip.AddrFrom4(u.far); far.IsPrivate() || far.IsLoopback() || far.IsLinkLocalUnicast() || far.IsMulticast() || far.IsUnspecified() {
		return false
	}
	for _, port := range commonPorts {
		if u.port == port {
			return false
		}
	}
	return true
}

// EndUndecidedFlows ends the conntrack entries of the TCP connections a device opened to uncommon
// ports that the detector left as forwarded (the suspicion by fan-out: the module calls it when the early check
// of a suspect told that the device runs a client). An offloaded connection ends being offloaded
// with its entry; its next packet makes a new entry, which bt_tcp resets: the device is put in
// bt_ended first, for bitTorrentEndedFor (a table without that set, which has no suspicion, has
// no rule to reset by either). It tells how many it ended.
func EndUndecidedFlows(device netip.Addr) (int, error) {
	if !device.Is4() {
		return 0, nil
	}
	_ = renewElement(setBitTorrentEnded, device, bitTorrentEndedFor)
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return 0, E.Cause(err, "open netlink of netfilter")
	}
	defer conn.Close()
	header := []byte{unix.AF_INET, nfnetlinkV0, 0, 0}
	messages, err := conn.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(nfnlSubsysCtnetlink<<8 | ipctnlMsgCtGet), Flags: netlink.Request | netlink.Dump},
		Data:   header,
	})
	if err != nil {
		return 0, E.Cause(err, "read the conntrack entries")
	}
	ended := 0
	var failed error
	for _, message := range messages {
		entry, ok := parseUndecided(message.Data)
		if !ok || !entry.isUndecided(device.As4()) {
			continue
		}
		attributes, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: ctaTupleOrig | unix.NLA_F_NESTED, Data: entry.tuple}})
		if err != nil {
			return ended, err
		}
		_, err = conn.Execute(netlink.Message{
			Header: netlink.Header{Type: netlink.HeaderType(nfnlSubsysCtnetlink<<8 | ipctnlMsgCtDelete), Flags: netlink.Request | netlink.Acknowledge},
			Data:   append(append([]byte(nil), header...), attributes...),
		})
		switch {
		case err == nil:
			ended++
		case errors.Is(err, unix.ENOENT):
			// gone meanwhile
		case failed == nil:
			failed = E.Cause(err, "end a conntrack entry")
		}
	}
	return ended, failed
}
