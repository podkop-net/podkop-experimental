package firewall

import (
	"encoding/binary"
	"errors"

	"github.com/mdlayher/netlink"
	"github.com/podkop-net/podkop-experimental/src/backend/btstats"
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
	flow.Incoming = status&statusDNAT != 0
	return flow, decoder.Err() == nil && flow.Key != ""
}

// BitTorrentDrops reads the counters of the rules of the detector that drop BitTorrent: bt_block's
// by kind (in the mode block), bt_incoming's (a new connection from outside to a client's socket),
// and bt_decided's drop of a uTP SYN on a flow of discovery. A chain that is not there counts 0; a
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
	for _, count := range dropped(ChainBitTorrentDecided) {
		drops.UTPToTCP.Packets += count.Packets
		drops.UTPToTCP.Bytes += count.Bytes
	}
	if failed != nil {
		return btstats.Drops{}, failed
	}
	return drops, nil
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
