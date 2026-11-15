package firewall

import (
	"encoding/binary"

	"github.com/mdlayher/netlink"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

// What a delete of conntrack takes over netlink (linux/netfilter/nfnetlink.h,
// nfnetlink_conntrack.h): the subsystem, the message, the attributes of the mark.
const (
	nfnlSubsysCtnetlink = 1
	ipctnlMsgCtDelete   = 2
	nfnetlinkV0         = 0
	ctaMark             = 8
	ctaMarkMask         = 21
)

// Forget is which connections of BitTorrent a change of the mode ends (ForgetFor).
type Forget int

const (
	// ForgetNone: every connection of BitTorrent goes on the way it had, or the new mode takes
	// its next packet by its mark
	ForgetNone Forget = iota
	// ForgetIntercepted: those podkop takes, which the mode bypass let past it
	ForgetIntercepted
	// ForgetAll: every one, which the block of the whole LAN drops; those podkop does not take
	// went past it in every other mode
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
// connection of BitTorrent podkop does not take in every mode but the block of the whole LAN, and
// one podkop takes in the mode bypass; it may offload what it forwards, and an offloaded
// connection passes no rule of nftables: the new mode reaches it only once ForgetBitTorrentFlows
// ended its entry. A detector made when there was none leaves the connections alone: its sets are
// empty, the new entries of the connections it ended could not be told, and the marks of those
// entries tell them as they are (bt_decided).
func ForgetFor(previous, next BitTorrent) Forget {
	lan := func(detector BitTorrent) bool { return detector.Mode == BitTorrentBlock && detector.BlockLAN }
	switch {
	case previous.Mode == "":
		return ForgetNone
	case lan(next) && !lan(previous):
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
