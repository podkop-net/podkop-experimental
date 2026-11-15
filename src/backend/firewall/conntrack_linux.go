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

// LeavesBypass tells whether an update from previous to next takes BitTorrent out of the mode
// bypass while the backend runs: a connection bypass let past podkop that the router offloads
// passes no rule of nftables, so the new mode reaches it only once ForgetBitTorrentFlows ended its
// entry. A start (no previous plan) leaves the connections alone: the sets of the detector were
// taken down with the table at the stop, and the new entries of the connections it ended could not
// be told (bitTorrentKept).
func LeavesBypass(previous, next *Plan) bool {
	return previous != nil && previous.BitTorrent.Mode == BitTorrentBypass && next.BitTorrent.Mode != BitTorrentBypass
}

// ForgetBitTorrentFlows ends the conntrack entries the detector marked as BitTorrent (ctnetlink: a
// delete without a tuple ends the entries the mark and its mask match; the module
// nf_conntrack_netlink, kmod-nf-conntrack-netlink of OpenWrt). The next packet of such a connection
// makes a new entry, which the detector tells again by its sets and the mode of now takes: the
// router offloads a connection by its entry, so the offloading ends with it.
func ForgetBitTorrentFlows() error {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return E.Cause(err, "open netlink of netfilter")
	}
	defer conn.Close()
	encoder := netlink.NewAttributeEncoder()
	encoder.ByteOrder = binary.BigEndian
	encoder.Uint32(ctaMark, ctBitTorrent)
	encoder.Uint32(ctaMarkMask, ctBitTorrent)
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
