package firewall

import (
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/podkop-net/podkop-experimental/src/backend/btstats"
	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/sagernet/nftables"
	"golang.org/x/sys/unix"
)

// An entry of a dump of ctnetlink as the kernel sends it: the tuple (its protocol), the status (a
// rewritten destination: a port forward), the counters each way, the mark, the id.
func TestParseFlow(t *testing.T) {
	encoder := netlink.NewAttributeEncoder()
	encoder.ByteOrder = binary.BigEndian
	encoder.Nested(ctaTupleOrig, func(tuple *netlink.AttributeEncoder) error {
		tuple.Nested(1, func(ip *netlink.AttributeEncoder) error {
			ip.Bytes(1, []byte{203, 0, 113, 7})
			ip.Bytes(2, []byte{192, 168, 1, 10})
			return nil
		})
		tuple.Nested(ctaTupleProto, func(proto *netlink.AttributeEncoder) error {
			proto.Uint8(ctaProtoNum, unix.IPPROTO_UDP)
			proto.Uint16(2, 51413)
			proto.Uint16(3, 6881)
			return nil
		})
		return nil
	})
	encoder.Uint32(ctaStatus, statusDNAT|1<<3)
	encoder.Nested(ctaCountersOrig, func(counters *netlink.AttributeEncoder) error {
		counters.Uint64(ctaCountersPackets, 10)
		counters.Uint64(ctaCountersBytes, 1000)
		return nil
	})
	encoder.Nested(ctaCountersReply, func(counters *netlink.AttributeEncoder) error {
		counters.Uint64(ctaCountersPackets, 20)
		counters.Uint64(ctaCountersBytes, 30000)
		return nil
	})
	encoder.Uint32(ctaMark, ctBitTorrent|ctIntercepted)
	encoder.Uint32(ctaID, 77)
	data, err := encoder.Encode()
	if err != nil {
		t.Fatal(err)
	}
	flow, ok := parseFlow(append([]byte{unix.AF_INET, 0, 0, 0}, data...))
	if !ok || flow.ID != 77 || !flow.UDP || !flow.Incoming || !flow.Counted || flow.Mark != ctBitTorrent|ctIntercepted ||
		flow.Original != (btstats.Count{Packets: 10, Bytes: 1000}) || flow.Reply != (btstats.Count{Packets: 20, Bytes: 30000}) || flow.Key == "" {
		t.Errorf("%v %+v", ok, flow)
	}
	// without the counters (accounting off): not counted
	encoder = netlink.NewAttributeEncoder()
	encoder.ByteOrder = binary.BigEndian
	encoder.Nested(ctaTupleOrig, func(tuple *netlink.AttributeEncoder) error {
		tuple.Nested(ctaTupleProto, func(proto *netlink.AttributeEncoder) error {
			proto.Uint8(ctaProtoNum, unix.IPPROTO_TCP)
			return nil
		})
		return nil
	})
	encoder.Uint32(ctaMark, ctInspect)
	data, _ = encoder.Encode()
	flow, ok = parseFlow(append([]byte{unix.AF_INET, 0, 0, 0}, data...))
	if !ok || flow.UDP || flow.Counted || flow.Incoming {
		t.Errorf("%v %+v", ok, flow)
	}
	// a connection from outside to a client on the router itself: no rewritten destination, told
	// by bt_router's mark of it
	encoder = netlink.NewAttributeEncoder()
	encoder.ByteOrder = binary.BigEndian
	encoder.Nested(ctaTupleOrig, func(tuple *netlink.AttributeEncoder) error {
		tuple.Nested(ctaTupleProto, func(proto *netlink.AttributeEncoder) error {
			proto.Uint8(ctaProtoNum, unix.IPPROTO_TCP)
			return nil
		})
		return nil
	})
	encoder.Uint32(ctaMark, dataplane.BitTorrentInboundCt)
	data, _ = encoder.Encode()
	flow, ok = parseFlow(append([]byte{unix.AF_INET, 0, 0, 0}, data...))
	if !ok || !flow.Incoming {
		t.Errorf("to the router's client: %v %+v", ok, flow)
	}
}

// The kernel's entries with a mark of the detector, and none other: a UDP flow over loopback that
// a rule marks as BitTorrent, beside one it does not mark. Root and nft (the container of
// lab/bth/bhfw.sh: a network namespace of its own).
func TestBitTorrentFlowsFromKernel(t *testing.T) {
	needNft(t)
	nft(t, "add table inet pdk_cttest")
	t.Cleanup(func() { _ = exec.Command("nft", "delete table inet pdk_cttest").Run() })
	nft(t, "add chain inet pdk_cttest out { type filter hook output priority 0; policy accept; }")
	nft(t, "add rule inet pdk_cttest out udp dport 39001 ct mark set 0x00018000")
	for _, port := range []string{"39001", "39002"} {
		// a socket that takes them: without one the second write would fail (ICMP unreachable)
		listener, err := net.ListenPacket("udp4", "127.0.0.1:"+port)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		conn, err := net.Dial("udp4", "127.0.0.1:"+port)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"))
		_, _ = conn.Write([]byte("again"))
		conn.Close()
	}
	flows, err := BitTorrentFlows()
	if err != nil {
		t.Fatal(err)
	}
	acct, _ := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_acct")
	counting := strings.TrimSpace(string(acct)) == "1"
	found := 0
	for _, flow := range flows {
		if flow.Mark&ctBitTorrent == 0 {
			t.Errorf("an entry without the mark: %+v", flow)
		}
		if flow.Mark == ctBitTorrent|ctIntercepted && flow.UDP {
			found++
			if counting && (flow.Original.Packets != 2 || !flow.Counted) {
				t.Errorf("counted %+v", flow)
			}
		}
	}
	if found != 1 {
		t.Errorf("%d marked flows of %d: %+v", found, len(flows), flows)
	}
	t.Logf("accounting %v, %d entries", counting, len(flows))
}

// The rules BitTorrentDrops reads are there in each mode: bt_block's three in block, bt_incoming's
// two a device, bt_decided's drop of a uTP SYN outside block.
func TestBitTorrentDropRules(t *testing.T) {
	needNft(t)
	_ = Remove()
	t.Cleanup(func() { _ = Remove() })
	for name, c := range map[string]struct {
		detector                         BitTorrent
		block, incoming, decided, router int
	}{
		"bypass":         {BitTorrent{Mode: BitTorrentBypass}, 0, 0, 2, 0},
		"block":          {BitTorrent{Mode: BitTorrentBlock, Sources: prefixes("192.168.1.60/32")}, 3, 2, 0, 0},
		"block, the LAN": {BitTorrent{Mode: BitTorrentBlock, LAN: true}, 3, 2, 0, 0},
		// bt_router's two drops, which BitTorrentDrops adds to the block's; none outside block
		"block, a user of the router":   {BitTorrent{Mode: BitTorrentBlock, RouterUsers: []uint32{4321}}, 3, 0, 0, 2},
		"section, a user of the router": {BitTorrent{Mode: BitTorrentSection, RouterUsers: []uint32{4321}}, 0, 0, 2, 0},
	} {
		if err := Apply(&Plan{Interfaces: []string{"br-lan"}, BitTorrent: c.detector}); err != nil {
			t.Fatal(name, err)
		}
		conn, err := newConn()
		if err != nil {
			t.Fatal(err)
		}
		table := &nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}
		var got [4]int
		for index, chain := range []string{ChainBitTorrentBlock, ChainBitTorrentIncoming, ChainBitTorrentDecided, ChainBitTorrentRouter} {
			counts, err := dropCounts(conn, table, chain)
			if err != nil {
				t.Error(name, chain, err)
			}
			got[index] = len(counts)
		}
		if got != [4]int{c.block, c.incoming, c.decided, c.router} {
			t.Errorf("%s: bt_block %d, bt_incoming %d, bt_decided %d, bt_router %d", name, got[0], got[1], got[2], got[3])
		}
		if _, err := BitTorrentDrops(); err != nil {
			t.Error(name, err)
		}
	}
}

// What a read of the statistics costs (BitTorrentFlows and BitTorrentDrops, every
// btstats.PollEvery): the table of a mode with the detector, FLOWS marked flows over loopback (200
// by default), the wall time and the CPU of the process per read. Run by hand:
// POLLCOST=1 go test -run TestBitTorrentPollCost -v.
func TestBitTorrentPollCost(t *testing.T) {
	needNft(t)
	if os.Getenv("POLLCOST") == "" {
		t.Skip("POLLCOST not set")
	}
	_ = Remove()
	t.Cleanup(func() { _ = Remove() })
	if err := Apply(&Plan{Interfaces: []string{"br-lan"}, BitTorrent: BitTorrent{Mode: BitTorrentBypass}}); err != nil {
		t.Fatal(err)
	}
	nft(t, "add table inet pdk_cttest")
	t.Cleanup(func() { _ = exec.Command("nft", "delete table inet pdk_cttest").Run() })
	nft(t, "add chain inet pdk_cttest out { type filter hook output priority 0; policy accept; }")
	nft(t, "add rule inet pdk_cttest out udp dport 40000-49999 ct mark set 0x00018000")
	count := 200
	if n, err := strconv.Atoi(os.Getenv("FLOWS")); err == nil {
		count = n
	}
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for i := range count {
		conn, err := net.Dial("udp4", "127.0.0.1:"+strconv.Itoa(40000+i%10000))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte("x"))
		conn.Close()
	}
	cpu := func() time.Duration {
		var usage unix.Rusage
		_ = unix.Getrusage(unix.RUSAGE_SELF, &usage)
		return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
	}
	const reads = 100
	flows := 0
	measure := func(name string, read func() error) {
		start, startCPU := time.Now(), cpu()
		for range reads {
			if err := read(); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("%s, %d flows: %.2f ms a read, %.2f ms of CPU a read", name, flows,
			float64(time.Since(start).Microseconds())/1000/reads, float64((cpu()-startCPU).Microseconds())/1000/reads)
	}
	measure("flows", func() error {
		got, err := BitTorrentFlows()
		flows = len(got)
		return err
	})
	measure("drops", func() error {
		_, err := BitTorrentDrops()
		return err
	})
}

func TestParseUndecided(t *testing.T) {
	// an entry as ctnetlink dumps it: the tuple of the original direction (the addresses, the
	// protocol and the ports, nested) and the mark
	nested := func(kind uint16, attributes ...netlink.Attribute) netlink.Attribute {
		data, err := netlink.MarshalAttributes(attributes)
		if err != nil {
			t.Fatal(err)
		}
		return netlink.Attribute{Type: kind | unix.NLA_F_NESTED, Data: data}
	}
	entry := func(source [4]byte, protocol byte, port uint16, mark uint32) []byte {
		data, err := netlink.MarshalAttributes([]netlink.Attribute{
			nested(ctaTupleOrig,
				nested(ctaTupleIP, netlink.Attribute{Type: ctaIPv4Src, Data: source[:]}, netlink.Attribute{Type: 2, Data: []byte{203, 0, 113, 9}}),
				nested(ctaTupleProto, netlink.Attribute{Type: ctaProtoNum, Data: []byte{protocol}},
					netlink.Attribute{Type: 2, Data: []byte{0xa4, 0x10}}, netlink.Attribute{Type: ctaProtoDstPort, Data: []byte{byte(port >> 8), byte(port)}})),
			{Type: ctaMark, Data: []byte{byte(mark >> 24), byte(mark >> 16), byte(mark >> 8), byte(mark)}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte{unix.AF_INET, 0, 0, 0}, data...)
	}
	device := [4]byte{192, 168, 80, 10}
	for _, test := range []struct {
		name      string
		data      []byte
		undecided bool
	}{
		{"not BitTorrent, an uncommon port", entry(device, unix.IPPROTO_TCP, 51413, ctNot), true},
		{"no mark (offloaded before its first data)", entry(device, unix.IPPROTO_TCP, 6881, 0), true},
		{"another device", entry([4]byte{192, 168, 80, 11}, unix.IPPROTO_TCP, 51413, 0), false},
		{"UDP", entry(device, unix.IPPROTO_UDP, 51413, 0), false},
		{"port 443", entry(device, unix.IPPROTO_TCP, 443, 0), false},
		{"a port under 1024", entry(device, unix.IPPROTO_TCP, 990, 0), false},
		{"inspected", entry(device, unix.IPPROTO_TCP, 51413, ctInspect), false},
		{"a suspect's", entry(device, unix.IPPROTO_TCP, 51413, ctSuspect), false},
		{"BitTorrent", entry(device, unix.IPPROTO_TCP, 51413, ctBitTorrent), false},
		{"taken by podkop", entry(device, unix.IPPROTO_TCP, 51413, ctIntercepted|ctNot), false},
	} {
		parsed, ok := parseUndecided(test.data)
		if !ok {
			t.Errorf("%s: not parsed", test.name)
			continue
		}
		if got := parsed.isUndecided(device); got != test.undecided {
			t.Errorf("%s: undecided %v, want %v (%+v)", test.name, got, test.undecided, parsed)
		}
	}
	if _, ok := parseUndecided([]byte{2, 0}); ok {
		t.Error("a short message parsed")
	}
}
