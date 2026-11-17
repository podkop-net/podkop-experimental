package bittorrent

import (
	"bytes"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// fakePacketConn is a session's LAN side: ReadPacket gives what the device sent (reads), WritePacket
// keeps what goes to it (written).
type fakePacketConn struct {
	N.PacketConn
	reads   []fakePacket
	written []fakePacket
}

type fakePacket struct {
	data []byte
	far  M.Socksaddr
}

func (f *fakePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if len(f.reads) == 0 {
		return M.Socksaddr{}, net.ErrClosed
	}
	packet := f.reads[0]
	f.reads = f.reads[1:]
	_, _ = buffer.Write(packet.data)
	return packet.far, nil
}

func (f *fakePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	f.written = append(f.written, fakePacket{bytes.Clone(buffer.Bytes()), destination})
	return nil
}

var (
	testDevice  = netip.MustParseAddr("192.168.80.10")
	trackerFar  = M.SocksaddrFromNetIP(netip.MustParseAddrPort("93.158.213.92:1337"))
	dhtNodeFar  = M.SocksaddrFromNetIP(netip.MustParseAddrPort("67.215.246.10:6881"))
	someoneElse = M.SocksaddrFromNetIP(netip.MustParseAddrPort("198.51.100.99:1337"))
)

func session(s *Service, reads ...fakePacket) (*packetConn, *fakePacketConn) {
	fake := &fakePacketConn{reads: reads}
	return &packetConn{PacketConn: fake, service: s, device: testDevice}, fake
}

func sendAll(t *testing.T, c *packetConn) {
	for {
		buffer := buf.New()
		_, err := c.ReadPacket(buffer)
		buffer.Release()
		if err != nil {
			return
		}
	}
}

func reply(t *testing.T, c *packetConn, data []byte, far M.Socksaddr) {
	if err := c.WritePacket(buf.As(data), far); err != nil {
		t.Fatal(err)
	}
}

// A reply to the device's request, from where the request went, is learned; it reaches the device
// as it came.
func TestLearnPaired(t *testing.T) {
	s, sink := testService()
	c, fake := session(s, fakePacket{trackerAnnounceRequest(41), trackerFar}, fakePacket{dhtGetPeers("q1"), dhtNodeFar})
	sendAll(t, c)
	reply(t, c, trackerAnnounceReply(41, testPeers), trackerFar)
	reply(t, c, dhtValues("q1", []netip.AddrPort{netip.MustParseAddrPort("203.0.113.50:6881"), netip.MustParseAddrPort("203.0.113.51:6881")}), dhtNodeFar)
	if sink.count() != 5 || s.counters.replies.Load() != 2 {
		t.Errorf("learned %d of 5, replies %d", sink.count(), s.counters.replies.Load())
	}
	if len(fake.written) != 2 || !bytes.Equal(fake.written[0].data, trackerAnnounceReply(41, testPeers)) {
		t.Errorf("the replies reached the device changed: %d", len(fake.written))
	}
	// each request is answered once
	reply(t, c, trackerAnnounceReply(41, testPeers), trackerFar)
	if sink.count() != 5 {
		t.Errorf("a second reply to one request learned: %d", sink.count())
	}
}

// R11: a reply no request of the device asked for (another transaction, another far end) is not
// learned, only counted.
func TestLearnUnpaired(t *testing.T) {
	s, sink := testService()
	c, fake := session(s, fakePacket{trackerAnnounceRequest(41), trackerFar})
	sendAll(t, c)
	reply(t, c, trackerAnnounceReply(42, testPeers), trackerFar)
	reply(t, c, trackerAnnounceReply(41, testPeers), someoneElse)
	if sink.count() != 0 || s.counters.unpaired.Load() != 2 {
		t.Errorf("learned %d, unpaired %d", sink.count(), s.counters.unpaired.Load())
	}
	if len(fake.written) != 2 {
		t.Errorf("unpaired replies did not reach the device: %d", len(fake.written))
	}
}

// A reply after pendingLife is not learned.
func TestLearnLate(t *testing.T) {
	s, sink := testService()
	c, _ := session(s)
	c.request(trackerAnnounceRequest(5), trackerFar.AddrPort(), time.Now().Add(-pendingLife-time.Second))
	reply(t, c, trackerAnnounceReply(5, testPeers), trackerFar)
	if sink.count() != 0 {
		t.Errorf("a late reply learned %d", sink.count())
	}
}

// Peers on a port under 1024, on a port never learned, of a private range or of FakeIP's are left.
func TestLearnable(t *testing.T) {
	s, sink := testService()
	c, _ := session(s, fakePacket{trackerAnnounceRequest(7), trackerFar})
	sendAll(t, c)
	peers := []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.7:80"),
		netip.MustParseAddrPort("203.0.113.7:443"),
		netip.MustParseAddrPort("192.168.1.5:51413"),
		netip.MustParseAddrPort("198.18.0.9:51413"),
		netip.MustParseAddrPort("100.64.3.3:51413"),
		netip.MustParseAddrPort("0.0.0.0:51413"),
		netip.MustParseAddrPort("203.0.113.8:51413"),
	}
	reply(t, c, trackerAnnounceReply(7, peers), trackerFar)
	if sink.count() != 1 || s.counters.notLearnable.Load() != 6 {
		t.Errorf("learned %d of 1, left %d of 6", sink.count(), s.counters.notLearnable.Load())
	}
}

// A session that shows uTP is stood aside: its uTP client learns its peers from its own writes.
func TestLearnUTP(t *testing.T) {
	s, sink := testService()
	syn := append([]byte{0x41, 0}, make([]byte, 18)...)
	c, _ := session(s, fakePacket{syn, trackerFar}, fakePacket{trackerAnnounceRequest(9), trackerFar})
	sendAll(t, c)
	reply(t, c, trackerAnnounceReply(9, testPeers), trackerFar)
	if sink.count() != 0 || !c.ReaderReplaceable() || s.counters.utpSessions.Load() != 1 {
		t.Errorf("learned %d, stood aside %v", sink.count(), c.ReaderReplaceable())
	}
}

// The cap per device counts a peer once: a reply that names peers written already writes none of
// them again; new ones past the cap are left.
func TestLearnCap(t *testing.T) {
	s, sink := testService()
	s.devices.cap = 4
	more := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:51413"), netip.MustParseAddrPort("203.0.113.10:51413")}
	c, _ := session(s, fakePacket{trackerAnnounceRequest(1), trackerFar}, fakePacket{trackerAnnounceRequest(2), trackerFar},
		fakePacket{trackerAnnounceRequest(3), trackerFar})
	sendAll(t, c)
	reply(t, c, trackerAnnounceReply(1, testPeers), trackerFar)
	reply(t, c, trackerAnnounceReply(2, testPeers), trackerFar)
	reply(t, c, trackerAnnounceReply(3, more), trackerFar)
	if sink.count() != 4 || s.counters.known.Load() != 3 || s.counters.capped.Load() != 1 {
		t.Errorf("learned %d of 4, known %d of 3, capped %d of 1", sink.count(), s.counters.known.Load(), s.counters.capped.Load())
	}
}

// A peer written for the device is written again after the window (its element has gone), and a
// write that failed is no write.
func TestLearnAgain(t *testing.T) {
	s, sink := testService()
	s.devices.window = 20 * time.Millisecond
	c, _ := session(s, fakePacket{trackerAnnounceRequest(1), trackerFar}, fakePacket{trackerAnnounceRequest(2), trackerFar})
	sendAll(t, c)
	reply(t, c, trackerAnnounceReply(1, testPeers), trackerFar)
	time.Sleep(40 * time.Millisecond)
	reply(t, c, trackerAnnounceReply(2, testPeers), trackerFar)
	if sink.count() != 6 {
		t.Errorf("learned %d of 6", sink.count())
	}
	s, _ = testService()
	s.sink = failingSink{}
	c, _ = session(s, fakePacket{trackerAnnounceRequest(1), trackerFar}, fakePacket{trackerAnnounceRequest(2), trackerFar})
	sendAll(t, c)
	reply(t, c, trackerAnnounceReply(1, testPeers), trackerFar)
	recorded := &recordSink{}
	s.sink = recorded
	reply(t, c, trackerAnnounceReply(2, testPeers), trackerFar)
	if recorded.count() != 3 || s.counters.writeFailed.Load() != 1 {
		t.Errorf("after a failed write: learned %d of 3, failed %d", recorded.count(), s.counters.writeFailed.Load())
	}
}

type failingSink struct{}

func (failingSink) add(keys [][]byte, wait time.Duration) error { return errNoSet }

// A sink that does not answer in time lets the reply go: the reply is held at most the wait.
type slowSink struct{}

func (slowSink) add(keys [][]byte, wait time.Duration) error {
	time.Sleep(wait)
	return errLate
}

func TestLearnLateWrite(t *testing.T) {
	s, _ := testService()
	s.sink = slowSink{}
	s.wait = 20 * time.Millisecond
	c, fake := session(s, fakePacket{trackerAnnounceRequest(3), trackerFar})
	sendAll(t, c)
	start := time.Now()
	reply(t, c, trackerAnnounceReply(3, testPeers), trackerFar)
	if held := time.Since(start); held > 200*time.Millisecond || len(fake.written) != 1 || s.counters.late.Load() != 1 {
		t.Errorf("held %v, written %d, late %d", held, len(fake.written), s.counters.late.Load())
	}
}

// The writer with no set to write: every request answered, none waits past its bound.
func TestWriterNoSet(t *testing.T) {
	w := newWriter("NoSuchTable", "no_set", time.Minute, 100*time.Millisecond, &counters{})
	if err := w.start(); err != nil {
		t.Skip("no netlink here: ", err)
	}
	defer w.close()
	start := time.Now()
	err := w.add([][]byte{elementKey(testDevice, testPeers[0])}, time.Second)
	if err == nil || time.Since(start) > time.Second+100*time.Millisecond {
		t.Errorf("%v after %v", err, time.Since(start))
	}
}

// A session whose device sends something that is no discovery before any request stands aside.
// The DHT's messages that ask for no peers (a bootstrap's find_node, a ping) and a tracker's scrape
// (whose connection id may begin as uTP does) keep it, and so does a request before.
func TestLearnQuiet(t *testing.T) {
	other := fakePacket{[]byte{0x17, 0x03, 0x03, 0, 1, 2}, trackerFar}
	s, _ := testService()
	c, _ := session(s, other)
	sendAll(t, c)
	if !c.ReaderReplaceable() || s.counters.quietSessions.Load() != 1 {
		t.Errorf("a session of another protocol did not stand aside")
	}
	s, sink := testService()
	var packets []fakePacket
	for i := range 100 {
		packets = append(packets, fakePacket{dhtFindNode(strconv.Itoa(i)), dhtNodeFar})
	}
	packets = append(packets, fakePacket{scrapeRequest(0x41), trackerFar}, fakePacket{dhtGetPeers("q9"), dhtNodeFar})
	c, _ = session(s, packets...)
	sendAll(t, c)
	reply(t, c, dhtValues("q9", testPeers), dhtNodeFar)
	if c.ReaderReplaceable() || sink.count() != 3 || s.counters.quietSessions.Load() != 0 || s.counters.utpSessions.Load() != 0 {
		t.Errorf("a session of discovery stood aside: learned %d, quiet %d, uTP %d", sink.count(),
			s.counters.quietSessions.Load(), s.counters.utpSessions.Load())
	}
	s, sink = testService()
	c, _ = session(s, fakePacket{trackerAnnounceRequest(4), trackerFar}, other)
	sendAll(t, c)
	reply(t, c, trackerAnnounceReply(4, testPeers), trackerFar)
	if c.ReaderReplaceable() || sink.count() != 3 {
		t.Errorf("a session that asked stood aside: learned %d", sink.count())
	}
}

// The device's packets are not held while a reply waits for the set.
func TestLearnReplyUnlocked(t *testing.T) {
	s, _ := testService()
	s.sink = slowSink{}
	s.wait = 300 * time.Millisecond
	c, _ := session(s, fakePacket{trackerAnnounceRequest(3), trackerFar})
	sendAll(t, c)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.WritePacket(buf.As(trackerAnnounceReply(3, testPeers)), trackerFar)
	}()
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	c.request(dhtGetPeers("q2"), dhtNodeFar.AddrPort(), time.Now())
	if held := time.Since(start); held > 100*time.Millisecond {
		t.Errorf("a request of the device waited %v for a reply's write", held)
	}
	<-done
}
