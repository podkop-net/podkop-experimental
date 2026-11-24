package bittorrent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/nftables"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
)

// The tests of the limits and the corrections of 0.8.19 (the review of 0.8.18).

// One reply teaches at most replyMost peers, each once; the rest are counted and left.
func TestLearnReplyMost(t *testing.T) {
	s, sink := testService()
	var peers []netip.AddrPort
	for i := range 1000 {
		peers = append(peers, netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, byte(113 + i>>8), byte(i)}), 51413))
	}
	// the first named five times over
	peers = append([]netip.AddrPort{peers[0], peers[0], peers[0], peers[0]}, peers...)
	c, _ := session(s, fakePacket{trackerAnnounceRequest(1), trackerFar}, fakePacket{trackerAnnounceRequest(2), trackerFar})
	sendAll(t, c)
	reply(t, c, trackerAnnounceReply(1, peers), trackerFar)
	if sink.count() != replyMost || s.counters.overReply.Load() != int64(1000-replyMost) || s.counters.learned.Load() != replyMost {
		t.Fatalf("learned %d of %d, left %d of %d", sink.count(), replyMost, s.counters.overReply.Load(), 1000-replyMost)
	}
	seen := make(map[string]bool)
	for _, key := range sink.keys {
		seen[string(key)] = true
	}
	if len(seen) != replyMost {
		t.Errorf("%d distinct keys of %d written", len(seen), replyMost)
	}
	// the same reply again writes the same peers again (an add of userspace cannot tell what the
	// set holds), and takes no more of the device's cap
	reply(t, c, trackerAnnounceReply(2, peers), trackerFar)
	if sink.count() != 2*replyMost || s.counters.known.Load() != replyMost {
		t.Errorf("the second reply: written %d, known %d", sink.count(), s.counters.known.Load())
	}
}

// A peer on a common port is learned by its own handshake (learnFar), never by a reply's word.
func TestLearnFarCommonPort(t *testing.T) {
	s, sink := testService()
	s.learn(testDevice, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.8:443"), netip.MustParseAddrPort("203.0.113.8:80")})
	if sink.count() != 0 || s.counters.notLearnable.Load() != 2 {
		t.Fatalf("a reply taught peers on common ports: %d, left %d", sink.count(), s.counters.notLearnable.Load())
	}
	for _, far := range []string{"203.0.113.7:443", "203.0.113.7:80", "203.0.113.7:51413"} {
		if !s.learnFar(testDevice, netip.MustParseAddrPort(far)) {
			t.Errorf("the far end %s of a confirmed connection was not learned", far)
		}
	}
	if sink.count() != 3 {
		t.Errorf("learned %d far ends of 3", sink.count())
	}
	for _, far := range []string{"192.168.1.5:443", "198.18.0.9:443", "0.1.2.3:443", "240.0.0.1:51413", "203.0.113.7:0"} {
		if s.learnFar(testDevice, netip.MustParseAddrPort(far)) {
			t.Errorf("the far end %s was learned", far)
		}
	}
}

// A get_peers query with a transaction id longer than dhtIDLongest is not kept: its answer is not
// paired, and nothing is learned from it.
func TestLearnLongTransaction(t *testing.T) {
	s, sink := testService()
	long, short := strings.Repeat("x", dhtIDLongest+1), strings.Repeat("y", dhtIDLongest)
	c, _ := session(s, fakePacket{dhtGetPeers(long), dhtNodeFar}, fakePacket{dhtGetPeers(short), dhtNodeFar})
	sendAll(t, c)
	if len(c.pending) != 1 {
		t.Fatalf("%d requests kept of 1", len(c.pending))
	}
	reply(t, c, dhtValues(long, testPeers[:1]), dhtNodeFar)
	if sink.count() != 0 {
		t.Errorf("an answer to a query with a long transaction id was learned")
	}
	reply(t, c, dhtValues(short, testPeers[:1]), dhtNodeFar)
	if sink.count() != 1 {
		t.Errorf("an answer to a query with a transaction id of %d bytes was not learned", dhtIDLongest)
	}
}

// Devices with nothing counted within the window are forgotten once a window; past devicesMost
// devices within it, nothing is counted for another.
func TestDevicesForgotten(t *testing.T) {
	d := devices{cap: 16, window: time.Minute}
	start := time.Unix(1000, 0)
	peer := netip.MustParseAddrPort("203.0.113.7:51413")
	device := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}) }
	for i := range 10 {
		d.take(device(i), [][]byte{elementKey(device(i), peer)}, start)
	}
	d.take(device(0), [][]byte{elementKey(device(0), peer)}, start.Add(2*time.Minute))
	if len(d.counted) != 1 {
		t.Errorf("%d devices kept of 1 after the window", len(d.counted))
	}
	d = devices{cap: 16, window: time.Minute}
	for i := range devicesMost {
		d.take(device(i), [][]byte{elementKey(device(i), peer)}, start)
	}
	taken, _, capped := d.take(device(devicesMost), [][]byte{elementKey(device(devicesMost), peer)}, start.Add(time.Second))
	if len(taken) != 0 || capped != 1 || len(d.counted) != devicesMost {
		t.Errorf("one device too many: taken %d, capped %d, devices %d", len(taken), capped, len(d.counted))
	}
	// those of the first window go when it has passed, and there is room again
	taken, _, _ = d.take(device(devicesMost), [][]byte{elementKey(device(devicesMost), peer)}, start.Add(2*time.Minute))
	if len(taken) != 1 || len(d.counted) != 1 {
		t.Errorf("after the window: taken %d, devices %d", len(taken), len(d.counted))
	}
}

// early gives a service of the early check and a function that adds n connections of the device
// confirmed at a time, to far addresses from first on.
func early(t *testing.T, confirmed Confirmed) (*Service, *recordSink, func(first int, n int, at time.Time) []*conn) {
	s, sink := testService()
	s.pending = make(map[netip.Addr][]*waiting)
	return s, sink, func(first int, n int, at time.Time) []*conn {
		var conns []*conn
		for i := range n {
			device, other := net.Pipe()
			t.Cleanup(func() { other.Close() })
			far := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(first + i)}), 51413)
			c := &conn{Conn: device, service: s, cnt: &s.early, early: true, device: testDevice, far: far, inspect: true, confirmed: confirmed}
			c.done.Store(true)
			c.waits = s.pend(c, at)
			conns = append(conns, c)
		}
		return conns
	}
}

// The bug of 0.8.18: a device told by its own peers was judged only while a connection of some
// device waited. With none waiting (the usual state: its connections were just closed), one that
// connected again stayed "watched", and its next confirmed connection, hours later, took it for
// one that had not connected again: its connections were left open for earlyFor. And one that did
// not connect again was not told so until a connection waited.
func TestEarlyWatchWithNothingWaiting(t *testing.T) {
	for _, retries := range []bool{true, false} {
		s, _, add := early(t, ConfirmedLearnReset)
		known := false
		s.known = func() (map[netip.Addr]bool, error) { return map[netip.Addr]bool{testDevice: known}, nil }
		start := time.Now()
		add(10, 3, start)
		s.actOnKnown(start)
		if s.early.reset.Load() != 3 || len(s.pending) != 0 || len(s.selfTold) != 1 {
			t.Fatalf("the first three: reset %d, waiting %d, watched %d", s.early.reset.Load(), len(s.pending), len(s.selfTold))
		}
		known = retries
		s.actOnKnown(start.Add(10 * time.Second))
		if retries {
			if len(s.selfTold) != 0 {
				t.Fatalf("a device that connected again is still watched, with nothing waiting")
			}
			// two hours later the device is in no set, and one connection of it is confirmed
			known = false
			later := start.Add(2 * time.Hour)
			add(20, 1, later)
			s.actOnKnown(later)
			if s.earlyNoRetry.Load() != 0 || len(s.noRetry) != 0 || len(s.pending[testDevice]) != 1 {
				t.Errorf("taken as one that did not connect again: no retry %d, waiting %d", s.earlyNoRetry.Load(), len(s.pending[testDevice]))
			}
			continue
		}
		s.actOnKnown(start.Add(earlyRetry + time.Second))
		if s.earlyNoRetry.Load() != 1 || len(s.noRetry) != 1 || len(s.selfTold) != 0 {
			t.Errorf("a device that did not connect again, nothing waiting: no retry %d, watched %d", s.earlyNoRetry.Load(), len(s.selfTold))
		}
	}
}

// A connection that closed while it waited counts as a peer the device shook hands with; when the
// device is known its far end is learned (not in block), and it is not closed or counted again.
func TestEarlyClosedWhileWaiting(t *testing.T) {
	for _, confirmed := range []Confirmed{ConfirmedLearnReset, ConfirmedReject} {
		s, sink, add := early(t, confirmed)
		s.known = func() (map[netip.Addr]bool, error) { return map[netip.Addr]bool{}, nil }
		start := time.Now()
		conns := add(10, 3, start)
		_ = conns[0].Close()
		if conns[0].waits != nil || s.pending[testDevice][0].conn.Load() != nil {
			t.Fatalf("a closed connection is still held")
		}
		s.actOnKnown(start)
		if s.earlySelfTold.Load() != 1 || s.earlyGone.Load() != 1 || s.earlyActed.Load() != 2 {
			t.Fatalf("%s: told %d, gone %d of 1, acted %d of 2", confirmed, s.earlySelfTold.Load(), s.earlyGone.Load(), s.earlyActed.Load())
		}
		switch confirmed {
		case ConfirmedLearnReset:
			if sink.count() != 3 || s.early.reset.Load() != 2 {
				t.Errorf("learned %d of 3, reset %d of 2", sink.count(), s.early.reset.Load())
			}
		case ConfirmedReject:
			if sink.count() != 0 || s.early.rejected.Load() != 2 {
				t.Errorf("block: learned %d, rejected %d of 2", sink.count(), s.early.rejected.Load())
			}
		}
	}
}

// A read of the set of devices that fails acts on nothing, is counted, and the connections that
// waited earlyFor still go; a panic of a round ends the round.
func TestEarlyReadFails(t *testing.T) {
	s, sink, add := early(t, ConfirmedLearnReset)
	reads := 0
	s.known = func() (map[netip.Addr]bool, error) { reads++; return nil, errors.New("no netlink") }
	start := time.Now()
	add(10, 3, start)
	s.actOnKnown(start)
	s.actOnKnown(start.Add(2 * time.Second))
	if s.earlyReadFailed.Load() != 2 || sink.count() != 0 || len(s.pending[testDevice]) != 3 || !s.knownFailing {
		t.Fatalf("failed reads %d of 2, learned %d, waiting %d", s.earlyReadFailed.Load(), sink.count(), len(s.pending[testDevice]))
	}
	s.actOnKnown(start.Add(earlyFor + time.Second))
	if len(s.pending) != 0 || s.earlyExpired.Load() != 3 || reads != 2 {
		t.Errorf("after earlyFor: waiting %d, expired %d of 3, reads %d of 2", len(s.pending), s.earlyExpired.Load(), reads)
	}
	add(20, 1, start)
	s.known = func() (map[netip.Addr]bool, error) { panic("a fault of the read") }
	s.poll(start)
	if s.counters.panics.Load() != 1 {
		t.Errorf("a panic of a round: counted %d", s.counters.panics.Load())
	}
	// the lock of the waiting connections is free after it
	add(30, 1, start)
}

// tcpPair is a TCP connection on loopback: the side the module wraps, and its other end.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := listener.Accept()
		accepted <- c
	}()
	near, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	far := <-accepted
	t.Cleanup(func() { near.Close(); far.Close() })
	return near.(*net.TCPConn), far.(*net.TCPConn)
}

// CloseWrite of a conn that has not stood aside half-closes the connection under it: the device
// reads the end and can still send. Over a connection that cannot, it closes it.
func TestConnCloseWrite(t *testing.T) {
	s, _ := testService()
	inbound, device := tcpPair(t)
	c := &conn{Conn: inbound, service: s, cnt: &s.counters, device: testDevice, far: testFar, inspect: true, confirmed: ConfirmedLearn}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = device.SetDeadline(time.Now().Add(5 * time.Second))
	if n, err := device.Read(make([]byte, 8)); n != 0 || err != io.EOF {
		t.Fatalf("the device read %d, %v: not the end", n, err)
	}
	if _, err := device.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	_ = inbound.SetDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 8)
	if n, err := c.Read(buffer); n != 4 || err != nil {
		t.Errorf("after the half-close the conn read %d, %v", n, err)
	}
	if s.counters.noData.Load() != 0 || c.gone {
		t.Errorf("a half-close was taken as the connection's end")
	}
	near, other := net.Pipe()
	defer other.Close()
	c = &conn{Conn: near, service: s, cnt: &s.counters, device: testDevice, far: testFar, inspect: true, confirmed: ConfirmedLearn}
	_ = c.CloseWrite()
	if s.counters.noData.Load() != 1 || !c.gone {
		t.Errorf("a connection with no half-close was not closed: verdicts %d", s.counters.noData.Load())
	}
}

const clientRequest = "GET /announce?info_hash=%12%34&peer_id=-qB5000-abcdefghijkl&port=51413&compact=1 HTTP/1.1\r\nHost: tracker.example:6969\r\n" +
	"User-Agent: qBittorrent/5.0.0\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"

func announcing(s *Service, request string) (*conn, net.Conn) {
	near, other := net.Pipe()
	c := &conn{Conn: near, service: s, cnt: &s.counters, device: testDevice, far: testFar}
	c.sent([]byte(request), time.Now())
	return c, other
}

// A request with an announce's path that a browser sent, or one with no info_hash, is not read as
// an announce: the answer of its server teaches nothing.
func TestAnnounceForeign(t *testing.T) {
	s, sink := testService()
	body := "d8:intervali1800e5:peers" + bstring(compact(testPeers)) + "e"
	answer := []byte("HTTP/1.1 200 OK\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + body)
	for name, request := range map[string]string{
		"a browser's language": "GET /announce?info_hash=%12%34&port=51413 HTTP/1.1\r\nHost: t.example:8000\r\nUser-Agent: Mozilla/5.0\r\nAccept-Language: en-US,en;q=0.9\r\n\r\n",
		"a page's referer":     "GET /announce?info_hash=%12%34 HTTP/1.1\r\nHost: t.example:8000\r\nReferer: http://page.example/\r\n\r\n",
		"no info_hash":         "GET /announce?x=1 HTTP/1.1\r\nHost: t.example:8000\r\n\r\n",
	} {
		c, other := announcing(s, request)
		c.answers(answer, time.Now())
		other.Close()
		if !c.done.Load() || sink.count() != 0 {
			t.Errorf("%s: read as an announce (learned %d)", name, sink.count())
		}
	}
	if s.counters.announcesForeign.Load() != 3 || s.counters.announces.Load() != 0 {
		t.Errorf("foreign %d of 3, announces %d", s.counters.announcesForeign.Load(), s.counters.announces.Load())
	}
	c, other := announcing(s, clientRequest)
	defer other.Close()
	c.answers(answer, time.Now())
	if sink.count() != 3 || s.counters.announces.Load() != 1 || s.replyBytes.Load() != 0 {
		t.Errorf("a client's announce: learned %d of 3, kept %d bytes", sink.count(), s.replyBytes.Load())
	}
}

func itoa(n int) string {
	var digits []byte
	for ; n > 0 || len(digits) == 0; n /= 10 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
	}
	return string(digits)
}

// What the conns keep of replies is bounded for each and in all, and is let go when a conn stands
// aside or its connection ends.
func TestReplyBudget(t *testing.T) {
	s, sink := testService()
	// in all: no room left
	s.replyBytes.Store(httpRepliesMost - 10)
	c, other := announcing(s, clientRequest)
	c.answers([]byte("HTTP/1.1 200 OK\r\nContent-Length: 400\r\n\r\n"), time.Now())
	other.Close()
	if !c.done.Load() || s.counters.announceUnread.Load() != 1 || s.replyBytes.Load() != httpRepliesMost-10 {
		t.Fatalf("no room in all: unread %d, kept %d", s.counters.announceUnread.Load(), s.replyBytes.Load())
	}
	s.replyBytes.Store(0)
	// one reply: a part is kept until the connection ends
	c, other = announcing(s, clientRequest)
	part := []byte("HTTP/1.1 200 OK\r\nContent-Length: 400\r\n\r\nd8:intervali1800e")
	c.answers(part, time.Now())
	if s.replyBytes.Load() != int64(len(part)) {
		t.Fatalf("kept %d of %d bytes", s.replyBytes.Load(), len(part))
	}
	_ = c.Close()
	other.Close()
	if s.replyBytes.Load() != 0 || s.counters.announceUnread.Load() != 2 {
		t.Errorf("after the close: kept %d, unread %d of 2", s.replyBytes.Load(), s.counters.announceUnread.Load())
	}
	// one reply longer than the limit
	c, other = announcing(s, clientRequest)
	defer other.Close()
	c.answers([]byte("HTTP/1.1 200 OK\r\n\r\nd5:peers"), time.Now())
	fill := bytes.Repeat([]byte{'1'}, 16<<10)
	for range 8 {
		if c.done.Load() {
			break
		}
		c.answers(fill, time.Now())
	}
	if !c.done.Load() || s.replyBytes.Load() != 0 || s.counters.announceUnread.Load() != 3 || sink.count() != 0 {
		t.Errorf("a reply past the limit: done %v, kept %d, unread %d of 3", c.done.Load(), s.replyBytes.Load(), s.counters.announceUnread.Load())
	}
}

// A reply that comes a byte at a time is read with a few decodings, not one for each byte; a body
// that ends with its connection and was not decoded whole before is read at the end, at the
// half-close as well.
func TestReplyStages(t *testing.T) {
	s, sink := testService()
	body := "d8:intervali1800e5:peers" + bstring(compact(testPeers)) + "e"
	chunked := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + "a\r\n" + body[:10] + "\r\n" + itoa16(len(body)-10) + "\r\n" + body[10:] + "\r\n0\r\n\r\n"
	c, other := announcing(s, clientRequest)
	for i := range len(chunked) {
		c.answers([]byte{chunked[i]}, time.Now())
	}
	other.Close()
	if sink.count() != 3 || c.parses > 2 {
		t.Fatalf("a chunked reply a byte at a time: learned %d of 3, decoded %d times", sink.count(), c.parses)
	}
	for _, half := range []bool{false, true} {
		s, sink = testService()
		inbound, device := tcpPair(t)
		c = &conn{Conn: inbound, service: s, cnt: &s.counters, device: testDevice, far: testFar}
		c.sent([]byte(clientRequest), time.Now())
		// decoded as often as allowed already: the end of the connection reads it
		c.parses = httpParsesMost
		c.answers([]byte("HTTP/1.0 200 OK\r\n\r\n"+body), time.Now())
		if sink.count() != 0 {
			t.Fatalf("decoded past the allowed times")
		}
		if half {
			_ = c.CloseWrite()
		} else {
			_ = c.Close()
		}
		_ = device.Close()
		if sink.count() != 3 || s.replyBytes.Load() != 0 {
			t.Errorf("half-close %v: learned %d of 3 at the end, kept %d", half, sink.count(), s.replyBytes.Load())
		}
	}
}

func itoa16(n int) string {
	const digits = "0123456789abcdef"
	if n < 16 {
		return digits[n : n+1]
	}
	return itoa16(n/16) + digits[n%16:n%16+1]
}

// fakeSetConn stands in for a netlink connection of the writer.
type fakeSetConn struct {
	lookup error
	flush  func() error
	access sync.Mutex
	added  int
	closed atomic.Bool
}

func (f *fakeSetConn) GetSetByName(table *nftables.Table, name string) (*nftables.Set, error) {
	if f.lookup != nil {
		return nil, f.lookup
	}
	return &nftables.Set{Table: table, Name: name}, nil
}

func (f *fakeSetConn) SetAddElements(set *nftables.Set, elements []nftables.SetElement) error {
	f.access.Lock()
	defer f.access.Unlock()
	f.added += len(elements)
	return nil
}

func (f *fakeSetConn) Flush() error {
	if f.flush != nil {
		return f.flush()
	}
	return nil
}

func (f *fakeSetConn) CloseLasting() error { f.closed.Store(true); return nil }

// writerOf gives a writer whose connections are conns, in their order (the last one again after).
func writerOf(wait time.Duration, conns ...*fakeSetConn) (*writer, *counters) {
	count := &counters{}
	w := newWriter("table", "set", time.Minute, wait, count)
	var opened atomic.Int64
	w.open = func() (setConn, error) {
		index := min(int(opened.Add(1))-1, len(conns)-1)
		return conns[index], nil
	}
	return w, count
}

var oneKey = [][]byte{elementKey(netip.MustParseAddr("192.168.80.10"), netip.MustParseAddrPort("203.0.113.7:51413"))}

// A write the kernel never answers: the replies are not held for it past stuckAfter, and another
// goroutine with a connection of its own takes the writes over.
func TestWriterStuck(t *testing.T) {
	release := make(chan struct{})
	stuck := &fakeSetConn{flush: func() error { <-release; return nil }}
	healthy := &fakeSetConn{}
	w, count := writerOf(20*time.Millisecond, stuck, healthy)
	if err := w.start(); err != nil {
		t.Fatal(err)
	}
	if err := w.add(oneKey, 20*time.Millisecond); err != errLate {
		t.Fatalf("the stuck write answered %v", err)
	}
	time.Sleep(w.stuckAfter + 30*time.Millisecond)
	began := time.Now()
	if err := w.add(oneKey, time.Second); err != errLate || time.Since(began) > 100*time.Millisecond {
		t.Fatalf("with a stuck write: %v after %v", err, time.Since(began))
	}
	if count.writerRestarts.Load() != 1 {
		t.Fatalf("taken over %d times of 1", count.writerRestarts.Load())
	}
	if err := w.add(oneKey, time.Second); err != nil {
		t.Fatalf("after the take-over: %v", err)
	}
	if healthy.added != 1 {
		t.Errorf("the new connection wrote %d of 1", healthy.added)
	}
	// the goroutine left behind ends when its write does, and closes its connection
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for !stuck.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !stuck.closed.Load() {
		t.Errorf("the goroutine left behind did not end")
	}
	if err := w.add(oneKey, time.Second); err != nil {
		t.Errorf("after the old write ended: %v", err)
	}
	began = time.Now()
	w.close()
	if time.Since(began) > time.Second || !healthy.closed.Load() {
		t.Errorf("close took %v, the connection closed %v", time.Since(began), healthy.closed.Load())
	}
}

// A panic of a write fails its batch, and the writer goes on with a fresh connection; a set that
// cannot be looked up on a connection is looked up on a fresh one.
func TestWriterFaults(t *testing.T) {
	faulty := &fakeSetConn{flush: func() error { panic("a fault of the library") }}
	healthy := &fakeSetConn{}
	w, count := writerOf(100*time.Millisecond, faulty, healthy)
	if err := w.start(); err != nil {
		t.Fatal(err)
	}
	if err := w.add(oneKey, time.Second); err != errFault || count.panics.Load() != 1 {
		t.Fatalf("a panic of the write: %v, counted %d", err, count.panics.Load())
	}
	if err := w.add(oneKey, time.Second); err != nil || healthy.added != 1 || !faulty.closed.Load() {
		t.Errorf("after the panic: %v, written %d, the old connection closed %v", err, healthy.added, faulty.closed.Load())
	}
	w.close()

	broken := &fakeSetConn{lookup: errors.New("a broken connection")}
	healthy = &fakeSetConn{}
	w, _ = writerOf(100*time.Millisecond, broken, healthy)
	if err := w.start(); err != nil {
		t.Fatal(err)
	}
	defer w.close()
	if err := w.add(oneKey, time.Second); err != nil || healthy.added != 1 || !broken.closed.Load() {
		t.Errorf("a set not found on the first connection: %v, written %d", err, healthy.added)
	}
}

// A first data of MSE's length that is text, or a header with zero bytes, where MSE's first
// message has its key is not inspected further (0.8.19, the study of 2026-11-18): SIP's REGISTER
// and PostgreSQL's startup message were confirmed on every connection, as the far side's answer
// and the client's next message have MSE's lengths and timing.
func TestLooksRandom(t *testing.T) {
	sip := []byte("REGISTER sip:192.0.2.10:5060 SIP/2.0\r\nVia: SIP/2.0/TCP 192.168.80.10:5061;branch=z9hG4bK-1-0\r\nFrom: <sip:1001@192.0.2.10>;tag=1\r\n")
	// PostgreSQL's startup message: the length, the protocol 3.0, then names and values
	postgres := append([]byte{0, 0, 0, 138, 0, 3, 0, 0}, []byte("user\x00an_application_user_with_a_long_name\x00database\x00a_database_with_a_long_name\x00application_name\x00psql\x00\x00")...)
	key := []byte{0x9c, 0x31, 0x00, 0xf2, 0x41, 0x42, 0x00, 0x7e, 0x20, 0xd5, 0x00, 0x11, 0x61, 0x62, 0x63, 0xff}
	for name, c := range map[string]struct {
		data []byte
		want bool
	}{
		"SIP":                    {sip, false},
		"PostgreSQL":             {postgres, false},
		"text with a tab":        {[]byte("a\tb\r\nc d e f g h i j k l m n o p"), false},
		"four zero bytes":        {[]byte{0x9c, 0, 0x31, 0, 0xf2, 0, 0x41, 0, 0x42, 0x7e, 0x20, 0xd5, 0x11, 0x61, 0x62, 0xff}, false},
		"three zero bytes":       {key, true},
		"a byte over the text's": {append([]byte("REGISTER sip:19"), 0x80), true},
		"zeros after the head":   {append(append([]byte{}, key...), make([]byte, 80)...), true},
		"shorter than the head":  {[]byte{0x9c, 0x31}, true},
	} {
		if got := looksRandom(c.data); got != c.want {
			t.Errorf("%s: looks random %v, want %v", name, got, c.want)
		}
	}
	// the exchange of a SIP registration through the inspection: not confirmed, counted, and the
	// connection goes on whole; the same exchange with a random first data is confirmed
	e := exchange{first: len(sip), answer: 430, third: 544, bulk: 1 << 16}
	s, sink, wrapped, got, err := run(t, e, ConfirmedReject, sip)
	if err != nil || got != e.bulk {
		t.Errorf("SIP: bulk %d of %d: %v", got, e.bulk, err)
	}
	if s.counters.confirmed.Load() != 0 || s.counters.inspected.Load() != 0 || s.counters.notRandom.Load() != 1 || s.counters.notShaped.Load() != 1 || sink.count() != 0 {
		t.Errorf("SIP: %v", s.counters.snapshot())
	}
	if wrapped.NeedHandshakeForRead() {
		t.Errorf("SIP: not stood aside")
	}
	s, _, _, got, _ = run(t, e, ConfirmedReject, nil)
	if got != 0 || s.counters.confirmed.Load() != 1 || s.counters.notRandom.Load() != 0 {
		t.Errorf("the same lengths, random: bulk %d, %v", got, s.counters.snapshot())
	}
}

// In block, the connection that makes a device's third distinct far address wakes the poller,
// which judges the device at once (0.8.19): 0.8.18 judged it at the next round, up to earlyPoll
// later, and a client with encryption required passed megabytes meanwhile. Not for fewer far
// addresses, not outside block (learn_reset waits for the round, see pend), not while the set
// cannot be read.
func TestEarlyKick(t *testing.T) {
	asked := func(s *Service) bool {
		select {
		case <-s.kick:
			return true
		default:
			return false
		}
	}
	s, _, add := early(t, ConfirmedReject)
	s.kick = make(chan struct{}, 1)
	s.stopPolling = make(chan struct{})
	s.known = func() (map[netip.Addr]bool, error) { return map[netip.Addr]bool{}, nil }
	start := time.Now()
	add(10, 2, start)
	add(10, 1, start)
	if asked(s) {
		t.Fatalf("a round asked for with two distinct far addresses")
	}
	add(12, 1, start)
	if len(s.kick) != 1 {
		t.Fatalf("no round asked for at the third distinct far address")
	}
	// the poller acts on it well within a round
	go s.pollPending()
	defer close(s.stopPolling)
	deadline := time.Now().Add(earlyPoll / 4)
	for s.early.rejected.Load() != 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.early.rejected.Load() != 4 || s.earlySelfTold.Load() != 1 {
		t.Fatalf("within %s: rejected %d of 4, told %d", earlyPoll/4, s.early.rejected.Load(), s.earlySelfTold.Load())
	}

	// learn_reset: the round judges the device, as in 0.8.18
	reset, _, add := early(t, ConfirmedLearnReset)
	reset.kick = make(chan struct{}, 1)
	reset.known = func() (map[netip.Addr]bool, error) { return map[netip.Addr]bool{}, nil }
	add(10, 3, start)
	if asked(reset) {
		t.Errorf("learn_reset: a round asked for at the third")
	}

	// the set cannot be read: the rounds try again, a connection does not ask for one more
	failing, _, add := early(t, ConfirmedReject)
	failing.kick = make(chan struct{}, 1)
	failing.known = func() (map[netip.Addr]bool, error) { return nil, errors.New("no netlink") }
	add(10, 3, start)
	if !asked(failing) {
		t.Fatalf("no round asked for before the read failed")
	}
	failing.actOnKnown(start)
	add(20, 1, start)
	if asked(failing) {
		t.Errorf("a round asked for while the set cannot be read")
	}
}

// On an inbound of discovery a connection is watched for an announce whatever the sniffer named
// it, HTTP or nothing (0.8.19: the BitTorrent inbound is not sniffed, and the firewall sends the
// announces to a known tracker there); of the transparent proxy, only one named HTTP. One watched
// for an announce only stands aside at any other first data and counts nothing: in the section
// the peers' connections come through the same inbound.
func TestAnnounceOnLearnInbound(t *testing.T) {
	s, sink := testService()
	s.learnOn = map[string]bool{"bt-in": true}
	s.sniffedOn = map[string]bool{"tproxy-in": true}
	wraps := func(inbound string, protocol string) *conn {
		near, other := net.Pipe()
		t.Cleanup(func() { near.Close(); other.Close() })
		routed := s.RoutedConnection(context.Background(), near, adapter.InboundContext{Inbound: inbound, Protocol: protocol,
			Source: M.ParseSocksaddr("192.168.80.10:50000"), Destination: M.ParseSocksaddr("203.0.113.9:6969")}, nil, nil)
		wrapped, _ := routed.(*conn)
		return wrapped
	}
	for _, c := range []struct {
		inbound, protocol string
		want              bool
	}{
		{"bt-in", "", true}, {"bt-in", C.ProtocolHTTP, true}, {"bt-in", C.ProtocolTLS, false}, {"bt-in", C.ProtocolBitTorrent, false},
		{"tproxy-in", C.ProtocolHTTP, true}, {"tproxy-in", "", false}, {"mixed-in", C.ProtocolHTTP, false},
	} {
		if got := wraps(c.inbound, c.protocol); (got != nil) != c.want {
			t.Errorf("%s, protocol %q: watched %v, want %v", c.inbound, c.protocol, got != nil, c.want)
		} else if got != nil && (got.inspect || got.early) {
			t.Errorf("%s, protocol %q: inspected", c.inbound, c.protocol)
		}
	}
	// an announce: its reply is read
	body := "d8:intervali1800e5:peers" + bstring(compact(testPeers)) + "e"
	announce := wraps("bt-in", "")
	announce.sent([]byte(clientRequest), time.Now())
	announce.answers([]byte("HTTP/1.1 200 OK\r\nContent-Length: "+itoa(len(body))+"\r\n\r\n"+body), time.Now())
	if sink.count() != 3 || s.counters.announces.Load() != 1 || !announce.done.Load() {
		t.Errorf("an announce on the BitTorrent inbound: learned %d of 3, announces %d", sink.count(), s.counters.announces.Load())
	}
	// a peer's connection: a plaintext handshake, or MSE's first message
	for name, first := range map[string][]byte{"a plaintext handshake": append(append([]byte{}, plaintextHandshake...), make([]byte, 48)...), "MSE": randomBytes(200)} {
		peer := wraps("bt-in", "")
		peer.sent(first, time.Now())
		if !peer.done.Load() {
			t.Errorf("%s: not stood aside", name)
		}
	}
	counted := s.counters.snapshot()
	for _, name := range []string{"plaintext", "confirmed", "watched", "inspected", "not_shaped", "handed_back"} {
		want := int64(0)
		if name == "handed_back" {
			want = 3
		}
		if counted[name] != want {
			t.Errorf("%s: %d, want %d", name, counted[name], want)
		}
	}
}

// A suspect (a device the firewall suspects by the fan-out of its connection
// openings, its connections on an early inbound of its own) that the early check tells is put in
// the set of devices by the module, and the connections it opened before are ended, once within
// endOlderEvery, before its confirmed connections are acted on. A device of the transparent proxy
// is not.
func TestSuspectTold(t *testing.T) {
	var calls []netip.Addr
	// (kept known: a device whose handshake is confirmed again keepKnownEvery after it was told
	// is put back in the firewall's set, off the connection's path)
	keptKnown := make(chan netip.Addr, 16)
	// the hooks the backend gives every service of the module (each service below has them)
	hooks := Hooks{
		EndOlder: func(device netip.Addr) (int, error) {
			calls = append(calls, device)
			return 7, nil
		},
		KeepKnown: func(device netip.Addr) error {
			keptKnown <- device
			return nil
		},
	}
	suspects := func(conns []*conn) {
		for _, c := range conns {
			c.suspect, c.waits.suspect = true, true
		}
	}
	s, _, add := early(t, ConfirmedReject)
	s.hooks = hooks
	hosts := &recordSink{}
	s.hostsSink = hosts
	s.known = func() (map[netip.Addr]bool, error) { return map[netip.Addr]bool{}, nil }
	start := time.Now()
	suspects(add(10, 2, start))
	s.actOnKnown(start)
	if len(calls) != 0 || hosts.count() != 0 || s.early.rejected.Load() != 0 {
		t.Fatalf("two distinct far addresses: ended %d times, devices written %d, rejected %d", len(calls), hosts.count(), s.early.rejected.Load())
	}
	suspects(add(12, 1, start))
	s.actOnKnown(start)
	if len(calls) != 1 || calls[0] != testDevice || hosts.count() != 1 || string(hosts.keys[0]) != string(testDevice.AsSlice()) {
		t.Fatalf("the third: ended for %v, devices written %x", calls, hosts.keys)
	}
	if s.early.rejected.Load() != 3 || s.earlySuspects.Load() != 1 || s.earlyEnded.Load() != 7 {
		t.Fatalf("the third: rejected %d, suspects %d, ended %d", s.early.rejected.Load(), s.earlySuspects.Load(), s.earlyEnded.Load())
	}
	// within endOlderEvery: its next confirmed connections are closed, nothing is ended again
	suspects(add(20, 2, start.Add(10*time.Second)))
	s.actOnKnown(start.Add(10 * time.Second))
	if len(calls) != 1 || s.early.rejected.Load() != 5 {
		t.Fatalf("ten seconds later: ended %d times, rejected %d", len(calls), s.early.rejected.Load())
	}
	// after it: once more
	suspects(add(30, 1, start.Add(2*endOlderEvery)))
	s.actOnKnown(start.Add(2 * endOlderEvery))
	if len(calls) != 2 || hosts.count() != 2 {
		t.Fatalf("after endOlderEvery: ended %d times, devices written %d", len(calls), hosts.count())
	}

	// the module wrote the device when it told it, and its confirmed connections since came
	// within keepKnownEvery: not kept known again yet; with the suspicion on (an inbound of
	// suspects) and the time gone, once
	select {
	case device := <-keptKnown:
		t.Fatalf("kept known within keepKnownEvery: %v", device)
	default:
	}
	s.suspectOn = map[string]bool{"bt-suspect": true}
	s.keepKnown(testDevice)
	s.pendingMu.Lock()
	s.kept[testDevice] = time.Now().Add(-2 * keepKnownEvery)
	s.pendingMu.Unlock()
	s.keepKnown(testDevice)
	s.keepKnown(testDevice)
	select {
	case device := <-keptKnown:
		if device != testDevice {
			t.Fatalf("kept known: %v", device)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a told device was not kept known after keepKnownEvery")
	}
	select {
	case <-keptKnown:
		t.Fatal("kept known twice within keepKnownEvery")
	case <-time.After(50 * time.Millisecond):
	}
	// (counted when the write is done: off the caller's path)
	for wait := 0; s.earlyKeptKnown.Load() != 1 && wait < 100; wait++ {
		time.Sleep(10 * time.Millisecond)
	}
	if s.earlyKeptKnown.Load() != 1 {
		t.Fatalf("kept known %d times", s.earlyKeptKnown.Load())
	}
	// the device was told twice (its older connections ended again after endOlderEvery): one device
	if s.earlySuspects.Load() != 1 {
		t.Fatalf("%d devices told, of one", s.earlySuspects.Load())
	}

	// a device of the transparent proxy told by its own peers: nothing of this, with an inbound of
	// suspects in the service too. Its device is not in the firewall's set, and act must not put
	// it there (keepKnown): the next round would take it for one that connected again, and a
	// client that does not would have every later connection closed instead of left open
	calls = nil
	for len(keptKnown) > 0 {
		<-keptKnown
	}
	routed, _, add := early(t, ConfirmedReject)
	routed.hooks = hooks
	routed.suspectOn = map[string]bool{"bt-suspect": true}
	routedHosts := &recordSink{}
	routed.hostsSink = routedHosts
	routed.known = func() (map[netip.Addr]bool, error) { return map[netip.Addr]bool{}, nil }
	add(10, 3, start)
	routed.actOnKnown(start)
	if len(calls) != 0 || routedHosts.count() != 0 || routed.earlySelfTold.Load() != 1 || routed.earlySuspects.Load() != 0 {
		t.Fatalf("the transparent proxy: ended %d times, devices written %d, told %d", len(calls), routedHosts.count(), routed.earlySelfTold.Load())
	}
	if routed.early.rejected.Load() != 3 {
		t.Fatalf("the transparent proxy: %d connections closed", routed.early.rejected.Load())
	}
	select {
	case device := <-keptKnown:
		t.Fatalf("a device of the transparent proxy's early check was put in the firewall's set: %v", device)
	case <-time.After(100 * time.Millisecond):
	}
	// an inspected connection (its device is in the firewall's set: that is why it is inspected)
	// and a suspect's keep the device known through act itself
	for _, c := range []*conn{{early: false}, {early: true, suspect: true}} {
		kept, _, _ := early(t, ConfirmedReject)
		kept.hooks = hooks
		kept.suspectOn = map[string]bool{"bt-suspect": true}
		device, other := net.Pipe()
		t.Cleanup(func() { other.Close() })
		c.Conn, c.service, c.cnt, c.device, c.confirmed = device, kept, &kept.counters, testDevice, ConfirmedReject
		c.far = netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, 77}), 51413)
		c.act()
		select {
		case <-keptKnown:
		case <-time.After(5 * time.Second):
			t.Fatalf("a confirmed connection (early %v, suspect %v) did not keep its device known", c.early, c.suspect)
		}
	}

	// a suspect the firewall knows by now (a signature that came after its first connections):
	// one confirmed connection is enough, and its older connections are ended too
	known, _, add := early(t, ConfirmedLearnReset)
	known.hooks = hooks
	known.hostsSink = &recordSink{}
	known.known = func() (map[netip.Addr]bool, error) { return map[netip.Addr]bool{testDevice: true}, nil }
	suspects(add(10, 1, start))
	known.actOnKnown(start)
	if len(calls) != 1 || known.early.reset.Load() != 1 {
		t.Fatalf("known to the firewall: ended %d times, reset %d", len(calls), known.early.reset.Load())
	}
}
