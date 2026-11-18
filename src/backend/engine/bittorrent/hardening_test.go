package bittorrent

import (
	"bytes"
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
