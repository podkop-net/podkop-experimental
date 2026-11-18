package bittorrent

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	sbufio "github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

type recordSink struct {
	access sync.Mutex
	keys   [][]byte
}

func (r *recordSink) add(keys [][]byte, wait time.Duration) error {
	r.access.Lock()
	defer r.access.Unlock()
	r.keys = append(r.keys, keys...)
	return nil
}

func (r *recordSink) count() int {
	r.access.Lock()
	defer r.access.Unlock()
	return len(r.keys)
}

func testService() (*Service, *recordSink) {
	sink := &recordSink{}
	s := &Service{thirdStep: 50 * time.Millisecond, thirdStepLate: 300 * time.Millisecond, wait: 100 * time.Millisecond, neverPorts: map[uint16]struct{}{443: {}},
		devices: devices{cap: 16384, window: 30 * time.Minute}, sink: sink}
	return s, sink
}

// The far end a test's connections are given: a made-up peer (the real far end is on loopback,
// which is not learnable).
var testFar = netip.MustParseAddrPort("203.0.113.7:51413")

// relay is what sing-box does with a connection of an inspected inbound, on loopback: the first
// read of the sniffer kept in a CachedConn, the module's conn over it (wrap, nil for none), the
// counters of the Clash API over that, and sing's copy each way (route/conn.go's connectionCopy).
type relay struct {
	listener net.Listener
	far      string
	wrap     func(net.Conn) net.Conn
	read     atomic.Int64
	written  atomic.Int64
	wrapped  chan net.Conn
}

func newRelay(t testing.TB, far string, wrap func(net.Conn) net.Conn) *relay {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{listener: listener, far: far, wrap: wrap, wrapped: make(chan net.Conn, 16)}
	go r.serve()
	return r
}

func (r *relay) address() string { return r.listener.Addr().String() }
func (r *relay) close()          { _ = r.listener.Close() }

func (r *relay) serve() {
	for {
		device, err := r.listener.Accept()
		if err != nil {
			return
		}
		go r.handle(device)
	}
}

func (r *relay) handle(device net.Conn) {
	remote, err := net.Dial("tcp4", r.far)
	if err != nil {
		_ = device.Close()
		return
	}
	// the sniffer's read
	sniffed := buf.NewSize(buf.BufferSize)
	_ = device.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err = sniffed.ReadOnceFrom(device)
	_ = device.SetReadDeadline(time.Time{})
	var inbound net.Conn = device
	if sniffed.Len() > 0 {
		inbound = sbufio.NewCachedConn(device, sniffed)
	} else {
		sniffed.Release()
	}
	if r.wrap != nil {
		inbound = r.wrap(inbound)
	}
	r.wrapped <- inbound
	inbound = sbufio.NewCounterConn(inbound, []N.CountFunc{func(n int64) { r.read.Add(n) }}, []N.CountFunc{func(n int64) { r.written.Add(n) }})
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = inbound.Close()
			_ = remote.Close()
		})
	}
	go func() {
		_, _ = sbufio.CopyWithIncreateBuffer(remote, inbound, sbufio.DefaultIncreaseBufferAfter, sbufio.DefaultBatchSize)
		if tcp, ok := remote.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() {
		_, _ = sbufio.CopyWithIncreateBuffer(inbound, remote, sbufio.DefaultIncreaseBufferAfter, sbufio.DefaultBatchSize)
		closeBoth()
	}()
}

// The endpoints of an exchange shaped like MSE: the device sends first (first bytes), the far side
// answers (answer bytes), the device sends its third message after pause, then the far side sends
// bulk bytes and closes.
type exchange struct {
	first, answer, third int
	again                bool // the device sends a second message before the answer
	pause                time.Duration
	bulk                 int64
}

var mse = exchange{first: 200, answer: 300, third: 100, bulk: 8 << 20}

func farServer(t testing.TB, e exchange) (string, func()) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go serveFar(c, e)
		}
	}()
	return listener.Addr().String(), func() { _ = listener.Close() }
}

func serveFar(c net.Conn, e exchange) {
	defer c.Close()
	first := e.first
	if e.again {
		first += e.third
	}
	if _, err := io.ReadFull(c, make([]byte, first)); err != nil {
		return
	}
	if _, err := c.Write(randomBytes(e.answer)); err != nil {
		return
	}
	if !e.again {
		if _, err := io.ReadFull(c, make([]byte, e.third)); err != nil {
			return
		}
	}
	_, _ = io.Copy(c, io.LimitReader(zeroReader{}, e.bulk))
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func randomBytes(n int) []byte {
	data := make([]byte, n)
	_, _ = rand.Read(data)
	return data
}

// runDevice runs the device's side; it gives the bulk bytes it received.
func runDevice(address string, e exchange, first []byte) (int64, error) {
	c, err := net.Dial("tcp4", address)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if first == nil {
		first = randomBytes(e.first)
	}
	if _, err := c.Write(first); err != nil {
		return 0, err
	}
	if e.again {
		time.Sleep(20 * time.Millisecond)
		if _, err := c.Write(randomBytes(e.third)); err != nil {
			return 0, err
		}
	}
	if _, err := io.ReadFull(c, make([]byte, e.answer)); err != nil {
		return 0, err
	}
	if !e.again {
		time.Sleep(e.pause)
		if _, err := c.Write(randomBytes(e.third)); err != nil {
			return 0, err
		}
	}
	return io.Copy(io.Discard, c)
}

func inspectWith(s *Service, confirmed Confirmed) func(net.Conn) net.Conn {
	return func(inbound net.Conn) net.Conn {
		return &conn{Conn: inbound, service: s, cnt: &s.counters, device: netip.MustParseAddr("192.168.80.10"), far: testFar, inspect: true, confirmed: confirmed}
	}
}

func run(t *testing.T, e exchange, confirmed Confirmed, first []byte) (*Service, *recordSink, *conn, int64, error) {
	t.Helper()
	far, stop := farServer(t, e)
	defer stop()
	s, sink := testService()
	r := newRelay(t, far, inspectWith(s, confirmed))
	defer r.close()
	got, err := runDevice(r.address(), e, first)
	wrapped := (<-r.wrapped).(*conn)
	return s, sink, wrapped, got, err
}

// Confirmed by the three steps, the far end learned for the device, the conn given back to sing's
// copy: at most one more transfer each way goes through it, the rest is spliced.
func TestInspectConfirmedLearn(t *testing.T) {
	s, sink, c, got, err := run(t, mse, ConfirmedLearn, nil)
	if err != nil || got != mse.bulk {
		t.Fatalf("bulk %d of %d: %v", got, mse.bulk, err)
	}
	if s.counters.confirmed.Load() != 1 || sink.count() != 1 {
		t.Errorf("confirmed %d, learned %d", s.counters.confirmed.Load(), sink.count())
	}
	want := elementKey(netip.MustParseAddr("192.168.80.10"), testFar)
	if sink.count() == 1 && !bytes.Equal(sink.keys[0], want) {
		t.Errorf("key %x, not %x", sink.keys[0], want)
	}
	if after := c.after.Load(); after > 2 {
		t.Errorf("%d reads and writes through the conn after it stood aside: not given back", after)
	}
}

// Kept on the copy (A6's control), every transfer goes through the conn.
func TestInspectHeld(t *testing.T) {
	handBack = false
	defer func() { handBack = true }()
	_, _, c, got, err := run(t, mse, ConfirmedLearn, nil)
	if err != nil || got != mse.bulk {
		t.Fatalf("bulk %d of %d: %v", got, mse.bulk, err)
	}
	if after := c.after.Load(); after != 0 {
		t.Errorf("%d transfers counted after a hand-back that did not happen", after)
	}
	if !c.NeedHandshakeForRead() {
		t.Error("a held conn stood aside")
	}
}

func TestInspectReject(t *testing.T) {
	s, sink, _, got, _ := run(t, mse, ConfirmedReject, nil)
	if got != 0 {
		t.Errorf("%d bulk bytes got through a rejected connection", got)
	}
	if s.counters.rejected.Load() != 1 || sink.count() != 0 {
		t.Errorf("rejected %d, learned %d", s.counters.rejected.Load(), sink.count())
	}
}

func TestInspectLearnReset(t *testing.T) {
	s, sink, _, got, _ := run(t, mse, ConfirmedLearnReset, nil)
	if got != 0 || sink.count() != 1 || s.counters.confirmed.Load() != 1 {
		t.Errorf("bulk %d, learned %d, confirmed %d", got, sink.count(), s.counters.confirmed.Load())
	}
}

// learn_reset leaves a confirmed connection open when its far end cannot be put in the set: closed,
// its retry would be inspected and closed again, for good.
func TestInspectLearnResetUnlearned(t *testing.T) {
	for name, c := range map[string]struct {
		far   netip.AddrPort
		setup func(*Service)
	}{
		"CGNAT":            {netip.MustParseAddrPort("100.64.1.1:51413"), nil},
		"the device's cap": {testFar, func(s *Service) { s.devices.cap = 0 }},
		"no netlink":       {testFar, func(s *Service) { s.sink = nil }},
		"a failed write":   {testFar, func(s *Service) { s.sink = failingSink{} }},
	} {
		farAddress, stop := farServer(t, mse)
		s, _ := testService()
		if c.setup != nil {
			c.setup(s)
		}
		r := newRelay(t, farAddress, func(inbound net.Conn) net.Conn {
			return &conn{Conn: inbound, service: s, cnt: &s.counters, device: testDevice, far: c.far, inspect: true, confirmed: ConfirmedLearnReset}
		})
		got, err := runDevice(r.address(), mse, nil)
		<-r.wrapped
		r.close()
		stop()
		if err != nil || got != mse.bulk || s.counters.confirmed.Load() != 1 || s.counters.keptOpen.Load() != 1 {
			t.Errorf("%s: bulk %d of %d (%v), confirmed %d, kept open %d", name, got, mse.bulk, err,
				s.counters.confirmed.Load(), s.counters.keptOpen.Load())
		}
	}
}

// A confirmed connection to a port other programs use (443, a port under 1024): its far end is
// learned by its own handshake, for its device, and the connection closed (learn_reset) as one to
// any other port (0.8.19: the firewall inspects a connection to a known peer on such a port).
func TestInspectLearnResetCommonPort(t *testing.T) {
	for _, far := range []string{"203.0.113.7:443", "203.0.113.7:1000"} {
		farAddress, stop := farServer(t, mse)
		s, sink := testService()
		r := newRelay(t, farAddress, func(inbound net.Conn) net.Conn {
			return &conn{Conn: inbound, service: s, cnt: &s.counters, device: testDevice, far: netip.MustParseAddrPort(far), inspect: true, confirmed: ConfirmedLearnReset}
		})
		got, _ := runDevice(r.address(), mse, nil)
		<-r.wrapped
		r.close()
		stop()
		if got != 0 || sink.count() != 1 || s.counters.reset.Load() != 1 || s.counters.keptOpen.Load() != 0 {
			t.Errorf("%s: bulk %d, learned %d of 1, reset %d of 1", far, got, sink.count(), s.counters.reset.Load())
		}
	}
}

// A plaintext handshake: sing-box's sniffer routed it as BitTorrent already, so learn_reset learns
// it and leaves it open; not routed so, it is closed.
func TestInspectPlaintext(t *testing.T) {
	e := exchange{first: 68, answer: 68, third: 100, bulk: 1 << 20}
	first := append(append([]byte{}, plaintextHandshake...), make([]byte, 48)...)
	for _, routed := range []bool{true, false} {
		farAddress, stop := farServer(t, e)
		s, sink := testService()
		r := newRelay(t, farAddress, func(inbound net.Conn) net.Conn {
			return &conn{Conn: inbound, service: s, cnt: &s.counters, device: testDevice, far: testFar, inspect: true, confirmed: ConfirmedLearnReset, routed: routed}
		})
		got, _ := runDevice(r.address(), e, first)
		<-r.wrapped
		r.close()
		stop()
		if (routed && got != e.bulk) || (!routed && got != 0) || sink.count() != 1 || s.counters.plaintext.Load() != 1 {
			t.Errorf("routed %v: bulk %d, learned %d, plaintext %d", routed, got, sink.count(), s.counters.plaintext.Load())
		}
	}
}

// ReadCached gives sing-box what its sniffer read ahead, through the conn: the conn takes it as the
// device's first data, the counters under it count it, and it is given once.
func TestInspectReadCached(t *testing.T) {
	s, _ := testService()
	device, other := net.Pipe()
	defer device.Close()
	defer other.Close()
	first := bytes.Repeat([]byte{0xa5}, 200)
	sniffed := buf.New()
	_, _ = sniffed.Write(first)
	var counted int64
	counter := sbufio.NewCounterConn(sbufio.NewCachedConn(device, sniffed), []N.CountFunc{func(n int64) { counted += n }}, nil)
	c := &conn{Conn: counter, service: s, cnt: &s.counters, device: testDevice, far: testFar, inspect: true, confirmed: ConfirmedLearnReset}
	given := c.ReadCached()
	if given == nil || !bytes.Equal(given.Bytes(), first) {
		t.Fatalf("not the sniffer's read: %v", given)
	}
	given.Release()
	if c.step != stepAnswer || s.counters.inspected.Load() != 1 || counted != int64(len(first)) {
		t.Errorf("step %d, inspected %d, counted %d", c.step, s.counters.inspected.Load(), counted)
	}
	if c.ReadCached() != nil {
		t.Error("given twice")
	}
	// nothing cached under it: none
	plain := &conn{Conn: device, service: s, cnt: &s.counters, device: testDevice, far: testFar, inspect: true}
	if plain.ReadCached() != nil {
		t.Error("a read of nothing")
	}
}

// Refuted: the far side's answer too long or too short, the third message too late (past
// thirdStepLate) or late and short, the device speaking again before any answer, a first data not
// shaped like MSE. Each goes on whole, nothing learned, counted by its kind.
func TestInspectRefuted(t *testing.T) {
	for name, c := range map[string]struct {
		e     exchange
		first []byte
		kind  func(*counters) int64
	}{
		"answer too long":      {exchange{first: 200, answer: 700, third: 100, bulk: 1 << 20}, nil, func(c *counters) int64 { return c.refutedLong.Load() }},
		"answer too short":     {exchange{first: 200, answer: 60, third: 100, bulk: 1 << 20}, nil, func(c *counters) int64 { return c.refutedShort.Load() }},
		"third too late":       {exchange{first: 200, answer: 300, third: 124, pause: 400 * time.Millisecond, bulk: 1 << 20}, nil, func(c *counters) int64 { return c.refutedThird.Load() }},
		"third late and short": {exchange{first: 200, answer: 300, third: 60, pause: 120 * time.Millisecond, bulk: 1 << 20}, nil, func(c *counters) int64 { return c.refutedThird.Load() }},
		"third too short":      {exchange{first: 200, answer: 300, third: 40, bulk: 1 << 20}, nil, func(c *counters) int64 { return c.refutedThird.Load() }},
		"device again":         {exchange{first: 200, answer: 300, third: 100, again: true, bulk: 1 << 20}, nil, func(c *counters) int64 { return c.refutedAgain.Load() }},
		"not shaped":           {exchange{first: 700, answer: 300, third: 100, bulk: 1 << 20}, nil, func(c *counters) int64 { return c.notShaped.Load() }},
		"TLS":                  {exchange{first: 200, answer: 300, third: 100, bulk: 1 << 20}, append([]byte{0x16, 0x03, 0x01}, randomBytes(197)...), func(c *counters) int64 { return c.notShaped.Load() }},
	} {
		s, sink, wrapped, got, err := run(t, c.e, ConfirmedReject, c.first)
		if err != nil || got != c.e.bulk {
			t.Errorf("%s: bulk %d of %d: %v", name, got, c.e.bulk, err)
		}
		if s.counters.confirmed.Load() != 0 || sink.count() != 0 {
			t.Errorf("%s: confirmed %d, learned %d", name, s.counters.confirmed.Load(), sink.count())
		}
		if c.kind(&s.counters) != 1 {
			t.Errorf("%s: not counted by its kind: %v", name, s.counters.snapshot())
		}
		if wrapped.NeedHandshakeForRead() {
			t.Errorf("%s: not stood aside", name)
		}
	}
}

// A third message of 96 to 636 bytes later than thirdStep but within thirdStepLate (Transmission's
// 124 bytes, 2 s late at the median: A1c) confirms the connection.
func TestInspectLateThird(t *testing.T) {
	e := exchange{first: 200, answer: 300, third: 124, pause: 150 * time.Millisecond, bulk: 1 << 20}
	s, sink, _, got, _ := run(t, e, ConfirmedLearnReset, nil)
	if got != 0 || sink.count() != 1 || s.counters.confirmed.Load() != 1 || s.counters.confirmedLate.Load() != 1 {
		t.Errorf("bulk %d, learned %d, confirmed %d, of them late %d", got, sink.count(), s.counters.confirmed.Load(), s.counters.confirmedLate.Load())
	}
}

// A connection that closes undecided gets the verdict of its step: the far side never answered
// (a peer that is gone, a server that cannot reach it), or the device sent nothing.
func TestInspectClosedUndecided(t *testing.T) {
	silent, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.ReadFull(c, make([]byte, 200))
				time.Sleep(50 * time.Millisecond)
				_ = c.Close()
			}()
		}
	}()
	for name, sends := range map[string]bool{"no answer": true, "no data": false} {
		s, _ := testService()
		r := newRelay(t, silent.Addr().String(), inspectWith(s, ConfirmedReject))
		c, err := net.Dial("tcp4", r.address())
		if err != nil {
			t.Fatal(err)
		}
		if sends {
			_, _ = c.Write(randomBytes(200))
			_, _ = io.ReadAll(c)
		} else {
			time.Sleep(400 * time.Millisecond)
		}
		_ = c.Close()
		<-r.wrapped
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) && s.counters.unanswered.Load()+s.counters.noData.Load() == 0 {
			time.Sleep(10 * time.Millisecond)
		}
		r.close()
		if sends && s.counters.unanswered.Load() != 1 || !sends && s.counters.noData.Load() != 1 {
			t.Errorf("%s: %v", name, s.counters.snapshot())
		}
	}
}

// An announce to an HTTP tracker: the peers of its reply are learned before the reply reaches the
// device, and the reply reaches it whole.
func TestInspectAnnounce(t *testing.T) {
	body := httpBody(testPeers)
	reply := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = bufio.NewReader(c).ReadString('\n')
		// in two parts: the learner holds the last
		_, _ = c.Write(reply[:20])
		time.Sleep(10 * time.Millisecond)
		_, _ = c.Write(reply[20:])
	}()
	s, sink := testService()
	r := newRelay(t, listener.Addr().String(), inspectWith(s, ConfirmedReject))
	defer r.close()
	c, err := net.Dial("tcp4", r.address())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("GET /announce?info_hash=%12%34&peer_id=-XX0001-abcdefghijkl&port=51413 HTTP/1.1\r\nHost: tracker.example\r\n\r\n"))
	got, _ := io.ReadAll(c)
	if !bytes.Equal(got, reply) {
		t.Errorf("the reply came changed: %q", got)
	}
	if sink.count() != 3 || s.counters.announces.Load() != 1 {
		t.Errorf("learned %d of 3, announces %d", sink.count(), s.counters.announces.Load())
	}
}

// Study A6 (the workspace's notes/2026-11-16-a5-decision.md, section 7): the relay's CPU for a
// connection given back after the three steps, against one kept on the copy for good and one never
// wrapped. The endpoints run in a child process (this test binary again, TestA6Endpoints), so this
// process's CPU is the relay's. Run with A6=1 (A6_BYTES, default 2 GiB; A6_ROUNDS, default 3):
//
//	RESULT a6 mode=MODE round=R bytes=N seconds=S relay_cpu_s=C cpu_s_per_gb=G after=A
func TestA6(t *testing.T) {
	if os.Getenv("A6") != "1" {
		t.Skip("A6=1 runs study A6")
	}
	size := int64(2 << 30)
	if text := os.Getenv("A6_BYTES"); text != "" {
		size, _ = strconv.ParseInt(text, 10, 64)
	}
	rounds := 3
	if text := os.Getenv("A6_ROUNDS"); text != "" {
		rounds, _ = strconv.Atoi(text)
	}
	modes := strings.Fields(os.Getenv("A6_MODES"))
	if len(modes) == 0 {
		modes = []string{"none", "handback", "refuted", "held"}
	}
	for round := 1; round <= rounds; round++ {
		for _, mode := range modes {
			a6Run(t, mode, round, size)
		}
	}
}

func a6Run(t *testing.T, mode string, round int, size int64) {
	child := exec.Command(os.Args[0], "-test.run=^TestA6Endpoints$")
	child.Env = append(os.Environ(), "A6_ENDPOINTS=1", "A6_BYTES="+strconv.FormatInt(size, 10), "A6_SHAPE="+map[bool]string{true: "plain", false: "mse"}[mode == "refuted"])
	stdin, _ := child.StdinPipe()
	stdout, _ := child.StdoutPipe()
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	lines := bufio.NewScanner(stdout)
	far := ""
	for lines.Scan() {
		if text, ok := strings.CutPrefix(lines.Text(), "FAR "); ok {
			far = text
			break
		}
	}
	s, _ := testService()
	var wrap func(net.Conn) net.Conn
	if mode != "none" {
		wrap = inspectWith(s, ConfirmedLearn)
	}
	handBack = mode != "held"
	defer func() { handBack = true }()
	r := newRelay(t, far, wrap)
	defer r.close()
	before := cpu()
	start := time.Now()
	_, _ = fmt.Fprintln(stdin, r.address())
	result := ""
	for lines.Scan() {
		if text, ok := strings.CutPrefix(lines.Text(), "DONE "); ok {
			result = text
			break
		}
	}
	elapsed := time.Since(start)
	used := cpu() - before
	_ = stdin.Close()
	_ = child.Wait()
	got, _ := strconv.ParseInt(result, 10, 64)
	if got != size {
		t.Errorf("%s: %d bytes of %d", mode, got, size)
	}
	var after int64
	if mode != "none" {
		after = (<-r.wrapped).(*conn).after.Load()
	}
	fmt.Printf("RESULT a6 mode=%s round=%d bytes=%d seconds=%.3f relay_cpu_s=%.3f cpu_s_per_gb=%.3f after=%d confirmed=%d handed_back=%d\n",
		mode, round, got, elapsed.Seconds(), used.Seconds(), used.Seconds()/(float64(got)/1e9), after,
		s.counters.confirmed.Load(), s.counters.handedBack.Load())
}

func cpu() time.Duration {
	var usage syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}

// TestA6Endpoints is A6's child: the far side listens and says where, then the device dials the
// relay it is told, makes the exchange (shaped like MSE, or a plain first data the first step
// refutes), downloads the bulk and says how much it got.
func TestA6Endpoints(t *testing.T) {
	if os.Getenv("A6_ENDPOINTS") != "1" {
		t.Skip("A6's child")
	}
	size, _ := strconv.ParseInt(os.Getenv("A6_BYTES"), 10, 64)
	e := exchange{first: 200, answer: 300, third: 100, bulk: size}
	var first []byte
	if os.Getenv("A6_SHAPE") == "plain" {
		first = append([]byte("GET /a6 HTTP/1.1\r\n"), bytes.Repeat([]byte{'x'}, e.first-18)...)
	}
	far, stop := farServer(t, e)
	defer stop()
	fmt.Println("FAR " + far)
	address, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	got, err := runDevice(strings.TrimSpace(address), e, first)
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(os.Stderr, "device:", err)
	}
	fmt.Println("DONE " + strconv.FormatInt(got, 10))
}

// The early check: a connection of the transparent proxy confirmed before its device was known
// waits (it goes on as routed); once the device is in the set, it is learned and closed, and the
// counters of the early check, not those of the inspection, count it.
func TestInspectEarly(t *testing.T) {
	e := mse
	e.bulk = 1 << 30
	far, stop := farServer(t, e)
	defer stop()
	s, sink := testService()
	s.pending = make(map[netip.Addr][]*waiting)
	known := false
	s.known = func() (map[netip.Addr]bool, error) {
		return map[netip.Addr]bool{testDevice: known}, nil
	}
	r := newRelay(t, far, func(inbound net.Conn) net.Conn {
		return &conn{Conn: inbound, service: s, cnt: &s.early, early: true, device: testDevice, far: testFar, inspect: true, confirmed: ConfirmedLearnReset}
	})
	defer r.close()
	type result struct {
		got int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		got, err := runDevice(r.address(), e, nil)
		done <- result{got, err}
	}()
	<-r.wrapped
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.early.confirmed.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if s.early.confirmed.Load() != 1 || s.counters.confirmed.Load() != 0 || sink.count() != 0 {
		t.Fatalf("early confirmed %d, inspection confirmed %d, learned %d", s.early.confirmed.Load(), s.counters.confirmed.Load(), sink.count())
	}
	s.actOnKnown(time.Now())
	if sink.count() != 0 || s.earlyActed.Load() != 0 {
		t.Fatalf("acted on a device not known: learned %d", sink.count())
	}
	known = true
	s.actOnKnown(time.Now())
	if sink.count() != 1 || s.earlyActed.Load() != 1 || s.early.reset.Load() != 1 {
		t.Errorf("learned %d, acted %d, reset %d", sink.count(), s.earlyActed.Load(), s.early.reset.Load())
	}
	select {
	case res := <-done:
		if res.got >= e.bulk {
			t.Errorf("the connection went on whole (%d bytes): not closed", res.got)
		}
	case <-time.After(5 * time.Second):
		t.Error("the connection was not closed")
	}
	if len(s.pending) != 0 {
		t.Errorf("%d devices still pending", len(s.pending))
	}
}

// A device not known to run a client, with confirmed connections waiting to earlySelf distinct far
// addresses, is taken as running one: its connections are done with. With fewer, they wait.
func TestEarlySelf(t *testing.T) {
	for _, distinct := range []int{2, 3} {
		s, sink := testService()
		s.pending = make(map[netip.Addr][]*waiting)
		s.known = func() (map[netip.Addr]bool, error) { return map[netip.Addr]bool{}, nil }
		for i := 0; i < distinct; i++ {
			device, other := net.Pipe()
			defer other.Close()
			far := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(10 + i)}), 51413)
			c := &conn{Conn: device, service: s, cnt: &s.early, early: true, device: testDevice, far: far, inspect: true,
				confirmed: ConfirmedLearn}
			c.done.Store(true)
			c.waits = s.pend(c, time.Now())
		}
		s.actOnKnown(time.Now())
		acted := int(s.earlyActed.Load())
		if distinct >= earlySelf && (acted != distinct || sink.count() != distinct || s.earlySelfTold.Load() != 1) {
			t.Errorf("%d distinct: acted %d, learned %d, told %d", distinct, acted, sink.count(), s.earlySelfTold.Load())
		}
		if distinct < earlySelf && (acted != 0 || len(s.pending[testDevice]) != distinct) {
			t.Errorf("%d distinct: acted %d, pending %d", distinct, acted, len(s.pending[testDevice]))
		}
	}
}

// A device told by its own peers that does not connect again within earlyRetry: its other
// confirmed connections are learned and left open, not closed; one that does connect again (it is
// in the set) has them closed.
func TestEarlyNoRetry(t *testing.T) {
	for _, retries := range []bool{false, true} {
		s, sink := testService()
		s.pending = make(map[netip.Addr][]*waiting)
		known := false
		s.known = func() (map[netip.Addr]bool, error) { return map[netip.Addr]bool{testDevice: known}, nil }
		var conns []*conn
		add := func(first int, n int) {
			for i := 0; i < n; i++ {
				device, other := net.Pipe()
				t.Cleanup(func() { other.Close() })
				far := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(first + i)}), 51413)
				c := &conn{Conn: device, service: s, cnt: &s.early, early: true, device: testDevice, far: far, inspect: true,
					confirmed: ConfirmedLearnReset}
				c.done.Store(true)
				conns = append(conns, c)
				c.waits = s.pend(c, time.Now())
			}
		}
		start := time.Now()
		add(10, 3)
		s.actOnKnown(start)
		if s.early.reset.Load() != 3 || s.earlySelfTold.Load() != 1 {
			t.Fatalf("the first three: reset %d, told %d", s.early.reset.Load(), s.earlySelfTold.Load())
		}
		add(20, 2)
		s.actOnKnown(start.Add(10 * time.Second))
		if s.early.reset.Load() != 3 || len(s.pending[testDevice]) != 2 {
			t.Fatalf("acted while watched for its retry: reset %d, pending %d", s.early.reset.Load(), len(s.pending[testDevice]))
		}
		known = retries
		s.actOnKnown(start.Add(earlyRetry + time.Second))
		s.actOnKnown(start.Add(earlyRetry + 2*time.Second))
		if retries && (s.early.reset.Load() != 5 || s.earlyKept.Load() != 0) {
			t.Errorf("a device that connected again: reset %d, kept %d", s.early.reset.Load(), s.earlyKept.Load())
		}
		if !retries && (s.early.reset.Load() != 3 || s.earlyKept.Load() != 2 || s.earlyNoRetry.Load() != 1 || sink.count() != 5) {
			t.Errorf("a device that did not: reset %d, kept %d, no retry %d, learned %d", s.early.reset.Load(), s.earlyKept.Load(), s.earlyNoRetry.Load(), sink.count())
		}
	}
}

// In block, a device told by its own peers has its confirmed connections closed at once, the
// first and the later ones: the wait for a retry is learn_reset's.
func TestEarlySelfBlock(t *testing.T) {
	s, sink := testService()
	s.pending = make(map[netip.Addr][]*waiting)
	s.known = func() (map[netip.Addr]bool, error) { return map[netip.Addr]bool{}, nil }
	add := func(first int, n int) {
		for i := 0; i < n; i++ {
			device, other := net.Pipe()
			t.Cleanup(func() { other.Close() })
			far := netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(first + i)}), 51413)
			c := &conn{Conn: device, service: s, cnt: &s.early, early: true, device: testDevice, far: far, inspect: true,
				confirmed: ConfirmedReject}
			c.done.Store(true)
			c.waits = s.pend(c, time.Now())
		}
	}
	start := time.Now()
	add(10, 3)
	s.actOnKnown(start)
	add(20, 3)
	s.actOnKnown(start.Add(10 * time.Second))
	if s.early.rejected.Load() != 6 || sink.count() != 0 || len(s.selfTold) != 0 {
		t.Errorf("rejected %d of 6, learned %d, watched %d", s.early.rejected.Load(), sink.count(), len(s.selfTold))
	}
	// told once, the device is known in block for earlyFor: one more connection (one peer, not
	// three) is closed at the next round, and it was told once only
	add(30, 1)
	s.actOnKnown(start.Add(20 * time.Second))
	if s.early.rejected.Load() != 7 || s.earlySelfTold.Load() != 1 || !s.selfKnownNow(testDevice, start.Add(20*time.Second)) {
		t.Errorf("a later one: rejected %d of 7, told %d", s.early.rejected.Load(), s.earlySelfTold.Load())
	}
}
