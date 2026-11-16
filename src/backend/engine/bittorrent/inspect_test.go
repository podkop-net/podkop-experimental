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
	s := &Service{thirdStep: 50 * time.Millisecond, wait: 100 * time.Millisecond, neverPorts: map[uint16]struct{}{443: {}},
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
		return &conn{Conn: inbound, service: s, device: netip.MustParseAddr("192.168.80.10"), far: testFar, inspect: true, confirmed: confirmed}
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

// Refuted: the far side's answer too long, the third message too late, the device speaking again
// before any answer, a first data not shaped like MSE. Each goes on whole, nothing learned.
func TestInspectRefuted(t *testing.T) {
	for name, c := range map[string]struct {
		e     exchange
		first []byte
	}{
		"answer too long":  {exchange{first: 200, answer: 700, third: 100, bulk: 1 << 20}, nil},
		"answer too short": {exchange{first: 200, answer: 60, third: 100, bulk: 1 << 20}, nil},
		"third too late":   {exchange{first: 200, answer: 300, third: 100, pause: 120 * time.Millisecond, bulk: 1 << 20}, nil},
		"third too short":  {exchange{first: 200, answer: 300, third: 40, bulk: 1 << 20}, nil},
		"device again":     {exchange{first: 200, answer: 300, third: 100, again: true, bulk: 1 << 20}, nil},
		"not shaped":       {exchange{first: 700, answer: 300, third: 100, bulk: 1 << 20}, nil},
		"TLS":              {exchange{first: 200, answer: 300, third: 100, bulk: 1 << 20}, append([]byte{0x16, 0x03, 0x01}, randomBytes(197)...)},
	} {
		s, sink, wrapped, got, err := run(t, c.e, ConfirmedReject, c.first)
		if err != nil || got != c.e.bulk {
			t.Errorf("%s: bulk %d of %d: %v", name, got, c.e.bulk, err)
		}
		if s.counters.confirmed.Load() != 0 || sink.count() != 0 {
			t.Errorf("%s: confirmed %d, learned %d", name, s.counters.confirmed.Load(), sink.count())
		}
		if wrapped.NeedHandshakeForRead() {
			t.Errorf("%s: not stood aside", name)
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
