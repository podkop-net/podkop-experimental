package bittorrent

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// A TCP connection the module watches (Service.RoutedConnection) is wrapped in a conn, which sees
// what the device sends (Read: the copy towards the far side reads it) and what the far side
// answers (Write: the copy towards the device writes it), until it has seen enough:
//
//   - The first data of the device is an announce to an HTTP tracker: the reply's peers are
//     learned before its last part reaches the device.
//   - On an inspected inbound, the three steps of the encrypted handshake of BitTorrent (MSE), as
//     study A1 measured them (the workspace's notes/2026-11-16-bt-phaseA.md):
//     1. the first data of the device is 96 to 608 bytes, begins as no known protocol and looks
//     random where MSE has its key (looksRandom);
//     2. the far side answers 96 to 608 bytes, and the device sends nothing before that answer
//     (the initiator of MSE needs the far side's key for its next message);
//     3. the device's next data follows the answer: 56 bytes or more within thirdStep (aria2 and
//     rTorrent, at once), or 96 to 636 bytes within thirdStepLate (MSE's third message with the
//     BitTorrent handshake as its initial payload: 124 bytes and up to 512 of padding; Transmission
//     and qBittorrent send it 0.1 to 15 s late, study A1c of 0.8.18).
//     All three confirm the connection, any step that fails refutes it. A plaintext handshake of
//     BitTorrent confirms it at once.
//
// Each inspected connection ends in one verdict, counted and told in the log at the level debug
// (the device, the far end, the lengths and delays of the steps): confirmed, not shaped like MSE,
// a first data that does not look random, the far side first, the device again before the answer, the answer too long or too short, the
// third step late or short, no first data (a dial that failed), no answer, no third step.
//
// Then the conn stands aside: it reports its handshake done (sing's copy asks NeedHandshakeFor*
// after every transfer) and lets the copy unwrap it (ReaderReplaceable, WriterReplaceable,
// Upstream), so the copy goes back to splice for the rest of the connection.

// The bounds of the three steps (A1).
const (
	mseShortest      = 96
	mseLongest       = 608
	mseThirdShortest = 56
	// the third message sent late: the handshake as its initial payload (20 + 20 + 8 + 4 + 2 + 2 +
	// 68 = 124 bytes) and up to 512 bytes of padding (A1c: Transmission 124, M4's clients 124-428)
	mseLateShortest = 96
	mseLateLongest  = 636
)

// knownStarts are how TLS, HTTP and SSH begin: such a first data is not MSE (A1's PREFIXES, the
// firewall's notBitTorrentStarts).
var knownStarts = [][]byte{{0x16, 0x03}, []byte("GET "), []byte("POST"), []byte("HEAD"), []byte("PUT "), []byte("DELE"),
	[]byte("OPTI"), []byte("PATC"), []byte("CONN"), []byte("TRAC"), []byte("PROP"), []byte("MKCO"), []byte("COPY"),
	[]byte("MOVE"), []byte("LOCK"), []byte("UNLO"), []byte("REPO"), []byte("PRI "), []byte("HTTP"), []byte("SSH-")}

// plaintextHandshake is the beginning of BitTorrent's plaintext handshake: the length 19 and
// "BitTorrent protocol".
var plaintextHandshake = append([]byte{19}, "BitTorrent protocol"...)

// mseShaped tells a first data shaped like MSE's first message: its length, no known beginning,
// and not one of the protocols whose first message has fixed bytes there (A1, M2):
// OpenVPN over TCP (a 16-bit length of the rest, then the opcode of a client's hard reset, 7 for
// v2 or 10 for tls-crypt-v2, and key id 0) and WireGuard over TCP (the length 148, then the
// initiation: type 1 and three zeros).
func mseShaped(data []byte) bool {
	if len(data) < mseShortest || len(data) > mseLongest {
		return false
	}
	for _, start := range knownStarts {
		if bytes.HasPrefix(data, start) {
			return false
		}
	}
	if int(binary.BigEndian.Uint16(data)) == len(data)-2 && (data[2] == 7<<3 || data[2] == 10<<3) {
		return false
	}
	return !bytes.HasPrefix(data, []byte{0x00, 0x94, 0x01, 0x00, 0x00, 0x00})
}

// randomHead is how much of a first data looksRandom reads; randomZerosMost the most zero bytes
// it may hold there.
const (
	randomHead      = 16
	randomZerosMost = 3
)

// looksRandom tells a first data that may begin with MSE's first message: a public key of
// Diffie-Hellman, 96 bytes that are uniformly random. Text (SIP's REGISTER) and a structured
// header (lengths and versions with zero bytes: PostgreSQL's startup message) are not: the first
// randomHead bytes all printable or white space (a key's are with a probability of 2e-7), or more
// than randomZerosMost zero bytes among them (4e-7). The study of 2026-11-18 (the workspace's
// notes/2026-11-18-one-vs-three-handshakes.md): without this test SIP over TCP and PostgreSQL
// without TLS were confirmed on every connection (80 of 80, 48 of 48: the far side's answer and
// the client's next message have MSE's lengths and timing), with it on none, and it lost none of
// 5346 confirmed handshakes of real clients. A proxy protocol that is random from its first byte
// (Shadowsocks, VMess) passes it as MSE does: only the count of distinct far addresses of the
// early check, and the firewall's evidence of a device running a client, stand between such a
// connection and a verdict.
func looksRandom(data []byte) bool {
	head := data[:min(randomHead, len(data))]
	zeros, text := 0, true
	for _, b := range head {
		switch {
		case b == 0:
			zeros++
			text = false
		case b == '\t' || b == '\n' || b == '\r' || (b >= 0x20 && b <= 0x7e):
		default:
			text = false
		}
	}
	return !text && zeros <= randomZerosMost
}

// Confirmed is what is done with a connection the three steps confirm.
type Confirmed string

const (
	// ConfirmedReject closes it (the mode block).
	ConfirmedReject Confirmed = "reject"
	// ConfirmedLearn puts its far end in the set, for the device: the device's next connection to
	// it is BitTorrent at its SYN; this one goes on where it was routed (the tentative route of
	// the owner's choice (ii), 2026-11-16).
	ConfirmedLearn Confirmed = "learn"
	// ConfirmedLearnReset learns it and closes it: the device's retry is BitTorrent at its SYN.
	// One whose far end cannot be put in the set (not learnable, the device's cap, a write that
	// failed) is left open as ConfirmedLearn leaves it: closed, its retry would be inspected and
	// closed again
	// (podkop's choice outside block since 2026-11-17: (ii) alone left 0 to 39 % of rTorrent's
	// bytes on the tentative route in bypass, and all of them in the section for the whole LAN; the
	// workspace's notes/2026-11-16-bt-phaseBC.md).
	ConfirmedLearnReset Confirmed = "learn_reset"
)

// The steps of a conn.
const (
	stepFirst    = iota // nothing from the device yet
	stepAnswer          // MSE-shaped first data; waiting for the far side's answer
	stepThird           // the answer came; waiting for the device's next data
	stepAnnounce        // an announce to an HTTP tracker; reading the reply
	stepDone
)

// handBack is false only in the measurements of study A6, to keep a conn on the copy for good.
var handBack = true

type conn struct {
	net.Conn
	service   *Service
	device    netip.Addr
	far       netip.AddrPort
	inspect   bool
	confirmed Confirmed
	// early: a connection of the transparent proxy (Options.Early), checked as an inspected one;
	// confirmed, it waits for its device to be known as running a client (the poller of pending)
	early bool
	// cnt: the counters it counts in (the service's, or its early ones)
	cnt *counters
	// waits: its place among the connections confirmed early that wait for their device (pend)
	waits *waiting
	// gone: Close was called
	gone bool
	// routed: sing-box's sniffer named the connection BitTorrent, and its route rule of the
	// protocol routed it as the mode says
	routed bool

	access   sync.Mutex
	step     int
	flight   int
	first    int       // the length of the device's first data
	sentAt   time.Time // when it came
	answered time.Time
	// reply: what came of the reply to an announce; head: its headers, once whole; scanned: how far
	// their end was looked for; parses: how many times its body was decoded
	reply   []byte
	head    *httpHead
	scanned int
	parses  int
	done    atomic.Bool
	// after counts the reads and writes that came after the conn stood aside: sing's copy makes
	// one more transfer each way before it unwraps the conn (study A6 checks that it does)
	after atomic.Int64
}

func (c *conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.done.Load() {
		c.after.Add(1)
		return n, err
	}
	if n == 0 {
		return n, err
	}
	verdict := c.sent(p[:n], time.Now())
	if verdict == verdictClosed {
		return 0, net.ErrClosed
	}
	return n, err
}

// ReadCached gives sing-box what its sniffer read of the connection ahead, for the outbound's
// handshake to carry (kickWriteHandshake of the engine's route/conn.go), after the conn saw it as
// the device's first data. The copy looks for it on the conn only: without this, the outbound's
// handshake went alone and the data after it (a separate write, another packet), for every
// connection the module wraps. The counters under the conn count it, as the copy would.
func (c *conn) ReadCached() *buf.Buffer {
	reader, counts := N.UnwrapCountReader(c.Conn, nil)
	cached, ok := reader.(N.CachedReader)
	if !ok {
		return nil
	}
	buffer := cached.ReadCached()
	if buffer == nil {
		return nil
	}
	for _, count := range counts {
		count(int64(buffer.Len()))
	}
	if !c.done.Load() && !buffer.IsEmpty() && c.sent(buffer.Bytes(), time.Now()) == verdictClosed {
		buffer.Release()
		return nil
	}
	return buffer
}

func (c *conn) Write(p []byte) (int, error) {
	// sing-box writes nothing to a conn that needs a handshake for writes when the connection
	// opens (kickWriteHandshake): that is no answer of the far side
	if len(p) > 0 {
		if c.done.Load() {
			c.after.Add(1)
		} else if c.answers(p, time.Now()) == verdictClosed {
			return 0, net.ErrClosed
		}
	}
	return c.Conn.Write(p)
}

const (
	verdictNone = iota
	verdictClosed
)

// sent takes data the device sent, at now.
func (c *conn) sent(data []byte, now time.Time) (verdict int) {
	c.access.Lock()
	defer c.access.Unlock()
	defer c.recover()
	switch c.step {
	case stepFirst:
		switch {
		case bytes.HasPrefix(data, plaintextHandshake):
			c.cnt.plaintext.Add(1)
			if c.routed && c.confirmed != ConfirmedReject {
				// on the mode's way already: learned, not closed
				c.cnt.confirmed.Add(1)
				if c.service.learnFar(c.device, c.far) {
					c.service.logConfirmed(c.device, c.far, "a plaintext handshake, its far end learned")
				}
				c.finish()
				return verdictNone
			}
			return c.confirm()
		case httpAnnounce(data) && clientAnnounce(data):
			c.cnt.announces.Add(1)
			c.step = stepAnnounce
			return verdictNone
		case httpAnnounce(data):
			// the path of an announce in a request no client sent (a browser's): not read
			c.cnt.announcesForeign.Add(1)
		case c.inspect && mseShaped(data) && !looksRandom(data):
			// MSE's length and no known beginning, but text or a header where MSE has a key
			c.cnt.notShaped.Add(1)
			c.cnt.notRandom.Add(1)
			c.verdict("the first data does not look random", len(data), now)
			c.finish()
			return verdictNone
		case c.inspect && mseShaped(data):
			c.cnt.inspected.Add(1)
			c.step = stepAnswer
			c.first, c.sentAt = len(data), now
			return verdictNone
		}
		if c.inspect {
			c.cnt.notShaped.Add(1)
			c.verdict("not shaped like MSE", len(data), now)
		}
		c.finish()
	case stepAnswer:
		// the device sent more before any answer
		c.refute(&c.cnt.refutedAgain, "the device sent again before an answer", len(data), now)
	case stepThird:
		delay := now.Sub(c.answered)
		switch {
		case c.flight < mseShortest:
			c.refute(&c.cnt.refutedShort, "the answer too short", len(data), now)
		case len(data) >= mseThirdShortest && delay <= c.service.thirdStep:
			c.verdict("confirmed", len(data), now)
			return c.confirm()
		case len(data) >= mseLateShortest && len(data) <= mseLateLongest && delay <= c.service.thirdStepLate:
			c.cnt.confirmedLate.Add(1)
			c.verdict("confirmed by a late third step", len(data), now)
			return c.confirm()
		default:
			c.refute(&c.cnt.refutedThird, "the third step late or short", len(data), now)
		}
	case stepAnnounce:
		// a request after the announce: the reply is read as it was
	}
	return verdictNone
}

// answers takes data of the far side, at now.
func (c *conn) answers(data []byte, now time.Time) (verdict int) {
	c.access.Lock()
	defer c.access.Unlock()
	defer c.recover()
	switch c.step {
	case stepFirst:
		// the far side spoke first
		if c.inspect {
			c.cnt.farFirst.Add(1)
			c.verdict("the far side spoke first", 0, now)
		}
		c.finish()
	case stepAnswer:
		c.answered = now
		c.step = stepThird
		fallthrough
	case stepThird:
		c.flight += len(data)
		if c.flight > mseLongest {
			c.refute(&c.cnt.refutedLong, "the answer too long", 0, now)
		}
	case stepAnnounce:
		c.readReply(data, false)
	}
	return verdictNone
}

// readReply takes more of the reply to an announce (closed: its connection ends, nothing more
// comes) and learns its peers once it is whole. The headers are read once; the body is decoded
// when it may be whole, at most httpParsesMost times before the end. A reply longer than
// httpReplyLimit, or one for which httpRepliesMost leaves no room, is let go unread. The caller
// holds access.
func (c *conn) readReply(data []byte, closed bool) {
	if len(data) > 0 {
		if len(c.reply)+len(data) > httpReplyLimit {
			c.unread()
			return
		}
		if c.service.replyBytes.Add(int64(len(data))) > httpRepliesMost {
			c.service.replyBytes.Add(-int64(len(data)))
			c.unread()
			return
		}
		c.reply = append(c.reply, data...)
	}
	if c.head == nil {
		head, err := readHTTPHead(c.reply, c.scanned)
		if err != nil || (head == nil && closed) {
			c.unread()
			return
		}
		if head == nil {
			c.scanned = max(0, len(c.reply)-3)
			return
		}
		c.head = head
	}
	if !closed && (c.parses >= httpParsesMost || !c.head.mayBeWhole(c.reply)) {
		return
	}
	c.parses++
	peers, whole, err := c.head.peers(c.reply)
	switch {
	case err != nil, !whole && closed:
		c.unread()
	case whole:
		c.service.learn(c.device, peers)
		c.finish()
	}
}

// unread counts a reply to an announce that could not be read and stands the conn aside.
func (c *conn) unread() {
	c.cnt.announceUnread.Add(1)
	c.finish()
}

// dropReply lets go of what was kept of a reply.
func (c *conn) dropReply() {
	if c.reply != nil {
		c.service.replyBytes.Add(-int64(len(c.reply)))
		c.reply = nil
	}
	c.head = nil
}

// confirm acts on a connection confirmed as BitTorrent; an early one waits for its device (pend).
func (c *conn) confirm() int {
	c.cnt.confirmed.Add(1)
	if c.early {
		now := time.Now()
		// a device told by its own peers in block: closed at once, not at the next poll
		if c.confirmed == ConfirmedReject && c.service.selfKnownNow(c.device, now) {
			c.service.earlyActed.Add(1)
			return c.act()
		}
		c.waits = c.service.pend(c, now)
		c.finish()
		return verdictNone
	}
	return c.act()
}

// act does with a confirmed connection what its inbound says: learn its far end (and close it), or
// close it. The caller holds access, or (pending) the conn stood aside already.
func (c *conn) act() int {
	switch c.confirmed {
	case ConfirmedLearn:
		if c.service.learnFar(c.device, c.far) {
			c.service.logConfirmed(c.device, c.far, "its far end learned")
		} else {
			c.service.logConfirmed(c.device, c.far, "its far end not learned")
		}
	case ConfirmedLearnReset:
		if !c.service.learnFar(c.device, c.far) {
			c.cnt.keptOpen.Add(1)
			c.service.logConfirmed(c.device, c.far, "left open: its far end not learned")
			break
		}
		c.cnt.reset.Add(1)
		c.service.logConfirmed(c.device, c.far, "its far end learned, the connection closed")
		c.close()
		return verdictClosed
	case ConfirmedReject:
		c.cnt.rejected.Add(1)
		c.service.logConfirmed(c.device, c.far, "closed")
		c.close()
		return verdictClosed
	}
	c.finish()
	return verdictNone
}

// refute counts a refutation of the kind and in the total, tells it and stands the conn aside.
func (c *conn) refute(kind *atomic.Int64, why string, length int, now time.Time) {
	kind.Add(1)
	c.cnt.refuted.Add(1)
	c.verdict(why, length, now)
	c.finish()
}

// verdict tells the end of an inspection in the log at the level debug: the device, the far end,
// the device's first data, the far side's answer after its delay, and length bytes of the device
// at now (its next data, or a first data not shaped like MSE). The caller holds access.
func (c *conn) verdict(why string, length int, now time.Time) {
	if c.service.logger == nil {
		return
	}
	line := fmt.Sprint("BitTorrent check of ", c.device, " to ", c.far, ": ", why)
	switch {
	case c.first == 0 && length > 0:
		line += fmt.Sprint("; first data ", length, " B")
	case c.first > 0:
		line += fmt.Sprint("; first data ", c.first, " B")
		if !c.answered.IsZero() {
			line += fmt.Sprint(", answer ", c.flight, " B after ", c.answered.Sub(c.sentAt).Round(time.Millisecond))
			if length > 0 {
				line += fmt.Sprint(", next data ", length, " B after ", now.Sub(c.answered).Round(time.Millisecond))
			}
		} else if length > 0 {
			line += fmt.Sprint(", next data ", length, " B after ", now.Sub(c.sentAt).Round(time.Millisecond))
		}
	}
	c.service.logger.Debug(line)
}

// Close ends the connection; an inspected one not decided yet gets its verdict from the step it
// was at: no first data (a dial that failed, a device that sent nothing), no answer from the far
// side, or no third step. A reply to an announce that ends with its connection is read now. One
// that waited for its device (pend) waits no more: its far end stays, as what the device shook
// hands with.
func (c *conn) Close() error {
	c.ended(true)
	return c.Conn.Close()
}

// CloseWrite ends the far side's way to the device and leaves the device's open, when the
// connection under the conn can: without it, sing-box's copy closed a connection whole at the far
// side's end while the conn had not stood aside (a connection the far side half-closes after its
// answer lost what the device still sent; since 0.8.18 the conn wraps every connection of the
// transparent proxy to an uncommon port). A reply to an announce that ends with its connection is
// read first: its peers are learned before the device sees the end.
func (c *conn) CloseWrite() error {
	if closer, ok := N.UnwrapWriter(c.Conn).(N.WriteCloser); ok {
		c.ended(false)
		return closer.CloseWrite()
	}
	return c.Close()
}

// ended is what Close (whole) and CloseWrite do before the connection under the conn: the far side
// sends nothing more.
func (c *conn) ended(whole bool) {
	c.access.Lock()
	defer c.access.Unlock()
	defer c.recover()
	if whole {
		c.gone = true
		if c.waits != nil {
			c.waits.conn.Store(nil)
			c.waits = nil
		}
	}
	if c.done.Load() || c.step == stepDone {
		return
	}
	if c.step == stepAnnounce {
		c.readReply(nil, true)
		return
	}
	if !whole || !c.inspect {
		// the device may still send: its steps go on
		return
	}
	now := time.Now()
	switch c.step {
	case stepFirst:
		c.cnt.noData.Add(1)
		c.verdict("closed before any data", 0, now)
	case stepAnswer:
		c.cnt.unanswered.Add(1)
		c.verdict("closed with no answer", 0, now)
	case stepThird:
		c.cnt.noThird.Add(1)
		c.verdict("closed before the third step", 0, now)
	}
	c.step = stepDone
}

// close ends the connection: the copies of both ways end with it.
func (c *conn) close() {
	c.step = stepDone
	c.dropReply()
	c.done.Store(true)
	_ = c.Conn.Close()
}

// recover ends a panic of the parsers or of the learning on network input (B2's requirement: one
// would end the whole backend), counts it and stands the conn aside.
func (c *conn) recover() {
	if recover() != nil {
		c.cnt.panics.Add(1)
		c.step = stepDone
		c.dropReply()
		c.done.Store(true)
	}
}

// finish stands the conn aside (once).
func (c *conn) finish() {
	if c.done.Load() {
		return
	}
	c.step = stepDone
	c.dropReply()
	if !handBack {
		return
	}
	c.done.Store(true)
	c.cnt.handedBack.Add(1)
}

// The hand-back (see the top): sing's copy reads these after each transfer.

func (c *conn) NeedHandshakeForRead() bool  { return !c.done.Load() }
func (c *conn) NeedHandshakeForWrite() bool { return !c.done.Load() }
func (c *conn) ReaderReplaceable() bool     { return c.done.Load() }
func (c *conn) WriterReplaceable() bool     { return c.done.Load() }
func (c *conn) Upstream() any               { return c.Conn }
