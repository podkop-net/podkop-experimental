package bittorrent

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// A TCP connection the module watches (Service.RoutedConnection) is wrapped in a conn, which sees
// what the device sends (Read: the copy towards the far side reads it) and what the far side
// answers (Write: the copy towards the device writes it), until it has seen enough:
//
//   - The first data of the device is an announce to an HTTP tracker: the reply's peers are
//     learned before its last part reaches the device.
//   - On an inspected inbound, the three steps of the encrypted handshake of BitTorrent (MSE), as
//     study A1 measured them (the workspace's notes/2026-11-16-bt-phaseA.md):
//     1. the first data of the device is 96 to 608 bytes and begins as no known protocol;
//     2. the far side answers 96 to 608 bytes, and the device sends nothing before that answer
//     (the initiator of MSE needs the far side's key for its next message);
//     3. the device's next data, 56 bytes or more, follows the answer within thirdStep.
//     All three confirm the connection, any step that fails refutes it. A plaintext handshake of
//     BitTorrent confirms it at once.
//
// Then the conn stands aside: it reports its handshake done (sing's copy asks NeedHandshakeFor*
// after every transfer) and lets the copy unwrap it (ReaderReplaceable, WriterReplaceable,
// Upstream), so the copy goes back to splice for the rest of the connection.

// The bounds of the three steps (A1).
const (
	mseShortest      = 96
	mseLongest       = 608
	mseThirdShortest = 56
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

// Confirmed is what is done with a connection the three steps confirm.
type Confirmed string

const (
	// ConfirmedReject closes it (the mode block).
	ConfirmedReject Confirmed = "reject"
	// ConfirmedLearn puts its far end in the set, for the device: the device's next connection to
	// it is BitTorrent at its SYN; this one goes on where it was routed (the tentative route of
	// the owner's choice (ii), 2026-11-16).
	ConfirmedLearn Confirmed = "learn"
	// ConfirmedLearnReset learns it and closes it: the device's retry is BitTorrent at its SYN
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

	access   sync.Mutex
	step     int
	flight   int
	answered time.Time
	reply    []byte
	done     atomic.Bool
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
			c.service.counters.plaintext.Add(1)
			return c.confirm()
		case httpAnnounce(data):
			c.service.counters.announces.Add(1)
			c.step = stepAnnounce
			return verdictNone
		case c.inspect && mseShaped(data):
			c.service.counters.inspected.Add(1)
			c.step = stepAnswer
			return verdictNone
		}
		if c.inspect {
			c.service.counters.notShaped.Add(1)
		}
		c.finish()
	case stepAnswer:
		// the device sent more before any answer
		c.service.counters.refuted.Add(1)
		c.finish()
	case stepThird:
		if c.flight >= mseShortest && len(data) >= mseThirdShortest && now.Sub(c.answered) <= c.service.thirdStep {
			return c.confirm()
		}
		c.service.counters.refuted.Add(1)
		c.finish()
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
			c.service.counters.farFirst.Add(1)
		}
		c.finish()
	case stepAnswer:
		c.answered = now
		c.step = stepThird
		fallthrough
	case stepThird:
		c.flight += len(data)
		if c.flight > mseLongest {
			c.service.counters.refuted.Add(1)
			c.finish()
		}
	case stepAnnounce:
		c.reply = append(c.reply, data...)
		peers, whole, err := httpReply(c.reply)
		switch {
		case err != nil:
			c.service.counters.announceUnread.Add(1)
			c.finish()
		case whole:
			c.service.learn(c.device, peers)
			c.finish()
		}
	}
	return verdictNone
}

// confirm acts on a connection confirmed as BitTorrent.
func (c *conn) confirm() int {
	c.service.counters.confirmed.Add(1)
	switch c.confirmed {
	case ConfirmedLearn:
		c.service.learn(c.device, []netip.AddrPort{c.far})
	case ConfirmedLearnReset:
		c.service.learn(c.device, []netip.AddrPort{c.far})
		c.close()
		return verdictClosed
	case ConfirmedReject:
		c.service.counters.rejected.Add(1)
		c.close()
		return verdictClosed
	}
	c.finish()
	return verdictNone
}

// close ends the connection: the copies of both ways end with it.
func (c *conn) close() {
	c.step = stepDone
	c.reply = nil
	c.done.Store(true)
	_ = c.Conn.Close()
}

// recover ends a panic of the parsers or of the learning on network input (B2's requirement: one
// would end the whole backend), counts it and stands the conn aside.
func (c *conn) recover() {
	if recover() != nil {
		c.service.counters.panics.Add(1)
		c.step = stepDone
		c.reply = nil
		c.done.Store(true)
	}
}

// finish stands the conn aside.
func (c *conn) finish() {
	c.step = stepDone
	c.reply = nil
	if !handBack {
		return
	}
	c.done.Store(true)
	c.service.counters.handedBack.Add(1)
}

// The hand-back (see the top): sing's copy reads these after each transfer.

func (c *conn) NeedHandshakeForRead() bool  { return !c.done.Load() }
func (c *conn) NeedHandshakeForWrite() bool { return !c.done.Load() }
func (c *conn) ReaderReplaceable() bool     { return c.done.Load() }
func (c *conn) WriterReplaceable() bool     { return c.done.Load() }
func (c *conn) Upstream() any               { return c.Conn }
