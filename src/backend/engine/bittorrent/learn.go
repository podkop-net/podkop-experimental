package bittorrent

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// A UDP session of a client socket (sing-box keys a session of the transparent proxy by the
// socket: all its far ends) on an inbound the module learns from is wrapped in a packetConn. What
// the device sends (ReadPacket) is a request when it is a connect or an announce of a UDP tracker
// or a get_peers query of the DHT: its transaction id is kept for the far end it went to. What is
// written to the device (WritePacket) is a reply when it comes from such a far end with such a
// transaction id: its peers are learned before it is written. A session that shows uTP (a uTP
// client learns its peers from its own writes: the firewall's bt_peers) is stood aside, as a conn
// is (R13 of the A5 review), and so is one whose device sends something that is no discovery
// before its first request (the session is of another protocol of the socket).

// pendingLife is how long a request waits for its reply: BEP 15 retransmits after 15 s, the DHT's
// clients give up within seconds.
const pendingLife = 15 * time.Second

// pendingMost is the most requests a session keeps; the oldest goes first.
const pendingMost = 512

type pendingKey struct {
	far netip.AddrPort
	id  string
}

type packetConn struct {
	N.PacketConn
	service *Service
	device  netip.Addr

	access  sync.Mutex
	pending map[pendingKey]time.Time
	asked   bool
	done    atomic.Bool
}

func (c *packetConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.PacketConn.ReadPacket(buffer)
	if err == nil && !c.done.Load() {
		c.request(buffer.Bytes(), destination.Unwrap().AddrPort(), time.Now())
	}
	return destination, err
}

func (c *packetConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if !c.done.Load() {
		c.reply(buffer.Bytes(), destination.Unwrap().AddrPort(), time.Now())
	}
	return c.PacketConn.WritePacket(buffer, destination)
}

// isUTP tells a uTP packet (BEP 29): version 1 in the low nibble of the first byte, a type of 0 to
// 4 in the high one, an extension of a known type or none (as the firewall's signature of a uTP
// SYN). A DHT message begins with 'd' (0x64), a tracker's connect with 0; a tracker's request
// with a connection id of any bytes is told before (trackerRequest, discoveryMessage).
func isUTP(payload []byte) bool {
	return len(payload) >= 20 && payload[0]&0x0f == 1 && payload[0]>>4 <= 4 && payload[1] < 3
}

func (c *packetConn) request(payload []byte, far netip.AddrPort, now time.Time) {
	c.access.Lock()
	defer c.access.Unlock()
	defer c.recover()
	var id string
	if transaction, ok := trackerRequest(payload); ok {
		id = trackerID(transaction)
	} else if transaction, ok := dhtQuery(payload); ok {
		id = "d" + transaction
	} else {
		// after the requests and the other discovery: an announce or a scrape begins with a
		// connection id of any bytes
		switch {
		case discoveryMessage(payload):
			// a message of the DHT that asks for no peers (a bootstrap's find_node, a ping, an
			// answer to a query of the far side) or a tracker's scrape: the session goes on
		case isUTP(payload):
			c.service.counters.utpSessions.Add(1)
			c.stand()
		case !c.asked:
			c.service.counters.quietSessions.Add(1)
			c.stand()
		}
		return
	}
	c.asked = true
	if c.pending == nil {
		c.pending = make(map[pendingKey]time.Time)
	}
	if len(c.pending) >= pendingMost {
		c.expire(now)
	}
	if len(c.pending) < pendingMost {
		c.pending[pendingKey{far, id}] = now
	}
}

// reply learns the peers of a reply to a request of the device; the session's lock is not held
// while the set is written, so the device's packets go on meanwhile.
func (c *packetConn) reply(payload []byte, far netip.AddrPort, now time.Time) {
	if peers := c.paired(payload, far, now); len(peers) > 0 {
		// a panic of the learning ends the learning of this reply (B2: not the backend)
		defer func() {
			if recover() != nil {
				c.service.counters.panics.Add(1)
			}
		}()
		c.service.learn(c.device, peers)
	}
}

// paired reads a reply and gives its peers when it answers a request of the device.
func (c *packetConn) paired(payload []byte, far netip.AddrPort, now time.Time) []netip.AddrPort {
	c.access.Lock()
	defer c.access.Unlock()
	defer c.recover()
	if len(c.pending) == 0 {
		return nil
	}
	var id string
	var peers []netip.AddrPort
	if transaction, found, ok := trackerReply(payload); ok {
		id, peers = trackerID(transaction), found
	} else if transaction, found, ok := dhtReply(payload); ok {
		id, peers = "d"+transaction, found
	} else {
		return nil
	}
	key := pendingKey{far, id}
	asked, ok := c.pending[key]
	if !ok || now.Sub(asked) > pendingLife {
		// no request of the device went there with that id: a forged or a late reply
		if len(peers) > 0 {
			c.service.counters.unpaired.Add(1)
		}
		return nil
	}
	delete(c.pending, key)
	c.service.counters.replies.Add(1)
	return peers
}

func trackerID(transaction uint32) string {
	return string([]byte{'u', byte(transaction >> 24), byte(transaction >> 16), byte(transaction >> 8), byte(transaction)})
}

// expire drops the requests older than pendingLife, and the oldest when none is.
func (c *packetConn) expire(now time.Time) {
	var oldest pendingKey
	var oldestTime time.Time
	for key, asked := range c.pending {
		if now.Sub(asked) > pendingLife {
			delete(c.pending, key)
			continue
		}
		if oldestTime.IsZero() || asked.Before(oldestTime) {
			oldest, oldestTime = key, asked
		}
	}
	if len(c.pending) >= pendingMost {
		delete(c.pending, oldest)
	}
}

func (c *packetConn) stand() {
	c.pending = nil
	if handBack {
		c.done.Store(true)
	}
}

func (c *packetConn) recover() {
	if recover() != nil {
		c.service.counters.panics.Add(1)
		c.pending = nil
		c.done.Store(true)
	}
}

// The hand-back, as conn's: sing's packet copy reads these after each packet.

func (c *packetConn) NeedHandshakeForRead() bool  { return !c.done.Load() }
func (c *packetConn) NeedHandshakeForWrite() bool { return !c.done.Load() }
func (c *packetConn) ReaderReplaceable() bool     { return c.done.Load() }
func (c *packetConn) WriterReplaceable() bool     { return c.done.Load() }
func (c *packetConn) Upstream() any               { return c.PacketConn }

// learnable tells a peer the set may take: an IPv4 address of the internet (not of a private
// range, not FakeIP's 198.18.0.0/15, which the firewall sends to the proxy anyway) and a port of
// 1024 or over that is none of the ports never learned (podkop's common ports: a connection there
// is no peer's, and it must not go past podkop).
func (s *Service) learnable(peer netip.AddrPort) bool {
	address := peer.Addr()
	if !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || fakeIPRange.Contains(address) ||
		sharedRange.Contains(address) || peer.Port() < 1024 {
		return false
	}
	_, never := s.neverPorts[peer.Port()]
	return !never
}

var (
	fakeIPRange = netip.MustParsePrefix("198.18.0.0/15")
	sharedRange = netip.MustParsePrefix("100.64.0.0/10")
)

// learn puts the learnable peers of a reply in the set for the device, and waits for the kernel's
// answer, at most wait: the reply is held until then, so the device's connection to a peer finds
// it (the race of F2: rTorrent connects 0.3-40 ms after a reply). Past wait, or on any error, the
// reply goes on unlearned, counted. Every peer is written, those written before too: an add of
// userspace neither moves an element's timer nor fails on one that is there (kernel 6.6), and makes
// one that has gone, so the module cannot tell from its own writes what the set holds.
func (s *Service) learn(device netip.Addr, peers []netip.AddrPort) {
	s.write(device, peers)
}

// learnFar learns the far end of a confirmed connection and tells whether it is in the set now, so
// that the device's retry finds it at its SYN.
func (s *Service) learnFar(device netip.Addr, far netip.AddrPort) bool {
	return s.write(device, []netip.AddrPort{far})
}

// write writes the peers for the device and tells whether every one is in the set.
func (s *Service) write(device netip.Addr, peers []netip.AddrPort) bool {
	if s.sink == nil || !device.Is4() {
		return false
	}
	keys := make([][]byte, 0, len(peers))
	for _, peer := range peers {
		if !s.learnable(peer) {
			s.counters.notLearnable.Add(1)
			continue
		}
		keys = append(keys, elementKey(device, peer))
	}
	whole := len(keys) == len(peers)
	if len(keys) == 0 {
		return false
	}
	taken, known, capped := s.devices.take(device, keys, time.Now())
	s.counters.known.Add(int64(known))
	s.counters.capped.Add(int64(capped))
	whole = whole && capped == 0
	if len(taken) == 0 {
		return false
	}
	switch s.sink.add(taken, s.wait) {
	case nil:
		s.counters.learned.Add(int64(len(taken)))
		return whole
	case errLate:
		s.counters.late.Add(1)
	default:
		s.counters.writeFailed.Add(1)
	}
	return false
}

// elementKey is the key of an element of the set, ipv4_addr . ipv4_addr . inet_service: each part
// in a register of 4 bytes, the port in network order and padded.
func elementKey(device netip.Addr, peer netip.AddrPort) []byte {
	key := make([]byte, 12)
	deviceBytes, peerBytes := device.As4(), peer.Addr().As4()
	copy(key, deviceBytes[:])
	copy(key[4:], peerBytes[:])
	key[8], key[9] = byte(peer.Port()>>8), byte(peer.Port())
	return key
}

// devices counts the peers learned for each device within the set's timeout, against the cap per
// device (R7 of the A5 review: one device's discovery must not fill the set for all). A peer counts
// once in the window, from the reply that first named it: replies name the same peers again and
// again (on the stand of 2026-11-16, aria2's 1204 peers learned in five minutes were 785 elements
// of the set), and the cap is of the set's elements. What counts is not what is written: every
// peer within the cap is written each time (Service.learn).
type devices struct {
	access  sync.Mutex
	cap     int
	window  time.Duration
	base    time.Time
	counted map[netip.Addr]*deviceKeys
}

// deviceKeys are the peers counted for a device, each with the time it was counted (from base, by
// the monotonic clock: the router's clock may jump at its first NTP answer), and in that order, so
// that those past the window go from the front.
type deviceKeys struct {
	last time.Duration
	keys map[[12]byte]time.Duration
	// order holds each key of keys once, from head on
	order []countedKey
	head  int
}

type countedKey struct {
	key [12]byte
	at  time.Duration
}

// devicesMost is how many devices devices keeps before it forgets those with nothing counted
// within the window.
const devicesMost = 4096

// take gives the keys of the device to write: those counted within the window, and new ones as
// many as its cap leaves room for (counted from now). known are the keys counted before, capped
// those left out.
func (d *devices) take(device netip.Addr, keys [][]byte, now time.Time) (taken [][]byte, known int, capped int) {
	d.access.Lock()
	defer d.access.Unlock()
	if d.counted == nil {
		d.counted = make(map[netip.Addr]*deviceKeys)
	}
	if d.base.IsZero() {
		d.base = now
	}
	at := now.Sub(d.base)
	entry := d.counted[device]
	if entry == nil {
		if len(d.counted) >= devicesMost {
			for address, old := range d.counted {
				if at-old.last > d.window {
					delete(d.counted, address)
				}
			}
		}
		entry = &deviceKeys{keys: make(map[[12]byte]time.Duration)}
		d.counted[device] = entry
	}
	entry.last = at
	// the keys past the window, from the front; the slice is made anew when most of it is behind
	for entry.head < len(entry.order) && at-entry.order[entry.head].at > d.window {
		delete(entry.keys, entry.order[entry.head].key)
		entry.head++
	}
	if entry.head > 1024 && entry.head > len(entry.order)/2 {
		entry.order = append([]countedKey(nil), entry.order[entry.head:]...)
		entry.head = 0
	}
	for _, key := range keys {
		id := [12]byte(key)
		if _, ok := entry.keys[id]; ok {
			known++
		} else if len(entry.keys) >= d.cap {
			capped++
			continue
		} else {
			entry.keys[id] = at
			entry.order = append(entry.order, countedKey{id, at})
		}
		taken = append(taken, key)
	}
	return taken, known, capped
}
