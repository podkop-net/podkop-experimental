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
// is (R13 of the A5 review).

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
// 4 in the high one. A DHT message begins with 'd' (0x64), a tracker's request with 0.
func isUTP(payload []byte) bool {
	return len(payload) >= 20 && payload[0]&0x0f == 1 && payload[0]>>4 <= 4
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
		// after the requests: an announce begins with a connection id of any bytes
		if isUTP(payload) {
			c.service.counters.utpSessions.Add(1)
			c.stand()
		}
		return
	}
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

func (c *packetConn) reply(payload []byte, far netip.AddrPort, now time.Time) {
	c.access.Lock()
	defer c.access.Unlock()
	defer c.recover()
	if len(c.pending) == 0 {
		return
	}
	var id string
	var peers []netip.AddrPort
	if transaction, found, ok := trackerReply(payload); ok {
		id, peers = trackerID(transaction), found
	} else if transaction, found, ok := dhtReply(payload); ok {
		id, peers = "d"+transaction, found
	} else {
		return
	}
	key := pendingKey{far, id}
	asked, ok := c.pending[key]
	if !ok || now.Sub(asked) > pendingLife {
		// no request of the device went there with that id: a forged or a late reply
		if len(peers) > 0 {
			c.service.counters.unpaired.Add(1)
		}
		return
	}
	delete(c.pending, key)
	c.service.counters.replies.Add(1)
	if len(peers) > 0 {
		c.service.learn(c.device, peers)
	}
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

// learn puts the learnable peers of a reply (or the far end of a confirmed connection) in the set
// for the device, and waits for the kernel's answer, at most wait: the reply is held until then,
// so the device's connection to a peer finds it (the race of F2: rTorrent connects 0.3-40 ms after
// a reply). Past wait, or on any error, the reply goes on unlearned, counted.
func (s *Service) learn(device netip.Addr, peers []netip.AddrPort) {
	if s.sink == nil || !device.Is4() {
		return
	}
	keys := make([][]byte, 0, len(peers))
	for _, peer := range peers {
		if !s.learnable(peer) {
			s.counters.notLearnable.Add(1)
			continue
		}
		keys = append(keys, elementKey(device, peer))
	}
	if len(keys) == 0 {
		return
	}
	if !s.devices.take(device, len(keys), time.Now()) {
		s.counters.capped.Add(int64(len(keys)))
		return
	}
	switch s.sink.add(keys, s.wait) {
	case nil:
		s.counters.learned.Add(int64(len(keys)))
	case errLate:
		s.counters.late.Add(1)
	default:
		s.counters.writeFailed.Add(1)
	}
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
// device (R7 of the A5 review: one device's discovery must not fill the set for all).
type devices struct {
	access  sync.Mutex
	cap     int
	window  time.Duration
	counted map[netip.Addr]*deviceCount
}

type deviceCount struct {
	since time.Time
	count int
}

func (d *devices) take(device netip.Addr, n int, now time.Time) bool {
	d.access.Lock()
	defer d.access.Unlock()
	if d.counted == nil {
		d.counted = make(map[netip.Addr]*deviceCount)
	}
	count := d.counted[device]
	if count == nil || now.Sub(count.since) > d.window {
		if len(d.counted) > 4096 {
			for address, old := range d.counted {
				if now.Sub(old.since) > d.window {
					delete(d.counted, address)
				}
			}
		}
		count = &deviceCount{since: now}
		d.counted[device] = count
	}
	if count.count+n > d.cap {
		return false
	}
	count.count += n
	return true
}
