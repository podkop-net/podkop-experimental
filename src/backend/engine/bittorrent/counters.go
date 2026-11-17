package bittorrent

import (
	"sync/atomic"
)

// counters are what the module counts while it runs (B4: the diagnostics show them).
type counters struct {
	// discovery
	replies      atomic.Int64 // replies paired with a request of the device
	unpaired     atomic.Int64 // replies with peers that no request of the device asked for
	learned      atomic.Int64 // peers written to the set
	known        atomic.Int64 // peers left out: written for the device within the set's timeout
	notLearnable atomic.Int64 // peers left out: a private address, a port under 1024 or podkop's
	capped       atomic.Int64 // peers left out: the device's cap
	late         atomic.Int64 // replies let go before the set took their peers
	writeFailed  atomic.Int64 // replies whose write failed
	setFull      atomic.Int64 // writes the kernel refused for a full set
	utpSessions  atomic.Int64 // sessions stood aside for uTP
	// quietSessions: sessions stood aside at a packet of the device that is no discovery, before
	// any request
	quietSessions atomic.Int64
	announces     atomic.Int64 // announces to HTTP trackers seen
	// announceUnread: tracker replies that could not be read (not 200, not bencode, too long)
	announceUnread atomic.Int64
	// inspection
	watched   atomic.Int64 // connections of an inspected inbound (its first data may never come: a dial that failed)
	farFirst  atomic.Int64 // watched connections whose far side spoke first
	inspected atomic.Int64 // connections whose first data was shaped like MSE
	notShaped atomic.Int64 // inspected connections whose first data was not
	confirmed atomic.Int64 // confirmed by the three steps (or a plaintext handshake)
	// keptOpen: confirmed connections left open (learn_reset), as their far end is not in the set
	keptOpen   atomic.Int64
	refuted    atomic.Int64 // refuted at the second or the third step
	rejected   atomic.Int64 // confirmed and closed in the mode block
	reset      atomic.Int64 // confirmed, learned and closed (learn_reset)
	plaintext  atomic.Int64 // plaintext handshakes
	handedBack atomic.Int64 // connections given back to sing-box's own copy
	panics     atomic.Int64 // panics on network input, ended by the module
}

// Counters is a snapshot of the module's counters, by name.
type Counters map[string]int64

func (c *counters) snapshot() Counters {
	return Counters{
		"replies":         c.replies.Load(),
		"unpaired":        c.unpaired.Load(),
		"learned":         c.learned.Load(),
		"known":           c.known.Load(),
		"not_learnable":   c.notLearnable.Load(),
		"capped":          c.capped.Load(),
		"late":            c.late.Load(),
		"write_failed":    c.writeFailed.Load(),
		"set_full":        c.setFull.Load(),
		"utp_sessions":    c.utpSessions.Load(),
		"quiet_sessions":  c.quietSessions.Load(),
		"announces":       c.announces.Load(),
		"announce_unread": c.announceUnread.Load(),
		"watched":         c.watched.Load(),
		"far_first":       c.farFirst.Load(),
		"inspected":       c.inspected.Load(),
		"not_shaped":      c.notShaped.Load(),
		"confirmed":       c.confirmed.Load(),
		"kept_open":       c.keptOpen.Load(),
		"refuted":         c.refuted.Load(),
		"rejected":        c.rejected.Load(),
		"reset":           c.reset.Load(),
		"plaintext":       c.plaintext.Load(),
		"handed_back":     c.handedBack.Load(),
		"panics":          c.panics.Load(),
	}
}
