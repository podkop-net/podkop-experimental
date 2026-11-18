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
	overReply    atomic.Int64 // peers left out: more than replyMost in one reply
	late         atomic.Int64 // replies let go before the set took their peers
	writeFailed  atomic.Int64 // replies whose write failed
	setFull      atomic.Int64 // writes the kernel refused for a full set
	utpSessions  atomic.Int64 // sessions stood aside for uTP
	// quietSessions: sessions stood aside at a packet of the device that is no discovery, before
	// any request
	quietSessions atomic.Int64
	announces     atomic.Int64 // announces to HTTP trackers seen
	// announcesForeign: requests of an announce's path that no BitTorrent client sent (a browser's
	// headers, no info_hash): their replies are not read
	announcesForeign atomic.Int64
	// writerRestarts: times another goroutine took the set's writes over from one the kernel never
	// answered
	writerRestarts atomic.Int64
	// announceUnread: tracker replies that could not be read (not 200, not bencode, too long)
	announceUnread atomic.Int64
	// inspection
	watched   atomic.Int64 // connections of an inspected inbound (its first data may never come: a dial that failed)
	farFirst  atomic.Int64 // watched connections whose far side spoke first
	inspected atomic.Int64 // connections whose first data was shaped like MSE
	notShaped atomic.Int64 // inspected connections whose first data was not
	// notRandom: of notShaped, MSE's length and no known beginning, but text or a structured header
	// where MSE's first message has a key (looksRandom)
	notRandom atomic.Int64
	confirmed atomic.Int64 // confirmed by the three steps (or a plaintext handshake)
	// confirmedLate: of confirmed, by a third step later than thirdStep (96-636 bytes within
	// thirdStepLate)
	confirmedLate atomic.Int64
	// keptOpen: confirmed connections left open (learn_reset), as their far end is not in the set
	keptOpen atomic.Int64
	refuted  atomic.Int64 // refuted at the second or the third step: the four below
	// refutedAgain: the device sent again before the answer; refutedLong, refutedShort: the
	// answer over 608 or under 96 bytes; refutedThird: the third step late or short
	refutedAgain, refutedLong, refutedShort, refutedThird atomic.Int64
	// the verdict of an inspected connection that closed undecided: noData before the device's
	// first data (a dial that failed), unanswered before the far side's answer, noThird before the
	// device's third step
	noData, unanswered, noThird atomic.Int64
	rejected                    atomic.Int64 // confirmed and closed in the mode block
	reset                       atomic.Int64 // confirmed, learned and closed (learn_reset)
	plaintext                   atomic.Int64 // plaintext handshakes
	handedBack                  atomic.Int64 // connections given back to sing-box's own copy
	panics                      atomic.Int64 // panics on network input, ended by the module
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
		"over_reply":      c.overReply.Load(),
		"late":            c.late.Load(),
		"write_failed":    c.writeFailed.Load(),
		"set_full":        c.setFull.Load(),
		"utp_sessions":    c.utpSessions.Load(),
		"quiet_sessions":  c.quietSessions.Load(),
		"announces":       c.announces.Load(),
		"announce_other":  c.announcesForeign.Load(),
		"writer_restarts": c.writerRestarts.Load(),
		"announce_unread": c.announceUnread.Load(),
		"watched":         c.watched.Load(),
		"far_first":       c.farFirst.Load(),
		"inspected":       c.inspected.Load(),
		"not_shaped":      c.notShaped.Load(),
		"not_random":      c.notRandom.Load(),
		"confirmed":       c.confirmed.Load(),
		"confirmed_late":  c.confirmedLate.Load(),
		"refuted_again":   c.refutedAgain.Load(),
		"refuted_long":    c.refutedLong.Load(),
		"refuted_short":   c.refutedShort.Load(),
		"refuted_third":   c.refutedThird.Load(),
		"no_data":         c.noData.Load(),
		"unanswered":      c.unanswered.Load(),
		"no_third":        c.noThird.Load(),
		"kept_open":       c.keptOpen.Load(),
		"refuted":         c.refuted.Load(),
		"rejected":        c.rejected.Load(),
		"reset":           c.reset.Load(),
		"plaintext":       c.plaintext.Load(),
		"handed_back":     c.handedBack.Load(),
		"panics":          c.panics.Load(),
	}
}
