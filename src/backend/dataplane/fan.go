package dataplane

import (
	"strconv"
	"strings"
	"time"
)

// The suspicion by the fan-out of a device's connection openings ("bittorrent_lan_suspect", for the
// block and the section of the whole LAN; the workspace's notes/2026-11-18-aria2-private.md and
// notes/2026-11-18-fan-prototype.md): a device no signature of BitTorrent has told, that opens
// connections to more far addresses on uncommon ports than its allowance (Fan), is a suspect, and
// the TCP it opens to uncommon ports from then on goes through sing-box, where the module's early
// check (three confirmed handshakes with distinct far addresses) decides whether it runs a client.
// Only the SYN of a connection is used: a forwarded connection is offloaded at its first ACK, and
// nothing after it passes a rule. A client set to hide (no DHT, no uTP, no peer exchange, an
// encrypted handshake, an HTTPS tracker) gives the firewall no other sign.

// BitTorrentSuspectTProxyPort is the inbound of a suspect's connections of the traffic podkop does
// not take: out directly, checked as the early check of the transparent proxy checks them.
const BitTorrentSuspectTProxyPort = 1607

// BitTorrentSuspectsSet is the set of the firewall's table of the suspects (ipv4_addr).
const BitTorrentSuspectsSet = "bt_suspects"

// BitTorrentSuspectCt is the conntrack mark of a suspect's connection under the early check: the
// two bits together, which no other connection carries (a connection under inspection never gets
// BitTorrentLateCt: bt_detect sends a decided one past bt_tcp). The statistics take it as checked.
const BitTorrentSuspectCt = BitTorrentInspectCt | BitTorrentLateCt

// Fan is the fan-out a device may have before it is a suspect.
type Fan struct {
	Burst uint32
	Rate  uint64
	// Unit is 1 (a second) or 60 (a minute)
	Unit    uint64
	Pair    time.Duration
	Suspect time.Duration
}

// DefaultFan is the allowance of a device: connections to 5 new far addresses at once and 6 more
// a minute; a far address counts once in 30 minutes; a suspect stays one for 2 minutes. From the
// stand (the rule played over 22 captures of BitTorrent clients and 88 of other programs, then run:
// the workspace's notes/2026-11-18-fan-prototype.md): a client's burst is over within a second (42-50
// distinct far addresses in a second for aria2, 12-51 for the others), so the refill and the pair's
// life move nothing there, and from 5 to 8 at once the captures tell the same devices; 5 leaves
// the fewest connections opened before the suspicion (a median of 5). The 30 minutes keep a
// program that connects to the same servers again and again (a subscription's client testing its
// servers) counted once. Of the other programs an I2P router and a client testing ten proxy
// servers are suspected at any allowance under 10; the check that follows, not the count, tells
// them from BitTorrent (the I2P router is taken for it).
var DefaultFan = Fan{Burst: 5, Rate: 6, Unit: 60, Pair: 30 * time.Minute, Suspect: 2 * time.Minute}

// On tells whether the suspicion is on (a Fan of nothing is off).
func (f Fan) On() bool { return f.Burst > 0 }

// ParseFan reads an allowance written as "BURST RATE/UNIT PAIR SUSPECT" ("bittorrent_lan_allowance",
// not on the page, for measurements): a device may open connections to BURST new far addresses at
// once and RATE more a UNIT (second or minute) after that; a far address counts once in PAIR
// seconds; a suspect stays one for SUSPECT seconds. Example: "8 6/minute 60 600".
func ParseFan(line string) (Fan, bool) {
	fields := strings.Fields(line)
	if len(fields) != 4 {
		return Fan{}, false
	}
	burst, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil || burst == 0 {
		return Fan{}, false
	}
	rate, unitName, ok := strings.Cut(fields[1], "/")
	if !ok {
		return Fan{}, false
	}
	fan := Fan{Burst: uint32(burst)}
	if fan.Rate, err = strconv.ParseUint(rate, 10, 32); err != nil || fan.Rate == 0 {
		return Fan{}, false
	}
	switch unitName {
	case "second":
		fan.Unit = 1
	case "minute":
		fan.Unit = 60
	default:
		return Fan{}, false
	}
	pair, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil || pair == 0 {
		return Fan{}, false
	}
	suspect, err := strconv.ParseUint(fields[3], 10, 32)
	if err != nil || suspect == 0 {
		return Fan{}, false
	}
	fan.Pair, fan.Suspect = time.Duration(pair)*time.Second, time.Duration(suspect)*time.Second
	return fan, true
}

// Refill is how long an empty allowance takes to be whole again: the set that counts a device
// keeps it twice as long after its last new far address.
func (f Fan) Refill() time.Duration {
	return time.Duration(uint64(f.Burst)*f.Unit/f.Rate+1) * time.Second
}
