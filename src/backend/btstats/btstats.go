// Package btstats keeps what the BitTorrent traffic of the LAN came to, by its kind and the way the
// mode sent it: the dashboard's table and the global check's lines of it.
//
// The kernel counts it. The firewall's detector of BitTorrent keeps its decision about each
// connection in the connection's conntrack mark (firewall/bittorrent_linux.go), and the router
// counts the packets and bytes of every conntrack entry each way (net.netfilter.nf_conntrack_acct,
// on in OpenWrt; fw4's flowtable has "counter", so a connection the router offloads is counted
// too). The backend reads the entries with those marks every PollEvery, and Stats adds what each
// one counted since the read before; an entry gone between two reads keeps what it had at the
// last. What the mode blocks never makes an entry (its first packet is dropped): the counters of
// the firewall's rules that drop it are read instead (Drops).
package btstats

import (
	"sort"
	"sync"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
)

// PollEvery is how often the backend reads the entries: half of the shortest time the kernel keeps
// an entry of a connection that ended (nf_conntrack_tcp_timeout_close, 10 s: a TCP connection
// ended by a reset; one ended by FIN stays 120 s, a UDP one 60 s and more after its last packet),
// so the last counts of nearly every connection are read before its entry goes.
const PollEvery = 5 * time.Second

// Kind is how the detector told the traffic.
type Kind string

const (
	// KindDiscovery: the DHT and the trackers (a UDP flow whose first packet is a DHT message or a
	// tracker's connect; a TCP connection to an HTTP tracker the device announced to)
	KindDiscovery Kind = "discovery"
	// KindUTP: the other UDP of a client's socket, uTP to its peers
	KindUTP Kind = "utp"
	// KindTCP: TCP to peers, told at the SYN (a peer known) or by the plaintext handshake
	KindTCP Kind = "tcp"
	// KindLate: a TCP connection the proxy had taken before its plaintext handshake told it: it
	// stays with sing-box, routed by the protocol
	KindLate Kind = "late"
	// KindChecked: TCP of a device running a client to an uncommon port, to a peer not known: the
	// module checks it (the three steps of MSE) when it goes through sing-box (WayChecked); one of
	// the traffic podkop does not take, outside the scope of the whole LAN, is forwarded untouched
	// (WayUntouched)
	KindChecked Kind = "checked"
	// KindIncoming: a connection from outside through a port forward to a client
	KindIncoming Kind = "incoming"
)

// kindOrder is the order of the rows.
var kindOrder = map[Kind]int{KindDiscovery: 0, KindUTP: 1, KindTCP: 2, KindLate: 3, KindChecked: 4, KindIncoming: 5}

// Way is where the mode sent it.
type Way string

const (
	// WayRelay: through sing-box, straight out (the discovery, whose replies the module reads)
	WayRelay Way = "relay"
	// WayPast: past podkop, forwarded by the router (the mode bypass, of what podkop takes)
	WayPast Way = "past"
	// WayUntouched: not podkop's traffic, forwarded as it would be without podkop
	WayUntouched Way = "untouched"
	// WayRule: through the servers of the rule of the mode section (Report.Rule)
	WayRule Way = "rule"
	// WayChecked: through sing-box while the module checks it: by podkop's rules (in the scope of
	// the whole LAN, straight out), but what sing-box's sniffer names BitTorrent the mode's way.
	// The entry does not tell which: the stand's aria2 retried its closed connections in
	// plaintext, which went straight, while the rest went to the rule's proxy
	WayChecked Way = "checked"
	// WayBlocked: dropped (of a connection decided before the mode block came, or one sing-box
	// rejects)
	WayBlocked Way = "blocked"
)

// Setup is the mode the firewall's detector has: "" (off), bypass, block or section; LAN for
// the scope of the whole LAN; Rule the name the page shows of the rule of the mode section.
type Setup struct {
	Mode string
	LAN  bool
	Rule string
}

// Count, Flow and Drops are what the kernel counted, as the firewall reads it (dataplane): a
// count of packets and bytes, a conntrack entry with a mark of the detector, the counters of the
// firewall's rules that drop BitTorrent and of what the detector could not take.
type (
	Count = dataplane.Count
	Flow  = dataplane.Flow
	Drops = dataplane.Drops
)

// Limits is what the detector could not take, in packets: by the set that had no room for the
// packet's device, socket, uTP socket or peer (the detector then tells less: it remembers no new
// one), and Foreign, the packets it did not look at because their source address is not of the
// interface they came in on.
type Limits struct {
	Devices uint64 `json:"devices,omitempty"`
	Sockets uint64 `json:"sockets,omitempty"`
	UTP     uint64 `json:"utp,omitempty"`
	Peers   uint64 `json:"peers,omitempty"`
	Foreign uint64 `json:"foreign,omitempty"`
}

// Full is the packets the sets had no room for, in all.
func (l Limits) Full() uint64 { return l.Devices + l.Sockets + l.UTP + l.Peers }

// Row is a line of the table: a kind, the way it went, the connections open at the last read
// and all seen, what the devices received and sent.
type Row struct {
	Kind        Kind   `json:"kind"`
	Way         Way    `json:"way"`
	Open        int    `json:"open"`
	Connections uint64 `json:"connections"`
	Received    Count  `json:"received"`
	Sent        Count  `json:"sent"`
}

// Blocked is a line of what the mode dropped: packets, not connections (a connection blocked at
// its first packet never had an entry).
type Blocked struct {
	Kind    Kind  `json:"kind"`
	Dropped Count `json:"dropped"`
}

// Report is what Stats came to.
type Report struct {
	// Mode, LAN and Rule are those of the last read; Mode "" when BitTorrent is off
	Mode string `json:"mode"`
	LAN  bool   `json:"lan"`
	Rule string `json:"rule,omitempty"`
	// Since is the seconds from the first read, Read those from the last; Counted is false when
	// the kernel does not count the connections (net.netfilter.nf_conntrack_acct is 0)
	Since   int64  `json:"since"`
	Read    int64  `json:"read"`
	Counted bool   `json:"counted"`
	Error   string `json:"error,omitempty"`
	Rows    []Row  `json:"rows"`
	// Blocked: by kind, then KindIncoming
	Blocked []Blocked `json:"blocked"`
	// UTPToTCP: uTP SYNs the firewall dropped on a flow of discovery (the client tries TCP)
	UTPToTCP Count `json:"utp_to_tcp"`
	// Limits: what the detector could not take (its sets full, sources not of their interface)
	Limits Limits `json:"limits"`
	// Module is what the BitTorrent module of the sing-box that runs counted
	// (engine.BitTorrentCounters), since that sing-box started or, after a reset, since the reset
	Module map[string]int64 `json:"module,omitempty"`
	// ResetAt is the seconds since the statistics were reset (Stats.ResetCounts), 0 when they
	// were not
	ResetAt int64 `json:"reset_at,omitempty"`
	// Problem says why BitTorrent goes as the other traffic although the settings ask otherwise:
	// ProblemRule, with the rule's name in Rule; "" when nothing is wrong
	Problem string `json:"problem,omitempty"`
}

// ProblemRule: the settings send BitTorrent through the servers of a rule that is not there, is
// switched off or goes nowhere, so the detector is off.
const ProblemRule = "rule"

type rowKey struct {
	kind Kind
	way  Way
}

type flowKey struct {
	id  uint32
	key string
}

type seen struct {
	original, reply Count
}

// Stats adds up the reads. It may be used from any goroutine.
type Stats struct {
	access  sync.Mutex
	setup   Setup
	first   time.Time
	last    time.Time
	counted bool
	err     string
	flows   map[flowKey]seen
	rows    map[rowKey]*Row
	// drops is what the rules of the table there now counted; a table made anew starts them at
	// 0, and what the one before had counted goes into dropped
	drops   Drops
	dropped Drops
	module  map[string]int64
	// reset is when ResetCounts ran; dropsBase what the rules had counted then; moduleBase what
	// the module had counted then (its counters keep counting in the sing-box that runs)
	reset      time.Time
	dropsBase  Drops
	moduleBase map[string]int64
}

// Observe takes a read made at now: the entries with a mark of the detector and the counters of
// its drops, under the mode of setup. err is the read's error, if any: the read is then left out
// whole, and the report says so. What a failed read got is a part or nothing, and taken as a read
// it ended every connection it did not name: the next read counted each as a new one, with all its
// bytes again, and the drops likewise (the review of 0.8.18).
func (s *Stats) Observe(setup Setup, flows []Flow, drops Drops, err error, now time.Time) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.first.IsZero() {
		s.first = now
	}
	s.last = now
	s.setup = setup
	s.err = ""
	if err != nil {
		s.err = err.Error()
		return
	}
	// the first read: the connections open already are counted from what they have now on (their
	// marks are older than this backend: a restart of podkop added the whole life of each to a
	// table that says "since" its own start), as ResetCounts leaves them
	baseline := s.flows == nil
	if baseline {
		s.flows = make(map[flowKey]seen)
		s.rows = make(map[rowKey]*Row)
		// "since" is from the read the counts begin at, not from one that failed before it
		s.first = now
	}
	for _, row := range s.rows {
		row.Open = 0
	}
	counted := len(flows) == 0 && s.counted
	present := make(map[flowKey]struct{}, len(flows))
	for _, flow := range flows {
		counted = counted || flow.Counted
		kind, way := Classify(setup, flow)
		key := flowKey{flow.ID, flow.Key}
		present[key] = struct{}{}
		before, known := s.flows[key]
		if known && (flow.Original.Bytes < before.original.Bytes || flow.Reply.Bytes < before.reply.Bytes) {
			// counts that went down: another entry under the same id
			known = false
		}
		row := s.rows[rowKey{kind, way}]
		if row == nil {
			row = &Row{Kind: kind, Way: way}
			s.rows[rowKey{kind, way}] = row
		}
		row.Open++
		if baseline {
			known, before = true, seen{flow.Original, flow.Reply}
		}
		if !known {
			row.Connections++
			before = seen{}
		}
		original := Count{Packets: flow.Original.Packets - before.original.Packets, Bytes: flow.Original.Bytes - before.original.Bytes}
		reply := Count{Packets: flow.Reply.Packets - before.reply.Packets, Bytes: flow.Reply.Bytes - before.reply.Bytes}
		// a connection a device began sent its original way; one from outside received it
		if flow.Incoming {
			row.Received.Add(original)
			row.Sent.Add(reply)
		} else {
			row.Sent.Add(original)
			row.Received.Add(reply)
		}
		s.flows[key] = seen{flow.Original, flow.Reply}
	}
	for key := range s.flows {
		if _, ok := present[key]; !ok {
			delete(s.flows, key)
		}
	}
	s.counted = counted
	// the rules' counters start at 0 with every table made anew: what they had goes into dropped
	if dropsLess(drops, s.drops) {
		addDrops(&s.dropped, s.drops)
	}
	s.drops = drops
}

// SetModule keeps the counters of the BitTorrent module for the next Report.
func (s *Stats) SetModule(counters map[string]int64) {
	s.access.Lock()
	defer s.access.Unlock()
	s.module = counters
}

// Total is what the rows of a report add up to: what the devices received and sent in all.
func Total(rows []Row) (received, sent Count) {
	for _, row := range rows {
		received.Add(row.Received)
		sent.Add(row.Sent)
	}
	return received, sent
}

// Report is what the reads came to, at now.
func (s *Stats) Report(now time.Time) Report {
	s.access.Lock()
	defer s.access.Unlock()
	report := Report{Mode: s.setup.Mode, LAN: s.setup.LAN, Rule: s.setup.Rule, Counted: s.counted, Error: s.err,
		Rows: []Row{}, Blocked: []Blocked{}, Module: s.module}
	if !s.first.IsZero() {
		report.Since = int64(now.Sub(s.first) / time.Second)
		report.Read = int64(now.Sub(s.last) / time.Second)
	}
	for _, row := range s.rows {
		report.Rows = append(report.Rows, *row)
	}
	sort.Slice(report.Rows, func(i, j int) bool {
		a, b := report.Rows[i], report.Rows[j]
		if kindOrder[a.Kind] != kindOrder[b.Kind] {
			return kindOrder[a.Kind] < kindOrder[b.Kind]
		}
		return a.Way < b.Way
	})
	total := s.dropped
	addDrops(&total, s.drops)
	subtractDrops(&total, s.dropsBase)
	if !s.reset.IsZero() {
		report.ResetAt = int64(now.Sub(s.reset) / time.Second)
	}
	for _, blocked := range []Blocked{{KindDiscovery, total.Discovery}, {KindUTP, total.UTP}, {KindTCP, total.TCP}, {KindIncoming, total.Incoming}} {
		if blocked.Dropped.Packets > 0 {
			report.Blocked = append(report.Blocked, blocked)
		}
	}
	report.UTPToTCP = total.UTPToTCP
	report.Limits = Limits{Devices: total.FullHosts.Packets, Sockets: total.FullSockets.Packets, UTP: total.FullUTP.Packets,
		Peers: total.FullPeers.Packets, Foreign: total.Foreign.Packets}
	return report
}

// Reset forgets everything: BitTorrent went off.
func (s *Stats) Reset() {
	s.access.Lock()
	defer s.access.Unlock()
	s.setup, s.first, s.last, s.counted, s.err = Setup{}, time.Time{}, time.Time{}, false, ""
	s.flows, s.rows, s.drops, s.dropped, s.module = nil, nil, Drops{}, Drops{}, nil
	s.reset, s.dropsBase, s.moduleBase = time.Time{}, Drops{}, nil
}

// ResetCounts starts the statistics again at now, the mode kept (the page's button, `podkop
// bittorrent_reset`): the rows from nothing, the connections open now counted from what they have
// now on, the drops and the module's counters from what they are now (module, read by the caller).
func (s *Stats) ResetCounts(module map[string]int64, now time.Time) {
	s.access.Lock()
	defer s.access.Unlock()
	if !s.first.IsZero() {
		s.first = now
	}
	s.rows = make(map[rowKey]*Row)
	s.dropsBase = s.dropped
	addDrops(&s.dropsBase, s.drops)
	s.moduleBase = module
	s.reset = now
}

// ModuleSince is the module's counters less what they were at the last ResetCounts; a counter
// that went down (another sing-box, started since) is taken whole, and the base goes.
func (s *Stats) ModuleSince(module map[string]int64) map[string]int64 {
	s.access.Lock()
	defer s.access.Unlock()
	if module == nil || s.moduleBase == nil {
		return module
	}
	since := make(map[string]int64, len(module))
	for name, value := range module {
		if value < s.moduleBase[name] {
			s.moduleBase = nil
			return module
		}
		since[name] = value - s.moduleBase[name]
	}
	return since
}

// dropCounts are the counters of d, each in its place.
func dropCounts(d *Drops) []*Count {
	return []*Count{&d.Discovery, &d.UTP, &d.TCP, &d.Incoming, &d.UTPToTCP, &d.FullHosts, &d.FullSockets, &d.FullPeers, &d.FullUTP, &d.Foreign}
}

// dropsLess tells whether a counter of d counted fewer packets than other's.
func dropsLess(d Drops, other Drops) bool {
	mine, theirs := dropCounts(&d), dropCounts(&other)
	for index := range mine {
		if mine[index].Packets < theirs[index].Packets {
			return true
		}
	}
	return false
}

// subtractDrops takes other's counters from d's, each that counted no less.
func subtractDrops(d *Drops, other Drops) {
	mine, theirs := dropCounts(d), dropCounts(&other)
	for index := range mine {
		if mine[index].Packets >= theirs[index].Packets && mine[index].Bytes >= theirs[index].Bytes {
			mine[index].Packets -= theirs[index].Packets
			mine[index].Bytes -= theirs[index].Bytes
		}
	}
}

// addDrops adds other's counters to d's.
func addDrops(d *Drops, other Drops) {
	mine, theirs := dropCounts(d), dropCounts(&other)
	for index := range mine {
		mine[index].Add(*theirs[index])
	}
}

// Classify tells the kind of a flow by its mark and protocol, and the way the mode sends it (the
// firewall's bt_act, bt_free and proxy, and the plan's route rules of the inbounds of BitTorrent).
func Classify(setup Setup, flow Flow) (Kind, Way) {
	taken := flow.Mark&dataplane.InterceptedCt != 0
	var kind Kind
	switch {
	case flow.Incoming:
		kind = KindIncoming
	case flow.Mark&dataplane.BitTorrentInspectCt != 0:
		kind = KindChecked
	case flow.Mark&dataplane.BitTorrentLateCt != 0:
		kind = KindLate
	case flow.Mark&dataplane.BitTorrentDiscoveryCt != 0:
		kind = KindDiscovery
	case flow.UDP:
		kind = KindUTP
	default:
		kind = KindTCP
	}
	section, block := setup.Mode == model.BitTorrentSection, setup.Mode == model.BitTorrentBlock
	switch kind {
	case KindIncoming:
		// the firewall leaves a connection from outside as forwarded; block drops a new one, of
		// every device (the whole LAN) or of the devices routed whole: one that is counted there
		// outside the scope of the whole LAN is of a device podkop does not route, and goes on
		if block && setup.LAN {
			return kind, WayBlocked
		}
		return kind, WayUntouched
	case KindChecked:
		// bt_free leaves one of the traffic podkop does not take forwarded, unless the scope is
		// the whole LAN (0.8.17 showed every such connection as checked: the field's report of
		// 595 MB "through sing-box" that the module never saw)
		if !taken && !setup.LAN {
			return kind, WayUntouched
		}
		return kind, WayChecked
	case KindLate:
		// sing-box routes it by the protocol its sniffer named: the mode's way
		switch {
		case section:
			return kind, WayRule
		case block:
			return kind, WayBlocked
		}
		return kind, WayRelay
	}
	switch {
	case section && (taken || setup.LAN):
		return kind, WayRule
	case block && (taken || setup.LAN):
		return kind, WayBlocked
	case kind == KindDiscovery && (taken || !block):
		// to the module through the BitTorrent inbound (taken) or the inbound of the LAN; block
		// does not send that of the traffic podkop does not take
		return kind, WayRelay
	case taken:
		return kind, WayPast
	}
	return kind, WayUntouched
}
