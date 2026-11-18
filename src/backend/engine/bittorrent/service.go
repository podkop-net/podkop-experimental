// Package bittorrent is podkop's BitTorrent module for sing-box: a service of sing-box (in the
// configuration's "services", type "podkop-bittorrent") that podkop's backend registers in the
// box it builds. It reads what sing-box relays, and writes one named nftables set that podkop's
// firewall owns. It is design H of the workspace's notes/2026-11-16-bittorrent-architecture.md,
// built as the A5 decision record says (notes/2026-11-16-a5-decision.md, approved 2026-11-16):
//
//   - The learner (R2): on the inbounds of "learn", the replies of UDP trackers and of the DHT to
//     the requests a device sent, and the replies of HTTP trackers to its announces. The peers they
//     name go into the set for that device (device . peer . port) before the reply reaches it, so
//     the firewall decides the device's connection to a peer at its SYN.
//   - The inspection (R3): on the inbounds of "inspect", the TCP connections the firewall could not
//     decide at their first packet (a device running a client, to a port no other program uses).
//     The three steps of MSE confirm or refute each one; a confirmed one is closed (block), or its
//     far end learned and the connection closed, so that the device's retry is decided at its SYN
//     (bypass, section; "learn" leaves it open where sing-box routed it).
//   - The early check (0.8.18): on the inbounds of "early" (the transparent proxy), a TCP connection
//     to a port no other program uses is checked as an inspected one, whatever its device. A
//     confirmed one waits until its device is in the firewall's set of devices running a client
//     ("hosts", read every earlyPoll), then it is done with as "confirmed" says. A client's first
//     connections, opened before the firewall knew the device (a client with no DHT and no uTP is
//     told only by its local peer discovery, a minute after its start on the stand of 0.8.18), went
//     by the lists for their whole life. A device with earlySelf confirmed connections to distinct
//     far addresses waiting is taken as running a client too (a client with no DHT, no uTP, no
//     local discovery and encryption required, fed by an HTTPS tracker, sends nothing in plaintext:
//     F7 of the workspace's notes/2026-11-16-bittorrent-architecture.md): its connections are done
//     with, and their retries, decided at the SYN, put the device in the firewall's set. A device
//     that never runs a client is never touched (proxy clients: 3 confirmed of 10473 connections
//     of six of them, Phase C; a client opens tens of peer connections a minute, A1). Closed, a
//     connection helps only a client that connects again (learn_reset; block closes it anyway, at
//     once): a device told so is watched for
//     earlyRetry, its other confirmed connections waiting meanwhile; one that did not reconnect
//     (it is still not in the set: its retries, decided at the SYN by the learned peer, would have
//     put it there) has its confirmed connections learned and left open for earlyFor (rTorrent
//     and aria2 with encryption required: 3 of 169 and 3 of 104 ended connections tried again, on
//     the stand of 0.8.18; closing each starved their downloads to a fifth and less). A watched
//     device is judged at every poll, whether a connection waits or not (0.8.18 judged it only
//     while one did, so a device that had connected again was taken hours later, at its next
//     confirmed connection, as one that had not). A connection that closed while it waited stays
//     as a far end the device shook hands with: it counts among the earlySelf, and its far end is
//     learned when the device is known (the device's next connection to it is decided at its SYN).
//   - A peer on a common port (0.8.19): the firewall does not take a reply's or a UDP flow's word
//     for a peer on port 443 or another port other programs use; it sends the device's connection
//     there to an inspected inbound, where the handshake of BitTorrent itself (plaintext, or MSE's
//     three steps) confirms it, and its far end is learned for that device (learnFar).
//
// It uses sing-box's public API only: a connection tracker, appended before the inbounds start.
// It fails open: when it cannot write the set, the replies and the connections go on as sing-box
// routed them, counted.
package bittorrent

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// Type is the type of the service in the configuration.
const Type = "podkop-bittorrent"

// Options are the service's options in the configuration.
type Options struct {
	// Table and Set name the set of the family inet that takes the peers: its key is
	// ipv4_addr . ipv4_addr . inet_service (the device, the peer, its port), with a timeout.
	Table string `json:"table"`
	Set   string `json:"set"`
	// Timeout is each peer's time in the set (default 30m: M4, a client reuses a learned peer
	// within 30 s; the firewall's sets of BitTorrent have the same).
	Timeout badoption.Duration `json:"timeout,omitempty"`
	// Wait is the longest a reply is held for the set write (default 100ms: oracle's p99 for a
	// write of 200 peers is 1.1 ms, a client's retry of a request is seconds away).
	Wait badoption.Duration `json:"wait,omitempty"`
	// Learn are the inbounds whose discovery is read: every UDP session (they carry what the
	// firewall told as BitTorrent), and the TCP connections sing-box's sniffer named HTTP.
	Learn badoption.Listable[string] `json:"learn,omitempty"`
	// LearnSniffed are inbounds of other traffic whose discovery is read too: only the UDP
	// sessions sing-box's sniffers named BitTorrent, and the TCP connections named HTTP.
	LearnSniffed badoption.Listable[string] `json:"learn_sniffed,omitempty"`
	// Inspect are the inbounds whose TCP connections are inspected, with what is done with a
	// confirmed one.
	Inspect []InspectOptions `json:"inspect,omitempty"`
	// Early are the inbounds whose TCP connections to an uncommon port are checked early (see
	// the top), with what is done with a confirmed one once its device is known; Hosts is the set
	// of the table that tells those devices (ipv4_addr).
	Early []InspectOptions `json:"early,omitempty"`
	Hosts string           `json:"hosts,omitempty"`
	// ThirdStep is the longest from the far side's answer to the device's next data, for the
	// third step (default 50ms: A1b, aria2 and rTorrent p99 1.0-2.0 ms; the two false
	// confirmations of all A1b's data, V2Ray's, came at 59-60 ms).
	ThirdStep badoption.Duration `json:"third_step,omitempty"`
	// ThirdStepLate is the longest for a third step of 96 to 636 bytes, MSE's third message with
	// the handshake as its initial payload (default 20s: A1c of 0.8.18, Transmission's p99 9.9 s,
	// its longest 15.5 s; no answered connection of a proxy client in A1 and A1b sent such data
	// later than 50 ms).
	ThirdStepLate badoption.Duration `json:"third_step_late,omitempty"`
	// NeverPorts are ports never learned, besides those under 1024: podkop's common ports, whose
	// connections the firewall never takes for BitTorrent.
	NeverPorts badoption.Listable[uint16] `json:"never_ports,omitempty"`
	// PerDevice is the most peers learned for one device within Timeout (default 8192: the set
	// holds 65535).
	PerDevice int `json:"per_device,omitempty"`
}

// InspectOptions is one inspected inbound.
type InspectOptions struct {
	Inbound   string    `json:"inbound"`
	Confirmed Confirmed `json:"confirmed"`
}

// Register adds the service to a registry of sing-box services.
func Register(registry *boxService.Registry) {
	boxService.Register[Options](registry, Type, New)
}

// Service is the module, a service of sing-box.
type Service struct {
	ctx        context.Context
	logger     log.ContextLogger
	tag        string
	options    Options
	learnOn    map[string]bool
	sniffedOn  map[string]bool
	inspectOn  map[string]Confirmed
	earlyOn    map[string]Confirmed
	neverPorts map[uint16]struct{}
	wait       time.Duration
	thirdStep  time.Duration
	// thirdStepLate: see Options.ThirdStepLate
	thirdStepLate time.Duration
	devices       devices
	writer        *writer
	// sink takes the keys learned: the writer, or a test's
	sink     adder
	counters counters
	// early: the counters of the early check; pending its confirmed connections by device, until
	// the device is known (or earlyFor passed)
	early        counters
	earlyActed   atomic.Int64
	earlyExpired atomic.Int64
	// earlySelfTold: devices taken as running a client by their own confirmed connections
	earlySelfTold atomic.Int64
	// earlyNoRetry: of those, the devices that did not connect again within earlyRetry;
	// earlyKept: the connections of such devices learned and left open
	earlyNoRetry atomic.Int64
	earlyKept    atomic.Int64
	// selfTold: when a device was told by its own peers (watched for earlyRetry); noRetry: until
	// when a device that did not connect again keeps its connections; selfKnown: until when a
	// device told by its own peers in block is taken as running a client (its closed connections
	// learn nothing, so their retries never put it in the set) (all under pendingMu)
	selfTold  map[netip.Addr]time.Time
	noRetry   map[netip.Addr]time.Time
	selfKnown map[netip.Addr]time.Time
	pendingMu sync.Mutex
	pending   map[netip.Addr][]*waiting
	// known tells whether a device is in the set Hosts (the poller's netlink read; a test's);
	// knownFailing: its last read failed (told in the log once), earlyReadFailed counts them
	known           func() (map[netip.Addr]bool, error)
	knownFailing    bool
	earlyReadFailed atomic.Int64
	// earlyGone: connections that had closed when their device was known (their far end learned)
	earlyGone   atomic.Int64
	stopPolling chan struct{}
	// replyBytes: what the conns keep of replies to announces, in all (httpRepliesMost)
	replyBytes atomic.Int64
}

// waiting is a connection confirmed early that waits for its device to be known: the connection
// while it is open, and after it closed its far end, as what the device shook hands with.
type waiting struct {
	conn      atomic.Pointer[conn]
	far       netip.AddrPort
	since     time.Time
	confirmed Confirmed
}

// earlyPoll is how often the devices of pending connections are looked up in the set Hosts: a
// dump of a set of a few devices, under a millisecond; a connection found early is acted on within
// it once its device is known. earlyFor is the longest a confirmed connection waits (the
// firewall's timeout of a device), earlyMost the most that wait for one device.
const (
	earlyPoll = 2 * time.Second
	earlyFor  = 30 * time.Minute
	earlyMost = 256
	earlySelf = 3
	// earlyRetry: how long a device told by its own peers has to connect again (the stand of
	// 0.8.18, the delay from a connection's end to the client's next SYN to the same peer:
	// qBittorrent 60-68 s, Transmission 8-119 s with a median of 10 s)
	earlyRetry = 90 * time.Second
)

type adder interface {
	add(keys [][]byte, wait time.Duration) error
}

// running is the service of the box that runs (Snapshot).
var running atomic.Pointer[Service]

// New makes the service of the options; nothing opens before Start.
func New(ctx context.Context, logger log.ContextLogger, tag string, options Options) (adapter.Service, error) {
	s := &Service{ctx: ctx, logger: logger, tag: tag, options: options,
		learnOn: make(map[string]bool), sniffedOn: make(map[string]bool), inspectOn: make(map[string]Confirmed), neverPorts: make(map[uint16]struct{}),
		earlyOn: make(map[string]Confirmed), pending: make(map[netip.Addr][]*waiting), stopPolling: make(chan struct{})}
	for _, inbound := range options.Learn {
		s.learnOn[inbound] = true
	}
	for _, inbound := range options.LearnSniffed {
		s.sniffedOn[inbound] = true
	}
	for _, inspected := range options.Inspect {
		s.inspectOn[inspected.Inbound] = inspected.Confirmed
	}
	if options.Table != "" && options.Hosts != "" {
		for _, early := range options.Early {
			s.earlyOn[early.Inbound] = early.Confirmed
		}
		s.known = func() (map[netip.Addr]bool, error) { return readHosts(options.Table, options.Hosts) }
	}
	for _, port := range options.NeverPorts {
		s.neverPorts[port] = struct{}{}
	}
	timeout := orDefault(options.Timeout.Build(), 30*time.Minute)
	s.wait = orDefault(options.Wait.Build(), 100*time.Millisecond)
	s.thirdStep = orDefault(options.ThirdStep.Build(), 50*time.Millisecond)
	s.thirdStepLate = orDefault(options.ThirdStepLate.Build(), 20*time.Second)
	perDevice := options.PerDevice
	if perDevice <= 0 {
		perDevice = 8192
	}
	s.devices = devices{cap: perDevice, window: timeout}
	if options.Table != "" && options.Set != "" {
		s.writer = newWriter(options.Table, options.Set, timeout, s.wait, &s.counters)
	}
	return s, nil
}

func orDefault(value time.Duration, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func (s *Service) Type() string { return Type }
func (s *Service) Tag() string  { return s.tag }

// Start appends the tracker at the first stage, before any inbound starts; the scope closes the
// service with the box.
func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	scope.Add(s.close)
	if s.writer != nil {
		if err := s.writer.start(); err != nil {
			// fail open: the inspection still works, nothing is learned
			s.logger.Error("BitTorrent: no netlink for the set, nothing is learned: ", err)
			s.writer = nil
		} else {
			s.sink = s.writer
		}
	}
	service.FromContext[adapter.Router](s.ctx).AppendTracker(s)
	running.Store(s)
	if len(s.earlyOn) > 0 {
		go s.pollPending()
	}
	return nil
}

func (s *Service) close() error {
	running.CompareAndSwap(s, nil)
	select {
	case <-s.stopPolling:
	default:
		close(s.stopPolling)
	}
	if s.writer != nil {
		s.writer.close()
	}
	return nil
}

// Snapshot is what the module of the box that runs has counted, or nil when none runs.
func Snapshot() Counters {
	s := running.Load()
	if s == nil {
		return nil
	}
	snapshot := s.counters.snapshot()
	early := s.early.snapshot()
	for _, name := range []string{"watched", "inspected", "confirmed", "confirmed_late", "refuted", "unanswered", "no_data", "not_shaped"} {
		snapshot["early_"+name] = early[name]
	}
	snapshot["early_acted"] = s.earlyActed.Load()
	snapshot["early_self"] = s.earlySelfTold.Load()
	snapshot["early_no_retry"] = s.earlyNoRetry.Load()
	snapshot["early_kept"] = s.earlyKept.Load()
	snapshot["early_expired"] = s.earlyExpired.Load()
	snapshot["early_gone"] = s.earlyGone.Load()
	snapshot["early_read_failed"] = s.earlyReadFailed.Load()
	return snapshot
}

func (s *Service) RoutedConnection(ctx context.Context, connection net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	confirmed, inspect := s.inspectOn[metadata.Inbound]
	// an announce to an HTTP tracker on an inbound of discovery: sing-box's sniffer named it HTTP
	announce := s.sink != nil && (s.learnOn[metadata.Inbound] || s.sniffedOn[metadata.Inbound]) && metadata.Protocol == C.ProtocolHTTP
	device := metadata.Source.Addr.Unmap()
	far := metadata.Destination.Unwrap().AddrPort()
	if metadata.Destination.IsFqdn() {
		far = metadata.OriginDestination.Unwrap().AddrPort()
	}
	// the early check: of the transparent proxy, to a far end that could be a peer (learnable:
	// a public address, a port of 1024 and over that no other program uses)
	earlyConfirmed, early := s.earlyOn[metadata.Inbound]
	early = early && !inspect && device.Is4() && s.learnable(far)
	if !inspect && !announce && !early {
		return connection
	}
	counted := &s.counters
	if early {
		counted, inspect, confirmed = &s.early, true, earlyConfirmed
	}
	if inspect {
		counted.watched.Add(1)
	}
	return &conn{Conn: connection, service: s, cnt: counted, early: early, device: device, far: far, inspect: inspect, confirmed: confirmed,
		routed: metadata.Protocol == C.ProtocolBitTorrent}
}

// logConfirmed tells a confirmed connection in the log: the device, the far end, what was done. A
// connection of another program taken for BitTorrent (3 of 10473 on the stand, the workspace's
// notes/2026-11-16-bt-phaseBC.md) is closed, and in bypass and section its far end is learned: the
// device's next connections to it go the mode's way until 30 minutes after the last of them. The
// line names that server.
func (s *Service) logConfirmed(device netip.Addr, far netip.AddrPort, done string) {
	if s.logger != nil {
		s.logger.Info("BitTorrent: the connection of ", device, " to ", far, " confirmed as BitTorrent: ", done)
	}
}

func (s *Service) initEarly() {
	if s.selfTold == nil {
		s.selfTold, s.noRetry, s.selfKnown = make(map[netip.Addr]time.Time), make(map[netip.Addr]time.Time), make(map[netip.Addr]time.Time)
	}
}

// selfKnownNow tells whether a device was told by its own peers in block (selfKnown): a connection
// of it confirmed early is closed at once.
func (s *Service) selfKnownNow(device netip.Addr, now time.Time) bool {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	until, ok := s.selfKnown[device]
	return ok && now.Before(until)
}

// pend keeps a connection confirmed early, at now, until its device is known (pollPending).
func (s *Service) pend(c *conn, now time.Time) *waiting {
	w := &waiting{far: c.far, since: now, confirmed: c.confirmed}
	w.conn.Store(c)
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	list := s.pending[c.device]
	if len(list) >= earlyMost {
		list[0] = nil
		list = list[1:]
		s.earlyExpired.Add(1)
	}
	s.pending[c.device] = append(list, w)
	return w
}

// pollPending looks the devices of pending connections up in the set every earlyPoll, and acts on
// the connections of a device that is there; one that waited earlyFor goes.
func (s *Service) pollPending() {
	ticker := time.NewTicker(earlyPoll)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopPolling:
			return
		case now := <-ticker.C:
			s.poll(now)
		}
	}
}

// poll is a round of pollPending whose panic ends the round, not the backend (the poller is a
// goroutine of its own).
func (s *Service) poll(now time.Time) {
	defer func() {
		if recover() != nil {
			s.counters.panics.Add(1)
		}
	}()
	s.actOnKnown(now)
}

// due is a waiting connection to act on: kept, its far end is learned and it is left open.
type due struct {
	device  netip.Addr
	waiting *waiting
	kept    bool
}

// actOnKnown is a round of pollPending at now.
func (s *Service) actOnKnown(now time.Time) {
	if !s.expireEarly(now) {
		// no connection waits and no device is watched: the set is not read
		return
	}
	known, err := s.known()
	if err != nil {
		// fail open: the connections go on as they were routed, and no device is judged without
		// the set; what waited earlyFor still goes
		s.earlyReadFailed.Add(1)
		s.pendingMu.Lock()
		first := !s.knownFailing
		s.knownFailing = true
		s.pendingMu.Unlock()
		if first && s.logger != nil {
			s.logger.Warn("BitTorrent: the set of devices cannot be read, the connections confirmed early wait: ", err)
		}
		return
	}
	for _, d := range s.sweep(now, known) {
		s.actOn(d)
	}
}

// expireEarly forgets, at now, what ran out (the devices that keep their connections, those told
// in block, the connections that waited earlyFor) and tells whether a connection waits or a
// device is watched.
func (s *Service) expireEarly(now time.Time) bool {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	s.initEarly()
	for _, states := range []map[netip.Addr]time.Time{s.noRetry, s.selfKnown} {
		for device, until := range states {
			if now.After(until) {
				delete(states, device)
			}
		}
	}
	for device, list := range s.pending {
		kept := list[:0]
		for _, w := range list {
			if now.Sub(w.since) > earlyFor {
				s.earlyExpired.Add(1)
				continue
			}
			kept = append(kept, w)
		}
		clear(list[len(kept):])
		if len(kept) == 0 {
			delete(s.pending, device)
		} else {
			s.pending[device] = kept
		}
	}
	return len(s.pending) > 0 || len(s.selfTold) > 0
}

// sweep judges, at now and with the devices known to the firewall, the devices watched and the
// connections that wait, and gives those to act on.
func (s *Service) sweep(now time.Time, known map[netip.Addr]bool) []due {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	s.knownFailing = false
	// a device told by its own peers: known since (it connected again), or not within earlyRetry
	for device, at := range s.selfTold {
		switch {
		case known[device]:
			delete(s.selfTold, device)
		case now.Sub(at) > earlyRetry:
			delete(s.selfTold, device)
			s.noRetry[device] = now.Add(earlyFor)
			s.earlyNoRetry.Add(1)
			if s.logger != nil {
				s.logger.Info("BitTorrent: ", device, " did not connect again to the peers whose connections were closed: its connections are left open from now on")
			}
		}
	}
	var all []due
	for device, list := range s.pending {
		// a connection of the transparent proxy is done with as the mode says: all of a
		// device's waiting ones alike; only learn_reset waits for a device to connect again
		resets := list[0].confirmed == ConfirmedLearnReset
		if _, watched := s.selfTold[device]; watched && resets {
			// waiting for the verdict of earlyRetry
			continue
		}
		distinct := make(map[netip.Addr]struct{})
		for _, w := range list {
			distinct[w.far.Addr()] = struct{}{}
		}
		_, noRetry := s.noRetry[device]
		_, selfKnown := s.selfKnown[device]
		self := !known[device] && (noRetry || selfKnown || len(distinct) >= earlySelf)
		if !known[device] && !self {
			continue
		}
		kept := noRetry && !known[device]
		if self && !noRetry && !selfKnown {
			if resets {
				s.selfTold[device] = now
			} else {
				s.selfKnown[device] = now.Add(earlyFor)
			}
			s.earlySelfTold.Add(1)
			if s.logger != nil {
				s.logger.Info("BitTorrent: ", device, " made the encrypted handshake of BitTorrent with ", len(distinct), " peers: taken as running a client")
			}
		}
		for _, w := range list {
			all = append(all, due{device: device, waiting: w, kept: kept})
		}
		delete(s.pending, device)
	}
	return all
}

// actOn does with a connection that waited what its inbound says, now that its device is known.
// One that closed meanwhile has its far end learned (outside block): the device's next connection
// to that peer is decided at its SYN.
func (s *Service) actOn(d due) {
	c := d.waiting.conn.Load()
	if c != nil {
		c.access.Lock()
		defer c.access.Unlock()
	}
	if c == nil || c.gone {
		s.earlyGone.Add(1)
		if d.waiting.confirmed != ConfirmedReject {
			s.learnFar(d.device, d.waiting.far)
		}
		return
	}
	c.waits = nil
	s.earlyActed.Add(1)
	if s.logger != nil {
		s.logger.Info("BitTorrent: the connection of ", c.device, " to ", c.far, ", confirmed before the device was known to run a client, is taken as BitTorrent now")
	}
	if d.kept && c.confirmed == ConfirmedLearnReset {
		c.confirmed = ConfirmedLearn
		s.earlyKept.Add(1)
	}
	c.act()
}

func (s *Service) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	switch {
	case s.sink == nil:
		return conn
	case s.learnOn[metadata.Inbound]:
	case s.sniffedOn[metadata.Inbound] && metadata.Protocol == C.ProtocolBitTorrent:
	default:
		return conn
	}
	return &packetConn{PacketConn: conn, service: s, device: metadata.Source.Addr.Unmap()}
}

func (s *Service) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return nil
}
