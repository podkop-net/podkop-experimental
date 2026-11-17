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
//     of six of them, Phase C; a client opens tens of peer connections a minute, A1).
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
	// PerDevice is the most peers learned for one device within Timeout (default 16384: the set
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
	pendingMu    sync.Mutex
	pending      map[netip.Addr][]*conn
	// known tells whether a device is in the set Hosts (the poller's netlink read; a test's)
	known       func() (map[netip.Addr]bool, error)
	stopPolling chan struct{}
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
		earlyOn: make(map[string]Confirmed), pending: make(map[netip.Addr][]*conn), stopPolling: make(chan struct{})}
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
		perDevice = 16384
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
	snapshot["early_expired"] = s.earlyExpired.Load()
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

// pend keeps a connection confirmed early until its device is known (pollPending).
func (s *Service) pend(c *conn) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	list := s.pending[c.device]
	if len(list) >= earlyMost {
		list = list[1:]
		s.earlyExpired.Add(1)
	}
	s.pending[c.device] = append(list, c)
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
			s.actOnKnown(now)
		}
	}
}

// actOnKnown is a round of pollPending at now.
func (s *Service) actOnKnown(now time.Time) {
	s.pendingMu.Lock()
	if len(s.pending) == 0 {
		s.pendingMu.Unlock()
		return
	}
	s.pendingMu.Unlock()
	known, err := s.known()
	if err != nil {
		// fail open: the connections go on as they were routed
		return
	}
	s.pendingMu.Lock()
	var due []*conn
	for device, list := range s.pending {
		kept := list[:0]
		distinct := make(map[netip.Addr]struct{})
		for _, c := range list {
			if now.Sub(c.pendingSince) > earlyFor {
				s.earlyExpired.Add(1)
				continue
			}
			kept = append(kept, c)
			distinct[c.far.Addr()] = struct{}{}
		}
		self := !known[device] && len(distinct) >= earlySelf
		if known[device] || self {
			if self {
				s.earlySelfTold.Add(1)
				if s.logger != nil {
					s.logger.Info("BitTorrent: ", device, " made the encrypted handshake of BitTorrent with ", len(distinct), " peers: taken as running a client")
				}
			}
			due = append(due, kept...)
			delete(s.pending, device)
			continue
		}
		if len(kept) == 0 {
			delete(s.pending, device)
		} else {
			s.pending[device] = kept
		}
	}
	s.pendingMu.Unlock()
	for _, c := range due {
		s.earlyActed.Add(1)
		if s.logger != nil {
			s.logger.Info("BitTorrent: the connection of ", c.device, " to ", c.far, ", confirmed before the device was known to run a client, is taken as BitTorrent now")
		}
		c.access.Lock()
		c.act()
		c.access.Unlock()
	}
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
