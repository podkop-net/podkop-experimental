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
//     The three steps of MSE confirm or refute each one; a confirmed one is closed (block) or its
//     far end learned (bypass, section).
//
// It uses sing-box's public API only: a connection tracker, appended before the inbounds start.
// It fails open: when it cannot write the set, the replies and the connections go on as sing-box
// routed them, counted.
package bittorrent

import (
	"context"
	"net"
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
	// ThirdStep is the longest from the far side's answer to the device's next data, for the
	// third step (default 50ms: A1b, aria2 and rTorrent p99 1.0-2.0 ms; the two false
	// confirmations of all A1b's data, V2Ray's, came at 59-60 ms).
	ThirdStep badoption.Duration `json:"third_step,omitempty"`
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
	neverPorts map[uint16]struct{}
	wait       time.Duration
	thirdStep  time.Duration
	devices    devices
	writer     *writer
	// sink takes the keys learned: the writer, or a test's
	sink     adder
	counters counters
}

type adder interface {
	add(keys [][]byte, wait time.Duration) error
}

// running is the service of the box that runs (Snapshot).
var running atomic.Pointer[Service]

// New makes the service of the options; nothing opens before Start.
func New(ctx context.Context, logger log.ContextLogger, tag string, options Options) (adapter.Service, error) {
	s := &Service{ctx: ctx, logger: logger, tag: tag, options: options,
		learnOn: make(map[string]bool), sniffedOn: make(map[string]bool), inspectOn: make(map[string]Confirmed), neverPorts: make(map[uint16]struct{})}
	for _, inbound := range options.Learn {
		s.learnOn[inbound] = true
	}
	for _, inbound := range options.LearnSniffed {
		s.sniffedOn[inbound] = true
	}
	for _, inspected := range options.Inspect {
		s.inspectOn[inspected.Inbound] = inspected.Confirmed
	}
	for _, port := range options.NeverPorts {
		s.neverPorts[port] = struct{}{}
	}
	timeout := orDefault(options.Timeout.Build(), 30*time.Minute)
	s.wait = orDefault(options.Wait.Build(), 100*time.Millisecond)
	s.thirdStep = orDefault(options.ThirdStep.Build(), 50*time.Millisecond)
	perDevice := options.PerDevice
	if perDevice <= 0 {
		perDevice = 16384
	}
	s.devices = devices{cap: perDevice, window: timeout}
	if options.Table != "" && options.Set != "" {
		s.writer = newWriter(options.Table, options.Set, timeout, &s.counters)
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
	return nil
}

func (s *Service) close() error {
	running.CompareAndSwap(s, nil)
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
	return s.counters.snapshot()
}

func (s *Service) RoutedConnection(ctx context.Context, connection net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	confirmed, inspect := s.inspectOn[metadata.Inbound]
	// an announce to an HTTP tracker on an inbound of discovery: sing-box's sniffer named it HTTP
	announce := s.sink != nil && (s.learnOn[metadata.Inbound] || s.sniffedOn[metadata.Inbound]) && metadata.Protocol == C.ProtocolHTTP
	if !inspect && !announce {
		return connection
	}
	device := metadata.Source.Addr.Unmap()
	far := metadata.Destination.Unwrap().AddrPort()
	if metadata.Destination.IsFqdn() {
		far = metadata.OriginDestination.Unwrap().AddrPort()
	}
	if inspect {
		s.counters.watched.Add(1)
	}
	return &conn{Conn: connection, service: s, device: device, far: far, inspect: inspect, confirmed: confirmed}
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
