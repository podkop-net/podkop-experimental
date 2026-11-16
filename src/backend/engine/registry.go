package engine

import (
	"context"

	"github.com/podkop-net/podkop-experimental/src/backend/engine/bittorrent"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
)

// BitTorrentCounters are what the BitTorrent module of the running box has counted, by name; nil
// when none runs.
func BitTorrentCounters() map[string]int64 {
	return bittorrent.Snapshot()
}

// boxContext is include.Context with podkop's own services of sing-box registered besides those of
// the engine: the BitTorrent module (package bittorrent, type "podkop-bittorrent").
func boxContext(ctx context.Context) context.Context {
	services := include.ServiceRegistry()
	bittorrent.Register(services)
	return box.Context(ctx, include.InboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry(),
		include.DNSTransportRegistry(), services, include.CertificateProviderRegistry())
}
