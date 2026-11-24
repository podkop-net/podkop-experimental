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

// Services are what podkop's own services of sing-box are given by the backend that builds the box
// (BuildLogged): the hooks of the BitTorrent module into the firewall. None (the zero value) where
// nothing runs: a configuration built to be checked.
type Services struct {
	BitTorrent bittorrent.Hooks
}

// boxContext is include.Context with podkop's own services of sing-box registered besides those of
// the engine, given the services: the BitTorrent module (package bittorrent, type
// "podkop-bittorrent").
func boxContext(ctx context.Context, services Services) context.Context {
	registry := include.ServiceRegistry()
	bittorrent.Register(registry, services.BitTorrent)
	return box.Context(ctx, include.InboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry(),
		include.DNSTransportRegistry(), registry, include.CertificateProviderRegistry())
}
