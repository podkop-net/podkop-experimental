package engine

import (
	"context"

	"github.com/podkop-net/podkop-experimental/src/backend/bittorrent"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
)

// boxContext is include.Context with podkop's own services of sing-box registered besides those of
// the engine: the BitTorrent module (package bittorrent, type "podkop-bittorrent").
func boxContext(ctx context.Context) context.Context {
	services := include.ServiceRegistry()
	bittorrent.Register(services)
	return box.Context(ctx, include.InboundRegistry(), include.OutboundRegistry(), include.EndpointRegistry(),
		include.DNSTransportRegistry(), services, include.CertificateProviderRegistry())
}
