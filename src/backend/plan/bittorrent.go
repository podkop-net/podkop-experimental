package plan

import (
	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
)

// BitTorrent (notes/2026-11-15-bittorrent.md of the workspace). The firewall tells the traffic of
// BitTorrent clients by its first packets and does with what the backend would take what the
// settings say (firewall/bittorrent_linux.go): past podkop, dropped, or to the inbound of
// BitTorrent, whose route rule sends it to the servers of a rule. A connection the proxy had
// taken before it was told (a plaintext handshake to a peer not known yet) is led by the route
// rule of the protocol, after the sniffer of the engine named it.

// tagBitTorrentInbound is the transparent proxy inbound of what the firewall sends to a rule.
const tagBitTorrentInbound = "bt-in"

// bitTorrent is the mode the settings ask for, and the rule of the mode section; off, with a
// warning, for a mode it does not know or a rule that is not there or carries nothing.
func (b *builder) bitTorrent() (string, *model.Section) {
	settings := &b.config.Settings
	switch settings.BitTorrent {
	case "", model.BitTorrentOff:
		return model.BitTorrentOff, nil
	case model.BitTorrentBypass, model.BitTorrentBlock:
		return settings.BitTorrent, nil
	case model.BitTorrentSection:
		section := b.config.Section(settings.BitTorrentSection)
		if section == nil || !b.routes(section) {
			b.warnOnce("BitTorrent: the rule \"", settings.BitTorrentSection, "\" is not there, is off or goes nowhere: BitTorrent goes as the other traffic")
			return model.BitTorrentOff, nil
		}
		return model.BitTorrentSection, section
	}
	b.warnOnce("BitTorrent: unknown mode \"", settings.BitTorrent, "\": BitTorrent goes as the other traffic")
	return model.BitTorrentOff, nil
}

// buildBitTorrentInbound adds the inbound of BitTorrent in the mode section.
func (b *builder) buildBitTorrentInbound() {
	if b.bitTorrentMode != model.BitTorrentSection {
		return
	}
	b.inbounds = append(b.inbounds, newObject("type", "tproxy", "tag", tagBitTorrentInbound, "listen", dataplane.TProxyAddress,
		"listen_port", dataplane.BitTorrentTProxyPort, "tcp_fast_open", true, "udp_fragment", true))
}

// addBitTorrentRoutes adds the route rules of BitTorrent: the inbound of BitTorrent to its rule,
// and what the sniffer names BitTorrent from the transparent proxy where the mode sends it.
func (b *builder) addBitTorrentRoutes() {
	switch b.bitTorrentMode {
	case model.BitTorrentBypass:
		b.addRouteRule("", newObject("action", "route", "inbound", tagTProxyInbound, "protocol", "bittorrent", "outbound", tagDirectOutbound))
	case model.BitTorrentBlock:
		b.addRouteRule("", newObject("action", "reject", "inbound", tagTProxyInbound, "protocol", "bittorrent"))
	case model.BitTorrentSection:
		b.addRouteRule("", b.sectionRoute(b.bitTorrentSection, tagBitTorrentInbound))
		sniffed := b.sectionRoute(b.bitTorrentSection, tagTProxyInbound)
		sniffed.set("protocol", "bittorrent")
		b.addRouteRule("", sniffed)
	}
}

// bitTorrentDataplane is what the firewall is told of BitTorrent: the mode (none when off), and
// whether a block holds for the whole LAN.
func (b *builder) bitTorrentDataplane() (string, bool) {
	if b.bitTorrentMode == model.BitTorrentOff {
		return "", false
	}
	return b.bitTorrentMode, b.bitTorrentMode == model.BitTorrentBlock && b.config.Settings.BitTorrentBlockLAN
}
