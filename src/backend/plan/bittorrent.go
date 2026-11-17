package plan

import (
	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
)

// BitTorrent, design H (the workspace's notes/2026-11-16-bittorrent-architecture.md and
// notes/2026-11-16-a5-decision.md). The firewall tells the traffic of BitTorrent clients by its
// first packets (firewall/bittorrent_linux.go) and sends what needs sing-box to three inbounds of
// its own; podkop's module (package bittorrent, a service of sing-box) learns the peers of the
// discovery replies and inspects what the firewall could not decide:
//   - bt-in: what the firewall told as BitTorrent of the traffic podkop takes (and in the section
//     for the whole LAN, of every device): its route rule does what the mode says;
//   - bt-lan: of the traffic podkop does not take, the discovery (learned) and the connections
//     inspected for the whole LAN: out directly;
//   - bt-check: the connections of the traffic podkop takes that the firewall could not decide at
//     their SYN: inspected, and routed by podkop's rules as tproxy-in is (the tentative route of
//     the owner's choice (ii), 2026-11-16) until the module confirms one: it learns the far end
//     and closes the connection, so that the device's retry is BitTorrent at its SYN (the owner's
//     choice of 2026-11-17, after the measurement of (ii) alone).
// A connection the proxy had taken before it was told (a plaintext handshake to a peer not known
// yet) is led by the route rule of the protocol, after the sniffer of the engine named it.

// The module's type and what it does with a confirmed connection (package bittorrent: Type,
// ConfirmedReject, ConfirmedLearn, ConfirmedLearnReset; the engine's tests build a configuration of
// each mode with it).
const (
	bitTorrentServiceType = "podkop-bittorrent"
	bitTorrentReject      = "reject"
	bitTorrentLearn       = "learn"
	bitTorrentLearnReset  = "learn_reset"
)

const (
	tagBitTorrentInbound      = "bt-in"
	tagBitTorrentLANInbound   = "bt-lan"
	tagBitTorrentCheckInbound = "bt-check"
	tagBitTorrentService      = "bittorrent"
)

// BitTorrentCheckInboundTag is the inbound of the connections the module inspects: they are of the
// traffic the firewall marks, as those of TProxyInboundTag.
const BitTorrentCheckInboundTag = tagBitTorrentCheckInbound

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

// bitTorrentLAN tells the scope of the whole LAN: the block or the section of every device.
func (b *builder) bitTorrentLAN() bool {
	settings := &b.config.Settings
	switch b.bitTorrentMode {
	case model.BitTorrentBlock:
		return settings.BitTorrentBlockLAN
	case model.BitTorrentSection:
		return settings.BitTorrentSectionLAN
	}
	return false
}

// proxyInbounds are the inbounds of the traffic the firewall marks, which podkop's rules route:
// the transparent proxy, and the inspection inbound of BitTorrent when it is on.
func (b *builder) proxyInbounds() any {
	if b.bitTorrentMode == model.BitTorrentOff {
		return tagTProxyInbound
	}
	return []any{tagTProxyInbound, tagBitTorrentCheckInbound}
}

// bitTorrentSniffed are the inbounds of BitTorrent whose connections sing-box sniffs as those of
// the transparent proxy: the rules of the lists go by the names it sniffs, and the route rule of
// the protocol by what it names BitTorrent. bt-in is not sniffed: its route goes by the inbound.
func (b *builder) bitTorrentSniffed() []any {
	if b.bitTorrentMode == model.BitTorrentOff {
		return nil
	}
	return []any{tagBitTorrentCheckInbound, tagBitTorrentLANInbound}
}

// buildBitTorrentInbound adds the inbounds of BitTorrent (bt-in, of no use in block, where the
// firewall drops what it told) and the module.
func (b *builder) buildBitTorrentInbound() {
	if b.bitTorrentMode == model.BitTorrentOff {
		return
	}
	tproxy := func(tag string, port int) {
		b.inbounds = append(b.inbounds, newObject("type", "tproxy", "tag", tag, "listen", dataplane.TProxyAddress,
			"listen_port", port, "tcp_fast_open", true, "udp_fragment", true))
	}
	if b.bitTorrentMode != model.BitTorrentBlock {
		tproxy(tagBitTorrentInbound, dataplane.BitTorrentTProxyPort)
	}
	tproxy(tagBitTorrentLANInbound, dataplane.BitTorrentLANTProxyPort)
	tproxy(tagBitTorrentCheckInbound, dataplane.BitTorrentCheckTProxyPort)
	b.buildBitTorrentService()
}

// buildBitTorrentService adds the module: it learns from the discovery of the three inbounds and,
// of the transparent proxy, from what sing-box names BitTorrent or HTTP (an announce to an HTTP
// tracker of a device podkop takes), and inspects
// the connections of bt-check and bt-lan. What it does with a confirmed connection: closes it in
// block; else learns its far end for the device and closes it, so that the device's retry is
// BitTorrent at its SYN (the setting "learn" keeps it open on its tentative route, for the
// measurements of (ii) alone).
func (b *builder) buildBitTorrentService() {
	confirmed := bitTorrentLearnReset
	switch {
	case b.bitTorrentMode == model.BitTorrentBlock:
		confirmed = bitTorrentReject
	case b.config.Settings.BitTorrentConfirmed == bitTorrentLearn:
		confirmed = bitTorrentLearn
	}
	var never []any
	for _, port := range dataplane.BitTorrentCommonPorts {
		never = append(never, port)
	}
	b.services = append(b.services, newObject("type", bitTorrentServiceType, "tag", tagBitTorrentService,
		"table", dataplane.FirewallTable, "set", dataplane.BitTorrentLearnedSet,
		"learn", []any{tagBitTorrentInbound, tagBitTorrentLANInbound, tagBitTorrentCheckInbound},
		"learn_sniffed", []any{tagTProxyInbound},
		"inspect", []any{
			newObject("inbound", tagBitTorrentCheckInbound, "confirmed", confirmed),
			newObject("inbound", tagBitTorrentLANInbound, "confirmed", confirmed),
		},
		// the early check (0.8.18): a connection of the transparent proxy to an uncommon port,
		// confirmed before the firewall knew its device runs a client, is done with as those of
		// bt-check once it knows
		"early", []any{newObject("inbound", tagTProxyInbound, "confirmed", confirmed)},
		"hosts", dataplane.BitTorrentHostsSet,
		"never_ports", never))
}

// addBitTorrentRoutes adds the route rules of BitTorrent, before the devices and the lists: the
// BitTorrent inbound to the mode's way; what the sniffer names BitTorrent where the proxy or the
// inspection took it, to the same; then the inbound of the LAN straight out.
func (b *builder) addBitTorrentRoutes() {
	taken := []any{tagTProxyInbound, tagBitTorrentCheckInbound}
	switch b.bitTorrentMode {
	case model.BitTorrentOff:
		return
	case model.BitTorrentBypass:
		b.addRouteRule("", newObject("action", "route", "inbound", tagBitTorrentInbound, "outbound", tagDirectOutbound))
		b.addRouteRule("", newObject("action", "route", "inbound", append(taken, tagBitTorrentLANInbound), "protocol", "bittorrent", "outbound", tagDirectOutbound))
	case model.BitTorrentBlock:
		b.addRouteRule("", newObject("action", "reject", "inbound", append(taken, tagBitTorrentLANInbound), "protocol", "bittorrent"))
	case model.BitTorrentSection:
		b.addRouteRule("", b.sectionRoute(b.bitTorrentSection, tagBitTorrentInbound))
		if b.bitTorrentLAN() {
			taken = append(taken, tagBitTorrentLANInbound)
		}
		sniffed := b.sectionRoute(b.bitTorrentSection, taken)
		sniffed.set("protocol", "bittorrent")
		b.addRouteRule("", sniffed)
	}
	b.addRouteRule("", newObject("action", "route", "inbound", tagBitTorrentLANInbound, "outbound", tagDirectOutbound))
}

// bitTorrentDataplane is what the firewall is told of BitTorrent: the mode (none when off), and
// whether it acts on the whole LAN.
func (b *builder) bitTorrentDataplane() (string, bool) {
	if b.bitTorrentMode == model.BitTorrentOff {
		return "", false
	}
	return b.bitTorrentMode, b.bitTorrentLAN()
}
