package engine

import (
	"github.com/podkop-net/podkop-experimental/src/backend/engine/bittorrent"
	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
)

// The BitTorrent module ends the older connections of a suspect it told (the suspicion by fan-out:
// dataplane.Fan) and keeps a device whose handshakes it confirms known to the firewall, both by
// the firewall's own code.
func init() {
	bittorrent.EndOlder = firewall.EndUndecidedFlows
	bittorrent.KeepKnown = firewall.KnowBitTorrentHost
}
