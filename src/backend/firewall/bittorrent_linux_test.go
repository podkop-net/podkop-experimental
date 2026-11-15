package firewall

import (
	"testing"
)

// bitTorrentTable makes the table of a plan with the BitTorrent detector with the nft program: the
// table of the shell backend (shellBackendTable), then the sets and the chains of the detector as
// they read written by hand, the rules of each mode with them.
func bitTorrentTable(t *testing.T, plan *Plan) {
	shellBackendTable(t, plan)
	table := "inet " + tableName
	mode := plan.BitTorrent.Mode
	ports := "{ 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995, 3478, 5222, 5223, 5228, 8080, 8443 }"
	rule := func(chain string, text string) string { return "add rule " + table + " " + chain + " " + text }
	lines := []string{
		"add set " + table + " bt_sockets { type ipv4_addr . inet_service; flags dynamic,timeout; timeout 30m; }",
		"add set " + table + " bt_hosts { type ipv4_addr; flags dynamic,timeout; timeout 30m; }",
		"add set " + table + " bt_peers { type ipv4_addr . inet_service; flags dynamic,timeout; timeout 30m; }",
		"add chain " + table + " bt_detect { type filter hook prerouting priority -160; policy accept; }",
		"add chain " + table + " bt_udp",
		"add chain " + table + " bt_socket",
		"add chain " + table + " bt_flow",
		"add chain " + table + " bt_tcp",
		"add chain " + table + " bt_syn",
		"add chain " + table + " bt_handshake",
		"add chain " + table + " bt_decided",
		"add chain " + table + " bt_act { type filter hook prerouting priority -149; policy accept; }",
		rule("bt_detect", "iifname != @interfaces return"),
		rule("bt_detect", "meta nfproto != ipv4 return"),
		rule("bt_detect", "ct mark & 0x70000000 != 0 goto bt_decided"),
		rule("bt_detect", "meta l4proto udp goto bt_udp"),
		rule("bt_detect", "meta l4proto tcp goto bt_tcp"),
		rule("bt_udp", "ip daddr 239.192.152.143 udp dport 6771 update @bt_hosts { ip saddr } counter return"),
		rule("bt_udp", "ip daddr @localv4 return"),
		rule("bt_udp", "ip saddr . udp sport @bt_sockets goto bt_flow"),
		rule("bt_udp", "@ih,0,56 0x64313a6164323a counter goto bt_socket"),
		rule("bt_udp", "@ih,0,56 0x64313a7264323a counter goto bt_socket"),
		rule("bt_udp", "@ih,0,56 0x64323a6970363a counter goto bt_socket"),
		rule("bt_udp", "@ih,0,48 0x64313a656c69 counter goto bt_socket"),
		rule("bt_udp", "@ih,0,96 0x000004172710198000000000 counter goto bt_socket"),
		rule("bt_udp", "@ih,0,8 0x41 @ih,8,8 < 0x3 @ih,64,32 0x0 counter goto bt_socket"),
		rule("bt_udp", "ct mark set ct mark | 0x40000000"),
		rule("bt_socket", "update @bt_sockets { ip saddr . udp sport }"),
		rule("bt_socket", "update @bt_hosts { ip saddr }"),
		rule("bt_socket", "goto bt_flow"),
		rule("bt_flow", "update @bt_peers { ip daddr . udp dport }"),
		rule("bt_flow", "ct mark set ct mark | 0x10000000 counter"),
		rule("bt_flow", "goto bt_decided"),
		rule("bt_tcp", "ip daddr @localv4 return"),
		rule("bt_tcp", "tcp flags & (syn | ack) == syn goto bt_syn"),
		rule("bt_tcp", "@ih,0,96 0x13426974546f7272656e7420 @ih,96,64 0x70726f746f636f6c counter goto bt_handshake"),
	}
	if mode == BitTorrentBlock {
		for _, start := range []string{"@ih,0,16 0x1603", "@ih,0,32 0x47455420", "@ih,0,32 0x504f5354", "@ih,0,32 0x48454144", "@ih,0,32 0x5353482d"} {
			lines = append(lines, rule("bt_tcp", start+" ct mark set ct mark | 0x40000000 return"))
		}
		intercepted := " ct mark & 0x08000000 != 0"
		if plan.BitTorrent.BlockLAN {
			intercepted = ""
		}
		lines = append(lines, rule("bt_tcp", "ip saddr @bt_hosts tcp dport != "+ports+" @ih,0,8 0x0-0xff ip length 136-668"+intercepted+
			" update @bt_peers { ip daddr . tcp dport } ct mark set ct mark | 0x10000000 counter drop"))
	}
	lines = append(lines,
		rule("bt_tcp", "@ih,0,8 0x0-0xff ct mark set ct mark | 0x40000000"),
		rule("bt_syn", "ip saddr @bt_hosts ip daddr . tcp dport @bt_peers ct mark set ct mark | 0x10000000 counter goto bt_decided"),
	)
	if mode == BitTorrentSection {
		lines = append(lines, rule("bt_syn", "ip saddr @bt_hosts tcp dport != "+ports+" ct mark set ct mark | 0x10000000 counter goto bt_decided"))
	}
	lines = append(lines,
		rule("bt_handshake", "update @bt_hosts { ip saddr }"),
		rule("bt_handshake", "update @bt_peers { ip daddr . tcp dport }"),
		rule("bt_handshake", "ct mark & 0x08000000 != 0 ct mark set ct mark | 0x20000000 counter return"),
		rule("bt_handshake", "ct mark set ct mark | 0x10000000 counter goto bt_decided"),
		rule("bt_decided", "ct mark & 0x10000000 == 0 return"),
	)
	if mode == BitTorrentBlock && plan.BitTorrent.BlockLAN {
		lines = append(lines, rule("bt_decided", "counter drop"))
	}
	lines = append(lines,
		rule("bt_act", "meta mark & 0x00100000 == 0 return"),
		rule("bt_act", "ct mark & 0x08000000 == 0 ct mark set ct mark | 0x08000000"),
		rule("bt_act", "ct mark & 0x10000000 == 0 return"),
	)
	switch mode {
	case BitTorrentBypass:
		lines = append(lines, rule("bt_act", "meta mark set meta mark & 0xffefffff counter"))
	case BitTorrentBlock:
		lines = append(lines, rule("bt_act", "counter drop"))
	case BitTorrentSection:
		// before the rules of proxy: the last one inserted is the first
		for _, transport := range []string{"udp", "tcp"} {
			lines = append(lines, "insert rule "+table+" proxy ct mark & 0x10000000 != 0 meta mark & 0x00100000 == 0x00100000 meta l4proto "+
				transport+" tproxy ip to 127.0.0.1:1604 counter accept")
		}
	}
	for _, line := range lines {
		nft(t, line)
	}
}

// The detector made over netlink reads back, by the nft program, as the same detector written by
// hand, in each mode; a second run replaces it.
func TestBitTorrentTable(t *testing.T) {
	needNft(t)
	for name, detector := range map[string]BitTorrent{
		"bypass":         {Mode: BitTorrentBypass},
		"block":          {Mode: BitTorrentBlock},
		"block, the LAN": {Mode: BitTorrentBlock, BlockLAN: true},
		"section":        {Mode: BitTorrentSection},
	} {
		plan := &Plan{Interfaces: []string{"br-lan"}, Sources: prefixes("192.168.1.60/32"), BitTorrent: detector}
		_ = Remove()
		bitTorrentTable(t, plan)
		want := dump(t)
		if err := Remove(); err != nil {
			t.Fatal(err)
		}
		if err := Apply(plan); err != nil {
			t.Fatal(name, ": ", err)
		}
		got := dump(t)
		if got != want {
			t.Errorf("%s:\n--- over netlink\n%s\n--- by the nft program\n%s", name, got, want)
		}
		if err := Apply(plan); err != nil {
			t.Fatal(err)
		}
		if again := dump(t); again != want {
			t.Errorf("%s, applied twice:\n%s", name, again)
		}
	}
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
}

// A change of the mode is one of the rules: the table is made anew.
func TestBitTorrentModeIsStructure(t *testing.T) {
	off := &Plan{Interfaces: []string{"br-lan"}}
	bypass := &Plan{Interfaces: []string{"br-lan"}, BitTorrent: BitTorrent{Mode: BitTorrentBypass}}
	block := &Plan{Interfaces: []string{"br-lan"}, BitTorrent: BitTorrent{Mode: BitTorrentBlock}}
	lan := &Plan{Interfaces: []string{"br-lan"}, BitTorrent: BitTorrent{Mode: BitTorrentBlock, BlockLAN: true}}
	structures := map[string]bool{}
	for _, plan := range []*Plan{off, bypass, block, lan} {
		structures[plan.structure()] = true
	}
	if len(structures) != 4 {
		t.Errorf("modes share a structure: %d of 4", len(structures))
	}
}
