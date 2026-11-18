package firewall

import (
	"fmt"
	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/nftables"
)

// The tests save no sets at a Remove and take none at an Apply (TestBitTorrentSaved sets a file
// of its own): the tables of one test must not carry what another left.
func init() { bitTorrentSaved = "" }

// bitTorrentTable makes the table of a plan with the BitTorrent detector with the nft program: the
// table of the shell backend (shellBackendTable), then the sets and the chains of the detector as
// they read written by hand, the rules of each mode with them.
func bitTorrentTable(t *testing.T, plan *Plan) {
	shellBackendTable(t, plan)
	table := "inet " + tableName
	detector := plan.BitTorrent
	mode := detector.Mode
	ports := "{ 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995, 3478, 5222, 5223, 5228, 8080, 8443 }"
	rule := func(chain string, text string) string { return "add rule " + table + " " + chain + " " + text }
	lines := []string{
		"add set " + table + " bt_sockets { type ipv4_addr . inet_service; size 4096; flags dynamic,timeout; timeout 30m; }",
		"add set " + table + " bt_hosts { type ipv4_addr; size 1024; flags dynamic,timeout; timeout 30m; }",
		"add set " + table + " bt_peers { type ipv4_addr . inet_service; size 32768; flags dynamic,timeout; timeout 30m; }",
		"add set " + table + " bt_utp { type ipv4_addr . inet_service; size 4096; flags dynamic,timeout; timeout 30m; }",
		"add set " + table + " bt_learned { type ipv4_addr . ipv4_addr . inet_service; size 32768; flags dynamic,timeout; timeout 30m; }",
		"add set " + table + " bt_trackers { type ipv4_addr . ipv4_addr . inet_service; size 1024; flags dynamic,timeout; timeout 2h; }",
		"add chain " + table + " bt_detect { type filter hook prerouting priority -160; policy accept; }",
		"add chain " + table + " bt_udp",
		"add chain " + table + " bt_discovery",
		"add chain " + table + " bt_socket",
		"add chain " + table + " bt_flow",
		"add chain " + table + " bt_tcp",
		"add chain " + table + " bt_syn",
		"add chain " + table + " bt_handshake",
		"add chain " + table + " bt_decided",
		"add chain " + table + " bt_add_hosts",
		"add chain " + table + " bt_add_sockets",
		"add chain " + table + " bt_add_peers",
		"add chain " + table + " bt_full_utp",
		"add chain " + table + " bt_act { type filter hook prerouting priority -149; policy accept; }",
		"add chain " + table + " bt_free",
	}
	if mode == BitTorrentBlock {
		lines = append(lines, "add chain "+table+" bt_block")
	}
	lines = append(lines, "add chain "+table+" bt_incoming { type filter hook forward priority -1; policy accept; }")
	lines = append(lines,
		rule("bt_detect", "iifname != @interfaces return"),
		rule("bt_detect", "meta nfproto != ipv4 return"),
		rule("bt_detect", "fib daddr type local return"),
		rule("bt_detect", "ct mark & 0x000f0000 != 0 goto bt_decided"),
		rule("bt_detect", "fib saddr . iif oif missing counter return"),
		rule("bt_detect", "meta l4proto udp goto bt_udp"),
		rule("bt_detect", "meta l4proto tcp goto bt_tcp"),
		rule("bt_udp", "ip daddr 239.192.152.143 udp dport 6771 update @bt_hosts { ip saddr } counter return"),
		rule("bt_udp", "ip daddr @localv4 return"),
		rule("bt_udp", "udp length 28 @ih,0,16 0x4100 @ih,64,32 0x0 @ih,144,16 0x0 update @bt_utp { ip saddr . udp sport } counter goto bt_socket"),
		rule("bt_udp", "udp length 38 @ih,0,16 0x4102 @ih,64,32 0x0 @ih,144,32 0x8 update @bt_utp { ip saddr . udp sport } counter goto bt_socket"),
		rule("bt_udp", "udp length 28 @ih,0,16 0x4100 @ih,64,32 0x0 @ih,144,16 0x0 jump bt_full_utp"),
		rule("bt_udp", "udp length 38 @ih,0,16 0x4102 @ih,64,32 0x0 @ih,144,32 0x8 jump bt_full_utp"),
		rule("bt_full_utp", "counter"),
		rule("bt_udp", "@ih,0,56 0x64313a6164323a counter goto bt_discovery"),
		rule("bt_udp", "@ih,0,56 0x64313a7264323a counter goto bt_discovery"),
		rule("bt_udp", "@ih,0,56 0x64323a6970363a counter goto bt_discovery"),
		rule("bt_udp", "@ih,0,48 0x64313a656c69 counter goto bt_discovery"),
		rule("bt_udp", "@ih,0,96 0x000004172710198000000000 counter goto bt_discovery"),
		rule("bt_udp", "ip saddr . udp sport @bt_sockets goto bt_flow"),
		rule("bt_udp", "ct mark set ct mark | 0x00040000"),
		rule("bt_discovery", "update @bt_sockets { ip saddr . udp sport }"),
		rule("bt_discovery", "update @bt_hosts { ip saddr }"),
		rule("bt_discovery", "ip saddr . udp sport @bt_utp goto bt_flow"),
		rule("bt_discovery", "ct mark set ct mark | 0x00004000 counter goto bt_flow"),
		rule("bt_socket", "update @bt_sockets { ip saddr . udp sport }"),
		rule("bt_socket", "update @bt_hosts { ip saddr }"),
		rule("bt_socket", "goto bt_flow"),
		rule("bt_flow", "update @bt_peers { ip daddr . udp dport }"),
		rule("bt_flow", "ct mark set ct mark | 0x00010000 counter"),
		rule("bt_flow", "goto bt_decided"),
		rule("bt_tcp", "ip daddr @localv4 return"),
		rule("bt_tcp", "tcp flags & (syn | ack) == syn goto bt_syn"),
		rule("bt_tcp", "@ih,0,96 0x13426974546f7272656e7420 @ih,96,64 0x70726f746f636f6c counter goto bt_handshake"),
		// "GET /announce?", and "GET /announc" "e.php?"
		rule("bt_tcp", "@ih,0,112 0x474554202f616e6e6f756e63653f tcp dport != "+ports+" update @bt_trackers { ip saddr . ip daddr . tcp dport }"),
		rule("bt_tcp", "@ih,0,112 0x474554202f616e6e6f756e63653f update @bt_hosts { ip saddr } ct mark set ct mark | 0x00040000 counter return"),
		rule("bt_tcp", "@ih,0,96 0x474554202f616e6e6f756e63 @ih,96,48 0x652e7068703f tcp dport != "+ports+" update @bt_trackers { ip saddr . ip daddr . tcp dport }"),
		rule("bt_tcp", "@ih,0,96 0x474554202f616e6e6f756e63 @ih,96,48 0x652e7068703f update @bt_hosts { ip saddr } ct mark set ct mark | 0x00040000 counter return"),
		rule("bt_tcp", "ip saddr . ip daddr . tcp dport @bt_learned counter goto bt_handshake"),
		rule("bt_tcp", "ip saddr @bt_hosts tcp dport >= 1024 tcp dport != "+ports+" ip daddr . tcp dport @bt_peers counter goto bt_handshake"),
		rule("bt_tcp", "@ih,0,8 0x0-0xff ct mark set ct mark | 0x00040000"),
		rule("bt_syn", "ip saddr . ip daddr . tcp dport @bt_learned update @bt_learned { ip saddr . ip daddr . tcp dport } ct mark set ct mark | 0x00010000 counter goto bt_decided"),
		rule("bt_syn", "ip saddr . ip daddr . tcp dport @bt_trackers update @bt_trackers { ip saddr . ip daddr . tcp dport } update @bt_hosts { ip saddr } ct mark set ct mark | 0x00014000 counter goto bt_decided"),
		rule("bt_syn", "ip saddr @bt_hosts tcp dport >= 1024 tcp dport != "+ports+" ip daddr . tcp dport @bt_peers ct mark set ct mark | 0x00010000 counter goto bt_decided"),
		rule("bt_syn", "ip saddr @bt_hosts ip daddr . tcp dport @bt_peers ct mark set ct mark | 0x00080000 counter return"),
		rule("bt_syn", "ip saddr @bt_hosts tcp dport != "+ports+" ct mark set ct mark | 0x00080000 counter return"),
		rule("bt_handshake", "update @bt_hosts { ip saddr }"),
		rule("bt_handshake", "ct direction original update @bt_peers { ip daddr . tcp dport }"),
		rule("bt_handshake", "ct mark & 0x00008000 != 0 ct mark set ct mark | 0x00020000 counter return"),
		rule("bt_handshake", "ct mark set ct mark | 0x00010000 counter goto bt_decided"),
		rule("bt_decided", "ct mark & 0x00090000 != 0 @ih,0,112 0x474554202f616e6e6f756e63653f tcp dport != "+ports+" update @bt_trackers { ip saddr . ip daddr . tcp dport }"),
		rule("bt_decided", "ct mark & 0x00090000 != 0 @ih,0,96 0x474554202f616e6e6f756e63 @ih,96,48 0x652e7068703f tcp dport != "+ports+" update @bt_trackers { ip saddr . ip daddr . tcp dport }"),
		rule("bt_decided", "ct mark & 0x00010000 == 0 return"),
		rule("bt_decided", "ip saddr != @bt_hosts jump bt_add_hosts"),
		rule("bt_decided", "ip saddr . udp sport != @bt_sockets jump bt_add_sockets"),
		rule("bt_decided", "ip daddr . udp dport != @bt_peers jump bt_add_peers"),
		rule("bt_decided", "ct direction original ip daddr . tcp dport != @bt_peers jump bt_add_peers"),
		rule("bt_add_hosts", "update @bt_hosts { ip saddr } return"),
		rule("bt_add_hosts", "counter"),
		rule("bt_add_sockets", "update @bt_sockets { ip saddr . udp sport } return"),
		rule("bt_add_sockets", "counter"),
		rule("bt_add_peers", "update @bt_peers { ip daddr . udp dport } return"),
		rule("bt_add_peers", "update @bt_peers { ip daddr . tcp dport } return"),
		rule("bt_add_peers", "counter"),
	)
	if mode != BitTorrentBlock {
		lines = append(lines,
			rule("bt_decided", "ct mark & 0x00004000 != 0 udp length 28 @ih,0,16 0x4100 @ih,64,32 0x0 @ih,144,16 0x0 update @bt_utp { ip saddr . udp sport } counter drop"),
			rule("bt_decided", "ct mark & 0x00004000 != 0 udp length 38 @ih,0,16 0x4102 @ih,64,32 0x0 @ih,144,32 0x8 update @bt_utp { ip saddr . udp sport } counter drop"))
	}
	if mode == BitTorrentBlock && detector.LAN {
		lines = append(lines, rule("bt_decided", "goto bt_block"))
	}
	lines = append(lines,
		rule("bt_act", "meta mark & 0x00100000 == 0 goto bt_free"),
		rule("bt_act", "ct mark & 0x00008000 == 0 ct mark set ct mark | 0x00008000"),
		rule("bt_act", "ct mark & 0x00080000 != 0 return"),
		rule("bt_act", "ct mark & 0x00010000 == 0 return"),
	)
	switch mode {
	case BitTorrentBypass:
		lines = append(lines,
			rule("bt_act", "ip daddr 198.18.0.0/15 return"),
			rule("bt_act", "ct mark & 0x00004000 != 0 return"),
			rule("bt_act", "meta mark set meta mark & 0xffefffff counter"))
	case BitTorrentBlock:
		lines = append(lines, rule("bt_act", "goto bt_block"))
	}
	lines = append(lines, rule("bt_free", "iifname != @interfaces return"), rule("bt_free", "ct direction reply return"))
	if detector.LAN {
		lines = append(lines, rule("bt_free", "ct mark & 0x00080000 != 0 meta mark set meta mark | 0x00100000 counter return"))
	}
	lines = append(lines, rule("bt_free", "ct mark & 0x00010000 == 0 return"))
	switch {
	case mode == BitTorrentSection && detector.LAN:
		lines = append(lines, rule("bt_free", "meta mark set meta mark | 0x00100000 counter"))
	case mode != BitTorrentBlock:
		lines = append(lines, rule("bt_free", "ct mark & 0x00004000 != 0 meta mark set meta mark | 0x00100000 counter"))
	}
	if mode == BitTorrentBlock {
		lines = append(lines,
			rule("bt_block", "meta l4proto udp ct mark & 0x00004000 != 0 counter drop"),
			rule("bt_block", "meta l4proto udp counter drop"),
			rule("bt_block", "counter drop"))
	}
	lines = append(lines, rule("bt_incoming", "ct state & new == 0 return"), rule("bt_incoming", "iifname @interfaces return"))
	if mode == BitTorrentBlock {
		devices := []string{""}
		if !detector.LAN {
			devices = nil
			for _, device := range detector.Sources {
				devices = append(devices, "ip daddr "+device.String()+" ")
			}
		}
		for _, device := range devices {
			device = strings.TrimSuffix(strings.Replace(device, "/32 ", " ", 1), "/32")
			for _, transport := range []string{"tcp", "udp"} {
				lines = append(lines, rule("bt_incoming", device+"ip daddr . "+transport+" dport @bt_sockets counter drop"))
			}
		}
	}
	// a connection from outside to a client's socket that is not dropped is told as BitTorrent
	if mode != BitTorrentBlock || !detector.LAN {
		for _, transport := range []string{"tcp", "udp"} {
			lines = append(lines, rule("bt_incoming", "ip daddr . "+transport+" dport @bt_sockets ct mark set ct mark | 0x00010000 counter"))
		}
	}
	// the first rules of proxy, before the transparent proxy's: the last one inserted is the first
	type route struct {
		marks string
		port  int
	}
	routes := []route{{"ct mark & 0x00080000 != 0 ct mark & 0x00008000 != 0", 1606}}
	if detector.LAN {
		routes = append(routes, route{"ct mark & 0x00080000 != 0 ct mark & 0x00008000 == 0", 1605})
	}
	if mode != BitTorrentBlock {
		free := 1605
		if mode == BitTorrentSection && detector.LAN {
			free = 1604
		}
		routes = append(routes, route{"ct mark & 0x00010000 != 0 ct mark & 0x00008000 != 0", 1604}, route{"ct mark & 0x00010000 != 0 ct mark & 0x00008000 == 0", free})
	}
	for index := len(routes) - 1; index >= 0; index-- {
		for _, transport := range []string{"udp", "tcp"} {
			lines = append(lines, fmt.Sprintf("insert rule %s proxy %s meta mark & 0x00100000 == 0x00100000 meta l4proto %s tproxy ip to 127.0.0.1:%d counter accept",
				table, routes[index].marks, transport, routes[index].port))
		}
	}
	// the block of the whole LAN: the device's side of a connection from outside whose entry was
	// ended, after the rule of the SYN
	if mode == BitTorrentBlock && detector.LAN {
		for index, line := range lines {
			if strings.Contains(line, "bt_tcp @ih,0,96 0x13426974546f7272656e7420") {
				lines = append(lines[:index], append([]string{rule("bt_tcp", "ip saddr . tcp sport @bt_sockets ct state new counter goto bt_block")}, lines[index:]...)...)
				break
			}
		}
	}
	// the programs of the router that run as one of RouterUsers: bt_router, the jumps to it after
	// the second rule of mangle_output, and proxy's rule of what it marked
	if users := detector.RouterUsers; len(users) > 0 {
		for index, line := range lines {
			if strings.Contains(line, "add chain "+table+" bt_detect") {
				lines = append(lines[:index], append([]string{"add chain " + table + " bt_router"}, lines[index:]...)...)
				break
			}
		}
		for index, user := range users {
			lines = append(lines, fmt.Sprintf("add rule %s mangle_output index %d meta nfproto ipv4 meta skuid %d jump bt_router", table, index+1, user))
		}
		if mode != BitTorrentBlock {
			lines = append(lines, fmt.Sprintf("add rule %s mangle_output index %d meta nfproto ipv4 ct direction original ct mark & 0x00010000 != 0 jump bt_router", table, len(users)+1))
		}
		lines = append(lines, rule("bt_router", "fib daddr type local accept"))
		switch mode {
		case BitTorrentBlock:
			lines = append(lines, rule("bt_router", "meta l4proto udp counter drop"), rule("bt_router", "counter drop"))
		case BitTorrentSection:
			lines = append(lines,
				rule("bt_router", "ct direction reply ct mark set ct mark | 0x00050000 accept"),
				rule("bt_router", "ct mark set ct mark | 0x00018000"),
				rule("bt_router", "meta l4proto tcp meta mark set 0x00400000 counter accept"),
				rule("bt_router", "meta l4proto udp meta mark set 0x00400000 counter accept"))
		default:
			lines = append(lines, rule("bt_router", "ct direction reply ct mark set ct mark | 0x00050000 accept"),
				rule("bt_router", "ct mark set ct mark | 0x00010000"), rule("bt_router", "ip daddr != 198.18.0.0/15 counter accept"))
		}
		if mode != BitTorrentBlock {
			for _, transport := range []string{"udp", "tcp"} {
				lines = append(lines, fmt.Sprintf("insert rule %s proxy ct mark & 0x00010000 != 0 meta mark & 0x00400000 == 0x00400000 meta l4proto %s tproxy ip to 127.0.0.1:1604 counter accept", table, transport))
			}
		}
	}
	// the suspicion by the fan-out of connection openings: its sets and its rules, each at its place
	// among those of its chain
	// (the condition and the times written out here: the code's own must not be what is tested by)
	if fan := detector.Fan; fan.Burst > 0 && detector.LAN && (mode == BitTorrentBlock || mode == BitTorrentSection) {
		before := func(anchor string, added ...string) {
			for index, line := range lines {
				if strings.Contains(line, anchor) {
					lines = append(lines[:index], append(append([]string{}, added...), lines[index:]...)...)
					return
				}
			}
			t.Fatalf("no line with %q", anchor)
		}
		free := "tcp dport >= 1024 tcp dport != " + ports + " "
		limit := fmt.Sprintf("limit rate over %d/%s burst %d packets", fan.Rate, map[uint64]string{1: "second", 60: "minute"}[fan.Unit], fan.Burst)
		before("add chain "+table+" bt_detect",
			"add set "+table+" bt_suspects { type ipv4_addr; size 1024; flags dynamic,timeout; timeout "+fan.Suspect.String()+"; }",
			"add set "+table+" bt_fan_pairs { type ipv4_addr . ipv4_addr; size 16384; flags dynamic,timeout; timeout "+fan.Pair.String()+"; }",
			"add set "+table+" bt_fan { type ipv4_addr; size 1024; flags dynamic,timeout; timeout "+(2*time.Duration(uint64(fan.Burst)*fan.Unit/fan.Rate+1)*time.Second).String()+"; }",
			"add set "+table+" bt_ended { type ipv4_addr; size 1024; flags dynamic,timeout; timeout 5m; }")
		before("bt_tcp @ih,0,8 0x0-0xff", rule("bt_tcp", "ip saddr @bt_ended "+free+"ct state new counter reject with tcp reset"))
		before("bt_handshake update @bt_hosts",
			rule("bt_syn", "ip saddr @bt_suspects "+free+"ct mark set ct mark | 0x000a0000 counter return"),
			rule("bt_syn", free+"ip saddr . ip daddr @bt_fan_pairs update @bt_fan_pairs { ip saddr . ip daddr } return"),
			rule("bt_syn", free+"add @bt_fan_pairs { ip saddr . ip daddr } update @bt_fan { ip saddr "+limit+" } update @bt_suspects { ip saddr } ct mark set ct mark | 0x000a0000 counter return"))
		before("bt_act ct mark & 0x00008000 == 0 ct mark set", rule("bt_act", "ct mark & 0x000a0000 == 0x000a0000 ct mark set ct mark & 0xfff5ffff counter"))
		lines = append(lines, "insert rule "+table+" proxy ct mark & 0x000a0000 == 0x000a0000 ct mark & 0x00008000 == 0 meta mark & 0x00100000 == 0x00100000 meta l4proto tcp tproxy ip to 127.0.0.1:1607 counter accept")
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
		"bypass":           {Mode: BitTorrentBypass},
		"block":            {Mode: BitTorrentBlock, Sources: prefixes("192.168.1.60/32", "192.168.1.64/30")},
		"block, the LAN":   {Mode: BitTorrentBlock, LAN: true},
		"section":          {Mode: BitTorrentSection},
		"section, the LAN": {Mode: BitTorrentSection, LAN: true},
		// the suspicion by fan-out, on in the scope of the whole LAN alone: outside it the setting
		// changes nothing of the table
		"block, the LAN, hidden clients":   {Mode: BitTorrentBlock, LAN: true, Fan: dataplane.DefaultFan},
		"section, the LAN, hidden clients": {Mode: BitTorrentSection, LAN: true, Fan: dataplane.DefaultFan},
		"block, hidden clients asked":      {Mode: BitTorrentBlock, Fan: dataplane.DefaultFan},
		// a client on the router itself, by its user
		"bypass, a user of the router":            {Mode: BitTorrentBypass, RouterUsers: []uint32{4321}},
		"block, users of the router":              {Mode: BitTorrentBlock, RouterUsers: []uint32{4321, 4322}},
		"section, the LAN, hidden, a router user": {Mode: BitTorrentSection, LAN: true, Fan: dataplane.DefaultFan, RouterUsers: []uint32{4321}},
		"bypass, hidden clients asked":            {Mode: BitTorrentBypass, Fan: dataplane.DefaultFan},
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

// KnowBitTorrentHost puts a device in bt_hosts for the whole timeout from now: one that is not
// there is added; one that is there with little time left has the whole timeout again (an element
// added again keeps its timer: it is taken out and put back, in one transaction); a table without
// the set is an error. And EndUndecidedFlows's set of the devices whose connections were ended.
func TestKnowBitTorrentHost(t *testing.T) {
	needNft(t)
	_ = Remove()
	t.Cleanup(func() { _ = Remove() })
	device := netip.MustParseAddr("192.168.1.60")
	if err := KnowBitTorrentHost(device); err == nil {
		t.Error("no table: no error")
	}
	if err := Apply(&Plan{Interfaces: []string{"br-lan"}, BitTorrent: BitTorrent{Mode: BitTorrentBlock, LAN: true, Fan: dataplane.DefaultFan}}); err != nil {
		t.Fatal(err)
	}
	left := func(set string) time.Duration {
		listing := nft(t, "list", "set", "inet", tableName, set)
		match := regexp.MustCompile(`192\.168\.1\.60 (?:timeout \S+ )?expires (\S+?)[ ,}]`).FindStringSubmatch(listing)
		if match == nil {
			return -1
		}
		expires, err := time.ParseDuration(match[1])
		if err != nil {
			t.Fatalf("the time left %q: %v", match[1], err)
		}
		return expires
	}
	if got := left("bt_hosts"); got != -1 {
		t.Fatalf("in the set before it was put there: %v", got)
	}
	// not there: added
	if err := KnowBitTorrentHost(device); err != nil {
		t.Fatal(err)
	}
	if got := left("bt_hosts"); got < bitTorrentTimeout-time.Minute {
		t.Errorf("added: %v left of %v", got, bitTorrentTimeout)
	}
	// there with 10 s left: the whole timeout again
	nft(t, "delete element inet "+tableName+" bt_hosts { 192.168.1.60 }")
	nft(t, "add element inet "+tableName+" bt_hosts { 192.168.1.60 timeout 10s }")
	if got := left("bt_hosts"); got < 0 || got > 10*time.Second {
		t.Fatalf("the element of 10 s: %v left", got)
	}
	if err := KnowBitTorrentHost(device); err != nil {
		t.Fatal(err)
	}
	if got := left("bt_hosts"); got < bitTorrentTimeout-time.Minute {
		t.Errorf("kept known: %v left of %v", got, bitTorrentTimeout)
	}
	// the devices whose connections were ended: there for bitTorrentEndedFor
	if _, err := EndUndecidedFlows(device); err != nil {
		t.Fatal(err)
	}
	if got := left("bt_ended"); got < bitTorrentEndedFor-time.Minute || got > bitTorrentEndedFor {
		t.Errorf("bt_ended: %v left of %v", got, bitTorrentEndedFor)
	}
}

// A change of the mode is one of the rules: the table is made anew.
func TestBitTorrentModeIsStructure(t *testing.T) {
	off := &Plan{Interfaces: []string{"br-lan"}}
	bypass := &Plan{Interfaces: []string{"br-lan"}, BitTorrent: BitTorrent{Mode: BitTorrentBypass}}
	block := &Plan{Interfaces: []string{"br-lan"}, BitTorrent: BitTorrent{Mode: BitTorrentBlock}}
	lan := &Plan{Interfaces: []string{"br-lan"}, BitTorrent: BitTorrent{Mode: BitTorrentBlock, LAN: true}}
	sectionLAN := &Plan{Interfaces: []string{"br-lan"}, BitTorrent: BitTorrent{Mode: BitTorrentSection, LAN: true}}
	structures := map[string]bool{}
	for _, plan := range []*Plan{off, bypass, block, lan, sectionLAN} {
		structures[plan.structure()] = true
	}
	if len(structures) != 5 {
		t.Errorf("modes share a structure: %d of 5", len(structures))
	}
}

// What a change of the mode ends: leaving bypass the connections podkop takes, which bypass let
// past it; the block of the whole LAN every connection of BitTorrent. Nothing from a detector made
// anew (its sets are empty, the marks of the entries tell them), nor between the modes that take
// them as they were.
func TestForgetFor(t *testing.T) {
	off, bypass, block, section := BitTorrent{}, BitTorrent{Mode: BitTorrentBypass}, BitTorrent{Mode: BitTorrentBlock}, BitTorrent{Mode: BitTorrentSection}
	lan := BitTorrent{Mode: BitTorrentBlock, LAN: true}
	sectionLAN := BitTorrent{Mode: BitTorrentSection, LAN: true}
	for _, c := range []struct {
		previous, next BitTorrent
		forget         Forget
	}{
		{bypass, block, ForgetIntercepted},
		{bypass, section, ForgetIntercepted},
		{bypass, off, ForgetIntercepted},
		{bypass, lan, ForgetAll},
		{bypass, bypass, ForgetNone},
		{block, lan, ForgetAll},
		{section, lan, ForgetAll},
		{lan, lan, ForgetNone},
		{lan, block, ForgetNone},
		{lan, bypass, ForgetNone},
		{block, section, ForgetNone},
		{section, bypass, ForgetNone},
		{off, lan, ForgetNone},
		{off, block, ForgetNone},
		// the section of the whole LAN takes what went past podkop
		{bypass, sectionLAN, ForgetAll},
		{section, sectionLAN, ForgetAll},
		{lan, sectionLAN, ForgetAll},
		{sectionLAN, lan, ForgetAll},
		{sectionLAN, sectionLAN, ForgetNone},
		{sectionLAN, section, ForgetNone},
		{sectionLAN, bypass, ForgetNone},
	} {
		if got := ForgetFor(c.previous, c.next); got != c.forget {
			t.Errorf("from %+v to %+v: %v, not %v", c.previous, c.next, got, c.forget)
		}
	}
}

// What the detector learned is in the table a change of its mode makes anew, each element with
// the time it had left.
func TestBitTorrentKept(t *testing.T) {
	needNft(t)
	_ = Remove()
	t.Cleanup(func() { _ = Remove() })
	plan := func(mode string) *Plan {
		return &Plan{Interfaces: []string{"br-lan"}, Sources: prefixes("192.168.1.60/32"), BitTorrent: BitTorrent{Mode: mode}}
	}
	bypass, block := plan(BitTorrentBypass), plan(BitTorrentBlock)
	if err := Apply(bypass); err != nil {
		t.Fatal(err)
	}
	learned := map[string]string{"bt_hosts": "192.168.1.60", "bt_sockets": "192.168.1.60 . 6881", "bt_peers": "203.0.113.7 . 51413",
		"bt_utp": "192.168.1.60 . 6881", "bt_learned": "192.168.1.60 . 203.0.113.8 . 51413", "bt_trackers": "192.168.1.60 . 203.0.113.9 . 6969"}
	for set, element := range learned {
		nft(t, "add element inet "+tableName+" "+set+" { "+element+" timeout 10m }")
	}
	if err := Update(bypass, block); err != nil {
		t.Fatal(err)
	}
	for set, element := range learned {
		listed := nft(t, "list", "set", "inet", tableName, set)
		if !strings.Contains(listed, element+" timeout") {
			t.Errorf("%s of the new table has not %s:\n%s", set, element, listed)
		}
	}
	if listed := nft(t, "list", "chain", "inet", tableName, "bt_act"); !strings.Contains(listed, "goto bt_block") {
		t.Errorf("the new table is not of the mode block:\n%s", listed)
	}
}

// A stop saves what the sets hold (Remove), and the next start takes it back (Apply with no table),
// each element with the time it had left less the time between; a file older than an element's
// time has nothing of it.
func TestBitTorrentSaved(t *testing.T) {
	needNft(t)
	saved := bitTorrentSaved
	bitTorrentSaved = filepath.Join(t.TempDir(), "sets.json")
	t.Cleanup(func() { _ = Remove(); bitTorrentSaved = saved })
	_ = Remove()
	plan := &Plan{Interfaces: []string{"br-lan"}, Sources: prefixes("192.168.1.60/32"), BitTorrent: BitTorrent{Mode: BitTorrentBypass}}
	if err := Apply(plan); err != nil {
		t.Fatal(err)
	}
	nft(t, "add element inet "+tableName+" bt_hosts { 192.168.1.60 timeout 10m }")
	nft(t, "add element inet "+tableName+" bt_learned { 192.168.1.60 . 203.0.113.8 . 51413 timeout 20s }")
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	// the second removal of a stop (`podkop release`): no table, the file stays
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	if err := Apply(plan); err != nil {
		t.Fatal(err)
	}
	if listed := nft(t, "list", "set", "inet", tableName, "bt_hosts"); !strings.Contains(listed, "192.168.1.60 timeout") {
		t.Errorf("the device is not back after a restart:\n%s", listed)
	}
	if _, err := os.Stat(bitTorrentSaved); !os.IsNotExist(err) {
		t.Error("the file stays after the start took it")
	}
	// an element whose time ran out meanwhile is left out
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	kept := loadBitTorrentSets(time.Now().Add(time.Minute))
	if len(kept["bt_learned"]) != 0 || len(kept["bt_hosts"]) != 1 {
		t.Errorf("after a minute: %v", kept)
	}
}

// The receive buffer the transaction of the whole table needs (netlinkReadBuffer): found for each
// mode by halving, logged, and at most a quarter of what the firewall asks for. The kernel gives
// twice what is asked, and a socket's default is 212992 bytes given.
func TestReadBufferNeeded(t *testing.T) {
	needNft(t)
	asked := netlinkReadBuffer
	t.Cleanup(func() { netlinkReadBuffer = asked; _ = Remove() })
	for _, mode := range []string{"", BitTorrentBypass, BitTorrentBlock, BitTorrentSection} {
		plan := &Plan{Interfaces: []string{"br-lan"}, Sources: prefixes("192.168.1.60/32"), BitTorrent: BitTorrent{Mode: mode, LAN: mode != BitTorrentBypass}}
		low, high := 2<<10, asked
		for high-low > 2<<10 {
			middle := (low + high) / 2
			netlinkReadBuffer = asked
			_ = Remove()
			netlinkReadBuffer = middle
			if err := Apply(plan); err != nil {
				low = middle
			} else {
				high = middle
			}
		}
		netlinkReadBuffer = asked
		rules := strings.Count(nft(t, "list", "table", "inet", tableName), "\n")
		t.Logf("mode %q: the table (%d lines listed) needs a receive buffer of about %d bytes given (%d asked)", mode, rules, 2*high, high)
		if high > asked/4 {
			t.Errorf("mode %q: the table needs %d bytes asked, more than a quarter of the %d the firewall asks for", mode, high, asked)
		}
	}
}

// What is kept of the sets for a new table: the sets of the detector only, keys of their length, a
// time left within the set's timeout, and of a set with more than its most, those with the most
// time left.
func TestKeepBitTorrent(t *testing.T) {
	key := func(length int, last byte) []byte {
		data := make([]byte, length)
		data[length-1] = last
		return data
	}
	read := map[string][]nftables.SetElement{
		SetBitTorrentHosts: {{Key: key(4, 1), Timeout: 10 * time.Minute}, {Key: key(8, 2), Timeout: 10 * time.Minute}, {Key: key(4, 3), Timeout: 500 * time.Millisecond},
			{Key: key(4, 4), Timeout: 3 * time.Hour}},
		SetBitTorrentTrackers: {{Key: key(12, 1), Timeout: 100 * time.Minute}, {Key: key(12, 2), Timeout: 5 * time.Hour}, {Key: key(8, 3), Timeout: time.Minute}},
		"another_set":         {{Key: key(4, 1), Timeout: time.Minute}},
	}
	for index := range bitTorrentKeptMost[SetBitTorrentPeers] + 500 {
		element := nftables.SetElement{Key: []byte{198, 51, 100, 7, byte(index >> 8), byte(index), 0, 0}, Timeout: time.Duration(index+1) * 100 * time.Millisecond}
		read[SetBitTorrentPeers] = append(read[SetBitTorrentPeers], element)
	}
	kept := keepBitTorrent(read)
	hosts := kept[SetBitTorrentHosts]
	if len(hosts) != 2 || hosts[0].Timeout != 10*time.Minute || hosts[1].Timeout != bitTorrentTimeout {
		t.Errorf("the devices kept: %v", hosts)
	}
	trackers := kept[SetBitTorrentTrackers]
	if len(trackers) != 2 || trackers[0].Timeout != 100*time.Minute || trackers[1].Timeout != trackerTimeout {
		t.Errorf("the trackers kept: %v", trackers)
	}
	if _, has := kept["another_set"]; has {
		t.Error("a set that is not the detector's was kept")
	}
	peers := kept[SetBitTorrentPeers]
	shortest := peers[0].Timeout
	for _, peer := range peers {
		shortest = min(shortest, peer.Timeout)
	}
	// the 9 first have under a second left; of the rest, the 4000 with the most time
	if len(peers) != bitTorrentKeptMost[SetBitTorrentPeers] || shortest != 501*100*time.Millisecond {
		t.Errorf("%d peers kept, the shortest time left %v", len(peers), shortest)
	}
	total := 0
	for _, most := range bitTorrentKeptMost {
		total += most
	}
	if total > fillLot {
		t.Errorf("the sets may keep %d elements in all, more than a transaction's %d", total, fillLot)
	}
}

// More elements than one netlink message takes go into the new table whole: bt_peers holds up to
// 65535, and the attribute of the elements of one message about two thousand.
func TestBitTorrentKeptMany(t *testing.T) {
	needNft(t)
	_ = Remove()
	t.Cleanup(func() { _ = Remove() })
	plan := func(mode string) *Plan {
		return &Plan{Interfaces: []string{"br-lan"}, Sources: prefixes("192.168.1.60/32"), BitTorrent: BitTorrent{Mode: mode}}
	}
	bypass, block := plan(BitTorrentBypass), plan(BitTorrentBlock)
	if err := Apply(bypass); err != nil {
		t.Fatal(err)
	}
	const many = 3000
	var elements []string
	for port := 1; port <= many; port++ {
		elements = append(elements, fmt.Sprintf("198.51.100.7 . %d timeout 10m", port))
	}
	nft(t, "add element inet "+tableName+" bt_peers { "+strings.Join(elements, ", ")+" }")
	if err := Update(bypass, block); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(nft(t, "list", "set", "inet", tableName, "bt_peers"), "198.51.100.7 . "); got != many {
		t.Errorf("bt_peers of the new table has %d of the %d elements", got, many)
	}
}
