package firewall

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/nftables"
	"github.com/stretchr/testify/require"

	"go4.org/netipx"
)

// The tests need the right to change the firewall of their network namespace and the nft
// program to compare with: they run as root in a container with the right to administer
// the network, and are skipped elsewhere.
func needNft(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("not root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("no nft program")
	}
}

func nft(t *testing.T, arguments ...string) string {
	output, err := exec.Command("nft", arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("nft %s: %v: %s", strings.Join(arguments, " "), err, output)
	}
	return string(output)
}

// shellBackendTable makes the table with the commands the shell backend of podkop 0.7.24
// runs, one nft a line and in its order: create_nft_rules, then
// nft_list_all_traffic_from_ip for every device, then what the list update adds for the
// Discord list, then the elements. Three differences are the backend's own: what the router
// sends has a mark of its own (dataplane.RouterMark), and proxy has rules for it; the NTP
// of the router goes past the proxy; the replies of a connection that did not begin on the LAN
// return first, before the rules of the devices routed whole (the shell backend's return of
// DNAT, below them, let a port forward to such a device break).
func shellBackendTable(t *testing.T, plan *Plan) {
	table := "inet " + tableName
	lines := []string{
		"add table " + table,
		"add set " + table + " localv4 { type ipv4_addr; flags interval; auto-merge; }",
		"add element " + table + " localv4 { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0-255.255.255.255 }",
		"add set " + table + " podkop_subnets { type ipv4_addr; flags interval; auto-merge; }",
		"add set " + table + " interfaces { type ifname; flags interval; }",
	}
	for _, name := range plan.Interfaces {
		lines = append(lines, "add element "+table+" interfaces { "+name+" }")
	}
	lines = append(lines,
		"add chain "+table+" mangle { type filter hook prerouting priority -150; policy accept; }",
		"add chain "+table+" mangle_output { type route hook output priority -150; policy accept; }",
		"add chain "+table+" proxy { type filter hook prerouting priority -100; policy accept; }",
		"add rule "+table+" mangle ct status dnat return",
		"add rule "+table+" mangle iifname @interfaces ip daddr @podkop_subnets meta l4proto tcp meta mark set 0x00100000 counter",
		"add rule "+table+" mangle iifname @interfaces ip daddr @podkop_subnets meta l4proto udp meta mark set 0x00100000 counter",
		"add rule "+table+" mangle iifname @interfaces ip daddr 198.18.0.0/15 meta l4proto tcp meta mark set 0x00100000 counter",
		"add rule "+table+" mangle iifname @interfaces ip daddr 198.18.0.0/15 meta l4proto udp meta mark set 0x00100000 counter",
		"add rule "+table+" proxy meta mark & 0x00100000 == 0x00100000 meta l4proto tcp tproxy ip to 127.0.0.1:1602 counter",
		"add rule "+table+" proxy meta mark & 0x00100000 == 0x00100000 meta l4proto udp tproxy ip to 127.0.0.1:1602 counter",
		"add rule "+table+" proxy meta mark & 0x00400000 == 0x00400000 meta l4proto tcp tproxy ip to 127.0.0.1:1602 counter",
		"add rule "+table+" proxy meta mark & 0x00400000 == 0x00400000 meta l4proto udp tproxy ip to 127.0.0.1:1602 counter",
		"add rule "+table+" mangle_output ip daddr @localv4 return",
		"add rule "+table+" mangle_output meta mark & 0x00200000 == 0x00200000 counter return",
		"add rule "+table+" mangle_output ip daddr != 198.18.0.0/15 udp dport 123 return",
		"add rule "+table+" mangle_output ip daddr @podkop_subnets meta l4proto tcp meta mark set 0x00400000 counter",
		"add rule "+table+" mangle_output ip daddr @podkop_subnets meta l4proto udp meta mark set 0x00400000 counter",
		"add rule "+table+" mangle_output ip daddr 198.18.0.0/15 meta l4proto tcp meta mark set 0x00400000 counter",
		"add rule "+table+" mangle_output ip daddr 198.18.0.0/15 meta l4proto udp meta mark set 0x00400000 counter",
	)
	// IPv6 (Plan.IPv6, the backend's own): its sets, and its rules after those of IPv4 in each
	// chain
	if plan.IPv6 {
		lines = append(lines,
			"add set "+table+" localv6 { type ipv6_addr; flags interval; auto-merge; }",
			"add element "+table+" localv6 { ::/127, ::ffff:0:0/96, 64:ff9b::/96, 64:ff9b:1::/48, 100::/64, 2001:db8::/32, fc00::/7, fe80::/10, ff00::/8 }",
			"add set "+table+" podkop_subnets_v6 { type ipv6_addr; flags interval; auto-merge; }",
			"add rule "+table+" mangle iifname @interfaces ip6 daddr @podkop_subnets_v6 meta l4proto tcp meta mark set 0x00100000 counter",
			"add rule "+table+" mangle iifname @interfaces ip6 daddr @podkop_subnets_v6 meta l4proto udp meta mark set 0x00100000 counter",
			"add rule "+table+" proxy meta mark & 0x00100000 == 0x00100000 meta l4proto tcp tproxy ip6 to [::1]:1602 counter",
			"add rule "+table+" proxy meta mark & 0x00100000 == 0x00100000 meta l4proto udp tproxy ip6 to [::1]:1602 counter",
			"add rule "+table+" proxy meta mark & 0x00400000 == 0x00400000 meta l4proto tcp tproxy ip6 to [::1]:1602 counter",
			"add rule "+table+" proxy meta mark & 0x00400000 == 0x00400000 meta l4proto udp tproxy ip6 to [::1]:1602 counter",
			"add rule "+table+" mangle_output ip6 daddr @localv6 return",
			"add rule "+table+" mangle_output meta nfproto ipv6 udp dport 123 return",
			"add rule "+table+" mangle_output ip6 daddr @podkop_subnets_v6 meta l4proto tcp meta mark set 0x00400000 counter",
			"add rule "+table+" mangle_output ip6 daddr @podkop_subnets_v6 meta l4proto udp meta mark set 0x00400000 counter",
		)
	}
	if plan.ExcludeNTP {
		lines = append(lines, "insert rule "+table+" mangle udp dport 123 return")
	}
	for _, source := range plan.Sources {
		address := source.String()
		if source.Bits() == 32 {
			address = source.Addr().String()
		}
		lines = append(lines,
			"insert rule "+table+" mangle iifname @interfaces ip saddr "+address+" meta l4proto tcp meta mark set 0x00100000 counter",
			"insert rule "+table+" mangle iifname @interfaces ip saddr "+address+" meta l4proto udp meta mark set 0x00100000 counter",
			"insert rule "+table+" mangle ip saddr "+address+" ip daddr @localv4 return",
		)
	}
	// the backend's own: the replies of what did not begin on the LAN first, above every device
	lines = append(lines, "insert rule "+table+" mangle ct direction reply return")
	elements := func(set string, ranges []Range) {
		if len(ranges) == 0 {
			return
		}
		texts := RangeStrings(ranges)
		lines = append(lines, "add element "+table+" "+set+" { "+strings.Join(texts, ", ")+" }")
	}
	elements6 := func(set string, ranges []netipx.IPRange) {
		if len(ranges) == 0 {
			return
		}
		var texts []string
		for _, item := range ranges {
			if prefix, ok := item.Prefix(); ok {
				texts = append(texts, prefix.String())
			} else {
				texts = append(texts, item.From().String()+"-"+item.To().String())
			}
		}
		lines = append(lines, "add element "+table+" "+set+" { "+strings.Join(texts, ", ")+" }")
	}
	for _, group := range plan.Groups {
		var ports []string
		for _, item := range group.Ports {
			ports = append(ports, fmt.Sprintf("%d-%d", item.From, item.To))
		}
		lines = append(lines,
			"add set "+table+" "+group.Set+" { type ipv4_addr; flags interval; auto-merge; }",
			"add rule "+table+" mangle iifname @interfaces ip daddr @"+group.Set+" udp dport { "+strings.Join(ports, ", ")+" } meta mark set 0x00100000 counter",
		)
		elements(group.Set, group.Ranges)
		if plan.IPv6 {
			lines = append(lines,
				"add set "+table+" "+group.Set+"_v6 { type ipv6_addr; flags interval; auto-merge; }",
				"add rule "+table+" mangle iifname @interfaces ip6 daddr @"+group.Set+"_v6 udp dport { "+strings.Join(ports, ", ")+" } meta mark set 0x00100000 counter",
			)
			elements6(group.Set+"_v6", group.Ranges6)
		}
	}
	elements(SetSubnets, plan.Subnets)
	if plan.IPv6 {
		elements6(SetSubnets6, plan.Subnets6)
	}
	for _, line := range lines {
		nft(t, line)
	}
}

var handles = regexp.MustCompile(` # handle \d+`)

func dump(t *testing.T) string {
	return handles.ReplaceAllString(nft(t, "list", "table", "inet", tableName), "")
}

func ranges6(texts ...string) []netipx.IPRange {
	var result []netipx.IPRange
	for _, prefix := range prefixes(texts...) {
		result = append(result, netipx.RangeOfPrefix(prefix))
	}
	return result
}

func prefixes(texts ...string) []netip.Prefix {
	result := make([]netip.Prefix, len(texts))
	for index, text := range texts {
		result[index] = netip.MustParsePrefix(text)
	}
	return result
}

// The table made over netlink reads back, by the nft program, as the table the shell
// backend makes with that program.
func TestTableAsTheShellBackendMakesIt(t *testing.T) {
	needNft(t)
	discord := Group{Set: "podkop_discord_subnets", Protocol: 17, Ports: []PortRange{{19000, 20000}, {50000, 65535}},
		Ranges: RangesOf(prefixes("104.16.0.0/12", "138.128.136.0/21", "162.158.0.0/15", "66.22.192.0/18"))}
	discord6 := discord
	discord6.Ranges6 = Merge6(ranges6("2606:4700::/32", "2a06:98c0::/29"))
	for name, plan := range map[string]*Plan{
		"one interface":    {Interfaces: []string{"br-lan"}},
		"nothing":          {},
		"interfaces, NTP":  {Interfaces: []string{"br-lan", "eth1", "wlan0.20"}, ExcludeNTP: true},
		"subnets":          {Interfaces: []string{"br-lan"}, Subnets: RangesOf(prefixes("203.0.112.0/24", "198.51.99.7/32", "8.8.8.0/24", "8.8.9.0/24", "8.8.8.128/25", "9.0.0.0/8"))},
		"devices":          {Interfaces: []string{"br-lan"}, Sources: prefixes("192.168.1.60/32", "192.168.1.64/30", "192.168.1.70/32")},
		"devices, NTP":     {Interfaces: []string{"br-lan"}, ExcludeNTP: true, Sources: prefixes("192.168.1.60/32")},
		"a group of ports": {Interfaces: []string{"br-lan"}, Groups: []Group{discord}},
		"everything at once": {Interfaces: []string{"br-lan", "eth1"}, ExcludeNTP: true, Sources: prefixes("192.168.1.60/32", "10.7.0.0/24"),
			Subnets: RangesOf(prefixes("149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22")), Groups: []Group{discord}},
		"IPv6, no subnets": {Interfaces: []string{"br-lan"}, IPv6: true},
		"IPv6": {Interfaces: []string{"br-lan"}, IPv6: true, Subnets: RangesOf(prefixes("149.154.160.0/20")),
			Subnets6: Merge6(ranges6("2001:67c:4e8::/48", "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2a0a:f280::/32"))},
		"IPv6, everything at once": {Interfaces: []string{"br-lan", "eth1"}, ExcludeNTP: true, Sources: prefixes("192.168.1.60/32"), IPv6: true,
			Subnets: RangesOf(prefixes("149.154.160.0/20")), Subnets6: Merge6(ranges6("2001:67c:4e8::/48", "2a0a:f280::/32")),
			Groups: []Group{discord6}},
	} {
		_ = Remove()
		shellBackendTable(t, plan)
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
		// a second run replaces the table: nothing is doubled
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
	if output, err := exec.Command("nft", "list", "table", "inet", tableName).CombinedOutput(); err == nil {
		t.Errorf("the table is still there after Remove: %s", output)
	}
}

// The chain that keeps the Clash API of YACD to its devices reads back, by the nft program, as
// the same chain made with that program; a plan without devices has none.
func TestClashAPIGuard(t *testing.T) {
	needNft(t)
	plan := &Plan{Interfaces: []string{"br-lan"}, ClashAPIInterfaces: []string{"br-lan", "eth1"}}
	_ = Remove()
	shellBackendTable(t, plan)
	table := "inet " + tableName
	nft(t, "add chain "+table+" clash_api { type filter hook input priority filter - 1; policy accept; }")
	for _, name := range []string{"lo", "br-lan", "eth1"} {
		nft(t, "add rule "+table+" clash_api meta l4proto tcp th dport 9090 iifname \""+name+"\" return")
	}
	nft(t, "add rule "+table+" clash_api meta l4proto tcp th dport 9090 counter drop")
	want := dump(t)
	require.NoError(t, Remove())
	require.NoError(t, Apply(plan))
	got := dump(t)
	require.Equal(t, want, got)
	require.Contains(t, got, "hook input priority filter - 1")

	// the devices of YACD are rules: a change of them replaces the table, and without them
	// there is no chain
	require.NoError(t, Update(plan, &Plan{Interfaces: []string{"br-lan"}}))
	require.NotContains(t, dump(t), "clash_api")
	require.NoError(t, Remove())
}

// A plan that differs only in what a set holds refills that set and leaves the rules in
// place, their handles and counters with them; a plan with other rules replaces the table.
func TestUpdate(t *testing.T) {
	needNft(t)
	_ = Remove()
	first := &Plan{Interfaces: []string{"br-lan"}, Subnets: RangesOf(prefixes("8.8.8.0/24")),
		Groups: []Group{{Set: "voice", Protocol: 17, Ports: []PortRange{{50000, 65535}}, Ranges: RangesOf(prefixes("66.22.192.0/18"))}}}
	if err := Update(nil, first); err != nil {
		t.Fatal(err)
	}
	rules := func() string { return nft(t, "-a", "list", "chain", "inet", tableName, "mangle") }
	before := rules()
	second := &Plan{Interfaces: []string{"br-lan"}, Subnets: RangesOf(prefixes("8.8.8.0/24", "1.1.1.0/24")),
		Groups: []Group{{Set: "voice", Protocol: 17, Ports: []PortRange{{50000, 65535}}, Ranges: RangesOf(prefixes("66.22.192.0/18", "5.5.0.0/16"))}}}
	if err := Update(first, second); err != nil {
		t.Fatal(err)
	}
	if rules() != before {
		t.Error("the rules were made anew for a change of the sets only")
	}
	for set, want := range map[string]string{SetSubnets: "1.1.1.0/24", "voice": "5.5.0.0/16"} {
		if !strings.Contains(nft(t, "list", "set", "inet", tableName, set), want) {
			t.Errorf("the set %s was not refilled", set)
		}
	}
	// the same plan again: nothing to do, nothing done
	if err := Update(second, second); err != nil {
		t.Fatal(err)
	}
	if rules() != before {
		t.Error("the rules changed with nothing to change")
	}
	third := &Plan{Interfaces: []string{"br-lan"}, ExcludeNTP: true, Subnets: second.Subnets, Groups: second.Groups}
	if err := Update(second, third); err != nil {
		t.Fatal(err)
	}
	if after := rules(); after == before || !strings.Contains(after, "udp dport 123") {
		t.Error("the table was not replaced for a change of the rules")
	}
	// IPv6: turning it on replaces the table; a change of its sets refills them, the rules
	// staying
	fourth := &Plan{Interfaces: []string{"br-lan"}, IPv6: true, Subnets: second.Subnets, Subnets6: Merge6(ranges6("2001:67c:4e8::/48")),
		Groups: []Group{{Set: "voice", Protocol: 17, Ports: []PortRange{{50000, 65535}}, Ranges: second.Groups[0].Ranges, Ranges6: Merge6(ranges6("2606:4700::/32"))}}}
	if err := Update(third, fourth); err != nil {
		t.Fatal(err)
	}
	before = rules()
	if !strings.Contains(before, "ip6 daddr @podkop_subnets_v6") || !strings.Contains(before, "ip6 daddr @voice_v6") {
		t.Fatalf("no rules of IPv6:\n%s", before)
	}
	fifth := &Plan{Interfaces: []string{"br-lan"}, IPv6: true, Subnets: second.Subnets, Subnets6: Merge6(ranges6("2001:67c:4e8::/48", "2001:b28:f23d::/48")),
		Groups: []Group{{Set: "voice", Protocol: 17, Ports: []PortRange{{50000, 65535}}, Ranges: second.Groups[0].Ranges, Ranges6: Merge6(ranges6("2a06:98c0::/29"))}}}
	if err := Update(fourth, fifth); err != nil {
		t.Fatal(err)
	}
	if rules() != before {
		t.Error("the rules were made anew for a change of the sets of IPv6 only")
	}
	for set, want := range map[string]string{SetSubnets6: "2001:b28:f23d::/48", "voice_v6": "2a06:98c0::/29"} {
		if text := nft(t, "list", "set", "inet", tableName, set); !strings.Contains(text, want) {
			t.Errorf("the set %s was not refilled: %s", set, text)
		}
	}
	if text := nft(t, "list", "set", "inet", tableName, "voice_v6"); strings.Contains(text, "2606:4700") {
		t.Errorf("the set voice_v6 keeps what went: %s", text)
	}
	// and off again: nothing of IPv6
	if err := Update(fifth, third); err != nil {
		t.Fatal(err)
	}
	if after := nft(t, "list", "table", "inet", tableName); strings.Contains(after, "ip6") || strings.Contains(after, "_v6") {
		t.Errorf("IPv6 off left its rules or sets:\n%s", after)
	}
	_ = Remove()
}

// subnets makes count prefixes in no order: mostly /24, with single addresses, wider
// prefixes, neighbours that merge and repeats, as a downloaded list has them.
func subnets(count int) []netip.Prefix {
	result := make([]netip.Prefix, 0, count)
	state := uint32(2463534242)
	for len(result) < count {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		// public unicast only: 1.0.0.0 to 223.255.255.255
		first := byte(1 + state%223)
		address := netip.AddrFrom4([4]byte{first, byte(state >> 8), byte(state >> 16), byte(state >> 24)})
		bits := 24
		switch state % 10 {
		case 0:
			bits = 32
		case 1:
			bits = 22
		case 2:
			bits = 28
		}
		prefix := netip.PrefixFrom(address, bits).Masked()
		result = append(result, prefix)
		if state%7 == 0 && len(result) < count {
			// the next block of the same size: the two merge into one range
			next := netip.PrefixFrom(netipxNext(prefix), bits)
			if next.IsValid() {
				result = append(result, next)
			}
		}
	}
	return result
}

func netipxNext(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Addr().As4()
	value := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
	value += 1 << (32 - prefix.Bits())
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

func elementsOfSet(t *testing.T) int {
	conn, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	set, err := conn.GetSetByName(&nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}, SetSubnets)
	if err != nil {
		t.Fatal(err)
	}
	elements, err := conn.GetSetElements(set)
	if err != nil {
		t.Fatal(err)
	}
	return len(elements)
}

// run runs a program and returns how long it took and the most memory it held, in KiB.
func run(t *testing.T, name string, arguments ...string) (time.Duration, int64) {
	command := exec.Command(name, arguments...)
	started := time.Now()
	output, err := command.CombinedOutput()
	took := time.Since(started)
	if err != nil {
		text := string(output)
		if len(text) > 300 {
			text = text[:300]
		}
		t.Fatalf("%s: %v: %s", name, err, text)
	}
	return took, command.ProcessState.SysUsage().(*syscall.Rusage).Maxrss
}

// Filling the set of subnets three ways: over netlink, by one run of nft with a file, and
// by a run of nft for every five thousand items as the shell backend does (without its
// per-line work in the shell). The sets must come out the same.
func TestFillTheSubnetSet(t *testing.T) {
	needNft(t)
	directory := t.TempDir()
	for _, count := range []int{1000, 10000} {
		list := subnets(count)
		texts := make([]string, len(list))
		for index, prefix := range list {
			texts[index] = prefix.String()
			if prefix.Bits() == 32 {
				texts[index] = prefix.Addr().String()
			}
		}
		if err := Apply(&Plan{Interfaces: []string{"br-lan"}}); err != nil {
			t.Fatal(err)
		}

		// over netlink, one transaction
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		started := time.Now()
		ranges, err := ReplaceSet(SetSubnets, RangesOf(list), 0)
		whole := time.Since(started)
		runtime.ReadMemStats(&after)
		if err != nil {
			t.Fatalf("%d prefixes over netlink in one transaction: %v", count, err)
		}
		wantElements := elementsOfSet(t)
		dumpNetlink := nft(t, "list", "set", "inet", tableName, SetSubnets)

		// over netlink, a thousand ranges a transaction
		started = time.Now()
		_, err = ReplaceSet(SetSubnets, RangesOf(list), 1000)
		lots := time.Since(started)
		if err != nil {
			t.Fatalf("%d prefixes over netlink in lots: %v", count, err)
		}
		if got := elementsOfSet(t); got != wantElements {
			t.Errorf("%d prefixes: %d elements in lots, %d in one transaction", count, got, wantElements)
		}

		// one run of nft with a file
		file := directory + "/set.nft"
		content := "flush set inet " + tableName + " " + SetSubnets + "\nadd element inet " + tableName + " " + SetSubnets + " { " + strings.Join(texts, ", ") + " }\n"
		if err = os.WriteFile(file, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		fileTime, fileMemory := run(t, "nft", "-f", file)
		dumpFile := nft(t, "list", "set", "inet", tableName, SetSubnets)
		if dumpFile != dumpNetlink {
			t.Errorf("%d prefixes: the set filled by nft -f reads back differently from the one filled over netlink (%d and %d bytes)", count, len(dumpFile), len(dumpNetlink))
		}

		// a run of nft for every five thousand items
		nft(t, "flush", "set", "inet", tableName, SetSubnets)
		var chunkTime time.Duration
		var chunkMemory int64
		runs := 0
		for start := 0; start < len(texts); start += 5000 {
			end := min(start+5000, len(texts))
			took, memory := run(t, "nft", "add", "element", "inet", tableName, SetSubnets, "{ "+strings.Join(texts[start:end], ",")+" }")
			chunkTime += took
			chunkMemory = max(chunkMemory, memory)
			runs++
		}
		dumpChunks := nft(t, "list", "set", "inet", tableName, SetSubnets)
		if dumpChunks != dumpNetlink {
			t.Errorf("%d prefixes: the set filled in chunks reads back differently from the one filled over netlink (%d and %d bytes)", count, len(dumpChunks), len(dumpNetlink))
		}
		fmt.Printf("fill %6d prefixes -> %6d ranges | netlink, one transaction: %8.1f ms, %6d KiB allocated | netlink, lots of 1000: %8.1f ms | nft -f: %8.1f ms, peak %6d KiB | nft add element x%d: %8.1f ms, peak %6d KiB\n",
			count, ranges, float64(whole.Microseconds())/1000, (after.TotalAlloc-before.TotalAlloc)/1024, float64(lots.Microseconds())/1000,
			float64(fileTime.Microseconds())/1000, fileMemory, runs, float64(chunkTime.Microseconds())/1000, chunkMemory)
	}
	_ = Remove()
}

// rangesOfSet reads a set of the table back as ranges.
func rangesOfSet(t *testing.T, name string) []netipx.IPRange {
	conn, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	set, err := conn.GetSetByName(&nftables.Table{Name: tableName, Family: nftables.TableFamilyINet}, name)
	if err != nil {
		t.Fatal(err)
	}
	elements, err := conn.GetSetElements(set)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(elements, func(left int, right int) bool {
		return bytes.Compare(elements[left].Key, elements[right].Key) < 0
	})
	var result []netipx.IPRange
	for index := 0; index < len(elements); index++ {
		if elements[index].IntervalEnd {
			t.Fatalf("an end without a start in the set %s", name)
		}
		from, _ := netip.AddrFromSlice(elements[index].Key)
		to := netip.MustParseAddr("255.255.255.255")
		if index+1 < len(elements) && elements[index+1].IntervalEnd {
			end, _ := netip.AddrFromSlice(elements[index+1].Key)
			to = end.Prev()
			index++
		}
		result = append(result, netipx.IPRangeFrom(from, to))
	}
	return result
}

func wantRanges(t *testing.T, ranges []Range) []netipx.IPRange {
	var builder netipx.IPSetBuilder
	for _, item := range ranges {
		builder.AddRange(netipx.IPRangeFrom(address4(uint32(item>>32)), address4(uint32(item))))
	}
	set, err := builder.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	return set.Ranges()
}

// sameRanges takes no ranges as no ranges, nil or not.
// rangesOfRanges writes packed ranges as ranges of addresses, for a comparison.
func rangesOfRanges(ranges []Range) []netipx.IPRange {
	var result []netipx.IPRange
	for _, item := range ranges {
		var from, to [4]byte
		binary.BigEndian.PutUint32(from[:], uint32(item>>32))
		binary.BigEndian.PutUint32(to[:], uint32(item))
		result = append(result, netipx.IPRangeFrom(netip.AddrFrom4(from), netip.AddrFrom4(to)))
	}
	return result
}

func sameRanges(t *testing.T, want []netipx.IPRange, got []netipx.IPRange, message ...any) {
	if len(want) == 0 && len(got) == 0 {
		return
	}
	require.Equal(t, want, got, message...)
}

// Merge makes the ranges a set builder of netipx makes, without its memory: random
// lists, and the edges of the address space, neighbours, prefixes inside others, IPv6.
// What it makes is merged (IsMerged), and merged again it stays the same.
func TestMergeAsASetBuilder(t *testing.T) {
	for _, count := range []int{0, 1, 2, 10, 1000, 20000} {
		list := subnets(count)
		ranges := Merge(RangesOf(list))
		sameRanges(t, wantRanges(t, RangesOf(list)), rangesOfRanges(ranges), "%d prefixes", count)
		require.True(t, IsMerged(ranges))
		require.Equal(t, ranges, Merge(slices.Clone(ranges)))
	}
	for _, list := range [][]netip.Prefix{
		prefixes("0.0.0.0/0"),
		prefixes("255.255.255.255/32", "255.255.255.254/32"),
		prefixes("255.255.255.0/24", "0.0.0.0/8", "10.0.0.0/8", "10.1.0.0/16", "11.0.0.0/8"),
		prefixes("1.1.1.0/24", "1.1.2.0/24", "1.1.4.0/24", "1.1.1.128/25", "2001:db8::/32", "1.1.3.0/24"),
		prefixes("::ffff:1.2.3.4/128", "9.9.9.9/32", "9.9.9.9/32"),
	} {
		sameRanges(t, wantRanges(t, RangesOf(list)), rangesOfRanges(Merge(RangesOf(list))), "%v", list)
	}
	// what differs of two lists, by one walk, is what differs of the two sets
	before, after := Merge(RangesOf(prefixes("1.1.1.0/24", "2.2.2.0/24", "3.3.3.0/24"))), Merge(RangesOf(prefixes("1.1.1.0/24", "1.1.2.0/24", "3.3.4.0/24")))
	gone, came := rangesDiffer(before, after)
	require.Equal(t, Merge(RangesOf(prefixes("1.1.1.0/24", "2.2.2.0/24", "3.3.3.0/24")))[0:3], gone)
	require.Equal(t, Merge(RangesOf(prefixes("1.1.1.0/24", "1.1.2.0/24", "3.3.4.0/24"))), came)
}

// IsMerged takes only ranges in order with a gap between each two; a plan's merged ranges
// are those given when they are merged, and a merged copy of them otherwise, the plan's
// own left as they were.
func TestIsMerged(t *testing.T) {
	ranges := RangesOf(prefixes("1.1.1.0/24", "1.1.3.0/24", "255.255.255.255/32"))
	require.True(t, IsMerged(nil))
	require.True(t, IsMerged(ranges))
	for _, list := range [][]netip.Prefix{
		prefixes("1.1.3.0/24", "1.1.1.0/24"),
		prefixes("1.1.1.0/24", "1.1.2.0/24"),
		prefixes("1.1.0.0/16", "1.1.2.0/24"),
		prefixes("1.1.1.0/24", "1.1.1.0/24"),
		prefixes("255.255.255.255/32", "1.1.1.0/24"),
	} {
		require.False(t, IsMerged(RangesOf(list)), "%v", list)
	}
	require.False(t, IsMerged([]Range{2<<32 | 1}), "a range that ends before it starts")

	var plan merged
	require.Same(t, &ranges[0], &plan.of(ranges)[0], "merged ranges are taken as they are")
	unsorted := RangesOf(prefixes("1.1.3.0/24", "1.1.1.0/24", "1.1.2.0/24"))
	kept := slices.Clone(unsorted)
	var other merged
	require.Equal(t, []Range{0x01010100<<32 | 0x010103ff}, other.of(unsorted))
	require.Equal(t, kept, unsorted, "the ranges of the plan are not changed")
}

// A change of the lists reaches the set by what differs, and the set holds what a set
// filled anew would: ranges that went, came, grew into a neighbour, and a range that
// begins where one that went ended. A set the kernel does not have as the previous plan
// says is filled anew.
func TestUpdateByDifference(t *testing.T) {
	needNft(t)
	_ = Remove()
	defer Remove()
	base := subnets(3000)
	first := &Plan{Interfaces: []string{"br-lan"}, Subnets: RangesOf(append(prefixes("1.1.1.0/24", "2.2.2.0/24"), base...))}
	if err := Update(nil, first); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, wantRanges(t, first.Subnets), rangesOfSet(t, SetSubnets))
	// 1.1.1.0/24 grows into its neighbour: the start of the range stays, its end moves;
	// 2.2.2.0/24 goes and 2.2.3.0/24 comes, which begins where the one that went ended;
	// a part of the rest goes, and new ones come
	second := &Plan{Interfaces: []string{"br-lan"}, Subnets: RangesOf(append(prefixes("1.1.1.0/24", "1.1.2.0/24", "2.2.3.0/24"), append(base[500:], subnets(3500)[3000:]...)...))}
	if err := Update(first, second); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, wantRanges(t, second.Subnets), rangesOfSet(t, SetSubnets))
	// the kernel has another set than the previous plan says: filled anew
	if _, err := ReplaceSet(SetSubnets, RangesOf(prefixes("9.9.9.0/24")), 0); err != nil {
		t.Fatal(err)
	}
	if err := Update(first, second); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, wantRanges(t, second.Subnets), rangesOfSet(t, SetSubnets))
}

// A set of more ranges than fillLot is filled whole when the table is made, in lots.
func TestBigSetInLots(t *testing.T) {
	needNft(t)
	_ = Remove()
	defer Remove()
	var big []netip.Prefix
	for index := 0; index < fillLot*2+500; index++ {
		// /24 networks with a gap between each two: they do not merge
		big = append(big, netip.PrefixFrom(netip.AddrFrom4([4]byte{11 + byte(index/32768), byte(index / 128), byte(index%128) * 2, 0}), 24))
	}
	plan := &Plan{Interfaces: []string{"br-lan"}, Subnets: RangesOf(big)}
	if err := Apply(plan); err != nil {
		t.Fatal(err)
	}
	require.Len(t, rangesOfSet(t, SetSubnets), fillLot*2+500)
	require.Equal(t, wantRanges(t, RangesOf(big)), rangesOfSet(t, SetSubnets))
	// one item more is one element more, not a set filled anew
	next := &Plan{Interfaces: []string{"br-lan"}, Subnets: RangesOf(append(prefixes("200.0.0.0/24"), big...))}
	if err := Update(plan, next); err != nil {
		t.Fatal(err)
	}
	require.Equal(t, wantRanges(t, next.Subnets), rangesOfSet(t, SetSubnets))
}
