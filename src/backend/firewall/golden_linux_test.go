package firewall

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"golang.org/x/sys/unix"
)

// The goldens of the table: for each plan of goldenPlans, the table Apply makes, as `nft list
// table` prints it (the handles and the counts of the counters left out), is
// testdata/kernel/<name>.nft, byte for byte; and an update to it from the table of any other plan
// (Update) prints the same. They hold the table to what it is while the code that makes the plans
// and the table is rearranged: a diff of them in a commit that only rearranges is a failure.
//
// The text is that of the nft program that prints it: the goldens were recorded with the nft of
// testdata/kernel/nft-version (that of Alpine, which the kernel job of CI installs:
// .github/ci/kernel.sh), and with another nft they skip, saying so (the nft of Debian trixie,
// 1.1.3, prints a fib compare of one byte otherwise). CI's kernel job fails on a skip it does not
// allow: an nft that changed under it says so there.
//
//	go test -count=1 -run 'TestTableGolden' -update ./firewall/
//
// as root with the right to administer the network, under that nft, rewrites them and the version
// (on nexus: lab/v0822/kern/kern.sh NAME update).
var updateGoldens = flag.Bool("update", false, "rewrite the goldens of testdata/kernel")

const goldenDir = "testdata/kernel"

// goldenPlan is a plan of a golden: what the supervisor hands to Apply and Update for some
// settings (supervisor.firewallPlan maps plan.Dataplane and the sets of the lists into it).
type goldenPlan struct {
	name string
	plan func() *Plan
}

// the lists of the goldens: Telegram's subnets, a list of single addresses, Discord's voice
// servers on their ports, and IPv6 of Telegram and Cloudflare. Never appended to: a plan made
// after another would see what it added (slices.Concat makes a list of them)
var (
	telegram  = []string{"149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.56.0/22", "95.161.64.0/20"}
	addresses = []string{"203.0.112.7/32", "198.51.99.7/32", "8.8.8.8/32", "1.1.1.1/32"}
	discord   = []string{"104.16.0.0/12", "138.128.136.0/21", "162.158.0.0/15", "66.22.192.0/18"}
	telegram6 = []string{"2001:67c:4e8::/48", "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2a0a:f280::/32"}
	discord6  = []string{"2606:4700::/32", "2a06:98c0::/29"}
)

func voice(ipv6 bool) Group {
	group := Group{Set: "podkop_discord_subnets", Protocol: unix.IPPROTO_UDP, Ports: []PortRange{{19000, 20000}, {50000, 65535}}, Ranges: RangesOf(prefixes(discord...))}
	if ipv6 {
		group.Ranges6 = Merge6(ranges6(discord6...))
	}
	return group
}

// web is a group of TCP to the ports of the web (a list of a section with its own ports).
func web() Group {
	return Group{Set: "podkop_web_subnets", Protocol: unix.IPPROTO_TCP, Ports: []PortRange{{80, 80}, {443, 443}, {8443, 8443}}, Ranges: RangesOf(prefixes("185.199.108.0/22", "140.82.112.0/20"))}
}

// goldenPlans covers the kinds of tables the settings make. Some differ from another only by what
// the sets hold ("lists, changed", "ipv6-podkop, changed"): the update between them refills the
// sets, the rules staying.
func goldenPlans() []goldenPlan {
	devices := prefixes("192.168.1.60/32", "192.168.1.64/30", "10.7.0.0/24")
	return []goldenPlan{
		// a rule whose lists are not loaded yet: FakeIP only
		{"lan-only", func() *Plan { return &Plan{Interfaces: []string{"br-lan"}} }},
		// plain proxying by lists, NTP of the LAN left alone
		{"lists", func() *Plan {
			return &Plan{Interfaces: []string{"br-lan"}, ExcludeNTP: true, Subnets: RangesOf(prefixes(slices.Concat(telegram, addresses)...))}
		}},
		// the same rules, a list grown and an address gone
		{"lists-changed", func() *Plan {
			return &Plan{Interfaces: []string{"br-lan"}, ExcludeNTP: true, Subnets: RangesOf(prefixes(slices.Concat(telegram[1:], []string{"91.108.20.0/22", "8.8.8.8/32", "9.9.9.9/32"})...))}
		}},
		// lists with ports of their own (UDP and TCP), from two interfaces
		{"groups", func() *Plan {
			return &Plan{Interfaces: []string{"br-lan", "wlan0.20"}, Subnets: RangesOf(prefixes(telegram...)), Groups: []Group{voice(false), web()}}
		}},
		// devices routed whole (fully_routed_ips; a rule only for some devices gives its devices
		// routed whole the same way), with lists
		{"devices", func() *Plan {
			return &Plan{Interfaces: []string{"br-lan"}, Sources: devices, Subnets: RangesOf(prefixes(telegram...))}
		}},
		// IPv6 through podkop: the sets and the rules of IPv6, of the groups too
		{"ipv6-podkop", func() *Plan {
			return &Plan{Interfaces: []string{"br-lan"}, IPv6: true, Subnets: RangesOf(prefixes(telegram...)), Subnets6: Merge6(ranges6(telegram6...)),
				Groups: []Group{voice(true)}}
		}},
		{"ipv6-podkop-changed", func() *Plan {
			group := voice(false)
			group.Ranges6 = Merge6(ranges6(discord6[1:]...))
			return &Plan{Interfaces: []string{"br-lan"}, IPv6: true, Subnets: RangesOf(prefixes(telegram...)), Subnets6: Merge6(ranges6(slices.Concat(telegram6[:2], []string{"2001:db8:1::/48", "2a03:2880::/32"})...)),
				Groups: []Group{group}}
		}},
		// IPv6 past podkop (bypass, or a router without IPv6): the same lists, nothing of IPv6
		{"ipv6-bypass", func() *Plan {
			return &Plan{Interfaces: []string{"br-lan"}, Subnets: RangesOf(prefixes(telegram...)), Groups: []Group{voice(false)}}
		}},
		// BitTorrent past podkop, a client on the router itself (by its user), devices routed whole
		{"bittorrent-bypass", func() *Plan {
			return &Plan{Interfaces: []string{"br-lan"}, Sources: devices[:1], Subnets: RangesOf(prefixes(telegram...)),
				BitTorrent: BitTorrent{Mode: BitTorrentBypass, Sources: devices[:1], RouterUsers: []uint32{4321}}}
		}},
		// BitTorrent dropped for what podkop takes: the devices routed whole are its own
		{"bittorrent-block", func() *Plan {
			return &Plan{Interfaces: []string{"br-lan"}, Sources: devices, Subnets: RangesOf(prefixes(telegram...)),
				BitTorrent: BitTorrent{Mode: BitTorrentBlock, Sources: devices}}
		}},
		// BitTorrent dropped for every device of the LAN, hidden clients told by their fan-out, two
		// users of the router
		{"bittorrent-block-lan", func() *Plan {
			return &Plan{Interfaces: []string{"br-lan"}, Subnets: RangesOf(prefixes(telegram...)),
				BitTorrent: BitTorrent{Mode: BitTorrentBlock, LAN: true, Fan: dataplane.DefaultFan, RouterUsers: []uint32{4321, 4322}}}
		}},
		// BitTorrent through the servers of a rule, for what podkop takes
		{"bittorrent-section", func() *Plan {
			return &Plan{Interfaces: []string{"br-lan"}, Sources: devices[:1], Subnets: RangesOf(prefixes(telegram...)),
				BitTorrent: BitTorrent{Mode: BitTorrentSection, Sources: devices[:1]}}
		}},
		// and for every device of the LAN, hidden clients told by their fan-out
		{"bittorrent-section-lan", func() *Plan {
			return &Plan{Interfaces: []string{"br-lan"}, Subnets: RangesOf(prefixes(telegram...)),
				BitTorrent: BitTorrent{Mode: BitTorrentSection, LAN: true, Fan: dataplane.DefaultFan}}
		}},
		// YACD on: the Clash API kept to its devices and the router itself
		{"clash-api", func() *Plan {
			return &Plan{Interfaces: []string{"br-lan"}, Subnets: RangesOf(prefixes(telegram...)), ClashAPIInterfaces: []string{"br-lan", "eth1"}}
		}},
		// interface sources with routing marks of their own: what the router sends with them goes by
		{"routing-marks", func() *Plan {
			return &Plan{Interfaces: []string{"br-lan"}, Subnets: RangesOf(prefixes(telegram...)), OwnMarks: []uint32{0x10000, 0x80000000}}
		}},
		// everything at once
		{"everything", func() *Plan {
			return &Plan{Interfaces: []string{"br-lan", "eth1"}, ExcludeNTP: true, Sources: devices, IPv6: true,
				Subnets: RangesOf(prefixes(slices.Concat(telegram, addresses)...)), Subnets6: Merge6(ranges6(telegram6...)),
				Groups: []Group{voice(true), web()}, ClashAPIInterfaces: []string{"br-lan"}, OwnMarks: []uint32{0x10000},
				BitTorrent: BitTorrent{Mode: BitTorrentSection, LAN: true, Sources: devices, Fan: dataplane.DefaultFan, RouterUsers: []uint32{4321}}}
		}},
	}
}

var counters = regexp.MustCompile(`counter packets \d+ bytes \d+`)

// goldenDump is the table as the goldens have it: dump, the counts of the counters as nothing
// passed (a test of another package in the same network namespace may send a packet meanwhile).
func goldenDump(t *testing.T) string {
	return counters.ReplaceAllString(dump(t), "counter packets 0 bytes 0")
}

// needGoldenNft skips, saying why, where the nft program is not the one that recorded the goldens;
// with -update it records its own version.
func needGoldenNft(t *testing.T) {
	needNft(t)
	version := strings.TrimSpace(nft(t, "--version"))
	path := filepath.Join(goldenDir, "nft-version")
	if *updateGoldens {
		writeGolden(t, path, version+"\n")
		return
	}
	recorded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimSpace(string(recorded)); version != want {
		t.Skipf("the goldens of %s were recorded with %q, this nft is %q, which may print the same table otherwise: run them under that nft (golang:1.26.8-alpine with its nftables, as .github/ci/kernel.sh), or record them anew with -update and review the diff", goldenDir, want, version)
	}
}

func TestTableGolden(t *testing.T) {
	needGoldenNft(t)
	defer Remove()
	for _, golden := range goldenPlans() {
		_ = Remove()
		if err := Apply(golden.plan()); err != nil {
			t.Fatal(golden.name, ": ", err)
		}
		compareGolden(t, filepath.Join(goldenDir, golden.name+".nft"), goldenDump(t))
	}
}

// An update from the table of any plan to that of another prints the table a fresh Apply of the
// other makes: by difference of the sets where only they changed, the table made anew otherwise.
func TestTableGoldenUpdate(t *testing.T) {
	needGoldenNft(t)
	if *updateGoldens {
		t.Skip("-update: the goldens are being written")
	}
	defer Remove()
	plans := goldenPlans()
	want := make(map[string]string, len(plans))
	for _, golden := range plans {
		content, err := os.ReadFile(filepath.Join(goldenDir, golden.name+".nft"))
		if err != nil {
			t.Fatal(err)
		}
		want[golden.name] = string(content)
	}
	for _, from := range plans {
		for _, to := range plans {
			_ = Remove()
			previous := from.plan()
			if err := Apply(previous); err != nil {
				t.Fatal(from.name, ": ", err)
			}
			if err := Update(previous, to.plan()); err != nil {
				t.Fatal(from.name, " to ", to.name, ": ", err)
			}
			if got := goldenDump(t); got != want[to.name] {
				t.Errorf("an update from %s to %s:\n%s", from.name, to.name, firstDifference(want[to.name], got))
			}
		}
	}
}

func writeGolden(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// compareGolden holds got to the golden at path, byte for byte; -update writes it instead.
func compareGolden(t *testing.T, path string, got string) {
	t.Helper()
	if *updateGoldens {
		writeGolden(t, path, got)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (-update writes it)", err)
	}
	if string(want) != got {
		t.Errorf("%s is not what the test makes (-update rewrites it, for a change that is meant):\n%s", path, firstDifference(string(want), got))
	}
}

// firstDifference shows where two texts part: the line before and the first differing lines of
// each.
func firstDifference(want string, got string) string {
	wantLines, gotLines := strings.Split(want, "\n"), strings.Split(got, "\n")
	line := 0
	for line < len(wantLines) && line < len(gotLines) && wantLines[line] == gotLines[line] {
		line++
	}
	part := func(lines []string) string {
		if line >= len(lines) {
			return "\t(the end)\n"
		}
		var text strings.Builder
		for _, item := range lines[line:min(line+6, len(lines))] {
			text.WriteString("\t" + item + "\n")
		}
		return text.String()
	}
	before := "(the start)"
	if line > 0 {
		before = wantLines[line-1]
	}
	return "after line " + strconv.Itoa(line) + " (" + strings.TrimSpace(before) + "):\n--- the golden\n" + part(wantLines) + "--- now\n" + part(gotLines)
}
