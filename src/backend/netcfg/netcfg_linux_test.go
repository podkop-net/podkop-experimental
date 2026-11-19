package netcfg

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
)

// The tests change the routing of their network namespace and compare with the ip
// program: they run as root in a container with the right to administer the network, and
// are skipped elsewhere.
func needIP(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("not root")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("no ip program")
	}
}

func ip(t *testing.T, arguments ...string) string {
	output, err := exec.Command("ip", arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(arguments, " "), err, output)
	}
	return string(output)
}

func state(t *testing.T) string {
	// a table without a route does not exist for the ip program: it fails, with nothing printed
	routes, _ := exec.Command("ip", "-4", "route", "show", "table", "105").Output()
	return ip(t, "-4", "rule", "list") + string(routes)
}

// The rules and the route made over netlink read back, by the ip program, as the ones the
// commands of the shell backend make (route_table_rule_mark of podkop 0.7.24), with the
// backend's own two: the rule of the check of the source and the rule of the router's mark.
func TestRulesAndRouteAsTheShellBackendMakesThem(t *testing.T) {
	needIP(t)
	TableNamesPath = filepath.Join(t.TempDir(), "rt_tables")
	if err := os.WriteFile(TableNamesPath, []byte("255 local\n254 main"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	clean := state(t)
	ip(t, "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "105")
	ip(t, "-4", "rule", "add", "fwmark", "0x00100000/0x00100000", "table", "105", "priority", "105")
	ip(t, "-4", "rule", "add", "fwmark", "0x00400000/0x00400000", "table", "105", "priority", "105")
	ip(t, "-4", "rule", "add", "iif", "lo", "fwmark", "0x00100000/0x00100000", "lookup", "main", "priority", "104")
	want := state(t)
	if want == clean {
		t.Fatal("the commands of the shell backend changed nothing")
	}
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	if after := state(t); after != clean {
		t.Fatalf("Remove left something:\n%s", after)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		// twice: what is there already is not doubled
		if err := Apply(false); err != nil {
			t.Fatal(err)
		}
		if got := state(t); got != want {
			t.Fatalf("run %d:\n--- over netlink\n%s--- by the ip program\n%s", attempt, got, want)
		}
	}
	names, _ := os.ReadFile(TableNamesPath)
	if string(names) != "255 local\n254 main\n105 podkop\n" {
		t.Errorf("the names of the tables: %q", names)
	}
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	if after := state(t); after != clean {
		t.Fatalf("Remove left something:\n%s", after)
	}
	// nothing to remove is no error
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
}

func TestLANAddress(t *testing.T) {
	needIP(t)
	_ = exec.Command("ip", "link", "del", "lantest0").Run()
	ip(t, "link", "add", "lantest0", "type", "veth", "peer", "name", "lantest1")
	defer exec.Command("ip", "link", "del", "lantest0").Run()
	ip(t, "addr", "add", "192.168.77.1/24", "dev", "lantest0")
	ip(t, "addr", "add", "192.168.78.1/24", "dev", "lantest0")
	NetworkConfigPath = filepath.Join(t.TempDir(), "network")
	for content, want := range map[string]string{
		"config interface 'loopback'\n\toption device 'lo'\n\nconfig interface 'lan'\n\toption device 'lantest0'\n\toption proto 'static'\n": "192.168.77.1",
		"config interface 'lan'\n\toption ifname 'lantest0'\n":                                                                               "192.168.77.1",
		// the device carries the address of another interface first: the one of the settings
		"config interface 'lan'\n\toption device 'lantest0'\n\toption ipaddr '192.168.78.1'\n":  "192.168.78.1",
		"config interface 'lan'\n\toption device 'lantest0'\n\tlist ipaddr '192.168.78.1/24'\n": "192.168.78.1",
		"config interface 'lan'\n\toption device 'lantest0'\n\toption ipaddr '10.9.9.9'\n":      "192.168.77.1",
		"config interface 'lan'\n\toption device 'nosuchdevice0'\n":                             "",
		"config interface 'wan'\n\toption device 'lantest0'\n":                                  "",
		"config interface 'lan'\n\toption device 'lantest1'\n":                                  "",
		"config interface 'lan'\n\toption device 'lantest0 lantest1'\n":                         "",
	} {
		if err := os.WriteFile(NetworkConfigPath, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		address, err := lanAddressOfDevice()
		if want == "" {
			if err == nil {
				t.Errorf("%q: address %s, an error expected", content, address)
			}
		} else if err != nil || address.String() != want {
			t.Errorf("%q: %v %v, want %s", content, address, err, want)
		}
	}
}

// The kernel says where a marked packet of a LAN device goes: to the router itself once
// the rule and the route of the backend are there, past it without them, or when a rule
// of higher priority takes the packet first.
func TestMarkedRoute(t *testing.T) {
	needIP(t)
	TableNamesPath = filepath.Join(t.TempDir(), "rt_tables")
	ip(t, "link", "add", "pdktest0", "type", "dummy")
	defer exec.Command("ip", "link", "del", "pdktest0").Run()
	ip(t, "addr", "add", "10.99.0.1/24", "dev", "pdktest0")
	ip(t, "link", "set", "pdktest0", "up")
	source, destination := netip.MustParseAddr("10.99.0.2"), netip.MustParseAddr("198.18.0.1")
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	// without the rule the packet is not the router's (or not routed at all here)
	if route, err := MarkedRoute("pdktest0", source, destination, dataplane.ProxyMark); err == nil && route.Local {
		t.Fatalf("local without the rule of the backend: %+v", route)
	}
	if err := Apply(false); err != nil {
		t.Fatal(err)
	}
	defer Remove()
	route, err := MarkedRoute("pdktest0", source, destination, dataplane.ProxyMark)
	if err != nil {
		t.Fatal(err)
	}
	if !route.Local || route.Table != dataplane.RoutingTable {
		t.Fatalf("with the rule of the backend: %+v", route)
	}
	// the ip program says the same
	if text := ip(t, "route", "get", destination.String(), "from", source.String(), "iif", "pdktest0", "mark", "0x100000"); !strings.HasPrefix(text, "local ") || !strings.Contains(text, "table 105") {
		t.Fatalf("ip route get: %s", text)
	}
	// with src_valid_mark (Tailscale sets it) the kernel checks the source by a lookup with
	// the mark of the packet: the rule of priority 104 keeps the table out of it, without it
	// the packet is a martian
	const validMark = "/proc/sys/net/ipv4/conf/all/src_valid_mark"
	saved, err := os.ReadFile(validMark)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(validMark, []byte("1"), 0o644); err != nil {
		t.Logf("src_valid_mark is not tested: %v", err)
	} else {
		defer os.WriteFile(validMark, saved, 0o644)
		route, err = MarkedRoute("pdktest0", source, destination, dataplane.ProxyMark)
		if err != nil || !route.Local || route.Table != dataplane.RoutingTable {
			t.Fatalf("with src_valid_mark: %+v, %v", route, err)
		}
		ip(t, "rule", "del", "priority", "104")
		if route, err = MarkedRoute("pdktest0", source, destination, dataplane.ProxyMark); err == nil {
			t.Fatalf("with src_valid_mark and without the rule of priority 104: %+v", route)
		}
		if present, _ := Present(false); present {
			t.Fatal("Present without the rule of priority 104")
		}
		if err = Apply(false); err != nil {
			t.Fatal(err)
		}
		if route, err = MarkedRoute("pdktest0", source, destination, dataplane.ProxyMark); err != nil || !route.Local {
			t.Fatalf("with src_valid_mark, the rule made again: %+v, %v", route, err)
		}
	}
	// a rule of higher priority takes the packet before the one of the backend
	ip(t, "rule", "add", "from", "10.99.0.0/24", "lookup", "main", "priority", "50")
	defer exec.Command("ip", "rule", "del", "priority", "50").Run()
	if route, err := MarkedRoute("pdktest0", source, destination, dataplane.ProxyMark); err == nil && route.Local {
		t.Fatalf("local past a rule of priority 50: %+v", route)
	}
}

func state6(t *testing.T) string {
	routes, _ := exec.Command("ip", "-6", "route", "show", "table", "105").Output()
	return ip(t, "-6", "rule", "list") + string(routes)
}

// With IPv6 the same rules and route of IPv6, as the ip program makes them (as homeproxy's
// "ip -6 rule add fwmark ... table ..." and "ip -6 route add local ::/0 dev lo table ..."), and
// those of IPv4 as before; without it again, those of IPv6 are gone.
func TestRulesAndRouteOfIPv6(t *testing.T) {
	needIP(t)
	if !IPv6Loopback() {
		t.Skip("no ::1 here (IPv6 turned off in the namespace)")
	}
	TableNamesPath = filepath.Join(t.TempDir(), "rt_tables")
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	clean4, clean6 := state(t), state6(t)
	ip(t, "-6", "route", "add", "local", "::/0", "dev", "lo", "table", "105")
	ip(t, "-6", "rule", "add", "fwmark", "0x00100000/0x00100000", "table", "105", "priority", "105")
	ip(t, "-6", "rule", "add", "fwmark", "0x00400000/0x00400000", "table", "105", "priority", "105")
	ip(t, "-6", "rule", "add", "iif", "lo", "fwmark", "0x00100000/0x00100000", "lookup", "main", "priority", "104")
	want6 := state6(t)
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	if after := state6(t); after != clean6 {
		t.Fatalf("Remove left something of IPv6:\n%s", after)
	}
	if err := Apply(false); err != nil {
		t.Fatal(err)
	}
	want4 := state(t)
	if after := state6(t); after != clean6 {
		t.Fatalf("Apply without IPv6 made something of IPv6:\n%s", after)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := Apply(true); err != nil {
			t.Fatal(err)
		}
		if got := state6(t); got != want6 {
			t.Fatalf("run %d:\n--- over netlink\n%s--- by the ip program\n%s", attempt, got, want6)
		}
		if got := state(t); got != want4 {
			t.Fatalf("run %d, IPv4:\n%s\nwant\n%s", attempt, got, want4)
		}
	}
	if present, err := Present(true); !present || err != nil {
		t.Fatalf("Present(true) after Apply(true): %v %v", present, err)
	}
	ip(t, "-6", "rule", "del", "priority", "104")
	if present, _ := Present(true); present {
		t.Fatal("Present(true) without the rule of IPv6 of priority 104")
	}
	if present, _ := Present(false); !present {
		t.Fatal("Present(false) wants nothing of IPv6")
	}
	// back without IPv6: those of IPv6 go, those of IPv4 stay
	if err := Apply(false); err != nil {
		t.Fatal(err)
	}
	if after := state6(t); after != clean6 {
		t.Fatalf("Apply(false) left something of IPv6:\n%s", after)
	}
	if got := state(t); got != want4 {
		t.Fatalf("Apply(false) changed IPv4:\n%s", got)
	}
	if err := Remove(); err != nil {
		t.Fatal(err)
	}
	if state(t) != clean4 || state6(t) != clean6 {
		t.Fatal("Remove left something")
	}
}

func TestIPv6Loopback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "if_inet6")
	saved := IPv6LoopbackPath
	IPv6LoopbackPath = path
	defer func() { IPv6LoopbackPath = saved }()
	if IPv6Loopback() {
		t.Fatal("no file: IPv6")
	}
	for content, want := range map[string]bool{
		"00000000000000000000000000000001 01 80 10 80       lo\n":                                                        true,
		"fe800000000000000000000000000001 02 40 20 80     eth0\n00000000000000000000000000000001 01 80 10 80       lo\n": true,
		"fe800000000000000000000000000001 02 40 20 80     eth0\n":                                                        false,
		"00000000000000000000000000000001 01 80 10 80     eth0\n":                                                        false,
		"": false,
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := IPv6Loopback(); got != want {
			t.Errorf("%q: %v", content, got)
		}
	}
}
