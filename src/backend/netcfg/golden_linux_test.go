package netcfg

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The goldens of the routing: for each state the supervisor brings the routing to (ApplyRouting
// with IPv6 or without, then RouteUplinks with the uplinks of the router), the rules and the
// routes of the table as the ip program prints them are testdata/kernel/<name>.txt, byte for
// byte, from a clean namespace and from each other state. They are in this package, not beside
// the firewall's: go test runs the binaries of the packages at once, in the same network
// namespace, and the tests of this one compare what ip prints.
//
// The text is that of the ip program: recorded with the iproute2 of testdata/kernel/ip-version
// (Alpine's, which the kernel job of CI installs: .github/ci/kernel.sh); with another one they
// skip, saying so.
//
//	go test -count=1 -run TestRoutingGolden -update ./netcfg/
//
// as root with the right to administer the network rewrites them and the version (on nexus:
// lab/v0822/kern/kern.sh NAME update).
var updateGoldens = flag.Bool("update", false, "rewrite the goldens of testdata/kernel")

const goldenDir = "testdata/kernel"

type routingState struct {
	name    string
	ipv6    bool
	uplinks []string
}

var routingStates = []routingState{
	{"ipv4", false, nil},
	{"ipv4-uplinks", false, []string{"wwan0", "eth1"}},
	{"ipv6", true, nil},
	{"ipv6-uplinks", true, []string{"wwan0"}},
}

// routingDump is what ip prints of the rules of both families and of the routes of the table.
func routingDump(t *testing.T) string {
	var text strings.Builder
	for _, family := range []string{"-4", "-6"} {
		text.WriteString("# ip " + family + " rule list\n" + ip(t, family, "rule", "list"))
		// a table without a route does not exist for the ip program: it fails, with nothing printed
		routes, _ := exec.Command("ip", family, "route", "show", "table", strconv.Itoa(tableID)).Output()
		text.WriteString("# ip " + family + " route show table " + strconv.Itoa(tableID) + "\n" + string(routes))
	}
	return text.String()
}

func bringRouting(t *testing.T, state routingState) {
	if err := Apply(state.ipv6); err != nil {
		t.Fatal(state.name, ": ", err)
	}
	if _, err := syncUplinkRules(state.uplinks); err != nil {
		t.Fatal(state.name, ": ", err)
	}
}

func TestRoutingGolden(t *testing.T) {
	needIP(t)
	if !IPv6Loopback() {
		t.Skip("no ::1 here (IPv6 turned off in the namespace)")
	}
	output, err := exec.Command("ip", "-V").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	version := strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0])
	versionPath := filepath.Join(goldenDir, "ip-version")
	if *updateGoldens {
		writeGolden(t, versionPath, version+"\n")
	} else if recorded, err := os.ReadFile(versionPath); err != nil {
		t.Fatal(err)
	} else if want := strings.TrimSpace(string(recorded)); want != version {
		t.Skipf("the goldens of %s were recorded with %q, this ip is %q, which may print the same rules otherwise: run them under that ip (golang:1.26.8-alpine with its iproute2, as .github/ci/kernel.sh), or record them anew with -update and review the diff", goldenDir, want, version)
	}
	TableNamesPath = filepath.Join(t.TempDir(), "rt_tables")
	clean := func() {
		if err := Remove(); err != nil {
			t.Fatal(err)
		}
	}
	defer clean()
	for _, state := range routingStates {
		clean()
		bringRouting(t, state)
		compareGolden(t, filepath.Join(goldenDir, state.name+".txt"), routingDump(t))
	}
	if *updateGoldens {
		return
	}
	// from each state to each other, as a change of the settings or of the uplinks brings it
	for _, from := range routingStates {
		for _, to := range routingStates {
			clean()
			bringRouting(t, from)
			bringRouting(t, to)
			want, err := os.ReadFile(filepath.Join(goldenDir, to.name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			if got := routingDump(t); got != string(want) {
				t.Errorf("from %s to %s:\n%s", from.name, to.name, firstDifference(string(want), got))
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
