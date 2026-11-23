package podkop

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Besides its imports (TestOneDoorToSingBox), the backend reaches sing-box by two more doors that
// a new version of podkop-engine has to be checked at:
//
//   - the Clash API of the configuration that runs, over HTTP: its routes, its key, its port;
//   - the switches the engine reads from its environment (os.Getenv in the fork), set by the
//     daemon or by the scripts of the package.
//
// They are opened today outside engine, by the files of otherDoors: this test fails for a file
// that opens one and is not listed, and for a listed file that no longer uses what is listed, so
// that the list stays the list of what is there. Moving a use into engine, or adding one, changes
// the list in the same commit. The Go files of the backend (but those of engine, the tests and
// testdata, cmd/podkop included) are read as syntax: string and number literals count, comments
// do not. The files of the packages (their Makefiles, scripts and configuration) and install.sh
// are read as text without their comments. The page and the dashboard (YACD) talk to the Clash
// API from the browser by design and are not read.
var otherDoors = map[string][]string{
	// the daemon: a rule set with nothing cached starts empty, unless the service says otherwise
	"src/backend/cmd/podkop/daemon.go": {"switch SING_BOX_RULE_SET_START_EMPTY"},
	// the commands of the page and of the CLI: the outbounds and groups of the configuration that
	// runs, their latency tests, the choice of a selector, the update of the dashboard
	"src/backend/ctl/choice.go":    {"clash-api /proxies"},
	"src/backend/ctl/clash.go":     {"clash-api key"},
	"src/backend/ctl/commands.go":  {"clash-api /proxies", "clash-api /upgrade"},
	"src/backend/ctl/oneoff.go":    {"clash-api /group", "clash-api /proxies"},
	"src/backend/ctl/outbounds.go": {"clash-api /group", "clash-api /proxies"},
	// the port the configuration gives the Clash API (dataplane.ClashAPIPort)
	"src/backend/dataplane/dataplane.go": {"clash-api port"},
	// the service: the provider's DNS as the fallback (settings dns_fallback), the memory limit of
	// the settings in place of the engine's own (memory_limit)
	"podkop/files/etc/init.d/podkop": {"switch GOMEMLIMIT", "switch SING_BOX_DNS_FALLBACK"},
}

// clashRoutes are the routes of the Clash API of sing-box (experimental/clashapi: server.go,
// api_meta.go), by the first part of their path. Left out: / and /ui, the files of the
// dashboard rather than the API, and /logs, a route of the backend's own API as well
// (api.Client.Logs). A literal is a route when it starts with one (then the end, / or ?), or
// when it is a URL whose path does.
var clashRoutes = []string{
	"/cache", "/configs", "/connections", "/dns", "/group", "/memory", "/profile", "/providers",
	"/proxies", "/rules", "/script", "/traffic", "/upgrade", "/version",
}

const (
	// clashPort is the port of the Clash API: a URL that names it, or the number itself
	clashPort = "9090"
	// clashKey is how a client gives the Clash API its key (the header Authorization)
	clashKey = "Bearer "
)

// engineSwitch matches the names of the environment variables the engine reads (os.Getenv in
// the fork at r28): its own switches (SING_BOX_*), those of upstream (ENABLE_DEPRECATED_*,
// DISABLE_NFTABLES, SINGBOX_TS_TUN_DEBUG), and GOMEMLIMIT, which turns the engine's own memory
// limit off (memory_limit.go).
var engineSwitch = regexp.MustCompile(`\b(?:SING_BOX_|SINGBOX_|ENABLE_DEPRECATED_)[A-Z0-9_]*|\b(?:DISABLE_NFTABLES|GOMEMLIMIT)\b`)

// packageScripts are the places of the files of the packages, from the root of the repository;
// the files of the dashboard are skipped.
var (
	packageScripts = []string{"podkop", "luci-app-podkop/Makefile", "luci-app-podkop/root", "install.sh"}
	dashboardFiles = "podkop/files/usr/share/podkop/yacd"
	initScript     = "podkop/files/etc/init.d/podkop"
)

func TestOtherDoorsToSingBox(t *testing.T) {
	const (
		root    = "../.."
		backend = "src/backend"
		theDoor = "engine"
	)
	found := make(map[string][]string)
	goFiles := 0
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path == theDoor || entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		uses, err := goDoors(path)
		if err != nil {
			return err
		}
		goFiles++
		if len(uses) > 0 {
			found[backend+"/"+filepath.ToSlash(path)] = uses
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if goFiles < 50 {
		t.Fatalf("only %d Go files were read: the test does not look where the backend is", goFiles)
	}
	scripts := make(map[string]bool)
	for _, place := range packageScripts {
		err := filepath.WalkDir(filepath.Join(root, place), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			name = filepath.ToSlash(name)
			if entry.IsDir() {
				if name == dashboardFiles {
					return filepath.SkipDir
				}
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if bytes.IndexByte(content, 0) >= 0 {
				return nil
			}
			scripts[name] = true
			if uses := scriptDoors(string(content)); len(uses) > 0 {
				found[name] = uses
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if !scripts[initScript] {
		t.Fatalf("%s was not read (%d files of the packages were): the test does not look where the packages are", initScript, len(scripts))
	}
	for name, uses := range found {
		listed, known := otherDoors[name]
		listed = slices.Sorted(slices.Values(listed))
		switch {
		case !known:
			t.Errorf("%s reaches sing-box past engine: %s; move it into engine, or list it in otherDoors", name, strings.Join(uses, ", "))
		case !slices.Equal(uses, listed):
			t.Errorf("%s reaches sing-box past engine with %s; otherDoors lists %s", name, strings.Join(uses, ", "), strings.Join(listed, ", "))
		}
	}
	for name, listed := range otherDoors {
		if _, seen := found[name]; !seen {
			t.Errorf("%s no longer uses %s: take it out of otherDoors", name, strings.Join(listed, ", "))
		}
	}
}

// goDoors returns what a Go file uses of the doors, sorted, from its literals.
func goDoors(path string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var uses []string
	ast.Inspect(file, func(node ast.Node) bool {
		literal, isLiteral := node.(*ast.BasicLit)
		if !isLiteral {
			return true
		}
		switch literal.Kind {
		case token.INT:
			if literal.Value == clashPort {
				uses = append(uses, "clash-api port")
			}
		case token.STRING:
			text, err := strconv.Unquote(literal.Value)
			if err == nil {
				uses = append(uses, textDoors(text, true)...)
			}
		}
		return true
	})
	slices.Sort(uses)
	return slices.Compact(uses), nil
}

// scriptDoors returns what a script uses of the doors, sorted: the text of its lines up to a
// comment.
func scriptDoors(content string) []string {
	var uses []string
	for _, line := range strings.Split(content, "\n") {
		uses = append(uses, textDoors(withoutComment(line), false)...)
	}
	slices.Sort(uses)
	return slices.Compact(uses)
}

// textDoors returns what a piece of text uses of the doors: a Go literal (path: one that starts
// with / is the path of a request), or a line of a script (only the paths of URLs count).
func textDoors(text string, path bool) []string {
	var uses []string
	for _, name := range engineSwitch.FindAllString(text, -1) {
		uses = append(uses, "switch "+name)
	}
	if strings.Contains(text, ":"+clashPort) {
		uses = append(uses, "clash-api port")
	}
	if strings.Contains(text, clashKey) {
		uses = append(uses, "clash-api key")
	}
	var paths []string
	if path && strings.HasPrefix(text, "/") {
		paths = append(paths, text)
	}
	for rest := text; ; {
		_, after, found := strings.Cut(rest, "://")
		if !found {
			break
		}
		rest = after
		address := after
		if end := strings.IndexAny(address, " \t\"'`"); end >= 0 {
			address = address[:end]
		}
		if at := strings.IndexByte(address, '/'); at >= 0 {
			paths = append(paths, address[at:])
		}
	}
	for _, requested := range paths {
		for _, route := range clashRoutes {
			if rest, found := strings.CutPrefix(requested, route); found && (rest == "" || rest[0] == '/' || rest[0] == '?') {
				uses = append(uses, "clash-api "+route)
			}
		}
	}
	return uses
}

// withoutComment is a line of a script up to its comment: a # that begins a word.
func withoutComment(line string) string {
	for at := 0; at < len(line); at++ {
		if line[at] == '#' && (at == 0 || line[at-1] == ' ' || line[at-1] == '\t') {
			return line[:at]
		}
	}
	return line
}
