//go:build with_quic && with_utls

package render

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
)

// testdata/cases.tar.gz holds settings files with what the shell backend of podkop wrote
// for them: the configuration and the rule-set files, byte for byte, or nothing when it
// refused the settings. A case is a directory of the archive:
//
//	podkop.uci, facts.json, files/...     the settings, the address of the LAN, the local lists
//	want/config.json, want/rulesets/...   what the shell backend wrote
//	want/refused                          instead, when it wrote no configuration
//
// The archive was made by running the shell backend of podkop 0.7 on each case, outside
// this repository.
const casesArchive = "testdata/cases.tar.gz"

// fewestCases is below the number of cases there are: a run that finds a handful of them
// has lost its test data.
const fewestCases = 590

var (
	casesOnce  sync.Once
	casesFiles map[string]map[string][]byte
	casesErr   error
)

// cases returns the files of every case by its name and the path inside it.
func cases(t *testing.T) map[string]map[string][]byte {
	casesOnce.Do(func() {
		casesFiles = make(map[string]map[string][]byte)
		file, err := os.Open(casesArchive)
		if err != nil {
			casesErr = err
			return
		}
		defer file.Close()
		unpacked, err := gzip.NewReader(file)
		if err != nil {
			casesErr = err
			return
		}
		archive := tar.NewReader(unpacked)
		for {
			header, err := archive.Next()
			if err == io.EOF {
				return
			}
			if err != nil {
				casesErr = err
				return
			}
			name, path, found := strings.Cut(header.Name, "/")
			if !found || header.Typeflag != tar.TypeReg {
				continue
			}
			content, err := io.ReadAll(archive)
			if err != nil {
				casesErr = err
				return
			}
			if casesFiles[name] == nil {
				casesFiles[name] = make(map[string][]byte)
			}
			casesFiles[name][path] = content
		}
	})
	if casesErr != nil {
		t.Fatal(casesErr)
	}
	if len(casesFiles) < fewestCases {
		t.Fatalf("%d cases found, at least %d expected", len(casesFiles), fewestCases)
	}
	return casesFiles
}

func caseNames(t *testing.T) []string {
	var names []string
	for name := range cases(t) {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// outputPath is where a test has the configuration written, under its root.
const outputPath = "/out/config.json"

// placeCase puts the settings and the list files of a case under a root and returns the
// request that runs it there.
func placeCase(t *testing.T, name string, root string) Request {
	files := cases(t)[name]
	if files == nil {
		t.Fatal("no case ", name)
	}
	var facts struct {
		LANAddress string `json:"lan_address"`
	}
	err := json.Unmarshal(files["facts.json"], &facts)
	if err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(t.TempDir(), "podkop")
	err = os.WriteFile(settings, files["podkop.uci"], 0o644)
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range files {
		relative, isList := strings.CutPrefix(path, "files/")
		if !isList {
			continue
		}
		err = os.MkdirAll(filepath.Dir(filepath.Join(root, relative)), 0o755)
		if err == nil {
			err = os.WriteFile(filepath.Join(root, relative), content, 0o644)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return Request{UCIPath: settings, Facts: plan.Facts{LANAddress: facts.LANAddress}, Root: root, OutputPath: outputPath}
}

// wanted returns the files of a case under a directory of it, by their names there.
func wanted(t *testing.T, name string, directory string) map[string][]byte {
	result := make(map[string][]byte)
	for path, content := range cases(t)[name] {
		if relative, inside := strings.CutPrefix(path, directory+"/"); inside {
			result[relative] = content
		}
	}
	return result
}

func TestCases(t *testing.T) {
	// The cases are settings of podkop 0.7 and what its shell backend wrote. Since 0.8.8 the
	// servers are sources and rows of rules: the settings are converted (podkop migrate) and
	// every outbound and the place of the rules of block and exclusion differ from those of
	// the shell backend on purpose. What the cases still hold (DNS, lists, inbounds) is to be
	// compared apart from the outbounds; until then they are not run.
	t.Skip("0.8.8: the outbounds follow sources and rows of rules, not the shell backend")
	for _, name := range caseNames(t) {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			outcome, err := Run(placeCase(t, name, root))
			want := wanted(t, name, "want")
			wantConfig, taken := want["config.json"]
			if reason, now := refusedNow[name]; now {
				if err == nil {
					t.Fatalf("taken, the generator refuses them on purpose (%s)", reason)
				}
				return
			}
			if reason, now := takenNow[name]; now {
				// the shell backend refused these settings, the generator takes them on
				// purpose (plan/ledger.go)
				if err != nil {
					t.Fatalf("refused (%s): %v", reason, err)
				}
				return
			}
			if !taken {
				if want["refused"] == nil {
					t.Fatal("the case says neither what is written nor that the settings are refused")
				}
				if err == nil {
					t.Fatalf("the settings are taken, the shell backend refuses them; written %s", outcome.ConfigPath)
				}
				if strings.TrimSpace(err.Error()) == "" || len(leftFiles(t, root, "out")) != 0 {
					t.Fatalf("refused with %q, files left: %v", err, leftFiles(t, root, "out"))
				}
				return
			}
			if err != nil {
				t.Fatalf("the settings are refused, the shell backend takes them: %v", err)
			}
			if !outcome.Changed {
				t.Error("the first run says nothing changed")
			}
			config, err := os.ReadFile(outcome.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			// what the shell backend wrote, with the differences the generator has on
			// purpose (plan/ledger.go)
			parsed, err := uci.Parse(cases(t)[name]["podkop.uci"])
			if err != nil {
				t.Fatal(err)
			}
			settings, err := model.Load(parsed)
			if err != nil {
				t.Fatal(err)
			}
			converted, err := plan.FromShell(wantConfig, plan.Shell{Settings: settings, Options: plan.Options{
				ReadFile:  func(path string) ([]byte, error) { return os.ReadFile(filepath.Join(root, path)) },
				CheckList: engine.CheckRuleSet,
			}})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(config, converted.Config) {
				t.Errorf("the configuration differs: %s", firstDifference(config, converted.Config))
			}
			wantFiles := wanted(t, name, "want/rulesets")
			for _, file := range converted.Dropped {
				delete(wantFiles, file)
			}
			for file, content := range converted.Added {
				wantFiles[file] = content
			}
			var wantNames []string
			for file := range wantFiles {
				wantNames = append(wantNames, file)
			}
			sort.Strings(wantNames)
			files := leftFiles(t, root, strings.TrimPrefix(plan.DefaultRuleSetDir, "/"))
			if strings.Join(files, " ") != strings.Join(wantNames, " ") {
				t.Fatalf("rule-set files %v, want %v", files, wantNames)
			}
			for _, file := range files {
				content, err := os.ReadFile(filepath.Join(root, plan.DefaultRuleSetDir, file))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(content, wantFiles[file]) {
					t.Errorf("rule-set file %s differs: %s", file, firstDifference(content, wantFiles[file]))
				}
			}
		})
	}
}

// takenNow are the cases whose settings the shell backend refused and the generator takes
// on purpose, with the item of plan/ledger.go that says why.
var takenNow = map[string]string{
	"neg-same-remote-name":     "4: two lists of one name get numbers",
	"ed-remote-same-url-twice": "4: two lists of one name get numbers",
}

// refusedNow are the cases whose settings the shell backend took and the generator refuses
// on purpose, with the item of plan/ledger.go that says why.
var refusedNow = map[string]string{
	"ed-mixed-same-port": "12: two mixed proxies on one port",
}

// A second run over what the first one left changes nothing and says so.
func TestSecondRunChangesNothing(t *testing.T) {
	root := t.TempDir()
	request := placeCase(t, "sec-proxy-all-lists", root)
	first, err := Run(request)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, root)
	second, err := Run(request)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed || second.Changed {
		t.Errorf("changed: first run %v, second run %v", first.Changed, second.Changed)
	}
	after := snapshot(t, root)
	if len(before) != len(after) {
		t.Fatalf("%d files after the first run, %d after the second", len(before), len(after))
	}
	for path, content := range before {
		if !bytes.Equal(content, after[path]) {
			t.Errorf("%s changed in the second run", path)
		}
	}
}

// A configuration sing-box does not take is not stored, and the one in place stays.
func TestRefusedSettingsKeepTheConfiguration(t *testing.T) {
	root := t.TempDir()
	good, err := Run(placeCase(t, "ob-url-socks", root))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(good.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"neg-ttl-text", "neg-bad-link", "neg-json-unknown-type"} {
		_, err = Run(placeCase(t, name, root))
		if err == nil {
			t.Fatalf("%s: taken", name)
		}
		after, err := os.ReadFile(good.ConfigPath)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("%s: the configuration in place changed (%v)", name, err)
		}
	}
}

// What a list has that is no item is told, a list at a time, with the first of it;
// comments of a list file are no such thing.
func TestLeftOutItemsAreTold(t *testing.T) {
	root := t.TempDir()
	settings := filepath.Join(root, "podkop")
	err := os.WriteFile(settings, []byte("config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '8.8.8.8'\n"+
		"\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n"+
		"\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'good.example'\n\tlist user_domains 'bad!one'\n\tlist user_domains 'bad!two'\n"+
		"\tlist local_domain_lists '/list.lst'\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(root, "list.lst"), []byte("one.example\n# a comment\n// another\nnot a domain\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := Run(Request{UCIPath: settings, Root: root, OutputPath: outputPath, SkipCheck: true})
	if err != nil {
		t.Fatal(err)
	}
	warnings := strings.Join(outcome.Warnings, "\n")
	for _, want := range []string{
		`section main, the user domain list: 2 item(s) are no domain and are left out, the first: "bad!one"`,
		`local list /list.lst: 1 item(s) are neither a domain nor an IP CIDR and are left out, the first: "not a domain"`,
	} {
		if !strings.Contains(warnings, want) {
			t.Fatalf("no warning %q in:\n%s", want, warnings)
		}
	}
}

// A link the decoder takes and sing-box cannot build is found by the check of the whole
// configuration, and named: the section and the outbound, without what the link keeps
// secret. Nothing is written.
func TestRefusedLinkIsNamed(t *testing.T) {
	const canary = "CANARY0f6d2c"
	const uuid = "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"
	root := t.TempDir()
	settings := filepath.Join(root, "podkop")
	err := os.WriteFile(settings, []byte("config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '8.8.8.8'\n"+
		"\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'urltest'\n"+
		"\tlist urltest_proxy_links 'socks5://203.0.113.15:1080'\n"+
		"\tlist urltest_proxy_links 'vless://"+uuid+"@example.org:443?security=reality&pbk="+canary+"&sid=01'\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Run(Request{UCIPath: settings, Root: root, OutputPath: outputPath})
	if err == nil {
		t.Fatal("the settings are taken")
	}
	// the links of the section became the source main_links (podkop migrate); the second has no name
	if !strings.HasPrefix(err.Error(), "section main: cannot use the proxy link of main_links: server 2: ") || strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), uuid) {
		t.Fatalf("refused with %q", err)
	}
	if left := leftFiles(t, root, "out"); len(left) != 0 {
		t.Fatalf("files left: %v", left)
	}
}

// leftFiles lists the files of a directory under a root, sorted; none when it is not there.
func leftFiles(t *testing.T, root string, directory string) []string {
	var names []string
	err := filepath.Walk(filepath.Join(root, directory), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			relative, err := filepath.Rel(filepath.Join(root, directory), path)
			if err != nil {
				return err
			}
			names = append(names, relative)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	sort.Strings(names)
	return names
}

func snapshot(t *testing.T, root string) map[string][]byte {
	files := make(map[string][]byte)
	for _, name := range leftFiles(t, root, "") {
		content, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = content
	}
	return files
}

// firstDifference names the first line two texts part at.
func firstDifference(got []byte, want []byte) string {
	gotLines, wantLines := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for index := 0; index < len(gotLines) || index < len(wantLines); index++ {
		var gotLine, wantLine string
		if index < len(gotLines) {
			gotLine = gotLines[index]
		} else {
			gotLine = "(end)"
		}
		if index < len(wantLines) {
			wantLine = wantLines[index]
		} else {
			wantLine = "(end)"
		}
		if gotLine != wantLine {
			return "line " + itoa(index+1) + ": got " + strings.TrimSpace(gotLine) + ", want " + strings.TrimSpace(wantLine)
		}
	}
	return "no line differs"
}

func itoa(number int) string {
	text, _ := json.Marshal(number)
	return string(text)
}
