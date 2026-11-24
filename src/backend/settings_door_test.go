package podkop

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The settings file, /etc/config/podkop, is written by uci.Edit alone: under the lock of libuci, by
// a rename, what another program wrote meanwhile kept (the page writes it as well, through LuCI).
// Another way of writing it in the sources is found by what it would have to have:
//
//   - a Go file that runs the program uci, or has the command lines of uci that change the settings
//     ("set podkop.", "commit podkop"), or gives a uci batch to run;
//   - a Go call that writes, renames or removes a file by a path of the settings (settingsPath);
//   - a script of the packages that changes the settings by uci, or commits every package with a
//     plain "uci commit", or writes to /etc/config/podkop.
//
// The uses there are for another reason are listed: a use not listed fails, and so does a listed one
// that is gone.
var settingsDoors = map[string][]string{
	// what reads one option with the program, and dnsmasq's own file
	"src/backend/ctl/btrecord.go":    {"uci program get"},
	"src/backend/dnsmasq/dnsmasq.go": {"uci batch", "uci program batch"},
	// the copy of the old settings, kept beside them
	"src/backend/migrate/file.go": {"file uci.Copy"},
	// the settings a removed package took along are put back as they were
	"install.sh": {"file"},
}

// settingsWriter is the file of uci.Edit, and settingsEdits the files that call it.
const settingsWriter = "src/backend/uci/edit.go"

var settingsEdits = []string{
	"src/backend/migrate/file.go", "src/backend/migrate/steps.go", "src/backend/supervisor/cure.go", "src/backend/supervisor/router_linux.go",
}

var (
	// uciChange matches a command of uci that changes the settings, in a script or in the text of
	// "uci batch"
	uciChange = regexp.MustCompile(`\b(?:set|add|add_list|del_list|delete|rename|reorder|revert|commit|import)\s+(?:-\S+\s+)*["']?podkop(?:["'.\s;&|]|$)`)
	// uciShellChange matches the functions of /lib/config/uci.sh
	uciShellChange = regexp.MustCompile(`\buci_(?:set|add|add_list|remove|remove_list|rename|revert_state|commit)\s+["']?podkop(?:["'\s;&|]|$)`)
	// uciCommitAll matches a commit of every package
	uciCommitAll = regexp.MustCompile(`\buci\s+(?:-\S+\s+)*commit\s*(?:[;&|>)]|$)`)
	// uciMerge matches import and batch, which change whatever their input says
	uciMerge = regexp.MustCompile(`\buci\s+(?:-\S+\s+)*(?:import|batch)\b`)
	// fileChange matches a script that writes to the settings file: a redirection, or a command
	// whose last word it is
	fileChange = regexp.MustCompile(`(?:>\s*["']?|\b(?:cp|mv|ln|install|tee|rm|touch|truncate|dd)\b[^;&|]*\s["']?(?:of=)?|\bsed\s+(?:-\S+\s+)*-i[^;&|]*\s["']?)/etc/config/podkop["']?(?:\s*[;&|)>]|\s+2>|\s*$)`)
	// settingsPath matches the names the path of the settings has in the backend
	settingsPath = regexp.MustCompile(`(?i)^(?:settingspath|ucipath|commanddaemonflaguci|commandmigrateflaguci|commandrenderflaguci)$`)
)

// fileCalls are the functions that change the file their arguments name.
var fileCalls = []string{
	"os.Chmod", "os.Chown", "os.Create", "os.CreateTemp", "os.Link", "os.OpenFile", "os.Remove", "os.RemoveAll", "os.Rename", "os.Symlink",
	"os.Truncate", "os.WriteFile", "render.WriteFile", "syscall.Flock", "syscall.Open", "syscall.Rename", "uci.Copy",
}

func TestOneWriterOfTheSettings(t *testing.T) {
	const root, backend = "../..", "src/backend"
	found := make(map[string][]string)
	var edits []string
	goFiles := 0
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		name := backend + "/" + filepath.ToSlash(path)
		uses, edit, err := settingsUses(path)
		if err != nil {
			return err
		}
		goFiles++
		if len(uses) > 0 && name != settingsWriter {
			found[name] = uses
		}
		if edit {
			edits = append(edits, name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if goFiles < 100 {
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
			if uses := settingsUsesOfScript(string(content)); len(uses) > 0 {
				found[name] = uses
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, script := range []string{initScript, "podkop/files/etc/uci-defaults/99-podkop", "install.sh"} {
		if !scripts[script] {
			t.Fatalf("%s was not read (%d files of the packages were): the test does not look where the packages are", script, len(scripts))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(found)) {
		listed, known := settingsDoors[name]
		switch {
		case !known:
			t.Errorf("%s may write the settings past uci.Edit: %s; have uci.Edit write them, or list it in settingsDoors with what it writes", name, strings.Join(found[name], ", "))
		case !slices.Equal(found[name], listed):
			t.Errorf("%s may write the settings with %s; settingsDoors lists %s", name, strings.Join(found[name], ", "), strings.Join(listed, ", "))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(settingsDoors)) {
		if _, seen := found[name]; !seen {
			t.Errorf("%s no longer has %s: take it out of settingsDoors", name, strings.Join(settingsDoors[name], ", "))
		}
	}
	slices.Sort(edits)
	if !slices.Equal(edits, settingsEdits) {
		t.Errorf("uci.Edit is called in %s; settingsEdits lists %s", strings.Join(edits, ", "), strings.Join(settingsEdits, ", "))
	}
}

// settingsUses returns what a Go file uses of what would write the settings, sorted, and whether it
// calls uci.Edit.
func settingsUses(path string) (uses []string, edit bool, err error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, false, err
	}
	// the variables that hold the path of the settings, by their name, a file at once
	holders := make(map[string]bool)
	names := func(expression ast.Node) bool {
		named := false
		ast.Inspect(expression, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.Ident:
				named = named || holders[node.Name] || settingsPath.MatchString(node.Name)
			case *ast.BasicLit:
				text, _ := strconv.Unquote(node.Value)
				named = named || strings.HasPrefix(text, "/etc/config/podkop")
			case *ast.FuncLit:
				return false
			}
			return !named
		})
		return named
	}
	ast.Inspect(file, func(node ast.Node) bool {
		assign, isAssign := node.(*ast.AssignStmt)
		if !isAssign || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for index, value := range assign.Rhs {
			if _, isCall := value.(*ast.CallExpr); isCall {
				continue
			}
			if name, isName := assign.Lhs[index].(*ast.Ident); isName && names(value) {
				holders[name.Name] = true
			}
		}
		return true
	})
	ast.Inspect(file, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.BasicLit:
			if text, err := strconv.Unquote(node.Value); err == nil && node.Kind == token.STRING && uciChange.MatchString(text) {
				uses = append(uses, "uci change")
			}
		case *ast.CallExpr:
			selector, isSelector := node.Fun.(*ast.SelectorExpr)
			if !isSelector {
				return true
			}
			called := selector.Sel.Name
			if from, isName := selector.X.(*ast.Ident); isName {
				called = from.Name + "." + called
			}
			switch {
			case called == "uci.Edit":
				edit = true
			case selector.Sel.Name == "Batch":
				uses = append(uses, "uci batch")
			case called == "exec.Command" || called == "exec.CommandContext":
				if words, runs := uciRun(node.Args); runs {
					uses = append(uses, "uci program"+words)
				}
			case slices.Contains(fileCalls, called):
				for _, argument := range node.Args {
					if names(argument) {
						uses = append(uses, "file "+called)
					}
				}
			}
		}
		return true
	})
	slices.Sort(uses)
	return slices.Compact(uses), edit, nil
}

// uciRun tells whether the arguments of exec.Command run the program uci, and its command (" get"),
// when it is written there.
func uciRun(arguments []ast.Expr) (string, bool) {
	runs := false
	for _, argument := range arguments {
		literal, isLiteral := argument.(*ast.BasicLit)
		if !isLiteral {
			continue
		}
		switch text, _ := strconv.Unquote(literal.Value); {
		case text == "uci" || text == "/sbin/uci":
			runs = true
		case runs && !strings.HasPrefix(text, "-"):
			return " " + text, true
		}
	}
	return "", runs
}

// settingsUsesOfScript returns what a script uses of what would write the settings, sorted.
func settingsUsesOfScript(content string) []string {
	var uses []string
	for _, line := range strings.Split(content, "\n") {
		line = withoutComment(line)
		if uciChange.MatchString(line) || uciShellChange.MatchString(line) {
			uses = append(uses, "uci change")
		}
		if uciCommitAll.MatchString(line) {
			uses = append(uses, "uci commit of all")
		}
		if uciMerge.MatchString(line) {
			uses = append(uses, "uci batch")
		}
		if fileChange.MatchString(line) {
			uses = append(uses, "file")
		}
	}
	slices.Sort(uses)
	return slices.Compact(uses)
}

// What the test above looks for is found in the ways the settings were written before uci.Edit, and
// in others like them; what only reads them is not.
func TestSettingsUses(t *testing.T) {
	for line, want := range map[string]string{
		"uci -q delete podkop.settings.config_path":                                     "uci change",
		`uci -q set podkop.settings.cache_path="$new"`:                                  "uci change",
		"uci -q commit podkop":                                                          "uci change",
		"	uci commit podkop && echo done":                                               "uci change",
		"uci add podkop member":                                                         "uci change",
		"uci add_list 'podkop.main.user_domains=x'":                                     "uci change",
		"uci_set podkop settings guard 1":                                               "uci change",
		"uci commit":                                                                    "uci commit of all",
		"uci -q commit; exit 0":                                                         "uci commit of all",
		"printf 'set podkop.a.b=c' | uci -q batch":                                      "uci batch,uci change",
		"uci import podkop < /tmp/x":                                                    "uci batch,uci change",
		"cp -p /etc/config/podkop.pre-0.8.8 /etc/config/podkop":                         "file",
		"mv /tmp/x /etc/config/podkop && exit 0":                                        "file",
		`cp "$D/podkop.config" /etc/config/podkop 2>/dev/null`:                          "file",
		"echo x >> /etc/config/podkop":                                                  "file",
		"sed -i s/a/b/ /etc/config/podkop":                                              "file",
		"rm -f /etc/config/podkop":                                                      "file",
		"# uci commit podkop":                                                           "",
		"/usr/bin/podkop migrate 2>&1 | logger -t podkop":                               "",
		"uci -q get podkop.settings.config_path":                                        "",
		"SET=$(uci -q show podkop)":                                                     "",
		"uci commit dhcp":                                                               "",
		"uci -q set sing-box.main.enabled=0 && uci -q commit sing-box":                  "",
		`cp /etc/config/podkop "$D/podkop.config" 2>/dev/null`:                          "",
		`rm -rf "$D" /etc/config/podkop-opkg /etc/config/podkop.apk-new`:                "",
		"$(INSTALL_CONF) ./files/etc/config/podkop $(1)/etc/config/podkop":              "",
		"[ -f /etc/config/podkop ] || return 0":                                         "",
		`if [ -f /etc/config/podkop ] && cp -p /etc/config/podkop "$COPY"; then :; fi`:  "",
		`config_load podkop; config_get memory_limit settings memory_limit; uci_load x`: "",
	} {
		if got := strings.Join(settingsUsesOfScript(line), ","); got != want {
			t.Errorf("%q: %q, not %q", line, got, want)
		}
	}
	path := filepath.Join(t.TempDir(), "x.go")
	for body, want := range map[string]string{
		`dnsmasq.Router{}.Batch("set podkop.settings.yacd_secret_key=" + dnsmasq.Quote(key) + "\ncommit podkop\n")`: "uci batch,uci change",
		`exec.Command("uci", "commit", "podkop")`:                                       "uci program commit",
		`exec.CommandContext(ctx, "/sbin/uci", arguments...)`:                           "uci program",
		`os.WriteFile(s.options.SettingsPath, nil, 0)`:                                  "file os.WriteFile",
		`path := r.options.SettingsPath; os.Rename(temporary.Name(), path)`:             "file os.Rename",
		`path := r.options.SettingsPath; os.CreateTemp(filepath.Dir(path), ".x")`:       "file os.CreateTemp",
		`os.OpenFile("/etc/config/podkop", os.O_WRONLY, 0)`:                             "file os.OpenFile",
		`os.ReadFile(s.options.SettingsPath)`:                                           "",
		`content, err := os.ReadFile(SettingsPath); os.WriteFile("/tmp/x", content, 0)`: "",
		`os.WriteFile(filepath.Join(s.options.ConfigDir, "running.json"), nil, 0)`:      "",
		`s.log("info", "podkop.settings.yacd_secret_key is set")`:                       "",
	} {
		if err := os.WriteFile(path, []byte("package x\n\nfunc f() { "+body+" }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		uses, _, err := settingsUses(path)
		if err != nil {
			t.Fatal(body, err)
		}
		if got := strings.Join(uses, ","); got != want {
			t.Errorf("%s: %q, not %q", body, got, want)
		}
	}
}
