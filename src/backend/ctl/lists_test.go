package ctl

import (
	"encoding/json"
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

// The names of the commands are kept in several lists by hand: the help (Commands), the switch of
// Run, the commands answered inside the backend (inProcess), the actions of clash_api (its help,
// its switch, the list its unknown action answers), and on the side of the page the commands it
// runs (fe-app-podkop: the methods of methods/shell, and the bundle of them the package ships,
// main.js), the methods of ubus it calls (rpc.declare) and the ACL of rpcd that grants them
// (luci-app-podkop.json). TestCommandLists holds them together: a command the help names and
// Run does not handle, one Run handles that the help leaves out and that is not listed as hidden,
// a name of inProcess that is no command, a command the page runs that is none or that the ACL
// does not let it run, a grant of the ACL that names nothing the page calls. The methods of the
// object podkop on ubus and their grants are held by TestBusMethodsInACL (cmd/podkop).
//
// A known difference is listed below with its reason; a listed difference that is gone fails as
// well, so that the lists stay what is there.

// hiddenCommands are the commands Run handles that the help does not list.
var hiddenCommands = map[string]string{
	// a finding of the 0.8.22 review of the lists, kept as it is
	"show_sing_box_version": "a command of podkop 0.7's shell backend, never in the help of this one (since 9fe7cc7); src/backend/README.md names it",
}

// pagePrograms are the commands the page runs with /usr/bin/podkop that the backend does not
// answer itself (inProcess): the call to ubus is refused, and the page starts the program.
var pagePrograms = map[string]string{
	"global_check": "rare and long: in a program of its own a mistake in it cannot take the backend down (ctl/bus.go)",
	// a finding of the 0.8.22 review of the lists, kept as it is
	"subscription_update_start": "not in inProcess since it came (130e013): the Update now of a subscription starts the program",
}

// pageUncalled are the methods of methods/shell no part of the page calls.
var pageUncalled = map[string]string{
	"subscriptionLoad": "the page loads a list as a job (subscription_load_start, _state, _cancel); the CLI keeps subscription_load",
}

// aclUncalled are the grants of ubus in the ACL that no call of the page names.
var aclUncalled = map[string]string{
	// a finding of the 0.8.22 review of the lists, kept as it is
	"service list": "granted since upstream's a6a171e (2024); nothing of the page asks it today",
}

// pageLuCICalls are the calls of ubus the page makes through LuCI's own modules: the text of the
// call in a view, and the method of ubus LuCI asks.
var pageLuCICalls = map[string]string{
	"network.getHostHints(": "luci-rpc getHostHints",
}

// rcCommonActions are the actions /etc/rc.common gives a script of a service (USE_PROCD).
var rcCommonActions = []string{"start", "stop", "restart", "reload", "enable", "disable", "enabled", "boot", "shutdown", "running", "status", "trace"}

const (
	repository  = "../../.."
	pageSources = "fe-app-podkop/src"
	pageViews   = "luci-app-podkop/htdocs/luci-static/resources/view/podkop"
	pageBundle  = pageViews + "/main.js"
	pageACL     = "luci-app-podkop/root/usr/share/rpcd/acl.d/luci-app-podkop.json"
	initScript  = "podkop/files/etc/init.d/podkop"
	packageMake = "podkop/Makefile"
	program     = "/usr/bin/podkop"
	service     = "/etc/init.d/podkop"
)

func TestCommandLists(t *testing.T) {
	if _, err := os.Stat(filepath.Join(repository, pageACL)); os.IsNotExist(err) {
		t.Skip("no page of the package next to the backend")
	}
	help := helpNames(t)
	handled := switchCases(t, "commands.go", "Run", "arguments")
	if len(handled) < 30 {
		t.Fatalf("only %d cases of Run were read: the test does not look where the switch is", len(handled))
	}

	// the help and the switch
	for _, name := range help {
		if !slices.Contains(handled, name) {
			t.Errorf("the help names %s, which Run does not handle", name)
		}
	}
	for _, name := range handled {
		_, hidden := hiddenCommands[name]
		switch {
		case slices.Contains(help, name) && hidden:
			t.Errorf("%s is in the help: take it out of hiddenCommands", name)
		case !slices.Contains(help, name) && !hidden:
			t.Errorf("Run handles %s, which the help does not name: add it to Commands, or to hiddenCommands with why", name)
		}
	}
	for name := range hiddenCommands {
		if !slices.Contains(handled, name) {
			t.Errorf("Run no longer handles %s: take it out of hiddenCommands", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(inProcess)) {
		if !slices.Contains(handled, name) {
			t.Errorf("inProcess names %s, which Run does not handle", name)
		}
	}

	// the actions of clash_api: its help, its switch, the list of its unknown action
	actions := switchCases(t, "commands.go", "clashAPI", "argument")
	helped := clashHelp(t)
	available := clashAvailable(t)
	if len(actions) < 4 {
		t.Fatalf("only %d actions of clash_api were read", len(actions))
	}
	if !slices.Equal(slices.Sorted(slices.Values(actions)), slices.Sorted(slices.Values(helped))) {
		t.Errorf("clash_api handles %v, its help names %v", actions, helped)
	}
	if !slices.Equal(slices.Sorted(slices.Values(actions)), slices.Sorted(slices.Values(available))) {
		t.Errorf("clash_api handles %v, its unknown action answers %v", actions, available)
	}

	// what the page runs, from its sources and from the bundle the package ships
	source := readPage(t, false)
	bundle := readPage(t, true)
	if !slices.Equal(source.calls, bundle.calls) {
		t.Errorf("the bundle %s runs other commands than the sources: the bundle %v, the sources %v", pageBundle, bundle.calls, source.calls)
	}
	if !slices.Equal(source.declared, bundle.declared) {
		t.Errorf("the bundle %s calls other methods of ubus than the sources: the bundle %v, the sources %v", pageBundle, bundle.declared, source.declared)
	}
	if len(source.calls) < 20 {
		t.Fatalf("only %d calls of commands were read from the page", len(source.calls))
	}
	used := pageUses(t)
	defined := make(map[string]bool)
	for _, call := range source.calls {
		defined[call.method] = true
		_, uncalled := pageUncalled[call.method]
		switch {
		case used[call.method] && uncalled:
			t.Errorf("the page calls %s now: take it out of pageUncalled", call.method)
		case !used[call.method] && !uncalled:
			t.Errorf("no part of the page calls %s (%s %s): take it out of methods/shell, or list it in pageUncalled with why", call.method, call.program, call.command)
		}
	}
	for method := range used {
		if !defined[method] {
			t.Errorf("the page calls PodkopShellMethods.%s, which methods/shell does not define", method)
		}
	}
	for method := range pageUncalled {
		if !defined[method] {
			t.Errorf("methods/shell no longer defines %s: take it out of pageUncalled", method)
		}
	}
	actionsOfService := initActions(t)
	asProgram := make(map[string]bool)
	for _, call := range source.calls {
		if !used[call.method] {
			continue
		}
		switch call.program {
		case program:
			if !slices.Contains(handled, call.command) {
				t.Errorf("the page runs podkop %s (%s), which Run does not handle", call.command, call.method)
			}
			if call.command == "clash_api" && !slices.Contains(actions, call.action) {
				t.Errorf("the page runs podkop clash_api %s (%s), which clash_api does not handle", call.action, call.method)
			}
			if !inProcess[call.command] {
				asProgram[call.command] = true
			}
		case service:
			if !slices.Contains(actionsOfService, call.command) {
				t.Errorf("the page runs %s %s (%s), which the script of the service does not have", service, call.command, call.method)
			}
		default:
			t.Errorf("the page runs %s %s (%s): a program the test does not know", call.program, call.command, call.method)
		}
	}
	for command := range asProgram {
		if _, listed := pagePrograms[command]; !listed {
			t.Errorf("the page runs podkop %s, which the backend does not answer itself (inProcess): each call starts the program; add it to inProcess, or to pagePrograms with why", command)
		}
	}
	for command := range pagePrograms {
		if !asProgram[command] {
			t.Errorf("podkop %s is answered inside the backend now, or the page no longer runs it: take it out of pagePrograms", command)
		}
	}

	// the ACL of the page: what the page runs and calls is granted, and every grant is used
	acl := readACL(t)
	declared := slices.Clone(source.declared)
	for text, call := range pageLuCICalls {
		if viewsContain(t, text) {
			declared = append(declared, call)
		}
	}
	programs := map[string]bool{}
	for _, call := range source.calls {
		if used[call.method] {
			programs[call.program] = true
		}
	}
	if programs[program] && !slices.Contains(declared, "podkop run") {
		t.Errorf("the page runs %s without asking the backend first (podkop run)", program)
	}
	for _, call := range declared {
		if call == "file exec" {
			// granted by the files of the ACL
			continue
		}
		if !acl.ubus[call] {
			t.Errorf("the page calls %s, which the ACL %s does not grant", call, pageACL)
		}
	}
	for path := range programs {
		if !slices.Contains(acl.files[path], "exec") {
			t.Errorf("the page runs %s, which the ACL does not let it run", path)
		}
	}
	for grant := range acl.ubus {
		_, uncalled := aclUncalled[grant]
		object, _, _ := strings.Cut(grant, " ")
		switch {
		case object == "podkop":
			// the methods of the backend: TestBusMethodsInACL holds them to those it has; the page
			// calls them by rpc.declare
			if !slices.Contains(declared, grant) {
				t.Errorf("the ACL grants %s, which the page does not call", grant)
			}
		case slices.Contains(declared, grant) && uncalled:
			t.Errorf("the page calls %s now: take it out of aclUncalled", grant)
		case !slices.Contains(declared, grant) && !uncalled:
			t.Errorf("the ACL grants %s, which no call of the page names: take it out of the ACL, or list it in aclUncalled with why", grant)
		}
	}
	for grant := range aclUncalled {
		if !acl.ubus[grant] {
			t.Errorf("the ACL no longer grants %s: take it out of aclUncalled", grant)
		}
	}
	t.Logf("%d commands in the help, %d cases of Run, %d answered inside the backend, %d actions of clash_api; "+
		"the page: %d methods of methods/shell (%d called), %d methods of ubus declared; the ACL: %d grants of ubus, %d programs",
		len(help), len(handled), len(inProcess), len(actions), len(source.calls), len(used), len(source.declared), len(acl.ubus), len(acl.files))
	makefile, err := os.ReadFile(filepath.Join(repository, packageMake))
	if err != nil {
		t.Fatal(err)
	}
	for path := range acl.files {
		if !programs[path] {
			t.Errorf("the ACL lets the page run %s, which it does not run", path)
		}
		if !strings.Contains(string(makefile), "$(1)"+path+"\n") {
			t.Errorf("the ACL lets the page run %s, which %s does not install", path, packageMake)
		}
	}
}

// helpNames are the commands of the help: "start | stop | restart" is three.
func helpNames(t *testing.T) []string {
	var names []string
	for _, command := range Commands {
		for name := range strings.SplitSeq(command[0], "|") {
			name = strings.TrimSpace(name)
			if slices.Contains(names, name) {
				t.Errorf("the help names %s twice", name)
			}
			names = append(names, name)
		}
	}
	return names
}

// switchCases are the string cases of the outer switch of a function on a value read from a
// variable (Run: arguments[0]) or by a call (clashAPI: argument(0)), from the source.
func switchCases(t *testing.T, file string, function string, value string) []string {
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var cases []string
	for _, declaration := range parsed.Decls {
		body, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || body.Name.Name != function || body.Recv != nil {
			continue
		}
		for _, statement := range body.Body.List {
			choice, isSwitch := statement.(*ast.SwitchStmt)
			if !isSwitch || !switchesOn(choice.Tag, value) {
				continue
			}
			for _, clause := range choice.Body.List {
				for _, expression := range clause.(*ast.CaseClause).List {
					literal, isLiteral := expression.(*ast.BasicLit)
					if !isLiteral || literal.Kind != token.STRING {
						t.Fatalf("%s: a case of the switch of %s is no string: %T", file, function, expression)
					}
					name, err := strconv.Unquote(literal.Value)
					if err != nil {
						t.Fatal(err)
					}
					if slices.Contains(cases, name) {
						t.Errorf("%s handles %s twice", function, name)
					}
					cases = append(cases, name)
				}
			}
			return cases
		}
	}
	t.Fatalf("%s: no switch on %s(0) in %s", file, value, function)
	return nil
}

// switchesOn tells whether the tag of a switch is name[0] or name(0).
func switchesOn(tag ast.Expr, name string) bool {
	var called ast.Expr
	var index ast.Expr
	switch expression := tag.(type) {
	case *ast.IndexExpr:
		called, index = expression.X, expression.Index
	case *ast.CallExpr:
		if len(expression.Args) != 1 {
			return false
		}
		called, index = expression.Fun, expression.Args[0]
	default:
		return false
	}
	identifier, isIdentifier := called.(*ast.Ident)
	zero, isLiteral := index.(*ast.BasicLit)
	return isIdentifier && identifier.Name == name && isLiteral && zero.Value == "0"
}

// clashHelp are the actions the help of clash_api names: the first word of each part between
// the bars, what is in parentheses left out.
func clashHelp(t *testing.T) []string {
	for _, command := range Commands {
		if command[0] != "clash_api" {
			continue
		}
		text, depth := "", 0
		for _, character := range command[1] {
			switch {
			case character == '(':
				depth++
			case character == ')':
				depth--
			case depth == 0:
				text += string(character)
			}
		}
		var actions []string
		for part := range strings.SplitSeq(text, "|") {
			if fields := strings.Fields(part); len(fields) > 0 {
				actions = append(actions, fields[0])
			}
		}
		return actions
	}
	t.Fatal("the help has no clash_api")
	return nil
}

// clashAvailable is the list of actions the unknown action of clash_api answers.
func clashAvailable(t *testing.T) []string {
	parsed, err := parser.ParseFile(token.NewFileSet(), "commands.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var available []string
	ast.Inspect(parsed, func(node ast.Node) bool {
		literal, isLiteral := node.(*ast.BasicLit)
		if !isLiteral || literal.Kind != token.STRING || !strings.Contains(literal.Value, "unknown action") {
			return true
		}
		text, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		var answer struct {
			Available []string `json:"available"`
		}
		if json.Unmarshal([]byte(text), &answer) == nil {
			available = answer.Available
		}
		return true
	})
	if len(available) == 0 {
		t.Fatal("no answer of an unknown action of clash_api lists the actions")
	}
	return available
}

// pageCall is a method of methods/shell: the program it runs, the command, and for clash_api its
// action.
type pageCall struct {
	method  string
	program string
	command string
	action  string
}

// page is what the page runs and calls, read from its sources or from its bundle.
type page struct {
	calls []pageCall
	// declared are the methods of ubus it declares (rpc.declare), as "object method", sorted
	declared []string
}

var (
	enumBlock      = regexp.MustCompile(`enum\s+(\w+)\s*\{([^}]*)\}`)
	enumMember     = regexp.MustCompile(`(\w+)\s*=\s*'([^']*)'`)
	bundleEnum     = regexp.MustCompile(`\b(\w+?)\d*\["(\w+)"\]\s*=\s*"([^"]*)"`)
	asyncProperty  = regexp.MustCompile(`(\w+):\s*async\b`)
	enumReference  = regexp.MustCompile(`^Podkop\.(\w+)\.(\w+)$`)
	quoted         = regexp.MustCompile(`^['"]([^'"]*)['"]$`)
	declaration    = regexp.MustCompile(`rpc\.declare(?:<[^(]*>)?\(\{\s*object:\s*['"]([\w-]+)['"],\s*method:\s*(?:['"](\w+)['"]|Podkop\.(\w+)\.(\w+))`)
	defaultCommand = regexp.MustCompile(`function callBaseMethod(?:<\w+>)?\([^)]*?command(?::\s*string)?\s*=\s*['"]([^'"]+)['"]`)
	shellUse       = regexp.MustCompile(`PodkopShellMethods\.(\w+)`)
)

// readPage reads what the page runs and calls: from the sources (fe-app-podkop/src: the enums of
// types.ts, the methods of methods/shell, every rpc.declare) or from the bundle main.js.
func readPage(t *testing.T, fromBundle bool) page {
	var texts []string
	if fromBundle {
		texts = []string{readText(t, pageBundle)}
	} else {
		texts = pageFiles(t, pageSources, ".ts")
	}
	whole := strings.Join(texts, "\n")
	enums := make(map[string]map[string]string)
	member := func(enum string, key string, value string) {
		if enums[enum] == nil {
			enums[enum] = make(map[string]string)
		}
		enums[enum][key] = value
	}
	if fromBundle {
		for _, found := range bundleEnum.FindAllStringSubmatch(whole, -1) {
			member(found[1], found[2], found[3])
		}
	} else {
		for _, block := range enumBlock.FindAllStringSubmatch(whole, -1) {
			for _, found := range enumMember.FindAllStringSubmatch(block[2], -1) {
				member(block[1], found[1], found[2])
			}
		}
	}
	for _, enum := range []string{"AvailableMethods", "AvailableClashAPIMethods", "CureMethods"} {
		if len(enums[enum]) == 0 {
			t.Fatalf("the enum %s of the page was not read (bundle: %v)", enum, fromBundle)
		}
	}
	resolve := func(reference string) (string, string, bool) {
		found := enumReference.FindStringSubmatch(reference)
		if found == nil {
			return "", "", false
		}
		value, known := enums[found[1]][found[2]]
		if !known {
			t.Errorf("the page names %s, which its enums do not have", reference)
		}
		return found[1], value, known
	}
	defaults := defaultCommand.FindStringSubmatch(whole)
	if defaults == nil {
		t.Fatalf("the default program of callBaseMethod was not read (bundle: %v)", fromBundle)
	}
	var result page
	for at := 0; ; {
		found := strings.Index(whole[at:], "callBaseMethod")
		if found < 0 {
			break
		}
		start := at + found
		at = start + len("callBaseMethod")
		open := skipTypeArguments(whole, at)
		if open >= len(whole) || whole[open] != '(' {
			continue
		}
		arguments, end, closed := callArguments(whole, open)
		if !closed {
			t.Fatalf("a call of callBaseMethod does not end: %.80s", whole[start:])
		}
		at = end
		if len(arguments) == 0 {
			continue
		}
		enum, command, known := resolve(arguments[0])
		if enum != "AvailableMethods" || !known {
			// the definition of callBaseMethod, or a call by a value it is passed
			continue
		}
		properties := asyncProperty.FindAllStringSubmatch(whole[:start], -1)
		if len(properties) == 0 {
			t.Fatalf("a call of callBaseMethod outside a method: %.80s", whole[start:])
		}
		call := pageCall{method: properties[len(properties)-1][1], program: defaults[1], command: command}
		if len(arguments) > 1 && strings.HasPrefix(arguments[1], "[") {
			elements, _, _ := callArguments(arguments[1], 0)
			if len(elements) > 0 {
				if enum, action, known := resolve(elements[0]); known && enum == "AvailableClashAPIMethods" {
					call.action = action
				}
			}
		}
		if len(arguments) > 2 {
			literal := quoted.FindStringSubmatch(arguments[2])
			if literal == nil {
				t.Fatalf("%s runs a program that is no literal: %s", call.method, arguments[2])
			}
			call.program = literal[1]
		}
		if call.command == "clash_api" && call.action == "" {
			t.Errorf("%s runs clash_api with no action the test can read", call.method)
		}
		result.calls = append(result.calls, call)
	}
	slices.SortFunc(result.calls, func(a, b pageCall) int { return strings.Compare(a.method, b.method) })
	for _, found := range declaration.FindAllStringSubmatch(whole, -1) {
		method := found[2]
		if method == "" {
			_, value, known := resolve("Podkop." + found[3] + "." + found[4])
			if !known {
				continue
			}
			method = value
		}
		if call := found[1] + " " + method; !slices.Contains(result.declared, call) {
			result.declared = append(result.declared, call)
		}
	}
	slices.Sort(result.declared)
	if len(result.declared) < 5 {
		t.Fatalf("only %d declarations of ubus methods were read (bundle: %v)", len(result.declared), fromBundle)
	}
	return result
}

// pageUses are the methods of methods/shell the page calls: in its sources but methods/shell
// itself, and in its views (main.js, the bundle, left out).
func pageUses(t *testing.T) map[string]bool {
	used := make(map[string]bool)
	texts := pageFiles(t, pageSources, ".ts", "podkop/methods/shell/index.ts")
	texts = append(texts, pageFiles(t, pageViews, ".js", "main.js")...)
	for _, text := range texts {
		for _, found := range shellUse.FindAllStringSubmatch(text, -1) {
			used[found[1]] = true
		}
	}
	return used
}

// viewsContain tells whether a view of the page (main.js left out) has the text.
func viewsContain(t *testing.T, text string) bool {
	for _, content := range pageFiles(t, pageViews, ".js", "main.js") {
		if strings.Contains(content, text) {
			return true
		}
	}
	return false
}

// pageFiles are the texts of the files of a directory of the repository with the suffix, but the
// tests (a directory "tests", a name with ".test.") and the paths left out (from the directory).
func pageFiles(t *testing.T, directory string, suffix string, leftOut ...string) []string {
	var texts []string
	root := filepath.Join(repository, directory)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "tests" || entry.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if !strings.HasSuffix(path, suffix) || strings.Contains(entry.Name(), ".test.") || slices.Contains(leftOut, filepath.ToSlash(name)) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		texts = append(texts, string(content))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(texts) == 0 {
		t.Fatalf("no file %s in %s", suffix, directory)
	}
	return texts
}

func readText(t *testing.T, path string) string {
	content, err := os.ReadFile(filepath.Join(repository, path))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

// skipTypeArguments is where the text goes on after type arguments (<...>) at, and spaces.
func skipTypeArguments(text string, at int) int {
	if at < len(text) && text[at] == '<' {
		depth := 0
		for ; at < len(text); at++ {
			if text[at] == '<' {
				depth++
			} else if text[at] == '>' {
				depth--
				if depth == 0 {
					at++
					break
				}
			}
		}
	}
	for at < len(text) && (text[at] == ' ' || text[at] == '\n' || text[at] == '\t') {
		at++
	}
	return at
}

// callArguments are the arguments of a call (or the elements of a list) whose bracket is at
// open, trimmed, and where it closes: commas inside brackets, strings and comments do not count,
// and comments are left out of the arguments.
func callArguments(text string, open int) ([]string, int, bool) {
	var arguments []string
	var current strings.Builder
	depth := 0
	for at := open; at < len(text); at++ {
		character := text[at]
		switch {
		case strings.HasPrefix(text[at:], "//"):
			for at < len(text) && text[at] != '\n' {
				at++
			}
			continue
		case strings.HasPrefix(text[at:], "/*"):
			end := strings.Index(text[at:], "*/")
			if end < 0 {
				return nil, 0, false
			}
			at += end + 1
			continue
		case character == '\'' || character == '"' || character == '`':
			end := at + 1
			for end < len(text) && text[end] != character {
				if text[end] == '\\' {
					end++
				}
				end++
			}
			current.WriteString(text[at:min(end+1, len(text))])
			at = end
			continue
		case character == '(' || character == '[' || character == '{':
			depth++
			if depth == 1 {
				continue
			}
		case character == ')' || character == ']' || character == '}':
			depth--
			if depth == 0 {
				if argument := strings.TrimSpace(current.String()); argument != "" {
					arguments = append(arguments, argument)
				}
				return arguments, at, true
			}
		case character == ',' && depth == 1:
			arguments = append(arguments, strings.TrimSpace(current.String()))
			current.Reset()
			continue
		}
		current.WriteByte(character)
	}
	return nil, 0, false
}

// initActions are the actions of the script of the service: those of rc.common, and its
// EXTRA_COMMANDS.
func initActions(t *testing.T) []string {
	script := readText(t, initScript)
	if !strings.HasPrefix(script, "#!/bin/sh /etc/rc.common\n") {
		t.Fatalf("%s is no script of rc.common: the test does not know its actions", initScript)
	}
	actions := slices.Clone(rcCommonActions)
	for _, line := range strings.Split(script, "\n") {
		if extra, found := strings.CutPrefix(line, "EXTRA_COMMANDS="); found {
			actions = append(actions, strings.Fields(strings.Trim(extra, `"'`))...)
		}
	}
	return actions
}

// acl is what the ACL of the page grants: the methods of ubus as "object method", read or
// write, and the files with what may be done with them.
type acl struct {
	ubus  map[string]bool
	files map[string][]string
}

func readACL(t *testing.T) acl {
	var groups map[string]struct {
		Read struct {
			File map[string][]string `json:"file"`
			Ubus map[string][]string `json:"ubus"`
		} `json:"read"`
		Write struct {
			File map[string][]string `json:"file"`
			Ubus map[string][]string `json:"ubus"`
		} `json:"write"`
	}
	if err := json.Unmarshal([]byte(readText(t, pageACL)), &groups); err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("the ACL has %d groups, the test knows one", len(groups))
	}
	result := acl{ubus: make(map[string]bool), files: make(map[string][]string)}
	for _, group := range groups {
		for _, ubus := range []map[string][]string{group.Read.Ubus, group.Write.Ubus} {
			for object, methods := range ubus {
				for _, method := range methods {
					result.ubus[object+" "+method] = true
				}
			}
		}
		for _, files := range []map[string][]string{group.Read.File, group.Write.File} {
			for path, rights := range files {
				result.files[path] = append(result.files[path], rights...)
			}
		}
	}
	return result
}
