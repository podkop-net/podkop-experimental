package plan_test

// The golden corpus of the planner. A case is settings, the facts of the router and the servers of
// the subscriptions. It goes through what the supervisor does with them before sing-box runs
// (supervisor.prepare: a settings file of an older format converted as migrate.File converts it,
// read by model.Load, given the key of the Clash API the supervisor writes, built by plan.Build with
// the options of the daemon), and what comes out is compared byte for byte with what was recorded
// of it. The order of the output is what the users get (route rules are matched in order), and a
// hot swap compares configurations byte for byte (supervisor/hot.go): a refactoring of the planner,
// of the intent of the dataplane or of the supervisor passes these cases unchanged.
//
// The cases are in testdata/golden/<case>/: settings of the format of this version, made for the
// corpus, named by what they cover; a case named refused-* is settings the planner refuses.
//
// The files of a case: podkop.uci (the settings), facts.json (goldenFacts), servers.json (the
// servers of the subscriptions by their source, in the order of the list), files/<path> (the files
// of the router the settings name: local lists); the rest is what was built of them: settings.uci and migrate.txt (the converted settings and the notes
// of the conversion), config.json, rulesets/<file> (the rule-set files of the plan, which are in
// plan.DefaultRuleSetDir), intent.json (the dataplane: plan.Dataplane), tags.json (the tags of the
// outbounds, what sing-box may swap, the rule sets, the links), warnings.txt, or error.txt when the
// settings are refused.
//
//	go test ./plan/ -run TestGolden -args -update
//
// records what is built now; the commit of an update says why each difference is wanted. With the
// tags of the engine's protocols (golden_engine_test.go), sing-box builds the configuration of every
// case as the supervisor has it built before a start.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/migrate"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/probe"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	"github.com/podkop-net/podkop-experimental/src/backend/yacd"
)

var update = flag.Bool("update", false, "TestGolden: record what is built now as the output of every case")

const (
	curatedDir = "testdata/golden"
	// below the number of cases there are: a run that finds a handful has lost its test data
	fewestCurated = 30
)

// The files of a case: its inputs, and what is built of them.
const (
	inSettings   = "podkop.uci"
	inFacts      = "facts.json"
	inServers    = "servers.json"
	inFiles      = "files/"
	outConverted = "settings.uci"
	outMigrate   = "migrate.txt"
	outConfig    = "config.json"
	outRuleSets  = "rulesets/"
	outIntent    = "intent.json"
	outTags      = "tags.json"
	outWarnings  = "warnings.txt"
	outError     = "error.txt"
)

func isInput(name string) bool {
	return name == inSettings || name == inFacts || name == inServers || strings.HasPrefix(name, inFiles)
}

// goldenExcluded are the cases left out of the corpus, by name, with the reason: a build that is
// not a function of its input, or a fault of the code under test, found when the corpus was
// recorded. None so far.
var goldenExcluded = map[string]string{}

// daemonDownloadURL is the download test URL the daemon gives the supervisor (cmd/podkop/daemon.go,
// downloadURL): the URL tests of the rules that leave the download check at its default have it.
const daemonDownloadURL = "https://speed.cloudflare.com/__down?bytes=65536"

// goldenFacts are what the supervisor learns of the router for a build (plan.Facts), and the key
// of the Clash API it writes into settings that have none (supervisor clashKey).
type goldenFacts struct {
	// LANAddress, Devices and NTPServerNames are those of plan.Facts: the address of the LAN, the
	// devices of the interface names, the names of the NTP servers of the router
	LANAddress     string            `json:"lan_address,omitempty"`
	Devices        map[string]string `json:"devices,omitempty"`
	NTPServerNames []string          `json:"ntp_server_names,omitempty"`
	// Users are the users of the router by name: the supervisor looks up those of
	// bittorrent_router_users (plan.Facts.UserIDs)
	Users map[string]uint32 `json:"users,omitempty"`
	// IPv6 tells that the router has the address ::1 (System.IPv6): plan.Facts.IPv6 when the
	// settings send IPv6 through podkop
	IPv6 bool `json:"ipv6,omitempty"`
	// ClashSecret is the key the supervisor writes into settings that have none
	ClashSecret string `json:"clash_secret,omitempty"`
}

// plan are the facts the supervisor builds the settings with (supervisor.prepare).
func (f goldenFacts) plan(settings *model.Config) plan.Facts {
	facts := plan.Facts{LANAddress: f.LANAddress, Devices: f.Devices, NTPServerNames: f.NTPServerNames,
		IPv6: settings.Settings.IPv6Routing == model.IPv6Podkop && f.IPv6}
	// supervisor userIDs: the users of the settings the router has
	for _, name := range settings.Settings.BitTorrentRouterUsers {
		if id, found := f.Users[name]; found {
			if facts.UserIDs == nil {
				facts.UserIDs = make(map[string]uint32)
			}
			facts.UserIDs[name] = id
		}
	}
	return facts
}

// goldenServer is a server of a subscription as the supervisor gives it to the builder
// (plan.SubscriptionServer).
type goldenServer struct {
	Name string `json:"name"`
	Link string `json:"link"`
}

// goldenCase is a case: its files by their paths in it, inputs and outputs.
type goldenCase struct {
	name  string
	files map[string][]byte
}

// outputs are the files of the case that were built.
func (c *goldenCase) outputs() map[string][]byte {
	outputs := make(map[string][]byte)
	for name, content := range c.files {
		if !isInput(name) {
			outputs[name] = content
		}
	}
	return outputs
}

// readFile reads a file of the router: one of files/ of the case.
func (c *goldenCase) readFile(name string) ([]byte, error) {
	content, found := c.files[inFiles+strings.TrimPrefix(path.Clean("/"+name), "/")]
	if !found {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return content, nil
}

// options are those the supervisor builds with (supervisor.prepare): the daemon has the check names
// of probe, the download test URL and the dashboard of yacd, and the servers are those of the lists
// of the subscriptions taken last. The local lists are the files of the case.
func (c *goldenCase) options(servers map[string][]plan.SubscriptionServer, ruleSetDir string, localPath func(string) string) plan.Options {
	return plan.Options{RuleSetDir: ruleSetDir, ReadFile: c.readFile, CheckList: engine.CheckRuleSet, LocalPath: localPath,
		DecodeLink: engine.DecodeLink, DownloadURL: daemonDownloadURL, ExternalUI: yacd.ServedDir, Servers: servers,
		CheckNames: plan.CheckNames{Suffix: probe.Suffix, DeadEndAddress: probe.DeadEndAddress, DeadEndPort: probe.DeadEndPort}}
}

// reading is a case read as the supervisor reads it.
type reading struct {
	settings *model.Config
	facts    plan.Facts
	servers  map[string][]plan.SubscriptionServer
	// outputs of the reading: the converted settings and the notes of the conversion, or the
	// refusal of the settings (no settings then)
	outputs map[string][]byte
}

// readCase reads a case as supervisor.prepare reads the settings file. An error is test data that
// cannot be read.
func readCase(c *goldenCase) (*reading, error) {
	result := &reading{outputs: make(map[string][]byte)}
	var known goldenFacts
	if err := decodeStrict(c.files[inFacts], &known); err != nil {
		return nil, fmt.Errorf("%s: %w", inFacts, err)
	}
	if content, found := c.files[inServers]; found {
		var lists map[string][]goldenServer
		if err := decodeStrict(content, &lists); err != nil {
			return nil, fmt.Errorf("%s: %w", inServers, err)
		}
		result.servers = make(map[string][]plan.SubscriptionServer, len(lists))
		for name, list := range lists {
			for _, server := range list {
				result.servers[name] = append(result.servers[name], plan.SubscriptionServer{Name: server.Name, Link: server.Link})
			}
		}
	}
	content, found := c.files[inSettings]
	if !found {
		return nil, errors.New("the case has no " + inSettings)
	}
	parsed, err := uci.Parse(content)
	if err != nil {
		result.outputs[outError] = textLines("read the settings: " + err.Error())
		return result, nil
	}
	// a file of an older format is converted on the disk before it is read (migrate.File)
	if migrate.Needed(parsed) {
		notes := migrate.Convert(parsed)
		content = parsed.Format()
		result.outputs[outConverted] = content
		result.outputs[outMigrate] = textLines(notes...)
		if parsed, err = uci.Parse(content); err != nil {
			result.outputs[outError] = textLines("read the converted settings: " + err.Error())
			return result, nil
		}
	}
	settings, err := model.Load(parsed)
	if err != nil {
		result.outputs[outError] = textLines("read the settings: " + err.Error())
		return result, nil
	}
	if settings.Settings.YACDSecretKey == "" {
		settings.Settings.YACDSecretKey = known.ClashSecret
	}
	result.settings = settings
	result.facts = known.plan(settings)
	return result, nil
}

// build builds a case as the supervisor does and returns its outputs by their paths in the case.
// An error is test data that cannot be read, or a fault of the code under test.
func build(c *goldenCase) (outputs map[string][]byte, err error) {
	defer func() {
		if fault := recover(); fault != nil {
			outputs, err = nil, fmt.Errorf("a fault while the case was built: %v\n%s", fault, debug.Stack())
		}
	}()
	read, err := readCase(c)
	if err != nil {
		return nil, err
	}
	outputs = read.outputs
	if read.settings == nil {
		return outputs, nil
	}
	result, err := plan.Build(read.settings, read.facts, c.options(read.servers, plan.DefaultRuleSetDir, nil))
	if err != nil {
		outputs[outError] = textLines(err.Error())
		return outputs, nil
	}
	outputs[outConfig] = result.Config
	for name, content := range result.Files {
		file, inside := strings.CutPrefix(name, plan.DefaultRuleSetDir+"/")
		if !inside || file == "" || strings.Contains(file, "/") {
			return nil, fmt.Errorf("a rule-set file outside %s: %s", plan.DefaultRuleSetDir, name)
		}
		outputs[outRuleSets+file] = content
	}
	outputs[outIntent] = encode(intentOf(result.Dataplane))
	outputs[outTags] = encode(tagsOf(read.settings, result))
	outputs[outWarnings] = textLines(result.Warnings...)
	return outputs, nil
}

// goldenIntent is plan.Dataplane field by field: what the router needs around the configuration
// (the firewall, the DNS of the LAN, the Clash API). A refactoring that moves the fields keeps the
// file.
type goldenIntent struct {
	Interfaces            []string  `json:"interfaces"`
	ExcludeNTP            bool      `json:"exclude_ntp"`
	Sources               []string  `json:"sources"`
	TakeDNS               bool      `json:"take_dns"`
	ClashAPI              string    `json:"clash_api"`
	ClashSecret           string    `json:"clash_secret"`
	ClashAPIInterfaces    []string  `json:"clash_api_interfaces"`
	BitTorrent            string    `json:"bittorrent"`
	BitTorrentLAN         bool      `json:"bittorrent_lan"`
	BitTorrentFan         goldenFan `json:"bittorrent_fan"`
	BitTorrentRouterUsers []uint32  `json:"bittorrent_router_users"`
	OwnMarks              []uint32  `json:"own_marks"`
	IPv6                  bool      `json:"ipv6"`
}

// goldenFan is dataplane.Fan with its durations as text.
type goldenFan struct {
	Burst   uint32 `json:"burst"`
	Rate    uint64 `json:"rate"`
	Unit    uint64 `json:"unit"`
	Pair    string `json:"pair"`
	Suspect string `json:"suspect"`
}

func intentOf(intent plan.Dataplane) goldenIntent {
	sources := []string{}
	for _, prefix := range intent.Sources {
		sources = append(sources, prefix.String())
	}
	fan := intent.BitTorrentFan
	return goldenIntent{
		Interfaces:            orEmpty(intent.Interfaces),
		ExcludeNTP:            intent.ExcludeNTP,
		Sources:               sources,
		TakeDNS:               intent.TakeDNS,
		ClashAPI:              intent.ClashAPI,
		ClashSecret:           intent.ClashSecret,
		ClashAPIInterfaces:    orEmpty(intent.ClashAPIInterfaces),
		BitTorrent:            intent.BitTorrent,
		BitTorrentLAN:         intent.BitTorrentLAN,
		BitTorrentFan:         goldenFan{Burst: fan.Burst, Rate: fan.Rate, Unit: fan.Unit, Pair: fan.Pair.String(), Suspect: fan.Suspect.String()},
		BitTorrentRouterUsers: orEmpty(intent.BitTorrentRouterUsers),
		OwnMarks:              orEmpty(intent.OwnMarks),
		IPv6:                  intent.IPv6,
	}
}

// goldenTags is the rest of plan.Result: what the outbounds are (plan.Tags, with the stable
// identities of the servers, which plan.TagOf does not serialize), what sing-box may swap while it
// runs, the tags of older releases and the choices of the dashboard carried over from them
// (plan.Adoptions at a start), the outbounds kept off the downloads (plan.NoDownloads), the rule
// sets, the links and the order of the rule-set files. Routes is model.Config.Routes: settings
// without a rule that routes are not built by the supervisor at all (errNothingToRoute).
type goldenTags struct {
	Routes      bool                   `json:"routes"`
	Rules       map[string]goldenRule  `json:"rules"`
	Outbounds   map[string]goldenOwner `json:"outbounds"`
	Swappable   []string               `json:"swappable"`
	Legacy      map[string]string      `json:"legacy"`
	Selectors   map[string]string      `json:"adopted_selectors"`
	Members     map[string]string      `json:"adopted_members"`
	NoDownloads []string               `json:"no_downloads"`
	RuleSets    []goldenRuleSet        `json:"rule_sets"`
	Links       []goldenLink           `json:"links"`
	FileOrder   []string               `json:"file_order"`
}

type goldenRule struct {
	Name     string `json:"name"`
	Selector string `json:"selector"`
	Test     string `json:"test,omitempty"`
}

type goldenOwner struct {
	Rule       string `json:"rule,omitempty"`
	Fallback   int    `json:"fallback,omitempty"`
	Source     string `json:"source,omitempty"`
	Server     string `json:"server,omitempty"`
	Via        string `json:"via,omitempty"`
	StableHash string `json:"stable_hash,omitempty"`
}

type goldenRuleSet struct {
	Tag    string `json:"tag"`
	Path   string `json:"path,omitempty"`
	URL    string `json:"url,omitempty"`
	Format string `json:"format"`
}

type goldenLink struct {
	Section string `json:"section"`
	Name    string `json:"name"`
	Tag     string `json:"tag"`
	Text    string `json:"text"`
}

func tagsOf(settings *model.Config, result *plan.Result) goldenTags {
	tags := goldenTags{
		Routes:      settings.Routes(),
		Rules:       make(map[string]goldenRule),
		Outbounds:   make(map[string]goldenOwner),
		Swappable:   []string{},
		Legacy:      make(map[string]string),
		NoDownloads: orEmpty(plan.NoDownloads(settings, result.Tags)),
		RuleSets:    []goldenRuleSet{},
		Links:       []goldenLink{},
		FileOrder:   orEmpty(result.FileOrder),
	}
	for section, rule := range result.Tags.Rules {
		tags.Rules[section] = goldenRule{Name: rule.Name, Selector: rule.Selector, Test: rule.Test}
	}
	for tag, owner := range result.Tags.Outbounds {
		tags.Outbounds[tag] = goldenOwner{Rule: owner.Rule, Fallback: owner.Fallback, Source: owner.Source, Server: owner.Server, Via: owner.Via, StableHash: owner.StableHash}
	}
	for tag, swappable := range result.Swappable {
		if swappable {
			tags.Swappable = append(tags.Swappable, tag)
		}
	}
	sort.Strings(tags.Swappable)
	for old, now := range result.Legacy {
		tags.Legacy[old] = now
	}
	tags.Selectors, tags.Members = plan.Adoptions(result, nil)
	for _, ruleSet := range result.RuleSets {
		tags.RuleSets = append(tags.RuleSets, goldenRuleSet{Tag: ruleSet.Tag, Path: ruleSet.Path, URL: ruleSet.URL, Format: ruleSet.Format})
	}
	for _, link := range result.Links {
		tags.Links = append(tags.Links, goldenLink{Section: link.Section, Name: link.Name, Tag: link.Tag, Text: link.Text})
	}
	return tags
}

// The golden files carry every field of what a build gives (but plan.Result.Facts, which are its
// input): a field added to these types is to be mapped by goldenIntent or goldenTags.
func TestGoldenMapsTheResult(t *testing.T) {
	for _, known := range []struct {
		value  any
		fields int
	}{
		{plan.Result{}, 11}, {plan.Dataplane{}, 13}, {dataplane.Fan{}, 5}, {plan.Tags{}, 2}, {plan.RuleTags{}, 3}, {plan.TagOf{}, 6},
		{plan.RuleSet{}, 4}, {plan.Link{}, 4},
	} {
		if fields := reflect.TypeOf(known.value).NumField(); fields != known.fields {
			t.Errorf("%T has %d fields, the golden files map %d: map the new ones (golden_test.go)", known.value, fields, known.fields)
		}
	}
}

// goldenSummary counts what the cases gave.
type goldenSummary struct {
	cases, refused, excluded, checked, unchecked int
}

func TestGolden(t *testing.T) {
	curated := curatedCases(t)
	if len(curated) < fewestCurated {
		t.Fatalf("%d curated cases found, at least %d expected", len(curated), fewestCurated)
	}
	var summary goldenSummary
	for _, c := range curated {
		t.Run("curated/"+c.name, func(t *testing.T) { runGolden(t, c, &summary) })
	}
	t.Logf("golden summary: %d cases, %d refused, %d excluded; checked by sing-box %d, not by this build %d",
		summary.cases, summary.refused, summary.excluded, summary.checked, summary.unchecked)
}

// goldenEngineCheck has sing-box build the configuration of a case (golden_engine_test.go): it
// tells whether it did, and why sing-box refuses the configuration; nil without the tags of the
// engine's protocols.
var goldenEngineCheck func(t *testing.T, c *goldenCase) (checked bool, refusal error)

func runGolden(t *testing.T, c *goldenCase, summary *goldenSummary) {
	if reason, excluded := goldenExcluded[c.name]; excluded {
		summary.excluded++
		t.Skip("excluded: " + reason)
	}
	summary.cases++
	built, err := build(c)
	if err != nil {
		t.Fatal(err)
	}
	again, err := build(c)
	if err != nil {
		t.Fatal(err)
	}
	if diff := differences(built, again); diff != "" {
		t.Fatalf("%s: two builds of the case differ: the output is not a function of the input\n%s", c.name, diff)
	}
	_, refused := built[outError]
	if refused {
		summary.refused++
	}
	if refused != strings.HasPrefix(c.name, "refused-") {
		t.Errorf("refused %v: a curated case is refused when its name begins with refused-, and only then (%s)", refused, bytes.TrimSpace(built[outError]))
	}
	if *update {
		record(t, c, built)
	} else if diff := differences(c.outputs(), built); diff != "" {
		t.Errorf("%s: what is built differs from what was recorded (go test ./plan/ -run TestGolden -args -update records it; its commit says why)\n%s", c.name, diff)
	}
	if !refused && goldenEngineCheck != nil {
		checked, refusal := goldenEngineCheck(t, c)
		switch {
		case !checked:
			summary.unchecked++
		case refusal == nil:
			summary.checked++
		default:
			summary.checked++
			t.Errorf("sing-box does not take the configuration: %v", refusal)
		}
	}
}

// record puts what was built in the place of the outputs of the case, in its directory.
func record(t *testing.T, c *goldenCase, built map[string][]byte) {
	old := c.outputs()
	root := filepath.Join(curatedDir, c.name)
	for name := range old {
		if _, kept := built[name]; !kept {
			if err := os.Remove(filepath.Join(root, filepath.FromSlash(name))); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, content := range built {
		if previous, found := old[name]; found && bytes.Equal(previous, content) {
			continue
		}
		file := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// the directory of the rule-set files goes when the build makes none any more
	_ = os.Remove(filepath.Join(root, strings.TrimSuffix(outRuleSets, "/")))
}

// curatedCases are the cases of testdata/golden, by name.
func curatedCases(t *testing.T) []*goldenCase {
	entries, err := os.ReadDir(curatedDir)
	if err != nil {
		t.Fatal(err)
	}
	var cases []*goldenCase
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		c := &goldenCase{name: entry.Name(), files: make(map[string][]byte)}
		root := filepath.Join(curatedDir, entry.Name())
		err := filepath.WalkDir(root, func(name string, file fs.DirEntry, err error) error {
			if err != nil || file.IsDir() {
				return err
			}
			relative, err := filepath.Rel(root, name)
			if err != nil {
				return err
			}
			content, err := os.ReadFile(name)
			c.files[filepath.ToSlash(relative)] = content
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, c)
	}
	return cases
}

// differences tells how two sets of outputs differ: a file in one of them only, and the first
// lines that differ of the first few files that differ; nothing when they are the same.
func differences(want map[string][]byte, got map[string][]byte) string {
	var names []string
	for name := range want {
		names = append(names, name)
	}
	for name := range got {
		if _, found := want[name]; !found {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var report strings.Builder
	shown := 0
	for _, name := range names {
		wantContent, inWant := want[name]
		gotContent, inGot := got[name]
		switch {
		case !inGot:
			fmt.Fprintf(&report, "%s: recorded, not built now\n", name)
		case !inWant:
			fmt.Fprintf(&report, "%s: built now, not recorded\n", name)
			writeSome(&report, "+", strings.Split(strings.TrimSuffix(string(gotContent), "\n"), "\n"))
		case bytes.Equal(wantContent, gotContent):
		case shown < 3:
			shown++
			report.WriteString(lineDiff(name, wantContent, gotContent))
		default:
			fmt.Fprintf(&report, "%s: differs\n", name)
		}
	}
	return report.String()
}

// lineDiff shows where two texts part: from the first line that differs to the last one, a few
// lines of each at most, after two lines they have in common.
func lineDiff(name string, want []byte, got []byte) string {
	wantLines := strings.Split(string(want), "\n")
	gotLines := strings.Split(string(got), "\n")
	start := 0
	for start < len(wantLines) && start < len(gotLines) && wantLines[start] == gotLines[start] {
		start++
	}
	wantEnd, gotEnd := len(wantLines), len(gotLines)
	for wantEnd > start && gotEnd > start && wantLines[wantEnd-1] == gotLines[gotEnd-1] {
		wantEnd--
		gotEnd--
	}
	var report strings.Builder
	fmt.Fprintf(&report, "%s: from line %d (- recorded, + built now):\n", name, start+1)
	for index := max(0, start-2); index < start; index++ {
		fmt.Fprintf(&report, "  %s\n", wantLines[index])
	}
	writeSome(&report, "-", wantLines[start:wantEnd])
	writeSome(&report, "+", gotLines[start:gotEnd])
	return report.String()
}

func writeSome(report *strings.Builder, mark string, lines []string) {
	const most = 12
	for index, line := range lines {
		if index == most {
			fmt.Fprintf(report, "%s ... %d more lines\n", mark, len(lines)-most)
			return
		}
		fmt.Fprintf(report, "%s %s\n", mark, line)
	}
}

// encode is JSON the way the golden files have it: indented, the keys of maps sorted, without the
// escapes of HTML.
func encode(value any) []byte {
	var content bytes.Buffer
	encoder := json.NewEncoder(&content)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		panic(err)
	}
	return content.Bytes()
}

func decodeStrict(content []byte, value any) error {
	if content == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

// textLines is lines of text, each ended.
func textLines(lines ...string) []byte {
	var text bytes.Buffer
	for _, line := range lines {
		text.WriteString(line)
		text.WriteByte('\n')
	}
	return text.Bytes()
}

func orEmpty[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}
