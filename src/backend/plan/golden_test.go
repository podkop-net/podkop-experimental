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
// The cases:
//   - testdata/golden/<case>/: settings of the format of this version, made for the corpus, named by
//     what they cover; a case named refused-* is settings the planner refuses;
//   - testdata/golden-shell07.tar.gz: the settings of podkop 0.7 its shell backend was run with
//     (render/testdata/cases.tar.gz: their inputs, and "refused" where the shell backend refused
//     them), converted and built as a router that upgraded from 0.7 builds them.
//
// The files of a case: podkop.uci (the settings), facts.json (goldenFacts), servers.json (the
// servers of the subscriptions by their source, in the order of the list), files/<path> (the files
// of the router the settings name: local lists), refused (the message of the shell backend); the
// rest is what was built of them: settings.uci and migrate.txt (the converted settings and the notes
// of the conversion), config.json, rulesets/<file> (the rule-set files of the plan, which are in
// plan.DefaultRuleSetDir), intent.json (the dataplane: dataplane.Intent), tags.json (the tags of the
// outbounds, what sing-box may swap, the rule sets, the links), warnings.txt, or error.txt when the
// settings are refused.
//
//	go test ./plan/ -run TestGolden -args -update
//
// records what is built now; the commit of an update says why each difference is wanted. With the
// tags of the engine's protocols (golden_engine_test.go), sing-box builds the configuration of every
// curated case as the supervisor has it built before a start (GOLDEN_CHECK_ALL=1: of the cases of
// the shell backend too).

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"
	"testing"
	"time"

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
	// shellArchive holds the cases of the shell backend; shellOrigin is the archive of their
	// inputs (render.TestCases), read while shellArchive is not there yet
	shellArchive = "testdata/golden-shell07.tar.gz"
	shellOrigin  = "../render/testdata/cases.tar.gz"
	// below the numbers of cases there are: a run that finds a handful has lost its test data
	fewestCurated = 30
	fewestShell   = 590
)

// The files of a case: its inputs, and what is built of them.
const (
	inSettings   = "podkop.uci"
	inFacts      = "facts.json"
	inServers    = "servers.json"
	inFiles      = "files/"
	inRefused    = "refused"
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
	return name == inSettings || name == inFacts || name == inServers || name == inRefused || strings.HasPrefix(name, inFiles)
}

// goldenExcluded are the cases left out of the corpus, by name, with the reason: a build that is
// not a function of its input, or a fault of the code under test, found when the corpus was
// recorded. None so far.
var goldenExcluded = map[string]string{}

// shellRefusedNow are the cases of the shell backend whose settings the shell backend of podkop 0.7
// took and the planner refuses, with the reason.
var shellRefusedNow = map[string]string{
	"ed-mixed-same-port": "two mixed proxies on one port (plan/ledger.go, item 12): sing-box would fail on the second socket at every start",
}

// openWrtNTPServers are the NTP servers of the default settings of OpenWrt (system.ntp.server):
// the facts of the cases of the shell backend, which were run without them.
var openWrtNTPServers = []string{"0.openwrt.pool.ntp.org", "1.openwrt.pool.ntp.org", "2.openwrt.pool.ntp.org", "3.openwrt.pool.ntp.org"}

// goldenClashSecret is the key of the Clash API of the cases of the shell backend: the supervisor
// writes one into settings without one (clashKey: 16 random bytes in hex).
const goldenClashSecret = "00112233445566778899aabbccddeeff"

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

// goldenIntent is plan.Result.Dataplane (dataplane.Intent) field by field: what the router needs
// around the configuration (the firewall, the DNS of the LAN, the Clash API). A refactoring that
// moves the fields keeps the file.
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

func intentOf(intent dataplane.Intent) goldenIntent {
	sources := []string{}
	for _, prefix := range intent.Sources {
		sources = append(sources, prefix.String())
	}
	fan := intent.BitTorrent.Fan
	return goldenIntent{
		Interfaces:            orEmpty(intent.Interfaces),
		ExcludeNTP:            intent.ExcludeNTP,
		Sources:               sources,
		TakeDNS:               intent.TakeDNS,
		ClashAPI:              intent.ClashAPI,
		ClashSecret:           intent.ClashSecret,
		ClashAPIInterfaces:    orEmpty(intent.ClashAPIInterfaces),
		BitTorrent:            intent.BitTorrent.Mode,
		BitTorrentLAN:         intent.BitTorrent.LAN,
		BitTorrentFan:         goldenFan{Burst: fan.Burst, Rate: fan.Rate, Unit: fan.Unit, Pair: fan.Pair.String(), Suspect: fan.Suspect.String()},
		BitTorrentRouterUsers: orEmpty(intent.BitTorrent.RouterUsers),
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
		{plan.Result{}, 11}, {dataplane.Intent{}, 10}, {dataplane.BitTorrent{}, 4}, {dataplane.Fan{}, 5}, {plan.Tags{}, 2}, {plan.RuleTags{}, 3}, {plan.TagOf{}, 6},
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
	// refusedNow are the cases of the shell backend it took and the planner refuses, takenNow those
	// it refused and the planner takes, checkRefused those of takenNow whose configuration sing-box
	// refuses (GOLDEN_CHECK_ALL)
	refusedNow, takenNow, checkRefused []string
}

func TestGolden(t *testing.T) {
	curated := curatedCases(t)
	shell := shellCases(t)
	if len(curated) < fewestCurated || len(shell) < fewestShell {
		t.Fatalf("%d curated cases and %d of the shell backend found, at least %d and %d expected", len(curated), len(shell), fewestCurated, fewestShell)
	}
	var summary goldenSummary
	for _, c := range curated {
		t.Run("curated/"+c.name, func(t *testing.T) { runGolden(t, c, true, &summary) })
	}
	for _, c := range shell {
		t.Run("shell07/"+c.name, func(t *testing.T) { runGolden(t, c, false, &summary) })
	}
	t.Logf("golden summary: %d cases (%d curated, %d of the shell backend), %d refused, %d excluded; checked by sing-box %d, not by this build %d",
		summary.cases, len(curated), len(shell), summary.refused, summary.excluded, summary.checked, summary.unchecked)
	t.Logf("golden summary: refused now, taken by the shell backend (%d): %s", len(summary.refusedNow), strings.Join(summary.refusedNow, " "))
	t.Logf("golden summary: taken now, refused by the shell backend (%d): %s", len(summary.takenNow), strings.Join(summary.takenNow, " "))
	t.Logf("golden summary: of those, refused by the check of sing-box (%d): %s", len(summary.checkRefused), strings.Join(summary.checkRefused, " "))
	if *update {
		writeShellArchive(t, shell)
	}
}

// goldenEngineCheck has sing-box build the configuration of a case (golden_engine_test.go): it
// tells whether it did, and why sing-box refuses the configuration; nil without the tags of the
// engine's protocols.
var goldenEngineCheck func(t *testing.T, c *goldenCase) (checked bool, refusal error)

func runGolden(t *testing.T, c *goldenCase, curated bool, summary *goldenSummary) {
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
	if curated && refused != strings.HasPrefix(c.name, "refused-") {
		t.Errorf("refused %v: a curated case is refused when its name begins with refused-, and only then (%s)", refused, bytes.TrimSpace(built[outError]))
	}
	if !curated {
		_, shellRefused := c.files[inRefused]
		_, named := shellRefusedNow[c.name]
		switch {
		case refused && !shellRefused:
			summary.refusedNow = append(summary.refusedNow, c.name)
			if !named {
				t.Errorf("refused, the shell backend of podkop 0.7 took these settings: name the reason in shellRefusedNow (%s)", bytes.TrimSpace(built[outError]))
			}
		case !refused && shellRefused:
			summary.takenNow = append(summary.takenNow, c.name)
		}
		if named && !refused {
			t.Error("named in shellRefusedNow, and taken")
		}
	}
	if *update {
		record(t, c, built, curated)
	} else if diff := differences(c.outputs(), built); diff != "" {
		t.Errorf("%s: what is built differs from what was recorded (go test ./plan/ -run TestGolden -args -update records it; its commit says why)\n%s", c.name, diff)
	}
	if !refused && goldenEngineCheck != nil && (curated || os.Getenv("GOLDEN_CHECK_ALL") != "") {
		checked, refusal := goldenEngineCheck(t, c)
		_, shellRefused := c.files[inRefused]
		switch {
		case !checked:
			summary.unchecked++
		case refusal == nil:
			summary.checked++
		case !curated && shellRefused:
			// refused before a start by the check of the supervisor, as the shell backend refused them
			summary.checked++
			summary.checkRefused = append(summary.checkRefused, c.name)
		default:
			summary.checked++
			t.Errorf("sing-box does not take the configuration: %v", refusal)
		}
	}
}

// record puts what was built in the place of the outputs of the case: in its directory for a
// curated case, in the case for the archive of the shell backend (writeShellArchive).
func record(t *testing.T, c *goldenCase, built map[string][]byte, curated bool) {
	old := c.outputs()
	for name := range old {
		delete(c.files, name)
	}
	for name, content := range built {
		c.files[name] = content
	}
	if !curated {
		return
	}
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

// shellCases are the cases of the archive of the shell backend, by name; while there is none, the
// inputs of render's archive, for an update to record (shellFacts).
func shellCases(t *testing.T) []*goldenCase {
	entries, err := readArchive(shellArchive)
	origin := false
	if errors.Is(err, fs.ErrNotExist) && *update {
		entries, err = readArchive(shellOrigin)
		origin = true
	}
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]*goldenCase)
	for name, content := range entries {
		caseName, inside, found := strings.Cut(name, "/")
		if !found || caseName == "" || inside == "" {
			continue
		}
		if origin {
			switch {
			case inside == "want/refused":
				inside = inRefused
			case inside == inFacts:
				content, err = shellFacts(content)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
			case inside == inSettings || strings.HasPrefix(inside, inFiles):
			default:
				// what the shell backend wrote
				continue
			}
		}
		c := byName[caseName]
		if c == nil {
			c = &goldenCase{name: caseName, files: make(map[string][]byte)}
			byName[caseName] = c
		}
		c.files[inside] = content
	}
	var cases []*goldenCase
	for _, c := range byName {
		cases = append(cases, c)
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].name < cases[j].name })
	return cases
}

// shellFacts are the facts of a case of the shell backend: the address of the LAN it was run with,
// the NTP servers of OpenWrt's default settings, a key of the Clash API.
func shellFacts(content []byte) ([]byte, error) {
	var old struct {
		LANAddress string `json:"lan_address"`
	}
	if err := json.Unmarshal(content, &old); err != nil {
		return nil, err
	}
	return encode(goldenFacts{LANAddress: old.LANAddress, NTPServerNames: openWrtNTPServers, ClashSecret: goldenClashSecret}), nil
}

// writeShellArchive stores the cases of the shell backend; an archive of the same files stays as
// it is.
func writeShellArchive(t *testing.T, cases []*goldenCase) {
	entries := make(map[string][]byte)
	for _, c := range cases {
		for name, content := range c.files {
			entries[c.name+"/"+name] = content
		}
	}
	if existing, err := readArchive(shellArchive); err == nil && sameEntries(existing, entries) {
		return
	}
	content, err := packArchive(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shellArchive, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func sameEntries(left map[string][]byte, right map[string][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for name, content := range left {
		other, found := right[name]
		if !found || !bytes.Equal(content, other) {
			return false
		}
	}
	return true
}

// packArchive makes a tar.gz of the files in the order of their names, with nothing that changes
// from one update to the next.
func packArchive(entries map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	var packed bytes.Buffer
	compressed, err := gzip.NewWriterLevel(&packed, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	archive := tar.NewWriter(compressed)
	for _, name := range names {
		header := &tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(entries[name])), ModTime: time.Unix(0, 0)}
		if err := archive.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := archive.Write(entries[name]); err != nil {
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	if err := compressed.Close(); err != nil {
		return nil, err
	}
	return packed.Bytes(), nil
}

// readArchive returns the regular files of a tar.gz by their names.
func readArchive(name string) (map[string][]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	unpacked, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	archive := tar.NewReader(unpacked)
	entries := make(map[string][]byte)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		content, err := io.ReadAll(archive)
		if err != nil {
			return nil, err
		}
		entries[header.Name] = content
	}
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
