package ctl

import (
	"bytes"
	"encoding/json"
	"errors"
	flags "flag"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/btstats"
	"github.com/podkop-net/podkop-experimental/src/backend/diag"
	"github.com/podkop-net/podkop-experimental/src/backend/logbuf"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

// The answers of the commands recorded, those the page reads and those of "podkop device" above
// all: each command runs as the page's run runs it (Run, in the process), against a backend of
// fixed answers on a socket (the fake of ctl_test.go), a fake Clash API, and fixed settings
// (testdata/inputs). Each file of testdata/answers holds the command line, what the case is, the
// exit status, the standard output as it is and the error output; a file no case writes fails as
// well. A change of an answer is a change of what the page gets: a refactor keeps the files as they
// are, a change of an answer writes them anew in the commit that says why:
//
//	go test ./ctl -run TestRecordedAnswers -update
//
// The commands that need the kernel or the network (check_dns_available asks DNS servers,
// check_nft_rules reads the firewall over netlink, get_system_info the router's own files) are
// recorded as the answer they print to fixed findings (the compat shapes of answers.go), not run.
// get_sing_box_status and check_sing_box read the host (/etc/rc.d, /proc/net): they are not
// recorded on a host that has sing-box's autostart or listens where sing-box does. Left out:
// global_check (the kernel, the network and the system log; the page runs it as a program),
// check_nft (the nft program), hwid, show_system_info and yacd_builtin (the files of the host), the
// lines of subscription_update (told by the time that passed; TestSubscriptionCommands) and the
// reports of bittorrent_record (TestBitTorrentRecord). Besides what the page reads, the help, the
// failures and the actions of the CLI are recorded (recordActions). Each case of "podkop device" is
// also compared with the route rules of the configuration plan.Build makes of the same settings
// (compareWithPlan), but the one of settings it refuses.
var updateAnswers = flags.Bool("update", false, "write the recorded answers of testdata/answers anew")

const (
	answersDir = "testdata/answers"
	inputsDir  = "testdata/inputs"
)

// recorder runs the cases and compares their answers with the files, or writes them.
type recorder struct {
	t       *testing.T
	written map[string]bool
	// temporary is the directory of the test's temporary files, "<tmp>" in the answers
	temporary string
}

// record runs a command line and keeps what it answered under the name.
func (r *recorder) record(name string, about string, env Environment, arguments ...string) string {
	return r.recordWith(name, about, nil, env, arguments...)
}

// recordWith is record with what changes from run to run (the times of log lines) made fixed.
func (r *recorder) recordWith(name string, about string, normalize func(string) string, env Environment, arguments ...string) string {
	r.t.Helper()
	var output, errorOutput bytes.Buffer
	code := Run(env, arguments, &output, &errorOutput)
	stdout, stderr := output.String(), errorOutput.String()
	if normalize != nil {
		stdout, stderr = normalize(stdout), normalize(stderr)
	}
	stdout, stderr = strings.ReplaceAll(stdout, r.temporary, "<tmp>"), strings.ReplaceAll(stderr, r.temporary, "<tmp>")
	r.keep(name, "$ podkop "+strings.Join(arguments, " "), about, code, stdout, stderr)
	return stdout
}

// keep compares an answer with its file, or writes the file.
func (r *recorder) keep(name string, command string, about string, code int, stdout string, stderr string) {
	r.t.Helper()
	if r.written[name] {
		r.t.Fatalf("two cases are named %s", name)
	}
	r.written[name] = true
	text := command + "\n# " + about + "\nexit " + strconv.Itoa(code) + "\n--- stdout\n" + stdout
	if stderr != "" {
		text += "--- stderr\n" + stderr
	}
	path := filepath.Join(answersDir, name+".txt")
	if *updateAnswers {
		require.NoError(r.t, os.MkdirAll(answersDir, 0o755))
		require.NoError(r.t, os.WriteFile(path, []byte(text), 0o644))
		return
	}
	content, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		r.t.Errorf("%s: no recorded answer of %q: go test ./ctl -run TestRecordedAnswers -update", path, command)
		return
	}
	require.NoError(r.t, err)
	if string(content) != text {
		r.t.Errorf("%s: the answer of %q changed; if that is meant, write it anew (go test ./ctl -run TestRecordedAnswers -update) in a commit that says why\n--- recorded\n%s\n--- now\n%s", path, command, content, text)
	}
}

// finish fails for a file of answersDir no case wrote.
func (r *recorder) finish() {
	entries, err := os.ReadDir(answersDir)
	require.NoError(r.t, err)
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), ".txt")
		if !r.written[name] {
			if *updateAnswers {
				require.NoError(r.t, os.Remove(filepath.Join(answersDir, entry.Name())))
				continue
			}
			r.t.Errorf("%s/%s: no case records it: remove it", answersDir, entry.Name())
		}
	}
}

// encodeAnswer is an answer as Run prints it, indented as "pretty" does.
func encodeAnswer(t *testing.T, value any) string {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	require.NoError(t, encoder.Encode(value))
	return output.String()
}

// logTimes are the times at the start of the lines of the log, logLineTimes those at the start of
// its lines in JSON, runOfLog the run it is of.
var (
	logTimes     = regexp.MustCompile(`(?m)^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d `)
	logLineTimes = regexp.MustCompile(`"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d `)
	runOfLog     = regexp.MustCompile(`"run":"\w+"`)
)

func TestRecordedAnswers(t *testing.T) {
	directory := t.TempDir()
	r := &recorder{t: t, written: make(map[string]bool), temporary: filepath.Dir(directory)}
	autostart := filepath.Join(directory, "S99podkop")
	require.NoError(t, os.WriteFile(autostart, []byte("#!/bin/sh\n"), 0o755))
	msk := time.FixedZone("MSK", 3*60*60)
	at := func(hour, minute int) *time.Time {
		moment := time.Date(2026, 11, 23, hour, minute, 0, 0, msk)
		return &moment
	}

	// the Clash API of sing-box: a selector of a rule with its URL test, two servers of a source
	// (one does not answer its delay tests), the group's round
	clash := http.NewServeMux()
	clash.HandleFunc("GET /proxies", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte(`{"proxies":{` +
			`"main-out":{"type":"Selector","name":"main-out","now":"main-urltest-out","all":["main-urltest-out","own-1-out","own-2-out"],"history":[]},` +
			`"main-urltest-out":{"type":"URLTest","name":"main-urltest-out","now":"own-1-out","all":["own-1-out","own-2-out"],"history":[{"time":"2026-11-23T12:00:00+03:00","delay":120}]},` +
			`"own-1-out":{"type":"VLESS","name":"own-1-out","udp":true,"history":[{"time":"2026-11-23T12:00:00+03:00","delay":120}]},` +
			`"own-2-out":{"type":"Shadowsocks","name":"own-2-out","udp":true,"history":[]},` +
			`"direct-out":{"type":"Direct","name":"direct-out","udp":true,"history":[]}}}`))
	})
	clash.HandleFunc("GET /proxies/{tag}/delay", func(writer http.ResponseWriter, request *http.Request) {
		if request.PathValue("tag") == "own-2-out" {
			writer.WriteHeader(http.StatusServiceUnavailable)
			writer.Write([]byte(`{"message":"An error occurred in the delay test"}`))
			return
		}
		writer.Write([]byte(`{"delay":118}`))
	})
	clash.HandleFunc("GET /group/{tag}/delay", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte(`{"own-1-out":131}`))
	})
	clash.HandleFunc("PUT /proxies/{group}", func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		json.NewDecoder(request.Body).Decode(&body)
		switch {
		case request.PathValue("group") != "main-out":
			http.Error(writer, `{"message":"Resource not found"}`, http.StatusNotFound)
		case body.Name != "own-1-out" && body.Name != "own-2-out" && body.Name != "main-urltest-out":
			http.Error(writer, `{"message":"Selector update error: not found"}`, http.StatusBadRequest)
		default:
			writer.WriteHeader(http.StatusNoContent)
		}
	})
	upgradeFails := false
	clash.HandleFunc("POST /upgrade/ui", func(writer http.ResponseWriter, request *http.Request) {
		if upgradeFails {
			http.Error(writer, `{"message":"download external ui failed: 404 Not Found"}`, http.StatusInternalServerError)
			return
		}
		writer.Write([]byte(`{"status":"ok"}`))
	})
	server := httptest.NewServer(clash)
	defer server.Close()

	// the backend: the answers of its socket
	logs := logbuf.New(1 << 16)
	logs.Write("backend", "info", "podkop 0.8.22-test: the settings applied in 40 ms, sing-box runs the new configuration")
	logs.Write("backend", "warn", "rule main: the server own-2-out does not answer its delay test")
	logs.Write("sing-box", "error", "outbound/vless[own-2-out]: dial tcp 203.0.113.11:443: i/o timeout")
	fake := &backend{
		status: api.Status{Protocol: api.ProtocolVersion, Running: true, Since: time.Date(2026, 11, 23, 12, 3, 4, 123456789, msk),
			Last: api.Result{OK: true, Message: "applied in 40 ms, sing-box runs the new configuration"}, LastAt: time.Date(2026, 11, 23, 12, 3, 4, 163000000, msk)},
		facts: api.Facts{ClashAPI: server.Listener.Addr().String(), ClashSecret: "s3cret-key",
			Tags: json.RawMessage(`{"rules":{"main":{"name":"Main","selector":"main-out","test":"main-urltest-out"}},` +
				`"outbounds":{"main-out":{"rule":"main"},"main-urltest-out":{"rule":"main"},"own-1-out":{"source":"own","server":"NL 1"},"own-2-out":{"source":"own","server":"DE 2"}}}`)},
		states: []api.ListState{
			{Tag: "main-youtube-community-ruleset", Kind: "remote", URL: "https://github.com/itdoginfo/allow-domains/releases/latest/download/youtube.srs", Format: "binary", LastUpdated: at(11, 0)},
			{Tag: "main-user-domains-ruleset", Kind: "local", Path: "/tmp/podkop/rulesets/main-user-domains-ruleset.json", Format: "source"},
		},
		probe: api.ProbeResult{DNS: true, Connection: true, Client: "192.168.1.23", Address: "198.18.0.9"},
		subscriptions: []api.SubscriptionState{
			{Name: "prov1", Servers: 12, Usable: 10, Changed: at(9, 0), Checked: at(11, 0), Route: "direct", Attempted: at(11, 0), Took: 840,
				Attempts: []api.Attempt{{Route: "direct", Phase: "done", Took: 840, FirstByte: 310, Bytes: 5120}}, Next: at(17, 0),
				Provider: &subscription.ProviderInfo{Title: "Provider One", Upload: 1 << 30, Download: 3 << 30, Total: 100 << 30, Traffic: true, Expire: at(23, 59), UpdateHours: 6},
				Changes:  &subscription.ListChanges{Renamed: 1, Changed: 2, Added: 1, Fields: []string{"address"}}, Agent: "Happ/1.0", Preset: "custom", Headers: []string{"Authorization", "X-Device"},
				Format: "base64", Configs: 12, Now: at(12, 5)},
			{Name: "prov2", Error: "the provider answers 403 Forbidden", ErrorCode: "status", ErrorArgs: []string{"403"}, Attempted: at(11, 30), Took: 220,
				Attempts: []api.Attempt{{Route: "direct", Phase: "failed", Took: 220, Error: "403 Forbidden", Code: "status", Args: []string{"403"}}}, Next: at(12, 30), Busy: true, Now: at(12, 5)},
		},
		preview: api.SubscriptionPreview{Route: "direct", Took: 800, Attempts: []api.Attempt{{Route: "direct", Phase: "done", Took: 800}},
			Servers: []api.PreviewServer{
				{Name: "NL 1", Scheme: "vless", Address: "nl1.example:443", Link: "vless://b831381d-6324-4d53-ad4f-8cda48b30811@nl1.example:443?type=tcp#NL%201"},
				{Name: "XX", Scheme: "vmess", Link: "vmess://x", Reason: "the link cannot be read", Notes: []string{"kcp"}},
			}, Provider: &subscription.ProviderInfo{Title: "Provider One"}, Agent: "Happ/1.0", Preset: "custom", Format: "base64", Configs: 2},
		group: api.GroupPreview{Chosen: []string{"NL 1", "NL 2"}, Total: 12, Missing: []string{"prov3"}},
	}
	running := Environment{
		Version: "0.8.22-test", SingBoxVersion: "1.14.4-test", Engine: "podkop-engine r28 (test)", Features: PageFeatures,
		Socket:        serve(t, fake, logs),
		Paths:         diag.Paths{Settings: filepath.Join(inputsDir, "podkop"), DHCP: filepath.Join(inputsDir, "dhcp"), Network: filepath.Join(inputsDir, "network")},
		ConfigDir:     filepath.Join(inputsDir, "run"),
		AutostartPath: autostart,
		CheckLink: func(link string) error {
			switch {
			case strings.Contains(link, "type=kcp"):
				return errors.New("the mKCP transport is not supported")
			case strings.HasPrefix(link, "vmess://"):
				return errors.New("vmess is not included in this build, install podkop-engine-full")
			}
			return nil
		},
	}
	stopped := running
	stopped.Socket, stopped.AutostartPath = filepath.Join(directory, "none.sock"), filepath.Join(directory, "none")
	stopped.ConfigDir = filepath.Join(directory, "none")

	// the status of the dashboard and of the apply bar
	r.record("get_status-running", "the backend runs, sing-box runs since a time; the last change of the settings applied", running, "get_status")
	fake.status = api.Status{Protocol: api.ProtocolVersion, Since: time.Date(2026, 11, 23, 12, 0, 0, 0, msk),
		Last: api.Result{Message: "the settings cannot be used: rule a: mixed proxy port 2080 <taken> by rule b"}, LastAt: time.Date(2026, 11, 23, 12, 5, 0, 0, time.UTC)}
	r.record("get_status-refused", "the backend runs, sing-box does not: the settings were refused at the boot", running, "get_status")
	fake.status = api.Status{Protocol: api.ProtocolVersion, Running: true}
	r.record("get_status-no-result", "the backend runs and has no result yet", running, "get_status")
	r.record("get_status-stopped", "no backend answers, the service does not start at boot", stopped, "get_status")
	if executable(singBoxAutostartPath) {
		t.Logf("get_sing_box_status not recorded: %s is there on this host", singBoxAutostartPath)
		r.written["get_sing_box_status-running"], r.written["get_sing_box_status-stopped"] = true, true
	} else {
		r.record("get_sing_box_status-running", "the backend runs; dnsmasq asks the backend alone", running, "get_sing_box_status")
		r.record("get_sing_box_status-stopped", "no backend answers", stopped, "get_sing_box_status")
	}
	r.record("get_sing_box_features", "the names of the page's features (PageFeatures)", running, "get_sing_box_features")

	// the diagnostics
	if diag.CheckSingBox(false).Listening {
		t.Logf("check_sing_box not recorded: this host listens where sing-box does")
		r.written["check_sing_box-running"], r.written["check_sing_box-stopped"] = true, true
	} else {
		r.record("check_sing_box-running", "the backend tells that sing-box runs; nothing listens on this host (/proc/net)", running, "check_sing_box")
		r.record("check_sing_box-stopped", "no backend answers", stopped, "check_sing_box")
	}
	r.keep("check_dns_available", "$ podkop check_dns_available", "the answer to fixed findings (AnswerDNS): the command asks the DNS servers of the settings over the network",
		0, encodeAnswer(t, AnswerDNS(&diag.DNS{Type: "doh", Server: "dns.example", Bootstrap: "77.88.8.8", Mode: "fastest", ServerAnswers: true, RouterAnswers: true,
			BootstrapAnswers: false, DHCPAsksBackend: true, Upstreams: []diag.DNSUpstreamReport{{Type: "doh", Server: "dns.example", Answers: true},
				{Type: "udp", Server: "192.0.2.53", Refusal: "REFUSED"}, {Type: "provider", Server: "", Providers: []string{"192.0.2.1", "192.0.2.2"}, Answers: true}}})), "")
	r.keep("check_dns_available-none", "$ podkop check_dns_available", "the answer to fixed findings (AnswerDNS): nothing answers, no server in the settings",
		0, encodeAnswer(t, AnswerDNS(&diag.DNS{})), "")
	r.keep("check_nft_rules", "$ podkop check_nft_rules", "the answer to fixed findings (answerFirewall): the command reads the firewall of the kernel over netlink",
		0, encodeAnswer(t, answerFirewall(&diag.Firewall{Table: true, Mangle: true, MangleCounted: true, MangleOutput: true, Proxy: true, ProxyCounted: true, ForeignMarks: []string{"0x100"}})), "")
	r.keep("check_nft_rules-none", "$ podkop check_nft_rules", "the answer to fixed findings (answerFirewall): no table",
		0, encodeAnswer(t, answerFirewall(&diag.Firewall{})), "")
	r.keep("get_system_info", "$ podkop get_system_info", "the answer to fixed findings (answerSystem): the command reads the router's own files (/etc/os-release, /tmp/sysinfo/model, the page)",
		0, encodeAnswer(t, answerSystem(&diag.System{PodkopVersion: "0.8.22-test", PodkopLatestVersion: "unknown", LuCIAppVersion: "0.8.22-test", SingBoxVersion: "1.14.4-test",
			OpenWrtVersion: "OpenWrt 24.10.4 r28959-29397011cc", DeviceModel: "Routerich AX3000"}, "podkop-engine r28 (test)")), "")
	fake.probe = api.ProbeResult{DNS: true, Connection: true, Client: "192.168.1.23", Address: "198.18.0.9"}
	r.record("check_fakeip", "the router's name is answered from FakeIP and its connection reaches sing-box", running, "check_fakeip")
	r.record("check_fakeip_client", "what the backend saw of the check name a device opened a connection to", running, "check_fakeip_client", "0a1b2c3d4e5f", "1500")
	fake.probe = api.ProbeResult{DNS: true}
	r.record("check_fakeip-no-connection", "the name is answered from FakeIP, no connection came", running, "check_fakeip")
	r.record("check_fakeip_client-no-connection", "the device asked the name, its connection did not come", running, "check_fakeip_client", "0a1b2c3d4e5f")
	r.record("check_fakeip-stopped", "no backend answers", stopped, "check_fakeip")
	r.record("check_fakeip_client-bad-label", "a label that is no label", running, "check_fakeip_client", "UPPER")
	r.recordWith("check_logs", "the log of the backend and of sing-box (the times of the lines made fixed)", func(text string) string {
		return logTimes.ReplaceAllString(text, "<time> ")
	}, running, "check_logs")

	// the dashboard: the outbounds of the Clash API, their delays, the choice of a selector
	r.record("clash_api-get_proxies", "the outbounds of the Clash API with podkop_tags of the backend", running, "clash_api", "get_proxies")
	r.record("clash_api-get_proxy_latency", "a server that answers its delay test (the check URLs of the configuration that runs)", running, "clash_api", "get_proxy_latency", "own-1-out", "5000")
	r.record("clash_api-get_proxy_latency-silent", "a server that does not answer", running, "clash_api", "get_proxy_latency", "own-2-out", "5000")
	r.record("clash_api-get_group_latency", "a round of the URL test of a rule's selector", running, "clash_api", "get_group_latency", "main-out", "12000")
	r.record("clash_api-set_group_proxy", "the choice of a selector", running, "clash_api", "set_group_proxy", "main-out", "own-1-out")
	r.record("clash_api-set_group_proxy-no-group", "a group the API does not know", running, "clash_api", "set_group_proxy", "other-out", "own-1-out")
	r.record("clash_api-set_group_proxy-no-proxy", "a server the group does not have", running, "clash_api", "set_group_proxy", "main-out", "other-1-out")
	r.record("clash_api-get_proxies-stopped", "no backend answers: no Clash API", stopped, "clash_api", "get_proxies")

	// the configuration and the settings, masked
	r.record("show_sing_box_config", "the configuration that runs, masked", running, "show_sing_box_config")
	r.record("show_sing_box_config-rejected", "the configuration sing-box refused last, masked", running, "show_sing_box_config", "--rejected")
	r.record("show_config", "the settings, masked", running, "show_config")
	r.record("check_links", "the links of the form before a save, as the engine of the build takes them", running, "check_links",
		"socks5://192.0.2.1:1080", "vless://b831381d-6324-4d53-ad4f-8cda48b30811@192.0.2.1:443?type=kcp", "vmess://b831381d-6324-4d53-ad4f-8cda48b30811@192.0.2.1:443")

	// the lists and the subscriptions
	r.record("list_status", "the lists of what runs", running, "list_status")
	r.record("list_status-stopped", "no backend answers", stopped, "list_status")
	r.record("subscription_status", "the subscriptions: one with its list, one whose provider refuses it", running, "subscription_status")
	r.record("subscription_status-stopped", "no backend answers", stopped, "subscription_status")
	r.record("subscription_update_start", "Update now of a subscription: the states at once", running, "subscription_update_start", "prov1")
	r.record("subscription_load_start", "a download of a list of the form started as a job", running, "subscription_load_start", "https://sub.example/sub/TOKEN",
		`{"user_agent_preset":"custom","user_agent":"Happ/1.0","headers":["X-Device: tv"]}`)
	r.record("subscription_load_state", "the job has ended with its preview", running, "subscription_load_state", "job1")
	r.record("subscription_load_state-unknown", "a job the backend does not know", running, "subscription_load_state", "job9")
	r.record("subscription_load_state-stopped", "no backend answers", stopped, "subscription_load_state", "job1")
	r.record("subscription_load_cancel", "the job stopped", running, "subscription_load_cancel", "job1")
	r.record("group_check", "the servers a group would choose", running, "group_check", `{"subscriptions":["prov1","prov3"],"include":["NL"],"exclude":["XX"]}`)

	recordDevices(t, r)
	recordActions(t, r, fake, running, stopped, &upgradeFails)
	r.finish()
}

// recordActions records what the page does not read: the help and the calls that end in it, the
// other failures of the commands, and the actions on the service, the lists, the subscriptions and
// the statistics of BitTorrent. upgradeFails makes the Clash API fail the upgrade of the dashboard.
func recordActions(t *testing.T, r *recorder, fake *backend, running Environment, stopped Environment, upgradeFails *bool) {
	r.record("help", "no command: the help", running)
	var help bytes.Buffer
	Run(running, nil, &bytes.Buffer{}, &help)
	asHelp := func(name string, about string, arguments ...string) {
		r.recordWith(name, about, func(text string) string { return strings.ReplaceAll(text, help.String(), "<the help>\n") }, running, arguments...)
	}
	asHelp("help-unknown", "a command that is none", "no_such_command")
	asHelp("help-empty", "an empty name", "")
	asHelp("help-run", "a method of the bus, which is no command", "run", "get_status")
	asHelp("group_check-none", "no group", "group_check")
	asHelp("group_check-not-json", "a group that is no JSON", "group_check", "NL")
	for _, command := range []string{"subscription_load", "subscription_load_start", "subscription_load_state", "subscription_load_cancel"} {
		asHelp(command+"-none", "no address or job", command)
	}
	asHelp("subscription_load-not-json", "a request that is no JSON", "subscription_load", "https://sub.example/sub/TOKEN", "Happ")
	asHelp("subscription_load_start-not-json", "a request that is no JSON", "subscription_load_start", "https://sub.example/sub/TOKEN", "Happ")

	r.record("show_version", "the version of the backend", running, "show_version")
	r.record("show_sing_box_version", "the version of sing-box", running, "show_sing_box_version")
	r.record("check_links-none", "no link", running, "check_links")
	r.record("show_config-none", "no settings file", Environment{Paths: diag.Paths{Settings: filepath.Join(r.temporary, "none")}}, "show_config")
	r.record("show_sing_box_config-none", "no directory of the configurations", Environment{}, "show_sing_box_config")
	r.record("show_sing_box_config-no-rejected", "no configuration was refused", stopped, "show_sing_box_config", "--rejected")
	last := stopped
	last.ConfigDir = t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(last.ConfigDir, api.LastConfig), []byte(`{"outbounds":[{"type":"socks","tag":"main-out","server":"203.0.113.15","server_port":1080,"password":"p"}]}`), 0o600))
	r.record("show_sing_box_config-last", "nothing runs: the configuration that ran last, masked", last, "show_sing_box_config")
	r.record("device-none", "no address", running, "device")
	r.record("check_fakeip_client-none", "no label", running, "check_fakeip_client")
	r.record("check_fakeip_client-stopped", "no backend answers", stopped, "check_fakeip_client", "0a1b2c3d4e5f")
	r.record("group_check-stopped", "no backend answers", stopped, "group_check", `{"subscriptions":["prov1"],"include":[],"exclude":[]}`)
	r.recordWith("check_logs-since", "the lines after a number of another run: all of this one (the times of the lines and the run made fixed)", func(text string) string {
		return runOfLog.ReplaceAllString(logLineTimes.ReplaceAllString(text, `"<time> `), `"run":"<run>"`)
	}, running, "check_logs", "--since", "otherrun:1")

	// the actions of the Clash API but its answers to the page
	r.record("clash_api-none", "no action", running, "clash_api")
	r.record("clash_api-unknown", "an action that is none", running, "clash_api", "get_rules")
	r.record("clash_api-get_proxy_latency-none", "no outbound", running, "clash_api", "get_proxy_latency")
	r.record("clash_api-get_group_latency-none", "no group", running, "clash_api", "get_group_latency")
	r.record("clash_api-get_group_latency-stopped", "no backend answers: no Clash API", stopped, "clash_api", "get_group_latency", "main-out")
	r.record("clash_api-set_group_proxy-none", "no group and no server", running, "clash_api", "set_group_proxy")
	r.record("clash_api-set_group_proxy-stopped", "no backend answers: no Clash API", stopped, "clash_api", "set_group_proxy", "main-out", "own-1-out")
	r.record("clash_api-upgrade_ui", "the dashboard of GitHub", running, "clash_api", "upgrade_ui")
	*upgradeFails = true
	r.record("clash_api-upgrade_ui-failed", "the dashboard of GitHub, not downloaded", running, "clash_api", "upgrade_ui")
	r.record("clash_api-upgrade_ui-stopped", "no backend answers: no Clash API", stopped, "clash_api", "upgrade_ui")

	// the subscriptions and the jobs
	r.record("subscription_load", "a list downloaded to be shown: the job's preview once it ended", running, "subscription_load", "https://sub.example/sub/TOKEN")
	r.record("subscription_load-stopped", "no backend answers", stopped, "subscription_load", "https://sub.example/sub/TOKEN")
	r.record("subscription_load_start-stopped", "no backend answers", stopped, "subscription_load_start", "https://sub.example/sub/TOKEN")
	r.record("subscription_load_cancel-unknown", "a job the backend does not know", running, "subscription_load_cancel", "job9")
	r.record("subscription_update_start-stopped", "no backend answers", stopped, "subscription_update_start", "prov1")
	r.record("subscription_update-stopped", "no backend answers", stopped, "subscription_update", "prov1")

	// the statistics of BitTorrent
	fake.bitTorrent = btstats.Report{Mode: "bypass", Rule: "Main <1>", Since: 3600, Read: 2, Counted: true,
		Rows: []btstats.Row{{Kind: btstats.KindUTP, Way: btstats.WayPast, Open: 2, Connections: 3,
			Received: btstats.Count{Packets: 10, Bytes: 12000}, Sent: btstats.Count{Packets: 5, Bytes: 600}}},
		Module: map[string]int64{"watched": 4, "confirmed": 1}}
	for _, command := range []string{"bittorrent_stats", "bittorrent_reset", "bittorrent_counters"} {
		r.record(command, "the backend's answer", running, command)
		r.record(command+"-stopped", "no backend answers", stopped, command)
	}
	r.record("bittorrent_record-minutes", "no number of minutes", running, "bittorrent_record", "0")
	r.record("bittorrent_record-stopped", "no backend answers", stopped, "bittorrent_record")
	fake.bitTorrent = btstats.Report{}
	r.record("bittorrent_record-off", "BitTorrent is as the other traffic", running, "bittorrent_record")

	// the actions on what runs, the lists and the service
	fake.result = api.Result{OK: true, Message: "applied in 40 ms, sing-box runs the new configuration"}
	r.record("reload", "the settings applied", running, "reload")
	fake.result = api.Result{Message: "the settings cannot be used, nothing is changed: no link"}
	r.record("reload-refused", "the settings refused", running, "reload")
	r.record("reload-stopped", "no backend answers", stopped, "reload")
	fake.lists = api.ListsUpdate{OK: true, Lines: []string{"rule sets: 3 asked, 1 with a new list, 0 failed"}}
	r.record("list_update", "every list downloaded", running, "list_update")
	fake.lists = api.ListsUpdate{Lines: []string{"rule sets: 3 asked, 0 with a new list, 1 failed"}}
	r.record("list_update-failed", "a list not downloaded", running, "list_update")
	r.record("list_update-stopped", "no backend answers", stopped, "list_update")
	r.record("restore_routing", "what the backend put back", running, "restore_routing")
	r.record("restore_routing-stopped", "no backend answers", stopped, "restore_routing")
	service := running
	service.ServicePath = filepath.Join(filepath.Dir(stopped.Socket), "service")
	require.NoError(t, os.WriteFile(service.ServicePath, []byte("#!/bin/sh\necho \"asked to $1 ($PODKOP_SERVICE_ACTION)\"\necho failing >&2\n[ $1 != stop ]\n"), 0o755))
	for _, action := range []string{"start", "stop", "restart"} {
		r.record(action, "the script of the service (here one that tells what it was asked, and fails to stop)", service, action)
	}
	t.Setenv(serviceActionVariable, "restart")
	r.record("start-called-back", "the script of the service calls podkop back", service, "start")
}

// deviceCase is a case of "podkop device": the address, what the case is, the settings it reads,
// the facts of the router the plan is built with, and a known difference to the plan.
type deviceCase struct {
	name    string
	address string
	about   string
	// settings is a file of inputsDir
	settings string
	facts    plan.Facts
	// differs tells why the report and the plan do not agree, for a known difference
	differs string
}

// The cases of "podkop device", recorded, and each compared with the plan: the route rules of the
// configuration plan.Build makes that can take a connection from the address, in their order
// (planTakes), against the rules the report says take it (reportTakes).
func recordDevices(t *testing.T, r *recorder) {
	routerIPv6 := plan.Facts{IPv6: true}
	cases := []deviceCase{
		{"device-only-devices-one-rule", "192.168.1.10", "in Only for devices of one rule (TV), and of a rule that is off", "devices", routerIPv6, ""},
		{"device-mapped", "::ffff:192.168.1.10", "the same device by its IPv4-mapped IPv6 address", "devices", routerIPv6, ""},
		{"device-two-rules", "192.168.2.5", "in Only for devices of two rules (TV and lan)", "devices", routerIPv6, ""},
		{"device-leading-direct", "192.168.1.30", "in Only for devices of a direct rule at the top (bank)", "devices", routerIPv6, ""},
		{"device-leading-block", "192.168.1.20", "in Only for devices of a block rule at the top (ads)", "devices", routerIPv6, ""},
		{"device-fully-routed", "192.168.3.60", "in Fully Routed IPs of a rule below (pc)", "devices", routerIPv6, ""},
		{"device-excluded", "192.168.2.70", "in Routing Excluded IPs, and in the subnets of TV and lan", "devices", routerIPv6, ""},
		{"device-no-rule", "192.168.9.9", "a device no rule takes", "devices", routerIPv6, ""},
		{"device-ipv6-only-devices", "2001:db8:1::50", "an IPv6 address in Only for devices of TV", "devices", routerIPv6, ""},
		{"device-ipv6-fully-routed", "2001:db8:3::60", "an IPv6 address in Fully Routed IPs of pc", "devices", routerIPv6, ""},
		{"device-ipv6-excluded", "2001:db8:1::70", "an IPv6 address in Routing Excluded IPs", "devices", routerIPv6, ""},
		{"device-ipv6-no-rule", "2001:db8:9::9", "an IPv6 address no rule takes", "devices", routerIPv6, ""},
		{"device-ipv6-bypass", "2001:db8:1::50", "IPv6 traffic past podkop in the settings", "devices-bypass", routerIPv6, ""},
		{"device-ipv6-no-router-ipv6", "2001:db8:1::50", "IPv6 through podkop in the settings, on a router without IPv6 (no ::1)", "devices", plan.Facts{}, ""},
		{"device-not-an-address", "tv.lan", "no address", "devices", routerIPv6, ""},
		{"device-ipv6-every-device", "2001:db8:5::5", "an IPv6 address, and a rule of every device (Main)", "podkop", routerIPv6, ""},
	}
	for _, test := range cases {
		env := Environment{Paths: diag.Paths{Settings: filepath.Join(inputsDir, test.settings)}, Socket: filepath.Join(t.TempDir(), "none.sock"),
			IPv6: func() bool { return test.facts.IPv6 }}
		output := r.record(test.name, test.about, env, "device", test.address)
		compareWithPlan(t, test, output)
	}
	// settings the planner refuses, which the backend does not apply either: no plan to compare with
	r.record("device-refused", "settings the planner refuses: a link the engine cannot use", Environment{Paths: diag.Paths{Settings: filepath.Join(inputsDir, "devices-refused")},
		Socket: filepath.Join(t.TempDir(), "none.sock"), IPv6: func() bool { return true }}, "device", "192.168.1.10")
}

// compareWithPlan fails when the report of a device and the plan disagree, or agree where a
// difference is listed.
func compareWithPlan(t *testing.T, test deviceCase, output string) {
	t.Helper()
	address, err := netip.ParseAddr(test.address)
	if err != nil {
		return
	}
	content, err := os.ReadFile(filepath.Join(inputsDir, test.settings))
	require.NoError(t, err)
	parsed, err := uci.Parse(content)
	require.NoError(t, err)
	config, err := model.Load(parsed)
	require.NoError(t, err)
	planned := planTakes(t, config, test.facts, address.Unmap())
	reported := reportTakes(t, output)
	agree := slices.Equal(planned, reported)
	switch {
	case !agree && test.differs == "":
		t.Errorf("podkop device %s (%s): the report says %v take it, the plan's route rules %v", test.address, test.name, reported, planned)
	case agree && test.differs != "":
		t.Errorf("podkop device %s (%s): the report and the plan agree now (%v): take the difference out (%s)", test.address, test.name, planned, test.differs)
	case !agree:
		t.Logf("podkop device %s, a known difference (%s): the report %v, the plan %v", test.address, test.differs, reported, planned)
	}
}

// planTakes are the route rules of the configuration plan.Build makes of the settings that can
// take a connection from the address, in their order: "<rule> lists" (the route rule of the lists
// of a rule), "<rule> all" (that of the devices a rule routes whole), "excluded" (Routing Excluded
// IPs); the first rule that takes every connection of the address ends them. "past": no route rule
// has the transparent proxy inbound of the address's family.
func planTakes(t *testing.T, config *model.Config, facts plan.Facts, address netip.Addr) []string {
	t.Helper()
	result, err := plan.Build(config, facts, plan.Options{RuleSetDir: t.TempDir(), DecodeLink: func(string) ([]byte, []string, error) {
		return []byte(`{"type":"socks","server":"192.0.2.1","server_port":1080}`), nil, nil
	}})
	require.NoError(t, err)
	var built struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	require.NoError(t, json.Unmarshal(result.Config, &built))
	inbound := "tproxy-in"
	if address.Is6() {
		inbound = "tproxy-in6"
	}
	known := []string{"action", "inbound", "outbound", "source_ip_cidr", "rule_set", "protocol", "ip_cidr", "port"}
	var takes []string
	family := false
	for _, rule := range built.Route.Rules {
		inbounds := textsOf(rule["inbound"])
		if !slices.Contains(inbounds, inbound) {
			continue
		}
		family = true
		action := rule["action"]
		if action != "route" && action != "reject" {
			continue
		}
		for key := range rule {
			if !slices.Contains(known, key) {
				t.Fatalf("a route rule with %s, which planTakes does not read: %v", key, rule)
			}
		}
		if rule["protocol"] != nil || rule["ip_cidr"] != nil {
			// QUIC refused, BitTorrent, the dead end of the check names: not by the device
			continue
		}
		sources := textsOf(rule["source_ip_cidr"])
		if len(sources) > 0 && !withinAny(address, sources) {
			continue
		}
		if sets := textsOf(rule["rule_set"]); len(sets) > 0 {
			section, _, _ := strings.Cut(sets[0], "-")
			takes = append(takes, section+" lists")
			continue
		}
		if len(sources) == 0 {
			t.Fatalf("a route rule of every connection, which planTakes does not read: %v", rule)
		}
		if slices.Equal(slices.Sorted(slices.Values(sources)), slices.Sorted(slices.Values(config.Settings.RoutingExcludedIPs))) {
			return append(takes, "excluded")
		}
		for index := range config.Sections {
			routed := model.Texts(config.Sections[index].Devices().Routed)
			if slices.Equal(slices.Sorted(slices.Values(routed)), slices.Sorted(slices.Values(sources))) {
				return append(takes, config.Sections[index].Name+" all")
			}
		}
		t.Fatalf("a route rule of devices that are no rule's: %v", rule)
	}
	if !family {
		return []string{"past"}
	}
	return takes
}

// reportTakes are the rules the report of a device says take it, as planTakes names them.
func reportTakes(t *testing.T, output string) []string {
	t.Helper()
	takes := []string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		switch {
		case strings.Contains(line, "IPv6 traffic goes past podkop"):
			return []string{"past"}
		case strings.HasPrefix(line, "↪️ It is among the Routing Excluded IPs"):
			takes = append(takes, "excluded")
		case strings.HasPrefix(line, "✅ Rule "):
			found := reportedRule.FindStringSubmatch(line)
			if found == nil {
				t.Fatalf("a line of the report reportTakes does not read: %s", line)
			}
			name := found[1]
			if labelled := labelledRule.FindStringSubmatch(name); labelled != nil {
				name = labelled[1]
			}
			switch {
			case strings.Contains(found[2], "(Fully Routed IPs, "):
				takes = append(takes, name+" all")
			case strings.HasPrefix(found[2], "its connections to the lists of the rule"):
				takes = append(takes, name+" lists")
			default:
				t.Fatalf("a line of the report reportTakes does not read: %s", line)
			}
		}
	}
	return takes
}

var (
	reportedRule = regexp.MustCompile(`^✅ Rule (.+?) takes (.*)$`)
	labelledRule = regexp.MustCompile(`^.* \((\w+)\)$`)
)

// textsOf is a value of a route rule that is a string or a list of them.
func textsOf(value any) []string {
	switch value := value.(type) {
	case string:
		return []string{value}
	case []any:
		var texts []string
		for _, item := range value {
			if text, isText := item.(string); isText {
				texts = append(texts, text)
			}
		}
		return texts
	}
	return nil
}

// withinAny tells whether the address is one of the addresses or within one of the subnets.
func withinAny(address netip.Addr, items []string) bool {
	for _, item := range items {
		if prefix, err := netip.ParsePrefix(item); err == nil && prefix.Contains(address) {
			return true
		}
		if single, err := netip.ParseAddr(item); err == nil && single.Unmap() == address {
			return true
		}
	}
	return false
}
