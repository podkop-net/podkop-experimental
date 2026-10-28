package ctl

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/diag"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/probe"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	"github.com/podkop-net/podkop-experimental/src/backend/yacd"
)

// Environment is what the commands need to know of where they run.
type Environment struct {
	// Version is the version of the backend (podkop.Version), SingBoxVersion the one of
	// sing-box, Engine what the sing-box inside is, for a person (podkop.Engine).
	Version        string
	SingBoxVersion string
	Engine         string
	// Features are the names get_sing_box_features gives the user interface: PageFeatures.
	Features []string
	// Socket is the socket of the running backend.
	Socket string
	Paths  diag.Paths
	// ConfigDir is where the backend keeps the configuration that runs and the last one
	// refused (supervisor.Options.ConfigDir).
	ConfigDir string
	// AutostartPath is the link the service manager starts the backend by at boot.
	AutostartPath string
	// ServicePath is the script of the service.
	ServicePath string
	// CheckLink tells why the engine of this build cannot use a proxy link, as the
	// configuration would refuse it (engine.CheckLink); nil returns are links it can use.
	CheckLink func(link string) error
}

// LinkCheck is what check_links tells of a link: whether the engine takes it, and why not.
type LinkCheck struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// PageFeatures are the names get_sing_box_features gives: those the user interface of
// podkop 0.7.24 asks for before it shows an option (fallbacks and the download test of a
// urltest group, the uTLS fingerprint fallback). The backend writes these options itself,
// so the names are its own, not those of the Features line of "sing-box version", which
// may change without the page changing.
// compat: page-features
var PageFeatures = []string{"urltest.fallbacks", "urltest.download_url", "tls.utls-fallback"}

// serviceActionVariable marks the script of the service run by start, stop and restart.
const serviceActionVariable = "PODKOP_SERVICE_ACTION"

const (
	singBoxAutostartPath = "/etc/rc.d/S99sing-box"
	// the page the delay of an outbound is measured with, as the shell backend has it
	delayTestURL = "https://www.gstatic.com/generate_204"
)

// Commands lists the commands with what each does, for the help.
var Commands = [][2]string{
	{"get_status", "Whether the backend starts at boot"},
	{"get_sing_box_status", "Whether sing-box runs and the DNS of the LAN asks it"},
	{"get_system_info", "Versions and the model of the device"},
	{"get_sing_box_features", "What this build adds to sing-box, as a JSON list"},
	{"check_dns_available", "Whether the DNS servers of the settings answer"},
	{"check_sing_box", "Whether sing-box runs and listens"},
	{"check_nft_rules", "[label]: whether the firewall table is there and counts packets; with the label of a check name a device opened a connection to, that connection is waited for where the LAN has not been counted yet"},
	{"check_fakeip", "Whether a name asked on the router is answered from FakeIP and a connection of the router to it reaches sing-box"},
	{"check_fakeip_client", "<label> [ms]: what the backend saw of the check name a device opened a connection to"},
	{"clash_api", "get_proxies | get_proxy_latency <tag> [ms] | get_group_latency <tag> [ms] | set_group_proxy <group> <proxy> | upgrade_ui (the dashboard YACD of GitHub in place of the one served)"},
	{"yacd_builtin", "The dashboard YACD of the package served again in place of the one upgraded from GitHub"},
	{"global_check", "[label port]: every check as one report; with the label of a check name and a port the device that asks opens connections to meanwhile, also what came of its DNS question and its connections"},
	{"check_links", "<link>...: each proxy link as the engine of this build takes it when the settings run, as JSON: [{ok, error}]"},
	{"subscription_load", "<address>: download the list of a subscription to be shown, not taken, as JSON: {route, error, error_code, took_ms, attempts, provider, servers: [{name, scheme, address, link, reason, notes}]}"},
	{"subscription_load_start", "<address>: start a download of the list of a subscription to be shown, as JSON: {id, state, elapsed_ms, attempts}"},
	{"subscription_load_state", "<id>: how a download started by subscription_load_start goes, as JSON: {id, state (running, done, failed, canceled), elapsed_ms, attempts, preview}"},
	{"subscription_load_cancel", "<id>: stop a download started by subscription_load_start"},
	{"group_check", "<JSON {subscriptions, include, exclude}>: the servers a group would choose, as JSON: {chosen, total, missing}"},
	{"subscription_status", "Each subscription of the settings, as JSON: its servers, when its list was taken and checked, the way it came, the last error, the next download"},
	{"subscription_update", "[name]: download the list of a subscription now (every one without a name)"},
	{"hwid", "What the identifier of this device that providers are told (x-hwid) is made of, and its beginning"},
	{"check_logs", "[--since RUN:NUMBER]: the log of the backend and of sing-box; with --since, as JSON, only the lines after that number of that run (all of another run), and where to go on from"},
	{"show_sing_box_config", "The sing-box configuration that runs, secrets masked; --rejected: the last one refused"},
	{"show_config", "The settings, secrets masked"},
	{"show_version", "The version of the backend"},
	{"show_system_info", "The version of OpenWrt and the model of the device"},
	{"check_nft", "The firewall table of the backend as nft prints it"},
	{"list_update", "Download every list now instead of at the update interval"},
	{"restore_routing", "Put back the routing rule and route, the firewall table and the DNS of the LAN when the network took them, apply the settings again when the network changed under them, try a start that failed again (the hotplug script of the package runs it at every ifup, the guard after a failed start)"},
	{"list_status", "Each list of what runs, as JSON: who fills it, its URL or file, when it was last downloaded, the last error of each plain list's URL"},
	{"reload", "Apply the settings again and tell what that came to"},
	{"start | stop | restart", "The same action of the service /etc/init.d/podkop"},
}

// Run runs a command and returns its exit status. As with the shell backend, the user
// interface takes an empty output for a failure and anything else for an answer.
func Run(env Environment, arguments []string, output io.Writer, errorOutput io.Writer) int {
	if len(arguments) == 0 {
		return usage(errorOutput)
	}
	ctx := context.Background()
	client := api.Client{Path: env.Socket}
	running := func() bool {
		status, err := client.Status()
		return err == nil && status.Running
	}
	// JSON as the shell backend prints it: text as it is, with no escapes for HTML
	write := func(value any, indent string) int {
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", indent)
		if encoder.Encode(value) != nil {
			return 1
		}
		return 0
	}
	compact := func(value any) int { return write(value, "") }
	pretty := func(value any) int { return write(value, "  ") }
	// the settings as the backend reads them, with its defaults
	settings := new(model.Settings)
	var sections []model.Section
	if config, err := model.Load(readUCI(env.Paths.Settings)); err == nil {
		settings, sections = &config.Settings, config.Sections
	}
	switch arguments[0] {
	case "get_status":
		enabled := executable(env.AutostartPath)
		return compact(struct {
			Enabled int    `json:"enabled"`
			Status  string `json:"status"`
		}{asNumber(enabled), words(enabled, "enabled", "disabled")})
	case "get_sing_box_status":
		// "enabled" is the autostart of a sing-box service of its own, which the shell
		// backend switches off and this backend does not have: sing-box starts with it
		isRunning, enabled := running(), executable(singBoxAutostartPath)
		status := words(isRunning, "running", "stopped") + words(isRunning == enabled, " & ", " but ") + words(enabled, "enabled", "disabled")
		return compact(struct {
			Running       int    `json:"running"`
			Enabled       int    `json:"enabled"`
			Status        string `json:"status"`
			DNSConfigured int    `json:"dns_configured"`
		}{asNumber(isRunning), asNumber(enabled), status, asNumber(diag.DNSOfLAN(readUCI(env.Paths.DHCP)))})
	case "get_system_info":
		return pretty(answerSystem(diag.SystemInfo(ctx, env.Version, env.SingBoxVersion, false), env.Engine))
	case "check_links":
		// the page asks before it saves the settings: the reason of a link the configuration
		// would be refused for, by the field it is in, and not in the log after the apply
		results := make([]LinkCheck, 0, len(arguments)-1)
		for _, link := range arguments[1:] {
			result := LinkCheck{OK: true}
			if env.CheckLink == nil {
				result = LinkCheck{Error: "links are not checked by this program"}
			} else if err := env.CheckLink(link); err != nil {
				// a kind of outbound the slim build leaves out: the advice of the engine names its
				// own packages, which are not those of podkop
				message, _, _ := strings.Cut(err.Error(), ", install podkop-engine-full")
				result = LinkCheck{Error: message}
			}
			results = append(results, result)
		}
		return compact(results)
	case "subscription_load":
		if len(arguments) < 2 {
			return usage(errorOutput)
		}
		return compact(loadAndWait(client, arguments[1]))
	case "subscription_load_start", "subscription_load_state", "subscription_load_cancel":
		if len(arguments) < 2 {
			return usage(errorOutput)
		}
		var job *api.LoadJob
		var err error
		switch arguments[0] {
		case "subscription_load_start":
			job, err = client.StartLoad(arguments[1])
		case "subscription_load_state":
			job, err = client.LoadState(arguments[1])
		default:
			job, err = client.CancelLoad(arguments[1])
		}
		if err != nil {
			job = &api.LoadJob{State: "failed", Attempts: []api.Attempt{}, Preview: notRunning()}
			if _, down := client.Status(); down == nil {
				// the backend runs: the job ended long ago, or the backend started anew
				job.Preview = &api.SubscriptionPreview{Servers: []api.PreviewServer{}, Error: "the download is not known to podkop: it ended long ago, or podkop restarted", ErrorCode: "nojob"}
			}
		}
		return compact(job)
	case "group_check":
		var check api.GroupCheck
		if len(arguments) < 2 || json.Unmarshal([]byte(arguments[1]), &check) != nil {
			return usage(errorOutput)
		}
		preview, err := client.CheckGroup(check, 19*time.Second)
		if err != nil {
			return 1
		}
		return compact(preview)
	case "subscription_status":
		states, err := client.Subscriptions()
		if err != nil {
			states = []api.SubscriptionState{}
		}
		return compact(states)
	case "subscription_update":
		name := ""
		if len(arguments) > 1 {
			name = arguments[1]
		}
		states, err := client.UpdateSubscriptions(name)
		if err != nil {
			io.WriteString(errorOutput, "podkop does not run: "+err.Error()+"\n")
			return 1
		}
		io.WriteString(output, strings.Join(subscriptionLines(states, time.Now()), "\n")+"\n")
		return 0
	case "hwid":
		device := subscription.ReadDevice("/")
		io.WriteString(output, "source: "+device.Source+"\nhwid: "+device.HWID[:min(8, len(device.HWID))]+"…\n")
		return 0
	case "get_sing_box_features":
		features := env.Features
		if features == nil {
			features = []string{}
		}
		return compact(features)
	case "check_dns_available":
		return pretty(AnswerDNS(diag.CheckDNS(ctx, diag.DNSSettings{Type: settings.DNSType, Server: settings.DNSServer, Bootstrap: settings.BootstrapDNSServer}, readUCI(env.Paths.DHCP))))
	case "check_sing_box":
		return pretty(answerSingBox(diag.CheckSingBox(running())))
	case "check_nft_rules":
		// with the label of a check name the device that asks has opened a connection to
		var awaitDevice func(context.Context)
		if len(arguments) > 1 && probe.ValidLabel(arguments[1]) {
			awaitDevice = func(context.Context) { _, _ = client.Probe(arguments[1], 0) }
		}
		return pretty(answerFirewall(diag.CheckFirewall(ctx, awaitDevice)))
	case "check_fakeip":
		// the answer of the shell backend came from a server outside and had the flag
		// "fakeip"; the flag stays, and what it is made of is shown beside it
		result, err := client.ProbeSelf()
		if err != nil {
			return 1
		}
		return pretty(struct {
			FakeIP     bool `json:"fakeip"`
			DNS        bool `json:"dns"`
			Connection bool `json:"connection"`
		}{result.DNS && result.Connection, result.DNS, result.Connection})
	case "check_fakeip_client":
		if len(arguments) < 2 || !probe.ValidLabel(arguments[1]) {
			io.WriteString(errorOutput, "check_fakeip_client <label> [ms]: the label is 8 to 40 lower-case letters and digits\n")
			return 1
		}
		var wait time.Duration
		if len(arguments) > 2 {
			milliseconds, _ := strconv.Atoi(arguments[2])
			wait = time.Duration(milliseconds) * time.Millisecond
		}
		result, err := client.Probe(arguments[1], wait)
		if err != nil {
			return 1
		}
		return pretty(result)
	case "clash_api":
		return clashAPI(client, arguments[1:], output)
	case "global_check":
		// with the label of a check name and a port: the device that asks opens
		// connections to them while the report is made
		var device *deviceCheck
		if len(arguments) > 2 && probe.ValidLabel(arguments[1]) {
			if port, err := strconv.ParseUint(arguments[2], 10, 16); err == nil && port > 0 {
				device = &deviceCheck{label: arguments[1], port: uint16(port), probe: client.Probe, sources: settings.SourceNetworkInterfaces}
			}
		}
		io.WriteString(output, globalCheck(ctx, env.Paths, settings, sections, env.Version, env.SingBoxVersion, env.Engine, running(), func() (bool, bool) {
			result, err := client.ProbeSelf()
			return err == nil && result.DNS && result.Connection, err == nil
		}, func() []string { return outboundLines(&clashCaller{client: client}, sections) }, func() []string {
			states, err := client.Subscriptions()
			if err != nil {
				return nil
			}
			return subscriptionLines(states, time.Now())
		}, device))
		return 0
	case "check_logs":
		if len(arguments) > 2 && arguments[1] == "--since" {
			return compact(logsSince(client, arguments[2]))
		}
		return logs(client, output)
	case "show_sing_box_config":
		return showConfig(env, len(arguments) > 1 && arguments[1] == "--rejected", output, errorOutput)
	case "show_config":
		content, err := os.ReadFile(env.Paths.Settings)
		if err != nil {
			return 1
		}
		io.WriteString(output, diag.MaskSettings(content))
		return 0
	case "show_version":
		io.WriteString(output, env.Version+"\n")
		return 0
	case "show_sing_box_version":
		io.WriteString(output, env.SingBoxVersion+"\n")
		return 0
	case "show_system_info":
		release, model := diag.Device()
		io.WriteString(output, "=== OpenWrt Version ===\n"+release+"\n\n=== Device Model ===\n"+model+"\n")
		return 0
	case "check_nft":
		return printTable(output)
	case "yacd_builtin":
		err := yacd.Restore(yacd.BuiltinDir, yacd.ServedDir)
		if err != nil {
			message, _ := json.Marshal(err.Error())
			io.WriteString(output, `{"success":false,"message":`+string(message)+"}\n")
			return 1
		}
		io.WriteString(output, `{"success":true}`+"\n")
		return 0
	case "restore_routing":
		result, err := client.RestoreRouting()
		if err != nil {
			io.WriteString(errorOutput, "the backend does not run: "+err.Error()+"\n")
			return 1
		}
		io.WriteString(output, result+"\n")
		return 0
	case "list_status":
		states, err := client.Lists()
		if err != nil {
			io.WriteString(errorOutput, "the backend does not run: "+err.Error()+"\n")
			return 1
		}
		return pretty(states)
	case "list_update":
		io.WriteString(output, "🔄 Starting lists update...\n")
		result, err := client.UpdateLists()
		if err != nil {
			io.WriteString(errorOutput, "the backend does not run: "+err.Error()+"\n")
			return 1
		}
		for _, line := range result.Lines {
			io.WriteString(output, line+"\n")
		}
		if !result.OK {
			io.WriteString(output, "❌ Lists update failed\n")
			return 1
		}
		io.WriteString(output, "✅ Lists update completed successfully\n")
		return 0
	case "start", "stop", "restart":
		// the shell backend did these itself; here they are the actions of the service.
		// A script of the service that calls these back is not the script of this package
		// (the shell backend's, kept by apk as an edited file, with this package's beside
		// it as .apk-new): the two would call each other until the memory runs out.
		if os.Getenv(serviceActionVariable) != "" {
			io.WriteString(errorOutput, "the script "+env.ServicePath+" calls podkop back: it is not the script of this backend ("+
				"compare it with "+env.ServicePath+".apk-new); "+arguments[0]+" is not done\n")
			return 1
		}
		command := exec.Command(env.ServicePath, arguments[0])
		command.Env = append(os.Environ(), serviceActionVariable+"="+arguments[0])
		command.Stdout, command.Stderr = output, errorOutput
		if command.Run() != nil {
			return 1
		}
		return 0
	case "reload":
		result, err := client.Apply()
		if err != nil {
			io.WriteString(errorOutput, "the backend does not run: "+err.Error()+"\n")
			return 1
		}
		io.WriteString(output, result.Message+"\n")
		if !result.OK {
			return 1
		}
		return 0
	}
	return usage(errorOutput)
}

func usage(errorOutput io.Writer) int {
	io.WriteString(errorOutput, "Commands:\n")
	for _, command := range Commands {
		io.WriteString(errorOutput, "    "+command[0]+strings.Repeat(" ", 24-len(command[0]))+command[1]+"\n")
	}
	return 1
}

// printTable prints the firewall table of the backend as the nft program shows it. The
// backend itself needs no nft program: this command is for the eyes, and nft is what
// people read. As with the shell backend, the words around the table are for a terminal
// only: a program that reads the output gets the table and the exit status.
func printTable(output io.Writer) int {
	say := func(string) {}
	if file, isFile := output.(*os.File); isFile {
		if info, err := file.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			say = func(text string) { io.WriteString(output, text+"\n") }
		}
	}
	program, err := exec.LookPath("nft")
	if err != nil {
		say("nft is not installed")
		return 1
	}
	say("Checking " + dataplane.FirewallTable + " rules...")
	table, err := exec.Command(program, "list", "table", "inet", dataplane.FirewallTable).Output()
	if err != nil {
		say("❌ " + dataplane.FirewallTable + " not found")
		return 1
	}
	say("Sets configuration:")
	output.Write(table)
	say("NFT check completed")
	return 0
}

func asNumber(value bool) int {
	if value {
		return 1
	}
	return 0
}

func words(value bool, yes string, no string) string {
	if value {
		return yes
	}
	return no
}

func executable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&0o111 != 0
}

// readUCI reads a settings file; a file that cannot be read is one without sections.
func readUCI(path string) *uci.Package {
	content, err := os.ReadFile(path)
	if err == nil {
		parsed, err := uci.Parse(content)
		if err == nil {
			return parsed
		}
	}
	return new(uci.Package)
}

// logAnswerLimit is the most of the log one answer carries. rpcd refuses to pass on the
// output of a command larger than about 256 KiB ("Operation not supported"), and the user
// interface then has no log at all: the newest lines are given, up to this size.
const logAnswerLimit = 192 << 10

// newest keeps the last lines that fit in the limit.
func newest(lines []string) []string {
	size := 0
	for index := len(lines) - 1; index >= 0; index-- {
		size += len(lines[index]) + 1
		if size > logAnswerLimit {
			return lines[index+1:]
		}
	}
	return lines
}

// systemLog is what the system log has of the backend: the last words of one that died.
func systemLog() []string {
	system, err := exec.Command("logread", "-e", "podkop").Output()
	if err != nil || len(system) == 0 {
		return nil
	}
	all := strings.Split(strings.TrimRight(string(system), "\n"), "\n")
	if len(all) > 100 {
		all = all[len(all)-100:]
	}
	return all
}

// logs prints the log of this run of the backend. When no backend answers, what the
// system log has of it is printed instead.
func logs(client api.Client, output io.Writer) int {
	page, err := client.Logs(0)
	if err != nil {
		lines := systemLog()
		if len(lines) == 0 {
			return 1
		}
		io.WriteString(output, strings.Join(lines, "\n")+"\n")
		return 0
	}
	if len(page.Lines) == 0 {
		return 1
	}
	io.WriteString(output, strings.Join(newest(page.Lines), "\n")+"\n")
	return 0
}

// logsSince prints, as JSON, the lines a reader has not seen: those after the number of
// "run:number" when the backend still runs that run, else all of the run it runs now; and
// where to go on from. The notices of the user interface ask with it, and so raise each
// line once, however long the log and however often the page is opened. With no backend
// the run is "system" and the lines are those of the system log.
func logsSince(client api.Client, cursor string) *api.LogPage {
	run, number, _ := strings.Cut(cursor, ":")
	since, _ := strconv.ParseUint(number, 10, 64)
	page, err := client.Logs(since)
	if err == nil && page.Run != run && since != 0 {
		page, err = client.Logs(0)
	}
	if err != nil {
		page = &api.LogPage{Run: "system", Lines: systemLog()}
	}
	page.Lines = newest(page.Lines)
	if page.Lines == nil {
		page.Lines = []string{}
	}
	return page
}

// showConfig prints a sing-box configuration, masked: the one that runs, or with rejected
// the last one sing-box refused. When nothing runs, the refused one is printed if there is
// one, else the one that ran last; the terminal is told which (the user interface reads
// the output alone, as JSON).
func showConfig(env Environment, rejected bool, output io.Writer, errorOutput io.Writer) int {
	type source struct {
		path string
		note string
	}
	if env.ConfigDir == "" {
		return 1
	}
	sources := []source{
		{filepath.Join(env.ConfigDir, api.RunningConfig), ""},
		{filepath.Join(env.ConfigDir, api.RejectedConfig), "nothing runs; this is the configuration sing-box refused last"},
		{filepath.Join(env.ConfigDir, api.LastConfig), "nothing runs; this is the configuration that ran last"},
	}
	if rejected {
		sources = []source{{sources[1].path, ""}}
	}
	for _, from := range sources {
		content, err := os.ReadFile(from.path)
		if err != nil {
			continue
		}
		masked, err := diag.MaskConfig(content)
		if err != nil {
			return 1
		}
		if from.note != "" {
			io.WriteString(errorOutput, from.note+"\n")
		}
		output.Write(masked)
		return 0
	}
	if rejected {
		io.WriteString(errorOutput, "no configuration was refused since the backend started\n")
	}
	return 1
}

// clashAPI asks the Clash API of sing-box, where the dashboard of the user interface
// gets the outbounds, their delays and the choice of a group from. The answers are
// printed as the shell backend prints them. Where the API listens and its key are what
// the backend that runs tells (api.Facts): with no backend there is no API.
func clashAPI(client api.Client, arguments []string, output io.Writer) int {
	say := func(text string) {
		content, err := plan.Pretty([]byte(text))
		if err == nil {
			output.Write(content)
		}
	}
	call := (&clashCaller{client: client}).call
	argument := func(index int) string {
		if index < len(arguments) {
			return arguments[index]
		}
		return ""
	}
	delay := func(kind string, missing string, defaultTimeout string) int {
		tag := argument(1)
		if tag == "" {
			say(`{"error":"` + missing + ` required"}`)
			return 1
		}
		timeout := argument(2)
		if timeout == "" {
			timeout = defaultTimeout
		}
		milliseconds, _ := strconv.Atoi(timeout)
		query := url.Values{"url": {delayTestURL}, "timeout": {timeout}}
		_, content := call(http.MethodGet, "/"+kind+"/"+url.PathEscape(tag)+"/delay?"+query.Encode(), "", time.Duration(milliseconds)*time.Millisecond+5*time.Second)
		if len(bytes.TrimSpace(content)) == 0 {
			return 1
		}
		say(string(content))
		return 0
	}
	switch argument(0) {
	case "get_proxies":
		_, content := call(http.MethodGet, "/proxies", "", 10*time.Second)
		if len(bytes.TrimSpace(content)) == 0 {
			return 1
		}
		say(string(content))
		return 0
	case "get_proxy_latency":
		return delay("proxies", "proxy_tag", "2000")
	case "get_group_latency":
		return delay("group", "group_tag", "5000")
	case "upgrade_ui":
		// sing-box downloads the dashboard of GitHub (Yacd-meta) and puts it in place of
		// the one it serves (POST /upgrade/ui), through its direct outbound, as the button
		// of the dashboard asks
		status, content := call(http.MethodPost, "/upgrade/ui", "", 3*time.Minute)
		if status == http.StatusOK {
			say(`{"success":true}`)
			return 0
		}
		message := "the Clash API did not answer (YACD off, or podkop not running)"
		if status != 0 {
			var answer struct {
				Message string `json:"message"`
			}
			_ = json.Unmarshal(content, &answer)
			message = cmp.Or(answer.Message, http.StatusText(status))
		}
		quoted, _ := json.Marshal(message)
		say(`{"success":false,"http_code":` + strconv.Itoa(status) + `,"message":` + string(quoted) + `}`)
		return 1
	case "set_group_proxy":
		group, proxy := argument(1), argument(2)
		if group == "" || proxy == "" {
			say(`{"error":"group_tag and proxy_tag required"}`)
			return 1
		}
		name, _ := json.Marshal(proxy)
		status, content := call(http.MethodPut, "/proxies/"+url.PathEscape(group), `{"name":`+string(name)+`}`, 10*time.Second)
		text := func(value string) string {
			quoted, _ := json.Marshal(value)
			return string(quoted)
		}
		switch status {
		case http.StatusNoContent:
			say(`{"success":true,"group":` + text(group) + `,"proxy":` + text(proxy) + `}`)
			return 0
		case http.StatusNotFound:
			say(`{"success":false,"error":"group_not_found","message":` + text(group+" does not exist") + `}`)
		case http.StatusBadRequest:
			if bytes.Contains(content, []byte("not found")) {
				say(`{"success":false,"error":"proxy_not_found","message":` + text(proxy+" not found in group "+group) + `}`)
			} else {
				say(`{"success":false,"error":"bad_request","message":"Invalid request"}`)
			}
		default:
			if json.Valid(content) && len(bytes.TrimSpace(content)) > 0 {
				say(`{"success":false,"http_code":` + strconv.Itoa(status) + `,"body":` + string(content) + `}`)
			} else {
				say(`{"success":false,"http_code":` + strconv.Itoa(status) + `}`)
			}
		}
		return 1
	}
	say(`{"error":"unknown action","available":["get_proxies","get_proxy_latency","get_group_latency","set_group_proxy","upgrade_ui"]}`)
	return 1
}
