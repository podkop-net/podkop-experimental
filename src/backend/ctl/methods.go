package ctl

import (
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/ubus"
)

// Method is a command of the program (podkop <name>), a method of the object "podkop" the running
// backend publishes on ubus, or both.
type Method struct {
	Name string
	// Also are other names of a command, told with it on one line of the help.
	Also []string
	// Help is the line of a command in the help; of a method of the bus, what it is.
	Help  string
	Class Class

	// InProcess: the running backend answers the command itself, by the method "run" of the bus:
	// the page calls it through uhttpd and no program starts for the call, where each call of
	// /usr/bin/podkop was a start of the whole binary. These read and check, or act on what goes on
	// in the backend (a choice, a download). The actions on the service and the settings (start,
	// stop, reload, list_update, restore_routing) stay programs of their own: the backend would end
	// in the middle of its answer. global_check too: it is rare and long, and in a program of its
	// own a mistake in it cannot take the backend down.
	InProcess bool
	// Answer gives what the command prints as JSON, in its Form; or the command writes its text
	// itself with Print, which returns its exit status. An error of Answer ends the command with
	// status 1 and the error on the error output: but errUsage with the help there, and errSilent
	// with nothing.
	Form   Form
	Answer func(c *Call) (any, error)
	Print  func(c *Call) int

	// Bus is the method on ubus.
	Bus *BusMethod
}

// Class is what a method does: the ACL of the page grants the methods of the bus under it. The
// commands come to the page by the method "run" and by the program itself, both granted under read
// whatever the class of the command is: those of the class Write answered by "run" are listed with
// why (TestCommandLists).
type Class string

const (
	// Read is for a method that tells and checks.
	Read Class = "read"
	// Write is for a method that acts: on the settings, on what runs or is kept, or by work that
	// goes on after it or through a server.
	Write Class = "write"
)

// BusMethod is the part of a method on ubus: its arguments by name, with their types, and what
// answers a call with them (ubus.Method).
type BusMethod struct {
	Arguments map[string]int
	Call      func(c *Call, arguments map[string]any) (any, int)
}

// onBus answers a call of the bus with what a command prints as JSON.
func onBus(answer func(c *Call) (any, error)) *BusMethod {
	return &BusMethod{Call: func(c *Call, _ map[string]any) (any, int) {
		value, err := answer(c)
		if err != nil {
			return nil, ubus.StatusUnknownError
		}
		return value, ubus.StatusOK
	}}
}

// Form is how a command prints what it answers.
type Form int

const (
	// Compact is JSON on one line.
	Compact Form = iota + 1
	// Pretty is JSON indented by two spaces.
	Pretty
)

// Methods are the commands, in the order of the help, and the methods of the bus that are theirs;
// cmd/podkop adds the methods of the bus that ask the supervisor. Each is here once: the help, Run,
// the commands the running backend answers itself and the object on ubus are made from the table,
// and the ACL of the page is held to it.
var Methods = []Method{
	{Name: "get_status", Class: Read, InProcess: true, Form: Compact, Answer: (*Call).getStatus,
		Help: "Whether the backend starts at boot; whether it runs, and then whether sing-box runs and since when, and what the last boot or change of the settings came to and when, as JSON: {enabled, status, backend, running, since, last: {ok, message}, last_at} (times in RFC 3339, UTC)"},
	{Name: "get_sing_box_status", Class: Read, InProcess: true, Form: Compact, Answer: (*Call).getSingBoxStatus,
		Help: "Whether sing-box runs and the DNS of the LAN asks it"},
	{Name: "get_system_info", Class: Read, InProcess: true, Form: Pretty, Answer: (*Call).getSystemInfo,
		Help: "Versions and the model of the device"},
	{Name: "get_sing_box_features", Class: Read, InProcess: true, Form: Compact, Answer: (*Call).getSingBoxFeatures,
		Help: "What this build adds to sing-box, as a JSON list"},
	{Name: "check_dns_available", Class: Read, InProcess: true, Form: Pretty, Answer: (*Call).checkDNS,
		Help: "Whether the DNS servers of the settings answer"},
	{Name: "check_sing_box", Class: Read, InProcess: true, Form: Pretty, Answer: (*Call).checkSingBox,
		Help: "Whether sing-box runs and listens"},
	{Name: "check_nft_rules", Class: Read, InProcess: true, Form: Pretty, Answer: (*Call).checkFirewall,
		Help: "[label]: whether the firewall table is there and counts packets; with the label of a check name a device opened a connection to, that connection is waited for where the LAN has not been counted yet"},
	{Name: "check_fakeip", Class: Read, InProcess: true, Form: Pretty, Answer: (*Call).checkFakeIP,
		Help: "Whether a name asked on the router is answered from FakeIP and a connection of the router to it reaches sing-box"},
	{Name: "check_fakeip_client", Class: Read, InProcess: true, Form: Pretty, Answer: (*Call).checkFakeIPOfClient,
		Help: "<label> [ms]: what the backend saw of the check name a device opened a connection to"},
	{Name: "clash_api", Class: Write, InProcess: true, Print: (*Call).clashAPI,
		Help: "get_proxies | get_proxy_latency <tag> [ms] (with the first server check URL of HTTPS, then the second when it does not answer; direct-out: all of them at once, the median) | get_group_latency <tag> [ms] (a selector with a URL test: a round of it; one without: each server as get_proxy_latency, 0 for no answer) | set_group_proxy <group> <proxy> | upgrade_ui (the dashboard YACD of GitHub in place of the one served)"},
	{Name: "yacd_builtin", Class: Write, Print: (*Call).restoreYACD,
		Help: "The dashboard YACD of the package served again in place of the one upgraded from GitHub"},
	{Name: "global_check", Class: Read, Print: (*Call).globalCheck,
		Help: "[label port]: every check as one report; with the label of a check name and a port the device that asks opens connections to meanwhile, also what came of its DNS question and its connections"},
	{Name: "device", Class: Read, Print: (*Call).showDevice,
		Help: "<address>: the rules that take the traffic of the device of that IPv4 or IPv6 address, in the order they are matched: by their Only for devices, with the devices excluded from routing and those routed whole (for a device that cannot open the page)"},
	{Name: "check_links", Class: Read, InProcess: true, Form: Compact, Answer: (*Call).checkLinks,
		Help: "<link>...: each proxy link as the engine of this build takes it when the settings run, as JSON: [{ok, error}]"},
	{Name: "subscription_load", Class: Write, InProcess: true, Form: Compact, Answer: (*Call).loadSubscription,
		Help: "<address> [JSON {user_agent_preset, user_agent, headers}]: download the list of a subscription to be shown, not taken, asked as that preset (podkop, happ, incy, sing-box, custom), with that User-Agent of custom and those headers (Name: value), as JSON: {route, error, error_code, took_ms, attempts, provider, agent, preset, format, configs, servers: [{name, scheme, address, link, reason, notes, made}]}"},
	{Name: "subscription_load_start", Class: Write, InProcess: true, Form: Compact, Answer: (*Call).startLoad,
		Help: "<address> [JSON {user_agent_preset, user_agent, headers}]: start a download of the list of a subscription to be shown, as JSON: {id, state, elapsed_ms, attempts}"},
	{Name: "subscription_load_state", Class: Read, InProcess: true, Form: Compact, Answer: (*Call).loadState,
		Help: "<id>: how a download started by subscription_load_start goes, as JSON: {id, state (running, done, failed, canceled), elapsed_ms, attempts, preview}"},
	{Name: "subscription_load_cancel", Class: Write, InProcess: true, Form: Compact, Answer: (*Call).cancelLoad,
		Help: "<id>: stop a download started by subscription_load_start"},
	{Name: "group_check", Class: Read, InProcess: true, Form: Compact, Answer: (*Call).checkGroup,
		Help: "<JSON {subscriptions, include, exclude, addresses, requests}>: the servers a group would choose, as JSON: {chosen, total, missing}; addresses and requests ({user_agent_preset, user_agent, headers}) are those of the form by the name of the subscription, those of the settings that run when not given"},
	{Name: "subscription_status", Class: Read, InProcess: true, Form: Compact, Answer: (*Call).subscriptionStatus,
		Help: "Each subscription of the settings, as JSON: its servers, when its list was taken and checked, the way it came, the last error, the next download"},
	{Name: "subscription_update", Class: Write, Print: (*Call).updateSubscriptions,
		Help: "[name]: download the list of a subscription now (every one without a name)"},
	{Name: "subscription_update_start", Class: Write, InProcess: true, Form: Compact, Answer: (*Call).startSubscriptionUpdate,
		Help: "<name>: start a download of the list of a subscription now, as JSON: the states of subscription_status at once; the attempted time of the subscription is new once it has ended"},
	{Name: "hwid", Class: Read, InProcess: true, Print: (*Call).showHWID,
		Help: "What the identifier of this device that providers are told (x-hwid) is made of, and its beginning"},
	{Name: "check_logs", Class: Read, InProcess: true, Print: (*Call).checkLogs,
		Help: "[--since RUN:NUMBER]: the log of the backend and of sing-box; with --since, as JSON, only the lines after that number of that run (all of another run), and where to go on from"},
	{Name: "show_sing_box_config", Class: Read, InProcess: true, Print: (*Call).showSingBoxConfig,
		Help: "The sing-box configuration that runs, secrets masked; --rejected: the last one refused"},
	{Name: "show_config", Class: Read, InProcess: true, Print: (*Call).showSettings,
		Help: "The settings, secrets masked"},
	{Name: "show_version", Class: Read, InProcess: true, Print: (*Call).showVersion,
		Help: "The version of the backend"},
	{Name: "show_sing_box_version", Class: Read, Print: (*Call).showSingBoxVersion,
		Help: "The version of sing-box in the backend"},
	{Name: "show_system_info", Class: Read, InProcess: true, Print: (*Call).showSystemInfo,
		Help: "The version of OpenWrt and the model of the device"},
	{Name: "check_nft", Class: Read, InProcess: true, Print: (*Call).checkNft,
		Help: "The firewall table of the backend as nft prints it"},
	{Name: "bittorrent_counters", Class: Read, InProcess: true, Form: Pretty, Answer: (*Call).bitTorrentCounters,
		Help: "What the BitTorrent module has counted since sing-box started, as JSON (empty when BitTorrent is off)"},
	{Name: "bittorrent_stats", Class: Read, InProcess: true, Form: Pretty, Answer: (*Call).bitTorrentStats,
		Help: "What the BitTorrent traffic of the LAN came to since the detector was on (or the last bittorrent_reset), by its kind and the way the mode sent it, as JSON: {mode, lan, rule, since, read, counted, rows: [{kind, way, open, connections, received, sent}], blocked, utp_to_tcp, limits, module, reset_at}"},
	{Name: "bittorrent_reset", Class: Write, Form: Pretty, Answer: (*Call).resetBitTorrentStats, Bus: onBus((*Call).resetBitTorrentStats),
		Help: "Start the BitTorrent statistics again from now (the dashboard's Reset), without a restart of podkop"},
	{Name: "bittorrent_record", Class: Write, Print: (*Call).recordBitTorrent,
		Help: "[minutes] [--reset]: write a report of BitTorrent for a test, a sample every 10 s for the minutes (default 10): the router, the settings, CPU, memory, connections and the BitTorrent statistics, without any address or name; --reset starts the statistics first. It prints the file it wrote"},
	{Name: "list_update", Class: Write, Print: (*Call).updateLists,
		Help: "Download every list now instead of at the update interval"},
	{Name: "restore_routing", Class: Write, Print: (*Call).restoreRouting,
		Help: "Put back the routing rule and route, the firewall table and the DNS of the LAN when the network took them, apply the settings again when the network changed under them, try a start that failed again (the hotplug script of the package runs it at every ifup)"},
	{Name: "list_status", Class: Read, InProcess: true, Form: Pretty, Answer: (*Call).listStatus,
		Help: "Each list of what runs, as JSON: who fills it, its URL or file, when it was last downloaded, the last error of each plain list's URL"},
	{Name: "reload", Class: Write, Print: (*Call).reload,
		Help: "Apply the settings again and tell what that came to"},
	{Name: "start", Also: []string{"stop", "restart"}, Class: Write, Print: (*Call).serviceAction,
		Help: "The same action of the service /etc/init.d/podkop"},

	{Name: "run", Class: Read, Bus: runCommand,
		Help: "A command the running backend answers itself"},
	{Name: "bittorrent", Class: Read, Bus: onBus((*Call).bitTorrentStats),
		Help: "bittorrent_stats: the dashboard's table of BitTorrent, asked with stats while BitTorrent is on"},
}

// command tells whether a method is a command.
func (m *Method) command() bool {
	return m.Answer != nil || m.Print != nil
}

// Names are the name of a method and its other names.
func (m *Method) Names() []string {
	return append([]string{m.Name}, m.Also...)
}

// find is the command of a name; nil when there is none.
func find(methods []Method, name string) *Method {
	for index := range methods {
		if method := &methods[index]; method.command() && slices.Contains(method.Names(), name) {
			return method
		}
	}
	return nil
}

// execute runs the command a call names and returns its exit status.
func execute(c *Call) int {
	method := find(c.methods, c.Name)
	if method == nil {
		return usage(c.methods, c.Errors)
	}
	if method.Print != nil {
		return method.Print(c)
	}
	value, err := method.Answer(c)
	switch {
	case err == nil:
		return c.write(value, method.Form)
	case errors.Is(err, errUsage):
		return usage(c.methods, c.Errors)
	case errors.Is(err, errSilent):
		return 1
	}
	return c.fail(err.Error())
}

// usage prints the help and returns the exit status of a command that cannot be run.
func usage(methods []Method, errorOutput io.Writer) int {
	io.WriteString(errorOutput, "Commands:\n")
	for index := range methods {
		method := &methods[index]
		if !method.command() {
			continue
		}
		name := strings.Join(method.Names(), " | ")
		// a name longer than the column gets one space
		io.WriteString(errorOutput, "    "+name+strings.Repeat(" ", max(1, 24-len(name)))+method.Help+"\n")
	}
	return 1
}
