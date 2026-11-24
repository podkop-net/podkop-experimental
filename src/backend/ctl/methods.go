package ctl

import (
	"io"
	"strings"
)

// Method is a command of the program: podkop <name>.
type Method struct {
	// Name is the command.
	Name string
	// Also are other names of it, told with it on one line of the help.
	Also []string
	// Help is what the help tells of it.
	Help string
}

// Methods are the commands, in the order of the help: each is here once.
var Methods = []Method{
	{Name: "get_status",
		Help: "Whether the backend starts at boot; whether it runs, and then whether sing-box runs and since when, and what the last boot or change of the settings came to and when, as JSON: {enabled, status, backend, running, since, last: {ok, message}, last_at} (times in RFC 3339, UTC)"},
	{Name: "get_sing_box_status",
		Help: "Whether sing-box runs and the DNS of the LAN asks it"},
	{Name: "get_system_info",
		Help: "Versions and the model of the device"},
	{Name: "get_sing_box_features",
		Help: "What this build adds to sing-box, as a JSON list"},
	{Name: "check_dns_available",
		Help: "Whether the DNS servers of the settings answer"},
	{Name: "check_sing_box",
		Help: "Whether sing-box runs and listens"},
	{Name: "check_nft_rules",
		Help: "[label]: whether the firewall table is there and counts packets; with the label of a check name a device opened a connection to, that connection is waited for where the LAN has not been counted yet"},
	{Name: "check_fakeip",
		Help: "Whether a name asked on the router is answered from FakeIP and a connection of the router to it reaches sing-box"},
	{Name: "check_fakeip_client",
		Help: "<label> [ms]: what the backend saw of the check name a device opened a connection to"},
	{Name: "clash_api",
		Help: "get_proxies | get_proxy_latency <tag> [ms] (with the first server check URL of HTTPS, then the second when it does not answer; direct-out: all of them at once, the median) | get_group_latency <tag> [ms] (a selector with a URL test: a round of it; one without: each server as get_proxy_latency, 0 for no answer) | set_group_proxy <group> <proxy> | upgrade_ui (the dashboard YACD of GitHub in place of the one served)"},
	{Name: "yacd_builtin",
		Help: "The dashboard YACD of the package served again in place of the one upgraded from GitHub"},
	{Name: "global_check",
		Help: "[label port]: every check as one report; with the label of a check name and a port the device that asks opens connections to meanwhile, also what came of its DNS question and its connections"},
	{Name: "device",
		Help: "<address>: the rules that take the traffic of the device of that IPv4 or IPv6 address, in the order they are matched: by their Only for devices, with the devices excluded from routing and those routed whole (for a device that cannot open the page)"},
	{Name: "check_links",
		Help: "<link>...: each proxy link as the engine of this build takes it when the settings run, as JSON: [{ok, error}]"},
	{Name: "subscription_load",
		Help: "<address> [JSON {user_agent_preset, user_agent, headers}]: download the list of a subscription to be shown, not taken, asked as that preset (podkop, happ, incy, sing-box, custom), with that User-Agent of custom and those headers (Name: value), as JSON: {route, error, error_code, took_ms, attempts, provider, agent, preset, format, configs, servers: [{name, scheme, address, link, reason, notes, made}]}"},
	{Name: "subscription_load_start",
		Help: "<address> [JSON {user_agent_preset, user_agent, headers}]: start a download of the list of a subscription to be shown, as JSON: {id, state, elapsed_ms, attempts}"},
	{Name: "subscription_load_state",
		Help: "<id>: how a download started by subscription_load_start goes, as JSON: {id, state (running, done, failed, canceled), elapsed_ms, attempts, preview}"},
	{Name: "subscription_load_cancel",
		Help: "<id>: stop a download started by subscription_load_start"},
	{Name: "group_check",
		Help: "<JSON {subscriptions, include, exclude, addresses, requests}>: the servers a group would choose, as JSON: {chosen, total, missing}; addresses and requests ({user_agent_preset, user_agent, headers}) are those of the form by the name of the subscription, those of the settings that run when not given"},
	{Name: "subscription_status",
		Help: "Each subscription of the settings, as JSON: its servers, when its list was taken and checked, the way it came, the last error, the next download"},
	{Name: "subscription_update",
		Help: "[name]: download the list of a subscription now (every one without a name)"},
	{Name: "subscription_update_start",
		Help: "<name>: start a download of the list of a subscription now, as JSON: the states of subscription_status at once; the attempted time of the subscription is new once it has ended"},
	{Name: "hwid",
		Help: "What the identifier of this device that providers are told (x-hwid) is made of, and its beginning"},
	{Name: "check_logs",
		Help: "[--since RUN:NUMBER]: the log of the backend and of sing-box; with --since, as JSON, only the lines after that number of that run (all of another run), and where to go on from"},
	{Name: "show_sing_box_config",
		Help: "The sing-box configuration that runs, secrets masked; --rejected: the last one refused"},
	{Name: "show_config",
		Help: "The settings, secrets masked"},
	{Name: "show_version",
		Help: "The version of the backend"},
	{Name: "show_sing_box_version",
		Help: "The version of sing-box in the backend"},
	{Name: "show_system_info",
		Help: "The version of OpenWrt and the model of the device"},
	{Name: "check_nft",
		Help: "The firewall table of the backend as nft prints it"},
	{Name: "bittorrent_counters",
		Help: "What the BitTorrent module has counted since sing-box started, as JSON (empty when BitTorrent is off)"},
	{Name: "bittorrent_stats",
		Help: "What the BitTorrent traffic of the LAN came to since the detector was on (or the last bittorrent_reset), by its kind and the way the mode sent it, as JSON: {mode, lan, rule, since, read, counted, rows: [{kind, way, open, connections, received, sent}], blocked, utp_to_tcp, limits, module, reset_at}"},
	{Name: "bittorrent_reset",
		Help: "Start the BitTorrent statistics again from now (the dashboard's Reset), without a restart of podkop"},
	{Name: "bittorrent_record",
		Help: "[minutes] [--reset]: write a report of BitTorrent for a test, a sample every 10 s for the minutes (default 10): the router, the settings, CPU, memory, connections and the BitTorrent statistics, without any address or name; --reset starts the statistics first. It prints the file it wrote"},
	{Name: "list_update",
		Help: "Download every list now instead of at the update interval"},
	{Name: "restore_routing",
		Help: "Put back the routing rule and route, the firewall table and the DNS of the LAN when the network took them, apply the settings again when the network changed under them, try a start that failed again (the hotplug script of the package runs it at every ifup)"},
	{Name: "list_status",
		Help: "Each list of what runs, as JSON: who fills it, its URL or file, when it was last downloaded, the last error of each plain list's URL"},
	{Name: "reload",
		Help: "Apply the settings again and tell what that came to"},
	{Name: "start", Also: []string{"stop", "restart"},
		Help: "The same action of the service /etc/init.d/podkop"},
}

// Names are the name of a method and its other names.
func (m *Method) Names() []string {
	return append([]string{m.Name}, m.Also...)
}

// usage prints the help and returns the exit status of a command that cannot be run.
func usage(methods []Method, errorOutput io.Writer) int {
	io.WriteString(errorOutput, "Commands:\n")
	for index := range methods {
		name := strings.Join(methods[index].Names(), " | ")
		// a name longer than the column gets one space
		io.WriteString(errorOutput, "    "+name+strings.Repeat(" ", max(1, 24-len(name)))+methods[index].Help+"\n")
	}
	return 1
}
