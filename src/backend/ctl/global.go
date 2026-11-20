package ctl

import (
	"context"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/diag"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/netcfg"
	"github.com/podkop-net/podkop-experimental/src/backend/sockets"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
)

// compat: page-answers
// The report of global_check is the shell backend's, line for line: people paste it into
// bug reports, and those who read them know it. The checks themselves are in diag; this is
// their text.

const rule = "━━━━━━━━━━━━━━━━━━━━━━━━━━━"

// interfaceDevices is netcfg.Devices; a test has its own
var interfaceDevices = netcfg.Devices

// the first two octets of the addresses WARP endpoints have
var warpPrefixes = []string{"8.47", "162.159", "188.114"}

func mark(ok bool, good string, bad string) string {
	if ok {
		return good
	}
	return bad
}

func flag(value bool, text string) string {
	return mark(value, "✅ ", "❌ ") + text
}

func counted(value bool, text string) string {
	return mark(value, "✅ ", "⚠️  ") + text
}

// globalCheck runs every check and writes the report the user interface shows and people
// paste into bug reports: the text of the shell backend's report, line for line, with the
// settings masked. The settings are those the backend reads (model.Load), with its
// defaults; the file of paths.Settings is shown as it is. Running tells whether the
// backend runs. routerFakeIP asks the backend to check the router itself with a check
// name: whether that worked, and whether the backend answered at all.
//
// With the label of a check name and a port (device), the device that asks (the browser
// of the page) opens connections to that name and port meanwhile: the report tells whether
// its DNS question came to sing-box, whether its connection came through the transparent
// proxy, and, when not, what the kernel did to its packets (a trace of them).
//
// engine tells what the sing-box inside is (podkop.Engine); outbounds tests the outbound of
// every section and the direct one (outboundLines).
func globalCheck(ctx context.Context, paths diag.Paths, config *model.Config, version string, singBoxVersion string, engine string, running bool, routerFakeIP func() (works bool, answered bool), outbounds func() []string, choices func() []string, subscriptions func() []string, bitTorrent func() []string, device *deviceCheck) string {
	settings := &config.Settings
	var lines []string
	add := func(text ...string) { lines = append(lines, text...) }

	// What asks the network is asked at once, each part waiting for its own answer: one
	// after another they add up to several seconds on a slow link.
	settingsContent, _ := os.ReadFile(paths.Settings)
	dhcpContent, _ := os.ReadFile(paths.DHCP)
	dhcp, _ := uci.Parse(dhcpContent)
	if settings == nil {
		settings = new(model.Settings)
	}
	// the devices of layer 3 the interface names of the settings stand for now: the
	// firewall and sing-box use those
	uses := interfaceUses(settings, config.Sources, config.Names())
	names := make([]string, 0, len(uses))
	for _, use := range uses {
		names = append(names, use.name)
	}
	devices := interfaceDevices(names)
	sources := sourceDevices(settings, devices)
	if device != nil {
		device.sources = sources
	}
	var (
		system          *diag.System
		dns             *diag.DNS
		tables          *diag.Firewall
		works, answered bool
		address         string
		outboundResults []string
		choiceResults   []string
		subscriptionAt  []string
		bitTorrentLines []string
		deviceLines     []string
		clockReport     []string
		client          netip.Addr
		asked           sync.WaitGroup
	)
	asks := []func(){
		func() {
			switch {
			case device == nil:
			case !running:
				// the router answers the LAN with its own DNS meanwhile: a check of the
				// device would tell nothing of podkop
				deviceLines = []string{"❌ This device was not checked: sing-box does not run"}
			default:
				deviceLines, client = device.run()
			}
		},
		func() { system = diag.SystemInfo(ctx, version, singBoxVersion, true) },
		func() {
			dns = diag.CheckDNS(ctx, dnsSettings(settings), dhcp)
		},
		func() { tables = diag.CheckFirewall(ctx, nil) },
		func() { clockReport = clockLines(ctx, routerClockFacts) },
		func() { works, answered = routerFakeIP() },
		func() { address = diag.FakeIPAddress(ctx) },
		func() {
			if running && outbounds != nil {
				outboundResults = outbounds()
			}
		},
		func() {
			if running && choices != nil {
				choiceResults = choices()
			}
		},
		func() {
			if running && subscriptions != nil {
				subscriptionAt = subscriptions()
			}
		},
		func() {
			if running && bitTorrent != nil && settings.BitTorrent != "" && settings.BitTorrent != model.BitTorrentOff {
				bitTorrentLines = bitTorrent()
			}
		},
	}
	for _, ask := range asks {
		asked.Add(1)
		go func() {
			defer asked.Done()
			ask()
		}()
	}
	asked.Wait()
	// read once the asks are done, not before them: the trace of the device check is armed
	// first, a scan of every process of the router is slow on a slow one
	listeners := diag.Listeners()

	add("📡 Global check run!", rule, "🛠️ System info")
	add("🕳️ Podkop:        "+system.PodkopVersion+" (latest: "+system.PodkopLatestVersion+")",
		"🕳️ LuCI App:      "+system.LuCIAppVersion,
		"⚙️ Engine:        "+engine,
		"🛜 OpenWrt:       "+system.OpenWrtVersion,
		"🛜 Device:        "+system.DeviceModel)

	add(rule, "🕰️ Clock")
	add(clockReport...)

	add(rule, "➡️ DNS status")
	if dns.Bootstrap != "" {
		add(flag(dns.BootstrapAnswers, "Bootstrap DNS: "+dns.Bootstrap))
	}
	add(dnsServerLines(dns)...)
	add(flag(dns.RouterAnswers, "DNS on router"))
	if settings.DontTouchDHCP {
		add("⚠️ dont_touch_dhcp is enabled. 📄 DHCP config:")
		add(blocks(string(dhcpContent), func(fields []string) bool { return fields[1] == "dnsmasq" })...)
	}
	// who answers the DNS of each interface the LAN comes in on, and where dnsmasq sends it
	for _, lan := range diag.CheckLANDNS(sources, listeners) {
		add(lanDNSLines(lan, running)...)
	}
	// what dnsmasq runs with, not what its settings say: a restart of it that procd lost
	// leaves it with the old configuration
	for _, loaded := range diag.CheckDnsmasq(listeners) {
		add(dnsmasqLoadedLine(loaded))
	}
	// the forwardings of dnsmasq for the names of a domain, with dnsmasq on the LAN or behind
	// another resolver, and those of their domains that podkop's lists have
	forwarded := diag.Forwarded(diag.DnsmasqDomains(listeners))
	var listed []diag.ForwardedDomain
	if running {
		listed = diag.ListedForwards(ctx, forwarded)
	}
	add(forwardingLines(forwarded, listed)...)

	add(rule, "📦 Podkop status")
	// sing-box is a part of the backend: what is asked is whether the backend runs it and
	// whether it listens where the DNS of the LAN and the firewall send to
	singBox := diag.CheckSingBox(running)
	add(flag(singBox.Running, "Podkop runs"),
		flag(singBox.Listening, "Podkop listens for the DNS of the LAN on "+dataplane.DNSServer.String()+
			" and for the transparent proxy on "+dataplane.TProxyAddress+":"+strconv.Itoa(int(dataplane.TProxyPort))))
	// another program on an address sing-box listens on keeps it from starting
	for _, taken := range diag.BackendPorts(listeners) {
		add("❌ " + taken)
	}
	// the mixed proxies of the rules: whether each listens, and whether it asks for a login
	add(diag.MixedProxyLines(config, mixedProxyAddress(config), listeners)...)
	add(ruleDeviceLines(config)...)

	if len(subscriptionAt) > 0 {
		add(rule, "🗂️ Subscriptions")
		add(subscriptionAt...)
	}

	add(rule, "🔌 Interfaces")
	add(interfaceLines(uses, devices, diag.DeviceAddresses)...)

	add(rule, "🧱 NFT rules status")
	add(flag(tables.Table, "Table exist"),
		flag(tables.Mangle, "Rules mangle exist"), counted(tables.MangleCounted, "Rules mangle counters"),
		flag(tables.MangleOutput, "Rules mangle output exist"), counted(tables.MangleOutputCounted, "Rules mangle output counters"),
		flag(tables.Proxy, "Rules proxy exist"), counted(tables.ProxyCounted, "Rules proxy counters"))
	if len(tables.ForeignMarks) > 0 {
		add("⚠️  Additional marking rules found:")
		for _, chain := range tables.ForeignMarks {
			add("\tchain " + chain + " sets a packet mark")
		}
	} else {
		add("✅ Additional marking rules found")
	}
	// the conntrack mark: the detector of BitTorrent keeps 0x0000c000 and 0x0f000000 in it, and
	// a program that writes it whole takes them away
	if len(tables.ForeignConntrackMarks) > 0 {
		add("ℹ️ Chains of other programs that set the conntrack mark (podkop's BitTorrent mode keeps 0x0f00c000 in it):")
		for _, chain := range tables.ForeignConntrackMarks {
			add("\tchain " + chain + " sets a conntrack mark")
		}
	}
	// where the kernel sends what the firewall marked: to the router itself, where the
	// transparent proxy inbound is
	if running {
		for _, marked := range diag.CheckMarkedRoutes(sources, client) {
			add(markedRouteLine(marked))
		}
	}
	if present, values := diag.BridgedTraffic(); present {
		for _, name := range []string{"net.bridge.bridge-nf-call-iptables", "net.bridge.bridge-nf-call-ip6tables"} {
			if value, known := values[name]; known {
				add(mark(value == "0", "✅ ", "❌ ") + name + " = " + value + " (br_netfilter)")
			}
		}
	}

	add(rule, "🌐 IPv6")
	ipv6Routed := false
	if settings.IPv6Routing == model.IPv6Podkop {
		ipv6Routed, _ = netcfg.Present(true)
	}
	add(ipv6Lines(settings, netcfg.IPv6Now(), listeners, ipv6Routed, dhcp)...)

	if len(bitTorrentLines) > 0 {
		add(rule, "🧲 BitTorrent")
		add(bitTorrentLines...)
	}

	add(rule, "📄 Podkop config")
	add(cutSettings(strings.TrimSuffix(diag.MaskSettings(settingsContent), "\n")))

	add(rule, "📄 WAN config")
	networkContent, _ := os.ReadFile(paths.Network)
	network, _ := uci.Parse(networkContent)
	if network != nil && network.Section("wan") != nil {
		add(wanBlock(string(networkContent))...)
	} else {
		add("❌ WAN configuration not found")
	}
	if network != nil {
		for _, section := range network.Sections {
			host := strings.TrimSpace(section.Get("endpoint_host"))
			if host == "" {
				continue
			}
			if host == "engage.cloudflareclient.com" {
				add("⚠️ WARP detected: " + host)
				continue
			}
			octets := strings.SplitN(host, ".", 3)
			if len(octets) < 2 {
				continue
			}
			for _, prefix := range warpPrefixes {
				if octets[0]+"."+octets[1] == prefix {
					add(rule, "⚠️ WARP detected: "+host)
				}
			}
		}
		for _, section := range network.Sections {
			if strings.HasPrefix(section.Type, "wireguard_") && section.Get("route_allowed_ips") == "1" && section.Get("allowed_ips") == "0.0.0.0/0" {
				add(rule, "⚠️ WG Route allowed IP enabled with 0.0.0.0/0")
			}
		}
	}
	if _, err := os.Stat("/etc/init.d/zapret"); err == nil {
		add(rule, "⚠️ Zapret detected")
	}

	add(rule, "🥸 FakeIP status")
	if !answered {
		add("❌ Failed to get FakeIP info")
	} else {
		add(mark(works, "✅ The router's own connections go through podkop (its DNS answers with FakeIP)",
			"⚠️ The router's own connections do NOT go through podkop"))
	}
	parsed, err := netip.ParseAddr(address)
	add(mark(err == nil && dataplane.FakeIPPrefix.Contains(parsed), "✅ Podkop's DNS answers with FakeIP addresses", "❌ Podkop's DNS does NOT answer with FakeIP addresses") +
		mark(address != "", " (a test name got "+address+")", " (a test name got no answer)"))
	if running {
		add(rule, "🌍 Outbounds")
		add(outboundResults...)
		// a VPN section whose test did not pass: the MTU of its tunnel against the way out
		add(vpnMTUHints(config, outboundResults, network, devices, routerMTUFacts)...)
		if len(choiceResults) > 0 {
			add(rule, "🎯 Server choice")
			add(choiceResults...)
		}
	}
	if device != nil {
		add(rule, "🌐 This device")
		add(deviceLines...)
		add(deviceRuleLines(config, client)...)
	}
	return strings.Join(lines, "\n") + "\n"
}

// settingsShown bounds the settings in the report. rpcd passes on no output larger than
// about 256 KiB, and the page then shows no report at all: a list of ten thousand names
// pasted into the settings would take the whole report with it.
const settingsShown = 96 << 10

// cutSettings keeps the settings up to settingsShown, cut at the end of a line.
func cutSettings(text string) string {
	if len(text) <= settingsShown {
		return text
	}
	cut := strings.LastIndexByte(text[:settingsShown], '\n')
	if cut < 0 {
		cut = settingsShown
	}
	return text[:cut] + "\n… " + strconv.Itoa(len(text)-cut) + " bytes more of the settings are left out"
}

// lanDNSLines tells who answers DNS on an interface of the LAN, a line a process. dnsmasq is
// as the backend sets it up when it forwards every name to the DNS inbound only and reads
// no resolv file.
func lanDNSLines(lan diag.LANDNS, running bool) []string {
	where := "DNS on " + lan.Interface
	if len(lan.Addresses) == 0 {
		return []string{"❌ " + where + ": the interface has no address"}
	}
	if len(lan.Holders) == 0 {
		var addresses []string
		for _, address := range lan.Addresses {
			addresses = append(addresses, address.String())
		}
		return []string{"❌ " + where + " (" + strings.Join(addresses, ", ") + "): nobody listens on port 53"}
	}
	var order []int
	processes := make(map[int][]sockets.Listener)
	for _, holder := range lan.Holders {
		if _, seen := processes[holder.PID]; !seen {
			order = append(order, holder.PID)
		}
		processes[holder.PID] = append(processes[holder.PID], holder)
	}
	var result []string
	for _, pid := range order {
		holders := processes[pid]
		who := where + ": " + sockets.Describe(holders)
		if holders[0].Program != "dnsmasq" {
			result = append(result, "⚠️ "+who)
			continue
		}
		if !lan.Dnsmasq {
			result = append(result, "⚠️ "+who+", its configuration not found")
			continue
		}
		asks := len(lan.Servers) == 1 && lan.Servers[0] == dataplane.DNSAddress && lan.NoResolv
		result = append(result, mark(asks, "✅ ", mark(running, "❌ ", "⚠️ "))+who+", "+forwardsText(diag.Forwards{Servers: lan.Servers, NoResolv: lan.NoResolv}))
	}
	return result
}

// forwardingLines tells the forwardings of dnsmasq for the names of a domain (diag.Forwarded)
// and warns of each of their domains that podkop's lists have (listed).
func forwardingLines(forwarded []diag.ForwardedDomain, listed []diag.ForwardedDomain) []string {
	var result, forwardings []string
	for _, domain := range forwarded {
		if !slices.Contains(forwardings, domain.Line) {
			forwardings = append(forwardings, domain.Line)
		}
	}
	if len(forwardings) > 0 {
		result = append(result, "ℹ️ dnsmasq sends the names of these domains to their own servers, not to podkop: "+strings.Join(forwardings, ", "))
	}
	for _, domain := range listed {
		result = append(result, "⚠️ podkop's lists have "+domain.Domain+", but dnsmasq sends its names to their own server ("+domain.Line+
			"): they get no FakeIP address, and the lists route them by their subnets only")
	}
	return result
}

// forwardsText tells where a configuration of dnsmasq sends every name.
func forwardsText(forwards diag.Forwards) string {
	switch {
	case len(forwards.Servers) == 0:
		return "forwards to the servers of its resolv file only"
	case !forwards.NoResolv:
		return "forwards to " + strings.Join(forwards.Servers, ", ") + " and to the servers of its resolv file"
	}
	return "forwards to " + strings.Join(forwards.Servers, ", ") + ", no-resolv"
}

// dnsmasqLoadedLine tells whether a dnsmasq process runs with the configuration written
// for it.
func dnsmasqLoadedLine(loaded diag.DnsmasqLoaded) string {
	who := "dnsmasq (pid " + strconv.Itoa(loaded.PID) + ")"
	if !loaded.Stale {
		return "✅ " + who + " runs with the configuration written for it"
	}
	return "❌ " + who + " runs with an older configuration than the one written for it (written: " +
		forwardsText(loaded.Written) + "; in use: " + forwardsText(loaded.Loaded) +
		"): procd did not start it again; /etc/init.d/dnsmasq restart applies it"
}

// markedRouteLine tells where the kernel sends a marked packet of an interface.
func markedRouteLine(marked diag.MarkedRoute) string {
	from := "Marked packets from " + marked.Interface + " (" + marked.Source.String() + ")"
	switch {
	case marked.Err != nil:
		return "❌ " + from + ": " + marked.Err.Error()
	case marked.Route.Local && marked.Route.Table == dataplane.RoutingTable:
		return "✅ " + from + " go to the router (table " + strconv.Itoa(marked.Route.Table) + ")"
	case marked.Route.Local:
		return "✅ " + from + " go to the router (table " + strconv.Itoa(marked.Route.Table) + ", not " + strconv.Itoa(dataplane.RoutingTable) + ")"
	}
	via := marked.Route.Device
	if marked.Route.Gateway.IsValid() {
		via = marked.Route.Gateway.String() + " dev " + via
	}
	return "❌ " + from + " are routed via " + via + " (table " + strconv.Itoa(marked.Route.Table) + "), not to the router"
}

// blocks returns the lines of the sections of a settings file that a test of the "config"
// line picks, as they are written.
func blocks(content string, pick func(fields []string) bool) []string {
	var result []string
	inside := false
	for _, line := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
		if strings.HasPrefix(line, "config ") {
			fields := strings.Fields(line)
			inside = len(fields) > 1 && pick(fields)
		}
		if inside {
			result = append(result, line)
		}
	}
	return result
}

// wanBlock returns the section of the interface "wan" with its addresses and its
// credentials hidden.
func wanBlock(content string) []string {
	var result []string
	inside := false
	protocol := ""
	for _, line := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
		fields := strings.Fields(line)
		if strings.HasPrefix(line, "config ") {
			inside = len(fields) > 2 && fields[1] == "interface" && fields[2] == "'wan'"
			protocol = ""
		}
		if !inside {
			continue
		}
		isOption := len(fields) > 2 && fields[0] == "option"
		switch {
		case isOption && fields[1] == "proto":
			protocol = fields[2]
			result = append(result, line)
		case isOption && protocol == "'static'" && (fields[1] == "ipaddr" || fields[1] == "netmask" || fields[1] == "gateway"),
			isOption && protocol == "'pppoe'" && (fields[1] == "username" || fields[1] == "password"):
			result = append(result, "        option "+fields[1]+" '******'")
		default:
			result = append(result, line)
		}
	}
	return result
}

// dnsSettings is what the check of the DNS takes of the settings: the list, its mode, and the
// provider's servers netifd knows when the list has a row of the provider.
func dnsSettings(settings *model.Settings) diag.DNSSettings {
	result := diag.DNSSettings{Upstreams: settings.DNSUpstreams, Mode: settings.DNSMode, Bootstrap: settings.BootstrapDNSServer}
	for _, upstream := range settings.DNSUpstreams {
		if upstream.Type == model.DNSTypeProvider {
			result.Providers = netcfg.UplinkDNSServers()
			break
		}
	}
	return result
}

// dnsServerLines are the lines of the DNS servers of the list: the one server as before the
// list, or how the list is asked and a line of each server in its order. A row of the provider
// tells how many servers netifd knows, not their addresses: the report is copied into bug
// reports.
func dnsServerLines(dns *diag.DNS) []string {
	name := func(upstream diag.DNSUpstreamReport) string {
		if upstream.Type == model.DNSTypeProvider {
			count := strconv.Itoa(len(upstream.Providers)) + " servers"
			if len(upstream.Providers) == 1 {
				count = "1 server"
			}
			return "the provider's DNS (" + count + " known to netifd)"
		}
		return upstream.Server + " [" + upstream.Type + "]"
	}
	// a server that replies, but with a refusal, is asked and skipped by sing-box each time
	line := func(upstream diag.DNSUpstreamReport) string {
		if upstream.Refusal != "" {
			return name(upstream) + " (replies " + upstream.Refusal + ")"
		}
		return name(upstream)
	}
	if len(dns.Upstreams) < 2 {
		if len(dns.Upstreams) == 1 {
			return []string{flag(dns.ServerAnswers, "Main DNS: "+line(dns.Upstreams[0]))}
		}
		return []string{flag(dns.ServerAnswers, "Main DNS: "+dns.Server+" ["+dns.Type+"]")}
	}
	mode := "in their order"
	if dns.Mode == model.DNSModeFastest {
		mode = "the fastest first"
	}
	lines := []string{"ℹ️ DNS servers: " + strconv.Itoa(len(dns.Upstreams)) + ", asked " + mode}
	for index, upstream := range dns.Upstreams {
		lines = append(lines, flag(upstream.Answers, "DNS "+strconv.Itoa(index+1)+": "+line(upstream)))
	}
	return lines
}

// mixedProxyAddress is the address the mixed proxies listen on (plan: the service address
// of the settings, or that of the LAN); netifd is asked only when a rule has one.
func mixedProxyAddress(config *model.Config) netip.Addr {
	if !slices.ContainsFunc(config.Sections, func(section model.Section) bool { return section.MixedProxyEnabled }) {
		return netip.Addr{}
	}
	if config.Settings.ServiceListenAddress != "" {
		address, _ := netip.ParseAddr(config.Settings.ServiceListenAddress)
		return address
	}
	address, _ := netcfg.LANAddress()
	return address
}

// ipv6Lines are the lines of IPv6 of the global check: what the router has of it, what the
// settings make of IPv6 traffic and of the DNS answers, whether the inbound of IPv6 listens and
// the routing of IPv6 is there while IPv6 goes through podkop, and the interfaces of the DHCP
// that relay the router's IPv6 from the provider, whose devices get the provider's DNS server.
func ipv6Lines(settings *model.Settings, state netcfg.IPv6State, listeners []sockets.Listener, routed bool, dhcp *uci.Package) []string {
	var lines []string
	switch {
	case !state.Loopback:
		lines = append(lines, "ℹ️ The router has no IPv6 (no address ::1)")
	case state.Global == 0:
		lines = append(lines, "ℹ️ The router has no global IPv6 address"+mark(state.DefaultRoute, ", a default route of IPv6", ""))
	default:
		lines = append(lines, "✅ The router has IPv6: "+strconv.Itoa(state.Global)+" global address(es)"+mark(state.DefaultRoute, ", a default route", ", no default route"))
	}
	switch settings.IPv6Routing {
	case model.IPv6Podkop:
		if !state.Loopback {
			lines = append(lines, "❌ IPv6 traffic is set to go through podkop, but the router has no IPv6: it goes past podkop")
			break
		}
		lines = append(lines, "ℹ️ IPv6 traffic: to the IPv6 subnets of the lists, through podkop")
		listening := false
		inbound := netip.AddrPortFrom(netip.MustParseAddr(dataplane.TProxyAddress6), dataplane.TProxyPort)
		for _, listener := range listeners {
			listening = listening || listener.Protocol == "tcp" && listener.Address == inbound
		}
		lines = append(lines, flag(listening, "Podkop listens for the transparent proxy of IPv6 on "+inbound.String()),
			flag(routed, "The rules and the route of IPv6 of the routing table"))
	default:
		lines = append(lines, "ℹ️ IPv6 traffic: past podkop")
	}
	switch settings.DNSAddresses {
	case model.DNSAddressesIPv4Only:
		lines = append(lines, "ℹ️ DNS answers: IPv4 only")
	case model.DNSAddressesBoth:
		lines = append(lines, "ℹ️ DNS answers: IPv4 and IPv6 (the names of the lists: FakeIP IPv4 only)")
	default:
		lines = append(lines, "ℹ️ DNS answers: IPv4, and IPv6 for a name without IPv4 (the names of the lists: FakeIP IPv4 only)")
	}
	if dhcp != nil {
		for _, section := range dhcp.SectionsOfType("dhcp") {
			// the master of the relay is the side of the provider (wan6), not one of devices
			relayed := (section.Get("ra") == "relay" || section.Get("dhcpv6") == "relay") && section.Get("master") != "1"
			if relayed && len(section.List("dns")) == 0 {
				lines = append(lines, "⚠️ dhcp."+section.Name+" relays IPv6 from the provider: its devices get the provider's DNS server and resolve the names of the lists past podkop (give them the router's: list dns in that section)")
			}
		}
	}
	return lines
}
