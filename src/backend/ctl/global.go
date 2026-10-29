package ctl

import (
	"context"
	"net/netip"
	"os"
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
func globalCheck(ctx context.Context, paths diag.Paths, config *model.Config, version string, singBoxVersion string, engine string, running bool, routerFakeIP func() (works bool, answered bool), outbounds func() []string, subscriptions func() []string, device *deviceCheck) string {
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
	uses := interfaceUses(settings, config.Sources)
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
		subscriptionAt  []string
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
			dns = diag.CheckDNS(ctx, diag.DNSSettings{Type: settings.DNSType, Server: settings.DNSServer, Bootstrap: settings.BootstrapDNSServer}, dhcp)
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
			if running && subscriptions != nil {
				subscriptionAt = subscriptions()
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
	add(flag(dns.ServerAnswers, "Main DNS: "+dns.Server+" ["+dns.Type+"]"), flag(dns.RouterAnswers, "DNS on router"))
	if settings.DontTouchDHCP {
		add("⚠️ dont_touch_dhcp is enabled. 📄 DHCP config:")
		add(blocks(string(dhcpContent), func(fields []string) bool { return fields[1] == "dnsmasq" })...)
	}
	// who answers the DNS of each interface the LAN comes in on, and where dnsmasq sends it
	for _, lan := range diag.CheckLANDNS(sources, listeners) {
		add(lanDNSLines(lan, running)...)
	}

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
	}
	if device != nil {
		add(rule, "🌐 This device")
		add(deviceLines...)
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
		forwards := "forwards to " + strings.Join(lan.Servers, ", ")
		if len(lan.Servers) == 0 {
			forwards = "forwards to the servers of its resolv file only"
		} else if !lan.NoResolv {
			forwards += " and to the servers of its resolv file"
		} else {
			forwards += ", no-resolv"
		}
		asks := len(lan.Servers) == 1 && lan.Servers[0] == dataplane.DNSAddress && lan.NoResolv
		result = append(result, mark(asks, "✅ ", mark(running, "❌ ", "⚠️ "))+who+", "+forwards)
	}
	return result
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
