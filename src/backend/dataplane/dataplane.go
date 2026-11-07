// Package dataplane is what the parts of the backend agree on to carry the traffic of the
// LAN through sing-box: where the DNS inbound listens, the port of the transparent proxy
// and the mark that sends traffic to it, the FakeIP range, the routing table, the firewall
// table, the port of the Clash API, the name sing-box is asked for to tell that it is up.
// The sing-box configuration (plan) is one side of each value; the firewall, the routing
// (netcfg), the resolver of the LAN (dnsmasq), the supervisor and the checks (diag, ctl)
// are the other: a value changed here changes on both sides.
//
// The values are those of the shell backend of podkop 0.7.24, and some are known outside
// this program as well: each says where.
package dataplane

import "net/netip"

const (
	// DNSAddress and DNSPort are where the DNS inbound of sing-box listens: dnsmasq of the
	// LAN forwards to it.
	DNSAddress = "127.0.0.42"
	DNSPort    = 53

	// TProxyAddress and TProxyPort are where the transparent proxy inbound listens: the
	// firewall sends the traffic it marks there.
	TProxyAddress = "127.0.0.1"
	TProxyPort    = 1602

	// ProxyMark is the mark the firewall gives the traffic of the LAN that goes to the
	// proxy; the rule of the routing table sends what has it to the table.
	ProxyMark = 0x00100000

	// RouterMark is the mark the firewall gives what the router itself sends to the proxy;
	// a rule of its own sends it to the table. It is not ProxyMark: the routing of what
	// the router sends and the check of the source of a packet the router receives are
	// both lookups from the loopback, and the rule of ReverseRulePriority sends the latter
	// with ProxyMark to the main table (netcfg).
	RouterMark = 0x00400000

	// OutboundMark is the mark sing-box gives every connection it opens itself
	// (route.default_mark). mangle_output lets what has it go by: a server of sing-box
	// whose address is in the subnets of a section, or in FakeIP's, is not sent back into
	// sing-box. A tunnel of the router with it as its firewall mark (AmneziaWG,
	// WireGuard) goes by the same way. The rule compares it under its mask: mwan3 adds
	// its own bits to the mark of what the router sends.
	OutboundMark = 0x00200000

	// FakeIPRange is the range the FakeIP answers of sing-box come from; the firewall
	// sends every destination of it to the proxy.
	FakeIPRange = "198.18.0.0/15"

	// RoutingTable is the number of the routing table, RoutingTableName its name in
	// /etc/iproute2/rt_tables (the prerm script of the package removes that line by the
	// number and the name), RulePriority the priority of its rule.
	RoutingTable     = 105
	RoutingTableName = "podkop"
	RulePriority     = 105

	// ReverseRulePriority is the priority of the rule that sends the check of the source of
	// a marked packet of the LAN to the main table (netcfg).
	ReverseRulePriority = 104

	// UplinkRulePriority is the priority of the rules that route what sing-box sends from a
	// socket bound to the device of an uplink by the main table (netcfg.RouteUplinks).
	UplinkRulePriority = 106

	// FirewallTable is the nftables table of the backend, of the family inet.
	FirewallTable = "PodkopTable"

	// ClashAPIPort is the port of the Clash API; the page of podkop has it too
	// (getClashApiUrl.ts).
	ClashAPIPort = 9090

	// ReadinessName is the name the supervisor asks the DNS inbound for after a start: an
	// answer from the FakeIP range tells that the DNS inbound, the DNS rules and the FakeIP
	// store work. Every configuration has to answer it from FakeIP (plan keeps a DNS rule for
	// it, and a test of plan holds it to that); without that every start would end in
	// "does not answer" and the LAN would be given back its own DNS. It is under the
	// domain of the check names (probe.Suffix), which the backend answers from FakeIP as
	// well, and it never leaves the router.
	ReadinessName = "ready.fakeipchecker.podkop.net"

	// RunDir keeps what the backend has while it runs, in RAM (/var/run is /tmp/run on
	// OpenWrt): its state, the configuration that runs and the rule-set files. DataDir
	// keeps what stays over a reboot. Neither is a directory of a sing-box package: the
	// backend has sing-box inside and touches nothing of a sing-box installed beside it
	// (/etc/sing-box, /usr/share/sing-box, /etc/config/sing-box).
	RunDir  = "/var/run/podkop"
	DataDir = "/usr/share/podkop"
)

// DNSServer is the address and the port of the DNS inbound, as a DNS client dials it.
var DNSServer = netip.AddrPortFrom(netip.MustParseAddr(DNSAddress), DNSPort)

// FakeIPPrefix is FakeIPRange parsed.
var FakeIPPrefix = netip.MustParsePrefix(FakeIPRange)
