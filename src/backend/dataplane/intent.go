package dataplane

import "net/netip"

// Intent is what the router needs around a configuration, made of the settings (plan.Build, its
// Result.Dataplane): the rules of the firewall, whether the resolver of the LAN asks the DNS
// inbound, where the Clash API is reached. The firewall's table is an intent with what its sets
// hold, from the rule sets (firewall.Plan); the values that do not depend on the settings are the
// constants of this package.
type Intent struct {
	// Interfaces are the interfaces the firewall takes traffic from: those the settings name,
	// br-lan when they name none.
	Interfaces []string
	// ExcludeNTP leaves UDP port 123 alone.
	ExcludeNTP bool
	// Sources are the devices of the LAN routed whole (fully_routed_ips), IPv4: their traffic
	// goes to the proxy whatever its destination is, the local networks excepted. In block (not
	// the whole LAN), a new connection from outside to a client's socket on one of them is
	// dropped.
	Sources []netip.Prefix
	// TakeDNS tells that the resolver of the LAN is pointed at the DNS inbound; off with
	// dont_touch_dhcp, and then a resolver the backend took is given back.
	TakeDNS bool
	// ClashAPI is where the Clash API of the configuration is reached from the router
	// (host:port: an API open on every address is asked on this host), and ClashSecret its key;
	// the commands of the user interface ask it.
	ClashAPI    string
	ClashSecret string
	// ClashAPIInterfaces are the devices that reach the Clash API, which listens on every
	// address while YACD is on: a chain of the input lets their connections to its port in, and
	// those of the router itself (lo), and drops the others. Those of yacd_interfaces, or
	// Interfaces; none with YACD off: no such chain, the API listens on this host only.
	ClashAPIInterfaces []string
	// BitTorrent is what becomes of the traffic of BitTorrent clients: the detector of the
	// firewall (firewall/bittorrent_linux.go).
	BitTorrent BitTorrent
	// OwnMarks are the routing marks of the interface sources (routing_mark): sing-box gives an
	// outbound with one that mark in place of OutboundMark (route.default_mark), so what the
	// router sends with one of them goes by, as what has OutboundMark does (a mark under its own
	// mask: pbr and mwan3 add their bits).
	OwnMarks []uint32
	// IPv6 tells that the IPv6 traffic to the subnets of the lists goes to their rules: the
	// settings ask for it (model.IPv6Podkop) and the router has IPv6 (plan.Facts.IPv6). The
	// firewall and the routing then have their IPv6 rules, and sing-box the inbound of IPv6;
	// without it the table has nothing of IPv6, and IPv6 goes past the proxy.
	IPv6 bool
}

// BitTorrent is the mode of the BitTorrent detector of the firewall.
type BitTorrent struct {
	// Mode is "" (off), bypass, block or section (model.BitTorrent*, firewall.BitTorrent*).
	Mode string
	// LAN is the scope of the whole LAN, for block and section: every device of the interfaces,
	// not only what the backend takes.
	LAN bool
	// Fan is the allowance of the suspicion by the fan-out of a device's connection openings,
	// for the block and the section of the whole LAN; off when it is nothing.
	Fan Fan
	// RouterUsers are the users (their numbers) of the programs of the router itself whose
	// traffic the mode takes as BitTorrent's ("bittorrent_router_users"): a client on the router
	// sends from the output hook, which the detector does not look at (bt_router).
	RouterUsers []uint32
}
