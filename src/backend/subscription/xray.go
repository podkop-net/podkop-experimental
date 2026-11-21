package subscription

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Xray JSON: a list of configurations of Xray (Remnawave, 3x-ui, Marzban's forks) or one. Each
// server outbound becomes a share link (madeLink) with what Xray itself would connect with, and
// the link goes through the engine's decoder as a link of a list does. The rest of a
// configuration (its routing, DNS, balancers, inbounds) is the app's and is not taken: the rules
// of podkop choose the servers.
//
// The rule against half-supported servers: every key of an outbound is mapped to a parameter of
// the link, left out by a reviewed list below (each with its reason: a setting of this client
// alone, of the server alone, or of the app's own route), or named in a note. Nothing is dropped
// without a word, and no note holds a value. What Xray would refuse to load, podkop takes where
// it is plain what is meant (a port as text, encryption left empty for none), as the decoder
// takes the same in a link.

// xrayNotServers are the protocols of the outbounds of a configuration that are the app's own,
// not servers: skipped without a word.
var xrayNotServers = map[string]bool{"freedom": true, "blackhole": true, "dns": true, "loopback": true}

// xrayConfig is a configuration as podkop reads it: its name, its outbounds, and what its routing
// sends traffic to.
type xrayConfig struct {
	remarks   string
	outbounds []*xrayOutbound
	tags      map[string]*xrayOutbound
	// routed are the tags the rules of the routing name (outboundTag)
	routed map[string]bool
	// prefixes are those of the selectors of the balancers, fallbacks their fallbackTag
	prefixes  []string
	fallbacks map[string]bool
	// relays are the tags a dialerProxy (or proxySettings) names
	relays map[string]bool
}

type xrayOutbound struct {
	tag      string
	protocol string
	content  json.RawMessage
	// relay is the tag the outbound connects through
	relay  string
	server bool
}

// readXrayConfig reads a configuration; nil when it is not one (no list of outbounds).
func readXrayConfig(content json.RawMessage) *xrayConfig {
	root := objectOf(content)
	if root == nil {
		return nil
	}
	raw := root.raw("outbounds")
	if raw == nil || raw[0] != '[' {
		return nil
	}
	config := &xrayConfig{remarks: root.text("remarks"), tags: make(map[string]*xrayOutbound), routed: make(map[string]bool),
		fallbacks: make(map[string]bool), relays: make(map[string]bool)}
	for _, item := range root.list("outbounds") {
		outbound := objectOf(item)
		if outbound == nil {
			continue
		}
		found := &xrayOutbound{tag: outbound.text("tag"), protocol: strings.ToLower(strings.TrimSpace(outbound.text("protocol"))), content: item}
		found.server = found.protocol != "" && !xrayNotServers[found.protocol]
		found.relay = outbound.child("streamSettings").child("sockopt").text("dialerProxy")
		if found.relay == "" {
			found.relay = outbound.child("proxySettings").text("tag")
		}
		if found.relay != "" && found.relay != found.tag {
			// a relay of another outbound: one that names itself is no relay of another
			config.relays[found.relay] = true
		}
		config.outbounds = append(config.outbounds, found)
		if _, taken := config.tags[found.tag]; !taken && found.tag != "" {
			config.tags[found.tag] = found
		}
	}
	routing := root.child("routing")
	for _, item := range routing.list("rules") {
		if tag := objectOf(item).text("outboundTag"); tag != "" {
			config.routed[tag] = true
		}
	}
	for _, item := range routing.list("balancers") {
		balancer := objectOf(item)
		for _, prefix := range balancer.texts("selector") {
			if prefix != "" {
				config.prefixes = append(config.prefixes, prefix)
			}
		}
		if tag := balancer.text("fallbackTag"); tag != "" {
			config.fallbacks[tag] = true
		}
	}
	return config
}

// xrayOutboundCount is how many server outbounds a configuration has.
func (c *xrayConfig) serverCount() int {
	count := 0
	for _, outbound := range c.outbounds {
		if outbound.server {
			count++
		}
	}
	return count
}

// servers are the outbounds of the configuration that are its servers: the outbound tagged
// proxy, the members of its balancers (by the prefixes of their selectors, and their fallbacks)
// and the servers its rules send traffic to; with none of these, every server outbound but those
// that are only relays of others (dialerProxy).
func (c *xrayConfig) servers() []*xrayOutbound {
	var chosen []*xrayOutbound
	for _, outbound := range c.outbounds {
		if !outbound.server {
			continue
		}
		member := outbound.tag == "proxy" || c.routed[outbound.tag] || c.fallbacks[outbound.tag]
		for _, prefix := range c.prefixes {
			member = member || strings.HasPrefix(outbound.tag, prefix)
		}
		if member && outbound.tag != "" {
			chosen = append(chosen, outbound)
		}
	}
	if len(chosen) > 0 {
		return chosen
	}
	for _, outbound := range c.outbounds {
		if outbound.server && (outbound.tag == "" || !c.relays[outbound.tag]) {
			chosen = append(chosen, outbound)
		}
	}
	return chosen
}

// xrayListing is a server outbound of a configuration before the servers of all of them are put
// together: the server, the link made of it (none for a server that has a reason before the
// decoder), the notes on the chain it is connected through, and where it is listed.
type xrayListing struct {
	server Server
	link   *madeLink
	chain  []string
	// key tells the server apart: its ID; the link, or the listing itself, for one without
	key     string
	remarks string
	tag     string
	// main tells that it is the main server of its configuration
	main bool
}

// readXray takes the servers of Xray JSON: configurations, each a JSON object with outbounds. It
// tells how many configurations there were and how many server outbounds they had.
//
// A configuration is the app's entry for a location (Remnawave: the host, with its relay and its
// variants, DIRECT and VIA a relay, in a balancer) or for a group (a balancer over the servers of
// other entries). Its main server is its outbound tagged proxy or, with none, the one server all
// its servers are (one ID: the variants differ by the chain only, which is a note); a group has
// none. A server is named as the app shows it: by the remarks of the configuration it is the main
// server of (the first one), else of the first one it is listed in; the tags of the outbounds are
// the configuration's own, used only for a configuration without remarks. Each (ID, name) once: the
// variants of one server and the members of a group that are servers of other entries are those
// entries; a server that is the main server of two entries of other names stays two servers, as
// the provider lists it twice. The provider's chain is noted only when every listing of the server
// is chained: one listed directly too is connected directly as the provider also does.
func readXray(configurations []json.RawMessage, decode Decoder) ([]Server, int, int) {
	var listings []*xrayListing
	configs, outbounds := 0, 0
	for _, content := range configurations {
		config := readXrayConfig(content)
		if config == nil {
			continue
		}
		configs++
		outbounds += config.serverCount()
		var made []*xrayListing
		for _, outbound := range config.servers() {
			listing := convertXray(config, outbound, decode)
			listing.key = listing.server.ID
			if listing.key == "" {
				listing.key = "\x00" + listing.server.Link
				if listing.server.Link == "" {
					// no link to tell it by: a listing of its own
					listing.key += "\x00" + strconv.Itoa(len(listings)+len(made))
				}
			}
			made = append(made, listing)
		}
		// the main server: the proxy, else the one server of the configuration
		main := ""
		for _, listing := range made {
			if listing.tag == "proxy" {
				main = listing.key
				break
			}
		}
		if main == "" && len(made) > 0 {
			main = made[0].key
			for _, listing := range made {
				if listing.key != main {
					main = ""
				}
			}
		}
		for _, listing := range made {
			listing.main = main != "" && listing.key == main
		}
		listings = append(listings, made...)
	}
	// the name of a server where it is not the main server: that of its first entry
	entryName := make(map[string]string)
	nameOf := func(listing *xrayListing) string {
		if listing.remarks != "" {
			return listing.remarks
		}
		return listing.tag
	}
	for _, listing := range listings {
		if _, named := entryName[listing.key]; listing.main && !named {
			entryName[listing.key] = nameOf(listing)
		}
	}
	for _, listing := range listings {
		if _, named := entryName[listing.key]; !named {
			entryName[listing.key] = nameOf(listing)
		}
	}
	// the chain is noted when every listing of the server is chained
	chained := make(map[string]bool)
	chains := make(map[string][]string)
	for _, listing := range listings {
		if _, seen := chained[listing.key]; !seen {
			chained[listing.key] = true
		}
		chained[listing.key] = chained[listing.key] && len(listing.chain) > 0
		for _, note := range listing.chain {
			if !slices.Contains(chains[listing.key], note) {
				chains[listing.key] = append(chains[listing.key], note)
			}
		}
	}
	// the entries, each where its main listing is (else its first one), with what that listing
	// says of the server
	type entry struct {
		listing *xrayListing
		name    string
		main    bool
	}
	var entries []*entry
	byKey := make(map[string]*entry)
	for _, listing := range listings {
		name := entryName[listing.key]
		if listing.main {
			name = nameOf(listing)
		}
		name = cleanName(name, len(entries)+1)
		key := listing.key + "\x00" + name
		if known := byKey[key]; known != nil {
			if listing.main && !known.main {
				// the main listing is the entry: in its place, with its notes
				known.listing, known.main = listing, true
				entries = slices.DeleteFunc(entries, func(item *entry) bool { return item == known })
				entries = append(entries, known)
			}
			continue
		}
		byKey[key] = &entry{listing: listing, name: name, main: listing.main}
		entries = append(entries, byKey[key])
	}
	servers := make([]Server, 0, len(entries))
	for _, item := range entries {
		server := item.listing.server
		server.Name = item.name
		if item.listing.link != nil {
			item.listing.link.name = item.name
			server.Link = item.listing.link.String()
		}
		if chained[item.listing.key] {
			server.Notes = append(slices.Clone(chains[item.listing.key]), server.Notes...)
		}
		servers = append(servers, server)
	}
	return servers, configs, outbounds
}

// convertXray makes the server of an outbound: its link through the decoder, the notes of the
// conversion before the warnings of the decoder, those on the chain apart; a reason when it
// cannot be made.
func convertXray(config *xrayConfig, outbound *xrayOutbound, decode Decoder) *xrayListing {
	conversion := &xrayConversion{config: config, outbound: outbound}
	listing := &xrayListing{remarks: config.remarks, tag: outbound.tag}
	conversion.convert()
	if conversion.odd {
		conversion.note("a key of the configuration that is not a name is ignored")
	}
	listing.chain = conversion.chains
	if conversion.reason != "" {
		listing.server = Server{Reason: conversion.reason, Notes: conversion.notes}
		return listing
	}
	listing.link = &conversion.link
	server := parseLink(conversion.link.String(), 1, decode)
	if unverified(server.outbound) {
		conversion.note(unverifiedNote)
	}
	server.Notes = append(conversion.notes, server.Notes...)
	listing.server = server
	return listing
}

type xrayConversion struct {
	config   *xrayConfig
	outbound *xrayOutbound
	link     madeLink
	notes    []string
	reason   string
	// odd tells that a key that is not a name was left out
	odd bool
	// alpn is that of the TLS of the outbound: XHTTP runs over QUIC with h3 alone
	alpn []string
	// fragments are the fragment masks of the older form, a freedom outbound the server is
	// dialed through
	fragments []json.RawMessage
	// chains are the notes on the chain the provider connects the server through
	chains []string
}

func (x *xrayConversion) note(text string) {
	for _, known := range x.notes {
		if known == text {
			return
		}
	}
	x.notes = append(x.notes, text)
}

// refuse gives the server its reason; the first one stays.
func (x *xrayConversion) refuse(reason string) {
	if x.reason == "" {
		x.reason = reason
	}
}

// keyName is a key of the configuration as a note names it: where it is, and the key as written
// when it is a name.
func (x *xrayConversion) keyName(where string, key string) (string, bool) {
	if !optionName(key) {
		x.odd = true
		return "", false
	}
	return where + key, true
}

// account accounts for the keys of an object the conversion did not read: those of the reviewed
// list are left out (silent: key → why), those of the client list with a note that they are the
// app's settings, any other with a note that it is not supported.
func (x *xrayConversion) account(where string, node *object, silent map[string]string, client ...string) {
	for _, key := range node.rest() {
		lower := strings.ToLower(key)
		if _, reviewed := silent[lower]; reviewed {
			continue
		}
		name, plain := x.keyName(where, key)
		if !plain {
			continue
		}
		isClient := false
		for _, known := range client {
			isClient = isClient || known == lower
		}
		if isClient {
			x.note(name + " is a setting of the provider's app and is left out")
		} else {
			x.note(name + " is not supported and is ignored")
		}
	}
}

// The keys left out without a word, each with why: they are the app's own, or the server's.
var (
	// of an outbound
	xrayOutboundSilent = map[string]string{
		"tag":            "the name of the outbound in the configuration: the server is named by the configuration",
		"sendthrough":    "the local address the app sends from: the local route is podkop's",
		"targetstrategy": "how the app resolves the destinations of its connections: podkop's DNS does",
	}
	// of a user of a server (vnext, servers, the flat form)
	xrayUserSilent = map[string]string{
		"level": "the policy level of the user in the app",
		"email": "the name of the user in the app's statistics",
		// infra/conf/vless.go reads it and leaves it out
		"seed": "Xray does not use it",
		// proxy/vless/outbound: connections the client makes before they are asked for
		"testpre": "the client's own connections made ahead",
		// the padding of Vision as the client sends it: the server reads any
		"testseed": "the client's own padding",
		// VMess of Xray is AEAD only (infra/conf/vmess.go has no alterId): alter_id 0
		"alterid": "Xray reads no alterId",
	}
	// of a Shadowsocks server, besides the user's
	xrayShadowsocksSilent = map[string]string{
		"level": "the policy level of the user in the app",
		"email": "the name of the user in the app's statistics",
		// infra/conf/shadowsocks.go has neither: Xray's client sends UDP as Shadowsocks does, its
		// server has no UDP over TCP, and the link of the same host carries none either
		"uot":        "Xray reads no uot",
		"uotversion": "Xray reads no UoTVersion",
		"ivcheck":    "the server's check of repeated IVs",
	}
	// the settings of the transports and the securities: Xray builds them all and dials by the
	// network and the security chosen, so those of another one say nothing
	xrayTransportSettings = map[string]string{
		"rawsettings": "tcp", "tcpsettings": "tcp", "xhttpsettings": "xhttp", "splithttpsettings": "xhttp",
		"kcpsettings": "kcp", "grpcsettings": "grpc", "wssettings": "ws", "httpupgradesettings": "httpupgrade",
		"hysteriasettings": "hysteria", "quicsettings": "quic", "httpsettings": "http", "dssettings": "domainsocket",
		"masquesettings": "masque", "xdrivesettings": "xdrive",
	}
	xrayTLSSilent = map[string]string{
		"enablesessionresumption": "the client's resumption of TLS sessions: the server takes a full handshake",
		"minversion":              "the hello of the fingerprint sets the versions (Chrome's when none is named)",
		"maxversion":              "the hello of the fingerprint sets the versions (Chrome's when none is named)",
		"curvepreferences":        "the hello of the fingerprint sets the curves (Chrome's when none is named)",
		"masterkeylog":            "a file of the app's keys, for debugging",
		"usesystemca":             "the app's choice of roots: sing-box verifies against the system's",
		"echsockopt":              "the local route of the app's query for the ECH configuration",
		"rejectunknownsni":        "the server's own",
		"show":                    "the app's debug output",
		"echserverkeys":           "the server's own",
	}
	xrayREALITYSilent = map[string]string{
		"show":                  "the app's debug output",
		"masterkeylog":          "a file of the app's keys, for debugging",
		"target":                "the server's own",
		"dest":                  "the server's own",
		"type":                  "the server's own",
		"xver":                  "the server's own",
		"servernames":           "the server's own",
		"privatekey":            "the server's own",
		"minclientver":          "the server's own",
		"maxclientver":          "the server's own",
		"maxtimediff":           "the server's own",
		"shortids":              "the server's own",
		"mldsa65seed":           "the server's own",
		"limitfallbackupload":   "the server's own",
		"limitfallbackdownload": "the server's own",
	}
	// of the sockets of the app: the local route, the marks and the tuning of this client
	xraySockoptSilent = map[string]string{
		"mark":                 "the routing mark of the app: the marks are podkop's",
		"interface":            "the interface the app leaves by: the local route is podkop's",
		"domainstrategy":       "how the app resolves the server's name: podkop's resolver does",
		"tproxy":               "the app's transparent proxy",
		"acceptproxyprotocol":  "the server's own",
		"tcpkeepaliveinterval": "the client's keepalive of TCP",
		"tcpkeepaliveidle":     "the client's keepalive of TCP",
		"tcpcongestion":        "the congestion control of the client's sockets",
		"tcpwindowclamp":       "the client's tuning of its sockets",
		"tcpmaxseg":            "the client's tuning of its sockets",
		"tcpusertimeout":       "the client's limit of data not acknowledged",
		"penetrate":            "a setting of the app's own sockets (TProxy)",
		"v6only":               "a setting of a listener",
		"tcpmptcp":             "Multipath TCP of the client: the server takes plain TCP",
		"customsockopt":        "raw options of the app's sockets, never taken from a subscription",
		"happyeyeballs":        "how the app races the addresses of a name",
		"trustedxforwardedfor": "the server's own",
	}
	xrayAcceptSilent = map[string]string{
		"acceptproxyprotocol": "the server's own",
	}
	xrayGRPCSilent = map[string]string{
		"idle_timeout":          "the client's keepalive of HTTP/2",
		"health_check_timeout":  "the client's keepalive of HTTP/2",
		"permit_without_stream": "the client's keepalive of HTTP/2",
		"initial_windows_size":  "the client's windows of HTTP/2",
	}
	xrayHTTPSilent = map[string]string{
		"read_idle_timeout":    "the client's keepalive of HTTP/2",
		"health_check_timeout": "the client's keepalive of HTTP/2",
	}
	xrayHysteriaSilent = map[string]string{
		"udpidletimeout": "how long the app keeps an idle UDP session",
		"masquerade":     "the server's own",
	}
	xrayMuxSilent = map[string]string{
		"enabled": "read", "concurrency": "a setting of the mux, which is not used",
		"xudpconcurrency": "a setting of the mux, which is not used", "xudpproxyudp443": "a setting of the mux, which is not used",
	}
	// the QUIC of Hysteria: the tuning of this client; its congestion control and the speeds of
	// Brutal are read. udpHop is not a key of Xray's quicParams (infra/conf QuicParamsConfig):
	// Xray hops by the udphop mask alone, and Remnawave writes it for sing-box and mihomo
	xrayQUICSilent = map[string]string{
		"congestion": "read", "brutalup": "read", "brutaldown": "read",
		"udphop":                        "Xray does not read it",
		"debug":                         "the app's debug output",
		"bbrprofile":                    "the client's congestion control",
		"brutaldisablelosscompensation": "the client's congestion control",
		"initstreamreceivewindow":       "the client's windows of QUIC",
		"maxstreamreceivewindow":        "the client's windows of QUIC",
		"initconnectionreceivewindow":   "the client's windows of QUIC",
		"maxconnectionreceivewindow":    "the client's windows of QUIC",
		"maxidletimeout":                "the client's keepalive of QUIC",
		"keepaliveperiod":               "the client's keepalive of QUIC",
		"disablepathmtudiscovery":       "the client's tuning of QUIC",
		"disablechromeparrot":           "the client's tuning of QUIC",
		"disablegso":                    "the client's tuning of QUIC",
		"maxincomingstreams":            "the client's tuning of QUIC",
		"disablestatelessreset":         "the client's tuning of QUIC",
	}
	xrayFreedomSilent = map[string]string{
		"domainstrategy": "how the app resolves the server's name: podkop's resolver does",
		"targetstrategy": "how the app resolves the server's name: podkop's resolver does",
		"userlevel":      "the policy level of the app",
		"ipsblocked":     "the app's own filter of addresses",
		"firewall":       "the app's own filter of addresses",
		"finalrules":     "the app's own filter of addresses",
	}
)

func (x *xrayConversion) convert() {
	outbound := objectOf(x.outbound.content)
	protocol := x.outbound.protocol
	outbound.raw("protocol")
	settings := outbound.child("settings")
	stream := outbound.child("streamSettings")
	switch protocol {
	case "vless":
		x.vless(settings)
	case "vmess":
		x.vmess(settings)
	case "trojan":
		x.trojan(settings)
	case "shadowsocks":
		x.shadowsocks(settings)
	case "socks":
		x.socks(settings)
	case "http":
		x.httpProxy(settings)
	case "hysteria":
		x.hysteria(settings, stream)
	default:
		if optionName(protocol) {
			x.refuse("a server of type " + protocol + " is not taken from a subscription")
		} else {
			x.refuse("a server of a type podkop does not know is not taken from a subscription")
		}
		return
	}
	if x.reason != "" {
		return
	}
	if relay := x.config.tags[x.outbound.relay]; relay != nil && relay.protocol == "freedom" && relay != x.outbound {
		// the older form of the cut of the hello, before the masks are read
		x.freedom(objectOf(relay.content))
	}
	if protocol != "hysteria" {
		x.stream(stream, protocol)
	}
	if x.reason != "" {
		return
	}
	if mux := outbound.child("mux"); mux != nil {
		if mux.flag("enabled") {
			x.note("Xray's mux is not in sing-box: the server is used without it")
		}
		x.account("mux.", mux, xrayMuxSilent)
	}
	if proxy := outbound.child("proxySettings"); proxy != nil {
		proxy.raw("tag")
		x.account("proxySettings.", proxy, map[string]string{"transportlayer": "how Xray chains through the relay"})
	}
	x.chain()
	x.account("", outbound, xrayOutboundSilent)
}

// endpoint reads the address and the port of a server into the link; false when either is not
// one.
func (x *xrayConversion) endpoint(server *object) bool {
	host, plain := serverHost(server.text("address"))
	if !plain {
		x.refuse("the address of the server is not an address")
		return false
	}
	port, isPort := server.port("port")
	if !isPort {
		x.refuse("the port of the server is not a port")
		return false
	}
	x.link.host, x.link.port = host, port
	return true
}

// single is the one server of a list (vnext, servers) or of the flat form, and its one user (the
// flat form is its own user): Xray takes one of each in an outbound and refuses several.
func (x *xrayConversion) single(settings *object, list string, users bool) (*object, *object) {
	if settings == nil {
		x.refuse("the outbound has no settings")
		return nil, nil
	}
	if settings.has("address") {
		// the flat form, which Xray takes before the list
		settings.raw(list)
		return settings, settings
	}
	items := settings.list(list)
	if len(items) != 1 {
		x.refuse("the outbound names several servers or none, which Xray does not take")
		return nil, nil
	}
	server := objectOf(items[0])
	if server == nil {
		x.refuse("the outbound names no server")
		return nil, nil
	}
	x.account("settings.", settings, nil)
	if !users {
		return server, server
	}
	accounts := server.list("users")
	switch len(accounts) {
	case 0:
		return server, nil
	case 1:
		return server, objectOf(accounts[0])
	}
	x.refuse("the outbound names several users, which Xray does not take")
	return nil, nil
}

func (x *xrayConversion) vless(settings *object) {
	server, user := x.single(settings, "vnext", true)
	if server == nil || !x.endpoint(server) {
		return
	}
	if user == nil {
		x.refuse("the outbound names no user")
		return
	}
	x.link.scheme = "vless"
	x.link.user = linkUser(user.text("id"))
	encryption := user.text("encryption")
	if encryption == "" {
		// Xray asks for "none" to be written; nothing else is meant
		encryption = "none"
	}
	x.link.set("encryption", encryption)
	x.link.set("flow", user.text("flow"))
	if user.has("reverse") {
		x.note("reverse is a setting of the provider's app and is left out")
	}
	if user != server {
		x.account("settings.vnext.", server, nil)
		x.account("settings.vnext.users.", user, xrayUserSilent)
	} else {
		x.account("settings.", server, xrayUserSilent)
	}
}

func (x *xrayConversion) vmess(settings *object) {
	server, user := x.single(settings, "vnext", true)
	if server == nil || !x.endpoint(server) {
		return
	}
	if user == nil {
		x.refuse("the outbound names no user")
		return
	}
	x.link.scheme = "vmess"
	x.link.user = linkUser(user.text("id"))
	x.link.set("encryption", user.text("security"))
	for _, experiment := range strings.Split(user.text("experiments"), "|") {
		switch experiment = strings.TrimSpace(experiment); strings.ToLower(experiment) {
		case "":
		case "authenticatedlength":
			// the length of a chunk authenticated: the server expects it
			x.link.set("sb.authenticated_length", "true")
		case "noterminationsignal":
			// the client does not send the end of the stream: the server takes either
		default:
			if optionName(experiment) {
				x.note("the VMess experiment " + experiment + " is not supported and is ignored")
			} else {
				x.note("a VMess experiment is not supported and is ignored")
			}
		}
	}
	if user != server {
		x.account("settings.vnext.", server, nil)
		x.account("settings.vnext.users.", user, xrayUserSilent)
	} else {
		x.account("settings.", server, xrayUserSilent)
	}
}

func (x *xrayConversion) trojan(settings *object) {
	server, _ := x.single(settings, "servers", false)
	if server == nil || !x.endpoint(server) {
		return
	}
	x.link.scheme = "trojan"
	x.link.user = linkUser(server.text("password"))
	// Xray refuses a flow of Trojan; the decoder warns of it
	x.link.set("flow", server.text("flow"))
	x.account("settings.", server, xrayUserSilent)
}

func (x *xrayConversion) shadowsocks(settings *object) {
	server, _ := x.single(settings, "servers", false)
	if server == nil || !x.endpoint(server) {
		return
	}
	x.link.scheme = "ss"
	// SIP002: the method and the password in base64, as Remnawave writes its links
	x.link.user = base64.RawURLEncoding.EncodeToString([]byte(server.text("method") + ":" + server.text("password")))
	x.account("settings.", server, xrayShadowsocksSilent)
}

// userPassword is the user of a link of a SOCKS or HTTP proxy: the name and the password.
func (x *xrayConversion) userPassword(user *object, name string, password string) {
	if user == nil {
		return
	}
	login, secret := user.text(name), user.text(password)
	if strings.Contains(login, ":") {
		x.refuse("the user name of the proxy has a colon, which a link cannot carry")
		return
	}
	if login != "" || secret != "" {
		x.link.user = linkUser(login) + ":" + linkUser(secret)
	}
}

func (x *xrayConversion) socks(settings *object) {
	server, user := x.single(settings, "servers", true)
	if server == nil || !x.endpoint(server) {
		return
	}
	x.link.scheme = "socks5"
	if user == server {
		x.userPassword(user, "user", "pass")
		x.account("settings.", server, xrayUserSilent)
		return
	}
	x.userPassword(user, "user", "pass")
	x.account("settings.servers.", server, nil)
	x.account("settings.servers.users.", user, xrayUserSilent)
}

func (x *xrayConversion) httpProxy(settings *object) {
	// the headers of the request to the proxy (CONNECT), beside the servers
	headers := settings.child("headers")
	server, user := x.single(settings, "servers", true)
	if server == nil || !x.endpoint(server) {
		return
	}
	x.link.scheme = "http"
	x.userPassword(user, "user", "pass")
	x.headers("sb.headers.", headers, nil, false)
	switch {
	case user == server:
		x.account("settings.", server, xrayUserSilent)
	case user != nil:
		x.account("settings.servers.", server, nil)
		x.account("settings.servers.users.", user, xrayUserSilent)
	default:
		x.account("settings.servers.", server, nil)
	}
}

// headers puts the headers of a transport into the link by their paths (sb.<path>.<Name>): the
// names of headers are names, the values whole. host takes a Host among them.
func (x *xrayConversion) headers(path string, headers *object, host *string, stringList bool) {
	if headers == nil {
		return
	}
	names := make([]string, 0, len(headers.values))
	for name := range headers.values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		// a list of values (Xray's StringList, which splits a text by commas) or one value
		values := []string{headers.text(name)}
		if stringList {
			values = headers.texts(name)
		}
		if strings.EqualFold(name, "host") && host != nil {
			if *host == "" && len(values) > 0 {
				*host = strings.Join(values, ",")
			}
			continue
		}
		if !optionName(name) || strings.Contains(name, ".") {
			x.odd = true
			continue
		}
		if len(values) > 0 {
			// Xray sends one of a list of values; sing-box would send them all
			x.link.set(path+name, pathText(values[0]))
		}
		if len(values) > 1 {
			x.note("only the first of the values of the header " + name + " is sent")
		}
	}
}

// hysteria reads Xray's Hysteria (version 2, over its own transport) as the engine's Hysteria 2.
func (x *xrayConversion) hysteria(settings *object, stream *object) {
	if settings == nil {
		x.refuse("the outbound has no settings")
		return
	}
	if version, _ := settings.number("version"); version != 2 {
		x.refuse("a Hysteria server of another version than 2 is not supported")
		return
	}
	if !x.endpoint(settings) {
		return
	}
	x.account("settings.", settings, xrayUserSilent)
	x.link.scheme, x.link.slash = "hysteria2", true
	network := strings.ToLower(stream.text("network"))
	if network != "hysteria" {
		x.refuse("a Hysteria server over another transport is not supported")
		return
	}
	transport := stream.child("hysteriaSettings")
	transport.raw("version")
	x.link.user = linkUser(transport.text("auth"))
	x.account("streamSettings.hysteriaSettings.", transport, xrayHysteriaSilent)
	switch security := strings.ToLower(stream.text("security")); security {
	case "tls":
		x.tls(stream.child("tlsSettings"), true)
	default:
		x.refuse("a Hysteria server without TLS is not supported")
		return
	}
	x.finalMask(stream.child("finalmask"), "hysteria")
	x.sockopt(stream.child("sockopt"))
	silent := map[string]string{"network": "read", "security": "read", "tlssettings": "read", "finalmask": "read", "sockopt": "read", "hysteriasettings": "read"}
	for key := range xrayTransportSettings {
		silent[key] = "the settings of a transport the outbound does not use"
	}
	silent["realitysettings"] = "the settings of a security the outbound does not use"
	x.account("streamSettings.", stream, silent)
}

// stream reads the transport, the security, the sockets and the masks of an outbound over TCP.
func (x *xrayConversion) stream(stream *object, protocol string) {
	network := strings.ToLower(strings.TrimSpace(stream.text("method")))
	if network == "" {
		network = strings.ToLower(strings.TrimSpace(stream.text("network")))
	}
	stream.raw("network")
	security := strings.ToLower(strings.TrimSpace(stream.text("security")))
	switch network {
	case "", "raw", "tcp":
		network = "tcp"
	case "websocket":
		network = "ws"
	case "splithttp":
		network = "xhttp"
	case "mkcp":
		network = "kcp"
	case "h2":
		network = "http"
	}
	switch protocol {
	case "socks":
		if (security != "" && security != "none") || network != "tcp" {
			x.refuse("SOCKS over TLS or over a transport is not supported")
			return
		}
	case "http":
		if network != "tcp" {
			x.refuse("an HTTP proxy over a transport is not supported")
			return
		}
		if security == "reality" {
			x.refuse("an HTTP proxy over REALITY is not supported")
			return
		}
	}
	silent := map[string]string{"network": "read", "method": "read", "security": "read", "sockopt": "read", "finalmask": "read"}
	for key, transport := range xrayTransportSettings {
		if transport != network {
			silent[key] = "the settings of a transport the outbound does not use"
		}
	}
	// the security first: XHTTP with h3 alone runs over QUIC
	switch security {
	case "", "none":
		silent["tlssettings"] = "the settings of a security the outbound does not use"
		silent["realitysettings"] = "the settings of a security the outbound does not use"
		if protocol != "http" && protocol != "socks" {
			x.link.set("security", "none")
		}
	case "tls":
		silent["realitysettings"] = "the settings of a security the outbound does not use"
		if protocol == "http" {
			x.link.scheme = "https"
		} else {
			x.link.set("security", "tls")
		}
		x.tls(stream.child("tlsSettings"), false)
	case "reality":
		silent["tlssettings"] = "the settings of a security the outbound does not use"
		x.link.set("security", "reality")
		x.reality(stream.child("realitySettings"))
	default:
		// the decoder refuses it with its reason (xtls)
		silent["tlssettings"] = "the settings of a security the outbound does not use"
		silent["realitysettings"] = "the settings of a security the outbound does not use"
		if !optionName(security) {
			x.refuse("unsupported security")
			return
		}
		x.link.set("security", security)
	}
	udp := x.transport(stream, network, protocol)
	if x.reason != "" {
		return
	}
	x.finalMask(stream.child("finalmask"), map[bool]string{true: "udp", false: "tcp"}[udp])
	x.sockopt(stream.child("sockopt"))
	x.account("streamSettings.", stream, silent)
}

// transport reads the settings of the transport into the link; it tells whether the transport
// carries UDP of its own, on which the masks of UDP act.
func (x *xrayConversion) transport(stream *object, network string, protocol string) bool {
	switch network {
	case "tcp":
		settings := stream.child("rawSettings")
		if settings == nil {
			settings = stream.child("tcpSettings")
		} else {
			stream.raw("tcpSettings")
		}
		if protocol == "socks" || protocol == "http" {
			// the links of proxies have no transport
			if kind := strings.ToLower(settings.child("header").text("type")); kind != "" && kind != "none" {
				x.refuse("a proxy with a header of the TCP transport is not supported")
			}
			x.account("streamSettings.tcpSettings.", settings, xrayAcceptSilent)
			return false
		}
		x.link.set("type", "tcp")
		x.tcpHeader(settings.child("header"))
		x.account("streamSettings.tcpSettings.", settings, xrayAcceptSilent)
		return false
	case "ws", "httpupgrade":
		key := "wsSettings"
		if network == "httpupgrade" {
			key = "httpupgradeSettings"
		}
		settings := stream.child(key)
		x.link.set("type", network)
		x.link.set("path", settings.text("path"))
		host := settings.text("host")
		// Xray: host before a Host header (HTTPUpgrade refuses the header; podkop takes host)
		x.headers("sb.transport.headers.", settings.child("headers"), &host, false)
		x.link.set("host", host)
		if network == "ws" {
			if period, found := settings.number("heartbeatPeriod"); found && period > 0 {
				x.link.set("heartbeatPeriod", strconv.FormatFloat(period, 'f', -1, 64))
			}
		}
		x.account("streamSettings."+key+".", settings, xrayAcceptSilent)
		return false
	case "grpc":
		settings := stream.child("grpcSettings")
		x.link.set("type", "grpc")
		x.link.set("serviceName", settings.text("serviceName"))
		if settings.flag("multiMode") {
			x.link.set("mode", "multi")
		} else {
			x.link.set("mode", "gun")
		}
		x.link.set("authority", settings.text("authority"))
		x.account("streamSettings.grpcSettings.", settings, xrayGRPCSilent, "user_agent")
		return false
	case "xhttp":
		settings := stream.child("xhttpSettings")
		if settings == nil {
			settings = stream.child("splithttpSettings")
		} else {
			stream.raw("splithttpSettings")
		}
		x.link.set("type", "xhttp")
		x.link.set("path", settings.text("path"))
		x.link.set("host", settings.text("host"))
		x.link.set("mode", settings.text("mode"))
		x.link.set("extra", string(x.xhttpExtra(settings)))
		return len(x.alpn) == 1 && strings.EqualFold(x.alpn[0], "h3")
	case "kcp":
		// the decoder refuses it, with its reason
		stream.raw("kcpSettings")
		x.link.set("type", "kcp")
		return true
	case "quic":
		settings := stream.child("quicSettings")
		x.link.set("type", "quic")
		x.link.set("quicSecurity", settings.text("security"))
		settings.raw("key")
		x.link.set("headerType", settings.child("header").text("type"))
		x.account("streamSettings.quicSettings.", settings, nil)
		return true
	case "http":
		settings := stream.child("httpSettings")
		x.link.set("type", "http")
		x.link.set("host", strings.Join(settings.texts("host"), ","))
		x.link.set("path", settings.text("path"))
		x.link.set("method", settings.text("method"))
		x.headers("sb.transport.headers.", settings.child("headers"), nil, true)
		x.account("streamSettings.httpSettings.", settings, xrayHTTPSilent)
		return false
	case "hysteria":
		x.refuse("the Hysteria transport is supported with the Hysteria protocol only")
		return false
	}
	if !optionName(network) {
		x.refuse("unsupported transport")
		return false
	}
	// masque, xdrive and what comes after: the decoder refuses them, with its reason
	x.link.set("type", network)
	return false
}

// tcpHeader reads the header of the TCP transport: HTTP's request is the http transport of
// sing-box (without TLS: the decoder refuses it with TLS).
func (x *xrayConversion) tcpHeader(header *object) {
	if header == nil {
		return
	}
	kind := strings.ToLower(header.text("type"))
	switch kind {
	case "", "none":
	case "http":
		x.link.set("headerType", "http")
		request := header.child("request")
		x.link.set("path", strings.Join(request.texts("path"), ","))
		host := ""
		x.headers("sb.transport.headers.", request.child("headers"), &host, true)
		x.link.set("host", host)
		// the server reads the request whatever its method and version, and sing-box writes its
		// own (lab of the decoder, LINKS.md: the HTTP header of the TCP transport)
		x.account("streamSettings.tcpSettings.header.request.", request, map[string]string{
			"method": "the server takes any", "version": "the server takes any"})
		// what the server answers is the server's own
		header.raw("response")
	default:
		if optionName(kind) {
			// the decoder refuses it, with its reason
			x.link.set("headerType", kind)
		} else {
			x.refuse("unsupported header type of the TCP transport")
		}
	}
	x.account("streamSettings.tcpSettings.header.", header, nil)
}

// xhttpExtra is the extra of a link of XHTTP: Xray's extra replaces all the settings but the
// host, the path and the mode (infra/conf SplitHTTPConfig.Build); without one, the settings
// themselves are. What the decoder reads of it, and the notes on what it does not, are its own.
func (x *xrayConversion) xhttpExtra(settings *object) json.RawMessage {
	if settings == nil {
		return nil
	}
	settings.raw("host")
	settings.raw("path")
	settings.raw("mode")
	var content json.RawMessage
	if extra := settings.raw("extra"); extra != nil {
		content = extra
		// Xray reads extra in their place
		for _, key := range settings.rest() {
			settings.raw(key)
		}
	} else {
		content = settings.without("host", "path", "mode")
		for _, key := range settings.rest() {
			settings.raw(key)
		}
	}
	if content == nil {
		return nil
	}
	cleaned, err := cleanXHTTP(content)
	if err != nil {
		x.note("the extra settings of XHTTP cannot be read and are ignored")
		return nil
	}
	return cleaned
}

// cleanXHTTP takes out of the settings of XHTTP what is the server's alone (h2Params) and, in
// the settings of the download, the keys of TLS, REALITY and the sockets this client leaves out
// anyway (the reviewed lists), so that the decoder notes only what matters.
func cleanXHTTP(content json.RawMessage) (json.RawMessage, error) {
	var settings map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.UseNumber()
	if err := decoder.Decode(&settings); err != nil {
		return nil, err
	}
	if settings == nil {
		return nil, nil
	}
	drop := func(node map[string]any, silent map[string]string) {
		for key := range node {
			if _, reviewed := silent[strings.ToLower(key)]; reviewed {
				delete(node, key)
			}
		}
	}
	drop(settings, map[string]string{"h2params": "the server's own"})
	for key, value := range settings {
		download, isObject := value.(map[string]any)
		if !strings.EqualFold(key, "downloadSettings") || !isObject {
			continue
		}
		for name, inner := range download {
			node, isNode := inner.(map[string]any)
			if !isNode {
				continue
			}
			switch strings.ToLower(name) {
			case "tlssettings":
				drop(node, xrayTLSSilent)
			case "realitysettings":
				drop(node, xrayREALITYSilent)
			case "sockopt":
				drop(node, xraySockoptSilent)
				if len(node) == 0 {
					delete(download, name)
				}
			}
		}
	}
	return json.Marshal(settings)
}

// tls reads Xray's TLS settings into the link; quic for Hysteria, which has no fingerprint and
// asks for h3 when no ALPN is named.
func (x *xrayConversion) tls(settings *object, quic bool) {
	where := "streamSettings.tlsSettings."
	x.link.set("sni", settings.text("serverName"))
	x.alpn = settings.texts("alpn")
	if !(quic && len(x.alpn) == 1 && strings.EqualFold(x.alpn[0], "h3")) {
		x.link.set("alpn", strings.Join(x.alpn, ","))
	}
	fingerprint := settings.text("fingerprint")
	if !quic {
		// none is Chrome's, in Xray (tls.GetFingerprint) as in the decoder
		x.link.set("fp", fingerprint)
	}
	// over QUIC no browser's hello is imitated: the hello is the QUIC library's own
	if settings.flag("allowInsecure") {
		// Xray 26 refuses it (pins and vcn in its place); older Xray and the links take it
		x.link.set("allowInsecure", "1")
	}
	x.link.set("pcs", settings.text("pinnedPeerCertSha256"))
	x.link.set("vcn", settings.text("verifyPeerCertByName"))
	x.link.set("ech", settings.text("echConfigList"))
	x.link.set("cs", settings.text("cipherSuites"))
	if certificates := settings.list("certificates"); len(certificates) > 0 {
		// the roots to trust, given in the configuration; files and the client's own
		// certificates are not taken
		var roots []string
		taken := true
		for _, item := range certificates {
			certificate := objectOf(item)
			lines := certificate.texts("certificate")
			if !strings.EqualFold(certificate.text("usage"), "verify") || len(lines) == 0 {
				taken = false
				continue
			}
			roots = append(roots, lines...)
		}
		if !taken {
			x.note(where + "certificates is a setting of the provider's app and is left out")
		}
		x.link.set("cert", strings.Join(roots, "\n"))
	}
	x.account(where, settings, xrayTLSSilent, "echforcequery", "disablesystemroot")
}

func (x *xrayConversion) reality(settings *object) {
	x.link.set("sni", settings.text("serverName"))
	x.link.set("fp", settings.text("fingerprint"))
	// "password" is the name of the public key since Xray 25, and wins (infra/conf REALITYConfig)
	key, older := settings.text("password"), settings.text("publicKey")
	if key == "" {
		key = older
	}
	x.link.set("pbk", key)
	x.link.set("sid", settings.text("shortId"))
	x.link.set("spx", settings.text("spiderX"))
	x.link.set("pqv", settings.text("mldsa65Verify"))
	x.account("streamSettings.realitySettings.", settings, xrayREALITYSilent)
}

// sockopt reads the settings of the sockets: the relay (dialerProxy, see chain), TCP Fast Open;
// the rest is the app's own route and tuning.
func (x *xrayConversion) sockopt(settings *object) {
	if settings == nil {
		return
	}
	settings.raw("dialerProxy")
	if value := settings.raw("tcpFastOpen"); value != nil {
		// true, or a length of the queue: a number above 0 (infra/conf SocketConfig)
		var on bool
		var number float64
		if json.Unmarshal(value, &on) == nil && on || json.Unmarshal(value, &number) == nil && number > 0 {
			x.link.set("tfo", "1")
		}
	}
	if strategy := strings.ToLower(settings.text("addressPortStrategy")); strategy != "" && strategy != "none" {
		x.refuse("the address and the port of the server come from DNS records (addressPortStrategy), which podkop does not read")
	}
	x.account("streamSettings.sockopt.", settings, xraySockoptSilent)
}

// finalMask makes the fm of the link: the masks of the outbound the decoder reads, without those
// that never act on this connection. on is tcp (a transport over TCP: the masks of UDP never act
// on it), udp (one with UDP of its own: both) or hysteria (QUIC: the masks of TCP never act).
func (x *xrayConversion) finalMask(mask *object, on string) {
	var tcp, udp []json.RawMessage
	if on != "hysteria" {
		tcp = append(tcp, x.fragments...)
	}
	if mask != nil {
		for _, item := range mask.list("tcp") {
			// the filter is a listener's: on a client it does nothing (finalmask/filter)
			if on != "hysteria" && !strings.EqualFold(objectOf(item).text("type"), "filter") {
				tcp = append(tcp, item)
			}
		}
		for _, item := range mask.list("udp") {
			if on != "tcp" && !strings.EqualFold(objectOf(item).text("type"), "filter") {
				udp = append(udp, item)
			}
		}
	}
	final := make(map[string]any)
	if len(tcp) > 0 {
		final["tcp"] = tcp
	}
	if len(udp) > 0 {
		final["udp"] = udp
	}
	if quic := mask.child("quicParams"); quic != nil && on == "hysteria" {
		params := make(map[string]any)
		switch congestion := strings.ToLower(quic.text("congestion")); congestion {
		case "", "brutal", "force-brutal":
			// Brutal with the speeds, as Xray's dialer of Hysteria uses them
			if up := quic.raw("brutalUp"); up != nil {
				params["brutalUp"] = up
			}
			if down := quic.raw("brutalDown"); down != nil {
				params["brutalDown"] = down
			}
		default:
			// BBR or Reno: the speeds are not used; sing-box takes BBR without them
			quic.raw("brutalUp")
			quic.raw("brutalDown")
		}
		if len(params) > 0 {
			final["quicParams"] = params
		}
		x.account("finalmask.quicParams.", quic, xrayQUICSilent)
	} else if quic != nil {
		// the QUIC of XHTTP over h3: the tuning of this client, which sing-box's XHTTP has not
		for _, key := range quic.rest() {
			quic.raw(key)
		}
	}
	if mask != nil {
		x.account("streamSettings.finalmask.", mask, nil)
	}
	if len(final) == 0 {
		return
	}
	content, err := json.Marshal(final)
	if err == nil {
		x.link.set("fm", string(content))
	}
}

// chain notes the relay the provider connects the server through: podkop connects it directly
// (the owner, 2026-11-21: a note only at this stage). A freedom outbound with a fragment is the
// older form of the cut of the hello: its fragment becomes a mask, as finalmask has it.
func (x *xrayConversion) chain() {
	relay := x.outbound.relay
	if relay == "" {
		return
	}
	target := x.config.tags[relay]
	shown := shownName(relay)
	switch {
	case target == nil:
		x.chains = append(x.chains, "the provider connects it through "+shown+", which its configuration does not have; podkop connects it directly")
	case target.protocol == "freedom":
		// read before the masks (freedom)
	case target == x.outbound:
		x.chains = append(x.chains, "the provider connects it through itself; podkop connects it directly")
	default:
		x.chains = append(x.chains, "the provider connects it through "+shown+"; podkop connects it directly")
	}
}

// freedom reads a freedom outbound the server is dialed through.
func (x *xrayConversion) freedom(outbound *object) {
	settings := outbound.child("settings")
	if fragment := settings.child("fragment"); fragment != nil {
		mask := map[string]any{}
		if packets := fragment.raw("packets"); packets != nil {
			mask["packets"] = packets
		}
		if length := fragment.raw("length"); length != nil {
			mask["length"] = length
		}
		// the interval between the pieces is the delay of the mask
		if interval := fragment.raw("interval"); interval != nil {
			mask["delay"] = interval
		}
		if split := fragment.raw("maxSplit"); split != nil {
			mask["maxSplit"] = split
		}
		content, err := json.Marshal(map[string]any{"type": "fragment", "settings": mask})
		if err == nil {
			x.fragments = append(x.fragments, content)
		}
		x.account("dialerProxy settings.fragment.", fragment, nil)
	}
	if settings.has("noise") || settings.has("noises") {
		x.note("noise is a setting of the client of Xray and is not applied")
	}
	if settings.text("redirect") != "" {
		x.refuse("the provider's configuration sends the connections of the server to another address (redirect)")
	}
	if version, _ := settings.number("proxyProtocol"); version > 0 {
		x.refuse("the provider's configuration starts the connections of the server with a PROXY header, which is not supported")
	}
	x.account("dialerProxy settings.", settings, xrayFreedomSilent)
	stream := outbound.child("streamSettings")
	if sockopt := stream.child("sockopt"); sockopt != nil {
		var on bool
		var number float64
		if value := sockopt.raw("tcpFastOpen"); value != nil && (json.Unmarshal(value, &on) == nil && on || json.Unmarshal(value, &number) == nil && number > 0) {
			// the connections to the server open with TCP Fast Open
			x.link.set("tfo", "1")
		}
		if relay := sockopt.text("dialerProxy"); relay != "" {
			x.chains = append(x.chains, "the provider connects it through "+shownName(relay)+" too; podkop connects it directly")
		}
		x.account("dialerProxy streamSettings.sockopt.", sockopt, xrayFreedomSockoptSilent)
	}
	x.account("dialerProxy streamSettings.", stream, nil)
}

// xrayFreedomSockoptSilent are the settings of the sockets of the dialer: those of the outbound's
// own, and tcpNoDelay, which Marzban writes and Xray reads no longer (Go sets it on every TCP
// socket)
var xrayFreedomSockoptSilent = func() map[string]string {
	silent := map[string]string{"tcpnodelay": "Go sets it on every TCP socket"}
	for key, why := range xraySockoptSilent {
		silent[key] = why
	}
	return silent
}()
