package subscription

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"sort"
	"strings"
)

// sing-box JSON: the configuration SFA, SFI and the like get. Its outbounds of the proxy types
// become links of their schemes, every option written by its path (sb.<path>, LINKS.md "Любая
// опция по её пути"), after sing-box itself has read and written the outbound again: an option of
// a syntax this sing-box does not have gives the server its reason, and the outbound is written
// as this sing-box writes it (no option at its default, a list of one as one value), as the
// decoder makes the outbound of a link. Its groups (selector, urltest), direct, block and dns are
// the app's and are skipped, as are its routing and DNS.
//
// Paths and not the parameters of the scheme: a sing-box outbound means what it says in sing-box,
// and the parameters of a scheme are read as Xray reads them (a default fingerprint, the Host of
// WebSocket taken from the server name, no ALPN over WebSocket and gRPC). The few parameters
// written are those whose default would add what the outbound does not say (security=none of
// Trojan), the decoder's own name for a value it reads (encryption of VMess, alpn of TUIC). The
// defaults of sing-box panels write and links leave out (packet_encoding xudp, the ALPN a
// transport asks for anyway, a group switched off) are taken out, so that a server is the server
// of the provider's link: TestSingBoxIDsOfTheLinks and the Remnawave cases hold it.

// singBoxGroups are the outbound types of a configuration that are not servers.
var singBoxGroups = map[string]bool{"selector": true, "urltest": true, "direct": true, "block": true, "dns": true}

// singBoxTypes are the outbound types a link carries (the decoder's schemes).
var singBoxTypes = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "shadowsocks": true, "socks": true, "http": true,
	"hysteria": true, "hysteria2": true, "tuic": true, "anytls": true, "naive": true,
}

// singBoxDenied are the options a link does not set, by their names at any depth, as the
// decoder's policy has them (common/sharelink fallback.go deniedNames, and any name that ends in
// _path but tcp_multi_path: a local file). TestSingBoxDeniedAgreesWithTheDecoder holds this list
// to the decoder's list of every option of every outbound (sharelink testdata/options-1.14.txt):
// an option the engine adds or denies fails it until this list is looked at.
var singBoxDenied = map[string]string{
	"detour": "another object", "domain_resolver": "another object", "netns": "another object", "http_client": "another object",
	"bind_interface": "the local route", "inet4_bind_address": "the local route", "inet6_bind_address": "the local route",
	"bind_address_no_port": "the local route", "reuse_addr": "the local route", "routing_mark": "the local route",
	"protect_path": "the local route", "network_strategy": "the local route", "network_type": "the local route",
	"fallback_network_type": "the local route", "fallback_delay": "the local route",
	"engine": "the system", "kernel_tx": "the system", "kernel_rx": "the system",
	"handshake_timeout": "a limit of this host", "fragment_fallback_delay": "a limit of this host",
	"realm":           "another service",
	"domain_strategy": "deprecated", "pq_signature_schemes_enabled": "deprecated", "dynamic_record_sizing_disabled": "deprecated",
	"recv_window_conn": "deprecated", "recv_window": "deprecated", "disable_mtu_discovery": "deprecated",
}

// singBoxDeniedName tells an option a link does not set, by its name as sing-box reads it: folded
// as encoding/json folds the names of fields (domain_reſolver is domain_resolver).
func singBoxDeniedName(name string) bool {
	name = fold(name)
	if _, denied := singBoxDenied[name]; denied {
		return true
	}
	return strings.HasSuffix(name, "_path") && name != "tcp_multi_path"
}

// singBoxMaps are the options whose keys are names of headers, not of options.
var singBoxMaps = map[string]bool{"headers": true, "extra_headers": true}

// readSingBox takes the servers of a sing-box configuration; it tells how many of its outbounds
// were of the types of servers.
func readSingBox(reading *reading, root *object, codec Codec) ([]Server, int) {
	type entry struct {
		kind, tag string
		content   json.RawMessage
		detour    string
	}
	var entries []entry
	kinds := make(map[string]string)
	referenced := make(map[string]bool)
	relays := make(map[string]bool)
	for _, item := range root.list("outbounds") {
		outbound := objectOf(item)
		if outbound == nil {
			continue
		}
		found := entry{kind: strings.ToLower(strings.TrimSpace(outbound.text("type"))), tag: outbound.text("tag"), content: item, detour: outbound.text("detour")}
		if _, known := kinds[found.tag]; !known {
			kinds[found.tag] = found.kind
		}
		if singBoxGroups[found.kind] {
			for _, member := range outbound.texts("outbounds") {
				referenced[member] = true
			}
			referenced[outbound.text("default")] = true
			continue
		}
		if found.detour != "" {
			relays[found.detour] = true
		}
		entries = append(entries, found)
	}
	route := root.child("route")
	referenced[route.text("final")] = true
	for _, item := range route.list("rules") {
		referenced[objectOf(item).text("outbound")] = true
	}
	var servers []Server
	seen := make(map[string]bool)
	for _, found := range entries {
		if !reading.goes() {
			return nil, 0
		}
		if found.kind == "" || relays[found.tag] && !referenced[found.tag] {
			// a relay of others only, as a dialerProxy of Xray: not a server of its own
			continue
		}
		name := cleanName(found.tag, len(servers)+1)
		server := convertSingBox(found.content, found.kind, name, kinds, codec)
		if !reading.takes(&server) {
			return nil, 0
		}
		key := server.ID + "\x00" + server.Name
		if server.ID == "" {
			key = "\x00" + server.Link + "\x00" + server.Reason + "\x00" + server.Name
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		servers = append(servers, server)
	}
	return servers, len(entries)
}

// singBoxConversion is the conversion of one outbound.
type singBoxConversion struct {
	codec  Codec
	notes  []string
	noted  map[string]bool
	reason string
	odd    bool
}

func (c *singBoxConversion) note(text string) {
	if c.noted[text] {
		return
	}
	if c.noted == nil {
		c.noted = make(map[string]bool)
	}
	c.noted[text] = true
	c.notes = append(c.notes, text)
}

func (c *singBoxConversion) refuse(reason string) {
	if c.reason == "" {
		c.reason = reason
	}
}

// convertSingBox makes the server of an outbound of a sing-box configuration.
func convertSingBox(content json.RawMessage, kind string, name string, kinds map[string]string, codec Codec) Server {
	conversion := &singBoxConversion{codec: codec}
	link, normal := conversion.link(content, kind, name, kinds)
	if conversion.odd {
		conversion.note("an option of the configuration that is not a name is ignored")
	}
	if conversion.reason != "" {
		return Server{Name: name, Reason: conversion.reason, Notes: conversion.notes}
	}
	server := parseLink(link.String(), 1, codec.Decode)
	if quoted := oneValues(normal, server.outbound); len(quoted) > 0 {
		// a list option of one value, which the decoder made a list of: the one value as JSON
		for index := range link.params {
			if quoted[link.params[index].key] {
				content, _ := json.Marshal(link.params[index].value)
				link.params[index].value = string(content)
			}
		}
		server = parseLink(link.String(), 1, codec.Decode)
	}
	server.Name = name
	if unverified(server.outbound) {
		conversion.note(unverifiedNote)
	}
	// a path replaces what the decoder sets of a scheme of its own (the security of VMess): the
	// option is the configuration's, and no parameter the user sees replaces another
	server.Notes = slices.DeleteFunc(server.Notes, func(note string) bool {
		path, rest, found := strings.Cut(note, " ")
		return found && strings.HasPrefix(path, "sb.") && rest == "replaces what the link sets otherwise"
	})
	server.Notes = append(conversion.notes, server.Notes...)
	return server
}

func (c *singBoxConversion) link(content json.RawMessage, kind string, name string, kinds map[string]string) (*madeLink, map[string]any) {
	if !singBoxTypes[kind] {
		if optionName(kind) {
			c.refuse("a server of type " + kind + " is not taken from a subscription")
		} else {
			c.refuse("a server of a type podkop does not know is not taken from a subscription")
		}
		return nil, nil
	}
	fields, err := decodeTree(content)
	if err != nil {
		c.refuse("the outbound cannot be read")
		return nil, nil
	}
	delete(fields, "type")
	delete(fields, "tag")
	if detour, found := fields["detour"].(string); found && detour != "" {
		relay, known := kinds[detour]
		switch {
		case !known:
			c.note("the provider connects it through " + shownName(detour) + ", which its configuration does not have; podkop connects it directly")
		case relay == "direct":
			// connected directly: as podkop connects it
		default:
			c.note("the provider connects it through " + shownName(detour) + "; podkop connects it directly")
		}
	}
	delete(fields, "detour")
	dropDisabled(fields)
	c.dropDenied(fields, "")
	normal := c.normalize(kind, fields)
	if normal == nil {
		return nil, nil
	}
	written, err := decodeTree(mustJSON(normal))
	if err != nil {
		c.refuse("the outbound cannot be read")
		return nil, nil
	}
	return c.write(kind, name, normal), written
}

func mustJSON(value any) []byte {
	content, _ := json.Marshal(value)
	return content
}

// oneValues are the parameters of a link whose text is the one value of an option the outbound
// has as text, which the decoder made a list of one: a list option (badoption.Listable) sing-box
// writes as its one value. A JSON text is that one value for the decoder.
func oneValues(normal map[string]any, outbound []byte) map[string]bool {
	var decoded map[string]any
	if normal == nil || json.Unmarshal(outbound, &decoded) != nil {
		return nil
	}
	quoted := make(map[string]bool)
	var walk func(path string, want map[string]any, got map[string]any)
	walk = func(path string, want map[string]any, got map[string]any) {
		for key, value := range want {
			where := strings.TrimPrefix(path+"."+key, ".")
			switch value := value.(type) {
			case map[string]any:
				if child, isObject := got[key].(map[string]any); isObject {
					walk(where, value, child)
				}
			case string:
				if list, isList := got[key].([]any); isList && len(list) == 1 && list[0] == value {
					quoted["sb."+where] = true
				}
			}
		}
	}
	walk("", normal, decoded)
	return quoted
}

// decodeTree reads JSON into maps and lists, the numbers as they are written.
func decodeTree(content json.RawMessage) (map[string]any, error) {
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.UseNumber()
	var fields map[string]any
	err := decoder.Decode(&fields)
	if err == nil && fields == nil {
		fields = make(map[string]any)
	}
	return fields, err
}

// dropDisabled takes out the groups of options that are switched off ("enabled": false, as
// Marzban writes multiplex): sing-box does not use them, and with them the server would not be
// the server of the provider's link.
func dropDisabled(node map[string]any) {
	for key, value := range node {
		child, isObject := value.(map[string]any)
		if !isObject || singBoxMaps[fold(key)] {
			continue
		}
		if enabled, has := child["enabled"].(bool); has && !enabled {
			delete(node, key)
			continue
		}
		dropDisabled(child)
	}
}

// dropDenied takes out the options a link does not set (singBoxDenied), with a note each: a
// panel's template writes them for its own app, and the server is reached without them.
func (c *singBoxConversion) dropDenied(node map[string]any, path string) {
	keys := make([]string, 0, len(node))
	for key := range node {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		where := strings.TrimPrefix(path+"."+key, ".")
		if singBoxDeniedName(key) {
			delete(node, key)
			// named as sing-box reads it
			if folded := strings.TrimPrefix(path+"."+fold(key), "."); optionName(folded) {
				c.note(folded + " is a setting of the provider's app and is left out")
			} else {
				c.odd = true
			}
			continue
		}
		if child, isObject := node[key].(map[string]any); isObject && !singBoxMaps[fold(key)] {
			c.dropDenied(child, where)
		}
	}
}

// normalize has sing-box read the options and write them again: an option this sing-box does
// not have (the syntax of another version) is the server's reason. Then the options at the
// default of sing-box that a link of the provider does not write are taken out, so that the
// server is the server of that link (TestSingBoxIDsOfTheLinks).
func (c *singBoxConversion) normalize(kind string, fields map[string]any) map[string]any {
	content, err := json.Marshal(fields)
	if err != nil {
		c.refuse("the outbound cannot be read")
		return nil
	}
	if c.codec.Normalize == nil {
		c.refuse("this build reads no sing-box JSON")
		return nil
	}
	content, err = c.codec.Normalize(kind, content)
	if err != nil {
		// the engine's message names no value
		c.refuse(err.Error())
		return nil
	}
	normal, err := decodeTree(content)
	if err != nil {
		c.refuse("the outbound cannot be written by this sing-box")
		return nil
	}
	if kind == "vless" && normal["packet_encoding"] == "xudp" {
		// sing-box's VLESS takes xudp when none is named (protocol/vless/outbound.go)
		delete(normal, "packet_encoding")
	}
	// the ALPN a transport asks for when none is set (transport/v2raywebsocket, v2rayhttpupgrade,
	// v2raygrpc, v2rayhttp; sing-quic's Hysteria 2): the same, and what a link of it decodes to
	defaultALPN := ""
	if transport, has := normal["transport"].(map[string]any); has {
		switch transport["type"] {
		case "ws", "httpupgrade":
			defaultALPN = "http/1.1"
		case "grpc", "http":
			// the http transport over TLS speaks HTTP/2 (transport/v2rayhttp)
			defaultALPN = "h2"
		}
	} else if kind == "hysteria2" {
		defaultALPN = "h3"
	}
	if tls, has := normal["tls"].(map[string]any); has && defaultALPN != "" {
		switch alpn := tls["alpn"].(type) {
		case string:
			if alpn == defaultALPN {
				delete(tls, "alpn")
			}
		case []any:
			if len(alpn) == 1 && alpn[0] == defaultALPN {
				delete(tls, "alpn")
			}
		}
	}
	return normal
}

// write makes the link of the outbound: the server and its user as the scheme writes them, every
// other option by its path.
func (c *singBoxConversion) write(kind string, name string, normal map[string]any) *madeLink {
	link := &madeLink{name: name}
	host, plain := serverHost(textOf(normal["server"]))
	if !plain {
		c.refuse("the address of the server is not an address")
		return nil
	}
	port, isPort := portOf(normal["server_port"])
	if !isPort {
		c.refuse("the port of the server is not a port")
		return nil
	}
	link.host, link.port = host, port
	delete(normal, "server")
	delete(normal, "server_port")
	take := func(key string) string {
		value := textOf(normal[key])
		delete(normal, key)
		return value
	}
	login := func(user string, password string) {
		if strings.Contains(user, ":") {
			c.refuse("the user name of the server has a colon, which a link cannot carry")
			return
		}
		if user != "" || password != "" {
			link.user = linkUser(user) + ":" + linkUser(password)
		}
	}
	link.scheme = kind
	switch kind {
	case "vless":
		link.user = linkUser(take("uuid"))
	case "vmess":
		link.user = linkUser(take("uuid"))
		// the securities the decoder takes as they are; another one is set by its path, and the
		// decoder says it replaces auto
		switch security := textOf(normal["security"]); security {
		case "", "auto", "aes-128-gcm", "chacha20-poly1305":
			link.set("encryption", take("security"))
		}
	case "trojan":
		link.user = linkUser(take("password"))
		// TLS as the outbound has it, by its path: not the decoder's default for Trojan
		link.set("security", "none")
	case "shadowsocks":
		link.scheme = "ss"
		method, password := take("method"), take("password")
		link.user = base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
	case "socks":
		link.scheme = "socks5"
		login(take("username"), take("password"))
	case "http":
		login(take("username"), take("password"))
	case "hysteria":
	case "hysteria2":
		link.slash = true
		link.user = linkUser(take("password"))
	case "tuic":
		uuid, password := take("uuid"), take("password")
		link.user = linkUser(uuid) + ":" + linkUser(password)
		// the ALPN by the decoder's own parameter: without it the decoder warns that none is
		// offered
		if tls, has := normal["tls"].(map[string]any); has {
			if alpn := listText(tls["alpn"]); alpn != "" {
				link.set("alpn", alpn)
				delete(tls, "alpn")
			}
		}
	case "anytls":
		link.user = linkUser(take("password"))
	case "naive":
		link.scheme = "naive+https"
		if quic, _ := normal["quic"].(bool); quic {
			link.scheme = "naive+quic"
		}
		delete(normal, "quic")
		login(take("username"), take("password"))
	}
	if c.reason != "" {
		return nil
	}
	c.flatten(link, "", normal)
	if c.reason != "" {
		return nil
	}
	return link
}

// flatten writes the options as sb.<path>: a value as the configuration writes it, a list of
// plain values as a JSON list, a map by its names; a list of objects cannot be carried. A list of
// one, which sing-box writes as the one value, the decoder reads as a list: oneValues finds those.
func (c *singBoxConversion) flatten(link *madeLink, path string, node map[string]any) {
	keys := make([]string, 0, len(node))
	for key := range node {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		where := strings.TrimPrefix(path+"."+key, ".")
		if !optionName(key) || strings.Contains(key, ".") || len("sb."+where) > 128 {
			c.refuse("an option of the outbound cannot be carried by a link")
			return
		}
		switch value := node[key].(type) {
		case nil:
		case map[string]any:
			c.flatten(link, where, value)
		case []any:
			if len(value) == 0 {
				continue
			}
			for _, item := range value {
				switch item.(type) {
				case map[string]any, []any:
					c.refuse("the option " + where + " cannot be carried by a link")
					return
				}
			}
			content, err := json.Marshal(value)
			if err != nil {
				c.refuse("the option " + where + " cannot be carried by a link")
				return
			}
			link.params = append(link.params, linkParam{"sb." + where, string(content)})
		case string:
			link.params = append(link.params, linkParam{"sb." + where, pathText(value)})
		case bool:
			link.params = append(link.params, linkParam{"sb." + where, map[bool]string{true: "true", false: "false"}[value]})
		case json.Number:
			link.params = append(link.params, linkParam{"sb." + where, value.String()})
		default:
			c.refuse("the option " + where + " cannot be carried by a link")
			return
		}
	}
}

func textOf(value any) string {
	switch value := value.(type) {
	case string:
		return value
	case json.Number:
		return value.String()
	}
	return ""
}

func portOf(value any) (uint16, bool) {
	number, isNumber := value.(json.Number)
	if !isNumber {
		return 0, false
	}
	port, err := number.Int64()
	if err != nil || port <= 0 || port > 65535 {
		return 0, false
	}
	return uint16(port), true
}

// listText is a list of plain values separated by commas, or one value.
func listText(value any) string {
	switch value := value.(type) {
	case string:
		return value
	case []any:
		var items []string
		for _, item := range value {
			items = append(items, textOf(item))
		}
		return strings.Join(items, ",")
	}
	return ""
}
