package model

import (
	"slices"
	"strings"
	"unicode"
)

// Protocols are the protocols of the servers a proxy link makes, each by the type of its outbound
// in sing-box: the names a row chooses its servers by (Member.Protocols), in the order the page
// offers them. An outbound JSON may be of a type that is none of these (ssh, shadowtls, …): its
// protocol is its type.
var Protocols = []string{"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "hysteria", "tuic", "anytls", "naive", "socks", "http"}

// protocolSchemes are the schemes of the links that are not the name of their protocol: the list of
// a subscription in the page shows its servers by them. With Protocols, they are all the schemes
// the engine reads (engine, TestLinkProtocols).
var protocolSchemes = map[string]string{
	"ss": "shadowsocks", "hy2": "hysteria2", "https": "http", "naive+https": "naive", "naive+quic": "naive",
	"socks4": "socks", "socks4a": "socks", "socks5": "socks", "socks5h": "socks",
}

// ProtocolName is a protocol by its name in Protocols: in small letters, and the protocol of a
// scheme of links by the scheme (ss, hy2, socks5). A text that is neither stays, in small letters.
func ProtocolName(text string) string {
	name := strings.ToLower(strings.TrimSpace(text))
	if protocol, found := protocolSchemes[name]; found {
		return protocol
	}
	return name
}

// LinkProtocol is the protocol of the server of a proxy link, by its scheme; "" for a text that is
// no link.
func LinkProtocol(link string) string {
	return ProtocolName(linkScheme(strings.TrimSpace(link)))
}

// TakesProtocol tells whether the row takes a server of the protocol: the type of its outbound, or
// LinkProtocol of its link. A row of an interface does not ask: it has no server.
func (m *Member) TakesProtocol(protocol string) bool {
	return len(m.Protocols) == 0 || slices.Contains(m.Protocols, ProtocolName(protocol))
}

// ProtocolNames are the protocols of the items of a list, each once, by their names (ProtocolName):
// an item is a name, or names by commas or spaces, as a user types them.
func ProtocolNames(items []string) []string {
	var names []string
	for _, item := range items {
		for _, word := range strings.FieldsFunc(item, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
			if name := ProtocolName(word); !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	return names
}
