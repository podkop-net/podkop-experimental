// Package subscription reads what a provider lists at the address of a subscription: proxy
// links, one a line, the whole often in base64, or the configurations of Xray and sing-box
// (JSON), whose servers become links. It downloads the list (Download), takes it apart into
// servers (ParseList), finds the servers this sing-box cannot use (Check), keeps the last list
// that was taken (Store) and tells the provider which device asks (ReadDevice).
//
// The address and the links are secrets: the token in the address is the account, a link
// holds the keys of a server. No message of this package repeats them.
package subscription

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/podkop-net/podkop-experimental/src/backend/serverid"
)

// Server is a server a subscription lists.
type Server struct {
	// Name is what the provider calls it: the part of the link after "#".
	Name string `json:"name"`
	// Link is the proxy link, a secret.
	Link string `json:"link"`
	// ID tells servers apart whatever the provider names them: a hash of the outbound the
	// link decodes to, without its name. A link that cannot be decoded has none.
	ID string `json:"id,omitempty"`
	// Reason tells why the server cannot be used; empty when it can.
	Reason string `json:"reason,omitempty"`
	// Notes are what the link asks for and the outbound cannot do.
	Notes []string `json:"notes,omitempty"`

	// outbound is the decoded outbound without its tag, for Check
	outbound []byte
}

// Usable tells whether sing-box can use the server.
func (s *Server) Usable() bool {
	return s.Reason == ""
}

// Codec is what the readers of a list ask the engine: Decode makes the outbound of a link
// (engine.DecodeLink), Normalize has this sing-box read the options of an outbound of a type of
// sing-box JSON and write them again (engine.NormalizeOutbound; none: sing-box JSON gives its
// servers a reason).
type Codec struct {
	Decode    Decoder
	Normalize func(kind string, options []byte) ([]byte, error)
}

// Decoder turns a proxy link into an outbound, a JSON object whose tag is the name of the
// link, and the warnings about it (engine.DecodeLink).
type Decoder func(link string) (outbound []byte, warnings []string, err error)

// The formats of a list besides links (List.Format).
const (
	FormatXray    = "xray"
	FormatSingBox = "sing-box"
)

// List is what an answer of a provider was read as: its servers, and the format it came in.
type List struct {
	Servers []Server
	// Format is "" for a list of links, FormatXray or FormatSingBox for a configuration whose
	// servers podkop made links of
	Format string
	// Configs is the number of the configurations of Xray JSON; Outbounds the number of the
	// outbounds of servers the configurations had, of which Servers are those taken
	Configs   int
	Outbounds int
}

// FormatText names a format for the log: "a list of links", "Xray JSON", "sing-box JSON".
func FormatText(format string) string {
	switch format {
	case FormatXray:
		return "Xray JSON"
	case FormatSingBox:
		return "sing-box JSON"
	}
	return "a list of links"
}

// Parse takes the body of an answer of a provider apart into its servers (ParseList).
func Parse(body []byte, decode Decoder) ([]Server, error) {
	list, err := ParseList(body, Codec{Decode: decode})
	return list.Servers, err
}

// ParseList takes the body of an answer of a provider apart into its servers, in its order,
// whatever the format the provider sent: a list of links, or the configurations of Xray or
// sing-box (JSON). A line that is not a proxy link is skipped: the comments some providers put
// in (#…) and the lines for other programs (happ://…). Links that cannot be decoded are servers
// with a reason; a body with no server at all is refused.
func ParseList(body []byte, codec Codec) (List, error) {
	decode := codec.Decode
	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
	if text == "" {
		return List{}, fail("empty", true, "the provider sent an empty list")
	}
	if !strings.Contains(text, "://") {
		if decoded, isBase64 := decodeBase64(text); isBase64 {
			text = strings.TrimSpace(strings.TrimPrefix(decoded, "\ufeff"))
		}
	}
	switch {
	case strings.HasPrefix(text, "<"):
		return List{}, fail("page", true, "the provider sent a web page, not a list of servers")
	case strings.HasPrefix(text, "{"), strings.HasPrefix(text, "["):
		return parseJSON([]byte(text), codec)
	case isClashYAML(text):
		return List{}, fail("clash", true, "the provider sent a configuration of Clash (YAML), which podkop does not read: an address that ends with /clash, /clash-meta, /mihomo or /stash gets a list of links without that ending")
	}
	var servers []Server
	encrypted := 0
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		scheme, rest, isLink := strings.Cut(line, "://")
		if strings.EqualFold(scheme, "happ") && len(rest) >= len("crypt") && strings.EqualFold(rest[:len("crypt")], "crypt") {
			encrypted++
		}
		if !isLink || strings.ContainsAny(scheme, " \t") || strings.EqualFold(scheme, "happ") {
			continue
		}
		servers = append(servers, parseLink(line, len(servers)+1, decode))
	}
	if len(servers) == 0 && encrypted > 0 {
		return List{}, fail("happ-crypt", true, "the provider sent only links encrypted for Happ (happ://crypt…), which only Happ reads")
	}
	return finished(List{Servers: servers})
}

// finished refuses a list with no server, and one of placeholders.
func finished(list List) (List, error) {
	if len(list.Servers) == 0 {
		return List{}, fail("nolinks", true, "the answer of the provider has no servers")
	}
	if notes := placeholderNotes(list.Servers); notes != nil {
		return List{}, fail("placeholder", true, "the provider sent notes instead of servers: "+strings.Join(notes, "; "), strings.Join(notes, "; "))
	}
	return list, nil
}

// parseJSON reads a configuration: a list of Xray's (each an object with outbounds), one of
// Xray's (its outbounds have a protocol) or one of sing-box (its outbounds have a type). Other
// JSON is refused; a configuration with no server is a list with no server.
func parseJSON(content []byte, codec Codec) (List, error) {
	other := fail("json", true, "the provider sent JSON that is not a configuration of Xray or sing-box")
	if !json.Valid(content) {
		return List{}, other
	}
	if content[0] == '[' {
		var items []json.RawMessage
		if json.Unmarshal(content, &items) != nil {
			return List{}, other
		}
		var configurations []json.RawMessage
		for _, item := range items {
			if outbounds := objectOf(item).raw("outbounds"); outbounds != nil && outbounds[0] == '[' {
				configurations = append(configurations, item)
			}
		}
		if len(items) > 0 && len(configurations) == 0 {
			return List{}, other
		}
		list := List{Format: FormatXray}
		list.Servers, list.Configs, list.Outbounds = readXray(configurations, codec.Decode)
		return finished(list)
	}
	root := objectOf(content)
	outbounds := root.raw("outbounds")
	if outbounds == nil || outbounds[0] != '[' {
		return List{}, other
	}
	format := ""
	items := root.list("outbounds")
	for _, item := range items {
		outbound := objectOf(item)
		switch {
		case format != "":
		case outbound.has("protocol"):
			format = FormatXray
		case outbound.has("type"):
			format = FormatSingBox
		}
	}
	switch {
	case format == FormatXray:
		list := List{Format: FormatXray}
		list.Servers, list.Configs, list.Outbounds = readXray([]json.RawMessage{content}, codec.Decode)
		return finished(list)
	case format == FormatSingBox:
		list := List{Format: FormatSingBox}
		list.Servers, list.Outbounds = readSingBox(root, codec)
		return finished(list)
	case len(items) == 0:
		// a configuration with no outbound at all: no server
		return finished(List{})
	}
	return List{}, other
}

// placeholderNotes are the names of a list whose every server is the address 0.0.0.0: what
// Remnawave sends in place of the servers (an ended subscription, a device it does not take,
// "contact support"), its notes in the names. None for a list of servers.
func placeholderNotes(servers []Server) []string {
	var notes []string
	for index := range servers {
		_, address := servers[index].Endpoint()
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		if host != "0.0.0.0" {
			return nil
		}
		notes = append(notes, servers[index].Name)
	}
	return notes
}

// decodeBase64 reads a body in base64, with or without padding, of either alphabet, broken
// into lines or not. It tells false when the body is not base64 of text.
func decodeBase64(text string) (string, bool) {
	compact := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, text)
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(compact)
		if err == nil && utf8.Valid(decoded) {
			return string(decoded), true
		}
	}
	return "", false
}

// isClashYAML tells a configuration of Clash by its list of proxies.
func isClashYAML(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "proxies:") {
			return true
		}
	}
	return false
}

func parseLink(link string, number int, decode Decoder) Server {
	server := Server{Link: link}
	content, warnings, err := decode(link)
	if err != nil {
		server.Name = cleanName(fragmentOf(link), number)
		server.Reason = err.Error()
		return server
	}
	var fields map[string]any
	err = json.Unmarshal(content, &fields)
	if err != nil {
		server.Name = cleanName(fragmentOf(link), number)
		server.Reason = "the outbound of the link is not a JSON object"
		return server
	}
	name, _ := fields["tag"].(string)
	delete(fields, "tag")
	// the keys of a map are written in order: the same outbound is the same bytes
	canonical, err := json.Marshal(fields)
	if err != nil {
		server.Name = cleanName(name, number)
		server.Reason = "the outbound of the link cannot be encoded"
		return server
	}
	// the stable identity of the outbound: the same value as before (a sharelink outbound has
	// no detour), now from the one definition shared with the plan and the cure store
	server.ID = serverid.Canonical(content)
	server.Name = cleanName(name, number)
	server.Notes = warnings
	server.outbound = canonical
	return server
}

// fragmentOf is the name a link that cannot be decoded has: the part after "#".
func fragmentOf(link string) string {
	at := strings.LastIndexByte(link, '#')
	if at < 0 {
		return ""
	}
	fragment := link[at+1:]
	if unescaped, err := url.PathUnescape(fragment); err == nil {
		return unescaped
	}
	return fragment
}

// cleanName is the name of a server as it is shown: on one line, without what Remnawave adds
// after the name for some clients (?serverDescription=…), or "server N" when it has none.
func cleanName(name string, number int) string {
	name, _, _ = strings.Cut(name, "?serverDescription=")
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		return "server " + strconv.Itoa(number)
	}
	return name
}

// Endpoint is the scheme of the link of a server and the address of the server (host:port)
// as its outbound has it; no address for a link that cannot be decoded.
func (s *Server) Endpoint() (scheme string, address string) {
	scheme, _, _ = strings.Cut(s.Link, "://")
	scheme = strings.ToLower(scheme)
	var fields struct {
		Server string `json:"server"`
		Port   any    `json:"server_port"`
	}
	if s.outbound == nil || json.Unmarshal(s.outbound, &fields) != nil || fields.Server == "" {
		return scheme, ""
	}
	if number, isNumber := fields.Port.(float64); isNumber {
		return scheme, net.JoinHostPort(fields.Server, strconv.Itoa(int(number)))
	}
	return scheme, fields.Server
}
