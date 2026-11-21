package subscription

import (
	"bytes"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A server of a provider's configuration (Xray JSON, sing-box JSON) becomes a share link in the
// grammar of the engine's decoder (podkop-engine, docs/LINKS.md), and that link goes the way of
// every link of a list (parseLink): one policy for links and configurations, the same ID for a
// server that comes both ways, and the list on flash, Check and the plan as they are.

// madeLink is a share link podkop makes: the scheme, the user before "@" (escaped), the server,
// and the parameters in the order they were set, the name after "#".
type madeLink struct {
	scheme string
	user   string
	host   string
	port   uint16
	// slash puts "/" before the parameters, as Hysteria 2 links have it
	slash  bool
	params []linkParam
	name   string
}

type linkParam struct {
	key, value string
}

// set adds a parameter that has a value.
func (l *madeLink) set(key string, value string) {
	if value != "" {
		l.params = append(l.params, linkParam{key, value})
	}
}

// has tells whether a parameter is set.
func (l *madeLink) has(key string) bool {
	for _, param := range l.params {
		if param.key == key {
			return true
		}
	}
	return false
}

func (l *madeLink) String() string {
	var text strings.Builder
	text.WriteString(l.scheme + "://")
	if l.user != "" {
		text.WriteString(l.user + "@")
	}
	host := l.host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	text.WriteString(host + ":" + strconv.Itoa(int(l.port)))
	if l.slash {
		text.WriteByte('/')
	}
	for index, param := range l.params {
		if index == 0 {
			text.WriteByte('?')
		} else {
			text.WriteByte('&')
		}
		// the decoder reads "+" as a space, as form encoding has it, and "%2B" as a plus
		text.WriteString(url.QueryEscape(param.key) + "=" + url.QueryEscape(param.value))
	}
	if l.name != "" {
		text.WriteString("#" + url.PathEscape(l.name))
	}
	return text.String()
}

// pathText is a value of a parameter sb.<path> that is a text: the decoder reads a value that
// begins with a bracket or a quote as JSON, so such a one is written as a JSON text.
func pathText(text string) string {
	if text != "" && strings.ContainsRune(`[{"`, rune(text[0])) {
		content, _ := json.Marshal(text)
		return string(content)
	}
	return text
}

// maxName is as long as the name of a server is, in characters: the names the panels give are
// some tens of characters, and one value of a configuration (its remarks) is the name of each of
// its servers. A longer one is cut, with "…".
const maxName = 128

// budget bounds what the servers made of a body take: a value one configuration shares among
// its servers (its remarks, the fragment of a dialer) is in each of them, and a small body could
// make many megabytes of links, held in memory and written to flash.
type budget struct {
	left int
}

// newBudget is the budget of a body: four times its size and 256 KiB. A list of links takes
// about twice its body (the links, their outbounds), and a configuration less (its template is
// not taken); the names are cut (maxName), so what one configuration shares stays within it.
func newBudget(body int) *budget {
	return &budget{left: 4*body + 256<<10}
}

// spend takes what a server takes of the budget; false when it is spent.
func (b *budget) spend(server *Server) bool {
	if b == nil {
		return true
	}
	b.left -= len(server.Link) + len(server.Name) + len(server.ID) + len(server.Reason) + len(server.outbound)
	for _, note := range server.Notes {
		b.left -= len(note)
	}
	return b.left >= 0
}

// oversize is the failure of a body whose servers would take more than its budget.
func oversize() *Failure {
	return fail("oversize", true, "the servers the provider's configuration makes would take much more than the configuration itself: it is not read")
}

// unverifiedNote is the note of a server whose configuration does not verify its certificate:
// Remnawave's sing-box JSON writes a pinned certificate so (tls.insecure, no pin), and Xray JSON
// of older panels has allowInsecure.
const unverifiedNote = "the provider's configuration does not verify the certificate of the server"

// unverified tells an outbound whose certificate is not verified (tls.insecure).
func unverified(outbound []byte) bool {
	var fields struct {
		TLS *struct {
			Insecure bool `json:"insecure"`
		} `json:"tls"`
	}
	return json.Unmarshal(outbound, &fields) == nil && fields.TLS != nil && fields.TLS.Insecure
}

// linkUser is the user of a link as the decoder reads it back (url.PathUnescape of what is before
// the last "@").
func linkUser(user string) string {
	return url.PathEscape(user)
}

// serverHost is the address of a server as a link carries it: a name or an IP address (an IPv6
// one without its brackets); false for what is no address, which the decoder would read as a part
// of another link or of the path.
func serverHost(address string) (string, bool) {
	address = strings.TrimSpace(address)
	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
		address = address[1 : len(address)-1]
	}
	if address == "" || len(address) > 253 {
		return "", false
	}
	for index := 0; index < len(address); index++ {
		switch char := address[index]; {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
		case char == '.', char == '-', char == '_', char == ':', char == '%':
		default:
			return "", false
		}
	}
	return address, true
}

// optionName tells a name a key of a configuration may be named by in a note, in a link
// parameter (sb.<path>) and in a reason: letters, digits, "-", "_" and ".", as the decoder names
// the parameters it does not take (a key is as free a text as a value, and a value may be a
// secret).
func optionName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for index := 0; index < len(name); index++ {
		switch char := name[index]; {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
		case char == '-', char == '_', char == '.':
		default:
			return false
		}
	}
	return true
}

// shownName is the name of an outbound of a configuration (a relay) as a note gives it: one line,
// 64 characters at most. A tag is a name, not a secret.
func shownName(name string) string {
	name = strings.Join(strings.Fields(name), " ")
	if len(name) > 64 {
		cut := 64
		for cut > 0 && !utf8Start(name[cut]) {
			cut--
		}
		name = name[:cut] + "…"
	}
	return name
}

func utf8Start(char byte) bool {
	return char&0xc0 != 0x80
}

// object is a JSON object of a configuration, read as Xray reads its own: a key in any case
// (encoding/json matches the fields of a structure so), the key written exactly winning over
// another case. It remembers the keys it was asked for, so that the rest is accounted for: every
// key is mapped, left out by a reviewed list with its reason, or named in a note.
type object struct {
	values map[string]json.RawMessage
	// lower are the keys by their folded case (fold), the first written of a case, and
	// spellings every key written of a case
	lower     map[string]string
	spellings map[string][]string
	used      map[string]bool
}

// fold is a key as encoding/json matches it to a field: by Unicode's simple case folding (the
// long s is s, the Kelvin sign k), so a name of another spelling is the same name.
func fold(name string) string {
	plain := true
	for index := 0; index < len(name); index++ {
		plain = plain && name[index] < utf8.RuneSelf
	}
	if plain {
		return strings.ToLower(name)
	}
	return strings.Map(func(r rune) rune {
		least := r
		for other := unicode.SimpleFold(r); other != r; other = unicode.SimpleFold(other) {
			least = min(least, other)
		}
		return unicode.ToLower(least)
	}, name)
}

// objectOf reads a JSON object; nil for anything else (null included).
func objectOf(content json.RawMessage) *object {
	content = bytes.TrimSpace(content)
	if len(content) == 0 || content[0] != '{' {
		return nil
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(content, &values) != nil {
		return nil
	}
	found := &object{values: values, lower: make(map[string]string, len(values)), spellings: make(map[string][]string, len(values)), used: make(map[string]bool)}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		folded := fold(key)
		if _, taken := found.lower[folded]; !taken {
			found.lower[folded] = key
		}
		found.spellings[folded] = append(found.spellings[folded], key)
	}
	return found
}

// raw is the value of a key, marked as read; nil when there is none or it is null.
func (o *object) raw(key string) json.RawMessage {
	if o == nil {
		return nil
	}
	folded := fold(key)
	name, found := key, false
	if _, found = o.values[key]; !found {
		name, found = o.lower[folded]
	}
	if !found {
		return nil
	}
	// every spelling of the key is read: Xray takes one of them
	for _, written := range o.spellings[folded] {
		o.used[written] = true
	}
	value := bytes.TrimSpace(o.values[name])
	if string(value) == "null" {
		return nil
	}
	return value
}

func (o *object) has(key string) bool {
	return o.raw(key) != nil
}

// text is a string value; a number or a flag as it is written (Xray would refuse both for a
// string, and a panel that writes a short id as a number means its digits).
func (o *object) text(key string) string {
	value := o.raw(key)
	if value == nil {
		return ""
	}
	var text string
	if json.Unmarshal(value, &text) == nil {
		return text
	}
	if value[0] != '{' && value[0] != '[' && value[0] != '"' {
		return string(value)
	}
	return ""
}

// flag is a boolean value: true, or "true" and "1" as text.
func (o *object) flag(key string) bool {
	value := o.raw(key)
	if value == nil {
		return false
	}
	var flag bool
	if json.Unmarshal(value, &flag) == nil {
		return flag
	}
	switch strings.ToLower(o.text(key)) {
	case "true", "1":
		return true
	}
	return false
}

// number is a numeric value, also as text; false when there is none.
func (o *object) number(key string) (float64, bool) {
	text := strings.TrimSpace(o.text(key))
	if text == "" {
		return 0, false
	}
	number, err := strconv.ParseFloat(text, 64)
	return number, err == nil
}

// port is the port of a server: a number, also as text (Xray takes a number).
func (o *object) port(key string) (uint16, bool) {
	number, found := o.number(key)
	if !found || number <= 0 || number > 65535 || number != float64(int(number)) {
		return 0, false
	}
	return uint16(number), true
}

// list is an array value; nil for anything else.
func (o *object) list(key string) []json.RawMessage {
	value := o.raw(key)
	if value == nil || value[0] != '[' {
		return nil
	}
	var list []json.RawMessage
	if json.Unmarshal(value, &list) != nil {
		return nil
	}
	return list
}

// texts is a list of strings, as Xray's StringList reads one: an array, or one text separated by
// commas.
func (o *object) texts(key string) []string {
	value := o.raw(key)
	if value == nil {
		return nil
	}
	var list []string
	if json.Unmarshal(value, &list) == nil {
		return list
	}
	var items []string
	for _, item := range strings.Split(o.text(key), ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

func (o *object) child(key string) *object {
	return objectOf(o.raw(key))
}

// rest are the keys not read, as written, in order.
func (o *object) rest() []string {
	if o == nil {
		return nil
	}
	var keys []string
	for key := range o.values {
		if !o.used[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// without is the object as JSON without some keys (in any case), the others as they are, in the
// order of their names; nil when nothing is left.
func (o *object) without(keys ...string) json.RawMessage {
	if o == nil {
		return nil
	}
	left := make(map[string]json.RawMessage)
	for key, value := range o.values {
		skip := false
		for _, name := range keys {
			skip = skip || fold(key) == fold(name)
		}
		if !skip {
			left[key] = value
		}
	}
	if len(left) == 0 {
		return nil
	}
	content, err := json.Marshal(left)
	if err != nil {
		return nil
	}
	return content
}
