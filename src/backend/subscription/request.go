package subscription

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
)

// Custom is what the settings of a subscription add to its requests: the User-Agent of another
// app (some providers give the list only to the apps they name), by a preset or typed, and
// headers the provider asks for (a key, a cookie). The identity of the router is never among
// them: it sends its own HWID and device headers whatever the User-Agent, and takes its own place
// among the devices of the subscription.
type Custom struct {
	// Preset is the app whose User-Agent is sent (PresetHapp, PresetINCY, PresetSingBox); ""
	// for podkop's own and for a User-Agent typed in the settings.
	Preset string
	// UserAgent is sent in place of podkop/<version>; "" sends that. A preset's is here too.
	UserAgent string
	// Headers are the extra headers, in the order of the settings.
	Headers []Field
}

// The presets of the User-Agent (option user_agent_preset): the apps the panels give their
// formats to by name. The backend turns a preset into the header at request time, so a release
// can move a preset's version without touching the settings. The strings and where they come
// from: notes/2026-11-21-0821-json-design.md §1.1 of the workspace.
const (
	PresetPodkop  = "podkop"
	PresetHapp    = "happ"
	PresetINCY    = "incy"
	PresetSingBox = "sing-box"
	PresetCustom  = "custom"
)

const (
	// happAgent is Happ's form Happ/<version>/<OS>/<build digits> (design §1.1): 4.8.3 is its
	// desktop release of 2026-11-20, Linux the OS of its desktop build; no panel reads the digits
	// after the OS, which differ between builds of one version, so they are left out
	happAgent = "Happ/4.8.3/Linux"
	// incyAgent is INCY's own form INCY/<version>/<platform> (design §1.1, INCY-DEV/incy-docs
	// subscription-format.en.md); 3.9.1 is its desktop release
	incyAgent = "INCY/3.9.1/linux"
)

// SingBoxVersion is the version of the sing-box of the engine (constant.Version of the module
// github.com/sagernet/sing-box, "1.14.4-pdk-209086dbd08a" in a build): the program sets it
// (cmd/podkop), as only the engine and the program import sing-box.
var SingBoxVersion = ""

// singBoxAgent is the User-Agent of SFA since 1.13.20 ("Unify user agent", design §1.1:
// sing-box-for-android HTTPClient.kt, sing-box-for-apple HTTPClient.swift) with the version of the
// sing-box inside: Remnawave and Pasarguard give sing-box JSON only to a name like SFA's.
func singBoxAgent() string {
	return "SFA (sing-box " + singBoxVersion(SingBoxVersion) + "; language en_US)"
}

// singBoxVersion is the version of the sing-box inside as SFA writes its own: the version of the
// engine's sing-box (SingBoxVersion) without podkop's part; a build without it (a test) takes the
// version of the module go.mod requires, where the binary tells its modules.
func singBoxVersion(constant string) string {
	version, _, _ := strings.Cut(constant, "-pdk-")
	if version != "" && version[0] >= '0' && version[0] <= '9' {
		return version
	}
	if info, found := debug.ReadBuildInfo(); found {
		for _, module := range info.Deps {
			if module.Path == "github.com/sagernet/sing-box" {
				return strings.TrimPrefix(module.Version, "v")
			}
		}
	}
	if constant == "" {
		return "unknown"
	}
	return constant
}

// presetAgent is the User-Agent of a preset; "" for podkop's own, false for a preset podkop does
// not know.
func presetAgent(preset string) (string, bool) {
	switch preset {
	case "", PresetPodkop:
		return "", true
	case PresetHapp:
		return happAgent, true
	case PresetINCY:
		return incyAgent, true
	case PresetSingBox:
		return singBoxAgent(), true
	}
	return "", false
}

// PresetName is how the log and the global check name a preset ("" for none): as the page names
// it.
func PresetName(preset string) string {
	switch preset {
	case PresetHapp:
		return "Happ"
	case PresetINCY:
		return "INCY"
	case PresetSingBox:
		return "sing-box (SFA)"
	}
	return preset
}

// Field is a header of the settings.
type Field struct {
	Name  string
	Value string
}

// The limits of what the settings add to a request. The page checks the same
// (fe-app-podkop/src/validators/validateRequestHeader.ts): a change goes into both, and into the
// tables of both tests. 256 characters are about twice the longest real User-Agent found (131, a
// browser's); the extra headers together stay far within what the servers of the panels take of
// a request (16 KiB by Node.js, 8 KiB a line by nginx).
const (
	MaxAgent   = 256
	MaxName    = 64
	MaxValue   = 1024
	MaxHeaders = 8
	MaxCustom  = 4096
	// shownAgent is as much of a User-Agent as the log and the global check show: it is the name
	// of an app, not a secret, but a browser's is long
	shownAgent = 64
)

// Problem is a line of the settings left out of the request: its number among the header lines
// (1 for the first; 0 is the User-Agent), the name when it is one a header can have, and why, as a
// code with its arguments for the page and the English text of the log. It never holds a value:
// a value may be a secret.
type Problem struct {
	Line int
	Name string
	Code string
	Args []string
	Text string
}

// Where names the line of the problem: "the User-Agent", "header 2 (X-Api-Key)".
func (p Problem) Where() string {
	if p.Line == 0 {
		return "the User-Agent"
	}
	line := "header " + strconv.Itoa(p.Line)
	if p.Name != "" {
		line += " (" + p.Name + ")"
	}
	return line
}

// Describe tells the problem of a line of the settings for the log.
func (p Problem) Describe() string {
	if p.Line == 0 {
		return "the User-Agent of the settings is not sent (" + p.Text + ")"
	}
	return p.Where() + " of the settings is left out: " + p.Text
}

// the names of a device's identity (x-hwid, Device-Id, X-Hardware-Id…) and of the address of the
// client (X-Forwarded-For, CF-Connecting-IPv6, X-Azure-ClientIP, X-Envoy-External-Address…), as
// parts of a name and as its ends
var (
	deviceParts = []string{"hwid", "device-id", "deviceid", "hardware-id"}
	clientParts = []string{"forwarded", "clientip", "socketip"}
	clientEnds  = []string{"-ip", "-ipv4", "-ipv6", "-ip6", "-addr", "-address"}
)

// the names of the identity of the router, or of another device: podkop sends its own values, so
// the router takes its own place among the devices of the subscription and never that of another
// device (the owner's rule)
func deviceName(lower string) bool {
	return slices.ContainsFunc(deviceParts, func(part string) bool { return strings.Contains(lower, part) }) ||
		strings.HasPrefix(lower, "x-device") || lower == "x-ver-os"
}

// the names that tell a server behind a proxy the address of the client (X-Forwarded-For,
// Forwarded, X-Real-IP, CF-Connecting-IP, True-Client-IP, X-Client-IP…): the address the provider
// sees is the router's own
func clientName(lower string) bool {
	return slices.ContainsFunc(clientParts, func(part string) bool { return strings.Contains(lower, part) }) ||
		slices.ContainsFunc(clientEnds, func(end string) bool { return strings.HasSuffix(lower, end) })
}

// the headers of the connection itself: Go writes them, ignores them (Host comes from the
// address) or refuses them over HTTP/2; with an Accept-Encoding of its own Go would not unpack
// the body
var connectionNames = []string{"host", "content-length", "transfer-encoding", "connection", "keep-alive", "proxy-connection", "upgrade", "te", "trailer", "expect", "accept-encoding"}

// the headers that ask for a part of the list or none (206, 304): podkop needs the whole list
var partialNames = []string{"range", "if-range", "if-match", "if-none-match", "if-modified-since", "if-unmodified-since"}

// deniedName is why a header of the settings is not sent by its name, "" when it may be.
func deniedName(lower string) (code string, text string) {
	switch {
	case deviceName(lower):
		return "device", "podkop sends the device identifier itself"
	case clientName(lower):
		return "client", "the address of the client is the router's own"
	case lower == "user-agent":
		return "agent", "the User-Agent has an option of its own"
	case slices.Contains(connectionNames, lower):
		return "connection", "it belongs to the connection"
	case slices.Contains(partialNames, lower):
		return "partial", "podkop needs the whole list"
	case strings.HasPrefix(lower, "proxy-"):
		// Proxy-Authorization: the ways of podkop have no proxy of HTTP, the secret would go to
		// the provider
		return "proxy", "it is meant for a proxy on the way"
	}
	return "", ""
}

// headerName tells a name a header of the settings may have: Latin letters, digits and dashes,
// the names real headers have (a quote or a space, which the token of HTTP allows in part, would
// only break the masking of the settings).
func headerName(name string) bool {
	if name == "" {
		return false
	}
	for index := 0; index < len(name); index++ {
		switch char := name[index]; {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9', char == '-':
		default:
			return false
		}
	}
	return true
}

// printable tells a text a header can carry: printable ASCII, so no line break and no NUL that
// would put another header into the request.
func printable(text string) bool {
	for index := 0; index < len(text); index++ {
		if text[index] < 0x20 || text[index] > 0x7e {
			return false
		}
	}
	return true
}

// ParseCustom reads a User-Agent typed in the settings and their header lines: ParseRequest of
// custom.
func ParseCustom(agent string, lines []string) (Custom, []Problem) {
	return ParseRequest(PresetCustom, agent, lines)
}

// ParseRequest reads the preset of the User-Agent, the User-Agent and the header lines (Name:
// value) of the settings of a subscription. No preset with a User-Agent (a file written by hand)
// is custom; podkop and a preset of an app send their own User-Agent whatever the option
// user_agent says; custom sends that, and podkop's own when it is empty. What cannot be sent is
// left out, each with its problem: a preset podkop does not know or an invalid User-Agent leaves
// podkop's own, an invalid line leaves out that line; the rest is sent. The settings are never
// refused for it.
func ParseRequest(preset string, agent string, lines []string) (Custom, []Problem) {
	var custom Custom
	var problems []Problem
	preset, agent = strings.TrimSpace(preset), strings.TrimSpace(agent)
	if preset == "" && agent != "" {
		preset = PresetCustom
	}
	if preset != PresetCustom {
		agent = ""
		sent, known := presetAgent(preset)
		switch {
		case !known:
			problems = append(problems, Problem{Code: "preset", Text: "the preset is not one podkop knows"})
		case sent != "":
			custom.Preset, custom.UserAgent = preset, sent
		}
	}
	switch {
	case agent == "":
	case !printable(agent):
		problems = append(problems, Problem{Code: "chars", Text: "it has characters a header cannot carry"})
	case len(agent) > MaxAgent:
		limit := strconv.Itoa(MaxAgent)
		problems = append(problems, Problem{Code: "long", Args: []string{limit}, Text: "it is longer than " + limit + " characters"})
	default:
		custom.UserAgent = agent
	}
	seen := make(map[string]bool)
	size := 0
	for index, raw := range lines {
		text := strings.TrimSpace(raw)
		if text == "" {
			// an empty item says nothing
			continue
		}
		problem := Problem{Line: index + 1}
		left := func(code string, text string, args ...string) {
			problem.Code, problem.Text, problem.Args = code, text, args
			problems = append(problems, problem)
		}
		name, value, found := strings.Cut(text, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !found || name == "" {
			left("syntax", "it is not Name: value")
			continue
		}
		if !headerName(name) {
			left("name", "the name is not a header name: Latin letters, digits and dashes only")
			continue
		}
		if len(name) > MaxName {
			limit := strconv.Itoa(MaxName)
			left("name-long", "the name is longer than "+limit+" characters", limit)
			continue
		}
		problem.Name = name
		lower := strings.ToLower(name)
		if code, reason := deniedName(lower); code != "" {
			left(code, reason)
			continue
		}
		switch {
		case value == "":
			left("empty", "the value is empty")
		case !printable(value):
			left("chars", "the value has characters a header cannot carry")
		case len(value) > MaxValue:
			limit := strconv.Itoa(MaxValue)
			left("long", "the value is longer than "+limit+" characters", limit)
		case seen[lower]:
			left("twice", "the name is given twice")
		case len(custom.Headers) >= MaxHeaders:
			limit := strconv.Itoa(MaxHeaders)
			left("count", "more than "+limit+" headers", limit)
		case size+len(name)+2+len(value) > MaxCustom:
			limit := strconv.Itoa(MaxCustom)
			left("size", "the headers of the settings are longer than "+limit+" bytes", limit)
		default:
			seen[lower] = true
			size += len(name) + 2 + len(value)
			custom.Headers = append(custom.Headers, Field{Name: name, Value: value})
		}
	}
	return custom, problems
}

// Empty tells a request of podkop's own.
func (c Custom) Empty() bool {
	return c.UserAgent == "" && len(c.Headers) == 0
}

// Key tells requests apart: "" for one of podkop's own, else a hash of the User-Agent and the
// headers as they are sent. It holds no value.
func (c Custom) Key() string {
	if c.Empty() {
		return ""
	}
	hash := sha256.New()
	hash.Write([]byte(c.UserAgent + "\x00"))
	for _, field := range c.Headers {
		hash.Write([]byte(http.CanonicalHeaderKey(field.Name) + ": " + field.Value + "\n"))
	}
	return hex.EncodeToString(hash.Sum(nil)[:16])
}

// Names are the names of the headers, for the state, the log and the global check: never the
// values.
func (c Custom) Names() []string {
	var names []string
	for _, field := range c.Headers {
		names = append(names, field.Name)
	}
	return names
}

// RequestKey is the key of a download of an address with a request: the key of the address alone
// for a request of podkop's own, so that what was keyed by the address before stays found.
func RequestKey(address string, c Custom) string {
	if key := c.Key(); key != "" {
		return AddressKey(address + "\x00" + key)
	}
	return AddressKey(address)
}

// AskedAs tells what a request is asked as, for the log and the global check: "" for podkop's
// own User-Agent, "asked as Happ (Happ/4.8.3/Linux)" for a preset, "User-Agent <agent>" for one
// typed in the settings.
func AskedAs(preset string, agent string) string {
	switch {
	case agent == "":
		return ""
	case preset != "" && preset != PresetCustom:
		return "asked as " + PresetName(preset) + " (" + ShownAgent(agent) + ")"
	}
	return "User-Agent " + ShownAgent(agent)
}

// ShownAgent is a User-Agent as the log and the global check show it: whole up to 64 characters.
func ShownAgent(agent string) string {
	if len(agent) > shownAgent {
		return agent[:shownAgent] + "…"
	}
	return agent
}

// ForAgent is the failure of a download with the User-Agent of the settings when the answer may
// be to it: some providers give another format to the apps they know (JSON, YAML), their page to
// a browser, notes or a refusal to an app they do not take. The code tells the page so; the
// failure stays final. A web page over plain HTTP may be one of the ISP: it stays a page. Without a
// User-Agent of the settings the failure is as it was.
func ForAgent(err error, c Custom, address string) error {
	var failure *Failure
	if c.UserAgent == "" || !errors.As(err, &failure) {
		return err
	}
	to := "the User-Agent \"" + ShownAgent(c.UserAgent) + "\""
	secure := false
	if target, parseErr := url.Parse(address); parseErr == nil {
		secure = target.Scheme == "https"
	}
	switch failure.Code {
	case "json":
		return fail("json-agent", true, "the provider sent JSON that is not a configuration of Xray or sing-box to "+to)
	case "clash":
		return fail("clash-agent", true, "the provider sent a configuration of Clash (YAML) to "+to+", which podkop does not read")
	case "happ-crypt":
		return fail("happ-crypt-agent", true, "the provider sent "+to+" only links encrypted for Happ (happ://crypt…), which only Happ reads")
	case "page":
		if secure {
			return fail("page-agent", true, "the provider sent a web page to "+to+", or the address is that of the provider's site: providers show their page to browsers")
		}
	case "refused":
		return fail("refused-agent", true, failure.Text+"; or the provider does not accept "+to, failure.Args...)
	case "placeholder":
		return fail("placeholder-agent", true, "the provider sent notes instead of servers to "+to+": "+strings.Join(failure.Args, "; "), failure.Args...)
	case "nolinks":
		return fail("nolinks-agent", true, "the answer of the provider to "+to+" has no servers")
	}
	return err
}
