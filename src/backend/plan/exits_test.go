package plan

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

const exitHead = "config settings 'settings'\n\toption config_version '2'\n\toption dns_type 'udp'\n\toption dns_server '8.8.8.8'\n"

// decodeTestLink decodes a link of a test: the host is the server, the name after # the tag,
// socks5 and ss give their types, a host "bad.example" is refused.
func decodeTestLink(link string) ([]byte, []string, error) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.Hostname() == "bad.example" {
		return nil, nil, errors.New("not a link")
	}
	kind := map[string]string{"socks5": "socks", "ss": "shadowsocks"}[parsed.Scheme]
	if kind == "" {
		kind = "vless"
	}
	content, _ := json.Marshal(map[string]any{"type": kind, "server": parsed.Hostname(), "server_port": 443, "tag": parsed.Fragment})
	return content, nil, nil
}

func subscriptionList(names ...string) []SubscriptionServer {
	var result []SubscriptionServer
	for index, name := range names {
		result = append(result, SubscriptionServer{Name: name, Link: "vless://u@s" + string(rune('a'+index)) + ".example:443#" + url.PathEscape(name)})
	}
	return result
}

// ruleText is a rule with a list of its own and its rows.
func ruleText(name string, rows ...string) string {
	text := "\nconfig section '" + name + "'\n\toption user_domain_list_type 'dynamic'\n\tlist user_domains '" + name + ".example'\n"
	for _, row := range rows {
		text += "\nconfig member\n\toption section '" + name + "'\n" + row
	}
	return text
}

// row is a member: "server prov1" or "fallback direct", then options as "include AI".
func row(role string, source string, more ...string) string {
	text := "\toption role '" + role + "'\n\toption source '" + source + "'\n"
	for _, option := range more {
		name, value, _ := strings.Cut(option, " ")
		switch name {
		case "include", "exclude":
			text += "\tlist " + name + " '" + value + "'\n"
		default:
			text += "\toption " + name + " '" + value + "'\n"
		}
	}
	return text
}

type exitOutbound struct {
	Type           string   `json:"type"`
	Tag            string   `json:"tag"`
	Server         string   `json:"server"`
	Default        string   `json:"default"`
	Detour         string   `json:"detour"`
	BindInterface  string   `json:"bind_interface"`
	RoutingMark    int      `json:"routing_mark"`
	DomainResolver string   `json:"domain_resolver"`
	Outbounds      []string `json:"outbounds"`
	Fallbacks      []string `json:"fallbacks"`
	Interval       string   `json:"interval"`
	Tolerance      int      `json:"tolerance"`
	DownloadURL    *string  `json:"download_url"`
	UDPOverTCP     *struct {
		Enabled bool `json:"enabled"`
	} `json:"udp_over_tcp"`
}

type exitConfig struct {
	DNS struct {
		Servers []map[string]any `json:"servers"`
	} `json:"dns"`
	Outbounds []exitOutbound `json:"outbounds"`
	Route     struct {
		Rules []map[string]any `json:"rules"`
	} `json:"route"`
}

func buildRules(t *testing.T, settings string, servers map[string][]SubscriptionServer) (*Result, error) {
	t.Helper()
	parsed, err := uci.Parse([]byte(exitHead + settings))
	require.NoError(t, err)
	config, err := model.Load(parsed)
	require.NoError(t, err)
	return Build(config, Facts{}, Options{DecodeLink: decodeTestLink, Servers: servers})
}

func outboundsOf(t *testing.T, result *Result) (exitConfig, map[string]exitOutbound) {
	t.Helper()
	var config exitConfig
	require.NoError(t, json.Unmarshal(result.Config, &config))
	byTag := make(map[string]exitOutbound)
	for _, outbound := range config.Outbounds {
		_, twice := byTag[outbound.Tag]
		require.False(t, twice, "the tag %s is there twice", outbound.Tag)
		byTag[outbound.Tag] = outbound
	}
	return config, byTag
}

// ruleRoutes are the outbounds and actions of the route rules of the rules, in their order.
func ruleRoutes(config exitConfig) []string {
	var routes []string
	for _, rule := range config.Route.Rules {
		if rule["inbound"] != tagTProxyInbound {
			continue
		}
		if outbound, found := rule["outbound"]; found {
			routes = append(routes, outbound.(string))
		} else {
			routes = append(routes, rule["action"].(string))
		}
	}
	return routes
}

func TestExitsOfRows(t *testing.T) {
	t.Parallel()
	settings := "\toption urltest_check_interval '1m'\n\toption urltest_tolerance '80'\n\toption urltest_download_check 'off'\n" +
		"\nconfig source 'prov1'\n\toption type 'subscription'\n\toption url 'https://sub.example/x'\n" +
		"\nconfig source 'warp'\n\toption type 'interface'\n\toption interface 'awg0'\n\toption routing_mark '0x10000'\n" +
		"\toption domain_resolver_enabled '1'\n\toption domain_resolver_dns_type 'doh'\n\toption domain_resolver_dns_server '1.1.1.1'\n" +
		"\nconfig source 'own'\n\toption type 'links'\n\tlist link 'socks5://own.example:1080#Own'\n\toption udp_over_tcp '1'\n" +
		"\nconfig source 'pair'\n\toption type 'links'\n\tlist link 'vless://u@a.example:443#A'\n\tlist link 'vless://u@b.example:443#B'\n" +
		ruleText("main", row("server", "prov1", "exclude AI"), row("fallback", "own"), row("fallback", "direct")) +
		ruleText("ai", row("server", "prov1", "include AI", "via warp"), row("server", "prov1", "exclude AI")) +
		ruleText("yt", row("server", "prov1", "include NL"), row("fallback", "prov1", "include DE"), row("fallback", "block")) +
		ruleText("duo", row("server", "pair", "via own"))
	result, err := buildRules(t, settings, map[string][]SubscriptionServer{"prov1": subscriptionList("🇳🇱 NL 1", "🇩🇪 DE 1", "🇩🇪 DE 2", "🇺🇸 USA AI-1", "🇪🇸 Spain")})
	require.NoError(t, err)
	config, outbounds := outboundsOf(t, result)

	nl, de1, de2, spain := "prov1: 🇳🇱 NL 1", "prov1: 🇩🇪 DE 1", "prov1: 🇩🇪 DE 2", "prov1: 🇪🇸 Spain"
	require.Equal(t, "vless", outbounds[nl].Type)
	require.Equal(t, "sa.example", outbounds[nl].Server)
	viaWarp := outbounds["prov1: 🇺🇸 USA AI-1 via warp"]
	require.Equal(t, "warp", viaWarp.Detour)
	_, aiDirect := outbounds["prov1: 🇺🇸 USA AI-1"]
	require.False(t, aiDirect, "AI is taken only through warp")
	_, spainViaWarp := outbounds["prov1: 🇪🇸 Spain via warp"]
	require.False(t, spainViaWarp, "\"AI\" does not take Spain: a filter matches the start of a word")

	warp := outbounds["warp"]
	require.Equal(t, "direct", warp.Type)
	require.Equal(t, "awg0", warp.BindInterface)
	require.Equal(t, 65536, warp.RoutingMark)
	require.Equal(t, "warp-domain-resolver", warp.DomainResolver)
	var resolver map[string]any
	for _, server := range config.DNS.Servers {
		if server["tag"] == "warp-domain-resolver" {
			resolver = server
		}
	}
	require.NotNil(t, resolver)
	require.Equal(t, "https", resolver["type"])
	require.Equal(t, "warp", resolver["detour"])

	own := outbounds["own"]
	require.Equal(t, "socks", own.Type)
	require.NotNil(t, own.UDPOverTCP)
	require.True(t, own.UDPOverTCP.Enabled)
	require.Equal(t, "own", outbounds["pair: A via own"].Detour)
	require.Equal(t, "own", outbounds["pair: B via own"].Detour)

	main := outbounds["main-urltest-out"]
	require.Equal(t, "urltest", main.Type)
	require.Equal(t, []string{nl, de1, de2, spain}, main.Outbounds)
	require.Equal(t, []string{"own", "direct-out"}, main.Fallbacks)
	require.Equal(t, "1m", main.Interval)
	require.Equal(t, 80, main.Tolerance)
	require.NotNil(t, main.DownloadURL)
	require.Empty(t, *main.DownloadURL, "the download check is off")
	require.Equal(t, exitOutbound{Type: "selector", Tag: "main-out", Default: "main-urltest-out", Outbounds: []string{"main-urltest-out", nl, de1, de2, spain, "own"}}, outbounds["main-out"])

	require.Equal(t, []string{"prov1: 🇺🇸 USA AI-1 via warp", nl, de1, de2, spain}, outbounds["ai-urltest-out"].Outbounds)

	yt := outbounds["yt-urltest-out"]
	require.Equal(t, []string{nl}, yt.Outbounds)
	require.Equal(t, []string{"yt-fallback-1-out", "block"}, yt.Fallbacks)
	require.Equal(t, []string{de1, de2}, outbounds["yt-fallback-1-out"].Outbounds)

	require.Equal(t, []string{"main-out", "ai-out", "yt-out", "duo-out"}, ruleRoutes(config))
	for tag := range outbounds {
		if tag == tagDirectOutbound || tag == tagBlockOutbound {
			continue
		}
		require.True(t, result.Swappable[tag], "%s is swapped while sing-box runs", tag)
	}
	var routes []string
	for _, link := range result.Links {
		routes = append(routes, link.Name)
	}
	require.Contains(t, routes, nl, "the servers are ways to download a subscription")
	require.Contains(t, routes, "own")
}

func TestExitsWithoutServers(t *testing.T) {
	t.Parallel()
	settings := "\nconfig source 'prov1'\n\toption type 'subscription'\n\toption url 'https://sub.example/x'\n" +
		"\nconfig source 'empty'\n" +
		ruleText("a", row("server", "prov1")) +
		ruleText("b", row("server", "prov1"), row("fallback", "direct")) +
		ruleText("c", row("server", "empty")) +
		ruleText("d", row("server", "block")) +
		ruleText("e", row("server", "direct")) +
		ruleText("f")
	result, err := buildRules(t, settings, nil)
	require.NoError(t, err)
	config, outbounds := outboundsOf(t, result)
	require.Equal(t, exitOutbound{Type: "selector", Tag: "a-out", Default: "block", Outbounds: []string{"block"}}, outbounds["a-out"])
	b := outbounds["b-urltest-out"]
	require.NotNil(t, b.Outbounds, "no servers: an empty list, the engine takes it with fallbacks")
	require.Empty(t, b.Outbounds)
	require.Equal(t, []string{"direct-out"}, b.Fallbacks)
	for _, tag := range []string{"c-out", "d-out", "e-out", "f-out"} {
		_, found := outbounds[tag]
		require.False(t, found, tag)
	}
	require.Equal(t, []string{"a-out", "b-out", "reject", "direct-out"}, ruleRoutes(config), "c does nothing, d and e keep their places")
	warnings := strings.Join(result.Warnings, "\n")
	require.Contains(t, warnings, "rule a: its sources name no server now: its connections are refused")
	require.Contains(t, warnings, "rule c: its sources are not filled yet: the rule does nothing")
	require.Contains(t, warnings, "source prov1 has no servers yet")
}

// Rows that repeat a fallback, or name a server of the rule as a fallback, give each outbound
// once: sing-box refuses a URL test that lists one twice. Two rows of direct are a rule of direct.
func TestExitRepeatedRows(t *testing.T) {
	t.Parallel()
	settings := "\nconfig source 'own'\n\toption type 'links'\n\tlist link 'vless://u@own.example:443#Own'\n" +
		ruleText("x", row("server", "own"), row("fallback", "direct"), row("fallback", "own"), row("fallback", "direct"), row("fallback", "block")) +
		ruleText("y", row("server", "direct"), row("server", "direct"))
	result, err := buildRules(t, settings, nil)
	require.NoError(t, err)
	config, outbounds := outboundsOf(t, result)
	require.Equal(t, []string{"own"}, outbounds["x-urltest-out"].Outbounds)
	require.Equal(t, []string{"direct-out", "block"}, outbounds["x-urltest-out"].Fallbacks)
	_, hasY := outbounds["y-out"]
	require.False(t, hasY)
	require.Equal(t, []string{"x-out", "direct-out"}, ruleRoutes(config))
}

// The rules of direct and block at the top go before the devices routed whole, as the block and
// exclusion sections of 0.8 did; a rule of direct below another goes after it.
func TestFullyRoutedAfterLeadingDirectAndBlock(t *testing.T) {
	t.Parallel()
	tv := strings.Replace(ruleText("tv", row("server", "own")), "list user_domains 'tv.example'\n", "list user_domains 'tv.example'\n\tlist fully_routed_ips '192.168.1.50'\n", 1)
	settings := "\nconfig source 'own'\n\toption type 'links'\n\tlist link 'vless://u@own.example:443#Own'\n" +
		ruleText("bank", row("server", "direct")) + ruleText("ads", row("server", "block")) + tv + ruleText("late", row("server", "direct"))
	result, err := buildRules(t, settings, nil)
	require.NoError(t, err)
	config, _ := outboundsOf(t, result)
	require.Equal(t, []string{"direct-out", "reject", "tv-out", "tv-out", "direct-out"}, ruleRoutes(config))
	var whole map[string]any
	for _, rule := range config.Route.Rules {
		if rule["source_ip_cidr"] != nil {
			whole = rule
		}
	}
	require.Equal(t, "tv-out", whole["outbound"])
}

func TestExitViaSourceOfSeveralServers(t *testing.T) {
	t.Parallel()
	settings := "\nconfig source 'pair'\n\toption type 'links'\n\tlist link 'vless://u@a.example:443#A'\n\tlist link 'vless://u@b.example:443#B'\n" +
		"\nconfig source 'far'\n\toption type 'links'\n\tlist link 'vless://u@far.example:443#Far'\n" +
		ruleText("x", row("server", "far", "via pair"))
	result, err := buildRules(t, settings, nil)
	require.NoError(t, err)
	_, outbounds := outboundsOf(t, result)
	require.Equal(t, "pair-best", outbounds["far via pair"].Detour)
	require.Equal(t, []string{"pair: A", "pair: B"}, outbounds["pair-best"].Outbounds)
	require.True(t, result.Swappable["pair-best"])
}

// A row through a subscription not downloaded yet takes no server for now: the rule goes by its
// fallbacks instead of the whole configuration being refused.
func TestExitViaSourceWithoutServers(t *testing.T) {
	t.Parallel()
	settings := "\nconfig source 'prov1'\n\toption type 'subscription'\n\toption url 'https://sub.example/x'\n" +
		"\nconfig source 'far'\n\toption type 'links'\n\tlist link 'vless://u@far.example:443#Far'\n" +
		ruleText("x", row("server", "far", "via prov1"), row("fallback", "direct"))
	result, err := buildRules(t, settings, nil)
	require.NoError(t, err)
	_, outbounds := outboundsOf(t, result)
	require.Empty(t, outbounds["x-urltest-out"].Outbounds)
	require.Equal(t, []string{"direct-out"}, outbounds["x-urltest-out"].Fallbacks)
	require.Contains(t, strings.Join(result.Warnings, "\n"), "the source prov1 to connect through has no servers yet")
}

func TestExitMistakes(t *testing.T) {
	t.Parallel()
	sources := "\nconfig source 'one'\n\toption type 'links'\n\tlist link 'vless://u@one.example:443#One'\n" +
		"\nconfig source 'warp'\n\toption type 'interface'\n\toption interface 'awg0'\n" +
		"\nconfig source 'bad'\n\toption type 'links'\n\tlist link 'vless://u@bad.example:443#Bad'\n"
	for _, testCase := range []struct{ rows, mistake string }{
		{row("server", "bad"), "cannot use the proxy link 1 of the source bad"},
	} {
		_, err := buildRules(t, sources+ruleText("x", testCase.rows), nil)
		require.ErrorContains(t, err, testCase.mistake)
	}
	// a row that cannot go the way it names takes no server: the rule goes by its fallback,
	// and the rest of the settings run
	for _, testCase := range []struct{ rows, warning string }{
		{row("server", "one", "via one"), "rule x: a row of the source one connects through the same source: the row takes no server"},
		{row("server", "warp", "via one"), "rule x: the interface of the source warp does not connect through another source: the row takes no server"},
		{row("server", "one", "via gone"), "rule x: there is no source gone to connect through: the row takes no server"},
		{row("server", "one", "via empty"), "rule x: the source empty to connect through is not filled: the row takes no server"},
		{row("server", "odd"), "rule x: the source odd is of a type podkop does not know (wireguard): its row takes no server"},
	} {
		settings := sources + "\nconfig source 'empty'\n\toption type 'links'\n\nconfig source 'odd'\n\toption type 'wireguard'\n" +
			ruleText("x", testCase.rows, row("fallback", "direct")) + ruleText("y", row("server", "one"))
		result, err := buildRules(t, settings, nil)
		require.NoError(t, err, testCase.warning)
		require.Contains(t, result.Warnings, testCase.warning)
		_, outbounds := outboundsOf(t, result)
		require.Empty(t, outbounds["x-urltest-out"].Outbounds, testCase.warning)
		require.Equal(t, []string{"direct-out"}, outbounds["x-urltest-out"].Fallbacks, testCase.warning)
		require.Equal(t, []string{"one"}, outbounds["y-urltest-out"].Outbounds, testCase.warning)
	}
	_, err := buildRules(t, "\toption urltest_tolerance 'much'\n", nil)
	require.ErrorContains(t, err, "tolerance")
}

func TestExitTagsOfNames(t *testing.T) {
	t.Parallel()
	settings := "\nconfig source 'prov1'\n\toption type 'subscription'\n\toption url 'https://sub.example/x'\n" +
		"\nconfig section 'block'\n\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'b.example'\n" +
		"\nconfig member\n\toption section 'block'\n\toption role 'server'\n\toption source 'prov1'\n"
	result, err := buildRules(t, settings, map[string][]SubscriptionServer{"prov1": subscriptionList("NL", "NL", "")})
	require.NoError(t, err)
	_, outbounds := outboundsOf(t, result)
	require.Equal(t, []string{"prov1: NL", "prov1: NL #2", "prov1: server 3"}, outbounds["block-urltest-out"].Outbounds)
	require.Equal(t, "block", outbounds["block"].Type, "a rule named block keeps the block outbound apart")
	require.Equal(t, "selector", outbounds["block-out"].Type)
}
