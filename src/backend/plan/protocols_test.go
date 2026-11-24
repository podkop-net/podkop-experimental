package plan

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// mixedList is a subscription of servers of several protocols.
func mixedList() map[string][]SubscriptionServer {
	return map[string][]SubscriptionServer{"prov1": {
		{Name: "FI 1", Link: "vless://u@fi1.example:443#FI%201"},
		{Name: "FI 2", Link: "hy2://p@fi2.example:443#FI%202"},
		{Name: "SE 1", Link: "ss://x@se1.example:8388#SE%201"},
		{Name: "SE 2", Link: "hy2://p@se2.example:443#SE%202"},
		{Name: "DE 1", Link: "trojan://p@de1.example:443#DE%201"},
		{Name: "DE 2", Link: "vless://u@de2.example:443#DE%202"},
	}}
}

const protocolSources = "\nconfig source 'prov1'\n\toption label 'prov1'\n\toption type 'subscription'\n\toption url 'https://sub.example/x'\n" +
	"\nconfig source 'pair'\n\toption label 'pair'\n\toption type 'links'\n\tlist link 'vless://u@a.example:443#A'\n\tlist link 'hy2://p@b.example:443#B'\n" +
	"\nconfig source 'own'\n\toption label 'own'\n\toption type 'links'\n\tlist link 'trojan://p@own.example:443#Own'\n" +
	"\nconfig source 'ssh'\n\toption label 'ssh'\n\toption type 'json'\n\toption outbound_json '{\"type\":\"ssh\",\"server\":\"j.example\"}'\n" +
	"\nconfig source 'warp'\n\toption label 'warp'\n\toption type 'interface'\n\toption interface 'awg0'\n"

// A row takes the servers of its protocols, by the type of the outbound, whatever the link calls it
// (hy2), in the order of the source, and of those only the ones its words take. Without protocols it
// takes every server.
func TestRowsOfProtocols(t *testing.T) {
	t.Parallel()
	result, err := buildRules(t, protocolSources+
		ruleText("all", row("server", "prov1"))+
		ruleText("vless", row("server", "prov1", "protocols VLESS"))+
		ruleText("two", row("server", "prov1", "protocols hy2", "protocols trojan"))+
		ruleText("typed", row("server", "prov1", "protocols Hysteria2, vless ,ss"))+
		ruleText("words", row("server", "prov1", "include FI", "include SE", "exclude 2", "protocols vless", "protocols hysteria2"))+
		ruleText("links", row("server", "pair", "protocols hysteria2"))+
		ruleText("via", row("server", "prov1", "protocols trojan", "via pair"))+
		// a fallback of several servers is a URL test of them, one of one server is the server
		ruleText("spare", row("server", "prov1", "protocols trojan"), row("fallback", "prov1", "protocols vless"), row("fallback", "prov1", "include SE", "protocols hy2")),
		mixedList())
	require.NoError(t, err)
	require.Empty(t, result.Warnings)
	_, outbounds := outboundsOf(t, result)
	server := func(names ...string) []string {
		var tags []string
		for _, name := range names {
			tags = append(tags, "prov1: "+name)
		}
		return tags
	}
	require.Equal(t, server("FI 1", "FI 2", "SE 1", "SE 2", "DE 1", "DE 2"), outbounds["all-urltest-out"].Outbounds)
	require.Equal(t, server("FI 1", "DE 2"), outbounds["vless-urltest-out"].Outbounds)
	require.Equal(t, server("FI 2", "SE 2", "DE 1"), outbounds["two-urltest-out"].Outbounds)
	require.Equal(t, server("FI 1", "FI 2", "SE 1", "SE 2", "DE 2"), outbounds["typed-urltest-out"].Outbounds)
	require.Equal(t, server("FI 1"), outbounds["words-urltest-out"].Outbounds, "the words and the protocols both")
	require.Equal(t, []string{"pair: B"}, outbounds["links-out"].Outbounds)
	// the servers a row connects through are not chosen by its protocols
	require.Equal(t, []string{"prov1: DE 1 via pair"}, outbounds["via-urltest-out"].Outbounds)
	require.Equal(t, "pair-best", outbounds["prov1: DE 1 via pair"].Detour)
	require.Equal(t, []string{"pair: A", "pair: B"}, outbounds["pair-best"].Outbounds)

	spare := outbounds["spare-urltest-out"]
	require.Equal(t, server("DE 1"), spare.Outbounds)
	require.Equal(t, []string{"spare-fallback-1-out", "prov1: SE 2"}, spare.Fallbacks)
	require.Equal(t, server("FI 1", "DE 2"), outbounds["spare-fallback-1-out"].Outbounds)
}

// A source of one server is asked too: one link, an outbound JSON by its type, whatever sing-box
// calls it. An interface has no protocol: its row goes through it whatever its protocols.
func TestProtocolsOfOneServer(t *testing.T) {
	t.Parallel()
	result, err := buildRules(t, protocolSources+
		ruleText("ours", row("server", "own", "protocols trojan"))+
		ruleText("oursnot", row("server", "own", "protocols vless"))+
		ruleText("obj", row("server", "ssh", "protocols SSH"))+
		ruleText("objnot", row("server", "ssh", "protocols vless"), row("server", "own"))+
		ruleText("iface", row("server", "warp", "protocols vless")), nil)
	require.NoError(t, err)
	_, outbounds := outboundsOf(t, result)
	require.Equal(t, []string{"own"}, outbounds["ours-out"].Outbounds)
	require.Equal(t, []string{"block"}, outbounds["oursnot-out"].Outbounds)
	require.Equal(t, []string{"ssh"}, outbounds["obj-out"].Outbounds)
	require.Equal(t, []string{"own"}, outbounds["objnot-out"].Outbounds)
	require.Equal(t, []string{"warp"}, outbounds["iface-out"].Outbounds)
	// a rule left without a server is told as one whose words take none
	require.Equal(t, []string{"rule oursnot: its sources name no server now: its connections are refused"}, result.Warnings)
}

// A protocol that is none is told once, by the name the settings give it, and the row goes on with
// its others; a row of such names alone takes no server. An interface asks for none.
func TestUnknownProtocols(t *testing.T) {
	t.Parallel()
	const known = "vless, vmess, trojan, shadowsocks, hysteria2, hysteria, tuic, anytls, naive, socks, http"
	unknown := func(rule string, name string, source string) string {
		return "rule " + rule + ": \"" + name + "\" among the protocols of the row of the source " + source + " is not known (" + known + "): no server is of it"
	}
	result, err := buildRules(t, protocolSources+
		ruleText("typo", row("server", "prov1", "protocols vles", "protocols trojan"), row("fallback", "prov1", "protocols vles"))+
		ruleText("none", row("server", "prov1", "protocols Reality"))+
		// ssh is the type of an outbound JSON, and no link makes a server of it
		ruleText("obj", row("server", "prov1", "protocols ssh", "protocols hy2"), row("server", "ssh", "protocols ssh"))+
		ruleText("iface", row("server", "warp", "protocols vles")), mixedList())
	require.NoError(t, err)
	_, outbounds := outboundsOf(t, result)
	require.Equal(t, []string{"prov1: DE 1"}, outbounds["typo-urltest-out"].Outbounds)
	require.Empty(t, outbounds["typo-urltest-out"].Fallbacks)
	require.Equal(t, []string{"block"}, outbounds["none-out"].Outbounds)
	require.Equal(t, []string{"prov1: FI 2", "prov1: SE 2", "ssh"}, outbounds["obj-urltest-out"].Outbounds)
	require.Equal(t, []string{"warp"}, outbounds["iface-out"].Outbounds)
	require.Equal(t, []string{
		unknown("typo", "vles", "prov1"),
		unknown("none", "reality", "prov1"),
		"rule none: its sources name no server now: its connections are refused",
		unknown("obj", "ssh", "prov1"),
	}, result.Warnings, strings.Join(result.Warnings, "\n"))
}
