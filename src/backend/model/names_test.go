package model

import (
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

// A rule is called by its label or its section; a source by its label or as the page calls one
// without a label; names alike are told apart by the section.
func TestNames(t *testing.T) {
	t.Parallel()
	text := "config settings 'settings'\n\toption config_version '2'\n" +
		"\nconfig source 'src1'\n\toption label '  mouse \n'\n\toption type 'links'\n\tlist link 'socks5://m.example:1080#Fox'\n" +
		"\nconfig source 'src2'\n\toption type 'links'\n\tlist link 'vless://u@c.example:443?security=tls#%F0%9F%87%A9%F0%9F%87%AA%20Germany'\n" +
		"\nconfig source 'src3'\n\toption type 'links'\n\tlist link 'socks5://203.0.113.5:1080'\n" +
		"\nconfig source 'src4'\n\toption type 'links'\n\tlist link 'ss://YWVzOnBhc3M=#'\n" +
		"\nconfig source 'src5'\n\toption type 'links'\n\tlist link 'vless://u@a.example:443#A vless://u@b.example:443#B'\n" +
		"\nconfig source 'src6'\n\toption type 'subscription'\n\toption url 'https://sub.example:8443/x/TOKEN'\n" +
		"\nconfig source 'src7'\n\toption type 'json'\n\toption outbound_json '\ufeff{\"type\":\"socks\",\"tag\":\"my socks\"}'\n" +
		"\nconfig source 'src8'\n\toption type 'json'\n\toption outbound_json '{\"type\":\"trojan\"}'\n" +
		"\nconfig source 'src9'\n\toption type 'interface'\n\toption interface 'awg0'\n" +
		"\nconfig source 'src10'\n\toption type 'interface'\n" +
		"\nconfig source 'src11'\n" +
		"\nconfig source 'src12'\n\toption label 'mouse'\n\toption type 'links'\n\tlist link 'socks5://n.example:1080'\n" +
		"\nconfig section 'main'\n\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'x.example'\n" +
		"\nconfig section 'rule2'\n\toption label 'YouTube'\n\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'y.example'\n" +
		"\nconfig section 'rule3'\n\toption label 'YouTube'\n\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'z.example'\n"
	parsed, err := uci.Parse([]byte(text))
	require.NoError(t, err)
	config, err := Load(parsed)
	require.NoError(t, err)
	names := config.Names()
	require.Equal(t, map[string]string{"main": "main", "rule2": "YouTube", "rule3": "YouTube (rule3)"}, names.Rules)
	require.Equal(t, map[string]string{
		"src1": "mouse", "src2": "🇩🇪 Germany", "src3": "socks5 203.0.113.5:1080", "src4": "ss", "src5": "My servers",
		"src6": "sub.example", "src7": "my socks", "src8": "trojan", "src9": "awg0", "src10": "Main route", "src11": "src11",
		"src12": "mouse (src12)",
	}, names.Sources)
	require.Equal(t, "gone", names.Source("gone"))
	require.Equal(t, "mouse (src1)", names.SourceText("src1"))
	require.Equal(t, "mouse (src12)", names.SourceText("src12"))
	require.Equal(t, "main", names.RuleText("main"))
	require.Equal(t, "YouTube (rule2)", names.RuleText("rule2"))
}
