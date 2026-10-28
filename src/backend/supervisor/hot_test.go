package supervisor

import (
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/plan"

	"github.com/stretchr/testify/require"
)

// hotConfig is a configuration of a section of a group, with what else the test puts in.
func hotConfig(servers []string, extra string) *plan.Result {
	swappable := map[string]bool{"g-group": true, "yt-out": true}
	var outbounds, members []string
	for _, name := range servers {
		tag := "prov: " + name
		swappable[tag] = true
		outbounds = append(outbounds, `{"type": "vless", "tag": "`+tag+`", "server": "`+strings.ToLower(name)+`.example"}`)
		members = append(members, `"`+tag+`"`)
	}
	config := `{"dns": {"final": "dns-server"}, "outbounds": [{"type": "direct", "tag": "direct-out"}, {"type": "block", "tag": "block-out"}, ` +
		strings.Join(outbounds, ", ") + `, {"type": "urltest", "tag": "g-group", "outbounds": [` + strings.Join(members, ", ") + `]}` +
		`, {"type": "selector", "tag": "yt-out", "outbounds": ["g-group", ` + strings.Join(members, ", ") + `], "default": "g-group"}` + extra + `],` +
		` "route": {"rules": [{"inbound": "tproxy-in", "outbound": "yt-out"}], "final": "direct-out"}}`
	return &plan.Result{Config: []byte(config), Swappable: swappable}
}

// The servers of the groups change while sing-box runs; what else changes, or goes through
// what changes, needs a new sing-box.
func TestHotPlan(t *testing.T) {
	current := hotConfig([]string{"DE", "NL"}, "")
	hot, reason := hotPlan(current, hotConfig([]string{"DE2", "NL", "SE"}, ""))
	require.NotNil(t, hot, reason)
	require.Equal(t, 2, hot.added)
	require.Equal(t, 2, hot.changed)
	require.Equal(t, 1, hot.removed)
	require.Equal(t, []string{"prov: DE"}, hot.swap.Remove)
	require.Len(t, hot.swap.Put, 4)

	for name, next := range map[string]*plan.Result{
		"the route":           {Config: []byte(strings.Replace(string(hotConfig([]string{"DE2", "NL"}, "").Config), `"final": "direct-out"}}`, `"final": "yt-out"}}`, 1)), Swappable: hotConfig([]string{"DE2", "NL"}, "").Swappable},
		"a fixed outbound":    {Config: []byte(strings.Replace(string(hotConfig([]string{"DE2", "NL"}, "").Config), `"tag": "direct-out"}`, `"tag": "direct-out", "connect_timeout": "5s"}`, 1)), Swappable: hotConfig([]string{"DE2", "NL"}, "").Swappable},
		"what goes through":   hotConfig([]string{"DE2", "NL"}, `, {"type": "vless", "tag": "main-out", "server": "m.example", "detour": "yt-out"}`),
		"only the order":      reordered(current),
		"a detour of the DNS": withDNSDetour(hotConfig([]string{"DE2", "NL"}, "")),
	} {
		if name == "what goes through" {
			current := hotConfig([]string{"DE", "NL"}, `, {"type": "vless", "tag": "main-out", "server": "m.example", "detour": "yt-out"}`)
			hot, reason = hotPlan(current, next)
		} else if name == "a detour of the DNS" {
			hot, reason = hotPlan(withDNSDetour(current), next)
		} else {
			hot, reason = hotPlan(current, next)
		}
		require.Nil(t, hot, name)
		require.NotEmpty(t, reason, name)
	}
}

func reordered(result *plan.Result) *plan.Result {
	config := string(result.Config)
	de := `{"type": "vless", "tag": "prov: DE", "server": "de.example"}, `
	config = strings.Replace(config, de, "", 1)
	config = strings.Replace(config, `{"type": "urltest"`, de+`{"type": "urltest"`, 1)
	return &plan.Result{Config: []byte(config), Swappable: result.Swappable}
}

func withDNSDetour(result *plan.Result) *plan.Result {
	config := strings.Replace(string(result.Config), `{"dns": {"final": "dns-server"}`, `{"dns": {"final": "dns-server", "servers": [{"type": "udp", "tag": "dns-server", "detour": "yt-out"}]}`, 1)
	return &plan.Result{Config: []byte(config), Swappable: result.Swappable}
}
