package ctl

import (
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/model"

	"github.com/stretchr/testify/require"
)

// The lines of the global check: the servers, the last check and its way, the last change of
// the servers, and what the provider told; or why there is no list.
func TestSubscriptionLines(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	checked, changed := now.Add(-5*time.Minute), now.Add(-50*time.Hour)
	expire := now.Add(64 * 24 * time.Hour)
	ended := now.Add(-24 * time.Hour)
	lines := subscriptionLines([]api.SubscriptionState{
		{Name: "prov1", Servers: 12, Usable: 11, Checked: &checked, Changed: &changed, Route: "direct",
			Provider: &api.ProviderInfo{Title: "My VPN", Traffic: true, Download: 13421772800, Total: 107374182400, Expire: &expire}},
		{Name: "prov2", Servers: 3, Usable: 3, Changed: &changed, Error: "no answer in time",
			Provider: &api.ProviderInfo{Traffic: true, Upload: 1 << 20, Expire: &ended}},
		{Name: "prov3", Error: "the provider sent a web page, not a list of servers"},
		{Name: "prov4"},
	}, model.Names{Sources: map[string]string{"prov1": "Lab", "prov2": "prov2"}}, now)
	require.Equal(t, []string{
		`✅ Lab (prov1): 12 servers, 11 can be used; checked 5 min ago (direct); servers changed 2 days ago; "My VPN", traffic 12.5 GiB of 100.0 GiB, until ` + expire.Local().Format("2006-01-02") + ` (64 days)`,
		`⚠️ prov2: 3 servers, 3 can be used; servers changed 2 days ago; not checked since the start; the last download failed: no answer in time; traffic 1 MiB, no limit, ended ` + ended.Local().Format("2006-01-02"),
		`❌ prov3: no list: the provider sent a web page, not a list of servers`,
		`⏳ prov4: the list is not downloaded yet`,
	}, lines)
}

// What the settings add to the request is told at the end of the line: the User-Agent whole up to
// 64 characters, the names of the headers, never a value, and the lines left out.
func TestSubscriptionLinesTellTheRequest(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	changed := now.Add(-time.Hour)
	browser := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	lines := subscriptionLines([]api.SubscriptionState{
		{Name: "prov1", Servers: 2, Usable: 2, Changed: &changed, Checked: &changed, Route: "direct", Agent: "INCY", Headers: []string{"Authorization"}},
		{Name: "prov2", Error: "the provider sent a web page", Agent: browser,
			Problems: []api.RequestProblem{{Line: 2, Name: "x-hwid", Code: "device"}, {Line: 3, Code: "syntax"}, {Line: 0, Code: "chars"}}},
	}, model.Names{}, now)
	require.Equal(t, "✅ prov1: 2 servers, 2 can be used; checked 1 h ago (direct); servers changed 1 h ago; User-Agent INCY; headers Authorization", lines[0])
	require.Equal(t, "❌ prov2: no list: the provider sent a web page; User-Agent "+browser[:64]+"…; left out of the request: header 2 (x-hwid), header 3, the User-Agent", lines[1])
}

// The global check names the preset with the User-Agent it sends and the format the servers came
// in; podkop's own and a list of links are not named.
func TestSubscriptionLinesTellThePresetAndTheFormat(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	changed := now.Add(-time.Hour)
	lines := subscriptionLines([]api.SubscriptionState{
		{Name: "prov1", Servers: 12, Usable: 12, Changed: &changed, Checked: &changed, Route: "direct", Preset: "happ", Agent: "Happ/4.8.3/Linux", Format: "xray", Configs: 11},
		{Name: "prov2", Servers: 3, Usable: 2, Changed: &changed, Checked: &changed, Route: "direct", Preset: "sing-box", Agent: "SFA (sing-box 1.14.4; language en_US)", Format: "sing-box"},
		{Name: "prov3", Servers: 1, Usable: 1, Changed: &changed, Checked: &changed, Route: "direct"},
		{Name: "prov4", Error: "the provider sent a web page", Problems: []api.RequestProblem{{Line: 0, Code: "preset"}}},
	}, model.Names{}, now)
	require.Equal(t, []string{
		"✅ prov1: 12 servers, 12 can be used, from Xray JSON; checked 1 h ago (direct); servers changed 1 h ago; asked as Happ (Happ/4.8.3/Linux)",
		"✅ prov2: 3 servers, 2 can be used, from sing-box JSON; checked 1 h ago (direct); servers changed 1 h ago; asked as sing-box (SFA) (SFA (sing-box 1.14.4; language en_US))",
		"✅ prov3: 1 servers, 1 can be used; checked 1 h ago (direct); servers changed 1 h ago",
		"❌ prov4: no list: the provider sent a web page; left out of the request: the preset of the User-Agent",
	}, lines)
}
