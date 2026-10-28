package ctl

import (
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"

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
	}, now)
	require.Equal(t, []string{
		`✅ prov1: 12 servers, 11 can be used; checked 5 min ago (direct); servers changed 2 days ago; "My VPN", traffic 12.5 GiB of 100.0 GiB, until ` + expire.Local().Format("2006-01-02") + ` (64 days)`,
		`⚠️ prov2: 3 servers, 3 can be used; servers changed 2 days ago; not checked since the start; the last download failed: no answer in time; traffic 1 MiB, no limit, ended ` + ended.Local().Format("2006-01-02"),
		`❌ prov3: no list: the provider sent a web page, not a list of servers`,
		`⏳ prov4: the list is not downloaded yet`,
	}, lines)
}
