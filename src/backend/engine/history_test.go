package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// The results of the outbounds that stay as they were are kept from one configuration to
// the next; those of an outbound that changed, went, or dials through one that changed are
// forgotten.
func TestForgetChanged(t *testing.T) {
	shared := &sharedHistory{storage: urltest.NewHistoryStorage()}
	before := dialersOf([]byte(`{"outbounds": [
		{"type": "vless", "tag": "main-1-out", "server": "a.example"},
		{"type": "vless", "tag": "main-2-out", "server": "b.example"},
		{"type": "direct", "tag": "chained-out", "detour": "main-2-out"},
		{"type": "vless", "tag": "gone-out", "server": "c.example"},
		{"type": "urltest", "tag": "main-urltest-out", "outbounds": ["main-1-out", "main-2-out"]}
	], "endpoints": [{"type": "wireguard", "tag": "wg-out", "address": ["10.0.0.2/32"]}]}`))
	shared.forgetChanged(before)
	for tag := range before {
		shared.storage.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	}
	// the link of main-2 points at another server now
	shared.forgetChanged(dialersOf([]byte(`{"outbounds": [
		{"type": "vless", "tag": "main-1-out", "server": "a.example"},
		{"type": "vless", "tag": "main-2-out", "server": "d.example"},
		{"type": "direct", "tag": "chained-out", "detour": "main-2-out"},
		{"type": "urltest", "tag": "main-urltest-out", "outbounds": ["main-1-out", "main-2-out"]}
	], "endpoints": [{"type": "wireguard", "tag": "wg-out", "address": ["10.0.0.2/32"]}]}`)))
	for tag, kept := range map[string]bool{"main-1-out": true, "main-urltest-out": true, "wg-out": true, "main-2-out": false, "chained-out": false, "gone-out": false} {
		require.Equal(t, kept, shared.storage.LoadURLTestHistory(tag) != nil, tag)
	}
}

// A group whose members changed stays the way of its rule: what the downloads found of it is
// kept, while a server that changed or went is forgotten.
func TestForgetChangedKeepsTheDownloadsOfGroups(t *testing.T) {
	shared := &sharedHistory{storage: urltest.NewHistoryStorage()}
	shared.forgetChanged(dialersOf([]byte(`{"outbounds": [
		{"type": "vless", "tag": "a", "server": "a.example"},
		{"type": "vless", "tag": "b", "server": "b.example"},
		{"type": "selector", "tag": "yt-out", "outbounds": ["a", "b"]}
	]}`)))
	done := shared.forgetChanged(dialersOf([]byte(`{"outbounds": [
		{"type": "vless", "tag": "a", "server": "a.example"},
		{"type": "vless", "tag": "c", "server": "c.example"},
		{"type": "selector", "tag": "yt-out", "outbounds": ["a", "c"]}
	]}`)))
	require.ElementsMatch(t, []string{"b", "yt-out"}, done.tags)
	require.Equal(t, []string{"b"}, done.downloads)
}

// The instances of the process share one history: a result found while one configuration
// ran is there for the next, until the outbound it was found for changes.
func TestInstancesShareHistory(t *testing.T) {
	dnsPort, mixedPort := freePort(t), freePort(t)
	config := configuration(t, dnsPort, mixedPort)
	start := func(config []byte) *Instance {
		instance, err := Build(config)
		require.NoError(t, err)
		require.Same(t, history.storage, service.PtrFromContext[urltest.HistoryStorage](instance.ctx))
		require.NoError(t, instance.Start())
		return instance
	}
	instance := start(config)
	history.storage.StoreURLTestHistory("direct-out", &adapter.URLTestHistory{Time: time.Now(), Delay: 42})
	require.NoError(t, instance.Close(10*time.Second))

	instance = start(config)
	require.NotNil(t, history.storage.LoadURLTestHistory("direct-out"), "the same configuration again")
	require.NoError(t, instance.Close(10*time.Second))

	changed := strings.Replace(string(config), `{"type": "direct", "tag": "direct-out"}`, `{"type": "direct", "tag": "direct-out", "connect_timeout": "5s"}`, 1)
	require.NotEqual(t, string(config), changed, "the outbound of the test configuration is not where the test looks")
	instance = start([]byte(changed))
	require.Nil(t, history.storage.LoadURLTestHistory("direct-out"), "the outbound changed")
	require.NoError(t, instance.Close(10*time.Second))
}
