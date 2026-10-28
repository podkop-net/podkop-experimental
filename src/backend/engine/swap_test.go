package engine

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// swapConfiguration is a configuration of a section of a group of two servers, as the backend
// makes it, with the names of the servers given.
func swapConfiguration(t *testing.T, first string, second string) []byte {
	server := func(name string, host string) string {
		return fmt.Sprintf(`{"type": "vless", "tag": "prov: %s", "server": %q, "server_port": 1, "uuid": "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"}`, name, host)
	}
	return []byte(`{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "direct", "tag": "direct-out"},
    ` + server(first, "127.0.0.2") + `,
    ` + server(second, "127.0.0.3") + `,
    {"type": "urltest", "tag": "g-group", "outbounds": ["prov: ` + first + `", "prov: ` + second + `"], "url": "http://127.0.0.1:9/", "interval": "1h", "idle_timeout": "2h"},
    {"type": "selector", "tag": "yt-out", "outbounds": ["g-group", "prov: ` + first + `", "prov: ` + second + `"], "default": "g-group"}
  ],
  "route": {"final": "direct-out"},
  "experimental": {"clash_api": {}, "cache_file": {"enabled": true, "path": "` + filepath.Join(t.TempDir(), "cache.db") + `"}}
}`)
}

// outboundsOf picks the outbounds of a configuration by tag.
func pickOutbounds(t *testing.T, configuration []byte, tags ...string) []json.RawMessage {
	var parsed struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	require.NoError(t, json.Unmarshal(configuration, &parsed))
	var picked []json.RawMessage
	for _, outbound := range parsed.Outbounds {
		for _, tag := range tags {
			if strings.Contains(string(outbound), `"tag": "`+tag+`"`) {
				picked = append(picked, outbound)
			}
		}
	}
	require.Len(t, picked, len(tags))
	return picked
}

// A server renamed while sing-box runs: replaced with its group and selector, and its result
// goes with it.
func TestInstanceSwap(t *testing.T) {
	before := swapConfiguration(t, "DE 113d", "NL")
	instance, err := Build(before)
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close(10 * time.Second) })
	history.storage.StoreURLTestHistory("prov: DE 113d", &adapter.URLTestHistory{Time: time.Now(), Delay: 120})
	// the server chosen in the dashboard
	selector, _ := instance.box.Outbound().Outbound("yt-out")
	require.True(t, selector.(interface{ SelectOutbound(string) bool }).SelectOutbound("prov: DE 113d"))

	after := swapConfiguration(t, "DE 112d", "NL")
	swapped, err := instance.Swap(after, Swap{Put: pickOutbounds(t, after, "prov: DE 112d", "g-group", "yt-out"), Remove: []string{"prov: DE 113d"}}, 0)
	require.NoError(t, err)
	require.Equal(t, Swapped{Added: 1, Replaced: 2, Removed: 1, Kept: 3}, swapped)
	carried := history.storage.LoadURLTestHistory("prov: DE 112d")
	require.NotNil(t, carried, "the result of the name before")
	require.Equal(t, uint16(120), carried.Delay)
	require.Nil(t, history.storage.LoadURLTestHistory("prov: DE 113d"))
	found, loaded := instance.box.Outbound().Outbound("prov: DE 112d")
	require.True(t, loaded)
	require.Equal(t, "vless", found.Type())
	_, loaded = instance.box.Outbound().Outbound("prov: DE 113d")
	require.False(t, loaded)
	require.Contains(t, instance.dialers, "prov: DE 112d")
	selector, _ = instance.box.Outbound().Outbound("yt-out")
	require.Equal(t, "prov: DE 112d", selector.(adapter.OutboundGroup).Selected("tcp").Tag(), "the choice went with the name")
	require.Equal(t, "prov: DE 112d", service.FromContext[adapter.CacheFile](instance.ctx).LoadSelected("yt-out"))

	// what sing-box does not take changes nothing
	_, err = instance.Swap(after, Swap{Put: pickOutbounds(t, after, "prov: NL")}, 0)
	require.ErrorContains(t, err, "goes through prov: NL")
	require.NoError(t, instance.Close(10*time.Second))
	_, err = instance.Swap(after, Swap{}, 0)
	require.ErrorIs(t, err, ErrClosed)
}
