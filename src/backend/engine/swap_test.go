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
	return groupConfiguration(t, [2]string{first, "127.0.0.2"}, [2]string{second, "127.0.0.3"})
}

// groupConfiguration is swapConfiguration with the name and the address of each server given.
func groupConfiguration(t *testing.T, first [2]string, second [2]string) []byte {
	return []byte(`{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "direct", "tag": "direct-out"},
    ` + testServer("prov: "+first[0], first[1]) + `,
    ` + testServer("prov: "+second[0], second[1]) + `,
    {"type": "urltest", "tag": "g-group", "outbounds": ["prov: ` + first[0] + `", "prov: ` + second[0] + `"], "url": "http://127.0.0.1:9/", "interval": "1h", "idle_timeout": "2h"},
    {"type": "selector", "tag": "yt-out", "outbounds": ["g-group", "prov: ` + first[0] + `", "prov: ` + second[0] + `"], "default": "g-group"}
  ],
  "route": {"final": "direct-out"},
  "experimental": {"clash_api": {}, "cache_file": {"enabled": true, "path": "` + filepath.Join(t.TempDir(), "cache.db") + `"}}
}`)
}

// testServer is the outbound of a server of a subscription at the address given.
func testServer(tag string, host string) string {
	return fmt.Sprintf(`{"type": "vless", "tag": %q, "server": %q, "server_port": 1, "uuid": "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"}`, tag, host)
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

// Servers of one name that changed places in the list: their tags are numbered in its order, and
// the choice of the dashboard follows the server, not the number. A swap sing-box refuses puts
// the choice back in the cache file.
func TestInstanceSwapCarriesTheChoiceWithTheServer(t *testing.T) {
	before := groupConfiguration(t, [2]string{"NL", "127.0.0.2"}, [2]string{"NL #2", "127.0.0.3"})
	instance, err := Build(before)
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close(10 * time.Second) })
	selector, _ := instance.box.Outbound().Outbound("yt-out")
	require.True(t, selector.(interface{ SelectOutbound(string) bool }).SelectOutbound("prov: NL #2"))
	cacheFile := service.FromContext[adapter.CacheFile](instance.ctx)

	after := groupConfiguration(t, [2]string{"NL", "127.0.0.3"}, [2]string{"NL #2", "127.0.0.2"})
	// the group and the selector that stay go through the servers replaced: sing-box refuses
	_, err = instance.Swap(after, Swap{Put: pickOutbounds(t, after, "prov: NL", "prov: NL #2")}, 0)
	require.Error(t, err)
	require.Equal(t, "prov: NL #2", cacheFile.LoadSelected("yt-out"), "the choice is put back")

	_, err = instance.Swap(after, Swap{Put: pickOutbounds(t, after, "prov: NL", "prov: NL #2", "g-group", "yt-out")}, 0)
	require.NoError(t, err)
	selector, _ = instance.box.Outbound().Outbound("yt-out")
	require.Equal(t, "prov: NL", selector.(adapter.OutboundGroup).Selected("tcp").Tag(), "the choice went with the server")
	require.Equal(t, "prov: NL", cacheFile.LoadSelected("yt-out"))
}

// A rename sing-box refuses leaves the history as the configuration that runs has it: no result
// under the new name, the one of the name that runs back.
func TestInstanceSwapRefusedKeepsTheHistory(t *testing.T) {
	before := swapConfiguration(t, "SE 113d", "FI")
	instance, err := Build(before)
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close(10 * time.Second) })
	history.storage.StoreURLTestHistory("prov: SE 113d", &adapter.URLTestHistory{Time: time.Now(), Delay: 130})

	after := swapConfiguration(t, "SE 112d", "FI")
	// the group and the selector that stay go through the server taken out: sing-box refuses
	_, err = instance.Swap(after, Swap{Put: pickOutbounds(t, after, "prov: SE 112d"), Remove: []string{"prov: SE 113d"}}, 0)
	require.Error(t, err)
	require.Nil(t, history.storage.LoadURLTestHistory("prov: SE 112d"), "nothing under a name that does not run")
	kept := history.storage.LoadURLTestHistory("prov: SE 113d")
	require.NotNil(t, kept, "the result of the server that runs is back")
	require.Equal(t, uint16(130), kept.Delay)
	history.access.Lock()
	_, started := history.started["prov: SE 113d"]
	history.access.Unlock()
	require.True(t, started, "the next start compares with what runs")
}

func TestCarriedSelections(t *testing.T) {
	selector := func(tag string, members ...string) string {
		content, err := json.Marshal(map[string]any{"type": "selector", "tag": tag, "outbounds": members, "default": members[0]})
		require.NoError(t, err)
		return string(content)
	}
	dialers := func(outbounds ...string) map[string]dialer {
		return dialersOf([]byte(`{"outbounds": [` + strings.Join(outbounds, ", ") + `]}`))
	}
	group := `{"type": "urltest", "tag": "g-group", "outbounds": ["prov: A", "prov: B"]}`
	previous := dialers(testServer("prov: A", "10.0.0.1"), testServer("prov: B", "10.0.0.2"), group,
		selector("yt-out", "g-group", "prov: A", "prov: B"))
	for _, test := range []struct {
		name   string
		choice string
		next   map[string]dialer
		want   map[string]string
	}{
		{"renamed", "prov: B", dialers(testServer("prov: A", "10.0.0.1"), testServer("prov: B 112d", "10.0.0.2"),
			selector("yt-out", "g-group", "prov: A", "prov: B 112d")), map[string]string{"yt-out": "prov: B 112d"}},
		{"servers that changed places", "prov: B", dialers(testServer("prov: A", "10.0.0.2"), testServer("prov: B", "10.0.0.1"),
			selector("yt-out", "g-group", "prov: A", "prov: B")), map[string]string{"yt-out": "prov: A"}},
		{"the same", "prov: B", dialers(testServer("prov: A", "10.0.0.3"), testServer("prov: B", "10.0.0.2"),
			selector("yt-out", "g-group", "prov: A", "prov: B")), map[string]string{}},
		{"another server under the name", "prov: B", dialers(testServer("prov: A", "10.0.0.1"), testServer("prov: B", "10.0.0.9"),
			selector("yt-out", "g-group", "prov: A", "prov: B")), map[string]string{}},
		{"gone to another group", "prov: B", dialers(testServer("prov: A", "10.0.0.1"), testServer("prov: SE", "10.0.0.2"),
			selector("yt-out", "g-group", "prov: A"), selector("gm-out", "h-group", "prov: SE")), map[string]string{}},
		{"under two names: the first of the selector", "prov: B", dialers(testServer("prov: A", "10.0.0.1"), testServer("prov: B2", "10.0.0.2"),
			testServer("prov: B1", "10.0.0.2"), selector("yt-out", "g-group", "prov: A", "prov: B1", "prov: B2")), map[string]string{"yt-out": "prov: B1"}},
		{"the group", "g-group", dialers(testServer("prov: A", "10.0.0.1"), `{"type": "urltest", "tag": "g-group", "outbounds": ["prov: A"]}`,
			selector("yt-out", "g-group", "prov: A")), map[string]string{}},
		{"no choice", "", dialers(testServer("prov: B 112d", "10.0.0.2"), selector("yt-out", "g-group", "prov: B 112d")), map[string]string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			chosen := func(tag string) string {
				if tag == "yt-out" {
					return test.choice
				}
				return ""
			}
			require.Equal(t, test.want, carriedSelections(previous, test.next, chosen))
		})
	}
}
