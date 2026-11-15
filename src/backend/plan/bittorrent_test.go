package plan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/probe"

	"github.com/stretchr/testify/require"
)

type bitTorrentConfig struct {
	Inbounds []map[string]any `json:"inbounds"`
	Route    struct {
		Rules []map[string]any `json:"rules"`
	} `json:"route"`
}

func bitTorrentBuild(t *testing.T, options string, rules string) (*Result, bitTorrentConfig) {
	const head = "config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '8.8.8.8'\n"
	const main = "\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n\tlist fully_routed_ips '192.168.1.23'\n"
	result := buildText(t, head+options+main+rules, Facts{})
	var config bitTorrentConfig
	require.NoError(t, json.Unmarshal(result.Config, &config))
	return result, config
}

// ruleIndex is the place of the first route rule with every field of want, -1 when none has them.
func ruleIndex(config bitTorrentConfig, want map[string]any) int {
	for index, entry := range config.Route.Rules {
		matches := true
		for key, value := range want {
			if got, found := entry[key]; !found || !jsonEqual(got, value) {
				matches = false
			}
		}
		if matches {
			return index
		}
	}
	return -1
}

// firstWith is the place of the first route rule that has the field, -1 when none has it.
func firstWith(config bitTorrentConfig, key string) int {
	for index, entry := range config.Route.Rules {
		if _, found := entry[key]; found {
			return index
		}
	}
	return -1
}

func jsonEqual(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}

func hasInbound(config bitTorrentConfig, tag string) map[string]any {
	for _, inbound := range config.Inbounds {
		if inbound["tag"] == tag {
			return inbound
		}
	}
	return nil
}

// Off by default: nothing of BitTorrent in the configuration or the firewall.
func TestBitTorrentOff(t *testing.T) {
	for _, options := range []string{"", "\toption bittorrent 'off'\n"} {
		result, config := bitTorrentBuild(t, options, "")
		require.Empty(t, result.Dataplane.BitTorrent)
		require.Nil(t, hasInbound(config, tagBitTorrentInbound))
		require.Equal(t, -1, ruleIndex(config, map[string]any{"protocol": "bittorrent"}))
	}
}

// Each mode: what the firewall is told, and the route rules of what the proxy had taken before it
// was told, before the devices routed whole.
func TestBitTorrentModes(t *testing.T) {
	result, config := bitTorrentBuild(t, "\toption bittorrent 'bypass'\n", "")
	require.Equal(t, "bypass", result.Dataplane.BitTorrent)
	require.False(t, result.Dataplane.BitTorrentBlockLAN)
	require.Nil(t, hasInbound(config, tagBitTorrentInbound))
	sniffed := ruleIndex(config, map[string]any{"inbound": tagTProxyInbound, "protocol": "bittorrent", "outbound": tagDirectOutbound})
	require.GreaterOrEqual(t, sniffed, 0)
	require.Less(t, sniffed, firstWith(config, "source_ip_cidr"))

	result, config = bitTorrentBuild(t, "\toption bittorrent 'block'\n", "")
	require.Equal(t, "block", result.Dataplane.BitTorrent)
	require.False(t, result.Dataplane.BitTorrentBlockLAN)
	require.GreaterOrEqual(t, ruleIndex(config, map[string]any{"action": "reject", "protocol": "bittorrent"}), 0)

	result, _ = bitTorrentBuild(t, "\toption bittorrent 'block'\n\toption bittorrent_block_scope 'lan'\n", "")
	require.True(t, result.Dataplane.BitTorrentBlockLAN)
	// the scope is of the block only
	result, _ = bitTorrentBuild(t, "\toption bittorrent 'bypass'\n\toption bittorrent_block_scope 'lan'\n", "")
	require.False(t, result.Dataplane.BitTorrentBlockLAN)

	const torrents = "\nconfig section 'torrents'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.16:1080'\n"
	result, config = bitTorrentBuild(t, "\toption bittorrent 'section'\n\toption bittorrent_section 'torrents'\n", torrents)
	require.Equal(t, "section", result.Dataplane.BitTorrent)
	inbound := hasInbound(config, tagBitTorrentInbound)
	require.NotNil(t, inbound)
	require.Equal(t, "tproxy", inbound["type"])
	require.EqualValues(t, dataplane.BitTorrentTProxyPort, inbound["listen_port"])
	routed := ruleIndex(config, map[string]any{"inbound": tagBitTorrentInbound, "outbound": "torrents-out"})
	require.GreaterOrEqual(t, routed, 0)
	sniffed = ruleIndex(config, map[string]any{"inbound": tagTProxyInbound, "protocol": "bittorrent", "outbound": "torrents-out"})
	require.GreaterOrEqual(t, sniffed, 0)
	require.Less(t, sniffed, firstWith(config, "source_ip_cidr"))
	require.Empty(t, result.Warnings)
}

// A mode the backend does not know, or a rule that is not there or is off: as the other traffic,
// with a warning.
func TestBitTorrentWrongSettings(t *testing.T) {
	const off = "\nconfig section 'torrents'\n\toption enabled '0'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.16:1080'\n"
	for name, settings := range map[string][2]string{
		"no such rule": {"\toption bittorrent 'section'\n\toption bittorrent_section 'none'\n", ""},
		"a rule off":   {"\toption bittorrent 'section'\n\toption bittorrent_section 'torrents'\n", off},
		"no mode":      {"\toption bittorrent 'sometimes'\n", ""},
	} {
		result, config := bitTorrentBuild(t, settings[0], settings[1])
		require.Empty(t, result.Dataplane.BitTorrent, name)
		require.Nil(t, hasInbound(config, tagBitTorrentInbound), name)
		require.Equal(t, -1, ruleIndex(config, map[string]any{"protocol": "bittorrent"}), name)
		found := false
		for _, warning := range result.Warnings {
			found = found || strings.HasPrefix(warning, "BitTorrent: ")
		}
		require.True(t, found, name+": %v", result.Warnings)
	}
}

// The inbound of BitTorrent listens where nothing else of the backend does: the transparent proxy,
// the dead end of the check names (probe), the DNS inbound, the Clash API.
func TestBitTorrentPortIsItsOwn(t *testing.T) {
	require.NotContains(t, []int{dataplane.TProxyPort, probe.DeadEndPort, dataplane.DNSPort, dataplane.ClashAPIPort}, dataplane.BitTorrentTProxyPort)
}
