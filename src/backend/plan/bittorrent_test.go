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

type bitTorrentServices struct {
	Services []map[string]any `json:"services"`
}

func services(t *testing.T, result *Result) []map[string]any {
	var document bitTorrentServices
	require.NoError(t, json.Unmarshal(result.Config, &document))
	return document.Services
}

var (
	proxyInbounds = []any{tagTProxyInbound, tagBitTorrentCheckInbound}
	allInbounds   = []any{tagTProxyInbound, tagBitTorrentCheckInbound, tagBitTorrentLANInbound}
)

// Off by default: nothing of BitTorrent in the configuration or the firewall.
func TestBitTorrentOff(t *testing.T) {
	for _, options := range []string{"", "\toption bittorrent 'off'\n"} {
		result, config := bitTorrentBuild(t, options, "")
		require.Empty(t, result.Dataplane.BitTorrent)
		for _, tag := range []string{tagBitTorrentInbound, tagBitTorrentLANInbound, tagBitTorrentCheckInbound} {
			require.Nil(t, hasInbound(config, tag))
		}
		require.Equal(t, -1, ruleIndex(config, map[string]any{"protocol": "bittorrent"}))
		require.Empty(t, services(t, result))
		// the devices routed whole come in through the transparent proxy alone
		require.True(t, jsonEqual(config.Route.Rules[firstWith(config, "source_ip_cidr")]["inbound"], tagTProxyInbound))
	}
}

// Each mode: what the firewall is told, the inbounds and the module, the route rules of BitTorrent
// before the devices routed whole, and podkop's rules on the inspection inbound too.
func TestBitTorrentModes(t *testing.T) {
	inbounds := func(config bitTorrentConfig, in bool) {
		require.Equal(t, in, hasInbound(config, tagBitTorrentInbound) != nil)
		for tag, port := range map[string]int{tagBitTorrentLANInbound: dataplane.BitTorrentLANTProxyPort, tagBitTorrentCheckInbound: dataplane.BitTorrentCheckTProxyPort} {
			inbound := hasInbound(config, tag)
			require.NotNil(t, inbound, tag)
			require.Equal(t, "tproxy", inbound["type"])
			require.EqualValues(t, port, inbound["listen_port"])
		}
		// podkop's rules take the inspected connections too
		require.True(t, jsonEqual(config.Route.Rules[firstWith(config, "source_ip_cidr")]["inbound"], proxyInbounds))
		require.GreaterOrEqual(t, ruleIndex(config, map[string]any{"action": "sniff", "inbound": []any{tagTProxyInbound, tagDNSInbound, tagBitTorrentCheckInbound, tagBitTorrentLANInbound}}), 0)
		lan := ruleIndex(config, map[string]any{"inbound": tagBitTorrentLANInbound, "outbound": tagDirectOutbound})
		require.GreaterOrEqual(t, lan, 0)
		require.Less(t, lan, firstWith(config, "source_ip_cidr"))
	}
	module := func(result *Result, confirmed string) {
		list := services(t, result)
		require.Len(t, list, 1)
		require.Equal(t, bitTorrentServiceType, list[0]["type"])
		require.Equal(t, "bt_learned", list[0]["set"])
		require.True(t, jsonEqual(list[0]["inspect"], []any{
			map[string]any{"inbound": tagBitTorrentCheckInbound, "confirmed": confirmed},
			map[string]any{"inbound": tagBitTorrentLANInbound, "confirmed": confirmed},
		}), "%v", list[0]["inspect"])
	}

	result, config := bitTorrentBuild(t, "\toption bittorrent 'bypass'\n", "")
	require.Equal(t, "bypass", result.Dataplane.BitTorrent)
	require.False(t, result.Dataplane.BitTorrentLAN)
	inbounds(config, true)
	module(result, bitTorrentLearnReset)
	require.GreaterOrEqual(t, ruleIndex(config, map[string]any{"inbound": tagBitTorrentInbound, "outbound": tagDirectOutbound}), 0)
	sniffed := ruleIndex(config, map[string]any{"inbound": allInbounds, "protocol": "bittorrent", "outbound": tagDirectOutbound})
	require.GreaterOrEqual(t, sniffed, 0)
	require.Less(t, sniffed, firstWith(config, "source_ip_cidr"))

	result, config = bitTorrentBuild(t, "\toption bittorrent 'block'\n", "")
	require.Equal(t, "block", result.Dataplane.BitTorrent)
	require.False(t, result.Dataplane.BitTorrentLAN)
	inbounds(config, false)
	module(result, bitTorrentReject)
	require.GreaterOrEqual(t, ruleIndex(config, map[string]any{"action": "reject", "inbound": allInbounds, "protocol": "bittorrent"}), 0)

	result, _ = bitTorrentBuild(t, "\toption bittorrent 'block'\n\toption bittorrent_block_scope 'lan'\n", "")
	require.True(t, result.Dataplane.BitTorrentLAN)
	// each scope is of its mode only
	result, _ = bitTorrentBuild(t, "\toption bittorrent 'bypass'\n\toption bittorrent_block_scope 'lan'\n\toption bittorrent_section_scope 'lan'\n", "")
	require.False(t, result.Dataplane.BitTorrentLAN)
	result, _ = bitTorrentBuild(t, "\toption bittorrent 'block'\n\toption bittorrent_section_scope 'lan'\n", "")
	require.False(t, result.Dataplane.BitTorrentLAN)

	const torrents = "\nconfig section 'torrents'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.16:1080'\n"
	result, config = bitTorrentBuild(t, "\toption bittorrent 'section'\n\toption bittorrent_section 'torrents'\n", torrents)
	require.Equal(t, "section", result.Dataplane.BitTorrent)
	require.False(t, result.Dataplane.BitTorrentLAN)
	inbounds(config, true)
	module(result, bitTorrentLearnReset)
	require.EqualValues(t, dataplane.BitTorrentTProxyPort, hasInbound(config, tagBitTorrentInbound)["listen_port"])
	routed := ruleIndex(config, map[string]any{"inbound": tagBitTorrentInbound, "outbound": "torrents-out"})
	require.GreaterOrEqual(t, routed, 0)
	sniffed = ruleIndex(config, map[string]any{"inbound": proxyInbounds, "protocol": "bittorrent", "outbound": "torrents-out"})
	require.GreaterOrEqual(t, sniffed, 0)
	require.Less(t, sniffed, firstWith(config, "source_ip_cidr"))
	require.Empty(t, result.Warnings)

	result, config = bitTorrentBuild(t, "\toption bittorrent 'section'\n\toption bittorrent_section 'torrents'\n\toption bittorrent_section_scope 'lan'\n", torrents)
	require.True(t, result.Dataplane.BitTorrentLAN)

	// the measurements' setting: learn a confirmed connection and leave it open ((ii) alone), or
	// close it as well (the default); block rejects it whatever
	result, _ = bitTorrentBuild(t, "\toption bittorrent 'bypass'\n\toption bittorrent_confirmed 'learn'\n", "")
	module(result, bitTorrentLearn)
	result, _ = bitTorrentBuild(t, "\toption bittorrent 'section'\n\toption bittorrent_section 'torrents'\n\toption bittorrent_confirmed 'learn'\n", torrents)
	module(result, bitTorrentLearn)
	result, _ = bitTorrentBuild(t, "\toption bittorrent 'bypass'\n\toption bittorrent_confirmed 'learn_reset'\n", "")
	module(result, bitTorrentLearnReset)
	result, _ = bitTorrentBuild(t, "\toption bittorrent 'block'\n\toption bittorrent_confirmed 'learn'\n", "")
	module(result, bitTorrentReject)
	require.GreaterOrEqual(t, ruleIndex(config, map[string]any{"inbound": allInbounds, "protocol": "bittorrent", "outbound": "torrents-out"}), 0)
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
		require.Nil(t, hasInbound(config, tagBitTorrentCheckInbound), name)
		require.Equal(t, -1, ruleIndex(config, map[string]any{"protocol": "bittorrent"}), name)
		found := false
		for _, warning := range result.Warnings {
			found = found || strings.HasPrefix(warning, "BitTorrent: ")
		}
		require.True(t, found, name+": %v", result.Warnings)
	}
}

// The suspicion by the fan-out of connection openings ("bittorrent_lan_suspect") is on only in the
// scope of the whole LAN: the inbound of the suspects, the module's early check of it, and the
// allowance for the firewall. Outside that scope, and without the setting, nothing of it is there.
func TestBitTorrentSuspicion(t *testing.T) {
	const rule = "\nconfig section 'torrents'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.16:1080'\n"
	for name, c := range map[string]struct {
		settings string
		fan      dataplane.Fan
	}{
		"block of the LAN":            {"\toption bittorrent 'block'\n\toption bittorrent_block_scope 'lan'\n\toption bittorrent_lan_suspect '1'\n", dataplane.DefaultFan},
		"section of the LAN":          {"\toption bittorrent 'section'\n\toption bittorrent_section 'torrents'\n\toption bittorrent_section_scope 'lan'\n\toption bittorrent_lan_suspect '1'\n", dataplane.DefaultFan},
		"an allowance of the lab":     {"\toption bittorrent 'block'\n\toption bittorrent_block_scope 'lan'\n\toption bittorrent_lan_suspect '1'\n\toption bittorrent_lan_allowance '8 1/second 60 600'\n", dataplane.Fan{Burst: 8, Rate: 1, Unit: 1, Pair: 60e9, Suspect: 600e9}},
		"an allowance that is none":   {"\toption bittorrent 'block'\n\toption bittorrent_block_scope 'lan'\n\toption bittorrent_lan_suspect '1'\n\toption bittorrent_lan_allowance 'many'\n", dataplane.DefaultFan},
		"block of what podkop takes":  {"\toption bittorrent 'block'\n\toption bittorrent_lan_suspect '1'\n", dataplane.Fan{}},
		"bypass":                      {"\toption bittorrent 'bypass'\n\toption bittorrent_lan_suspect '1'\n", dataplane.Fan{}},
		"the LAN without the setting": {"\toption bittorrent 'block'\n\toption bittorrent_block_scope 'lan'\n", dataplane.Fan{}},
		"an allowance alone":          {"\toption bittorrent 'block'\n\toption bittorrent_block_scope 'lan'\n\toption bittorrent_lan_allowance '8 1/second 60 600'\n", dataplane.Fan{}},
	} {
		result, config := bitTorrentBuild(t, c.settings, rule)
		require.Equal(t, c.fan, result.Dataplane.BitTorrentFan, name)
		inbound := hasInbound(config, tagBitTorrentSuspectInbound)
		early := ""
		for _, service := range services(t, result) {
			text, _ := json.Marshal(service["early"])
			early += string(text)
		}
		if !c.fan.On() {
			require.Nil(t, inbound, name)
			require.NotContains(t, early, tagBitTorrentSuspectInbound, name)
			continue
		}
		require.NotNil(t, inbound, name)
		require.EqualValues(t, dataplane.BitTorrentSuspectTProxyPort, inbound["listen_port"], name)
		require.Contains(t, early, `"inbound":"`+tagBitTorrentSuspectInbound+`"`, name)
		require.Contains(t, early, `"suspect":true`, name)
	}
	// an allowance that cannot be read is told
	result, _ := bitTorrentBuild(t, "\toption bittorrent 'block'\n\toption bittorrent_block_scope 'lan'\n\toption bittorrent_lan_suspect '1'\n\toption bittorrent_lan_allowance 'many'\n", "")
	require.Contains(t, strings.Join(result.Warnings, "\n"), "bittorrent_lan_allowance")
}

// The inbound of BitTorrent listens where nothing else of the backend does: the transparent proxy,
// the dead end of the check names (probe), the DNS inbound, the Clash API, and each other.
func TestBitTorrentPortIsItsOwn(t *testing.T) {
	ports := []int{dataplane.TProxyPort, probe.DeadEndPort, dataplane.DNSPort, dataplane.ClashAPIPort}
	for _, port := range []int{dataplane.BitTorrentTProxyPort, dataplane.BitTorrentLANTProxyPort, dataplane.BitTorrentCheckTProxyPort} {
		require.NotContains(t, ports, port)
		ports = append(ports, port)
	}
}
