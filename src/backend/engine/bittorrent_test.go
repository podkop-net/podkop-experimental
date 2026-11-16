package engine

import (
	"encoding/json"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/engine/bittorrent"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	"github.com/stretchr/testify/require"
)

// The configuration plan makes for each mode of BitTorrent builds with this engine and the
// module registered: its type and its options are those of package bittorrent.
func TestBitTorrentModuleBuilds(t *testing.T) {
	const head = "config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '8.8.8.8'\n"
	const sections = "\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n\tlist fully_routed_ips '192.168.1.23'\n" +
		"\nconfig section 'torrents'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.16:1080'\n"
	for name, options := range map[string]string{
		"bypass":           "\toption bittorrent 'bypass'\n",
		"block":            "\toption bittorrent 'block'\n",
		"block, the LAN":   "\toption bittorrent 'block'\n\toption bittorrent_block_scope 'lan'\n",
		"section":          "\toption bittorrent 'section'\n\toption bittorrent_section 'torrents'\n",
		"section, the LAN": "\toption bittorrent 'section'\n\toption bittorrent_section 'torrents'\n\toption bittorrent_section_scope 'lan'\n",
	} {
		parsed, err := uci.Parse([]byte(head + options + sections))
		require.NoError(t, err, name)
		config, err := model.Load(parsed)
		require.NoError(t, err, name)
		result, err := plan.Build(config, plan.Facts{}, plan.Options{DecodeLink: func(string) ([]byte, []string, error) {
			return []byte(`{"type": "socks", "server": "203.0.113.15", "server_port": 1080}`), nil, nil
		}})
		require.NoError(t, err, name)
		var document struct {
			Services []struct {
				Type    string `json:"type"`
				Inspect []struct {
					Confirmed string `json:"confirmed"`
				} `json:"inspect"`
			} `json:"services"`
		}
		require.NoError(t, json.Unmarshal(result.Config, &document), name)
		require.Len(t, document.Services, 1, name)
		require.Equal(t, bittorrent.Type, document.Services[0].Type, name)
		for _, inspected := range document.Services[0].Inspect {
			require.Contains(t, []bittorrent.Confirmed{bittorrent.ConfirmedReject, bittorrent.ConfirmedLearn}, bittorrent.Confirmed(inspected.Confirmed), name)
		}
		_, err = Check(result.Config)
		require.NoError(t, err, name)
	}
}
