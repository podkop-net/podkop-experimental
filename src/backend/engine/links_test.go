package engine

import (
	"encoding/json"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/model"

	"github.com/sagernet/sing-box/common/sharelink"
	"github.com/stretchr/testify/require"
)

// A link is decoded without sing-box building its outbound; CheckLink builds it and tells why
// this sing-box cannot use it, without what the link keeps secret.
func TestDecodeLinkDoesNotBuild(t *testing.T) {
	const canary = "CANARY0f6d2c"
	const uuid = "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"
	// a REALITY key that is none: the decoder takes it, the outbound cannot be built
	link := "vless://" + uuid + "@example.org:443?security=reality&pbk=" + canary + "&sid=01"
	_, _, err := DecodeLink(link)
	require.NoError(t, err)
	err = CheckLink(link)
	require.Error(t, err)
	require.NotContains(t, err.Error(), canary)
	require.NotContains(t, err.Error(), uuid)
	require.NoError(t, CheckLink("socks5://203.0.113.15:1080"))
	// what the decoder refuses is refused by both
	_, _, err = DecodeLink("vless://broken")
	require.Error(t, err)
	require.Error(t, CheckLink("vless://broken"))
}

// The protocols the rows of the rules choose servers by (model.Protocols) are the types of the
// outbounds the links make: every scheme the decoder reads is of one of them, by model.LinkProtocol
// (the page counts the servers of a row by it) as by the type of the outbound (the plan goes by it),
// and each of them has a scheme and the options of this sing-box.
func TestLinkProtocols(t *testing.T) {
	schemes := sharelink.Schemes()
	require.GreaterOrEqual(t, len(schemes), 18)
	found := make(map[string]bool)
	for scheme, kind := range schemes {
		require.Equal(t, kind, model.LinkProtocol(scheme+"://host.example:443"), scheme)
		require.Contains(t, model.Protocols, kind, scheme)
		found[kind] = true
	}
	for _, protocol := range model.Protocols {
		require.True(t, found[protocol], "no link makes a server of %s", protocol)
		require.NotNil(t, outboundOptions(protocol), protocol)
	}

	// links read: the type of the outbound is the protocol of the link
	const uuid = "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"
	for _, link := range []string{
		"vless://" + uuid + "@example.org:443?security=tls&sni=example.org",
		"trojan://p@example.org:443?sni=example.org",
		"ss://aes-256-gcm:p@example.org:8388",
		"hy2://p@example.org:443/?sni=example.org",
		"hysteria2://p@example.org:443/?sni=example.org",
		"tuic://" + uuid + ":p@example.org:443?sni=example.org",
		"socks5h://example.org:1080",
		"https://u:p@example.org:8443",
		"anytls://p@example.org:443?sni=example.org",
		"naive+https://u:p@example.org:443",
	} {
		content, _, err := DecodeLink(link)
		require.NoError(t, err, link)
		var outbound struct {
			Type string `json:"type"`
		}
		require.NoError(t, json.Unmarshal(content, &outbound))
		require.Equal(t, outbound.Type, model.LinkProtocol(link), link)
	}
}
