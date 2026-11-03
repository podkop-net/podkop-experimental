package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/detect"

	"github.com/stretchr/testify/require"
)

// What the kinds come from: every shape of an outbound.
func TestServersOf(t *testing.T) {
	configuration := []byte(`{
  "outbounds": [
    {"type": "direct", "tag": "direct-out"},
    {"type": "block", "tag": "block"},
    {"type": "direct", "tag": "wan2", "bind_interface": "eth2"},
    {"type": "selector", "tag": "main-out", "outbounds": ["reality"], "default": "reality"},
    {"type": "urltest", "tag": "main-urltest-out", "outbounds": ["reality", "ws"], "fallbacks": ["plain"], "url": "http://x.example/", "interval": "1m"},
    {"type": "vless", "tag": "reality", "server": "192.0.2.1", "server_port": 443, "uuid": "secret-uuid",
      "tls": {"enabled": true, "server_name": "a.example", "utls": {"enabled": true, "fingerprint": "firefox"}, "reality": {"enabled": true, "public_key": "k"}}},
    {"type": "vless", "tag": "ws", "server": "b.example", "server_port": 8443, "tls": {"enabled": true, "utls": {"enabled": true}}, "transport": {"type": "ws"}},
    {"type": "vless", "tag": "upgrade", "server": "192.0.2.2", "server_port": 443, "tls": {"enabled": true, "utls": {"enabled": true, "fingerprint": "chrome"}}, "transport": {"type": "httpupgrade"}},
    {"type": "trojan", "tag": "plain-tls", "server": "192.0.2.3", "server_port": 443, "tls": {"enabled": true, "server_name": "c.example"}},
    {"type": "vless", "tag": "xhttp", "server": "192.0.2.4", "server_port": 443, "tls": {"enabled": true, "utls": {"enabled": true, "fingerprint": "chrome"}}, "transport": {"type": "xhttp"}},
    {"type": "vless", "tag": "grpc", "server": "192.0.2.5", "server_port": 443, "tls": {"enabled": true}, "transport": {"type": "grpc"}},
    {"type": "vless", "tag": "http", "server": "192.0.2.6", "server_port": 443, "transport": {"type": "http"}},
    {"type": "vless", "tag": "mux", "server": "192.0.2.7", "server_port": 443, "tls": {"enabled": true, "utls": {"enabled": true, "fingerprint": "chrome"}}, "multiplex": {"enabled": true}},
    {"type": "vless", "tag": "mux-off", "server": "192.0.2.8", "server_port": 443, "tls": {"enabled": true, "utls": {"enabled": true, "fingerprint": "chrome"}}, "multiplex": {"enabled": false}},
    {"type": "hysteria2", "tag": "hy2", "server": "192.0.2.9", "server_port": 443, "password": "secret", "tls": {"enabled": true, "server_name": "h.example", "utls": {"enabled": true}}},
    {"type": "tuic", "tag": "tuic", "server": "192.0.2.10", "server_port": 443, "tls": {"enabled": true}},
    {"type": "shadowsocks", "tag": "plain", "server": "2001:db8::1", "server_port": 8388, "password": "secret"},
    {"type": "socks", "tag": "socks", "server": "192.0.2.11", "server_port": 1080},
    {"type": "vless", "tag": "reality via ws", "server": "192.0.2.1", "server_port": 443, "detour": "ws",
      "tls": {"enabled": true, "server_name": "a.example", "utls": {"enabled": true, "fingerprint": "firefox"}, "reality": {"enabled": true, "public_key": "k"}}},
    {"type": "vless", "tag": "reality via wan2", "server": "192.0.2.1", "server_port": 443, "detour": "wan2",
      "tls": {"enabled": true, "server_name": "a.example", "utls": {"enabled": true, "fingerprint": "firefox"}, "reality": {"enabled": true, "public_key": "k"}}},
    {"type": "vless", "tag": "via group", "server": "192.0.2.12", "server_port": 443, "detour": "main-urltest-out"},
    {"type": "vless", "tag": "quic", "server": "192.0.2.13", "server_port": 443, "tls": {"enabled": true, "server_name": "q.example"}, "transport": {"type": "quic"}},
    {"type": "vless", "tag": "xhttp h3", "server": "192.0.2.14", "server_port": 443, "tls": {"enabled": true, "alpn": ["h3"], "utls": {"enabled": true, "fingerprint": "chrome"}}, "transport": {"type": "xhttp"}},
    {"type": "vless", "tag": "xhttp h3 as text", "server": "192.0.2.15", "server_port": 443, "tls": {"enabled": true, "alpn": "h3"}, "transport": {"type": "xhttp"}},
    {"type": "vless", "tag": "xhttp h3 h2", "server": "192.0.2.16", "server_port": 443, "tls": {"enabled": true, "alpn": ["h3", "h2"]}, "transport": {"type": "xhttp"}},
    {"type": "vless", "tag": "xhttp h3 reality", "server": "192.0.2.17", "server_port": 443, "tls": {"enabled": true, "alpn": ["h3"], "reality": {"enabled": true, "public_key": "k"}, "utls": {"enabled": true}}, "transport": {"type": "xhttp"}},
    {"type": "vless", "tag": "ws plain", "server": "192.0.2.18", "server_port": 80, "transport": {"type": "ws"}},
    {"type": "tor", "tag": "no server"},
    {"type": "vless", "tag": 7}
  ],
  "experimental": {"utls_fallback": {"enabled": true}}
}`)
	servers, fallback := ServersOf(configuration)
	require.True(t, fallback)
	byTag := make(map[string]detect.Server)
	var order []string
	for _, server := range servers {
		byTag[server.Tag] = server
		order = append(order, server.Tag)
	}
	require.Equal(t, []string{"reality", "ws", "upgrade", "plain-tls", "xhttp", "grpc", "http", "mux", "mux-off", "hy2", "tuic", "plain", "socks",
		"reality via ws", "reality via wan2", "via group", "quic", "xhttp h3", "xhttp h3 as text", "xhttp h3 h2", "xhttp h3 reality", "ws plain", "no server"}, order)

	kinds := map[string]detect.Kind{
		"reality": detect.KindFingerprint, "ws": detect.KindFingerprint, "upgrade": detect.KindFingerprint, "plain-tls": detect.KindTLS,
		"xhttp": detect.KindPooled, "grpc": detect.KindPooled, "http": detect.KindPooled, "mux": detect.KindPooled, "mux-off": detect.KindFingerprint,
		"hy2": detect.KindUDP, "tuic": detect.KindUDP, "plain": detect.KindPlain, "socks": detect.KindPlain,
		"reality via ws": detect.KindNone, "reality via wan2": detect.KindFingerprint, "via group": detect.KindNone, "no server": detect.KindNone,
		"quic": detect.KindUDP, "xhttp h3": detect.KindUDP, "xhttp h3 as text": detect.KindUDP, "xhttp h3 h2": detect.KindPooled, "xhttp h3 reality": detect.KindPooled, "ws plain": detect.KindPlain,
	}
	for tag, kind := range kinds {
		require.Equal(t, kind, byTag[tag].Kind, tag)
	}
	require.Empty(t, byTag["xhttp h3"].Fingerprint, "QUIC has no fingerprint")

	// what the stages go by
	for tag, server := range byTag {
		require.Equal(t, tag == "reality" || tag == "reality via ws" || tag == "reality via wan2" || tag == "xhttp h3 reality", server.Reality, tag)
		require.Equal(t, tag == "grpc" || tag == "http", server.LazyDial, tag)
		require.Equal(t, tag == "ws" || tag == "upgrade", server.UpgradeInDial, tag)
	}

	reality := byTag["reality"]
	require.Equal(t, "firefox", reality.Fingerprint)
	require.Equal(t, "a.example", reality.ServerName)
	require.Equal(t, "192.0.2.1:443", reality.Destination)
	require.Empty(t, reality.Detour)
	require.Equal(t, time.Minute, reality.TestInterval)
	require.Contains(t, string(reality.Content), "secret-uuid")
	require.NotEmpty(t, reality.Hash)
	require.NotContains(t, reality.Hash, "secret")

	ws := byTag["ws"]
	require.Equal(t, "chrome", ws.Fingerprint, "the engine's default")
	require.Equal(t, "b.example", ws.ServerName, "the server, when no name is told")
	require.Equal(t, "b.example:8443", ws.Destination)

	require.Empty(t, byTag["plain-tls"].Fingerprint)
	require.Equal(t, "c.example", byTag["plain-tls"].ServerName)
	require.Equal(t, "chrome", byTag["xhttp"].Fingerprint)
	require.Empty(t, byTag["hy2"].Fingerprint, "QUIC has no fingerprint")
	require.Equal(t, time.Minute, byTag["plain"].TestInterval, "a fallback of a group is tested as well")
	require.Zero(t, byTag["socks"].TestInterval)
	require.Equal(t, "[2001:db8::1]:8388", byTag["plain"].Destination)
	require.Equal(t, "ws", byTag["reality via ws"].Detour)
	require.Equal(t, "wan2", byTag["reality via wan2"].Detour)

	// a tag that names another server has another hash
	other, _ := ServersOf([]byte(`{"outbounds": [{"type": "vless", "tag": "reality", "server": "192.0.2.99", "server_port": 443}]}`))
	require.NotEqual(t, reality.Hash, other[0].Hash)
	again, _ := ServersOf(configuration)
	require.Equal(t, reality.Hash, again[0].Hash)

	_, fallback = ServersOf([]byte(`{"experimental": {"utls_fallback": {"enabled": false}}}`))
	require.False(t, fallback)
	_, fallback = ServersOf([]byte(`{}`))
	require.False(t, fallback)
	none, fallback := ServersOf([]byte(`not json`))
	require.Empty(t, none)
	require.False(t, fallback)
}

// A band widened for the frames of a transport, not for what a probe does not have; a download on
// a leg of its own.
func TestServersOfFramedAndDownloadLeg(t *testing.T) {
	servers, _ := ServersOf([]byte(`{"outbounds": [
    {"type": "vless", "tag": "xhttp", "server": "192.0.2.1", "server_port": 443, "tls": {"enabled": true}, "transport": {"type": "xhttp"}},
    {"type": "vless", "tag": "grpc", "server": "192.0.2.2", "server_port": 443, "tls": {"enabled": true}, "transport": {"type": "grpc"}},
    {"type": "vless", "tag": "http", "server": "192.0.2.3", "server_port": 443, "tls": {"enabled": true}, "transport": {"type": "http"}},
    {"type": "vless", "tag": "mux", "server": "192.0.2.4", "server_port": 443, "tls": {"enabled": true}, "multiplex": {"enabled": true}},
    {"type": "vless", "tag": "mux over grpc", "server": "192.0.2.5", "server_port": 443, "tls": {"enabled": true}, "transport": {"type": "grpc"}, "multiplex": {"enabled": true}},
    {"type": "naive", "tag": "naive", "server": "192.0.2.6", "server_port": 443, "tls": {"enabled": true}},
    {"type": "anytls", "tag": "anytls", "server": "192.0.2.7", "server_port": 443, "tls": {"enabled": true}},
    {"type": "vless", "tag": "ws", "server": "192.0.2.8", "server_port": 443, "tls": {"enabled": true}, "transport": {"type": "ws"}},
    {"type": "vless", "tag": "reality h2, download h3", "server": "192.0.2.9", "server_port": 443, "tls": {"enabled": true, "reality": {"enabled": true, "public_key": "k"}, "utls": {"enabled": true}},
      "transport": {"type": "xhttp", "download": {"server": "192.0.2.10", "server_port": 443, "tls": {"enabled": true, "alpn": ["h3"]}}}},
    {"type": "vless", "tag": "a null download", "server": "192.0.2.11", "server_port": 443, "tls": {"enabled": true}, "transport": {"type": "xhttp", "download": null}},
    {"type": "vless", "tag": "a download of another transport", "server": "192.0.2.12", "server_port": 443, "tls": {"enabled": true}, "transport": {"type": "ws", "download": {"server": "x"}}}
  ]}`))
	byTag := make(map[string]detect.Server)
	for _, server := range servers {
		byTag[server.Tag] = server
	}
	require.Len(t, byTag, 11)
	for tag, framed := range map[string]bool{
		"xhttp": true, "grpc": true, "http": true, "mux": false, "mux over grpc": true, "naive": false, "anytls": false, "ws": false,
		"reality h2, download h3": true, "a null download": true, "a download of another transport": false,
	} {
		require.Equal(t, framed, byTag[tag].Framed, tag)
	}
	for tag, server := range byTag {
		require.Equal(t, tag == "reality h2, download h3", server.DownloadLeg, tag)
	}
	require.Equal(t, detect.KindPooled, byTag["reality h2, download h3"].Kind, "the main leg is TCP")
	require.Equal(t, detect.KindPooled, byTag["mux"].Kind)
	require.Equal(t, "chrome", byTag["reality h2, download h3"].Fingerprint)
}

// The key ServersOf reads is the key under which the engine itself records a real handshake.
func TestServersOfKeyIsTheEngines(t *testing.T) {
	address, _ := tlsListener(t, "tcp", "127.0.0.1:0")
	port := address.Port
	cases := map[string]string{
		"with a name":    probeServer("with a name", "127.0.0.1", port, `, "server_name": "a.example", "utls": {"enabled": true, "fingerprint": "chrome"}`),
		"without a name": probeServer("without a name", "127.0.0.1", port, `, "utls": {"enabled": true, "fingerprint": "chrome"}`),
		"no fingerprint": probeServer("no fingerprint", "127.0.0.1", port, `, "server_name": "b.example", "utls": {"enabled": true}`),
		"firefox":        probeServer("firefox", "127.0.0.1", port, `, "server_name": "a.example", "utls": {"enabled": true, "fingerprint": "firefox"}`),
		"safari":         probeServer("safari", "127.0.0.1", port, `, "server_name": "a.example", "utls": {"enabled": true, "fingerprint": "safari"}`),
		"classic":        probeServer("classic", "127.0.0.1", port, `, "server_name": "a.example", "utls": {"enabled": true, "fingerprint": "edge"}`),
		"random":         probeServer("random", "127.0.0.1", port, `, "server_name": "a.example", "utls": {"enabled": true, "fingerprint": "random"}`),
	}
	// non-canonical text of an address: the destination is the parsed one, the name as written
	if listener, err := net.Listen("tcp", "[::1]:0"); err == nil {
		listener.Close()
		address6, _ := tlsListener(t, "tcp", "[::1]:0")
		cases["IPv6"] = probeServer("IPv6", "::1", address6.Port, `, "utls": {"enabled": true, "fingerprint": "chrome"}`)
		cases["IPv6 long"] = probeServer("IPv6 long", "0:0:0:0:0:0:0:1", address6.Port, `, "utls": {"enabled": true, "fingerprint": "chrome"}`)
	} else {
		t.Log("no IPv6 here: the two cases of it are left out")
	}
	var outbounds []string
	for _, outbound := range cases {
		outbounds = append(outbounds, outbound)
	}
	instance := probeInstance(t, true, outbounds...)
	servers := serversOfInstance(t, outbounds)
	require.Len(t, servers, len(cases))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, server := range servers {
		t.Run(server.Tag, func(t *testing.T) {
			conn, err := instance.Dial(ctx, server.Tag, "example.test:80")
			require.NoError(t, err)
			conn.Close()
			require.Eventually(t, func() bool {
				outcome, told := instance.DetectOutcome(server.Fingerprint, server.ServerName, server.Destination)
				return told && !outcome.NoAnswer && !outcome.Failed && outcome.Fingerprint != ""
			}, 5*time.Second, 10*time.Millisecond, "no record under the key %q %q %q", server.Fingerprint, server.ServerName, server.Destination)
		})
	}
}

// With the fallback off, REALITY records under the same key: the only client that does.
func TestServersOfKeyWithoutTheFallback(t *testing.T) {
	address, _ := tlsListener(t, "tcp", "127.0.0.1:0")
	content := fmt.Sprintf(`{"type": "vless", "tag": "a", "server": "127.0.0.1", "server_port": %d, "uuid": %q,
		"tls": {"enabled": true, "server_name": "probe.test", "utls": {"enabled": true},
		"reality": {"enabled": true, "public_key": %q, "short_id": "00"}}}`, address.Port, probeUUID, probePublicKey)
	instance := probeInstance(t, false, content)
	servers := serversOfInstance(t, []string{content})
	require.Equal(t, "chrome", servers[0].Fingerprint)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := instance.Dial(ctx, "a", "example.test:80")
	require.Error(t, err)
	require.Eventually(t, func() bool {
		outcome, told := instance.DetectOutcome(servers[0].Fingerprint, servers[0].ServerName, servers[0].Destination)
		return told && outcome.Failed
	}, 5*time.Second, 10*time.Millisecond)
}

func serversOfInstance(t *testing.T, outbounds []string) []detect.Server {
	t.Helper()
	list := make([]json.RawMessage, len(outbounds))
	for index, outbound := range outbounds {
		list[index] = json.RawMessage(outbound)
	}
	content, err := json.Marshal(map[string]any{"outbounds": list})
	require.NoError(t, err)
	servers, _ := ServersOf(content)
	return servers
}
