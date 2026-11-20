package diag

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaskSettings(t *testing.T) {
	t.Parallel()
	settings := `config settings 'settings'
	option dns_type 'doh'
	option dns_server 'dns.nextdns.io/abc123'
	option yacd_secret_key 's3cret'
	option log_level 'warn'

config section 'main'
	option proxy_string 'vless://uuid@host:443?x=1#name'
	option user_domains_text 'a.example
b.example'
	list selector_proxy_links 'trojan://p@h:1'
	list selector_proxy_links 'ss://x@h:2'
	list urltest_proxy_links 'vless://u@h:3'
	list urltest_fallback_links 'socks5://u:p@h:4'
	option outbound_json '{
  "type": "socks",
  "password": "it'\''s"
}'
	option interface 'wg0'
	option urltest_testing_url 'https://kept.example/generate_204'
	option mixed_proxy_enabled '1'
	option mixed_proxy_port '2080'
	option mixed_proxy_username 'pdk-user'
	option mixed_proxy_password 'Zx9-mixed'

config subscription 'prov1'
	option url 'https://sub.example/api/sub/TOK3N'
	option update_interval '12h'

config section 'vpn'
	option domain_resolver_dns_server 'dns.example.org/secret-path?x'
	option outbound_json '{"type":"direct"}'
	option proxy_string 'trojan://first
vless://second'
	option after 'kept'
`
	masked := MaskSettings([]byte(settings))
	require.Contains(t, masked, "kept.example/generate_204")
	require.Contains(t, masked, "option update_interval '12h'")
	for _, secret := range []string{"abc123", "s3cret", "uuid@host", "trojan://", "ss://", "socks5://", "vless://", `"password"`, "secret-path", `"type"`, "TOK3N", "pdk-user", "Zx9-mixed"} {
		require.NotContains(t, masked, secret)
	}
	require.Equal(t, `config settings 'settings'
	option dns_type 'doh'
	option dns_server 'dns.nextdns.io/MASKED'
	option yacd_secret_key 'MASKED'
	option log_level 'warn'

config section 'main'
	option proxy_string 'MASKED'
	option user_domains_text 'a.example
b.example'
	list selector_proxy_links 'MASKED'
	list selector_proxy_links 'MASKED'
	list urltest_proxy_links 'MASKED'
	list urltest_fallback_links 'MASKED'
	option outbound_json 'MASKED'
	option interface 'wg0'
	option urltest_testing_url 'https://kept.example/generate_204'
	option mixed_proxy_enabled '1'
	option mixed_proxy_port '2080'
	option mixed_proxy_username 'MASKED'
	option mixed_proxy_password 'MASKED'

config subscription 'prov1'
	option url 'MASKED'
	option update_interval '12h'

config section 'vpn'
	option domain_resolver_dns_server 'dns.example.org/MASKED'
	option outbound_json 'MASKED'
	option proxy_string 'MASKED'
	option after 'kept'
`, masked)
}

func TestMaskConfig(t *testing.T) {
	t.Parallel()
	masked, err := MaskConfig([]byte(`{"outbounds":[{"type":"vless","tag":"main-out","server":"203.0.113.10","server_port":443,"uuid":"u","tls":{"enabled":true,"server_name":"x","utls":{"fingerprint":"chrome"},"reality":{"public_key":"k","short_id":"01"}}},{"type":"trojan","password":"p"}],"dns":{"servers":[{"type":"udp","server":"8.8.8.8","server_port":53}]}}`))
	require.NoError(t, err)
	text := string(masked)
	for _, secret := range []string{"203.0.113.10", "443", `"u"`, `"x"`, "chrome", `"k"`, `"01"`, `"p"`, "8.8.8.8"} {
		require.NotContains(t, text, secret)
	}
	require.Contains(t, text, `"tag": "main-out"`)
	require.Equal(t, 10, strings.Count(text, `"MASKED"`))

	// the credentials an outbound or an endpoint may carry besides, the path of a DoH
	// server and the secret of the Clash API; the same keys elsewhere are kept
	masked, err = MaskConfig([]byte(`{
		"dns": {"servers": [{"type": "https", "tag": "dns-server", "server": "dns.example.org", "path": "/abc123"}]},
		"outbounds": [
			{"type": "vless", "tag": "a", "encryption": "mlkem768x25519plus.native.0rtt.secret-e", "transport": {"type": "xhttp", "path": "/xh", "headers": {"X-Token": "secret-h"}, "extra": {"xPaddingBytes": "secret-x"}}},
			{"type": "socks", "tag": "b", "username": "secret-u"},
			{"type": "hysteria", "tag": "c", "auth_str": "secret-a", "obfs": "secret-o"},
			{"type": "shadowsocks", "tag": "d", "plugin": "obfs-local", "plugin_opts": "obfs=http;obfs-host=secret-p"},
			{"type": "ssh", "tag": "e", "user": "secret-s", "private_key": "secret-k", "private_key_passphrase": "secret-q"}
		],
		"endpoints": [{"type": "wireguard", "tag": "f", "private_key": "secret-w", "peers": [{"public_key": "pk", "pre_shared_key": "secret-r"}]}],
		"route": {"rule_set": [{"type": "local", "tag": "g", "format": "source", "path": "/var/run/podkop/rulesets/g.json"}]},
		"experimental": {"clash_api": {"external_controller": "192.168.1.1:9090", "secret": "secret-c"}}
	}`))
	require.NoError(t, err)
	text = string(masked)
	require.NotContains(t, text, "secret-")
	require.NotContains(t, text, "abc123")
	for _, kept := range []string{`"path": "/xh"`, `"path": "/var/run/podkop/rulesets/g.json"`, `"plugin": "obfs-local"`, `"external_controller": "192.168.1.1:9090"`, `"type": "xhttp"`} {
		require.Contains(t, text, kept)
	}

	// the login of a mixed proxy; where it listens is kept
	masked, err = MaskConfig([]byte(`{"inbounds": [{"type": "mixed", "tag": "main-mixed-in", "listen": "192.168.1.1", "listen_port": 2080, "users": [{"username": "pdk-user", "password": "Zx9-mixed"}]}]}`))
	require.NoError(t, err)
	text = string(masked)
	require.NotContains(t, text, "pdk-user")
	require.NotContains(t, text, "Zx9-mixed")
	require.Contains(t, text, `"username": "MASKED"`)
	require.Contains(t, text, `"password": "MASKED"`)
	require.Contains(t, text, `"listen": "192.168.1.1"`)
	require.Contains(t, text, `"listen_port": 2080`)
	require.Contains(t, text, `"tag": "main-mixed-in"`)
}

func TestListens(t *testing.T) {
	// the tables of this very host: a TCP listener and a UDP socket of the test
	if _, err := os.Stat("/proc/net/tcp"); err != nil {
		t.Skip("no /proc/net")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	require.True(t, listens("/proc/net/tcp", net.IPv4(127, 0, 0, 1), port, "0A"))
	require.False(t, listens("/proc/net/tcp", net.IPv4(127, 0, 0, 2), port, "0A"))
	packets, err := net.ListenPacket("udp", "127.0.0.42:0")
	require.NoError(t, err)
	defer packets.Close()
	udpPort := uint16(packets.LocalAddr().(*net.UDPAddr).Port)
	require.True(t, listens("/proc/net/udp", net.IPv4(127, 0, 0, 42), udpPort, ""))
	require.False(t, listens("/proc/net/udp", net.IPv4(127, 0, 0, 1), udpPort, ""))
	require.False(t, listens(filepath.Join(t.TempDir(), "none"), net.IPv4(127, 0, 0, 1), port, ""))
}

func TestSystemInfoAsksLatestOnlyWhenTold(t *testing.T) {
	var asked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		asked.Add(1)
		io.WriteString(writer, `{"tag_name": "v0.8.1"}`)
	}))
	defer server.Close()
	saved := latestReleaseURL
	latestReleaseURL = server.URL
	defer func() { latestReleaseURL = saved }()

	report := SystemInfo(context.Background(), "0.8.0", "1.14.3", false)
	require.Equal(t, "unknown", report.PodkopLatestVersion)
	require.Equal(t, "0.8.0", report.PodkopVersion)
	require.Zero(t, asked.Load())

	report = SystemInfo(context.Background(), "0.8.0", "1.14.3", true)
	require.Equal(t, "v0.8.1", report.PodkopLatestVersion)
	require.EqualValues(t, 1, asked.Load())
}
