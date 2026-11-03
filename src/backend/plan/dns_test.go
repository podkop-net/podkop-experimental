package plan

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// dnsServersOf are the DNS servers of a built configuration by their tags.
func dnsServersOf(t *testing.T, settings string) (map[string]map[string]any, []string) {
	t.Helper()
	result, err := buildRules(t, settings, nil)
	require.NoError(t, err)
	config, _ := outboundsOf(t, result)
	byTag := make(map[string]map[string]any)
	var tags []string
	for _, server := range config.DNS.Servers {
		tag := server["tag"].(string)
		byTag[tag] = server
		tags = append(tags, tag)
	}
	return byTag, tags
}

func dnsRow(serverType string, server string) string {
	text := "\nconfig dns_server\n\toption type '" + serverType + "'\n"
	if server != "" {
		text += "\toption server '" + server + "'\n"
	}
	return text
}

func TestDNSOfOneServer(t *testing.T) {
	t.Parallel()
	// a file without the list: the server of the options before it
	servers, tags := dnsServersOf(t, "")
	require.Equal(t, []string{"bootstrap-dns-server", "dns-server", "fakeip-server"}, tags)
	require.Equal(t, "udp", servers["dns-server"]["type"])
	require.Equal(t, "8.8.8.8", servers["dns-server"]["server"])

	// one row is the server itself, its name resolved by the bootstrap server
	servers, _ = dnsServersOf(t, dnsRow("doh", "dns.example/q"))
	require.Equal(t, map[string]any{"type": "https", "tag": "dns-server", "server": "dns.example", "server_port": float64(443), "path": "/q", "domain_resolver": "bootstrap-dns-server"}, servers["dns-server"])

	// the provider alone
	servers, _ = dnsServersOf(t, dnsRow("provider", ""))
	require.Equal(t, map[string]any{"type": "provider", "tag": "dns-server"}, servers["dns-server"])
}

func TestDNSOfList(t *testing.T) {
	t.Parallel()
	rows := dnsRow("doh", "1.1.1.1") + dnsRow("provider", "") + dnsRow("dot", "dns.example:8853") + dnsRow("udp", "77.88.8.8")
	servers, tags := dnsServersOf(t, rows)
	require.Equal(t, []string{"bootstrap-dns-server", "dns-server-1", "dns-server-2", "dns-server-3", "dns-server-4", "dns-server", "fakeip-server"}, tags)
	require.Equal(t, map[string]any{"type": "group", "tag": "dns-server", "servers": []any{"dns-server-1", "dns-server-2", "dns-server-3", "dns-server-4"}, "strategy": "order"}, servers["dns-server"])
	require.Equal(t, "https", servers["dns-server-1"]["type"])
	require.Nil(t, servers["dns-server-1"]["domain_resolver"], "an address needs no resolver")
	require.Equal(t, map[string]any{"type": "provider", "tag": "dns-server-2"}, servers["dns-server-2"])
	require.Equal(t, float64(8853), servers["dns-server-3"]["server_port"])
	require.Equal(t, "bootstrap-dns-server", servers["dns-server-3"]["domain_resolver"])
	require.Equal(t, "udp", servers["dns-server-4"]["type"])

	servers, _ = dnsServersOf(t, "\toption dns_mode 'fastest'\n"+rows)
	require.Equal(t, "fastest", servers["dns-server"]["strategy"])
	// a mode the engine does not know is the strict order
	servers, _ = dnsServersOf(t, "\toption dns_mode 'random'\n"+rows)
	require.Equal(t, "order", servers["dns-server"]["strategy"])
}

func TestDNSOfListGivenTwice(t *testing.T) {
	t.Parallel()
	// a row given twice is asked once: one left is the server itself
	servers, tags := dnsServersOf(t, dnsRow("udp", "77.88.8.8")+dnsRow("udp", "77.88.8.8"))
	require.Equal(t, []string{"bootstrap-dns-server", "dns-server", "fakeip-server"}, tags)
	require.Equal(t, "udp", servers["dns-server"]["type"])
	servers, _ = dnsServersOf(t, dnsRow("provider", "")+dnsRow("udp", "77.88.8.8")+dnsRow("provider", ""))
	require.Equal(t, []any{"dns-server-1", "dns-server-2"}, servers["dns-server"]["servers"])
}

func TestDNSOfListRefused(t *testing.T) {
	t.Parallel()
	for _, rows := range []string{dnsRow("doh", ""), dnsRow("udp", "1.1.1.1") + dnsRow("quic", "1.1.1.1")} {
		_, err := buildRules(t, rows, nil)
		require.Error(t, err, rows)
	}
}
