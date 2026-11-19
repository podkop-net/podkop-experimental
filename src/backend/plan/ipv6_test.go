package plan

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// DNS answers IPv4 only, and the IPv6 addresses of a name that has no IPv4 address
// (ledger item 15).
func TestIPv6IfNoIPv4(t *testing.T) {
	const settings = "config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '8.8.8.8'\n" +
		"\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n"
	result := buildText(t, settings, Facts{})
	var document struct {
		DNS map[string]any `json:"dns"`
	}
	require.NoError(t, json.Unmarshal(result.Config, &document))
	require.Equal(t, "ipv4_only", document.DNS["strategy"])
	require.Equal(t, true, document.DNS["ipv6_if_no_ipv4"])
}

const ipv6Head = "config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '8.8.8.8'\n"
const ipv6Section = "\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n" +
	"\toption user_subnet_list_type 'dynamic'\n\tlist user_subnets '149.154.160.0/20'\n\tlist user_subnets '2001:67c:4e8::/48'\n\tlist user_subnets '2001:b28:f23d::1'\n"

type ipv6Document struct {
	DNS struct {
		Strategy     string `json:"strategy"`
		IPv6IfNoIPv4 *bool  `json:"ipv6_if_no_ipv4"`
		Servers      []map[string]any
	} `json:"dns"`
	Inbounds []map[string]any `json:"inbounds"`
	Route    struct {
		Rules []map[string]any `json:"rules"`
	} `json:"route"`
}

func ipv6Build(t *testing.T, settings string, facts Facts) (*Result, ipv6Document) {
	result := buildText(t, settings, facts)
	var document ipv6Document
	require.NoError(t, json.Unmarshal(result.Config, &document))
	return result, document
}

// The modes of the DNS addresses: the default is that of 0.8.4 on; ipv4_only is the shell
// backend's; both gives both kinds, sing-box's own lookups IPv4 first. An unknown mode is the
// default, with a warning.
func TestDNSAddresses(t *testing.T) {
	yes := true
	for mode, want := range map[string]struct {
		strategy string
		ifNo     *bool
		warned   bool
	}{
		"":            {"ipv4_only", &yes, false},
		"prefer_ipv4": {"ipv4_only", &yes, false},
		"ipv4_only":   {"ipv4_only", nil, false},
		"both":        {"prefer_ipv4", nil, false},
		"ipv6_only":   {"ipv4_only", &yes, true},
	} {
		settings := ipv6Head
		if mode != "" {
			settings += "\toption dns_addresses '" + mode + "'\n"
		}
		result, document := ipv6Build(t, settings+ipv6Section, Facts{})
		require.Equal(t, want.strategy, document.DNS.Strategy, mode)
		require.Equal(t, want.ifNo, document.DNS.IPv6IfNoIPv4, mode)
		warned := false
		for _, warning := range result.Warnings {
			warned = warned || strings.Contains(warning, "DNS addresses")
		}
		require.Equal(t, want.warned, warned, "%s: %v", mode, result.Warnings)
	}
}

// IPv6 through podkop: an inbound of IPv6 on ::1, named wherever the inbound of IPv4 is (the
// sniffer, the rules of the lists, QUIC refused); only when the router has IPv6, and the
// dataplane says so. Bypass, the default, and a router without IPv6 have none of it.
func TestIPv6Routing(t *testing.T) {
	inbound6 := func(document ipv6Document) bool {
		for _, inbound := range document.Inbounds {
			if inbound["tag"] == "tproxy-in6" {
				require.Equal(t, "::1", inbound["listen"])
				require.Equal(t, float64(1602), inbound["listen_port"])
				return true
			}
		}
		return false
	}
	names := func(value any) []any {
		if list, ok := value.([]any); ok {
			return list
		}
		return []any{value}
	}
	for _, test := range []struct {
		option string
		facts  Facts
		want   bool
		warned bool
	}{
		{"", Facts{IPv6: true}, false, false},
		{"bypass", Facts{IPv6: true}, false, false},
		{"podkop", Facts{IPv6: true}, true, false},
		{"podkop", Facts{}, false, true},
		{"sideways", Facts{IPv6: true}, false, true},
	} {
		settings := ipv6Head + "\toption disable_quic '1'\n"
		if test.option != "" {
			settings += "\toption ipv6_routing '" + test.option + "'\n"
		}
		result, document := ipv6Build(t, settings+ipv6Section, test.facts)
		label := test.option + " " + fmt.Sprint(test.facts.IPv6)
		require.Equal(t, test.want, inbound6(document), label)
		require.Equal(t, test.want, result.Dataplane.IPv6, label)
		warned := false
		for _, warning := range result.Warnings {
			warned = warned || strings.Contains(warning, "IPv6")
		}
		require.Equal(t, test.warned, warned, "%s: %v", label, result.Warnings)
		sniffed, quic, rule := false, false, false
		for _, entry := range document.Route.Rules {
			inbound, has := entry["inbound"]
			if !has {
				continue
			}
			has6 := slices.Contains(names(inbound), any("tproxy-in6"))
			require.True(t, slices.Contains(names(inbound), any("tproxy-in")), "%s: %v", label, entry)
			switch {
			case entry["action"] == "sniff":
				sniffed = has6
			case entry["protocol"] == "quic":
				quic = has6
			case entry["outbound"] == "main-out":
				rule = has6
			}
		}
		require.Equal(t, test.want, sniffed, label)
		require.Equal(t, test.want, quic, label)
		require.Equal(t, test.want, rule, label)
		if !test.want {
			// as before 0.8.20: the inbound a tag alone
			for _, entry := range document.Route.Rules {
				if entry["outbound"] == "main-out" {
					require.Equal(t, "tproxy-in", entry["inbound"], label)
				}
			}
		}
	}
}

// The IPv6 items of a user subnet list stay in the list (sing-box matches them; the firewall
// sends them to it while IPv6 goes through podkop).
func TestUserSubnetsKeepIPv6(t *testing.T) {
	result, _ := ipv6Build(t, ipv6Head+ipv6Section, Facts{})
	var found []string
	for _, file := range result.Files {
		text := string(file)
		for _, item := range []string{"149.154.160.0/20", "2001:67c:4e8::/48", "2001:b28:f23d::1"} {
			if strings.Contains(text, item) {
				found = append(found, item)
			}
		}
	}
	require.ElementsMatch(t, []string{"149.154.160.0/20", "2001:67c:4e8::/48", "2001:b28:f23d::1"}, found)
	for _, warning := range result.Warnings {
		require.NotContains(t, warning, "no subnet")
	}
}

// DNS servers of IPv6: in brackets with a port, or bare; no bootstrap for an address.
func TestDNSServersOfIPv6(t *testing.T) {
	for server, want := range map[string][3]string{
		"[2001:4860:4860::8888]:853":            {"2001:4860:4860::8888", "853", ""},
		"[2001:4860:4860::8888]":                {"2001:4860:4860::8888", "", ""},
		"2001:4860:4860::8888":                  {"2001:4860:4860::8888", "", ""},
		"[2a10:50c0::ad1:ff]:443/dns-query":     {"2a10:50c0::ad1:ff", "443", "/dns-query"},
		"https://[2a10:50c0::ad1:ff]/dns-query": {"2a10:50c0::ad1:ff", "", "/dns-query"},
		"8.8.8.8:5353":                          {"8.8.8.8", "5353", ""},
		"dns.example.com/q":                     {"dns.example.com", "", "/q"},
	} {
		host, port, path := splitServer(server)
		require.Equal(t, want, [3]string{host, port, path}, server)
	}
	settings := "config settings 'settings'\n\toption bootstrap_dns_server '[2a02:6b8::feed:0ff]'\n" +
		"\nconfig dns_server\n\toption type 'dot'\n\toption server '[2001:4860:4860::8888]:853'\n" +
		"\nconfig dns_server\n\toption type 'doh'\n\toption server 'dns.example.com/q'\n" + ipv6Section
	_, document := ipv6Build(t, settings, Facts{})
	byTag := map[string]map[string]any{}
	for _, server := range document.DNS.Servers {
		byTag[server["tag"].(string)] = server
	}
	require.Equal(t, "2a02:6b8::feed:ff", normalized(byTag["bootstrap-dns-server"]["server"]))
	require.Equal(t, "2001:4860:4860::8888", byTag["dns-server-1"]["server"])
	require.Equal(t, float64(853), byTag["dns-server-1"]["server_port"])
	require.Nil(t, byTag["dns-server-1"]["domain_resolver"])
	require.Equal(t, "bootstrap-dns-server", byTag["dns-server-2"]["domain_resolver"])
}

func normalized(value any) string {
	text, _ := value.(string)
	if address, err := netip.ParseAddr(text); err == nil {
		return address.String()
	}
	return text
}
