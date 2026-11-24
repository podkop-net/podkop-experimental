package plan

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

const devicesSource = "\nconfig source 'own'\n\toption type 'links'\n\tlist link 'vless://u@own.example:443#Own'\n"

// limited is the rule of ruleText with more options (each a line "\tlist …" or "\toption …").
func limited(name string, rows string, more ...string) string {
	text := ruleText(name, rows)
	return strings.Replace(text, "list user_domains '"+name+".example'\n", "list user_domains '"+name+".example'\n"+strings.Join(more, ""), 1)
}

func devicesBuild(t *testing.T, settings string, facts Facts) *Result {
	t.Helper()
	parsed, err := uci.Parse([]byte(exitHead + settings))
	require.NoError(t, err)
	config, err := model.Load(parsed)
	require.NoError(t, err)
	result, err := Build(config, facts, Options{DecodeLink: decodeTestLink})
	require.NoError(t, err)
	return result
}

type devicesConfig struct {
	DNS struct {
		Rules []map[string]any `json:"rules"`
	} `json:"dns"`
	Route struct {
		Rules []map[string]any `json:"rules"`
	} `json:"route"`
}

func devicesOf(t *testing.T, result *Result) devicesConfig {
	t.Helper()
	var config devicesConfig
	require.NoError(t, json.Unmarshal(result.Config, &config))
	return config
}

// routeWith is the first route rule with every field of want; nil when none has them.
func routeWith(config devicesConfig, want map[string]any) map[string]any {
	for _, entry := range config.Route.Rules {
		matches := true
		for key, value := range want {
			if got, found := entry[key]; !found || !jsonEqual(got, value) {
				matches = false
			}
		}
		if matches {
			return entry
		}
	}
	return nil
}

func hasWarning(result *Result, part string) bool {
	for _, warning := range result.Warnings {
		if strings.Contains(warning, part) {
			return true
		}
	}
	return false
}

// withoutSources is the document of a configuration with the source_ip_cidr of its rules of lists
// (those with rule sets, the resolve rules too) taken out: what is left must be the configuration
// without the field.
func withoutSources(t *testing.T, result *Result) map[string]any {
	t.Helper()
	var document map[string]any
	require.NoError(t, json.Unmarshal(result.Config, &document))
	for _, entry := range document["route"].(map[string]any)["rules"].([]any) {
		if fields := entry.(map[string]any); fields["rule_set"] != nil {
			delete(fields, "source_ip_cidr")
		}
	}
	return document
}

// T1, T2, T8: the route rule of a rule only for some devices has their addresses beside its rule
// sets, as the settings write them; the rest of the configuration, the DNS, the files and what the
// firewall is told are those of the same rule without the field.
func TestOnlyDevicesRouteRule(t *testing.T) {
	t.Parallel()
	subnets := "\toption user_subnet_list_type 'dynamic'\n\tlist user_subnets '100.71.61.61/32'\n"
	only := "\tlist only_devices '192.168.78.10'\n\tlist only_devices '2001:2:0:78::10'\n\tlist only_devices '192.168.79.0/24'\n"
	with := devicesBuild(t, devicesSource+limited("tv", row("server", "own"), subnets, only), Facts{})
	without := devicesBuild(t, devicesSource+limited("tv", row("server", "own"), subnets), Facts{})

	config := devicesOf(t, with)
	rule := routeWith(config, map[string]any{"outbound": "tv-out"})
	require.NotNil(t, rule)
	require.Equal(t, tagTProxyInbound, rule["inbound"])
	require.Equal(t, []any{"192.168.78.10", "2001:2:0:78::10", "192.168.79.0/24"}, rule["source_ip_cidr"])
	require.Equal(t, []any{"tv-user-domains-ruleset", "tv-user-subnets-ruleset"}, rule["rule_set"])
	require.Nil(t, routeWith(devicesOf(t, without), map[string]any{"outbound": "tv-out"})["source_ip_cidr"])
	require.Equal(t, withoutSources(t, without), withoutSources(t, with))
	require.Equal(t, without.Warnings, with.Warnings)
	require.Empty(t, with.Warnings)

	// T2: the DNS is the same for every device, and so are the rule sets and their files
	require.Equal(t, devicesOf(t, without).DNS, config.DNS)
	dns, _ := json.Marshal(config.DNS)
	require.NotContains(t, string(dns), "source_ip_cidr")
	require.Equal(t, without.RuleSets, with.RuleSets)
	require.Equal(t, without.Files, with.Files)
	// T8: the firewall is made of the dataplane and the rule sets: the same
	require.Equal(t, without.Dataplane, with.Dataplane)
}

// T3: a device a rule does not take goes on to the rules below: the rule of block below a rule
// only for the TV has no source and takes everyone else. A rule of block only for some devices at
// the top is still before the devices left out.
func TestOnlyDevicesOrder(t *testing.T) {
	t.Parallel()
	only := "\tlist only_devices '192.168.78.10'\n"
	result := devicesBuild(t, devicesSource+limited("tv", row("server", "own"), only)+
		strings.ReplaceAll(ruleText("others", row("server", "block")), "others.example", "tv.example"), Facts{})
	config := devicesOf(t, result)
	var routes []string
	for _, rule := range config.Route.Rules {
		if rule["inbound"] != tagTProxyInbound {
			continue
		}
		if outbound, found := rule["outbound"]; found {
			routes = append(routes, outbound.(string))
		} else {
			routes = append(routes, rule["action"].(string))
		}
	}
	require.Equal(t, []string{"tv-out", "reject"}, routes)
	require.Nil(t, routeWith(config, map[string]any{"action": "reject", "inbound": tagTProxyInbound})["source_ip_cidr"])
	require.Equal(t, []any{"192.168.78.10"}, routeWith(config, map[string]any{"outbound": "tv-out"})["source_ip_cidr"])

	// a block only for the child's tablet at the top, the devices left out after it
	config = devicesOf(t, devicesBuild(t, "\tlist routing_excluded_ips '192.168.78.30'\n"+devicesSource+
		limited("kids", row("server", "block"), "\tlist only_devices '192.168.78.40'\n")+ruleText("tv", row("server", "own")), Facts{}))
	block := -1
	excluded := -1
	for index, rule := range config.Route.Rules {
		if rule["action"] == "reject" && jsonEqual(rule["source_ip_cidr"], []any{"192.168.78.40"}) {
			block = index
		}
		if rule["outbound"] == tagDirectOutbound && rule["source_ip_cidr"] == "192.168.78.30" {
			excluded = index
		}
	}
	require.GreaterOrEqual(t, block, 0)
	require.Greater(t, excluded, block)
}

// T4: the resolve rule of a rule only for some devices has their addresses as well: the names the
// other devices ask for are not resolved for a rule that does not take them.
func TestOnlyDevicesResolve(t *testing.T) {
	t.Parallel()
	result := devicesBuild(t, devicesSource+limited("tv", row("server", "own"), "\toption resolve_real_ip_for_routing '1'\n\tlist only_devices '192.168.78.10'\n"), Facts{})
	config := devicesOf(t, result)
	resolve := routeWith(config, map[string]any{"action": "resolve"})
	require.NotNil(t, resolve)
	require.Equal(t, []any{"192.168.78.10"}, resolve["source_ip_cidr"])
	require.Equal(t, "tv-user-domains-ruleset", resolve["rule_set"])
	require.Equal(t, []any{"192.168.78.10"}, routeWith(config, map[string]any{"outbound": "tv-out"})["source_ip_cidr"])
}

// T5, T9: the devices routed whole of a rule only for some devices are those within its devices
// (strict AND), in sing-box and in the firewall; one outside is left out with a warning. A word
// never reaches sing-box, which refused the whole configuration for it. Without the field all are
// kept, as in 0.8.20; a rule that does not route keeps the firewall of 0.8.20.
func TestOnlyDevicesFullyRouted(t *testing.T) {
	t.Parallel()
	only := "\tlist only_devices '192.168.78.0/24'\n"
	fully := func(items ...string) string {
		text := ""
		for _, item := range items {
			text += "\tlist fully_routed_ips '" + item + "'\n"
		}
		return text
	}
	whole := func(config devicesConfig) map[string]any {
		for _, rule := range config.Route.Rules {
			if rule["outbound"] == "tv-out" && rule["rule_set"] == nil {
				return rule
			}
		}
		return nil
	}

	result := devicesBuild(t, devicesSource+limited("tv", row("server", "own"), only, fully("192.168.78.10")), Facts{})
	require.Equal(t, "192.168.78.10", whole(devicesOf(t, result))["source_ip_cidr"])
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.168.78.10/32")}, result.Dataplane.Sources)
	require.Empty(t, result.Warnings)

	result = devicesBuild(t, devicesSource+limited("tv", row("server", "own"), only, fully("192.168.80.7")), Facts{})
	require.Nil(t, whole(devicesOf(t, result)))
	require.Empty(t, result.Dataplane.Sources)
	require.Equal(t, []string{"rule tv: the fully routed IP 192.168.80.7 is not among its devices (only for devices): left out"}, result.Warnings)

	// both kept within, the one outside left out
	result = devicesBuild(t, devicesSource+limited("tv", row("server", "own"), only, fully("192.168.78.10", "192.168.80.7", "192.168.78.64/26")), Facts{})
	require.Equal(t, []any{"192.168.78.10", "192.168.78.64/26"}, whole(devicesOf(t, result))["source_ip_cidr"])
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.168.78.10/32"), netip.MustParsePrefix("192.168.78.64/26")}, result.Dataplane.Sources)

	// the control: without the field, both, as in 0.8.20
	result = devicesBuild(t, devicesSource+limited("tv", row("server", "own"), fully("192.168.78.10", "192.168.80.7")), Facts{})
	require.Equal(t, []any{"192.168.78.10", "192.168.80.7"}, whole(devicesOf(t, result))["source_ip_cidr"])
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.168.78.10/32"), netip.MustParsePrefix("192.168.80.7/32")}, result.Dataplane.Sources)

	// T9: a word is left out with a warning, the valid items keep their text
	result = devicesBuild(t, devicesSource+limited("tv", row("server", "own"), fully("word", "192.168.78.0/24")), Facts{})
	require.Equal(t, "192.168.78.0/24", whole(devicesOf(t, result))["source_ip_cidr"])
	require.Equal(t, []string{`rule tv, fully routed IPs: 1 item(s) are no address or subnet and are left out, the first: "word"`}, result.Warnings)
	result = devicesBuild(t, devicesSource+limited("tv", row("server", "own"), fully("word")), Facts{})
	require.Nil(t, whole(devicesOf(t, result)))

	// a rule that is off: no route rule, no warning, and the firewall marks its devices routed
	// whole as 0.8.20 did, whatever its devices
	off := strings.Replace(limited("tv", row("server", "own"), only, fully("192.168.80.7", "word")), "config section 'tv'\n", "config section 'tv'\n\toption enabled '0'\n", 1)
	result = devicesBuild(t, devicesSource+off, Facts{})
	require.Nil(t, whole(devicesOf(t, result)))
	require.Empty(t, result.Warnings)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.168.80.7/32")}, result.Dataplane.Sources)
	// one without servers filled likewise
	result = devicesBuild(t, limited("tv", "", only, fully("192.168.80.7")), Facts{})
	require.False(t, hasWarning(result, "devices"))
	require.False(t, hasWarning(result, "fully routed"))
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.168.80.7/32")}, result.Dataplane.Sources)
}

// T6: what is no device is left out with a warning; a rule of which no item is a device takes
// nothing, for anyone, its names are not answered from FakeIP, and the log says what that means
// for its exit, with no warning about its devices routed whole.
func TestOnlyDevicesLeftOut(t *testing.T) {
	t.Parallel()
	bad := []string{"word", "192.168.1.050", "10.0.0.0/0", "::/0", "fe80::1%eth0", "0.0.0.0", "::ffff:192.168.1.50", "192.168.1.0/08", "fe80::1"}
	items := ""
	for _, item := range bad {
		items += "\tlist only_devices '" + item + "'\n"
	}
	result := devicesBuild(t, devicesSource+limited("tv", row("server", "own"), items, "\tlist only_devices '192.168.78.10'\n"), Facts{})
	require.Equal(t, []any{"192.168.78.10"}, routeWith(devicesOf(t, result), map[string]any{"outbound": "tv-out"})["source_ip_cidr"])
	require.Equal(t, []string{`rule tv, only for devices: 9 item(s) are no address or subnet of a device and are left out, the first: "word"`}, result.Warnings)

	for exit, told := range map[string]string{
		"own":    "the rule takes no traffic: its devices go past its servers, by the rules below or directly",
		"block":  "the rule blocks nobody",
		"direct": "the rule takes no traffic",
	} {
		result = devicesBuild(t, devicesSource+limited("tv", row("server", exit), items, "\tlist fully_routed_ips '192.168.78.10'\n"), Facts{})
		config := devicesOf(t, result)
		for _, rule := range append(config.Route.Rules, config.DNS.Rules...) {
			sets, _ := json.Marshal(rule["rule_set"])
			require.NotContains(t, string(sets), "tv-", exit)
			require.NotContains(t, rule, "source_ip_cidr", exit)
		}
		require.Empty(t, result.Dataplane.Sources, exit)
		require.Equal(t, []string{
			`rule tv, only for devices: 9 item(s) are no address or subnet of a device and are left out, the first: "word"`,
			`rule tv: no item of "only for devices" is an address or a subnet: ` + told,
		}, result.Warnings, exit)
	}
}

// T7: the field limits neither the mixed proxy of the rule nor the BitTorrent mode through its
// servers. A rule with neither lists nor devices routed whole is told the field does nothing.
func TestOnlyDevicesNotLimited(t *testing.T) {
	t.Parallel()
	only := "\tlist only_devices '192.168.78.10'\n"
	result := devicesBuild(t, devicesSource+limited("tv", row("server", "own"), only, "\toption mixed_proxy_enabled '1'\n\toption mixed_proxy_port '2080'\n"), Facts{LANAddress: "192.168.78.1"})
	config := devicesOf(t, result)
	mixed := routeWith(config, map[string]any{"inbound": "tv-mixed-in"})
	require.NotNil(t, mixed)
	require.NotContains(t, mixed, "source_ip_cidr")

	result = devicesBuild(t, "\toption bittorrent 'section'\n\toption bittorrent_section 'tv'\n"+devicesSource+limited("tv", row("server", "own"), only), Facts{})
	config = devicesOf(t, result)
	routed := routeWith(config, map[string]any{"inbound": tagBitTorrentInbound, "outbound": "tv-out"})
	require.NotNil(t, routed)
	require.NotContains(t, routed, "source_ip_cidr")
	sniffed := routeWith(config, map[string]any{"protocol": "bittorrent", "outbound": "tv-out"})
	require.NotNil(t, sniffed)
	require.NotContains(t, sniffed, "source_ip_cidr")
	// the list rule takes the inspected connections too, of the TV alone
	require.Equal(t, []any{"192.168.78.10"}, routeWith(config, map[string]any{"outbound": "tv-out", "rule_set": "tv-user-domains-ruleset"})["source_ip_cidr"])

	// no list, a mixed proxy: the field does nothing
	text := strings.Replace(limited("tv", row("server", "own"), only, "\toption mixed_proxy_enabled '1'\n\toption mixed_proxy_port '2080'\n"), "\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'tv.example'\n", "", 1)
	result = devicesBuild(t, devicesSource+text, Facts{LANAddress: "192.168.78.1"})
	require.Equal(t, []string{`rule tv: "only for devices" limits the lists and the fully routed IPs of the rule, and it has neither: the field does nothing`}, result.Warnings)
}

// The lists whose rule sets have several rules (a local list of two rules, a list written as
// text, which sing-box makes a rule of names and one of addresses of) are named in the same rule as
// the devices: sing-box matches such a set once the source matched (the engine's test of the
// matching is engine/devices_test.go).
func TestOnlyDevicesListsOfSeveralRules(t *testing.T) {
	t.Parallel()
	more := "\tlist only_devices '192.168.78.10'\n\tlist local_domain_lists '/etc/podkop-test/two.json'\n\tlist remote_domain_lists 'https://lists.example/text.lst'\n"
	parsed, err := uci.Parse([]byte(exitHead + devicesSource + limited("tv", row("server", "own"), more)))
	require.NoError(t, err)
	config, err := model.Load(parsed)
	require.NoError(t, err)
	result, err := Build(config, Facts{}, Options{DecodeLink: decodeTestLink, ReadFile: func(string) ([]byte, error) {
		return []byte(`{"version": 3, "rules": [{"domain_suffix": ["two.example"]}, {"ip_cidr": ["100.71.62.0/24"]}]}`), nil
	}})
	require.NoError(t, err)
	rule := routeWith(devicesOf(t, result), map[string]any{"outbound": "tv-out"})
	require.Equal(t, []any{"192.168.78.10"}, rule["source_ip_cidr"])
	require.Equal(t, []any{"tv-user-domains-ruleset", "tv-two-local-domains-ruleset", "tv-text-text-domains-ruleset"}, rule["rule_set"])
}

// An enabled list with no item adds no rule to its file, which then matches nothing: a rule of an
// empty list is a rule without items, which would match every connection and every name (sing-box
// drops it as it reads the file: engine/devices_test.go). A list whose items are all left out
// likewise.
func TestEmptyListMatchesNothing(t *testing.T) {
	t.Parallel()
	text := "\nconfig section 'tv'\n\toption user_domain_list_type 'dynamic'\n\toption user_subnet_list_type 'text'\n\toption user_subnets_text '// nothing yet\nword'\n" +
		"\nconfig member\n\toption section 'tv'\n" + row("server", "own")
	result := devicesBuild(t, devicesSource+text, Facts{})
	for _, path := range result.FileOrder {
		require.JSONEq(t, `{"version": 3, "rules": []}`, string(result.Files[path]), path)
	}
	require.Len(t, result.FileOrder, 2)
	// a list with items is as before
	result = devicesBuild(t, devicesSource+ruleText("tv", row("server", "own")), Facts{})
	require.JSONEq(t, `{"version": 3, "rules": [{"domain_suffix": ["tv.example"]}]}`, string(result.Files[result.FileOrder[0]]))
}

// DeviceRoutes are the route rules of the configuration Build makes, in its order: the leading rule
// of direct, the devices left out, the devices routed whole, the rules of lists (one only for a word,
// which has no route rule, in its place); each that is written is the next route rule of the
// configuration with its devices as source_ip_cidr. IPv6 needs the settings and the facts both.
func TestDeviceRoutes(t *testing.T) {
	t.Parallel()
	settings := exitHead + "\toption ipv6_routing 'podkop'\n\tlist routing_excluded_ips '192.168.78.70'\n\tlist routing_excluded_ips '2001:2:0:78::70'\n" +
		devicesSource +
		limited("bank", row("server", "direct"), "\tlist only_devices '192.168.78.30'\n") +
		limited("tv", row("server", "own"), "\tlist only_devices '192.168.78.10'\n\tlist only_devices '2001:2:0:78::/64'\n") +
		limited("bad", row("server", "block"), "\tlist only_devices 'word'\n") +
		limited("pc", row("server", "own"), "\tlist fully_routed_ips '192.168.78.60'\n\tlist fully_routed_ips '2001:2:0:78::60'\n") +
		ruleText("all", row("server", "own")) +
		limited("off", row("server", "own"), "\toption enabled '0'\n\tlist only_devices '192.168.78.10'\n")
	parsed, err := uci.Parse([]byte(settings))
	require.NoError(t, err)
	config, err := model.Load(parsed)
	require.NoError(t, err)
	options := Options{DecodeLink: decodeTestLink}
	routes, err := BuildDeviceRoutes(config, Facts{IPv6: true}, options)
	require.NoError(t, err)
	require.True(t, routes.IPv6)
	var told []string
	var written [][]string
	for _, route := range routes.Routes {
		limit := "every"
		if route.Limited {
			limit = "only " + strings.Join(model.Texts(route.Devices), " ")
		}
		told = append(told, route.Kind+" "+route.Section+" "+route.Exit+" "+limit)
		if !route.Limited || len(route.Devices) > 0 {
			written = append(written, model.Texts(route.Devices))
		}
	}
	require.Equal(t, []string{
		"lists bank direct only 192.168.78.30",
		"excluded  direct only 192.168.78.70 2001:2:0:78::70",
		"fully_routed pc servers only 192.168.78.60 2001:2:0:78::60",
		"lists tv servers only 192.168.78.10 2001:2:0:78::/64",
		"lists bad block only ",
		"lists pc servers every",
		"lists all servers every",
	}, told)

	result, err := Build(config, Facts{IPv6: true}, options)
	require.NoError(t, err)
	var routed [][]string
	for _, rule := range devicesOf(t, result).Route.Rules {
		if (rule["action"] != "route" && rule["action"] != "reject") || rule["protocol"] != nil || (rule["rule_set"] == nil && rule["source_ip_cidr"] == nil) {
			continue
		}
		require.True(t, jsonEqual(rule["inbound"], []any{tagTProxyInbound, tagTProxyInbound6}), rule)
		sources := []string{}
		switch value := rule["source_ip_cidr"].(type) {
		case string:
			sources = []string{value}
		case []any:
			for _, item := range value {
				sources = append(sources, item.(string))
			}
		}
		routed = append(routed, sources)
	}
	require.Equal(t, written, routed)

	// a router without ::1: IPv6 goes past podkop
	routes, err = BuildDeviceRoutes(config, Facts{}, options)
	require.NoError(t, err)
	require.False(t, routes.IPv6)
	require.Len(t, routes.Routes, len(told))
}
