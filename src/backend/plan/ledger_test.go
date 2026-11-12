package plan

import (
	"os"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/model"

	"github.com/stretchr/testify/require"
)

// The differences of ledger.go, one case each.
func TestFromShell(t *testing.T) {
	noFiles := Options{ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }}

	// the shell backend's download_detour goes: the HTTP client of the lists, named the
	// default, goes directly (no rule has servers here to fall back through, see
	// TestListsClients); independent_cache goes; the key of the settings goes
	// to the Clash API, which listens on this host (YACD is off); the uTLS fallback is
	// told as the settings have it
	settings := &model.Config{Settings: model.Settings{UpdateInterval: "1d", YACDSecretKey: "k3y", UTLSFallback: true}, Sections: []model.Section{{Name: "main",
		RemoteDomainLists: []string{"https://lists.example/a.srs"}}}}
	shell := []byte(`{"dns":{"final":"dns-server","independent_cache":true},"certificate":{},"endpoints":[],"route":{"rules":[{"action":"route","rule_set":"main-a-remote-domains-ruleset"}],"rule_set":[` +
		`{"type":"remote","tag":"main-a-remote-domains-ruleset","format":"binary","url":"https://lists.example/a.srs","download_detour":"main-out","update_interval":"1d"}],"final":"direct-out"},` +
		`"experimental":{"clash_api":{"external_controller":"192.168.1.1:9090"}}}`)
	converted, err := FromShell(shell, Shell{Settings: settings, Options: noFiles})
	require.NoError(t, err)
	require.Empty(t, converted.Dropped)
	require.Equal(t, `{
  "dns": {
    "final": "dns-server"
  },
  "certificate": {},
  "http_clients": [
    {
      "tag": "lists"
    }
  ],
  "endpoints": [],
  "route": {
    "rules": [
      {
        "action": "route",
        "rule_set": "main-a-remote-domains-ruleset"
      }
    ],
    "rule_set": [
      {
        "type": "remote",
        "tag": "main-a-remote-domains-ruleset",
        "format": "binary",
        "url": "https://lists.example/a.srs",
        "update_interval": "1d"
      }
    ],
    "final": "direct-out",
    "default_http_client": "lists"
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "k3y"
    },
    "utls_fallback": {
      "enabled": true
    }
  }
}
`, string(converted.Config))

	// the one file of the plain lists of a section becomes a rule set a URL: those written
	// as text together, a rule set file of a query or an upper-case extension where it
	// is; the service proxy inbound and its rule go, a mixed inbound of a section of that
	// name stays
	settings = &model.Config{Settings: model.Settings{UpdateInterval: "1d"}, Sections: []model.Section{{Name: "main",
		RemoteDomainLists: []string{"https://a.example/x.srs", "https://a.example/one.lst", "https://b.example/q.json?raw=1", "https://b.example/dir/one.lst", "https://c.example/"}}}}
	shell = []byte(`{"certificate":{},"inbounds":[{"type":"mixed","tag":"service-mixed-in","listen":"127.0.0.1","listen_port":4534},{"type":"direct","tag":"dns-in"}],` +
		`"route":{"rules":[{"action":"route","inbound":"service-mixed-in","outbound":"main-out"},{"action":"route","rule_set":["main-x-remote-domains-ruleset","main-remote-domains-ruleset"]}],"rule_set":[` +
		`{"type":"remote","tag":"main-x-remote-domains-ruleset","format":"binary","url":"https://a.example/x.srs","update_interval":"1d"},` +
		`{"type":"local","tag":"main-remote-domains-ruleset","format":"source","path":"/tmp/sing-box/rulesets/main-remote-domains-ruleset.json"}]},` +
		`"dns":{"rules":[{"action":"route","server":"fakeip-server","rule_set":["main-x-remote-domains-ruleset","main-remote-domains-ruleset"]}]}}`)
	converted, err = FromShell(shell, Shell{Settings: settings, Options: noFiles})
	require.NoError(t, err)
	require.Equal(t, []string{"main-remote-domains-ruleset.json"}, converted.Dropped)
	text := string(converted.Config)
	require.NotContains(t, text, "service-mixed-in")
	require.NotContains(t, text, `"main-remote-domains-ruleset"`)
	want := []string{"main-x-remote-domains-ruleset", "main-one-text-domains-ruleset", "main-one-2-text-domains-ruleset", "main-list-text-domains-ruleset", "main-q-remote-domains-ruleset"}
	var tags []string
	for _, entry := range remoteOrder(listEntries("main", "domains", settings.Sections[0].RemoteDomainLists, false)) {
		tags = append(tags, entry.tag)
	}
	require.Equal(t, want, tags)
	require.Contains(t, text, `"url": "https://b.example/q.json?raw=1"`)
	require.Contains(t, text, `"format": "source"`)

	// the files of the router: a file each, one that cannot be read an empty file of the
	// backend
	settings = &model.Config{Settings: model.Settings{UpdateInterval: "1d"}, Sections: []model.Section{{Name: "main",
		LocalDomainLists: []string{"/etc/lists/good.lst", "/etc/lists/gone.lst"}}}}
	files := Options{ReadFile: func(path string) ([]byte, error) {
		if path == "/etc/lists/good.lst" {
			return []byte("good.example\n"), nil
		}
		return nil, os.ErrNotExist
	}}
	shell = []byte(`{"certificate":{},"route":{"rules":[{"action":"route","rule_set":"main-local-domains-ruleset"}],"rule_set":[` +
		`{"type":"local","tag":"main-local-domains-ruleset","format":"source","path":"/tmp/sing-box/rulesets/main-local-domains-ruleset.json"}]}}`)
	converted, err = FromShell(shell, Shell{Settings: settings, Options: files})
	require.NoError(t, err)
	require.Equal(t, []string{"main-local-domains-ruleset.json"}, converted.Dropped)
	require.Contains(t, converted.Added, "main-gone-local-domains-ruleset.json")
	text = string(converted.Config)
	require.Contains(t, text, `"path": "/etc/lists/good.lst"`)
	require.Contains(t, text, `"format": "text"`)
	require.Contains(t, text, `"path": "/var/run/podkop/rulesets/main-gone-local-domains-ruleset.json"`)
	require.Contains(t, text, `"main-good-local-domains-ruleset",`)

	// the files of the shell backend in the directories of the sing-box package are the
	// backend's in its own (item 8)
	shell = []byte(`{"route":{"rule_set":[{"type":"local","tag":"main-user-domains-ruleset","format":"source","path":"/tmp/sing-box/rulesets/main-user-domains-ruleset.json"}]},` +
		`"experimental":{"cache_file":{"enabled":true,"path":"/usr/share/sing-box/cache.db","store_fakeip":true}}}`)
	converted, err = FromShell(shell, Shell{Settings: &model.Config{}, Options: noFiles})
	require.NoError(t, err)
	text = string(converted.Config)
	require.Contains(t, text, `"path": "/var/run/podkop/rulesets/main-user-domains-ruleset.json"`)
	require.Contains(t, text, `"path": "/usr/share/podkop/cache.db"`)
	require.NotContains(t, text, "sing-box")

	// the rules of the names of podkop 0.7's page checks go, and their DNS rule answers
	// the readiness name (item 9); a rule of a list stays
	shell = []byte(`{"dns":{"rules":[{"action":"route","server":"fakeip-server","rewrite_ttl":60,"domain":["fakeip.podkop.fyi","ip.podkop.fyi"]}]},` +
		`"route":{"rules":[{"action":"route","inbound":"tproxy-in","outbound":"main-out","domain":"ip.podkop.fyi"},` +
		`{"action":"route-options","domain":"fakeip.podkop.fyi","override_port":8443},` +
		`{"action":"route","inbound":"tproxy-in","outbound":"main-out","domain":["ip.podkop.fyi"]}]}}`)
	converted, err = FromShell(shell, Shell{Settings: &model.Config{}, Options: noFiles})
	require.NoError(t, err)
	require.Equal(t, `{
  "dns": {
    "rules": [
      {
        "action": "route",
        "server": "fakeip-server",
        "rewrite_ttl": 60,
        "domain": [
          "`+dataplane.ReadinessName+`"
        ]
      }
    ]
  },
  "route": {
    "rules": [
      {
        "action": "route",
        "inbound": "tproxy-in",
        "outbound": "main-out",
        "domain": [
          "ip.podkop.fyi"
        ]
      }
    ],
    "rule_set": []
  }
}
`, string(converted.Config))
}

// The lists go directly, and fall back through the first three rules that have servers now,
// in the order of the settings: a rule that is off, goes direct or blocks, has no servers or
// is refused (usable) is passed by.
func TestListsClients(t *testing.T) {
	servers := func(source string) []model.Member { return []model.Member{{Source: source}} }
	config := &model.Config{
		Sources: []model.Source{{Name: "nl", Type: "links", Links: []string{"vless://x@nl.example:443"}}, {Name: "empty", Type: "links"}},
		Sections: []model.Section{
			{Name: "off", Servers: servers("nl")},
			{Name: "direct", Enabled: true, Servers: servers(model.SourceDirect)},
			{Name: "none", Enabled: true, Servers: servers("empty")},
			{Name: "first", Enabled: true, Servers: servers("nl")},
			{Name: "refused", Enabled: true, Servers: servers("nl")},
			{Name: "second", Enabled: true, Servers: append(servers("nl"), model.Member{Source: model.SourceDirect})},
			{Name: "third", Enabled: true, Servers: servers("nl")},
			{Name: "fourth", Enabled: true, Servers: servers("nl")},
		},
	}
	usable := func(section *model.Section) bool { return config.HasOutbound(section) && section.Name != "refused" }
	clients := listsClients(config, usable)
	var want []any
	var fallback []any
	for _, name := range []string{"first", "second", "third"} {
		tag := "lists-" + RuleOutbound(config, name)
		fallback = append(fallback, tag)
		want = append(want, newObject("tag", tag, "detour", RuleOutbound(config, name)))
	}
	want = append([]any{newObject("tag", "lists", "fallback", fallback)}, want...)
	got, err := indented(clients)
	require.NoError(t, err)
	expected, err := indented(want)
	require.NoError(t, err)
	require.Equal(t, string(expected), string(got))

	// no rule has servers: the client of the lists alone, without fallbacks
	got, err = indented(listsClients(&model.Config{}, usable))
	require.NoError(t, err)
	require.Equal(t, "[\n  {\n    \"tag\": \"lists\"\n  }\n]\n", string(got))
}
