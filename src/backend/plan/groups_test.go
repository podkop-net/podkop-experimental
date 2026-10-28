package plan

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

// decodeServer decodes a link of a test: the host is the server, "bad" hosts are refused.
func decodeServer(link string) ([]byte, []string, error) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.Hostname() == "bad.example" {
		return nil, nil, json.Unmarshal([]byte("x"), new(any))
	}
	content, _ := json.Marshal(map[string]any{"type": "vless", "server": parsed.Hostname(), "server_port": 443, "uuid": "u", "tag": parsed.Fragment})
	return content, nil, nil
}

func servers(names ...string) []SubscriptionServer {
	var result []SubscriptionServer
	for index, name := range names {
		result = append(result, SubscriptionServer{Name: name, Link: "vless://u@s" + string(rune('a'+index)) + ".example:443#" + url.PathEscape(name)})
	}
	return result
}

func groupSection(name string, group string) string {
	return "\nconfig section '" + name + "'\n\toption connection_type 'group'\n\toption group '" + group + "'\n" +
		"\toption user_domain_list_type 'dynamic'\n\tlist user_domains '" + name + ".example'\n"
}

func buildGroups(t *testing.T, settings string, list map[string][]SubscriptionServer) (*Result, error) {
	t.Helper()
	parsed, err := uci.Parse([]byte(detourHead + settings))
	require.NoError(t, err)
	config, err := model.Load(parsed)
	require.NoError(t, err)
	return Build(config, Facts{}, Options{DecodeLink: decodeServer, Servers: list})
}

type outbound struct {
	Type      string   `json:"type"`
	Tag       string   `json:"tag"`
	Server    string   `json:"server"`
	Outbounds []string `json:"outbounds"`
	Default   string   `json:"default"`
}

type configuration struct {
	Outbounds []outbound `json:"outbounds"`
	Route     struct {
		Rules []map[string]any `json:"rules"`
	} `json:"route"`
}

func parsed(t *testing.T, result *Result) (configuration, map[string]outbound) {
	t.Helper()
	var config configuration
	require.NoError(t, json.Unmarshal(result.Config, &config))
	byTag := make(map[string]outbound)
	for _, entry := range config.Outbounds {
		_, twice := byTag[entry.Tag]
		require.False(t, twice, entry.Tag)
		byTag[entry.Tag] = entry
	}
	return config, byTag
}

// the route rule of a section by its user domain
func sectionRule(config configuration, section string) map[string]any {
	for _, rule := range config.Route.Rules {
		if sets, has := rule["rule_set"]; has && strings.Contains(strings.Join(anyStrings(sets), " "), section+"-user-domains") {
			return rule
		}
	}
	return nil
}

func anyStrings(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		var result []string
		for _, item := range typed {
			result = append(result, item.(string))
		}
		return result
	}
	return nil
}

const twoSubscriptions = "\nconfig subscription 'prov1'\n\toption url 'https://a.example/sub/1'\n" +
	"\nconfig subscription 'prov2'\n\toption url 'https://b.example/sub/2'\n"

// A section of the type group goes through a selector of its group and the servers of the
// group; a server two groups choose is one outbound, and its tag has the name of the
// subscription; a name the list has twice is numbered.
func TestGroupSections(t *testing.T) {
	settings := twoSubscriptions +
		"\nconfig group 'nl'\n\tlist subscription 'prov1'\n\tlist subscription 'prov2'\n\tlist include 'nl'\n\tlist exclude 'old'\n" +
		"\nconfig group 'all'\n\tlist subscription 'prov1'\n" +
		groupSection("youtube", "nl") + groupSection("other", "all")
	list := map[string][]SubscriptionServer{
		"prov1": servers("🇳🇱 NL 1", "🇩🇪 DE", "🇳🇱 NL 1", "NL old"),
		"prov2": servers("Amsterdam NL"),
	}
	result, err := buildGroups(t, settings, list)
	require.NoError(t, err)
	config, byTag := parsed(t, result)
	require.Equal(t, []string{"prov1: 🇳🇱 NL 1", "prov1: 🇳🇱 NL 1 #2", "prov2: Amsterdam NL"}, byTag["nl-group"].Outbounds)
	require.Equal(t, "urltest", byTag["nl-group"].Type)
	require.Equal(t, []string{"nl-group", "prov1: 🇳🇱 NL 1", "prov1: 🇳🇱 NL 1 #2", "prov2: Amsterdam NL"}, byTag["youtube-out"].Outbounds)
	require.Equal(t, "nl-group", byTag["youtube-out"].Default)
	require.Equal(t, "selector", byTag["youtube-out"].Type)
	require.Len(t, byTag["all-group"].Outbounds, 4)
	require.Equal(t, "sa.example", byTag["prov1: 🇳🇱 NL 1"].Server)
	require.Equal(t, "sc.example", byTag["prov1: 🇳🇱 NL 1 #2"].Server)
	require.Equal(t, "youtube-out", sectionRule(config, "youtube")["outbound"])
	// every server once, the shared ones included
	count := 0
	for _, entry := range config.Outbounds {
		if strings.HasPrefix(entry.Tag, "prov") {
			count++
		}
	}
	require.Equal(t, 5, count)
	// the links name a server sing-box refuses
	require.Len(t, result.Links, 5)
	require.Equal(t, "youtube", result.Links[0].Section)
}

// A group that chooses no server does what its option empty says.
func TestEmptyGroups(t *testing.T) {
	list := map[string][]SubscriptionServer{"prov1": servers("DE 1", "DE 2")}
	head := twoSubscriptions + proxySection("main", "")
	for empty, check := range map[string]func(configuration, map[string]outbound, *Result){
		"all": func(config configuration, byTag map[string]outbound, result *Result) {
			require.Equal(t, []string{"prov1: DE 1", "prov1: DE 2"}, byTag["nl-group"].Outbounds)
			require.Contains(t, strings.Join(result.Warnings, "\n"), "all 2 are used")
		},
		"section": func(config configuration, byTag map[string]outbound, result *Result) {
			require.Equal(t, []string{"main-out"}, byTag["youtube-out"].Outbounds)
			require.NotContains(t, byTag, "nl-group")
			require.NotContains(t, strings.Join(result.Warnings, "\n"), "main has no list")
		},
		"direct": func(config configuration, byTag map[string]outbound, result *Result) {
			require.Equal(t, []string{"direct-out"}, byTag["youtube-out"].Outbounds)
		},
		"block": func(config configuration, byTag map[string]outbound, result *Result) {
			// refused through a selector of the block outbound, which sing-box replaces while
			// it runs when the group has servers again
			require.Equal(t, []string{"block"}, byTag["youtube-out"].Outbounds)
			require.Equal(t, "block", byTag["block"].Type)
			require.Equal(t, "youtube-out", sectionRule(config, "youtube")["outbound"])
			require.True(t, result.Swappable["youtube-out"])
			require.False(t, result.Swappable["block"])
		},
	} {
		settings := head + "\nconfig group 'nl'\n\tlist subscription 'prov1'\n\tlist include 'NL'\n\toption empty '" + empty + "'\n\toption empty_section 'main'\n" +
			groupSection("youtube", "nl")
		result, err := buildGroups(t, settings, list)
		require.NoError(t, err, empty)
		config, byTag := parsed(t, result)
		check(config, byTag, result)
	}
	// the section for no server turned block or exclusion after the group was set: followed
	for kind, check := range map[string]func(configuration, map[string]outbound){
		"block": func(config configuration, byTag map[string]outbound) {
			require.Equal(t, []string{"block"}, byTag["youtube-out"].Outbounds)
		},
		"exclusion": func(config configuration, byTag map[string]outbound) {
			require.Equal(t, []string{"direct-out"}, byTag["youtube-out"].Outbounds)
		},
	} {
		settings := twoSubscriptions + "\nconfig section 'main'\n\toption connection_type '" + kind + "'\n\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'main.lab.example'\n" +
			"\nconfig group 'nl'\n\tlist subscription 'prov1'\n\tlist include 'NL'\n\toption empty 'section'\n\toption empty_section 'main'\n" +
			groupSection("youtube", "nl")
		result, err := buildGroups(t, settings, list)
		require.NoError(t, err, kind)
		config, byTag := parsed(t, result)
		check(config, byTag)
		require.Contains(t, strings.Join(result.Warnings, "\n"), "section main", kind)
	}
	// no list at all: refused, whatever the group says
	result, err := buildGroups(t, head+"\nconfig group 'nl'\n\tlist subscription 'prov1'\n"+groupSection("youtube", "nl")+
		"\toption mixed_proxy_enabled '1'\n\toption mixed_proxy_port '2080'\n", nil)
	require.NoError(t, err)
	config, byTag := parsed(t, result)
	require.Equal(t, []string{"block"}, byTag["youtube-out"].Outbounds)
	require.Equal(t, "youtube-out", sectionRule(config, "youtube")["outbound"])
	require.Contains(t, strings.Join(result.Warnings, "\n"), "prov1 has no servers yet")
}

func TestGroupMistakes(t *testing.T) {
	list := map[string][]SubscriptionServer{"prov1": servers("A")}
	for settings, want := range map[string]string{
		groupSection("youtube", "nope"):                                  "there is no group nope",
		"\nconfig section 'youtube'\n\toption connection_type 'group'\n": "the group is not set",
		"\nconfig group 'g'\n\tlist subscription 'prov1'\n\tlist include 'zzz'\n\toption empty 'section'\n\toption empty_section 'youtube'\n" + groupSection("youtube", "g"): "loop: youtube → youtube",
		"\nconfig group 'g'\n\tlist subscription 'prov1'\n\tlist include 'zzz'\n\toption empty 'section'\n\toption empty_section 'b'\n" +
			"\nconfig group 'h'\n\tlist subscription 'prov1'\n\tlist include 'zzz'\n\toption empty 'section'\n\toption empty_section 'a'\n" +
			groupSection("a", "g") + groupSection("b", "h"): "loop: a → b → a",
		"\nconfig group 'g'\n\tlist subscription 'prov1'\n\tlist include 'zzz'\n\toption empty 'section'\n\toption empty_section 'gone'\n" + groupSection("youtube", "g"): "there is no section gone",
		proxySection("main", "\toption detour 'youtube'\n") + "\nconfig group 'g'\n\tlist subscription 'prov1'\n" + groupSection("youtube", "g"):                          "a group cannot be connected through yet",
	} {
		_, err := buildGroups(t, twoSubscriptions+settings, list)
		require.ErrorContains(t, err, want, settings)
		require.NotContains(t, err.Error(), "section youtube: section youtube", "the section is named once")
	}
}

// A provider that renames its servers changes the configuration; the supervisor keeps the
// old names of a list whose servers are the same (subscription.SameServers), and the same
// list is the same configuration.
func TestGroupConfigurationIsStable(t *testing.T) {
	settings := twoSubscriptions + "\nconfig group 'g'\n\tlist subscription 'prov1'\n" + groupSection("youtube", "g")
	first, err := buildGroups(t, settings, map[string][]SubscriptionServer{"prov1": servers("A", "B")})
	require.NoError(t, err)
	second, err := buildGroups(t, settings, map[string][]SubscriptionServer{"prov1": servers("A", "B")})
	require.NoError(t, err)
	require.Equal(t, string(first.Config), string(second.Config))
}

// A link the decoder no longer takes is left out of the group, never sent elsewhere.
func TestGroupLeavesOutWhatIsNotDecoded(t *testing.T) {
	settings := twoSubscriptions + "\nconfig group 'g'\n\tlist subscription 'prov1'\n" + groupSection("youtube", "g")
	list := map[string][]SubscriptionServer{"prov1": {{Name: "A", Link: "vless://u@bad.example:443#A"}, {Name: "B", Link: "vless://u@ok.example:443#B"}}}
	result, err := buildGroups(t, settings, list)
	require.NoError(t, err)
	_, byTag := parsed(t, result)
	require.Equal(t, []string{"prov1: B"}, byTag["g-group"].Outbounds)
	require.NotContains(t, byTag, "prov1: A")
	require.Contains(t, strings.Join(result.Warnings, "\n"), "prov1: A is left out")
}

// What sing-box may replace while it runs: the servers of the groups, the groups, the
// selectors of the sections of the type group; not the outbounds of other sections, nor
// direct-out and the block outbound.
func TestSwappable(t *testing.T) {
	settings := twoSubscriptions + proxySection("main", "") + "\nconfig group 'nl'\n\tlist subscription 'prov1'\n" + groupSection("youtube", "nl")
	result, err := buildGroups(t, settings, map[string][]SubscriptionServer{"prov1": servers("NL 1", "NL 2")})
	require.NoError(t, err)
	require.Equal(t, map[string]bool{"prov1: NL 1": true, "prov1: NL 2": true, "nl-group": true, "youtube-out": true}, result.Swappable)
	_, byTag := parsed(t, result)
	require.Equal(t, "block", byTag["block"].Type, "there with a section of the type group, servers or not")
}

// A section may be named block: its outbound is block-out, and the block outbound of the groups is
// another tag.
func TestSectionNamedBlock(t *testing.T) {
	settings := twoSubscriptions + proxySection("block", "") + "\nconfig group 'nl'\n\tlist subscription 'prov1'\n\tlist include 'XX'\n\toption empty 'block'\n" +
		groupSection("youtube", "nl")
	result, err := buildGroups(t, settings, map[string][]SubscriptionServer{"prov1": servers("NL 1")})
	require.NoError(t, err)
	_, byTag := parsed(t, result)
	require.Equal(t, "vless", byTag["block-out"].Type, "the stub decoder of the tests gives vless")
	require.Equal(t, "block", byTag["block"].Type)
	require.Equal(t, []string{"block"}, byTag["youtube-out"].Outbounds)
}
