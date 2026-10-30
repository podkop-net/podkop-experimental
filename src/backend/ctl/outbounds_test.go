package ctl

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/logbuf"
	"github.com/podkop-net/podkop-experimental/src/backend/model"

	"github.com/stretchr/testify/require"
)

// The test of the outbounds tests what the selector of a rule has chosen: its URL test with
// its own servers, or what is pinned on the dashboard, never the selector, which would test
// every server of every fallback. When no server of the URL test answers, what it goes
// through now is tested.
func TestOutboundLinesTestWhatTheRuleUses(t *testing.T) {
	proxies := map[string]map[string]any{
		"main-out":            {"type": "Socks"},
		"ru-out":              {"type": "Selector", "now": "ru-urltest-out"},
		"ru-urltest-out":      {"type": "URLTest", "now": "s-ru", "all": []string{"s-ru", "s-us", "ru-fallback-1-out"}, "fallbacks": []string{"ru-fallback-1-out"}},
		"ru-fallback-1-out":   {"type": "URLTest", "now": "s-de"},
		"pin-out":             {"type": "Selector", "now": "s-de", "all": []string{"pin-urltest-out", "s-de"}},
		"one-out":             {"type": "Selector", "now": "s-de", "all": []string{"s-de"}},
		"tier-out":            {"type": "Selector", "now": "tier-fallback-1-out", "all": []string{"tier-urltest-out", "tier-fallback-1-out"}},
		"tier-fallback-1-out": {"type": "URLTest", "now": "s-de"},
		"down-out":            {"type": "Selector", "now": "down-urltest-out"},
		"down-urltest-out":    {"type": "URLTest", "now": "down-fallback-1-out"},
		"down-fallback-1-out": {"type": "URLTest", "now": "s-de"},
		"lost-out":            {"type": "Selector", "now": "lost-urltest-out"},
		"lost-urltest-out":    {"type": "URLTest", "now": "lost-fallback-1-out"},
		"lost-fallback-1-out": {"type": "URLTest", "now": "s-us"},
		"busy-out":            {"type": "Selector", "now": "busy-urltest-out"},
		"busy-urltest-out":    {"type": "URLTest", "now": "s-us"},
		"dead-out":            {"type": "Selector", "now": "dead-urltest-out"},
		"dead-urltest-out":    {"type": "URLTest", "now": "block"},
		"yt-out":              {"type": "Selector", "now": "block"},
		"tv-out":              {"type": "Selector", "now": "block-out"},
		"s-ru":                {"type": "VLESS"},
		"s-de":                {"type": "VLESS"},
		"s-us":                {"type": "VLESS"},
		"direct-out":          {"type": "Direct"},
	}
	groups := map[string]string{
		"ru-urltest-out":      `{"s-ru": 142}`,
		"tier-fallback-1-out": `{"s-de": 150, "s-us": 409}`,
	}
	clash := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case path == "/proxies":
			_ = json.NewEncoder(writer).Encode(map[string]any{"proxies": proxies})
		case path == "/proxies/lost-fallback-1-out/delay":
			_, _ = writer.Write([]byte(`{"message": "An error occurred in the delay test"}`))
		case strings.HasPrefix(path, "/proxies/") && strings.HasSuffix(path, "/delay"):
			_, _ = writer.Write([]byte(`{"delay": 120}`))
		case strings.HasPrefix(path, "/proxies/"):
			_ = json.NewEncoder(writer).Encode(proxies[strings.TrimPrefix(path, "/proxies/")])
		case strings.HasPrefix(path, "/group/") && strings.HasSuffix(path, "/delay"):
			tag := strings.TrimSuffix(strings.TrimPrefix(path, "/group/"), "/delay")
			if proxies[tag]["type"] != "URLTest" {
				t.Errorf("a test of the group %s", tag)
			}
			answer, found := groups[tag]
			if !found {
				// none answers, or a round of the test is under way
				answer = "{}"
			}
			_, _ = writer.Write([]byte(answer))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer clash.Close()
	running := &backend{facts: api.Facts{ClashAPI: strings.TrimPrefix(clash.URL, "http://")}}
	caller := &clashCaller{client: api.Client{Path: serve(t, running, logbuf.New(1<<12))}}
	rows := []model.Member{{Source: "src"}}
	config := &model.Config{Sources: []model.Source{{Name: "src", Type: "links", Links: []string{"vless://x"}}}}
	// a rule whose sources name no server and refuses; one that goes as the rule named
	// block; one the configuration that runs does not have yet; one that is off; one whose
	// one row is block, a route rule without an outbound
	for _, name := range []string{"main", "ru", "pin", "one", "tier", "down", "lost", "busy", "dead", "yt", "tv", "new"} {
		config.Sections = append(config.Sections, model.Section{Name: name, Enabled: true, Servers: rows})
	}
	config.Sections = append(config.Sections,
		model.Section{Name: "off", Servers: rows},
		model.Section{Name: "ads", Enabled: true, Servers: []model.Member{{Source: model.SourceBlock}}})
	lines := outboundLines(caller, config)
	require.Equal(t, []string{
		"✅ main: 120 ms",
		"✅ ru (urltest): s-ru 142 ms (1 of 2 answer; no answer: s-us)",
		"✅ pin (pinned s-de): 120 ms",
		"✅ one: 120 ms",
		"✅ tier (pinned tier-fallback-1-out, urltest): s-de 150 ms, s-us 409 ms",
		"⚠️ down (urltest): none of its servers answers; it goes through the fallback down-fallback-1-out now: 120 ms",
		"❌ lost (urltest): none of its servers answers, nor the fallback lost-fallback-1-out it goes through now (An error occurred in the delay test)",
		"✅ busy (urltest): it goes through s-us now: 120 ms",
		"❌ dead (urltest): none of its servers answers; its fallback block refuses its connections",
		"✅ tv: 120 ms",
		"✅ direct (without a proxy): 120 ms",
		"⛔ yt: its sources name no server now, and its connections are refused",
	}, lines)
}
