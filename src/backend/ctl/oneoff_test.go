package ctl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/model"

	"github.com/stretchr/testify/require"
)

// The URLs of a test of one outbound are the check URLs of HTTPS, in their order: the Clash API
// tests www.gstatic.com in place of an http:// URL.
func TestOneOffURLs(t *testing.T) {
	require.Equal(t, model.DefaultTestingURLs, oneOffURLs(model.DefaultTestingURLs))
	require.Equal(t, []string{"https://b.example/y", "https://d.example/z"},
		oneOffURLs([]string{"http://a.example/x", "https://b.example/y", " https://b.example/y ", "ftp://c.example/", "https://d.example/z"}))
	require.Equal(t, []string{engineDefaultURL}, oneOffURLs([]string{"http://a.example/x"}))
	require.Equal(t, []string{engineDefaultURL}, oneOffURLs(nil))
}

// The check URLs are those of the configuration that runs, which the rounds use; without one, or
// without a URL test in it, those of the settings.
func TestCheckURLs(t *testing.T) {
	directory := t.TempDir()
	settings := model.Check{TestingURLs: []string{"https://saved.example/1"}}
	require.Equal(t, settings.TestingURLs, checkURLs("", settings))
	require.Equal(t, settings.TestingURLs, checkURLs(directory, settings), "nothing runs")
	write := func(content string) {
		require.NoError(t, os.WriteFile(filepath.Join(directory, api.RunningConfig), []byte(content), 0o600))
	}
	write(`{"outbounds":[{"type":"selector","tag":"main-out"},{"type":"urltest","tag":"main-urltest-out","urls":["https://running.example/1","https://running.example/2"]}]}`)
	require.Equal(t, []string{"https://running.example/1", "https://running.example/2"}, checkURLs(directory, settings))
	write(`{"outbounds":[{"type":"selector","tag":"main-out","outbounds":["s1"]},{"type":"vless","tag":"s1"}]}`)
	require.Equal(t, settings.TestingURLs, checkURLs(directory, settings), "a rule of one server has no URL test")
	write(`{"outbounds":`)
	require.Equal(t, settings.TestingURLs, checkURLs(directory, settings))
	require.Equal(t, model.DefaultTestingURLs, checkURLs(directory, model.Check{}), "settings that cannot be read")
}

// shortWaits makes the waits of a test of one outbound those of a test.
func shortWaits(t *testing.T, budget time.Duration) {
	t.Helper()
	saved := oneOffBudget
	oneOffBudget = budget
	t.Cleanup(func() { oneOffBudget = saved })
}

// latencyOf runs get_proxy_latency against the fake and reads what it printed.
func latencyOf(t *testing.T, fake *fakeClash, tag string) (oneOff, int) {
	t.Helper()
	output, status := run(Environment{Socket: fake.caller(t).client.Path}, "clash_api", "get_proxy_latency", tag, "5000")
	var answer oneOff
	if status == 0 {
		require.NoError(t, json.Unmarshal([]byte(output), &answer), output)
	}
	return answer, status
}

// One server is tested with the first check URL, and with the second when that does not answer
// through it, one after the other; never more.
func TestProxyLatencyTriesTheNextURL(t *testing.T) {
	servers := map[string]map[string]any{"s1": {"type": "VLESS"}}

	fake := &fakeClash{proxies: servers}
	answer, status := latencyOf(t, fake, "s1")
	require.Zero(t, status)
	require.Equal(t, oneOff{Delay: 120, URLs: []string{"https://www.gstatic.com/generate_204"}}, answer)
	require.Equal(t, []string{"s1 www.gstatic.com 5000"}, fake.tests())

	fake = &fakeClash{proxies: servers, failing: []string{"s1 www.gstatic.com"}, delays: map[string]int{"s1 cp.cloudflare.com": 48}}
	answer, _ = latencyOf(t, fake, "s1")
	require.Equal(t, oneOff{Delay: 48, URLs: []string{"https://cp.cloudflare.com/generate_204"}, Silent: []string{"https://www.gstatic.com/generate_204"}}, answer)
	require.Equal(t, []string{"s1 www.gstatic.com 5000", "s1 cp.cloudflare.com 5000"}, fake.tests())

	fake = &fakeClash{proxies: servers, failing: []string{"s1"}}
	answer, status = latencyOf(t, fake, "s1")
	require.Zero(t, status)
	require.Equal(t, oneOff{Message: "An error occurred in the delay test", Silent: []string{"https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"}}, answer)
	require.Len(t, fake.tests(), 2)
	require.Equal(t, 1, fake.mostBusy, "the tries through one server go one after the other")
}

// The two tries keep within the budget: the second gets what is left, and none when too little is.
func TestProxyLatencyKeepsWithinTheBudget(t *testing.T) {
	servers := map[string]map[string]any{"s1": {"type": "VLESS"}}

	shortWaits(t, 2500*time.Millisecond)
	fake := &fakeClash{proxies: servers, failing: []string{"s1"}, hold: 1100 * time.Millisecond}
	latencyOf(t, fake, "s1")
	tests := fake.tests()
	require.Len(t, tests, 2)
	require.True(t, strings.HasPrefix(tests[0], "s1 www.gstatic.com "), tests[0])
	timeout, err := strconv.Atoi(strings.Fields(tests[1])[2])
	require.NoError(t, err)
	require.LessOrEqual(t, timeout, 1400)
	require.Greater(t, timeout, 1000)

	shortWaits(t, 1200*time.Millisecond)
	fake = &fakeClash{proxies: servers, failing: []string{"s1"}, hold: 1100 * time.Millisecond}
	start := time.Now()
	answer, _ := latencyOf(t, fake, "s1")
	require.Less(t, time.Since(start), 2*time.Second)
	require.Len(t, fake.tests(), 1, "less than leastProxyTest left")
	require.Equal(t, []string{"https://www.gstatic.com/generate_204"}, answer.Silent)

	// no Clash API: no answer at all
	output, status := run(Environment{Socket: filepath.Join(t.TempDir(), "none.sock")}, "clash_api", "get_proxy_latency", "s1", "5000")
	require.Equal(t, 1, status)
	require.Empty(t, output)
}

// What goes without a proxy is tested with all the check URLs at once: the median of those that
// answered, and those that did not named.
func TestProxyLatencyOfDirect(t *testing.T) {
	direct := map[string]map[string]any{"direct-out": {"type": "Direct"}}
	delays := map[string]int{
		"direct-out www.gstatic.com":          50,
		"direct-out cp.cloudflare.com":        30,
		"direct-out captive.apple.com":        40,
		"direct-out detectportal.firefox.com": 90,
		"direct-out www.apple.com":            20,
	}

	fake := &fakeClash{proxies: direct, delays: delays, hold: 300 * time.Millisecond}
	answer, _ := latencyOf(t, fake, "direct-out")
	require.Equal(t, oneOff{Delay: 40, URLs: model.DefaultTestingURLs}, answer)
	require.Equal(t, 5, fake.mostBusy, "at once")

	fake = &fakeClash{proxies: direct, delays: delays, failing: []string{"direct-out www.gstatic.com"}}
	answer, _ = latencyOf(t, fake, "direct-out")
	require.Equal(t, 35, answer.Delay, "the mean of the middle two, 30 and 40")
	require.Equal(t, []string{"https://www.gstatic.com/generate_204"}, answer.Silent)
	require.Len(t, answer.URLs, 4)

	fake = &fakeClash{proxies: direct, failing: []string{"direct-out"}}
	answer, status := latencyOf(t, fake, "direct-out")
	require.Zero(t, status)
	require.Equal(t, oneOff{Message: "An error occurred in the delay test", Silent: model.DefaultTestingURLs}, answer)
	require.Len(t, fake.tests(), 5)
}

// The test of a rule's group is a round of the rule's URL test, not a test of the selector with
// the one-offs of every server besides; a selector without a URL test has its server tested alone.
func TestGroupLatency(t *testing.T) {
	proxies := map[string]map[string]any{
		"main-out":            {"type": "Selector", "now": "main-urltest-out", "all": []string{"main-urltest-out", "a", "b", "c", "d"}},
		"main-urltest-out":    {"type": "URLTest", "now": "a", "all": []string{"a", "b", "main-fallback-1-out"}, "fallbacks": []string{"main-fallback-1-out"}},
		"main-fallback-1-out": {"type": "URLTest", "now": "c", "all": []string{"c", "d"}},
		"busy-out":            {"type": "Selector", "now": "busy-urltest-out", "all": []string{"busy-urltest-out", "a"}},
		"busy-urltest-out":    {"type": "URLTest", "now": "a", "all": []string{"a"}},
		"one-out":             {"type": "Selector", "now": "s1", "all": []string{"s1"}},
		"none-out":            {"type": "Selector", "now": "block", "all": []string{"block"}},
		"block":               {"type": "Reject"},
		"a":                   {"type": "VLESS"},
		"b":                   {"type": "VLESS"},
		"c":                   {"type": "VLESS"},
		"d":                   {"type": "VLESS"},
		"s1":                  {"type": "Trojan"},
	}
	groups := map[string]string{"main-urltest-out": `{"a": 100, "c": 90, "main-fallback-1-out": 90}`}
	latency := func(fake *fakeClash, tag string) (map[string]int, []string, int) {
		output, status := run(Environment{Socket: fake.caller(t).client.Path}, "clash_api", "get_group_latency", tag, "12000")
		delays := map[string]int{}
		if status == 0 {
			require.NoError(t, json.Unmarshal([]byte(output), &delays), output)
		}
		return delays, fake.tests(), status
	}

	delays, tests, status := latency(&fakeClash{proxies: proxies, groups: groups}, "main-out")
	require.Zero(t, status)
	require.Equal(t, map[string]int{"a": 100, "c": 90, "main-fallback-1-out": 90}, delays)
	require.Len(t, tests, 1)
	fields := strings.Fields(tests[0])
	require.Equal(t, []string{"group", "main-urltest-out", "www.gstatic.com"}, fields[:3])
	timeout, err := strconv.Atoi(fields[3])
	require.NoError(t, err)
	require.LessOrEqual(t, timeout, 12000)
	require.Greater(t, timeout, 11000, "the round gets the wait of the page")

	// a URL test is asked itself; one in a round of its own answers nothing
	delays, tests, _ = latency(&fakeClash{proxies: proxies, groups: groups}, "main-urltest-out")
	require.Contains(t, delays, "a")
	require.Len(t, tests, 1)
	delays, tests, status = latency(&fakeClash{proxies: proxies, groups: groups}, "busy-out")
	require.Zero(t, status)
	require.Empty(t, delays)
	require.True(t, strings.HasPrefix(tests[0], "group busy-urltest-out "), tests[0])

	// one server: alone, with the first check URL and then the second; 0 when neither answers
	delays, tests, _ = latency(&fakeClash{proxies: proxies}, "one-out")
	require.Equal(t, map[string]int{"s1": 120}, delays)
	require.Equal(t, []string{"s1 www.gstatic.com 5000"}, tests)
	delays, tests, _ = latency(&fakeClash{proxies: proxies, failing: []string{"s1"}}, "one-out")
	require.Equal(t, map[string]int{"s1": 0}, delays)
	require.Equal(t, []string{"s1 www.gstatic.com 5000", "s1 cp.cloudflare.com 5000"}, tests)
	// a block is not tested
	delays, tests, status = latency(&fakeClash{proxies: proxies}, "none-out")
	require.Zero(t, status)
	require.Empty(t, delays)
	require.Empty(t, tests)
}

// The line of what goes without a proxy in the global check: the median of the check URLs, those
// that do not answer named; and a server that answered the second URL only.
func TestOutboundLinesDirectAndSecondURL(t *testing.T) {
	proxies := map[string]map[string]any{
		"main-out":   {"type": "Socks"},
		"direct-out": {"type": "Direct"},
	}
	config := &model.Config{
		Sources:  []model.Source{{Name: "src", Type: "links", Links: []string{"socks5://m.example:1080"}}},
		Sections: []model.Section{{Name: "main", Enabled: true, Servers: []model.Member{{Source: "src"}}}},
	}
	lines := func(links []string, failing ...string) []string {
		return outboundLines(outboundsCaller(t, proxies, nil, failing...), config, links)
	}
	require.Equal(t, []string{
		"✅ main: 120 ms with cp.cloudflare.com; www.gstatic.com did not answer through it",
		"⚠️ direct (without a proxy): 120 ms, the median of 4 check URLs; no answer without a proxy from www.gstatic.com: the provider may block it",
	}, lines(checkLinks, "main-out www.gstatic.com", "direct-out www.gstatic.com"))
	require.Equal(t, []string{
		"❌ main: does not work (An error occurred in the delay test; tried www.gstatic.com, cp.cloudflare.com)",
		"❌ direct (without a proxy): none of the 5 check URLs answers (An error occurred in the delay test): check the router's internet and DNS",
	}, lines(checkLinks, "main-out", "direct-out"))
	require.Equal(t, "⚠️ direct (without a proxy): 120 ms with www.apple.com; no answer without a proxy from www.gstatic.com, cp.cloudflare.com, captive.apple.com, detectportal.firefox.com: the provider may block them",
		lines(checkLinks, "direct-out www.gstatic.com", "direct-out cp.cloudflare.com", "direct-out captive.apple.com", "direct-out detectportal.firefox.com")[1])
	// a list of one URL
	one := []string{"https://cp.cloudflare.com/generate_204"}
	require.Equal(t, []string{"✅ main: 120 ms", "✅ direct (without a proxy): 120 ms"}, lines(one))
	require.Equal(t, []string{
		"❌ main: does not work (An error occurred in the delay test; tried cp.cloudflare.com)",
		"❌ direct (without a proxy): does not work (An error occurred in the delay test; tried cp.cloudflare.com)",
	}, lines(one, "main-out", "direct-out"))
}

func TestMedianOf(t *testing.T) {
	require.Equal(t, 40, medianOf([]int{50, 30, 40, 90, 20}))
	require.Equal(t, 35, medianOf([]int{50, 30, 40, 20}))
	require.Equal(t, 36, medianOf([]int{31, 40}), "rounded up, as the engine does")
	require.Equal(t, 7, medianOf([]int{7}))
}
