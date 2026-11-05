package ctl

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/logbuf"
	"github.com/podkop-net/podkop-experimental/src/backend/model"

	"github.com/stretchr/testify/require"
)

// outboundsCaller is the Clash API of a running sing-box, standing in: the proxies, the answers of
// the delay test of the groups, and the outbounds whose own delay test fails.
func outboundsCaller(t *testing.T, proxies map[string]map[string]any, groups map[string]string, failing ...string) *clashCaller {
	t.Helper()
	clash := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case path == "/proxies":
			_ = json.NewEncoder(writer).Encode(map[string]any{"proxies": proxies})
		case strings.HasPrefix(path, "/proxies/") && strings.HasSuffix(path, "/delay"):
			if slices.Contains(failing, strings.TrimSuffix(strings.TrimPrefix(path, "/proxies/"), "/delay")) {
				_, _ = writer.Write([]byte(`{"message": "An error occurred in the delay test"}`))
				return
			}
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
	t.Cleanup(clash.Close)
	running := &backend{facts: api.Facts{ClashAPI: strings.TrimPrefix(clash.URL, "http://")}}
	return &clashCaller{client: api.Client{Path: serve(t, running, logbuf.New(1<<12))}}
}

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
		"tier-fallback-1-out": {"type": "URLTest", "now": "s-de", "all": []string{"s-de", "s-us"}},
		"down-out":            {"type": "Selector", "now": "down-urltest-out"},
		"down-urltest-out":    {"type": "URLTest", "now": "down-fallback-1-out", "all": []string{"s-ru", "down-fallback-1-out"}, "fallbacks": []string{"down-fallback-1-out"}},
		"down-fallback-1-out": {"type": "URLTest", "now": "s-de"},
		"lost-out":            {"type": "Selector", "now": "lost-urltest-out"},
		"lost-urltest-out":    {"type": "URLTest", "now": "lost-fallback-1-out", "all": []string{"s-ru", "lost-fallback-1-out"}, "fallbacks": []string{"lost-fallback-1-out"}},
		"lost-fallback-1-out": {"type": "URLTest", "now": "s-us"},
		"busy-out":            {"type": "Selector", "now": "busy-urltest-out"},
		"busy-urltest-out":    {"type": "URLTest", "now": "s-us", "all": []string{"s-us", "s-ru"}},
		"dead-out":            {"type": "Selector", "now": "dead-urltest-out"},
		"dead-urltest-out":    {"type": "URLTest", "now": "block", "all": []string{"s-ru", "block"}, "fallbacks": []string{"block"}},
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
	caller := outboundsCaller(t, proxies, groups, "lost-fallback-1-out")
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
		"✅ ru (urltest): s-ru 142 ms (1 of 2 answer; no answer in time: s-us)",
		"✅ pin (pinned s-de): 120 ms",
		"✅ one: 120 ms",
		"✅ tier (pinned tier-fallback-1-out, urltest): s-de 150 ms, s-us 409 ms",
		"⚠️ down (urltest): none of its servers answers in time; it goes through the fallback down-fallback-1-out now: 120 ms",
		"❌ lost (urltest): none of its servers answers in time, nor the fallback lost-fallback-1-out it goes through now (An error occurred in the delay test)",
		"✅ busy (urltest): it goes through s-us now: 120 ms",
		"❌ dead (urltest): none of its servers answers in time; its fallback block refuses its connections",
		"✅ tv: 120 ms",
		"✅ direct (without a proxy): 120 ms",
		"⛔ yt: its sources name no server now, and its connections are refused",
	}, lines)
}

// The delay test of a URL test answers for its fallbacks too, and for the servers inside them. The
// servers of a rule and their count are its own: a fallback that answers is no server that answers.
// A fallback is what the URL test lists as one, whatever its type: a row that gave one server is
// that server.
func TestOutboundLinesFallbacksAreNoServers(t *testing.T) {
	test := func(now string, own []string, fallbacks ...string) map[string]any {
		return map[string]any{"type": "URLTest", "now": now, "all": slices.Concat(own, fallbacks), "fallbacks": fallbacks}
	}
	selector := func(rule string) map[string]any {
		return map[string]any{"type": "Selector", "now": rule + "-urltest-out"}
	}
	proxies := map[string]map[string]any{
		"whole-out":            selector("whole"),
		"whole-urltest-out":    test("own", []string{"own"}, "whole-fallback-1-out"),
		"whole-fallback-1-out": {"type": "URLTest", "now": "s-de", "all": []string{"s-de", "s-nl"}},
		"multi-out":            selector("multi"),
		"multi-urltest-out":    test("s-de", []string{"s-de", "s-nl", "s-us"}, "multi-fallback-1-out"),
		"multi-fallback-1-out": {"type": "URLTest", "now": "s-fi", "all": []string{"s-fi", "s-se"}},
		"tier-out":             selector("tier"),
		"tier-urltest-out":     test("tier-fallback-1-out", []string{"own"}, "tier-fallback-1-out"),
		"tier-fallback-1-out":  {"type": "URLTest", "now": "s-de", "all": []string{"s-de", "s-nl"}},
		"one-out":              selector("one"),
		"one-urltest-out":      test("s-de", []string{"own"}, "s-de"),
		"gone-out":             selector("gone"),
		"gone-urltest-out":     test("s-se", []string{"own"}, "s-se"),
		"open-out":             selector("open"),
		"open-urltest-out":     test("direct-out", []string{"own"}, "direct-out"),
		"self-out":             selector("self"),
		"self-urltest-out":     test("s-nl", []string{"s-nl", "own"}, "s-de"),
		"own":                  {"type": "VLESS"},
		"s-de":                 {"type": "VLESS"},
		"s-nl":                 {"type": "Hysteria2"},
		"s-us":                 {"type": "VLESS"},
		"s-fi":                 {"type": "VLESS"},
		"s-se":                 {"type": "VLESS"},
		"direct-out":           {"type": "Direct"},
	}
	groups := map[string]string{
		"whole-urltest-out": `{"own": 48, "whole-fallback-1-out": 47, "s-de": 47, "s-nl": 49}`,
		"multi-urltest-out": `{"s-nl": 47, "multi-fallback-1-out": 40, "s-fi": 40, "s-se": 41}`,
		"tier-urltest-out":  `{"tier-fallback-1-out": 47, "s-de": 47, "s-nl": 49}`,
		"one-urltest-out":   `{"s-de": 45}`,
		"gone-urltest-out":  `{"s-se": 45}`,
		"open-urltest-out":  `{"direct-out": 30}`,
		"self-urltest-out":  `{"s-de": 45}`,
	}
	caller := outboundsCaller(t, proxies, groups, "s-se")
	config := &model.Config{Sources: []model.Source{{Name: "src", Type: "links", Links: []string{"vless://x"}}}}
	for _, name := range []string{"whole", "multi", "tier", "one", "gone", "open", "self"} {
		config.Sections = append(config.Sections, model.Section{Name: name, Enabled: true, Servers: []model.Member{{Source: "src"}}})
	}
	require.Equal(t, []string{
		"✅ whole (urltest): own 48 ms",
		"✅ multi (urltest): s-nl 47 ms (1 of 3 answer; no answer in time: s-de, s-us)",
		"⚠️ tier (urltest): none of its servers answers in time; it goes through the fallback tier-fallback-1-out now: 120 ms",
		"⚠️ one (urltest): none of its servers answers in time; it goes through the fallback s-de now: 120 ms",
		"❌ gone (urltest): none of its servers answers in time, nor the fallback s-se it goes through now (An error occurred in the delay test)",
		"⚠️ open (urltest): none of its servers answers in time; it goes through the fallback direct-out now: 120 ms",
		"✅ self (urltest): it goes through s-nl now: 120 ms",
		"✅ direct (without a proxy): 120 ms",
	}, outboundLines(caller, config))
}

// What a delay test of a group gets for so many servers: a slot of the engine for each, a server
// without TCP holding one for the whole of outboundWait, up to what the call of the page leaves.
func TestGroupWait(t *testing.T) {
	for servers, wait := range map[int]time.Duration{
		0:  5 * time.Second,
		1:  5 * time.Second,
		4:  5 * time.Second,
		5:  10 * time.Second,
		8:  10 * time.Second,
		9:  12 * time.Second,
		22: 12 * time.Second,
		99: 12 * time.Second,
	} {
		require.Equal(t, wait, groupWait(servers), servers)
	}
	// the page gives global_check 19 s; a test of what the rule goes through still fits after the wait
	require.LessOrEqual(t, outboundsBudget+4*time.Second, 19*time.Second)
	require.GreaterOrEqual(t, outboundsBudget-groupWaitMax, leastProxyTest)
}

func TestServersOfGroup(t *testing.T) {
	proxies := map[string]clashProxy{
		"test":   {Type: "URLTest", All: []string{"a", "b", "tier-1", "one", "pick", "block"}, Fallbacks: []string{"tier-1", "one", "pick", "block"}},
		"tier-1": {Type: "URLTest", All: []string{"c", "d", "block"}},
		"pick":   {Type: "Selector", All: []string{"e", "tier-1"}},
		"a":      {Type: "VLESS"},
		"b":      {Type: "VLESS"},
		"c":      {Type: "VLESS"},
		"d":      {Type: "VLESS"},
		"e":      {Type: "VLESS"},
		"one":    {Type: "VLESS"},
		"block":  {Type: "Reject"},
	}
	// a, b, one, e and those of tier-1, which is a group of a selector as well; no block
	require.Equal(t, 6, serversOfGroup(proxies, "test", map[string]bool{}))
}

// roundOfEngine is what the delay test of a URL test answers within its deadline, without the time
// passing: the servers in order, a slot each out of groupSlots; a dead one holds its slot for the
// time of a dial and is not told of, one still under way at the deadline is not told of either.
func roundOfEngine(members []string, dead map[string]bool, deadline time.Duration) map[string]int {
	const working, dial = 300 * time.Millisecond, 5 * time.Second
	slots := make([]time.Duration, groupSlots)
	answer := map[string]int{}
	for _, member := range members {
		earliest := slices.Index(slots, slices.Min(slots))
		took := working
		if dead[member] {
			took = dial
		}
		slots[earliest] += took
		if !dead[member] && slots[earliest] <= deadline {
			answer[member] = 100
		}
	}
	return answer
}

// A fake of the Clash API whose round is cut by the timeout of the request, as the engine's is.
func roundCaller(t *testing.T, proxies map[string]map[string]any, dead map[string]bool) (*clashCaller, func() []string) {
	t.Helper()
	var access sync.Mutex
	var asked []string
	timeouts := func() []string {
		access.Lock()
		defer access.Unlock()
		return slices.Clone(asked)
	}
	clash := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case path == "/proxies":
			_ = json.NewEncoder(writer).Encode(map[string]any{"proxies": proxies})
		case strings.HasPrefix(path, "/group/") && strings.HasSuffix(path, "/delay"):
			tag := strings.TrimSuffix(strings.TrimPrefix(path, "/group/"), "/delay")
			milliseconds, err := strconv.Atoi(request.URL.Query().Get("timeout"))
			if err != nil {
				t.Errorf("the timeout of a test of a group: %v", err)
			}
			access.Lock()
			asked = append(asked, request.URL.Query().Get("timeout"))
			access.Unlock()
			_ = json.NewEncoder(writer).Encode(roundOfEngine(proxies[tag]["all"].([]string), dead, time.Duration(milliseconds)*time.Millisecond))
		case strings.HasPrefix(path, "/proxies/") && strings.HasSuffix(path, "/delay"):
			_, _ = writer.Write([]byte(`{"delay": 120}`))
		case strings.HasPrefix(path, "/proxies/"):
			_ = json.NewEncoder(writer).Encode(proxies[strings.TrimPrefix(path, "/proxies/")])
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(clash.Close)
	running := &backend{facts: api.Facts{ClashAPI: strings.TrimPrefix(clash.URL, "http://")}}
	return &clashCaller{client: api.Client{Path: serve(t, running, logbuf.New(1<<12))}}, timeouts
}

// servers22 are the 22 servers of a stand, 9 without TCP among them, those at the start of the list
// holding the slots: at 5 s only those ahead of them answered, and working servers after them were
// named as giving no answer (research_notes/detector/stand/subs.md).
func servers22() ([]string, map[string]bool) {
	var members []string
	dead := map[string]bool{}
	for index := range 22 {
		member := fmt.Sprintf("s%02d", index)
		members = append(members, member)
		if slices.Contains([]int{0, 2, 3, 8, 12, 13, 15, 18, 21}, index) {
			dead[member] = true
		}
	}
	return members, dead
}

func ruleOfServers(rule string, members []string) (map[string]map[string]any, *model.Config) {
	proxies := map[string]map[string]any{
		rule + "-out":         {"type": "Selector", "now": rule + "-urltest-out"},
		rule + "-urltest-out": {"type": "URLTest", "now": members[1], "all": members},
	}
	for _, member := range members {
		proxies[member] = map[string]any{"type": "VLESS"}
	}
	config := &model.Config{
		Sources:  []model.Source{{Name: "src", Type: "links", Links: []string{"vless://x"}}},
		Sections: []model.Section{{Name: rule, Enabled: true, Servers: []model.Member{{Source: "src"}}}},
	}
	return proxies, config
}

// The deadline of the round grows with the servers, and the working ones after the dead ones get
// their test: the timeout of the request is what ends the round, not the patience of the client.
func TestURLTestLineWaitsForAllServers(t *testing.T) {
	members, dead := servers22()
	proxies, config := ruleOfServers("sweep", members)
	caller, timeouts := roundCaller(t, proxies, dead)
	lines := outboundLines(caller, config)
	require.Equal(t, []string{"12000"}, timeouts())
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "(13 of 22 answer; no answer in time: s00, s02, s03, s08, s12, s13, s15, s18, s21)")
}

// The cap of the wait cuts a list too long for it: working servers it left out are named in the one
// wording true of them as well, and the deadline stays within what the page leaves.
func TestURLTestLineCutByTheCap(t *testing.T) {
	var members []string
	dead := map[string]bool{}
	for index := range 40 {
		member := fmt.Sprintf("s%02d", index)
		members = append(members, member)
		dead[member] = index < 8
	}
	proxies, config := ruleOfServers("sweep", members)
	caller, timeouts := roundCaller(t, proxies, dead)
	lines := outboundLines(caller, config)
	require.Equal(t, []string{"12000"}, timeouts())
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "(24 of 40 answer; no answer in time: s00, ")
	require.Contains(t, lines[0], ", s39)")
	require.NotContains(t, lines[0], "no answer:")
}

// A list the cap leaves no answer of goes by what the rule goes through, which is tested on its own.
func TestURLTestLineNoAnswerWithinTheCap(t *testing.T) {
	var members []string
	dead := map[string]bool{}
	for index := range 40 {
		member := fmt.Sprintf("s%02d", index)
		members = append(members, member)
		dead[member] = index < 20
	}
	proxies, config := ruleOfServers("sweep", members)
	proxies["sweep-urltest-out"]["now"] = "s00"
	caller, _ := roundCaller(t, proxies, dead)
	require.Equal(t, []string{"✅ sweep (urltest): it goes through s00 now: 120 ms"}, outboundLines(caller, config))
}

// A fake of the Clash API for what follows a round without an answer: no server answers the round,
// and the timeout of each test of an outbound is written down. A round that hangs waits for the end
// of the request.
func followUpCaller(t *testing.T, proxies map[string]map[string]any, hang bool, answer string) (*clashCaller, func() []string) {
	t.Helper()
	var access sync.Mutex
	var asked []string
	clash := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		access.Lock()
		if strings.HasSuffix(path, "/delay") && strings.HasPrefix(path, "/proxies/") {
			asked = append(asked, request.URL.Query().Get("timeout"))
		} else if strings.HasPrefix(path, "/proxies/") {
			asked = append(asked, "the group")
		}
		access.Unlock()
		switch {
		case strings.HasPrefix(path, "/group/"):
			if hang {
				<-request.Context().Done()
				return
			}
			_, _ = writer.Write([]byte("{}"))
		case strings.HasSuffix(path, "/delay"):
			_, _ = writer.Write([]byte(answer))
		default:
			_ = json.NewEncoder(writer).Encode(proxies[strings.TrimPrefix(path, "/proxies/")])
		}
	}))
	t.Cleanup(clash.Close)
	running := &backend{facts: api.Facts{ClashAPI: strings.TrimPrefix(clash.URL, "http://")}}
	return &clashCaller{client: api.Client{Path: serve(t, running, logbuf.New(1<<12))}}, func() []string {
		access.Lock()
		defer access.Unlock()
		return slices.Clone(asked)
	}
}

// A round that used its whole wait leaves the test of what the rule goes through what is left of the
// budget, not a wait of its own on top of it: the two together are a bound, not a sum.
func TestURLTestLineFollowUpGetsWhatIsLeft(t *testing.T) {
	proxies, _ := ruleOfServers("sweep", []string{"a", "b"})
	test := func(left time.Duration, answer string) (string, []string) {
		caller, asked := followUpCaller(t, proxies, false, answer)
		line := urlTestLine(caller, "sweep", "sweep-urltest-out", []string{"a", "b"}, nil, 5*time.Second, time.Now().Add(left))
		return line, asked()
	}

	line, asked := test(3*time.Second, `{"delay": 120}`)
	require.Equal(t, "✅ sweep: it goes through b now: 120 ms", line)
	require.Len(t, asked, 2)
	timeout, err := strconv.Atoi(asked[1])
	require.NoError(t, err)
	require.LessOrEqual(t, timeout, 3000)
	require.Greater(t, timeout, 2000)

	// the wait the test tells of is the one it got
	line, _ = test(3*time.Second, `{}`)
	require.Equal(t, "❌ sweep: b, which it goes through now, does not work (no answer within 3 s)", line)

	// plenty left: its usual wait
	_, asked = test(14*time.Second, `{"delay": 120}`)
	require.Equal(t, []string{"the group", "5000"}, asked)

	// too little left for a test to tell anything: none is made
	line, asked = test(leastProxyTest/2, `{"delay": 120}`)
	require.Equal(t, "❌ sweep: none of its servers answers in time", line)
	require.Empty(t, asked)
}

// A round that hangs past its own deadline ends at the deadline of the outbounds as well: the wait
// for its answer is 3 s longer than the round, and this is where those 3 s are taken away.
func TestURLTestLineEndsAtTheDeadline(t *testing.T) {
	proxies, _ := ruleOfServers("sweep", []string{"a", "b"})
	caller, asked := followUpCaller(t, proxies, true, `{"delay": 120}`)
	start := time.Now()
	line := urlTestLine(caller, "sweep", "sweep-urltest-out", []string{"a", "b"}, nil, 5*time.Second, start.Add(300*time.Millisecond))
	require.Less(t, time.Since(start), 3*time.Second)
	require.Equal(t, "❌ sweep: none of its servers answers in time", line)
	require.Empty(t, asked())
}

// A slow read of what the group goes through takes from the test after it: with too little left by
// then, none is made. Whatever the machine's pace, nothing but the test can turn the line green.
func TestURLTestLineNoTestAfterASlowRead(t *testing.T) {
	var access sync.Mutex
	tests := 0
	clash := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case strings.HasPrefix(path, "/group/"):
			_, _ = writer.Write([]byte("{}"))
		case strings.HasSuffix(path, "/delay"):
			access.Lock()
			tests++
			access.Unlock()
			_, _ = writer.Write([]byte(`{"delay": 120}`))
		default:
			time.Sleep(600 * time.Millisecond)
			_, _ = writer.Write([]byte(`{"now": "b"}`))
		}
	}))
	t.Cleanup(clash.Close)
	running := &backend{facts: api.Facts{ClashAPI: strings.TrimPrefix(clash.URL, "http://")}}
	caller := &clashCaller{client: api.Client{Path: serve(t, running, logbuf.New(1<<12))}}
	line := urlTestLine(caller, "sweep", "sweep-urltest-out", []string{"a", "b"}, nil, 5*time.Second, time.Now().Add(leastProxyTest+300*time.Millisecond))
	require.Equal(t, "❌ sweep: none of its servers answers in time", line)
	access.Lock()
	defer access.Unlock()
	require.Zero(t, tests)
}

// The rounds of all rules share the slots: each gets the time of them all.
func TestOutboundLinesGroupsShareTheSlots(t *testing.T) {
	first, config := ruleOfServers("one", []string{"a1", "a2", "a3", "a4"})
	second, other := ruleOfServers("two", []string{"b1", "b2", "b3"})
	for tag, proxy := range second {
		first[tag] = proxy
	}
	config.Sections = append(config.Sections, other.Sections...)
	caller, timeouts := roundCaller(t, first, map[string]bool{})
	lines := outboundLines(caller, config)
	require.Equal(t, []string{"10000", "10000"}, timeouts())
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], "a1 100 ms")
}

// The outbounds of a rule are those the backend that runs tells (plan.Tags): their tags are made
// of the names of the rules and the sources, and a rule is told by its name. Without a backend
// that tells, the settings name them.
func TestOutboundLinesOfNames(t *testing.T) {
	proxies := map[string]map[string]any{
		"Cats-out":         {"type": "Selector", "now": "Cats-urltest-out", "all": []string{"Cats-urltest-out", "mouse via dog"}},
		"Cats-urltest-out": {"type": "URLTest", "now": "mouse via dog", "all": []string{"mouse via dog"}},
		"Pin-out":          {"type": "Selector", "now": "mouse via dog", "all": []string{"Pin-urltest-out", "mouse via dog"}},
		"Pin-urltest-out":  {"type": "URLTest", "now": "mouse via dog", "all": []string{"mouse via dog"}},
		"mouse via dog":    {"type": "Socks"},
	}
	groups := map[string]string{"Cats-urltest-out": `{"mouse via dog": 99}`}
	rows := []model.Member{{Source: "src1", Via: "src2"}}
	config := &model.Config{
		Sources: []model.Source{{Name: "src1", Label: "mouse", Type: "links", Links: []string{"socks5://m.example:1080"}},
			{Name: "src2", Label: "dog", Type: "links", Links: []string{"socks5://d.example:1080"}}},
		Sections: []model.Section{{Name: "rule1", Label: "Cats", Enabled: true, Servers: rows}, {Name: "rule2", Label: "Pin", Enabled: true, Servers: rows}},
	}

	caller := outboundsCaller(t, proxies, groups)
	facts, err := caller.client.Facts()
	require.NoError(t, err)
	facts.Tags = json.RawMessage(`{"rules":{"rule1":{"name":"Cats","selector":"Cats-out","test":"Cats-urltest-out"}},"outbounds":{}}`)
	caller.once.Do(func() { caller.facts = *facts })
	require.Equal(t, []string{"✅ Cats (urltest): mouse via dog 99 ms"}, outboundLines(caller, config), "rule2 does not run")

	// what the settings make: the tags of the names
	require.Equal(t, []string{"✅ Cats (urltest): mouse via dog 99 ms", "✅ Pin (pinned mouse via dog): 120 ms"},
		outboundLines(outboundsCaller(t, proxies, groups), config))
}

// The proxies of the Clash API go to the page with what their tags are.
func TestProxiesWithTags(t *testing.T) {
	joined := withTags([]byte(`{"proxies":{"a":{"type":"Socks"}}}`), json.RawMessage(`{"rules":{}}`))
	require.JSONEq(t, `{"proxies":{"a":{"type":"Socks"}},"podkop_tags":{"rules":{}}}`, string(joined))
	require.Equal(t, `[1]`, string(withTags([]byte(`[1]`), json.RawMessage(`{}`))))
	require.Equal(t, `{"proxies":{}}`, string(withTags([]byte(`{"proxies":{}}`), nil)))
}
