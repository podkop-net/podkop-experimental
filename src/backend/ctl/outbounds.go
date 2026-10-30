package ctl

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
)

// outboundWait bounds the test of an outbound: global_check has to come within the 20 s
// LuCI gives a call, and the tests run beside its other checks.
const outboundWait = 5 * time.Second

// directTag is the outbound of what goes without a proxy, blockTag the one a rule whose sources
// name no server now refuses with.
const (
	directTag = plan.DirectOutboundTag
	blockTag  = plan.BlockOutboundTag
)

// outboundLines tests the outbound of every rule that has one, and the direct one, as the
// dashboard of the page does: the delay of a request through it to delayTestURL. A rule goes
// through the selector "<rule>-out" of its URL test, its servers and the URL tests of its
// fallbacks (plan/exits.go), and what the selector has chosen is tested: the URL test with its
// own servers, the one server of the rule, or what is pinned on the dashboard. A test of the
// selector itself would test every server of every fallback with them. The tests run at once.
func outboundLines(caller *clashCaller, config *model.Config) []string {
	_, content := caller.call(http.MethodGet, "/proxies", "", 10*time.Second)
	var listed struct {
		Proxies map[string]struct {
			Type string   `json:"type"`
			Now  string   `json:"now"`
			All  []string `json:"all"`
		} `json:"proxies"`
	}
	if json.Unmarshal(content, &listed) != nil || len(listed.Proxies) == 0 {
		return []string{"❌ The outbounds could not be tested: the Clash API of podkop does not answer"}
	}
	type test struct {
		label, tag, kind string
	}
	var tests []test
	var refused []string
	for index := range config.Sections {
		section := &config.Sections[index]
		if !config.HasOutbound(section) {
			continue
		}
		tag := section.Name + "-out"
		proxy, found := listed.Proxies[tag]
		if !found {
			continue
		}
		if proxy.Now == blockTag {
			refused = append(refused, "⛔ "+section.Name+": its sources name no server now, and its connections are refused")
			continue
		}
		item := test{label: section.Name, tag: tag, kind: proxy.Type}
		var details []string
		if proxy.Type == "Selector" && proxy.Now != "" {
			item.tag, item.kind = proxy.Now, listed.Proxies[proxy.Now].Type
			// a selector of one outbound is a rule of one server: nothing is pinned
			if proxy.Now != section.Name+"-urltest-out" && len(proxy.All) > 1 {
				details = append(details, "pinned "+proxy.Now)
			}
		}
		if item.kind == "URLTest" {
			details = append(details, "urltest")
		}
		item.label = named(item.label, details...)
		tests = append(tests, item)
	}
	if _, found := listed.Proxies[directTag]; found {
		tests = append(tests, test{label: "direct (without a proxy)", tag: directTag, kind: "Direct"})
	}
	// a fallback of a URL test: one of several servers, or direct
	fallback := func(tag string) bool {
		return tag == directTag || listed.Proxies[tag].Type == "URLTest"
	}
	results := make([]string, len(tests))
	var tested sync.WaitGroup
	for index, item := range tests {
		tested.Add(1)
		go func() {
			defer tested.Done()
			if item.kind == "URLTest" {
				results[index] = urlTestLine(caller, item.label, item.tag, fallback)
			} else {
				results[index] = proxyLine(caller, item.label, item.tag)
			}
		}()
	}
	tested.Wait()
	results = append(results, refused...)
	if len(results) == 0 {
		return []string{"⚠️ No rule has an outbound"}
	}
	return results
}

// named is a label with what is said of it in parentheses: "main (via entry, selector, main-2-out)".
func named(label string, details ...string) string {
	var said []string
	for _, detail := range details {
		if detail != "" {
			said = append(said, detail)
		}
	}
	if len(said) == 0 {
		return label
	}
	return label + " (" + strings.Join(said, ", ") + ")"
}

func delayQuery() string {
	return url.Values{"url": {delayTestURL}, "timeout": {strconv.Itoa(int(outboundWait.Milliseconds()))}}.Encode()
}

// proxyLine tests one outbound: "✅ main: 123 ms".
func proxyLine(caller *clashCaller, label string, tag string) string {
	delay, reason := proxyDelay(caller, tag)
	if delay > 0 {
		return "✅ " + label + ": " + strconv.Itoa(delay) + " ms"
	}
	return "❌ " + label + ": does not work (" + reason + ")"
}

// proxyDelay is the delay of a request through an outbound, or 0 and why there is none.
func proxyDelay(caller *clashCaller, tag string) (int, string) {
	_, content := caller.call(http.MethodGet, "/proxies/"+url.PathEscape(tag)+"/delay?"+delayQuery(), "", outboundWait+3*time.Second)
	var answer struct {
		Delay   int    `json:"delay"`
		Message string `json:"message"`
	}
	if json.Unmarshal(content, &answer) == nil && answer.Delay > 0 {
		return answer.Delay, ""
	}
	if answer.Message != "" {
		return 0, answer.Message
	}
	return 0, "no answer within " + strconv.Itoa(int(outboundWait.Seconds())) + " s"
}

// urlTestLine tests the servers of a URL test, not its fallbacks, the fastest first. sing-box
// answers the delays of the servers that answered, and nothing while a round of the test is
// under way: what the test goes through then is tested, a server of it or a fallback.
func urlTestLine(caller *clashCaller, label string, tag string, fallback func(tag string) bool) string {
	_, content := caller.call(http.MethodGet, "/group/"+url.PathEscape(tag)+"/delay?"+delayQuery(), "", outboundWait+3*time.Second)
	delays := map[string]int{}
	_ = json.Unmarshal(content, &delays)
	answering := make([]string, 0, len(delays))
	for member, delay := range delays {
		if delay > 0 {
			answering = append(answering, member)
		}
	}
	if len(answering) > 0 {
		sort.Slice(answering, func(left int, right int) bool { return delays[answering[left]] < delays[answering[right]] })
		var answered []string
		for _, member := range answering {
			answered = append(answered, member+" "+strconv.Itoa(delays[member])+" ms")
		}
		return "✅ " + label + ": " + strings.Join(answered, ", ")
	}
	none := "❌ " + label + ": none of its servers answers"
	_, content = caller.call(http.MethodGet, "/proxies/"+url.PathEscape(tag), "", outboundWait)
	var group struct {
		Now string `json:"now"`
	}
	if json.Unmarshal(content, &group) != nil || group.Now == "" {
		return none
	}
	if group.Now == blockTag {
		return none + "; its fallback block refuses its connections"
	}
	delay, reason := proxyDelay(caller, group.Now)
	switch {
	case fallback(group.Now) && delay > 0:
		return "⚠️ " + label + ": none of its servers answers; it goes through the fallback " + group.Now + " now: " + strconv.Itoa(delay) + " ms"
	case fallback(group.Now):
		return none + ", nor the fallback " + group.Now + " it goes through now (" + reason + ")"
	case delay > 0:
		return "✅ " + label + ": it goes through " + group.Now + " now: " + strconv.Itoa(delay) + " ms"
	}
	return "❌ " + label + ": " + group.Now + ", which it goes through now, does not work (" + reason + ")"
}
