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
)

// outboundWait bounds the test of an outbound: global_check has to come within the 20 s
// LuCI gives a call, and the tests run beside its other checks.
const outboundWait = 5 * time.Second

// directTag is the outbound of what goes without a proxy (plan: tagDirectOutbound), blockTag
// the one a section of the type group whose group has no server refuses with (tagBlockOutbound).
const (
	directTag = "direct-out"
	blockTag  = "block"
)

// outboundLines tests the outbound of every section that has one, and the direct one, as
// the dashboard of the page does: the delay of a request through it to delayTestURL; for a
// group (urltest, selector) that of each member. The tests run at once.
func outboundLines(caller *clashCaller, sections []model.Section) []string {
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
		label, via, tag, kind, now string
		members                    int
	}
	var tests []test
	var refused []string
	for _, section := range sections {
		if section.ConnectionType == "block" || section.ConnectionType == "exclusion" {
			continue
		}
		tag := section.Name + "-out"
		proxy, found := listed.Proxies[tag]
		if !found || section.ConnectionType == "group" && proxy.Now == blockTag {
			if section.ConnectionType == "group" {
				refused = append(refused, "⛔ "+section.Name+": its group chooses no server, and its connections are refused")
			}
			continue
		}
		// a section that connects through another one says so: its test goes through that one
		via := ""
		if section.ConnectionType == "proxy" && section.Detour != "" {
			via = "via " + section.Detour
		}
		tests = append(tests, test{label: section.Name, via: via, tag: tag, kind: proxy.Type, now: proxy.Now, members: len(proxy.All)})
	}
	if _, found := listed.Proxies[directTag]; found {
		tests = append(tests, test{label: "direct (without a proxy)", tag: directTag, kind: "Direct"})
	}
	results := make([]string, len(tests))
	var tested sync.WaitGroup
	for index, item := range tests {
		tested.Add(1)
		go func() {
			defer tested.Done()
			if item.kind == "Selector" || item.kind == "URLTest" {
				results[index] = groupLine(caller, item.label, item.via, item.tag, item.kind, item.now, item.members)
			} else {
				results[index] = proxyLine(caller, named(item.label, item.via), item.tag)
			}
		}()
	}
	tested.Wait()
	results = append(results, refused...)
	if len(results) == 0 {
		return []string{"⚠️ No section has an outbound"}
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

// proxyLine tests one outbound: "✅ main: 123 ms", "✅ main (via entry): 180 ms".
func proxyLine(caller *clashCaller, label string, tag string) string {
	_, content := caller.call(http.MethodGet, "/proxies/"+url.PathEscape(tag)+"/delay?"+delayQuery(), "", outboundWait+3*time.Second)
	var answer struct {
		Delay   int    `json:"delay"`
		Message string `json:"message"`
	}
	if json.Unmarshal(content, &answer) == nil && answer.Delay > 0 {
		return "✅ " + label + ": " + strconv.Itoa(answer.Delay) + " ms"
	}
	reason := "no answer within " + strconv.Itoa(int(outboundWait.Seconds())) + " s"
	if answer.Message != "" {
		reason = answer.Message
	}
	return "❌ " + label + ": does not work (" + reason + ")"
}

// groupLine tests the members of a group: of an urltest the fastest and how many answer,
// of a selector the one chosen.
func groupLine(caller *clashCaller, label string, via string, tag string, kind string, now string, members int) string {
	_, content := caller.call(http.MethodGet, "/group/"+url.PathEscape(tag)+"/delay?"+delayQuery(), "", outboundWait+3*time.Second)
	delays := map[string]int{}
	_ = json.Unmarshal(content, &delays)
	answering := make([]string, 0, len(delays))
	for member, delay := range delays {
		if delay > 0 {
			answering = append(answering, member)
		}
	}
	sort.Slice(answering, func(left int, right int) bool { return delays[answering[left]] < delays[answering[right]] })
	if kind == "Selector" {
		if delay := delays[now]; delay > 0 {
			return "✅ " + named(label, via, "selector", now) + ": " + strconv.Itoa(delay) + " ms"
		}
		return "❌ " + named(label, via, "selector", now) + ": does not work; " + strconv.Itoa(len(answering)) + " of its outbounds answer"
	}
	if len(answering) == 0 {
		return "❌ " + named(label, via, "urltest") + ": none of its outbounds answers"
	}
	var answered []string
	for _, member := range answering {
		answered = append(answered, member+" "+strconv.Itoa(delays[member])+" ms")
	}
	line := "✅ " + named(label, via, "urltest") + ": " + strings.Join(answered, ", ")
	if len(answering) < members {
		line += " (" + strconv.Itoa(len(answering)) + " of " + strconv.Itoa(members) + " answer)"
	}
	return line
}
