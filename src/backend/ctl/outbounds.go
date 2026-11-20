package ctl

import (
	"cmp"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
)

// outboundWait bounds a test of an outbound with one URL: global_check has to come within the
// 20 s LuCI gives a call, and the tests run beside its other checks.
const outboundWait = 5 * time.Second

const (
	// groupSlots is how many URL tests the engine runs at once: its probeSlots, for the whole process,
	// so the rounds of all rules share them. A round itself takes ten at a time (urlTestConcurrency).
	groupSlots = 4
	// groupWaitMax is the most a delay test of the groups waits.
	groupWaitMax = 12 * time.Second
	// outboundsBudget is the most all the tests of the outbounds take, from the first request on: what
	// follows a round that used its whole wait gets only what is left of it. Of the 19 s the page asks
	// for, 4 s are left to the rest of the report: a sum of waits leaves that to chance, and an overrun
	// loses the whole report. Not measured on a slow router.
	outboundsBudget = 15 * time.Second
	// leastProxyTest is the least worth a test of what a rule goes through: with less left, it is not
	// made.
	leastProxyTest = time.Second
)

// clashProxy is an outbound as the Clash API lists it.
type clashProxy struct {
	Type string   `json:"type"`
	Now  string   `json:"now"`
	All  []string `json:"all"`
	// the end of All: a delay test of a URL test tests them too, but they are not its servers
	Fallbacks []string `json:"fallbacks"`
}

// directTag is the outbound of what goes without a proxy, blockTag the one a rule whose sources
// name no server now refuses with.
const (
	directTag = plan.DirectOutboundTag
	blockTag  = plan.BlockOutboundTag
)

// outboundLines tests the outbound of every rule that has one, and the direct one, with the check
// URLs links (oneOffURLs). A rule goes through the selector "<rule>-out" of its URL test, its
// servers and the URL tests of its fallbacks (plan/exits.go), and what the selector has chosen is
// tested: the URL test with a round of its own, the one server of the rule, or what is pinned on
// the dashboard, with the first URL and then the second (serverDelay). A test of the selector
// itself would test every server of every fallback with them. The direct one is tested with all
// the URLs at once (directDelay). The tests run at once.
func outboundLines(caller *clashCaller, config *model.Config, links []string) []string {
	deadline := time.Now().Add(outboundsBudget)
	_, content := caller.call(http.MethodGet, "/proxies", "", 10*time.Second)
	var listed struct {
		Proxies map[string]clashProxy `json:"proxies"`
	}
	if json.Unmarshal(content, &listed) != nil || len(listed.Proxies) == 0 {
		return []string{"❌ The outbounds could not be tested: the Clash API of podkop does not answer"}
	}
	type test struct {
		label, tag, kind string
		direct           bool
	}
	var tests []test
	var refused []string
	// the outbounds of a rule are those the backend that runs tells; without, those the
	// settings make
	tags := caller.tags()
	names := config.Names()
	for index := range config.Sections {
		section := &config.Sections[index]
		if !config.HasOutbound(section) {
			continue
		}
		outbounds := plan.RuleTags{Name: names.Rule(section.Name), Selector: plan.RuleOutbound(config, section.Name)}
		if tags != nil {
			outbounds = tags.Rules[section.Name]
		}
		proxy, found := listed.Proxies[outbounds.Selector]
		if !found {
			continue
		}
		if proxy.Now == blockTag {
			refused = append(refused, "⛔ "+outbounds.Name+": its sources name no server now, and its connections are refused")
			continue
		}
		item := test{label: outbounds.Name, tag: outbounds.Selector, kind: proxy.Type}
		var details []string
		if proxy.Type == "Selector" && proxy.Now != "" {
			item.tag, item.kind = proxy.Now, listed.Proxies[proxy.Now].Type
			// a selector of one outbound is a rule of one server: nothing is pinned
			if proxy.Now != outbounds.Test && proxy.Now != ruleTest(outbounds) && len(proxy.All) > 1 {
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
		tests = append(tests, test{label: "direct (without a proxy)", tag: directTag, kind: "Direct", direct: true})
	}
	// the rounds run at once and share the slots of the engine
	servers := 0
	for _, item := range tests {
		if item.kind == "URLTest" {
			servers += serversOfGroup(listed.Proxies, item.tag, map[string]bool{})
		}
	}
	wait := groupWait(servers)
	results := make([]string, len(tests))
	var tested sync.WaitGroup
	for index, item := range tests {
		tested.Add(1)
		go func() {
			defer tested.Done()
			switch {
			case item.kind == "URLTest":
				proxy := listed.Proxies[item.tag]
				results[index] = urlTestLine(caller, item.label, item.tag, proxy.All[:max(len(proxy.All)-len(proxy.Fallbacks), 0)], proxy.Fallbacks, links, wait, deadline)
			case item.direct:
				results[index] = directLine(caller, item.label, links, deadline)
			default:
				results[index] = proxyLine(caller, item.label, item.tag, links, deadline)
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

// ruleTest is the tag the URL test of a rule has when the backend did not tell it.
func ruleTest(outbounds plan.RuleTags) string {
	return strings.TrimSuffix(outbounds.Selector, "-out") + "-urltest-out"
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

// serversOfGroup counts the URL tests a delay test of a group makes: its members, its fallbacks
// among them, and those of the groups inside (protocol/group/urltest.go). A block is not tested.
func serversOfGroup(proxies map[string]clashProxy, tag string, seen map[string]bool) int {
	if seen[tag] {
		return 0
	}
	seen[tag] = true
	servers := 0
	for _, member := range proxies[tag].All {
		switch proxies[member].Type {
		case "Reject":
		case "URLTest", "Selector":
			servers += serversOfGroup(proxies, member, seen)
		default:
			servers++
		}
	}
	return servers
}

// groupWait is how long the delay test of the groups gets for so many servers. It is the deadline
// of the round in the engine and not only of the answer: at its end the tests under way are cut,
// and those that have no slot yet never run. A server without TCP holds a slot for outboundWait
// (one that connects and stays silent, up to 15 s); a round that ends sooner answers sooner.
func groupWait(servers int) time.Duration {
	rounds := max((servers+groupSlots-1)/groupSlots, 1)
	return min(time.Duration(rounds)*outboundWait, groupWaitMax)
}

// proxyLine tests one outbound with the first check URL and then the second (serverDelay): "✅ main:
// 123 ms", "✅ main: 123 ms with cp.cloudflare.com; www.gstatic.com did not answer through it".
func proxyLine(caller *clashCaller, label string, tag string, links []string, deadline time.Time) string {
	result := serverDelay(caller, tag, links, outboundWait, deadline)
	if result.Delay > 0 {
		return "✅ " + label + ": " + result.text()
	}
	return "❌ " + label + ": does not work (" + result.why() + ")"
}

// directLine tests what goes without a proxy with all the check URLs at once (directDelay): "✅
// direct (without a proxy): 45 ms, the median of 5 check URLs". The URLs that do not answer
// without a proxy are named: the provider may block them, and the line is a warning.
func directLine(caller *clashCaller, label string, links []string, deadline time.Time) string {
	result := directDelay(caller, links, outboundWait, deadline)
	switch {
	case len(links) == 1 && result.Delay > 0:
		return "✅ " + label + ": " + strconv.Itoa(result.Delay) + " ms"
	case len(links) == 1:
		return "❌ " + label + ": does not work (" + result.why() + ")"
	case result.Delay == 0:
		return "❌ " + label + ": none of the " + strconv.Itoa(len(links)) + " check URLs answers (" + cmp.Or(result.Message, "no answer") + "): check the router's internet and DNS"
	}
	text := strconv.Itoa(result.Delay) + " ms, the median of " + strconv.Itoa(len(result.URLs)) + " check URLs"
	if len(result.URLs) == 1 {
		text = strconv.Itoa(result.Delay) + " ms with " + hostOf(result.URLs[0])
	}
	if len(result.Silent) == 0 {
		return "✅ " + label + ": " + text
	}
	return "⚠️ " + label + ": " + text + "; no answer without a proxy from " + hostsOf(result.Silent) + ": the provider may block " + words(len(result.Silent) == 1, "it", "them")
}

// urlTestLine tells of the servers of a URL test, the fastest first. sing-box tests its fallbacks
// too and answers their delays with them, these are not counted; it answers nothing while a round
// of the test is under way: when no server of the test has a delay, what it goes through then is
// tested, a server of it or a fallback. The servers that gave no delay are named after those that
// did. The answer holds only those that passed: one whose test failed, one whose test the deadline
// cut and one that never got a slot look alike, and the slots are shared with the rounds of other
// rules, so it is "no answer in time" for all of them. Nothing here goes past deadline: what it goes
// through is tested with what is left, not at all when too little is. The round tests with the
// check URLs of the URL test itself, in turn, and takes no URL of the Clash API; the first of links
// is given all the same. What it goes through is tested as one outbound (outboundDelay).
func urlTestLine(caller *clashCaller, label string, tag string, members []string, fallbacks []string, links []string, wait time.Duration, deadline time.Time) string {
	_, content := caller.call(http.MethodGet, "/group/"+url.PathEscape(tag)+"/delay?"+delayQuery(links[0], wait), "", min(wait+answerSlack, time.Until(deadline)))
	delays := map[string]int{}
	_ = json.Unmarshal(content, &delays)
	answering := make([]string, 0, len(members))
	for _, member := range members {
		if delays[member] > 0 {
			answering = append(answering, member)
		}
	}
	if len(answering) > 0 {
		sort.Slice(answering, func(left int, right int) bool { return delays[answering[left]] < delays[answering[right]] })
		var answered []string
		for _, member := range answering {
			answered = append(answered, member+" "+strconv.Itoa(delays[member])+" ms")
		}
		line := "✅ " + label + ": " + strings.Join(answered, ", ")
		var silent []string
		for _, member := range members {
			if delays[member] <= 0 {
				silent = append(silent, member)
			}
		}
		if len(silent) > 0 {
			line += " (" + strconv.Itoa(len(answering)) + " of " + strconv.Itoa(len(answering)+len(silent)) + " answer; no answer in time: " + strings.Join(silent, ", ") + ")"
		}
		return line
	}
	none := "❌ " + label + ": none of its servers answers in time"
	if time.Until(deadline) < leastProxyTest {
		return none
	}
	_, content = caller.call(http.MethodGet, "/proxies/"+url.PathEscape(tag), "", min(outboundWait, time.Until(deadline)))
	var group struct {
		Now string `json:"now"`
	}
	if json.Unmarshal(content, &group) != nil || group.Now == "" {
		return none
	}
	if group.Now == blockTag {
		return none + "; its fallback block refuses its connections"
	}
	if time.Until(deadline) < leastProxyTest {
		return none
	}
	result := outboundDelay(caller, group.Now, links, outboundWait, deadline)
	fallback := slices.Contains(fallbacks, group.Now)
	switch {
	case fallback && result.Delay > 0:
		return "⚠️ " + label + ": none of its servers answers in time; it goes through the fallback " + group.Now + " now: " + result.text()
	case fallback:
		return none + ", nor the fallback " + group.Now + " it goes through now (" + result.why() + ")"
	case result.Delay > 0:
		return "✅ " + label + ": it goes through " + group.Now + " now: " + result.text()
	}
	return "❌ " + label + ": " + group.Now + ", which it goes through now, does not work (" + result.why() + ")"
}
