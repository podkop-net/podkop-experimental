package ctl

import (
	"bytes"
	"cmp"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
)

// engineDefaultURL is the URL the engine tests a delay with when it is given none, or one of
// plain HTTP, which its Clash API takes for none (common/urltest, experimental/clashapi).
const engineDefaultURL = "https://www.gstatic.com/generate_204"

// testsAtOnce is how many servers a test of several tests at a time, each alone: as many as a
// round of a URL test of the engine (urlTestConcurrency).
const testsAtOnce = 10

// The waits of a test of one outbound by the commands; variables, so that the tests wait less.
var (
	// oneOffBudget is the most a test of one outbound takes, the second URL included: the page
	// cuts its call at 15 s (callBaseMethod.ts).
	oneOffBudget = groupWaitMax
	// answerSlack is how much longer than its test the answer of the Clash API is waited for.
	answerSlack = 3 * time.Second
)

// checkURLs are the URLs the servers are checked with: the list of the URL tests of the
// configuration that runs (every URL test has the list of the settings, plan/exits.go), else
// the list of the settings, else (settings that cannot be read) the default one. The first two
// differ only after a list was applied and sing-box refused it, or its start failed: the rounds
// then go on with the list that runs. Changes LuCI has saved and not applied are in neither.
func checkURLs(configDir string, check model.Check) []string {
	if configDir != "" {
		if content, err := os.ReadFile(filepath.Join(configDir, api.RunningConfig)); err == nil {
			var running struct {
				Outbounds []struct {
					Type string   `json:"type"`
					URLs []string `json:"urls"`
				} `json:"outbounds"`
			}
			if json.Unmarshal(content, &running) == nil {
				for _, outbound := range running.Outbounds {
					if outbound.Type == "urltest" && len(outbound.URLs) > 0 {
						return outbound.URLs
					}
				}
			}
		}
	}
	if len(check.TestingURLs) == 0 {
		return model.DefaultTestingURLs
	}
	return check.TestingURLs
}

// oneOffURLs are the check URLs a test of one outbound by the commands takes, in their order:
// those of HTTPS only, because the Clash API tests with the URL of the engine in place of any
// http:// URL. That URL when none is left.
func oneOffURLs(links []string) []string {
	var kept []string
	for _, link := range links {
		link = strings.TrimSpace(link)
		parsed, err := url.Parse(link)
		if err == nil && parsed.Scheme == "https" && parsed.Host != "" && !slices.Contains(kept, link) {
			kept = append(kept, link)
		}
	}
	if len(kept) == 0 {
		return []string{engineDefaultURL}
	}
	return kept
}

// delayTry is what one test of an outbound with one URL came to: the delay, or why there is
// none, and whether the Clash API answered at all.
type delayTry struct {
	delay    int
	reason   string
	answered bool
}

// tryDelay tests an outbound with link: the engine tests for at most wait, and its answer is
// waited for no later than deadline.
func tryDelay(caller *clashCaller, tag string, link string, wait time.Duration, deadline time.Time) delayTry {
	_, content := caller.call(http.MethodGet, "/proxies/"+url.PathEscape(tag)+"/delay?"+delayQuery(link, wait), "", min(wait+answerSlack, time.Until(deadline)))
	var answer struct {
		Delay   int    `json:"delay"`
		Message string `json:"message"`
	}
	result := delayTry{answered: len(strings.TrimSpace(string(content))) > 0}
	if json.Unmarshal(content, &answer) == nil && answer.Delay > 0 {
		result.delay = answer.Delay
		return result
	}
	result.reason = cmp.Or(answer.Message, "no answer within "+strconv.Itoa(int(wait.Round(time.Second).Seconds()))+" s")
	return result
}

// delayQuery asks for a test with link for at most wait.
func delayQuery(link string, wait time.Duration) string {
	return url.Values{"url": {link}, "timeout": {strconv.Itoa(int(wait.Milliseconds()))}}.Encode()
}

// oneOff is what a test of one outbound by the commands came to, as get_proxy_latency prints it:
// the delay, or the reason there is none; the check URLs the delay is of, and those that did not
// answer through the outbound.
type oneOff struct {
	Delay   int      `json:"delay,omitempty"`
	Message string   `json:"message,omitempty"`
	URLs    []string `json:"urls,omitempty"`
	Silent  []string `json:"silent,omitempty"`
	// the Clash API answered a test, if only with an error
	answered bool
}

// serverDelay tests an outbound with the first of the check URLs and, when that does not answer
// through it, with the second, once: as a round of the server check does, where a server is
// unavailable when two URLs do not answer through it (retryLink of the engine). The tries go one
// after the other, never at once: parallel TLS handshakes through one REALITY server are known
// to make the DPI of some providers freeze its connections for about 40 s. Each try tests for at
// most try; neither goes past deadline, and the second is made only with leastProxyTest left and
// when the Clash API answered the first.
func serverDelay(caller *clashCaller, tag string, links []string, try time.Duration, deadline time.Time) oneOff {
	var result oneOff
	for index, link := range links[:min(len(links), 2)] {
		left := time.Until(deadline)
		if left <= 0 || (index > 0 && (left < leastProxyTest || !result.answered)) {
			break
		}
		got := tryDelay(caller, tag, link, min(try, left), deadline)
		result.answered = result.answered || got.answered
		if got.delay > 0 {
			result.Delay, result.Message, result.URLs = got.delay, "", []string{link}
			return result
		}
		result.Message = got.reason
		result.Silent = append(result.Silent, link)
	}
	return result
}

// directDelay tests the outbound without a proxy with all the check URLs at once: no server is
// in between, and the hosts are of different companies, so this is no burst through one. The
// delay is the median of those that answered, as the engine takes it of its rounds (the mean of
// the middle two of an even count, common/urltest). The reason, when none answered, is that of
// the first.
func directDelay(caller *clashCaller, links []string, try time.Duration, deadline time.Time) oneOff {
	tries := make([]delayTry, len(links))
	var tested sync.WaitGroup
	for index, link := range links {
		tested.Add(1)
		go func() {
			defer tested.Done()
			tries[index] = tryDelay(caller, directTag, link, min(try, time.Until(deadline)), deadline)
		}()
	}
	tested.Wait()
	var result oneOff
	var delays []int
	for index, got := range tries {
		result.answered = result.answered || got.answered
		if got.delay > 0 {
			delays = append(delays, got.delay)
			result.URLs = append(result.URLs, links[index])
			continue
		}
		result.Silent = append(result.Silent, links[index])
		result.Message = cmp.Or(result.Message, got.reason)
	}
	if len(delays) > 0 {
		result.Delay, result.Message = medianOf(delays), ""
	}
	return result
}

// medianOf is the median of delays as the engine takes it: of an even count, the mean of the
// middle two, rounded up.
func medianOf(delays []int) int {
	sorted := slices.Sorted(slices.Values(delays))
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle] + 1) / 2
}

// outboundDelay tests one outbound as the commands do: the outbound without a proxy with all the
// check URLs at once, any other with the first and then the second.
func outboundDelay(caller *clashCaller, tag string, links []string, try time.Duration, deadline time.Time) oneOff {
	if tag == directTag {
		return directDelay(caller, links, try, deadline)
	}
	return serverDelay(caller, tag, links, try, deadline)
}

// selectorDelays tests the choices of a selector without a URL test, each alone (serverDelay),
// testsAtOnce at a time: different servers, each with its tries one after the other. A group, a
// block and the direct outbound are left out. A choice that did not answer is 0, so that a
// reader does not take the answer for a group in a round of its own. It tells whether the Clash
// API answered.
func selectorDelays(caller *clashCaller, proxies map[string]clashProxy, choices []string, links []string, try time.Duration, deadline time.Time) (map[string]int, bool) {
	var servers []string
	for _, choice := range choices {
		switch proxies[choice].Type {
		case "Selector", "URLTest", "Direct", "Reject", "Block":
		default:
			servers = append(servers, choice)
		}
	}
	delays := make(map[string]int, len(servers))
	answered := len(servers) == 0
	var access sync.Mutex
	var tested sync.WaitGroup
	slots := make(chan struct{}, testsAtOnce)
	for _, server := range servers {
		tested.Add(1)
		go func() {
			defer tested.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			result := serverDelay(caller, server, links, try, deadline)
			access.Lock()
			delays[server] = result.Delay
			answered = answered || result.answered
			access.Unlock()
		}()
	}
	tested.Wait()
	return delays, answered
}

// hostOf names a check URL by its host: "www.gstatic.com".
func hostOf(link string) string {
	if parsed, err := url.Parse(link); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return link
}

func hostsOf(links []string) string {
	hosts := make([]string, 0, len(links))
	for _, link := range links {
		hosts = append(hosts, hostOf(link))
	}
	return strings.Join(hosts, ", ")
}

// text is the delay a test found, with the URL it is of when that was not the first: "120 ms",
// "120 ms with cp.cloudflare.com; www.gstatic.com did not answer through it".
func (r oneOff) text() string {
	text := strconv.Itoa(r.Delay) + " ms"
	if len(r.Silent) > 0 && len(r.URLs) == 1 {
		text += " with " + hostOf(r.URLs[0]) + "; " + hostsOf(r.Silent) + " did not answer through it"
	}
	return text
}

// why is the reason a test found no delay, with the URLs it tried: "Timeout; tried
// www.gstatic.com, cp.cloudflare.com".
func (r oneOff) why() string {
	reason := cmp.Or(r.Message, "no answer")
	if len(r.Silent) > 0 {
		reason += "; tried " + hostsOf(r.Silent)
	}
	return reason
}

// groupLatency is get_group_latency: what a test of the group tag finds of the delays of its
// servers. A selector of a rule with a URL test (plan/exits.go: the URL test, its servers and
// those of its fallbacks) is answered by a round of that URL test, as its own rounds go: each
// server with the check URL of the round and, when that does not answer, with the next one; the
// delay is the median of the server's last rounds, this one among them. The test of the selector
// by the engine would test its URL test and every server of it alone besides, all at once with
// the URL given (URLTestOutbounds), each server's delay being whichever of the two came last. A
// selector without a URL test (a rule of one server) has each of its choices tested alone
// (selectorDelays). Any other group is asked itself. The round ends at wait from now; a URL test
// already in a round of its own answers {} at once.
func groupLatency(caller *clashCaller, tag string, links []string, wait time.Duration) []byte {
	start := time.Now()
	deadline := start.Add(wait)
	_, content := caller.call(http.MethodGet, "/proxies", "", min(wait, 10*time.Second))
	var listed struct {
		Proxies map[string]clashProxy `json:"proxies"`
	}
	_ = json.Unmarshal(content, &listed)
	test := tag
	if proxy := listed.Proxies[tag]; proxy.Type == "Selector" {
		test = ""
		for _, choice := range proxy.All {
			if listed.Proxies[choice].Type == "URLTest" {
				test = choice
				break
			}
		}
		if test == "" {
			delays, answered := selectorDelays(caller, listed.Proxies, proxy.All, links, min(wait, outboundWait), start.Add(min(wait, oneOffBudget)))
			if !answered {
				return nil
			}
			return jsonText(delays)
		}
	}
	left := time.Until(deadline)
	if left <= 0 {
		return nil
	}
	_, content = caller.call(http.MethodGet, "/group/"+url.PathEscape(test)+"/delay?"+delayQuery(links[0], left), "", left+answerSlack)
	return content
}

// jsonText is a value as JSON, its text as it is, with no escapes for HTML (a URL keeps its &).
func jsonText(value any) []byte {
	var content bytes.Buffer
	encoder := json.NewEncoder(&content)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return nil
	}
	return content.Bytes()
}
