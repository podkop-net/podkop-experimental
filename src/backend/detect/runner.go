package detect

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

// The addresses a probe asks for through the server. Plain HTTP on purpose: nothing of the
// limit is spent on a TLS inside, and the raw bytes are the yardstick of the band.
const (
	ProbeTarget       = "http://speed.cloudflare.com/__down?bytes=64000"
	ProbeSecondTarget = "http://www.gstatic.com/generate_204"
)

// Budget is how long the probe of one server may take at most. The steps below add up to less on
// every path; it bounds a step that does not keep to its time.
const Budget = 90 * time.Second

const (
	tcpTimeout    = 5 * time.Second
	singleTimeout = 12 * time.Second
	burstTimeout  = 15 * time.Second
	burstSize     = 8
	// pooled connections are asked one after another, each through outbounds of its own
	pooledRequests = 3
	// how many other servers are asked at most
	relayCandidates = 2
)

// uplinkAddresses are asked to tell a router without internet from a server without an answer.
var uplinkAddresses = []string{"1.1.1.1:443", "8.8.8.8:443"}

// ProbeRequest is one request of a probe through a throw-away copy of a server's outbound, its
// uTLS fallback off and no record of it kept: what it sends is what is asked for.
type ProbeRequest struct {
	// Fingerprint replaces the one of the server, when it has uTLS.
	Fingerprint string
	// Detour is the outbound the copy dials through.
	Detour string
	// URL is what is asked for; none: only the dial, which is the handshake for most protocols.
	URL string
}

// Prober is what a probe needs of the engine, kept apart so that the daemon and a stand run the
// same runner. A method keeps to the context it is given.
type Prober interface {
	// TCP connects to the server through the dialer of its outbound, and tells what it met.
	TCP(ctx context.Context, server Server) ErrorClass
	// Fetch makes one request through a throw-away copy of the server's outbound.
	Fetch(ctx context.Context, server Server, request ProbeRequest) Attempt
	// Control makes one request through the outbound of the tag as it runs.
	Control(ctx context.Context, tag string, url string) Attempt
	// Reachable connects to an address past every proxy, as direct connections of the router go.
	Reachable(ctx context.Context, address string) bool
}

// RunOptions are what a probe knows of the configuration.
type RunOptions struct {
	// Fallback tells that the uTLS fallback of the configuration is on.
	Fallback bool
	// Relays are the servers to ask through, the first ones first (RelayCandidates).
	Relays []Server
}

// Run probes a server and names its block. It sends real connections, a burst among them, which
// may freeze the server for a while: it runs on demand only.
func Run(ctx context.Context, prober Prober, server Server, options RunOptions) Verdict {
	policy := DefaultPolicy
	stages := &Stages{Kind: server.Kind, Fallback: options.Fallback, Reality: server.Reality, LazyDial: server.LazyDial, UpgradeInDial: server.UpgradeInDial,
		Framed: server.Framed, DownloadLeg: server.DownloadLeg}
	if server.Fingerprint != "" {
		stages.Fingerprint = ProbeFingerprint(server.Fingerprint)
		stages.Alternate = AlternateFingerprint(stages.Fingerprint)
		stages.StandIn = stages.Fingerprint != server.Fingerprint
	}
	for {
		verdict, step := ClassifyStages(stages, policy)
		if step == StepDone {
			return verdict
		}
		runStep(ctx, prober, server, options, stages, step)
		if ctx.Err() != nil {
			// what an attempt cut by the budget met says nothing of the server
			return inconclusive("the probe ran out of time")
		}
	}
}

func runStep(ctx context.Context, prober Prober, server Server, options RunOptions, stages *Stages, step Step) {
	switch step {
	case StepTCP:
		attemptCtx, cancel := context.WithTimeout(ctx, tcpTimeout)
		defer cancel()
		class := prober.TCP(attemptCtx, server)
		stages.TCP = &class
	case StepSingle:
		attempt := fetchWithin(ctx, prober, server, ProbeRequest{Fingerprint: stages.Fingerprint, URL: ProbeTarget}, singleTimeout)
		stages.Single = &attempt
	case StepSecond:
		attempt := fetchWithin(ctx, prober, server, ProbeRequest{Fingerprint: stages.Fingerprint, URL: ProbeSecondTarget}, singleTimeout)
		stages.Second = &attempt
	case StepBurst:
		if stages.Kind == KindPooled {
			stages.Burst = make([]Attempt, 0, pooledRequests)
			for range pooledRequests {
				stages.Burst = append(stages.Burst, fetchWithin(ctx, prober, server, ProbeRequest{Fingerprint: stages.Fingerprint, URL: ProbeTarget}, singleTimeout))
			}
			return
		}
		stages.Burst = burst(ctx, prober, server, stages.Fingerprint)
	case StepAlternateBurst:
		stages.AlternateBurst = burst(ctx, prober, server, stages.Alternate)
	case StepAlternateSingle:
		attempt := fetchWithin(ctx, prober, server, ProbeRequest{Fingerprint: stages.Alternate, URL: ProbeTarget}, singleTimeout)
		stages.AlternateSingle = &attempt
	case StepUplink:
		up := uplinkUp(ctx, prober)
		stages.Uplink = &up
	case StepRelay:
		// without TLS (ServerName is set exactly with it) what goes through a relay is the secret of
		// the server in the clear, in the hands of another operator: the base verdict stands
		result := RelayResult{}
		if server.ServerName != "" {
			result = relay(ctx, prober, server, stages.Fingerprint, options.Relays)
		}
		stages.Relay = &result
	case StepControl:
		attemptCtx, cancel := context.WithTimeout(ctx, singleTimeout)
		defer cancel()
		attempt := prober.Control(attemptCtx, server.Tag, ProbeSecondTarget)
		stages.Control = &attempt
	}
}

func fetchWithin(ctx context.Context, prober Prober, server Server, request ProbeRequest, timeout time.Duration) Attempt {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return prober.Fetch(ctx, server, request)
}

// burst makes the requests of a burst at once.
func burst(ctx context.Context, prober Prober, server Server, fingerprint string) []Attempt {
	ctx, cancel := context.WithTimeout(ctx, burstTimeout)
	defer cancel()
	attempts := make([]Attempt, burstSize)
	var group sync.WaitGroup
	for index := range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			// these goroutines are out of reach of the worker's guard: a fault in what a server
			// sent is one attempt that came to nothing, not the end of the backend
			defer func() {
				if recover() != nil {
					attempts[index] = Attempt{Class: ClassOther}
				}
			}()
			attempts[index] = prober.Fetch(ctx, server, ProbeRequest{Fingerprint: fingerprint, URL: ProbeTarget})
		}()
	}
	group.Wait()
	return attempts
}

func uplinkUp(ctx context.Context, prober Prober) bool {
	for _, address := range uplinkAddresses {
		attemptCtx, cancel := context.WithTimeout(ctx, tcpTimeout)
		up := prober.Reachable(attemptCtx, address)
		cancel()
		if up {
			return true
		}
	}
	return false
}

// relay asks the server through other ones. Only an answer of the server proves anything: most
// protocols dial lazily, so a connection through B says nothing of A, and a request of a pooled
// transport is the one thing that goes out. First each candidate carries a request of its own, or
// its silence would say nothing of A.
func relay(ctx context.Context, prober Prober, server Server, fingerprint string, relays []Server) RelayResult {
	var result RelayResult
	for _, candidate := range relays[:min(len(relays), relayCandidates)] {
		controlCtx, cancel := context.WithTimeout(ctx, singleTimeout)
		control := prober.Control(controlCtx, candidate.Tag, ProbeSecondTarget)
		cancel()
		if control.Bytes == 0 {
			continue
		}
		request := ProbeRequest{Fingerprint: fingerprint, Detour: candidate.Tag}
		if server.Kind == KindPooled {
			request.URL = ProbeTarget
		}
		attempt := fetchWithin(ctx, prober, server, request, singleTimeout)
		// a verification that failed is an answer of the server as well
		if attempt.Bytes > 0 || (attempt.Handshake && request.URL == "") || attempt.Class == ClassVerify || attempt.Class == ClassClock {
			result.Proven = true
			return result
		}
		// only what reached out and got no answer says that A is silent: a copy that could not be
		// built, or a detour it refuses, never asked A
		switch attempt.Class {
		case ClassNoTCP, ClassNoHello, ClassCut:
			result.Tested++
		}
	}
	return result
}

// RelayCandidates are the servers a probe of server may ask through: those works tells of, with
// no detour of their own, of another host. Servers of the same source go first: the operator of a
// relay sees the address of the server.
func RelayCandidates(server Server, servers []Server, works func(Server) bool) []Server {
	var candidates []Server
	host := hostOf(server.Destination)
	for _, candidate := range servers {
		if candidate.Tag == server.Tag || candidate.Kind == KindNone || candidate.Detour != "" ||
			hostOf(candidate.Destination) == host || !works(candidate) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	source := sourceOf(server.Tag)
	slices.SortStableFunc(candidates, func(left, right Server) int {
		return rank(left.Tag, source) - rank(right.Tag, source)
	})
	return candidates
}

func rank(tag string, source string) int {
	if sourceOf(tag) == source {
		return 0
	}
	return 1
}

// sourceOf is the source of a server by its tag, "<source>: <name>" (plan.numberedTags).
func sourceOf(tag string) string {
	source, _, found := strings.Cut(tag, ": ")
	if !found {
		return tag
	}
	return source
}

func hostOf(destination string) string {
	host, _, err := net.SplitHostPort(destination)
	if err != nil {
		return destination
	}
	return host
}

// ProbeFingerprint is the fingerprint a probe sends for the one configured: as it is, or chrome
// for one a freeze says nothing of. A classic one has no key share to freeze, and random is a
// choice of the process the probe cannot name.
func ProbeFingerprint(configured string) string {
	switch configured {
	case "", "edge", "ios", "qq", "360", "android", "random", "randomized":
		return "chrome"
	}
	return configured
}

// AlternateFingerprint is the one compared with the fingerprint probed.
func AlternateFingerprint(fingerprint string) string {
	if fingerprint == "firefox" {
		return "chrome"
	}
	return "firefox"
}

// Report is the answer of the method detect of the backend: the verdicts by tag, passive ones with
// active ones over them while those hold; a server with nothing to say has no entry.
type Report struct {
	Verdicts map[string]Verdict `json:"verdicts"`
	// Servers is the stable id, the way (via) and the applied cure of every live server, by tag
	// and parallel to Verdicts: a server with a stored cure has an entry even with no verdict, so
	// the dashboard shows its treatment badge, and the page joins a tag to its stable id here.
	Servers map[string]Identity `json:"servers,omitempty"`
	// StaleCures counts the stored treatments that name no live server, and the rows this build
	// cannot read; the dashboard offers to remove them (drop_stale_cures)
	StaleCures int `json:"stale_cures,omitempty"`
	// Probing is the server a probe runs on now, Queued those waiting.
	Probing string   `json:"probing"`
	Queued  []string `json:"queued"`
	// NoProbe are the servers a probe does not apply to.
	NoProbe []string `json:"noprobe"`
	// Fallback tells that the uTLS fallback of the configuration is on.
	Fallback bool `json:"fallback"`
}

// The states of an answer of the method force_detect.
const (
	ForceStarted    = "started"
	ForceQueued     = "queued"
	ForceRunning    = "running"
	ForceThrottled  = "throttled"
	ForceUnknown    = "unknown"
	ForceNotRunning = "not_running"
	ForceCanceled   = "canceled"
)

// ForceAnswer is the answer of the method force_detect.
type ForceAnswer struct {
	State string `json:"state"`
	// RetryAfter is how many seconds a server throttled has to wait.
	RetryAfter int `json:"retry_after,omitempty"`
}
