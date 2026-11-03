package detect

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeProber answers a probe from functions of the test and remembers what was asked.
type fakeProber struct {
	access    sync.Mutex
	tcp       ErrorClass
	fetch     func(server Server, request ProbeRequest) Attempt
	control   map[string]Attempt
	reachable bool
	requests  []ProbeRequest
	controls  []string
	uplinks   int
}

func (p *fakeProber) TCP(ctx context.Context, server Server) ErrorClass { return p.tcp }

func (p *fakeProber) Fetch(ctx context.Context, server Server, request ProbeRequest) Attempt {
	p.access.Lock()
	p.requests = append(p.requests, request)
	p.access.Unlock()
	return p.fetch(server, request)
}

func (p *fakeProber) Control(ctx context.Context, tag string, url string) Attempt {
	p.access.Lock()
	defer p.access.Unlock()
	p.controls = append(p.controls, tag)
	return p.control[tag]
}

func (p *fakeProber) Reachable(ctx context.Context, address string) bool {
	p.access.Lock()
	defer p.access.Unlock()
	p.uplinks++
	return p.reachable
}

// count is how many requests were made with a fingerprint, through a detour, of an address.
func (p *fakeProber) count(fingerprint string, detour string, url string) int {
	total := 0
	for _, request := range p.requests {
		if request.Fingerprint == fingerprint && request.Detour == detour && request.URL == url {
			total++
		}
	}
	return total
}

var (
	probeFull  = Attempt{Handshake: true, Bytes: 64400, Status: 200}
	probeCut   = Attempt{Handshake: true, Bytes: 18 << 10, Status: 200, Class: ClassNoHello}
	probeZero  = Attempt{Class: ClassNoHello}
	probeClose = Attempt{Handshake: true, Class: ClassCut}
	testA      = Server{Tag: "sub: a", Kind: KindFingerprint, Fingerprint: "chrome", ServerName: "a.example", Destination: "192.0.2.1:443"}
	relayOne   = Server{Tag: "sub: b", Kind: KindFingerprint, Fingerprint: "chrome", Destination: "192.0.2.2:443"}
	relayTwo   = Server{Tag: "sub: c", Kind: KindPlain, Destination: "192.0.2.3:443"}
	relayThree = Server{Tag: "sub: d", Kind: KindPlain, Destination: "192.0.2.4:443"}
)

func runAll(prober *fakeProber, server Server, fallback bool, relays ...Server) Verdict {
	ctx, cancel := context.WithTimeout(context.Background(), Budget)
	defer cancel()
	return Run(ctx, prober, server, RunOptions{Fallback: fallback, Relays: relays})
}

func always(attempt Attempt) func(Server, ProbeRequest) Attempt {
	return func(Server, ProbeRequest) Attempt { return attempt }
}

func TestRunHealthy(t *testing.T) {
	prober := &fakeProber{fetch: always(probeFull)}
	verdict := runAll(prober, testA, true)
	require.Equal(t, BlockNone, verdict.Block)
	require.Empty(t, verdict.Notes)
	require.Equal(t, 1+burstSize, prober.count("chrome", "", ProbeTarget))
	require.Len(t, prober.requests, 1+burstSize, "no firefox when the burst is full")
}

func TestRunStopsOnVerification(t *testing.T) {
	reality := testA
	reality.Reality = true
	for _, class := range []ErrorClass{ClassVerify, ClassClock} {
		prober := &fakeProber{fetch: always(Attempt{Class: class})}
		verdict := runAll(prober, reality, true, relayOne)
		require.Equal(t, BlockWrongParams, verdict.Block)
		require.NotContains(t, verdict.Notes, NoteTLSCert)
		require.Len(t, prober.requests, 1, "no burst after a verification that failed")
		require.Equal(t, []string{reality.Tag}, prober.controls, "one request through the running outbound, no relay")

		prober = &fakeProber{fetch: always(Attempt{Class: class})}
		require.Contains(t, runAll(prober, testA, true, relayOne).Notes, NoteTLSCert, "without REALITY it is a certificate")
	}
}

// A hello of the probe an old server refuses, while the running outbound passes: nothing is wrong
// with the settings. No burst here either.
func TestRunProbeHelloRefused(t *testing.T) {
	for _, class := range []ErrorClass{ClassVerify, ClassClock} {
		prober := &fakeProber{fetch: always(Attempt{Class: class}), control: map[string]Attempt{testA.Tag: {Handshake: true, Bytes: 200, Status: 204}}}
		verdict := runAll(prober, testA, true, relayOne)
		require.Equal(t, BlockUnknown, verdict.Block)
		require.Equal(t, []string{NoteProbeHelloRefused}, verdict.Notes)
		require.Len(t, prober.requests, 1)
		require.Equal(t, []string{testA.Tag}, prober.controls)
	}
	// the same after the alternate got as far
	prober := &fakeProber{control: map[string]Attempt{testA.Tag: {Handshake: true, Bytes: 200, Status: 204}}, fetch: func(server Server, request ProbeRequest) Attempt {
		if request.Fingerprint == "firefox" {
			return Attempt{Class: ClassVerify}
		}
		return probeZero
	}}
	verdict := runAll(prober, testA, true)
	require.Equal(t, []string{NoteProbeHelloRefused}, verdict.Notes)
	require.Len(t, prober.requests, 2)
}

// A pooled control may go over a live connection, which sends no hello: a certificate that changed
// under a warm pool is not "nothing needs changing".
func TestRunPooledControlProvesNothing(t *testing.T) {
	pooled := Server{Tag: "p", Kind: KindPooled, Fingerprint: "chrome", ServerName: "p.example", Destination: "192.0.2.5:443"}
	for _, class := range []ErrorClass{ClassVerify, ClassClock} {
		prober := &fakeProber{fetch: always(Attempt{Class: class}), control: map[string]Attempt{pooled.Tag: {Handshake: true, Bytes: 46, Status: 204}}}
		verdict := runAll(prober, pooled, true, relayOne)
		require.Equal(t, BlockUnknown, verdict.Block)
		require.Equal(t, []string{NoteInconclusive}, verdict.Notes)
		require.Equal(t, []string{pooled.Tag}, prober.controls)

		prober = &fakeProber{fetch: always(Attempt{Class: class})}
		require.Equal(t, BlockWrongParams, runAll(prober, pooled, true, relayOne).Block)
	}
}

// The running hello verified and the exit gave no answer: an old server with an ML-KEM cover, not a
// wrong key.
func TestRunControlHandshakeWithoutBytes(t *testing.T) {
	reality := testA
	reality.Reality = true
	prober := &fakeProber{fetch: always(Attempt{Class: ClassVerify}), control: map[string]Attempt{reality.Tag: {Handshake: true, Class: ClassCut}}}
	verdict := runAll(prober, reality, true, relayOne)
	require.Equal(t, BlockUnknown, verdict.Block)
	require.Equal(t, []string{NoteInconclusive}, verdict.Notes)
	require.Len(t, prober.requests, 1)
}

func TestRunFreezeUnderBurst(t *testing.T) {
	var access sync.Mutex
	chromes := 0
	prober := &fakeProber{fetch: func(server Server, request ProbeRequest) Attempt {
		if request.Fingerprint == "firefox" {
			return probeFull
		}
		access.Lock()
		defer access.Unlock()
		chromes++
		if chromes > 3 {
			return probeZero
		}
		return probeFull
	}}
	verdict := runAll(prober, testA, true)
	require.Equal(t, BlockFreeze, verdict.Block)
	require.Equal(t, []string{NoteCured}, verdict.Notes)
	require.Equal(t, "chrome", verdict.Fingerprint)
	require.Equal(t, burstSize, prober.count("firefox", "", ProbeTarget))
}

func TestRunFreezeAtOnce(t *testing.T) {
	prober := &fakeProber{fetch: func(server Server, request ProbeRequest) Attempt {
		if request.Fingerprint == "firefox" {
			return probeFull
		}
		return probeZero
	}}
	verdict := runAll(prober, testA, false, relayOne)
	require.Equal(t, BlockFreeze, verdict.Block)
	require.Equal(t, []string{NoteFallbackOff}, verdict.Notes)
	require.Len(t, prober.requests, 2, "a lone request each, no burst at a frozen server")
	require.Empty(t, prober.controls)
}

func TestRunLimit(t *testing.T) {
	prober := &fakeProber{fetch: always(probeCut)}
	verdict := runAll(prober, testA, true)
	require.Equal(t, BlockLimit, verdict.Block)
	require.Equal(t, int64(18), verdict.KB)
	require.Zero(t, prober.count("firefox", "", ProbeTarget))
}

func TestRunRejected(t *testing.T) {
	prober := &fakeProber{fetch: always(probeClose)}
	verdict := runAll(prober, testA, true)
	require.Equal(t, BlockRejected, verdict.Block)
	require.Equal(t, 1, prober.count("chrome", "", ProbeTarget))
	require.Equal(t, 1, prober.count("chrome", "", ProbeSecondTarget))
	require.Len(t, prober.requests, 2)
}

func TestRunTargetFailed(t *testing.T) {
	prober := &fakeProber{fetch: func(server Server, request ProbeRequest) Attempt {
		if request.URL == ProbeSecondTarget {
			return Attempt{Handshake: true, Bytes: 200, Status: 204}
		}
		return probeClose
	}}
	verdict := runAll(prober, testA, true)
	require.Equal(t, BlockUnknown, verdict.Block)
	require.Equal(t, []string{NoteTargetFailed}, verdict.Notes)
}

// An address of the check that refuses is asked about through the other one first.
func TestRunTargetStatus(t *testing.T) {
	answers := func(second Attempt) func(Server, ProbeRequest) Attempt {
		return func(server Server, request ProbeRequest) Attempt {
			if request.URL == ProbeSecondTarget {
				return second
			}
			return Attempt{Handshake: true, Bytes: 66, Status: 400}
		}
	}
	prober := &fakeProber{fetch: answers(Attempt{Handshake: true, Bytes: 200, Status: 204})}
	require.Equal(t, []string{NoteTargetFailed}, runAll(prober, testA, true).Notes)
	require.Len(t, prober.requests, 2)
	prober = &fakeProber{fetch: answers(Attempt{Handshake: true, Bytes: 66, Status: 400})}
	require.Equal(t, []string{NoteInconclusive}, runAll(prober, testA, true).Notes)
	require.Len(t, prober.requests, 2)
}

// A single in full and a burst in the band: a limit cuts every flow, so it is no limit.
func TestRunFullSingleIsNoLimit(t *testing.T) {
	var access sync.Mutex
	first := true
	prober := &fakeProber{fetch: func(Server, ProbeRequest) Attempt {
		access.Lock()
		defer access.Unlock()
		if first {
			first = false
			return probeFull
		}
		return probeCut
	}}
	verdict := runAll(prober, testA, true)
	require.Equal(t, BlockUnknown, verdict.Block)
	require.Equal(t, []string{NoteInconclusive}, verdict.Notes)
}

// A dial that sends nothing: a request closed may be a hello closed, and nothing more is asked.
func TestRunLazyDial(t *testing.T) {
	lazy := Server{Tag: "g", Kind: KindPooled, Fingerprint: "chrome", ServerName: "g.example", Destination: "192.0.2.5:443", LazyDial: true}
	prober := &fakeProber{fetch: always(probeClose)}
	verdict := runAll(prober, lazy, true, relayOne)
	require.Equal(t, BlockUnknown, verdict.Block)
	require.Equal(t, []string{NoteInconclusive}, verdict.Notes)
	require.Len(t, prober.requests, 1)
}

// A freeze of chrome that stands in for a fingerprint of the link: the fallback may not need to be
// turned on for it, and the note tells so.
func TestRunStandIn(t *testing.T) {
	server := testA
	server.Fingerprint = "edge"
	frozen := func(server Server, request ProbeRequest) Attempt {
		if request.Fingerprint == "firefox" {
			return probeFull
		}
		return probeZero
	}
	verdict := runAll(&fakeProber{fetch: frozen}, server, false)
	require.Equal(t, BlockFreeze, verdict.Block)
	require.Equal(t, "chrome", verdict.Fingerprint)
	require.Equal(t, []string{NoteStandIn}, verdict.Notes)
	require.ElementsMatch(t, []string{NoteStandIn, NoteCured}, runAll(&fakeProber{fetch: frozen}, server, true).Notes)
	server.Fingerprint = "chrome"
	require.Equal(t, []string{NoteFallbackOff}, runAll(&fakeProber{fetch: frozen}, server, false).Notes)
}

// ws or httpupgrade over TLS: the silence may be of the upgrade.
func TestRunUpgradeInDial(t *testing.T) {
	server := Server{Tag: "w", Kind: KindTLS, ServerName: "w.example", Destination: "192.0.2.5:443", UpgradeInDial: true}
	verdict := runAll(&fakeProber{fetch: always(probeZero)}, server, true)
	require.Equal(t, BlockHelloDrop, verdict.Block)
	require.Equal(t, []string{NoteUpgradeInDial}, verdict.Notes)
}

// A fingerprint configured that a freeze says nothing of: chrome goes out in its place, and
// firefox is what it is compared with; a configured firefox is compared with chrome.
func TestRunFingerprints(t *testing.T) {
	server := testA
	server.Fingerprint = "edge"
	prober := &fakeProber{fetch: always(probeFull)}
	runAll(prober, server, true)
	require.Equal(t, 1+burstSize, prober.count("chrome", "", ProbeTarget))

	server.Fingerprint = "firefox"
	prober = &fakeProber{fetch: func(server Server, request ProbeRequest) Attempt {
		if request.Fingerprint == "chrome" {
			return probeFull
		}
		return probeZero
	}}
	verdict := runAll(prober, server, true)
	require.Equal(t, BlockFreeze, verdict.Block)
	require.Equal(t, "firefox", verdict.Fingerprint)
}

// What a server without a burst of ClientHellos, or without any, gets.
func TestRunKinds(t *testing.T) {
	pooled := Server{Tag: "p", Kind: KindPooled, Fingerprint: "chrome", Destination: "192.0.2.5:443"}
	prober := &fakeProber{fetch: always(probeFull)}
	require.Equal(t, BlockNone, runAll(prober, pooled, true).Block)
	require.Len(t, prober.requests, 1+pooledRequests)

	// a limit near the end of the band: what comes through after TLS and the frames of the transport
	framed := pooled
	framed.Framed = true
	prober = &fakeProber{fetch: always(Attempt{Handshake: true, Bytes: 6 << 10, Status: 200, Class: ClassNoHello})}
	verdict := runAll(prober, framed, true)
	require.Equal(t, BlockLimit, verdict.Block, verdict.Why)
	require.EqualValues(t, 6, verdict.KB)
	require.Len(t, prober.requests, 1+pooledRequests, "one after another, no other fingerprint")
	require.Zero(t, prober.count("firefox", "", ProbeTarget))

	// multiplex is pooled, but a probe goes without it: nothing to widen the band for
	prober = &fakeProber{fetch: always(Attempt{Handshake: true, Bytes: 6 << 10, Status: 200, Class: ClassNoHello})}
	verdict = runAll(prober, pooled, true)
	require.Equal(t, BlockUnknown, verdict.Block, verdict.Why)
	require.Contains(t, verdict.Notes, NoteInconclusive)

	// no answer on a transport whose download has a leg of its own: no relay is asked
	split := pooled
	split.Fingerprint, split.DownloadLeg = "", true
	prober = &fakeProber{reachable: true, fetch: always(Attempt{Class: ClassNoHello}), control: map[string]Attempt{relayOne.Tag: probeFull}}
	verdict = runAll(prober, split, true, relayOne)
	require.Equal(t, BlockUnknown, verdict.Block, verdict.Why)
	require.Contains(t, verdict.Notes, NoteInconclusive)
	require.Len(t, prober.requests, 1)

	udp := Server{Tag: "u", Kind: KindUDP, Destination: "192.0.2.6:443"}
	prober = &fakeProber{tcp: ClassNoTCP, fetch: always(probeFull)}
	require.Equal(t, BlockNone, runAll(prober, udp, true).Block, "UDP asks nothing of TCP")
	require.Len(t, prober.requests, 1)

	via := Server{Tag: "v", Kind: KindNone, Destination: "192.0.2.7:443"}
	prober = &fakeProber{fetch: always(probeFull)}
	verdict = runAll(prober, via, true)
	require.Equal(t, BlockUnknown, verdict.Block)
	require.Equal(t, []string{NoteNotApplicable}, verdict.Notes)
	require.Empty(t, prober.requests)

	plain := Server{Tag: "s", Kind: KindPlain, Destination: "192.0.2.8:443"}
	prober = &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{relayOne.Tag: probeFull}}
	require.Equal(t, BlockUnreachable, runAll(prober, plain, true, relayOne).Block)
	require.Empty(t, prober.controls, "nothing through a relay can prove a server without TLS")
}

func TestRunRelay(t *testing.T) {
	proof := func(detourAnswers Attempt) func(Server, ProbeRequest) Attempt {
		return func(server Server, request ProbeRequest) Attempt {
			if request.Detour != "" {
				return detourAnswers
			}
			return probeZero
		}
	}
	t.Run("uplink down ends it", func(t *testing.T) {
		prober := &fakeProber{tcp: ClassNoTCP, reachable: false, control: map[string]Attempt{relayOne.Tag: probeFull}}
		verdict := runAll(prober, testA, true, relayOne)
		require.Equal(t, BlockUnreachable, verdict.Block)
		require.Equal(t, []string{NoteUplinkDown}, verdict.Notes)
		require.Equal(t, len(uplinkAddresses), prober.uplinks)
		require.Empty(t, prober.controls)
	})
	t.Run("the name does not resolve", func(t *testing.T) {
		prober := &fakeProber{tcp: ClassDNS, reachable: true}
		verdict := runAll(prober, testA, true, relayOne)
		require.Equal(t, BlockUnreachable, verdict.Block)
		require.Equal(t, []string{NoteDNSFailed}, verdict.Notes)
		require.Equal(t, 1, prober.uplinks, "the uplink is asked first")
		require.Empty(t, prober.controls)
	})
	// an outage silences the resolver too: the verdict tells of the router, and is over in minutes
	t.Run("the name does not resolve, the uplink is down", func(t *testing.T) {
		prober := &fakeProber{tcp: ClassDNS, reachable: false}
		verdict := runAll(prober, testA, true, relayOne)
		require.Equal(t, BlockUnreachable, verdict.Block)
		require.Equal(t, []string{NoteUplinkDown}, verdict.Notes)
		require.Equal(t, len(uplinkAddresses), prober.uplinks)
		require.Empty(t, prober.controls)
		require.Empty(t, prober.requests)
	})
	t.Run("the name does not resolve for the dial, the uplink is down", func(t *testing.T) {
		udp := Server{Tag: "u", Kind: KindUDP, Destination: "h.example:443"}
		prober := &fakeProber{reachable: false, fetch: always(Attempt{Class: ClassDNS})}
		require.Equal(t, []string{NoteUplinkDown}, runAll(prober, udp, true).Notes)
		prober = &fakeProber{reachable: true, fetch: always(Attempt{Class: ClassDNS})}
		require.Equal(t, []string{NoteDNSFailed}, runAll(prober, udp, true).Notes)
		require.Len(t, prober.requests, 1)
	})
	t.Run("proof: a handshake through the relay", func(t *testing.T) {
		prober := &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{relayOne.Tag: probeFull, relayTwo.Tag: probeFull},
			fetch: proof(Attempt{Handshake: true})}
		verdict := runAll(prober, testA, true, relayOne, relayTwo)
		require.Equal(t, BlockPathBlock, verdict.Block)
		require.Equal(t, []string{relayOne.Tag}, prober.controls, "the first that proves it is enough")
		require.Equal(t, 1, prober.count("chrome", relayOne.Tag, ""))
		require.Equal(t, 1, prober.uplinks)
	})
	t.Run("proof: a server that answers with what does not verify", func(t *testing.T) {
		prober := &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{relayOne.Tag: probeFull},
			fetch: proof(Attempt{Class: ClassVerify})}
		require.Equal(t, BlockPathBlock, runAll(prober, testA, true, relayOne).Block)
	})
	t.Run("silent through every working relay", func(t *testing.T) {
		prober := &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{relayOne.Tag: probeFull, relayTwo.Tag: probeFull, relayThree.Tag: probeFull},
			fetch: proof(Attempt{Class: ClassNoHello})}
		verdict := runAll(prober, testA, true, relayOne, relayTwo, relayThree)
		require.Equal(t, BlockDead, verdict.Block)
		require.Equal(t, 2, verdict.N)
		require.Equal(t, []string{relayOne.Tag, relayTwo.Tag}, prober.controls, "two at most")
	})
	t.Run("a relay whose control fails counts for nothing", func(t *testing.T) {
		prober := &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{relayTwo.Tag: {Handshake: true, Bytes: 200, Status: 204}},
			fetch: proof(Attempt{Class: ClassNoHello})}
		verdict := runAll(prober, testA, true, relayOne, relayTwo)
		require.Equal(t, BlockUnreachable, verdict.Block, "one working relay is too few for dead")
		require.Equal(t, []string{NoteRelaySilent}, verdict.Notes)
		require.Equal(t, 1, verdict.N)
		require.Zero(t, prober.count("chrome", relayOne.Tag, ""), "nothing goes through a relay whose control failed")
	})
	t.Run("all controls fail", func(t *testing.T) {
		prober := &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{}, fetch: proof(Attempt{Handshake: true})}
		verdict := runAll(prober, testA, true, relayOne, relayTwo)
		require.Equal(t, BlockUnreachable, verdict.Block)
		require.Empty(t, verdict.Notes, "no relay was asked")
		require.Zero(t, verdict.N)
	})
	t.Run("no candidates", func(t *testing.T) {
		prober := &fakeProber{tcp: ClassNoTCP, reachable: true, fetch: proof(Attempt{Handshake: true})}
		verdict := runAll(prober, testA, true)
		require.Equal(t, BlockUnreachable, verdict.Block)
		require.Empty(t, verdict.Notes)
		require.Zero(t, verdict.N)
	})
	t.Run("a hello drop goes to the relays without the check of the uplink", func(t *testing.T) {
		prober := &fakeProber{reachable: false, control: map[string]Attempt{relayOne.Tag: probeFull}, fetch: proof(Attempt{Handshake: true})}
		require.Equal(t, BlockPathBlock, runAll(prober, testA, true, relayOne).Block)
		require.Zero(t, prober.uplinks)
	})
	t.Run("a hello drop stays one without relays", func(t *testing.T) {
		prober := &fakeProber{reachable: true, fetch: proof(Attempt{Class: ClassNoHello})}
		require.Equal(t, BlockHelloDrop, runAll(prober, testA, true).Block)
	})
	t.Run("a pooled server has to answer a request", func(t *testing.T) {
		pooled := Server{Tag: "p", Kind: KindPooled, Fingerprint: "chrome", ServerName: "p.example", Destination: "192.0.2.5:443"}
		prober := &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{relayOne.Tag: probeFull},
			fetch: proof(Attempt{Handshake: true, Class: ClassCut})}
		verdict := runAll(prober, pooled, true, relayOne)
		require.Equal(t, BlockUnreachable, verdict.Block, "a dial of a pooled transport proves nothing")
		require.Equal(t, []string{NoteRelaySilent}, verdict.Notes)
		require.Equal(t, 1, prober.count("chrome", relayOne.Tag, ProbeTarget))
		prober = &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{relayOne.Tag: probeFull, relayTwo.Tag: probeFull},
			fetch: proof(Attempt{Handshake: true, Class: ClassCut})}
		require.Equal(t, BlockDead, runAll(prober, pooled, true, relayOne, relayTwo).Block)

		prober = &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{relayOne.Tag: probeFull},
			fetch: proof(Attempt{Handshake: true, Bytes: 100})}
		require.Equal(t, BlockPathBlock, runAll(prober, pooled, true, relayOne).Block)
	})
	t.Run("without TLS nothing goes through a relay: it would carry the secret", func(t *testing.T) {
		noTLS := Server{Tag: "p", Kind: KindPooled, Destination: "192.0.2.5:443"}
		prober := &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{relayOne.Tag: probeFull}, fetch: proof(Attempt{Handshake: true, Bytes: 100})}
		require.Equal(t, BlockUnreachable, runAll(prober, noTLS, true, relayOne).Block)
		require.Empty(t, prober.controls)
		for _, request := range prober.requests {
			require.Empty(t, request.Detour)
		}
	})
	t.Run("a hello drop silent through relays stays one", func(t *testing.T) {
		prober := &fakeProber{reachable: true, control: map[string]Attempt{relayOne.Tag: probeFull, relayTwo.Tag: probeFull}, fetch: proof(Attempt{Class: ClassNoHello})}
		verdict := runAll(prober, testA, true, relayOne, relayTwo)
		require.Equal(t, BlockHelloDrop, verdict.Block)
		require.Equal(t, []string{NoteRelaySilent}, verdict.Notes)
		require.Equal(t, 2, verdict.N)
	})
	t.Run("a copy that never asked the server does not count", func(t *testing.T) {
		for _, class := range []ErrorClass{ClassOther, ClassCanceled, ClassDNS} {
			prober := &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{relayOne.Tag: probeFull}, fetch: proof(Attempt{Class: class})}
			verdict := runAll(prober, testA, true, relayOne)
			require.Equal(t, BlockUnreachable, verdict.Block, class)
			require.Empty(t, verdict.Notes, class)
			require.Zero(t, verdict.N, class)
		}
	})
	t.Run("every class of silence counts", func(t *testing.T) {
		for _, class := range []ErrorClass{ClassNoTCP, ClassNoHello, ClassCut} {
			prober := &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{relayOne.Tag: probeFull}, fetch: proof(Attempt{Class: class})}
			verdict := runAll(prober, testA, true, relayOne)
			require.Equal(t, BlockUnreachable, verdict.Block, class)
			require.Equal(t, []string{NoteRelaySilent}, verdict.Notes, class)
			require.Equal(t, 1, verdict.N)

			prober = &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{relayOne.Tag: probeFull, relayTwo.Tag: probeFull}, fetch: proof(Attempt{Class: class})}
			verdict = runAll(prober, testA, true, relayOne, relayTwo)
			require.Equal(t, BlockDead, verdict.Block, class)
			require.Equal(t, 2, verdict.N)
		}
	})
	// an unstable relay: the server is live through nobody but it did not answer through this one
	t.Run("one relay of two that works names nobody dead", func(t *testing.T) {
		prober := &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{relayOne.Tag: probeFull, relayTwo.Tag: probeFull},
			fetch: func(server Server, request ProbeRequest) Attempt {
				if request.Detour == relayOne.Tag {
					return Attempt{Class: ClassNoHello}
				}
				return Attempt{Class: ClassOther}
			}}
		verdict := runAll(prober, testA, true, relayOne, relayTwo)
		require.Equal(t, BlockUnreachable, verdict.Block)
		require.Equal(t, []string{NoteRelaySilent}, verdict.Notes)
		require.Equal(t, 1, verdict.N)
		require.Contains(t, verdict.Why, "1 working server")
	})
}

// A probe that ran out of its budget concludes nothing from attempts the budget cut.
func TestRunBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	prober := &fakeProber{fetch: func(Server, ProbeRequest) Attempt {
		cancel()
		return probeZero
	}}
	verdict := Run(ctx, prober, testA, RunOptions{})
	require.Equal(t, BlockUnknown, verdict.Block)
	require.Equal(t, []string{NoteInconclusive}, verdict.Notes)
	require.Len(t, prober.requests, 1)
}

// The budget ends in the relay step: what it left is no silence of the server, whatever was counted.
func TestRunBudgetInTheRelays(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	prober := &fakeProber{tcp: ClassNoTCP, reachable: true, control: map[string]Attempt{relayOne.Tag: probeFull}, fetch: func(Server, ProbeRequest) Attempt {
		cancel()
		return Attempt{Class: ClassNoHello}
	}}
	verdict := Run(ctx, prober, testA, RunOptions{Relays: []Server{relayOne}})
	require.Equal(t, BlockUnknown, verdict.Block)
	require.Equal(t, []string{NoteInconclusive}, verdict.Notes)
}

// A fault in one attempt of a burst is that attempt.
func TestRunBurstSurvivesAFault(t *testing.T) {
	var access sync.Mutex
	calls := 0
	prober := &fakeProber{fetch: func(Server, ProbeRequest) Attempt {
		access.Lock()
		defer access.Unlock()
		calls++
		if calls == 2 {
			panic("what a server sent")
		}
		return probeFull
	}}
	verdict := runAll(prober, testA, true)
	require.Equal(t, BlockNone, verdict.Block)
	require.Equal(t, []string{NoteSomeLost}, verdict.Notes)
}

func TestRelayCandidates(t *testing.T) {
	a := Server{Tag: "sub: a", Kind: KindFingerprint, Destination: "192.0.2.1:443"}
	servers := []Server{
		a,
		{Tag: "other: first", Kind: KindFingerprint, Destination: "192.0.2.2:443"},
		{Tag: "sub: same", Kind: KindFingerprint, Destination: "192.0.2.3:443"},
		{Tag: "sub: same host", Kind: KindFingerprint, Destination: "192.0.2.1:8443"},
		{Tag: "sub: idle", Kind: KindFingerprint, Destination: "192.0.2.4:443"},
		{Tag: "sub: via", Kind: KindNone, Destination: "192.0.2.5:443", Detour: "x"},
		{Tag: "sub: second", Kind: KindUDP, Destination: "[2001:db8::1]:443"},
		{Tag: "sub: detour", Kind: KindFingerprint, Destination: "192.0.2.6:443", Detour: "wan2"},
	}
	candidates := RelayCandidates(a, servers, func(server Server) bool { return server.Tag != "sub: idle" })
	tags := make([]string, len(candidates))
	for index, candidate := range candidates {
		tags[index] = candidate.Tag
	}
	require.Equal(t, []string{"sub: same", "sub: second", "other: first"}, tags)
}

func TestProbeTimesFitTheBudget(t *testing.T) {
	require.GreaterOrEqual(t, relayCandidates, deadRelays, "a probe asks enough relays to name a server dead")
	// the longest paths: both bursts; a hello drop and its relays; no TCP, the uplink and the relays
	relays := time.Duration(relayCandidates) * (singleTimeout + singleTimeout)
	require.Less(t, tcpTimeout+singleTimeout+2*burstTimeout, Budget)
	require.Less(t, tcpTimeout+singleTimeout+singleTimeout+relays, Budget)
	// a single, the alternate, the control of a verification that failed
	require.Less(t, tcpTimeout+singleTimeout+singleTimeout+singleTimeout, Budget)
	require.Less(t, tcpTimeout+time.Duration(len(uplinkAddresses))*tcpTimeout+relays, Budget)
}
