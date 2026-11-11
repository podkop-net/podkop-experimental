// Package detect names what stops a proxy server: a block of the network it is under, its
// settings, or that it does not answer. It holds no engine and no network: the caller (the
// supervisor) reads what the engine observes and hands it to Classify (passive), or gives Run a
// Prober that dials through the engine (active, on demand) -- research 2026-10-31 and 2026-11-01,
// reports in reports/.
//
// A verdict is one Block with Notes, stable codes the page translates. Its Why is English, for
// the log and the command line, and holds counts and fingerprint names only: never an address, a
// link or the text of an error, which carry both.
//
// The passive side sees a freeze of a fingerprint no more: the engine's fallback cures an ordinary
// one and leaves no mark. It names only what the traffic shows; the rest is for the button.
package detect

import (
	"strconv"
	"time"
)

// Block is what a server is under, one for a server.
type Block string

const (
	// BlockNone: flows go past the limit (passive), or a single and a burst went through in full
	// (active).
	BlockNone Block = "none"
	// BlockLimit: flows are cut after a fixed number of bytes.
	BlockLimit Block = "limit"
	// BlockFreeze: the configured fingerprint does not pass, at once or under a burst, and another
	// one does. Active only.
	BlockFreeze Block = "freeze"
	// BlockWrongParams: the server answered and the verification of REALITY or x509 failed.
	BlockWrongParams Block = "wrongparams"
	// BlockRejected: the handshake completes and requests are closed without a byte, on two
	// addresses: a wrong UUID, an account that ended, or a fault of the server.
	BlockRejected Block = "rejected"
	// BlockHelloDrop: TCP connects and no ClientHello is answered (with upgrade_in_dial: or the
	// upgrade that follows it).
	BlockHelloDrop Block = "hellodrop"
	// BlockPathBlock: it does not work from here, and through another server the handshake with
	// it completes.
	BlockPathBlock Block = "pathblock"
	// BlockDead: no TCP from here, and no answer through at least two working servers: one may be
	// unstable itself.
	BlockDead Block = "dead"
	// BlockUnreachable: the port does not answer, and no relay can tell more (with relay_silent: one
	// working server was asked in vain, too few to name the server dead).
	BlockUnreachable Block = "unreachable"
	// BlockUnknown: too little was seen, or what was seen says nothing clear.
	BlockUnknown Block = "unknown"
)

// The notes of a verdict: stable codes, the page translates them.
const (
	NoteNeedsMLKEM      = "needs_mlkem"
	NoteFPSwitched      = "fp_switched"
	NoteHandshakeFailed = "handshake_failed"
	NoteCured           = "cured"
	NoteFallbackOff     = "fallback_off"
	NoteClockSuspect    = "clock_suspect"
	NoteBurstAnyFP      = "burst_any_fp"
	NoteUplinkDown      = "uplink_down"
	NoteDNSFailed       = "dns_failed"
	NoteTargetFailed    = "target_failed"
	NoteDownloadTest    = "download_test"
	NoteInconclusive    = "inconclusive"
	NoteSomeLost        = "some_lost"
	NoteThroughDetour   = "through_detour"
	NoteNotApplicable   = "not_applicable"
	// NoteProbeHelloRefused: the hello of the probe did not verify and a request through the running
	// outbound, which sends another hello, went through.
	NoteProbeHelloRefused = "probe_hello_refused"
	// NoteRelaySilent: with a hello drop or an unreachable port: through working servers there is no
	// answer either.
	NoteRelaySilent = "relay_silent"
	// NoteTLSCert: with wrongparams: what failed is the certificate of a server without REALITY.
	NoteTLSCert = "tls_cert"
	// NoteStandIn: with a freeze: the fingerprint of the link was not probed, another stood in.
	NoteStandIn = "stand_in"
	// NoteUpgradeInDial: with a hello drop: the upgrade of ws or httpupgrade is inside the dial, so
	// the silence may be of the upgrade after a TLS handshake that completed.
	NoteUpgradeInDial = "upgrade_in_dial"
	// NoteServerSilent: a real handshake completed, and a request over it got no byte in the time of
	// the attempt.
	NoteServerSilent = "server_silent"
)

// The sources of a verdict.
const (
	SourcePassive = "passive"
	SourceActive  = "active"
)

// Verdict is what the detector concluded for one server.
type Verdict struct {
	Block  Block    `json:"block"`
	Source string   `json:"source,omitempty"`
	Notes  []string `json:"notes,omitempty"`
	// Fingerprint is the one a freeze is of (active) or the one the engine went over to (passive,
	// with fp_switched).
	Fingerprint string `json:"fp,omitempty"`
	// KB is around where flows are cut.
	KB int64 `json:"kb,omitempty"`
	// N is how many working servers were asked in vain (dead, relay_silent): 1 for an unreachable
	// port, more makes it dead.
	N int `json:"n,omitempty"`
	// Age is how many seconds ago an active verdict was reached.
	Age int64 `json:"age,omitempty"`
	// Why is the reason in English, for the log and the command line: no secrets, counts and
	// fingerprint names only.
	Why string `json:"why,omitempty"`
}

func (v *Verdict) note(codes ...string) {
	v.Notes = append(v.Notes, codes...)
}

// Kind is what a probe of a server can do, by how it connects.
type Kind string

const (
	// KindFingerprint: uTLS over TCP, ws or httpupgrade: every connection is a new ClientHello.
	KindFingerprint Kind = "fingerprint"
	// KindTLS: TLS without uTLS: no fingerprint to compare.
	KindTLS Kind = "tls"
	// KindPooled: xhttp not over h3, grpc, http, multiplex, naive or anytls: connections are shared,
	// a burst is no burst of ClientHellos, and a request through the running outbound may send no
	// hello at all.
	KindPooled Kind = "pooled"
	// KindPlain: no TLS.
	KindPlain Kind = "plain"
	// KindUDP: hysteria, hysteria2, tuic, the transport quic, and xhttp with h3 as its single ALPN
	// without REALITY: no TCP to the server.
	KindUDP Kind = "udp"
	// KindNone: through a tunnel: its handshake is inside the tunnel, not on the path from here.
	KindNone Kind = "none"
)

// Cure is the treatment applied to a server, as the page shows it on the tile. Kind is one of the
// model.Cure* strings; SNI is set only for a spoof.
type Cure struct {
	Kind string `json:"kind"`
	SNI  string `json:"sni,omitempty"`
}

// Identity is what the detect report tells the page about a live server besides its verdict: its
// stable id (to join a verdict and to tell a rename from a new server), the source it connects
// through (via, "" = direct), and the cure applied to it, if any. It carries a cure even for a
// server with no block, so the tile badge shows without a verdict.
type Identity struct {
	Hash string `json:"hash"`
	Via  string `json:"via,omitempty"`
	// ViaInterface: the source of Via is an interface, which gives the server its own socket
	// (a mask works through it, unlike through a proxy)
	ViaInterface bool  `json:"via_interface,omitempty"`
	Cure         *Cure `json:"cure,omitempty"`
}

// Server is one proxy of a configuration as the detector sees it. Fingerprint, ServerName and
// Destination make the key the engine records its handshakes by; Fingerprint is empty when the
// connection has no uTLS.
type Server struct {
	Tag string
	// Hash tells the outbound: a tag may name another server after a change of the settings. It
	// changes when a cure is applied, so it is the liveness key that gates an active verdict.
	Hash string
	// StableHash is the tag/detour/cure-independent identity (serverid.Canonical of the uncured
	// outbound), filled by the supervisor from the plan. It keys the cure store and joins a
	// verdict to a server on the page; unlike Hash it does not change when a cure is applied.
	StableHash  string
	Kind        Kind
	Fingerprint string
	ServerName  string
	Destination string
	Detour      string
	// TestInterval is how often a URL test asks it; zero without one.
	TestInterval time.Duration
	// Reality: its TLS is REALITY, so a failed verification is not of a certificate.
	Reality bool
	// LazyDial: its dial sends nothing, the handshake comes with the first request (grpc, http), so
	// Attempt.Handshake says nothing of the server.
	LazyDial bool
	// UpgradeInDial: ws or httpupgrade over TLS: the dial ends after the upgrade, so
	// Attempt.Handshake false does not mean that the TLS handshake failed.
	UpgradeInDial bool
	// Framed: xhttp, grpc or http: the copy of a probe keeps the frames of the transport, which count
	// on the wire and not in the raw bytes. Multiplex is no such thing: a probe goes without it.
	Framed bool
	// DownloadLeg: xhttp with the download on a leg of its own, maybe another server and over UDP:
	// what is asked of the main server says nothing of it.
	DownloadLeg bool
	// Content is the outbound as the configuration has it. It holds the secrets of the server:
	// it goes to the probe and nowhere else.
	Content []byte `json:"-"`
}

// Flow is a closed connection that ended in the band of possible cuts, its client waiting for the
// server when it closed (trafficcontrol.DetectFlow, so this package does not import the engine).
type Flow struct {
	Download  int64
	Upload    int64
	CreatedAt time.Time
	ClosedAt  time.Time
	// PendingSince is since when its client had been waiting for the server when it closed.
	PendingSince time.Time
}

// FlowSample is what the engine keeps of the closed TCP connections of a server
// (trafficcontrol.DetectFlowSample).
type FlowSample struct {
	Cuts []Flow
	// LastBigAt is when the last flow that went past the band closed.
	LastBigAt time.Time
	// LastDataAt is when the newest flow that got data was opened.
	LastDataAt time.Time
}

// Conn is an open TCP connection through a server.
type Conn struct {
	Outbound  string
	Down      int64
	Up        int64
	CreatedAt time.Time
	// PendingSince is since when its client has been waiting for the server; zero when it is not.
	PendingSince time.Time
}

// Outcome is what the engine recorded of the handshakes with a server. At is when the state
// last changed, not when the last handshake was.
type Outcome struct {
	// NoAnswer: TCP connects and no ClientHello got an answer.
	NoAnswer bool
	// Refused: the server refuses a ClientHello without an X25519MLKEM768 key share (Xray >=26.9.8).
	Refused bool
	// Failed: the server answered and no handshake completed.
	Failed bool
	// Fingerprint is the candidate in use, "" after a failure.
	Fingerprint string
	At          time.Time
}

// DownloadResult is what the last download test of a server found (urltest.DownloadResult).
type DownloadResult struct {
	At       time.Time
	Received int64
	// Stopped: the body stopped on the way, after Received bytes.
	Stopped bool
}

// Signals are what the engine tells of the running configuration.
type Signals struct {
	Flows    map[string]FlowSample
	Open     []Conn
	Outcome  func(fingerprint string, serverName string, destination string) (Outcome, bool)
	Failure  func(tag string) (time.Time, bool)
	Download func(tag string) (DownloadResult, bool)
	// Delays are what the URL tests last found, by tag.
	Delays map[string]uint16
	// Started is when the instance started; Now is passed in so that a result is deterministic.
	Started time.Time
	Now     time.Time
}

// Policy is the thresholds of the verdicts. First estimates from the stands, to be tuned against
// ground truth.
type Policy struct {
	// Window is how far back closed flows are weighed.
	Window time.Duration
	// CutLow and CutHigh bound the band a cut flow ends in (~16-20 KB, with margin).
	CutLow, CutHigh int64
	// ShortLow is the least a flow under CutLow has to have received to count as cut on a framed
	// transport: a stall after the headers of the answer is no limit. Between those (under 1 KB at
	// the address of the check) and the 8 KB a stand saw at a cut of 18 KB, not measured: the Why of
	// a burst of mixed ends names the bytes of its flows, to set it from.
	ShortLow int64
	// CutHits is how many cut flows, none larger, in different intervals of CutSpread name the
	// limit: a mass close (a selector moved, an instance action) ends many in one interval.
	CutHits   int
	CutSpread time.Duration
	// OpenCutAfter is how long the client of an open flow in the band has to wait for the server
	// for the flow to count as a cut: the browser does not close most flows that hang. It is above
	// the wait of a long poll: at 30 s three keep-alive flows of 20 KB polled every 45 s, short
	// requests going on, gave 8 false chips in 6.9 minutes on a healthy server, and a poll of 25 s
	// none (a stand, 2026-11-01). The price: on a real limit the chip comes up to a minute later, to
	// be measured; a poll longer than this still looks like a limit. A wait older than Window counts
	// no more: nothing clears the stamp of a lone write the server never answers.
	OpenCutAfter time.Duration
	// WaitUploadMax is the most a flow may have uploaded and still be waiting for the server: a flow
	// above it is sending, and more upload does not clear its stamp. A client on a silenced flow was
	// measured writing 35-503 bytes.
	WaitUploadMax int64
	// DownloadFresh is how long a download test counts: a group runs one only before it switches
	// to a member, and nothing else renews it.
	DownloadFresh time.Duration
	// DefaultInterval is the interval of a URL test whose interval is not known.
	DefaultInterval time.Duration
	// Target is the bytes of a full download of the probe; FullPercent of it count as full.
	Target      int64
	FullPercent int64
	// MinZeros is how many attempts of a burst with no byte mean more than a lost connection.
	MinZeros int
	// MinCut is the fewest cut flows of a burst that name a limit. MinZeros was set for a burst of 8:
	// of a pooled one, of 3, it leaves 1 flow.
	MinCut int
}

// DefaultPolicy is the starting policy; see Policy on tuning it.
var DefaultPolicy = Policy{
	Window:          15 * time.Minute,
	CutLow:          8 << 10,
	CutHigh:         48 << 10,
	ShortLow:        2 << 10,
	CutHits:         3,
	CutSpread:       2 * time.Second,
	OpenCutAfter:    90 * time.Second,
	WaitUploadMax:   64 << 10,
	DownloadFresh:   time.Hour,
	DefaultInterval: 3 * time.Minute,
	Target:          64000,
	FullPercent:     94,
	MinZeros:        3,
	MinCut:          2,
}

// without what is added to the name of a candidate of the fallback that sends a fingerprint
// without its key share, its first try: no sign of a block (engine, utlsFallbackCandidate)
const noKeyShareSuffix = " without X25519MLKEM768"

// Classify names the block of every server from the signals, by its tag. Nothing is sent: a
// server that carried nothing is BlockUnknown.
func Classify(servers []Server, signals Signals, policy Policy) map[string]Verdict {
	open := make(map[string][]Conn)
	for _, conn := range signals.Open {
		open[conn.Outbound] = append(open[conn.Outbound], conn)
	}
	responding := 0
	for _, server := range servers {
		if signals.Delays[server.Tag] > 0 {
			responding++
		}
	}
	verdicts := make(map[string]Verdict, len(servers))
	for _, server := range servers {
		others := responding
		if signals.Delays[server.Tag] > 0 {
			others--
		}
		verdicts[server.Tag] = classifyOne(server, open[server.Tag], others > 0, signals, policy)
	}
	return verdicts
}

func classifyOne(server Server, open []Conn, others bool, signals Signals, policy Policy) Verdict {
	verdict := Verdict{Block: BlockUnknown, Source: SourcePassive}
	now := signals.Now
	sample := signals.Flows[server.Tag]
	// the newest flow that got data was opened then: a failure before that is over
	lastData := sample.LastDataAt
	bigNow := false
	for _, conn := range open {
		if conn.Down > policy.CutHigh {
			bigNow = true
		}
		if conn.Down > 0 && conn.CreatedAt.After(lastData) {
			lastData = conn.CreatedAt
		}
	}
	var download DownloadResult
	var tested bool
	if signals.Download != nil {
		download, tested = signals.Download(server.Tag)
	}
	if tested && download.Received > 0 && download.At.After(lastData) {
		lastData = download.At
	}
	downloadFresh := tested && !download.At.After(now) && now.Sub(download.At) <= policy.DownloadFresh

	// a tunnel's handshake is not recorded: the record under this key is of the direct path
	var outcome Outcome
	var told bool
	if server.Fingerprint != "" && server.Kind != KindNone && signals.Outcome != nil {
		outcome, told = signals.Outcome(server.Fingerprint, server.ServerName, server.Destination)
	}
	if told {
		if outcome.Refused {
			verdict.note(NoteNeedsMLKEM)
		}
		if switched(server.Fingerprint, outcome) {
			verdict.note(NoteFPSwitched)
			verdict.Fingerprint = outcome.Fingerprint
		}
	}
	// a record from the future (the clock went back) says nothing of when it happened
	failedNow := told && !outcome.At.After(now) && outcome.At.After(signals.Started) && outcome.At.After(lastData)

	cuts, cutKB := countCuts(sample.Cuts, open, lastData, now, policy)
	switch {
	case failedNow && outcome.NoAnswer:
		verdict.Block, verdict.Why = BlockHelloDrop, "TCP connects, no fingerprint got an answer"
	case failedNow && outcome.Failed:
		verdict.note(NoteHandshakeFailed)
		verdict.Why = "the server answers, no handshake completes"
	case server.Kind != KindNone && others && urlTestFailed(server, lastData, signals, policy):
		verdict.Block, verdict.Why = BlockUnreachable, "the URL test failed, nothing came since, other servers answer"
	// below the failures: they compare with when a flow was opened, so a flow opened after one clears
	// it, and one older hides nothing of what new connections meet
	case bigNow:
		verdict.Block, verdict.Why = BlockNone, "an open flow carries on past the limit"
	case !sample.LastBigAt.IsZero() && now.Sub(sample.LastBigAt) <= policy.Window:
		verdict.Block, verdict.Why = BlockNone, "a flow carried on past the limit"
	case downloadFresh && !download.Stopped:
		verdict.Block, verdict.Why = BlockNone, "the download test passed"
	case cuts >= policy.CutHits:
		verdict.Block, verdict.KB = BlockLimit, cutKB
		verdict.Why = strconv.Itoa(cuts) + " flows cut, none larger"
	case downloadFresh && download.Received >= policy.CutLow && download.Received <= policy.CutHigh:
		verdict.Block, verdict.KB = BlockLimit, download.Received>>10
		verdict.note(NoteDownloadTest)
		verdict.Why = "the download test stopped in the band"
	default:
		if verdict.Why == "" {
			verdict.Why = "not enough traffic to tell"
		}
	}
	if server.Kind == KindNone && verdict.Block != BlockUnknown {
		verdict.note(NoteThroughDetour)
	}
	return verdict
}

// switched tells that the engine uses a fingerprint the server's refusal and the fallback's
// first try do not explain.
func switched(configured string, outcome Outcome) bool {
	return !outcome.Refused && outcome.Fingerprint != "" && outcome.Fingerprint != configured && outcome.Fingerprint != configured+noKeyShareSuffix
}

// urlTestFailed tells of a recent failed URL test of a server with nothing through it since.
func urlTestFailed(server Server, lastData time.Time, signals Signals, policy Policy) bool {
	if signals.Failure == nil {
		return false
	}
	at, failed := signals.Failure(server.Tag)
	if !failed || at.After(signals.Now) || !at.After(lastData) {
		return false
	}
	interval := server.TestInterval
	if interval <= 0 {
		interval = policy.DefaultInterval
	}
	return signals.Now.Sub(at) <= 2*interval
}

// countCuts counts the possible cuts within the window, those closed within one interval as one,
// and tells about where they ended. The engine's band starts lower than the policy's. An open flow
// whose client has waited long enough, for no longer than the window, counts too; its interval is
// that of the start of the wait, which does not move from one read to the next.
//
// A flow that waits is a cut only if the path was alive after the wait began (lastData): under a
// limit new flows still get their first bytes, under an outage of the uplink nothing does. So a
// limit the user stops opening flows through is not counted here; the button remains for it.
func countCuts(cuts []Flow, open []Conn, lastData time.Time, now time.Time, policy Policy) (int, int64) {
	intervals := make(map[int64]bool)
	var total, inBand int64
	count := func(download int64, at time.Time) {
		intervals[at.UnixNano()/int64(policy.CutSpread)] = true
		total += download
		inBand++
	}
	waiting := func(download int64, upload int64, pendingSince time.Time) bool {
		return download >= policy.CutLow && download <= policy.CutHigh && upload <= policy.WaitUploadMax &&
			!pendingSince.IsZero() && lastData.After(pendingSince)
	}
	for _, cut := range cuts {
		if waiting(cut.Download, cut.Upload, cut.PendingSince) && now.Sub(cut.ClosedAt) <= policy.Window && cut.ClosedAt.Sub(cut.PendingSince) <= policy.Window {
			count(cut.Download, cut.ClosedAt)
		}
	}
	for _, conn := range open {
		if waiting(conn.Down, conn.Up, conn.PendingSince) && now.Sub(conn.PendingSince) > policy.OpenCutAfter && now.Sub(conn.PendingSince) <= policy.Window {
			count(conn.Down, conn.PendingSince)
		}
	}
	if inBand == 0 {
		return 0, 0
	}
	return len(intervals), (total / inBand) >> 10
}
