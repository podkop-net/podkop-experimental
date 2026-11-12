package detect

import (
	"strconv"
	"strings"
)

// ErrorClass is what an attempt of a probe met, the only thing of an error that is kept: its text
// carries addresses.
type ErrorClass string

const (
	ClassNone     ErrorClass = ""
	ClassDNS      ErrorClass = "dns"
	ClassNoTCP    ErrorClass = "no_tcp"
	ClassVerify   ErrorClass = "verify"
	ClassClock    ErrorClass = "clock_suspect"
	ClassNoHello  ErrorClass = "no_hello"
	ClassCanceled ErrorClass = "canceled"
	ClassCut      ErrorClass = "cut"
	ClassOther    ErrorClass = "other"
)

// Attempt is what one request of a probe came to. Bytes outrank the rest: with bytes, Class only
// tells a flow that was cut from an answer that ended.
type Attempt struct {
	Class ErrorClass
	// Handshake: the dial through the outbound completed. For most protocols that is the TLS
	// handshake with the server and no byte of the request yet.
	Handshake bool
	// Bytes are the raw bytes received, the headers of the answer too.
	Bytes int64
	// Status is the HTTP status of the answer, 0 before one was read.
	Status int
	// Receiving: its time ran out with bytes still coming: a slow flow, not one that was cut.
	Receiving bool
}

// RelayResult is what asking through other servers came to.
type RelayResult struct {
	// Tested is how many working servers were asked: their own control passed.
	Tested int
	// Proven: through one of them the server answered.
	Proven bool
	// Via is the tag of the server it answered through (with Proven).
	Via string
}

// Stages are the stages of a probe of a server as far as they went; a stage not run yet is nil.
// ClassifyStages reads nothing else, so a table of stages is a test of every verdict.
type Stages struct {
	Kind Kind
	// Fingerprint is the one probed, Alternate the one compared with: empty without uTLS.
	Fingerprint string
	Alternate   string
	// Fallback tells that the uTLS fallback of the configuration is on.
	Fallback bool
	// StandIn: Fingerprint is not the one configured (ProbeFingerprint).
	StandIn bool
	// Reality, LazyDial, UpgradeInDial, Framed and DownloadLeg are those of the server.
	Reality       bool
	LazyDial      bool
	UpgradeInDial bool
	Framed        bool
	DownloadLeg   bool

	TCP             *ErrorClass
	Single          *Attempt
	Second          *Attempt
	Control         *Attempt
	Burst           []Attempt
	AlternateSingle *Attempt
	AlternateBurst  []Attempt
	Uplink          *bool
	Relay           *RelayResult
}

// deadRelays is how many working servers have to get no answer from a server without TCP for it to
// be named dead.
const deadRelays = 2

// Step is what a probe does next.
type Step int

const (
	StepDone Step = iota
	StepTCP
	StepSingle
	StepSecond
	StepBurst
	StepAlternateBurst
	StepAlternateSingle
	StepUplink
	StepRelay
	StepControl
)

// ClassifyStages names the block from the stages so far, or the stage it needs next. No burst is
// asked for after a failure of verification or of the first answer: it would only freeze the
// server for the real connections. The verdict means nothing unless the step is StepDone.
func ClassifyStages(stages *Stages, policy Policy) (Verdict, Step) {
	if stages.Kind == "" || stages.Kind == KindNone {
		return finished(BlockUnknown, "the connection goes through a tunnel", NoteNotApplicable), StepDone
	}
	if stages.Kind != KindUDP {
		if stages.TCP == nil {
			return Verdict{}, StepTCP
		}
		switch *stages.TCP {
		case ClassNone:
		case ClassDNS:
			return stages.noName()
		case ClassCanceled:
			return inconclusive("the probe was stopped"), StepDone
		default:
			return stages.noWay(BlockUnreachable, "no TCP to the server")
		}
	}
	if stages.Single == nil {
		return Verdict{}, StepSingle
	}
	if stages.Single.Bytes == 0 {
		return stages.noBytes()
	}
	if targetFailed(*stages.Single) {
		return stages.secondAddress()
	}
	return stages.flows(policy)
}

// noBytes is a first request that received nothing: what it met counts.
func (s *Stages) noBytes() (Verdict, Step) {
	single := *s.Single
	switch single.Class {
	case ClassVerify, ClassClock:
		return s.verification(single.Class)
	case ClassDNS:
		return s.noName()
	case ClassNoTCP:
		return s.noWay(BlockUnreachable, "no TCP to the server")
	case ClassCanceled:
		return inconclusive("the probe was stopped"), StepDone
	}
	if s.LazyDial && single.Class == ClassCut {
		return inconclusive("no way to tell a closed hello from a closed request"), StepDone
	}
	if single.Handshake {
		if single.Class != ClassCut {
			if s.silent(single) {
				return serverSilent(), StepDone
			}
			return inconclusive("handshake completed, no answer in time"), StepDone
		}
		if s.Second == nil {
			return Verdict{}, StepSecond
		}
		if s.Second.Bytes > 0 {
			return s.secondAddress()
		}
		if s.Second.Handshake && s.Second.Class == ClassCut {
			return finished(BlockRejected, "handshake completed, requests to two addresses closed without a byte"), StepDone
		}
		return inconclusive("handshake completed, requests got no bytes"), StepDone
	}
	if single.Class != ClassNoHello && single.Class != ClassCut {
		return inconclusive("the handshake ended in another way"), StepDone
	}
	switch s.Kind {
	case KindUDP:
		if s.DownloadLeg {
			return noAnswerOfALeg(), StepDone
		}
		return s.noWay(BlockUnreachable, "no answer over UDP")
	case KindPlain:
		return inconclusive("the server does not answer its protocol"), StepDone
	}
	if s.Alternate != "" {
		if s.AlternateSingle == nil {
			return Verdict{}, StepAlternateSingle
		}
		alternate := *s.AlternateSingle
		switch {
		case alternate.Bytes > 0:
			return s.freeze("the configured fingerprint gets no answer, another one passes"), StepDone
		case alternate.Class == ClassVerify || alternate.Class == ClassClock:
			return s.verification(alternate.Class)
		case s.silent(alternate):
			return serverSilent(), StepDone
		case alternate.Handshake:
			return inconclusive("handshake with another fingerprint completed, no bytes"), StepDone
		case alternate.Class == ClassCanceled:
			return inconclusive("the probe was stopped"), StepDone
		}
	}
	if s.DownloadLeg {
		return noAnswerOfALeg(), StepDone
	}
	return s.noWay(BlockHelloDrop, "TCP connects, no ClientHello is answered")
}

// noAnswerOfALeg is no answer on a transport with a leg of its own for the download: the check of
// TCP and the relays ask the main server, and a hello without an answer may be of the other one.
func noAnswerOfALeg() Verdict {
	return inconclusive("no answer, and the download of the transport has a leg of its own")
}

// noName is a name of the server that does not resolve. Under an outage the resolver is silent as
// well, so the uplink is asked first: that says it of the router, not of the name.
func (s *Stages) noName() (Verdict, Step) {
	if s.Uplink == nil {
		return Verdict{}, StepUplink
	}
	if !*s.Uplink {
		return finished(BlockUnreachable, "the uplink check failed", NoteUplinkDown), StepDone
	}
	return finished(BlockUnreachable, "the name of the server does not resolve", NoteDNSFailed), StepDone
}

// verification is a hello of the probe that failed verification. The hello is the probe's, which
// may not be the one the running outbound sends (its fallback goes first without ML-KEM, and a
// server of an old Xray refuses ML-KEM): so a request through the running outbound comes before
// the settings are blamed. It is one request: no burst here.
//
// What the control proves depends on the kind. A pooled one may go over a connection of the pool
// and send no hello at all, so its bytes and its handshake say nothing of the hello: only no bytes
// leave the failure as it is. On a kind whose dial is a real handshake, a handshake without bytes
// is a hello that verified with an exit that gave no answer, not wrong settings.
func (s *Stages) verification(class ErrorClass) (Verdict, Step) {
	if s.Control == nil {
		return Verdict{}, StepControl
	}
	pooled := s.Kind == KindPooled
	switch {
	case s.Control.Bytes == 0 && s.silent(*s.Control):
		return serverSilent(), StepDone
	case pooled && s.Control.Bytes > 0:
		return inconclusive("the hello of the probe did not verify, the pool of the running outbound carries a request"), StepDone
	case s.Control.Bytes > 0:
		return finished(BlockUnknown, "the hello of the probe did not verify, the running outbound carries a request", NoteProbeHelloRefused), StepDone
	case !pooled && s.Control.Handshake && !s.LazyDial && s.Kind != KindPlain:
		return inconclusive("the hello of the probe did not verify, that of the running outbound did, no bytes came"), StepDone
	}
	var verdict Verdict
	if class == ClassClock {
		verdict = finished(BlockWrongParams, "the certificate of the server is not valid now", NoteClockSuspect)
	} else {
		verdict = finished(BlockWrongParams, "verification of the server failed")
	}
	if !s.Reality {
		verdict.note(NoteTLSCert)
	}
	return verdict, StepDone
}

// secondAddress is what the second address of the check tells of the first, which gave no answer
// of the download. Only its own 204 clears the server: a fallback of the server, or an exit that
// blocks both, answers both alike.
func (s *Stages) secondAddress() (Verdict, Step) {
	if s.Second == nil {
		return Verdict{}, StepSecond
	}
	if s.Second.Status == 204 {
		return targetFailure(), StepDone
	}
	return inconclusive("neither address of the check answered as it should"), StepDone
}

// flows reads a first request that received something, and what follows it. A limit cuts every
// flow, so a single that went through in full excludes one.
func (s *Stages) flows(policy Policy) (Verdict, Step) {
	singleFull := countFlows([]Attempt{*s.Single}, policy).full == 1
	if s.Kind == KindUDP {
		if singleFull {
			return finished(BlockNone, "a single request went through in full"), StepDone
		}
		return inconclusive("a single request stopped on the way"), StepDone
	}
	if s.Burst == nil {
		return Verdict{}, StepBurst
	}
	burst := countFlows(s.Burst, policy)
	if s.Framed {
		burst = burst.shortInBand()
	}
	n := strconv.Itoa(len(s.Burst))
	switch {
	case burst.failed:
		return targetFailure(), StepDone
	case burst.cutOnly(policy) && !singleFull:
		verdict := finished(BlockLimit, strconv.Itoa(burst.band)+" of "+n+" flows cut in the band, none full")
		verdict.KB = burst.kb()
		if !s.Kind.Maskable() {
			verdict.note(NoteNoMask)
		}
		return verdict, StepDone
	case burst.zero >= policy.MinZeros && s.Kind == KindFingerprint:
		if s.AlternateBurst == nil {
			return Verdict{}, StepAlternateBurst
		}
		alternate := countFlows(s.AlternateBurst, policy)
		switch {
		case alternate.failed:
			return targetFailure(), StepDone
		// a clear gap and half of the burst: a line that loses a share of parallel connections gives
		// one fingerprint one flow more than the other as well
		case alternate.zero < policy.MinZeros && alternate.full*2 >= len(s.AlternateBurst) && alternate.full >= burst.full+2:
			return s.freeze(strconv.Itoa(burst.zero) + " of " + n + " hellos lost under a burst, another fingerprint passes"), StepDone
		case alternate.cutOnly(policy) && !singleFull:
			verdict := finished(BlockLimit, strconv.Itoa(alternate.band)+" flows of another fingerprint cut in the band, none full")
			verdict.KB = alternate.kb()
			return verdict, StepDone
		}
		return finished(BlockUnknown, "a single request passes, several at once do not, with another fingerprint too", NoteBurstAnyFP), StepDone
	case burst.zero >= policy.MinZeros:
		return finished(BlockUnknown, "a single request passes, several at once do not", NoteBurstAnyFP), StepDone
	case burst.zero > 0 && burst.full > 0:
		return finished(BlockNone, strconv.Itoa(burst.zero)+" of "+n+" flows lost, the rest passed", NoteSomeLost), StepDone
	case burst.full == len(s.Burst) && burst.full > 0:
		return finished(BlockNone, "a single request and a burst went through in full"), StepDone
	}
	return inconclusive("flows of a burst ended differently, bytes: " + flowBytes(s.Burst)), StepDone
}

// flowBytes names the raw bytes of each flow, for the thresholds of the band (Policy.ShortLow); a
// flow still receiving has a "+".
func flowBytes(attempts []Attempt) string {
	bytes := make([]string, len(attempts))
	for index, attempt := range attempts {
		bytes[index] = strconv.FormatInt(attempt.Bytes, 10)
		if attempt.Receiving {
			bytes[index] += "+"
		}
	}
	return strings.Join(bytes, " ")
}

// noWay is a server that does not answer from here: the base block, unless the uplink is down or
// another server can tell more. Over UDP or without TLS nothing through a relay can prove it.
// A hello drop saw TCP to the server: the uplink is known to work, whatever the two addresses of
// its check say (a network of few allowed addresses). For the same reason a hello drop stays one
// when relays get no answer either: the server is not off the network, so it is not dead. One relay
// is too few for dead: it may be unstable itself, and a stand saw a live server named so (2026-11-01).
func (s *Stages) noWay(base Block, why string) (Verdict, Step) {
	if base == BlockUnreachable {
		if s.Uplink == nil {
			return Verdict{}, StepUplink
		}
		if !*s.Uplink {
			return finished(BlockUnreachable, "the uplink check failed", NoteUplinkDown), StepDone
		}
	}
	if s.Kind == KindUDP || s.Kind == KindPlain {
		return finished(base, why), StepDone
	}
	if s.Relay == nil {
		return Verdict{}, StepRelay
	}
	switch {
	case s.Relay.Proven:
		verdict := finished(BlockPathBlock, "no way from here, through another server it answers")
		verdict.Via = s.Relay.Via
		return verdict, StepDone
	case s.Relay.Tested >= deadRelays && base == BlockUnreachable:
		verdict := finished(BlockDead, "no answer from here, nor through "+workingServers(s.Relay.Tested))
		verdict.N = s.Relay.Tested
		return verdict, StepDone
	case s.Relay.Tested > 0 && base == BlockUnreachable:
		verdict := finished(BlockUnreachable, "no answer from here, nor through "+workingServers(s.Relay.Tested), NoteRelaySilent)
		verdict.N = s.Relay.Tested
		return verdict, StepDone
	}
	verdict := finished(base, why)
	if base == BlockHelloDrop {
		if s.UpgradeInDial {
			verdict.note(NoteUpgradeInDial)
		}
		if s.Relay.Tested > 0 {
			verdict.N = s.Relay.Tested
			verdict.note(NoteRelaySilent)
			verdict.Why += ", nor through " + workingServers(s.Relay.Tested)
		}
	}
	return verdict, StepDone
}

// workingServers counts the working servers a relay asked in vain, for a Why.
func workingServers(n int) string {
	if n == 1 {
		return "1 working server"
	}
	return strconv.Itoa(n) + " working servers"
}

// freeze is the verdict of a fingerprint that does not pass where another one does.
func (s *Stages) freeze(why string) Verdict {
	verdict := finished(BlockFreeze, why)
	verdict.Fingerprint = s.Fingerprint
	if s.StandIn {
		verdict.note(NoteStandIn)
	}
	// the advice is about a hello the box sends: with a stand-in it may not send this one
	switch {
	case s.Fallback:
		verdict.note(NoteCured)
	case !s.StandIn:
		verdict.note(NoteFallbackOff)
	}
	return verdict
}

func finished(block Block, why string, notes ...string) Verdict {
	return Verdict{Block: block, Source: SourceActive, Why: why, Notes: notes}
}

func inconclusive(why string) Verdict {
	return finished(BlockUnknown, why, NoteInconclusive)
}

// silent tells a handshake that completed and a request over it that ran out of time with nothing
// back. Only where the dial is a real handshake of this connection: a lazy one sends nothing, a
// pooled one may send no hello, and a plain or UDP one proves nothing of TLS.
func (s *Stages) silent(attempt Attempt) bool {
	return attempt.Handshake && attempt.Class == ClassNoHello && !s.LazyDial && (s.Kind == KindFingerprint || s.Kind == KindTLS)
}

// serverSilent is a server that takes the handshake and answers nothing. It repeats as it is, so a
// later check is no advice; where the cause lies a check from here cannot tell.
func serverSilent() Verdict {
	return finished(BlockUnknown, "handshake completed, a request got no answer in time", NoteServerSilent)
}

func targetFailure() Verdict {
	return finished(BlockUnknown, "the address of the check did not answer as it should", NoteTargetFailed)
}

// targetFailed tells that the address of the check, not the server, gave the answer: bytes came
// and the status is not the one of the download. A cut flow has its status 200 before the cut.
func targetFailed(attempt Attempt) bool {
	return attempt.Bytes > 0 && attempt.Status != 0 && attempt.Status != 200
}

// flowCount is how the attempts of a burst ended.
type flowCount struct {
	full, band, zero, total int
	// short flows were cut under the band
	short                 int
	bandBytes, shortBytes int64
	failed                bool
}

func countFlows(attempts []Attempt, policy Policy) flowCount {
	count := flowCount{total: len(attempts)}
	fullAt := policy.Target * policy.FullPercent / 100
	for _, attempt := range attempts {
		if targetFailed(attempt) {
			count.failed = true
		}
		// A cut flow has read the status and met an error. An answer that ended by itself is what an
		// exit gives instead of the download, whatever its size: the addresses of the check send a
		// Content-Length, so a cut one does not end by itself.
		cut := attempt.Status == 200 && attempt.Class != ClassNone && !attempt.Receiving
		switch {
		case attempt.Bytes >= fullAt:
			count.full++
		case attempt.Bytes == 0:
			count.zero++
		case cut && attempt.Bytes >= policy.CutLow && attempt.Bytes <= policy.CutHigh:
			count.band++
			count.bandBytes += attempt.Bytes
		case cut && attempt.Bytes >= policy.ShortLow && attempt.Bytes < policy.CutLow:
			count.short++
			count.shortBytes += attempt.Bytes
		}
	}
	return count
}

// cutOnly: flows ended in the band, none in full, and whatever else there is are a few lost.
func (c flowCount) cutOnly(policy Policy) bool {
	return c.full == 0 && c.band >= policy.MinCut && c.band+c.zero == c.total && c.zero < policy.MinZeros
}

// shortInBand counts the flows cut under the band in it, when none is full. For a framed transport:
// a limit counts what goes on the wire, and of a cut at 18 KB TLS and the frames leave about 8 KB
// of raw bytes, on either side of the end of the band (a stand: 8 KB, and 16 at 24).
func (c flowCount) shortInBand() flowCount {
	if c.full == 0 {
		c.band += c.short
		c.bandBytes += c.shortBytes
	}
	return c
}

func (c flowCount) kb() int64 {
	return (c.bandBytes / int64(c.band)) >> 10
}
