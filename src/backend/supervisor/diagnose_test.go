package supervisor

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/detect"
	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

// heldProber answers every step of a probe as a healthy server does, the first request held until
// the test lets it go or the context ends.
type heldProber struct {
	access   sync.Mutex
	entered  chan string
	release  chan struct{}
	requests map[string]int
}

func newHeldProber() *heldProber {
	return &heldProber{entered: make(chan string, 256), release: make(chan struct{}), requests: make(map[string]int)}
}

func (p *heldProber) TCP(context.Context, detect.Server) detect.ErrorClass { return detect.ClassNone }

func (p *heldProber) Fetch(ctx context.Context, server detect.Server, request detect.ProbeRequest) detect.Attempt {
	p.access.Lock()
	first := p.requests[server.Tag] == 0
	p.requests[server.Tag]++
	p.access.Unlock()
	if first {
		p.entered <- server.Tag
		select {
		case <-p.release:
		case <-ctx.Done():
			return detect.Attempt{Class: detect.ClassCanceled}
		}
	}
	return detect.Attempt{Handshake: true, Bytes: 64400, Status: 200}
}

func (p *heldProber) Control(context.Context, string, string) detect.Attempt {
	return detect.Attempt{Handshake: true, Bytes: 200, Status: 204}
}

func (p *heldProber) Reachable(context.Context, string) bool { return true }

func (p *heldProber) wait(t *testing.T, tag string) {
	t.Helper()
	select {
	case entered := <-p.entered:
		require.Equal(t, tag, entered)
	case <-time.After(10 * time.Second):
		t.Fatal("the probe of ", tag, " did not start")
	}
}

// diagnoseFixture is a supervisor that runs, with servers of the test in place of those of its
// configuration.
func diagnoseFixture(t *testing.T, servers ...detect.Server) (*Supervisor, *fakeEngine, *heldProber) {
	t.Helper()
	s, fake, _, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	require.True(t, s.Boot().OK)
	prober := newHeldProber()
	fake.prober = prober
	setServers(s, servers...)
	t.Cleanup(func() {
		select {
		case <-prober.release:
		default:
			close(prober.release)
		}
	})
	return s, fake, prober
}

func setServers(s *Supervisor, servers ...detect.Server) {
	s.statusAccess.Lock()
	defer s.statusAccess.Unlock()
	s.liveServers = servers
	s.liveEpoch++
}

func probed(tag string, destination string) detect.Server {
	return detect.Server{Tag: tag, Hash: "h-" + tag, Kind: detect.KindFingerprint, Fingerprint: "chrome", ServerName: "s.example", Destination: destination}
}

func waitIdle(t *testing.T, s *Supervisor) {
	t.Helper()
	require.Eventually(t, func() bool {
		s.diag.access.Lock()
		defer s.diag.access.Unlock()
		return s.diag.current == ""
	}, 10*time.Second, 5*time.Millisecond)
}

func TestForceDetectSingleFlight(t *testing.T) {
	a, b, c := probed("a", "192.0.2.1:443"), probed("b", "192.0.2.2:443"), probed("c", "192.0.2.3:443")
	s, _, prober := diagnoseFixture(t, a, b, c)

	require.Equal(t, detect.ForceAnswer{State: detect.ForceStarted}, s.ForceDetect("a", false))
	prober.wait(t, "a")
	require.Equal(t, detect.ForceAnswer{State: detect.ForceRunning}, s.ForceDetect("a", false))
	require.Equal(t, detect.ForceAnswer{State: detect.ForceQueued}, s.ForceDetect("b", false))
	require.Equal(t, detect.ForceAnswer{State: detect.ForceQueued}, s.ForceDetect("b", false), "once in the queue")
	require.Equal(t, detect.ForceAnswer{State: detect.ForceQueued}, s.ForceDetect("c", false))

	report := s.Detect()
	require.Equal(t, "a", report.Probing)
	require.Equal(t, []string{"b", "c"}, report.Queued)
	require.Empty(t, prober.entered, "one at a time")

	close(prober.release)
	waitIdle(t, s)
	report = s.Detect()
	require.Empty(t, report.Queued)
	for _, tag := range []string{"a", "b", "c"} {
		verdict, found := report.Verdicts[tag]
		require.True(t, found, tag)
		require.Equal(t, detect.BlockNone, verdict.Block)
		require.Equal(t, detect.SourceActive, verdict.Source)
	}
}

func TestForceDetectAnswers(t *testing.T) {
	via := probed("via", "192.0.2.4:443")
	via.Kind = detect.KindNone
	via.Detour = "a"
	s, _, _ := diagnoseFixture(t, probed("a", "192.0.2.1:443"), via)
	require.Equal(t, detect.ForceUnknown, s.ForceDetect("no such tag", false).State)
	require.Equal(t, detect.ForceUnknown, s.ForceDetect("via", false).State, "a probe does not apply to it")
	require.Equal(t, []string{"via"}, s.Detect().NoProbe)

	s.Stop()
	require.Equal(t, detect.ForceAnswer{State: detect.ForceNotRunning}, s.ForceDetect("a", false))
}

// Before the first start nothing has an answer, and the answer has its shape.
func TestDetectOfNothing(t *testing.T) {
	s, _, _, _ := fakeFixture(t)
	report := s.Detect()
	require.NotNil(t, report.Verdicts)
	require.Empty(t, report.Verdicts)
	require.NotNil(t, report.Queued)
	require.NotNil(t, report.NoProbe)
	require.Equal(t, detect.ForceNotRunning, s.ForceDetect("a", false).State)
}

func TestForceDetectThrottle(t *testing.T) {
	a, sameDestination := probed("a", "192.0.2.1:443"), probed("a2", "192.0.2.1:443")
	s, _, prober := diagnoseFixture(t, a, sameDestination)
	close(prober.release)
	require.Equal(t, detect.ForceStarted, s.ForceDetect("a", false).State)
	waitIdle(t, s)

	answer := s.ForceDetect("a", false)
	require.Equal(t, detect.ForceThrottled, answer.State)
	require.Greater(t, answer.RetryAfter, 170)
	require.LessOrEqual(t, answer.RetryAfter, 180)
	// the interval is of the destination: another tag of the same server waits as well
	require.Equal(t, detect.ForceThrottled, s.ForceDetect("a2", false).State)

	s.diag.access.Lock()
	s.diag.lastByDestination["192.0.2.1:443"] = time.Now().Add(-DiagnoseMinInterval - time.Second)
	s.diag.access.Unlock()
	require.Equal(t, detect.ForceStarted, s.ForceDetect("a", false).State)
	waitIdle(t, s)
}

// A server at a destination another one waits for is refused at once and told when to come back,
// not passed over in the queue without a word.
func TestForceDetectRefusesADestinationQueued(t *testing.T) {
	a, sameDestination, c := probed("a", "192.0.2.1:443"), probed("a2", "192.0.2.1:443"), probed("c", "192.0.2.3:443")
	s, _, prober := diagnoseFixture(t, a, sameDestination, c)
	require.Equal(t, detect.ForceStarted, s.ForceDetect("c", false).State)
	prober.wait(t, "c")
	require.Equal(t, detect.ForceQueued, s.ForceDetect("a", false).State)
	require.Equal(t, detect.ForceAnswer{State: detect.ForceThrottled, RetryAfter: 180}, s.ForceDetect("a2", false))
	require.Equal(t, detect.ForceQueued, s.ForceDetect("a", false).State, "what is queued stays so")
	require.Equal(t, []string{"a"}, s.Detect().Queued)
	close(prober.release)
	waitIdle(t, s)
	require.Contains(t, s.Detect().Verdicts, "a")
}

// Of a queue, a server at a destination just probed is passed over all the same: its probe would
// measure the one before. A change of the settings can put two there.
func TestDiagnosisQueuePassesOverADestination(t *testing.T) {
	a, sameDestination, c := probed("a", "192.0.2.1:443"), probed("a2", "192.0.2.1:443"), probed("c", "192.0.2.3:443")
	s, _, prober := diagnoseFixture(t, a, sameDestination, c)
	require.Equal(t, detect.ForceStarted, s.ForceDetect("c", false).State)
	prober.wait(t, "c")
	s.diag.access.Lock()
	s.diag.queue = []string{"a", "a2"}
	s.diag.access.Unlock()
	close(prober.release)
	waitIdle(t, s)
	report := s.Detect()
	require.Contains(t, report.Verdicts, "a")
	require.NotContains(t, report.Verdicts, "a2")
}

func TestForceDetectCancel(t *testing.T) {
	s, _, prober := diagnoseFixture(t, probed("a", "192.0.2.1:443"), probed("b", "192.0.2.2:443"), probed("c", "192.0.2.3:443"))
	s.ForceDetect("a", false)
	prober.wait(t, "a")
	s.ForceDetect("b", false)
	s.ForceDetect("c", false)
	require.Equal(t, detect.ForceAnswer{State: detect.ForceCanceled}, s.ForceDetect("", true))
	report := s.Detect()
	require.Empty(t, report.Queued)
	require.Equal(t, "a", report.Probing, "the probe that runs goes on")
	close(prober.release)
	waitIdle(t, s)
	report = s.Detect()
	require.Contains(t, report.Verdicts, "a")
	require.NotContains(t, report.Verdicts, "b")
}

func TestForceDetectQueueLimit(t *testing.T) {
	servers := []detect.Server{probed("first", "192.0.2.1:443")}
	for index := range diagnoseQueueLimit + 1 {
		servers = append(servers, probed("s"+string(rune('A'+index)), "198.51.100."+string(rune('0'+index%10))+":"+string(rune('0'+index/10))+"443"))
	}
	s, _, prober := diagnoseFixture(t, servers...)
	s.ForceDetect("first", false)
	prober.wait(t, "first")
	for _, server := range servers[1 : diagnoseQueueLimit+1] {
		require.Equal(t, detect.ForceQueued, s.ForceDetect(server.Tag, false).State)
	}
	answer := s.ForceDetect(servers[diagnoseQueueLimit+1].Tag, false)
	require.Equal(t, detect.ForceThrottled, answer.State)
	require.Positive(t, answer.RetryAfter)
	s.ForceDetect("", true)
}

// A result of an outbound that is not the one under the tag any more is dropped.
func TestDiagnosisDroppedOnHashChange(t *testing.T) {
	a := probed("a", "192.0.2.1:443")
	s, _, prober := diagnoseFixture(t, a)
	s.ForceDetect("a", false)
	prober.wait(t, "a")
	changed := a
	changed.Hash = "another"
	setServers(s, changed)
	close(prober.release)
	waitIdle(t, s)
	require.NotContains(t, s.Detect().Verdicts, "a")
}

// The same for a tag that went while its probe ran.
func TestDiagnosisDroppedOnTagGone(t *testing.T) {
	a := probed("a", "192.0.2.1:443")
	s, _, prober := diagnoseFixture(t, a)
	s.ForceDetect("a", false)
	prober.wait(t, "a")
	setServers(s)
	close(prober.release)
	waitIdle(t, s)
	require.Empty(t, s.Detect().Verdicts)
}

// A stop while a probe runs: the stop does not wait for it, the result is dropped, what was queued
// goes, and the worker ends.
func TestDiagnosisDuringStop(t *testing.T) {
	a, b := probed("a", "192.0.2.1:443"), probed("b", "192.0.2.2:443")
	s, _, prober := diagnoseFixture(t, a, b)
	s.ForceDetect("a", false)
	prober.wait(t, "a")
	s.ForceDetect("b", false)
	stopped := make(chan struct{})
	go func() {
		s.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("the stop waits for a probe")
	}
	close(prober.release)
	waitIdle(t, s)
	require.Empty(t, s.Detect().Verdicts)
	s.diag.access.Lock()
	defer s.diag.access.Unlock()
	require.Empty(t, s.diag.queue)
	require.Empty(t, s.diag.active)
}

// cutProber is a probe cut by the close of its instance: what it comes to is what the cut did.
type cutProber struct{ *heldProber }

func (p cutProber) Fetch(ctx context.Context, server detect.Server, request detect.ProbeRequest) detect.Attempt {
	p.access.Lock()
	p.requests[server.Tag]++
	p.access.Unlock()
	p.entered <- server.Tag
	<-p.release
	return detect.Attempt{Class: detect.ClassCanceled}
}

// An apply while a probe runs: the close of the instance cuts the probe before the next instance is
// up. What it found is dropped, and the queue with it: nothing is probed on the way out, nor stored
// for 30 minutes over a server nothing is known of.
func TestDiagnosisDuringApply(t *testing.T) {
	a, b := probed("a", "192.0.2.1:443"), probed("b", "192.0.2.2:443")
	s, fake, prober := diagnoseFixture(t, a, b)
	fake.prober = cutProber{prober}
	require.Equal(t, detect.ForceStarted, s.ForceDetect("a", false).State)
	prober.wait(t, "a")
	require.Equal(t, detect.ForceQueued, s.ForceDetect("b", false).State)
	closes := 0
	fake.onClose = func() {
		closes++
		close(prober.release)
		// the probe sees its cut and the worker ends before the instance is done with
		waitIdle(t, s)
		require.Nil(t, s.detectSnapshot().instance)
	}
	require.True(t, s.close(s.current.instance))
	require.Equal(t, 1, closes)
	s.diag.access.Lock()
	defer s.diag.access.Unlock()
	require.Empty(t, s.diag.active, "what the cut did is not a finding")
	require.Empty(t, s.diag.queue)
	require.NotContains(t, s.diag.lastByDestination, b.Destination, "the next probe of the queue did not start")
	prober.access.Lock()
	defer prober.access.Unlock()
	require.Zero(t, prober.requests["b"])
}

// The whole apply through the same order: the next instance runs without what the probe found.
func TestDiagnosisDuringWholeApply(t *testing.T) {
	s, fake, _, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	require.True(t, s.Boot().OK)
	prober := newHeldProber()
	fake.prober = cutProber{prober}
	server := s.detectSnapshot().servers[0]
	require.Equal(t, detect.ForceStarted, s.ForceDetect(server.Tag, false).State)
	prober.wait(t, server.Tag)
	fake.onClose = func() {
		fake.onClose = nil
		close(prober.release)
		waitIdle(t, s)
	}
	settings("one.lab.example", "61")
	result := s.Apply()
	require.True(t, result.OK, result.Message)
	after := s.detectSnapshot()
	require.Same(t, s.current.instance, after.instance)
	require.Equal(t, server.Hash, after.servers[0].Hash, "the same outbound: only the instance tells")
	require.NotContains(t, s.Detect().Verdicts, server.Tag)
}

// A fault in a probe is one line of the log: the next one can run.
func TestDiagnosisSurvivesAFault(t *testing.T) {
	a, b := probed("a", "192.0.2.1:443"), probed("b", "192.0.2.2:443")
	s, fake, prober := diagnoseFixture(t, a, b)
	fake.prober = faultyProber{prober}
	require.Equal(t, detect.ForceStarted, s.ForceDetect("a", false).State)
	waitIdle(t, s)
	fake.access.Lock()
	fake.prober = prober
	fake.access.Unlock()
	close(prober.release)
	require.Equal(t, detect.ForceStarted, s.ForceDetect("b", false).State)
	waitIdle(t, s)
	require.Contains(t, s.Detect().Verdicts, "b")
}

type faultyProber struct{ detect.Prober }

func (faultyProber) TCP(context.Context, detect.Server) detect.ErrorClass {
	panic("what a server sent")
}

func TestDetectMerge(t *testing.T) {
	a := probed("a", "192.0.2.1:443")
	s, fake, _ := diagnoseFixture(t, a)
	fake.flows = map[string]detect.FlowSample{"a": {LastBigAt: time.Now()}}
	require.Equal(t, detect.SourcePassive, s.Detect().Verdicts["a"].Source)

	store := func(block detect.Block, at time.Time, hash string) {
		s.diag.access.Lock()
		defer s.diag.access.Unlock()
		s.diag.active = map[string]activeVerdict{"a": {verdict: detect.Verdict{Block: block, Source: detect.SourceActive}, at: at, hash: hash}}
	}
	// an active verdict over the passive one, with its age
	store(detect.BlockFreeze, time.Now().Add(-time.Minute), a.Hash)
	verdict := s.Detect().Verdicts["a"]
	require.Equal(t, detect.BlockFreeze, verdict.Block)
	require.Equal(t, detect.SourceActive, verdict.Source)
	require.GreaterOrEqual(t, verdict.Age, int64(60))
	require.Less(t, verdict.Age, int64(70))
	// until its time is over
	store(detect.BlockFreeze, time.Now().Add(-activeVerdictTTL-time.Second), a.Hash)
	require.Equal(t, detect.SourcePassive, s.Detect().Verdicts["a"].Source)
	// and only of the outbound it was found for
	store(detect.BlockFreeze, time.Now(), "another outbound")
	require.Equal(t, detect.SourcePassive, s.Detect().Verdicts["a"].Source)
}

// What a probe of a freeze advises follows the settings of now, and the verdict stored stays as
// it was: the proof of the freeze does not depend on them.
func TestDetectFreezeFollowsTheFallback(t *testing.T) {
	a := probed("a", "192.0.2.1:443")
	s, _, _ := diagnoseFixture(t, a)
	store := func(notes ...string) {
		s.diag.access.Lock()
		defer s.diag.access.Unlock()
		s.diag.active = map[string]activeVerdict{"a": {verdict: detect.Verdict{Block: detect.BlockFreeze, Source: detect.SourceActive, Notes: notes}, at: time.Now(), hash: a.Hash}}
	}
	fallback := func(on bool) {
		s.statusAccess.Lock()
		defer s.statusAccess.Unlock()
		s.liveFallback = on
	}
	store(detect.NoteFallbackOff)
	fallback(false)
	require.Equal(t, []string{detect.NoteFallbackOff}, s.Detect().Verdicts["a"].Notes)
	fallback(true)
	require.Equal(t, []string{detect.NoteCured}, s.Detect().Verdicts["a"].Notes)
	s.diag.access.Lock()
	require.Equal(t, []string{detect.NoteFallbackOff}, s.diag.active["a"].verdict.Notes, "what is stored is not touched")
	s.diag.access.Unlock()

	store(detect.NoteCured)
	fallback(false)
	require.Equal(t, []string{detect.NoteFallbackOff}, s.Detect().Verdicts["a"].Notes)

	// a stand-in gets no advice to turn the fallback on
	store(detect.NoteStandIn, detect.NoteCured)
	require.Equal(t, []string{detect.NoteStandIn}, s.Detect().Verdicts["a"].Notes)
	fallback(true)
	require.ElementsMatch(t, []string{detect.NoteStandIn, detect.NoteCured}, s.Detect().Verdicts["a"].Notes)
}

// The merge rule: a weak verdict lives as long as the next press has to wait, and stands over any
// passive verdict but the three that say more; a strong one stands for 30 minutes over all of them.
func TestDetectMergeByWhatAVerdictSays(t *testing.T) {
	a := probed("a", "192.0.2.1:443")
	s, _, _ := diagnoseFixture(t, a)
	store := func(age time.Duration, block detect.Block, notes ...string) {
		s.diag.access.Lock()
		defer s.diag.access.Unlock()
		s.diag.active = map[string]activeVerdict{"a": {verdict: detect.Verdict{Block: block, Source: detect.SourceActive, Notes: notes}, at: time.Now().Add(-age), hash: a.Hash}}
	}
	// passive sets what the traffic shows; an empty block: nothing
	passive := func(block detect.Block, notes ...string) {
		s.diag.access.Lock()
		defer s.diag.access.Unlock()
		s.diag.passive = map[string]detect.Verdict{}
		if block != "" {
			s.diag.passive["a"] = detect.Verdict{Block: block, Source: detect.SourcePassive, Notes: notes}
		}
		s.diag.passiveAt, s.diag.passiveEpoch = time.Now(), s.liveEpoch
	}
	type verdictOf struct {
		block detect.Block
		notes []string
	}
	weak := []verdictOf{
		{detect.BlockUnknown, []string{detect.NoteInconclusive}},
		{detect.BlockUnknown, []string{detect.NoteTargetFailed}},
		{detect.BlockUnreachable, []string{detect.NoteUplinkDown}},
		{detect.BlockUnreachable, []string{detect.NoteDNSFailed}},
		{detect.BlockWrongParams, []string{detect.NoteClockSuspect}},
		{detect.BlockWrongParams, []string{detect.NoteClockSuspect, detect.NoteTLSCert}},
		{detect.BlockUnknown, []string{detect.NoteProbeHelloRefused}},
	}
	strong := []verdictOf{
		{detect.BlockNone, nil},
		{detect.BlockNone, []string{detect.NoteSomeLost}},
		{detect.BlockLimit, nil},
		{detect.BlockFreeze, []string{detect.NoteStandIn}},
		{detect.BlockWrongParams, nil},
		{detect.BlockWrongParams, []string{detect.NoteTLSCert}},
		{detect.BlockRejected, nil},
		{detect.BlockHelloDrop, []string{detect.NoteRelaySilent}},
		{detect.BlockPathBlock, nil},
		{detect.BlockDead, nil},
		{detect.BlockUnreachable, nil},
		{detect.BlockUnreachable, []string{detect.NoteRelaySilent}},
		{detect.BlockUnknown, []string{detect.NoteBurstAnyFP}},
	}
	saysMore := []verdictOf{
		{detect.BlockLimit, nil},
		{detect.BlockLimit, []string{detect.NoteDownloadTest}},
		{detect.BlockHelloDrop, nil},
		{detect.BlockUnknown, []string{detect.NoteHandshakeFailed}},
		{detect.BlockUnknown, []string{detect.NoteNeedsMLKEM, detect.NoteHandshakeFailed}},
	}
	saysLess := []verdictOf{
		{"", nil},
		{detect.BlockNone, nil},
		{detect.BlockNone, []string{detect.NoteFPSwitched}},
		{detect.BlockUnreachable, nil},
		{detect.BlockUnknown, nil},
		{detect.BlockUnknown, []string{detect.NoteNeedsMLKEM}},
		{detect.BlockUnknown, []string{detect.NoteFPSwitched}},
		{detect.BlockUnknown, []string{detect.NoteNeedsMLKEM, detect.NoteFPSwitched}},
	}
	active := func(t *testing.T) {
		t.Helper()
		require.Equal(t, detect.SourceActive, s.Detect().Verdicts["a"].Source)
	}
	notActive := func(t *testing.T) {
		t.Helper()
		require.NotEqual(t, detect.SourceActive, s.Detect().Verdicts["a"].Source)
	}

	for _, verdict := range weak {
		for _, over := range saysLess {
			passive(over.block, over.notes...)
			store(time.Minute, verdict.block, verdict.notes...)
			active(t)
			store(DiagnoseMinInterval-time.Second, verdict.block, verdict.notes...)
			active(t)
			// its time is over: what the traffic shows is back
			store(DiagnoseMinInterval+time.Second, verdict.block, verdict.notes...)
			notActive(t)
			store(activeVerdictTTL-time.Minute, verdict.block, verdict.notes...)
			notActive(t)
		}
		for _, over := range saysMore {
			passive(over.block, over.notes...)
			store(time.Second, verdict.block, verdict.notes...)
			// failed handshakes are the symptom of wrong parameters, the check names their cause
			if verdict.block == detect.BlockWrongParams && slices.Contains(over.notes, detect.NoteHandshakeFailed) {
				active(t)
				require.Equal(t, detect.BlockWrongParams, s.Detect().Verdicts["a"].Block)
				continue
			}
			notActive(t)
			require.Equal(t, over.block, s.Detect().Verdicts["a"].Block)
		}
	}
	for _, verdict := range strong {
		for _, over := range append(slices.Clone(saysLess), saysMore...) {
			passive(over.block, over.notes...)
			store(time.Second, verdict.block, verdict.notes...)
			active(t)
			store(activeVerdictTTL-time.Second, verdict.block, verdict.notes...)
			active(t)
			store(activeVerdictTTL+time.Second, verdict.block, verdict.notes...)
			notActive(t)
		}
	}

	// the weak one reads as it was stored, its age with it
	passive(detect.BlockNone)
	store(time.Minute, detect.BlockUnreachable, detect.NoteDNSFailed)
	verdict := s.Detect().Verdicts["a"]
	require.Equal(t, detect.BlockUnreachable, verdict.Block)
	require.Equal(t, []string{detect.NoteDNSFailed}, verdict.Notes)
	require.GreaterOrEqual(t, verdict.Age, int64(60))
}

// hungProber is a server whose handshake completes and which sends no byte (a hung server): its
// verdict lives as long as a weak one.
type hungProber struct{}

func (hungProber) TCP(context.Context, detect.Server) detect.ErrorClass { return detect.ClassNone }

func (hungProber) Fetch(context.Context, detect.Server, detect.ProbeRequest) detect.Attempt {
	return detect.Attempt{Handshake: true, Class: detect.ClassNoHello}
}

func (hungProber) Control(context.Context, string, string) detect.Attempt { return detect.Attempt{} }

func (hungProber) Reachable(context.Context, string) bool { return true }

// A verdict hidden under what the traffic shows leaves its notes and its why in the log, and no
// address of the server.
func TestDiagnosisLogLine(t *testing.T) {
	s, fake, _, settings := fakeFixture(t)
	var access sync.Mutex
	var lines []string
	s.options.Log = func(level string, message string) {
		access.Lock()
		defer access.Unlock()
		lines = append(lines, level+" "+message)
	}
	settings("one.lab.example", "60")
	require.True(t, s.Boot().OK)
	a := probed("a", "192.0.2.1:443")
	fake.access.Lock()
	fake.prober = hungProber{}
	fake.access.Unlock()
	setServers(s, a)
	require.Equal(t, detect.ForceStarted, s.ForceDetect("a", false).State)
	waitIdle(t, s)
	access.Lock()
	defer access.Unlock()
	var line string
	for _, logged := range lines {
		if strings.Contains(logged, "diagnosis of server") {
			line = logged
		}
	}
	require.Equal(t, "info diagnosis of server a: unknown (server_silent): handshake completed, a request got no answer in time", line)
	require.NotContains(t, line, a.Destination)
	require.NotContains(t, line, a.ServerName)
}

func TestDiagnosisLineWithoutNotes(t *testing.T) {
	require.Equal(t, "diagnosis of server a: none: a single request and a burst went through in full",
		diagnosisLine("a", detect.Verdict{Block: detect.BlockNone, Why: "a single request and a burst went through in full"}))
}

// A press ends visibly, over what the traffic shows as well, but for a limit it read from real flows.
func TestDetectPressEndsVisibly(t *testing.T) {
	a := probed("a", "192.0.2.1:443")
	s, fake, _ := diagnoseFixture(t, a)
	fake.access.Lock()
	fake.prober = hungProber{}
	fake.flows = map[string]detect.FlowSample{"a": {LastBigAt: time.Now()}}
	fake.access.Unlock()
	require.Equal(t, detect.BlockNone, s.Detect().Verdicts["a"].Block)
	require.Equal(t, detect.ForceStarted, s.ForceDetect("a", false).State)
	waitIdle(t, s)
	verdict := s.Detect().Verdicts["a"]
	require.Equal(t, detect.SourceActive, verdict.Source)
	require.Equal(t, []string{detect.NoteServerSilent}, verdict.Notes)

	now := time.Now()
	wait := func(closedAt time.Time) detect.Flow {
		return detect.Flow{Download: 18 << 10, ClosedAt: closedAt, PendingSince: closedAt.Add(-10 * time.Second)}
	}
	fake.access.Lock()
	fake.flows = map[string]detect.FlowSample{"a": {LastDataAt: now, Cuts: []detect.Flow{
		wait(now.Add(-time.Minute)), wait(now.Add(-50 * time.Second)), wait(now.Add(-40 * time.Second)),
	}}}
	fake.access.Unlock()
	s.diag.access.Lock()
	s.diag.passive = nil
	s.diag.access.Unlock()
	verdict = s.Detect().Verdicts["a"]
	require.Equal(t, detect.BlockLimit, verdict.Block)
	require.Equal(t, detect.SourcePassive, verdict.Source)
}

// A server with nothing to say has no entry; a note is something to say.
func TestDetectLeavesOutNothing(t *testing.T) {
	s, _, _ := diagnoseFixture(t, probed("a", "192.0.2.1:443"))
	require.Empty(t, s.Detect().Verdicts)
	s.diag.access.Lock()
	s.diag.passive = map[string]detect.Verdict{"a": {Block: detect.BlockUnknown, Notes: []string{detect.NoteNeedsMLKEM}}}
	s.diag.passiveAt, s.diag.passiveEpoch = time.Now(), s.liveEpoch
	s.diag.access.Unlock()
	require.Contains(t, s.Detect().Verdicts, "a")
}

// What the traffic shows is read at most every few seconds, and a change of the servers reads anew.
func TestDetectCache(t *testing.T) {
	a := probed("a", "192.0.2.1:443")
	s, fake, _ := diagnoseFixture(t, a)
	reads := func() int {
		fake.access.Lock()
		defer fake.access.Unlock()
		return fake.flowReads
	}
	s.Detect()
	first := reads()
	require.Positive(t, first)
	s.Detect()
	s.Detect()
	require.Equal(t, first, reads())

	s.diag.access.Lock()
	s.diag.passiveAt = time.Now().Add(-passiveCacheFor - time.Second)
	s.diag.access.Unlock()
	s.Detect()
	require.Equal(t, first+1, reads())

	setServers(s, a)
	s.Detect()
	require.Equal(t, first+2, reads())
}

// The relays of a probe: working by a probe, by the traffic or by a URL test.
func TestRelaysFor(t *testing.T) {
	a := probed("a", "192.0.2.1:443")
	working, tested, traffic, idle, frozen := probed("working", "192.0.2.2:443"), probed("tested", "192.0.2.3:443"), probed("traffic", "192.0.2.4:443"), probed("idle", "192.0.2.5:443"), probed("frozen", "192.0.2.6:443")
	s, fake, _ := diagnoseFixture(t, a, working, tested, traffic, idle, frozen)
	fake.delays = map[string]uint16{"tested": 100}
	fake.flows = map[string]detect.FlowSample{"traffic": {LastBigAt: time.Now()}}
	s.diag.access.Lock()
	s.diag.active = map[string]activeVerdict{
		"working": {verdict: detect.Verdict{Block: detect.BlockNone}, at: time.Now()},
		"frozen":  {verdict: detect.Verdict{Block: detect.BlockFreeze}, at: time.Now()},
	}
	s.diag.access.Unlock()
	var tags []string
	for _, relay := range s.relaysFor(a, s.detectSnapshot()) {
		tags = append(tags, relay.Tag)
	}
	require.Equal(t, []string{"working", "tested", "traffic"}, tags)
}

// The servers of a configuration the plan makes, every kind of source.
func TestServersOfPlan(t *testing.T) {
	const uuid = "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"
	const publicKey = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
	reality := "vless://" + uuid + "@192.0.2.1:443?security=reality&type=tcp&sni=a.example&fp=Chrome&pbk=" + publicKey + "&sid=00#R"
	noName := "vless://" + uuid + "@192.0.2.2:443?security=tls&type=ws&fp=firefox&host=x.example&path=/w#W"
	xhttp := "vless://" + uuid + "@192.0.2.3:443?security=tls&type=xhttp&sni=x.example&fp=chrome#X"
	hysteria := "hysteria2://secret@192.0.2.4:443?sni=h.example#H"
	socks := "socks5://192.0.2.5:1080"
	multiplexed := `{"type": "trojan", "server": "192.0.2.6", "server_port": 443, "password": "secret", "tls": {"enabled": true, "server_name": "m.example", "utls": {"enabled": true}}, "multiplex": {"enabled": true, "protocol": "h2mux"}}`
	text := "config settings 'settings'\n\toption config_version '2'\n\toption dns_type 'udp'\n\toption dns_server '8.8.8.8'\n\toption urltest_check_interval '1m'\n" +
		"\nconfig source 'prov'\n\toption type 'subscription'\n\toption url 'https://sub.example/x'\n" +
		"\nconfig source 'links'\n\toption type 'links'\n\tlist link '" + reality + "'\n\tlist link '" + noName + "'\n" +
		"\nconfig source 'one'\n\toption type 'links'\n\tlist link '" + socks + "'\n" +
		"\nconfig source 'own'\n\toption type 'json'\n\toption outbound_json '" + multiplexed + "'\n" +
		"\nconfig source 'wan2'\n\toption type 'interface'\n\toption interface 'eth2'\n" +
		"\nconfig section 'x'\n\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'x.example'\n" +
		"\nconfig member\n\toption section 'x'\n\toption role 'server'\n\toption source 'prov'\n" +
		"\nconfig member\n\toption section 'x'\n\toption role 'server'\n\toption source 'links'\n" +
		"\nconfig member\n\toption section 'x'\n\toption role 'server'\n\toption source 'one'\n" +
		"\nconfig member\n\toption section 'x'\n\toption role 'server'\n\toption source 'own'\n" +
		"\nconfig member\n\toption section 'x'\n\toption role 'server'\n\toption source 'wan2'\n" +
		"\nconfig member\n\toption section 'x'\n\toption role 'server'\n\toption source 'one'\n\toption via 'own'\n" +
		"\nconfig member\n\toption section 'x'\n\toption role 'server'\n\toption source 'own'\n\toption via 'wan2'\n"
	parsed, err := uci.Parse([]byte(text))
	require.NoError(t, err)
	config, err := model.Load(parsed)
	require.NoError(t, err)
	result, err := plan.Build(config, plan.Facts{}, plan.Options{DecodeLink: engine.DecodeLink, Servers: map[string][]plan.SubscriptionServer{
		"prov": {{Name: "XH", Link: xhttp}, {Name: "HY", Link: hysteria}},
	}})
	require.NoError(t, err)
	servers, fallback := engine.ServersOf(result.Config)
	require.True(t, fallback)
	byTag := make(map[string]detect.Server)
	for _, server := range servers {
		byTag[server.Tag] = server
	}

	first := byTag["links: R"]
	require.Equal(t, detect.KindFingerprint, first.Kind)
	require.Equal(t, "chrome", first.Fingerprint, "the decoder's spelling, which the engine keys by")
	require.Equal(t, "a.example", first.ServerName)
	require.Equal(t, "192.0.2.1:443", first.Destination)
	require.Equal(t, time.Minute, first.TestInterval)

	second := byTag["links: W"]
	require.Equal(t, detect.KindFingerprint, second.Kind)
	require.Equal(t, "firefox", second.Fingerprint)
	require.NotEmpty(t, second.ServerName)

	require.Equal(t, detect.KindPooled, byTag["prov: XH"].Kind)
	require.Equal(t, detect.KindUDP, byTag["prov: HY"].Kind)
	require.Equal(t, detect.KindPlain, byTag["one"].Kind)
	require.Equal(t, detect.KindPooled, byTag["own"].Kind)
	require.Equal(t, "chrome", byTag["own"].Fingerprint)
	require.Contains(t, string(byTag["own"].Content), `"secret"`)

	viaProxy, found := byTag["one via own"]
	require.True(t, found)
	require.Equal(t, detect.KindNone, viaProxy.Kind)
	require.Equal(t, "own", viaProxy.Detour)

	viaInterface, found := byTag["own via wan2"]
	require.True(t, found)
	require.NotEqual(t, detect.KindNone, viaInterface.Kind, "a socket to the server all the same")
	require.Equal(t, "wan2", viaInterface.Detour)

	require.NotContains(t, byTag, "wan2", "an interface is no server")
	require.NotContains(t, byTag, plan.DirectOutboundTag)
	require.NotContains(t, byTag, plan.BlockOutboundTag)
	for tag := range byTag {
		require.NotContains(t, tag, "-out", "a group or a selector")
	}
}

// done keeps the servers of what runs, and the stop lets them go.
func TestLiveServers(t *testing.T) {
	s, _, _, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	require.True(t, s.Boot().OK)
	snapshot := s.detectSnapshot()
	require.NotNil(t, snapshot.instance)
	require.Len(t, snapshot.servers, 1)
	require.Equal(t, detect.KindPlain, snapshot.servers[0].Kind)
	require.Equal(t, "203.0.113.15:1080", snapshot.servers[0].Destination)
	s.Stop()
	after := s.detectSnapshot()
	require.Nil(t, after.instance)
	require.Empty(t, after.servers)
	require.Greater(t, after.epoch, snapshot.epoch)
}
