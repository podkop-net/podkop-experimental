package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClassify(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	started := now.Add(-time.Hour)
	reality := Server{Tag: "s", Kind: KindFingerprint, Fingerprint: "chrome", ServerName: "a.example", Destination: "192.0.2.1:443", TestInterval: time.Minute}
	via := Server{Tag: "v", Kind: KindNone, Fingerprint: "chrome", ServerName: "a.example", Destination: "192.0.2.1:443", Detour: "b"}

	outcome := func(value Outcome) func(string, string, string) (Outcome, bool) {
		return func(string, string, string) (Outcome, bool) { return value, true }
	}
	// a cut: its client began to wait a while before the close
	cutAt := func(download int64, closedAt time.Time) Flow {
		return Flow{Download: download, ClosedAt: closedAt, PendingSince: closedAt.Add(-10 * time.Second)}
	}
	cuts := func(count int, spread time.Duration) []Flow {
		var flows []Flow
		for index := range count {
			flows = append(flows, cutAt(18<<10, now.Add(-time.Minute+time.Duration(index)*spread)))
		}
		return flows
	}
	// a flow with data was opened a second ago: the path is alive after every wait below
	alive := now.Add(-time.Second)
	aliveFlows := func(tag string) map[string]FlowSample { return map[string]FlowSample{tag: {LastDataAt: alive}} }
	failure := func(at time.Time) func(string) (time.Time, bool) {
		return func(string) (time.Time, bool) { return at, true }
	}
	download := func(result DownloadResult) func(string) (DownloadResult, bool) {
		return func(string) (DownloadResult, bool) { return result, true }
	}
	waiting := func(waits ...time.Duration) []Conn {
		var conns []Conn
		for _, wait := range waits {
			conns = append(conns, Conn{Outbound: "s", Down: 18 << 10, CreatedAt: now.Add(-4 * time.Hour), PendingSince: now.Add(-wait)})
		}
		return conns
	}

	cases := []struct {
		name    string
		server  Server
		signals Signals
		block   Block
		notes   []string
		kb      int64
		fp      string
	}{
		{name: "nothing seen", server: reality, block: BlockUnknown},
		{name: "a big flow closed in the window", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {LastBigAt: now.Add(-time.Minute)}}}, block: BlockNone},
		{name: "a big flow closed before the window", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {LastBigAt: now.Add(-time.Hour)}}}, block: BlockUnknown},
		{name: "a big open flow", server: reality,
			signals: Signals{Open: []Conn{{Outbound: "s", Down: 200 << 10, CreatedAt: now.Add(-time.Hour)}}}, block: BlockNone},
		{name: "a small open flow says nothing", server: reality,
			signals: Signals{Open: []Conn{{Outbound: "s", Down: 20 << 10, CreatedAt: now}}}, block: BlockUnknown},
		{name: "the open flow of another server", server: reality,
			signals: Signals{Open: []Conn{{Outbound: "other", Down: 200 << 10, CreatedAt: now}}}, block: BlockUnknown},
		{name: "three cuts at different moments", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: cuts(3, 3*time.Second), LastDataAt: alive}}}, block: BlockLimit, kb: 18},
		{name: "a mass close is one moment", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: cuts(8, time.Millisecond), LastDataAt: alive}}}, block: BlockUnknown},
		{name: "two cuts are not enough", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: cuts(2, 3*time.Second), LastDataAt: alive}}}, block: BlockUnknown},
		{name: "cuts before the window", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: []Flow{
				cutAt(18<<10, now.Add(-time.Hour)),
				cutAt(18<<10, now.Add(-50*time.Minute)),
				cutAt(18<<10, now.Add(-40*time.Minute)),
			}, LastDataAt: alive}}}, block: BlockUnknown},
		{name: "cuts below the band of the policy", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: []Flow{
				cutAt(5<<10, now.Add(-time.Minute)),
				cutAt(5<<10, now.Add(-50*time.Second)),
				cutAt(5<<10, now.Add(-40*time.Second)),
			}, LastDataAt: alive}}}, block: BlockUnknown},
		{name: "a big flow outweighs cuts", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: cuts(3, 3*time.Second), LastBigAt: now.Add(-time.Minute), LastDataAt: alive}}}, block: BlockNone},
		{name: "the download test passed", server: reality,
			signals: Signals{Download: download(DownloadResult{At: now.Add(-time.Minute), Received: 64 << 10})}, block: BlockNone},
		{name: "the download test stopped in the band", server: reality,
			signals: Signals{Download: download(DownloadResult{At: now.Add(-time.Minute), Received: 18 << 10, Stopped: true})}, block: BlockLimit, notes: []string{NoteDownloadTest}, kb: 18},
		{name: "the download test stopped out of the band", server: reality,
			signals: Signals{Download: download(DownloadResult{At: now.Add(-time.Minute), Received: 2 << 10, Stopped: true})}, block: BlockUnknown},
		{name: "a download test long ago", server: reality,
			signals: Signals{Download: download(DownloadResult{At: now.Add(-2 * time.Hour), Received: 18 << 10, Stopped: true})}, block: BlockUnknown},
		{name: "no answer since the start", server: reality,
			signals: Signals{Outcome: outcome(Outcome{NoAnswer: true, At: now.Add(-time.Minute)})}, block: BlockHelloDrop},
		{name: "no answer before the start", server: reality,
			signals: Signals{Outcome: outcome(Outcome{NoAnswer: true, At: now.Add(-2 * time.Hour)})}, block: BlockUnknown},
		{name: "no answer, data since", server: reality,
			signals: Signals{Outcome: outcome(Outcome{NoAnswer: true, At: now.Add(-time.Minute)}),
				Flows: map[string]FlowSample{"s": {LastDataAt: now.Add(-time.Second)}}}, block: BlockUnknown},
		{name: "no answer, an open flow with data since", server: reality,
			signals: Signals{Outcome: outcome(Outcome{NoAnswer: true, At: now.Add(-time.Minute)}),
				Open: []Conn{{Outbound: "s", Down: 100, CreatedAt: now.Add(-time.Second)}}}, block: BlockUnknown},
		{name: "no answer outweighs a big flow of before", server: reality,
			signals: Signals{Outcome: outcome(Outcome{NoAnswer: true, At: now.Add(-time.Minute)}),
				Flows: map[string]FlowSample{"s": {LastBigAt: now.Add(-5 * time.Minute), LastDataAt: now.Add(-5 * time.Minute)}}}, block: BlockHelloDrop},
		// an old flow says nothing of the handshakes after it opened
		{name: "no answer outweighs an open big flow of before", server: reality,
			signals: Signals{Outcome: outcome(Outcome{NoAnswer: true, At: now.Add(-time.Minute)}),
				Open: []Conn{{Outbound: "s", Down: 200 << 10, CreatedAt: now.Add(-time.Hour)}}}, block: BlockHelloDrop},
		{name: "an open big flow opened after no answer clears it", server: reality,
			signals: Signals{Outcome: outcome(Outcome{NoAnswer: true, At: now.Add(-time.Minute)}),
				Open: []Conn{{Outbound: "s", Down: 200 << 10, CreatedAt: now.Add(-10 * time.Second)}}}, block: BlockNone},
		{name: "failed handshakes outweigh an open big flow of before", server: reality,
			signals: Signals{Outcome: outcome(Outcome{Failed: true, At: now.Add(-time.Minute)}),
				Open: []Conn{{Outbound: "s", Down: 200 << 10, CreatedAt: now.Add(-time.Hour)}}}, block: BlockUnknown, notes: []string{NoteHandshakeFailed}},
		{name: "a failed URL test outweighs an open big flow of before", server: reality,
			signals: Signals{Failure: failure(now.Add(-time.Minute)), Delays: map[string]uint16{"other": 100},
				Open: []Conn{{Outbound: "s", Down: 200 << 10, CreatedAt: now.Add(-time.Hour)}}}, block: BlockUnreachable},
		{name: "an open big flow outweighs cuts", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: cuts(3, 3*time.Second), LastDataAt: alive}},
				Open: []Conn{{Outbound: "s", Down: 200 << 10, CreatedAt: now.Add(-time.Hour)}}}, block: BlockNone},
		// open flows whose client waits for the server
		{name: "three open flows that wait, from different moments", server: reality,
			signals: Signals{Flows: aliveFlows("s"), Open: waiting(100*time.Second, 110*time.Second, 120*time.Second)}, block: BlockLimit, kb: 18},
		{name: "open flows that began to wait at one moment are one", server: reality,
			signals: Signals{Flows: aliveFlows("s"), Open: waiting(100*time.Second, 100*time.Second+time.Millisecond, 100*time.Second+2*time.Millisecond)}, block: BlockUnknown},
		// a long poll: its client waits as long as the client of a cut flow, then gets its answer
		{name: "a wait of no more than 90 s is no cut", server: reality,
			signals: Signals{Flows: aliveFlows("s"), Open: waiting(90*time.Second, 85*time.Second, 80*time.Second)}, block: BlockUnknown},
		{name: "a wait of 45 s, a long poll of a stand, is no cut", server: reality,
			signals: Signals{Flows: aliveFlows("s"), Open: waiting(39*time.Second, 43*time.Second, 47*time.Second)}, block: BlockUnknown},
		// two cuts closed lately, each in an interval of its own: the wait is the third, or nothing
		{name: "a wait of 60 s does not count", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: []Flow{cutAt(18<<10, now.Add(-30*time.Second)), cutAt(18<<10, now.Add(-20*time.Second))}, LastDataAt: alive}}, Open: waiting(60 * time.Second)}, block: BlockUnknown},
		{name: "a wait of 91 s counts", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: []Flow{cutAt(18<<10, now.Add(-30*time.Second)), cutAt(18<<10, now.Add(-20*time.Second))}, LastDataAt: alive}}, Open: waiting(91 * time.Second)}, block: BlockLimit, kb: 18},
		// a stamp only a download clears: a lone write the server never answers stays for good
		{name: "a wait older than the window is no cut", server: reality,
			signals: Signals{Flows: aliveFlows("s"), Open: waiting(time.Hour, 2*time.Hour, 3*time.Hour)}, block: BlockUnknown},
		{name: "a wait just past the window is no cut", server: reality,
			signals: Signals{Flows: aliveFlows("s"), Open: waiting(15*time.Minute+time.Second, 15*time.Minute+3*time.Second, 15*time.Minute+5*time.Second)}, block: BlockUnknown},
		{name: "a wait of the whole window counts", server: reality,
			signals: Signals{Flows: aliveFlows("s"), Open: waiting(15*time.Minute, 14*time.Minute, 13*time.Minute)}, block: BlockLimit, kb: 18},
		// the path was alive after the wait began: under an outage nothing comes through
		{name: "an outage: open flows wait, nothing was opened since", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {LastDataAt: now.Add(-8 * time.Minute)}}, Open: waiting(95*time.Second, 100*time.Second, 105*time.Second)}, block: BlockUnknown},
		{name: "an outage: closed flows waited, nothing was opened since", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: cuts(3, 3*time.Second), LastDataAt: now.Add(-8 * time.Minute)}}}, block: BlockUnknown},
		{name: "an outage: no flow got data at all", server: reality,
			signals: Signals{Open: waiting(95*time.Second, 100*time.Second, 105*time.Second)}, block: BlockUnknown},
		{name: "data after only two waits began: two cuts", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {LastDataAt: now.Add(-102 * time.Second)}}, Open: waiting(95*time.Second, 105*time.Second, 110*time.Second)}, block: BlockUnknown},
		{name: "data after every wait began, from an open flow", server: reality,
			signals: Signals{Open: append(waiting(95*time.Second, 100*time.Second, 105*time.Second), Conn{Outbound: "s", Down: 100, CreatedAt: alive})}, block: BlockLimit, kb: 18},
		{name: "an open flow without data proves nothing", server: reality,
			signals: Signals{Open: append(waiting(95*time.Second, 100*time.Second, 105*time.Second), Conn{Outbound: "s", CreatedAt: alive})}, block: BlockUnknown},
		{name: "data from the flows that wait themselves proves nothing", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: []Flow{
				{Download: 18 << 10, CreatedAt: now.Add(-5 * time.Minute), ClosedAt: now.Add(-time.Minute), PendingSince: now.Add(-70 * time.Second)},
				{Download: 18 << 10, CreatedAt: now.Add(-5 * time.Minute), ClosedAt: now.Add(-50 * time.Second), PendingSince: now.Add(-60 * time.Second)},
				{Download: 18 << 10, CreatedAt: now.Add(-5 * time.Minute), ClosedAt: now.Add(-40 * time.Second), PendingSince: now.Add(-50 * time.Second)},
			}, LastDataAt: now.Add(-5 * time.Minute)}}}, block: BlockUnknown},
		// a lone write hours ago says nothing of the close that came now
		{name: "closed flows that waited longer than the window", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: []Flow{
				{Download: 18 << 10, ClosedAt: now.Add(-time.Minute), PendingSince: now.Add(-3 * time.Hour)},
				{Download: 18 << 10, ClosedAt: now.Add(-50 * time.Second), PendingSince: now.Add(-3 * time.Hour)},
				{Download: 18 << 10, ClosedAt: now.Add(-40 * time.Second), PendingSince: now.Add(-3 * time.Hour)},
			}, LastDataAt: alive}}}, block: BlockUnknown},
		{name: "a closed flow with no stamp is no cut", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: []Flow{
				{Download: 18 << 10, ClosedAt: now.Add(-time.Minute)},
				{Download: 18 << 10, ClosedAt: now.Add(-50 * time.Second)},
				{Download: 18 << 10, ClosedAt: now.Add(-40 * time.Second)},
			}, LastDataAt: alive}}}, block: BlockUnknown},
		// a flow that moved real upload is sending, whatever its stamp says
		{name: "open flows above the upload of a wait", server: reality,
			signals: Signals{Flows: aliveFlows("s"), Open: []Conn{
				{Outbound: "s", Down: 18 << 10, Up: 64<<10 + 1, PendingSince: now.Add(-100 * time.Second)},
				{Outbound: "s", Down: 18 << 10, Up: 10 << 20, PendingSince: now.Add(-110 * time.Second)},
				{Outbound: "s", Down: 18 << 10, Up: 64<<10 + 1, PendingSince: now.Add(-120 * time.Second)},
			}}, block: BlockUnknown},
		{name: "open flows at the upload of a wait", server: reality,
			signals: Signals{Flows: aliveFlows("s"), Open: []Conn{
				{Outbound: "s", Down: 18 << 10, Up: 64 << 10, PendingSince: now.Add(-100 * time.Second)},
				{Outbound: "s", Down: 18 << 10, Up: 503, PendingSince: now.Add(-110 * time.Second)},
				{Outbound: "s", Down: 18 << 10, Up: 35, PendingSince: now.Add(-120 * time.Second)},
			}}, block: BlockLimit, kb: 18},
		{name: "closed flows above the upload of a wait", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: []Flow{
				{Download: 18 << 10, Upload: 64<<10 + 1, ClosedAt: now.Add(-time.Minute), PendingSince: now.Add(-70 * time.Second)},
				{Download: 18 << 10, Upload: 10 << 20, ClosedAt: now.Add(-50 * time.Second), PendingSince: now.Add(-60 * time.Second)},
				{Download: 18 << 10, Upload: 64<<10 + 1, ClosedAt: now.Add(-40 * time.Second), PendingSince: now.Add(-50 * time.Second)},
			}, LastDataAt: alive}}}, block: BlockUnknown},
		{name: "closed flows at the upload of a wait", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: []Flow{
				{Download: 18 << 10, Upload: 64 << 10, ClosedAt: now.Add(-time.Minute), PendingSince: now.Add(-70 * time.Second)},
				{Download: 18 << 10, Upload: 503, ClosedAt: now.Add(-50 * time.Second), PendingSince: now.Add(-60 * time.Second)},
				{Download: 18 << 10, Upload: 35, ClosedAt: now.Add(-40 * time.Second), PendingSince: now.Add(-50 * time.Second)},
			}, LastDataAt: alive}}}, block: BlockLimit, kb: 18},
		{name: "open flows not waiting are no cuts", server: reality,
			signals: Signals{Open: []Conn{
				{Outbound: "s", Down: 18 << 10, CreatedAt: now.Add(-time.Hour)},
				{Outbound: "s", Down: 18 << 10, CreatedAt: now.Add(-50 * time.Minute)},
				{Outbound: "s", Down: 18 << 10, CreatedAt: now.Add(-40 * time.Minute)},
			}}, block: BlockUnknown},
		{name: "open flows out of the band are no cuts", server: reality,
			signals: Signals{Open: []Conn{
				{Outbound: "s", Down: 5 << 10, PendingSince: now.Add(-120 * time.Second)},
				{Outbound: "s", Down: 5 << 10, PendingSince: now.Add(-110 * time.Second)},
				{Outbound: "s", Down: 5 << 10, PendingSince: now.Add(-100 * time.Second)},
			}, Flows: aliveFlows("s")}, block: BlockUnknown},
		{name: "two closed and one open make three", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {Cuts: cuts(2, 3*time.Second), LastDataAt: alive}}, Open: waiting(100 * time.Second)}, block: BlockLimit, kb: 18},
		{name: "a big flow closed in the window outweighs those that wait", server: reality,
			signals: Signals{Flows: map[string]FlowSample{"s": {LastBigAt: now.Add(-time.Minute), LastDataAt: alive}}, Open: waiting(100*time.Second, 110*time.Second, 120*time.Second)}, block: BlockNone},
		{name: "no answer from the future: the clock went back", server: reality,
			signals: Signals{Outcome: outcome(Outcome{NoAnswer: true, At: now.Add(time.Hour)})}, block: BlockUnknown},
		{name: "a failure from the future keeps the refusal", server: reality,
			signals: Signals{Outcome: outcome(Outcome{Failed: true, Refused: true, At: now.Add(time.Hour)})}, block: BlockUnknown, notes: []string{NoteNeedsMLKEM}},
		{name: "handshakes fail", server: reality,
			signals: Signals{Outcome: outcome(Outcome{Failed: true, At: now.Add(-time.Minute)})}, block: BlockUnknown, notes: []string{NoteHandshakeFailed}},
		{name: "a server that needs ML-KEM", server: reality,
			signals: Signals{Outcome: outcome(Outcome{Refused: true, Fingerprint: "firefox", At: now.Add(-time.Minute)})}, block: BlockUnknown, notes: []string{NoteNeedsMLKEM}},
		{name: "the first try of the fallback is no switch", server: reality,
			signals: Signals{Outcome: outcome(Outcome{Fingerprint: "chrome without X25519MLKEM768", At: now.Add(-time.Minute)})}, block: BlockUnknown},
		{name: "the fingerprint configured is no switch", server: reality,
			signals: Signals{Outcome: outcome(Outcome{Fingerprint: "chrome", At: now.Add(-time.Minute)})}, block: BlockUnknown},
		{name: "a switch nothing explains", server: reality,
			signals: Signals{Outcome: outcome(Outcome{Fingerprint: "firefox", At: now.Add(-time.Minute)})}, block: BlockUnknown, notes: []string{NoteFPSwitched}, fp: "firefox"},
		{name: "the URL test failed, others answer", server: reality,
			signals: Signals{Failure: failure(now.Add(-time.Minute)), Delays: map[string]uint16{"other": 100}}, block: BlockUnreachable},
		{name: "the URL test failed, nothing else answers", server: reality,
			signals: Signals{Failure: failure(now.Add(-time.Minute))}, block: BlockUnknown},
		{name: "the URL test failed long ago", server: reality,
			signals: Signals{Failure: failure(now.Add(-3 * time.Minute)), Delays: map[string]uint16{"other": 100}}, block: BlockUnknown},
		{name: "the URL test failed, data since", server: reality,
			signals: Signals{Failure: failure(now.Add(-time.Minute)), Delays: map[string]uint16{"other": 100},
				Flows: map[string]FlowSample{"s": {LastDataAt: now.Add(-time.Second)}}}, block: BlockUnknown},
		{name: "a failure from the future", server: reality,
			signals: Signals{Failure: failure(now.Add(time.Hour)), Delays: map[string]uint16{"other": 100}}, block: BlockUnknown},
		{name: "no answer tells more than the URL test", server: reality,
			signals: Signals{Failure: failure(now.Add(-time.Minute)), Delays: map[string]uint16{"other": 100},
				Outcome: outcome(Outcome{NoAnswer: true, At: now.Add(-time.Minute)})}, block: BlockHelloDrop},
		{name: "through a tunnel: no record is read", server: via,
			signals: Signals{Outcome: outcome(Outcome{NoAnswer: true, At: now.Add(-time.Minute)}), Failure: failure(now.Add(-time.Minute)), Delays: map[string]uint16{"other": 100}}, block: BlockUnknown},
		{name: "through a tunnel: bytes count", server: via,
			signals: Signals{Flows: map[string]FlowSample{"v": {Cuts: []Flow{
				cutAt(18<<10, now.Add(-time.Minute)),
				cutAt(18<<10, now.Add(-50*time.Second)),
				cutAt(18<<10, now.Add(-40*time.Second)),
			}, LastDataAt: alive}}}, block: BlockLimit, notes: []string{NoteThroughDetour}, kb: 18},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			signals := testCase.signals
			signals.Now, signals.Started = now, started
			verdict := Classify([]Server{testCase.server, {Tag: "other", Kind: KindPlain}}, signals, DefaultPolicy)[testCase.server.Tag]
			require.Equal(t, testCase.block, verdict.Block)
			require.Equal(t, SourcePassive, verdict.Source)
			require.ElementsMatch(t, testCase.notes, verdict.Notes)
			require.Equal(t, testCase.kb, verdict.KB)
			require.Equal(t, testCase.fp, verdict.Fingerprint)
		})
	}
}

// What the passive stand does with open flows: one flow every gap seconds, each stalling at the
// limit at once, its client writing 6 s later. If this moves, so does what the stand has to wait for
// (rs-lab/r21/det/run_passive.py, limit-open and swap).
func TestClassifyOpenFlowsOfThePassiveStand(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	reality := Server{Tag: "s", Kind: KindFingerprint, Fingerprint: "chrome", ServerName: "a.example", Destination: "192.0.2.1:443"}
	block := func(flows int, gap time.Duration, at time.Duration) Block {
		var open []Conn
		for index := range flows {
			created := start.Add(time.Duration(index) * gap)
			open = append(open, Conn{Outbound: "s", Down: 18 << 10, Up: 60, CreatedAt: created, PendingSince: created.Add(6 * time.Second)})
		}
		return Classify([]Server{reality}, Signals{Now: start.Add(at), Started: start.Add(-time.Hour), Open: open}, DefaultPolicy)["s"].Block
	}
	// limit-open: the third wait passes 90 s at 114 s, and the flows close at 150 s, after its read
	require.Equal(t, BlockUnknown, block(5, 9*time.Second, 113*time.Second))
	require.Equal(t, BlockLimit, block(5, 9*time.Second, 118*time.Second))
	// the 75 s the stand read at under a value of 30 s are far too early now
	require.Equal(t, BlockUnknown, block(5, 9*time.Second, 75*time.Second))
	// swap: without the filter of Instance.Connections the old flows it reads at 124 s would count, so
	// the check can fail
	require.Equal(t, BlockLimit, block(4, 9*time.Second, 124*time.Second))
	// flows 2 s apart cannot, however long they wait: no flow with data comes after their waits begin
	require.Equal(t, BlockUnknown, block(3, 2*time.Second, 124*time.Second))
}

// the server itself answering is no other server that answers
func TestClassifyOwnDelayIsNoOther(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	server := Server{Tag: "s", Kind: KindPlain, Destination: "192.0.2.1:1"}
	verdicts := Classify([]Server{server}, Signals{
		Now: now, Delays: map[string]uint16{"s": 100},
		Failure: func(string) (time.Time, bool) { return now.Add(-time.Minute), true },
	}, DefaultPolicy)
	require.Equal(t, BlockUnknown, verdicts["s"].Block)
}

// what ClassifyStages asks for next, and that it ends: a stage that is there is not asked for again
func stagesOf(kind Kind, build func(stages *Stages)) *Stages {
	stages := &Stages{Kind: kind}
	if kind == KindFingerprint || kind == KindPooled {
		stages.Fingerprint, stages.Alternate = "chrome", "firefox"
	}
	class := ClassNone
	if kind != KindUDP {
		stages.TCP = &class
	}
	if build != nil {
		build(stages)
	}
	return stages
}

func repeated(attempt Attempt, count int) []Attempt {
	attempts := make([]Attempt, count)
	for index := range attempts {
		attempts[index] = attempt
	}
	return attempts
}

func TestClassifyStages(t *testing.T) {
	const fullBytes, bandBytes = 64400, 18 << 10
	full := Attempt{Handshake: true, Bytes: fullBytes, Status: 200}
	cut := Attempt{Handshake: true, Bytes: bandBytes, Status: 200, Class: ClassNoHello}
	zero := Attempt{Class: ClassNoHello}
	short := Attempt{Handshake: true, Bytes: 6 << 10, Status: 200, Class: ClassNoHello}
	tiny := Attempt{Handshake: true, Bytes: 300, Status: 200, Class: ClassCut}
	slow := Attempt{Handshake: true, Bytes: 5 << 10, Status: 200, Class: ClassNoHello, Receiving: true}
	ended := Attempt{Handshake: true, Bytes: 1 << 10, Status: 200}
	refused := Attempt{Handshake: true, Bytes: 300, Status: 503}
	noTCP := ClassNoTCP
	dns := ClassDNS
	yes, no := true, false
	burst := func(fulls, cuts, zeros int) []Attempt {
		return append(append(repeated(full, fulls), repeated(cut, cuts)...), repeated(zero, zeros)...)
	}
	singleFull := func(stages *Stages) { stages.Single = &full }

	cases := []struct {
		name   string
		stages *Stages
		block  Block
		notes  []string
		kb     int64
		n      int
		fp     string
	}{
		// the dictionary, row by row
		{name: "none: a single and a burst in full", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst = &full, burst(8, 0, 0) }), block: BlockNone},
		{name: "limit: every flow cut", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst = &cut, burst(0, 8, 0) }), block: BlockLimit, kb: 18},
		{name: "no limit: a full single excludes it", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst = &full, burst(0, 8, 0) }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "no limit: a full single excludes it for another fingerprint too", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst, s.AlternateBurst = &full, burst(0, 5, 3), burst(0, 8, 0) }),
			block: BlockUnknown, notes: []string{NoteBurstAnyFP}},
		{name: "limit: a few lost among the cut", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst = &cut, burst(0, 6, 2) }), block: BlockLimit, kb: 18},
		{name: "freeze under a burst, fallback on", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Fallback, s.Single, s.Burst, s.AlternateBurst = true, &full, burst(5, 0, 3), burst(8, 0, 0)
		}), block: BlockFreeze, notes: []string{NoteCured}, fp: "chrome"},
		{name: "freeze under a burst, fallback off", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single, s.Burst, s.AlternateBurst = &full, burst(0, 0, 8), burst(8, 0, 0)
		}), block: BlockFreeze, notes: []string{NoteFallbackOff}, fp: "chrome"},
		{name: "freeze at once", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Fallback, s.Single, s.AlternateSingle = true, &zero, &full
		}), block: BlockFreeze, notes: []string{NoteCured}, fp: "chrome"},
		{name: "freeze at once, the other fingerprint cut", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.AlternateSingle = &zero, &cut }),
			block: BlockFreeze, notes: []string{NoteFallbackOff}, fp: "chrome"},
		{name: "wrongparams: verification of REALITY, the running outbound fails too", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Reality, s.Single, s.Control = true, &Attempt{Class: ClassVerify}, &Attempt{Class: ClassCut}
		}), block: BlockWrongParams},
		// a hello of the running outbound that verified, and an exit that does not answer, is no wrong key
		{name: "inconclusive: the control has a handshake and no bytes", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Reality, s.Single, s.Control = true, &Attempt{Class: ClassVerify}, &Attempt{Handshake: true, Class: ClassCut}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "silent: the control has a handshake and runs out of time", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Reality, s.Single, s.Control = true, &Attempt{Class: ClassVerify}, &Attempt{Handshake: true, Class: ClassNoHello}
		}), block: BlockUnknown, notes: []string{NoteServerSilent}},
		{name: "silent: the same without uTLS, a clock class", stages: stagesOf(KindTLS, func(s *Stages) {
			s.Single, s.Control = &Attempt{Class: ClassClock}, &Attempt{Handshake: true, Class: ClassNoHello}
		}), block: BlockUnknown, notes: []string{NoteServerSilent}},
		{name: "not silent: a control of a pool may send no hello", stages: stagesOf(KindPooled, func(s *Stages) {
			s.Reality, s.Single, s.Control = true, &Attempt{Class: ClassVerify}, &Attempt{Handshake: true, Class: ClassNoHello}
		}), block: BlockWrongParams},
		{name: "inconclusive: the same over UDP", stages: stagesOf(KindUDP, func(s *Stages) {
			s.Single, s.Control = &Attempt{Class: ClassVerify}, &Attempt{Handshake: true}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "wrongparams: a lazy dial's handshake is nothing", stages: stagesOf(KindTLS, func(s *Stages) {
			s.LazyDial, s.Single, s.Control = true, &Attempt{Class: ClassVerify}, &Attempt{Handshake: true, Class: ClassCut}
		}), block: BlockWrongParams, notes: []string{NoteTLSCert}},
		{name: "wrongparams: a dial without TLS is no handshake", stages: stagesOf(KindPlain, func(s *Stages) {
			s.Single, s.Control = &Attempt{Class: ClassVerify}, &Attempt{Handshake: true, Class: ClassCut}
		}), block: BlockWrongParams, notes: []string{NoteTLSCert}},
		// a pooled control may go over a live connection: it sends no hello
		{name: "pooled: the control carries a request, that proves nothing", stages: stagesOf(KindPooled, func(s *Stages) {
			s.Single, s.Control = &Attempt{Class: ClassVerify}, &Attempt{Handshake: true, Bytes: 200, Status: 204}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "pooled: the same for a lazy dial and a certificate out of time", stages: stagesOf(KindPooled, func(s *Stages) {
			s.LazyDial, s.Single, s.Control = true, &Attempt{Handshake: true, Class: ClassClock}, &Attempt{Handshake: true, Bytes: 200, Status: 204}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "pooled: the control has no bytes", stages: stagesOf(KindPooled, func(s *Stages) {
			s.Single, s.Control = &Attempt{Class: ClassVerify}, &Attempt{Class: ClassCut}
		}), block: BlockWrongParams, notes: []string{NoteTLSCert}},
		{name: "pooled: its handshake says nothing, no bytes are no bytes", stages: stagesOf(KindPooled, func(s *Stages) {
			s.Single, s.Control = &Attempt{Class: ClassVerify}, &Attempt{Handshake: true, Class: ClassCut}
		}), block: BlockWrongParams, notes: []string{NoteTLSCert}},
		{name: "wrongparams: a certificate", stages: stagesOf(KindTLS, func(s *Stages) { s.Single, s.Control = &Attempt{Class: ClassVerify}, &Attempt{} }),
			block: BlockWrongParams, notes: []string{NoteTLSCert}},
		{name: "wrongparams: the clock may be why", stages: stagesOf(KindTLS, func(s *Stages) { s.Single, s.Control = &Attempt{Class: ClassClock}, &Attempt{} }),
			block: BlockWrongParams, notes: []string{NoteClockSuspect, NoteTLSCert}},
		{name: "wrongparams: the other fingerprint got as far", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Reality, s.Single, s.AlternateSingle, s.Control = true, &zero, &Attempt{Class: ClassVerify}, &Attempt{}
		}), block: BlockWrongParams},
		{name: "wrongparams: the other fingerprint met the clock", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Reality, s.Single, s.AlternateSingle, s.Control = true, &zero, &Attempt{Class: ClassClock}, &Attempt{}
		}), block: BlockWrongParams, notes: []string{NoteClockSuspect}},
		{name: "probe_hello_refused: verification, the running outbound passes", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Reality, s.Single, s.Control = true, &Attempt{Class: ClassVerify}, &Attempt{Handshake: true, Bytes: 200, Status: 204}
		}), block: BlockUnknown, notes: []string{NoteProbeHelloRefused}},
		{name: "probe_hello_refused: a certificate, the running outbound passes", stages: stagesOf(KindTLS, func(s *Stages) {
			s.Single, s.Control = &Attempt{Class: ClassClock}, &Attempt{Handshake: true, Bytes: 200, Status: 204}
		}), block: BlockUnknown, notes: []string{NoteProbeHelloRefused}},
		{name: "probe_hello_refused: the other fingerprint, the running outbound passes", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single, s.AlternateSingle, s.Control = &zero, &Attempt{Class: ClassVerify}, &Attempt{Handshake: true, Bytes: 200, Status: 204}
		}), block: BlockUnknown, notes: []string{NoteProbeHelloRefused}},
		// bytes came, the time ran out after them: the exit answers, so it is no silence
		{name: "probe_hello_refused: the control has bytes and runs out of time", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Reality, s.Single, s.Control = true, &Attempt{Class: ClassVerify}, &Attempt{Handshake: true, Bytes: 200, Status: 200, Class: ClassNoHello}
		}), block: BlockUnknown, notes: []string{NoteProbeHelloRefused}},
		{name: "rejected: closed on two addresses", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single = &Attempt{Handshake: true, Class: ClassCut}
			s.Second = &Attempt{Handshake: true, Class: ClassCut}
		}), block: BlockRejected},
		{name: "not rejected: the second address answers", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single = &Attempt{Handshake: true, Class: ClassCut}
			s.Second = &Attempt{Handshake: true, Bytes: 200, Status: 204}
		}), block: BlockUnknown, notes: []string{NoteTargetFailed}},
		{name: "not rejected, not the address: the second answers with something else", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single = &Attempt{Handshake: true, Class: ClassCut}
			s.Second = &Attempt{Handshake: true, Bytes: 66, Status: 400}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "not rejected: the second request timed out", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single = &Attempt{Handshake: true, Class: ClassCut}
			s.Second = &Attempt{Handshake: true, Class: ClassNoHello}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "silent: a handshake and no answer in time", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single = &Attempt{Handshake: true, Class: ClassNoHello}
		}), block: BlockUnknown, notes: []string{NoteServerSilent}},
		{name: "silent: the same without uTLS", stages: stagesOf(KindTLS, func(s *Stages) {
			s.Single = &Attempt{Handshake: true, Class: ClassNoHello}
		}), block: BlockUnknown, notes: []string{NoteServerSilent}},
		{name: "silent: another fingerprint has a handshake and no answer in time", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single, s.AlternateSingle = &zero, &Attempt{Handshake: true, Class: ClassNoHello}
		}), block: BlockUnknown, notes: []string{NoteServerSilent}},
		{name: "not silent: another fingerprint has a handshake and another end", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single, s.AlternateSingle = &zero, &Attempt{Handshake: true, Class: ClassOther}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "not silent: an end that is no timeout", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single = &Attempt{Handshake: true, Class: ClassOther}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "not silent: a pooled dial proves no handshake", stages: stagesOf(KindPooled, func(s *Stages) {
			s.Single = &Attempt{Handshake: true, Class: ClassNoHello}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "not silent: a lazy dial proves no handshake", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.LazyDial, s.Single = true, &Attempt{Handshake: true, Class: ClassNoHello}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "not silent: a plain dial is no handshake", stages: stagesOf(KindPlain, func(s *Stages) {
			s.Single = &Attempt{Handshake: true, Class: ClassNoHello}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "not silent: nor one over UDP", stages: stagesOf(KindUDP, func(s *Stages) {
			s.Single = &Attempt{Handshake: true, Class: ClassNoHello}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "download leg: no answer may be of it, no relay is asked", stages: stagesOf(KindPooled, func(s *Stages) {
			s.DownloadLeg, s.Single, s.AlternateSingle = true, &zero, &zero
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "download leg: a reset without a handshake", stages: stagesOf(KindPooled, func(s *Stages) {
			s.DownloadLeg, s.Single, s.AlternateSingle = true, &Attempt{Class: ClassCut}, &Attempt{Class: ClassCut}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "download leg: without a fingerprint to compare", stages: stagesOf(KindTLS, func(s *Stages) { s.DownloadLeg, s.Single = true, &zero }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "download leg: the other fingerprint passes, the leg answers", stages: stagesOf(KindPooled, func(s *Stages) {
			s.DownloadLeg, s.Single, s.AlternateSingle = true, &zero, &full
		}), block: BlockFreeze, notes: []string{NoteFallbackOff}, fp: "chrome"},
		{name: "download leg: a main leg over UDP is no proof either", stages: stagesOf(KindUDP, func(s *Stages) { s.DownloadLeg, s.Single = true, &zero }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "download leg: no TCP to the main server is as it was", stages: stagesOf(KindPooled, func(s *Stages) {
			s.DownloadLeg, s.TCP, s.Uplink, s.Relay = true, &noTCP, &yes, &RelayResult{}
		}), block: BlockUnreachable},
		{name: "hellodrop: the other fingerprint gets no answer either, no relay", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single, s.AlternateSingle, s.Relay = &zero, &zero, &RelayResult{}
		}), block: BlockHelloDrop},
		{name: "hellodrop: a reset is no answer", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single, s.AlternateSingle, s.Relay = &Attempt{Class: ClassCut}, &Attempt{Class: ClassCut}, &RelayResult{}
		}), block: BlockHelloDrop},
		{name: "hellodrop without uTLS: no fingerprint to compare", stages: stagesOf(KindTLS, func(s *Stages) { s.Single, s.Relay = &zero, &RelayResult{} }), block: BlockHelloDrop},
		{name: "pathblock: no TCP, proven through a relay", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.TCP, s.Uplink, s.Relay = &noTCP, &yes, &RelayResult{Tested: 1, Proven: true}
		}), block: BlockPathBlock},
		{name: "pathblock: a hello drop, proven through a relay", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single, s.AlternateSingle, s.Relay = &zero, &zero, &RelayResult{Tested: 2, Proven: true}
		}), block: BlockPathBlock},
		{name: "dead: relays work, the server stays silent", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.TCP, s.Uplink, s.Relay = &noTCP, &yes, &RelayResult{Tested: 2}
		}), block: BlockDead, n: 2},
		// one relay may be unstable itself: too few to name a server dead
		{name: "not dead: no TCP, one relay works, the server stays silent through it", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.TCP, s.Uplink, s.Relay = &noTCP, &yes, &RelayResult{Tested: 1}
		}), block: BlockUnreachable, notes: []string{NoteRelaySilent}, n: 1},
		{name: "not dead: no TCP for the dial, one relay", stages: stagesOf(KindPooled, func(s *Stages) {
			s.Single, s.Uplink, s.Relay = &Attempt{Class: ClassNoTCP}, &yes, &RelayResult{Tested: 1}
		}), block: BlockUnreachable, notes: []string{NoteRelaySilent}, n: 1},
		{name: "a hello drop stays one, silent through relays too", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single, s.AlternateSingle, s.Relay = &zero, &zero, &RelayResult{Tested: 1}
		}), block: BlockHelloDrop, notes: []string{NoteRelaySilent}, n: 1},
		{name: "upgrade_in_dial: a hello drop that may be of the upgrade", stages: stagesOf(KindTLS, func(s *Stages) {
			s.UpgradeInDial, s.Single, s.Relay = true, &zero, &RelayResult{}
		}), block: BlockHelloDrop, notes: []string{NoteUpgradeInDial}},
		{name: "upgrade_in_dial: with relays silent too", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.UpgradeInDial, s.Single, s.AlternateSingle, s.Relay = true, &zero, &zero, &RelayResult{Tested: 2}
		}), block: BlockHelloDrop, notes: []string{NoteUpgradeInDial, NoteRelaySilent}, n: 2},
		{name: "upgrade_in_dial: a relay proves more", stages: stagesOf(KindTLS, func(s *Stages) {
			s.UpgradeInDial, s.Single, s.Relay = true, &zero, &RelayResult{Tested: 1, Proven: true}
		}), block: BlockPathBlock},
		{name: "upgrade_in_dial: no TCP is no hello drop", stages: stagesOf(KindTLS, func(s *Stages) {
			s.UpgradeInDial, s.TCP, s.Uplink, s.Relay = true, &noTCP, &yes, &RelayResult{}
		}), block: BlockUnreachable},
		{name: "a closed request on a lazy dial tells nothing", stages: stagesOf(KindPooled, func(s *Stages) {
			s.LazyDial, s.Single = true, &Attempt{Handshake: true, Class: ClassCut}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "a lazy dial: verification is still an answer", stages: stagesOf(KindPooled, func(s *Stages) {
			s.LazyDial, s.Single, s.Control = true, &Attempt{Handshake: true, Class: ClassVerify}, &Attempt{}
		}), block: BlockWrongParams, notes: []string{NoteTLSCert}},
		{name: "unreachable: nobody to ask", stages: stagesOf(KindFingerprint, func(s *Stages) { s.TCP, s.Uplink, s.Relay = &noTCP, &yes, &RelayResult{} }), block: BlockUnreachable},
		{name: "unreachable: uplink down", stages: stagesOf(KindFingerprint, func(s *Stages) { s.TCP, s.Uplink = &noTCP, &no }), block: BlockUnreachable, notes: []string{NoteUplinkDown}},
		{name: "unreachable: the name does not resolve", stages: stagesOf(KindFingerprint, func(s *Stages) { s.TCP, s.Uplink = &dns, &yes }), block: BlockUnreachable, notes: []string{NoteDNSFailed}},
		{name: "unreachable: the name does not resolve for the dial", stages: stagesOf(KindUDP, func(s *Stages) { s.Single, s.Uplink = &Attempt{Class: ClassDNS}, &yes }), block: BlockUnreachable, notes: []string{NoteDNSFailed}},
		{name: "unreachable: no name under an outage is the outage", stages: stagesOf(KindFingerprint, func(s *Stages) { s.TCP, s.Uplink = &dns, &no }), block: BlockUnreachable, notes: []string{NoteUplinkDown}},
		{name: "unreachable: no name for the dial under an outage is the outage", stages: stagesOf(KindUDP, func(s *Stages) { s.Single, s.Uplink = &Attempt{Class: ClassDNS}, &no }), block: BlockUnreachable, notes: []string{NoteUplinkDown}},
		{name: "unreachable: no relay can prove UDP", stages: stagesOf(KindUDP, func(s *Stages) { s.Single, s.Uplink = &zero, &yes }), block: BlockUnreachable},
		{name: "unreachable: no relay can prove what has no TLS", stages: stagesOf(KindPlain, func(s *Stages) { s.TCP, s.Uplink = &noTCP, &yes }), block: BlockUnreachable},
		{name: "not applicable: through a tunnel", stages: &Stages{Kind: KindNone}, block: BlockUnknown, notes: []string{NoteNotApplicable}},

		// bytes outrank the error
		{name: "bytes over an error: a full single that ended in a reset", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single = &Attempt{Handshake: true, Bytes: fullBytes, Status: 200, Class: ClassVerify}
			s.Burst = burst(8, 0, 0)
		}), block: BlockNone},
		{name: "bytes over an error: a stray verification in a burst is a lost flow", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single = &full
			s.Burst = append(burst(7, 0, 0), Attempt{Class: ClassVerify})
		}), block: BlockNone, notes: []string{NoteSomeLost}},

		// the status of the address of the check
		{name: "target_failed: a single refused by the address, the second answers 204", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single = &Attempt{Handshake: true, Bytes: 900, Status: 403}
			s.Second = &Attempt{Handshake: true, Bytes: 200, Status: 204}
		}), block: BlockUnknown, notes: []string{NoteTargetFailed}},
		{name: "not target_failed: the fallback of a server answers both", stages: stagesOf(KindTLS, func(s *Stages) {
			s.Single = &Attempt{Handshake: true, Bytes: 66, Status: 400}
			s.Second = &Attempt{Handshake: true, Bytes: 66, Status: 400}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "not target_failed: the second gets no answer", stages: stagesOf(KindTLS, func(s *Stages) {
			s.Single = &Attempt{Handshake: true, Bytes: 900, Status: 403}
			s.Second = &Attempt{Handshake: true, Class: ClassCut}
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "target_failed: a burst limited by the address", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single = &full
			s.Burst = append(burst(7, 0, 0), Attempt{Handshake: true, Bytes: 900, Status: 429})
		}), block: BlockUnknown, notes: []string{NoteTargetFailed}},
		{name: "a cut in the header has no status yet", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single, s.Burst = &Attempt{Handshake: true, Bytes: 200}, burst(8, 0, 0)
		}), block: BlockNone},

		// the thresholds of a burst
		{name: "one lost", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst = &full, burst(7, 0, 1) }), block: BlockNone, notes: []string{NoteSomeLost}},
		{name: "two lost", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst = &full, burst(6, 0, 2) }), block: BlockNone, notes: []string{NoteSomeLost}},
		{name: "two lost, the rest cut or full", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst = &full, burst(3, 3, 2) }), block: BlockNone, notes: []string{NoteSomeLost}},
		{name: "another fingerprint passes more and loses less", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst, s.AlternateBurst = &full, burst(2, 0, 6), burst(6, 0, 2) }),
			block: BlockFreeze, notes: []string{NoteFallbackOff}, fp: "chrome"},
		{name: "burst_any_fp: another fingerprint loses as many", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst, s.AlternateBurst = &full, burst(5, 0, 3), burst(5, 0, 3) }),
			block: BlockUnknown, notes: []string{NoteBurstAnyFP}},
		{name: "burst_any_fp: another fingerprint loses few, passes no more", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst, s.AlternateBurst = &full, burst(5, 0, 3), burst(5, 2, 1) }),
			block: BlockUnknown, notes: []string{NoteBurstAnyFP}},
		// a line that loses a share of parallel connections is no freeze because the other lost one less
		{name: "burst_any_fp: a gap of one flow", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst, s.AlternateBurst = &full, burst(5, 0, 3), burst(6, 0, 2) }),
			block: BlockUnknown, notes: []string{NoteBurstAnyFP}},
		{name: "freeze: a gap of two flows", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst, s.AlternateBurst = &full, burst(5, 0, 3), burst(7, 0, 1) }),
			block: BlockFreeze, notes: []string{NoteFallbackOff}, fp: "chrome"},
		{name: "burst_any_fp: partial ends, less than half of the other in full", stages: stagesOf(KindFingerprint, func(s *Stages) {
			partial := Attempt{Handshake: true, Bytes: 1 << 10, Status: 200}
			s.Single, s.Burst = &full, append(repeated(zero, 3), repeated(partial, 5)...)
			s.AlternateBurst = append(repeated(full, 1), repeated(partial, 7)...)
		}), block: BlockUnknown, notes: []string{NoteBurstAnyFP}},
		{name: "burst_any_fp: ends in the band, less than half of the other in full", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single, s.Burst, s.AlternateBurst = &full, burst(0, 5, 3), burst(1, 7, 0)
		}), block: BlockUnknown, notes: []string{NoteBurstAnyFP}},
		{name: "freeze: exactly half of the other in full", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst, s.AlternateBurst = &full, burst(0, 0, 8), burst(4, 4, 0) }),
			block: BlockFreeze, notes: []string{NoteFallbackOff}, fp: "chrome"},
		{name: "stand_in: a freeze of a fingerprint the link does not send, fallback off", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.StandIn, s.Single, s.AlternateSingle = true, &zero, &full
		}), block: BlockFreeze, notes: []string{NoteStandIn}, fp: "chrome"},
		{name: "stand_in: fallback on", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.StandIn, s.Fallback, s.Single, s.Burst, s.AlternateBurst = true, true, &full, burst(0, 0, 8), burst(8, 0, 0)
		}), block: BlockFreeze, notes: []string{NoteStandIn, NoteCured}, fp: "chrome"},
		{name: "burst_any_fp: less than half of another fingerprint passes", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst, s.AlternateBurst = &full, burst(5, 0, 3), burst(3, 0, 5) }),
			block: BlockUnknown, notes: []string{NoteBurstAnyFP}},
		{name: "burst_any_fp: without a fingerprint to compare", stages: stagesOf(KindTLS, func(s *Stages) { s.Single, s.Burst = &full, burst(5, 0, 3) }),
			block: BlockUnknown, notes: []string{NoteBurstAnyFP}},
		{name: "burst_any_fp: without TLS", stages: stagesOf(KindPlain, func(s *Stages) { s.Single, s.Burst = &full, burst(0, 0, 8) }),
			block: BlockUnknown, notes: []string{NoteBurstAnyFP}},
		{name: "limit: with zeros, another fingerprint is cut as well", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst, s.AlternateBurst = &cut, burst(0, 5, 3), burst(0, 8, 0) }),
			block: BlockLimit, kb: 18},
		{name: "a burst of mixed ends", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst = &full, burst(4, 4, 0) }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "no limit: complete answers in the band", stages: stagesOf(KindFingerprint, func(s *Stages) {
			page := Attempt{Handshake: true, Bytes: 20 << 10, Status: 200}
			s.Single, s.Burst = &page, repeated(page, 8)
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "no limit: complete answers in the band, without TLS", stages: stagesOf(KindPlain, func(s *Stages) {
			page := Attempt{Handshake: true, Bytes: 20 << 10, Status: 200}
			s.Single, s.Burst = &page, repeated(page, 8)
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "no limit: complete answers in the band, pooled", stages: stagesOf(KindPooled, func(s *Stages) {
			page := Attempt{Handshake: true, Bytes: 20 << 10, Status: 200}
			s.Framed, s.Single, s.Burst = true, &page, repeated(page, 3)
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "no limit: flows in the band still receiving", stages: stagesOf(KindFingerprint, func(s *Stages) {
			receiving := Attempt{Handshake: true, Bytes: 18 << 10, Status: 200, Class: ClassNoHello, Receiving: true}
			s.Single, s.Burst = &receiving, repeated(receiving, 8)
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "no limit: bytes in the band with no status are no download", stages: stagesOf(KindFingerprint, func(s *Stages) {
			other := Attempt{Handshake: true, Bytes: 18 << 10, Class: ClassOther}
			s.Single, s.Burst = &other, repeated(other, 8)
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "a burst of small ends", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single, s.Burst = &full, repeated(Attempt{Handshake: true, Bytes: 1 << 10, Status: 200}, 8)
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},

		// what the kinds change
		{name: "pooled: no freeze from sequential requests", stages: stagesOf(KindPooled, func(s *Stages) { s.Single, s.Burst = &full, burst(0, 0, 3) }),
			block: BlockUnknown, notes: []string{NoteBurstAnyFP}},
		{name: "pooled: limit", stages: stagesOf(KindPooled, func(s *Stages) { s.Single, s.Burst = &cut, burst(0, 3, 0) }), block: BlockLimit, kb: 18},
		{name: "pooled: none", stages: stagesOf(KindPooled, func(s *Stages) { s.Single, s.Burst = &full, burst(3, 0, 0) }), block: BlockNone},
		{name: "framed: a limit whose flows end under the band", stages: stagesOf(KindPooled, func(s *Stages) { s.Framed, s.Single, s.Burst = true, &short, repeated(short, 3) }), block: BlockLimit, kb: 6},
		{name: "framed: flows on both sides of the end of the band", stages: stagesOf(KindPooled, func(s *Stages) {
			s.Framed, s.Single, s.Burst = true, &short, []Attempt{short, cut, short}
		}), block: BlockLimit, kb: 10},
		{name: "framed: under the band, a request lost", stages: stagesOf(KindPooled, func(s *Stages) { s.Framed, s.Single, s.Burst = true, &short, []Attempt{short, zero, short} }), block: BlockLimit, kb: 6},
		{name: "framed: a reset of xhttp arrives as text, a cut all the same", stages: stagesOf(KindPooled, func(s *Stages) {
			reset := Attempt{Handshake: true, Bytes: 6 << 10, Status: 200, Class: ClassOther}
			s.Framed, s.Single, s.Burst = true, &reset, repeated(reset, 3)
		}), block: BlockLimit, kb: 6},
		{name: "framed: at the floor", stages: stagesOf(KindPooled, func(s *Stages) {
			floor := Attempt{Handshake: true, Bytes: DefaultPolicy.ShortLow, Status: 200, Class: ClassCut}
			s.Framed, s.Single, s.Burst = true, &floor, repeated(floor, 3)
		}), block: BlockLimit, kb: 2},
		{name: "framed: under the floor, the headers and no more", stages: stagesOf(KindPooled, func(s *Stages) { s.Framed, s.Single, s.Burst = true, &tiny, repeated(tiny, 3) }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "framed: a timeout after the headers", stages: stagesOf(KindPooled, func(s *Stages) {
			headers := Attempt{Handshake: true, Bytes: 300, Status: 200, Class: ClassNoHello}
			s.Framed, s.Single, s.Burst = true, &headers, repeated(headers, 3)
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "framed: no status, an answer that is no HTTP", stages: stagesOf(KindPooled, func(s *Stages) {
			other := Attempt{Handshake: true, Bytes: 3 << 10, Class: ClassOther}
			s.Framed, s.Single, s.Burst = true, &other, repeated(other, 3)
		}), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "framed: a slow exit, still receiving", stages: stagesOf(KindPooled, func(s *Stages) { s.Framed, s.Single, s.Burst = true, &slow, repeated(slow, 3) }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "framed: one flow and two lost name no limit", stages: stagesOf(KindPooled, func(s *Stages) { s.Framed, s.Single, s.Burst = true, &short, []Attempt{zero, zero, short} }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "pooled: one flow in the band and two lost name no limit", stages: stagesOf(KindPooled, func(s *Stages) { s.Single, s.Burst = &cut, []Attempt{zero, zero, cut} }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "pooled: two flows in the band and one lost name a limit", stages: stagesOf(KindPooled, func(s *Stages) { s.Single, s.Burst = &cut, []Attempt{cut, zero, cut} }),
			block: BlockLimit, kb: 18},
		{name: "multiplex: a probe goes without it, under the band is not in it", stages: stagesOf(KindPooled, func(s *Stages) { s.Single, s.Burst = &short, repeated(short, 3) }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "framed: a full single excludes a limit", stages: stagesOf(KindPooled, func(s *Stages) { s.Framed, s.Single, s.Burst = true, &full, repeated(short, 3) }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "framed: a full flow keeps those under the band out", stages: stagesOf(KindPooled, func(s *Stages) { s.Framed, s.Single, s.Burst = true, &short, []Attempt{full, short, short} }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "framed: a short answer that ended by itself is no cut", stages: stagesOf(KindPooled, func(s *Stages) { s.Framed, s.Single, s.Burst = true, &ended, repeated(ended, 3) }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "framed: the status of the target wins in a burst", stages: stagesOf(KindPooled, func(s *Stages) { s.Framed, s.Single, s.Burst = true, &short, []Attempt{short, short, refused} }),
			block: BlockUnknown, notes: []string{NoteTargetFailed}},
		{name: "framed: the status of the target wins in a single", stages: stagesOf(KindPooled, func(s *Stages) {
			s.Framed, s.Single, s.Second, s.Burst = true, &refused, &Attempt{Handshake: true, Bytes: 200, Status: 204}, repeated(short, 3)
		}), block: BlockUnknown, notes: []string{NoteTargetFailed}},
		{name: "framed: all lost is still burst_any_fp", stages: stagesOf(KindPooled, func(s *Stages) { s.Framed, s.Single, s.Burst = true, &short, repeated(zero, 3) }),
			block: BlockUnknown, notes: []string{NoteBurstAnyFP}},
		{name: "fingerprint: under the band is not in it", stages: stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst = &short, repeated(short, 8) }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "fingerprint: burst_any_fp is as it was", stages: stagesOf(KindFingerprint, func(s *Stages) {
			s.Single, s.Burst, s.AlternateBurst = &short, append(repeated(short, 5), repeated(zero, 3)...), append(repeated(short, 5), repeated(zero, 3)...)
		}), block: BlockUnknown, notes: []string{NoteBurstAnyFP}},
		{name: "tls: under the band is not in it", stages: stagesOf(KindTLS, func(s *Stages) { s.Single, s.Burst = &short, repeated(short, 8) }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "plain: under the band is not in it", stages: stagesOf(KindPlain, func(s *Stages) { s.Single, s.Burst = &short, repeated(short, 8) }),
			block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "udp: a single is all", stages: stagesOf(KindUDP, singleFull), block: BlockNone},
		{name: "udp: a single stopped on the way", stages: stagesOf(KindUDP, func(s *Stages) { s.Single = &cut }), block: BlockUnknown, notes: []string{NoteInconclusive}},
		{name: "plain: silence after a dial that is no handshake", stages: stagesOf(KindPlain, func(s *Stages) { s.Single = &zero }), block: BlockUnknown, notes: []string{NoteInconclusive}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			verdict, step := ClassifyStages(testCase.stages, DefaultPolicy)
			require.Equal(t, StepDone, step)
			require.Equal(t, testCase.block, verdict.Block)
			require.Equal(t, SourceActive, verdict.Source)
			require.ElementsMatch(t, testCase.notes, verdict.Notes)
			require.Equal(t, testCase.kb, verdict.KB)
			require.Equal(t, testCase.n, verdict.N)
			require.Equal(t, testCase.fp, verdict.Fingerprint)
		})
	}
}

// A burst of mixed ends tells the bytes of its flows, to set the thresholds from.
func TestClassifyStagesNamesTheBytes(t *testing.T) {
	single := Attempt{Handshake: true, Bytes: 300, Status: 200, Class: ClassCut}
	verdict, step := ClassifyStages(stagesOf(KindPooled, func(s *Stages) {
		s.Single = &single
		s.Burst = []Attempt{single, {Handshake: true, Bytes: 5 << 10, Status: 200, Class: ClassNoHello, Receiving: true}, {}}
	}), DefaultPolicy)
	require.Equal(t, StepDone, step)
	require.Contains(t, verdict.Notes, NoteInconclusive)
	require.Contains(t, verdict.Why, "bytes: 300 5120+ 0")
}

// What it asks for next, stage by stage.
func TestClassifyStagesSteps(t *testing.T) {
	full := Attempt{Handshake: true, Bytes: 64400, Status: 200}
	zero := Attempt{Class: ClassNoHello}
	closed := Attempt{Handshake: true, Class: ClassCut}
	noTCP := ClassNoTCP
	yes := true
	step := func(stages *Stages) Step {
		_, next := ClassifyStages(stages, DefaultPolicy)
		return next
	}
	require.Equal(t, StepTCP, step(&Stages{Kind: KindFingerprint}))
	require.Equal(t, StepSingle, step(&Stages{Kind: KindUDP}))
	require.Equal(t, StepSingle, step(stagesOf(KindFingerprint, nil)))
	require.Equal(t, StepBurst, step(stagesOf(KindFingerprint, func(s *Stages) { s.Single = &full })))
	require.Equal(t, StepBurst, step(stagesOf(KindPooled, func(s *Stages) { s.Single = &full })))
	require.Equal(t, StepAlternateBurst, step(stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.Burst = &full, repeated(zero, 8) })))
	require.Equal(t, StepAlternateSingle, step(stagesOf(KindFingerprint, func(s *Stages) { s.Single = &zero })))
	require.Equal(t, StepSecond, step(stagesOf(KindFingerprint, func(s *Stages) { s.Single = &closed })))
	require.Equal(t, StepRelay, step(stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.AlternateSingle = &zero, &zero })))
	require.Equal(t, StepUplink, step(stagesOf(KindFingerprint, func(s *Stages) { s.TCP = &noTCP })))
	require.Equal(t, StepRelay, step(stagesOf(KindFingerprint, func(s *Stages) { s.TCP, s.Uplink = &noTCP, &yes })))
	require.Equal(t, StepUplink, step(stagesOf(KindUDP, func(s *Stages) { s.Single = &zero })))
	require.Equal(t, StepControl, step(stagesOf(KindFingerprint, func(s *Stages) { s.Single = &Attempt{Class: ClassVerify} })))
	require.Equal(t, StepControl, step(stagesOf(KindTLS, func(s *Stages) { s.Single = &Attempt{Class: ClassClock} })))
	require.Equal(t, StepControl, step(stagesOf(KindFingerprint, func(s *Stages) { s.Single, s.AlternateSingle = &zero, &Attempt{Class: ClassVerify} })))
	require.Equal(t, StepSecond, step(stagesOf(KindFingerprint, func(s *Stages) { s.Single = &Attempt{Handshake: true, Bytes: 66, Status: 400} })), "the status of an address is asked of the other first")
	require.Equal(t, StepDone, step(stagesOf(KindPooled, func(s *Stages) { s.LazyDial, s.Single = true, &closed })), "no second address: it would tell nothing")
	require.Equal(t, StepDone, step(stagesOf(KindPooled, func(s *Stages) { s.DownloadLeg, s.Single, s.AlternateSingle = true, &zero, &zero })), "no relay: it would be asked of the main server")
	dns := ClassDNS
	require.Equal(t, StepUplink, step(stagesOf(KindFingerprint, func(s *Stages) { s.TCP = &dns })), "no name: the uplink first")
	require.Equal(t, StepUplink, step(stagesOf(KindFingerprint, func(s *Stages) { s.Single = &Attempt{Class: ClassDNS} })))
	require.Equal(t, StepDone, step(stagesOf(KindFingerprint, func(s *Stages) { s.TCP, s.Uplink = &dns, &yes })))
}

// One relay names nobody dead, and what it says is in the Why, for the log.
func TestClassifyStagesOneRelay(t *testing.T) {
	noTCP := ClassNoTCP
	yes := true
	verdict, step := ClassifyStages(stagesOf(KindFingerprint, func(s *Stages) {
		s.TCP, s.Uplink, s.Relay = &noTCP, &yes, &RelayResult{Tested: 1}
	}), DefaultPolicy)
	require.Equal(t, StepDone, step)
	require.Equal(t, BlockUnreachable, verdict.Block)
	require.Equal(t, "no answer from here, nor through 1 working server", verdict.Why)

	zero := Attempt{Class: ClassNoHello}
	for tested, tail := range map[int]string{1: ", nor through 1 working server", 2: ", nor through 2 working servers"} {
		verdict, _ = ClassifyStages(stagesOf(KindFingerprint, func(s *Stages) {
			s.Single, s.AlternateSingle, s.Relay = &zero, &zero, &RelayResult{Tested: tested}
		}), DefaultPolicy)
		require.Equal(t, BlockHelloDrop, verdict.Block)
		require.True(t, strings.HasSuffix(verdict.Why, tail), verdict.Why)
	}
}

func TestProbeFingerprint(t *testing.T) {
	for configured, probed := range map[string]string{
		"":           "chrome",
		"chrome":     "chrome",
		"chrome_pq":  "chrome_pq",
		"firefox":    "firefox",
		"safari":     "safari",
		"edge":       "chrome",
		"ios":        "chrome",
		"qq":         "chrome",
		"360":        "chrome",
		"android":    "chrome",
		"random":     "chrome",
		"randomized": "chrome",
	} {
		require.Equal(t, probed, ProbeFingerprint(configured), configured)
	}
	require.Equal(t, "firefox", AlternateFingerprint("chrome"))
	require.Equal(t, "chrome", AlternateFingerprint("firefox"))
}
