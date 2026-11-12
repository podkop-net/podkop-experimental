package supervisor

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/detect"
)

// The block detector of the servers. What the traffic shows is read when asked (Detect), and a
// probe of a server runs on demand, off the goroutine of Run: it takes up to detect.Budget and
// Run serves the reloads and the stop. One server at a time: its burst may freeze the server for
// the real connections, and probes side by side would measure each other.

const (
	// DiagnoseMinInterval is how long a destination is left alone after a probe: the freeze a
	// burst may bring lasts up to 2 minutes, and a probe within it measures the one before.
	DiagnoseMinInterval = 3 * time.Minute
	// a verdict of a probe stands over what the traffic shows for so long, a weak one for
	// DiagnoseMinInterval (holds)
	activeVerdictTTL = 30 * time.Minute
	// what the traffic shows is read at most so often: a bbolt view per server
	passiveCacheFor = 5 * time.Second
	// how many servers may wait for a probe
	diagnoseQueueLimit = 64
)

// activeVerdict is what a probe found of a server, and of which outbound.
type activeVerdict struct {
	verdict detect.Verdict
	at      time.Time
	hash    string
}

// weak tells a verdict that does not name what is wrong with the server: the probe found nothing
// clear, something of the state of the router or of its own hello, or a silence that may end any
// minute.
func (a activeVerdict) weak() bool {
	return slices.ContainsFunc(a.verdict.Notes, func(note string) bool {
		switch note {
		case detect.NoteInconclusive, detect.NoteTargetFailed, detect.NoteUplinkDown, detect.NoteDNSFailed, detect.NoteClockSuspect, detect.NoteProbeHelloRefused, detect.NoteServerSilent:
			return true
		}
		return false
	})
}

// holds tells that a verdict of a probe stands over what the traffic shows of the server. A strong
// one stands for activeVerdictTTL. A weak one is the answer to a press of the button, so it lives as
// long as the next press has to wait, and stands over everything but the passive verdicts that say
// more than it does: a limit, a hello drop and failed handshakes. A wrongparams stands over failed
// handshakes too: those are its symptom and it is their cause.
func (a activeVerdict) holds(passive detect.Verdict, now time.Time) bool {
	age := now.Sub(a.at)
	if !a.weak() {
		return age < activeVerdictTTL
	}
	if age >= DiagnoseMinInterval {
		return false
	}
	if passive.Block == detect.BlockLimit || passive.Block == detect.BlockHelloDrop {
		return false
	}
	return a.verdict.Block == detect.BlockWrongParams || !slices.Contains(passive.Notes, detect.NoteHandshakeFailed)
}

// freezeNotes are the notes of a freeze as the fallback is now: the proof of the freeze stays, the
// advice follows the settings. A copy: a verdict shares its notes with those read before.
func freezeNotes(notes []string, fallback bool) []string {
	rebuilt := slices.DeleteFunc(slices.Clone(notes), func(note string) bool {
		return note == detect.NoteCured || note == detect.NoteFallbackOff
	})
	switch {
	case fallback:
		rebuilt = append(rebuilt, detect.NoteCured)
	case !slices.Contains(rebuilt, detect.NoteStandIn):
		rebuilt = append(rebuilt, detect.NoteFallbackOff)
	}
	return rebuilt
}

// diagnosis is the state of the probes, under its own lock: a read of the status does not wait
// for it, nor it for a read of the status (the two are never held together).
type diagnosis struct {
	access sync.Mutex
	active map[string]activeVerdict
	// lastByDestination is when a probe of a destination started
	lastByDestination map[string]time.Time
	// current is the server a probe runs on, while a worker runs; queue those after it
	current string
	queue   []string
	// passive is what Classify last found, of the configuration of passiveEpoch
	passive      map[string]detect.Verdict
	passiveAt    time.Time
	passiveEpoch uint64
}

// detectSnapshot is what the detector reads of what runs.
type detectSnapshot struct {
	instance Instance
	servers  []detect.Server
	fallback bool
	epoch    uint64
	// stable is the identity, way and cure of each server by tag, for the report
	stable map[string]detect.Identity
	// staleCures counts the stored treatments that name no live server
	staleCures int
	// maskList is the public list of names a mask search downloads, "" when off
	maskList string
}

func (s *Supervisor) detectSnapshot() detectSnapshot {
	s.statusAccess.Lock()
	defer s.statusAccess.Unlock()
	return detectSnapshot{instance: s.live, servers: s.liveServers, fallback: s.liveFallback, epoch: s.liveEpoch, stable: s.liveStable, staleCures: s.liveStaleCures, maskList: s.liveMaskList}
}

func findServer(servers []detect.Server, tag string) (detect.Server, bool) {
	index := slices.IndexFunc(servers, func(server detect.Server) bool { return server.Tag == tag })
	if index < 0 {
		return detect.Server{}, false
	}
	return servers[index], true
}

// Detect tells what the block detector knows of the servers of the running sing-box: what the
// traffic shows, a recent probe over it, read in process. It may be called from any goroutine. A
// server with nothing to say has no entry.
func (s *Supervisor) Detect() detect.Report {
	report := detect.Report{Verdicts: map[string]detect.Verdict{}, Servers: map[string]detect.Identity{}, Queued: []string{}, NoProbe: []string{}}
	snapshot := s.detectSnapshot()
	if snapshot.instance == nil {
		return report
	}
	// every live server's stable id, way and cure: the page joins a tag to its id here and shows a
	// treatment badge even for a server with no verdict
	for tag, identity := range snapshot.stable {
		report.Servers[tag] = identity
	}
	report.StaleCures = snapshot.staleCures
	report.Fallback = snapshot.fallback
	passive := s.passiveVerdicts(snapshot)
	now := time.Now()
	d := &s.diag
	d.access.Lock()
	report.Probing = d.current
	report.Queued = append(report.Queued, d.queue...)
	active := make(map[string]activeVerdict, len(d.active))
	for tag, found := range d.active {
		active[tag] = found
	}
	d.access.Unlock()
	for _, server := range snapshot.servers {
		if server.Kind == detect.KindNone {
			report.NoProbe = append(report.NoProbe, server.Tag)
		}
		verdict, known := passive[server.Tag]
		if found, has := active[server.Tag]; has && found.hash == server.Hash && found.holds(verdict, now) {
			verdict, known = found.verdict, true
			verdict.Age = int64(now.Sub(found.at) / time.Second)
			if verdict.Block == detect.BlockFreeze {
				verdict.Notes = freezeNotes(verdict.Notes, snapshot.fallback)
			}
		}
		if known && (verdict.Block != detect.BlockUnknown || len(verdict.Notes) > 0) {
			report.Verdicts[server.Tag] = verdict
		}
	}
	return report
}

// passiveVerdicts is what the traffic shows of the servers, read at most every few seconds. The
// map is shared: not to be changed.
func (s *Supervisor) passiveVerdicts(snapshot detectSnapshot) map[string]detect.Verdict {
	now := time.Now()
	d := &s.diag
	d.access.Lock()
	cached, fresh := d.passive, d.passive != nil && d.passiveEpoch == snapshot.epoch && now.Sub(d.passiveAt) < passiveCacheFor
	d.access.Unlock()
	if fresh {
		return cached
	}
	flows, err := snapshot.instance.DetectFlows()
	if err != nil {
		return nil
	}
	open, err := snapshot.instance.Connections()
	if err != nil {
		return nil
	}
	tags := make([]string, len(snapshot.servers))
	for index, server := range snapshot.servers {
		tags[index] = server.Tag
	}
	verdicts := detect.Classify(snapshot.servers, detect.Signals{
		Flows:    flows,
		Open:     open,
		Outcome:  snapshot.instance.DetectOutcome,
		Failure:  s.options.Engine.URLTestFailure,
		Download: s.options.Engine.DownloadResult,
		Delays:   s.options.Engine.Delays(tags),
		Started:  snapshot.instance.StartedAt(),
		Now:      now,
	}, detect.DefaultPolicy)
	d.access.Lock()
	d.passive, d.passiveAt, d.passiveEpoch = verdicts, now, snapshot.epoch
	d.access.Unlock()
	return verdicts
}

// ForceDetect asks for a probe of a server: it starts now or waits its turn, and its verdict comes
// in a later Detect. cancel empties the queue instead, the probe that runs goes on: its burst is
// out already. It answers at once and may be called from any goroutine.
func (s *Supervisor) ForceDetect(tag string, cancel bool) detect.ForceAnswer {
	d := &s.diag
	if cancel {
		d.access.Lock()
		d.queue = nil
		d.access.Unlock()
		return detect.ForceAnswer{State: detect.ForceCanceled}
	}
	snapshot := s.detectSnapshot()
	if snapshot.instance == nil {
		return detect.ForceAnswer{State: detect.ForceNotRunning}
	}
	server, found := findServer(snapshot.servers, tag)
	if !found || server.Kind == detect.KindNone {
		return detect.ForceAnswer{State: detect.ForceUnknown}
	}
	now := time.Now()
	d.access.Lock()
	defer d.access.Unlock()
	switch {
	case d.current == tag:
		return detect.ForceAnswer{State: detect.ForceRunning}
	case slices.Contains(d.queue, tag):
		return detect.ForceAnswer{State: detect.ForceQueued}
	}
	if left := d.throttled(server.Destination, now); left > 0 {
		return detect.ForceAnswer{State: detect.ForceThrottled, RetryAfter: secondsUp(left)}
	}
	if d.current != "" {
		// of one destination one probe runs in an interval: the other would be passed over in the
		// queue without a word (nextDiagnosis)
		if slices.ContainsFunc(d.queue, func(queued string) bool {
			other, known := findServer(snapshot.servers, queued)
			return known && other.Destination == server.Destination
		}) {
			return detect.ForceAnswer{State: detect.ForceThrottled, RetryAfter: secondsUp(DiagnoseMinInterval)}
		}
		if len(d.queue) >= diagnoseQueueLimit {
			return detect.ForceAnswer{State: detect.ForceThrottled, RetryAfter: secondsUp(DiagnoseMinInterval)}
		}
		d.queue = append(d.queue, tag)
		return detect.ForceAnswer{State: detect.ForceQueued}
	}
	d.begin(tag, server.Destination, now)
	go s.diagnoseWorker(tag)
	return detect.ForceAnswer{State: detect.ForceStarted}
}

// throttled is how long a destination has to wait for its next probe. The caller holds the lock.
func (d *diagnosis) throttled(destination string, now time.Time) time.Duration {
	last, found := d.lastByDestination[destination]
	if !found {
		return 0
	}
	return DiagnoseMinInterval - now.Sub(last)
}

// begin makes a server the one a probe runs on. The caller holds the lock.
func (d *diagnosis) begin(tag string, destination string, now time.Time) {
	d.current = tag
	for known, last := range d.lastByDestination {
		if now.Sub(last) >= DiagnoseMinInterval {
			delete(d.lastByDestination, known)
		}
	}
	if d.lastByDestination == nil {
		d.lastByDestination = make(map[string]time.Time)
	}
	d.lastByDestination[destination] = now
}

func secondsUp(wait time.Duration) int {
	return int((wait + time.Second - 1) / time.Second)
}

// diagnoseWorker probes a server and then those in the queue, one at a time, and ends with the
// queue. A probe holds no lock and nothing of Run's.
func (s *Supervisor) diagnoseWorker(tag string) {
	defer s.survive("the probe of a server", func() {
		d := &s.diag
		d.access.Lock()
		d.current, d.queue = "", nil
		d.access.Unlock()
	})
	for tag != "" {
		s.diagnoseServer(tag)
		tag = s.nextDiagnosis()
	}
}

// nextDiagnosis takes the next server of the queue that can be probed now; "" ends the worker. A
// destination another server of the queue has just been probed at is passed over: its probe would
// measure the one before. Nothing stays queued when nothing runs.
func (s *Supervisor) nextDiagnosis() string {
	snapshot := s.detectSnapshot()
	now := time.Now()
	d := &s.diag
	d.access.Lock()
	defer d.access.Unlock()
	d.current = ""
	if snapshot.instance == nil {
		d.queue = nil
		return ""
	}
	for len(d.queue) > 0 {
		tag := d.queue[0]
		d.queue = d.queue[1:]
		server, found := findServer(snapshot.servers, tag)
		if !found || server.Kind == detect.KindNone || d.throttled(server.Destination, now) > 0 {
			continue
		}
		d.begin(tag, server.Destination, now)
		return tag
	}
	d.queue = nil
	return ""
}

// diagnoseServer runs the probe of a server. What it found of an instance or an outbound that is
// no longer there is dropped: a tag may name another server by then.
func (s *Supervisor) diagnoseServer(tag string) {
	snapshot := s.detectSnapshot()
	server, found := findServer(snapshot.servers, tag)
	if snapshot.instance == nil || !found {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), detect.Budget)
	defer cancel()
	verdict := detect.Run(ctx, snapshot.instance.Prober(), server, detect.RunOptions{Fallback: snapshot.fallback, Relays: s.relaysFor(server, snapshot)})
	latest := s.detectSnapshot()
	current, found := findServer(latest.servers, tag)
	if latest.instance != snapshot.instance || !found || current.Hash != server.Hash {
		return
	}
	now := time.Now()
	d := &s.diag
	d.access.Lock()
	for known, old := range d.active {
		if now.Sub(old.at) >= activeVerdictTTL {
			delete(d.active, known)
		}
	}
	if d.active == nil {
		d.active = make(map[string]activeVerdict)
	}
	d.active[tag] = activeVerdict{verdict: verdict, at: now, hash: server.Hash}
	d.access.Unlock()
	s.log("info", diagnosisLine(tag, verdict))
}

// diagnosisLine is what the log tells of a finished probe: a weak verdict may stay hidden under what
// the traffic shows, and this is then the only trace of what it found. Why and the notes hold no
// address (detect.Verdict).
func diagnosisLine(tag string, verdict detect.Verdict) string {
	line := "diagnosis of server " + tag + ": " + string(verdict.Block)
	if len(verdict.Notes) > 0 {
		line += " (" + strings.Join(verdict.Notes, ", ") + ")"
	}
	return line + ": " + verdict.Why
}

// relaysFor are the servers a probe may ask through: a probe or the traffic found them working, or
// their URL test passed.
func (s *Supervisor) relaysFor(server detect.Server, snapshot detectSnapshot) []detect.Server {
	passive := s.passiveVerdicts(snapshot)
	tags := make([]string, len(snapshot.servers))
	for index, candidate := range snapshot.servers {
		tags[index] = candidate.Tag
	}
	delays := s.options.Engine.Delays(tags)
	now := time.Now()
	probed := make(map[string]bool)
	d := &s.diag
	d.access.Lock()
	for tag, found := range d.active {
		probed[tag] = found.verdict.Block == detect.BlockNone && now.Sub(found.at) < activeVerdictTTL
	}
	d.access.Unlock()
	return detect.RelayCandidates(server, snapshot.servers, func(candidate detect.Server) bool {
		return probed[candidate.Tag] || passive[candidate.Tag].Block == detect.BlockNone || delays[candidate.Tag] > 0
	})
}
