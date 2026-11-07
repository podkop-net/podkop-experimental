package supervisor

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/render"
)

// A backend that ends without its stop (a panic, the kernel's OOM-killer, a SIGKILL) leaves
// the DNS of the LAN asking it, where nothing listens any more. procd starts it again 5 s
// later, and never gives up (respawn ... 0 in /etc/init.d/podkop): the backend that starts
// tells such an end by the state file of the one before, and gives the router back itself
// when they keep ending. A procd that gave up would leave the LAN without DNS, and nothing
// in the process could help it.
//
// An end counts towards a loop when the backend before it lived less than endWindow after
// the end before (and after the wait that end was given, retryPause); a later end starts the
// count again. The first few ends of a loop are started again at once, as a start that
// failed is; after them the router is given back first, and the next start waits as long as
// retryPause says for that many failures.
//
// endWindow: an end costs the LAN its DNS for procd's 5 s and the start of the next
// backend, 0.1-6 s on the stands and routers measured, 23 s the slowest seen. Ends that come
// endWindow apart or more are not held back: they cost the LAN (5 + 6) / 600 = 1.8 % of the
// time, (5 + 23) / 600 = 4.7 % with the slowest start. It is the window procd judged the
// backend's crashes by before (respawn 600 5 5).
const endWindow = 10 * time.Minute

// previousState is what the state file says of a backend.
type previousState struct {
	state string
	pid   int
	since time.Time
}

// readState reads the state file (writeState); false when there is none, or it is malformed.
func readState(path string) (previousState, bool) {
	content, err := os.ReadFile(path)
	if err != nil {
		return previousState{}, false
	}
	fields := strings.Fields(string(content))
	if len(fields) != 3 {
		return previousState{}, false
	}
	pid, err := strconv.Atoi(fields[1])
	if err != nil {
		return previousState{}, false
	}
	since, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return previousState{}, false
	}
	return previousState{state: fields[0], pid: pid, since: time.Unix(since, 0)}, true
}

// ends are the ends of the backend without its stop in a row, the last at last; kept in
// Options.EndsPath, in RAM: a reboot starts the count again.
type ends struct {
	count int
	last  time.Time
}

func readEnds(path string) ends {
	content, err := os.ReadFile(path)
	if err != nil {
		return ends{}
	}
	fields := strings.Fields(string(content))
	if len(fields) != 2 {
		return ends{}
	}
	count, err := strconv.Atoi(fields[0])
	if err != nil || count < 0 {
		return ends{}
	}
	last, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return ends{}
	}
	return ends{count: count, last: time.Unix(last, 0)}
}

// countEnd tells whether the backend before this one ended without its stop, and how many
// such ends came in a row. Called once, before this backend writes its own state.
func (s *Supervisor) countEnd() (before previousState, count int, ended bool) {
	path := s.options.EndsPath
	before, known := readState(s.options.StatePath)
	if !known || before.pid == os.Getpid() || before.state == stateStopped {
		// the first start since boot, or one after a stop: a count of its own
		if path != "" {
			_ = os.Remove(path)
		}
		return before, 0, false
	}
	now := time.Now()
	counted := ends{}
	if path != "" {
		counted = readEnds(path)
	}
	if now.Sub(counted.last)-retryPause(counted.count) >= endWindow {
		counted.count = 0
	}
	counted.count++
	counted.last = now
	if path != "" {
		_ = render.WriteFile(path, []byte(strconv.Itoa(counted.count)+" "+strconv.FormatInt(now.Unix(), 10)+"\n"))
	}
	return before, counted.count, true
}

// Begin is the start of the process: the backend before it, when it ended without its stop,
// is told in the log; after a few such ends in a row the router is given back and the start
// waits (see endWindow), otherwise the router is brought up from the settings (Boot).
func (s *Supervisor) Begin() Result {
	before, count, ended := s.countEnd()
	if !ended {
		return s.Boot()
	}
	told := "the backend before this one (pid " + strconv.Itoa(before.pid) + ") ended without its stop, " +
		before.state + " for " + time.Since(before.since).Truncate(time.Second).String()
	if cause := s.options.System.EndCause(before.pid); cause != "" {
		told += ": " + cause
	}
	pause := retryPause(count)
	if pause == 0 {
		s.log("warn", told, "; procd started this one")
		return s.Boot()
	}
	s.writeState(stateBooting)
	s.retireConfig()
	s.release()
	s.failed, s.failures, s.failedAt = true, count, time.Now()
	s.log("error", told, "; ", count, " such ends in a row: the router is given back, the DNS of the LAN is its own, the next start at ",
		time.Now().Add(pause).Format(time.TimeOnly))
	return s.done(false, false, count, " ends without a stop in a row: the router is given back")
}

// retryAtLeast is the shortest wait of a start that failed for the next try by the clock
// (retryDue): the first pause of retryPause. The first few failures are tried again at once
// when the network changes; a cause that no change of the network ends (a port another
// program held) waits for this.
const retryAtLeast = time.Minute

// retryDue tells when a start that failed is tried again by the clock; false when none is
// to be tried.
func (s *Supervisor) retryDue() (time.Time, bool) {
	if !s.failed || s.current != nil {
		return time.Time{}, false
	}
	return s.failedAt.Add(max(retryPause(s.failures), retryAtLeast)), true
}
