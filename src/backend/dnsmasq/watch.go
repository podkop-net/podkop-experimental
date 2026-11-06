package dnsmasq

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Stale is a dnsmasq process that runs with another configuration than its file has now.
type Stale struct {
	PID  int
	File string
	// Digest tells the contents of the file apart: a new file is a new case
	Digest string
}

// Watch keeps dnsmasq running with the configuration written for it. procd starts dnsmasq in
// a jail of its own (ujail) where the configuration file of its start is mounted; the init
// script writes a new file at every start and reload, and procd starts dnsmasq again when
// the content changed. A restart of dnsmasq that comes while procd starts it again for an
// interface that came up leaves the process started with the old file running, and no
// reload replaces it after that: only a restart does. The backend itself only reloads
// dnsmasq (Router.Reload), another program may restart it.
//
// The watch looks a while after each change of dnsmasq by the backend and each change of
// the network (Kick: the interfaces that come up are what procd starts dnsmasq again for),
// and every Every otherwise. A difference that stays Hold with the same process and the
// same file, while no init script of dnsmasq runs, is no start in progress: dnsmasq is
// restarted, at most Limit times in Window. The look reads a few files of /proc and starts
// no program.
type Watch struct {
	// Find returns the first dnsmasq process that runs with an older configuration than its
	// file has (FindStale).
	Find func() (Stale, bool)
	// Busy tells that an init script of dnsmasq runs (InitScriptRuns).
	Busy func() bool
	// Restart restarts dnsmasq (Router.Restart).
	Restart func() error
	Log     func(level string, message string)
	// Every is the time between two looks nothing asked for, Hold how long a difference has
	// to stay, Poll the time between two looks while an init script runs.
	Every, Hold, Poll time.Duration
	// Limit restarts in Window at most.
	Limit  int
	Window time.Duration

	access sync.Mutex
	// asked is the earliest look a Kick asked for, zero when none waits
	asked time.Time
	wake  chan struct{}
	// pending is the difference seen, since when; restarts are the times of the restarts
	// of the last Window; told is the difference the log said is left as it is
	pending  Stale
	since    time.Time
	restarts []time.Time
	told     Stale
}

// NewWatch is a Watch of the router.
func NewWatch(log func(level string, message string)) *Watch {
	return &Watch{
		Find:    FindStale,
		Busy:    InitScriptRuns,
		Restart: Router{}.Restart,
		Log:     log,
		Every:   5 * time.Minute,
		// procd ends a start it began within the term_timeout of the instance, 5 s by
		// default, which the init script of dnsmasq keeps
		Hold:   6 * time.Second,
		Poll:   2 * time.Second,
		Limit:  3,
		Window: 10 * time.Minute,
		wake:   make(chan struct{}, 1),
	}
}

// Kick asks for a look after a while. A look asked for earlier stays.
func (w *Watch) Kick(after time.Duration) {
	at := time.Now().Add(after)
	w.access.Lock()
	if w.asked.IsZero() || at.Before(w.asked) {
		w.asked = at
	}
	w.access.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Loop looks until the context ends.
func (w *Watch) Loop(ctx context.Context) {
	next := time.Now().Add(w.Every)
	for {
		due := next
		w.access.Lock()
		if !w.asked.IsZero() && w.asked.Before(due) {
			due = w.asked
		}
		w.access.Unlock()
		timer := time.NewTimer(time.Until(due))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-w.wake:
			timer.Stop()
			continue
		case <-timer.C:
		}
		now := time.Now()
		w.access.Lock()
		if !w.asked.IsZero() && !w.asked.After(now) {
			w.asked = time.Time{}
		}
		w.access.Unlock()
		next = now.Add(w.look(now))
	}
}

// look does one look and tells when the next is due.
func (w *Watch) look(now time.Time) time.Duration {
	stale, found := w.Find()
	if !found {
		w.pending = Stale{}
		return w.Every
	}
	if stale != w.pending {
		w.pending, w.since = stale, now
		return w.Hold
	}
	if waited := now.Sub(w.since); waited < w.Hold {
		return w.Hold - waited
	}
	if w.Busy() {
		// what the init script does is not done yet
		return w.Poll
	}
	recent := w.restarts[:0]
	for _, at := range w.restarts {
		if now.Sub(at) < w.Window {
			recent = append(recent, at)
		}
	}
	w.restarts = recent
	if len(recent) >= w.Limit {
		if w.told != stale {
			w.told = stale
			w.Log("warn", "dnsmasq (pid "+strconv.Itoa(stale.PID)+") still runs with an older configuration than "+stale.File+" after "+strconv.Itoa(len(recent))+" restarts in "+w.Window.String()+": left as it is")
		}
		return w.Every
	}
	w.restarts = append(w.restarts, now)
	w.pending = Stale{}
	w.restart(stale)
	// the next look sees whether the restart took
	return w.Hold + w.Poll
}

func (w *Watch) restart(stale Stale) {
	w.Log("warn", "dnsmasq (pid "+strconv.Itoa(stale.PID)+") runs with an older configuration than "+stale.File+": procd did not start it again after a change; restarting it")
	if err := w.Restart(); err != nil {
		w.Log("error", err.Error())
	}
}

// Settle looks until dnsmasq runs with its configuration or budget has passed, and restarts
// it once as a look would: at the stop of the backend, after it gave dnsmasq back, so that
// a race of that change does not leave the LAN asking a backend that is gone. Right after
// a reload the process procd is starting again still has the old file: a difference counts
// only while the same process keeps it for Hold.
func (w *Watch) Settle(budget time.Duration) {
	deadline := time.Now().Add(budget)
	var pending Stale
	var since time.Time
	for {
		now := time.Now()
		stale, found := w.Find()
		if !found {
			return
		}
		if stale != pending {
			pending, since = stale, now
		} else if now.Sub(since) >= w.Hold && !w.Busy() {
			w.restart(stale)
			return
		}
		if !now.Before(deadline) {
			w.Log("warn", "dnsmasq (pid "+strconv.Itoa(stale.PID)+") runs with an older configuration than "+stale.File+" at the stop of the backend: left as it is")
			return
		}
		time.Sleep(min(w.Poll/4, time.Until(deadline)) + time.Millisecond)
	}
}

// Restart restarts dnsmasq: a stop and a start, which replaces a process that no reload
// does (see Watch). The backend changes dnsmasq with Reload.
func (Router) Restart() error {
	output, err := exec.Command("/etc/init.d/dnsmasq", "restart").CombinedOutput()
	if err != nil {
		return E.Cause(err, "restart dnsmasq: ", strings.TrimSpace(string(output)))
	}
	return nil
}

// FindStale returns the first dnsmasq process in a jail of its own whose configuration
// file differs from the file of the system (see Watch). A dnsmasq outside a jail reads the
// file of the system: what it was started with cannot be seen, and it is left out.
func FindStale() (Stale, bool) {
	return findStale("/")
}

func findStale(root string) (Stale, bool) {
	entries, err := os.ReadDir(filepath.Join(root, "proc"))
	if err != nil {
		return Stale{}, false
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		name, err := os.ReadFile(filepath.Join(root, "proc", entry.Name(), "comm"))
		if err != nil || strings.TrimSpace(string(name)) != "dnsmasq" || !Jailed(root, pid) {
			continue
		}
		file := ConfFile(root, pid)
		if file == "" {
			continue
		}
		loaded, err := os.ReadFile(filepath.Join(root, "proc", entry.Name(), "root", file))
		if err != nil {
			continue
		}
		written, err := os.ReadFile(filepath.Join(root, file))
		if err != nil || bytes.Equal(loaded, written) {
			continue
		}
		sum := sha256.Sum256(written)
		return Stale{PID: pid, File: file, Digest: hex.EncodeToString(sum[:8])}, true
	}
	return Stale{}, false
}

// Jailed tells whether a process has a file system of its own (a jail), not that of this
// process; root is where /proc is.
func Jailed(root string, pid int) bool {
	own, err := os.Readlink(filepath.Join(root, "proc", strconv.Itoa(pid), "ns", "mnt"))
	if err != nil {
		return false
	}
	this, err := os.Readlink(filepath.Join(root, "proc", "self", "ns", "mnt"))
	return err == nil && own != this
}

// ConfFile is the configuration file of the command line of a dnsmasq process (-C,
// --conf-file); empty when there is none or the process is gone. root is where /proc is.
func ConfFile(root string, pid int) string {
	commandLine, err := os.ReadFile(filepath.Join(root, "proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return ""
	}
	arguments := strings.Split(strings.TrimRight(string(commandLine), "\x00"), "\x00")
	var file string
	for index, argument := range arguments {
		switch {
		case argument == "-C" && index+1 < len(arguments):
			file = arguments[index+1]
		case strings.HasPrefix(argument, "--conf-file="):
			file = strings.TrimPrefix(argument, "--conf-file=")
		}
	}
	return file
}

// initLock is the lock procd_lock of /etc/rc.common holds while an init script of dnsmasq
// starts, stops or reloads it.
const initLock = "/var/lock/procd_dnsmasq.lock"

// InitScriptRuns tells whether an init script of dnsmasq runs now: it holds the lock.
func InitScriptRuns() bool {
	file, err := os.Open(initLock)
	if err != nil {
		return false
	}
	defer file.Close()
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return errors.Is(err, syscall.EWOULDBLOCK)
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return false
}
