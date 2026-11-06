package dnsmasq

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const confFile = "/var/etc/dnsmasq.conf.cfg01411c"

// fakeProcess puts a process into a /proc under root: its name, its mount namespace, its
// command line and, when loaded is not empty, the configuration file it sees in its jail.
func fakeProcess(t *testing.T, root string, pid int, name string, namespace string, loaded string) {
	t.Helper()
	directory := filepath.Join(root, "proc", strconv.Itoa(pid))
	require.NoError(t, os.MkdirAll(filepath.Join(directory, "ns"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "comm"), []byte(name+"\n"), 0o644))
	require.NoError(t, os.Symlink(namespace, filepath.Join(directory, "ns", "mnt")))
	commandLine := "/usr/sbin/dnsmasq\x00-C\x00" + confFile + "\x00-k\x00-x\x00/var/run/dnsmasq/dnsmasq.cfg01411c.pid\x00"
	require.NoError(t, os.WriteFile(filepath.Join(directory, "cmdline"), []byte(commandLine), 0o644))
	if loaded != "" {
		inJail := filepath.Join(directory, "root", confFile)
		require.NoError(t, os.MkdirAll(filepath.Dir(inJail), 0o755))
		require.NoError(t, os.WriteFile(inJail, []byte(loaded), 0o644))
	}
}

func fakeRoot(t *testing.T, written string) string {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "proc", "self", "ns"), 0o755))
	require.NoError(t, os.Symlink("mnt:[4026531840]", filepath.Join(root, "proc", "self", "ns", "mnt")))
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, confFile)), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, confFile), []byte(written), 0o644))
	return root
}

// A dnsmasq in a jail whose file differs from the file of the system is found; one that
// sees the same file, one outside a jail and another program are not.
func TestFindStale(t *testing.T) {
	root := fakeRoot(t, "server=127.0.0.42\nno-resolv\n")
	fakeProcess(t, root, 300, "ujail", "mnt:[4026532001]", "")
	fakeProcess(t, root, 310, "dnsmasq", "mnt:[4026532001]", "server=127.0.0.42\nno-resolv\n")
	_, found := findStale(root)
	require.False(t, found)

	// outside a jail it reads the file of the system: what it loaded cannot be seen
	fakeProcess(t, root, 320, "dnsmasq", "mnt:[4026531840]", "resolv-file=/tmp/resolv.conf.d/resolv.conf.auto\n")
	_, found = findStale(root)
	require.False(t, found)

	fakeProcess(t, root, 330, "dnsmasq", "mnt:[4026532002]", "resolv-file=/tmp/resolv.conf.d/resolv.conf.auto\n")
	stale, found := findStale(root)
	require.True(t, found)
	require.Equal(t, 330, stale.PID)
	require.Equal(t, confFile, stale.File)
	require.Len(t, stale.Digest, 16)

	// a new file of the system is another case
	require.NoError(t, os.WriteFile(filepath.Join(root, confFile), []byte("server=127.0.0.42\nno-resolv\ncache-size=0\n"), 0o644))
	again, found := findStale(root)
	require.True(t, found)
	require.NotEqual(t, stale.Digest, again.Digest)
}

// watchFixture is a Watch whose dnsmasq is made up: what Find returns, whether an init
// script runs, the restarts and the log.
type watchFixture struct {
	access   sync.Mutex
	stale    Stale
	found    bool
	busy     bool
	restarts int
	log      []string
	watch    *Watch
}

func newWatchFixture() *watchFixture {
	f := &watchFixture{}
	f.watch = &Watch{
		Find: func() (Stale, bool) {
			f.access.Lock()
			defer f.access.Unlock()
			return f.stale, f.found
		},
		Busy: func() bool {
			f.access.Lock()
			defer f.access.Unlock()
			return f.busy
		},
		Restart: func() error {
			f.access.Lock()
			defer f.access.Unlock()
			f.restarts++
			// the restart takes: the process runs with its file
			f.found = false
			return nil
		},
		Log: func(level string, message string) {
			f.access.Lock()
			defer f.access.Unlock()
			f.log = append(f.log, "["+level+"] "+message)
		},
		Every: time.Hour, Hold: 6 * time.Second, Poll: 2 * time.Second,
		Limit: 3, Window: 10 * time.Minute,
		wake: make(chan struct{}, 1),
	}
	return f
}

func (f *watchFixture) set(stale Stale, found bool, busy bool) {
	f.access.Lock()
	defer f.access.Unlock()
	f.stale, f.found, f.busy = stale, found, busy
}

func (f *watchFixture) counts() (int, string) {
	f.access.Lock()
	defer f.access.Unlock()
	return f.restarts, strings.Join(f.log, "\n")
}

// A difference is a restart only when the same process keeps the same file for Hold and
// no init script runs; a new process or a new file starts the wait again.
func TestWatchLook(t *testing.T) {
	f := newWatchFixture()
	w := f.watch
	t0 := time.Unix(1_800_000_000, 0)
	require.Equal(t, time.Hour, w.look(t0))

	first := Stale{PID: 310, File: confFile, Digest: "aa"}
	f.set(first, true, false)
	require.Equal(t, 6*time.Second, w.look(t0))
	require.Equal(t, 4*time.Second, w.look(t0.Add(2*time.Second)))
	// procd started it again meanwhile, with the old file as well: the wait starts again
	second := Stale{PID: 320, File: confFile, Digest: "aa"}
	f.set(second, true, false)
	require.Equal(t, 6*time.Second, w.look(t0.Add(6*time.Second)))
	// an init script runs: what it does is not done yet
	f.set(second, true, true)
	require.Equal(t, 2*time.Second, w.look(t0.Add(12*time.Second)))
	restarts, _ := f.counts()
	require.Zero(t, restarts)
	f.set(second, true, false)
	require.Equal(t, 8*time.Second, w.look(t0.Add(14*time.Second)))
	restarts, log := f.counts()
	require.Equal(t, 1, restarts)
	require.Contains(t, log, "dnsmasq (pid 320) runs with an older configuration than "+confFile+": procd did not start it again after a change; restarting it")
	require.Equal(t, time.Hour, w.look(t0.Add(22*time.Second)))
}

// At most Limit restarts in Window; the log says once that it is left as it is, and a
// restart is tried again once the window has passed.
func TestWatchLimit(t *testing.T) {
	f := newWatchFixture()
	w := f.watch
	at := time.Unix(1_800_000_000, 0)
	stale := Stale{PID: 310, File: confFile, Digest: "aa"}
	// a restart that does not take
	w.Restart = func() error {
		f.access.Lock()
		defer f.access.Unlock()
		f.restarts++
		return nil
	}
	f.set(stale, true, false)
	for range 6 {
		w.look(at)
		at = at.Add(7 * time.Second)
		w.look(at)
		at = at.Add(time.Second)
	}
	restarts, log := f.counts()
	require.Equal(t, 3, restarts)
	require.Equal(t, 1, strings.Count(log, "after 3 restarts in 10m0s: left as it is"), log)
	at = at.Add(10 * time.Minute)
	w.look(at)
	w.look(at.Add(7 * time.Second))
	restarts, _ = f.counts()
	require.Equal(t, 4, restarts)
}

// A Kick brings the next look forward; the loop restarts a dnsmasq that stays stale and
// ends with its context.
func TestWatchLoop(t *testing.T) {
	f := newWatchFixture()
	w := f.watch
	w.Hold, w.Poll = 50*time.Millisecond, 20*time.Millisecond
	f.set(Stale{PID: 310, File: confFile, Digest: "aa"}, true, false)
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan struct{})
	go func() {
		w.Loop(ctx)
		close(ended)
	}()
	time.Sleep(100 * time.Millisecond)
	restarts, _ := f.counts()
	require.Zero(t, restarts, "nothing looks before Every unless kicked")
	w.Kick(0)
	require.Eventually(t, func() bool { restarts, _ := f.counts(); return restarts == 1 }, 2*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("the loop did not end with its context")
	}
}

// At the stop: nothing to do when dnsmasq runs with its file; a process procd replaces
// (right after a reload) is no difference; one that stays is restarted once; a budget that
// runs out is told.
func TestWatchSettle(t *testing.T) {
	f := newWatchFixture()
	w := f.watch
	w.Hold, w.Poll = 60*time.Millisecond, 40*time.Millisecond
	started := time.Now()
	w.Settle(time.Second)
	require.Less(t, time.Since(started), 50*time.Millisecond)

	// procd starts dnsmasq again with the new file after 30 ms
	f.set(Stale{PID: 310, File: confFile, Digest: "aa"}, true, false)
	go func() {
		time.Sleep(30 * time.Millisecond)
		f.set(Stale{}, false, false)
	}()
	w.Settle(time.Second)
	restarts, _ := f.counts()
	require.Zero(t, restarts)

	f.set(Stale{PID: 320, File: confFile, Digest: "aa"}, true, false)
	w.Settle(time.Second)
	restarts, log := f.counts()
	require.Equal(t, 1, restarts)
	require.Contains(t, log, "dnsmasq (pid 320) runs with an older configuration")

	// an init script that holds its lock past the budget
	f.set(Stale{PID: 330, File: confFile, Digest: "aa"}, true, true)
	w.Settle(150 * time.Millisecond)
	restarts, log = f.counts()
	require.Equal(t, 1, restarts)
	require.Contains(t, log, "dnsmasq (pid 330) runs with an older configuration than "+confFile+" at the stop of the backend: left as it is")
}

// The cost of one look on the system the test runs on, for the period of the watch: built
// with "go test -c" and run on a router as
// ./dnsmasq.test -test.run '^$' -test.bench FindStale -test.benchmem
func BenchmarkFindStale(b *testing.B) {
	for b.Loop() {
		findStale("/")
	}
}
