package supervisor

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// endsFixture is a supervisor of a fake engine whose state file is in directory, as a new
// process of the backend would find it; what it logs goes to log.
func endsFixture(t *testing.T, directory string, log *[]string) (*Supervisor, *fakeEngine, *recorder) {
	fake, system := &fakeEngine{refuse: map[string]error{}}, &recorder{endCause: "memory 241 MB, available 12 MB"}
	s := New(Options{
		SettingsPath: filepath.Join(directory, "podkop"), RuleSetDir: filepath.Join(directory, "rulesets"),
		StagingDir: filepath.Join(directory, "candidate"), StatePath: filepath.Join(directory, "state"),
		EndsPath: filepath.Join(directory, "ends"), ConfigDir: filepath.Join(directory, "run"),
		ReadyTimeout: time.Second, System: system, Engine: fake,
		Log: func(level string, message string) { *log = append(*log, "["+level+"] "+message) },
	})
	text := "config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '127.0.0.1:9'\n\toption dns_rewrite_ttl '60'\n" +
		"\toption cache_path '" + filepath.Join(directory, "cache.db") + "'\n\toption yacd_secret_key 'k'\n" +
		"\nconfig section 'main'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n" +
		"\toption user_domain_list_type 'dynamic'\n\tlist user_domains 'one.lab.example'\n"
	require.NoError(t, os.WriteFile(filepath.Join(directory, "podkop"), []byte(text), 0o644))
	return s, fake, system
}

// ended writes the state a backend that is gone left: another process, the state, since when.
func ended(t *testing.T, directory string, state string, ago time.Duration) {
	line := state + " 999999 " + strconv.FormatInt(time.Now().Add(-ago).Unix(), 10) + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(directory, "state"), []byte(line), 0o600))
}

func endsCount(t *testing.T, directory string) string {
	content, err := os.ReadFile(filepath.Join(directory, "ends"))
	if os.IsNotExist(err) {
		return "none"
	}
	require.NoError(t, err)
	return strings.Fields(string(content))[0]
}

// A backend that ended without its stop is started again at once the first few times; after
// them the router is given back before anything else and the start waits. An end long after
// the one before (and its wait) starts the count again, and so does a stop.
func TestBeginEnds(t *testing.T) {
	directory := t.TempDir()
	var log []string
	// the first start since boot: no state file
	s, _, _ := endsFixture(t, directory, &log)
	require.True(t, s.Begin().OK, "%v", log)
	require.Equal(t, "none", endsCount(t, directory))
	s.Stop()

	// three ends in a row, each soon after the backend came up: started again
	for round := 1; round <= 3; round++ {
		log = nil
		ended(t, directory, stateRunning, 30*time.Second)
		s, fake, _ := endsFixture(t, directory, &log)
		require.True(t, s.Begin().OK, "%v", log)
		require.Len(t, fake.built, 1)
		require.Equal(t, strconv.Itoa(round), endsCount(t, directory))
		require.Contains(t, log[0], "[warn] the backend before this one (pid 999999) ended without its stop, running for 30s: memory 241 MB, available 12 MB; procd started this one")
		s.Stop()
	}

	// the fourth: the router is given back, nothing starts, the start waits a minute
	log = nil
	ended(t, directory, stateRunning, 30*time.Second)
	s, fake, system := endsFixture(t, directory, &log)
	system.dnsOurs = true
	result := s.Begin()
	require.False(t, result.OK)
	require.Equal(t, "4 ends without a stop in a row: the router is given back", result.Message)
	require.Empty(t, fake.built)
	require.Equal(t, []string{"no dns", "no firewall", "no routing"}, system.take())
	require.False(t, system.dnsOurs)
	require.Equal(t, stateFailed, state(t, s))
	require.Contains(t, log[len(log)-1], "[error] the backend before this one (pid 999999) ended without its stop, running for 30s: memory 241 MB, available 12 MB; "+
		"4 such ends in a row: the router is given back, the DNS of the LAN is its own, the next start at ")
	due, ok := s.retryDue()
	require.True(t, ok)
	require.Equal(t, s.failedAt.Add(time.Minute), due)
	require.Contains(t, s.restoreRouting(), "the start failed 4 times in a row: it is tried again from ")
	require.Empty(t, fake.built)
	// when it is due it starts
	s.failedAt = s.failedAt.Add(-time.Minute)
	require.Contains(t, s.retryFailed(), "the start that had failed was tried again: started")
	require.True(t, s.Running())
	s.Stop()

	// the fifth, from a backend that was trying again, soon after: two minutes
	log = nil
	ended(t, directory, stateBooting, 5*time.Second)
	s, _, _ = endsFixture(t, directory, &log)
	require.False(t, s.Begin().OK)
	require.Equal(t, "5", endsCount(t, directory))
	due, _ = s.retryDue()
	require.Equal(t, s.failedAt.Add(2*time.Minute), due)

	// an end that came a while after the one before and its wait does not count with it
	log = nil
	ended(t, directory, stateRunning, endWindow)
	last := time.Now().Add(-endWindow - retryPause(5) - time.Second).Unix()
	require.NoError(t, os.WriteFile(filepath.Join(directory, "ends"), []byte("5 "+strconv.FormatInt(last, 10)+"\n"), 0o600))
	s, _, _ = endsFixture(t, directory, &log)
	require.True(t, s.Begin().OK, "%v", log)
	require.Equal(t, "1", endsCount(t, directory))
	// and a stop forgets it
	s.Stop()
	s, _, _ = endsFixture(t, directory, &log)
	require.True(t, s.Begin().OK, "%v", log)
	require.Equal(t, "none", endsCount(t, directory))
	s.Stop()
}

// A start that failed is tried again by the clock: a minute after the first few failures,
// then as retryPause says. Nothing is due while something runs, or after a stop.
func TestRetryDue(t *testing.T) {
	s, fake, _, settings := fakeFixture(t)
	settings("one.lab.example", "60")
	_, ok := s.retryDue()
	require.False(t, ok)
	fake.silent = []string{`"rewrite_ttl": 60`}
	require.False(t, s.Boot().OK)
	due, ok := s.retryDue()
	require.True(t, ok)
	require.Equal(t, s.failedAt.Add(time.Minute), due)
	s.failures = 6
	due, _ = s.retryDue()
	require.Equal(t, s.failedAt.Add(4*time.Minute), due)
	s.failures = 1
	fake.silent = nil
	s.failedAt = s.failedAt.Add(-time.Minute)
	require.Contains(t, s.retryFailed(), "started")
	_, ok = s.retryDue()
	require.False(t, ok)
	s.Stop()
	_, ok = s.retryDue()
	require.False(t, ok)
}
