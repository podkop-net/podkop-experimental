package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func freePort(t *testing.T) int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// a configuration of the shape the backend makes, at ports of this test: a DNS inbound
// that answers a name from FakeIP, a mixed inbound, a cache file
func configuration(t *testing.T, dnsPort int, mixedPort int) []byte {
	return []byte(fmt.Sprintf(`{
  "log": {"disabled": true},
  "dns": {
    "servers": [{"type": "fakeip", "tag": "fakeip-server", "inet4_range": "198.18.0.0/15"}, {"type": "udp", "tag": "dns-server", "server": "127.0.0.1", "server_port": 9}],
    "rules": [{"action": "route", "server": "fakeip-server", "domain": ["ready.check.example"]}],
    "final": "dns-server"
  },
  "inbounds": [
    {"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": %d},
    {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": %d}
  ],
  "outbounds": [{"type": "direct", "tag": "direct-out"}],
  "route": {"rules": [{"action": "sniff"}, {"action": "hijack-dns", "protocol": "dns"}], "final": "direct-out", "default_domain_resolver": "dns-server"},
  "experimental": {"cache_file": {"enabled": true, "path": %q, "store_fakeip": true}}
}`, dnsPort, mixedPort, filepath.Join(t.TempDir(), "cache.db")))
}

// An instance is built, started, answers and closes; then another one of the same
// configuration does, in the same process, and a third while nothing of the second is left.
func TestInstanceLifecycle(t *testing.T) {
	dnsPort, mixedPort := freePort(t), freePort(t)
	config := configuration(t, dnsPort, mixedPort)
	fakeRange := netip.MustParsePrefix("198.18.0.0/15")
	for round := 1; round <= 3; round++ {
		instance, err := Build(config)
		require.NoError(t, err)
		require.False(t, listening(fmt.Sprintf("127.0.0.1:%d", mixedPort)), "round %d: listening before the start", round)
		require.NoError(t, instance.Start())
		require.True(t, listening(fmt.Sprintf("127.0.0.1:%d", mixedPort)), "round %d: not listening after the start", round)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		require.NoError(t, Probe(ctx, fmt.Sprintf("127.0.0.1:%d", dnsPort), "ready.check.example", fakeRange))
		cancel()
		_, found := instance.RuleSetContent("no-such-rule-set")
		require.False(t, found)
		require.NoError(t, instance.Close(10*time.Second))
		require.False(t, listening(fmt.Sprintf("127.0.0.1:%d", mixedPort)), "round %d: listening after the close", round)
	}
}

// A candidate is built while another instance runs: building takes no port and no file.
func TestBuildBesideARunningInstance(t *testing.T) {
	dnsPort, mixedPort := freePort(t), freePort(t)
	config := configuration(t, dnsPort, mixedPort)
	running, err := Build(config)
	require.NoError(t, err)
	require.NoError(t, running.Start())
	candidate, err := Build(config)
	require.NoError(t, err)
	// it cannot start: the port and the cache file are taken, and the failed start leaves
	// the running one alone
	require.Error(t, candidate.Start())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, Probe(ctx, fmt.Sprintf("127.0.0.1:%d", dnsPort), "ready.check.example", netip.MustParsePrefix("198.18.0.0/15")))
	require.NoError(t, running.Close(10*time.Second))
}

func TestBuildRefuses(t *testing.T) {
	_, err := Build([]byte(`{"outbounds": [{"type": "nosuch"}]}`))
	require.Error(t, err)
	_, err = Build([]byte(`{"outbounds": [`))
	require.Error(t, err)
}

// What sing-box notes as deprecated comes with every check, and once to the process: a
// configuration applied again does not fill the log with the same note.
func TestNotes(t *testing.T) {
	// whatever an earlier test noted is forgotten
	told.access.Lock()
	told.seen, told.fresh = make(map[string]bool), nil
	told.access.Unlock()
	deprecatedOption := []byte(`{"log": {"disabled": true}, "dns": {"independent_cache": true}}`)
	for range 2 {
		notes, err := Check(deprecatedOption)
		require.NoError(t, err)
		require.Len(t, notes, 1)
	}
	once := Notes()
	require.Len(t, once, 1)
	require.Contains(t, once[0], "independent_cache")
	_, err := Check(deprecatedOption)
	require.NoError(t, err)
	require.Empty(t, Notes())
}

func TestProbeGivesUp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := Probe(ctx, fmt.Sprintf("127.0.0.1:%d", freePort(t)), "ready.check.example", netip.MustParsePrefix("198.18.0.0/15"))
	require.Error(t, err)
}

// listening tells whether something of this host accepts TCP connections at an address.
func listening(address string) bool {
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return false
	}
	connection.Close()
	return true
}

// The lines sing-box logs come to a sink as text, of the level the configuration asks
// for alone: without the colours and the prefix it writes for a terminal, and those below
// the level not even formatted.
func TestLogSink(t *testing.T) {
	var lines []string
	sink := func(level string, message string) { lines = append(lines, level+"|"+message) }
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now()}, io.Discard, "", sinkWriter{sink, log.LevelWarn}, false)
	factory.SetLevel(log.LevelWarn)
	require.NoError(t, factory.Start())
	defer factory.Close()
	logger := factory.NewLogger("dns")
	logger.Error("exchange failed for x. IN A")
	logger.Warn("a warning")
	logger.Info("an info line")
	logger.Debug("a debug line")
	require.Equal(t, []string{"error|dns: exchange failed for x. IN A", "warn|dns: a warning"}, lines)

	// the prefix goes at the start alone
	lines = nil
	sinkWriter{sink, log.LevelInfo}.WriteMessage(log.LevelInfo, "INFO[0001] plain [0001] text")
	require.Equal(t, []string{"info|plain [0001] text"}, lines)
	require.Equal(t, log.LevelInfo, sinkLevel(nil))
	require.Equal(t, log.LevelInfo, sinkLevel(&option.LogOptions{}))
	require.Equal(t, log.LevelWarn, sinkLevel(&option.LogOptions{Level: "warn"}))
	require.Equal(t, log.LevelDebug, sinkLevel(&option.LogOptions{Level: "debug"}))
	require.Equal(t, log.LevelPanic, sinkLevel(&option.LogOptions{Level: "debug", Disabled: true}))
}

// The traffic of an instance: the bytes of a connection through its mixed inbound, the
// connection while it is open, nothing to tell once it is closed.
func TestTraffic(t *testing.T) {
	dnsPort, mixedPort := freePort(t), freePort(t)
	instance, err := BuildLogged(configuration(t, dnsPort, mixedPort), func(string, string) {}, Services{})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	defer instance.Close(10 * time.Second)

	// a server that reads what comes and answers as much
	server, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	go func() {
		conn, err := server.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	before, err := instance.Traffic()
	require.NoError(t, err)
	require.Zero(t, before.Connections)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", mixedPort))
	require.NoError(t, err)
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", server.Addr(), server.Addr())
	require.NoError(t, err)
	answer := make([]byte, 64)
	n, err := conn.Read(answer)
	require.NoError(t, err)
	require.Contains(t, string(answer[:n]), " 200 ")
	payload := make([]byte, 64<<10)
	_, err = conn.Write(payload)
	require.NoError(t, err)
	_, err = io.ReadFull(conn, payload)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		now, err := instance.Traffic()
		return err == nil && now.Connections == 1 && now.Up >= int64(len(payload)) && now.Down >= int64(len(payload))
	}, 5*time.Second, 20*time.Millisecond)

	require.NoError(t, instance.Close(10*time.Second))
	_, err = instance.Traffic()
	require.ErrorIs(t, err, ErrClosed)
}
