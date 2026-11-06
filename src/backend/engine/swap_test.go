package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/detect"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// swapConfiguration is a configuration of a section of a group of two servers, as the backend
// makes it, with the names of the servers given.
func swapConfiguration(t *testing.T, first string, second string) []byte {
	return groupConfiguration(t, [2]string{first, "127.0.0.2"}, [2]string{second, "127.0.0.3"})
}

// groupConfiguration is swapConfiguration with the name and the address of each server given.
func groupConfiguration(t *testing.T, first [2]string, second [2]string) []byte {
	return []byte(`{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "direct", "tag": "direct-out"},
    ` + testServer("prov: "+first[0], first[1]) + `,
    ` + testServer("prov: "+second[0], second[1]) + `,
    {"type": "urltest", "tag": "g-group", "outbounds": ["prov: ` + first[0] + `", "prov: ` + second[0] + `"], "url": "http://127.0.0.1:9/", "interval": "1h", "idle_timeout": "2h"},
    {"type": "selector", "tag": "yt-out", "outbounds": ["g-group", "prov: ` + first[0] + `", "prov: ` + second[0] + `"], "default": "g-group"}
  ],
  "route": {"final": "direct-out"},
  "experimental": {"clash_api": {}, "cache_file": {"enabled": true, "path": "` + filepath.Join(t.TempDir(), "cache.db") + `"}}
}`)
}

// testServer is the outbound of a server of a subscription at the address given.
func testServer(tag string, host string) string {
	return fmt.Sprintf(`{"type": "vless", "tag": %q, "server": %q, "server_port": 1, "uuid": "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"}`, tag, host)
}

// outboundsOf picks the outbounds of a configuration by tag.
func pickOutbounds(t *testing.T, configuration []byte, tags ...string) []json.RawMessage {
	var parsed struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	require.NoError(t, json.Unmarshal(configuration, &parsed))
	var picked []json.RawMessage
	for _, outbound := range parsed.Outbounds {
		for _, tag := range tags {
			if strings.Contains(string(outbound), `"tag": "`+tag+`"`) {
				picked = append(picked, outbound)
			}
		}
	}
	require.Len(t, picked, len(tags))
	return picked
}

// A server renamed while sing-box runs: replaced with its group and selector, and its result
// goes with it.
func TestInstanceSwap(t *testing.T) {
	before := swapConfiguration(t, "DE 113d", "NL")
	instance, err := Build(before)
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close(10 * time.Second) })
	history.storage.StoreURLTestHistory("prov: DE 113d", &adapter.URLTestHistory{Time: time.Now(), Delay: 120})
	// the server chosen in the dashboard
	selector, _ := instance.box.Outbound().Outbound("yt-out")
	require.True(t, selector.(interface{ SelectOutbound(string) bool }).SelectOutbound("prov: DE 113d"))

	after := swapConfiguration(t, "DE 112d", "NL")
	swapped, err := instance.Swap(after, Swap{Put: pickOutbounds(t, after, "prov: DE 112d", "g-group", "yt-out"), Remove: []string{"prov: DE 113d"}}, 0)
	require.NoError(t, err)
	require.Equal(t, Swapped{Added: 1, Replaced: 2, Removed: 1, Kept: 3}, swapped)
	carried := history.storage.LoadURLTestHistory("prov: DE 112d")
	require.NotNil(t, carried, "the result of the name before")
	require.Equal(t, uint16(120), carried.Delay)
	require.Nil(t, history.storage.LoadURLTestHistory("prov: DE 113d"))
	found, loaded := instance.box.Outbound().Outbound("prov: DE 112d")
	require.True(t, loaded)
	require.Equal(t, "vless", found.Type())
	_, loaded = instance.box.Outbound().Outbound("prov: DE 113d")
	require.False(t, loaded)
	require.Contains(t, instance.dialers, "prov: DE 112d")
	selector, _ = instance.box.Outbound().Outbound("yt-out")
	require.Equal(t, "prov: DE 112d", selector.(adapter.OutboundGroup).Selected("tcp").Tag(), "the choice went with the name")
	require.Equal(t, "prov: DE 112d", service.FromContext[adapter.CacheFile](instance.ctx).LoadSelected("yt-out"))

	// what sing-box does not take changes nothing
	_, err = instance.Swap(after, Swap{Put: pickOutbounds(t, after, "prov: NL")}, 0)
	require.ErrorContains(t, err, "goes through prov: NL")
	require.NoError(t, instance.Close(10*time.Second))
	_, err = instance.Swap(after, Swap{}, 0)
	require.ErrorIs(t, err, ErrClosed)
}

// detectConfiguration is an instance a client reaches through its mixed inbound, every connection
// through a selector and a server of the test; packetEncoding only tells one outbound from another.
func detectConfiguration(t *testing.T, mixedPort int, serverPort int, packetEncoding string) []byte {
	return []byte(fmt.Sprintf(`{
  "log": {"disabled": true},
  "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": %d}],
  "outbounds": [
    {"type": "direct", "tag": "direct-out"},
    {"type": "vless", "tag": "a", "server": "127.0.0.1", "server_port": %d, "uuid": %q, "packet_encoding": %q},
    {"type": "selector", "tag": "sel", "outbounds": ["a"], "default": "a"}
  ],
  "route": {"final": "sel"},
  "experimental": {"cache_file": {"enabled": true, "path": %q}}
}`, mixedPort, serverPort, probeUUID, packetEncoding, filepath.Join(t.TempDir(), "cache.db")))
}

// detectInstance is a started instance of detectConfiguration; the manager of the traffic comes
// with the build for a log.
func detectInstance(t *testing.T, configuration []byte) *Instance {
	t.Helper()
	instance, err := BuildLogged(configuration, func(string, string) {})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close(10 * time.Second) })
	return instance
}

// detectServer is a VLESS server for what the block detector reads of a connection: it answers the
// first bytes of each connection with as many as the test tells, then holds it until told to cut.
type detectServer struct {
	listener net.Listener
	bytes    atomic.Int64
	access   sync.Mutex
	cuts     chan struct{}
}

func newDetectServer(t *testing.T) *detectServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &detectServer{listener: listener, cuts: make(chan struct{})}
	t.Cleanup(func() {
		listener.Close()
		server.cut()
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.serve(conn.(*net.TCPConn))
		}
	}()
	return server
}

// cut resets the connections held now: no end of the stream for the copy of the instance to see.
func (s *detectServer) cut() {
	s.access.Lock()
	defer s.access.Unlock()
	close(s.cuts)
	s.cuts = make(chan struct{})
}

func (s *detectServer) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *detectServer) serve(conn *net.TCPConn) {
	defer conn.Close()
	s.access.Lock()
	cuts := s.cuts
	s.access.Unlock()
	buffer := make([]byte, 4096)
	if _, err := conn.Read(buffer); err != nil {
		return
	}
	// the answer of VLESS, what the test asked for after it
	if _, err := conn.Write(append([]byte{0, 0}, make([]byte, s.bytes.Load())...)); err != nil {
		return
	}
	go io.Copy(io.Discard, conn)
	<-cuts
	_ = conn.SetLinger(0)
}

// detectClient opens a connection through the mixed inbound and reads what the server sends.
func detectClient(t *testing.T, mixedPort int, want int64) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", mixedPort))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	_, err = fmt.Fprint(conn, "CONNECT 203.0.113.9:80 HTTP/1.1\r\nHost: 203.0.113.9:80\r\n\r\n")
	require.NoError(t, err)
	answer := make([]byte, 64)
	n, err := conn.Read(answer)
	require.NoError(t, err)
	require.Contains(t, string(answer[:n]), " 200 ")
	// the request goes with the first bytes
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err = io.ReadFull(conn, make([]byte, want))
	require.NoError(t, err)
	return conn
}

func openOf(t *testing.T, instance *Instance) []detect.Conn {
	t.Helper()
	conns, err := instance.Connections()
	require.NoError(t, err)
	return conns
}

func flowsOf(t *testing.T, instance *Instance) map[string]detect.FlowSample {
	t.Helper()
	flows, err := instance.DetectFlows()
	require.NoError(t, err)
	return flows
}

// What the block detector reads of a real connection: a client that writes after a silence of the
// server waits for it, and such a connection that is cut counts; one that never waited does not.
func TestDetectFlowsOfRealConnections(t *testing.T) {
	const band = 18 << 10
	server := newDetectServer(t)
	mixedPort := freePort(t)
	instance := detectInstance(t, detectConfiguration(t, mixedPort, server.port(), "xudp"))

	server.bytes.Store(band)
	conn := detectClient(t, mixedPort, band)
	require.Eventually(t, func() bool {
		conns := openOf(t, instance)
		return len(conns) == 1 && conns[0].Down >= band
	}, 5*time.Second, 10*time.Millisecond)
	open := openOf(t, instance)[0]
	require.Equal(t, "a", open.Outbound, "the server, not the selector")
	require.True(t, open.PendingSince.IsZero(), "nothing asked of the server yet")

	// the silence of the server, and the client asks
	time.Sleep(5200 * time.Millisecond)
	_, err := conn.Write([]byte("more"))
	require.NoError(t, err)
	var since time.Time
	require.Eventually(t, func() bool {
		since = openOf(t, instance)[0].PendingSince
		return !since.IsZero()
	}, 5*time.Second, 10*time.Millisecond)
	require.Less(t, time.Since(since), 5*time.Second)
	require.GreaterOrEqual(t, openOf(t, instance)[0].Up, int64(len("more")))
	time.Sleep(3200 * time.Millisecond)
	server.cut()
	require.Eventually(t, func() bool { return len(flowsOf(t, instance)["a"].Cuts) == 1 }, 5*time.Second, 10*time.Millisecond)
	sample := flowsOf(t, instance)["a"]
	require.GreaterOrEqual(t, sample.Cuts[0].Download, int64(band))
	require.GreaterOrEqual(t, sample.Cuts[0].Upload, int64(len("more")), "a flow above the upload of a wait is no cut")
	require.WithinDuration(t, since, sample.Cuts[0].PendingSince, time.Second)
	require.GreaterOrEqual(t, sample.Cuts[0].ClosedAt.Sub(sample.Cuts[0].PendingSince), 3*time.Second)
	require.False(t, sample.LastDataAt.IsZero())
	require.True(t, sample.LastBigAt.IsZero())
	require.Empty(t, openOf(t, instance))

	// cut with its client never having waited: no cut
	detectClient(t, mixedPort, band)
	server.cut()
	require.Eventually(t, func() bool { return len(openOf(t, instance)) == 0 }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.Len(t, flowsOf(t, instance)["a"].Cuts, 1)
}

// A swap leaves out of what the block detector reads all that the outbound a tag had before did, its
// connections still open too; a swap that fails forgets nothing.
func TestSwapForgetsWhatTheOldOutboundDid(t *testing.T) {
	const big, band = 64 << 10, 18 << 10
	server := newDetectServer(t)
	mixedPort := freePort(t)
	instance := detectInstance(t, detectConfiguration(t, mixedPort, server.port(), "xudp"))

	// a big flow closed, and another that stays open
	server.bytes.Store(big)
	detectClient(t, mixedPort, big).Close()
	server.cut()
	require.Eventually(t, func() bool { return !flowsOf(t, instance)["a"].LastBigAt.IsZero() }, 5*time.Second, 10*time.Millisecond)
	held := detectClient(t, mixedPort, big)
	require.Eventually(t, func() bool {
		conns := openOf(t, instance)
		return len(conns) == 1 && conns[0].Down >= big
	}, 5*time.Second, 10*time.Millisecond)

	after := detectConfiguration(t, mixedPort, server.port(), "packetaddr")
	// the selector that stays goes through the server replaced: sing-box refuses, and nothing changes
	_, err := instance.Swap(after, Swap{Put: pickOutbounds(t, after, "a")}, 0)
	require.Error(t, err)
	require.False(t, flowsOf(t, instance)["a"].LastBigAt.IsZero(), "a swap that failed forgets nothing")
	require.Len(t, openOf(t, instance), 1)

	_, err = instance.Swap(after, Swap{Put: pickOutbounds(t, after, "a", "sel")}, 0)
	require.NoError(t, err)
	require.NotContains(t, flowsOf(t, instance), "a")
	require.Empty(t, openOf(t, instance), "a connection of the old outbound says nothing of the new link")

	// what the new outbound carries counts
	server.bytes.Store(band)
	fresh := detectClient(t, mixedPort, band)
	require.Eventually(t, func() bool {
		conns := openOf(t, instance)
		return len(conns) == 1 && conns[0].Down >= band
	}, 5*time.Second, 10*time.Millisecond)
	fresh.Close()

	// and the old connection, when it closes, does not
	held.Close()
	server.cut()
	require.Eventually(t, func() bool {
		traffic, err := instance.Traffic()
		return err == nil && traffic.Connections == 0
	}, 5*time.Second, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	sample := flowsOf(t, instance)["a"]
	require.True(t, sample.LastBigAt.IsZero(), "the big flow of the old outbound")
	require.False(t, sample.LastDataAt.IsZero(), "the flow of the new one")
}

// Servers of one name that changed places in the list: their tags are numbered in its order, and
// the choice of the dashboard follows the server, not the number. A swap sing-box refuses puts
// the choice back in the cache file.
func TestInstanceSwapCarriesTheChoiceWithTheServer(t *testing.T) {
	before := groupConfiguration(t, [2]string{"NL", "127.0.0.2"}, [2]string{"NL #2", "127.0.0.3"})
	instance, err := Build(before)
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close(10 * time.Second) })
	selector, _ := instance.box.Outbound().Outbound("yt-out")
	require.True(t, selector.(interface{ SelectOutbound(string) bool }).SelectOutbound("prov: NL #2"))
	cacheFile := service.FromContext[adapter.CacheFile](instance.ctx)

	after := groupConfiguration(t, [2]string{"NL", "127.0.0.3"}, [2]string{"NL #2", "127.0.0.2"})
	// the group and the selector that stay go through the servers replaced: sing-box refuses
	_, err = instance.Swap(after, Swap{Put: pickOutbounds(t, after, "prov: NL", "prov: NL #2")}, 0)
	require.Error(t, err)
	require.Equal(t, "prov: NL #2", cacheFile.LoadSelected("yt-out"), "the choice is put back")

	_, err = instance.Swap(after, Swap{Put: pickOutbounds(t, after, "prov: NL", "prov: NL #2", "g-group", "yt-out")}, 0)
	require.NoError(t, err)
	selector, _ = instance.box.Outbound().Outbound("yt-out")
	require.Equal(t, "prov: NL", selector.(adapter.OutboundGroup).Selected("tcp").Tag(), "the choice went with the server")
	require.Equal(t, "prov: NL", cacheFile.LoadSelected("yt-out"))
}

// A rename sing-box refuses leaves the history as the configuration that runs has it: no result
// under the new name, the one of the name that runs back.
func TestInstanceSwapRefusedKeepsTheHistory(t *testing.T) {
	before := swapConfiguration(t, "SE 113d", "FI")
	instance, err := Build(before)
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close(10 * time.Second) })
	history.storage.StoreURLTestHistory("prov: SE 113d", &adapter.URLTestHistory{Time: time.Now(), Delay: 130})

	after := swapConfiguration(t, "SE 112d", "FI")
	// the group and the selector that stay go through the server taken out: sing-box refuses
	_, err = instance.Swap(after, Swap{Put: pickOutbounds(t, after, "prov: SE 112d"), Remove: []string{"prov: SE 113d"}}, 0)
	require.Error(t, err)
	require.Nil(t, history.storage.LoadURLTestHistory("prov: SE 112d"), "nothing under a name that does not run")
	kept := history.storage.LoadURLTestHistory("prov: SE 113d")
	require.NotNil(t, kept, "the result of the server that runs is back")
	require.Equal(t, uint16(130), kept.Delay)
	history.access.Lock()
	_, started := history.started["prov: SE 113d"]
	history.access.Unlock()
	require.True(t, started, "the next start compares with what runs")
}

// The choices kept under the tags of v0.8.10 are taken over: a selector of the same tag whose
// choice names a server by its old tag takes the server of now; a renamed one takes the choice
// of its old tag unless it has one of its own.
func TestInstanceAdoptsSelections(t *testing.T) {
	configuration := groupConfiguration(t, [2]string{"NL", "127.0.0.2"}, [2]string{"NL #2", "127.0.0.3"})
	instance, err := Build(configuration)
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close(10 * time.Second) })
	cacheFile := service.FromContext[adapter.CacheFile](instance.ctx)
	selected := func() string {
		selector, _ := instance.box.Outbound().Outbound("yt-out")
		return selector.(adapter.OutboundGroup).Selected("tcp").Tag()
	}
	require.NoError(t, cacheFile.StoreSelected("yt-out", "src3: NL #2"))
	instance.AdoptSelections(map[string]string{"yt-out": "yt-out"}, map[string]string{"src3: NL #2": "prov: NL #2"})
	require.Equal(t, "prov: NL #2", selected())
	// a choice that names a member of now stays as it is
	instance.AdoptSelections(map[string]string{"yt-out": "yt-out"}, map[string]string{"prov: NL #2": "prov: NL"})
	require.Equal(t, "prov: NL #2", selected())
	// a renamed selector: the choice of its old tag, unless it has one
	require.NoError(t, cacheFile.StoreSelected("old-out", "src3: NL"))
	instance.AdoptSelections(map[string]string{"old-out": "yt-out"}, map[string]string{"src3: NL": "prov: NL"})
	require.Equal(t, "prov: NL #2", selected(), "it has a choice of its own")
}

func TestCarriedSelections(t *testing.T) {
	selector := func(tag string, members ...string) string {
		content, err := json.Marshal(map[string]any{"type": "selector", "tag": tag, "outbounds": members, "default": members[0]})
		require.NoError(t, err)
		return string(content)
	}
	dialers := func(outbounds ...string) map[string]dialer {
		return dialersOf([]byte(`{"outbounds": [` + strings.Join(outbounds, ", ") + `]}`))
	}
	group := `{"type": "urltest", "tag": "g-group", "outbounds": ["prov: A", "prov: B"]}`
	previous := dialers(testServer("prov: A", "10.0.0.1"), testServer("prov: B", "10.0.0.2"), group,
		selector("yt-out", "g-group", "prov: A", "prov: B"))
	for _, test := range []struct {
		name   string
		choice string
		next   map[string]dialer
		want   map[string]string
	}{
		{"renamed", "prov: B", dialers(testServer("prov: A", "10.0.0.1"), testServer("prov: B 112d", "10.0.0.2"),
			selector("yt-out", "g-group", "prov: A", "prov: B 112d")), map[string]string{"yt-out": "prov: B 112d"}},
		{"servers that changed places", "prov: B", dialers(testServer("prov: A", "10.0.0.2"), testServer("prov: B", "10.0.0.1"),
			selector("yt-out", "g-group", "prov: A", "prov: B")), map[string]string{"yt-out": "prov: A"}},
		{"the same", "prov: B", dialers(testServer("prov: A", "10.0.0.3"), testServer("prov: B", "10.0.0.2"),
			selector("yt-out", "g-group", "prov: A", "prov: B")), map[string]string{}},
		{"another server under the name", "prov: B", dialers(testServer("prov: A", "10.0.0.1"), testServer("prov: B", "10.0.0.9"),
			selector("yt-out", "g-group", "prov: A", "prov: B")), map[string]string{}},
		{"gone to another group", "prov: B", dialers(testServer("prov: A", "10.0.0.1"), testServer("prov: SE", "10.0.0.2"),
			selector("yt-out", "g-group", "prov: A"), selector("gm-out", "h-group", "prov: SE")), map[string]string{}},
		{"under two names: the first of the selector", "prov: B", dialers(testServer("prov: A", "10.0.0.1"), testServer("prov: B2", "10.0.0.2"),
			testServer("prov: B1", "10.0.0.2"), selector("yt-out", "g-group", "prov: A", "prov: B1", "prov: B2")), map[string]string{"yt-out": "prov: B1"}},
		{"the group", "g-group", dialers(testServer("prov: A", "10.0.0.1"), `{"type": "urltest", "tag": "g-group", "outbounds": ["prov: A"]}`,
			selector("yt-out", "g-group", "prov: A")), map[string]string{}},
		{"no choice", "", dialers(testServer("prov: B 112d", "10.0.0.2"), selector("yt-out", "g-group", "prov: B 112d")), map[string]string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			chosen := func(tag string) string {
				if tag == "yt-out" {
					return test.choice
				}
				return ""
			}
			require.Equal(t, test.want, carriedSelections(previous, test.next, chosen))
		})
	}
}
