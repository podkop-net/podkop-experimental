package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/detect"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	"github.com/stretchr/testify/require"
)

func parseFile(t *testing.T, path string) *uci.Package {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	parsed, err := uci.Parse(content)
	require.NoError(t, err)
	return parsed
}

func cureByHash(parsed *uci.Package, hash, via string) *uci.Section {
	for _, section := range parsed.SectionsOfType("cure") {
		if section.Get("hash") == hash && section.Get("via") == via {
			return section
		}
	}
	return nil
}

// TestCureStoreRoundTrip writes, updates and removes cure sections in the settings file, keeping
// the other sections and the permissions, and never duplicating a {hash, via}.
func TestCureStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "podkop")
	require.NoError(t, os.WriteFile(path, []byte("config settings 'settings'\n\toption config_version '2'\n"), 0o640))
	s := &Supervisor{options: Options{SettingsPath: path}}

	require.NoError(t, s.writeCure(model.Cure{Hash: "h1", Kind: model.CureSpoof, SNI: "packagist.org"}))
	require.NoError(t, s.writeCure(model.Cure{Hash: "h2", Via: "relay", Kind: model.CureRecordFragment}))
	parsed := parseFile(t, path)
	require.Len(t, parsed.SectionsOfType("cure"), 2)
	require.Equal(t, "2", parsed.Section("settings").Get("config_version"), "the settings section is kept")

	h1 := cureByHash(parsed, "h1", "")
	require.NotNil(t, h1)
	require.Equal(t, "spoof", h1.Get("kind"))
	require.Equal(t, "packagist.org", h1.Get("sni"))
	h2 := cureByHash(parsed, "h2", "relay")
	require.NotNil(t, h2)
	require.Equal(t, "record_fragment", h2.Get("kind"))
	require.Empty(t, h2.Get("sni"))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), info.Mode().Perm(), "the permissions are kept")

	// updating the same {hash, via} replaces, it does not add a second row
	require.NoError(t, s.writeCure(model.Cure{Hash: "h1", Kind: model.CureRecordFragment}))
	parsed = parseFile(t, path)
	require.Len(t, parsed.SectionsOfType("cure"), 2)
	h1 = cureByHash(parsed, "h1", "")
	require.Equal(t, "record_fragment", h1.Get("kind"))
	require.Empty(t, h1.Get("sni"), "a non-spoof cure keeps no sni")

	removed, err := s.editCures(func(sections []*uci.Section) []*uci.Section { return dropCure(sections, "h2", "relay") })
	require.NoError(t, err)
	require.Equal(t, 1, removed)
	parsed = parseFile(t, path)
	require.Len(t, parsed.SectionsOfType("cure"), 1)
	require.Nil(t, cureByHash(parsed, "h2", "relay"))
	require.NotNil(t, cureByHash(parsed, "h1", ""))
}

func TestDropCure(t *testing.T) {
	sections := []*uci.Section{
		uci.NewSection("settings", "settings", false),
		cureSection("h1", "", "spoof", "a"),
		cureSection("h1", "relay", "record_fragment", ""),
		cureSection("h2", "", "record_fragment", ""),
	}
	kept := dropCure(sections, "h1", "")
	require.Len(t, kept, 3)
	require.Nil(t, cureByHash(&uci.Package{Sections: kept}, "h1", ""))
	require.NotNil(t, cureByHash(&uci.Package{Sections: kept}, "h1", "relay"), "a different via is left")
	require.NotNil(t, cureByHash(&uci.Package{Sections: kept}, "h2", ""))
}

func cureSection(hash, via, kind, sni string) *uci.Section {
	section := uci.NewSection("cure", "", true)
	section.Set("hash", hash)
	if via != "" {
		section.Set("via", via)
	}
	section.Set("kind", kind)
	if sni != "" {
		section.Set("sni", sni)
	}
	return section
}

// TestSetCureRefusals covers the states a set_cure call returns before it writes anything: these
// need no running daemon. The happy path (which reaches a rebuild) is covered on the stand.
func TestSetCureRefusals(t *testing.T) {
	ctx := context.Background()

	// nothing runs
	down := &Supervisor{}
	require.Equal(t, CureNotRunning, down.SetCure(ctx, "srv", "spoof", "x", "", "").State)

	s := &Supervisor{}
	s.live = &fakeInstance{}
	s.liveStable = map[string]detect.Identity{
		"srv":    {Hash: "h1", Via: ""},
		"srvVia": {Hash: "h2", Via: "relay"},
	}

	require.Equal(t, CureUnknown, s.SetCure(ctx, "nope", "spoof", "x", "", "").State, "a tag that is no live server")
	require.Equal(t, CureUnknown, s.SetCure(ctx, "srv", "spoof", "x", "other", "").State, "the server changed under the page")
	require.Equal(t, CureInvalid, s.SetCure(ctx, "srv", "bogus", "", "", "").State, "an unknown kind")
	require.Equal(t, CureInvalid, s.SetCure(ctx, "srv", "spoof", "", "", "").State, "spoof without an sni")
	require.Equal(t, CureInvalid, s.SetCure(ctx, "srv", "record_fragment", "x", "", "").State, "a non-spoof with an sni")
	require.Equal(t, CureViaDetour, s.SetCure(ctx, "srvVia", "spoof", "packagist.org", "", "").State, "a mask through a detour")
	require.Equal(t, CureInvalid, s.SetCure(ctx, "srv", "oob", "", "", "").State, "oob is not a kind of this build")
	require.Equal(t, CureInvalid, s.SetCure(ctx, "srv", "spoof", "not a name", "", "").State, "a mask that is no host name")
	require.Equal(t, CureInvalid, s.SetCure(ctx, "srv", "spoof", "192.0.2.1", "", "").State, "a mask that is an address")

	require.Equal(t, CureNotRunning, down.ClearCure(ctx, "srv").State)
	require.Equal(t, CureUnknown, s.ClearCure(ctx, "nope").State)
}

func TestValidMaskName(t *testing.T) {
	for _, name := range []string{"packagist.org", "a.b.example", "x-1.example.com"} {
		require.True(t, model.ValidMaskName(name), name)
	}
	for _, name := range []string{"", "org", "Packagist.org", "-a.org", "a-.org", "a..org", "a.org.", "192.0.2.1", "::1", "a b.org", "a'.org", strings.Repeat("a", 64) + ".org"} {
		require.False(t, model.ValidMaskName(name), name)
	}
}

// liveSupervisor is a supervisor with a running instance, a settings file and three live servers:
// one direct, one through a proxy source, one through an interface source.
func liveSupervisor(t *testing.T, instance *fakeInstance) (*Supervisor, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "podkop")
	require.NoError(t, os.WriteFile(path, []byte("config settings 'settings'\n\toption config_version '2'\n"), 0o600))
	s := &Supervisor{options: Options{SettingsPath: path, Log: func(string, string) {}}}
	s.live = instance
	s.liveServers = []detect.Server{
		{Tag: "srv", Kind: detect.KindTLS, Destination: "a.example:443", Content: []byte(`{"type":"vless","tls":{"server_name":"cover.example"}}`)},
		{Tag: "srvIf", Kind: detect.KindTLS, Destination: "b.example:443"},
	}
	s.liveStable = map[string]detect.Identity{
		"srv":    {Hash: "h1", Source: "own"},
		"srvVia": {Hash: "h2", Via: "relay", Source: "own2"},
		"srvIf":  {Hash: "h3", Via: "wan2", ViaInterface: true, Source: "own3"},
		"px1":    {Hash: "h4", Source: "relay"},
		"own2":   {Hash: "h5", Source: "own"},
	}
	return s, path
}

// A detour goes through a live server that connects directly, of another source or of the
// server's own (one subscription); that server is stored by its stable identity, with its source.
func TestSetCureDetour(t *testing.T) {
	s, path := liveSupervisor(t, &fakeInstance{})
	s.liveStable["chained"] = detect.Identity{Hash: "h6", Source: "relay", Cure: &detect.Cure{Kind: model.CureDetour, Through: "own"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Equal(t, CureInvalid, s.SetCure(ctx, "srv", "detour", "", "", "").State, "no way named")
	require.Equal(t, CureInvalid, s.SetCure(ctx, "srv", "detour", "", "", "nope").State, "no such server")
	require.Equal(t, CureInvalid, s.SetCure(ctx, "srv", "detour", "", "", "srv").State, "the server itself")
	require.Equal(t, CureInvalid, s.SetCure(ctx, "srv", "detour", "", "", "srvVia").State, "a way that is detoured itself")
	require.Equal(t, CureInvalid, s.SetCure(ctx, "srv", "detour", "", "", "chained").State, "a way with a detour of its own: a chain")
	require.Equal(t, CureInvalid, s.SetCure(ctx, "srv", "record_fragment", "", "", "px1").State, "a way is only for a detour")
	require.Equal(t, CureViaDetour, s.SetCure(ctx, "srvVia", "detour", "", "", "px1").State, "a server that goes another way already")

	require.Equal(t, CureOK, s.SetCure(ctx, "srv", "detour", "", "", "px1").State, "a server of another source")
	stored := cureByHash(parseFile(t, path), "h1", "")
	require.NotNil(t, stored)
	require.Equal(t, "detour", stored.Get("kind"))
	require.Equal(t, "relay", stored.Get("through"), "the source of px1")
	require.Equal(t, "h4", stored.Get("relay"), "px1 itself")

	// the report's case: a server of the same subscription
	require.Equal(t, CureOK, s.SetCure(ctx, "srv", "detour", "", "", "own2").State, "a server of its own source")
	parsed := parseFile(t, path)
	require.Len(t, parsed.SectionsOfType("cure"), 1, "the new treatment replaces the old one")
	stored = cureByHash(parsed, "h1", "")
	require.Equal(t, "own", stored.Get("through"))
	require.Equal(t, "h5", stored.Get("relay"))
}

// A detour whose relay server is not live is stale, as one whose own server is not; a detour of
// 0.8.13 (no relay) is stale only by its own server.
func TestStaleDetour(t *testing.T) {
	s, path := liveSupervisor(t, &fakeInstance{})
	content := "config settings 'settings'\n\toption config_version '2'\n" +
		"\nconfig cure\n\toption hash 'h1'\n\toption kind 'detour'\n\toption through 'own'\n\toption relay 'h5'\n" +
		"\nconfig cure\n\toption hash 'h4'\n\toption kind 'detour'\n\toption through 'own'\n\toption relay 'gone'\n" +
		"\nconfig cure\n\toption hash 'h5'\n\toption kind 'detour'\n\toption through 'relay'\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	parsed, err := uci.Parse([]byte(content))
	require.NoError(t, err)
	settings, err := model.Load(parsed)
	require.NoError(t, err)
	require.Equal(t, "h5", settings.Cures[0].Relay)
	require.Equal(t, 1, staleCures(settings, s.liveStable), "the relay of h4 is gone")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Equal(t, CureOK, s.DropStaleCures(ctx).State)
	left := parseFile(t, path)
	require.Len(t, left.SectionsOfType("cure"), 2)
	require.Nil(t, cureByHash(left, "h4", ""))
}

// A mask and a split of the hello are refused for a server whose handshake is no TLS over TCP:
// the build would leave them off, and the tile would say they are on.
func TestSetCureNoTLS(t *testing.T) {
	s, path := liveSupervisor(t, &fakeInstance{})
	s.liveServers = append(s.liveServers,
		detect.Server{Tag: "ss", Kind: detect.KindPlain, Destination: "c.example:8388"},
		detect.Server{Tag: "hy2", Kind: detect.KindUDP, Destination: "d.example:443"})
	s.liveStable["ss"] = detect.Identity{Hash: "h7", Source: "own"}
	s.liveStable["hy2"] = detect.Identity{Hash: "h8", Source: "own"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tag := range []string{"ss", "hy2"} {
		require.Equal(t, CureNoTLS, s.SetCure(ctx, tag, "spoof", "packagist.org", "", "").State, tag)
		require.Equal(t, CureNoTLS, s.SetCure(ctx, tag, "record_fragment", "", "", "").State, tag)
	}
	require.Empty(t, parseFile(t, path).SectionsOfType("cure"), "nothing stored")
	// a detour has nothing to do with TLS: it goes through another server
	require.Equal(t, CureOK, s.SetCure(ctx, "ss", "detour", "", "", "px1").State)
	require.Equal(t, SuggestNone, s.SuggestMask(ctx, "ss").State, "no scan for a mask")
}

// A mask is refused when it is the server's own name, and allowed through an interface, which
// gives the server its own socket.
func TestSetCureMaskRules(t *testing.T) {
	s, path := liveSupervisor(t, &fakeInstance{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the rebuild a stored cure asks for is not waited for here
	require.Equal(t, CureInvalid, s.SetCure(ctx, "srv", "spoof", "Cover.Example", "", "").State, "the server's own name")
	require.Equal(t, CureOK, s.SetCure(ctx, "srvIf", "spoof", " Packagist.org ", "", "").State, "through an interface")
	stored := cureByHash(parseFile(t, path), "h3", "wan2")
	require.NotNil(t, stored)
	require.Equal(t, "packagist.org", stored.Get("sni"), "the name is stored trimmed and in lower case")
}

// Clearing a server with no treatment writes nothing and asks for no rebuild.
func TestClearCureWithoutCure(t *testing.T) {
	s, path := liveSupervisor(t, &fakeInstance{})
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	info, err := os.Stat(path)
	require.NoError(t, err)
	// a context that is never done: a rebuild asked for would hang the test
	require.Equal(t, CureOK, s.ClearCure(context.Background(), "srv").State)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
	again, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, os.SameFile(info, again), "the file is not replaced")
}

// The stale treatments are the rows of no live server and the rows this build cannot read; they
// are counted, and removed only on request.
func TestStaleCures(t *testing.T) {
	s, path := liveSupervisor(t, &fakeInstance{})
	content := "config settings 'settings'\n\toption config_version '2'\n" +
		"\nconfig cure\n\toption hash 'h1'\n\toption kind 'record_fragment'\n" +
		"\nconfig cure\n\toption hash 'gone'\n\toption kind 'record_fragment'\n" +
		"\nconfig cure\n\toption hash 'h2'\n\toption kind 'record_fragment'\n" +
		"\nconfig cure\n\toption hash 'h1'\n\toption via 'relay'\n\toption kind 'oob'\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	parsed, err := uci.Parse([]byte(content))
	require.NoError(t, err)
	settings, err := model.Load(parsed)
	require.NoError(t, err)
	// h2 is live only through relay: the direct row of h2 is stale too
	require.Equal(t, 3, staleCures(settings, s.liveStable), "gone, h2 direct, and the oob row")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Equal(t, CureOK, s.DropStaleCures(ctx).State)
	left := parseFile(t, path)
	require.Len(t, left.SectionsOfType("cure"), 1)
	require.NotNil(t, cureByHash(left, "h1", ""))
	require.Equal(t, "2", left.Section("settings").Get("config_version"))
}

// suggestInstance answers SuggestMask after a release, counting the scans.
type suggestInstance struct {
	fakeInstance
	release chan struct{}
	scans   atomic.Int32
}

func (i *suggestInstance) SuggestMask(ctx context.Context, _ []byte, _ <-chan string) (string, int, error) {
	i.scans.Add(1)
	select {
	case <-i.release:
		return "packagist.org", 3, nil
	case <-ctx.Done():
		return "", 0, ctx.Err()
	}
}

// A scan longer than one call answers "running"; the page asks again and gets the result once;
// a scan of another server meanwhile is refused as busy, and asking again starts no second scan.
func TestSuggestMaskAsync(t *testing.T) {
	saved := suggestWait
	suggestWait = 50 * time.Millisecond
	defer func() { suggestWait = saved }()
	instance := &suggestInstance{release: make(chan struct{})}
	s, _ := liveSupervisor(t, &fakeInstance{})
	s.live = instance
	ctx := context.Background()

	require.Equal(t, SuggestRunning, s.SuggestMask(ctx, "srv").State)
	require.Equal(t, SuggestBusy, s.SuggestMask(ctx, "srvIf").State)
	require.Equal(t, SuggestRunning, s.SuggestMask(ctx, "srv").State)
	require.Equal(t, int32(1), instance.scans.Load(), "asking again joins the scan")
	close(instance.release)
	require.Eventually(t, func() bool {
		s.suggestAccess.Lock()
		defer s.suggestAccess.Unlock()
		return s.suggest != nil && !s.suggest.running
	}, 5*time.Second, 10*time.Millisecond)
	result := s.SuggestMask(ctx, "srv")
	require.Equal(t, SuggestResult{State: SuggestFound, SNI: "packagist.org", Tried: 3}, result)
	// collected once: the next call is a new scan, which the throttle of the destination stops
	require.Equal(t, SuggestThrottled, s.SuggestMask(ctx, "srv").State)
	require.Equal(t, int32(1), instance.scans.Load())
}
