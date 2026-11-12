package supervisor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/detect"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	E "github.com/sagernet/sing/common/exceptions"
)

// The states of a set_cure / clear_cure / drop_stale_cures call, read by the page.
const (
	CureOK         = "ok"
	CureViaDetour  = "via_detour"
	CureUnknown    = "unknown"
	CureInvalid    = "invalid"
	CureNotRunning = "not_running"
)

// The states of a suggest_mask call.
const (
	SuggestFound      = "found"
	SuggestNone       = "none"
	SuggestNotRunning = "not_running"
	SuggestThrottled  = "throttled"
	// the scan of this server goes on: ask again for its result
	SuggestRunning = "running"
	// a scan of another server goes on: one at a time
	SuggestBusy = "busy"
)

// suggestBudget is how long a whole white-SNI scan may take (the hand-over's value: the first hit
// came in about 1 s on the measured operator, 47 names at 6 at once stay within it when most
// fail fast). The names of the public list go in turn with the built-in ones (feedMasks), so a
// hit of either set comes in the first rounds, as it did there.
const suggestBudget = 35 * time.Second

// suggestWait is how long one suggest_mask call waits for the scan before it answers "running"
// and the page asks again: under the 20 s after which LuCI's rpc.js gives a call up
// (L.env.rpctimeout || 20, read on rodeo, OpenWrt 23.05.5), with 5 s for the round trip.
var suggestWait = 15 * time.Second

// suggestKeep is how long a finished scan's result waits for the page to collect it.
const suggestKeep = time.Minute

// CureResult is the answer of set_cure, clear_cure and drop_stale_cures: a state the page maps to
// a message.
type CureResult struct {
	State string `json:"state"`
}

// SuggestResult is the answer of suggest_mask: the state, and on "found" the name and how many were
// tried, on "throttled" the seconds to wait.
type SuggestResult struct {
	State      string `json:"state"`
	SNI        string `json:"sni,omitempty"`
	Tried      int    `json:"tried,omitempty"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

// suggestScan is the one white-SNI scan that runs or ran last; Supervisor.suggestAccess guards it.
type suggestScan struct {
	tag      string
	running  bool
	done     chan struct{}
	result   SuggestResult
	finished time.Time
}

// SetCure stores a treatment for the server a tag names and applies it. It refuses with a state
// when the tag is not a live server (unknown), the kind or sni is wrong (invalid: a mask must be a
// host name other than the server's own; a detour goes through a live server of another source,
// which itself connects directly), or a mask or a detour is asked of a server reached through a
// proxy (via_detour: a mask needs the server's own socket, an interface gives one; a detoured
// server already goes another way). through is the tag of the server a detour connects through
// (the one a pathblock answered through); the source of that server is stored. wantHash, when the
// page sends it, must still name the same server (unknown on a mismatch — the config changed under
// the page).
func (s *Supervisor) SetCure(ctx context.Context, tag, kind, sni, wantHash, through string) CureResult {
	snapshot := s.detectSnapshot()
	if snapshot.instance == nil {
		return CureResult{State: CureNotRunning}
	}
	identity, ok := snapshot.stable[tag]
	if !ok {
		return CureResult{State: CureUnknown}
	}
	if wantHash != "" && wantHash != identity.Hash {
		return CureResult{State: CureUnknown}
	}
	if !model.ValidCureKind(kind) {
		return CureResult{State: CureInvalid}
	}
	sni = strings.ToLower(strings.TrimSpace(sni))
	cure := model.Cure{Hash: identity.Hash, Via: identity.Via, Kind: kind, SNI: sni}
	if kind != model.CureDetour && through != "" {
		return CureResult{State: CureInvalid}
	}
	if kind == model.CureDetour {
		way, found := snapshot.stable[through]
		switch {
		case sni != "" || !found || way.Source == "" || way.Source == identity.Source || way.Via != "":
			return CureResult{State: CureInvalid}
		case identity.Via != "":
			return CureResult{State: CureViaDetour}
		}
		cure.Through = way.Source
	} else if kind == model.CureSpoof {
		if !model.ValidMaskName(sni) {
			return CureResult{State: CureInvalid}
		}
		if server, found := findServer(snapshot.servers, tag); found && strings.EqualFold(serverNameOf(server.Content), sni) {
			// the engine refuses a mask equal to the server name, and the build would fail
			return CureResult{State: CureInvalid}
		}
		if identity.Via != "" && !identity.ViaInterface {
			return CureResult{State: CureViaDetour}
		}
	} else if sni != "" {
		return CureResult{State: CureInvalid}
	}
	if err := s.writeCure(cure); err != nil {
		s.log("warn", "set the treatment of ", tag, ": ", err)
		return CureResult{State: CureInvalid}
	}
	s.Request(ctx)
	return CureResult{State: CureOK}
}

// ClearCure removes the treatment of the server a tag names and applies the change; a server with
// no treatment stored is left alone, without a rebuild.
func (s *Supervisor) ClearCure(ctx context.Context, tag string) CureResult {
	snapshot := s.detectSnapshot()
	if snapshot.instance == nil {
		return CureResult{State: CureNotRunning}
	}
	identity, ok := snapshot.stable[tag]
	if !ok {
		return CureResult{State: CureUnknown}
	}
	removed, err := s.editCures(func(sections []*uci.Section) []*uci.Section {
		return dropCure(sections, identity.Hash, identity.Via)
	})
	if err != nil {
		s.log("warn", "clear the treatment of ", tag, ": ", err)
		return CureResult{State: CureInvalid}
	}
	if removed > 0 {
		s.Request(ctx)
	}
	return CureResult{State: CureOK}
}

// DropStaleCures removes the stored treatments that name no live server (the server changed or
// went away, or its subscription is not downloaded yet) and the rows this build cannot read. The
// page offers it when the report counts stale treatments; nothing is dropped on its own, as a
// subscription that failed to download looks the same as a server that is gone.
func (s *Supervisor) DropStaleCures(ctx context.Context) CureResult {
	snapshot := s.detectSnapshot()
	if snapshot.instance == nil {
		return CureResult{State: CureNotRunning}
	}
	live := make(map[cureKey]bool, len(snapshot.stable))
	for _, identity := range snapshot.stable {
		live[cureKey{identity.Hash, identity.Via}] = true
	}
	removed, err := s.editCures(func(sections []*uci.Section) []*uci.Section {
		kept := make([]*uci.Section, 0, len(sections))
		for _, section := range sections {
			kind := section.Get("kind")
			if section.Type == "cure" && (!live[cureKey{section.Get("hash"), section.Get("via")}] || !model.ValidCureKind(kind) ||
				(kind == model.CureDetour && section.Get("through") == "")) {
				continue
			}
			kept = append(kept, section)
		}
		return kept
	})
	if err != nil {
		s.log("warn", "remove the stale treatments: ", err)
		return CureResult{State: CureInvalid}
	}
	if removed > 0 {
		s.log("info", "removed ", removed, " stale treatment(s)")
		s.Request(ctx)
	}
	return CureResult{State: CureOK}
}

type cureKey struct{ hash, via string }

// staleCures counts the stored treatments that name no live server, and the rows this build
// cannot read. The caller holds the state of the running configuration.
func staleCures(settings *model.Config, stable map[string]detect.Identity) int {
	live := make(map[cureKey]bool, len(stable))
	for _, identity := range stable {
		live[cureKey{identity.Hash, identity.Via}] = true
	}
	stale := settings.UnreadCures
	seen := make(map[cureKey]bool)
	for _, cure := range settings.Cures {
		key := cureKey{cure.Hash, cure.Via}
		if !live[key] && !seen[key] {
			stale++
		}
		seen[key] = true
	}
	return stale
}

// SuggestMask looks for a whitelisted SNI that lifts a limit on a server, on demand. One scan runs
// at a time, in the background with its own budget; a call waits for it up to suggestWait and
// answers "running" when it is not done yet, and the page asks again for the result. The scan is
// throttled per destination together with the detector's probes, so it does not burst a server the
// detector just probed (or the reverse), and sends real traffic to the server only when the page
// asks.
func (s *Supervisor) SuggestMask(ctx context.Context, tag string) SuggestResult {
	snapshot := s.detectSnapshot()
	if snapshot.instance == nil {
		return SuggestResult{State: SuggestNotRunning}
	}
	s.suggestAccess.Lock()
	scan := s.suggest
	switch {
	case scan != nil && scan.running && scan.tag != tag:
		s.suggestAccess.Unlock()
		return SuggestResult{State: SuggestBusy}
	case scan != nil && scan.running:
		// the page asks again for the scan it started
	case scan != nil && scan.tag == tag && time.Since(scan.finished) < suggestKeep:
		// a scan finished since the last call: its result, once
		s.suggest = nil
		s.suggestAccess.Unlock()
		return scan.result
	default:
		server, ok := findServer(snapshot.servers, tag)
		if !ok || server.Kind == detect.KindNone {
			s.suggestAccess.Unlock()
			return SuggestResult{State: SuggestNone}
		}
		now := time.Now()
		d := &s.diag
		d.access.Lock()
		if left := d.throttled(server.Destination, now); left > 0 {
			d.access.Unlock()
			s.suggestAccess.Unlock()
			return SuggestResult{State: SuggestThrottled, RetryAfter: secondsUp(left)}
		}
		if d.lastByDestination == nil {
			d.lastByDestination = make(map[string]time.Time)
		}
		d.lastByDestination[server.Destination] = now // reserve the destination for the detector too
		d.access.Unlock()
		scan = &suggestScan{tag: tag, running: true, done: make(chan struct{})}
		s.suggest = scan
		go s.runSuggest(scan, snapshot.instance, server.Content, snapshot.maskList)
	}
	s.suggestAccess.Unlock()

	timer := time.NewTimer(suggestWait)
	defer timer.Stop()
	select {
	case <-scan.done:
	case <-timer.C:
		return SuggestResult{State: SuggestRunning}
	case <-ctx.Done():
		return SuggestResult{State: SuggestRunning}
	}
	s.suggestAccess.Lock()
	defer s.suggestAccess.Unlock()
	if s.suggest == scan {
		s.suggest = nil
	}
	return scan.result
}

// runSuggest runs one scan to its end and keeps its result for the page. The built-in names go
// first, the names of the public list at maskList ("" none) after them (feedMasks).
func (s *Supervisor) runSuggest(scan *suggestScan, instance Instance, content []byte, maskList string) {
	ctx, cancel := context.WithTimeout(context.Background(), suggestBudget)
	defer cancel()
	names := make(chan string)
	go s.feedMasks(ctx, names, maskList)
	sni, tried, err := instance.SuggestMask(ctx, content, names)
	result := SuggestResult{State: SuggestNone, Tried: tried}
	switch {
	case err != nil:
		s.log("warn", "suggest a mask for ", scan.tag, ": ", err)
	case sni != "":
		result = SuggestResult{State: SuggestFound, SNI: sni, Tried: tried}
	}
	s.suggestAccess.Lock()
	scan.result, scan.running, scan.finished = result, false, time.Now()
	s.suggestAccess.Unlock()
	close(scan.done)
}

// serverNameOf is tls.server_name of an outbound, "" when it has none.
func serverNameOf(content []byte) string {
	var outbound struct {
		TLS struct {
			ServerName string `json:"server_name"`
		} `json:"tls"`
	}
	_ = json.Unmarshal(content, &outbound)
	return outbound.TLS.ServerName
}

// writeCure stores one cure, replacing any with the same {hash, via}.
func (s *Supervisor) writeCure(cure model.Cure) error {
	_, err := s.editCures(func(sections []*uci.Section) []*uci.Section {
		kept := dropCure(sections, cure.Hash, cure.Via)
		section := uci.NewSection("cure", "", true)
		section.Set("hash", cure.Hash)
		if cure.Via != "" {
			section.Set("via", cure.Via)
		}
		section.Set("kind", cure.Kind)
		switch cure.Kind {
		case model.CureSpoof:
			section.Set("sni", cure.SNI)
		case model.CureDetour:
			section.Set("through", cure.Through)
		}
		return append(kept, section)
	})
	return err
}

// dropCure returns the sections without the `cure` sections of a {hash, via}, the others untouched.
func dropCure(sections []*uci.Section, hash, via string) []*uci.Section {
	kept := make([]*uci.Section, 0, len(sections))
	for _, section := range sections {
		if section.Type == "cure" && section.Get("hash") == hash && section.Get("via") == via {
			continue
		}
		kept = append(kept, section)
	}
	return kept
}

// editCures reads the settings file, rewrites its sections with edit, and writes it back,
// atomically (a temporary in the same directory renamed over the file) and with the same
// permissions. It answers how many cure sections the edit took out. It holds the lock libuci takes
// for a commit (flock LOCK_EX on the file itself), so a `uci commit` of LuCI waits for it and it
// waits for that one; comments of the file are not kept, as libuci does not keep them either.
func (s *Supervisor) editCures(edit func([]*uci.Section) []*uci.Section) (int, error) {
	s.cureMu.Lock()
	defer s.cureMu.Unlock()
	path := s.options.SettingsPath
	file, err := lockFile(path)
	if err != nil {
		return 0, err
	}
	defer file.Close() // releases the lock
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	parsed, err := uci.Parse(content)
	if err != nil {
		return 0, E.Cause(err, "read ", path)
	}
	original := make(map[*uci.Section]bool)
	for _, section := range parsed.Sections {
		original[section] = true
	}
	sections := edit(parsed.Sections)
	kept := make(map[*uci.Section]bool)
	added := 0
	for _, section := range sections {
		if original[section] {
			kept[section] = true
		} else {
			added++
		}
	}
	removed := 0
	for _, section := range parsed.Sections {
		if !kept[section] {
			removed++
		}
	}
	if removed == 0 && added == 0 {
		// nothing to change: the file is not written
		return 0, nil
	}
	parsed.Sections = sections
	temporary, err := os.CreateTemp(filepath.Dir(path), ".podkop-cure-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(parsed.Format()); err != nil {
		temporary.Close()
		return 0, err
	}
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		temporary.Close()
		return 0, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return 0, err
	}
	if err := temporary.Close(); err != nil {
		return 0, err
	}
	return removed, os.Rename(temporary.Name(), path)
}

// lockFile opens the file at path and takes the exclusive flock libuci takes before it writes a
// configuration. A commit replaces the file by a rename: when the file at the path is no longer the
// one locked, the lock is taken again on the new one.
func lockFile(path string) (*os.File, error) {
	for attempt := 0; attempt < 10; attempt++ {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
			file.Close()
			return nil, err
		}
		locked, errLocked := file.Stat()
		current, errCurrent := os.Stat(path)
		if errLocked == nil && errCurrent == nil && os.SameFile(locked, current) {
			return file, nil
		}
		file.Close()
	}
	return nil, E.New("lock ", path, ": the file keeps being replaced")
}
