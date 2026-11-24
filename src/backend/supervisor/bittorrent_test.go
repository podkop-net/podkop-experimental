package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/btstats"
	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"

	"github.com/stretchr/testify/require"
)

// bitTorrentAsked is a bitTorrentHost that counts the applies it was asked for.
type bitTorrentAsked struct {
	applies int
}

func (h *bitTorrentAsked) log(string, ...any) {}

func (h *bitTorrentAsked) Apply() Result {
	h.applies++
	return Result{}
}

// readsSystem is a System that tells of each read of the BitTorrent traffic.
type readsSystem struct {
	recorder
	reads chan struct{}
}

func (r *readsSystem) BitTorrentFlows() ([]btstats.Flow, error) {
	r.reads <- struct{}{}
	return nil, nil
}

// A user of the router's torrent clients that came after the state that runs was built has the
// settings applied again by the clock, once for each state of the users; not while the users are
// those it was built with, nor with BitTorrent off.
func TestRouterUsersByTheClock(t *testing.T) {
	host := &bitTorrentAsked{}
	b := newBitTorrentRuntime(&Options{}, host)
	settings := &model.Config{}
	settings.Settings.BitTorrentRouterUsers = []string{"root", "no-such-user-of-podkop"}
	result := &plan.Result{}
	result.Dataplane.BitTorrent.Mode = model.BitTorrentBypass
	current := &running{settings: settings, result: result}

	result.Facts.UserIDs = map[string]uint32{"root": 0}
	b.tick(current)
	require.Zero(t, host.applies, "the users it was built with")
	result.Facts.UserIDs = map[string]uint32{}
	b.tick(current)
	require.Equal(t, 1, host.applies, "root came")
	b.tick(current)
	require.Equal(t, 1, host.applies, "the apply came to nothing: not again for the same users")
	b.usersTried = nil
	result.Dataplane.BitTorrent.Mode = ""
	b.tick(current)
	require.Equal(t, 1, host.applies, "BitTorrent is off")

	// the only user it was built with is gone: no user is there now
	settings.Settings.BitTorrentRouterUsers = []string{"no-such-user-of-podkop"}
	result.Dataplane.BitTorrent.Mode = model.BitTorrentBypass
	result.Facts.UserIDs = map[string]uint32{"no-such-user-of-podkop": 64999}
	b.tick(current)
	require.Equal(t, 2, host.applies, "a user went away")
	b.tick(current)
	require.Equal(t, 2, host.applies, "once")
}

// The traffic of a detector that came or changed is read at once, not at the next tick; not that of
// a table applied again with the detector it had, nor once the table is gone. What the report tells
// of the mode follows the table, and the rule of the mode section that is not there is told while
// something runs.
func TestBitTorrentReadAtOnce(t *testing.T) {
	system := &readsSystem{reads: make(chan struct{})}
	b := newBitTorrentRuntime(&Options{System: system}, &bitTorrentAsked{})
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		b.poll(ctx)
	}()
	read := func(want bool, why string) {
		t.Helper()
		wait := 10 * time.Second
		if !want {
			// much less than btstats.PollEvery
			wait = 100 * time.Millisecond
		}
		select {
		case <-system.reads:
			require.True(t, want, why)
		case <-time.After(wait):
			require.False(t, want, why)
		}
	}
	require.Empty(t, b.report().Mode)
	bypass := firewall.BitTorrent{Mode: firewall.BitTorrentBypass}
	b.updated(bypass)
	read(true, "the detector came")
	require.Equal(t, firewall.BitTorrentBypass, b.report().Mode)
	b.updated(bypass)
	read(false, "the same detector")
	b.updated(firewall.BitTorrent{Mode: firewall.BitTorrentBlock, LAN: true})
	read(true, "another mode")
	require.True(t, b.report().LAN)
	require.Equal(t, []string{"forget bittorrent all"}, system.take())
	b.released(false)
	require.Equal(t, firewall.BitTorrentBlock, b.report().Mode, "the table could not be removed")
	b.released(true)
	require.Empty(t, b.report().Mode)
	b.updated(firewall.BitTorrent{Mode: firewall.BitTorrentBlock})
	read(true, "the detector of a table made anew")
	require.Empty(t, system.take(), "a detector made when there was none")

	settings := &model.Config{Sections: []model.Section{{Name: "torrents", Label: "Torrents"}}}
	settings.Settings.BitTorrent, settings.Settings.BitTorrentSection = model.BitTorrentSection, "torrents"
	current := &running{settings: settings, result: &plan.Result{}}
	b.planned(current)
	b.updated(firewall.BitTorrent{})
	require.Equal(t, btstats.ProblemRule, b.report().Problem, "the plan has no detector for the rule")
	require.Equal(t, "Torrents", b.report().Rule)
	current.result.Dataplane.BitTorrent.Mode = model.BitTorrentSection
	b.planned(current)
	b.updated(firewall.BitTorrent{Mode: firewall.BitTorrentSection})
	read(true, "the detector came back")
	require.Equal(t, "Torrents", b.report().Rule)
	require.Empty(t, b.report().Problem)
	b.planned(&running{settings: settings, result: &plan.Result{}})
	b.released(true)
	require.Empty(t, b.report().Problem, "nothing runs")
	cancel()
	<-ended
}

// The report follows what the supervisor does with the table: the mode and the rule of the state a
// boot or an apply brought up, the rule chosen that is not there, nothing once the router is given
// back.
func TestBitTorrentReportOfAState(t *testing.T) {
	s, _, _, _ := fakeFixture(t)
	settings := func(rule string) {
		text := plainSettings("60", "\toption bittorrent 'section'\n\toption bittorrent_section '"+rule+"'\n", "")(filepath.Dir(s.options.SettingsPath))
		require.NoError(t, os.WriteFile(s.options.SettingsPath, []byte(text), 0o644))
	}
	told := func(mode string, problem string, rule string) {
		t.Helper()
		report := s.BitTorrentStats()
		require.Equal(t, []string{mode, problem, rule}, []string{report.Mode, report.Problem, report.Rule})
	}
	told("", "", "")
	settings("main")
	require.True(t, s.Boot().OK)
	told(firewall.BitTorrentSection, "", "main")
	settings("gone")
	require.True(t, s.Apply().OK)
	told("", btstats.ProblemRule, "gone")
	settings("main")
	require.True(t, s.Apply().OK)
	told(firewall.BitTorrentSection, "", "main")
	s.Stop()
	told("", "", "")
	settings("gone")
	require.True(t, s.Boot().OK)
	told("", btstats.ProblemRule, "gone")
	s.Stop()
	told("", "", "")
}
