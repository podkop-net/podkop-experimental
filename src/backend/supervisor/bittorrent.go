package supervisor

import (
	"context"
	"errors"
	"maps"
	"os/user"
	"strconv"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/btstats"
	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
)

// BitTorrent is what the BitTorrent module of the running sing-box has counted (api.Backend).
func (s *Supervisor) BitTorrent() map[string]int64 {
	return engine.BitTorrentCounters()
}

// pollBitTorrent reads what the BitTorrent traffic of the LAN came to every btstats.PollEvery
// while a table with the detector is there (bitTorrentSetup), until ctx ends; it starts again from
// nothing when the detector goes or its mode changes (the ways of the rows are of a mode). Its own
// goroutine: a read of the entries is a dump of conntrack.
func (s *Supervisor) pollBitTorrent(ctx context.Context) {
	ticker := time.NewTicker(btstats.PollEvery)
	defer ticker.Stop()
	var last *btstats.Setup
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			last = s.readBitTorrent(last, now)
		case <-s.bitTorrentWake:
			// a table was applied: only a detector that came or changed is read ahead of the tick
			if setup := s.bitTorrentSetup.Load(); setup != nil && (last == nil || setup.Mode != last.Mode || setup.LAN != last.LAN) {
				last = s.readBitTorrent(last, time.Now())
			}
		}
	}
}

// readBitTorrent is a read of pollBitTorrent at now: last is the setup of the read before, and the
// setup read now is given back.
func (s *Supervisor) readBitTorrent(last *btstats.Setup, now time.Time) *btstats.Setup {
	setup := s.bitTorrentSetup.Load()
	if last != nil && (setup == nil || setup.Mode != last.Mode || setup.LAN != last.LAN) {
		s.bitTorrentStats.Reset()
	}
	if setup == nil {
		return nil
	}
	flows, err := s.options.System.BitTorrentFlows()
	drops, dropsErr := s.options.System.BitTorrentDrops()
	s.bitTorrentStats.Observe(*setup, flows, drops, errors.Join(err, dropsErr), now)
	return setup
}

// BitTorrentStats is what the BitTorrent traffic of the LAN came to (btstats.Report), with the
// counters of the module of the sing-box that runs. It may be called from any goroutine.
func (s *Supervisor) BitTorrentStats() btstats.Report {
	setup := s.bitTorrentSetup.Load()
	if setup == nil {
		report := btstats.Report{Rows: []btstats.Row{}, Blocked: []btstats.Blocked{}, Module: engine.BitTorrentCounters()}
		if rule := s.bitTorrentNoRule.Load(); rule != nil {
			report.Problem, report.Rule = btstats.ProblemRule, *rule
		}
		return report
	}
	report := s.bitTorrentStats.Report(time.Now())
	// the mode the firewall has now: the first read comes btstats.PollEvery after it
	report.Mode, report.LAN, report.Rule = setup.Mode, setup.LAN, setup.Rule
	report.Module = s.bitTorrentStats.ModuleSince(engine.BitTorrentCounters())
	return report
}

// ResetBitTorrentStats starts the statistics of BitTorrent again from now, the mode kept (the
// page's button, `podkop bittorrent_reset`), and answers them: a test needs no restart of podkop,
// which also forgot the devices the detector knew.
func (s *Supervisor) ResetBitTorrentStats() btstats.Report {
	s.bitTorrentStats.ResetCounts(engine.BitTorrentCounters(), time.Now())
	return s.BitTorrentStats()
}

// forgetBitTorrent ends the connections of BitTorrent past podkop that the mode next takes
// otherwise than the mode previous did: those the router offloads pass no rule of the firewall,
// and the mode next takes them only when they go on with new entries.
func (s *Supervisor) forgetBitTorrent(previous, next firewall.BitTorrent, which firewall.Forget) {
	from, to := bitTorrentModeName(previous), bitTorrentModeName(next)
	err := s.options.System.ForgetBitTorrentFlows(which)
	if err != nil {
		s.log("warn", "BitTorrent went from the mode ", from, " to ", to, ", but its connections past podkop go on that way until they end: ", err)
		return
	}
	s.log("info", "BitTorrent went from the mode ", from, " to ", to, ": its connections past podkop were ended, and the mode ", to, " takes them when they go on")
}

// bitTorrentModeName is the mode of a detector as the log names it.
func bitTorrentModeName(detector firewall.BitTorrent) string {
	switch {
	case detector.Mode == "":
		return "off"
	case detector.LAN:
		return detector.Mode + " of the whole LAN"
	}
	return detector.Mode
}

// routerUsersChanged tells whether the users of the router's torrent clients the settings name are
// not those the configuration running was built with: one gained or lost since (the package of the
// client installed after the setting was made creates its user and fires no event). Only with
// BitTorrent on: off, the plan uses none.
func (s *Supervisor) routerUsersChanged(current *running) bool {
	if current == nil || current.settings == nil || current.result.Dataplane.BitTorrent.Mode == "" {
		return false
	}
	names := current.settings.Settings.BitTorrentRouterUsers
	return len(names) > 0 && !maps.Equal(userIDs(names), current.result.Facts.UserIDs)
}

// userIDs are the numbers of the users of the router with these names (the system's user
// database: /etc/passwd on OpenWrt); a name the router does not have is left out. None asked,
// nothing is read.
func userIDs(names []string) map[string]uint32 {
	if len(names) == 0 {
		return nil
	}
	found := make(map[string]uint32, len(names))
	for _, name := range names {
		account, err := user.Lookup(name)
		if err != nil {
			continue
		}
		number, err := strconv.ParseUint(account.Uid, 10, 32)
		if err != nil {
			continue
		}
		found[name] = uint32(number)
	}
	return found
}
