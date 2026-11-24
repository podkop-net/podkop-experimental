package supervisor

import (
	"context"
	"errors"
	"maps"
	"os/user"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/btstats"
	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
)

// bitTorrentRuntime is BitTorrent while the backend runs: the detector of the firewall table this
// process put in the kernel last, the reads of the traffic it marks and what they came to, and the
// users of the router's torrent clients. It is a part of the supervisor, which has one and tells it
// of the tables (planned, updated, released) and of the clock (tick), and hands on to it what is
// asked from outside (the methods of Supervisor at the end of this file).
//
// The goroutine of Run does all of it but the reads of the traffic, which have a goroutine of their
// own (poll: a read is a dump of conntrack), and the reports, which are the callers'. What passes
// between them is setup and noRule (atomic), wake, and stats (a lock of its own): there is no
// other lock.
type bitTorrentRuntime struct {
	options *Options
	host    bitTorrentHost

	// applied is the detector of the table this process put in the kernel last, nil before the
	// first and after the table was removed: what a change of its mode is told against (updated).
	// Not the plan of current: that is nil after an update that failed, which left the table
	// before it in the kernel.
	applied *firewall.BitTorrent
	// rule is the name the page shows of the rule of the mode section of the table made last
	// (planned)
	rule string
	// usersTried: the users of the router's torrent clients an apply was made for by the clock
	// (tick), so that one that fails is not made again for the same users
	usersTried map[string]uint32

	// setup is what the reads of the traffic take as the mode (nil while no table with the detector
	// is there), stats what they came to
	setup atomic.Pointer[btstats.Setup]
	stats btstats.Stats
	// noRule is the rule the settings chose for BitTorrent when the table made last has no detector
	// because of it (the rule is not there, is off or goes nowhere: the plan's bitTorrent); nil
	// otherwise. The report tells it, where the card of the page was just gone.
	noRule atomic.Pointer[string]
	// wake tells the reads of the traffic that a table was applied (updated): a detector that came
	// is read at once (poll)
	wake chan struct{}
}

// bitTorrentHost is what BitTorrent uses of the supervisor.
type bitTorrentHost interface {
	log(level string, message ...any)
	// Apply is for the goroutine of Run
	Apply() Result
}

func newBitTorrentRuntime(options *Options, host bitTorrentHost) *bitTorrentRuntime {
	return &bitTorrentRuntime{options: options, host: host, wake: make(chan struct{}, 1)}
}

// planned takes the rule of the mode section of a state whose table is made (firewallPlan): its
// name for the page, and that the rule chosen is not there when the plan has no detector for it.
func (b *bitTorrentRuntime) planned(current *running) {
	b.rule = ""
	var noRule *string
	if current.settings != nil && current.settings.Settings.BitTorrent == model.BitTorrentSection {
		name := current.settings.Settings.BitTorrentSection
		label := name
		if section := current.settings.Section(name); section != nil && section.Label != "" {
			label = section.Label
		}
		if current.result.Dataplane.BitTorrent.Mode == model.BitTorrentSection {
			b.rule = label
		} else {
			noRule = &label
		}
	}
	b.noRule.Store(noRule)
}

// updated takes the detector of a table the kernel has now (updateFirewall). It ends the
// connections of BitTorrent past podkop that a change of the mode takes another way
// (firewall.ForgetFor), told against the detector of the table this process put there last.
func (b *bitTorrentRuntime) updated(applied firewall.BitTorrent) {
	if b.applied != nil {
		if which := firewall.ForgetFor(*b.applied, applied); which != firewall.ForgetNone {
			b.forget(*b.applied, applied, which)
		}
	}
	b.applied = &applied
	if applied.Mode == "" {
		b.setup.Store(nil)
	} else {
		b.setup.Store(&btstats.Setup{Mode: applied.Mode, LAN: applied.LAN, Rule: b.rule})
	}
	// the statistics read now, not at their next tick: the first read is the baseline of the
	// connections open already, and those that begin before it are taken for such
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// released takes that the router was given back (release), and whether the firewall table was
// removed with it. Nothing runs: the notice of a rule that is off is of a configuration that is
// gone.
func (b *bitTorrentRuntime) released(tableRemoved bool) {
	if tableRemoved {
		b.applied = nil
		b.setup.Store(nil)
	}
	b.noRule.Store(nil)
}

// forget ends the connections of BitTorrent past podkop that the mode next takes
// otherwise than the mode previous did: those the router offloads pass no rule of the firewall,
// and the mode next takes them only when they go on with new entries.
func (b *bitTorrentRuntime) forget(previous, next firewall.BitTorrent, which firewall.Forget) {
	from, to := bitTorrentModeName(previous), bitTorrentModeName(next)
	err := b.options.System.ForgetBitTorrentFlows(which)
	if err != nil {
		b.host.log("warn", "BitTorrent went from the mode ", from, " to ", to, ", but its connections past podkop go on that way until they end: ", err)
		return
	}
	b.host.log("info", "BitTorrent went from the mode ", from, " to ", to, ": its connections past podkop were ended, and the mode ", to, " takes them when they go on")
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

// tick looks, by the clock of Run, whether a user of the router's torrent clients came or went since
// the state that runs was built: its number is in the firewall's rules (an apply again: the same
// configuration takes the table anew). Once for each state of them: an apply that fails is not
// tried again every tick.
func (b *bitTorrentRuntime) tick(current *running) {
	if !routerUsersChanged(current) {
		return
	}
	now := userIDs(current.settings.Settings.BitTorrentRouterUsers)
	if maps.Equal(now, b.usersTried) {
		return
	}
	b.usersTried = now
	b.host.log("info", "the users of the router's torrent clients changed: the settings are applied again")
	b.host.Apply()
}

// routerUsersChanged tells whether the users of the router's torrent clients the settings name are
// not those the configuration running was built with: one gained or lost since (the package of the
// client installed after the setting was made creates its user and fires no event). Only with
// BitTorrent on: off, the plan uses none.
func routerUsersChanged(current *running) bool {
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

// poll reads what the BitTorrent traffic of the LAN came to every btstats.PollEvery
// while a table with the detector is there (setup), until ctx ends; it starts again from
// nothing when the detector goes or its mode changes (the ways of the rows are of a mode). Its own
// goroutine: a read of the entries is a dump of conntrack.
func (b *bitTorrentRuntime) poll(ctx context.Context) {
	ticker := time.NewTicker(btstats.PollEvery)
	defer ticker.Stop()
	var last *btstats.Setup
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			last = b.read(last, now)
		case <-b.wake:
			// a table was applied: only a detector that came or changed is read ahead of the tick
			if setup := b.setup.Load(); setup != nil && (last == nil || setup.Mode != last.Mode || setup.LAN != last.LAN) {
				last = b.read(last, time.Now())
			}
		}
	}
}

// read is a read of poll at now: last is the setup of the read before, and the
// setup read now is given back.
func (b *bitTorrentRuntime) read(last *btstats.Setup, now time.Time) *btstats.Setup {
	setup := b.setup.Load()
	if last != nil && (setup == nil || setup.Mode != last.Mode || setup.LAN != last.LAN) {
		b.stats.Reset()
	}
	if setup == nil {
		return nil
	}
	flows, err := b.options.System.BitTorrentFlows()
	drops, dropsErr := b.options.System.BitTorrentDrops()
	b.stats.Observe(*setup, flows, drops, errors.Join(err, dropsErr), now)
	return setup
}

// report is what the BitTorrent traffic of the LAN came to (btstats.Report), with the counters of
// the module of the sing-box that runs. It may be called from any goroutine.
func (b *bitTorrentRuntime) report() btstats.Report {
	setup := b.setup.Load()
	if setup == nil {
		report := btstats.Report{Rows: []btstats.Row{}, Blocked: []btstats.Blocked{}, Module: engine.BitTorrentCounters()}
		if rule := b.noRule.Load(); rule != nil {
			report.Problem, report.Rule = btstats.ProblemRule, *rule
		}
		return report
	}
	report := b.stats.Report(time.Now())
	// the mode the firewall has now: the first read comes btstats.PollEvery after it
	report.Mode, report.LAN, report.Rule = setup.Mode, setup.LAN, setup.Rule
	report.Module = b.stats.ModuleSince(engine.BitTorrentCounters())
	return report
}

// reset starts the statistics of BitTorrent again from now, the mode kept (the
// page's button, `podkop bittorrent_reset`), and answers them: a test needs no restart of podkop,
// which also forgot the devices the detector knew.
func (b *bitTorrentRuntime) reset() btstats.Report {
	b.stats.ResetCounts(engine.BitTorrentCounters(), time.Now())
	return b.report()
}

// BitTorrent as it is asked from outside the goroutine of Run (api.Backend).

// BitTorrent is what the BitTorrent module of the running sing-box has counted (api.Backend).
func (s *Supervisor) BitTorrent() map[string]int64 {
	return engine.BitTorrentCounters()
}

// BitTorrentStats is what the BitTorrent traffic of the LAN came to (btstats.Report), with the
// counters of the module of the sing-box that runs. It may be called from any goroutine.
func (s *Supervisor) BitTorrentStats() btstats.Report {
	return s.bitTorrent.report()
}

// ResetBitTorrentStats starts the statistics of BitTorrent again from now and answers them. It may
// be called from any goroutine.
func (s *Supervisor) ResetBitTorrentStats() btstats.Report {
	return s.bitTorrent.reset()
}
