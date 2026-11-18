package btstats

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/stretchr/testify/require"
)

const (
	bt        = dataplane.BitTorrentCt
	discovery = dataplane.BitTorrentDiscoveryCt | dataplane.BitTorrentCt
	taken     = dataplane.InterceptedCt
	inspect   = dataplane.BitTorrentInspectCt
	late      = dataplane.BitTorrentLateCt
)

// The kind of each mark, and the way each mode sends it (the firewall's bt_act, bt_free, proxy and
// the plan's route rules).
func TestClassify(t *testing.T) {
	type flow struct {
		udp      bool
		mark     uint32
		incoming bool
	}
	cases := []struct {
		name  string
		setup Setup
		flow  flow
		kind  Kind
		way   Way
	}{
		{"bypass, discovery taken", Setup{Mode: "bypass"}, flow{true, discovery | taken, false}, KindDiscovery, WayRelay},
		{"bypass, discovery not taken", Setup{Mode: "bypass"}, flow{true, discovery, false}, KindDiscovery, WayRelay},
		{"bypass, uTP taken", Setup{Mode: "bypass"}, flow{true, bt | taken, false}, KindUTP, WayPast},
		{"bypass, uTP not taken", Setup{Mode: "bypass"}, flow{true, bt, false}, KindUTP, WayUntouched},
		{"bypass, TCP taken", Setup{Mode: "bypass"}, flow{false, bt | taken, false}, KindTCP, WayPast},
		{"bypass, checked", Setup{Mode: "bypass"}, flow{false, inspect | taken, false}, KindChecked, WayChecked},
		{"bypass, uncommon port not taken", Setup{Mode: "bypass"}, flow{false, inspect, false}, KindChecked, WayUntouched},
		{"block, uncommon port not taken", Setup{Mode: "block"}, flow{false, inspect, false}, KindChecked, WayUntouched},
		{"block LAN, uncommon port not taken", Setup{Mode: "block", LAN: true}, flow{false, inspect, false}, KindChecked, WayChecked},
		{"bypass, late", Setup{Mode: "bypass"}, flow{false, late | taken, false}, KindLate, WayRelay},
		{"bypass, incoming", Setup{Mode: "bypass"}, flow{true, discovery, true}, KindIncoming, WayUntouched},
		{"section, uTP taken", Setup{Mode: "section", Rule: "bt"}, flow{true, bt | taken, false}, KindUTP, WayRule},
		{"section, discovery taken", Setup{Mode: "section"}, flow{true, discovery | taken, false}, KindDiscovery, WayRule},
		{"section, discovery not taken", Setup{Mode: "section"}, flow{true, discovery, false}, KindDiscovery, WayRelay},
		{"section, TCP not taken", Setup{Mode: "section"}, flow{false, bt, false}, KindTCP, WayUntouched},
		{"section LAN, TCP not taken", Setup{Mode: "section", LAN: true}, flow{false, bt, false}, KindTCP, WayRule},
		{"section LAN, checked not taken", Setup{Mode: "section", LAN: true}, flow{false, inspect, false}, KindChecked, WayChecked},
		{"section, late", Setup{Mode: "section"}, flow{false, late | taken, false}, KindLate, WayRule},
		{"block, uTP taken", Setup{Mode: "block"}, flow{true, bt | taken, false}, KindUTP, WayBlocked},
		{"block, discovery not taken", Setup{Mode: "block"}, flow{true, discovery, false}, KindDiscovery, WayUntouched},
		{"block LAN, uTP not taken", Setup{Mode: "block", LAN: true}, flow{true, bt, false}, KindUTP, WayBlocked},
		{"block, incoming", Setup{Mode: "block"}, flow{false, bt, true}, KindIncoming, WayBlocked},
	}
	for _, c := range cases {
		kind, way := Classify(c.setup, Flow{UDP: c.flow.udp, Mark: c.flow.mark, Incoming: c.flow.incoming})
		require.Equal(t, c.kind, kind, c.name)
		require.Equal(t, c.way, way, c.name)
	}
}

func count(packets, bytes uint64) Count { return Count{Packets: packets, Bytes: bytes} }

// Each read adds what an entry counted since the one before; an entry gone keeps what it had; an
// id taken again by another entry (counts that went down) starts again; a connection from outside
// received its original way.
func TestObserve(t *testing.T) {
	var s Stats
	at := time.Unix(1000, 0)
	setup := Setup{Mode: "bypass"}
	utp := Flow{ID: 1, Key: "a", UDP: true, Mark: bt | taken, Counted: true, Original: count(10, 1000), Reply: count(20, 30000)}
	dht := Flow{ID: 2, Key: "b", UDP: true, Mark: discovery | taken, Counted: true, Original: count(1, 100), Reply: count(1, 500)}
	s.Observe(setup, []Flow{utp, dht}, Drops{}, nil, at)
	utp.Original, utp.Reply = count(15, 1500), count(40, 60000)
	s.Observe(setup, []Flow{utp}, Drops{}, nil, at.Add(PollEvery))
	report := s.Report(at.Add(PollEvery + time.Second))
	require.Equal(t, int64(6), report.Since)
	require.Equal(t, int64(1), report.Read)
	require.True(t, report.Counted)
	require.Equal(t, []Row{
		{Kind: KindDiscovery, Way: WayRelay, Open: 0, Connections: 1, Received: count(1, 500), Sent: count(1, 100)},
		{Kind: KindUTP, Way: WayPast, Open: 1, Connections: 1, Received: count(40, 60000), Sent: count(15, 1500)},
	}, report.Rows)
	// the id of the gone entry taken by another, with smaller counts
	again := Flow{ID: 1, Key: "a", UDP: true, Mark: bt | taken, Counted: true, Original: count(2, 200), Reply: count(3, 300)}
	incoming := Flow{ID: 3, Key: "c", Mark: bt, Incoming: true, Counted: true, Original: count(5, 5000), Reply: count(4, 400)}
	s.Observe(setup, []Flow{again, incoming}, Drops{}, nil, at.Add(2*PollEvery))
	report = s.Report(at.Add(2 * PollEvery))
	require.Equal(t, Row{Kind: KindUTP, Way: WayPast, Open: 1, Connections: 2, Received: count(43, 60300), Sent: count(17, 1700)}, report.Rows[1])
	require.Equal(t, Row{Kind: KindIncoming, Way: WayUntouched, Open: 1, Connections: 1, Received: count(5, 5000), Sent: count(4, 400)}, report.Rows[2])
}

// The rules' counters of a table made anew start at 0: what the one before dropped stays.
func TestDropsOverATableAnew(t *testing.T) {
	var s Stats
	at := time.Unix(1000, 0)
	setup := Setup{Mode: "block"}
	s.Observe(setup, nil, Drops{UTP: count(100, 9000), TCP: count(10, 600)}, nil, at)
	s.Observe(setup, nil, Drops{UTP: count(150, 13000), TCP: count(10, 600)}, nil, at.Add(PollEvery))
	s.Observe(setup, nil, Drops{UTP: count(5, 400), Incoming: count(2, 120), UTPToTCP: count(1, 60)}, nil, at.Add(2*PollEvery))
	report := s.Report(at.Add(2 * PollEvery))
	require.Equal(t, []Blocked{{KindUTP, count(155, 13400)}, {KindTCP, count(10, 600)}, {KindIncoming, count(2, 120)}}, report.Blocked)
	require.Equal(t, count(1, 60), report.UTPToTCP)
}

// A read that failed is left out whole: the connections it did not name are not ended, and the
// next read does not count them, their bytes and the drops once more.
func TestFailedReadIsLeftOut(t *testing.T) {
	var s Stats
	at := time.Unix(1000, 0)
	setup := Setup{Mode: "block"}
	flow := func(bytes uint64) []Flow {
		return []Flow{{ID: 1, Key: "a", UDP: true, Mark: bt, Counted: true, Original: count(10, bytes), Reply: count(10, bytes)}}
	}
	s.Observe(setup, flow(1000), Drops{UTP: count(5, 400)}, nil, at)
	s.Observe(setup, nil, Drops{}, errors.New("no netlink"), at.Add(PollEvery))
	require.Equal(t, "no netlink", s.Report(at.Add(PollEvery)).Error)
	s.Observe(setup, flow(1500), Drops{UTP: count(6, 480)}, nil, at.Add(2*PollEvery))
	report := s.Report(at.Add(2 * PollEvery))
	require.Empty(t, report.Error)
	var connections, sent, received uint64
	for _, row := range report.Rows {
		connections += row.Connections
		sent += row.Sent.Bytes
		received += row.Received.Bytes
	}
	require.Equal(t, uint64(1), connections)
	require.Equal(t, uint64(1500), sent)
	require.Equal(t, uint64(1500), received)
	require.Equal(t, []Blocked{{KindUTP, count(6, 480)}}, report.Blocked)
}

// A read that failed is told; the kernel that does not count is told; Reset forgets.
func TestReportStates(t *testing.T) {
	var s Stats
	at := time.Unix(1000, 0)
	s.Observe(Setup{Mode: "bypass"}, []Flow{{ID: 1, Key: "a", UDP: true, Mark: bt}}, Drops{}, nil, at)
	s.Observe(Setup{Mode: "bypass"}, nil, Drops{}, errors.New("no netlink"), at)
	report := s.Report(at)
	require.Equal(t, "no netlink", report.Error)
	require.False(t, report.Counted)
	lines := strings.Join(Lines(report), "\n")
	require.Contains(t, lines, "nf_conntrack_acct is 0")
	require.Contains(t, lines, "the last read of the connections failed: no netlink")
	s.Reset()
	report = s.Report(at)
	require.Empty(t, report.Mode)
	require.Empty(t, report.Rows)
	require.Equal(t, []string{"BitTorrent: as the other traffic (the detector is off)"}, Lines(report))
}

func TestLines(t *testing.T) {
	report := Report{Mode: "section", LAN: true, Rule: "Torrents", Since: 7380, Read: 3, Counted: true,
		Rows:     []Row{{Kind: KindUTP, Way: WayRule, Open: 4, Connections: 9, Received: count(1000, 1234567), Sent: count(500, 45600)}},
		Blocked:  []Blocked{},
		UTPToTCP: count(3, 180),
		Module:   map[string]int64{"learned": 120, "replies": 7, "announces": 1, "watched": 6, "confirmed": 2, "reset": 2}}
	require.Equal(t, []string{
		"BitTorrent: through the servers of the rule Torrents, the whole LAN; since 2 h 03 min, read 3 s ago",
		"  uTP, through the rule Torrents: 4 open, 9 in all; received 1.23 MB (1000 packets), sent 45.6 KB (500 packets)",
		"  uTP SYNs on a flow of discovery dropped, so that the client goes over TCP: 3",
		"  the module, since sing-box started: 120 peers learned from 7 replies and 1 announces (0 known already, 0 not learnable, 0 over the cap); " +
			"6 connections checked: 2 confirmed (0 of them by a late third step; 2 closed, 0 left open), 0 not BitTorrent " +
			"(0 not shaped like MSE, 0 the far side first, 0 refuted: 0 the device again, 0 the answer too long, 0 too short, 0 the third step late or short), " +
			"0 undecided (0 no data, 0 no answer, 0 no third step), 0 plaintext handshakes",
	}, Lines(report))
}

func TestBytes(t *testing.T) {
	for n, text := range map[uint64]string{0: "0 B", 999: "999 B", 1000: "1 KB", 1234: "1.23 KB", 12345: "12.3 KB", 120000: "120 KB",
		123456789: "123 MB", 2500000000: "2.5 GB"} {
		require.Equal(t, text, Bytes(n), n)
	}
}

// A reset starts the rows, the drops and the module's counters again from now; the connections
// open go on counting from what they had.
func TestResetCounts(t *testing.T) {
	var s Stats
	setup := Setup{Mode: "block"}
	start := time.Unix(1000, 0)
	open := Flow{ID: 1, Key: "a", Mark: bt | taken, Counted: true, Original: Count{10, 1000}, Reply: Count{20, 2000}}
	s.Observe(setup, []Flow{open}, Drops{TCP: Count{5, 300}}, nil, start)
	s.ResetCounts(map[string]int64{"watched": 7, "confirmed": 2}, start.Add(10*time.Second))
	open.Original, open.Reply = Count{11, 1100}, Count{25, 2500}
	s.Observe(setup, []Flow{open}, Drops{TCP: Count{6, 360}}, nil, start.Add(15*time.Second))
	report := s.Report(start.Add(20 * time.Second))
	require.Len(t, report.Rows, 1)
	require.Equal(t, uint64(0), report.Rows[0].Connections, "an open connection is not counted again")
	require.Equal(t, Count{1, 100}, report.Rows[0].Sent)
	require.Equal(t, Count{5, 500}, report.Rows[0].Received)
	require.Equal(t, []Blocked{{KindTCP, Count{1, 60}}}, report.Blocked)
	require.Equal(t, int64(10), report.Since)
	require.Equal(t, int64(10), report.ResetAt)
	require.Equal(t, map[string]int64{"watched": 3, "confirmed": 0}, s.ModuleSince(map[string]int64{"watched": 10, "confirmed": 2}))
	// another sing-box (its counters went down): taken whole, the base gone
	require.Equal(t, map[string]int64{"watched": 1, "confirmed": 0}, s.ModuleSince(map[string]int64{"watched": 1, "confirmed": 0}))
	require.Equal(t, map[string]int64{"watched": 4, "confirmed": 1}, s.ModuleSince(map[string]int64{"watched": 4, "confirmed": 1}))
}

// The DHT and the UDP trackers sent and got nothing back: the line of the global check says so;
// with an answer, too few flows or bytes not counted, it does not.
func TestQuietDiscovery(t *testing.T) {
	row := func(connections uint64, received uint64) Report {
		return Report{Mode: "bypass", Counted: true, Rows: []Row{{Kind: KindDiscovery, Way: WayRelay, Connections: connections, Received: Count{Bytes: received}, Sent: Count{220, 9920}}}}
	}
	require.Contains(t, QuietDiscovery(row(220, 0)), "no answer in 220 flows")
	require.Empty(t, QuietDiscovery(row(220, 112)))
	require.Empty(t, QuietDiscovery(row(20, 0)))
	quiet := row(220, 0)
	quiet.Counted = false
	require.Empty(t, QuietDiscovery(quiet))
	require.Contains(t, strings.Join(Lines(row(220, 0)), "\n"), "⚠️ the DHT and the UDP trackers got no answer")
}

// The early check has a line of its own once it watched something.
func TestLinesEarly(t *testing.T) {
	report := Report{Mode: "bypass", Counted: true, Module: map[string]int64{"early_watched": 78, "early_confirmed": 20, "early_acted": 20, "early_self": 1}}
	require.Contains(t, strings.Join(Lines(report), "\n"),
		"the early check: 78 connections of the transparent proxy watched, 20 confirmed before their device was known to run a client, 20 of them taken as BitTorrent since (1 devices told by their own peers), 0 waited too long")
}
