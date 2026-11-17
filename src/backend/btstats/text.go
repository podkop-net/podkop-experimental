package btstats

import (
	"fmt"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
)

// KindName is how the page and the global check name a kind.
func KindName(kind Kind) string {
	switch kind {
	case KindDiscovery:
		return "DHT and UDP trackers"
	case KindUTP:
		return "uTP"
	case KindTCP:
		return "TCP to peers"
	case KindLate:
		return "TCP told by its handshake in podkop"
	case KindChecked:
		return "TCP to uncommon ports, checked"
	case KindIncoming:
		return "Incoming through a port forward"
	}
	return string(kind)
}

// WayName is how the page and the global check name a way; rule is the name of the rule of the
// mode section.
func WayName(way Way, rule string) string {
	switch way {
	case WayRelay:
		return "through sing-box, straight out"
	case WayPast:
		return "past podkop"
	case WayUntouched:
		return "not through podkop"
	case WayRule:
		return "through the rule " + rule
	case WayChecked:
		return "through sing-box, being checked"
	case WayBlocked:
		return "blocked"
	}
	return string(way)
}

// ModeName is the mode of a report as the settings name it.
func ModeName(report Report) string {
	scope := "only what podkop takes"
	if report.LAN {
		scope = "the whole LAN"
	}
	switch report.Mode {
	case model.BitTorrentBypass:
		return "past podkop"
	case model.BitTorrentBlock:
		return "block, " + scope
	case model.BitTorrentSection:
		return "through the servers of the rule " + report.Rule + ", " + scope
	}
	return "as the other traffic"
}

// Bytes is a count of bytes as the page shows it (decimal units, three digits: prettyBytes of the
// page).
func Bytes(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
	exponent, divisor := 0, uint64(1)
	for exponent < len(units) && n/divisor >= 1000 {
		exponent++
		divisor *= 1000
	}
	value := float64(n) / float64(divisor)
	digits := 0
	switch {
	case value < 10:
		digits = 2
	case value < 100:
		digits = 1
	}
	text := fmt.Sprintf("%.*f", digits, value)
	if strings.Contains(text, ".") {
		text = strings.TrimRight(strings.TrimRight(text, "0"), ".")
	}
	return text + " " + units[exponent-1]
}

// Duration is a span of seconds as the global check says it.
func Duration(seconds int64) string {
	switch {
	case seconds < 60:
		return fmt.Sprintf("%d s", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%d min", seconds/60)
	}
	return fmt.Sprintf("%d h %02d min", seconds/3600, seconds/60%60)
}

// Lines are the global check's lines of a report.
func Lines(report Report) []string {
	if report.Mode == "" || report.Mode == model.BitTorrentOff {
		return []string{"BitTorrent: as the other traffic (the detector is off)"}
	}
	lines := []string{fmt.Sprintf("BitTorrent: %s; since %s, read %s ago", ModeName(report), Duration(report.Since), Duration(report.Read))}
	if report.Error != "" {
		lines = append(lines, "  ❌ the last read of the connections failed: "+report.Error)
	}
	if !report.Counted && len(report.Rows) > 0 {
		lines = append(lines, "  ❌ the router does not count the bytes of connections (net.netfilter.nf_conntrack_acct is 0): only the connections are told")
	}
	if len(report.Rows) == 0 {
		lines = append(lines, "  no BitTorrent traffic seen yet")
	}
	for _, row := range report.Rows {
		lines = append(lines, fmt.Sprintf("  %s, %s: %d open, %d in all; received %s (%d packets), sent %s (%d packets)",
			KindName(row.Kind), WayName(row.Way, report.Rule), row.Open, row.Connections,
			Bytes(row.Received.Bytes), row.Received.Packets, Bytes(row.Sent.Bytes), row.Sent.Packets))
	}
	for _, blocked := range report.Blocked {
		lines = append(lines, fmt.Sprintf("  blocked, %s: %d packets (%s)", KindName(blocked.Kind), blocked.Dropped.Packets, Bytes(blocked.Dropped.Bytes)))
	}
	if report.UTPToTCP.Packets > 0 {
		lines = append(lines, fmt.Sprintf("  uTP SYNs on a flow of discovery dropped, so that the client goes over TCP: %d", report.UTPToTCP.Packets))
	}
	if module := report.Module; module != nil {
		lines = append(lines, fmt.Sprintf("  the module, since sing-box started: %d peers learned from %d replies and %d announces (%d known already, %d not learnable, %d over the cap); "+
			"%d connections checked: %d confirmed (%d closed, %d left open), %d refuted, %d plaintext handshakes",
			module["learned"], module["replies"], module["announces"], module["known"], module["not_learnable"], module["capped"],
			module["watched"], module["confirmed"], module["rejected"]+module["reset"], module["kept_open"],
			module["refuted"], module["plaintext"]))
	}
	return lines
}
