package ctl

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/btstats"
	"github.com/podkop-net/podkop-experimental/src/backend/diag"
)

// `podkop bittorrent_record [minutes] [--reset]`: a report of BitTorrent for a test, written by the
// router itself, so that the reports of testers are alike and carry nothing private (0.8.18, after
// six field reports of 0.8.17 came as screenshots and whole logs). A sample every recordEvery for
// the minutes: CPU of the router and of podkop, podkop's memory, the connections of the router, and
// the BitTorrent statistics by way; then the global check's lines of BitTorrent. No address, name
// or link: the statistics have none, and the rest is counts.

// recordEvery is the time between samples, recordMinute a minute of the command's argument (the
// tests shorten both).
var recordEvery, recordMinute = 10 * time.Second, time.Minute

// recordDir is where the report goes (RAM).
var recordDir = "/tmp"

// bitTorrentRecord runs the command; arguments are those after its name.
func bitTorrentRecord(env Environment, client api.Client, arguments []string, output io.Writer, errorOutput io.Writer) int {
	minutes, reset := 10, false
	for _, argument := range arguments {
		switch {
		case argument == "--reset":
			reset = true
		default:
			n, err := strconv.Atoi(argument)
			if err != nil || n < 1 || n > 240 {
				fmt.Fprintln(errorOutput, "bittorrent_record [minutes, 1-240] [--reset]")
				return 2
			}
			minutes = n
		}
	}
	report, err := client.BitTorrentStats()
	if err != nil {
		fmt.Fprintln(errorOutput, "the backend does not answer:", err)
		return 1
	}
	if report.Mode == "" {
		fmt.Fprintln(errorOutput, "BitTorrent is \"as the other traffic\": nothing to record (Settings → BitTorrent)")
		return 1
	}
	if reset {
		if report, err = client.ResetBitTorrentStats(); err != nil {
			fmt.Fprintln(errorOutput, "the statistics were not reset:", err)
			return 1
		}
	}
	start := time.Now()
	path := filepath.Join(recordDir, "podkop-bittorrent-"+start.UTC().Format("20060102-150405")+".txt")
	file, err := os.Create(path)
	if err != nil {
		fmt.Fprintln(errorOutput, err)
		return 1
	}
	defer file.Close()
	w := bufio.NewWriter(file)
	release, model := diag.Device()
	fmt.Fprintf(w, "podkop BitTorrent record\npodkop %s, OpenWrt %s, %s, %s, %d cores, memory %s\n",
		env.Version, release, model, runtime.GOARCH, runtime.NumCPU(), memoryTotal())
	fmt.Fprintf(w, "started %s UTC, %d min, a sample every %s\n", start.UTC().Format("2006-01-02 15:04:05"), minutes, recordEvery)
	fmt.Fprintf(w, "BitTorrent: %s; flow offloading %s, hardware %s; global IPv6 addresses %d\n",
		btstats.ModeName(report), uciGet("firewall.@defaults[0].flow_offloading"), uciGet("firewall.@defaults[0].flow_offloading_hw"), globalIPv6())
	fmt.Fprintln(w, "\n# t: CPU of the router (podkop's part), load, podkop's memory, connections of the router; BitTorrent: open connections, received / sent by way")
	_ = w.Flush()
	fmt.Fprintf(output, "recording %d min into %s (Ctrl+C stops it; what is written stays)\n", minutes, path)

	cpu, podkop := readCPU(), podkopCPU()
	end := start.Add(time.Duration(minutes) * recordMinute)
	for now := range time.Tick(recordEvery) {
		cpuNow, podkopNow := readCPU(), podkopCPU()
		report, err = client.BitTorrentStats()
		line := fmt.Sprintf("t=%s cpu %s (podkop %s), load %s, podkop %s, conntrack %s",
			btstats.Duration(int64(now.Sub(start)/time.Second)), cpuNow.share(cpu), cpuNow.part(cpu, podkopNow-podkop),
			loadAverage(), podkopMemory(), conntrackCount())
		cpu, podkop = cpuNow, podkopNow
		if err != nil {
			line += "; BitTorrent: no answer: " + err.Error()
		} else {
			line += "; BitTorrent: " + byWay(report)
		}
		fmt.Fprintln(w, line)
		_ = w.Flush()
		if !now.Before(end) {
			break
		}
	}
	fmt.Fprintln(w, "\n# at the end (the global check's lines)")
	if report, err = client.BitTorrentStats(); err == nil {
		for _, line := range btstats.Lines(report) {
			fmt.Fprintln(w, line)
		}
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintln(errorOutput, err)
		return 1
	}
	fmt.Fprintln(output, "written:", path)
	return 0
}

// byWay is a sample's BitTorrent: the connections open, and what was received and sent by way,
// summed over the kinds.
func byWay(report btstats.Report) string {
	type total struct{ received, sent uint64 }
	ways := map[btstats.Way]*total{}
	var order []btstats.Way
	open := 0
	for _, row := range report.Rows {
		open += row.Open
		if ways[row.Way] == nil {
			ways[row.Way] = &total{}
			order = append(order, row.Way)
		}
		ways[row.Way].received += row.Received.Bytes
		ways[row.Way].sent += row.Sent.Bytes
	}
	parts := []string{fmt.Sprintf("open %d", open)}
	for _, way := range order {
		parts = append(parts, fmt.Sprintf("%s %s / %s", btstats.WayName(way, "of the mode"), btstats.Bytes(ways[way].received), btstats.Bytes(ways[way].sent)))
	}
	module := report.Module
	if module != nil {
		parts = append(parts, fmt.Sprintf("module: %d checked, %d confirmed, %d learned", module["watched"], module["confirmed"], module["learned"]))
	}
	return strings.Join(parts, "; ")
}

type cpuTimes struct{ busy, total uint64 }

// readCPU is the router's CPU time from /proc/stat, in ticks.
func readCPU() cpuTimes {
	content, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuTimes{}
	}
	line, _, _ := bytes.Cut(content, []byte("\n"))
	fields := strings.Fields(string(line))
	var times cpuTimes
	for i, field := range fields[1:] {
		value, _ := strconv.ParseUint(field, 10, 64)
		times.total += value
		// idle and iowait
		if i != 3 && i != 4 {
			times.busy += value
		}
	}
	return times
}

func (c cpuTimes) share(before cpuTimes) string {
	if c.total <= before.total {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", 100*float64(c.busy-before.busy)/float64(c.total-before.total))
}

// part is podkop's ticks of the router's, as a share of all of its CPU.
func (c cpuTimes) part(before cpuTimes, ticks uint64) string {
	if c.total <= before.total {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", 100*float64(ticks)/float64(c.total-before.total))
}

// podkopPID is the backend's process (podkop daemon), 0 when not found.
func podkopPID() int {
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(string(cmdline), "\x00")
		if len(args) > 1 && filepath.Base(args[0]) == "podkop" && slices.Contains(args[1:], "daemon") {
			return pid
		}
	}
	return 0
}

// podkopCPU is the backend's CPU time (user and system), in ticks.
func podkopCPU() uint64 {
	pid := podkopPID()
	if pid == 0 {
		return 0
	}
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0
	}
	// after the name in parentheses: state is field 3, utime 14, stime 15
	_, rest, ok := strings.Cut(string(content), ") ")
	if !ok {
		return 0
	}
	fields := strings.Fields(rest)
	if len(fields) < 13 {
		return 0
	}
	user, _ := strconv.ParseUint(fields[11], 10, 64)
	system, _ := strconv.ParseUint(fields[12], 10, 64)
	return user + system
}

func podkopMemory() string {
	pid := podkopPID()
	if pid == 0 {
		return "-"
	}
	return statusField(filepath.Join("/proc", strconv.Itoa(pid), "status"), "VmRSS:")
}

func memoryTotal() string {
	return statusField("/proc/meminfo", "MemTotal:")
}

// statusField is the value of a "Name:   1234 kB" line, in MB.
func statusField(path string, name string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return "-"
	}
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, name) {
			fields := strings.Fields(line[len(name):])
			if len(fields) > 0 {
				kb, _ := strconv.ParseFloat(fields[0], 64)
				return fmt.Sprintf("%.1f MB", kb/1024)
			}
		}
	}
	return "-"
}

func loadAverage() string {
	content, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "-"
	}
	fields := strings.Fields(string(content))
	if len(fields) == 0 {
		return "-"
	}
	return fields[0]
}

func conntrackCount() string {
	count, err1 := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count")
	limit, err2 := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max")
	if err1 != nil || err2 != nil {
		return "-"
	}
	return strings.TrimSpace(string(count)) + "/" + strings.TrimSpace(string(limit))
}

// globalIPv6 counts the router's global IPv6 addresses (scope 00 of /proc/net/if_inet6), not the
// addresses themselves.
func globalIPv6() int {
	content, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 6 && fields[3] == "00" && fields[5] != "lo" {
			n++
		}
	}
	return n
}

func uciGet(option string) string {
	out, err := exec.Command("uci", "-q", "get", option).Output()
	if err != nil {
		return "0"
	}
	return strings.TrimSpace(string(out))
}
