package supervisor

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/podkop-net/podkop-experimental/src/backend/clock"
	"github.com/podkop-net/podkop-experimental/src/backend/dnsmasq"
	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
	"github.com/podkop-net/podkop-experimental/src/backend/netcfg"
	"github.com/podkop-net/podkop-experimental/src/backend/sockets"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	E "github.com/sagernet/sing/common/exceptions"
)

// Router is the System of an OpenWrt router.
type Router struct{}

func (Router) LANAddress() string {
	address, err := netcfg.LANAddress()
	if err != nil {
		return ""
	}
	return address.String()
}

func (Router) Devices(names []string) map[string]string { return netcfg.Devices(names) }

func (Router) NTPServerNames() []string { return clock.ServerNames() }

func (Router) Listening() []sockets.Listener { return sockets.Bound("/") }

func (Router) ApplyRouting() error { return netcfg.Apply() }

func (Router) AllowBridgedTraffic() []string { return netcfg.AllowBridgedTraffic() }

func (Router) RemoveRouting() error { return netcfg.Remove() }

func (Router) RoutingPresent() (bool, error) { return netcfg.Present() }

func (Router) RouteUplinks() ([]string, error) { return netcfg.RouteUplinks() }

func (Router) FirewallPresent() (bool, error) { return firewall.Exists() }

func (Router) SetClashSecret(key string) error {
	// a line of uci batch a command: the key is quoted, and a key that would end the
	// line is refused
	if strings.ContainsAny(key, "\r\n") {
		return E.New("the key of the Clash API has a line break")
	}
	return dnsmasq.Router{}.Batch("set podkop.settings.yacd_secret_key=" + dnsmasq.Quote(key) + "\ncommit podkop\n")
}

func (Router) UpdateFirewall(previous *firewall.Plan, next *firewall.Plan) error {
	return firewall.Update(previous, next)
}

func (Router) RemoveFirewall() error { return firewall.Remove() }

func (Router) TakeOverDNS() (bool, error) { return dnsmasq.TakeOver(dnsmasq.Router{}) }

func (Router) RestoreDNS() (bool, error) {
	changed, err := dnsmasq.Restore(dnsmasq.Router{})
	markCleanShutdown()
	return changed, err
}

// EndCause looks in the kernel's log for the OOM-killer's line of the process ("Killed
// process 1234 (podkop) ... anon-rss:51200kB"), and adds the memory of the router now: a
// report then shows whether memory ran out there or the backend grew.
func (Router) EndCause(pid int) string {
	var cause []string
	if rss, killed := oomKilled(pid); killed {
		told := "killed by the kernel's OOM-killer"
		if rss != "" {
			told += " at " + rss + " of memory"
		}
		cause = append(cause, told)
	}
	if memory := memoryNow(); memory != "" {
		cause = append(cause, memory)
	}
	return strings.Join(cause, "; ")
}

// oomKilled tells whether the kernel's log has the OOM-killer's line of the process, and
// the anonymous memory it had then ("51 MB"), when the line says.
func oomKilled(pid int) (string, bool) {
	const readAll, sizeBuffer = 3, 10 // SYSLOG_ACTION_READ_ALL, SYSLOG_ACTION_SIZE_BUFFER
	size, err := syscall.Klogctl(sizeBuffer, nil)
	if err != nil || size <= 0 {
		return "", false
	}
	buffer := make([]byte, size)
	read, err := syscall.Klogctl(readAll, buffer)
	if err != nil || read <= 0 {
		return "", false
	}
	needle := []byte("Killed process " + strconv.Itoa(pid) + " (")
	var found []byte
	for line := range bytes.SplitSeq(buffer[:read], []byte("\n")) {
		if bytes.Contains(line, needle) {
			found = line
		}
	}
	if found == nil {
		return "", false
	}
	_, after, ok := bytes.Cut(found, []byte("anon-rss:"))
	if !ok {
		return "", true
	}
	kilobytes, _, _ := bytes.Cut(after, []byte("kB"))
	value, err := strconv.Atoi(string(kilobytes))
	if err != nil {
		return "", true
	}
	return strconv.Itoa(value/1024) + " MB", true
}

// memoryNow is the memory of the router as /proc/meminfo has it: "memory 241 MB, available
// 120 MB"; empty when it cannot be read.
func memoryNow() string {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return ""
	}
	defer file.Close()
	values := map[string]int{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && (fields[0] == "MemTotal:" || fields[0] == "MemAvailable:") {
			values[fields[0]], _ = strconv.Atoi(fields[1])
		}
	}
	total, available := values["MemTotal:"], values["MemAvailable:"]
	if total == 0 {
		return ""
	}
	return "memory " + strconv.Itoa(total/1024) + " MB, available " + strconv.Itoa(available/1024) + " MB"
}

// SettingsPath is the UCI file of the backend.
var SettingsPath = "/etc/config/podkop"

// compat: clean-shutdown
// markCleanShutdown keeps a promise to the shell backend, which may be installed again in
// place of this one: it sets dnsmasq up at its start only when its settings say that the
// previous stop was a clean one. This backend reads the state of dnsmasq from dnsmasq's
// own settings and has no use for the flag; it only never leaves it saying "not clean"
// after it gave dnsmasq back.
func markCleanShutdown() {
	content, err := os.ReadFile(SettingsPath)
	if err != nil {
		return
	}
	parsed, err := uci.Parse(content)
	if err != nil || parsed.Section("settings").Get("shutdown_correctly") != "0" {
		return
	}
	_ = dnsmasq.Router{}.Batch("set podkop.settings.shutdown_correctly='1'\ncommit podkop\n")
}
