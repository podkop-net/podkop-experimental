// Package dnsmasq points the DNS of the LAN at the backend and back. dnsmasq stays the
// resolver the devices ask; its upstream for every name becomes the DNS inbound of sing-box,
// and what it had before is kept in its own settings under other names, as the shell backend
// keeps it, so that either backend can undo what the other did. The servers of dnsmasq for
// the names of a domain (server=/example.com/192.168.1.5, the forwarding of Tailscale's
// MagicDNS) stay as they are: those names go where the user sent them, with the backend as
// without it. The shell backend took them too, and its restore puts back only what it kept:
// a shell backend that gives back a dnsmasq this backend took (one started after this one
// with dnsmasq still taken: a lost power, then a downgrade) drops them.
package dnsmasq

import (
	"os"
	"os/exec"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// address is where the DNS inbound of the backend listens
	address = dataplane.DNSAddress
	// what dnsmasq falls back to when nothing was kept: the resolvers netifd collects
	resolvFile = "/tmp/resolv.conf.d/resolv.conf.auto"
	section    = "dhcp.@dnsmasq[0]"
	// marker is the option the backend leaves on a dnsmasq it took over: what Restore
	// gives back is the backend's own doing, never a setting made by hand
	marker = "podkop_taken"
)

// System is the router as this package touches it; a test has its own.
type System interface {
	// ReadSettings returns the UCI file of dnsmasq.
	ReadSettings() ([]byte, error)
	// Batch runs commands of the uci program, one a line.
	Batch(script string) error
	// Apply has dnsmasq take its settings now.
	Apply() error
	// Exists tells whether a file is there.
	Exists(path string) bool
}

// Router is the System of an OpenWrt router.
type Router struct{}

func (Router) ReadSettings() ([]byte, error) { return os.ReadFile("/etc/config/dhcp") }

func (Router) Batch(script string) error {
	command := exec.Command("uci", "-q", "batch")
	command.Stdin = strings.NewReader(script)
	output, err := command.CombinedOutput()
	if err != nil {
		return E.Cause(err, "uci batch: ", strings.TrimSpace(string(output)))
	}
	return nil
}

// Apply runs "start" of the init script of dnsmasq: the script writes the configuration file
// from the settings and hands it to procd ("service set"), which starts dnsmasq again when the
// content changed, with the last configuration it was handed. Not "restart": its stop deletes
// the instance in procd, and one that comes while procd starts dnsmasq again for an interface
// that came up (that trigger runs "reload") leaves the process started with the old file
// running for good (on the stand "restart" 20 of 60 rounds, "start" 0 of 30, "reload" 0 of
// 30). Not "reload": it
// is the same start followed by a SIGHUP, which on a slow router reaches the new process
// before it has set its handlers and kills it; procd starts it again after its respawn
// timeout, 5 s without DNS (7 of 33 rounds on an emulated MIPS 24Kc, 0 of 15 with "start").
// A running dnsmasq that another program's restart left with an old file takes no new
// configuration at all: the watch (Watch) finds it and restarts it.
func (Router) Apply() error {
	output, err := exec.Command("/etc/init.d/dnsmasq", "start").CombinedOutput()
	if err != nil {
		return E.Cause(err, "start dnsmasq with its settings: ", strings.TrimSpace(string(output)))
	}
	return nil
}

func (Router) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// state is what the first dnsmasq of the settings has.
type state struct {
	servers    []string
	noResolv   string
	cacheSize  string
	resolvFile string
	// what was kept of the settings before the backend took dnsmasq over
	keptServers   []string
	keptNoResolv  string
	keptCacheSize string
	// marked tells that the backend took it over
	marked bool
}

func read(system System) (*state, error) {
	content, err := system.ReadSettings()
	if err != nil {
		return nil, E.Cause(err, "read the settings of dnsmasq")
	}
	parsed, err := uci.Parse(content)
	if err != nil {
		return nil, E.Cause(err, "read the settings of dnsmasq")
	}
	sections := parsed.SectionsOfType("dnsmasq")
	if len(sections) == 0 {
		return nil, E.New("the settings have no dnsmasq")
	}
	first := sections[0]
	return &state{
		servers:    strings.Fields(first.Get("server")),
		noResolv:   first.Get("noresolv"),
		cacheSize:  first.Get("cachesize"),
		resolvFile: first.Get("resolvfile"),
		// compat: dnsmasq-backup-keys
		keptServers:   strings.Fields(first.Get("podkop_server")),
		keptNoResolv:  first.Get("podkop_noresolv"),
		keptCacheSize: first.Get("podkop_cachesize"),
		marked:        first.Get(marker) == "1",
	}, nil
}

// taken tells whether a backend took this dnsmasq over: this one leaves its marker, the
// shell backend and earlier releases of this one leave what they kept (the cache size,
// which OpenWrt sets by default, among it).
func (s *state) taken() bool {
	return s.marked || len(s.keptServers) > 0 || s.keptNoResolv != "" || s.keptCacheSize != ""
}

// ours tells whether dnsmasq asks the backend for every name and nobody else, with no cache
// of its own: its servers for the names of a domain aside.
func (s *state) ours() bool {
	return AsksBackend(s.servers) && s.noResolv == "1" && s.cacheSize == "0"
}

// ForEveryName tells whether dnsmasq may ask the server of a "server=" line (a value of the
// list server of its settings) for any name. A line without a domain is ("8.8.8.8",
// "127.0.0.1#5053", "1.1.1.1@wan"), and so is one with the domain "#" or "*": dnsmasq 2.93
// asks "/#/1.1.1.1" and "/*/1.1.1.1" for every name beside the servers without a domain, and
// "/#/" answers every name itself with NXDOMAIN. A line for the names of its domains only is
// not: "/example.com/1.1.1.1" (and its subdomains), "/*.example.com/...", "/*example.com/...",
// "/a.lan/b.lan/...", "//1.1.1.1" (names without a dot), "/example.com/" (answered by dnsmasq
// itself), "/example.com/#" (asked of the servers for every name).
func ForEveryName(server string) bool {
	if !strings.HasPrefix(server, "/") {
		return true
	}
	end := strings.LastIndexByte(server, '/')
	if end == 0 {
		// a single slash names no domain: for every name, as far as it can be told
		return true
	}
	for _, domain := range strings.Split(server[1:end], "/") {
		if domain == "#" || domain == "*" {
			return true
		}
	}
	return false
}

// Split parses a "server=" line for the names of its domains: its domains and the server it
// names ("" for none: answered by dnsmasq itself, "#": the servers for every name).
func Split(server string) (domains []string, upstream string) {
	end := strings.LastIndexByte(server, '/')
	if !strings.HasPrefix(server, "/") || end == 0 {
		return nil, server
	}
	return strings.Split(server[1:end], "/"), server[end+1:]
}

// AsksBackend tells whether the servers of dnsmasq (the list server of its settings) send
// every name to the backend alone; servers for the names of a domain may be there beside it.
func AsksBackend(servers []string) bool {
	every := 0
	for _, server := range servers {
		if !ForEveryName(server) {
			continue
		}
		if server != address {
			return false
		}
		every++
	}
	return every > 0
}

// Ours tells whether dnsmasq is set up to ask the backend.
func Ours(system System) (bool, error) {
	current, err := read(system)
	if err != nil {
		return false, err
	}
	return current.ours(), nil
}

// TakeOver makes dnsmasq ask the backend for every name: its servers for every name
// (ForEveryName), its "noresolv" and its cache size are kept under other names, and it takes
// them (Apply). Its servers for the names of a domain stay where they are, and so do those
// another program adds while the backend runs. A dnsmasq that asks the backend already is left
// alone, not started again: the shell backend restarts it on every start, which takes the DNS
// of the LAN away for three seconds each time.
// A dnsmasq taken over before and changed since (a server added by hand while the backend
// ran) keeps what was kept the first time: its "noresolv" and its cache size now are the
// backend's own, and the servers added are kept beside the others. The servers for the names
// of a domain that the shell backend or a release before this one kept go back to work.
// It tells whether anything was changed.
func TakeOver(system System) (bool, error) {
	current, err := read(system)
	if err != nil {
		return false, err
	}
	kept := current.keptServers
	// taken over before, and given back by hand, or by the init script, since: what was kept
	// is stale
	stale := current.taken() && !contains(current.servers, address)
	if stale {
		kept = nil
	}
	var script strings.Builder
	write := func(line string) { script.WriteString(line + "\n") }
	var back []string
	for _, server := range kept {
		if !ForEveryName(server) && !contains(current.servers, server) && !contains(back, server) {
			back = append(back, server)
		}
	}
	if len(back) > 0 {
		write("delete " + section + ".podkop_server")
		for _, server := range kept {
			if ForEveryName(server) {
				write("add_list " + section + ".podkop_server=" + Quote(server))
			}
		}
		for _, server := range back {
			write("add_list " + section + ".server=" + Quote(server))
		}
	}
	if current.ours() {
		if !current.taken() {
			// set to ask the backend with nothing kept and no marker (the shell backend keeps
			// only the options that were set): marked, or nothing would ever give it back
			write("set " + section + "." + marker + "='1'")
		}
		if script.Len() == 0 {
			return false, nil
		}
		write("commit dhcp")
		err = system.Batch(script.String())
		if err != nil || len(back) == 0 {
			return false, err
		}
		return true, system.Apply()
	}
	if stale {
		write("delete " + section + ".podkop_server")
		write("delete " + section + ".podkop_noresolv")
		write("delete " + section + ".podkop_cachesize")
	}
	var moved []string
	for _, server := range current.servers {
		if server == address || !ForEveryName(server) || contains(moved, server) {
			continue
		}
		moved = append(moved, server)
		if !contains(kept, server) {
			write("add_list " + section + ".podkop_server=" + Quote(server))
		}
		write("del_list " + section + ".server=" + Quote(server))
	}
	// taken over before and still asking the backend: what was kept is the original
	again := current.taken() && !stale
	if current.noResolv != "" && !again {
		write("set " + section + ".podkop_noresolv=" + Quote(current.noResolv))
	}
	if current.cacheSize != "" && !again {
		write("set " + section + ".podkop_cachesize=" + Quote(current.cacheSize))
	}
	if !contains(current.servers, address) {
		write("add_list " + section + ".server=" + Quote(address))
	}
	write("set " + section + ".noresolv='1'")
	write("set " + section + ".cachesize='0'")
	write("set " + section + "." + marker + "='1'")
	write("commit dhcp")
	err = system.Batch(script.String())
	if err != nil {
		return false, err
	}
	return true, system.Apply()
}

// Prepare makes dnsmasq ask the backend as TakeOver does, without Apply: at boot,
// before the service of dnsmasq starts, so that it starts that way and the backend that
// starts later finds it set and leaves it alone: dnsmasq is not started again at boot.
// It tells whether anything was changed.
func Prepare(system System) (bool, error) {
	return TakeOver(notApplied{system})
}

// GiveBackBeforeStart gives dnsmasq back as Restore does, without Apply: at boot, before the
// service of dnsmasq starts, when the backend does not start at boot and one that ended
// without its stop (power lost, a panic) left dnsmasq asking it. It tells whether anything
// was changed.
func GiveBackBeforeStart(system System) (bool, error) {
	return Restore(notApplied{system})
}

// notApplied is a System whose dnsmasq is not running yet: nothing to apply.
type notApplied struct{ System }

func (notApplied) Apply() error { return nil }

// Restore gives dnsmasq back what was kept when it was taken over, and applies it. With
// nothing kept it gets the resolvers netifd collects, as the shell backend does it. Only
// a dnsmasq a backend took over is given back (see taken): one that was set to ask the
// backend by hand, with dont_touch_dhcp, is left as it is. The shell backend instead
// leaves dnsmasq alone whenever dont_touch_dhcp is set, also when it had taken it over
// before the option was turned on, and the LAN is then without DNS after the stop.
// It tells whether anything was changed.
func Restore(system System) (bool, error) {
	current, err := read(system)
	if err != nil {
		return false, err
	}
	if !current.taken() {
		return false, nil
	}
	var script strings.Builder
	if current.marked {
		script.WriteString("delete " + section + "." + marker + "\n")
	}
	if current.keptCacheSize == "" {
		script.WriteString("set " + section + ".cachesize='150'\n")
	} else {
		script.WriteString("set " + section + ".cachesize=" + Quote(current.keptCacheSize) + "\n")
		script.WriteString("delete " + section + ".podkop_cachesize\n")
	}
	if current.keptNoResolv == "" {
		script.WriteString("set " + section + ".noresolv='0'\n")
	} else {
		script.WriteString("set " + section + ".noresolv=" + Quote(current.keptNoResolv) + "\n")
		script.WriteString("delete " + section + ".podkop_noresolv\n")
	}
	// the servers kept go back beside those that stayed: the servers for the names of a
	// domain, and what was added by hand while the backend ran
	var servers []string
	for _, server := range current.servers {
		if server != address {
			servers = append(servers, server)
		}
	}
	if contains(current.servers, address) {
		script.WriteString("del_list " + section + ".server=" + Quote(address) + "\n")
	}
	for _, server := range current.keptServers {
		if !contains(servers, server) {
			servers = append(servers, server)
			script.WriteString("add_list " + section + ".server=" + Quote(server) + "\n")
		}
	}
	if len(current.keptServers) > 0 {
		script.WriteString("delete " + section + ".podkop_server\n")
	}
	if !general(servers) && system.Exists(resolvFile) {
		// a resolv file set by hand stays
		if current.resolvFile == "" {
			script.WriteString("set " + section + ".resolvfile=" + Quote(resolvFile) + "\n")
		}
		if isOne(current.keptNoResolv) {
			// no servers to ask and told not to read the resolvers: it would ask nobody
			script.WriteString("set " + section + ".noresolv='0'\n")
		}
	}
	script.WriteString("commit dhcp\n")
	err = system.Batch(script.String())
	if err != nil {
		return false, err
	}
	return true, system.Apply()
}

// general tells whether a server of a list is asked for every name (ForEveryName).
func general(servers []string) bool {
	for _, server := range servers {
		if ForEveryName(server) {
			return true
		}
	}
	return false
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func isOne(text string) bool {
	text = strings.TrimLeft(strings.TrimSpace(text), "+0")
	return text == "1"
}

// Quote writes a value for a line of "uci batch".
func Quote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
