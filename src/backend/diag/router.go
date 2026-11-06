package diag

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/dnsmasq"
	"github.com/podkop-net/podkop-experimental/src/backend/netcfg"
	"github.com/podkop-net/podkop-experimental/src/backend/sockets"
)

// ownProgram is the name the backend's process has (/proc/<pid>/comm).
const ownProgram = "podkop"

// procRoot is where /proc is looked for; a test may point it elsewhere.
var procRoot = "/"

// Listeners are the sockets of the system that wait for connections or datagrams.
func Listeners() []sockets.Listener {
	listeners, _ := sockets.List(procRoot)
	return listeners
}

// BackendPorts names the programs whose sockets take the addresses the backend listens
// on: the DNS inbound and the transparent proxy inbound, each over TCP and UDP. Such a
// socket keeps sing-box from starting.
func BackendPorts(listeners []sockets.Listener) []string {
	var lines []string
	for _, at := range []netip.AddrPort{dataplane.DNSServer, netip.AddrPortFrom(netip.MustParseAddr(dataplane.TProxyAddress), dataplane.TProxyPort)} {
		var holders []sockets.Listener
		for _, protocol := range []string{"tcp", "udp"} {
			for _, holder := range sockets.Holding(listeners, protocol, at) {
				if holder.Program != ownProgram {
					holders = append(holders, holder)
				}
			}
		}
		if len(holders) > 0 {
			lines = append(lines, at.String()+" is taken: "+sockets.Describe(holders))
		}
	}
	return lines
}

// LANDNS is who answers DNS on the addresses of an interface the LAN comes in on.
type LANDNS struct {
	Interface string
	Addresses []netip.Addr
	// Holders are the sockets on UDP port 53 of those addresses, or of every address
	Holders []sockets.Listener
	// Dnsmasq tells, when a holder is dnsmasq and its configuration could be read, the
	// servers it forwards every name to (those of "server=" without a domain) and
	// whether it reads no resolv file ("no-resolv")
	Dnsmasq  bool
	Servers  []string
	NoResolv bool
}

// CheckLANDNS looks, for each interface, at who listens on UDP port 53 of its addresses (the
// link-local ones of IPv6 aside) and, for dnsmasq, where it forwards.
func CheckLANDNS(interfaces []string, listeners []sockets.Listener) []LANDNS {
	var result []LANDNS
	for _, name := range interfaces {
		check := LANDNS{Interface: name, Addresses: interfaceAddresses(name)}
		seen := make(map[string]bool)
		for _, address := range check.Addresses {
			for _, holder := range sockets.Holding(listeners, "udp", netip.AddrPortFrom(address, 53)) {
				key := strconv.Itoa(holder.PID) + " " + holder.Address.String()
				if seen[key] {
					continue
				}
				seen[key] = true
				check.Holders = append(check.Holders, holder)
				if holder.Program == "dnsmasq" && !check.Dnsmasq {
					check.Servers, check.NoResolv, check.Dnsmasq = dnsmasqForwards(holder.PID)
				}
			}
		}
		result = append(result, check)
	}
	return result
}

// DeviceAddresses are the addresses of a device, the link-local ones aside, and whether
// there is a device of the name.
func DeviceAddresses(name string) ([]netip.Addr, bool) {
	if _, err := net.InterfaceByName(name); err != nil {
		return nil, false
	}
	return interfaceAddresses(name), true
}

func interfaceAddresses(name string) []netip.Addr {
	device, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addresses, _ := device.Addrs()
	var result []netip.Addr
	for _, address := range addresses {
		network, isNetwork := address.(*net.IPNet)
		if !isNetwork {
			continue
		}
		ip, _ := netip.AddrFromSlice(network.IP)
		ip = ip.Unmap()
		if ip.IsLinkLocalUnicast() {
			continue
		}
		result = append(result, ip)
	}
	return result
}

// dnsmasqForwards reads the configuration a dnsmasq process runs with, as the process sees
// it (see CheckDnsmasq): the file of its command line (-C, --conf-file) and the files of its
// conf-dir lines. It tells the servers every name goes to and whether no-resolv is there;
// read is false when the file is not found.
func dnsmasqForwards(pid int) (servers []string, noResolv bool, read bool) {
	file := dnsmasq.ConfFile(procRoot, pid)
	if file == "" {
		return nil, false, false
	}
	forwards, _, read := readForwards(processRoot(pid), file)
	if !read {
		// its root cannot be read: the file of the system
		forwards, _, read = readForwards(procRoot, file)
	}
	return forwards.Servers, forwards.NoResolv, read
}

// processRoot is the root of the file system as a process sees it.
func processRoot(pid int) string {
	return filepath.Join(procRoot, "proc", strconv.Itoa(pid), "root")
}

// Forwards is where a configuration of dnsmasq sends every name: the servers of its "server="
// lines without a domain, and whether it reads no resolv file ("no-resolv").
type Forwards struct {
	Servers  []string
	NoResolv bool
}

// readForwards reads a configuration file of dnsmasq and the files of its conf-dir lines,
// each under root. It returns the content of the file itself too; read is false when the
// file is not found.
func readForwards(root string, file string) (forwards Forwards, content []byte, read bool) {
	content, err := os.ReadFile(filepath.Join(root, file))
	if err != nil {
		return Forwards{}, nil, false
	}
	var directories []string
	readLines := func(content []byte) {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			key, value, _ := strings.Cut(line, "=")
			switch key {
			case "no-resolv":
				forwards.NoResolv = true
			case "server":
				// "server=/domain/address" is for the names of a domain only
				if !strings.HasPrefix(value, "/") {
					forwards.Servers = append(forwards.Servers, value)
				}
			case "conf-dir":
				directory, _, _ := strings.Cut(value, ",")
				directories = append(directories, directory)
			}
		}
	}
	readLines(content)
	for _, directory := range directories {
		entries, _ := os.ReadDir(filepath.Join(root, directory))
		for _, entry := range entries {
			if entry.IsDir() || strings.HasSuffix(entry.Name(), "~") {
				continue
			}
			content, err := os.ReadFile(filepath.Join(root, directory, entry.Name()))
			if err == nil {
				readLines(content)
			}
		}
	}
	return forwards, content, true
}

// DnsmasqLoaded is the configuration a dnsmasq process runs with against the one written for
// it now.
type DnsmasqLoaded struct {
	PID  int
	File string
	// Stale tells that the process runs with another content than its file has now
	Stale           bool
	Loaded, Written Forwards
}

// CheckDnsmasq compares, for each dnsmasq process in a jail, the configuration it runs with
// to the one written for it. procd starts dnsmasq in a jail of its own (ujail) where the
// file of its start is mounted, and the init script puts a new file in place of the old one
// on every start and reload: the process sees the file it was started with, and procd
// starts it again when the content changes. One it did not start again (a restart while
// procd restarted it for an interface that came up) runs with the old content for good.
// A process outside a jail reads the file of the system: what it was started with cannot be
// seen, and it is left out.
func CheckDnsmasq(listeners []sockets.Listener) []DnsmasqLoaded {
	var result []DnsmasqLoaded
	seen := make(map[int]bool)
	for _, listener := range listeners {
		if listener.Program != "dnsmasq" || seen[listener.PID] {
			continue
		}
		seen[listener.PID] = true
		if !dnsmasq.Jailed(procRoot, listener.PID) {
			continue
		}
		file := dnsmasq.ConfFile(procRoot, listener.PID)
		if file == "" {
			continue
		}
		loaded, loadedContent, readLoaded := readForwards(processRoot(listener.PID), file)
		written, writtenContent, readWritten := readForwards(procRoot, file)
		if !readLoaded || !readWritten {
			continue
		}
		result = append(result, DnsmasqLoaded{
			PID: listener.PID, File: file,
			Stale:  !bytes.Equal(loadedContent, writtenContent),
			Loaded: loaded, Written: written,
		})
	}
	return result
}

// MarkedRoute is where the kernel sends a packet marked for the transparent proxy that
// came in on an interface of the LAN.
type MarkedRoute struct {
	Interface string
	Source    netip.Addr
	Route     netcfg.Route
	Err       error
}

// CheckMarkedRoutes asks the kernel, for each interface, where a packet from a device of its
// network to an address of the FakeIP range goes once marked: the routing rule of the backend
// sends it to the router itself. The device is client where it is on that network, an
// address of the network that is not the router's otherwise.
func CheckMarkedRoutes(interfaces []string, client netip.Addr) []MarkedRoute {
	destination := dataplane.FakeIPPrefix.Addr().Next()
	var result []MarkedRoute
	for _, name := range interfaces {
		source, found := deviceOf(name, client)
		if !found {
			continue
		}
		route, err := netcfg.MarkedRoute(name, source, destination, dataplane.ProxyMark)
		result = append(result, MarkedRoute{Interface: name, Source: source, Route: route, Err: err})
	}
	return result
}

// deviceOf picks the address a device of an interface's IPv4 network has: client when it is
// on that network, else the first address of the network that is not the router's.
func deviceOf(name string, client netip.Addr) (netip.Addr, bool) {
	device, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}, false
	}
	addresses, _ := device.Addrs()
	for _, address := range addresses {
		network, isNetwork := address.(*net.IPNet)
		if !isNetwork {
			continue
		}
		ip, _ := netip.AddrFromSlice(network.IP)
		ip = ip.Unmap()
		ones, _ := network.Mask.Size()
		if !ip.Is4() || ones > 30 {
			continue
		}
		prefix := netip.PrefixFrom(ip, ones).Masked()
		if client.IsValid() && prefix.Contains(client) {
			return client, true
		}
		for candidate := prefix.Addr().Next(); prefix.Contains(candidate); candidate = candidate.Next() {
			if candidate != ip {
				return candidate, true
			}
		}
	}
	return netip.Addr{}, false
}

// BridgedTraffic is netcfg.BridgedTraffic: whether br_netfilter is in the kernel, and the
// value of each switch that passes bridged packets through the IP firewall hooks.
func BridgedTraffic() (present bool, values map[string]string) {
	return netcfg.BridgedTraffic()
}
