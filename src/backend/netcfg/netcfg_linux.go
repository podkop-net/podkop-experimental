// Package netcfg keeps what the backend needs of the routing of the router: the rules and
// the route that hand the packets the firewall marked to the transparent proxy, and the
// address of the LAN. It talks netlink; the ip program is not run.
package netcfg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	tableID             = dataplane.RoutingTable
	tableName           = dataplane.RoutingTableName
	rulePriority        = dataplane.RulePriority
	reverseRulePriority = dataplane.ReverseRulePriority
	// markProxy and markRouter are the marks of the firewall table (firewall): what comes
	// from the LAN, what the router itself sends
	markProxy  = dataplane.ProxyMark
	markRouter = dataplane.RouterMark
	// netifdTimeout is how long the answer of netifd is waited for.
	netifdTimeout = 3 * time.Second
)

// TableNamesPath is where iproute2 keeps the names of the routing tables. The shell
// backend finds its rule and its route by the name, so the name is kept there.
var TableNamesPath = "/etc/iproute2/rt_tables"

// NetworkConfigPath is the UCI file of netifd.
var NetworkConfigPath = "/etc/config/network"

// Apply makes the route and the rules; what is there already is left as it is. With ipv6
// those of IPv6 as well; without it those of IPv6 are removed, if a run with IPv6 left them.
func Apply(ipv6 bool) error {
	nameTable()
	err := applyFamily(unix.AF_INET)
	if err != nil {
		return err
	}
	if ipv6 {
		return applyFamily(unix.AF_INET6)
	}
	return removeFamily(unix.AF_INET6)
}

// applyFamily makes the route and the rules of one family. Those of IPv6 rules first: a kernel
// without rules of IPv6 (no IPV6_MULTIPLE_TABLES) refuses them, and puts a route of any table into
// its main one, where "local ::/0" would take all of IPv6 to the router itself.
func applyFamily(family int) error {
	if family == unix.AF_INET6 {
		err := addRules(family)
		if err != nil {
			return err
		}
		return addRoute(family)
	}
	err := addRoute(family)
	if err != nil {
		return err
	}
	return addRules(family)
}

// addRoute makes the route of the table: every marked packet is for this host, the transparent
// proxy inbound takes it.
func addRoute(family int) error {
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return E.Cause(err, "find the loopback interface")
	}
	err = netlink.RouteReplace(&netlink.Route{
		LinkIndex: loopback.Attrs().Index,
		Dst:       anyAddress(family),
		Table:     tableID,
		Type:      unix.RTN_LOCAL,
		Scope:     netlink.SCOPE_HOST,
	})
	if err != nil {
		return E.Cause(err, "add the route of the table ", tableID, familyText(family))
	}
	return nil
}

// addRules makes the rules of the marks of one family; what is there is left.
func addRules(family int) error {
	for _, rule := range backendRules(family) {
		exists, err := ruleExists(rule)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		err = netlink.RuleAdd(rule)
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return E.Cause(err, "add the rule of priority ", rule.Priority, " for marked packets", familyText(family))
		}
	}
	return nil
}

// anyAddress is the destination of every address of a family: 0.0.0.0/0 or ::/0.
func anyAddress(family int) *net.IPNet {
	if family == unix.AF_INET6 {
		return &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}
	return &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
}

func familyText(family int) string {
	if family == unix.AF_INET6 {
		return " (IPv6)"
	}
	return ""
}

// Present tells whether the rules and the route are all there, of IPv6 too with ipv6.
// netifd, when it is restarted, flushes the rules it does not own, and a loopback that goes
// down takes the route with it.
func Present(ipv6 bool) (bool, error) {
	families := []int{unix.AF_INET}
	if ipv6 {
		families = append(families, unix.AF_INET6)
	}
	for _, family := range families {
		for _, rule := range backendRules(family) {
			exists, err := ruleExists(rule)
			if err != nil || !exists {
				return false, err
			}
		}
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: tableID}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return false, E.Cause(err, "list the routes of the table ", tableID, familyText(family))
		}
		if len(routes) == 0 {
			return false, nil
		}
	}
	return true, nil
}

// Remove deletes the rules and the routes of the table, of both families, and the rules of
// the uplinks (RouteUplinks); what is not there is no error.
func Remove() error {
	_, err := syncUplinkRules(nil)
	if err != nil {
		return err
	}
	err = removeFamily(unix.AF_INET)
	if err != nil {
		return err
	}
	return removeFamily(unix.AF_INET6)
}

// removeFamily deletes the rules and the routes of the table of one family. A kernel without
// IPv6 has none of IPv6 to list: no error.
func removeFamily(family int) error {
	for _, rule := range backendRules(family) {
		for {
			exists, err := ruleExists(rule)
			if err != nil {
				if family == unix.AF_INET6 && errors.Is(err, unix.EAFNOSUPPORT) {
					return nil
				}
				return err
			}
			if !exists {
				break
			}
			err = netlink.RuleDel(rule)
			if err != nil && !errors.Is(err, unix.ENOENT) {
				return E.Cause(err, "delete the rule of priority ", rule.Priority, " for marked packets", familyText(family))
			}
		}
	}
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: tableID}, netlink.RT_FILTER_TABLE)
	if err != nil {
		if family == unix.AF_INET6 && errors.Is(err, unix.EAFNOSUPPORT) {
			return nil
		}
		return E.Cause(err, "list the routes of the table ", tableID, familyText(family))
	}
	for index := range routes {
		if routes[index].Dst == nil {
			// the list gives a default route without its destination, and a route
			// without one cannot be named for deletion
			routes[index].Dst = anyAddress(family)
		}
		err = netlink.RouteDel(&routes[index])
		if err != nil && !errors.Is(err, unix.ESRCH) {
			return E.Cause(err, "delete a route of the table ", tableID, familyText(family))
		}
	}
	return nil
}

// backendRules are the rules of the backend: one for each mark of the firewall sends a marked
// packet to the table, whose route makes it the router's own. The kernel checks the source
// of a packet it routes to itself by the lookup of the way back, as from the loopback, and
// with src_valid_mark (Tailscale sets it for all interfaces) that lookup has the mark of the
// packet: by the rule of the mark it would find the route of the table, take the address
// of the LAN device for the router's own and drop the packet. So the first rule sends a
// lookup from the loopback with the mark of the LAN to the main table. What the router
// sends is looked up from the loopback too: it has a mark of its own, which that rule
// leaves to the table. IPv6 has the same rules (a check of the source by fib, such as fw4's
// rpfilter, looks up the way back as well).
func backendRules(family int) []*netlink.Rule {
	reverse := markRule(family, reverseRulePriority, markProxy, unix.RT_TABLE_MAIN)
	reverse.IifName = "lo"
	return []*netlink.Rule{reverse, markRule(family, rulePriority, markProxy, tableID), markRule(family, rulePriority, markRouter, tableID)}
}

func markRule(family int, priority int, mark uint32, table int) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Family = family
	rule.Priority = priority
	rule.Table = table
	rule.Mark = mark
	rule.MarkSet = true
	rule.Mask = int(mark)
	return rule
}

func ruleExists(want *netlink.Rule) (bool, error) {
	rules, err := netlink.RuleList(want.Family)
	if err != nil {
		return false, E.Cause(err, "list the routing rules", familyText(want.Family))
	}
	for _, rule := range rules {
		if rule.Table == want.Table && rule.Priority == want.Priority && rule.Mark == want.Mark && rule.Mask == want.Mask && rule.IifName == want.IifName {
			return true, nil
		}
	}
	return false, nil
}

// IPv6State is what the router has of IPv6: ::1 on its loopback (IPv6Loopback), its global
// unicast addresses (2000::/3; unique local ones are not counted) and whether the main table
// has a default route of IPv6.
type IPv6State struct {
	Loopback     bool
	Global       int
	DefaultRoute bool
}

// IPv6Now reads the IPv6State of the router.
func IPv6Now() IPv6State {
	state := IPv6State{Loopback: IPv6Loopback()}
	if !state.Loopback {
		return state
	}
	globalUnicast := netip.MustParsePrefix("2000::/3")
	if addresses, err := netlink.AddrList(nil, unix.AF_INET6); err == nil {
		for _, address := range addresses {
			if parsed, ok := netip.AddrFromSlice(address.IP); ok && globalUnicast.Contains(parsed) {
				state.Global++
			}
		}
	}
	if routes, err := netlink.RouteListFiltered(unix.AF_INET6, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE); err == nil {
		for _, route := range routes {
			if route.Dst == nil || route.Dst.IP.IsUnspecified() && maskBits(route.Dst) == 0 {
				state.DefaultRoute = true
			}
		}
	}
	return state
}

func maskBits(network *net.IPNet) int {
	ones, _ := network.Mask.Size()
	return ones
}

// IPv6LoopbackPath is where the kernel lists the IPv6 addresses of the interfaces; a kernel
// without IPv6 (ipv6.disable=1) has no such file.
var IPv6LoopbackPath = "/proc/net/if_inet6"

// IPv6Loopback tells whether the router has IPv6: the address ::1 on the loopback, where the
// transparent proxy inbound of IPv6 listens. IPv6 turned off by sysctl
// (net.ipv6.conf.all.disable_ipv6 or that of lo) takes it away as well.
func IPv6Loopback() bool {
	content, err := os.ReadFile(IPv6LoopbackPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 6 && fields[0] == "00000000000000000000000000000001" && fields[5] == "lo" {
			return true
		}
	}
	return false
}

// nameTable writes the name of the table where iproute2 looks for it, once. A system
// without that file gets none: the name is for people and for the shell backend.
func nameTable() {
	content, err := os.ReadFile(TableNamesPath)
	if err != nil {
		return
	}
	line := strconv.Itoa(tableID) + " " + tableName
	for _, existing := range strings.Split(string(content), "\n") {
		if strings.Join(strings.Fields(existing), " ") == line {
			return
		}
	}
	if len(content) > 0 && !bytes.HasSuffix(content, []byte("\n")) {
		content = append(content, '\n')
	}
	_ = os.WriteFile(TableNamesPath, append(content, line+"\n"...), 0o644)
}

// LANAddress returns the IPv4 address of the interface "lan": the first one netifd reports
// for it, which is what the shell backend asks. The device of the interface is no
// substitute: it carries the addresses of every interface that names it, in the order
// they were set, so its first address can be another interface's. The device is asked
// only when netifd does not answer.
func LANAddress() (netip.Addr, error) {
	address, err := lanAddressOfNetifd()
	if err == nil {
		return address, nil
	}
	fromDevice, deviceErr := lanAddressOfDevice()
	if deviceErr == nil {
		return fromDevice, nil
	}
	return netip.Addr{}, E.Cause(deviceErr, "find the address of the LAN (netifd: ", err, ")")
}

func lanAddressOfDevice() (netip.Addr, error) {
	content, err := os.ReadFile(NetworkConfigPath)
	if err != nil {
		return netip.Addr{}, err
	}
	parsed, err := uci.Parse(content)
	if err != nil {
		return netip.Addr{}, err
	}
	section := parsed.Section("lan")
	if section == nil || section.Type != "interface" {
		return netip.Addr{}, E.New("the network settings have no interface lan")
	}
	device := section.Get("device")
	if device == "" {
		// the option of OpenWrt before 21.02
		device = section.Get("ifname")
	}
	if device == "" || strings.ContainsAny(device, " @") {
		return netip.Addr{}, E.New("the interface lan names no single device")
	}
	link, err := netlink.LinkByName(device)
	if err != nil {
		return netip.Addr{}, E.Cause(err, "find the device ", device)
	}
	addresses, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return netip.Addr{}, E.Cause(err, "list the addresses of ", device)
	}
	// the address the settings give the interface, when the device has it; else its first
	configured := section.List("ipaddr")
	var first netip.Addr
	for _, address := range addresses {
		parsed, isAddress := netip.AddrFromSlice(address.IP)
		if !isAddress {
			continue
		}
		parsed = parsed.Unmap()
		for _, item := range configured {
			item, _, _ = strings.Cut(item, "/")
			if item == parsed.String() {
				return parsed, nil
			}
		}
		if !first.IsValid() {
			first = parsed
		}
	}
	if first.IsValid() {
		return first, nil
	}
	return netip.Addr{}, E.New("the device ", device, " has no IPv4 address")
}

func lanAddressOfNetifd() (netip.Addr, error) {
	// netifd answers at once or is not there; a bus that hangs must not hold the caller
	ctx, cancel := context.WithTimeout(context.Background(), netifdTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ubus", "-t", "2", "call", "network.interface.lan", "status").Output()
	if err != nil {
		return netip.Addr{}, err
	}
	var status struct {
		Addresses []struct {
			Address string `json:"address"`
		} `json:"ipv4-address"`
	}
	err = json.Unmarshal(output, &status)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(status.Addresses) == 0 {
		return netip.Addr{}, E.New("netifd reports no IPv4 address of lan")
	}
	return netip.ParseAddr(status.Addresses[0].Address)
}

// BridgeSysctlDir holds the switches of br_netfilter. It is there whenever br_netfilter is
// in the kernel, as a module or built in: lsmod lists only the module, so the shell
// backend's look at lsmod misses a kernel that has it built in.
var BridgeSysctlDir = "/proc/sys/net/bridge"

// bridgeSwitches are the switches that pass bridged packets through the IP firewall hooks.
var bridgeSwitches = []string{"bridge-nf-call-iptables", "bridge-nf-call-ip6tables"}

// AllowBridgedTraffic turns off the passing of bridged packets through the IP firewall
// hooks where the kernel has it on, and returns the names of the switches it turned off.
// With it on, a packet that came in on a port of the LAN bridge and was taken by the
// transparent proxy is lost after the routing (measured on OpenWrt 24.10, kernel 6.6:
// neither the device check nor any proxied connection passes), and packets between the
// ports of the bridge meet the rules of the backend. The shell backend turns it off too.
func AllowBridgedTraffic() []string {
	var changed []string
	for _, name := range bridgeSwitches {
		path := BridgeSysctlDir + "/" + name
		content, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(content)) == "1" && os.WriteFile(path, []byte("0\n"), 0o644) == nil {
			changed = append(changed, "net.bridge."+name)
		}
	}
	return changed
}

// BridgedTraffic tells whether br_netfilter is in the kernel and, when it is, the value of
// each switch that passes bridged packets through the IP firewall hooks, by name.
func BridgedTraffic() (present bool, values map[string]string) {
	values = make(map[string]string)
	for _, name := range bridgeSwitches {
		content, err := os.ReadFile(BridgeSysctlDir + "/" + name)
		if err != nil {
			continue
		}
		present = true
		values["net.bridge."+name] = strings.TrimSpace(string(content))
	}
	return present, values
}
