package clock

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/sagernet/sing/common/ntp"
)

// Keeper runs the steps of the package documentation while sysntpd has not set the clock
// since the boot. It does nothing once it has, or when the user turned sysntpd off.
type Keeper struct {
	// Log takes what was done, a line an event.
	Log func(level string, message string)
	// DoH tells the DoH server of the settings, host[:port][/path]; empty when the DNS
	// server of the settings is not DoH.
	DoH func() string
	// UplinkDNS tells the DNS servers of the uplinks (netcfg.UplinkDNSServers).
	UplinkDNS func() []string

	// what a test replaces: the router, the clock, the network
	state     func() State
	sysntpd   sysntpd
	set       func(time.Time) error
	roots     *x509.CertPool
	lookup    func(ctx context.Context, server string, name string) ([]netip.Addr, error)
	ntpPort   string
	waitDNS   time.Duration
	tryDNS    time.Duration
	askWait   time.Duration
	checkGap  time.Duration
	restartAt time.Duration

	// run is held by a check; what follows it is read and written under it
	run       sync.Mutex
	checked   time.Time
	restarted time.Time
	quiet     bool
	// due makes the next check run A and C whatever checkGap says (the daily check)
	due atomic.Bool
}

const (
	// askWait bounds A and C each: at the start the LAN has no DNS until sing-box is up
	askWait = 3 * time.Second
	// checkGap is the least time between two runs of A and C: an uplink that comes up
	// again and again asks again only so often
	checkGap = 10 * time.Minute
	// restartGap is the least time between two restarts of sysntpd
	restartGap = 10 * time.Minute
	// waitDNS is how long B waits for the DNS of sing-box to answer a name of sysntpd,
	// asking every tryDNS
	waitDNS = 2 * time.Minute
	tryDNS  = 10 * time.Second
	// dailyCheck is how often the clock is checked while sysntpd has not set it since the
	// boot (UDP 123 closed): a clock drifts a few seconds a day
	dailyCheck = 24 * time.Hour
)

func (k *Keeper) defaults() {
	if k.state == nil {
		k.state = ReadState
	}
	if k.sysntpd.ubus == nil {
		k.sysntpd = defaultSysntpd
	}
	if k.set == nil {
		k.set = ntp.SetSystemTime
	}
	if k.lookup == nil {
		k.lookup = lookupAt
	}
	if k.ntpPort == "" {
		k.ntpPort = "123"
	}
	if k.waitDNS == 0 {
		k.waitDNS, k.tryDNS = waitDNS, tryDNS
	}
	if k.askWait == 0 {
		k.askWait = askWait
	}
	if k.checkGap == 0 {
		k.checkGap = checkGap
	}
	if k.restartAt == 0 {
		k.restartAt = restartGap
	}
}

// AtStart runs A and C before sing-box starts; it holds the start for some seconds at the
// most, and not at all when sysntpd has set the clock.
func (k *Keeper) AtStart(ctx context.Context) {
	k.run.Lock()
	defer k.run.Unlock()
	k.defaults()
	k.check(ctx, false)
}

// Kick runs A and C, when due, and B, in the background, while sing-box runs: after its
// start, when an interface comes up. A kick while a check runs is dropped.
func (k *Keeper) Kick() {
	if !k.run.TryLock() {
		return
	}
	k.defaults()
	go func() {
		defer k.run.Unlock()
		k.check(context.Background(), true)
	}()
}

// Loop kicks once a day until the context ends.
func (k *Keeper) Loop(ctx context.Context) {
	ticker := time.NewTicker(dailyCheck)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			k.due.Store(true)
			k.Kick()
		}
	}
}

func (k *Keeper) log(level string, message string) {
	if k.Log != nil {
		k.Log(level, message)
	}
}

// check runs the steps; restart: sing-box runs, and B may follow. A failure before the
// start is told at info: at a boot the WAN often comes up later, and the next kick asks
// again.
func (k *Keeper) check(ctx context.Context, restart bool) {
	if k.state().Synced {
		return
	}
	if !k.sysntpd.enabled(ctx) {
		if !k.quiet {
			k.quiet = true
			k.log("info", "the clock is not checked: the NTP service of the router (sysntpd) is off")
		}
		return
	}
	servers := k.sysntpd.servers(ctx)
	if k.due.Swap(false) || k.checked.IsZero() || time.Since(k.checked) >= k.checkGap {
		k.checked = time.Now()
		answered, problem := k.fromNTP(ctx, servers)
		if !answered {
			found, dohProblem := k.fromHTTPS(ctx)
			if !found {
				level := "warn"
				if !restart {
					level = "info"
				}
				k.log(level, "the clock is not checked: "+problem+"; "+dohProblem)
			}
		}
	}
	if restart && time.Since(k.restarted) >= k.restartAt && k.dnsAnswers(ctx, servers) {
		// what is read after the wait: sysntpd may have set the clock meanwhile
		if k.state().Synced {
			return
		}
		k.restarted = time.Now()
		err := k.sysntpd.restart(ctx)
		if err != nil {
			k.log("warn", "restart the NTP service of the router (sysntpd): "+err.Error())
			return
		}
		k.log("info", "the NTP service of the router (sysntpd) is restarted: it had not set the clock since the boot, and the DNS answers its servers now")
	}
}

// fromNTP is A: the servers of sysntpd by their addresses, their names resolved by the DNS
// servers of the uplinks. It tells whether a server answered, and why none did.
func (k *Keeper) fromNTP(ctx context.Context, servers []string) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, k.askWait)
	defer cancel()
	if len(servers) == 0 {
		return false, "sysntpd has no server"
	}
	addresses := k.resolve(ctx, servers)
	if len(addresses) == 0 {
		return false, "the names of the NTP servers of sysntpd (" + strings.Join(servers, ", ") + ") are not resolved by the DNS servers of the uplinks (" + strings.Join(k.uplinkDNS(), ", ") + ")"
	}
	result, err := Sync(ctx, addresses, Threshold, k.set)
	if err != nil {
		if result.Server != "" {
			// it answered, the clock could not be set
			k.log("warn", "set the clock: "+err.Error())
			return true, ""
		}
		return false, "no NTP server of sysntpd answered: " + err.Error()
	}
	if result.Set {
		k.log("warn", "the clock was "+describe(result.Offset)+"; it is set from the NTP server "+result.Server+" (a server of sysntpd)")
	}
	return true, ""
}

// fromHTTPS is C: the time of the HTTPS answer of the DoH server of the settings.
func (k *Keeper) fromHTTPS(ctx context.Context) (bool, string) {
	server := ""
	if k.DoH != nil {
		server = k.DoH()
	}
	if server == "" {
		return false, "the DNS server of the settings is not DoH, whose HTTPS answer would tell the time"
	}
	ctx, cancel := context.WithTimeout(ctx, k.askWait)
	defer cancel()
	host, port, path := splitDoH(server)
	address := host
	if _, err := netip.ParseAddr(host); err != nil {
		resolved := k.resolve(ctx, []string{host})
		if len(resolved) == 0 {
			return false, "the DoH server " + host + " is not resolved by the DNS servers of the uplinks"
		}
		address, _, _ = net.SplitHostPort(resolved[0])
	}
	told, err := HTTPSTime(ctx, net.JoinHostPort(address, port), host, path, k.roots)
	if err != nil {
		return false, "no time from the DoH server " + host + ": " + err.Error()
	}
	offset := time.Until(told)
	if offset > Threshold || offset < -Threshold {
		err = k.set(told)
		if err != nil {
			k.log("warn", "set the clock: "+err.Error())
			return true, ""
		}
		k.log("warn", "the clock was "+describe(offset)+"; it is set from the HTTPS answer of the DoH server "+host+" (no NTP server of sysntpd answered)")
	}
	return true, ""
}

// dnsAnswers is the condition of B: the DNS of the router (dnsmasq, then sing-box) answers
// a name of sysntpd with an address that is not FakeIP's, within waitDNS. A server given
// by address needs no DNS.
func (k *Keeper) dnsAnswers(ctx context.Context, servers []string) bool {
	var name string
	for _, server := range servers {
		if _, err := netip.ParseAddr(server); err == nil {
			return true
		}
		if name == "" {
			name = server
		}
	}
	if name == "" {
		return false
	}
	deadline := time.Now().Add(k.waitDNS)
	for {
		ask, cancel := context.WithTimeout(ctx, 2*time.Second)
		addresses, err := k.lookup(ask, "", name)
		cancel()
		if err == nil {
			for _, address := range addresses {
				if !dataplane.FakeIPPrefix.Contains(address) {
					return true
				}
			}
		}
		if time.Now().Add(k.tryDNS).After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(k.tryDNS):
		}
	}
}

func (k *Keeper) uplinkDNS() []string {
	if k.UplinkDNS == nil {
		return nil
	}
	return k.UplinkDNS()
}

// resolve turns servers into addresses with the NTP port: an address stays, a name is asked
// of the DNS servers of the uplinks, at once; two addresses a name at the most.
func (k *Keeper) resolve(ctx context.Context, servers []string) []string {
	var addresses []string
	dnsServers := k.uplinkDNS()
	for _, server := range servers {
		if address, err := netip.ParseAddr(server); err == nil {
			addresses = append(addresses, net.JoinHostPort(address.String(), k.ntpPort))
			continue
		}
		for _, dnsServer := range dnsServers {
			found, err := k.lookup(ctx, dnsServer, server)
			if err != nil || len(found) == 0 {
				continue
			}
			for _, address := range found[:min(2, len(found))] {
				addresses = append(addresses, net.JoinHostPort(address.String(), k.ntpPort))
			}
			break
		}
	}
	return addresses
}

// lookupAt resolves a name to IPv4 addresses by a DNS server, directly and never through
// the proxy, or by the resolver of the router when server is empty.
func lookupAt(ctx context.Context, server string, name string) ([]netip.Addr, error) {
	resolver := net.DefaultResolver
	if server != "" {
		resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			dialer := net.Dialer{Control: dataplane.MarkedControl}
			return dialer.DialContext(ctx, network, net.JoinHostPort(server, "53"))
		}}
	}
	return resolver.LookupNetIP(ctx, "ip4", name)
}

// splitDoH reads host[:port][/path] of a DoH server; the port is 443, the path /dns-query
// when not given.
func splitDoH(server string) (host string, port string, path string) {
	rest := server
	if _, after, found := strings.Cut(rest, "://"); found {
		rest = after
	}
	authority := rest
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		authority, path = rest[:slash], rest[slash:]
	}
	host, port = authority, "443"
	if parsedHost, parsedPort, err := net.SplitHostPort(authority); err == nil {
		host, port = parsedHost, parsedPort
	}
	if path == "" {
		path = "/dns-query"
	}
	return host, port, path
}

func describe(offset time.Duration) string {
	if offset < 0 {
		return (-offset).Round(time.Second).String() + " ahead"
	}
	return offset.Round(time.Second).String() + " behind"
}
