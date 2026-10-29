package diag

import (
	"bufio"
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/firewall"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	checkname "github.com/podkop-net/podkop-experimental/src/backend/probe"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	mDNS "github.com/miekg/dns"
)

// The checks tell what they found as values; the commands of the user interface print
// them in the shapes the shell backend printed (ctl).

// what the shell backend gives each of its web requests
const webTimeout = 3 * time.Second

// get asks a page from the router itself, as a program on it would: the system resolver,
// the routing of the router. It returns the body, nil when the page did not come.
func get(ctx context.Context, address string, timeout time.Duration) []byte {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil
	}
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil
	}
	return body
}

// Firewall is what the check of the firewall table found: whether the table and each of
// its three chains are there, and whether the chains have counted packets.
type Firewall struct {
	Table               bool
	Mangle              bool
	MangleCounted       bool
	MangleOutput        bool
	MangleOutputCounted bool
	Proxy               bool
	ProxyCounted        bool
	// ForeignMarks are the chains of other tables that set a packet mark.
	ForeignMarks []string
}

// how often the table is read while the requests of CheckFirewall are on their way
const counterPollInterval = 50 * time.Millisecond

// routerChainsCounted tells whether the chains a request of the router itself passes have counted
// packets. The third chain counts what the devices of the LAN send: nothing made here
// reaches it.
func routerChainsCounted(state *firewall.State) bool {
	return state != nil && state.MangleOutput.Counted && state.Proxy.Counted
}

// CheckFirewall reads the table: whether its chains are there and whether their rules
// have counted anything. On a router that has carried traffic that is all, and takes no
// time. Where the chains a connection of the router itself passes have not counted yet,
// such a connection is opened, to a check name (see the package probe), and the table is
// read again as soon as they have counted, or when the connection is over. The shell
// backend asks two pages of a server outside every time, waits for both and a second
// more: its answer is the same, later, and needs that server.
//
// The third chain counts what the devices of the LAN send, and nothing made on the router
// reaches it. Who asks from such a device opens a connection to a check name itself and
// passes awaitDevice, which returns when that connection has come or will not: only where
// the chain has not counted yet it is waited for. Nobody waits for the device to learn
// what became of its connection.
func CheckFirewall(ctx context.Context, awaitDevice func(context.Context)) *Firewall {
	report := new(Firewall)
	state, err := firewall.Inspect()
	if state != nil && state.Table && !state.Mangle.Counted && awaitDevice != nil {
		awaitDevice(ctx)
		state, err = firewall.Inspect()
	}
	if state != nil && state.Table && !routerChainsCounted(state) {
		over := make(chan struct{})
		go func() {
			_, _ = checkname.Knock(ctx, checkname.NewLabel())
			close(over)
		}()
		for waiting := true; waiting; {
			select {
			case <-over:
				waiting = false
			case <-time.After(counterPollInterval):
			}
			state, err = firewall.Inspect()
			if routerChainsCounted(state) {
				break
			}
		}
	}
	if state == nil || err != nil && !state.Table {
		return report
	}
	report.Table = state.Table
	report.Mangle, report.MangleCounted = state.Mangle.Exists, state.Mangle.Counted
	report.MangleOutput, report.MangleOutputCounted = state.MangleOutput.Exists, state.MangleOutput.Counted
	report.Proxy, report.ProxyCounted = state.Proxy.Exists, state.Proxy.Counted
	report.ForeignMarks = state.ForeignMarks
	return report
}

// SingBox is what the check of sing-box found. The shell backend looks at a package and
// a service of its own; here sing-box is a part of the backend, so it is installed, of a
// version that fits and without a service of its own to misconfigure by construction.
// What can be wrong is whether it runs and listens.
type SingBox struct {
	Running   bool
	Listening bool
}

// CheckSingBox tells whether sing-box runs and listens where the LAN's DNS and the
// firewall send to. Running is told by the caller, which knows how to ask the backend.
func CheckSingBox(running bool) *SingBox {
	return &SingBox{
		Running:   running,
		Listening: listens("/proc/net/udp", net.ParseIP(dataplane.DNSAddress), dataplane.DNSPort, "") && listens("/proc/net/tcp", net.ParseIP(dataplane.TProxyAddress), dataplane.TProxyPort, "0A"),
	}
}

// listens looks a socket up in a table of the kernel's sockets: the address as the kernel
// writes it, the bytes of this machine's order in hexadecimal, and for TCP the state.
func listens(path string, address net.IP, port uint16, state string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	four := address.To4()
	// the kernel prints the address as one number of the host's byte order
	want := strings.ToUpper(hex.EncodeToString(hostOrder(four))) + ":" + strings.ToUpper(hex.EncodeToString([]byte{byte(port >> 8), byte(port)}))
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 3 && fields[1] == want && (state == "" || fields[3] == state) {
			return true
		}
	}
	return false
}

// System is the versions and the device.
type System struct {
	PodkopVersion       string
	PodkopLatestVersion string
	LuCIAppVersion      string
	SingBoxVersion      string
	OpenWrtVersion      string
	DeviceModel         string
}

// the releases of podkop-exp; podkop of itdoginfo/podkop is another package (a variable for
// the tests)
var latestReleaseURL = "https://api.github.com/repos/podkop-net/podkop-experimental/releases/latest"

var (
	tagName        = regexp.MustCompile(`"tag_name":\s*"([^"]*)"`)
	luciAppVersion = regexp.MustCompile(`var PODKOP_LUCI_APP_VERSION[^"]*"([^"]*)"`)
	openWrtRelease = regexp.MustCompile(`(?m)^OPENWRT_RELEASE="([^"]*)"`)
)

// SystemInfo collects the versions and the model of the device: of the backend and of the
// sing-box it runs, which are one binary. With askLatest, the latest release of podkop is
// asked from the site that publishes it: the one part of the answer that waits. The page asks
// it from the browser itself, so only the global check has the router ask.
func SystemInfo(ctx context.Context, version string, singBoxVersion string, askLatest bool) *System {
	report := &System{PodkopVersion: version, SingBoxVersion: singBoxVersion, PodkopLatestVersion: "unknown", LuCIAppVersion: "not installed"}
	report.OpenWrtVersion, report.DeviceModel = Device()
	if askLatest {
		if found := tagName.FindSubmatch(get(ctx, latestReleaseURL, webTimeout)); found != nil && len(found[1]) > 0 {
			report.PodkopLatestVersion = string(found[1])
		}
	}
	if content, err := os.ReadFile("/www/luci-static/resources/view/podkop/main.js"); err == nil {
		report.LuCIAppVersion = ""
		if found := luciAppVersion.FindSubmatch(content); found != nil {
			report.LuCIAppVersion = string(found[1])
		}
	}
	return report
}

// Device returns the release of OpenWrt and the model of the device as the system files
// name them, "unknown" for what they do not tell.
func Device() (release string, model string) {
	release, model = "unknown", "unknown"
	if content, err := os.ReadFile("/etc/os-release"); err == nil {
		if found := openWrtRelease.FindSubmatch(content); found != nil && len(found[1]) > 0 {
			release = string(found[1])
		}
	}
	if content, err := os.ReadFile("/tmp/sysinfo/model"); err == nil && len(strings.TrimSpace(string(content))) > 0 {
		model = strings.TrimRight(string(content), "\n")
	}
	return release, model
}

// FakeIPAddress asks the DNS inbound for the test name and returns the first address of
// the answer, empty when there is none.
func FakeIPAddress(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	message := new(mDNS.Msg)
	message.SetQuestion(mDNS.Fqdn(dataplane.ReadinessName), mDNS.TypeA)
	response, _, err := (&mDNS.Client{Net: "udp", Timeout: probeTimeout}).ExchangeContext(ctx, message, dataplane.DNSServer.String())
	if err != nil {
		return ""
	}
	for _, record := range response.Answer {
		if address, isAddress := record.(*mDNS.A); isAddress {
			return address.A.String()
		}
	}
	return ""
}

// the options of the settings whose values are not shown: links, outbounds, secrets
var secretOptions = []string{"option proxy_string", "option outbound_json", "list urltest_proxy_links", "list urltest_fallback_links", "list selector_proxy_links", "option yacd_secret_key",
	// the address of a subscription: its token is the account
	"option url",
	// the links of a source of servers
	"list link", "option link"}

// the path of a DNS server may hold the identifier of an account
var serverPath = regexp.MustCompile(`(option (?:dns_server|domain_resolver_dns_server) '[^/']*)/[^']*'`)

// MaskSettings returns the settings file with what must not be shown replaced by the
// word MASKED, the lines otherwise as they are. A value that goes on over several lines,
// as an outbound written by hand does, is replaced whole.
func MaskSettings(content []byte) string {
	var result strings.Builder
	inside := false
	for _, line := range strings.SplitAfter(string(content), "\n") {
		if inside {
			// the value ends at the line that closes its quote
			inside = quoted(line, true)
			continue
		}
		masked := false
		for _, option := range secretOptions {
			at := strings.Index(line, option)
			if at < 0 || strings.TrimSpace(line[:at]) != "" {
				continue
			}
			// the whole name: "option url" is not "option urltest_testing_url"
			if rest := line[at+len(option):]; rest != "" && !strings.ContainsRune(" \t'", rune(rest[0])) {
				continue
			}
			result.WriteString(line[:at] + option + " 'MASKED'\n")
			inside = quoted(line[at+len(option):], false)
			masked = true
			break
		}
		if !masked {
			result.WriteString(serverPath.ReplaceAllString(line, "$1/MASKED'"))
		}
	}
	return result.String()
}

// quoted follows the single quotes of a line of a UCI file and tells whether the line
// ends inside a quoted value, given whether it began inside one. Outside the quotes a
// backslash takes the next character for itself: a quote within a value is written '\”.
func quoted(line string, inside bool) bool {
	for index := 0; index < len(line); index++ {
		switch {
		case line[index] == '\'':
			inside = !inside
		case line[index] == '\\' && !inside:
			index++
		}
	}
	return inside
}

// the keys of a sing-box configuration whose values are not shown wherever they are: those
// the shell backend hides
var secretKeys = []string{"uuid", "server", "server_name", "password", "public_key", "short_id", "fingerprint", "server_port"}

// and the keys hidden below a place only: what an outbound may carry of a user's
// credentials (outbound_json included, so whatever its kind), the path of a DoH server (the
// identifier of an account), the secret of the Clash API. Elsewhere such a key is a plain
// value: the path of a rule-set, the headers of a download.
var secretKeysBelow = map[string][]string{
	"outbounds":              outboundSecrets,
	"endpoints":              outboundSecrets,
	"dns.servers":            {"path", "headers"},
	"experimental.clash_api": {"secret"},
}

var outboundSecrets = []string{
	"encryption", "username", "user", "auth", "auth_str", "token", "psk", "obfs", "plugin_opts",
	"private_key", "private_key_passphrase", "pre_shared_key", "key",
	// of a transport, xhttp's above all: a token may ride in a header or in the extra
	// options
	"headers", "extra",
}

// secret tells whether the value of a key of a sing-box configuration is not shown.
func secret(path string, key string) bool {
	if slices.Contains(secretKeys, key) {
		return true
	}
	for below, keys := range secretKeysBelow {
		if (path == below || strings.HasPrefix(path, below+".")) && slices.Contains(keys, key) {
			return true
		}
	}
	return false
}

// MaskConfig returns a sing-box configuration that can be shown to others.
func MaskConfig(content []byte) ([]byte, error) {
	return plan.Masked(content, secret)
}

// DNSOfLAN tells whether the first dnsmasq of the settings asks the backend alone.
func DNSOfLAN(dhcp *uci.Package) bool {
	if dhcp == nil {
		return false
	}
	sections := dhcp.SectionsOfType("dnsmasq")
	return len(sections) > 0 && sections[0].Get("server") == dataplane.DNSAddress
}
