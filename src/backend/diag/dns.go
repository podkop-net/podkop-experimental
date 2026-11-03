// Package diag holds the checks the backend runs for its user interface.
package diag

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	mDNS "github.com/miekg/dns"
)

const (
	// probeName is the name every probe asks for, the one the shell backend asks for.
	probeName = "google.com."
	// probeTimeout is what the shell backend gives its DNS tool: one try of two seconds.
	probeTimeout = 2 * time.Second
)

// DNS is what the check of the DNS found.
type DNS struct {
	// Type, Server and Bootstrap are those of the settings, Type and Server of the first
	// server of the list; an account in the address of a server is masked.
	Type      string
	Server    string
	Bootstrap string
	// Mode is how the servers of the list are asked, Upstreams what each of them did
	Mode      string
	Upstreams []DNSUpstreamReport
	// ServerAnswers, RouterAnswers and BootstrapAnswers tell who answered: a server of the
	// list, the resolver of the router, the bootstrap server.
	ServerAnswers    bool
	RouterAnswers    bool
	BootstrapAnswers bool
	// DHCPAsksBackend tells whether dnsmasq is set up to ask the backend.
	DHCPAsksBackend bool
}

// DNSUpstreamReport is what the check found of a server of the list. Providers are the
// provider's servers netifd knows, for a row of the provider. Answers: it answered (NOERROR
// or NXDOMAIN). Refusal is the rcode of a server that replied with another one (REFUSED,
// SERVFAIL): it is there, but sing-box asks the next server, as it would of one that is not.
type DNSUpstreamReport struct {
	Type      string
	Server    string
	Providers []string
	Answers   bool
	Refusal   string
}

// DNSSettings is what the check needs of the settings, as written there. Providers are the DNS
// servers of the uplinks netifd knows: what a row of the provider asks.
type DNSSettings struct {
	Upstreams []model.DNSUpstream
	Mode      string
	Providers []string
	Bootstrap string
}

// probe is the settings of the probes; a test replaces the trusted certificates and the
// ports the local resolver is at.
type probe struct {
	roots        *x509.CertPool
	localAddress string
}

// CheckDNS asks the DNS server of the settings, the resolver of the router and the
// bootstrap server for a name, each from the router itself and not through the proxy, and
// tells whether dnsmasq is set up to ask the backend. The three questions are asked at
// once: the check takes the time of the slowest.
//
// Where it differs from the shell backend, which runs dig: a port in the setting is used
// (dig is given "host:port" as a name and fails), and the certificate of a DoT or DoH
// server is verified as sing-box verifies it (dig does not look at it).
func CheckDNS(ctx context.Context, settings DNSSettings, dhcp *uci.Package) *DNS {
	return (&probe{localAddress: "127.0.0.1:53"}).check(ctx, settings, dhcp)
}

func (p *probe) check(ctx context.Context, settings DNSSettings, dhcp *uci.Package) *DNS {
	report := &DNS{
		Mode:            settings.Mode,
		Bootstrap:       settings.Bootstrap,
		DHCPAsksBackend: dnsmasqAsksBackend(dhcp),
	}
	for _, upstream := range settings.Upstreams {
		row := DNSUpstreamReport{Type: upstream.Type, Server: maskServer(upstream.Server)}
		if upstream.Type == model.DNSTypeProvider {
			row.Providers = settings.Providers
		}
		report.Upstreams = append(report.Upstreams, row)
	}
	if len(report.Upstreams) > 0 {
		report.Type, report.Server = report.Upstreams[0].Type, report.Upstreams[0].Server
	}
	// every server of the list, the router and the bootstrap server are asked at once
	results := make(chan func(), len(settings.Upstreams)+2)
	for index, upstream := range settings.Upstreams {
		go func() {
			rcode := p.listed(ctx, upstream, settings.Providers)
			results <- func() {
				row := &report.Upstreams[index]
				row.Answers = answers(rcode)
				if rcode != noReply && !row.Answers {
					row.Refusal = mDNS.RcodeToString[rcode]
				}
				report.ServerAnswers = report.ServerAnswers || row.Answers
			}
		}()
	}
	go func() {
		ok := p.plain(ctx, p.localAddress)
		results <- func() { report.RouterAnswers = ok }
	}()
	go func() {
		ok := settings.Bootstrap != "" && p.plain(ctx, net.JoinHostPort(settings.Bootstrap, "53"))
		results <- func() { report.BootstrapAnswers = ok }
	}()
	for range len(settings.Upstreams) + 2 {
		(<-results)()
	}
	return report
}

// noReply is the rcode of a probe that got no reply.
const noReply = -1

// answers tells whether an rcode is an answer, as the DNS servers of the type group of the
// engine count it.
func answers(rcode int) bool {
	return rcode == mDNS.RcodeSuccess || rcode == mDNS.RcodeNameError
}

// listed asks a server of the list for the rcode of its reply; a row of the provider answers
// when one of its servers does, and refuses when none answers and one refuses.
func (p *probe) listed(ctx context.Context, upstream model.DNSUpstream, providers []string) int {
	if upstream.Type != model.DNSTypeProvider {
		return p.upstream(ctx, upstream.Type, upstream.Server)
	}
	replies := make(chan int, len(providers))
	for _, server := range providers {
		address := server
		if _, _, err := net.SplitHostPort(server); err != nil {
			address = net.JoinHostPort(server, "53")
		}
		go func() { replies <- p.plainReply(ctx, address) }()
	}
	best := noReply
	for range providers {
		rcode := <-replies
		if answers(rcode) {
			return rcode
		}
		if best == noReply {
			best = rcode
		}
	}
	return best
}

func (p *probe) upstream(ctx context.Context, serverType string, server string) int {
	host, port, path := plan.SplitServer(server)
	if host == "" {
		return noReply
	}
	switch serverType {
	case "udp":
		return p.plainReply(ctx, net.JoinHostPort(host, orDefault(port, "53")))
	case "dot":
		return p.overTLS(ctx, host, orDefault(port, "853"))
	case "doh":
		return p.overHTTPS(ctx, host, orDefault(port, "443"), orDefault(path, "/dns-query"))
	}
	return noReply
}

func orDefault(value string, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

func question() *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion(probeName, mDNS.TypeA)
	return message
}

// plain asks a resolver over UDP. Any reply counts, a refusal included: the resolver of the
// router or the bootstrap server is there.
func (p *probe) plain(ctx context.Context, address string) bool {
	return p.plainReply(ctx, address) != noReply
}

// plainReply asks over UDP for the rcode of the reply.
func (p *probe) plainReply(ctx context.Context, address string) int {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	client := &mDNS.Client{Net: "udp", Timeout: probeTimeout}
	return rcodeOf(client.ExchangeContext(ctx, question(), address))
}

func rcodeOf(reply *mDNS.Msg, _ time.Duration, err error) int {
	if err != nil || reply == nil {
		return noReply
	}
	return reply.Rcode
}

func (p *probe) overTLS(ctx context.Context, host string, port string) int {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	client := &mDNS.Client{Net: "tcp-tls", Timeout: probeTimeout, TLSConfig: &tls.Config{ServerName: host, RootCAs: p.roots}}
	return rcodeOf(client.ExchangeContext(ctx, question(), net.JoinHostPort(host, port)))
}

func (p *probe) overHTTPS(ctx context.Context, host string, port string, path string) int {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	packed, err := question().Pack()
	if err != nil {
		return noReply
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+net.JoinHostPort(host, port)+path, bytes.NewReader(packed))
	if err != nil {
		return noReply
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	transport := &http.Transport{ForceAttemptHTTP2: true, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: p.roots}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return noReply
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return noReply
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65535))
	if err != nil {
		return noReply
	}
	reply := new(mDNS.Msg)
	if reply.Unpack(body) != nil {
		return noReply
	}
	return reply.Rcode
}

// maskServer hides the identifier of a NextDNS account, which is a part of the server's
// name or path: the report is shown and copied into bug reports.
func maskServer(server string) string {
	const suffix = ".dns.nextdns.io"
	const prefix = "dns.nextdns.io/"
	if strings.HasSuffix(server, suffix) {
		identifier, _, _ := strings.Cut(server, ".")
		return strings.Repeat("*", len(identifier)) + suffix
	}
	if rest, found := strings.CutPrefix(server, prefix); found {
		return prefix + strings.Repeat("*", len(rest))
	}
	return server
}

// dnsmasqAsksBackend tells whether every dnsmasq of the settings sends its questions to
// the backend and keeps no cache of its own. With no dnsmasq at all the answer is yes, as
// the shell backend has it.
func dnsmasqAsksBackend(dhcp *uci.Package) bool {
	if dhcp == nil {
		return false
	}
	for _, section := range dhcp.SectionsOfType("dnsmasq") {
		asks := false
		for _, server := range strings.Fields(section.Get("server")) {
			if server == dataplane.DNSAddress {
				asks = true
				break
			}
		}
		if section.Get("cachesize") != "0" || section.Get("noresolv") != "1" || !asks {
			return false
		}
	}
	return true
}
