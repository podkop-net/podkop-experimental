package diag

import (
	"context"
	"net/netip"
	"strings"
	"sync"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/dnsmasq"

	mDNS "github.com/miekg/dns"
)

// forwardsAsked is how many domains of the forwardings of dnsmasq ListedForwards asks about
// at the most: a report must not wait on a list of hundreds.
const forwardsAsked = 16

// ForwardedDomain is a domain dnsmasq sends to a server of its own, and the line that does.
type ForwardedDomain struct {
	Domain string
	Line   string
}

// Forwarded are the domains of the lines of dnsmasq for the names of a domain that send
// those names to a server (not "/lan/", answered by dnsmasq itself, nor "/example.com/#",
// sent to the servers for every name), as a name to ask about: "*.example.com",
// ".example.com" and "*example.com" as example.com; names without a dot ("//...") and the
// reverse zones are left out.
func Forwarded(lines []string) []ForwardedDomain {
	var result []ForwardedDomain
	for _, line := range lines {
		domains, upstream := dnsmasq.Split(line)
		if upstream == "" || upstream == "#" {
			continue
		}
		for _, domain := range domains {
			name := strings.TrimLeft(domain, "*.")
			if name == "" || strings.HasSuffix(name, ".arpa") {
				continue
			}
			result = append(result, ForwardedDomain{Domain: name, Line: line})
		}
	}
	return result
}

// ListedForwards tells which of the forwarded domains of dnsmasq the backend answers from
// FakeIP: the names of a list of podkop, which dnsmasq sends to a server of their own, so
// that they never get a FakeIP address and go by the rules of the lists only by the
// subnets. The DNS inbound is asked for each, the first forwardsAsked at once.
func ListedForwards(ctx context.Context, forwarded []ForwardedDomain) []ForwardedDomain {
	return listedForwards(ctx, dataplane.DNSServer.String(), forwarded)
}

func listedForwards(ctx context.Context, server string, forwarded []ForwardedDomain) []ForwardedDomain {
	if len(forwarded) > forwardsAsked {
		forwarded = forwarded[:forwardsAsked]
	}
	listed := make([]bool, len(forwarded))
	var group sync.WaitGroup
	for i, domain := range forwarded {
		group.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, probeTimeout)
			defer cancel()
			message := new(mDNS.Msg)
			message.SetQuestion(mDNS.Fqdn(domain.Domain), mDNS.TypeA)
			response, _, err := (&mDNS.Client{Net: "udp", Timeout: probeTimeout}).ExchangeContext(ctx, message, server)
			if err != nil || response == nil {
				return
			}
			for _, record := range response.Answer {
				if address, isAddress := record.(*mDNS.A); isAddress {
					ip, valid := netip.AddrFromSlice(address.A)
					if valid && dataplane.FakeIPPrefix.Contains(ip.Unmap()) {
						listed[i] = true
					}
				}
			}
		})
	}
	group.Wait()
	var result []ForwardedDomain
	for i, domain := range forwarded {
		if listed[i] {
			result = append(result, domain)
		}
	}
	return result
}
