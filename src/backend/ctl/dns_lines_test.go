package ctl

import (
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/diag"
	"github.com/stretchr/testify/require"
)

func TestDNSServerLines(t *testing.T) {
	t.Parallel()
	// one server: the line before the list
	one := &diag.DNS{Type: "doh", Server: "1.1.1.1", ServerAnswers: true, Upstreams: []diag.DNSUpstreamReport{{Type: "doh", Server: "1.1.1.1", Answers: true}}}
	require.Equal(t, []string{"✅ Main DNS: 1.1.1.1 [doh]"}, dnsServerLines(one))

	// the provider alone tells how many servers it has, not their addresses
	provider := &diag.DNS{Type: "provider", Upstreams: []diag.DNSUpstreamReport{{Type: "provider", Providers: []string{"192.0.2.53", "192.0.2.54"}}}}
	require.Equal(t, []string{"❌ Main DNS: the provider's DNS (2 servers known to netifd)"}, dnsServerLines(provider))

	list := &diag.DNS{Mode: "fastest", ServerAnswers: true, Upstreams: []diag.DNSUpstreamReport{
		{Type: "udp", Server: "77.88.8.8"},
		{Type: "provider", Providers: []string{"192.0.2.53"}, Answers: true},
	}}
	require.Equal(t, []string{
		"ℹ️ DNS servers: 2, asked the fastest first",
		"❌ DNS 1: 77.88.8.8 [udp]",
		"✅ DNS 2: the provider's DNS (1 server known to netifd)",
	}, dnsServerLines(list))
	list.Mode = "order"
	require.Equal(t, "ℹ️ DNS servers: 2, asked in their order", dnsServerLines(list)[0])

	// a server that replies with a refusal is not counted as answering, and says so
	list.Upstreams[0].Refusal = "REFUSED"
	require.Equal(t, "❌ DNS 1: 77.88.8.8 [udp] (replies REFUSED)", dnsServerLines(list)[1])
	refusing := &diag.DNS{Type: "udp", Server: "77.88.8.8", Upstreams: []diag.DNSUpstreamReport{{Type: "udp", Server: "77.88.8.8", Refusal: "SERVFAIL"}}}
	require.Equal(t, []string{"❌ Main DNS: 77.88.8.8 [udp] (replies SERVFAIL)"}, dnsServerLines(refusing))
}
