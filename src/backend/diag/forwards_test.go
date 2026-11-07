package diag

import (
	"context"
	"net"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// The domains asked about are those a line sends to a server of its own, as a name.
func TestForwarded(t *testing.T) {
	t.Parallel()
	require.Equal(t, []ForwardedDomain{
		{Domain: "ts.net", Line: "/.ts.net/100.100.100.100"},
		{Domain: "corp.example", Line: "/*.corp.example/10.8.0.1"},
		{Domain: "google.example", Line: "/*google.example/192.168.1.5#5353"},
		{Domain: "a.lan", Line: "/a.lan/b.lan/192.168.1.5"},
		{Domain: "b.lan", Line: "/a.lan/b.lan/192.168.1.5"},
	}, Forwarded([]string{"/.ts.net/100.100.100.100", "/*.corp.example/10.8.0.1", "/*google.example/192.168.1.5#5353", "/a.lan/b.lan/192.168.1.5",
		"/lan/", "/www.example/#", "//192.168.1.1", "/1.168.192.in-addr.arpa/192.168.1.1"}))
}

// A forwarded domain the DNS inbound answers from FakeIP is in a list of podkop; one it
// answers otherwise, or not at all, is not.
func TestListedForwards(t *testing.T) {
	t.Parallel()
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &mDNS.Server{PacketConn: connection, Handler: mDNS.HandlerFunc(func(writer mDNS.ResponseWriter, request *mDNS.Msg) {
		reply := new(mDNS.Msg)
		reply.SetReply(request)
		answer := map[string]string{"youtube.com.": "198.18.0.7", "ts.net.": "100.100.100.100"}[request.Question[0].Name]
		if request.Question[0].Name == "silent.example." {
			return
		}
		if answer != "" {
			reply.Answer = append(reply.Answer, &mDNS.A{Hdr: mDNS.RR_Header{Name: request.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60},
				A: net.ParseIP(answer)})
		}
		_ = writer.WriteMsg(reply)
	})}
	go func() { _ = server.ActivateAndServe() }()
	defer server.Shutdown()
	forwarded := Forwarded([]string{"/.ts.net/100.100.100.100", "/youtube.com/silent.example/192.168.1.5", "/nothing.example/192.168.1.5"})
	listed := listedForwards(context.Background(), connection.LocalAddr().String(), forwarded)
	require.Equal(t, []ForwardedDomain{{Domain: "youtube.com", Line: "/youtube.com/silent.example/192.168.1.5"}}, listed)
}

// The page shows the DNS of the LAN as podkop's when the first dnsmasq asks the backend for
// every name: its forwardings for the names of a domain beside it change nothing.
func TestDNSOfLAN(t *testing.T) {
	t.Parallel()
	for content, want := range map[string]bool{
		"config dnsmasq\n\tlist server '127.0.0.42'\n":                                                                  true,
		"config dnsmasq\n\tlist server '127.0.0.42'\n\tlist server '/.ts.net/100.100.100.100'\n\tlist server '/lan/'\n": true,
		"config dnsmasq\n\tlist server '/.ts.net/100.100.100.100'\n\tlist server '127.0.0.42'\n":                        true,
		"config dnsmasq\n\tlist server '127.0.0.42'\n\tlist server '8.8.8.8'\n":                                         false,
		"config dnsmasq\n\tlist server '127.0.0.42'\n\tlist server '/#/1.1.1.1'\n":                                      false,
		"config dnsmasq\n\tlist server '/.ts.net/100.100.100.100'\n":                                                    false,
		"config dhcp 'lan'\n": false,
	} {
		parsed, err := uci.Parse([]byte(content))
		require.NoError(t, err)
		require.Equal(t, want, DNSOfLAN(parsed), content)
	}
}
