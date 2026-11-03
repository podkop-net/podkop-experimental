package diag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// answering answers every question with one address.
func answering(writer mDNS.ResponseWriter, request *mDNS.Msg) {
	response := new(mDNS.Msg)
	response.SetReply(request)
	record, _ := mDNS.NewRR(request.Question[0].Name + " 60 IN A 192.0.2.1")
	response.Answer = []mDNS.RR{record}
	writer.WriteMsg(response)
}

// refusing replies REFUSED to every question.
func refusing(writer mDNS.ResponseWriter, request *mDNS.Msg) {
	response := new(mDNS.Msg)
	response.SetRcode(request, mDNS.RcodeRefused)
	writer.WriteMsg(response)
}

func serveUDP(t *testing.T) string {
	return serveUDPWith(t, answering)
}

func serveUDPWith(t *testing.T, handler mDNS.HandlerFunc) string {
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &mDNS.Server{PacketConn: connection, Handler: handler}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })
	return connection.LocalAddr().String()
}

// A server of each kind on this host, and a server that is not there.
func TestCheckDNS(t *testing.T) {
	udp := serveUDP(t)
	_, udpPort, _ := net.SplitHostPort(udp)

	// DNS over HTTPS and over TLS behind the certificate of a test server
	web := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/dns-query" && request.URL.Path != "/custom/path" {
			http.NotFound(writer, request)
			return
		}
		body, _ := io.ReadAll(request.Body)
		question := new(mDNS.Msg)
		if question.Unpack(body) != nil {
			http.Error(writer, "no DNS message", http.StatusBadRequest)
			return
		}
		response := new(mDNS.Msg)
		response.SetReply(question)
		packed, _ := response.Pack()
		writer.Header().Set("Content-Type", "application/dns-message")
		writer.Write(packed)
	}))
	web.EnableHTTP2 = true
	web.StartTLS()
	t.Cleanup(web.Close)
	_, httpsPort, _ := net.SplitHostPort(web.Listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(web.Certificate())
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: web.TLS.Certificates})
	require.NoError(t, err)
	overTLS := &mDNS.Server{Listener: listener, Net: "tcp-tls", Handler: mDNS.HandlerFunc(answering)}
	go overTLS.ActivateAndServe()
	t.Cleanup(func() { overTLS.Shutdown() })
	_, tlsPort, _ := net.SplitHostPort(listener.Addr().String())

	// a port nothing listens on
	closed, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	_, closedPort, _ := net.SplitHostPort(closed.LocalAddr().String())
	closed.Close()

	trusting := &probe{roots: roots, localAddress: udp}
	// one server of the list
	one := func(serverType string, server string, bootstrap string) DNSSettings {
		return DNSSettings{Upstreams: []model.DNSUpstream{{Type: serverType, Server: server}}, Mode: "order", Bootstrap: bootstrap}
	}
	for _, test := range []struct {
		settings DNSSettings
		probe    *probe
		want     DNS
	}{
		{one("udp", "127.0.0.1:"+udpPort, "127.0.0.1"), trusting, DNS{ServerAnswers: true, RouterAnswers: true}},
		{one("udp", "127.0.0.1:"+closedPort, ""), trusting, DNS{RouterAnswers: true}},
		{one("dot", "127.0.0.1:"+tlsPort, ""), trusting, DNS{ServerAnswers: true, RouterAnswers: true}},
		{one("doh", "127.0.0.1:"+httpsPort, ""), trusting, DNS{ServerAnswers: true, RouterAnswers: true}},
		{one("doh", "127.0.0.1:"+httpsPort+"/custom/path", ""), trusting, DNS{ServerAnswers: true, RouterAnswers: true}},
		{one("doh", "127.0.0.1:"+httpsPort+"/no/such/path", ""), trusting, DNS{RouterAnswers: true}},
		// the certificate of the server is not trusted: sing-box would not talk to it either
		{one("dot", "127.0.0.1:"+tlsPort, ""), &probe{localAddress: udp}, DNS{RouterAnswers: true}},
		{one("doh", "127.0.0.1:"+httpsPort, ""), &probe{localAddress: udp}, DNS{RouterAnswers: true}},
		// a kind of server the backend does not know, and no server at all
		{one("quic", "127.0.0.1:"+udpPort, ""), trusting, DNS{RouterAnswers: true}},
		{one("udp", "", ""), &probe{localAddress: "127.0.0.1:" + closedPort}, DNS{}},
	} {
		got := test.probe.check(context.Background(), test.settings, nil)
		want := test.want
		upstream := test.settings.Upstreams[0]
		want.Type, want.Server, want.Bootstrap, want.Mode = upstream.Type, upstream.Server, test.settings.Bootstrap, "order"
		want.Upstreams = []DNSUpstreamReport{{Type: upstream.Type, Server: upstream.Server, Answers: want.ServerAnswers}}
		if test.settings.Bootstrap != "" {
			// the bootstrap server is asked at port 53, where this host has nothing
			want.BootstrapAnswers = got.BootstrapAnswers
		}
		require.Equal(t, want, *got, "%+v", test.settings)
	}

	// a list: each server is asked, one that answers is enough; a row of the provider asks the
	// provider's servers
	got := trusting.check(context.Background(), DNSSettings{
		Upstreams: []model.DNSUpstream{{Type: "udp", Server: "127.0.0.1:" + closedPort}, {Type: "provider"}, {Type: "doh", Server: "127.0.0.1:" + httpsPort}},
		Mode:      "fastest",
		Providers: []string{"127.0.0.1:" + closedPort, "127.0.0.1:" + udpPort},
	}, nil)
	require.Equal(t, "fastest", got.Mode)
	require.Equal(t, "udp", got.Type)
	require.True(t, got.ServerAnswers)
	require.Equal(t, []DNSUpstreamReport{
		{Type: "udp", Server: "127.0.0.1:" + closedPort},
		{Type: "provider", Providers: []string{"127.0.0.1:" + closedPort, "127.0.0.1:" + udpPort}, Answers: true},
		{Type: "doh", Server: "127.0.0.1:" + httpsPort, Answers: true},
	}, got.Upstreams)
	// the provider without servers netifd knows does not answer
	got = trusting.check(context.Background(), DNSSettings{Upstreams: []model.DNSUpstream{{Type: "provider"}}}, nil)
	require.False(t, got.ServerAnswers)

	// a server that refuses replies, but does not answer: sing-box asks the next one; a row of
	// the provider answers when one of its servers does
	refuser := serveUDPWith(t, refusing)
	got = trusting.check(context.Background(), DNSSettings{
		Upstreams: []model.DNSUpstream{{Type: "udp", Server: refuser}, {Type: "provider"}},
		Providers: []string{refuser, udp},
	}, nil)
	require.True(t, got.ServerAnswers)
	require.Equal(t, []DNSUpstreamReport{
		{Type: "udp", Server: refuser, Refusal: "REFUSED"},
		{Type: "provider", Providers: []string{refuser, udp}, Answers: true},
	}, got.Upstreams)
	got = trusting.check(context.Background(), DNSSettings{Upstreams: []model.DNSUpstream{{Type: "provider"}}, Providers: []string{refuser, "127.0.0.1:" + closedPort}}, nil)
	require.False(t, got.ServerAnswers)
	require.Equal(t, "REFUSED", got.Upstreams[0].Refusal)
	// the resolver of the router counts as there when it refuses
	got = (&probe{localAddress: refuser}).check(context.Background(), one("udp", refuser, ""), nil)
	require.True(t, got.RouterAnswers)
	require.False(t, got.ServerAnswers)
}

func TestMaskServer(t *testing.T) {
	t.Parallel()
	for server, want := range map[string]string{
		"1.1.1.1":                    "1.1.1.1",
		"dns.google/dns-query":       "dns.google/dns-query",
		"abc123.dns.nextdns.io":      "******.dns.nextdns.io",
		"dns.nextdns.io/abc123":      "dns.nextdns.io/******",
		"dns.nextdns.io/abc123/home": "dns.nextdns.io/***********",
		"dns.nextdns.io":             "dns.nextdns.io",
	} {
		require.Equal(t, want, maskServer(server))
	}
}

func TestDnsmasqAsksBackend(t *testing.T) {
	t.Parallel()
	for content, want := range map[string]bool{
		"config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n":                           true,
		"config dnsmasq\n\tlist server '9.9.9.9'\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n":  true,
		"config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '150'\n":                         false,
		"config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '0'\n\toption cachesize '0'\n":                           false,
		"config dnsmasq\n\tlist server '127.0.0.4'\n\toption noresolv '1'\n\toption cachesize '0'\n":                            false,
		"config dnsmasq\n\toption noresolv '1'\n\toption cachesize '0'\n":                                                       false,
		"config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n\nconfig dnsmasq 'guest'\n": false,
		"config dhcp 'lan'\n\toption interface 'lan'\n":                                                                         true,
	} {
		parsed, err := uci.Parse([]byte(content))
		require.NoError(t, err)
		require.Equal(t, want, dnsmasqAsksBackend(parsed), content)
	}
	require.False(t, dnsmasqAsksBackend(nil))
}
