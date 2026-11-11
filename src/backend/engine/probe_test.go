package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/detect"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

const probeUUID = "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"

// a public key of REALITY no server of these tests has
const probePublicKey = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"

// probeInstance is a started instance of the shape the backend makes, its fallback as told, with
// the outbounds given.
func probeInstance(t *testing.T, fallback bool, outbounds ...string) *Instance {
	t.Helper()
	config := fmt.Sprintf(`{
  "log": {"disabled": true},
  "outbounds": [{"type": "direct", "tag": "direct-out"}%s],
  "route": {"final": "direct-out"},
  "experimental": {"utls_fallback": {"enabled": %v}, "cache_file": {"enabled": true, "path": %q}}
}`, ","+strings.Join(outbounds, ","), fallback, filepath.Join(t.TempDir(), "cache.db"))
	instance, err := Build([]byte(config))
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close(10 * time.Second) })
	return instance
}

// probeServer is the outbound of a VLESS server with TLS, what is after the port as JSON.
func probeServer(tag string, host string, port int, tls string) string {
	return fmt.Sprintf(`{"type": "vless", "tag": %q, "server": %q, "server_port": %d, "uuid": %q, "tls": {"enabled": true, "insecure": true%s}}`, tag, host, port, probeUUID, tls)
}

// tlsListener is a server that completes the TLS handshake, then closes the connection.
func tlsListener(t *testing.T, network string, address string) (*net.TCPAddr, *atomic.Int32) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "probe.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Skip("cannot listen here: ", network, " ", address)
	}
	t.Cleanup(func() { listener.Close() })
	accepted := new(atomic.Int32)
	config := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				server := tls.Server(conn, config)
				_ = server.SetDeadline(time.Now().Add(5 * time.Second))
				_ = server.Handshake()
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr), accepted
}

// silentListener takes connections and never answers.
func silentListener(t *testing.T) (*net.TCPAddr, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	t.Cleanup(func() {
		listener.Close()
		close(done)
	})
	accepted := new(atomic.Int32)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				<-done
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr), accepted
}

// closingListener closes every connection as it comes.
func closingListener(t *testing.T) *net.TCPAddr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			buffer := make([]byte, 4096)
			_, _ = conn.Read(buffer)
			conn.Close()
		}
	}()
	return listener.Addr().(*net.TCPAddr)
}

func within(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// The probe's context has the fallback off and no cache file; the instance keeps its own.
func TestProbeContext(t *testing.T) {
	instance := probeInstance(t, true)
	ctx := instance.probeContext()
	require.False(t, service.FromContext[*option.UTLSFallbackOptions](ctx).Enabled)
	require.Nil(t, service.FromContext[adapter.CacheFile](ctx))
	require.NotNil(t, service.FromContext[adapter.OutboundRegistry](ctx))
	require.NotNil(t, service.FromContext[adapter.Router](ctx))

	require.True(t, service.FromContext[*option.UTLSFallbackOptions](instance.ctx).Enabled)
	require.NotNil(t, service.FromContext[adapter.CacheFile](instance.ctx))
}

// A probe with the fallback off makes one try, and its failure stays out of what the running
// outbound recorded: a dial of that one still goes by its fallback, and its record does not move.
func TestProbeLeavesTheRunningOutboundAlone(t *testing.T) {
	address, _ := tlsListener(t, "tcp", "127.0.0.1:0")
	silent, tries := silentListener(t)
	running := probeServer("running", "127.0.0.1", address.Port, `, "utls": {"enabled": true, "fingerprint": "chrome"}`)
	instance := probeInstance(t, true, running)
	server := detect.Server{Tag: "running", Content: []byte(running)}
	cache := service.FromContext[adapter.CacheFile](instance.ctx)
	key := "chrome 127.0.0.1 127.0.0.1:" + fmt.Sprint(address.Port)

	ctx, cancel := within(10 * time.Second)
	defer cancel()
	conn, err := instance.Dial(ctx, "running", "example.test:80")
	require.NoError(t, err)
	conn.Close()
	// the name of the candidate is the mark of the fallback: without it the engine records "chrome"
	var flags byte
	var fingerprint string
	var at time.Time
	require.Eventually(t, func() bool {
		var loaded bool
		flags, fingerprint, at, loaded = cache.LoadDetectOutcome(key)
		return loaded
	}, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, "chrome without X25519MLKEM768", fingerprint)
	require.Zero(t, flags)
	choice, choiceAt, chosen := cache.LoadUTLSChoice(key)

	// a handshake of the probe: another fingerprint, the same server
	attempt := instance.Prober().Fetch(ctx, server, detect.ProbeRequest{Fingerprint: "firefox"})
	require.True(t, attempt.Handshake, "class %q", attempt.Class)
	_, _, _, other := cache.LoadDetectOutcome("firefox 127.0.0.1 127.0.0.1:" + fmt.Sprint(address.Port))
	require.False(t, other, "a probe records nothing under a key of its own")

	// a hello without an answer: one try, no candidates after it
	frozen := probeServer("frozen", "127.0.0.1", silent.Port, `, "utls": {"enabled": true, "fingerprint": "chrome"}`)
	shortCtx, shortCancel := within(300 * time.Millisecond)
	defer shortCancel()
	attempt = instance.Prober().Fetch(shortCtx, detect.Server{Tag: "frozen", Content: []byte(frozen)}, detect.ProbeRequest{Fingerprint: "chrome", URL: detect.ProbeTarget})
	require.Equal(t, detect.Attempt{Class: detect.ClassNoHello}, attempt)
	require.Equal(t, int32(1), tries.Load())
	_, _, _, recorded := cache.LoadDetectOutcome("chrome 127.0.0.1 127.0.0.1:" + fmt.Sprint(silent.Port))
	require.False(t, recorded, "a probe writes no outcome")

	time.Sleep(50 * time.Millisecond)
	flagsAfter, fingerprintAfter, atAfter, _ := cache.LoadDetectOutcome(key)
	require.Equal(t, flags, flagsAfter)
	require.Equal(t, fingerprint, fingerprintAfter)
	require.True(t, at.Equal(atAfter))
	choiceAfter, choiceAtAfter, chosenAfter := cache.LoadUTLSChoice(key)
	require.Equal(t, chosen, chosenAfter)
	require.Equal(t, choice, choiceAfter)
	require.True(t, choiceAt.Equal(choiceAtAfter))
}

// What a copy changes: multiplex goes, the fingerprint and the detour are as asked, the outbound
// of the instance is left as it is.
func TestDecodeProbeOutbound(t *testing.T) {
	instance := probeInstance(t, true)
	content := []byte(`{"type": "vless", "tag": "a", "server": "192.0.2.1", "server_port": 443, "uuid": "` + probeUUID + `",
		"tls": {"enabled": true, "server_name": "a.example", "utls": {"enabled": true, "fingerprint": "chrome"}},
		"multiplex": {"enabled": true, "protocol": "h2mux"}}`)
	decoded, err := instance.decodeProbeOutbound(content, ProbeOptions{Fingerprint: "firefox", Detour: "direct-out"})
	require.NoError(t, err)
	options := decoded.Options.(*option.VLESSOutboundOptions)
	require.Nil(t, options.Multiplex)
	require.Equal(t, "firefox", options.TLS.UTLS.Fingerprint)
	require.Equal(t, "a.example", options.TLS.ServerName)
	require.Equal(t, "direct-out", options.Detour)
	plain, err := instance.decodeProbeOutbound(content, ProbeOptions{})
	require.NoError(t, err)
	require.Equal(t, "chrome", plain.Options.(*option.VLESSOutboundOptions).TLS.UTLS.Fingerprint)
	require.Empty(t, plain.Options.(*option.VLESSOutboundOptions).Detour)

	// Spoof sets tls.spoof on the copy, for SuggestMask to probe a whitelisted name
	spoofed, err := instance.decodeProbeOutbound(content, ProbeOptions{Spoof: "packagist.org"})
	require.NoError(t, err)
	require.Equal(t, "packagist.org", spoofed.Options.(*option.VLESSOutboundOptions).TLS.Spoof)

	_, err = instance.decodeProbeOutbound([]byte(`{"type": "no-such-type", "tag": "a"}`), ProbeOptions{})
	require.Error(t, err)
}

// The classes of errors, as the engine words them.
func TestProbeErrorClass(t *testing.T) {
	dialTimeout := &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	for _, testCase := range []struct {
		err   error
		class detect.ErrorClass
	}{
		{nil, detect.ClassNone},
		{dialTimeout, detect.ClassNoTCP},
		{E.Cause(dialTimeout, "dial server"), detect.ClassNoTCP},
		{&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, detect.ClassNoTCP},
		{&net.DNSError{Err: "no such host", Name: "x.example"}, detect.ClassDNS},
		{&net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "x.example"}}, detect.ClassDNS},
		// dns.Router.Lookup, over a connection that failed
		{E.Cause(&net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, "lookup x.example"), detect.ClassDNS},
		// common/tls: realityVerificationFailed and verificationFailed
		{E.New("reality verification failed"), detect.ClassVerify},
		{E.Cause(os.ErrDeadlineExceeded, "reality verification failed, possibly because of the uTLS fingerprint edge: a note"), detect.ClassVerify},
		{E.Cause(x509.UnknownAuthorityError{}, "tls: failed to verify certificate"), detect.ClassVerify},
		{x509.HostnameError{Certificate: &x509.Certificate{}, Host: "a.example"}, detect.ClassVerify},
		{E.Cause(x509.CertificateInvalidError{Reason: x509.Expired}, "tls: failed to verify certificate"), detect.ClassClock},
		{context.DeadlineExceeded, detect.ClassNoHello},
		{E.Cause(context.DeadlineExceeded, "TLS handshake"), detect.ClassNoHello},
		{os.ErrDeadlineExceeded, detect.ClassNoHello},
		{&net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, detect.ClassNoHello},
		{context.Canceled, detect.ClassCanceled},
		{ErrClosed, detect.ClassCanceled},
		{&net.OpError{Op: "read", Err: net.ErrClosed}, detect.ClassCanceled},
		{io.EOF, detect.ClassCut},
		{E.Cause(io.ErrUnexpectedEOF, "TLS handshake"), detect.ClassCut},
		{&net.OpError{Op: "read", Err: syscall.ECONNRESET}, detect.ClassCut},
		// QUIC: a timeout with its type, and what xhttp over h3 leaves of it (hideHTTPError)
		{&quic.IdleTimeoutError{}, detect.ClassNoHello},
		{&quic.HandshakeTimeoutError{}, detect.ClassNoHello},
		{errors.New(E.Cause(&quic.IdleTimeoutError{}, "xhttp: download").Error()), detect.ClassNoHello},
		{errors.New(E.Cause(&quic.HandshakeTimeoutError{}, "xhttp: upload").Error()), detect.ClassNoHello},
		{errors.New("xhttp: download: H3_REQUEST_REJECTED"), detect.ClassOther},
		{errors.New("remote error: tls: bad certificate"), detect.ClassOther},
	} {
		require.Equal(t, testCase.class, ProbeErrorClass(testCase.err), "%v", testCase.err)
	}
}

// A deadline that ends a lookup is no failure of TCP; of anything else, the context tells.
func TestClassAt(t *testing.T) {
	lookup := E.Cause(context.DeadlineExceeded, "lookup x.example")
	dial := &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	ended, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	canceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	require.Equal(t, detect.ClassDNS, classAt(ended, lookup))
	require.Equal(t, detect.ClassNoHello, classAt(ended, dial), "the error may be of the connection closed for the deadline")
	require.Equal(t, detect.ClassCanceled, classAt(canceled, lookup), "a probe that was stopped")
	require.Equal(t, detect.ClassDNS, classAt(context.Background(), lookup))
	require.Equal(t, detect.ClassNoTCP, classAt(context.Background(), dial))
}

// The name of a server and a resolver that stays silent: the check of TCP says so, not "no TCP".
func TestProbeSilentResolver(t *testing.T) {
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer sink.Close()
	config := fmt.Sprintf(`{"log": {"disabled": true},
	 "dns": {"servers": [{"type": "udp", "tag": "d", "server": "127.0.0.1", "server_port": %d}]},
	 "outbounds": [{"type": "direct", "tag": "direct-out"}],
	 "route": {"final": "direct-out", "default_domain_resolver": "d"}}`, sink.LocalAddr().(*net.UDPAddr).Port)
	instance, err := Build([]byte(config))
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close(10 * time.Second) })
	ctx, cancel := within(2 * time.Second)
	defer cancel()
	content := probeServer("a", "server.example.test", 443, "")
	require.Equal(t, detect.ClassDNS, instance.Prober().TCP(ctx, detect.Server{Tag: "a", Content: []byte(content)}))
}

// The address of a server asked through a relay stays out of the log of the instance, the page's,
// but at debug. xhttp is the exception: its session dials with a context of its own
// (transport/v2rayxhttp newSession), so the line stays at info there.
func TestProbeThroughADetourLogsAtDebug(t *testing.T) {
	const address = "203.0.113.7"
	tlsOn := `"tls": {"enabled": true, "insecure": true, "server_name": "probe.test", "utls": {"enabled": true, "fingerprint": "chrome"}}`
	vless := fmt.Sprintf(`{"type": "vless", "tag": "a", "server": %q, "server_port": 8443, "uuid": %q, %s`, address, probeUUID, tlsOn)
	for name, content := range map[string]string{
		"tcp":  vless + `}`,
		"grpc": vless + `, "transport": {"type": "grpc", "service_name": "x"}}`,
		"http": vless + `, "transport": {"type": "http"}}`,
		"ws":   vless + `, "transport": {"type": "ws"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			run := func(level string) []string {
				silent, _ := silentListener(t)
				var access sync.Mutex
				var lines []string
				config := fmt.Sprintf(`{"log": {"level": %q, "output": %q},
				 "outbounds": [{"type": "direct", "tag": "direct-out"}, {"type": "socks", "tag": "relay", "server": "127.0.0.1", "server_port": %d}],
				 "route": {"final": "direct-out"}}`, level, filepath.Join(t.TempDir(), "log"), silent.Port)
				instance, err := BuildLogged([]byte(config), func(level string, message string) {
					access.Lock()
					defer access.Unlock()
					if strings.Contains(message, address) {
						lines = append(lines, message)
					}
				})
				require.NoError(t, err)
				require.NoError(t, instance.Start())
				defer instance.Close(10 * time.Second)
				ctx, cancel := within(time.Second)
				defer cancel()
				instance.Prober().Fetch(ctx, detect.Server{Tag: "a", Content: []byte(content)}, detect.ProbeRequest{Detour: "relay", URL: detect.ProbeTarget})
				access.Lock()
				defer access.Unlock()
				return lines
			}
			require.NotEmpty(t, run("debug"), "the dial does go through the relay")
			require.Empty(t, run("info"))
		})
	}
}

// silentTLS completes the TLS handshake, then stays silent.
func silentTLS(t *testing.T) *net.TCPAddr {
	t.Helper()
	return tlsServer(t, func(conn *tls.Conn, done <-chan struct{}) {
		go io.Copy(io.Discard, conn)
		<-done
	})
}

// tlsServer completes the TLS handshake of each connection, then leaves it to serve.
func tlsServer(t *testing.T, serve func(conn *tls.Conn, done <-chan struct{})) *net.TCPAddr {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "probe.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	t.Cleanup(func() {
		listener.Close()
		close(done)
	})
	config := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"h2", "http/1.1"}}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				server := tls.Server(conn, config)
				if server.Handshake() == nil {
					serve(server, done)
				}
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr)
}

func silentUDP(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// Every transport of this build against a server that takes the connection and stays silent: a
// probe ends with its context, and with the instance, whose Close never waits for one (ErrStuck
// would end the process). xhttp and quic overrun a context by seconds (their dials have contexts of
// their own), so of those only the Close is held.
func TestProbeSilentServersOfEveryTransport(t *testing.T) {
	tcp := func(format string) func(t *testing.T) string {
		return func(t *testing.T) string {
			silent, _ := silentListener(t)
			return fmt.Sprintf(format, silent.Port)
		}
	}
	afterTLS := func(format string) func(t *testing.T) string {
		return func(t *testing.T) string { return fmt.Sprintf(format, silentTLS(t).Port) }
	}
	udp := func(format string) func(t *testing.T) string {
		return func(t *testing.T) string { return fmt.Sprintf(format, silentUDP(t)) }
	}
	host := `"tag": "h", "server": "127.0.0.1", "server_port": %d`
	vless := `{"type": "vless", ` + host + `, "uuid": "` + probeUUID + `"`
	trojan := `{"type": "trojan", ` + host + `, "password": "p"`
	insecure := `, "tls": {"enabled": true, "insecure": true, "server_name": "probe.test"}`
	cases := []struct {
		name     string
		content  func(t *testing.T) string
		overruns bool
	}{
		{name: "vless reality", content: tcp(vless + `, "tls": {"enabled": true, "server_name": "probe.test", "utls": {"enabled": true, "fingerprint": "chrome"}, "reality": {"enabled": true, "public_key": "` + probePublicKey + `"}}}`)},
		{name: "vless ws", content: tcp(vless + `, "transport": {"type": "ws"}}`)},
		{name: "vless ws, TLS", content: afterTLS(vless + insecure + `, "transport": {"type": "ws"}}`)},
		{name: "vless ws, early data", content: tcp(vless + `, "transport": {"type": "ws", "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"}}`)},
		{name: "vless httpupgrade", content: tcp(vless + `, "transport": {"type": "httpupgrade"}}`)},
		{name: "vless httpupgrade, TLS", content: afterTLS(vless + insecure + `, "transport": {"type": "httpupgrade"}}`)},
		{name: "trojan httpupgrade, TLS", content: afterTLS(trojan + insecure + `, "transport": {"type": "httpupgrade"}}`)},
		{name: "vless TLS", content: afterTLS(vless + insecure + `}`)},
		{name: "trojan TLS", content: afterTLS(trojan + insecure + `}`)},
		{name: "shadowsocks", content: tcp(`{"type": "shadowsocks", ` + host + `, "method": "aes-128-gcm", "password": "p"}`)},
		{name: "vless grpc, TLS", content: afterTLS(vless + insecure + `, "transport": {"type": "grpc", "service_name": "x"}}`)},
		{name: "vless http, TLS", content: afterTLS(vless + insecure + `, "transport": {"type": "http"}}`)},
		{name: "hysteria2", content: udp(`{"type": "hysteria2", ` + host + `, "password": "p"` + insecure + `}`)},
		{name: "tuic", content: udp(`{"type": "tuic", ` + host + `, "uuid": "` + probeUUID + `", "password": "p"` + insecure + `}`)},
		{name: "vless xhttp, TLS", content: afterTLS(vless + insecure + `, "transport": {"type": "xhttp"}}`), overruns: true},
		{name: "vless xhttp", content: tcp(vless + `, "transport": {"type": "xhttp"}}`), overruns: true},
		{name: "vless quic", content: udp(vless + insecure + `, "transport": {"type": "quic"}}`), overruns: true},
	}
	contents := make([]string, len(cases))
	for index, testCase := range cases {
		contents[index] = testCase.content(t)
	}
	fetchAll := func(instance *Instance, timeout time.Duration) []chan detect.Attempt {
		answers := make([]chan detect.Attempt, len(cases))
		for index := range cases {
			answers[index] = make(chan detect.Attempt, 1)
			go func() {
				ctx, cancel := within(timeout)
				defer cancel()
				answers[index] <- instance.Prober().Fetch(ctx, detect.Server{Content: []byte(contents[index])}, detect.ProbeRequest{URL: detect.ProbeTarget})
			}()
		}
		return answers
	}
	wait := func(answer <-chan detect.Attempt, until time.Time) (detect.Attempt, bool) {
		select {
		case attempt := <-answer:
			return attempt, true
		case <-time.After(time.Until(until)):
			return detect.Attempt{}, false
		}
	}

	t.Run("the end of the context", func(t *testing.T) {
		instance := probeInstance(t, true)
		started := time.Now()
		answers := fetchAll(instance, 2*time.Second)
		for index, testCase := range cases {
			if testCase.overruns {
				continue
			}
			// a margin for a loaded machine and the race detector
			attempt, answered := wait(answers[index], started.Add(6*time.Second))
			require.True(t, answered, "%s did not end with its context", testCase.name)
			require.Zero(t, attempt.Bytes, testCase.name)
		}
	})
	t.Run("the close of the instance", func(t *testing.T) {
		instance := probeInstance(t, true)
		answers := fetchAll(instance, 30*time.Second)
		time.Sleep(time.Second)
		closing := time.Now()
		require.NoError(t, instance.Close(StopTimeout), "ErrStuck: a dial does not end with the instance")
		require.Less(t, time.Since(closing), 5*time.Second)
		for index, testCase := range cases {
			if testCase.overruns {
				continue
			}
			attempt, answered := wait(answers[index], closing.Add(6*time.Second))
			require.True(t, answered, "%s did not end with the instance", testCase.name)
			require.Equal(t, detect.ClassCanceled, attempt.Class, testCase.name)
		}
	})
}

// What a whole run makes of real failures of real outbounds, the way the configuration has them.
func TestRunOverRealOutbounds(t *testing.T) {
	instance := probeInstance(t, true)
	closing := closingListener(t)
	fallbackOfATrojan := tlsServer(t, func(conn *tls.Conn, done <-chan struct{}) {
		buffer := make([]byte, 4096)
		if _, err := conn.Read(buffer); err == nil {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		}
	})
	silent := silentTLS(t)
	utls := `, "utls": {"enabled": true, "fingerprint": "chrome"}`
	vless := func(port int, tls string, transport string) string {
		return fmt.Sprintf(`{"type": "vless", "tag": "a", "server": "127.0.0.1", "server_port": %d, "uuid": %q, "tls": {"enabled": true, "insecure": true%s}%s}`, port, probeUUID, tls, transport)
	}
	for _, testCase := range []struct {
		name    string
		content string
		kind    detect.Kind
		block   detect.Block
		notes   []string
	}{
		{"a hello closed on tcp", vless(closing.Port, utls, ""), detect.KindFingerprint, detect.BlockHelloDrop, nil},
		{"a hello closed on grpc", vless(closing.Port, utls, `, "transport": {"type": "grpc", "service_name": "x"}`), detect.KindPooled, detect.BlockUnknown, []string{detect.NoteInconclusive}},
		{"a hello closed on http", vless(closing.Port, utls, `, "transport": {"type": "http"}`), detect.KindPooled, detect.BlockUnknown, []string{detect.NoteInconclusive}},
		{"a silent upgrade of ws over TLS", vless(silent.Port, "", `, "transport": {"type": "ws"}`), detect.KindTLS, detect.BlockHelloDrop, []string{detect.NoteUpgradeInDial}},
		{"a silent upgrade of httpupgrade over TLS", vless(silent.Port, "", `, "transport": {"type": "httpupgrade"}`), detect.KindTLS, detect.BlockHelloDrop, []string{detect.NoteUpgradeInDial}},
		{"the fallback of a trojan answers a wrong password", fmt.Sprintf(`{"type": "trojan", "tag": "a", "server": "127.0.0.1", "server_port": %d, "password": "wrong", "tls": {"enabled": true, "insecure": true}}`, fallbackOfATrojan.Port), detect.KindTLS, detect.BlockUnknown, []string{detect.NoteInconclusive}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			servers := serversOfInstance(t, []string{testCase.content})
			require.Equal(t, testCase.kind, servers[0].Kind)
			ctx, cancel := within(detect.Budget)
			defer cancel()
			verdict := detect.Run(ctx, instance.Prober(), servers[0], detect.RunOptions{Fallback: true})
			require.Equal(t, testCase.block, verdict.Block, verdict.Why)
			require.ElementsMatch(t, testCase.notes, verdict.Notes, verdict.Why)
		})
	}
}

// xhttp over h3 and UDP that nothing answers, as a real outbound fails: no answer over UDP, as on
// the other kinds of QUIC, not a handshake that "ended in another way".
func TestProbeXHTTPOverH3NoAnswer(t *testing.T) {
	instance := probeInstance(t, true)
	content := fmt.Sprintf(`{"type": "vless", "tag": "a", "server": "127.0.0.1", "server_port": %d, "uuid": %q,
		"tls": {"enabled": true, "insecure": true, "server_name": "probe.test", "alpn": ["h3"]}, "transport": {"type": "xhttp"}}`, silentUDP(t), probeUUID)
	servers := serversOfInstance(t, []string{content})
	require.Equal(t, detect.KindUDP, servers[0].Kind)

	ctx, cancel := within(10 * time.Second)
	defer cancel()
	require.Equal(t, detect.Attempt{Class: detect.ClassNoHello}, instance.Prober().Fetch(ctx, servers[0], detect.ProbeRequest{URL: detect.ProbeTarget}))

	// the uplink may be there or not where this runs: the block is the same
	ctx, cancel = within(detect.Budget)
	defer cancel()
	verdict := detect.Run(ctx, instance.Prober(), servers[0], detect.RunOptions{Fallback: true})
	require.Equal(t, detect.BlockUnreachable, verdict.Block, verdict.Why)
}

// The same classes from real failures of a copy of an outbound.
func TestProbeDialClasses(t *testing.T) {
	instance := probeInstance(t, true)
	utls := `, "utls": {"enabled": true, "fingerprint": "chrome"}`
	fetch := func(content string, timeout time.Duration, request detect.ProbeRequest) detect.Attempt {
		ctx, cancel := within(timeout)
		defer cancel()
		return instance.Prober().Fetch(ctx, detect.Server{Tag: "a", Content: []byte(content)}, request)
	}
	silent, _ := silentListener(t)
	closing := closingListener(t)
	free := freePort(t)

	t.Run("no TCP", func(t *testing.T) {
		attempt := fetch(probeServer("a", "127.0.0.1", free, utls), 3*time.Second, detect.ProbeRequest{})
		require.Equal(t, detect.ClassNoTCP, attempt.Class)
		require.False(t, attempt.Handshake)
		// and the check of TCP itself, through the dialer of the outbound
		ctx, cancel := within(3 * time.Second)
		defer cancel()
		require.Equal(t, detect.ClassNoTCP, instance.Prober().TCP(ctx, detect.Server{Content: []byte(probeServer("a", "127.0.0.1", free, utls))}))
	})
	t.Run("TCP is there", func(t *testing.T) {
		ctx, cancel := within(3 * time.Second)
		defer cancel()
		require.Equal(t, detect.ClassNone, instance.Prober().TCP(ctx, detect.Server{Content: []byte(probeServer("a", "127.0.0.1", silent.Port, utls))}))
	})
	t.Run("no answer to the hello", func(t *testing.T) {
		attempt := fetch(probeServer("a", "127.0.0.1", silent.Port, utls), 300*time.Millisecond, detect.ProbeRequest{})
		require.Equal(t, detect.Attempt{Class: detect.ClassNoHello}, attempt)
	})
	t.Run("the hello is cut", func(t *testing.T) {
		attempt := fetch(probeServer("a", "127.0.0.1", closing.Port, utls), 3*time.Second, detect.ProbeRequest{})
		require.Equal(t, detect.ClassCut, attempt.Class)
		require.False(t, attempt.Handshake)
	})
	t.Run("what the server shows does not verify", func(t *testing.T) {
		address, _ := tlsListener(t, "tcp", "127.0.0.1:0")
		reality := fmt.Sprintf(`{"type": "vless", "tag": "a", "server": "127.0.0.1", "server_port": %d, "uuid": %q,
			"tls": {"enabled": true, "server_name": "probe.test", "utls": {"enabled": true, "fingerprint": "chrome"},
			"reality": {"enabled": true, "public_key": %q, "short_id": "00"}}}`, address.Port, probeUUID, probePublicKey)
		attempt := fetch(reality, 5*time.Second, detect.ProbeRequest{})
		require.Equal(t, detect.ClassVerify, attempt.Class)
		require.False(t, attempt.Handshake)
	})
	t.Run("a detour that is not there", func(t *testing.T) {
		address, _ := tlsListener(t, "tcp", "127.0.0.1:0")
		attempt := fetch(probeServer("a", "127.0.0.1", address.Port, utls), 5*time.Second, detect.ProbeRequest{Detour: "no-such-outbound"})
		require.False(t, attempt.Handshake)
		require.NotEqual(t, detect.ClassNone, attempt.Class)
	})
	t.Run("an outbound that cannot be built", func(t *testing.T) {
		attempt := fetch(`{"type": "no-such-type", "tag": "a"}`, time.Second, detect.ProbeRequest{})
		require.Equal(t, detect.ClassOther, attempt.Class)
	})
}

// A copy with a detour goes through the outbound as it runs: a real proxy here, a second instance.
// Through it the handshake with a server is the proof of a relay, and its absence is no proof.
func TestProbeThroughADetour(t *testing.T) {
	proxyPort := freePort(t)
	proxy, err := Build(configuration(t, freePort(t), proxyPort))
	require.NoError(t, err)
	require.NoError(t, proxy.Start())
	t.Cleanup(func() { proxy.Close(10 * time.Second) })
	instance := probeInstance(t, true, fmt.Sprintf(`{"type": "socks", "tag": "relay", "server": "127.0.0.1", "server_port": %d}`, proxyPort))
	utls := `, "utls": {"enabled": true, "fingerprint": "chrome"}`

	address, accepted := tlsListener(t, "tcp", "127.0.0.1:0")
	ctx, cancel := within(5 * time.Second)
	defer cancel()
	attempt := instance.Prober().Fetch(ctx, detect.Server{Content: []byte(probeServer("a", "127.0.0.1", address.Port, utls))}, detect.ProbeRequest{Detour: "relay"})
	require.Equal(t, detect.Attempt{Handshake: true}, attempt)
	require.Equal(t, int32(1), accepted.Load())

	silent, _ := silentListener(t)
	shortCtx, shortCancel := within(500 * time.Millisecond)
	defer shortCancel()
	attempt = instance.Prober().Fetch(shortCtx, detect.Server{Content: []byte(probeServer("a", "127.0.0.1", silent.Port, utls))}, detect.ProbeRequest{Detour: "relay"})
	require.Equal(t, detect.Attempt{Class: detect.ClassNoHello}, attempt)

	// the control of a relay: a request through it as it runs
	web := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(web.Close)
	control := instance.Prober().Control(ctx, "relay", web.URL+"/")
	require.Equal(t, 204, control.Status)
	require.Positive(t, control.Bytes)
}

// The main leg of xhttp over TCP, the download over h3 and UDP that nothing answers, as a real
// outbound fails: the check of TCP passes on the main server, so the hello without an answer may
// not be blamed on it, and a relay would ask the same.
func TestProbeXHTTPDownloadLegNoAnswer(t *testing.T) {
	instance := probeInstance(t, true)
	content := fmt.Sprintf(`{"type": "vless", "tag": "a", "server": "127.0.0.1", "server_port": %d, "uuid": %q,
		"tls": {"enabled": true, "insecure": true, "server_name": "probe.test"},
		"transport": {"type": "xhttp", "download": {"server": "127.0.0.1", "server_port": %d,
			"tls": {"enabled": true, "insecure": true, "server_name": "probe.test", "alpn": ["h3"]}}}}`, silentTLS(t).Port, probeUUID, silentUDP(t))
	servers := serversOfInstance(t, []string{content})
	require.Equal(t, detect.KindPooled, servers[0].Kind)
	require.True(t, servers[0].DownloadLeg)

	ctx, cancel := within(10 * time.Second)
	defer cancel()
	require.Equal(t, detect.Attempt{Class: detect.ClassNoHello}, instance.Prober().Fetch(ctx, servers[0], detect.ProbeRequest{URL: detect.ProbeTarget}))

	ctx, cancel = within(detect.Budget)
	defer cancel()
	verdict := detect.Run(ctx, instance.Prober(), servers[0], detect.RunOptions{Fallback: true})
	require.Equal(t, detect.BlockUnknown, verdict.Block, verdict.Why)
	require.Equal(t, []string{detect.NoteInconclusive}, verdict.Notes, verdict.Why)
}

// A flow the deadline ends with bytes still coming is slow; one that stalled long before is cut.
func TestProbeExchangeStillReceiving(t *testing.T) {
	instance := probeInstance(t, true)
	handler := http.NewServeMux()
	handler.HandleFunc("/trickle", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "64000")
		for {
			io.WriteString(writer, strings.Repeat("x", 1<<10))
			writer.(http.Flusher).Flush()
			select {
			case <-time.After(100 * time.Millisecond):
			case <-request.Context().Done():
				return
			}
		}
	})
	handler.HandleFunc("/stall", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "64000")
		io.WriteString(writer, strings.Repeat("x", 18<<10))
		writer.(http.Flusher).Flush()
		<-request.Context().Done()
	})
	handler.HandleFunc("/end", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "1024")
		io.WriteString(writer, strings.Repeat("x", 1<<10))
	})
	web := httptest.NewServer(handler)
	t.Cleanup(web.Close)
	direct := detect.Server{Tag: "a", Content: []byte(`{"type": "direct", "tag": "a"}`)}
	fetch := func(path string, timeout time.Duration) detect.Attempt {
		ctx, cancel := within(timeout)
		defer cancel()
		return instance.Prober().Fetch(ctx, direct, detect.ProbeRequest{URL: web.URL + path})
	}
	t.Run("still receiving", func(t *testing.T) {
		t.Parallel()
		attempt := fetch("/trickle", time.Second)
		require.Equal(t, detect.ClassNoHello, attempt.Class)
		require.Positive(t, attempt.Bytes)
		require.True(t, attempt.Receiving)
	})
	t.Run("stalled before the last seconds", func(t *testing.T) {
		t.Parallel()
		attempt := fetch("/stall", stillReceiving+time.Second)
		require.Equal(t, detect.ClassNoHello, attempt.Class)
		require.GreaterOrEqual(t, attempt.Bytes, int64(18<<10))
		require.False(t, attempt.Receiving)
	})
	t.Run("an end is no running out of time", func(t *testing.T) {
		t.Parallel()
		attempt := fetch("/end", 5*time.Second)
		require.Equal(t, detect.ClassNone, attempt.Class)
		require.False(t, attempt.Receiving)
	})
}

// What a request through a copy counts. The copy here is a direct outbound: an HTTP server of the
// test is the address it asks for.
func TestProbeExchange(t *testing.T) {
	instance := probeInstance(t, true)
	body := strings.Repeat("x", 64000)
	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })
	handler := http.NewServeMux()
	handler.HandleFunc("/down", func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "close", request.Header.Get("Connection"))
		writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
		io.WriteString(writer, body)
	})
	handler.HandleFunc("/refused", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
		io.WriteString(writer, "no")
	})
	handler.HandleFunc("/empty", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	handler.HandleFunc("/cut", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
		io.WriteString(writer, body[:18<<10])
		writer.(http.Flusher).Flush()
		select {
		case <-stall:
		case <-request.Context().Done():
		}
	})
	web := httptest.NewServer(handler)
	t.Cleanup(web.Close)
	direct := detect.Server{Tag: "a", Content: []byte(`{"type": "direct", "tag": "a"}`)}
	fetch := func(path string, timeout time.Duration) detect.Attempt {
		ctx, cancel := within(timeout)
		defer cancel()
		return instance.Prober().Fetch(ctx, direct, detect.ProbeRequest{URL: web.URL + path})
	}

	full := fetch("/down", 5*time.Second)
	require.Equal(t, 200, full.Status)
	require.Equal(t, detect.ClassNone, full.Class)
	require.Greater(t, full.Bytes, int64(len(body)), "raw bytes: the headers too")
	require.True(t, full.Handshake)

	refused := fetch("/refused", 5*time.Second)
	require.Equal(t, 403, refused.Status)
	require.Positive(t, refused.Bytes)

	empty := fetch("/empty", 5*time.Second)
	require.Equal(t, 204, empty.Status)
	require.Positive(t, empty.Bytes)

	// a flow cut by a censor stalls: what came is counted, the deadline ends it
	cut := fetch("/cut", 500*time.Millisecond)
	require.Equal(t, 200, cut.Status)
	require.GreaterOrEqual(t, cut.Bytes, int64(18<<10))
	require.Less(t, cut.Bytes, int64(len(body)))
	require.Equal(t, detect.ClassNoHello, cut.Class)

	// a request through an outbound as it runs
	ctx, cancel := within(5 * time.Second)
	defer cancel()
	control := instance.Prober().Control(ctx, "direct-out", web.URL+"/down")
	require.Equal(t, 200, control.Status)
	require.Greater(t, control.Bytes, int64(len(body)))
	control = instance.Prober().Control(ctx, "no-such-outbound", web.URL+"/down")
	require.False(t, control.Handshake)
	require.Zero(t, control.Bytes)

	// a server that closes at once
	closing := closingListener(t)
	closed := instance.Prober().Control(ctx, "direct-out", "http://"+closing.String()+"/")
	require.True(t, closed.Handshake)
	require.Zero(t, closed.Bytes)
	require.Equal(t, detect.ClassCut, closed.Class)
}

func TestDirectReachable(t *testing.T) {
	instance := probeInstance(t, true)
	listener, _ := silentListener(t)
	ctx, cancel := within(3 * time.Second)
	defer cancel()
	require.True(t, instance.Prober().Reachable(ctx, listener.String()))
	require.False(t, instance.Prober().Reachable(ctx, "127.0.0.1:"+fmt.Sprint(freePort(t))))
}

// A Close of the instance cuts a probe at once, in its dial and past it, and a probe holds nothing
// that makes it wait.
func TestProbeEndsWithTheInstance(t *testing.T) {
	silent, _ := silentListener(t)
	content := probeServer("a", "127.0.0.1", silent.Port, `, "utls": {"enabled": true, "fingerprint": "chrome"}`)
	instance := probeInstance(t, true)
	ctx, cancel := within(time.Minute)
	defer cancel()
	inDial := make(chan detect.Attempt, 1)
	go func() {
		inDial <- instance.Prober().Fetch(ctx, detect.Server{Content: []byte(content)}, detect.ProbeRequest{URL: detect.ProbeTarget})
	}()
	// a server of the test that sends nothing: the request is past its dial, reading
	raw, _ := silentListener(t)
	pastDial := make(chan detect.Attempt, 1)
	go func() {
		pastDial <- instance.Prober().Fetch(ctx, detect.Server{Content: []byte(`{"type": "direct", "tag": "b"}`)}, detect.ProbeRequest{URL: "http://" + raw.String() + "/"})
	}()
	time.Sleep(200 * time.Millisecond)
	started := time.Now()
	require.NoError(t, instance.Close(10*time.Second))
	for _, attempt := range []detect.Attempt{<-inDial, <-pastDial} {
		require.Zero(t, attempt.Bytes)
		require.Equal(t, detect.ClassCanceled, attempt.Class)
	}
	require.Less(t, time.Since(started), 5*time.Second)
	// after it, nothing is dialed
	attempt := instance.Prober().Fetch(ctx, detect.Server{Content: []byte(content)}, detect.ProbeRequest{})
	require.Equal(t, detect.ClassCanceled, attempt.Class)
	require.Equal(t, detect.ClassCanceled, instance.Prober().TCP(ctx, detect.Server{Content: []byte(content)}))
	require.False(t, instance.Prober().Reachable(ctx, silent.String()))
}
