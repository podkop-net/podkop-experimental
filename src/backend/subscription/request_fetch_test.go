package subscription

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// recorder keeps the requests a server of a test got.
type recorder struct {
	access   sync.Mutex
	requests []*http.Request
}

func (r *recorder) record(request *http.Request) {
	r.access.Lock()
	defer r.access.Unlock()
	r.requests = append(r.requests, request.Clone(context.Background()))
}

func (r *recorder) all() []*http.Request {
	r.access.Lock()
	defer r.access.Unlock()
	return append([]*http.Request(nil), r.requests...)
}

// listening starts a server of a test on a port of its own, with TLS (the test certificate,
// for example.com) or without, and HTTP/2 when asked.
func listening(t *testing.T, secure bool, http2 bool, handler http.HandlerFunc) string {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = http2
	if secure {
		server.StartTLS()
		roots = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	return port
}

// local is a way that reaches the servers of a test by the port of the address it dials: the
// names of the addresses are those of the test certificate.
func local(ctx context.Context, network string, address string) (net.Conn, error) {
	_, port, _ := net.SplitHostPort(address)
	return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+port)
}

const oneLink = "vless://u@a.example:443#A\n"

// Every way to the provider asks with the User-Agent and the headers of the settings, and the
// router's own HWID.
func TestDownloadRequestOnEveryWay(t *testing.T) {
	var seen recorder
	var first atomic.Bool
	port := listening(t, true, false, func(writer http.ResponseWriter, request *http.Request) {
		seen.record(request)
		if first.CompareAndSwap(false, true) {
			// the first way to reach it stalls: the next one starts beside it
			time.Sleep(1500 * time.Millisecond)
		}
		_, _ = writer.Write([]byte(oneLink))
	})
	custom, problems := ParseCustom("INCY", []string{"Authorization: Bearer stand-token", "X-Stand-Secret: s1"})
	require.Empty(t, problems)
	header := Device{HWID: "0123456789abcdef0123456789abcdef"}.Headers("0.8.5", custom)
	routes := []Route{{Name: "direct", Direct: true, Dial: refused}, {Name: "px1", Dial: local}, {Name: "px2", Dial: local}}
	_, tries, err := Download(context.Background(), "https://example.com:"+port+"/sub/"+token, header, routes, Plan{Wait: 300 * time.Millisecond, Body: time.Second, Total: 10 * time.Second}, nil)
	require.NoError(t, err)
	require.Len(t, tries, 3)
	requests := seen.all()
	require.Len(t, requests, 2)
	for _, request := range requests {
		require.Equal(t, "INCY", request.Header.Get("User-Agent"))
		require.Equal(t, "Bearer stand-token", request.Header.Get("Authorization"))
		require.Equal(t, "s1", request.Header.Get("X-Stand-Secret"))
		require.Equal(t, "0123456789abcdef0123456789abcdef", request.Header.Get("x-hwid"))
		require.Equal(t, "OpenWrt", request.Header.Get("x-device-os"))
	}
}

// A redirect to another host gets podkop's own headers only, and no Referer, whose address
// holds the token; the host of the address keeps the headers of the settings, whatever the case
// of its name; plain HTTP after HTTPS gets podkop's own only.
func TestDownloadRedirectKeepsTheHeadersOnTheHost(t *testing.T) {
	var other, plain recorder
	otherPort := listening(t, true, false, func(writer http.ResponseWriter, request *http.Request) {
		other.record(request)
		_, _ = writer.Write([]byte(oneLink))
	})
	plainPort := listening(t, false, false, func(writer http.ResponseWriter, request *http.Request) {
		plain.record(request)
		_, _ = writer.Write([]byte(oneLink))
	})
	var own recorder
	var port string
	port = listening(t, true, false, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/sub/" + token + "/other":
			http.Redirect(writer, request, "https://example.com:"+otherPort+"/sub", http.StatusFound)
		case "/api/sub/" + token + "/same":
			http.Redirect(writer, request, "https://EXAMPLE.com:"+port+"/sub", http.StatusFound)
		case "/api/sub/" + token + "/plain":
			http.Redirect(writer, request, "http://example.com:"+plainPort+"/sub", http.StatusFound)
		default:
			own.record(request)
			_, _ = writer.Write([]byte(oneLink))
		}
	})
	custom, problems := ParseCustom("INCY", []string{"Authorization: Bearer stand-token", "X-Stand-Secret: s1", "Cookie: session=c1", "Referer: https://ref.example/", "Accept: text/plain"})
	require.Empty(t, problems)
	header := Device{HWID: "0123456789abcdef0123456789abcdef", Model: "AX3000T", Release: "24.10.4"}.Headers("0.8.5", custom)
	download := func(path string) {
		t.Helper()
		_, _, err := Download(context.Background(), "https://example.com:"+port+"/api/sub/"+token+path, header, []Route{{Name: "direct", Direct: true, Dial: local}}, turnPlan, nil)
		require.NoError(t, err, path)
	}
	podkopsOwn := func(request *http.Request) {
		t.Helper()
		require.Equal(t, "INCY", request.Header.Get("User-Agent"))
		require.Equal(t, "*/*", request.Header.Get("Accept"))
		require.Equal(t, "0123456789abcdef0123456789abcdef", request.Header.Get("x-hwid"))
		require.Equal(t, "OpenWrt", request.Header.Get("x-device-os"))
		require.Equal(t, "24.10.4", request.Header.Get("x-ver-os"))
		require.Equal(t, "AX3000T", request.Header.Get("x-device-model"))
		for _, name := range []string{"Authorization", "X-Stand-Secret", "Cookie", "Referer"} {
			require.Empty(t, request.Header.Values(name), name)
		}
		for name, values := range request.Header {
			require.NotContains(t, strings.Join(values, " "), token, name)
		}
	}

	download("/other")
	requests := other.all()
	require.Len(t, requests, 1)
	podkopsOwn(requests[0])

	download("/plain")
	requests = plain.all()
	require.Len(t, requests, 1)
	podkopsOwn(requests[0])

	// the control: the same host keeps them, but the Referer
	download("/same")
	requests = own.all()
	require.Len(t, requests, 1)
	require.Equal(t, "Bearer stand-token", requests[0].Header.Get("Authorization"))
	require.Equal(t, "s1", requests[0].Header.Get("X-Stand-Secret"))
	require.Equal(t, "text/plain", requests[0].Header.Get("Accept"))
	require.Empty(t, requests[0].Header.Values("Referer"), "the address before holds the token")

	// the Referer of the settings goes with the first request
	download("")
	requests = own.all()
	require.Len(t, requests, 2)
	require.Equal(t, "https://ref.example/", requests[1].Header.Get("Referer"))
}

// The host of a redirect is that of the address by its name in any case and its port, the one of
// the scheme when none is written.
func TestSameHost(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		first, next string
		same        bool
	}{
		{"https://prov.example/sub", "https://prov.example:443/x", true},
		{"https://Prov.Example/sub", "https://prov.example/x", true},
		{"https://[2001:db8::1]/sub", "https://[2001:DB8::1]:443/x", true},
		{"http://prov.example/sub", "https://prov.example/sub", true},
		{"http://prov.example:8080/sub", "https://prov.example:8080/sub", false},
		{"https://prov.example/sub", "https://prov.example:8443/x", false},
		{"https://prov.example/sub", "https://cdn.prov.example/x", false},
		{"https://prov.example/sub", "http://prov.example/x", false},
		{"https://prov.example/sub", "http://prov.example:443/x", true},
	} {
		first, err := url.Parse(test.first)
		require.NoError(t, err)
		next, err := url.Parse(test.next)
		require.NoError(t, err)
		require.Equal(t, test.same, sameHost(first, next), test.first+" "+test.next)
	}
	// https to http on the same port is still plain HTTP: podkop's own headers only
	first := httptest.NewRequest(http.MethodGet, "https://prov.example/sub", nil)
	first.Header.Set("Authorization", "t")
	first.Header.Set("User-Agent", "INCY")
	request := httptest.NewRequest(http.MethodGet, "http://prov.example:443/x", nil)
	request.Header = first.Header.Clone()
	request.Header.Set("Referer", "https://prov.example/sub")
	redirected(request, first)
	require.Empty(t, request.Header.Get("Authorization"))
	require.Empty(t, request.Header.Get("Referer"))
	require.Equal(t, "INCY", request.Header.Get("User-Agent"))
	// another case of the name: the headers Go left out come back, but the Referer
	request = httptest.NewRequest(http.MethodGet, "https://PROV.example/x", nil)
	request.Header.Set("User-Agent", "INCY")
	request.Header.Set("Referer", "https://prov.example/sub")
	redirected(request, first)
	require.Equal(t, "t", request.Header.Get("Authorization"))
	require.Empty(t, request.Header.Get("Referer"))
}

// With the User-Agent of another app and an address of HTTPS, a web page is the provider's
// answer: two ways at most ask, and neither is at fault for it. Without it, every way is asked:
// the page may be one of an ISP.
func TestDownloadPageIsAnswer(t *testing.T) {
	var asked atomic.Int32
	port := listening(t, true, false, func(writer http.ResponseWriter, request *http.Request) {
		asked.Add(1)
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte("<html>the site of the provider</html>"))
	})
	address := "https://example.com:" + port + "/sub/" + token
	routes := []Route{{Name: "direct", Direct: true, Dial: local}, {Name: "px1", Dial: local}, {Name: "px2", Dial: local}}
	plan := turnPlan
	plan.PageIsAnswer = true
	_, tries, err := Download(context.Background(), address, nil, routes, plan, nil)
	require.Equal(t, int32(2), asked.Load())
	require.Equal(t, "page", err.(*Failure).Code)
	require.True(t, err.(*Failure).Final())
	require.Len(t, tries, 2)
	for _, item := range tries {
		require.Equal(t, "page", item.Failure.Code)
		require.True(t, item.Failure.Final(), "not a fault of the way")
	}
	require.Equal(t, "page-agent", ForAgent(err, Custom{UserAgent: "Mozilla/5.0"}, address).(*Failure).Code)
	// one way only: its page is the answer
	asked.Store(0)
	_, _, err = Download(context.Background(), address, nil, routes[:1], plan, nil)
	require.Equal(t, "page", err.(*Failure).Code)
	require.Equal(t, int32(1), asked.Load())
	// a page by one way, the other way not reaching the provider, in either order: the page is
	// the answer, not a provider that does not answer
	for _, mixed := range [][]Route{
		{{Name: "direct", Direct: true, Dial: local}, {Name: "px1", Dial: refused}},
		{{Name: "direct", Direct: true, Dial: refused}, {Name: "px1", Dial: local}},
	} {
		asked.Store(0)
		_, tries, err = Download(context.Background(), address, nil, mixed, plan, nil)
		require.Equal(t, int32(1), asked.Load())
		require.Len(t, tries, 2)
		require.Equal(t, "page", err.(*Failure).Code, err.Error())
		require.True(t, err.(*Failure).Final())
		require.Contains(t, err.Error(), ": the name of the provider is not found")
		require.Equal(t, "page-agent", ForAgent(err, Custom{UserAgent: "Mozilla/5.0"}, address).(*Failure).Code)
	}

	// the control: podkop's own User-Agent, every way
	asked.Store(0)
	_, tries, err = Download(context.Background(), address, nil, routes, turnPlan, nil)
	require.Equal(t, int32(3), asked.Load())
	require.Equal(t, "page", err.(*Failure).Code)
	require.False(t, tries[0].Failure.Final())
}

// What a provider sends to the User-Agent of another app that podkop cannot read is told as the
// answer to it.
func TestDownloadAnswersToTheAgent(t *testing.T) {
	bodies := map[string]string{
		"/json":        `{"log":{"level":"info"},"rules":[]}`,
		"/clash":       "proxies:\n  - name: a\n",
		"/placeholder": "vless://u@0.0.0.0:1#Open%20in%20the%20app\n",
		"/nolinks":     "# no servers for this app\n",
	}
	port := listening(t, true, false, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/forbidden" {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = writer.Write([]byte(bodies[request.URL.Path]))
	})
	incy := Custom{UserAgent: "INCY/1.0"}
	for path, want := range map[string]string{"/json": "json-agent", "/clash": "clash-agent", "/placeholder": "placeholder-agent", "/nolinks": "nolinks-agent", "/forbidden": "refused-agent"} {
		address := "https://example.com:" + port + path
		answer, _, err := Download(context.Background(), address, Device{}.Headers("0.8.5", incy), []Route{{Name: "direct", Direct: true, Dial: local}, {Name: "px", Dial: local}}, turnPlan, nil)
		if err == nil {
			_, err = Parse(answer.Body, fakeDecode)
		}
		failure := ForAgent(err, incy, address).(*Failure)
		require.Equal(t, want, failure.Code, path)
		require.True(t, failure.Final(), path)
		require.Contains(t, failure.Text, `"INCY/1.0"`, path)
	}
}

// Over HTTP/2, as the panels behind nginx or Cloudflare answer: the headers of the connection a
// hand-edited file names are left out, the request goes, and the server sees the router's own
// Host, HWID and Accept-Encoding.
func TestDownloadHTTP2LeavesTheDeniedOut(t *testing.T) {
	var seen recorder
	port := listening(t, true, true, func(writer http.ResponseWriter, request *http.Request) {
		seen.record(request)
		_, _ = writer.Write([]byte(oneLink))
	})
	lines := []string{"Connection: upgrade", "Upgrade: h2c", "Transfer-Encoding: chunked", "TE: trailers", "Keep-Alive: 5", "Host: evil.example", "Accept-Encoding: br", "x-hwid: 0000000000", "Authorization: Bearer stand-token"}
	custom, problems := ParseCustom("INCY", lines)
	require.Len(t, problems, 8)
	header := Device{HWID: "0123456789abcdef0123456789abcdef"}.Headers("0.8.5", custom)
	address := "https://example.com:" + port + "/sub/" + token
	answer, _, err := Download(context.Background(), address, header, []Route{{Name: "direct", Direct: true, Dial: local}}, turnPlan, nil)
	require.NoError(t, err)
	require.Equal(t, oneLink, string(answer.Body))
	requests := seen.all()
	require.Len(t, requests, 1)
	request := requests[0]
	require.Equal(t, 2, request.ProtoMajor)
	require.Equal(t, "example.com:"+port, request.Host)
	require.Equal(t, "0123456789abcdef0123456789abcdef", request.Header.Get("x-hwid"))
	require.Equal(t, "Bearer stand-token", request.Header.Get("Authorization"))
	require.Equal(t, "gzip", request.Header.Get("Accept-Encoding"))
	for _, name := range []string{"Connection", "Upgrade", "Transfer-Encoding", "Keep-Alive"} {
		require.Empty(t, request.Header.Values(name), name)
	}

	// the control: an Upgrade sent as it is never reaches the server over HTTP/2 (Go refuses the
	// request, RFC 9113 §8.2.2): why the page and the backend leave it out
	raw := header.Clone()
	raw.Set("Upgrade", "h2c")
	_, _, err = Download(context.Background(), address, raw, []Route{{Name: "direct", Direct: true, Dial: local}}, turnPlan, nil)
	requests = seen.all()
	if err == nil {
		require.Empty(t, requests[len(requests)-1].Header.Values("Upgrade"))
	} else {
		require.Len(t, requests, 1, "the request did not go")
	}
}
