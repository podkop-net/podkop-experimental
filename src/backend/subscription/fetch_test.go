package subscription

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const token = "TOKEN5b1f0c"

// provider serves the answers of a test by path; every route of a test dials it, whatever
// name the request is for, as a resolver of the router or a proxy would reach the provider.
func provider(t *testing.T, tls bool, handler http.HandlerFunc) (address string, reach func(context.Context, string, string) (net.Conn, error)) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	if tls {
		server.StartTLS()
		roots = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	listener := server.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(listener)
	scheme := "http"
	if tls {
		// the name the test certificate is for
		scheme = "https"
	}
	address = scheme + "://example.com:" + port + "/sub/" + token
	reach = func(ctx context.Context, network string, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener)
	}
	return address, reach
}

func refused(context.Context, string, string) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "example.com"}}
}

// a plan with no wait: the next way starts when a try fails, or after a long while
var turnPlan = Plan{Wait: time.Minute, Body: time.Minute, Total: time.Minute}

func TestDownloadTriesTheRoutesInTurn(t *testing.T) {
	var seen []string
	address, reach := provider(t, true, func(writer http.ResponseWriter, request *http.Request) {
		seen = append(seen, request.Header.Get("x-hwid"))
		writer.Header().Set("subscription-userinfo", "upload=1; download=2; total=0; expire=0")
		_, _ = writer.Write([]byte(base64.StdEncoding.EncodeToString([]byte("vless://u@a.example:443#A\n"))))
	})
	header := Device{HWID: "0123456789abcdef"}.Headers("0.8.5")
	routes := []Route{{Name: "direct", Direct: true, Dial: refused}, {Name: "main: NL", Dial: reach}}
	answer, tries, err := Download(context.Background(), address, header, routes, turnPlan, nil)
	require.NoError(t, err)
	require.Equal(t, "main: NL", answer.Route)
	require.Equal(t, []string{"0123456789abcdef"}, seen)
	require.Equal(t, "upload=1; download=2; total=0; expire=0", answer.Info()["subscription-userinfo"])
	servers, err := Parse(answer.Body, fakeDecode)
	require.NoError(t, err)
	require.Equal(t, "A", servers[0].Name)
	require.Len(t, tries, 2)
	require.Equal(t, PhaseFailed, tries[0].Phase)
	require.Equal(t, "dns", tries[0].Failure.Code)
	require.Equal(t, PhaseDone, tries[1].Phase)
	require.Positive(t, tries[1].FirstByte)
	require.Positive(t, tries[1].Bytes)
}

func TestDownloadPlainHTTPGoesDirectOnly(t *testing.T) {
	address, reach := provider(t, false, func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("vless://u@a.example:443#A\n"))
	})
	_, _, err := Download(context.Background(), address, nil, []Route{{Name: "direct", Direct: true, Dial: refused}, {Name: "proxy", Dial: reach}}, turnPlan, nil)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "proxy")
	answer, _, err := Download(context.Background(), address, nil, []Route{{Name: "direct", Direct: true, Dial: reach}}, turnPlan, nil)
	require.NoError(t, err)
	require.Equal(t, "direct", answer.Route)
}

// blockPage is a way whose ISP serves a block page for the provider.
func blockPage(t *testing.T) func(context.Context, string, string) (net.Conn, error) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte("<html>blocked</html>"))
	}))
	t.Cleanup(server.Close)
	return func(ctx context.Context, network string, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
}

func TestDownloadPageGoesOn(t *testing.T) {
	address, reach := provider(t, true, func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("vless://u@a.example:443#A\n"))
	})
	page := blockPage(t)
	answer, tries, err := Download(context.Background(), address, nil, []Route{{Name: "direct", Direct: true, Dial: page}, {Name: "px", Dial: reach}}, turnPlan, nil)
	require.NoError(t, err)
	require.Equal(t, "px", answer.Route)
	require.Equal(t, "page", tries[0].Failure.Code)
	// a page on every way: the address may be of the provider's site
	_, _, err = Download(context.Background(), address, nil, []Route{{Name: "direct", Direct: true, Dial: page}, {Name: "px", Dial: page}}, turnPlan, nil)
	require.Equal(t, "page", err.(*Failure).Code)
}

func TestDownloadFinalAnswers(t *testing.T) {
	for name, test := range map[string]struct {
		handler http.HandlerFunc
		code    string
		want    string
		tries   int32
	}{
		"no content": {func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(http.StatusNoContent) }, "nocontent", "sent nothing", 1},
		"not found":  {func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(http.StatusNotFound) }, "notfound", "HTTP 404", 1},
		// a status a CDN or a firewall may give the address of the client: one more way
		"forbidden": {func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(http.StatusForbidden) }, "refused", "HTTP 403", 2},
		"busy": {func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusServiceUnavailable)
		}, "server", "HTTP 503", 2},
		"placeholder": {func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("x-hwid-not-supported", "true")
			writer.Header().Set("x-hwid-limit", "true")
			writer.Header().Set("announce", "base64:"+base64.StdEncoding.EncodeToString([]byte("App not supported")))
			_, _ = writer.Write([]byte("vless://placeholder@0.0.0.0:1?security=none#App%20not%20supported\n"))
		}, "hwid", "did not take the identifier of this device (HWID): App not supported", 1},
		"limit": {func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("x-hwid-max-devices-reached", "true")
			_, _ = writer.Write([]byte("vless://placeholder@0.0.0.0:1#Limit\n"))
		}, "devices", "limit of devices", 1},
	} {
		var tries atomic.Int32
		address, reach := provider(t, true, func(writer http.ResponseWriter, request *http.Request) {
			tries.Add(1)
			test.handler(writer, request)
		})
		_, _, err := Download(context.Background(), address, nil, []Route{{Name: "direct", Direct: true, Dial: reach}, {Name: "px", Dial: reach}, {Name: "px2", Dial: reach}}, turnPlan, nil)
		require.ErrorContains(t, err, test.want, name)
		require.Equal(t, test.code, err.(*Failure).Code, name)
		require.Equal(t, test.tries, tries.Load(), name)
	}
	// 403 on the direct way only, as a CDN gives it the address of the router: through a server
	address, reach := provider(t, true, func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("vless://u@a.example:443#A\n"))
	})
	forbidding := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(http.StatusForbidden) }))
	t.Cleanup(forbidding.Close)
	direct := func(ctx context.Context, network string, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, forbidding.Listener.Addr().String())
	}
	answer, tries, err := Download(context.Background(), address, nil, []Route{{Name: "direct", Direct: true, Dial: direct}, {Name: "px", Dial: reach}}, turnPlan, nil)
	require.NoError(t, err)
	require.Equal(t, "px", answer.Route)
	require.Equal(t, []string{"403"}, tries[0].Failure.Args)
}

// A status that came by one way only, the other ways not reaching the provider, is told as
// such: it may be the answer of a CDN to the address of that way.
func TestDownloadStatusOfOneWay(t *testing.T) {
	forbidding := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(http.StatusForbidden) }))
	t.Cleanup(forbidding.Close)
	direct := func(ctx context.Context, network string, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, forbidding.Listener.Addr().String())
	}
	_, tries, err := Download(context.Background(), "https://example.com/sub/"+token, nil, []Route{{Name: "direct", Direct: true, Dial: direct}, {Name: "px", Dial: refused}}, turnPlan, nil)
	require.Equal(t, "status-one", err.(*Failure).Code)
	require.Equal(t, []string{"403", "direct"}, err.(*Failure).Args)
	require.Contains(t, err.Error(), "px: the name of the provider is not found")
	require.Len(t, tries, 2)
	// the only way: the answer of the provider
	_, _, err = Download(context.Background(), "https://example.com/sub/"+token, nil, []Route{{Name: "direct", Direct: true, Dial: direct}}, turnPlan, nil)
	require.Equal(t, "refused", err.(*Failure).Code)
}

// A redirect to plain HTTP is not followed through a proxy: the token would go as it is.
func TestDownloadPlainRedirectGoesDirectOnly(t *testing.T) {
	address, reach := provider(t, true, func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "http://example.com/sub/"+token+"/", http.StatusMovedPermanently)
	})
	_, tries, err := Download(context.Background(), address, nil, []Route{{Name: "direct", Direct: true, Dial: refused}, {Name: "px", Dial: reach}}, turnPlan, nil)
	require.Error(t, err)
	require.Equal(t, "plain-redirect", tries[1].Failure.Code)
	require.NotContains(t, err.Error(), token)
}

// A way that does not connect in 5 s is told as no connection, not as no answer.
func TestDownloadConnectLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("takes 5 s")
	}
	hanging := func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	_, tries, err := Download(context.Background(), "https://example.com/sub/"+token, nil, []Route{{Name: "direct", Direct: true, Dial: hanging}}, turnPlan, nil)
	require.Error(t, err)
	require.Equal(t, "connect-timeout", tries[0].Failure.Code)
	require.Equal(t, []string{"5"}, tries[0].Failure.Args)
}

// A slow provider is waited for: the next way starts beside the first after the plan's wait,
// the first goes on and brings the list. With a long enough wait, no second request.
func TestDownloadWaitsForASlowProvider(t *testing.T) {
	var asked atomic.Int32
	address, reach := provider(t, true, func(writer http.ResponseWriter, request *http.Request) {
		asked.Add(1)
		time.Sleep(1200 * time.Millisecond)
		_, _ = writer.Write([]byte("vless://u@a.example:443#A\n"))
	})
	routes := []Route{{Name: "direct", Direct: true, Dial: reach}, {Name: "px", Dial: reach}}
	answer, tries, err := Download(context.Background(), address, nil, routes, Plan{Wait: 300 * time.Millisecond, Body: time.Second, Total: 10 * time.Second}, nil)
	require.NoError(t, err)
	require.Equal(t, "direct", answer.Route, "the first way went on")
	require.Len(t, tries, 2)
	require.Equal(t, PhaseCanceled, tries[1].Phase)
	require.Equal(t, int32(2), asked.Load())

	asked.Store(0)
	answer, tries, err = Download(context.Background(), address, nil, routes, Plan{Wait: 5 * time.Second, Body: time.Second, Total: 10 * time.Second}, nil)
	require.NoError(t, err)
	require.Equal(t, "direct", answer.Route)
	require.Len(t, tries, 1)
	require.Equal(t, int32(1), asked.Load())
	require.GreaterOrEqual(t, tries[0].FirstByte, time.Second)
}

// A body that stops on the way (a flow frozen after 16 KB) is left soon: the next way starts
// after the plan's wait in the body and brings the list.
func TestDownloadLeavesAStoppedBody(t *testing.T) {
	address, reach := provider(t, true, func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("vless://u@a.example:443#A\n"))
	})
	stopped := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "100000")
		_, _ = writer.Write([]byte(strings.Repeat("vless://u@a.example:443#A\n", 600)))
		writer.(http.Flusher).Flush()
		<-request.Context().Done()
	}))
	t.Cleanup(stopped.Close)
	frozen := func(ctx context.Context, network string, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, stopped.Listener.Addr().String())
	}
	var reports atomic.Int32
	start := time.Now()
	answer, tries, err := Download(context.Background(), address, nil, []Route{{Name: "direct", Direct: true, Dial: frozen}, {Name: "px", Dial: reach}},
		Plan{Wait: 5 * time.Second, Body: 300 * time.Millisecond, Total: 10 * time.Second}, func([]Try) { reports.Add(1) })
	require.NoError(t, err)
	require.Equal(t, "px", answer.Route)
	require.Less(t, time.Since(start), 3*time.Second)
	// the direct way is told by why it was left: its body stopped
	require.Equal(t, PhaseFailed, tries[0].Phase)
	require.Equal(t, "stalled", tries[0].Failure.Code)
	require.Equal(t, []string{"15"}, tries[0].Failure.Args)
	require.Positive(t, tries[0].Bytes)
	require.Positive(t, reports.Load())
}

// A way that is refused starts the next one at once; ways the last download found broken are
// not waited for (Together); at most three ways are tried at once.
func TestDownloadStartsTheWays(t *testing.T) {
	address, reach := provider(t, true, func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("vless://u@a.example:443#A\n"))
	})
	start := time.Now()
	_, _, err := Download(context.Background(), address, nil, []Route{{Name: "direct", Direct: true, Dial: refused}, {Name: "px", Dial: reach}}, turnPlan, nil)
	require.NoError(t, err)
	require.Less(t, time.Since(start), time.Second)

	hanging := func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start = time.Now()
	answer, _, err := Download(context.Background(), address, nil, []Route{{Name: "direct", Direct: true, Dial: hanging}, {Name: "px", Dial: reach}}, Plan{Wait: time.Minute, Body: time.Minute, Total: time.Minute, Together: true}, nil)
	require.NoError(t, err)
	require.Equal(t, "px", answer.Route)
	require.Less(t, time.Since(start), time.Second)

	var access sync.Mutex
	at, most := 0, 0
	counting := func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		access.Lock()
		at++
		most = max(most, at)
		access.Unlock()
		<-ctx.Done()
		access.Lock()
		at--
		access.Unlock()
		return nil, ctx.Err()
	}
	var routes []Route
	for _, name := range []string{"direct", "a", "b", "c", "d"} {
		routes = append(routes, Route{Name: name, Direct: name == "direct", Dial: counting})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	_, tries, err := Download(ctx, address, nil, routes, Plan{Wait: 50 * time.Millisecond, Body: 50 * time.Millisecond, Total: 100 * time.Millisecond}, nil)
	require.Error(t, err)
	require.Equal(t, "unreachable", err.(*Failure).Code)
	access.Lock()
	require.Equal(t, 3, most)
	access.Unlock()
	require.Len(t, tries, 3)
	for _, item := range tries {
		require.Equal(t, "timeout", item.Failure.Code, item.Route)
	}
}

// A failure names neither the address nor the host: the token is the account.
func TestDownloadMessagesKeepTheAddress(t *testing.T) {
	address := "https://sub.example.com/api/sub/" + token
	slow := func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	unknown := func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "sub.example.com"}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, _, err := Download(ctx, address, nil, []Route{{Name: "direct", Direct: true, Dial: unknown}, {Name: "px", Dial: slow}}, turnPlan, nil)
	require.Error(t, err)
	for _, secret := range []string{token, "sub.example.com"} {
		require.NotContains(t, err.Error(), secret)
	}
	require.True(t, strings.Contains(err.Error(), "direct: ") && strings.Contains(err.Error(), "px: "), err.Error())
	_, _, err = Download(context.Background(), "ftp://example.com/"+token, nil, nil, turnPlan, nil)
	require.ErrorContains(t, err, "not an address of HTTP")
	require.NotContains(t, err.Error(), token)
}
