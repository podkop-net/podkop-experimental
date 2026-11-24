package engine

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// What a client tried in a failed login, and the user name of one that passed, are masked in
// the lines of sing's handshakes; other lines are as they are.
func TestMaskLogin(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ message, masked string }{
		{"[1 2ms] inbound/mixed[main-mixed-in]: process connection from 192.168.1.50:51234: socks5: authentication failed, username=pdk-user, password=Zx9-tried",
			"[1 2ms] inbound/mixed[main-mixed-in]: process connection from 192.168.1.50:51234: socks5: authentication failed, username=MASKED"},
		{"socks4: authentication failed, username=pdk-user",
			"socks4: authentication failed, username=MASKED"},
		{"http: authentication failed, username=pdk-user, password=a,b, password=c",
			"http: authentication failed, username=MASKED"},
		{"http: authentication failed, Proxy-Authorization=Basic cGRrLXVzZXI=",
			"http: authentication failed, Proxy-Authorization=MASKED"},
		{"socks5: authentication failed, username=u, password=line\nsecond line",
			"socks5: authentication failed, username=MASKED"},
		{"[7 0ms] inbound/mixed[main-mixed-in]: [pdk-user] inbound connection to 1.1.1.1:443",
			"[7 0ms] inbound/mixed[main-mixed-in]: [MASKED] inbound connection to 1.1.1.1:443"},
		{"[7 0ms] inbound/mixed[a]: [b-mixed-in]: [pdk]user] inbound packet connection to 1.1.1.1:53",
			"[7 0ms] inbound/mixed[a]: [MASKED] inbound packet connection to 1.1.1.1:53"},
		{"[8 0ms] inbound/mixed[main-mixed-in]: [pdk-user] inbound packet connection",
			"[8 0ms] inbound/mixed[main-mixed-in]: [MASKED] inbound packet connection"},
		// kept: no value in it, and the lines of other inbounds
		{"http: authentication failed, no Proxy-Authorization header",
			"http: authentication failed, no Proxy-Authorization header"},
		{"[9 0ms] inbound/tproxy[tproxy-in]: inbound connection from 192.168.1.50:5000",
			"[9 0ms] inbound/tproxy[tproxy-in]: inbound connection from 192.168.1.50:5000"},
		{"outbound/vless[main-out]: open connection to 1.1.1.1:443 failed",
			"outbound/vless[main-out]: open connection to 1.1.1.1:443 failed"},
	} {
		require.Equal(t, test.masked, MaskLogin(test.message))
	}
}

// The mixed inbound of the fork with a login: SOCKS5 and HTTP pass with it and are refused
// without it or with a wrong password, SOCKS4 is refused; the lines the sink gets carry
// neither the login nor what was tried. The control: the same inbound without users passes
// clients without a login.
func TestMixedLogin(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		io.WriteString(writer, "reached")
	}))
	defer target.Close()
	const user, password = "pdk-user", "Zx9-mixed-secret"
	// one instance at a time: the control starts after the first is closed
	var running *Instance
	t.Cleanup(func() {
		if running != nil {
			running.Close(10 * time.Second)
		}
	})
	start := func(users string) (int, func() []string) {
		if running != nil {
			require.NoError(t, running.Close(10*time.Second))
			running = nil
		}
		port := freePort(t)
		var access sync.Mutex
		var lines []string
		config := fmt.Sprintf(`{"log": {"level": "info", "output": %q},
		 "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": %d%s}],
		 "outbounds": [{"type": "direct", "tag": "direct-out"}],
		 "route": {"final": "direct-out"}}`, filepath.Join(t.TempDir(), "log"), port, users)
		instance, err := BuildLogged([]byte(config), func(level string, message string) {
			access.Lock()
			defer access.Unlock()
			lines = append(lines, message)
		}, Services{})
		require.NoError(t, err)
		require.NoError(t, instance.Start())
		running = instance
		return port, func() []string {
			access.Lock()
			defer access.Unlock()
			return append([]string(nil), lines...)
		}
	}
	// the answer of the target through a proxy URL, or the error
	get := func(proxy string) (int, string, error) {
		proxyURL, err := url.Parse(proxy)
		require.NoError(t, err)
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}}
		response, err := client.Get(target.URL)
		if err != nil {
			return 0, "", err
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body), nil
	}
	// a SOCKS4 CONNECT to the target with a user id: the reply code
	socks4 := func(port int) byte {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		address := target.Listener.Addr().(*net.TCPAddr)
		request := append([]byte{4, 1, byte(address.Port >> 8), byte(address.Port)}, address.IP.To4()...)
		request = append(append(request, user...), 0)
		_, err = conn.Write(request)
		require.NoError(t, err)
		// 8 bytes; a refusal of sing has 4 (no address)
		reply := make([]byte, 8)
		_, err = io.ReadAtLeast(conn, reply, 2)
		require.NoError(t, err)
		return reply[1]
	}

	port, lines := start(fmt.Sprintf(`, "users": [{"username": %q, "password": %q}]`, user, password))
	for _, scheme := range []string{"http", "socks5"} {
		status, body, err := get(fmt.Sprintf("%s://%s:%s@127.0.0.1:%d", scheme, user, password, port))
		require.NoError(t, err, scheme)
		require.Equal(t, http.StatusOK, status, scheme)
		require.Equal(t, "reached", body, scheme)
	}
	status, _, err := get(fmt.Sprintf("http://127.0.0.1:%d", port))
	require.NoError(t, err)
	require.Equal(t, http.StatusProxyAuthRequired, status)
	status, _, err = get(fmt.Sprintf("http://%s:wrong-tried@127.0.0.1:%d", user, port))
	require.NoError(t, err)
	require.Equal(t, http.StatusProxyAuthRequired, status)
	_, _, err = get(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	require.Error(t, err)
	_, _, err = get(fmt.Sprintf("socks5://%s:wrong-tried@127.0.0.1:%d", user, port))
	require.Error(t, err)
	// 91: request rejected or failed
	require.Equal(t, byte(91), socks4(port))

	want := []string{
		"]: [MASKED] inbound connection to " + target.Listener.Addr().String(),
		"socks5: authentication failed, username=MASKED",
		"http: authentication failed, username=MASKED",
		"http: authentication failed, no Proxy-Authorization header",
		"socks4: authentication failed, username=MASKED",
	}
	require.Eventually(t, func() bool {
		text := strings.Join(lines(), "\n")
		for _, line := range want {
			if !strings.Contains(text, line) {
				return false
			}
		}
		return true
	}, 5*time.Second, 50*time.Millisecond, "the lines of the logins: %q", lines())
	text := strings.Join(lines(), "\n")
	for _, secret := range []string{user, password, "wrong-tried"} {
		require.NotContains(t, text, secret)
	}

	// the control: no users, no login asked
	port, _ = start("")
	for _, scheme := range []string{"http", "socks5"} {
		status, body, err := get(fmt.Sprintf("%s://127.0.0.1:%d", scheme, port))
		require.NoError(t, err, scheme)
		require.Equal(t, http.StatusOK, status, scheme)
		require.Equal(t, "reached", body, scheme)
	}
	// 90: request granted
	require.Equal(t, byte(90), socks4(port))
}
