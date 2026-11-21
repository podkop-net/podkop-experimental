package subscription

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The tables of these tests are those of the page (fe-app-podkop/src/validators/tests/
// validateRequestHeader.test.ts): a row added here goes there too, with the same verdict.

// The request of podkop's own is as before the settings had one: the same headers, the key of the
// address alone.
func TestRequestOfPodkopsOwn(t *testing.T) {
	t.Parallel()
	device := Device{HWID: "0123456789abcdef0123456789abcdef", Model: "Xiaomi AX3000T", Release: "24.10.4"}
	custom, problems := ParseCustom("", nil)
	require.Empty(t, problems)
	require.True(t, custom.Empty())
	require.Empty(t, custom.Key())
	header := device.Headers("0.8.5", custom)
	require.Equal(t, "podkop/0.8.5", header.Get("User-Agent"))
	require.Equal(t, "*/*", header.Get("Accept"))
	require.Equal(t, device.HWID, header.Get("x-hwid"))
	require.Equal(t, "OpenWrt", header.Get("x-device-os"))
	require.Equal(t, "24.10.4", header.Get("x-ver-os"))
	require.Equal(t, "Xiaomi AX3000T", header.Get("x-device-model"))
	require.Len(t, header, 6)
	address := "https://sub.example/api/sub/" + token
	require.Equal(t, AddressKey(address), RequestKey(address, Custom{}))
}

// The User-Agent and the headers of the settings are sent; the device is the router's own.
func TestRequestOfTheSettings(t *testing.T) {
	t.Parallel()
	device := Device{HWID: "0123456789abcdef0123456789abcdef", Model: "Xiaomi AX3000T", Release: "24.10.4"}
	custom, problems := ParseCustom("  INCY  ", []string{"Authorization: Bearer t", " Accept : application/octet-stream ", "", "X-Api-Key:k:1"})
	require.Empty(t, problems)
	require.Equal(t, "INCY", custom.UserAgent)
	require.Equal(t, []string{"Authorization", "Accept", "X-Api-Key"}, custom.Names())
	header := device.Headers("0.8.5", custom)
	require.Equal(t, "INCY", header.Get("User-Agent"))
	require.Equal(t, "Bearer t", header.Get("Authorization"))
	require.Equal(t, "application/octet-stream", header.Get("Accept"))
	require.Equal(t, "k:1", header.Get("X-Api-Key"), "the value goes on after its first colon")
	require.Equal(t, device.HWID, header.Get("x-hwid"))
	require.Equal(t, "OpenWrt", header.Get("x-device-os"))
	require.Equal(t, "24.10.4", header.Get("x-ver-os"))
	require.Equal(t, "Xiaomi AX3000T", header.Get("x-device-model"))
}

// The device headers come last: a field past the checks does not take their place, on a router
// with no model and no release too (an x86 container).
func TestRequestDeviceComesLast(t *testing.T) {
	t.Parallel()
	bypass := Custom{UserAgent: "INCY", Headers: []Field{{"x-hwid", "fake"}, {"X-Device-OS", "iOS"}, {"x-ver-os", "17"}, {"x-device-model", "iPhone"}}}
	header := Device{HWID: "0123456789abcdef0123456789abcdef"}.Headers("0.8.5", bypass)
	require.Equal(t, "0123456789abcdef0123456789abcdef", header.Get("x-hwid"))
	require.Equal(t, "OpenWrt", header.Get("x-device-os"))
	require.Empty(t, header.Values("x-ver-os"), "the router has no release: none is sent")
	require.Empty(t, header.Values("x-device-model"), "the router has no model: none is sent")
	require.Equal(t, []string{"0123456789abcdef0123456789abcdef"}, header.Values("x-hwid"))
}

// What cannot be sent is left out with its reason, the rest is sent; the router's identity stays.
func TestRequestDenied(t *testing.T) {
	t.Parallel()
	device := Device{HWID: "0123456789abcdef0123456789abcdef", Model: "Xiaomi AX3000T", Release: "24.10.4"}
	for name, code := range map[string]string{
		"x-hwid": "device", "X-HWID": "device", "hwid": "device", "x-hwid-limit": "device", "x-device-os": "device", "X-Device-Model": "device", "x-device-locale": "device", "x-ver-os": "device",
		"Device-Id": "device", "X-App-Device-Id": "device", "X-Client-Device-Id": "device", "X-Hardware-Id": "device",
		"X-Forwarded-For": "client", "X-Real-IP": "client", "Forwarded": "client", "True-Client-IP": "client", "CF-Connecting-IP": "client", "X-Client-IP": "client", "X-Cluster-Client-IP": "client", "X-Forwarded-Host": "client",
		"CF-Connecting-IPv6": "client", "X-Envoy-External-Address": "client", "X-Azure-ClientIP": "client", "X-Azure-SocketIP": "client", "X-Client-Address": "client",
		"User-Agent": "agent", "user-agent": "agent",
		"Host": "connection", "Content-Length": "connection", "Transfer-Encoding": "connection", "Connection": "connection", "Keep-Alive": "connection", "Proxy-Connection": "connection",
		"Upgrade": "connection", "TE": "connection", "Trailer": "connection", "Expect": "connection", "Accept-Encoding": "connection",
		"Range": "partial", "If-Range": "partial", "If-Match": "partial", "If-None-Match": "partial", "If-Modified-Since": "partial", "If-Unmodified-Since": "partial",
		"Proxy-Authorization": "proxy",
	} {
		custom, problems := ParseCustom("", []string{name + ": s3cret-value", "X-Kept: 1"})
		require.Len(t, problems, 1, name)
		require.Equal(t, code, problems[0].Code, name)
		require.Equal(t, 1, problems[0].Line, name)
		require.Equal(t, name, problems[0].Name, name)
		require.NotContains(t, problems[0].Text+problems[0].Describe(), "s3cret", name)
		require.Equal(t, []string{"X-Kept"}, custom.Names(), name)
		header := device.Headers("0.8.5", custom)
		require.Equal(t, device.HWID, header.Get("x-hwid"), name)
		require.Equal(t, "OpenWrt", header.Get("x-device-os"), name)
		require.Equal(t, "podkop/0.8.5", header.Get("User-Agent"), name)
	}
	// allowed, for example
	for _, name := range []string{"Authorization", "Cookie", "Accept", "Referer", "X-Api-Key", "X-Age-Public-Key", "Accept-Language"} {
		_, problems := ParseCustom("", []string{name + ": v"})
		require.Empty(t, problems, name)
	}
}

// The lines that are not a header, and the limits; a problem never holds the value.
func TestRequestSyntaxAndLimits(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		lines []string
		code  string
		line  int
	}{
		{"no colon", []string{"Authorization Bearer s3cret"}, "syntax", 1},
		{"no name", []string{": s3cret"}, "syntax", 1},
		{"a space in the name", []string{"Bad Name: s3cret"}, "name", 1},
		{"a NUL in the name", []string{"X-A\x00b: s3cret"}, "name", 1},
		{"a quote in the name", []string{"X'Key: s3cret"}, "name", 1},
		{"a token sign in the name", []string{"X_Key: s3cret"}, "name", 1},
		{"a Cyrillic name", []string{"Ключ: s3cret"}, "name", 1},
		{"a line break in the value", []string{"N: a\r\nX-Inject: s3cret"}, "chars", 1},
		{"an empty value", []string{"X-A:  "}, "empty", 1},
		{"a Cyrillic value", []string{"X-A: s3cret-ключ"}, "chars", 1},
		{"a name of 65", []string{strings.Repeat("n", 65) + ": s3cret"}, "name-long", 1},
		{"a value of 1025", []string{"X-A: s3cret" + strings.Repeat("v", 1019)}, "long", 1},
		{"a name twice", []string{"X-A: 1", "x-a: s3cret"}, "twice", 2},
		{"a ninth header", []string{"H1: 1", "H2: 2", "H3: 3", "H4: 4", "H5: 5", "H6: 6", "H7: 7", "H8: 8", "H9: s3cret"}, "count", 9},
		{"over 4096 bytes", []string{"H1: " + strings.Repeat("a", 1000), "H2: " + strings.Repeat("b", 1000), "H3: " + strings.Repeat("c", 1000), "H4: " + strings.Repeat("d", 1000), "H5: s3cret" + strings.Repeat("e", 100)}, "size", 5},
	} {
		custom, problems := ParseCustom("", test.lines)
		require.Len(t, problems, 1, test.name)
		require.Equal(t, test.code, problems[0].Code, test.name)
		require.Equal(t, test.line, problems[0].Line, test.name)
		require.NotContains(t, problems[0].Describe(), "s3cret", test.name)
		for _, field := range custom.Headers {
			require.NotContains(t, field.Value, "s3cret", test.name)
			require.NotEqual(t, "X-Inject", field.Name, test.name)
		}
	}
	// at the limits: 64, 1024, 8 headers, 4096 bytes
	_, problems := ParseCustom("", []string{strings.Repeat("n", 64) + ": " + strings.Repeat("v", 1024)})
	require.Empty(t, problems)
	_, problems = ParseCustom("", []string{"H1: 1", "H2: 2", "H3: 3", "H4: 4", "H5: 5", "H6: 6", "H7: 7", "H8: 8"})
	require.Empty(t, problems)
	// 4 lines of 2+1000+2, one of 2+2+76: 4096
	custom, problems := ParseCustom("", []string{"H1: " + strings.Repeat("a", 1000), "H2: " + strings.Repeat("b", 1000), "H3: " + strings.Repeat("c", 1000), "H4: " + strings.Repeat("d", 1000), "H5: " + strings.Repeat("e", 76)})
	require.Empty(t, problems)
	require.Len(t, custom.Headers, 5)
	// the first of a name is kept, a line left out does not count towards the twice
	custom, problems = ParseCustom("", []string{"X-A:", "X-A: 1", "x-a: 2"})
	require.Len(t, problems, 2)
	require.Equal(t, []Field{{"X-A", "1"}}, custom.Headers)
	require.Equal(t, "header 3 (x-a) of the settings is left out: the name is given twice", problems[1].Describe())
}

// A User-Agent that cannot be sent leaves podkop's own.
func TestRequestUserAgent(t *testing.T) {
	t.Parallel()
	for agent, code := range map[string]string{"a\nb": "chars", "INCY\x00": "chars", "ИНСИ": "chars", strings.Repeat("a", 257): "long"} {
		custom, problems := ParseCustom(agent, nil)
		require.Empty(t, custom.UserAgent, agent)
		require.Len(t, problems, 1, agent)
		require.Equal(t, code, problems[0].Code, agent)
		require.Zero(t, problems[0].Line, agent)
		require.Equal(t, "podkop/0.8.5", Device{}.Headers("0.8.5", custom).Get("User-Agent"))
	}
	custom, problems := ParseCustom(strings.Repeat("a", 256), nil)
	require.Empty(t, problems)
	require.Len(t, custom.UserAgent, 256)
	require.Equal(t, "the User-Agent of the settings is not sent (it is longer than 256 characters)", func() string {
		_, problems := ParseCustom(strings.Repeat("a", 257), nil)
		return problems[0].Describe()
	}())
	// shown whole up to 64 characters
	require.Equal(t, "INCY/1.0", ShownAgent("INCY/1.0"))
	browser := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	require.Equal(t, browser[:64]+"…", ShownAgent(browser))
}

// The key tells requests apart, the same request the same key, whatever the case of a name.
func TestRequestKey(t *testing.T) {
	t.Parallel()
	key := func(agent string, lines ...string) string {
		custom, _ := ParseCustom(agent, lines)
		return custom.Key()
	}
	require.Empty(t, key(""))
	require.Empty(t, key("", "x-hwid: fake"), "a request whose lines are all left out is podkop's own")
	require.Len(t, key("INCY"), 32)
	require.Equal(t, key("INCY", "Authorization: t"), key(" INCY ", "authorization:t"))
	require.NotEqual(t, key("INCY"), key("INCY/1.0"))
	require.NotEqual(t, key("INCY", "Authorization: a"), key("INCY", "Authorization: b"))
	require.NotEqual(t, key("", "Authorization: a"), key("INCY"))
	require.NotContains(t, key("INCY", "Authorization: s3cret"), "s3cret")
	address := "https://sub.example/api/sub/" + token
	custom, _ := ParseCustom("INCY", nil)
	require.NotEqual(t, AddressKey(address), RequestKey(address, custom))
	require.Equal(t, RequestKey(address, custom), RequestKey(address, custom))
}

// The failures that may be the answer to the User-Agent of the settings tell it, and stay final;
// without one, and for the others, nothing changes.
func TestForAgent(t *testing.T) {
	t.Parallel()
	incy := Custom{UserAgent: "INCY"}
	secure, plain := "https://sub.example/sub/"+token, "http://sub.example/sub/"+token
	for code, want := range map[string]string{"json": "json-agent", "clash": "clash-agent", "page": "page-agent", "refused": "refused-agent", "placeholder": "placeholder-agent", "nolinks": "nolinks-agent"} {
		failure := fail(code, true, "the text", "403")
		var told *Failure
		require.True(t, errors.As(ForAgent(failure, incy, secure), &told), code)
		require.Equal(t, want, told.Code, code)
		require.True(t, told.Final(), code)
		require.Contains(t, told.Text, `the User-Agent "INCY"`, code)
		require.Same(t, failure, ForAgent(failure, Custom{}, secure), code)
		require.Same(t, failure, ForAgent(failure, Custom{Headers: []Field{{"Authorization", "t"}}}, secure), code)
	}
	require.Equal(t, []string{"403"}, ForAgent(fail("refused", true, "x", "403"), incy, secure).(*Failure).Args)
	require.Equal(t, []string{"Open in the app"}, ForAgent(fail("placeholder", true, "x", "Open in the app"), incy, secure).(*Failure).Args)
	page := fail("page", true, "x")
	require.Same(t, page, ForAgent(page, incy, plain), "a page over plain HTTP may be one of the ISP")
	for _, code := range []string{"notfound", "nocontent", "unreachable", "devices", "hwid", "status-one", "server", "wait", "empty", "timeout"} {
		failure := fail(code, true, "x")
		require.Same(t, failure, ForAgent(failure, incy, secure), code)
	}
	other := errors.New("plain")
	require.Equal(t, other, ForAgent(other, incy, secure))
}
