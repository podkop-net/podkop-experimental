package plan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const mixedHead = "config settings 'settings'\n\toption dns_type 'udp'\n\toption dns_server '8.8.8.8'\n"

func mixedRule(name string, port string, login string) string {
	return "\nconfig section '" + name + "'\n\toption connection_type 'proxy'\n\toption proxy_config_type 'url'\n\toption proxy_string 'socks5://203.0.113.15:1080'\n" +
		"\toption mixed_proxy_enabled '1'\n\toption mixed_proxy_port '" + port + "'\n" + login
}

// the inbounds of a configuration, each compact, and the inbounds its route rules name
func mixedInbounds(t *testing.T, config []byte) (inbounds []string, routed []string) {
	var document struct {
		Inbounds []json.RawMessage `json:"inbounds"`
		Route    struct {
			Rules []struct {
				Inbound any `json:"inbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	require.NoError(t, json.Unmarshal(config, &document))
	for _, inbound := range document.Inbounds {
		var compact bytes.Buffer
		require.NoError(t, json.Compact(&compact, inbound))
		inbounds = append(inbounds, compact.String())
	}
	for _, rule := range document.Route.Rules {
		switch inbound := rule.Inbound.(type) {
		case string:
			routed = append(routed, inbound)
		case []any:
			for _, item := range inbound {
				routed = append(routed, item.(string))
			}
		}
	}
	return inbounds, routed
}

// A mixed proxy with a login asks for it (users of the mixed inbound); without one it is the
// inbound of 0.8.20; a login that is half there or that the protocols cannot carry leaves the
// proxy out with a warning that has no value of it, and the rest is built.
func TestMixedProxyUsers(t *testing.T) {
	facts := Facts{LANAddress: "192.168.1.1"}
	const login = "\toption mixed_proxy_username 'pdk-user'\n\toption mixed_proxy_password 'Zx9-\"secret\\'\n"
	result := buildText(t, mixedHead+mixedRule("main", "2080", login), facts)
	inbounds, routed := mixedInbounds(t, result.Config)
	require.Contains(t, inbounds, `{"type":"mixed","tag":"main-mixed-in","listen":"192.168.1.1","listen_port":2080,"users":[{"username":"pdk-user","password":"Zx9-\"secret\\"}]}`)
	require.Contains(t, routed, "main-mixed-in")

	// the control: no login, the inbound as it was
	result = buildText(t, mixedHead+mixedRule("main", "2080", ""), facts)
	inbounds, routed = mixedInbounds(t, result.Config)
	require.Contains(t, inbounds, `{"type":"mixed","tag":"main-mixed-in","listen":"192.168.1.1","listen_port":2080}`)
	require.Contains(t, routed, "main-mixed-in")
	require.NotContains(t, string(result.Config), `"users"`)

	for _, broken := range []struct{ login, warning string }{
		{"\toption mixed_proxy_username 'pdk-user'\n", "rule main: the mixed proxy has a user name and no password: the mixed proxy is not created"},
		{"\toption mixed_proxy_password 'Zx9-secret'\n", "rule main: the mixed proxy has a password and no user name: the mixed proxy is not created"},
		{"\toption mixed_proxy_username 'pdk:user'\n\toption mixed_proxy_password 'Zx9-secret'\n", "rule main: the user name of the mixed proxy has a colon, which HTTP cannot send: the mixed proxy is not created"},
		{"\toption mixed_proxy_username 'pdk-user'\n\toption mixed_proxy_password 'Zx9 secret'\n", "rule main: the password of the mixed proxy has a space"},
	} {
		result = buildText(t, mixedHead+mixedRule("main", "2080", broken.login), facts)
		inbounds, routed = mixedInbounds(t, result.Config)
		require.NotContains(t, routed, "main-mixed-in", broken.login)
		for _, inbound := range inbounds {
			require.NotContains(t, inbound, "main-mixed-in", broken.login)
		}
		warnings := strings.Join(result.Warnings, "\n")
		require.Contains(t, warnings, broken.warning)
		for _, value := range []string{"pdk-user", "pdk:user", "Zx9-secret", "Zx9 secret"} {
			require.NotContains(t, warnings, value)
		}
		// the rest of the rule is there
		require.Contains(t, string(result.Config), `"tag": "main-out"`)
	}

	// a proxy left out takes no port: the other rule's proxy on it is no conflict
	result = buildText(t, mixedHead+mixedRule("main", "2080", "\toption mixed_proxy_username 'pdk-user'\n")+mixedRule("other", "2080", login), facts)
	inbounds, _ = mixedInbounds(t, result.Config)
	require.Contains(t, inbounds, `{"type":"mixed","tag":"other-mixed-in","listen":"192.168.1.1","listen_port":2080,"users":[{"username":"pdk-user","password":"Zx9-\"secret\\"}]}`)
}
