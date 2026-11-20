package model

import (
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/uci"

	"github.com/stretchr/testify/require"
)

// The login of a mixed proxy is both parts or none; each part is what SOCKS5 and HTTP carry,
// and an error never holds the value.
func TestMixedProxyLogin(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 255)
	for _, test := range []struct {
		name, user, password string
		err                  string
	}{
		{name: "none"},
		{name: "a pair", user: "pdk-user", password: "Zx9-secret"},
		{name: "the longest", user: long, password: long},
		{name: "every sign but the colon in the user name", user: "!#$%&'()*+,-./;<=>?@[\\]^_`{|}~", password: "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"},
		{name: "a colon in the password", user: "u", password: "a:b"},
		{name: "a user name alone", user: "pdk-user", err: "the mixed proxy has a user name and no password"},
		{name: "a password alone", password: "Zx9-secret", err: "the mixed proxy has a password and no user name"},
		{name: "a user name too long", user: long + "a", password: "p", err: "the user name of the mixed proxy is longer than 255 bytes"},
		{name: "a password too long", user: "u", password: long + "a", err: "the password of the mixed proxy is longer than 255 bytes"},
		{name: "a space", user: "pdk user", password: "p", err: "the user name of the mixed proxy has a space, a control character or a letter outside ASCII"},
		{name: "a space at the end", user: "u", password: "secret ", err: "the password of the mixed proxy has a space, a control character or a letter outside ASCII"},
		{name: "a tab", user: "u", password: "se\tcret", err: "the password of the mixed proxy has a space"},
		{name: "DEL", user: "u\x7f", password: "p", err: "the user name of the mixed proxy has a space"},
		{name: "a Cyrillic letter", user: "u", password: "пароль", err: "the password of the mixed proxy has a space"},
		{name: "a colon in the user name", user: "pdk:user", password: "p", err: "the user name of the mixed proxy has a colon, which HTTP cannot send"},
	} {
		section := &Section{MixedProxyUsername: test.user, MixedProxyPassword: test.password}
		user, password, err := section.MixedProxyLogin()
		if test.err == "" {
			require.NoError(t, err, test.name)
			require.Equal(t, test.user, user, test.name)
			require.Equal(t, test.password, password, test.name)
			continue
		}
		require.Error(t, err, test.name)
		require.Contains(t, err.Error(), test.err, test.name)
		require.Empty(t, user, test.name)
		require.Empty(t, password, test.name)
		// the values of more than a letter or two (those are in the words of the text)
		for _, value := range []string{test.user, test.password} {
			if len(value) > 2 {
				require.NotContains(t, err.Error(), value, test.name)
			}
		}
	}
}

// The options are read as the settings have them: a space at either end is kept, so that the
// check refuses it rather than a changed secret being used.
func TestLoadMixedProxyLogin(t *testing.T) {
	t.Parallel()
	parsed, err := uci.Parse([]byte("config settings 'settings'\n\nconfig section 'main'\n\toption mixed_proxy_enabled '1'\n\toption mixed_proxy_port '2080'\n" +
		"\toption mixed_proxy_username 'pdk-user'\n\toption mixed_proxy_password ' Zx9 '\n\nconfig section 'other'\n"))
	require.NoError(t, err)
	config, err := Load(parsed)
	require.NoError(t, err)
	rule := config.Section("main")
	require.Equal(t, "pdk-user", rule.MixedProxyUsername)
	require.Equal(t, " Zx9 ", rule.MixedProxyPassword)
	_, _, err = rule.MixedProxyLogin()
	require.Error(t, err)
	other := config.Section("other")
	require.Empty(t, other.MixedProxyUsername)
	require.Empty(t, other.MixedProxyPassword)
}
