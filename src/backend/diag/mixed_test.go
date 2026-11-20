package diag

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/sockets"

	"github.com/stretchr/testify/require"
)

// A line for each mixed proxy of a rule that is on and goes somewhere: whether podkop listens
// on its port, with or without a login, who holds the port when it does not; never the login.
func TestMixedProxyLines(t *testing.T) {
	t.Parallel()
	direct := []model.Member{{Source: model.SourceDirect}}
	proxy := func(name string, port string, user string, password string) model.Section {
		return model.Section{Name: name, Enabled: true, Servers: direct, MixedProxyEnabled: true, MixedProxyPort: port, MixedProxyUsername: user, MixedProxyPassword: password}
	}
	main := proxy("main", "2080", "pdk-user", "Zx9-mixed")
	main.Label = "Main"
	off := proxy("off", "2090", "", "")
	off.Enabled = false
	config := &model.Config{Sections: []model.Section{
		main,
		proxy("open", "2081", "", ""),
		proxy("half", "2082", "pdk-user", ""),
		proxy("taken", "2083", "", ""),
		proxy("gone", "2084", "pdk-user", "Zx9-mixed"),
		off,
		// no proxy; and a rule without a server, which has no route rules
		{Name: "plain", Enabled: true, Servers: direct},
		{Name: "waiting", Enabled: true, MixedProxyEnabled: true, MixedProxyPort: "2091"},
	}}
	lan := netip.MustParseAddr("192.168.1.1")
	listeners := []sockets.Listener{
		{Protocol: "tcp", Address: netip.MustParseAddrPort("192.168.1.1:2080"), PID: 4100, Program: "podkop"},
		{Protocol: "tcp", Address: netip.MustParseAddrPort("192.168.1.1:2081"), PID: 4100, Program: "podkop"},
		{Protocol: "tcp", Address: netip.MustParseAddrPort("0.0.0.0:2083"), PID: 900, Program: "dropbear"},
		// UDP, and TCP at another address, do not take the port of the proxy
		{Protocol: "udp", Address: netip.MustParseAddrPort("192.168.1.1:2084"), PID: 4100, Program: "podkop"},
		{Protocol: "tcp", Address: netip.MustParseAddrPort("127.0.0.1:2084"), PID: 901, Program: "privoxy"},
	}
	lines := MixedProxyLines(config, lan, listeners)
	require.Equal(t, []string{
		"✅ Mixed proxy of rule Main (main) on port 2080, with a login",
		"ℹ️ Mixed proxy of rule open on port 2081, without a login: any device that reaches the port can use it",
		"❌ Mixed proxy of rule half on port 2082 is not created: its login is not valid (the mixed proxy has a user name and no password)",
		"❌ Mixed proxy of rule taken on port 2083 does not listen: taken by dropbear (pid 900) on 0.0.0.0:2083",
		"❌ Mixed proxy of rule gone on port 2084 does not listen",
	}, lines)
	for _, value := range []string{"pdk-user", "Zx9-mixed"} {
		require.NotContains(t, strings.Join(lines, "\n"), value)
	}

	// the address not known: a program on the port at any address is named
	require.Equal(t, "❌ Mixed proxy of rule gone on port 2084 does not listen: taken by privoxy (pid 901) on 127.0.0.1:2084",
		MixedProxyLines(config, netip.Addr{}, listeners)[4])
	// podkop at another address than that of the proxies does not count as its proxy
	require.Equal(t, "❌ Mixed proxy of rule Main (main) on port 2080 does not listen",
		MixedProxyLines(config, netip.MustParseAddr("192.168.2.1"), listeners)[0])
	require.Empty(t, MixedProxyLines(&model.Config{Sections: []model.Section{{Name: "plain", Enabled: true, Servers: direct}}}, lan, listeners))
}
