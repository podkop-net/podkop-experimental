package engine_test

import (
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	"github.com/stretchr/testify/require"
)

// The DNS servers of the list as the plan makes them are taken by this engine: its group of
// servers in both modes and the provider's servers, alone and in the group.
func TestDNSListTakenByEngine(t *testing.T) {
	head := "config settings 'settings'\n\toption config_version '2'\n"
	row := func(serverType string, server string) string {
		text := "\nconfig dns_server\n\toption type '" + serverType + "'\n"
		if server != "" {
			text += "\toption server '" + server + "'\n"
		}
		return text
	}
	list := row("doh", "dns.example/dns-query") + row("provider", "") + row("dot", "1.1.1.1") + row("udp", "77.88.8.8:5353")
	for _, settings := range []string{
		row("udp", "77.88.8.8"),
		row("provider", ""),
		list,
		"\toption dns_mode 'fastest'\n" + list,
	} {
		parsed, err := uci.Parse([]byte(head + settings))
		require.NoError(t, err)
		config, err := model.Load(parsed)
		require.NoError(t, err)
		result, err := plan.Build(config, plan.Facts{}, plan.Options{DecodeLink: engine.DecodeLink})
		require.NoError(t, err, settings)
		_, err = engine.Check(result.Config)
		require.NoError(t, err, settings)
	}
}
