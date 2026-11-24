package supervisor

import (
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/plan"

	"github.com/stretchr/testify/require"
)

// A rule only for some devices names them in the line of the configuration: the IPv4 ones in
// full, the IPv6 ones counted; one of which no item is a device says so; a rule without the field
// and a rule that is off are as before.
func TestDescribeOnlyDevices(t *testing.T) {
	t.Parallel()
	config := &model.Config{
		Sources: []model.Source{{Name: "own", Label: "Own", Type: "links", Links: []string{"vless://x"}}},
		Sections: []model.Section{
			{Name: "tv", Label: "TV", Enabled: true, Servers: []model.Member{{Source: "own"}}, OnlyDevices: []string{"192.168.78.10", "2001:db8:1::50"}},
			{Name: "bad", Enabled: true, Servers: []model.Member{{Source: model.SourceBlock}}, OnlyDevices: []string{"word"}},
			{Name: "noyt", Enabled: true, Servers: []model.Member{{Source: model.SourceBlock}}},
			{Name: "off", Enabled: false, Servers: []model.Member{{Source: "own"}}, OnlyDevices: []string{"192.168.78.20"}},
		},
	}
	line := describeConfig(&candidate{settings: config, result: &plan.Result{}})
	require.Contains(t, line, "configuration: rules TV (Own; only for 192.168.78.10, IPv6 items: 1), bad (block; only for no device), noyt (block), off (off);")
	require.NotContains(t, line, "2001:db8")
}

// The line names the interfaces of the LAN as the settings do; settings that name none, the one
// the plan takes then (br-lan: the transcripts have it of plan.Build).
func TestDescribeLAN(t *testing.T) {
	t.Parallel()
	named := &model.Config{Settings: model.Settings{DNSType: "udp", DNSServer: "127.0.0.1:9", SourceNetworkInterfaces: []string{"lan", "guest"}}}
	result := &plan.Result{Dataplane: plan.Dataplane{Interfaces: []string{"br-lan", "br-guest"}}}
	line := describeConfig(&candidate{settings: named, result: result})
	require.True(t, strings.HasSuffix(line, "; DNS udp 127.0.0.1:9; the LAN on lan, guest"), line)
	unnamed := &model.Config{Settings: model.Settings{DNSType: "udp", DNSServer: "127.0.0.1:9"}}
	result = &plan.Result{Dataplane: plan.Dataplane{Interfaces: []string{"br-lan"}}}
	line = describeConfig(&candidate{settings: unnamed, result: result})
	require.True(t, strings.HasSuffix(line, "; DNS udp 127.0.0.1:9; the LAN on br-lan (the default)"), line)
}
