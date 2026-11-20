package supervisor

import (
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
