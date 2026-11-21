package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/api"

	"github.com/stretchr/testify/require"
)

// twoServersXray is twoServers as Xray JSON: the same two servers.
const twoServersXray = `[{"remarks":"NL 1","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"address":"nl1.example","port":443,"id":"u1"},
	"streamSettings":{"security":"tls","tlsSettings":{"serverName":"nl1.example"}}},{"tag":"direct","protocol":"freedom"}],"dns":{"servers":["1.1.1.1"]}},
	{"remarks":"NL 2","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"address":"nl2.example","port":443,"id":"u2"},
	"streamSettings":{"security":"tls","tlsSettings":{"serverName":"nl2.example"}}},{"tag":"direct","protocol":"freedom"}]}]`

// A preset sends its app's User-Agent; what the provider sends to it, Xray JSON here, is read:
// the format is in the state, the list on flash and the log, and a change of the format is told.
// The same servers as links again are the list in use.
func TestSubscriptionPresetAndFormat(t *testing.T) {
	directory := t.TempDir()
	fake := &fakeEngine{refuse: map[string]error{}}
	source := &provider{body: twoServersXray}
	lines := new(logged)
	options := requestOptions(directory, source, fake, lines)
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(requestSettings(directory, "\toption user_agent_preset 'happ'\n\toption user_agent 'left over'\n")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	defer s.Stop()
	downloadNow(t, s)
	require.Equal(t, "Happ/4.8.3/Linux", source.headers[0].Get("User-Agent"))
	state := s.subscriptionStates()[0]
	require.Equal(t, "happ", state.Preset)
	require.Equal(t, "Happ/4.8.3/Linux", state.Agent)
	require.Equal(t, "xray", state.Format)
	require.Equal(t, 2, state.Configs)
	require.Len(t, s.servers()["prov1"], 2)
	require.Zero(t, lines.count("the provider now sends"), "the first list has no format before it")
	require.Equal(t, 1, lines.count("[info] subscription prov1: Xray JSON of 2 configurations: 2 server outbounds, 2 servers taken; their routing, DNS and balancers are left out"), lines.lines)
	require.Equal(t, 1, lines.count("2 servers, 2 can be used (direct in 0.8 s; asked as Happ (Happ/4.8.3/Linux))"), lines.lines)
	saved, found := s.store().Load("prov1", "https://sub.example/api/sub/TOKEN")
	require.True(t, found)
	require.Equal(t, "xray", saved.Format)
	require.Equal(t, 2, saved.Configs)
	first := saved.Changed
	content, err := os.ReadFile(filepath.Join(directory, "subscriptions", "prov1.json"))
	require.NoError(t, err)
	require.Contains(t, string(content), `"format":"xray"`)
	// the same servers as links: the list in use, now of the format it came in
	fake.access.Lock()
	built := len(fake.built)
	fake.access.Unlock()
	source.serve(twoServers)
	downloadNow(t, s)
	state = s.subscriptionStates()[0]
	require.Equal(t, "", state.Format)
	require.Zero(t, state.Configs)
	require.Equal(t, 1, lines.count("[info] subscription prov1: the provider now sends a list of links instead of Xray JSON"), lines.lines)
	require.Equal(t, 1, lines.count("the list has not changed"), lines.lines)
	fake.access.Lock()
	require.Equal(t, built, len(fake.built), "the same servers: nothing is applied again")
	fake.access.Unlock()
	saved, _ = s.store().Load("prov1", "https://sub.example/api/sub/TOKEN")
	require.Equal(t, "", saved.Format)
	require.True(t, first.Equal(saved.Changed), "the servers did not change: neither does the time they last did")
	require.True(t, first.Equal(*state.Changed))
	// no log line repeats a value of the servers
	for _, line := range lines.lines {
		require.NotContains(t, line, "nl1.example")
		require.NotContains(t, line, "u1@")
	}
}

// A preset podkop does not know is a problem of the request: podkop's own User-Agent is sent.
func TestSubscriptionUnknownPreset(t *testing.T) {
	directory := t.TempDir()
	fake := &fakeEngine{refuse: map[string]error{}}
	source := &provider{body: twoServers}
	lines := new(logged)
	options := requestOptions(directory, source, fake, lines)
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(requestSettings(directory, "\toption user_agent_preset 'v2rayN'\n")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	defer s.Stop()
	downloadNow(t, s)
	require.Equal(t, "podkop/0.8.5", source.headers[0].Get("User-Agent"))
	state := s.subscriptionStates()[0]
	require.Equal(t, []api.RequestProblem{{Line: 0, Code: "preset", Text: "the preset is not one podkop knows"}}, state.Problems)
	require.Empty(t, state.Preset)
	require.Empty(t, state.Agent)
	require.GreaterOrEqual(t, lines.count("[warn] subscription prov1: the User-Agent of the settings is not sent (the preset is not one podkop knows): podkop/0.8.5 is sent"), 1)
}

// The page asks with the preset of its form: the preview tells the preset, the User-Agent sent,
// the format and the links podkop made; the group check takes the list in use for the request
// that works out the same ({} and {podkop}).
func TestPreviewPresetAndFormat(t *testing.T) {
	directory := t.TempDir()
	fake := &fakeEngine{refuse: map[string]error{}}
	source := &provider{body: twoServersXray}
	lines := new(logged)
	options := requestOptions(directory, source, fake, lines)
	require.NoError(t, os.WriteFile(options.SettingsPath, []byte(requestSettings(directory, "")), 0o644))
	s := New(options)
	require.True(t, s.Boot().OK)
	defer s.Stop()
	preview := s.LoadSubscription(context.Background(), "https://sub.example/api/sub/OTHER", api.ListRequest{Preset: "incy"})
	require.Empty(t, preview.Error)
	require.Equal(t, "incy", preview.Preset)
	require.Equal(t, "INCY/3.9.1/linux", preview.Agent)
	require.Equal(t, "xray", preview.Format)
	require.Equal(t, 2, preview.Configs)
	require.Len(t, preview.Servers, 2)
	for _, server := range preview.Servers {
		require.True(t, server.Made)
		require.True(t, strings.HasPrefix(server.Link, "vless://"))
	}
	require.Equal(t, "INCY/3.9.1/linux", source.headers[len(source.headers)-1].Get("User-Agent"))
	unknown := s.LoadSubscription(context.Background(), "https://sub.example/api/sub/OTHER", api.ListRequest{Preset: "nope"})
	require.Equal(t, "request", unknown.ErrorCode)
	require.Equal(t, []string{"preset", "0", ""}, unknown.ErrorArgs)

	downloadNow(t, s)
	asked := len(source.headers)
	for _, request := range []api.ListRequest{{}, {Preset: "podkop"}, {Preset: "custom"}} {
		group := s.CheckGroup(context.Background(), GroupCheck{Subscriptions: []string{"prov1"}, Requests: map[string]api.ListRequest{"prov1": request}})
		require.Equal(t, 2, group.Total, request)
	}
	require.Equal(t, asked, len(source.headers), "the list in use: nothing downloaded")
}
