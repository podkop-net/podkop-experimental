//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/btstats"
	"github.com/podkop-net/podkop-experimental/src/backend/ctl"
	"github.com/podkop-net/podkop-experimental/src/backend/detect"
	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/supervisor"
	"github.com/podkop-net/podkop-experimental/src/backend/ubus"
	"github.com/stretchr/testify/require"
)

type fixedTraffic struct {
	traffic engine.Traffic
	running bool
}

func (f fixedTraffic) Traffic() (engine.Traffic, bool) { return f.traffic, f.running }

func (f fixedTraffic) Detect() detect.Report {
	return detect.Report{
		Verdicts: map[string]detect.Verdict{
			"sub: a": {Block: detect.BlockFreeze, Source: detect.SourceActive, Notes: []string{detect.NoteCured}, Fingerprint: "chrome", Age: 12, Why: "reason"},
			"sub: b": {Block: detect.BlockDead, Source: detect.SourceActive, N: 2},
			"sub: c": {Block: detect.BlockLimit, Source: detect.SourcePassive, KB: 18},
		},
		Probing:  "sub: d",
		Queued:   []string{"sub: e"},
		NoProbe:  []string{},
		Fallback: true,
	}
}

func (f fixedTraffic) ForceDetect(tag string, cancel bool) detect.ForceAnswer {
	if cancel {
		return detect.ForceAnswer{State: detect.ForceCanceled}
	}
	return detect.ForceAnswer{State: detect.ForceThrottled, RetryAfter: 170}
}

func (f fixedTraffic) SetCure(context.Context, string, string, string, string, string) supervisor.CureResult {
	return supervisor.CureResult{State: supervisor.CureOK}
}

func (f fixedTraffic) ClearCure(context.Context, string) supervisor.CureResult {
	return supervisor.CureResult{State: supervisor.CureOK}
}

func (f fixedTraffic) DropStaleCures(context.Context) supervisor.CureResult {
	return supervisor.CureResult{State: supervisor.CureOK}
}

func (f fixedTraffic) SuggestMask(context.Context, string) supervisor.SuggestResult {
	return supervisor.SuggestResult{State: supervisor.SuggestNone}
}

// fixedBitTorrent is a backend of fixed statistics of BitTorrent.
type fixedBitTorrent struct{ api.Backend }

func (f fixedBitTorrent) BitTorrentStats() btstats.Report {
	return btstats.Report{Mode: "bypass", Counted: true, Rows: []btstats.Row{{Kind: btstats.KindUTP, Way: btstats.WayPast, Open: 2, Connections: 3,
		Received: btstats.Count{Packets: 10, Bytes: 12000}, Sent: btstats.Count{Packets: 5, Bytes: 600}}}, Blocked: []btstats.Blocked{}}
}

func (f fixedBitTorrent) ResetBitTorrentStats() btstats.Report {
	return btstats.Report{Mode: "bypass", Rows: []btstats.Row{}, Blocked: []btstats.Blocked{}, ResetAt: 1}
}

// The methods bittorrent and bittorrent_reset answer the report as the page reads it.
func TestBusBitTorrent(t *testing.T) {
	object := busObject(ctl.Environment{}, api.Direct{Backend: fixedBitTorrent{}}, fixedTraffic{})
	answer, status := object.Methods["bittorrent_reset"].Call(context.Background(), nil)
	require.Equal(t, ubus.StatusOK, status)
	encoded, err := json.Marshal(answer)
	require.NoError(t, err)
	require.JSONEq(t, `{"mode":"bypass","lan":false,"since":0,"read":0,"counted":false,"rows":[],"blocked":[],"utp_to_tcp":{"packets":0,"bytes":0},"limits":{},"reset_at":1}`, string(encoded))

	answer, status = object.Methods["bittorrent"].Call(context.Background(), nil)
	require.Equal(t, ubus.StatusOK, status)
	encoded, err = json.Marshal(answer)
	require.NoError(t, err)
	require.JSONEq(t, `{"mode":"bypass","lan":false,"since":0,"read":0,"counted":true,"rows":[{"kind":"utp","way":"past","open":2,"connections":3,`+
		`"received":{"packets":10,"bytes":12000},"sent":{"packets":5,"bytes":600}}],"blocked":[],"utp_to_tcp":{"packets":0,"bytes":0},"limits":{}}`, string(encoded))
}

func TestBusStats(t *testing.T) {
	object := busObject(ctl.Environment{}, api.Direct{}, fixedTraffic{engine.Traffic{Up: 10, Down: 20, Connections: 3}, true})
	require.Contains(t, object.Methods, "run")
	answer, status := object.Methods["stats"].Call(context.Background(), nil)
	require.Equal(t, ubus.StatusOK, status)
	stats := answer.(Stats)
	require.True(t, stats.Running)
	require.Equal(t, int64(10), stats.Up)
	require.Equal(t, int64(20), stats.Down)
	require.Equal(t, 3, stats.Connections)
	require.NotZero(t, stats.Memory)
	later, _ := object.Methods["stats"].Call(context.Background(), nil)
	require.GreaterOrEqual(t, later.(Stats).At, stats.At)

	answer, _ = busObject(ctl.Environment{}, api.Direct{}, fixedTraffic{}).Methods["stats"].Call(context.Background(), nil)
	require.False(t, answer.(Stats).Running)
}

// What the page reads, in the form a call answers it: an object with these names.
func TestBusDetect(t *testing.T) {
	object := busObject(ctl.Environment{}, api.Direct{}, fixedTraffic{})
	answer, status := object.Methods["detect"].Call(context.Background(), nil)
	require.Equal(t, ubus.StatusOK, status)
	table, status := ubus.AsTable(answer)
	require.Equal(t, ubus.StatusOK, status)
	require.Equal(t, map[string]any{
		"verdicts": map[string]any{
			"sub: a": map[string]any{"block": "freeze", "source": "active", "notes": []any{"cured"}, "fp": "chrome", "age": json.Number("12"), "why": "reason"},
			"sub: b": map[string]any{"block": "dead", "source": "active", "n": json.Number("2")},
			"sub: c": map[string]any{"block": "limit", "source": "passive", "kb": json.Number("18")},
		},
		"probing":  "sub: d",
		"queued":   []any{"sub: e"},
		"noprobe":  []any{},
		"fallback": true,
	}, table)
}

func TestBusForceDetect(t *testing.T) {
	object := busObject(ctl.Environment{}, api.Direct{}, fixedTraffic{})
	method := object.Methods["force_detect"]
	require.Equal(t, map[string]int{"tag": ubus.TypeString, "cancel": ubus.TypeBool}, method.Arguments)

	answer, status := method.Call(context.Background(), map[string]any{"tag": "sub: a"})
	require.Equal(t, ubus.StatusOK, status)
	table, status := ubus.AsTable(answer)
	require.Equal(t, ubus.StatusOK, status)
	require.Equal(t, map[string]any{"state": "throttled", "retry_after": json.Number("170")}, table)

	answer, status = method.Call(context.Background(), map[string]any{"cancel": true})
	require.Equal(t, ubus.StatusOK, status)
	table, status = ubus.AsTable(answer)
	require.Equal(t, ubus.StatusOK, status)
	require.Equal(t, map[string]any{"state": "canceled"}, table)

	_, status = method.Call(context.Background(), map[string]any{})
	require.Equal(t, ubus.StatusInvalidArgument, status)
}

// The ACL of the page grants the methods of the bus under their classes, and no other method of the
// object. A method the ACL does not name is denied to the page, and the denial is easy to miss: the
// page goes on without what it asked for.
func TestBusMethodsInACL(t *testing.T) {
	const path = "luci-app-podkop/root/usr/share/rpcd/acl.d/luci-app-podkop.json"
	content, err := os.ReadFile("../../../../" + path)
	if os.IsNotExist(err) {
		t.Skip("no ACL of the package next to the backend")
	}
	require.NoError(t, err)
	var acl map[string]struct {
		Read struct {
			Ubus map[string][]string `json:"ubus"`
		} `json:"read"`
		Write struct {
			Ubus map[string][]string `json:"ubus"`
		} `json:"write"`
	}
	require.NoError(t, json.Unmarshal(content, &acl))
	group := acl["luci-app-podkop"]
	table := methods(fixedTraffic{})
	object := ctl.BusObject(ctl.Environment{}, api.Direct{}, table)
	onBus := 0
	for class, granted := range map[ctl.Class][]string{ctl.Read: group.Read.Ubus[object.Name], ctl.Write: group.Write.Ubus[object.Name]} {
		var names []string
		for _, method := range table {
			if method.Bus != nil && method.Class == class {
				require.Contains(t, object.Methods, method.Name)
				names = append(names, method.Name)
			}
		}
		onBus += len(names)
		require.ElementsMatch(t, names, granted, "the methods of the class %s of the object %s, and those %s grants under %s", class, object.Name, path, class)
	}
	require.Len(t, object.Methods, onBus)
	// the probe sends real connections: it is an action, reading what it found is not
	require.Contains(t, group.Read.Ubus[object.Name], "detect")
	require.Contains(t, group.Write.Ubus[object.Name], "force_detect")
}

// Each method of the table is there once and tells what it is and what it does; a command answers in
// one way, with a value in a form or with a text.
func TestMethods(t *testing.T) {
	seen := make(map[string]bool)
	for _, method := range methods(fixedTraffic{}) {
		for _, name := range method.Names() {
			require.False(t, seen[name], "%s is in the table twice", name)
			seen[name] = true
		}
		require.NotEmpty(t, method.Help, method.Name)
		require.Contains(t, []ctl.Class{ctl.Read, ctl.Write}, method.Class, method.Name)
		command := method.Answer != nil || method.Print != nil
		require.True(t, command || method.Bus != nil, "%s is no command and no method of the bus", method.Name)
		require.False(t, method.Answer != nil && method.Print != nil, "%s answers with a value and with a text", method.Name)
		require.Equal(t, method.Answer != nil, method.Form != 0, "%s: a form goes with a value", method.Name)
		require.True(t, command || (!method.InProcess && len(method.Also) == 0), "%s is no command", method.Name)
		require.True(t, method.Bus == nil || method.Bus.Call != nil, "nothing answers %s on the bus", method.Name)
	}
}

// A command of the page and of the CLI (ctl.Methods) has no name of a command of the program
// itself (daemon, release, ctl, migrate, ...): "podkop <name>" would run the program's own.
func TestCommandsOfTheProgramApart(t *testing.T) {
	own := make(map[string]bool)
	for _, command := range mainCommand.Commands() {
		own[command.Name()] = true
	}
	require.True(t, own["daemon"] && own["ctl"], "the commands of the program were not read: %v", own)
	for _, method := range ctl.Methods {
		if method.Answer == nil && method.Print == nil {
			continue
		}
		for _, name := range method.Names() {
			require.False(t, own[name], "podkop %s is a command of the program and of the CLI both", name)
			require.False(t, ownCommand(name), name)
		}
	}
}

// check_links with the engine of this build: a link it takes, one whose transport it does not
// have, and the answer of the build for VMess (the slim one has no VMess outbound)
func TestCheckLinksWithTheEngine(t *testing.T) {
	var output, errorOutput bytes.Buffer
	env := ctl.Environment{CheckLink: engine.CheckLink}
	status := ctl.Run(env, []string{"check_links",
		"socks5://192.0.2.1:1080",
		"vless://b831381d-6324-4d53-ad4f-8cda48b30811@192.0.2.1:443?type=kcp",
		"vmess://b831381d-6324-4d53-ad4f-8cda48b30811@192.0.2.1:443?type=ws",
	}, &output, &errorOutput)
	require.Zero(t, status)
	var results []ctl.LinkCheck
	require.NoError(t, json.Unmarshal(output.Bytes(), &results))
	require.Len(t, results, 3)
	require.True(t, results[0].OK)
	require.False(t, results[1].OK)
	require.Contains(t, results[1].Error, "mKCP")
	// the slim build says what it has not, without the advice of the engine's own packages
	require.False(t, results[2].OK)
	require.Contains(t, results[2].Error, "not included in this build")
	require.NotContains(t, results[2].Error, "podkop-engine-full")
}
