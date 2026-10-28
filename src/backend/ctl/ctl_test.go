package ctl

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/diag"
	"github.com/podkop-net/podkop-experimental/src/backend/logbuf"

	"github.com/stretchr/testify/require"
)

// backend is a Backend that answers what a test tells it to.
type backend struct {
	status api.Status
	result api.Result
	lists  api.ListsUpdate
	states []api.ListState
	probe  api.ProbeResult
	facts  api.Facts
	probed []string
	asked  int

	subscriptions []api.SubscriptionState
	preview       api.SubscriptionPreview
	group         api.GroupPreview
	updated       []string
	loaded        []string
	checked       []api.GroupCheck
}

func (b *backend) UpdateLists(context.Context) api.ListsUpdate { return b.lists }
func (b *backend) ListStatus(context.Context) []api.ListState  { return b.states }
func (b *backend) RestoreRouting(context.Context) string       { return "nothing was missing" }
func (b *backend) Probe(_ context.Context, label string, wait time.Duration) api.ProbeResult {
	b.probed = append(b.probed, label+" "+wait.String())
	return b.probe
}
func (b *backend) ProbeSelf(context.Context) api.ProbeResult { return b.probe }

func (b *backend) Subscriptions(context.Context) []api.SubscriptionState { return b.subscriptions }
func (b *backend) UpdateSubscriptions(_ context.Context, name string) []api.SubscriptionState {
	b.updated = append(b.updated, name)
	return b.subscriptions
}
func (b *backend) LoadSubscription(_ context.Context, address string) api.SubscriptionPreview {
	b.loaded = append(b.loaded, address)
	return b.preview
}
func (b *backend) CheckGroup(_ context.Context, check api.GroupCheck) api.GroupPreview {
	b.checked = append(b.checked, check)
	return b.group
}

func (b *backend) Status() api.Status { return b.status }
func (b *backend) Facts() api.Facts   { return b.facts }
func (b *backend) Request(context.Context) api.Result {
	b.asked++
	return b.result
}

func serve(t *testing.T, running *backend, logs *logbuf.Buffer) string {
	path := filepath.Join(t.TempDir(), "ctl.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- api.Serve(ctx, path, running, logs) }()
	require.Eventually(t, func() bool { _, err := os.Stat(path); return err == nil }, 5*time.Second, 10*time.Millisecond)
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
		_, err := os.Stat(path)
		require.True(t, os.IsNotExist(err), "the socket is left behind")
	})
	return path
}

func TestSocket(t *testing.T) {
	logs := logbuf.New(1 << 16)
	logs.Write("backend", "info", "running")
	logs.Write("sing-box", "error", "dns: exchange failed")
	running := &backend{status: api.Status{Running: true}, result: api.Result{OK: true, Message: "applied in 20 ms, sing-box keeps running"}}
	client := api.Client{Path: serve(t, running, logs)}
	status, err := client.Status()
	require.NoError(t, err)
	require.True(t, status.Running)
	page, err := client.Logs(0)
	require.NoError(t, err)
	require.Len(t, page.Lines, 2)
	require.Contains(t, page.Lines[0], "podkop: [info] running")
	require.Equal(t, logs.Run(), page.Run)
	page, err = client.Logs(page.Next)
	require.NoError(t, err)
	require.Empty(t, page.Lines)
	result, err := client.Apply()
	require.NoError(t, err)
	require.True(t, result.OK)
	require.Equal(t, 1, running.asked)
	info, err := os.Stat(client.Path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	_, err = api.Client{Path: filepath.Join(t.TempDir(), "none.sock")}.Status()
	require.Error(t, err)
}

func run(env Environment, arguments ...string) (string, int) {
	var output, errorOutput bytes.Buffer
	status := Run(env, arguments, &output, &errorOutput)
	return output.String(), status
}

func TestCommands(t *testing.T) {
	directory := t.TempDir()
	write := func(name string, content string) string {
		path := filepath.Join(directory, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o755))
		return path
	}
	logs := logbuf.New(1 << 16)
	logs.Write("backend", "info", "running")
	running := &backend{status: api.Status{Running: true}, result: api.Result{OK: false, Message: "the settings cannot be used, nothing is changed: no link"}}
	env := Environment{
		Version: "0.8.0-test", SingBoxVersion: "1.14.2-test", Features: []string{"tools.decode-link", "urltest.fallbacks"},
		Socket: serve(t, running, logs),
		Paths: diag.Paths{
			Settings: write("podkop", "config settings 'settings'\n\toption dns_type 'udp'\n\toption yacd_secret_key 'k'\n\nconfig section 'main'\n\toption proxy_string 'socks5://u:p@203.0.113.15:1080'\n"),
			DHCP:     write("dhcp", "config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n\toption cachesize '0'\n"),
			Network:  write("network", "config interface 'lan'\n"),
		},
		AutostartPath: write("S99podkop", "#!/bin/sh\n"),
	}
	output, status := run(env, "get_status")
	require.Equal(t, "{\"enabled\":1,\"status\":\"enabled\"}\n", output)
	require.Zero(t, status)
	output, _ = run(env, "get_sing_box_status")
	require.Equal(t, "{\"running\":1,\"enabled\":0,\"status\":\"running but disabled\",\"dns_configured\":1}\n", output)
	output, _ = run(env, "get_sing_box_features")
	require.Equal(t, "[\"tools.decode-link\",\"urltest.fallbacks\"]\n", output)
	// the copies the backend keeps, all in RAM: the one that runs; the refused one when
	// asked, and when nothing runs; the one that ran last when there is neither
	_, status = run(env, "show_sing_box_config")
	require.Equal(t, 1, status, "no directory of the copies")
	runDir := filepath.Join(directory, "run")
	require.NoError(t, os.MkdirAll(runDir, 0o755))
	env.ConfigDir = runDir
	require.NoError(t, os.WriteFile(filepath.Join(runDir, api.RunningConfig), []byte(`{"outbounds":[{"type":"direct","tag":"running"}]}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(runDir, api.RejectedConfig), []byte(`{"outbounds":[{"type":"socks","tag":"refused","server":"203.0.113.16"}]}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(runDir, api.LastConfig), []byte(`{"outbounds":[{"type":"socks","tag":"main-out","server":"203.0.113.15","server_port":1080,"password":"p"}]}`), 0o600))
	output, _ = run(env, "show_sing_box_config")
	require.Contains(t, output, `"tag": "running"`)
	output, _ = run(env, "show_sing_box_config", "--rejected")
	require.Contains(t, output, `"tag": "refused"`)
	require.NotContains(t, output, "203.0.113.16")
	require.NoError(t, os.Remove(filepath.Join(runDir, api.RunningConfig)))
	output, _ = run(env, "show_sing_box_config")
	require.Contains(t, output, `"tag": "refused"`)
	require.NoError(t, os.Remove(filepath.Join(runDir, api.RejectedConfig)))
	output, _ = run(env, "show_sing_box_config")
	require.Contains(t, output, `"tag": "main-out"`)
	require.NotContains(t, output, "203.0.113.15")
	_, status = run(env, "show_sing_box_config", "--rejected")
	require.Equal(t, 1, status)
	env.ConfigDir = ""
	output, _ = run(env, "show_config")
	require.Contains(t, output, "option proxy_string 'MASKED'")
	require.Contains(t, output, "option yacd_secret_key 'MASKED'")
	output, _ = run(env, "check_logs")
	require.Contains(t, output, "podkop: [info] running")
	output, _ = run(env, "show_version")
	require.Equal(t, "0.8.0-test\n", output, "the version of the backend")
	output, _ = run(env, "show_sing_box_version")
	require.Equal(t, "1.14.2-test\n", output)
	output, status = run(env, "show_system_info")
	require.True(t, strings.HasPrefix(output, "=== OpenWrt Version ===\n"), output)
	require.Contains(t, output, "\n\n=== Device Model ===\n")
	require.Zero(t, status)
	// an update of the lists is told a line a kind, between the words of the shell backend
	running.lists = api.ListsUpdate{OK: true, Lines: []string{"rule sets: 3 asked, 1 with a new list, 0 failed"}}
	output, status = run(env, "list_update")
	require.Equal(t, "🔄 Starting lists update...\nrule sets: 3 asked, 1 with a new list, 0 failed\n✅ Lists update completed successfully\n", output)
	require.Zero(t, status)
	running.lists = api.ListsUpdate{Lines: []string{"rule sets: 3 asked, 0 with a new list, 1 failed"}}
	output, status = run(env, "list_update")
	require.True(t, strings.HasSuffix(output, "1 failed\n❌ Lists update failed\n"), output)
	require.Equal(t, 1, status)
	output, status = run(env, "restore_routing")
	require.Zero(t, status)
	require.Equal(t, "nothing was missing\n", output)
	// the state of the lists comes as the backend tells it
	running.states = []api.ListState{{Tag: "main-telegram-community-ruleset", Kind: "remote", URL: "https://lists.example/telegram.srs", Format: "binary"}}
	output, status = run(env, "list_status")
	require.Zero(t, status)
	require.JSONEq(t, `[{"tag": "main-telegram-community-ruleset", "kind": "remote", "url": "https://lists.example/telegram.srs", "format": "binary"}]`, output)
	// the check of a device: the label goes to the backend with the time to wait, and
	// what the backend saw comes back
	running.probe = api.ProbeResult{DNS: true, Connection: true, Client: "192.168.1.23", Address: "198.18.0.9"}
	output, status = run(env, "check_fakeip_client", "0a1b2c3d4e5f", "1500")
	require.JSONEq(t, `{"dns": true, "connection": true, "client": "192.168.1.23", "address": "198.18.0.9"}`, output)
	require.Zero(t, status)
	require.Equal(t, []string{"0a1b2c3d4e5f 1.5s"}, running.probed)
	for _, label := range []string{"", "short", "UPPERCASE0", "with.dot.inside", "dash-inside-it"} {
		output, status = run(env, "check_fakeip_client", label)
		require.Empty(t, output, label)
		require.Equal(t, 1, status, label)
	}
	// the check of the router keeps the flag the user interface reads
	output, status = run(env, "check_fakeip")
	require.JSONEq(t, `{"fakeip": true, "dns": true, "connection": true}`, output)
	require.Zero(t, status)
	running.probe = api.ProbeResult{DNS: true}
	output, _ = run(env, "check_fakeip")
	require.JSONEq(t, `{"fakeip": false, "dns": true, "connection": false}`, output)
	// the actions of the service are passed to its script
	env.ServicePath = write("service", "#!/bin/sh\necho \"asked to $1 ($PODKOP_SERVICE_ACTION)\"\n")
	output, status = run(env, "restart")
	require.Equal(t, "asked to restart (restart)\n", output)
	require.Zero(t, status)
	// a script that calls podkop back (the shell backend's, kept by apk) is not run again:
	// the two would call each other without end
	t.Setenv(serviceActionVariable, "stop")
	var errorOutput bytes.Buffer
	status = Run(env, []string{"stop"}, &bytes.Buffer{}, &errorOutput)
	require.Equal(t, 1, status)
	require.Contains(t, errorOutput.String(), "calls podkop back")
	os.Unsetenv(serviceActionVariable)
	// a change that was refused is told as it is, and the command fails
	output, status = run(env, "reload")
	require.Contains(t, output, "nothing is changed")
	require.Equal(t, 1, status)
	output, _ = run(env, "check_sing_box")
	var singBox singBoxAnswer
	require.NoError(t, json.Unmarshal([]byte(output), &singBox))
	require.Equal(t, 1, singBox.ProcessRunning)

	// no backend runs, the service does not start at boot
	env.Socket, env.AutostartPath = filepath.Join(directory, "none.sock"), filepath.Join(directory, "none")
	output, _ = run(env, "get_status")
	require.Equal(t, "{\"enabled\":0,\"status\":\"disabled\"}\n", output)
	output, _ = run(env, "get_sing_box_status")
	require.Equal(t, "{\"running\":0,\"enabled\":0,\"status\":\"stopped & disabled\",\"dns_configured\":1}\n", output)
	_, status = run(env, "reload")
	require.Equal(t, 1, status)
	output, status = run(env, "list_update")
	require.Equal(t, "🔄 Starting lists update...\n", output)
	require.Equal(t, 1, status)
	for _, command := range [][]string{{"check_fakeip"}, {"check_fakeip_client", "0a1b2c3d4e5f"}} {
		output, status = run(env, command...)
		require.Empty(t, output, command)
		require.Equal(t, 1, status, command)
	}
	output, status = run(env, "no_such_command")
	require.Empty(t, output)
	require.Equal(t, 1, status)
	output, status = run(env)
	require.Empty(t, output)
	require.Equal(t, 1, status)
}

// The Clash API as the commands ask it and as they print its answers.
func TestClashAPI(t *testing.T) {
	var seen []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /proxies", func(writer http.ResponseWriter, request *http.Request) {
		seen = append(seen, request.Header.Get("Authorization"))
		writer.Write([]byte(`{"proxies":{"main-out":{"type":"Selector","name":"main-out","now":"main-1-out","all":["main-1-out"]}}}`))
	})
	mux.HandleFunc("GET /proxies/{tag}/delay", func(writer http.ResponseWriter, request *http.Request) {
		seen = append(seen, request.PathValue("tag")+" "+request.URL.Query().Get("timeout")+" "+request.URL.Query().Get("url"))
		writer.Write([]byte(`{"delay":42}`))
	})
	mux.HandleFunc("GET /group/{tag}/delay", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte(`{"main-1-out":42,"main-2-out":0}`))
	})
	mux.HandleFunc("PUT /proxies/{group}", func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		json.NewDecoder(request.Body).Decode(&body)
		switch {
		case request.PathValue("group") != "main-out":
			http.Error(writer, `{"message":"Resource not found"}`, http.StatusNotFound)
		case body.Name != "main-1-out":
			http.Error(writer, `{"message":"Selector update error: not found"}`, http.StatusBadRequest)
		default:
			writer.WriteHeader(http.StatusNoContent)
		}
	})
	upgrades := 0
	mux.HandleFunc("POST /upgrade/ui", func(writer http.ResponseWriter, request *http.Request) {
		upgrades++
		if upgrades > 1 {
			http.Error(writer, `{"message":"download external ui failed: 404 Not Found"}`, http.StatusInternalServerError)
			return
		}
		writer.Write([]byte(`{"status":"ok"}`))
	})
	// the commands ask the API where the backend says it listens, with the key it says
	server := httptest.NewServer(mux)
	defer server.Close()
	running := &backend{facts: api.Facts{ClashAPI: server.Listener.Addr().String(), ClashSecret: "s3cret"}}
	env := Environment{Socket: serve(t, running, logbuf.New(1<<16))}

	output, status := run(env, "clash_api", "get_proxies")
	require.Zero(t, status)
	require.True(t, strings.HasPrefix(output, "{\n  \"proxies\": {\n    \"main-out\": {\n      \"type\": \"Selector\","), output)
	require.Equal(t, []string{"Bearer s3cret"}, seen, "the key the backend tells")
	output, _ = run(env, "clash_api", "get_proxy_latency", "main-1-out", "5000")
	require.Equal(t, "{\n  \"delay\": 42\n}\n", output)
	require.Equal(t, "main-1-out 5000 https://www.gstatic.com/generate_204", seen[1])
	output, _ = run(env, "clash_api", "get_group_latency", "main-out")
	require.Contains(t, output, "\"main-1-out\": 42")
	output, status = run(env, "clash_api", "set_group_proxy", "main-out", "main-1-out")
	require.Zero(t, status)
	require.Equal(t, "{\n  \"success\": true,\n  \"group\": \"main-out\",\n  \"proxy\": \"main-1-out\"\n}\n", output)
	output, status = run(env, "clash_api", "set_group_proxy", "main-out", "other-out")
	require.Equal(t, 1, status)
	require.Contains(t, output, "\"error\": \"proxy_not_found\"")
	output, _ = run(env, "clash_api", "set_group_proxy", "no-group", "main-1-out")
	require.Contains(t, output, "\"error\": \"group_not_found\"")
	output, status = run(env, "clash_api", "get_proxy_latency")
	require.Equal(t, 1, status)
	require.Contains(t, output, "proxy_tag required")
	output, status = run(env, "clash_api", "what")
	require.Equal(t, 1, status)
	require.Contains(t, output, "unknown action")
	// the dashboard of GitHub, as sing-box downloads it; its failure as sing-box tells it
	output, status = run(env, "clash_api", "upgrade_ui")
	require.Zero(t, status)
	require.Equal(t, "{\n  \"success\": true\n}\n", output)
	output, status = run(env, "clash_api", "upgrade_ui")
	require.Equal(t, 1, status)
	require.Contains(t, output, "download external ui failed: 404 Not Found")
	require.Contains(t, output, "\"http_code\": 500")

	// nothing runs: no API, and no answer
	running.facts = api.Facts{}
	output, status = run(env, "clash_api", "get_proxies")
	require.Equal(t, 1, status)
	require.Empty(t, output)
	// no backend at all
	output, status = run(Environment{Socket: filepath.Join(t.TempDir(), "none.sock")}, "clash_api", "get_proxies")
	require.Equal(t, 1, status)
	require.Empty(t, output)
	require.Len(t, seen, 2, "the API was asked with nothing running")
}

// The notices of the user interface ask with a cursor: each line comes once, and the lines
// of another run come all.
func TestLogsSince(t *testing.T) {
	logs := logbuf.New(1 << 16)
	logs.Write("backend", "info", "one")
	logs.Write("backend", "error", "two")
	client := api.Client{Path: serve(t, &backend{}, logs)}
	page := logsSince(client, "")
	require.Len(t, page.Lines, 2)
	cursor := page.Run + ":" + strconv.FormatUint(page.Next, 10)
	require.Empty(t, logsSince(client, cursor).Lines)
	logs.Write("backend", "info", "three")
	page = logsSince(client, cursor)
	require.Len(t, page.Lines, 1)
	require.Contains(t, page.Lines[0], "three")
	// a number of another run says nothing of this one
	require.Len(t, logsSince(client, "anotherrun:2").Lines, 3)
	// no backend: the system log, whatever it holds, under the run "system"
	require.Equal(t, "system", logsSince(api.Client{Path: filepath.Join(t.TempDir(), "none.sock")}, cursor).Run)
}

// An answer stays below what rpcd passes on, with the newest lines.
func TestNewestLines(t *testing.T) {
	var lines []string
	for index := 0; index < 400; index++ {
		lines = append(lines, strconv.Itoa(index)+" "+strings.Repeat("x", 1000))
	}
	kept := newest(lines)
	size := 0
	for _, line := range kept {
		size += len(line) + 1
	}
	require.LessOrEqual(t, size, logAnswerLimit)
	require.Equal(t, lines[len(lines)-1], kept[len(kept)-1])
	require.Greater(t, len(kept), 150)
	require.Equal(t, []string{"a"}, newest([]string{"a"}))
}

// The commands of the subscriptions ask the backend and print its answers; without a
// backend the page gets an answer it can show.
func TestSubscriptionCommands(t *testing.T) {
	changed := time.Now().Add(-3 * time.Hour)
	running := &backend{
		status:        api.Status{Running: true},
		subscriptions: []api.SubscriptionState{{Name: "prov1", Servers: 12, Usable: 10, Changed: &changed, Route: "direct"}, {Name: "prov2", Error: "the provider answers 403 Forbidden"}},
		preview:       api.SubscriptionPreview{Route: "direct", Servers: []api.PreviewServer{{Name: "NL 1", Scheme: "vless", Address: "nl1.example:443", Link: "vless://x"}}},
		group:         api.GroupPreview{Chosen: []string{"NL 1"}, Total: 3},
	}
	env := Environment{Socket: serve(t, running, logbuf.New(1<<10))}
	output, status := run(env, "subscription_load", "https://sub.example/sub/TOKEN")
	require.Zero(t, status)
	require.Equal(t, []string{"https://sub.example/sub/TOKEN"}, running.loaded)
	var preview api.SubscriptionPreview
	require.NoError(t, json.Unmarshal([]byte(output), &preview))
	require.Equal(t, "NL 1", preview.Servers[0].Name)
	output, status = run(env, "group_check", `{"subscriptions":["prov1"],"include":["NL"],"exclude":[]}`)
	require.Zero(t, status)
	require.Equal(t, []string{"NL"}, running.checked[0].Include)
	require.JSONEq(t, `{"chosen":["NL 1"],"total":3}`, output)
	output, status = run(env, "subscription_status")
	require.Zero(t, status)
	require.Contains(t, output, `"name":"prov1"`)
	output, status = run(env, "subscription_update", "prov1")
	require.Zero(t, status)
	require.Equal(t, []string{"prov1"}, running.updated)
	require.Contains(t, output, "✅ prov1: 12 servers, 10 can be used; servers changed 3 h ago (direct); not checked since the start")
	require.Contains(t, output, "❌ prov2: no list: the provider answers 403 Forbidden")
	_, status = run(env, "group_check", "not json")
	require.NotZero(t, status)

	none := Environment{Socket: filepath.Join(t.TempDir(), "none.sock")}
	output, status = run(none, "subscription_load", "https://sub.example/sub/TOKEN")
	require.Zero(t, status)
	require.Contains(t, output, "podkop does not run")
	output, status = run(none, "subscription_status")
	require.Zero(t, status)
	require.Equal(t, "[]\n", output)
	output, status = run(none, "hwid")
	require.Zero(t, status)
	require.Contains(t, output, "source: ")
}
