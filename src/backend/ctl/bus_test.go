package ctl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/diag"
	"github.com/podkop-net/podkop-experimental/src/backend/logbuf"
	"github.com/podkop-net/podkop-experimental/src/backend/ubus"
	"github.com/stretchr/testify/require"
)

func TestBusObject(t *testing.T) {
	directory := t.TempDir()
	write := func(name string, content string) string {
		path := filepath.Join(directory, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o755))
		return path
	}
	logs := logbuf.New(1 << 16)
	logs.Write("backend", "info", "running")
	env := Environment{
		Version: "0.8.0-test", SingBoxVersion: "1.14.3-test",
		Socket: serve(t, &backend{status: api.Status{Running: true}}, logs),
		Paths: diag.Paths{
			Settings: write("podkop", "config settings 'settings'\n\toption dns_type 'udp'\n\nconfig section 'main'\n\toption proxy_string 'socks5://u:p@203.0.113.15:1080'\n"),
			DHCP:     write("dhcp", "config dnsmasq\n\tlist server '127.0.0.42'\n\toption noresolv '1'\n"),
			Network:  write("network", "config interface 'lan'\n"),
		},
		AutostartPath: write("S99podkop", "#!/bin/sh\n"),
	}
	object := BusObject(env)
	require.Equal(t, "podkop", object.Name)
	run := object.Methods["run"].Call
	ctx := context.Background()

	// the answer of the program, in the form of file.exec
	answer, status := run(ctx, map[string]any{"command": "get_status"})
	require.Equal(t, ubus.StatusOK, status)
	require.Equal(t, ExecResult{Code: 0, Stdout: "{\"enabled\":1,\"status\":\"enabled\",\"backend\":true,\"running\":true}\n"}, answer)
	answer, status = run(ctx, map[string]any{"command": "check_logs", "params": []any{"--since", logs.Run() + ":0"}})
	require.Equal(t, ubus.StatusOK, status)
	require.Zero(t, answer.(ExecResult).Code)
	require.Contains(t, answer.(ExecResult).Stdout, "podkop: [info] running")
	// a command that fails answers its code and its error, as the program would
	answer, status = run(ctx, map[string]any{"command": "check_fakeip_client"})
	require.Equal(t, ubus.StatusOK, status)
	require.NotZero(t, answer.(ExecResult).Code)

	// what the backend does not answer itself: the page runs the program
	for _, command := range []string{"start", "stop", "restart", "reload", "list_update", "restore_routing", "global_check", "subscription_update", "", "sh"} {
		_, status = run(ctx, map[string]any{"command": command})
		require.Equal(t, ubus.StatusNotSupported, status, command)
	}
	_, status = run(ctx, map[string]any{})
	require.Equal(t, ubus.StatusNotSupported, status)
	// arguments that are not a list of strings
	_, status = run(ctx, map[string]any{"command": "check_logs", "params": []any{int64(1)}})
	require.Equal(t, ubus.StatusInvalidArgument, status)
	_, status = run(ctx, map[string]any{"command": "check_logs", "params": "--since"})
	require.Equal(t, ubus.StatusInvalidArgument, status)

	// each command answered here is one of the commands
	known := map[string]bool{}
	for _, method := range Methods {
		known[method.Name] = true
	}
	for command := range inProcess {
		require.True(t, known[command], command)
	}

	// the links the page asks about before it saves: in the order asked
	env.CheckLink = func(link string) error {
		if strings.Contains(link, "kcp") {
			return errors.New("the mKCP transport is not supported")
		}
		return nil
	}
	answer, status = BusObject(env).Methods["run"].Call(ctx, map[string]any{"command": "check_links", "params": []any{"vless://a@b:1?type=kcp", "socks5://c:1080"}})
	require.Equal(t, ubus.StatusOK, status)
	require.Equal(t, ExecResult{Stdout: `[{"ok":false,"error":"the mKCP transport is not supported"},{"ok":true}]` + "\n"}, answer)

	// calls at once, as the bus makes them (run with -race)
	var group sync.WaitGroup
	commands := []string{"get_status", "get_sing_box_status", "show_config", "check_logs", "show_version"}
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			answer, status := run(ctx, map[string]any{"command": commands[i%len(commands)]})
			if status != ubus.StatusOK || answer.(ExecResult).Code != 0 {
				t.Errorf("%s: %d %+v", commands[i%len(commands)], status, answer)
			}
		}()
	}
	group.Wait()
}
