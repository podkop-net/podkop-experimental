package ctl

import (
	"bytes"
	"context"
	"fmt"

	"github.com/podkop-net/podkop-experimental/src/backend/ubus"
)

// The commands the running backend answers itself, as the method "run" of its object on
// ubus: the page calls them through uhttpd and no program starts for a call, where each call
// of /usr/bin/podkop was a start of the whole binary. These only read and check. The
// actions on the service and the settings (start, stop, reload, list_update,
// restore_routing) stay programs of their own: the backend would end in the middle of its
// answer. global_check too: it is rare and long, and in a program of its own a mistake in it
// cannot take the backend down.
var inProcess = map[string]bool{
	"get_status":               true,
	"get_sing_box_status":      true,
	"get_system_info":          true,
	"get_sing_box_features":    true,
	"check_dns_available":      true,
	"check_sing_box":           true,
	"check_nft_rules":          true,
	"check_fakeip":             true,
	"check_fakeip_client":      true,
	"clash_api":                true,
	"check_links":              true,
	"check_logs":               true,
	"show_sing_box_config":     true,
	"show_config":              true,
	"show_version":             true,
	"show_system_info":         true,
	"check_nft":                true,
	"list_status":              true,
	"subscription_load":        true,
	"subscription_load_start":  true,
	"subscription_load_state":  true,
	"subscription_load_cancel": true,
	"group_check":              true,
	"subscription_status":      true,
	"hwid":                     true,
}

// ExecResult is the answer of "run", in the form of the answer of rpcd's file.exec, so that
// the page reads both alike.
type ExecResult struct {
	Code   int    `json:"code"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

// BusObject is the object "podkop" the running backend publishes on ubus. Its method "run"
// takes the command and its arguments as file.exec takes those of a program ("command",
// "params") and answers ExecResult; a command that is not answered here is StatusNotSupported,
// and the page runs the program instead.
func BusObject(env Environment) ubus.Object {
	return ubus.Object{
		Name: "podkop",
		Methods: map[string]ubus.Method{
			"run": {
				Arguments: map[string]int{"command": ubus.TypeString, "params": ubus.TypeArray},
				Call: func(ctx context.Context, arguments map[string]any) (any, int) {
					command, _ := arguments["command"].(string)
					if !inProcess[command] {
						return nil, ubus.StatusNotSupported
					}
					line := []string{command}
					if params, found := arguments["params"]; found {
						list, isList := params.([]any)
						if !isList {
							return nil, ubus.StatusInvalidArgument
						}
						for _, param := range list {
							text, isText := param.(string)
							if !isText {
								return nil, ubus.StatusInvalidArgument
							}
							line = append(line, text)
						}
					}
					return runSafely(env, line), ubus.StatusOK
				},
			},
		},
	}
}

// runSafely runs a command inside the backend: a panic of the command ends the command, not
// the backend.
func runSafely(env Environment, line []string) (result ExecResult) {
	var output, errorOutput bytes.Buffer
	defer func() {
		if recovered := recover(); recovered != nil {
			result = ExecResult{Code: 1, Stderr: fmt.Sprint("the command failed: ", recovered)}
		}
	}()
	code := Run(env, line, &output, &errorOutput)
	return ExecResult{Code: code, Stdout: output.String(), Stderr: errorOutput.String()}
}
