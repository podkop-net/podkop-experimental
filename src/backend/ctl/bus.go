package ctl

import (
	"bytes"
	"context"
	"fmt"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/ubus"
)

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
// and the page runs the program instead. The commands ask the backend itself (direct).
func BusObject(env Environment, direct api.Direct) ubus.Object {
	return ubus.Object{
		Name: "podkop",
		Methods: map[string]ubus.Method{
			"run": {
				Arguments: map[string]int{"command": ubus.TypeString, "params": ubus.TypeArray},
				Call: func(ctx context.Context, arguments map[string]any) (any, int) {
					command, _ := arguments["command"].(string)
					if method := find(Methods, command); method == nil || !method.InProcess {
						return nil, ubus.StatusNotSupported
					}
					var line []string
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
					client := direct
					client.Context = ctx
					return runSafely(&Call{Name: command, Arguments: line, env: env, client: client}), ubus.StatusOK
				},
			},
		},
	}
}

// runSafely runs a command inside the backend: a panic of the command ends the command, not
// the backend.
func runSafely(c *Call) (result ExecResult) {
	var output, errorOutput bytes.Buffer
	c.Output, c.Errors = &output, &errorOutput
	defer func() {
		if recovered := recover(); recovered != nil {
			result = ExecResult{Code: 1, Stderr: fmt.Sprint("the command failed: ", recovered)}
		}
	}()
	code := execute(Methods, c)
	return ExecResult{Code: code, Stdout: output.String(), Stderr: errorOutput.String()}
}
