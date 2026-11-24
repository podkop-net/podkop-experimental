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

// BusObject is the object "podkop" the running backend publishes on ubus: the methods of the table
// that are on the bus. What they ask of the backend they ask it itself (direct).
func BusObject(env Environment, direct api.Direct, methods []Method) ubus.Object {
	object := ubus.Object{Name: "podkop", Methods: make(map[string]ubus.Method)}
	for _, method := range methods {
		if method.Bus == nil {
			continue
		}
		object.Methods[method.Name] = ubus.Method{
			Arguments: method.Bus.Arguments,
			Call: func(ctx context.Context, arguments map[string]any) (any, int) {
				client := direct
				client.Context = ctx
				return method.Bus.Call(&Call{Name: method.Name, Context: ctx, methods: methods, env: env, client: client}, arguments)
			},
		}
	}
	return object
}

// runCommand is the method "run": it takes the command and its arguments as file.exec takes those
// of a program ("command", "params") and answers ExecResult; a command that is not answered here is
// StatusNotSupported, and the page runs the program instead.
var runCommand = &BusMethod{
	Arguments: map[string]int{"command": ubus.TypeString, "params": ubus.TypeArray},
	Call: func(c *Call, arguments map[string]any) (any, int) {
		command, _ := arguments["command"].(string)
		if method := find(c.methods, command); method == nil || !method.InProcess {
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
		return runSafely(&Call{Name: command, Arguments: line, Context: context.Background(), methods: c.methods, env: c.env, client: c.client}), ubus.StatusOK
	},
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
	code := execute(c)
	return ExecResult{Code: code, Stdout: output.String(), Stderr: errorOutput.String()}
}
