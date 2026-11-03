//go:build linux

package main

import (
	"context"
	"runtime"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/ctl"
	"github.com/podkop-net/podkop-experimental/src/backend/detect"
	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/ubus"
)

// Stats is what the dashboard of the page shows of the backend, asked every few seconds
// while it is open, where it used to read two websockets of the Clash API (one of them a
// whole list of the connections every second): the bytes up and down since the sing-box
// that runs started (the page makes rates of two answers and their At), the connections
// open now, the memory of the process as the Clash API tells it.
type Stats struct {
	Running bool `json:"running"`
	// At is the time of the answer in milliseconds of a clock of the process
	At          int64  `json:"at"`
	Up          int64  `json:"up"`
	Down        int64  `json:"down"`
	Connections int    `json:"connections"`
	Memory      uint64 `json:"memory"`
}

type trafficSource interface {
	Traffic() (engine.Traffic, bool)
	// Detect is what the block detector tells of the servers (detect.Report).
	Detect() detect.Report
	// ForceDetect asks for a probe of a server by its tag, or to empty the queue of them; the
	// answer comes at once, the verdict in a later Detect.
	ForceDetect(tag string, cancel bool) detect.ForceAnswer
}

var processStart = time.Now()

// busObject is the object "podkop" of the backend on ubus: the commands of the page
// (ctl.BusObject) and the methods stats, detect and force_detect. A method here is denied to the
// page unless the ACL of its package names it (TestBusMethodsInACL).
func busObject(env ctl.Environment, source trafficSource) ubus.Object {
	object := ctl.BusObject(env)
	object.Methods["stats"] = ubus.Method{
		Call: func(ctx context.Context, arguments map[string]any) (any, int) {
			traffic, running := source.Traffic()
			var memory runtime.MemStats
			runtime.ReadMemStats(&memory)
			return Stats{
				Running:     running,
				At:          time.Since(processStart).Milliseconds(),
				Up:          traffic.Up,
				Down:        traffic.Down,
				Connections: traffic.Connections,
				Memory:      memory.StackInuse + memory.HeapInuse + memory.HeapIdle - memory.HeapReleased,
			}, ubus.StatusOK
		},
	}
	object.Methods["detect"] = ubus.Method{
		Call: func(ctx context.Context, arguments map[string]any) (any, int) {
			return source.Detect(), ubus.StatusOK
		},
	}
	object.Methods["force_detect"] = ubus.Method{
		Arguments: map[string]int{"tag": ubus.TypeString, "cancel": ubus.TypeBool},
		Call: func(ctx context.Context, arguments map[string]any) (any, int) {
			tag, _ := arguments["tag"].(string)
			cancel, _ := arguments["cancel"].(bool)
			if tag == "" && !cancel {
				return nil, ubus.StatusInvalidArgument
			}
			return source.ForceDetect(tag, cancel), ubus.StatusOK
		},
	}
	return object
}
