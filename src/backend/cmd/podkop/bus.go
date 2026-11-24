//go:build linux

package main

import (
	"context"
	"runtime"
	"slices"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/api"
	"github.com/podkop-net/podkop-experimental/src/backend/ctl"
	"github.com/podkop-net/podkop-experimental/src/backend/detect"
	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/supervisor"
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

// busBackend is the supervisor as the methods of the bus ask it, beside what the commands ask of
// the backend (api.Backend).
type busBackend interface {
	Traffic() (engine.Traffic, bool)
	// Detect is what the block detector tells of the servers (detect.Report).
	Detect() detect.Report
	// ForceDetect asks for a probe of a server by its tag, or to empty the queue of them; the
	// answer comes at once, the verdict in a later Detect.
	ForceDetect(tag string, cancel bool) detect.ForceAnswer
	// SetCure stores a treatment for a server and applies it; ClearCure removes it;
	// DropStaleCures removes the treatments of servers no longer in use; SuggestMask probes for a
	// whitelisted SNI that lifts a limit. Each answers with a state.
	SetCure(ctx context.Context, tag, kind, sni, hash, through string) supervisor.CureResult
	ClearCure(ctx context.Context, tag string) supervisor.CureResult
	DropStaleCures(ctx context.Context) supervisor.CureResult
	SuggestMask(ctx context.Context, tag string) supervisor.SuggestResult
}

var processStart = time.Now()

// busObject is the object "podkop" of the backend on ubus. The commands it answers ask the backend
// by direct.
func busObject(env ctl.Environment, direct api.Direct, backend busBackend) ubus.Object {
	return ctl.BusObject(env, direct, methods(backend))
}

// methods are the table of the methods: the commands and the methods of the bus that are theirs
// (ctl.Methods), and the methods of the bus that ask the supervisor. A method of the bus is denied to
// the page unless the ACL of its package grants it under its class (TestBusMethodsInACL).
func methods(backend busBackend) []ctl.Method {
	return append(slices.Clip(ctl.Methods),
		ctl.Method{Name: "stats", Class: ctl.Read, Bus: &ctl.BusMethod{
			Call: func(c *ctl.Call, arguments map[string]any) (any, int) {
				return stats(backend), ubus.StatusOK
			},
		}, Help: "What went through sing-box and the memory of the backend, for the dashboard"},
		ctl.Method{Name: "detect", Class: ctl.Read, Bus: &ctl.BusMethod{
			Call: func(c *ctl.Call, arguments map[string]any) (any, int) {
				return backend.Detect(), ubus.StatusOK
			},
		}, Help: "What the block detector tells of the servers"},
		ctl.Method{Name: "force_detect", Class: ctl.Write, Bus: &ctl.BusMethod{
			Arguments: map[string]int{"tag": ubus.TypeString, "cancel": ubus.TypeBool},
			Call: func(c *ctl.Call, arguments map[string]any) (any, int) {
				tag, _ := arguments["tag"].(string)
				cancel, _ := arguments["cancel"].(bool)
				if tag == "" && !cancel {
					return nil, ubus.StatusInvalidArgument
				}
				return backend.ForceDetect(tag, cancel), ubus.StatusOK
			},
		}, Help: "A probe of a server by its tag, or the queue of them emptied"},
		ctl.Method{Name: "set_cure", Class: ctl.Write, Bus: &ctl.BusMethod{
			Arguments: map[string]int{"tag": ubus.TypeString, "kind": ubus.TypeString, "sni": ubus.TypeString, "hash": ubus.TypeString, "through": ubus.TypeString},
			Call: func(c *ctl.Call, arguments map[string]any) (any, int) {
				tag, _ := arguments["tag"].(string)
				if tag == "" {
					return nil, ubus.StatusInvalidArgument
				}
				kind, _ := arguments["kind"].(string)
				sni, _ := arguments["sni"].(string)
				hash, _ := arguments["hash"].(string)
				through, _ := arguments["through"].(string)
				return backend.SetCure(c.Context, tag, kind, sni, hash, through), ubus.StatusOK
			},
		}, Help: "A treatment of a server stored and applied"},
		ctl.Method{Name: "clear_cure", Class: ctl.Write, Bus: ofServer(func(ctx context.Context, tag string) any {
			return backend.ClearCure(ctx, tag)
		}), Help: "The treatment of a server removed"},
		ctl.Method{Name: "drop_stale_cures", Class: ctl.Write, Bus: &ctl.BusMethod{
			Call: func(c *ctl.Call, arguments map[string]any) (any, int) {
				return backend.DropStaleCures(c.Context), ubus.StatusOK
			},
		}, Help: "The treatments of servers no longer in use removed"},
		ctl.Method{Name: "suggest_mask", Class: ctl.Write, Bus: ofServer(func(ctx context.Context, tag string) any {
			return backend.SuggestMask(ctx, tag)
		}), Help: "A whitelisted SNI that lifts the limit of a server, probed for"},
	)
}

// ofServer is a method of the bus of a server, by its tag.
func ofServer(answer func(ctx context.Context, tag string) any) *ctl.BusMethod {
	return &ctl.BusMethod{
		Arguments: map[string]int{"tag": ubus.TypeString},
		Call: func(c *ctl.Call, arguments map[string]any) (any, int) {
			tag, _ := arguments["tag"].(string)
			if tag == "" {
				return nil, ubus.StatusInvalidArgument
			}
			return answer(c.Context, tag), ubus.StatusOK
		},
	}
}

func stats(backend busBackend) Stats {
	traffic, running := backend.Traffic()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return Stats{
		Running:     running,
		At:          time.Since(processStart).Milliseconds(),
		Up:          traffic.Up,
		Down:        traffic.Down,
		Connections: traffic.Connections,
		Memory:      memory.StackInuse + memory.HeapInuse + memory.HeapIdle - memory.HeapReleased,
	}
}
