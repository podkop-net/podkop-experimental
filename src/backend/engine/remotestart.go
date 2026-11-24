package engine

import (
	"context"
	"os"

	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/service"
)

// startEmptyVariable is the switch of sing-box (route/rule) for rule sets that start empty instead
// of downloading during the start: the service may set it, to nothing as well.
const startEmptyVariable = "SING_BOX_RULE_SET_START_EMPTY"

// withRemoteStart gives a context how the rule sets of its box start: one with nothing cached
// starts empty and is downloaded after the start, so that an apply that adds a list does not leave
// the LAN without DNS while it downloads. The environment tells sing-box instead when the service
// set it.
func withRemoteStart(ctx context.Context) context.Context {
	if _, set := os.LookupEnv(startEmptyVariable); set {
		return ctx
	}
	return service.ContextWithPtr(ctx, &R.RemoteStart{Empty: true})
}
