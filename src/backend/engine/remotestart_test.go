package engine

import (
	"context"
	"os"
	"testing"
	"time"

	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

// The rule sets of every instance start empty when nothing of them is cached, unless the service
// tells sing-box by the environment, to nothing as well.
func TestRemoteStart(t *testing.T) {
	startOf := func(ctx context.Context) *R.RemoteStart { return service.PtrFromContext[R.RemoteStart](ctx) }
	t.Setenv(startEmptyVariable, "") // put back at the end of the test
	require.NoError(t, os.Unsetenv(startEmptyVariable))
	start := startOf(withRemoteStart(service.ExtendContext(context.Background())))
	require.NotNil(t, start)
	require.True(t, start.Empty)
	instance, err := BuildLogged([]byte(`{}`), nil, Services{})
	require.NoError(t, err)
	defer instance.Close(time.Second)
	start = startOf(instance.ctx)
	require.NotNil(t, start, "of an instance")
	require.True(t, start.Empty)

	for _, value := range []string{"", "1"} {
		t.Setenv(startEmptyVariable, value)
		require.Nil(t, startOf(withRemoteStart(service.ExtendContext(context.Background()))), "the service set it to %q", value)
	}
}
