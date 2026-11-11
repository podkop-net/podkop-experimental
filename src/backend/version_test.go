package podkop

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEngine(t *testing.T) {
	saved := EngineRelease
	defer func() { EngineRelease = saved }()
	EngineRelease = "r16"
	require.Equal(t, "sing-box 1.14.3, podkop-engine r16, "+Build+" (5d99dc7986cb)", Engine("1.14.3-pdk-5d99dc7986cb"))
	EngineRelease = ""
	require.Equal(t, "sing-box 1.14.3, "+Build, Engine("1.14.3"))
}

// The release of podkop-engine the package writes into the binary (ENGINE_RELEASE of its
// Makefile) is the one go.mod names in the comment of its replace: the replace moves to the
// commit of another release with both changed.
func TestEngineReleaseOfGoMod(t *testing.T) {
	goMod, err := os.ReadFile("go.mod")
	require.NoError(t, err)
	makefile, err := os.ReadFile("../../podkop/Makefile")
	if os.IsNotExist(err) {
		t.Skip("no Makefile of the package next to the backend")
	}
	require.NoError(t, err)
	named := regexp.MustCompile(`(?m)^// podkop-net/sing-box \(podkop-engine (r[0-9]+(?:-rc[0-9]+)?),`).FindSubmatch(goMod)
	require.NotNil(t, named, "go.mod names no release of podkop-engine above its replace")
	written := regexp.MustCompile(`(?m)^ENGINE_RELEASE:=(r[0-9]+(?:-rc[0-9]+)?)$`).FindSubmatch(makefile)
	require.NotNil(t, written, "the Makefile sets no ENGINE_RELEASE")
	require.Equal(t, string(named[1]), string(written[1]))
}
