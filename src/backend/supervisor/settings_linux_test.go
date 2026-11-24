package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// settingsAt has the settings of the OpenWrt adapter in a file of the test.
func settingsAt(t *testing.T, text string) string {
	t.Helper()
	path, before := filepath.Join(t.TempDir(), "podkop"), SettingsPath
	SettingsPath = path
	t.Cleanup(func() { SettingsPath = before })
	require.NoError(t, os.WriteFile(path, []byte(text), 0o640))
	return path
}

func fileText(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}

// The key of the Clash API goes into the settings, whatever is in it; the same key is not written
// again.
func TestSetClashSecret(t *testing.T) {
	path := settingsAt(t, "# by hand\nconfig settings 'settings'\n\toption dns_type 'udp'\n\nconfig section 'main'\n\toption yacd_secret_key 'not this one'\n")
	require.NoError(t, Router{}.SetClashSecret("it's \"a\" key"))
	require.Equal(t, "config settings 'settings'\n\toption dns_type 'udp'\n\toption yacd_secret_key 'it'\\''s \"a\" key'\n\nconfig section 'main'\n\toption yacd_secret_key 'not this one'\n", fileText(t, path))
	before, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), before.Mode())
	require.NoError(t, Router{}.SetClashSecret("it's \"a\" key"))
	after, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, os.SameFile(before, after))

	require.NoError(t, os.WriteFile(path, []byte("config section 'main'\n"), 0o640))
	require.ErrorContains(t, Router{}.SetClashSecret("key"), "has no section settings")
	require.Equal(t, "config section 'main'\n", fileText(t, path))
	require.NoError(t, os.Remove(path))
	require.ErrorIs(t, Router{}.SetClashSecret("key"), os.ErrNotExist)
	_, err = os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist, "the file is not made")
}

// Treatments that cannot be written into the settings are told to the page, and nothing is applied.
func TestCuresNotWritten(t *testing.T) {
	s, path := liveSupervisor(t, &fakeInstance{})
	require.NoError(t, os.Remove(path))
	// a context that is never done: a rebuild asked for would hang the test
	ctx := context.Background()
	require.Equal(t, CureInvalid, s.SetCure(ctx, "srv", "record_fragment", "", "", "").State)
	require.Equal(t, CureInvalid, s.ClearCure(ctx, "srv").State)
	require.Equal(t, CureInvalid, s.DropStaleCures(ctx).State)
	_, err := os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
}

// The flag of the shell backend that says "not clean" says "clean" after the DNS was given back;
// any other value, and settings without it, are left alone.
func TestMarkCleanShutdown(t *testing.T) {
	path := settingsAt(t, "")
	for text, want := range map[string]string{
		"config settings 'settings'\n\toption shutdown_correctly '0'\n\toption a 'x'\n": "config settings 'settings'\n\toption shutdown_correctly '1'\n\toption a 'x'\n",
		"# kept\nconfig settings 'settings'\n\toption shutdown_correctly '1'\n":         "# kept\nconfig settings 'settings'\n\toption shutdown_correctly '1'\n",
		"# kept\nconfig settings 'settings'\n\toption a 'x'\n":                          "# kept\nconfig settings 'settings'\n\toption a 'x'\n",
		"# kept\nconfig section 'main'\n\toption shutdown_correctly '0'\n":              "# kept\nconfig section 'main'\n\toption shutdown_correctly '0'\n",
		"config settings 'open\n": "config settings 'open\n",
	} {
		require.NoError(t, os.WriteFile(path, []byte(text), 0o640))
		markCleanShutdown()
		require.Equal(t, want, fileText(t, path))
	}
	require.NoError(t, os.Remove(path))
	markCleanShutdown()
	_, err := os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
}
