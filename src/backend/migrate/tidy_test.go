package migrate

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const tidySettings = "config settings 'settings'\n\toption config_version '2'\n\toption download_lists_via_proxy '%s'\n\toption download_lists_via_proxy_section '%s'\n" +
	"\nconfig section 'main'\n\toption enabled '1'\n\nconfig section 'youtube'\n\toption enabled '1'\n"

// The lists that downloaded through a section (podkop 0.7, podkop-exp up to 0.8.13, the file of
// 0.8.14 keeping the options it read no more) download through the servers of that rule now; the
// options of the settings go, whatever they were.
func TestTidyDownloadLists(t *testing.T) {
	parsed := parse(t, fmt.Sprintf(tidySettings, "1", "youtube"))
	notes, changed := Tidy(parsed)
	require.True(t, changed)
	require.Len(t, notes, 1)
	require.Contains(t, notes[0], "youtube")
	require.Equal(t, "1", parsed.Section("youtube").Get("download_lists"))
	require.False(t, parsed.Section("main").Has("download_lists"))
	settings := parsed.Section("settings")
	require.False(t, settings.Has("download_lists_via_proxy"))
	require.False(t, settings.Has("download_lists_via_proxy_section"))
	// once is enough
	notes, changed = Tidy(parsed)
	require.False(t, changed)
	require.Empty(t, notes)

	// turned off: the options go, no rule takes the lists
	parsed = parse(t, fmt.Sprintf(tidySettings, "0", "youtube"))
	notes, changed = Tidy(parsed)
	require.True(t, changed)
	require.Empty(t, notes)
	require.False(t, parsed.Section("youtube").Has("download_lists"))

	// a section that is not there: told, no rule takes them
	parsed = parse(t, fmt.Sprintf(tidySettings, "1", "gone"))
	notes, changed = Tidy(parsed)
	require.True(t, changed)
	require.Len(t, notes, 1)
	require.Contains(t, notes[0], "gone")
	require.False(t, parsed.Section("youtube").Has("download_lists"))
	require.False(t, parsed.Section("main").Has("download_lists"))
}

// The file of the format already is written when Tidy changes it, with no copy of the old one;
// written again it does not change.
func TestFileTidies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "podkop")
	require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf(tidySettings, "1", "main")), 0o600))
	notes, err := File(path)
	require.NoError(t, err)
	require.Len(t, notes, 1)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	parsed := parse(t, string(content))
	require.Equal(t, "1", parsed.Section("main").Get("download_lists"))
	require.False(t, parsed.Section("settings").Has("download_lists_via_proxy"))
	_, err = os.Stat(Backup(path))
	require.True(t, os.IsNotExist(err))
	notes, err = File(path)
	require.NoError(t, err)
	require.Empty(t, notes)
	again, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(content), string(again))
}
