package migrate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The settings podkop 0.7.24 installs and LuCI saved, with the options the steps look at, and what
// an install made of them: 0.8.22 with its uci-defaults script and this build (the differential
// test of the workspace, lab/v0823/set).
const settings07 = `# kept by hand
config settings 'settings'
	option dns_type 'udp'
	option config_path '/etc/sing-box/config.json'
	option cache_path '/tmp/sing-box/cache.db'
	option urltest_testing_url 'https://www.gstatic.com/generate_204'
	option urltest_check_interval '3m'
	option guard '1'
	option liveness '0'
	option nothing ''

config section 'main'
	option connection_type 'proxy'
	option proxy_config_type 'url'
	option proxy_string 'socks5://203.0.113.15:1080'
	option config_path 'not of the settings'
`

const settings2 = `
config settings 'settings'
	option dns_type 'udp'
	option cache_path '/var/run/podkop/cache.db'
	option config_version '2'
	option urltest_defaults '0.8.10'

config source 'main_link'
	option type 'links'
	list link 'socks5://203.0.113.15:1080'

config section 'main'
	option config_path 'not of the settings'

config member
	option section 'main'
	option role 'server'
	option source 'main_link'
`

// router is a place of a test: the settings file, and the root of the paths in it.
func router(t *testing.T, text string) place {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(root+"/etc/config", 0o755))
	place := place{settingsPath: root + "/etc/config/podkop", root: root}
	require.NoError(t, os.WriteFile(place.settingsPath, []byte(text), 0o600))
	return place
}

func (p place) read(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile(p.settingsPath)
	require.NoError(t, err)
	return string(content)
}

// file writes a file of the router.
func (p place) file(t *testing.T, path string, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(p.root+path), 0o755))
	require.NoError(t, os.WriteFile(p.root+path, []byte(content), 0o640))
}

// files are the files of the router but the settings, with what is in them.
func (p place) files(t *testing.T) map[string]string {
	t.Helper()
	found := make(map[string]string)
	require.NoError(t, filepath.WalkDir(p.root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || path == p.settingsPath {
			return err
		}
		content, err := os.ReadFile(path)
		found[strings.TrimPrefix(path, p.root)] = string(content)
		return err
	}))
	return found
}

// installed runs Install there and returns the lines for the journal, with the paths of the router.
func (p place) installed(t *testing.T) ([]string, error) {
	t.Helper()
	var notes []string
	err := install(p, func(note string) { notes = append(notes, strings.ReplaceAll(note, p.root, "")) })
	return notes, err
}

func stepNamed(t *testing.T, name string) step {
	t.Helper()
	for _, step := range steps {
		if step.name == name {
			return step
		}
	}
	t.Fatal("no step " + name)
	return step{}
}

// The steps are these, in this order: a step added goes to the end, and none moves.
func TestSteps(t *testing.T) {
	t.Parallel()
	var names []string
	for _, step := range steps {
		names = append(names, step.name)
		require.Equal(t, step.name == "copy of the old settings", step.must, step.name)
		require.NotEmpty(t, step.failed, step.name)
	}
	require.Equal(t, []string{"copy of the old settings", "options gone", "cache file", "format 2", "server check"}, names)
}

func TestInstall(t *testing.T) {
	t.Parallel()
	place := router(t, settings07)
	place.file(t, "/tmp/sing-box/cache.db", "the cache")
	notes, err := place.installed(t)
	require.NoError(t, err)
	require.Equal(t, []string{
		"the settings of podkop as they were are kept as /etc/config/podkop.pre-0.8.8",
		"the cache file moved from /tmp/sing-box/cache.db to /var/run/podkop/cache.db",
		"the settings were converted to the format 2: the old file is /etc/config/podkop.pre-0.8.8",
	}, notes)
	require.Equal(t, settings2, "\n"+place.read(t))
	require.Equal(t, map[string]string{
		// as it was before anything was changed, byte for byte: the way back to podkop 0.7
		"/etc/config/podkop.pre-0.8.8": settings07,
		"/var/run/podkop/cache.db":     "the cache",
	}, place.files(t))

	// a second run has nothing to do
	before, err := os.Stat(place.settingsPath)
	require.NoError(t, err)
	notes, err = place.installed(t)
	require.NoError(t, err)
	require.Empty(t, notes)
	after, err := os.Stat(place.settingsPath)
	require.NoError(t, err)
	require.True(t, os.SameFile(before, after), "the file is not written")
	require.Len(t, place.files(t), 2)
}

// A run cut short at any step (the power lost) is made whole by the next one, to the same end.
func TestInstallCutShort(t *testing.T) {
	t.Parallel()
	for count := range steps {
		place := router(t, settings07)
		place.file(t, "/tmp/sing-box/cache.db", "the cache")
		for _, step := range steps[:count] {
			_, err := step.run(place)
			require.NoError(t, err)
		}
		_, err := place.installed(t)
		require.NoError(t, err)
		require.Equal(t, settings2, "\n"+place.read(t), "cut short after %d steps", count)
		require.Equal(t, map[string]string{"/etc/config/podkop.pre-0.8.8": settings07, "/var/run/podkop/cache.db": "the cache"}, place.files(t))
	}
}

// The settings of the package: of the format already. The one change is the mark of the server check.
func TestInstallNewSettings(t *testing.T) {
	t.Parallel()
	place := router(t, "config settings 'settings'\n\toption config_version '2'\n\toption cache_path '/usr/share/podkop/cache.db'\n")
	notes, err := place.installed(t)
	require.NoError(t, err)
	require.Empty(t, notes)
	require.Equal(t, "config settings 'settings'\n\toption config_version '2'\n\toption cache_path '/usr/share/podkop/cache.db'\n\toption urltest_defaults '0.8.10'\n", place.read(t))
	require.Empty(t, place.files(t), "no copy")
}

func TestInstallNoSettings(t *testing.T) {
	t.Parallel()
	place := router(t, "")
	// an empty file, a file without the section: nothing to do, nothing to tell
	for _, text := range []string{"", "\n", "config section 'main'\n\toption connection_type 'block'\n"} {
		require.NoError(t, os.WriteFile(place.settingsPath, []byte(text), 0o600))
		notes, err := place.installed(t)
		require.NoError(t, err, text)
		require.Empty(t, notes)
		require.Equal(t, text, place.read(t))
		require.Empty(t, place.files(t))
	}
	// no file, and one that cannot be read: told once, as the conversion told it
	require.NoError(t, os.WriteFile(place.settingsPath, []byte("config settings 'open\n"), 0o600))
	notes, err := place.installed(t)
	require.Empty(t, notes)
	require.EqualError(t, err, "the settings were not converted: read "+place.settingsPath+": line 1: a single quote is not closed")
	require.Equal(t, "config settings 'open\n", place.read(t))
	require.NoError(t, os.Remove(place.settingsPath))
	notes, err = place.installed(t)
	require.Empty(t, notes)
	require.EqualError(t, err, "the settings were not converted: open "+place.settingsPath+": no such file or directory")
	require.Empty(t, place.files(t))
}

// The copy is made under config_version other than 2, when the settings are there and no copy is.
func TestKeepOldSettings(t *testing.T) {
	t.Parallel()
	const old = "# a comment\nconfig settings 'settings'\n\toption config_path '/etc/sing-box/config.json'\n"
	for _, test := range []struct {
		name, text, there string
		kept              bool
	}{
		{"no version", old, "", true},
		{"version 1", old + "\toption config_version '1'\n", "", true},
		{"a version to come", old + "\toption config_version '3'\n", "", true},
		{"version 2", old + "\toption config_version '2'\n", "", false},
		{"a copy is there", old, "the first copy", false},
		{"no settings", "config section 'settings'\n\toption config_path 'x'\n", "", false},
		{"settings without a name", "config settings\n\toption config_path 'x'\n", "", false},
	} {
		place := router(t, test.text)
		then := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		require.NoError(t, os.Chmod(place.settingsPath, 0o640))
		require.NoError(t, os.Chtimes(place.settingsPath, then, then))
		if test.there != "" {
			place.file(t, "/etc/config/podkop.pre-0.8.8", test.there)
		}
		notes, err := stepNamed(t, "copy of the old settings").run(place)
		require.NoError(t, err, test.name)
		require.Equal(t, test.text, place.read(t), test.name)
		switch {
		case test.kept:
			require.Len(t, notes, 1, test.name)
			require.Equal(t, map[string]string{"/etc/config/podkop.pre-0.8.8": test.text}, place.files(t), test.name)
			info, err := os.Stat(Backup(place.settingsPath))
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o640), info.Mode(), test.name)
			require.True(t, info.ModTime().Equal(then), test.name)
		case test.there != "":
			require.Empty(t, notes, test.name)
			require.Equal(t, map[string]string{"/etc/config/podkop.pre-0.8.8": test.there}, place.files(t), test.name)
		default:
			require.Empty(t, notes, test.name)
			require.Empty(t, place.files(t), test.name)
		}
	}
}

// asNobody runs do with the rights of nobody over the file system, when the test runs as root.
func asNobody(t *testing.T, root string, do func()) {
	t.Helper()
	for directory := filepath.Dir(root); directory != os.TempDir() && directory != "/"; directory = filepath.Dir(directory) {
		_ = os.Chmod(directory, 0o755)
	}
	require.NoError(t, os.Chmod(root, 0o755))
	if os.Geteuid() != 0 {
		do()
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	require.NoError(t, syscall.Setfsuid(65534))
	defer func() { require.NoError(t, syscall.Setfsuid(0)) }()
	do()
}

// Without the copy nothing is changed: the way back to podkop 0.7 needs what the next steps take.
func TestInstallWithoutCopy(t *testing.T) {
	t.Parallel()
	place := router(t, settings07)
	place.file(t, "/tmp/sing-box/cache.db", "the cache")
	require.NoError(t, os.Chmod(place.settingsPath, 0o644))
	require.NoError(t, os.Chmod(place.root+"/tmp/sing-box", 0o777))
	require.NoError(t, os.Chmod(filepath.Dir(place.settingsPath), 0o555))
	defer os.Chmod(filepath.Dir(place.settingsPath), 0o755)
	asNobody(t, place.root, func() {
		notes, err := place.installed(t)
		require.ErrorContains(t, err, "the old settings could not be kept, so nothing in them is changed: ")
		require.ErrorIs(t, err, os.ErrPermission)
		require.NotContains(t, err.Error(), "\n", "the other steps are not tried")
		require.Empty(t, notes)
	})
	require.Equal(t, settings07, place.read(t))
	require.Equal(t, map[string]string{"/tmp/sing-box/cache.db": "the cache"}, place.files(t))
}

// A step that fails does not keep the next ones from being made.
func TestInstallStepFails(t *testing.T) {
	t.Parallel()
	place := router(t, settings07)
	place.file(t, "/tmp/sing-box/cache.db", "the cache")
	// where the directory of the cache file is to be made is a file
	require.NoError(t, os.MkdirAll(place.root+"/var/run", 0o755))
	require.NoError(t, os.WriteFile(place.root+"/var/run/podkop", nil, 0o600))
	notes, err := place.installed(t)
	require.ErrorContains(t, err, "the cache file was not moved: ")
	require.Equal(t, []string{
		"the settings of podkop as they were are kept as /etc/config/podkop.pre-0.8.8",
		"the settings were converted to the format 2: the old file is /etc/config/podkop.pre-0.8.8",
	}, notes)
	require.Equal(t, settings2, "\n"+place.read(t))
	content, err := os.ReadFile(place.root + "/tmp/sing-box/cache.db")
	require.NoError(t, err)
	require.Equal(t, "the cache", string(content))
}

func TestDeleteGone(t *testing.T) {
	t.Parallel()
	for text, want := range map[string]string{
		"config settings 'settings'\n\toption a 'x'\n\toption config_path 'p'\n\toption guard '1'\n\toption liveness '0'\n\nconfig section 'main'\n\toption guard 'mine'\n": "config settings 'settings'\n\toption a 'x'\n\nconfig section 'main'\n\toption guard 'mine'\n",
		// each alone, a list
		"config settings 'settings'\n\toption config_path 'p'\n": "config settings 'settings'\n",
		"config settings 'settings'\n\toption guard '1'\n":       "config settings 'settings'\n",
		"config settings 'settings'\n\tlist liveness '1'\n":      "config settings 'settings'\n",
		// a section of another type that has the name is no settings
		"# a comment\nconfig section 'settings'\n\toption guard '1'\n": "# a comment\nconfig section 'settings'\n\toption guard '1'\n",
		// an option set to nothing is none to libuci: the file as it is
		"# a comment\nconfig settings 'settings'\n\toption guard ''\n": "# a comment\nconfig settings 'settings'\n\toption guard ''\n",
		// nothing to delete: the file as it is
		"# a comment\nconfig settings 'settings'\n\toption guards '1'\n": "# a comment\nconfig settings 'settings'\n\toption guards '1'\n",
		"# a comment\nconfig section 'main'\n\toption guard 'mine'\n":    "# a comment\nconfig section 'main'\n\toption guard 'mine'\n",
	} {
		place := router(t, text)
		notes, err := stepNamed(t, "options gone").run(place)
		require.NoError(t, err)
		require.Empty(t, notes)
		require.Equal(t, want, place.read(t))
		require.Empty(t, place.files(t))
	}
}

func TestMoveCache(t *testing.T) {
	t.Parallel()
	settings := func(path string) string { return "config settings 'settings'\n\toption cache_path '" + path + "'\n" }
	for _, test := range []struct {
		name, path  string
		files       map[string]string
		want        string
		moved       string
		filesBehind map[string]string
	}{
		{"in RAM", "/tmp/sing-box/cache.db", map[string]string{"/tmp/sing-box/cache.db": "c"},
			"/var/run/podkop/cache.db", "the cache file moved from /tmp/sing-box/cache.db to /var/run/podkop/cache.db", map[string]string{"/var/run/podkop/cache.db": "c"}},
		{"on flash", "/usr/share/sing-box/cache.db", map[string]string{"/usr/share/sing-box/cache.db": "c"},
			"/usr/share/podkop/cache.db", "the cache file moved from /usr/share/sing-box/cache.db to /usr/share/podkop/cache.db", map[string]string{"/usr/share/podkop/cache.db": "c"}},
		{"another name, deeper, with a space", "/tmp/sing-box/deep/my cache", map[string]string{"/tmp/sing-box/deep/my cache": "c"},
			"/var/run/podkop/deep/my cache", "the cache file moved from /tmp/sing-box/deep/my cache to /var/run/podkop/deep/my cache", map[string]string{"/var/run/podkop/deep/my cache": "c"}},
		{"a file is there", "/tmp/sing-box/cache.db", map[string]string{"/tmp/sing-box/cache.db": "old", "/var/run/podkop/cache.db": "new"},
			"/var/run/podkop/cache.db", "", map[string]string{"/tmp/sing-box/cache.db": "old", "/var/run/podkop/cache.db": "new"}},
		{"no file", "/tmp/sing-box/cache.db", map[string]string{"/tmp/sing-box/other.db": "c"},
			"/var/run/podkop/cache.db", "", map[string]string{"/tmp/sing-box/other.db": "c"}},
		{"a directory", "/tmp/sing-box/d", map[string]string{"/tmp/sing-box/d/x": "c"},
			"/var/run/podkop/d", "", map[string]string{"/tmp/sing-box/d/x": "c"}},
		{"the directory itself", "/tmp/sing-box/", map[string]string{"/tmp/sing-box/x": "c"},
			"/var/run/podkop/", "", map[string]string{"/tmp/sing-box/x": "c"}},
		{"a place of one's own", "/mnt/usb/cache.db", map[string]string{"/mnt/usb/cache.db": "c"},
			"/mnt/usb/cache.db", "", map[string]string{"/mnt/usb/cache.db": "c"}},
		{"the backend's own", "/usr/share/podkop/cache.db", map[string]string{"/usr/share/podkop/cache.db": "c"},
			"/usr/share/podkop/cache.db", "", map[string]string{"/usr/share/podkop/cache.db": "c"}},
		{"another directory of a like name", "/tmp/sing-box2/cache.db", map[string]string{"/tmp/sing-box2/cache.db": "c"},
			"/tmp/sing-box2/cache.db", "", map[string]string{"/tmp/sing-box2/cache.db": "c"}},
		{"a line break at the end", "/tmp/sing-box/cache.db\n", map[string]string{"/tmp/sing-box/cache.db": "c"},
			"/var/run/podkop/cache.db", "the cache file moved from /tmp/sing-box/cache.db to /var/run/podkop/cache.db", map[string]string{"/var/run/podkop/cache.db": "c"}},
	} {
		place := router(t, settings(test.path))
		for path, content := range test.files {
			place.file(t, path, content)
		}
		notes, err := stepNamed(t, "cache file").run(place)
		require.NoError(t, err, test.name)
		if test.moved == "" {
			require.Empty(t, notes, test.name)
		} else {
			require.Equal(t, []string{test.moved}, notes, test.name)
		}
		require.Equal(t, settings(test.want), place.read(t), test.name)
		require.Equal(t, test.filesBehind, place.files(t), test.name)
		// once: the second run finds the new path
		notes, err = stepNamed(t, "cache file").run(place)
		require.NoError(t, err, test.name)
		require.Empty(t, notes, test.name)
		require.Equal(t, test.filesBehind, place.files(t), test.name)
	}
	// without the option, and without the section, there is nothing to move
	for _, text := range []string{"config settings 'settings'\n", "config section 'main'\n\toption cache_path '/tmp/sing-box/cache.db'\n", "config section 'settings'\n\toption cache_path '/tmp/sing-box/cache.db'\n"} {
		place := router(t, text)
		place.file(t, "/tmp/sing-box/cache.db", "c")
		_, err := stepNamed(t, "cache file").run(place)
		require.NoError(t, err)
		require.Equal(t, text, place.read(t))
		require.Equal(t, map[string]string{"/tmp/sing-box/cache.db": "c"}, place.files(t))
	}
}

// The file is moved also when the settings cannot be written: the backend has the cache at the new
// place whatever they say.
func TestMoveCacheSettingsNotWritten(t *testing.T) {
	t.Parallel()
	text := "config settings 'settings'\n\toption cache_path '/tmp/sing-box/cache.db'\n"
	place := router(t, text)
	place.file(t, "/tmp/sing-box/cache.db", "c")
	require.NoError(t, os.Chmod(place.settingsPath, 0o644))
	require.NoError(t, os.Chmod(place.root+"/tmp/sing-box", 0o777))
	require.NoError(t, os.MkdirAll(place.root+"/var/run", 0o755))
	require.NoError(t, os.Chmod(place.root+"/var/run", 0o777))
	require.NoError(t, os.Chmod(filepath.Dir(place.settingsPath), 0o555))
	defer os.Chmod(filepath.Dir(place.settingsPath), 0o755)
	asNobody(t, place.root, func() {
		notes, err := stepNamed(t, "cache file").run(place)
		require.ErrorIs(t, err, os.ErrPermission)
		require.Equal(t, []string{"the cache file moved from /tmp/sing-box/cache.db to /var/run/podkop/cache.db"}, notes)
	})
	require.Equal(t, text, place.read(t))
	require.Equal(t, map[string]string{"/var/run/podkop/cache.db": "c"}, place.files(t))
}

// A file moved to another file system is there with its content, its mode and its time, and no
// longer where it was; one that cannot be moved whole leaves nothing half made.
func TestMoveAcross(t *testing.T) {
	t.Parallel()
	place := router(t, "")
	place.file(t, "/a/cache.db", "the cache")
	then := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	require.NoError(t, os.Chtimes(place.root+"/a/cache.db", then, then))
	info, err := os.Stat(place.root + "/a/cache.db")
	require.NoError(t, err)
	require.NoError(t, os.Mkdir(place.root+"/b", 0o755))
	require.NoError(t, moveAcross(place.root+"/a/cache.db", place.root+"/b/cache.db", info))
	require.Equal(t, map[string]string{"/b/cache.db": "the cache"}, place.files(t))
	moved, err := os.Stat(place.root + "/b/cache.db")
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), moved.Mode())
	require.True(t, moved.ModTime().Equal(then))

	// a directory cannot be read as a file: the copy begun is taken away
	require.NoError(t, os.Mkdir(place.root+"/a/dir", 0o755))
	require.Error(t, moveAcross(place.root+"/a/dir", place.root+"/b/dir", info))
	_, err = os.Stat(place.root + "/b/dir")
	require.ErrorIs(t, err, os.ErrNotExist)
	// what is there stays
	place.file(t, "/a/cache.db", "another")
	require.ErrorIs(t, moveAcross(place.root+"/a/cache.db", place.root+"/b/cache.db", info), os.ErrExist)
	require.Equal(t, map[string]string{"/a/cache.db": "another", "/b/cache.db": "the cache"}, place.files(t))
}

// /dev/shm is another file system than the directory of the test wherever the tests run in a
// container: the rename fails there, and the file is moved all the same.
func TestMoveFileToAnotherFileSystem(t *testing.T) {
	t.Parallel()
	other, err := os.MkdirTemp("/dev/shm", "podkop-test-*")
	if err != nil {
		t.Skip("no /dev/shm: ", err)
	}
	defer os.RemoveAll(other)
	place := router(t, "")
	place.file(t, "/a/cache.db", "the cache")
	if err := os.Rename(place.root+"/a/cache.db", other+"/cache.db"); err == nil {
		t.Skip("/dev/shm is on the file system of the test")
	}
	moved, err := moveFile(place.root+"/a/cache.db", other+"/made/cache.db")
	require.NoError(t, err)
	require.True(t, moved)
	content, err := os.ReadFile(other + "/made/cache.db")
	require.NoError(t, err)
	require.Equal(t, "the cache", string(content))
	require.Empty(t, place.files(t))
}

func TestCheckDefaults(t *testing.T) {
	t.Parallel()
	const mark = "\toption urltest_defaults '0.8.10'\n"
	for text, want := range map[string]string{
		"config settings 'settings'\n\toption urltest_testing_url 'https://www.gstatic.com/generate_204'\n\toption urltest_check_interval '3m'\n\toption a 'x'\n": "config settings 'settings'\n\toption a 'x'\n" + mark,
		"config settings 'settings'\n\toption urltest_testing_url 'https://www.gstatic.com/generate_204'\n\toption urltest_check_interval '30s'\n":                "config settings 'settings'\n\toption urltest_check_interval '30s'\n" + mark,
		"config settings 'settings'\n\toption urltest_testing_url 'https://cp.cloudflare.com/generate_204'\n\toption urltest_check_interval '3m'\n":               "config settings 'settings'\n\toption urltest_testing_url 'https://cp.cloudflare.com/generate_204'\n" + mark,
		// the URL alone, not among others; an interval as it is written, not as long
		"config settings 'settings'\n\tlist urltest_testing_url 'https://www.gstatic.com/generate_204'\n\tlist urltest_testing_url 'https://x.example/'\n\toption urltest_check_interval '180s'\n": "config settings 'settings'\n\tlist urltest_testing_url 'https://www.gstatic.com/generate_204'\n\tlist urltest_testing_url 'https://x.example/'\n\toption urltest_check_interval '180s'\n" + mark,
		"config settings 'settings'\n":                               "config settings 'settings'\n" + mark,
		"config settings 'settings'\n\toption urltest_defaults ''\n": "config settings 'settings'\n" + mark,
		// done: values of the old defaults set by hand afterwards stay
		"config settings 'settings'\n\toption urltest_check_interval '3m'\n\toption urltest_defaults '0.8.10'\n": "config settings 'settings'\n\toption urltest_check_interval '3m'\n\toption urltest_defaults '0.8.10'\n",
		"config settings 'settings'\n\toption urltest_check_interval '3m'\n\toption urltest_defaults '0.9'\n":    "config settings 'settings'\n\toption urltest_check_interval '3m'\n\toption urltest_defaults '0.9'\n",
		// the script of the package read a value without the line breaks at its end
		"config settings 'settings'\n\toption urltest_check_interval '3m\n'\n": "config settings 'settings'\n" + mark,
		// no settings
		"config section 'settings'\n\toption urltest_check_interval '3m'\n": "config section 'settings'\n\toption urltest_check_interval '3m'\n",
		"config section 'main'\n\toption urltest_check_interval '3m'\n":     "config section 'main'\n\toption urltest_check_interval '3m'\n",
	} {
		place := router(t, text)
		notes, err := stepNamed(t, "server check").run(place)
		require.NoError(t, err)
		require.Empty(t, notes)
		require.Equal(t, want, place.read(t))
		require.Empty(t, place.files(t))
	}
}

// Two that convert at once, the daemon and "podkop migrate" of an upgrade: one converts, the copy
// is of the old file.
func TestFileAtOnce(t *testing.T) {
	t.Parallel()
	for range 20 {
		place := router(t, settings07)
		var group sync.WaitGroup
		var access sync.Mutex
		var all []string
		for range 4 {
			group.Add(1)
			go func() {
				defer group.Done()
				notes, err := File(place.settingsPath)
				access.Lock()
				defer access.Unlock()
				if err != nil {
					t.Error(err)
				}
				all = append(all, notes...)
			}()
		}
		group.Wait()
		require.Len(t, all, 1, "converted once")
		require.Equal(t, map[string]string{"/etc/config/podkop.pre-0.8.8": settings07}, place.files(t))
	}
}

// Without the copy the file is not converted.
func TestFileWithoutCopy(t *testing.T) {
	t.Parallel()
	place := router(t, settings07)
	require.NoError(t, os.Chmod(place.settingsPath, 0o644))
	require.NoError(t, os.Chmod(filepath.Dir(place.settingsPath), 0o555))
	defer os.Chmod(filepath.Dir(place.settingsPath), 0o755)
	asNobody(t, place.root, func() {
		notes, err := File(place.settingsPath)
		require.ErrorContains(t, err, "keep the old settings")
		require.Empty(t, notes)
	})
	require.Equal(t, settings07, place.read(t))
	require.Empty(t, place.files(t))
}

// A file of the format already is not locked: an apply does not wait for a program that holds it.
func TestFileOfTheFormatIsNotLocked(t *testing.T) {
	t.Parallel()
	place := router(t, settings2)
	held, err := os.Open(place.settingsPath)
	require.NoError(t, err)
	defer held.Close()
	require.NoError(t, syscall.Flock(int(held.Fd()), syscall.LOCK_EX))
	ended := make(chan error, 1)
	go func() {
		_, err := File(place.settingsPath)
		ended <- err
	}()
	select {
	case err := <-ended:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("it waits for the lock")
	}
}
