package migrate

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	E "github.com/sagernet/sing/common/exceptions"
)

// step is a change the settings of an older release get once, at an install or an upgrade. A step
// looks at the settings itself and changes nothing where there is nothing (more) to change, so it
// may run any number of times, also after a run that was cut short. A step is never taken out of
// the list or moved in it: a router may come from any release.
type step struct {
	name string
	// run makes the change in the settings file; its notes are for the journal
	run func(place place) ([]string, error)
	// failed is what the journal is told when it fails
	failed string
	// must tells that the steps after it are not made when it fails
	must bool
}

// place is where the steps work: the settings file, and what goes before the other paths ("" on
// the router).
type place struct {
	settingsPath string
	root         string
}

// steps are the steps, in order.
var steps = []step{
	// The way back to podkop 0.7 puts this copy in place (README "Back to podkop"), and podkop 0.7
	// needs what the steps after it change (its config_path, its cache_path): the copy is made
	// before anything is changed, and without it nothing is.
	{"copy of the old settings", keepOldSettings, "the old settings could not be kept, so nothing in them is changed", true},
	// config_path named where podkop 0.7 wrote the configuration of its sing-box: nothing is
	// written there now. guard and liveness were the switches of the guard of 0.8.0-0.8.11.
	{"options gone", deleteGone, "the options of older releases were not deleted", false},
	// podkop 0.7 kept the cache of sing-box in the directories of the sing-box package; the file
	// moves with the option, so the FakeIP addresses handed out before stay
	{"cache file", moveCache, "the cache file was not moved", false},
	// the settings of podkop 0.7 and of podkop-exp up to 0.8.7
	{"format " + Version, convertFormat, "the settings were not converted", false},
	// the server check of 0.8.10
	{"server check", checkDefaults, "the defaults of the server check were not taken", false},
}

// Install makes in the settings file what an older release left to change (steps): "podkop
// migrate", run by the uci-defaults script of the package at an install and an upgrade and at the
// first boot of an image. tell gets a line for the journal of each change worth one. A step that
// fails does not keep the next ones from being made, but for the copy of the old settings. The
// daemon runs none but the conversion (File), also for a file of an older format put in place
// later: a start moves no files.
func Install(settingsPath string, tell func(note string)) error {
	return install(place{settingsPath: settingsPath}, tell)
}

func install(place place, tell func(note string)) error {
	// a file that is not there or cannot be read is told once
	if _, err := read(place.settingsPath); err != nil {
		return E.Cause(err, "the settings were not converted")
	}
	var failures []error
	for _, step := range steps {
		notes, err := step.run(place)
		for _, note := range notes {
			tell(note)
		}
		if err != nil {
			failures = append(failures, E.Cause(err, step.failed))
			if step.must {
				break
			}
		}
	}
	return errors.Join(failures...)
}

// keepOldSettings keeps the settings of an older format as Backup, unless a copy is there.
func keepOldSettings(place place) ([]string, error) {
	var notes []string
	_, err := uci.Edit(place.settingsPath, func(parsed *uci.Package) error {
		if !Needed(parsed) {
			return nil
		}
		kept, err := keepOld(place.settingsPath)
		if kept {
			notes = append(notes, "the settings of podkop as they were are kept as "+Backup(place.settingsPath))
		}
		return err
	})
	return notes, err
}

// goneOptions are options of older releases that nothing reads.
var goneOptions = []string{"config_path", "guard", "liveness"}

func deleteGone(place place) ([]string, error) {
	return nil, editSettings(place, func(settings *uci.Section) {
		for _, name := range goneOptions {
			settings.Delete(name)
		}
	})
}

// movedDirs are the directories of the sing-box package that podkop 0.7 offered for the
// cache file, and where the backend has it instead.
var movedDirs = [][2]string{
	{"/tmp/sing-box/", dataplane.RunDir + "/"},
	{"/usr/share/sing-box/", dataplane.DataDir + "/"},
}

// CachePath is where the backend has a cache file the settings name: a path in a directory of the
// sing-box package (settings kept from podkop 0.7 name those) is taken to the same name in the
// backend's own.
func CachePath(path string) string {
	for _, moved := range movedDirs {
		if rest, found := strings.CutPrefix(path, moved[0]); found {
			return moved[1] + rest
		}
	}
	return path
}

// moveCache writes the path of the cache file as the backend takes it (CachePath), and moves the
// file there unless one is there already.
func moveCache(place place) ([]string, error) {
	var from, to string
	err := editSettings(place, func(settings *uci.Section) {
		from, to = "", ""
		path := value(settings, "cache_path")
		if moved := CachePath(path); moved != path {
			from, to = path, moved
			settings.Set("cache_path", moved)
		}
	})
	if from == "" {
		return nil, err
	}
	// the backend has the cache there whatever the settings say (CachePath): the file is moved
	// also when they could not be written
	moved, errMove := moveFile(place.root+from, place.root+to)
	var notes []string
	if moved {
		notes = append(notes, "the cache file moved from "+from+" to "+to)
	}
	return notes, errors.Join(err, errMove)
}

// moveFile moves a file to a path where nothing is, into a directory made when it is missing; with
// no file there is nothing to move. It tells whether it moved it.
func moveFile(from string, to string) (bool, error) {
	info, err := os.Stat(from)
	if err != nil || !info.Mode().IsRegular() {
		return false, nil
	}
	if _, err := os.Stat(to); err == nil {
		return false, nil
	}
	if err := os.MkdirAll(to[:strings.LastIndexByte(to, '/')+1], 0o755); err != nil {
		return false, err
	}
	err = os.Rename(from, to)
	if errors.Is(err, syscall.EXDEV) {
		err = moveAcross(from, to, info)
	}
	return err == nil, err
}

// moveAcross moves a file to another file system.
func moveAcross(from string, to string, info os.FileInfo) error {
	source, err := os.Open(from)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(destination, source)
	if err == nil {
		if owner, known := info.Sys().(*syscall.Stat_t); known {
			_ = destination.Chown(int(owner.Uid), int(owner.Gid))
		}
		err = destination.Chmod(info.Mode().Perm())
	}
	if errClose := destination.Close(); err == nil {
		err = errClose
	}
	if err != nil {
		_ = os.Remove(to)
		return err
	}
	_ = os.Chtimes(to, info.ModTime(), info.ModTime())
	return os.Remove(from)
}

func convertFormat(place place) ([]string, error) {
	return File(place.settingsPath)
}

// checkDefaults takes the server check of 0.8.10: five URLs of different operators taken in turn,
// a round every minute. Settings that kept the defaults of an older release take the new ones,
// once: the URL of Google alone and a round every 3 minutes (LuCI wrote both when its page was
// saved) are deleted, and the defaults of the backend apply. URLs and an interval set by hand
// stay. settings.urltest_defaults tells that it was done.
func checkDefaults(place place) ([]string, error) {
	return nil, editSettings(place, func(settings *uci.Section) {
		if value(settings, "urltest_defaults") != "" {
			return
		}
		for name, old := range map[string]string{"urltest_testing_url": "https://www.gstatic.com/generate_204", "urltest_check_interval": "3m"} {
			if value(settings, name) == old {
				settings.Delete(name)
			}
		}
		settings.Set("urltest_defaults", "0.8.10")
	})
}

// editSettings changes the section settings of the settings file; a file without one, or with one
// of another type (no settings: the backend refuses such a file), is left as it is.
func editSettings(place place, edit func(settings *uci.Section)) error {
	_, err := uci.Edit(place.settingsPath, func(parsed *uci.Package) error {
		if settings := parsed.Section("settings"); settings != nil && settings.Type == "settings" {
			edit(settings)
		}
		return nil
	})
	return err
}

// value is an option as the script of the package read it, $(uci -q get ...): without the line
// breaks at its end.
func value(settings *uci.Section, name string) string {
	return strings.TrimRight(settings.Get(name), "\n")
}
