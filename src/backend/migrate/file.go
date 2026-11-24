package migrate

import (
	"os"

	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	E "github.com/sagernet/sing/common/exceptions"
)

// Backup is where the settings file is kept as it was before the format Version.
func Backup(settingsPath string) string {
	return settingsPath + ".pre-0.8.8"
}

// File converts the settings file in place. The file as it was is kept as Backup unless a
// copy is there already: a second conversion (a backup of 0.8 restored later) keeps the
// first copy. A file of the format already is not written, nor locked. The notes are those of
// Convert, after one that names the copy.
func File(settingsPath string) ([]string, error) {
	parsed, err := read(settingsPath)
	if err != nil {
		return nil, err
	}
	if !Needed(parsed) {
		return nil, nil
	}
	var notes []string
	_, err = uci.Edit(settingsPath, func(parsed *uci.Package) error {
		notes = nil
		if !Needed(parsed) {
			// another process converted it meanwhile
			return nil
		}
		if _, err := keepOld(settingsPath); err != nil {
			return E.Cause(err, "keep the old settings")
		}
		notes = append([]string{"the settings were converted to the format " + Version + ": the old file is " + Backup(settingsPath)}, Convert(parsed)...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return notes, nil
}

func read(settingsPath string) (*uci.Package, error) {
	content, err := os.ReadFile(settingsPath)
	if err != nil {
		return nil, err
	}
	parsed, err := uci.Parse(content)
	if err != nil {
		return nil, E.Cause(err, "read ", settingsPath)
	}
	return parsed, nil
}

// keepOld keeps the settings file, as it is on the disk now, as Backup, unless a copy is there
// already. It tells whether it made one.
func keepOld(settingsPath string) (bool, error) {
	if _, err := os.Stat(Backup(settingsPath)); !os.IsNotExist(err) {
		return false, nil
	}
	if err := uci.Copy(settingsPath, Backup(settingsPath)); err != nil {
		return false, err
	}
	return true, nil
}
