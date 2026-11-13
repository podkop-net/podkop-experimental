package migrate

import (
	"os"
	"path/filepath"

	"github.com/podkop-net/podkop-experimental/src/backend/uci"
	E "github.com/sagernet/sing/common/exceptions"
)

// Backup is where File keeps the settings file it converted.
func Backup(path string) string {
	return path + ".pre-0.8.8"
}

// File converts the settings file in place. The file as it was is kept as Backup unless a
// copy is there already: a second conversion (a backup of 0.8 restored later) keeps the
// first copy. A file of the format already is written only when Tidy changes it, with no copy.
// The notes are those of Convert and Tidy, after one that names the copy.
func File(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	parsed, err := uci.Parse(content)
	if err != nil {
		return nil, E.Cause(err, "read ", path)
	}
	needed := Needed(parsed)
	var notes []string
	if needed {
		notes = Convert(parsed)
	}
	tidied, changed := Tidy(parsed)
	if !needed && !changed {
		return nil, nil
	}
	notes = append(notes, tidied...)
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	backup := Backup(path)
	if needed {
		if _, err := os.Stat(backup); os.IsNotExist(err) {
			if err := os.WriteFile(backup, content, info.Mode().Perm()); err != nil {
				return nil, E.Cause(err, "keep the old settings")
			}
		}
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".podkop-migrate-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(parsed.Format()); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return nil, err
	}
	if !needed {
		return notes, nil
	}
	return append([]string{"the settings were converted to the format " + Version + ": the old file is " + backup}, notes...), nil
}
