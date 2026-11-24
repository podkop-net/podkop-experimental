package uci

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"
)

// Edit changes the configuration file at path: the one way the backend writes its settings. The
// file is read under the lock libuci takes for a commit (flock LOCK_EX on the file itself), so a
// "uci commit" waits for the edit and the edit waits for that one, and what another program wrote
// meanwhile is what edit gets. The result replaces the file by a rename, with the mode and the
// owner the file had; a link is followed, as libuci follows it. It tells whether the file was
// written: an edit that changes nothing libuci reads, or returns an error, leaves it as it is, its
// comments included.
//
// The lock is on the file, and each writer puts another file in its place: a writer that waited has
// the lock of a file that is no longer there. The edit starts over on the file that is, so edit may
// be called more than once, each time with what the file has then. A "uci commit" does not look: it
// takes what it read from the file that is gone for the settings, and one that waits while an edit
// ends can lose what the edit wrote, as two of them lose each other's changes. Nothing here can
// help that; an edit that such a commit overtakes starts over.
//
// What is written is what libuci would write of the same settings: no comments and no options set
// to nothing, which libuci does not read (edit gets them all the same). Changes staged with the uci
// program and not committed (/tmp/.uci) are not a part of the file: edit does not see them, they
// stay staged, and the next "uci commit" of that package puts them on what is written here.
func Edit(path string, edit func(parsed *Package) error) (bool, error) {
	// each time over, another writer has ended its work meanwhile
	for attempt := 0; attempt < 100; attempt++ {
		changed, err := editOnce(path, edit)
		if !errors.Is(err, errReplaced) {
			return changed, err
		}
	}
	return false, E.New("lock ", path, ": the file keeps being replaced")
}

// errReplaced tells that the file locked is not the one at the path any more.
var errReplaced = errors.New("the file was replaced")

// editOnce makes one attempt of Edit.
func editOnce(path string, edit func(parsed *Package) error) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close() // lets the lock go, also after a fault in edit
	if err := flock(file); err != nil {
		return false, E.Cause(err, "lock ", path)
	}
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	if !isAt(path, info) {
		return false, errReplaced
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return false, err
	}
	parsed, err := Parse(content)
	if err != nil {
		return false, E.Cause(err, "read ", path)
	}
	before, _ := Parse(content) // it was read just now
	before.dropEmpty()
	if err := edit(parsed); err != nil {
		return false, err
	}
	parsed.dropEmpty()
	after := parsed.Format()
	if bytes.Equal(before.Format(), after) {
		return false, nil
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, err
	}
	temporary, err := writeBeside(target, after, info)
	if err != nil {
		return false, err
	}
	if !isAt(path, info) {
		os.Remove(temporary)
		return false, errReplaced
	}
	return true, put(temporary, target)
}

// Copy copies the configuration file at from to the path to, as "cp -p" does: with its mode, its
// owner and its time. The copy is there whole or not at all.
func Copy(from string, to string) error {
	info, err := os.Stat(from)
	if err != nil {
		return err
	}
	content, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	temporary, err := writeBeside(to, content, info)
	if err != nil {
		return err
	}
	_ = os.Chtimes(temporary, info.ModTime(), info.ModTime())
	return put(temporary, to)
}

func flock(file *os.File) error {
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			return err
		}
	}
}

// isAt tells whether the file at the path is the one of info.
func isAt(path string, info os.FileInfo) bool {
	current, err := os.Stat(path)
	return err == nil && os.SameFile(info, current)
}

// writeBeside writes content to a temporary file in the directory of the path, with the mode and
// (when this process may give it) the owner of like, to the disk, and returns its name. Nothing is
// left behind when it fails.
func writeBeside(path string, content []byte, like os.FileInfo) (name string, err error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".edit-*")
	if err != nil {
		return "", err
	}
	defer func() {
		if errClose := temporary.Close(); err == nil {
			err = errClose
		}
		if err != nil {
			os.Remove(temporary.Name())
		}
	}()
	if _, err := temporary.Write(content); err != nil {
		return "", err
	}
	if owner, known := like.Sys().(*syscall.Stat_t); known {
		_ = temporary.Chown(int(owner.Uid), int(owner.Gid))
	}
	if err := temporary.Chmod(like.Mode().Perm()); err != nil {
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		return "", err
	}
	return temporary.Name(), nil
}

// put renames a temporary file to its path; nothing is left behind when it fails.
func put(temporary string, path string) error {
	err := os.Rename(temporary, path)
	if err != nil {
		os.Remove(temporary)
	}
	return err
}
