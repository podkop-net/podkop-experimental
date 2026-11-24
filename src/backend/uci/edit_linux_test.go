package uci

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const settingsText = "# kept by hand\nconfig settings 'settings'\n\toption a 'x'\n\toption none ''\n\tlist l 'one'\n\tlist l ''\n\nconfig member\n\toption section 'main'\n"

// settingsFile is a settings file in a directory of its own.
func settingsFile(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "podkop")
	require.NoError(t, os.WriteFile(path, []byte(text), 0o600))
	return path
}

func text(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(content)
}

// alone tells that nothing is in the directory of a file but the file: no temporary was left.
func alone(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, filepath.Base(path), entries[0].Name())
}

// untouched tells that a file is the very file it was, with the content it had.
func untouched(t *testing.T, path string, before os.FileInfo, content string) {
	t.Helper()
	after, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, os.SameFile(before, after), "the file is not replaced")
	require.Equal(t, before.ModTime(), after.ModTime())
	require.Equal(t, content, text(t, path))
	alone(t, path)
}

func stat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info
}

func set(name string, value string) func(*Package) error {
	return func(parsed *Package) error {
		parsed.Section("settings").Set(name, value)
		return nil
	}
}

func TestEdit(t *testing.T) {
	t.Parallel()
	path := settingsFile(t, settingsText)
	require.NoError(t, os.Chmod(path, 0o640))
	changed, err := Edit(path, set("a", "it's"))
	require.NoError(t, err)
	require.True(t, changed)
	// as libuci writes it: no comment, no option set to nothing, the empty item of a list kept
	require.Equal(t, "config settings 'settings'\n\toption a 'it'\\''s'\n\tlist l 'one'\n\tlist l ''\n\nconfig member\n\toption section 'main'\n", text(t, path))
	require.Equal(t, os.FileMode(0o640), stat(t, path).Mode())
	alone(t, path)
}

// An edit that changes nothing leaves the very file there, its comments and its options set to
// nothing included; so does one that returns an error.
func TestEditChangesNothing(t *testing.T) {
	t.Parallel()
	path := settingsFile(t, settingsText)
	before := stat(t, path)
	time.Sleep(20 * time.Millisecond) // a file written again would have another time
	changed, err := Edit(path, set("a", "x"))
	require.NoError(t, err)
	require.False(t, changed)
	untouched(t, path, before, settingsText)

	// an option set to nothing is none to libuci: to delete it, or to set another to nothing, is no
	// change of what it reads
	changed, err = Edit(path, func(parsed *Package) error {
		parsed.Section("settings").Delete("none")
		parsed.Section("settings").Set("more", "")
		return nil
	})
	require.NoError(t, err)
	require.False(t, changed)
	untouched(t, path, before, settingsText)

	refused := errors.New("refused")
	changed, err = Edit(path, func(parsed *Package) error {
		parsed.Section("settings").Set("a", "y")
		return refused
	})
	require.ErrorIs(t, err, refused)
	require.False(t, changed)
	untouched(t, path, before, settingsText)
}

// A link is followed, as libuci follows it: the file it names is replaced, in its own directory.
func TestEditLink(t *testing.T) {
	t.Parallel()
	path := settingsFile(t, settingsText)
	link := filepath.Join(t.TempDir(), "podkop")
	require.NoError(t, os.Symlink(path, link))
	changed, err := Edit(link, set("a", "y"))
	require.NoError(t, err)
	require.True(t, changed)
	info, err := os.Lstat(link)
	require.NoError(t, err)
	require.Equal(t, os.ModeSymlink, info.Mode()&os.ModeSymlink, "the link stays")
	require.Contains(t, text(t, path), "option a 'y'")
	alone(t, path)
	alone(t, link)
}

func TestEditNoFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "podkop")
	_, err := Edit(path, func(*Package) error { t.Fatal("there is nothing to edit"); return nil })
	require.ErrorIs(t, err, os.ErrNotExist)
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Empty(t, entries, "the file is not made")
}

func TestEditUnreadable(t *testing.T) {
	t.Parallel()
	broken := "config settings 'settings'\n\toption a 'open\n"
	path := settingsFile(t, broken)
	before := stat(t, path)
	_, err := Edit(path, func(*Package) error { t.Fatal("there is nothing to edit"); return nil })
	require.ErrorContains(t, err, "read "+path+": line 2")
	untouched(t, path, before, broken)
}

// asNobody runs do with the rights of nobody over the file system, when the test runs as root.
func asNobody(t *testing.T, do func()) {
	t.Helper()
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

// openTo lets another user reach a directory of the test.
func openTo(t *testing.T, directory string, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.Chmod(directory, mode))
	t.Cleanup(func() { _ = os.Chmod(directory, 0o755) })
	for parent := filepath.Dir(directory); parent != os.TempDir() && parent != "/"; parent = filepath.Dir(parent) {
		_ = os.Chmod(parent, 0o755)
	}
}

func TestEditReadOnlyDirectory(t *testing.T) {
	t.Parallel()
	path := settingsFile(t, settingsText)
	require.NoError(t, os.Chmod(path, 0o644))
	openTo(t, filepath.Dir(path), 0o555)
	before := stat(t, path)
	asNobody(t, func() {
		changed, err := Edit(path, set("a", "y"))
		require.ErrorIs(t, err, os.ErrPermission)
		require.False(t, changed)
	})
	untouched(t, path, before, settingsText)
}

// The owner stays, when the process may give a file away; when it may not, the file is written all
// the same.
func TestEditOwner(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Skip("only root gives files away")
	}
	path := settingsFile(t, settingsText)
	require.NoError(t, os.Chmod(path, 0o644))
	require.NoError(t, os.Chown(path, 1234, 4321))
	_, err := Edit(path, set("a", "y"))
	require.NoError(t, err)
	owner := stat(t, path).Sys().(*syscall.Stat_t)
	require.EqualValues(t, 1234, owner.Uid)
	require.EqualValues(t, 4321, owner.Gid)
	require.Equal(t, os.FileMode(0o644), stat(t, path).Mode())

	openTo(t, filepath.Dir(path), 0o777)
	asNobody(t, func() {
		changed, err := Edit(path, set("a", "z"))
		require.NoError(t, err)
		require.True(t, changed)
	})
	require.Contains(t, text(t, path), "option a 'z'")
	require.Equal(t, os.FileMode(0o644), stat(t, path).Mode())
}

// Edits of one process follow one another: none is lost.
func TestEditsAtOnce(t *testing.T) {
	t.Parallel()
	path := settingsFile(t, "config settings 'settings'\n\toption n '0'\n")
	const edits = 40
	var group sync.WaitGroup
	for range edits {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := Edit(path, func(parsed *Package) error {
				n, err := strconv.Atoi(parsed.Section("settings").Get("n"))
				parsed.Section("settings").Set("n", strconv.Itoa(n+1))
				return err
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	parsed, err := ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, strconv.Itoa(edits), parsed.Section("settings").Get("n"))
	alone(t, path)
}

const removeIt = "(remove it)"

// holder is another process (this test program run again, TestHolder) that holds the lock of a
// file the way a "uci commit" does.
type holder struct {
	t       *testing.T
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Scanner
}

// hold starts a process that tries the lock of the file (flock LOCK_EX, or LOCK_EX|LOCK_NB with
// "try") and says what came of it, "locked" or "busy".
func hold(t *testing.T, path string, how string) (*holder, string) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestHolder$")
	command.Env = append(os.Environ(), "UCI_HOLD="+path, "UCI_HOLD_HOW="+how)
	input, err := command.StdinPipe()
	require.NoError(t, err)
	output, err := command.StdoutPipe()
	require.NoError(t, err)
	command.Stderr = os.Stderr
	require.NoError(t, command.Start())
	h := &holder{t: t, command: command, input: input, output: bufio.NewScanner(output)}
	require.True(t, h.output.Scan(), "the other process says what came of the lock")
	return h, h.output.Text()
}

// end has the process replace the file by this text (unless it is empty; removeIt: remove it) while
// it holds the lock, and end, which lets the lock go.
func (h *holder) end(replace string) {
	h.t.Helper()
	_, err := io.WriteString(h.input, replace)
	require.NoError(h.t, err)
	require.NoError(h.t, h.input.Close())
	for h.output.Scan() {
	}
	require.NoError(h.t, h.command.Wait())
}

// TestHolder is the other process, not a test.
func TestHolder(t *testing.T) {
	path := os.Getenv("UCI_HOLD")
	if path == "" {
		t.Skip("run by the tests of the lock")
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	how := syscall.LOCK_EX
	if os.Getenv("UCI_HOLD_HOW") == "try" {
		how |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(file.Fd()), how); err != nil {
		require.ErrorIs(t, err, syscall.EWOULDBLOCK)
		fmt.Println("busy")
	} else {
		fmt.Println("locked")
	}
	replace, err := io.ReadAll(os.Stdin)
	require.NoError(t, err)
	switch {
	case string(replace) == removeIt:
		require.NoError(t, os.Remove(path))
	case len(replace) > 0:
		require.NoError(t, os.WriteFile(path+".new", replace, 0o600))
		require.NoError(t, os.Rename(path+".new", path))
	}
}

// waiting starts an edit and tells that it waits: it has not ended, nor called its function, after
// a while. The channel gives the answer.
func waiting(t *testing.T, path string, edit func(*Package) error) <-chan error {
	t.Helper()
	began, ended := make(chan struct{}), make(chan error, 1)
	go func() {
		var once sync.Once
		_, err := Edit(path, func(parsed *Package) error {
			once.Do(func() { close(began) })
			return edit(parsed)
		})
		ended <- err
	}()
	select {
	case <-began:
		t.Error("the edit began while another process held the lock")
	case err := <-ended:
		t.Error("the edit ended while another process held the lock:", err)
	case <-time.After(300 * time.Millisecond):
	}
	return ended
}

func answer(t *testing.T, ended <-chan error) error {
	t.Helper()
	select {
	case err := <-ended:
		return err
	case <-time.After(20 * time.Second):
		t.Fatal("the edit did not end after the lock was let go")
		return nil
	}
}

// An edit waits for a commit of another process, and then works on what that one left.
func TestEditWaitsForCommit(t *testing.T) {
	t.Parallel()
	t.Run("nothing changed", func(t *testing.T) {
		t.Parallel()
		path := settingsFile(t, settingsText)
		commit, said := hold(t, path, "")
		require.Equal(t, "locked", said)
		ended := waiting(t, path, set("b", "1"))
		commit.end("")
		require.NoError(t, answer(t, ended))
		require.Contains(t, text(t, path), "\toption a 'x'\n\tlist l 'one'\n\tlist l ''\n\toption b '1'\n")
	})
	t.Run("the file replaced", func(t *testing.T) {
		t.Parallel()
		path := settingsFile(t, settingsText)
		commit, said := hold(t, path, "")
		require.Equal(t, "locked", said)
		ended := waiting(t, path, set("b", "1"))
		commit.end("config settings 'settings'\n\toption other '2'\n")
		require.NoError(t, answer(t, ended))
		require.Equal(t, "config settings 'settings'\n\toption other '2'\n\toption b '1'\n", text(t, path), "the change of the other process stays")
	})
	t.Run("the file replaced by one the edit has to change", func(t *testing.T) {
		t.Parallel()
		path := settingsFile(t, settingsText)
		commit, said := hold(t, path, "")
		require.Equal(t, "locked", said)
		// in the file that was there it would change nothing
		ended := waiting(t, path, set("a", "x"))
		commit.end("config settings 'settings'\n\toption a 'y'\n")
		require.NoError(t, answer(t, ended))
		require.Equal(t, "config settings 'settings'\n\toption a 'x'\n", text(t, path))
	})
	t.Run("the file removed", func(t *testing.T) {
		t.Parallel()
		path := settingsFile(t, settingsText)
		commit, said := hold(t, path, "")
		require.Equal(t, "locked", said)
		ended := waiting(t, path, func(*Package) error { t.Error("there is nothing to edit"); return nil })
		commit.end(removeIt)
		require.ErrorIs(t, answer(t, ended), os.ErrNotExist)
		_, err := os.Stat(path)
		require.ErrorIs(t, err, os.ErrNotExist)
	})
	t.Run("the file made unreadable", func(t *testing.T) {
		t.Parallel()
		path := settingsFile(t, settingsText)
		commit, said := hold(t, path, "")
		require.Equal(t, "locked", said)
		ended := waiting(t, path, func(*Package) error { t.Error("there is nothing to edit"); return nil })
		commit.end("config settings 'open\n")
		require.ErrorContains(t, answer(t, ended), "line 1")
		require.Equal(t, "config settings 'open\n", text(t, path))
	})
}

// While an edit runs, the lock of the file is not to be had; after it, it is.
func TestEditHoldsTheLock(t *testing.T) {
	t.Parallel()
	path := settingsFile(t, settingsText)
	_, err := Edit(path, func(parsed *Package) error {
		other, said := hold(t, path, "try")
		require.Equal(t, "busy", said)
		other.end("")
		return set("a", "y")(parsed)
	})
	require.NoError(t, err)
	other, said := hold(t, path, "try")
	require.Equal(t, "locked", said)
	other.end("")
	// also after an edit that failed, or faulted
	_, err = Edit(path, func(*Package) error { return errors.New("no") })
	require.Error(t, err)
	other, said = hold(t, path, "try")
	require.Equal(t, "locked", said)
	other.end("")
	require.Panics(t, func() { _, _ = Edit(path, func(*Package) error { panic("a fault") }) })
	other, said = hold(t, path, "try")
	require.Equal(t, "locked", said)
	other.end("")
}

// A "uci commit" that had waited for the lock of a file that is no longer there writes while an edit
// runs: the edit is made over, on what it wrote.
func TestEditOvertaken(t *testing.T) {
	t.Parallel()
	path := settingsFile(t, settingsText)
	calls := 0
	changed, err := Edit(path, func(parsed *Package) error {
		if calls++; calls == 1 {
			require.Equal(t, "x", parsed.Section("settings").Get("a"))
			require.NoError(t, os.WriteFile(path+".new", []byte("config settings 'settings'\n\toption other '2'\n"), 0o600))
			require.NoError(t, os.Rename(path+".new", path))
		}
		return set("b", "1")(parsed)
	})
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, 2, calls)
	require.Equal(t, "config settings 'settings'\n\toption other '2'\n\toption b '1'\n", text(t, path))
	alone(t, path)

	// one that changes nothing has nothing to write over
	calls = 0
	changed, err = Edit(path, func(parsed *Package) error {
		calls++
		require.NoError(t, os.WriteFile(path+".new", []byte(settingsText), 0o600))
		require.NoError(t, os.Rename(path+".new", path))
		return nil
	})
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, 1, calls)
	require.Equal(t, settingsText, text(t, path))
}

// A file that is replaced each time the edit has it locked is given up, not waited for without end;
// one that goes away meanwhile is not made.
func TestEditOfAFileReplacedAllTheTime(t *testing.T) {
	t.Parallel()
	path := settingsFile(t, settingsText)
	calls := 0
	changed, err := Edit(path, func(parsed *Package) error {
		calls++
		require.NoError(t, os.WriteFile(path+".new", []byte(settingsText), 0o600))
		require.NoError(t, os.Rename(path+".new", path))
		return set("a", "y")(parsed)
	})
	require.ErrorContains(t, err, "keeps being replaced")
	require.False(t, changed)
	require.Equal(t, 100, calls)
	require.Equal(t, settingsText, text(t, path))
	alone(t, path)

	_, err = Edit(path, func(parsed *Package) error {
		require.NoError(t, os.Remove(path))
		return set("a", "y")(parsed)
	})
	require.ErrorIs(t, err, os.ErrNotExist)
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestCopy(t *testing.T) {
	t.Parallel()
	path := settingsFile(t, settingsText)
	require.NoError(t, os.Chmod(path, 0o640))
	then := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	require.NoError(t, os.Chtimes(path, then, then))
	if os.Geteuid() == 0 {
		require.NoError(t, os.Chown(path, 1234, 4321))
	}
	copied := path + ".copy"
	require.NoError(t, Copy(path, copied))
	require.Equal(t, settingsText, text(t, copied), "byte for byte, the comments too")
	info := stat(t, copied)
	require.Equal(t, os.FileMode(0o640), info.Mode())
	require.True(t, info.ModTime().Equal(then))
	if os.Geteuid() == 0 {
		require.EqualValues(t, 1234, info.Sys().(*syscall.Stat_t).Uid)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 2)

	require.ErrorIs(t, Copy(path+".none", path+".copy2"), os.ErrNotExist)
	_, err = os.Stat(path + ".copy2")
	require.ErrorIs(t, err, os.ErrNotExist)
}

// A copy that cannot be put in place leaves nothing behind.
func TestCopyOverADirectory(t *testing.T) {
	t.Parallel()
	path := settingsFile(t, settingsText)
	require.NoError(t, os.Mkdir(path+".copy", 0o755))
	require.Error(t, Copy(path, path+".copy"))
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

// Without room for the whole file nothing is changed and nothing is left behind (a "uci commit"
// leaves an empty file there): a process of its own that may write files of 4 KB at most.
func TestEditNoRoom(t *testing.T) {
	t.Parallel()
	settings := settingsText + "\toption long '" + strings.Repeat("x", 9000) + "'\n"
	path := settingsFile(t, settings)
	before := stat(t, path)
	command := exec.Command(os.Args[0], "-test.run=^TestNoRoom$")
	command.Env = append(os.Environ(), "UCI_NO_ROOM="+path)
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))
	untouched(t, path, before, settings)
}

// TestNoRoom is the process of TestEditNoRoom, not a test.
func TestNoRoom(t *testing.T) {
	path := os.Getenv("UCI_NO_ROOM")
	if path == "" {
		t.Skip("run by TestEditNoRoom")
	}
	signal.Ignore(syscall.SIGXFSZ)
	require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 4096, Max: 4096}))
	changed, err := Edit(path, set("a", "y"))
	require.ErrorIs(t, err, syscall.EFBIG)
	require.False(t, changed)
	require.ErrorIs(t, Copy(path, path+".copy"), syscall.EFBIG)
}

// The temporary has the name of the file in front: a file whose name leaves no room for more
// cannot be written, and stays as it is.
func TestEditNoTemporary(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), strings.Repeat("p", 250))
	require.NoError(t, os.WriteFile(path, []byte(settingsText), 0o600))
	before := stat(t, path)
	changed, err := Edit(path, set("a", "y"))
	require.ErrorIs(t, err, syscall.ENAMETOOLONG)
	require.False(t, changed)
	untouched(t, path, before, settingsText)
}
