package supervisor

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"

	"github.com/stretchr/testify/require"
)

// maskSource answers the download of the list of masks: body after the release, or err.
type maskSource struct {
	release chan struct{}
	body    string
	err     error
	header  http.Header
}

func (m *maskSource) download(ctx context.Context, _ string, header http.Header, _ []subscription.Route, _ subscription.Plan, _ func([]subscription.Try)) (*subscription.Answer, []subscription.Try, error) {
	m.header = header
	if m.release != nil {
		select {
		case <-m.release:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	if m.err != nil {
		return nil, nil, m.err
	}
	return &subscription.Answer{Body: []byte(m.body)}, nil, nil
}

func maskSupervisor(t *testing.T, source *maskSource) *Supervisor {
	t.Helper()
	return &Supervisor{options: Options{ConfigDir: t.TempDir(), Download: source.download, Log: func(string, string) {}}}
}

func collect(t *testing.T, names <-chan string, count int) []string {
	t.Helper()
	var got []string
	for len(got) < count {
		select {
		case name, open := <-names:
			if !open {
				return got
			}
			got = append(got, name)
		case <-time.After(5 * time.Second):
			t.Fatalf("no name after %v", got)
		}
	}
	return got
}

// The built-in names go first while the list downloads, then the two in turn; the list goes
// without the headers of the device, and is kept for a search whose download fails.
func TestFeedMasks(t *testing.T) {
	source := &maskSource{release: make(chan struct{}), body: "img.avito.st\n01.img.avito.st\nmail.ru\nwww.deepl.com\n"}
	s := maskSupervisor(t, source)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	names := make(chan string)
	go s.feedMasks(ctx, names, "https://lists.example/white.txt")
	builtin := engine.WhiteSNICandidates
	require.Equal(t, builtin[:2], collect(t, names, 2))
	close(source.release)
	// the list is taken in while a name waits to be given: the next is the waiting built-in one
	// or already a listed one; either way all come, the listed in their order, none twice
	rest := collect(t, names, len(builtin)+2)
	require.Len(t, rest, len(builtin))
	listed := []string{}
	for _, name := range rest {
		if name == "img.avito.st" || name == "mail.ru" {
			listed = append(listed, name)
		}
	}
	require.Equal(t, []string{"img.avito.st", "mail.ru"}, listed)
	require.Empty(t, source.header)
	kept, err := os.ReadFile(filepath.Join(s.options.ConfigDir, maskListFile))
	require.NoError(t, err)
	require.Equal(t, source.body, string(kept))

	failing := &maskSource{err: errors.New("no way")}
	s.options.Download = failing.download
	require.Equal(t, []string{"img.avito.st", "mail.ru"}, s.maskList(ctx, "https://lists.example/white.txt"))
}

// Once the list is in, its names alternate with the built-in ones.
func TestFeedMasksInTurn(t *testing.T) {
	source := &maskSource{body: "img.avito.st\nmail.ru\nvk.com\n"}
	s := maskSupervisor(t, source)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listed := s.maskList(ctx, "https://lists.example/white.txt")
	require.Equal(t, []string{"img.avito.st", "mail.ru", "vk.com"}, listed)
	names := make(chan string)
	go s.feedMasks(ctx, names, "https://lists.example/white.txt")
	got := collect(t, names, len(engine.WhiteSNICandidates)+len(listed)+1)
	require.Len(t, got, len(engine.WhiteSNICandidates)+len(listed))
	// each listed name comes within two places of the one before it
	last := -1
	for _, name := range listed {
		index := indexOf(got, name)
		require.GreaterOrEqual(t, index, 0, name)
		if last >= 0 {
			require.LessOrEqual(t, index-last, 2, "%s at %d after %d: %v", name, index, last, got)
		}
		last = index
	}
}

// No list: the built-in names only, then the channel closes.
func TestFeedMasksNoList(t *testing.T) {
	s := maskSupervisor(t, &maskSource{})
	names := make(chan string)
	go s.feedMasks(context.Background(), names, "")
	got := collect(t, names, len(engine.WhiteSNICandidates)+1)
	require.Equal(t, engine.WhiteSNICandidates, got)
}

func indexOf(names []string, name string) int {
	for index, each := range names {
		if each == name {
			return index
		}
	}
	return -1
}
