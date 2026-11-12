package supervisor

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"

	"github.com/stretchr/testify/require"
)

// maskSource answers the download of a list of masks: body (or the one of bodies for the
// address) after the release, or err.
type maskSource struct {
	release chan struct{}
	body    string
	bodies  map[string]string
	err     error
	access  sync.Mutex
	header  http.Header
}

func (m *maskSource) download(ctx context.Context, address string, header http.Header, _ []subscription.Route, _ subscription.Plan, _ func([]subscription.Try)) (*subscription.Answer, []subscription.Try, error) {
	m.access.Lock()
	m.header = header
	m.access.Unlock()
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
	if body, found := m.bodies[address]; found {
		return &subscription.Answer{Body: []byte(body)}, nil, nil
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
	go s.feedMasks(ctx, names, []string{"https://lists.example/white.txt"})
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
	source.access.Lock()
	require.Empty(t, source.header)
	source.access.Unlock()
	kept, err := os.ReadFile(maskListFile(s.options.ConfigDir, "https://lists.example/white.txt"))
	require.NoError(t, err)
	require.Equal(t, source.body, string(kept))

	failing := &maskSource{err: errors.New("no way")}
	s.options.Download = failing.download
	require.Equal(t, []string{"img.avito.st", "mail.ru"}, s.maskList(ctx, "https://lists.example/white.txt"))
}

// Once the lists are in, their names come in turn with the built-in ones, a name of each source
// after the other, and a site a list before named is not tried again; a list that comes late
// joins the turns where they are.
func TestMaskTurns(t *testing.T) {
	builtin := engine.WhiteSNICandidates
	turns := newMaskTurns(2)
	take := func() string {
		from, name := turns.next()
		require.GreaterOrEqual(t, from, 0)
		turns.took(from, name)
		return name
	}
	require.Equal(t, builtin[0], take())
	turns.sources[2] = []string{"ozon.ru", "wb.ru", "www.mail.ru", "ok.ru"}
	require.Equal(t, []string{"ozon.ru", builtin[1]}, []string{take(), take()})
	turns.sources[1] = []string{"img.avito.st", "mail.ru", "vk.com"}
	require.Equal(t, []string{"img.avito.st", "wb.ru", builtin[2], "mail.ru", "ok.ru", builtin[3], "vk.com", builtin[4]},
		[]string{take(), take(), take(), take(), take(), take(), take(), take()})
	rest := 0
	for from, _ := turns.next(); from >= 0; from, _ = turns.next() {
		require.Zero(t, from)
		take()
		rest++
	}
	require.Equal(t, len(builtin)-5, rest)
}

// Two lists downloaded at once: every name of both comes once, a site of both once.
func TestFeedMasksLists(t *testing.T) {
	first, second := "https://lists.example/white.txt", "https://other.example/domains.csv"
	source := &maskSource{bodies: map[string]string{
		first:  "img.avito.st\nmail.ru\nvk.com\n",
		second: "ozon.ru\nwww.mail.ru\nwb.ru\nok.ru\n",
	}}
	s := maskSupervisor(t, source)
	names := make(chan string)
	go s.feedMasks(context.Background(), names, []string{first, second})
	listed := []string{"img.avito.st", "vk.com", "ozon.ru", "wb.ru", "ok.ru"}
	// mail.ru or www.mail.ru, whichever list has its turn first
	got := collect(t, names, len(engine.WhiteSNICandidates)+len(listed)+2)
	require.Len(t, got, len(engine.WhiteSNICandidates)+len(listed)+1)
	require.True(t, (indexOf(got, "mail.ru") < 0) != (indexOf(got, "www.mail.ru") < 0), got)
	for _, name := range listed {
		require.GreaterOrEqual(t, indexOf(got, name), 0, name)
	}
	for _, address := range []string{first, second} {
		_, err := os.Stat(maskListFile(s.options.ConfigDir, address))
		require.NoError(t, err, address)
	}
}

// No list: the built-in names only, then the channel closes.
func TestFeedMasksNoList(t *testing.T) {
	s := maskSupervisor(t, &maskSource{})
	names := make(chan string)
	go s.feedMasks(context.Background(), names, nil)
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
