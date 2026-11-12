package supervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"

	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
)

// maskListDir keeps, in ConfigDir (RAM), the last copy of each public list of names a mask search
// downloaded, by the address: a search whose download fails takes it.
const maskListDir = "masklists"

// feedMasks gives a mask search its candidates: the built-in names (all lifted the limit on the
// operator they were measured on) while the public lists at addresses download, then the names
// of all of them in turn, one of each source after the other. In turn, not one set after the
// other: on an operator that lists none of one set, each miss of it may hold a probe for
// probeMaskPer, and a set after it would not start within the budget of the scan. A site is tried
// once, whichever list names it first (model.MaskSite). It closes names when it has given all,
// or when ctx ends.
func (s *Supervisor) feedMasks(ctx context.Context, names chan<- string, addresses []string) {
	defer close(names)
	type arrival struct {
		source int
		names  []string
	}
	arrived := make(chan arrival, len(addresses))
	for index, address := range addresses {
		go func() {
			arrived <- arrival{source: index + 1, names: s.maskList(ctx, address)}
		}()
	}
	waiting := len(addresses)
	turns := newMaskTurns(len(addresses))
	for {
		from, next := turns.next()
		if from < 0 && waiting == 0 {
			return
		}
		var out chan<- string
		if from >= 0 {
			out = names
		}
		select {
		case got := <-arrived:
			waiting--
			turns.sources[got.source] = got.names
		case out <- next:
			turns.took(from, next)
		case <-ctx.Done():
			return
		}
	}
}

// maskTurns is the order of the names of a mask search: source 0 is the built-in names, the lists
// follow in the order of the settings, empty until they come.
type maskTurns struct {
	sources [][]string
	tried   map[string]bool
	turn    int
}

func newMaskTurns(lists int) *maskTurns {
	sources := make([][]string, 1+lists)
	sources[0] = engine.WhiteSNICandidates
	return &maskTurns{sources: sources, tried: make(map[string]bool)}
}

// next is the name to give now: the first of the source whose turn it is, or of the next source
// that has one; -1 when none has a name. Names of a list whose site was tried are dropped.
func (m *maskTurns) next() (int, string) {
	for step := range m.sources {
		source := (m.turn + step) % len(m.sources)
		for source > 0 && len(m.sources[source]) > 0 && m.tried[model.MaskSite(m.sources[source][0])] {
			m.sources[source] = m.sources[source][1:]
		}
		if len(m.sources[source]) > 0 {
			return source, m.sources[source][0]
		}
	}
	return -1, ""
}

// took notes the name of next as given: the turn goes to the source after it.
func (m *maskTurns) took(source int, name string) {
	m.sources[source] = m.sources[source][1:]
	if source > 0 {
		m.tried[model.MaskSite(name)] = true
	}
	m.turn = source + 1
}

// maskListFile is the copy of the list at address in dir.
func maskListFile(dir string, address string) string {
	sum := sha256.Sum256([]byte(address))
	return filepath.Join(dir, maskListDir, hex.EncodeToString(sum[:8])+".txt")
}

// maskList downloads the public list at address the way a subscription is downloaded (directly,
// and through the fastest servers, so a blocked GitHub still gives it), without the headers of
// the device, and returns its names beyond the built-in ones (model.MaskNames). A list that does
// not come is taken from the copy of the last download.
func (s *Supervisor) maskList(ctx context.Context, address string) []string {
	download := s.options.Download
	if download == nil {
		download = subscription.Download
	}
	cache := ""
	if s.options.ConfigDir != "" {
		cache = maskListFile(s.options.ConfigDir, address)
	}
	routes, _ := s.routes(previewProxies, "")
	answer, _, err := download(ctx, address, http.Header{}, routes, subscription.DefaultPlan, nil)
	if err == nil {
		names := model.MaskNames(answer.Body, engine.WhiteSNICandidates)
		if len(names) > 0 {
			if cache != "" {
				if err := os.MkdirAll(filepath.Dir(cache), 0o700); err != nil {
					s.log("warn", "keep the list of masks: ", err)
				} else if err := os.WriteFile(cache, answer.Body, 0o600); err != nil {
					s.log("warn", "keep the list of masks: ", err)
				}
			}
			return names
		}
		s.log("warn", "the list of masks at ", address, " has no host names")
	} else if ctx.Err() == nil {
		s.log("warn", "download the list of masks at ", address, ": ", err)
	}
	if cache == "" {
		return nil
	}
	kept, err := os.ReadFile(cache)
	if err != nil {
		return nil
	}
	return model.MaskNames(kept, engine.WhiteSNICandidates)
}
