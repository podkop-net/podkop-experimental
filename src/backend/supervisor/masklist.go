package supervisor

import (
	"context"
	"net/http"
	"os"
	"path/filepath"

	"github.com/podkop-net/podkop-experimental/src/backend/engine"
	"github.com/podkop-net/podkop-experimental/src/backend/model"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
)

// maskListFile keeps, in ConfigDir (RAM), the last public list of names a mask search downloaded:
// a search whose download fails takes it.
const maskListFile = "masklist.txt"

// feedMasks gives a mask search its candidates: the built-in names (all lifted the limit on the
// operator they were measured on) while the public list at address downloads, then the names of
// both in turn. In turn, not one set after the other: on an operator that lists none of one set,
// each miss of it may hold a probe for probeMaskPer, and the set after it would not start within
// the budget of the scan. It closes names when it has given all, or when ctx ends.
func (s *Supervisor) feedMasks(ctx context.Context, names chan<- string, address string) {
	defer close(names)
	listed := make(chan []string, 1)
	if address != "" {
		go func(listed chan<- []string) {
			listed <- s.maskList(ctx, address)
		}(listed)
	} else {
		close(listed)
	}
	builtin := engine.WhiteSNICandidates
	var extra []string
	extraTurn := false
	for len(builtin) > 0 || len(extra) > 0 || listed != nil {
		var out chan<- string
		var next string
		takeExtra := len(extra) > 0 && (extraTurn || len(builtin) == 0)
		switch {
		case takeExtra:
			out, next = names, extra[0]
		case len(builtin) > 0:
			out, next = names, builtin[0]
		}
		select {
		case batch, open := <-listed:
			listed = nil
			if open {
				extra = batch
			}
		case out <- next:
			if takeExtra {
				extra = extra[1:]
			} else {
				builtin = builtin[1:]
			}
			extraTurn = !extraTurn
		case <-ctx.Done():
			return
		}
	}
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
		cache = filepath.Join(s.options.ConfigDir, maskListFile)
	}
	routes, _ := s.routes(previewProxies, "")
	answer, _, err := download(ctx, address, http.Header{}, routes, subscription.DefaultPlan, nil)
	if err == nil {
		names := model.MaskNames(answer.Body, engine.WhiteSNICandidates)
		if len(names) > 0 {
			if cache != "" {
				if err := os.WriteFile(cache, answer.Body, 0o600); err != nil {
					s.log("warn", "keep the list of masks: ", err)
				}
			}
			return names
		}
		s.log("warn", "the list of masks at ", address, " has no host names")
	} else if ctx.Err() == nil {
		s.log("warn", "download the list of masks: ", err)
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
