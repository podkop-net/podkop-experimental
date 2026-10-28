package engine

import (
	"encoding/json"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	sJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// Swap is a change of the outbounds of an instance while it runs (Instance.Swap): the
// outbounds to build anew, as the configuration has them, and the tags to take out.
type Swap struct {
	Put    []json.RawMessage
	Remove []string
}

// Swapped tells what a swap changed: the outbounds added, replaced and taken out, and how many
// of those replaced or taken out so far are kept for the connections that go through them.
type Swapped struct {
	Added, Replaced, Removed, Kept int
}

// ErrTooManyKept is what Swap returns while more servers of the changes before than its limit
// still carry connections: a new instance lets them all go.
var ErrTooManyKept = box.ErrTooManyKept

// Swap changes the outbounds of the instance while it runs (box.UpdateOutbounds): a connection
// routed after it goes through the new outbounds, one routed before keeps those it has, and
// what was replaced is closed once no connection goes through it. configuration is the whole
// next configuration: the history of the URL tests is kept by it (forgetChanged), as a start
// of it would. limit is how many servers of the changes before may still be kept (0: no
// limit). Nothing is changed when it fails.
func (i *Instance) Swap(configuration []byte, swap Swap, limit int) (Swapped, error) {
	if !i.enter() {
		return Swapped{}, ErrClosed
	}
	defer i.leave()
	content, err := json.Marshal(map[string]any{"outbounds": swap.Put})
	if err != nil {
		return Swapped{}, err
	}
	options, err := sJSON.UnmarshalExtendedContext[option.Options](i.ctx, content)
	if err != nil {
		return Swapped{}, E.Cause(err, "read the outbounds to replace")
	}
	next := dialersOf(configuration)
	// before the new selectors start: they read their choice from the cache file
	i.carrySelections(next)
	// before the new groups start: they test the members that have no result
	changed := history.forgetChanged(next)
	update, err := i.box.UpdateOutbounds(options.Outbounds, swap.Remove, limit)
	if err != nil {
		// the groups that run go on and may store results for the outbounds they have: the start
		// that follows forgets what changed again
		history.restart(i.dialers)
		return Swapped{}, err
	}
	// and again: a round of a group replaced, which stops only at the end of the swap, may have
	// stored meanwhile what it found through the outbound a tag had before
	history.forget(changed)
	i.dialers = next
	return Swapped{Added: update.Added, Replaced: update.Replaced, Removed: update.Removed, Kept: update.Kept}, nil
}

// CarrySelections moves the choices of the selectors to the new tags of the outbounds that
// configuration renames, in the cache file of the instance: the instance of configuration, which
// takes the file over, finds the server chosen in the dashboard under its new name.
func (i *Instance) CarrySelections(configuration []byte) {
	if !i.enter() {
		return
	}
	defer i.leave()
	i.carrySelections(dialersOf(configuration))
}

// carrySelections is CarrySelections for the dialers of the next configuration.
func (i *Instance) carrySelections(next map[string]dialer) {
	renamed := renamedTags(i.dialers, next)
	if len(renamed) == 0 {
		return
	}
	cacheFile := service.FromContext[adapter.CacheFile](i.ctx)
	if cacheFile == nil {
		return
	}
	for tag, now := range next {
		var head struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(now.content, &head) != nil || head.Type != C.TypeSelector {
			continue
		}
		if to, found := renamed[cacheFile.LoadSelected(tag)]; found {
			cacheFile.StoreSelected(tag, to)
		}
	}
}
