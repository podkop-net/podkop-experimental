package engine

import (
	"bytes"
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
	carried := i.carrySelections(next)
	// before the new groups start: they test the members that have no result
	forgot := history.forgetChanged(next)
	update, err := i.box.UpdateOutbounds(options.Outbounds, swap.Remove, limit)
	if err != nil {
		// nothing of next is left: the cache file has the choices of the selectors that run again,
		// the groups that run the results of their servers, and nothing has a result under a tag
		// of next only; a start that follows compares with what runs and forgets again what changed
		i.storeSelections(carried)
		history.undo(forgot, i.dialers)
		return Swapped{}, err
	}
	// and again: a round of a group replaced, which stops only at the end of the swap, may have
	// stored meanwhile what it found through the outbound a tag had before
	history.forget(forgot.tags)
	i.dialers = next
	return Swapped{Added: update.Added, Replaced: update.Replaced, Removed: update.Removed, Kept: update.Kept}, nil
}

// CarrySelections moves the choices of the selectors to the tags the servers chosen have in
// configuration (carriedSelections), in the cache file of the instance: the instance of
// configuration, which takes the file over, finds the server chosen in the dashboard under its
// new name. It returns the choices it changed, as they were (for Select, when configuration
// does not come up and this one starts again).
func (i *Instance) CarrySelections(configuration []byte) map[string]string {
	if !i.enter() {
		return nil
	}
	defer i.leave()
	return i.carrySelections(dialersOf(configuration))
}

// Select gives the selectors of the instance the choices, by the tag of the selector, as the
// dashboard does (and the cache file keeps them); a choice a selector does not have is passed
// over.
func (i *Instance) Select(choices map[string]string) {
	if !i.enter() {
		return
	}
	defer i.leave()
	for tag, choice := range choices {
		outbound, found := i.box.Outbound().Outbound(tag)
		if !found {
			continue
		}
		if selector, isSelector := outbound.(interface{ SelectOutbound(tag string) bool }); isSelector {
			selector.SelectOutbound(choice)
		}
	}
}

// carrySelections is CarrySelections for the dialers of the next configuration; it returns the
// choices it changed, as they were.
func (i *Instance) carrySelections(next map[string]dialer) map[string]string {
	cacheFile := service.FromContext[adapter.CacheFile](i.ctx)
	if cacheFile == nil {
		return nil
	}
	before := make(map[string]string)
	for selector, choice := range carriedSelections(i.dialers, next, cacheFile.LoadSelected) {
		before[selector] = cacheFile.LoadSelected(selector)
		cacheFile.StoreSelected(selector, choice)
	}
	return before
}

// storeSelections puts the choices of the selectors into the cache file of the instance.
func (i *Instance) storeSelections(choices map[string]string) {
	cacheFile := service.FromContext[adapter.CacheFile](i.ctx)
	if cacheFile == nil {
		return
	}
	for selector, choice := range choices {
		cacheFile.StoreSelected(selector, choice)
	}
}

// carriedSelections are the choices the selectors of next take, by the tag of the selector. A
// choice follows the server it named when its tag names another server in next or none: a
// server renamed, or servers of one name that changed places (their tags are numbered in the
// order of the list). It goes only to a member of the selector, the first one when the server
// is there under several names. A choice whose server is not in next, or is there under the
// same tag, stays.
func carriedSelections(previous map[string]dialer, next map[string]dialer, chosen func(string) string) map[string]string {
	carried := make(map[string]string)
	for tag, now := range next {
		var selector struct {
			Type      string   `json:"type"`
			Outbounds []string `json:"outbounds"`
		}
		if json.Unmarshal(now.content, &selector) != nil || selector.Type != C.TypeSelector {
			continue
		}
		choice := chosen(tag)
		before, found := previous[choice]
		if !found {
			continue
		}
		if after, kept := next[choice]; kept && bytes.Equal(after.content, before.content) {
			continue
		}
		body := withoutTag(before.content)
		if body == "" {
			continue
		}
		for _, member := range selector.Outbounds {
			if withoutTag(next[member].content) == body {
				carried[tag] = member
				break
			}
		}
	}
	return carried
}
