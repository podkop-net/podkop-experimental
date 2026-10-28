package engine

import (
	"encoding/json"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	sJSON "github.com/sagernet/sing/common/json"
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
	// before the new groups start: they test the members that have no result
	history.forgetChanged(next)
	update, err := i.box.UpdateOutbounds(options.Outbounds, swap.Remove, limit)
	if err != nil {
		return Swapped{}, err
	}
	i.dialers = next
	return Swapped{Added: update.Added, Replaced: update.Replaced, Removed: update.Removed, Kept: update.Kept}, nil
}
