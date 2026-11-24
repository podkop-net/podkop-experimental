package api

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"time"

	"github.com/podkop-net/podkop-experimental/src/backend/btstats"
	"github.com/podkop-net/podkop-experimental/src/backend/logbuf"
	E "github.com/sagernet/sing/common/exceptions"
)

// Direct asks the backend of this process, with no socket in between: so do the commands the
// running backend answers itself. It answers as Client does: what the server of the socket would
// answer, an error when that does not come within the time Client waits. The answer is of the
// backend itself, to be read only.
type Direct struct {
	Backend Backend
	Log     *logbuf.Buffer
	// Context ends what is asked, as the end of its server ends what Client asks; nil ends
	// nothing.
	Context context.Context
}

// ask asks the backend a question as the server of the socket does for a client: in a goroutine of
// its own, with a context that ends when no one waits for the answer any more; a fault of the
// backend is an error, and its trace goes to the log of the process.
func ask[T any](d Direct, wait time.Duration, question func(ctx context.Context) (T, error)) (T, error) {
	parent := d.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, wait)
	defer cancel()
	var none T
	if ctx.Err() != nil {
		return none, ctx.Err()
	}
	type outcome struct {
		answer T
		err    error
	}
	answered := make(chan outcome, 1)
	go func() {
		var got outcome
		defer func() {
			if fault := recover(); fault != nil {
				log.Printf("a question to the backend: %v\n%s", fault, debug.Stack())
				got.err = E.New("the backend failed: ", fmt.Sprint(fault))
			}
			answered <- got
		}()
		got.answer, got.err = question(ctx)
	}()
	select {
	case got := <-answered:
		if got.err != nil {
			return none, got.err
		}
		// what the backend answers when its context has ended is not waited for
		if ctx.Err() == nil {
			return got.answer, nil
		}
	case <-ctx.Done():
	}
	return none, ctx.Err()
}

// Status is Client.Status.
func (d Direct) Status() (*Status, error) {
	return ask(d, factsWait, func(context.Context) (*Status, error) { return statusOf(d.Backend), nil })
}

// Facts is Client.Facts.
func (d Direct) Facts() (*Facts, error) {
	return ask(d, factsWait, func(context.Context) (*Facts, error) {
		facts := d.Backend.Facts()
		return &facts, nil
	})
}

// Logs is Client.Logs.
func (d Direct) Logs(since uint64) (*LogPage, error) {
	return ask(d, stateWait, func(context.Context) (*LogPage, error) { return logPage(d.Log, since), nil })
}

// Apply is Client.Apply.
func (d Direct) Apply() (*Result, error) {
	return ask(d, applyWait, func(ctx context.Context) (*Result, error) {
		result := d.Backend.Request(ctx)
		return &result, nil
	})
}

// UpdateLists is Client.UpdateLists.
func (d Direct) UpdateLists() (*ListsUpdate, error) {
	return ask(d, updateListsWait, func(ctx context.Context) (*ListsUpdate, error) {
		result := d.Backend.UpdateLists(ctx)
		return &result, nil
	})
}

// RestoreRouting is Client.RestoreRouting.
func (d Direct) RestoreRouting() (string, error) {
	return ask(d, listsWait, func(ctx context.Context) (string, error) { return d.Backend.RestoreRouting(ctx), nil })
}

// Lists is Client.Lists.
func (d Direct) Lists() ([]ListState, error) {
	return ask(d, listsWait, func(ctx context.Context) ([]ListState, error) { return d.Backend.ListStatus(ctx), nil })
}

// Probe is Client.Probe.
func (d Direct) Probe(label string, wait time.Duration) (*ProbeResult, error) {
	return ask(d, wait+probeSlack, func(ctx context.Context) (*ProbeResult, error) {
		result := d.Backend.Probe(ctx, label, wait)
		return &result, nil
	})
}

// ProbeSelf is Client.ProbeSelf.
func (d Direct) ProbeSelf() (*ProbeResult, error) {
	return ask(d, probeSelfWait, func(ctx context.Context) (*ProbeResult, error) {
		result := d.Backend.ProbeSelf(ctx)
		return &result, nil
	})
}

// BitTorrentStats is Client.BitTorrentStats.
func (d Direct) BitTorrentStats() (btstats.Report, error) {
	return ask(d, stateWait, func(context.Context) (btstats.Report, error) { return d.Backend.BitTorrentStats(), nil })
}

// ResetBitTorrentStats is Client.ResetBitTorrentStats.
func (d Direct) ResetBitTorrentStats() (btstats.Report, error) {
	return ask(d, stateWait, func(context.Context) (btstats.Report, error) { return d.Backend.ResetBitTorrentStats(), nil })
}

// BitTorrent is Client.BitTorrent.
func (d Direct) BitTorrent() (map[string]int64, error) {
	return ask(d, stateWait, func(context.Context) (map[string]int64, error) { return d.Backend.BitTorrent(), nil })
}

// Subscriptions is Client.Subscriptions.
func (d Direct) Subscriptions() ([]SubscriptionState, error) {
	return ask(d, stateWait, func(ctx context.Context) ([]SubscriptionState, error) { return d.Backend.Subscriptions(ctx), nil })
}

// StartSubscriptionUpdate is Client.StartSubscriptionUpdate.
func (d Direct) StartSubscriptionUpdate(name string) ([]SubscriptionState, error) {
	return ask(d, startWait+stateWait, func(ctx context.Context) ([]SubscriptionState, error) {
		return startUpdate(ctx, d.Backend, name), nil
	})
}

// UpdateSubscriptions is Client.UpdateSubscriptions.
func (d Direct) UpdateSubscriptions(name string) ([]SubscriptionState, error) {
	return ask(d, updateWait, func(ctx context.Context) ([]SubscriptionState, error) {
		return d.Backend.UpdateSubscriptions(ctx, name), nil
	})
}

// StartLoad is Client.StartLoad.
func (d Direct) StartLoad(address string, request ListRequest) (*LoadJob, error) {
	return ask(d, stateWait, func(ctx context.Context) (*LoadJob, error) {
		job := d.Backend.StartLoad(ctx, address, request)
		return &job, nil
	})
}

// LoadState is Client.LoadState.
func (d Direct) LoadState(id string) (*LoadJob, error) {
	return ask(d, stateWait, func(ctx context.Context) (*LoadJob, error) { return knownJob(d.Backend.LoadState(ctx, id)) })
}

// CancelLoad is Client.CancelLoad.
func (d Direct) CancelLoad(id string) (*LoadJob, error) {
	return ask(d, stateWait, func(ctx context.Context) (*LoadJob, error) { return knownJob(d.Backend.CancelLoad(ctx, id)) })
}

// knownJob is a job the backend knows, an error when it knows none.
func knownJob(job LoadJob, known bool) (*LoadJob, error) {
	if !known {
		return nil, errNoJob
	}
	return &job, nil
}

// CheckGroup is Client.CheckGroup.
func (d Direct) CheckGroup(check GroupCheck, wait time.Duration) (*GroupPreview, error) {
	return ask(d, wait, func(ctx context.Context) (*GroupPreview, error) {
		preview := d.Backend.CheckGroup(ctx, check)
		return &preview, nil
	})
}
