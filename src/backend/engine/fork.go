package engine

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/route"
	R "github.com/sagernet/sing-box/route/rule"
)

// What the engine uses of the fork of sing-box it is built into besides the API of
// sing-box itself. Each is held to its type here, so that a rebase of the fork that loses
// one does not build: the run-time check of the interface that remains
// fails only for an object that is not the fork's own.
type (
	// peeker is the FakeIP store of the fork: it tells the address of a name without
	// giving one to a name that has none.
	peeker interface {
		Peek(domain string, isIPv6 bool) (netip.Addr, bool)
	}
	// ruleSetUpdater is the router of the fork: it downloads the remote rule sets now.
	ruleSetUpdater interface {
		UpdateRuleSets(ctx context.Context) (R.RuleSetUpdateSummary, error)
	}
	// detectOutcomes is the cache file of the fork: what it records of the handshakes with a
	// server, for the block detector.
	detectOutcomes interface {
		LoadDetectOutcome(key string) (flags byte, fingerprint string, at time.Time, loaded bool)
	}
	// detectFlows is the tracker of the fork: what it keeps of the closed connections, and how a swap
	// makes it forget those of the outbounds replaced.
	detectFlows interface {
		DetectFlows() map[string]trafficcontrol.DetectFlowSample
		ForgetDetectFlows(tags []string)
	}
	// detectPending is an open connection of the tracker of the fork: since when its client waits for
	// the server.
	detectPending interface {
		PendingSince() time.Time
	}
	// detectHistory is the history of the URL tests of the fork: their failures and the results of
	// the download tests.
	detectHistory interface {
		LoadURLTestFailure(tag string) (time.Time, bool)
		LoadDownloadResult(tag string) (urltest.DownloadResult, bool)
	}
)

var (
	_ peeker         = (*fakeip.Store)(nil)
	_ ruleSetUpdater = (*route.Router)(nil)
	_ detectOutcomes = adapter.CacheFile(nil)
	_ detectFlows    = (*trafficcontrol.Manager)(nil)
	_ detectPending  = (*trafficcontrol.TrackerMetadata)(nil)
	_ detectHistory  = (*urltest.HistoryStorage)(nil)
)

// The flags of the record of a server: what the block detector reads of them.
const (
	_ = adapter.DetectNoAnswer
	_ = adapter.DetectRefused
	_ = adapter.DetectFailed
)

// StopTimeout is how long an instance that is closed is waited for as a rule: sing-box's
// own limit for its close.
const StopTimeout = C.FatalStopTimeout
