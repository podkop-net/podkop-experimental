package engine

import (
	"context"
	"io"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/domainset"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/common/ruletext"
	"github.com/sagernet/sing-box/common/sharelink"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"

	"go4.org/netipx"
)

// What the engine uses of the fork of sing-box it is built into besides the API of
// sing-box itself: all of it, with the patch of podkop-engine that brings each (the list of
// podkop-engine's docs/EMBEDDING.md). Each is held to its type here, so that a rebase of the
// fork that loses one does not build: the run-time check of the interface that remains
// fails only for an object that is not the fork's own, and what the fork looks for in an object
// of the engine (the log writer) it simply does not find. What the engine calls by name would
// not build either; it is here so that this is the whole list.
type (
	// starter is the box of the fork: a start that fails leaves the box to its caller to close
	// (0420).
	starter interface {
		StartWithoutClose() error
	}
	// outboundSwapper is the box of the fork: it replaces outbounds while it runs (0314).
	outboundSwapper interface {
		UpdateOutbounds(outbounds []option.Outbound, remove []string, limit int) (box.OutboundUpdate, error)
	}
	// peeker is the FakeIP store of the fork: it tells the address of a name without
	// giving one to a name that has none (0405).
	peeker interface {
		Peek(domain string, isIPv6 bool) (netip.Addr, bool)
	}
	// ruleSetUpdater is the router of the fork: it downloads the remote rule sets now (0402).
	ruleSetUpdater interface {
		UpdateRuleSets(ctx context.Context) (R.RuleSetUpdateSummary, error)
	}
	// detectOutcomes is the cache file of the fork: what it records of the handshakes with a
	// server, for the block detector (0421).
	detectOutcomes interface {
		LoadDetectOutcome(key string) (flags byte, fingerprint string, at time.Time, loaded bool)
	}
	// detectFlows is the tracker of the fork: what it keeps of the closed connections, and how a swap
	// makes it forget those of the outbounds replaced (0421).
	detectFlows interface {
		DetectFlows() map[string]trafficcontrol.DetectFlowSample
		ForgetDetectFlows(tags []string)
	}
	// detectPending is an open connection of the tracker of the fork: since when its client waits for
	// the server (0421).
	detectPending interface {
		PendingSince() time.Time
	}
	// detectHistory is the history of the URL tests of the fork: their failures and the results of
	// the download tests (0410).
	detectHistory interface {
		LoadURLTestFailure(tag string) (time.Time, bool)
		LoadDownloadResult(tag string) (urltest.DownloadResult, bool)
	}
	// downloadWays is a downloader of an HTTP client of the fork (adapter.HTTPDownloader): the
	// order of the ways it takes for a host, and what a download through one came to (0423).
	downloadWays interface {
		Ways(host string) ([]string, bool)
		Record(host string, way string, err error, took time.Duration, bytes int64)
	}
	// downloadMemory is what the downloaders of the fork learn of the ways, which the engine keeps
	// for the process (0423).
	downloadMemory interface {
		Forget(way string)
		SetExcluded(tags []string)
	}
	// linkSecrets is the outbound of a share link the decoder of the fork made: what an error
	// about it must not repeat (0307).
	linkSecrets interface {
		Secrets() []string
		Unplain() []string
	}
	// addressRanges are the CIDR lists of a rule set as the fork keeps them (0419).
	addressRanges interface {
		Len() int
		Ranges() []netipx.IPRange
		Ranges4() []uint64
	}
)

var (
	_ starter         = (*box.Box)(nil)
	_ outboundSwapper = (*box.Box)(nil)
	_ error           = box.ErrTooManyKept
	_ peeker          = (*fakeip.TableStore)(nil)
	_ ruleSetUpdater  = (*route.Router)(nil)
	_ detectOutcomes  = adapter.CacheFile(nil)
	_ detectFlows     = (*trafficcontrol.Manager)(nil)
	_ detectPending   = (*trafficcontrol.TrackerMetadata)(nil)
	_ detectHistory   = (*urltest.HistoryStorage)(nil)
	// the HTTP clients of the box have downloaders: the run-time check of the engine finds none in
	// another manager
	_ adapter.HTTPDownloaders           = (*httpclient.Manager)(nil)
	_ downloadWays                      = adapter.HTTPDownloader(nil)
	_ downloadMemory                    = (*httpclient.DownloadMemory)(nil)
	_ func() *httpclient.DownloadMemory = httpclient.NewDownloadMemory
	// the platform writer of the engine takes the lines of its level only, without colours: the
	// log of the fork asks a writer whether it has a level, and colours a line for one that
	// does not tell (0411)
	_ log.PlatformWriterLevel  = sinkWriter{}
	_ log.PlatformWriterColors = sinkWriter{}
	// a server that is not the REALITY server it should be (0401), the key of what the cache file
	// keeps of a server (0421), how the rule sets of a box start (0402)
	_ error                                    = tls.ErrRealityVerification
	_ func(string, string, M.Socksaddr) string = adapter.DetectOutcomeKey
	_                                          = R.RemoteStart{Empty: true}
	// a copy of an outbound for a probe is built with the fallback off: the fork reads its options
	// from the context, as *option.UTLSFallbackOptions (0414)
	_ = &option.UTLSFallbackOptions{Enabled: false}
	// share links (0307)
	_ func(link string) (*sharelink.Outbound, []string, error) = sharelink.Decode
	_ func(message string) string                              = sharelink.OneLine
	_ func(message string, secrets []string) string            = sharelink.PlainMessage
	_ linkSecrets                                              = (*sharelink.Outbound)(nil)
	// rule-set files read as sing-box reads them: lists written as text (0309), the names in a
	// compact trie (0418), the addresses as ranges (0419)
	_ func(content []byte) (option.PlainRuleSetCompat, ruletext.Skipped, error) = ruletext.ReadAddresses
	_ func(content []byte) (option.PlainRuleSetCompat, error)                   = domainset.ReadSource
	_ func(content []byte) (option.PlainRuleSetCompat, error)                   = domainset.ReadSourceAddresses
	_ func(reader io.Reader) (option.PlainRuleSetCompat, error)                 = srs.ReadSets
	_ addressRanges                                                             = option.DefaultHeadlessRule{}.IPRanges
	_                                                                           = option.DefaultHeadlessRule{DomainSet: nil, SourceIPRanges: nil}
)

// The flags of the record of a server: what the block detector reads of them (0421). The
// format of lists written as text (0208). The XHTTP transport (0206).
const (
	_ = adapter.DetectNoAnswer
	_ = adapter.DetectRefused
	_ = adapter.DetectFailed
	_ = C.RuleSetFormatText
	_ = C.V2RayTransportTypeXHTTP
)

// StopTimeout is how long an instance that is closed is waited for as a rule: sing-box's
// own limit for its close.
const StopTimeout = C.FatalStopTimeout
