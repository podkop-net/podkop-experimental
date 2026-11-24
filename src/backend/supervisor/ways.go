package supervisor

import (
	"context"
	"net"
	"net/url"
	"slices"

	"github.com/podkop-net/podkop-experimental/src/backend/plan"
	"github.com/podkop-net/podkop-experimental/src/backend/subscription"
)

// The ways the backend's own downloads take to a host: the lists of the subscriptions
// (subscriptions.go) and the public lists of names of a mask search (masklist.go).

// routes are the ways to a provider at host, in the order they are tried. While sing-box runs
// with the HTTP client of the lists (http_client.outbounds, engine r26), its downloader orders
// them as it orders the ways of the lists: directly and the servers of the rules that download
// the lists, by what the downloads from the host found (downloadWays); together then tells that
// the first way failed for the host the last time. Else directly, then through the servers of
// the configuration that runs, the fastest first as the URL tests found them, those not tested
// after, at most proxies of them. Directly is through direct-out of sing-box while it runs: the
// resolver of the system answers the names of the lists from FakeIP then.
func (s *Supervisor) routes(proxies int, first string, host string) ([]subscription.Route, Instance, bool) {
	s.statusAccess.Lock()
	live, links := s.live, s.liveLinks
	s.statusAccess.Unlock()
	if live == nil {
		return []subscription.Route{subscription.DirectRoute()}, nil, false
	}
	through := func(tag string) func(ctx context.Context, network string, address string) (net.Conn, error) {
		return func(ctx context.Context, network string, address string) (net.Conn, error) {
			return live.Dial(ctx, tag, address)
		}
	}
	// a way is named as the page names the outbound: the name of the server of a subscription,
	// the section and number of a link
	var tags []string
	names := make(map[string]string)
	for _, link := range links {
		if !slices.Contains(tags, link.Tag) {
			tags = append(tags, link.Tag)
			names[link.Tag] = link.Name
		}
	}
	if ways, together := live.DownloadWays(plan.ListsHTTPClient, host); len(ways) > 0 {
		routes := make([]subscription.Route, 0, len(ways))
		for _, tag := range ways {
			route := subscription.Route{Name: names[tag], Tag: tag, Dial: through(tag)}
			switch {
			case tag == plan.DirectOutbound:
				route.Name, route.Direct = "direct", true
			case route.Name == "":
				route.Name = tag
			}
			routes = append(routes, route)
		}
		return routes, live, together
	}
	routes := []subscription.Route{{Name: "direct", Tag: plan.DirectOutbound, Direct: true, Dial: through(plan.DirectOutbound)}}
	delays := s.options.Engine.Delays(tags)
	slices.SortStableFunc(tags, func(left string, right string) int {
		// the way of the last download first: it brought the list then
		switch {
		case names[left] == first && names[right] != first:
			return -1
		case names[right] == first && names[left] != first:
			return 1
		}
		leftDelay, leftTested := delays[left]
		rightDelay, rightTested := delays[right]
		switch {
		case leftTested && rightTested:
			return int(leftDelay) - int(rightDelay)
		case leftTested:
			return -1
		case rightTested:
			return 1
		}
		return 0
	})
	for _, tag := range tags[:min(len(tags), proxies)] {
		routes = append(routes, subscription.Route{Name: names[tag], Tag: tag, Dial: through(tag)})
	}
	return routes, live, false
}

// liveInstance is the instance that runs now.
func (s *Supervisor) liveInstance() Instance {
	s.statusAccess.Lock()
	defer s.statusAccess.Unlock()
	return s.live
}

// recordTries tells the downloader of the lists what the tries of a download from host came to:
// a way that brought the list, and one that failed for a fault of its own (not one another way
// made needless, nor one the end of the download's context cut — a search that found its mask,
// a page that gave up, a budget spent —, nor an answer of the provider itself).
func recordTries(live Instance, host string, routes []subscription.Route, tries []subscription.Try) {
	if live == nil {
		return
	}
	tags := make(map[string]string, len(routes))
	for _, route := range routes {
		tags[route.Name] = route.Tag
	}
	for _, item := range tries {
		tag := tags[item.Route]
		if tag == "" {
			continue
		}
		switch {
		case item.Phase == subscription.PhaseDone:
			live.RecordDownload(plan.ListsHTTPClient, host, tag, nil, item.Took, item.Bytes)
		case item.Phase == subscription.PhaseFailed && item.Failure != nil && !item.Failure.Final() && item.Failure.Code != "canceled" && !item.Cut:
			live.RecordDownload(plan.ListsHTTPClient, host, tag, item.Failure, item.Took, item.Bytes)
		}
	}
}

// hostOf is the host of an address, "" for an address that has none.
func hostOf(address string) string {
	parsed, err := url.Parse(address)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// secureAddress tells an address of HTTPS.
func secureAddress(address string) bool {
	parsed, err := url.Parse(address)
	return err == nil && parsed.Scheme == "https"
}
