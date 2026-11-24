package subscription

import (
	"net"

	"github.com/podkop-net/podkop-experimental/src/backend/dataplane"
)

// DirectRoute is the way to the provider straight from the router, for when sing-box does
// not run: the socket has the mark of what sing-box sends (dataplane.OutboundMark), which
// keeps it out of the proxy, and the name is resolved by the resolver of the system. While
// sing-box runs the direct way is its outbound direct-out instead: the resolver of the
// system then answers the names of the lists from FakeIP.
func DirectRoute() Route {
	dialer := &net.Dialer{Control: dataplane.MarkedControl}
	return Route{Name: "direct", Direct: true, Dial: dialer.DialContext}
}
