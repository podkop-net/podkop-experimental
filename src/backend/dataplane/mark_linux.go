package dataplane

import "syscall"

// MarkedControl is the Control of a net.Dialer for a socket of the backend's own that must not go
// through the proxy: it gives the socket the mark of what sing-box sends (OutboundMark), and the
// firewall keeps it out of the proxy whatever its address is, as it does the connections of
// sing-box (a question about the time, a download of a subscription while sing-box does not run).
// Without the right to set the mark the socket goes without it.
func MarkedControl(network string, address string, conn syscall.RawConn) error {
	return conn.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(OutboundMark))
	})
}
