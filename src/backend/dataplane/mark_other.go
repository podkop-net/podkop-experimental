//go:build !linux

package dataplane

import "syscall"

// MarkedControl marks nothing on a system without socket marks.
func MarkedControl(network string, address string, conn syscall.RawConn) error {
	return nil
}
