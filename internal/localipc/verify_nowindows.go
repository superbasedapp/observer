//go:build !windows

package localipc

import "net"

// verifyServer is a no-op off Windows: the unix socket lives in the
// owner-only 0700 directory, so only this user can have created it.
func verifyServer(net.Conn) error { return nil }
