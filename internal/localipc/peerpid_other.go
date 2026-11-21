//go:build !linux && !darwin && !windows

package localipc

import "net"

// No peer lookup on this platform: the caller is not identified.
func peerPID(net.Conn) (int, bool) { return 0, false }
