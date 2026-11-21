//go:build darwin

package localipc

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func peerPID(conn net.Conn) (int, bool) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, false
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, false
	}
	pid := 0
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		pid, gerr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID) //nolint:gosec // G115: a descriptor number
	}); err != nil || gerr != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}
