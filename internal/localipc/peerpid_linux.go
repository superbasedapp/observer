//go:build linux

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
	var cred *unix.Ucred
	var cerr error
	if err := rc.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) //nolint:gosec // G115: a descriptor number
	}); err != nil || cerr != nil || cred == nil || cred.Pid <= 0 {
		return 0, false
	}
	return int(cred.Pid), true
}
