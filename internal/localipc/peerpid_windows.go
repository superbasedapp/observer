//go:build windows

package localipc

import (
	"net"

	"golang.org/x/sys/windows"
)

func peerPID(conn net.Conn) (int, bool) {
	h, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return 0, false
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(h.Fd()), &pid); err != nil || pid == 0 {
		return 0, false
	}
	return int(pid), true
}
