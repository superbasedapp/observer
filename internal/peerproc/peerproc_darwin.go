//go:build darwin

package peerproc

import (
	"context"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/callerid"
)

// macOS offers no caller lookup: no Seatbelt profile reaches the host's
// loopback (it refuses the host tier) and the Apple container row has its
// own network, so no box can be a loopback caller (package doc).
const supported = false

func find(context.Context, netip.AddrPort, netip.AddrPort, map[int]string) (Peer, error) {
	return Peer{SocketUID: -1}, ErrUnsupported
}

// sZomb is SZOMB in <sys/proc.h>: the process has exited and waits for its
// parent to reap it.
const sZomb = 5

// startToken is the process's start time from sysctl kern.proc.pid, so a
// sandboxed CLI launch's marker is not kept alive by a later process that
// reused its pid (callerid fixes-1, L2). A zombie keeps its start time
// until it is reaped, but has exited, so it has no token.
func startToken(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil || int(kp.Proc.P_pid) != pid || kp.Proc.P_stat == sZomb {
		return "", false
	}
	t := kp.Proc.P_starttime
	if t.Sec == 0 && t.Usec == 0 {
		return "", false
	}
	return fmt.Sprintf("%d.%06d", t.Sec, t.Usec), true
}

// ancestors walks pid's parents through sysctl kern.proc.pid. A parent that
// started after its child is a reused pid and ends the walk.
func ancestors(pid int) []int {
	return callerid.Ancestors(pid, func(child int) (int, bool) {
		kc, err := unix.SysctlKinfoProc("kern.proc.pid", child)
		if err != nil || kc == nil || int(kc.Proc.P_pid) != child {
			return 0, false
		}
		parent := int(kc.Eproc.Ppid)
		if parent <= 0 {
			return 0, false
		}
		kp, err := unix.SysctlKinfoProc("kern.proc.pid", parent)
		if err != nil || kp == nil || int(kp.Proc.P_pid) != parent {
			return 0, false
		}
		ct, pt := kc.Proc.P_starttime, kp.Proc.P_starttime
		if pt.Sec > ct.Sec || (pt.Sec == ct.Sec && pt.Usec > ct.Usec) {
			return 0, false
		}
		return parent, true
	})
}

// envMarker reads no other process's environment on this platform.
func envMarker([]int, []string) (string, bool) { return "", false }
