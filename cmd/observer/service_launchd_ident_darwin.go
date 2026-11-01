//go:build darwin

package main

import (
	"strconv"

	"golang.org/x/sys/unix"
)

// launchdProcessIdentity is pid's start time from the kernel's process
// table (sysctl kern.proc.pid), the identity `observer service stop`
// compares before it SIGKILLs a pid (MACUSER merge L1): a pid the system
// reused for another process has another start time.
func launchdProcessIdentity(pid int) (string, bool) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil || kp.Proc.P_pid != int32(pid) { //nolint:gosec // G115: a pid fits in int32
		return "", false
	}
	st := kp.Proc.P_starttime
	return strconv.FormatInt(st.Sec, 10) + "." + strconv.FormatInt(int64(st.Usec), 10), true
}
