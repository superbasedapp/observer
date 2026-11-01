//go:build darwin

package main

import (
	"bytes"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// platformGUIInstanceRunning lists this user's processes (sysctl
// kern.proc.uid) and reads each one's executable path (kern.procargs2): an
// app is running when a process executes from its bundle's Contents/MacOS
// directory. Execs nothing.
func platformGUIInstanceRunning(bin string) bool {
	if r, err := filepath.EvalSymlinks(bin); err == nil {
		bin = r
	}
	prefix := guiBundleExecDir(bin)
	if prefix == "" {
		return false
	}
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.uid", unix.Getuid())
	if err != nil {
		return false
	}
	for _, p := range procs {
		raw, err := unix.SysctlRaw("kern.procargs2", int(p.Proc.P_pid))
		if err != nil || len(raw) <= 4 {
			continue
		}
		// kern.procargs2: a 32-bit argc, then the NUL-terminated exec path.
		path := raw[4:]
		if i := bytes.IndexByte(path, 0); i >= 0 {
			path = path[:i]
		}
		if strings.HasPrefix(string(path), prefix) {
			return true
		}
	}
	return false
}
