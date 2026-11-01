//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// platformGUIInstanceRunning reads /proc/<pid>/exe for every process this
// user may inspect (another user's link is unreadable and skipped) and
// matches the FULL path of bin's resolved executable, never a base name: any
// unrelated program called `code` must not read as a running VS Code. A
// launcher script (/usr/bin/code runs the binary under /usr/share/code)
// therefore matches nothing, which keeps the launch verdict as it was.
func platformGUIInstanceRunning(bin string) bool {
	want, err := filepath.EvalSymlinks(bin)
	if err != nil {
		return false
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	self := os.Getpid()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		exe, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil {
			continue
		}
		// A binary replaced since the process started reads "<path> (deleted)".
		if strings.TrimSuffix(exe, " (deleted)") == want {
			return true
		}
	}
	return false
}
