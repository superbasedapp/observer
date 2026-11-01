//go:build unix && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByMe reports whether fi belongs to this process's user (a macOS
// driver's plan file must).
func ownedByMe(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
