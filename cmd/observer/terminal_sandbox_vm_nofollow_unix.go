//go:build !windows && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"syscall"
)

// openNoFollow opens path read-only and refuses a symlink at the final
// element (O_NOFOLLOW).
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: a content store path the caller derived
}
