//go:build unix

package guard

import (
	"os"
	"syscall"
)

// openSQLFile opens a SQL script read-only without blocking: O_NONBLOCK
// makes the open of a FIFO (a path swapped in after a check) return at once
// instead of waiting for a writer until the hook deadline; the caller then
// rejects it as not a regular file. A regular file is unaffected.
func openSQLFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // the path is the SQL script the guarded command names
}
