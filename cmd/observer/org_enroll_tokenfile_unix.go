//go:build unix

package main

import (
	"os"
	"syscall"
)

// openEnrolTokenFile opens a --token-file path without blocking: O_NONBLOCK
// makes the open of a FIFO with no writer return at once, so the caller's
// fstat refuses it by type instead of enrolment hanging in open(2) (O5
// audit finding O5-A7: a stat before a blocking open left a window in which
// the path could be swapped for a FIFO). O_NONBLOCK has no effect on reads
// of the regular file the caller then accepts. O_NOCTTY keeps a terminal
// device path from becoming the controlling terminal.
func openEnrolTokenFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0) //nolint:gosec // G304: the path the user named on the command line
}
