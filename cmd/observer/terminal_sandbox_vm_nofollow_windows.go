//go:build windows && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"os"
)

// openNoFollow refuses a reparse point at the final element, then opens
// (the microVM row never runs on Windows; the import verb does).
func openNoFollow(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return os.Open(path) //nolint:gosec // G304: a content store path the caller derived
}
