//go:build linux

package main

import (
	"os"
	"path/filepath"
)

// native reports whether the process at base runs one of the binding's
// installed images (os.SameFile of base/exe and each path). It is called
// only from terminal_native_process_linux.go (/proc), so it lives in a
// Linux file (WINFIX4 lint: unused on Windows).
func (b terminalProcessBinding) native(base string) bool {
	if len(b.paths) == 0 {
		return false
	}
	current, err := os.Stat(filepath.Join(base, "exe"))
	if err != nil {
		return false
	}
	for _, path := range b.paths {
		installed, err := os.Stat(path)
		if err == nil && os.SameFile(current, installed) {
			return true
		}
	}
	return false
}
