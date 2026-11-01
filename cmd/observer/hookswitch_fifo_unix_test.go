//go:build unix

package main

import (
	"syscall"
	"testing"
)

// makeHookSwitchFIFO creates a named pipe at path.
func makeHookSwitchFIFO(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
}
