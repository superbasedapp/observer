//go:build !unix

package main

import "testing"

// makeHookSwitchFIFO skips: Windows has no named pipe at a filesystem path
// (its pipes live under \\.\pipe\), so a hook-switch path can never be one.
func makeHookSwitchFIFO(t *testing.T, _ string) {
	t.Helper()
	t.Skip("no FIFO at a filesystem path on this OS: Windows named pipes live under \\\\.\\pipe\\")
}
