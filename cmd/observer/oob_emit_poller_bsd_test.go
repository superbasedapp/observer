//go:build (darwin || dragonfly || freebsd || netbsd || openbsd) && !sbo_omit_terminals

package main

import (
	"syscall"
	"testing"
)

// runtimePollerFD opens the kind of descriptor the Go runtime polls with on
// macOS and the BSDs (kqueue).
func runtimePollerFD(t *testing.T) (int, bool) {
	t.Helper()
	kq, err := syscall.Kqueue()
	if err != nil {
		t.Fatal(err)
	}
	return kq, true
}
