//go:build linux && !sbo_omit_terminals

package main

import (
	"syscall"
	"testing"
)

// runtimePollerFD opens the kind of descriptor the Go runtime polls with on
// Linux (epoll).
func runtimePollerFD(t *testing.T) (int, bool) {
	t.Helper()
	ep, err := syscall.EpollCreate1(0)
	if err != nil {
		t.Fatal(err)
	}
	return ep, true
}
