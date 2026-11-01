//go:build unix && !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !sbo_omit_terminals

package main

import "testing"

// runtimePollerFD has no portable poller to open on this unix (the Go
// runtime uses event ports or pollset here); the shape check is skipped.
func runtimePollerFD(*testing.T) (int, bool) { return -1, false }
