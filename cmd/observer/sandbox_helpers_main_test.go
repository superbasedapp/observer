package main

import (
	"os"
	"testing"
)

// TestMain lets the test binary stand in for the observer binary as a sandbox
// network helper: the live sandbox tests plan the host/guest helper verbs
// against os.Executable() (this binary), exactly as the daemon plans them
// against itself, so argv[1] naming a helper verb must run the helper, not the
// test suite.
func TestMain(m *testing.M) {
	if code, ok := sandboxHelperDispatch(os.Args); ok {
		os.Exit(code)
	}
	os.Exit(m.Run())
}
