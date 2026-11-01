//go:build !sbo_omit_terminals

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// TestLaunchIsolationFor: the run pill shows a sandboxed run's evidence and
// nothing for an unsandboxed one.
func TestLaunchIsolationFor(t *testing.T) {
	if launchIsolationFor(termrun.Isolation{Class: "none", CaptureOrigin: "local"}) != nil || launchIsolationFor(termrun.Isolation{}) != nil {
		t.Fatal("an unsandboxed run got a pill")
	}
	got := launchIsolationFor(termrun.Isolation{Class: "process", Stack: []string{"bwrap"}, EgressTier: "internet", CaptureLevel: "full", CaptureRule: "C6", Verification: "live"})
	if got == nil || got.Backend != "bwrap" || got.CaptureRule != "C6" || got.Class != "process" || got.EgressTier != "internet" {
		t.Fatalf("pill %+v", got)
	}
}
