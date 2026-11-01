//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestIsInternalChildEnvStripsSandboxMarker pins the U9 anti-spoof arm: the
// OBSERVER_SANDBOX marker is daemon-owned and must be classified internal so
// launchChildEnv strips it from inherited/caller env. Removing the arm makes
// this fail.
func TestIsInternalChildEnvStripsSandboxMarker(t *testing.T) {
	if !isInternalChildEnv(sandbox.EnvMarker + "=1") {
		t.Fatalf("isInternalChildEnv(%q=1) = false, want true (the marker must be strippable)", sandbox.EnvMarker)
	}
	// A user var that merely CONTAINS the name as a substring is not the marker
	// and must NOT be stripped.
	if isInternalChildEnv("MY_" + sandbox.EnvMarker + "=1") {
		t.Fatalf("isInternalChildEnv stripped an unrelated var containing the marker name")
	}
}

// TestLaunchChildEnvRefusesSpoofedSandboxMarker is the end-to-end anti-spoof
// proof: a caller that plants OBSERVER_SANDBOX=1 in the child's ExtraEnv on a
// NON-sandboxed launch must not get the marker through — otherwise a
// non-isolated session would falsely self-report Caps.Sandboxed=true on the
// hook lane. With the strip arm gone, the spoofed ExtraEnv entry survives and
// this fails.
func TestLaunchChildEnvRefusesSpoofedSandboxMarker(t *testing.T) {
	req := termsvc.LaunchRequest{
		Tool:      "claude-code",
		RunID:     "run-1",
		Sandboxed: false,                              // NOT sandboxed
		ExtraEnv:  []string{sandbox.EnvMarker + "=1"}, // spoof attempt
	}
	out := launchChildEnv(req, "auth-token")
	for _, kv := range out {
		if strings.HasPrefix(kv, sandbox.EnvMarker+"=") {
			t.Fatalf("non-sandboxed child env leaked %q - spoofed marker not stripped", kv)
		}
	}
}

// TestLaunchChildEnvSetsSandboxMarkerWhenSandboxed confirms the honest
// positive: a genuinely sandboxed launch gets exactly one daemon-set marker.
func TestLaunchChildEnvSetsSandboxMarkerWhenSandboxed(t *testing.T) {
	req := termsvc.LaunchRequest{Tool: "claude-code", RunID: "run-2", Sandboxed: true}
	out := launchChildEnv(req, "auth-token")
	n := 0
	for _, kv := range out {
		if kv == sandbox.EnvMarker+"=1" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("sandboxed child env has %d %q=1 entries, want exactly 1", n, sandbox.EnvMarker)
	}
}
