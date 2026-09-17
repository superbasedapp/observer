package integration_test

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestSandboxRowDeclaredForEveryAdapter widens the B9 honest-zero gate
// from the launchable rows (TestSandboxDeclaredForEveryLaunchableAdapter,
// registry_coverage_test.go) to EVERY registry row: each one must either
// declare grounded writable state (StateRW) or say, in its Note, why it
// has none.
//
// Why the wider sweep. "Not launchable" is not a reason a reader can see
// from the SandboxSpec itself — a zero-value row reads identically whether
// the tool is a browser-captured chat, an IDE-embedded agent nobody spawns,
// or a CLI whose state dirs were simply never grounded. Those are three
// different facts with three different follow-ups, and the registry's
// honesty rule is that a zero cell says which one it is.
//
// The assertion is on SHAPE, never on a tool name (CLAUDE.md #3): a new
// adapter fails this test until its author has either grounded the tool's
// state dirs against that adapter's own roots or written down why the tool
// cannot be sandboxed at all.
func TestSandboxRowDeclaredForEveryAdapter(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if len(c.Sandbox.StateRW) > 0 || len(c.Sandbox.StateRO) > 0 {
			continue
		}
		if strings.TrimSpace(c.Sandbox.Note) == "" {
			t.Errorf("adapter %q: SandboxSpec has no StateRW/StateRO and no Note — "+
				"ground the tool's state dirs against its adapter roots, or say why it has none",
				c.Tool)
		}
	}
}

// TestSandboxLaunchableToolsAreGrounded records, as a live floor, how many
// launchable tools can actually be sandboxed today — the set
// sandboxRuntime.tools() reports Available=true for, and therefore the set
// whose "Run in a sandbox" checkbox is enabled in the New Terminal dialog.
//
// It is deliberately a floor and not an exact set: grounding one more
// adapter must never fail this test, but LOSING a grounded row (a refactor
// that drops a StateRW list, or a lifecycle flip that un-advertises a
// grounded tool) must.
func TestSandboxLaunchableToolsAreGrounded(t *testing.T) {
	// claude-code (B9 v1) + the 22 CLIs grounded against their adapters'
	// own roots in the 2026-09-15 grounding pass.
	const floor = 23
	var grounded []string
	for _, c := range integration.Capabilities() {
		if integration.TerminalLaunchable(c) && len(c.Sandbox.StateRW) > 0 {
			grounded = append(grounded, c.Tool)
		}
	}
	if len(grounded) < floor {
		t.Errorf("sandbox-launchable tools = %d (%v), want at least %d", len(grounded), grounded, floor)
	}
}
