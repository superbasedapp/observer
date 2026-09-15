package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestAdvertisedCapabilityResolvesTargets pins the shared init-target
// resolver: the "-windows" virtual target resolves to its BASE adapter (and
// reports isWindows so the caller can gate on that row's own CrossOSBridge
// flag), an unknown tool is ok=false, and the returned zero Capability still
// echoes the BASE name so a caller can name the target in an error.
//
// There is no registry-override seam in this package, so the lifecycle veto
// is exercised against the predicate itself in
// TestAdvertisedCapabilityVetoesUnadvertisedRows below rather than by
// injecting a fake dead row.
func TestAdvertisedCapabilityResolvesTargets(t *testing.T) {
	for _, tc := range []struct {
		name        string
		tool        string
		wantBase    string
		wantWindows bool
		wantOK      bool
	}{
		{"plain tool", "claude-code", "claude-code", false, true},
		{"windows virtual target", "claude-code-windows", "claude-code", true, true},
		{"windows target of a row without a bridge", "codex-windows", "codex", true, true},
		{"browser rail", "chatgpt-web", "chatgpt-web", false, true},
		{"unknown tool", "definitely-not-a-tool", "definitely-not-a-tool", false, false},
		{"unknown windows target", "definitely-not-a-tool-windows", "definitely-not-a-tool", true, false},
		{"empty", "", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, isWindows, ok := advertisedCapability(tc.tool)
			if ok != tc.wantOK {
				t.Fatalf("advertisedCapability(%q) ok = %v, want %v", tc.tool, ok, tc.wantOK)
			}
			if isWindows != tc.wantWindows {
				t.Errorf("advertisedCapability(%q) isWindows = %v, want %v", tc.tool, isWindows, tc.wantWindows)
			}
			if c.Tool != tc.wantBase {
				t.Errorf("advertisedCapability(%q) Tool = %q, want %q", tc.tool, c.Tool, tc.wantBase)
			}
		})
	}
}

// TestAdvertisedCapabilityVetoesUnadvertisedRows pins rule 2 of the shared
// resolver against the live registry: it returns ok only for rows whose
// lifecycle is advertised, so a future deprecated/dead row drops out of every
// init predicate (hooks / MCP / proxy route / probe route / browser
// extension) with no edit to those predicates. Today every shipped row is
// active, so the assertion is an equivalence — which is exactly what should
// break loudly the first time a row is flipped without the predicates being
// re-read.
func TestAdvertisedCapabilityVetoesUnadvertisedRows(t *testing.T) {
	for _, c := range integration.Capabilities() {
		_, _, ok := advertisedCapability(c.Tool)
		if ok != c.Advertised() {
			t.Errorf("advertisedCapability(%q) ok = %v, want %v (Lifecycle %q)",
				c.Tool, ok, c.Advertised(), c.Lifecycle.String())
		}
		if !c.Advertised() {
			// The teeth: an unadvertised row must answer false on every
			// init-target predicate regardless of its capability shape.
			for name, got := range map[string]bool{
				"hookSupported":       hookSupported(c.Tool),
				"mcpSupported":        mcpSupported(c.Tool),
				"routeSupported":      routeSupported(c.Tool),
				"routeProbeSupported": routeProbeSupported(c.Tool),
				"extensionSupported":  extensionSupported(c.Tool),
			} {
				if got {
					t.Errorf("%s(%q) = true for lifecycle %q — an unadvertised product must never be an "+
						"`observer init` target", name, c.Tool, c.Lifecycle.String())
				}
			}
		}
	}
}
