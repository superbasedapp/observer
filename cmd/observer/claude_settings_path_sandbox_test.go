//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestSandboxRouteReaderRelativeUserScope pins FU-131's sandbox half: with a
// relative CLAUDE_CONFIG_DIR and no higher scope setting the key, the
// sandbox's effective-route reader for Claude Code says unknown, never "no
// route" (TestResolveClaudeRouteRelativeUserScope pins the resolver).
func TestSandboxRouteReaderRelativeUserScope(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "relative-dir")
	cwd := t.TempDir()
	reader := sandboxEffectiveRouteReaders[effectiveRouteKey{integration.RouteEnvSettings, "ANTHROPIC_BASE_URL"}]
	if got := reader("http://127.0.0.1:8820", cwd, nil); got != effectiveRouteUnknown {
		t.Errorf("sandbox reader = %v, want unknown", got)
	}
}
