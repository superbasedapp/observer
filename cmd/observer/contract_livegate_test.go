//go:build !sbo_omit_integration_mcp_server

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestContractDoesNotPublishGatedHooksAsWired: `observer contract` reports
// hook_auto_wired false for a hook writer that waits on a live check.
func TestContractDoesNotPublishGatedHooksAsWired(t *testing.T) {
	for _, w := range integration.LiveGatedWriters() {
		if w.Kind != "hooks" {
			continue
		}
		c, _ := integration.For(w.Tool)
		if publicAdapterRow(c).HookAutoWired {
			t.Errorf("%s: contract publishes hook_auto_wired for a gated writer", w.Tool)
		}
	}
}
