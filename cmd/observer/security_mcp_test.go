//go:build !sbo_omit_security && !sbo_omit_integration_mcp_server

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestSecurityMCPToolsGate (security pillar plan section 11.1 C: "the MCP
// tools are absent when the module or MCP is off"): registered while the
// module is active and [security.mcp].tools is on, absent otherwise.
func TestSecurityMCPToolsGate(t *testing.T) {
	cfg := config.Default()
	// The module active: by default, or selected where this edition leaves
	// it inert with no block (managed).
	selectIfInactive(t, &cfg, "security")
	if got := securityMCPTools(cfg, nil, nil); len(got) != 2 {
		t.Fatalf("module active, tools on: %d tools, want 2", len(got))
	}
	off := cfg
	off.Security.MCP.Tools = false
	if got := securityMCPTools(off, nil, nil); len(got) != 0 {
		t.Fatalf("tools off: %d tools", len(got))
	}
	minimal := cfg
	minimal.Components = config.ComponentsConfig{Distro: "minimal"}
	if got := securityMCPTools(minimal, nil, nil); len(got) != 0 {
		t.Fatalf("module not selected: %d tools", len(got))
	}
}
