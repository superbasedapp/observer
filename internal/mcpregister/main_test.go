package mcpregister

import (
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// TestMain fails the package run when any MCP config write was refused by
// testwriteguard.Check (incident 2026-10-20).
func TestMain(m *testing.M) {
	os.Exit(testwriteguard.Run(m))
}
