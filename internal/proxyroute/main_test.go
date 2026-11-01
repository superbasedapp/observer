package proxyroute

import (
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// TestMain fails the package run when any route write was refused by
// testwriteguard.Check (incident 2026-10-20).
func TestMain(m *testing.M) {
	os.Exit(testwriteguard.Run(m))
}
