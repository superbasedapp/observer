//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestOCIProbeNeverBlocksOnTheFirstUseFetch (SBX-P3D audit finding 3): the
// availability probe resolves the image through the hook that starts the
// first-use fetch; with that fetch hanging, the resolve still returns at
// once from what is installed (nothing: the empty default image).
func TestOCIProbeNeverBlocksOnTheFirstUseFetch(t *testing.T) {
	release := make(chan struct{})
	asDaemon(t, func(content.Kind, string) error { <-release; return nil })
	// Registered after asDaemon, so it runs first: the hanging attempt ends
	// and is waited for before asDaemon resets the attempt state, so it
	// never writes into the next test's state.
	t.Cleanup(func() {
		close(release)
		waitIdle(t, content.SandboxImage)
	})
	begin := time.Now()
	cfg, tr := ociEffectiveConfig(config.TerminalSandboxOCIConfig{}, t.TempDir())
	if d := time.Since(begin); d > time.Second {
		t.Fatalf("the probe's image resolve waited %s on the fetch", d)
	}
	if cfg.Image != "" || tr.refusal != "" {
		t.Fatalf("resolve with nothing installed: %+v %+v", cfg, tr)
	}
}
