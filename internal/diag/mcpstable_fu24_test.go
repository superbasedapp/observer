package diag

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/installshape"
)

// TestMCPRegistrationsStableCommandGate pins the DEC-12 gate on the FU-24
// bare MCP command: the doctor always names it as built and waiting on its
// live check, and only with the opt-in does a bare entry of this install
// count as registered.
func TestMCPRegistrationsStableCommandGate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the bare form is POSIX-only")
	}
	bin := t.TempDir()
	self := filepath.Join(bin, "observer")
	if err := os.WriteFile(self, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // G306: an executable test stub.
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"mcpServers":{"observer":{"command":"observer","args":["serve"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	off := checkMCPRegistrations(home, self, self, nil, false)
	if off.Status != StatusWarn {
		t.Errorf("opt-in off: a bare entry is a mismatch, got %v %q", off.Status, off.Message)
	}
	if d := strings.Join(off.Details, "\n"); !strings.Contains(d, "built, waiting on "+installshape.PathNameLiveCheck) || !strings.Contains(d, "off by default") {
		t.Errorf("opt-in off: details %q do not name the gate", d)
	}
	on := checkMCPRegistrations(home, self, self, nil, true)
	if on.Status != StatusOK || !strings.Contains(on.Message, "claude-code") {
		t.Errorf("opt-in on: got %v %q, want claude-code registered", on.Status, on.Message)
	}
	if d := strings.Join(on.Details, "\n"); !strings.Contains(d, "not live-verified") {
		t.Errorf("opt-in on: details %q do not say not live-verified", d)
	}
}
