//go:build !sbo_omit_adapter_cursor && !sbo_omit_terminals_sandbox && !sbo_omit_isolation

package hook

import (
	"encoding/json"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// TestBuildCursorEvent_CapsSandboxedReflectsMarker pins the cursor.go stamp:
// BuildCursorEvent's returned Caps.Sandboxed mirrors the OBSERVER_SANDBOX
// marker, matching the Claude Code hook lane's behaviour (plan §6 - both
// hook-spawned lanes self-report truthfully).
func TestBuildCursorEvent_CapsSandboxedReflectsMarker(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"conversation_id": "conv-1",
		"generation_id":   "gen-1",
		"command":         "ls -la",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	ev, ok := BuildCursorEvent("beforeShellExecution", body, nil)
	if !ok {
		t.Fatalf("BuildCursorEvent: ok=false, want true")
	}
	if ev.Caps.Sandboxed {
		t.Errorf("Caps.Sandboxed = true with no marker set, want false")
	}

	t.Setenv(sandbox.EnvMarker, "1")
	ev, ok = BuildCursorEvent("beforeShellExecution", body, nil)
	if !ok {
		t.Fatalf("BuildCursorEvent: ok=false, want true")
	}
	if !ev.Caps.Sandboxed {
		t.Errorf("Caps.Sandboxed = false with marker=1, want true")
	}
}
