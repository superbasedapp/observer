//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation

package hook

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// TestSandboxedChild pins the OBSERVER_SANDBOX env-marker read: set to "1" it
// reports true, and any other value (including unset) reports false — the
// hook lane must never assume sandboxed by default (honest-zero posture,
// plan §6).
func TestSandboxedChild(t *testing.T) {
	tests := []struct {
		name  string
		set   bool
		value string
		want  bool
	}{
		{name: "unset", set: false, want: false},
		{name: "marker set to 1", set: true, value: "1", want: true},
		{name: "marker set to other value", set: true, value: "true", want: false},
		{name: "marker set to empty string", set: true, value: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv(sandbox.EnvMarker, tt.value)
			}
			if got := sandboxedChild(); got != tt.want {
				t.Errorf("sandboxedChild() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBuildClaudeCodeEvent_CapsSandboxedReflectsMarker pins the guarded.go
// stamp: BuildClaudeCodeEvent's returned Caps.Sandboxed mirrors the
// OBSERVER_SANDBOX marker in this process's env, not a hardcoded value.
func TestBuildClaudeCodeEvent_CapsSandboxedReflectsMarker(t *testing.T) {
	body := preToolBody("Bash", "ls -la")

	ev, ok := BuildClaudeCodeEvent(body)
	if !ok {
		t.Fatalf("BuildClaudeCodeEvent: ok=false, want true")
	}
	if ev.Caps.Sandboxed {
		t.Errorf("Caps.Sandboxed = true with no marker set, want false")
	}

	t.Setenv(sandbox.EnvMarker, "1")
	ev, ok = BuildClaudeCodeEvent(body)
	if !ok {
		t.Fatalf("BuildClaudeCodeEvent: ok=false, want true")
	}
	if !ev.Caps.Sandboxed {
		t.Errorf("Caps.Sandboxed = false with marker=1, want true")
	}
}
