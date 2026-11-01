package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestGooseOnFailureFollowsEnforcement (gfiD, 2026-10-15): Goose fails OPEN
// on a hook failure unless the action says "on_failure":"block". Observer
// writes it only while guard enforcement closes the tool gate, and a change
// of posture rewrites the one entry in place (idempotent either way).
func TestGooseOnFailureFollowsEnforcement(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".agents"), 0o755); err != nil {
		t.Fatal(err)
	}
	hooksPath := filepath.Join(home, ".agents", "plugins", "superbased-observer", "hooks", "hooks.json")
	register := func(enforcing bool) RegistrationResult {
		t.Helper()
		reg, err := NewRegistry(Options{
			BinaryPath: "/opt/observer/bin/observer", HomeDir: home,
			ChecksumsPath:       filepath.Join(home, ".observer", "hook_checksums.json"),
			ToolGateFailsClosed: enforcing,
		})
		if err != nil {
			t.Fatal(err)
		}
		return reg.Register("goose")
	}
	onFailure := func() (any, int) {
		t.Helper()
		raw, err := os.ReadFile(hooksPath)
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			Hooks map[string][]struct {
				Hooks []map[string]any `json:"hooks"`
			} `json:"hooks"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatalf("parse: %v\n%s", err, raw)
		}
		groups := f.Hooks["PreToolUse"]
		if len(groups) != 1 || len(groups[0].Hooks) != 1 {
			t.Fatalf("want exactly one Observer PreToolUse action, got %s", raw)
		}
		return groups[0].Hooks[0]["on_failure"], len(groups)
	}
	for _, step := range []struct {
		name      string
		enforcing bool
		want      any
		wantAdded bool
	}{
		{"observe: host default (fail open)", false, nil, true},
		{"observe again: idempotent", false, nil, false},
		{"enforcement on: block on failure", true, "block", true},
		{"enforcement again: idempotent", true, "block", false},
		{"enforcement off: back to the host default", false, nil, true},
	} {
		res := register(step.enforcing)
		if res.Error != nil {
			t.Fatalf("%s: %v", step.name, res.Error)
		}
		if got := len(res.HooksAdded) > 0; got != step.wantAdded {
			t.Errorf("%s: HooksAdded=%v AlreadySet=%v", step.name, res.HooksAdded, res.AlreadySet)
		}
		if got, _ := onFailure(); got != step.want {
			t.Errorf("%s: on_failure = %v, want %v", step.name, got, step.want)
		}
	}
}
