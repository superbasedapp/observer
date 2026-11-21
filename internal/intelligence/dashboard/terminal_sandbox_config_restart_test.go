package dashboard

import (
	"net/http"
	"path/filepath"
	"testing"
)

// TestTerminalSandboxConfigPutRestartOnlyWhenNeeded (D-R4-1): a save that
// only turns the sandbox on applies on the next launch and answers
// restart_required false; a save that moves the workspaces directory answers
// true and names that key alone.
func TestTerminalSandboxConfigPutRestartOnlyWhenNeeded(t *testing.T) {
	_, h := newManageServer(t)
	code, out := putSandboxConfig(t, h, `{"enabled":true,"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":120}`)
	if code != http.StatusOK {
		t.Fatalf("PUT enable = %d: %v", code, out)
	}
	if out["restart_required"] != false {
		t.Fatalf("enable toggle only: restart_required = %v, want false (keys %v)", out["restart_required"], out["restart_required_keys"])
	}
	dir := filepath.ToSlash(filepath.Join(t.TempDir(), "ws"))
	code, out = putSandboxConfig(t, h, `{"enabled":true,"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":120,"workspaces_dir":"`+dir+`"}`)
	if code != http.StatusOK {
		t.Fatalf("PUT workspaces_dir = %d: %v", code, out)
	}
	if out["restart_required"] != true {
		t.Fatalf("workspaces_dir changed: restart_required = %v, want true", out["restart_required"])
	}
	keys, _ := out["restart_required_keys"].([]any)
	if len(keys) != 1 || keys[0] != "terminal.sandbox.workspaces_dir" {
		t.Fatalf("restart_required_keys = %v, want [terminal.sandbox.workspaces_dir]", out["restart_required_keys"])
	}
}
