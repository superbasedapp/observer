package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

// TestEmitManagedSettings_CodexEnforceManagedHooks pins CX-2 end to end:
// --enforce-managed-hooks never ships allow_managed_hooks_only alone. The
// requirements carry Observer's managed [hooks], and the scripts they run
// are written beside them, running the --hook-binary the admin names.
func TestEmitManagedSettings_CodexEnforceManagedHooks(t *testing.T) {
	out := t.TempDir()
	stdout, err := runEmitManagedSettings(t, "--provider", "codex", "--enforce-managed-hooks",
		"--hook-binary", "/opt/observer/bin/observer", "--codex-managed-dir", "/opt/corp/codex-hooks",
		"--out", out)
	if err != nil {
		t.Fatalf("emit: %v\n%s", err, stdout)
	}
	rq, err := os.ReadFile(filepath.Join(out, "requirements.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"\nallow_managed_hooks_only = true\n",
		"\n[hooks]\nmanaged_dir = \"/opt/corp/codex-hooks\"\n",
		"[[hooks.PreToolUse.hooks]]",
		`command = "/opt/corp/codex-hooks/` + hook.CodexManagedHookScriptPOSIX + ` PreToolUse"`,
	} {
		if !strings.Contains(string(rq), want) {
			t.Errorf("requirements.toml missing %q:\n%s", want, rq)
		}
	}
	sh, err := os.ReadFile(filepath.Join(out, hook.CodexManagedHookScriptPOSIX))
	if err != nil {
		t.Fatalf("POSIX script not written: %v", err)
	}
	if !strings.Contains(string(sh), "exec /opt/observer/bin/observer hook codex \"$@\"") {
		t.Errorf("POSIX script does not run --hook-binary:\n%s", sh)
	}
	cmdScript, err := os.ReadFile(filepath.Join(out, hook.CodexManagedHookScriptWindows))
	if err != nil {
		t.Fatalf("Windows script not written: %v", err)
	}
	if !strings.Contains(string(cmdScript), "/opt/observer/bin/observer hook codex %*\r\n") {
		t.Errorf("Windows script does not fall back to --hook-binary:\n%s", cmdScript)
	}
	if !strings.Contains(stdout, "deploy to /opt/corp/codex-hooks/"+hook.CodexManagedHookScriptPOSIX) {
		t.Errorf("output does not name the script deploy path:\n%s", stdout)
	}

	// Without the flag nothing about managed hooks is emitted.
	plain, err := runEmitManagedSettings(t, "--provider", "codex")
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if strings.Contains(plain, "[hooks]") || strings.Contains(plain, hook.CodexManagedHookScriptPOSIX) {
		t.Errorf("managed hooks emitted without --enforce-managed-hooks:\n%s", plain)
	}

	if _, err := runEmitManagedSettings(t, "--provider", "codex", "--enforce-managed-hooks", "--codex-managed-dir", "relative/dir"); err == nil {
		t.Error("a relative managed dir: want an error")
	}
}
