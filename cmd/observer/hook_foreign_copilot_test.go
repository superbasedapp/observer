package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
)

// copilotRegisteredHome pins the tool homes at a temp home and writes
// Observer's copilot-cli hooks file there from another Observer install path.
func copilotRegisteredHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	pinToolHomesAt(t, home)
	if err := os.MkdirAll(filepath.Join(home, ".copilot"), 0o755); err != nil {
		t.Fatal(err)
	}
	reg, err := hook.NewRegistry(hook.Options{BinaryPath: filepath.Join(home, "bin", "observer")})
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("copilot-cli"); res.Error != nil {
		t.Fatalf("register copilot-cli: %v", res.Error)
	}
	return home
}

// TestOwnGateRegisteredProbeRelayAnswersAbsent pins audit follow-up 2: the
// probe reads the home through the hook context, so on the host path it
// sees the registration in the hook process's own home, and on the relay
// path (hookctx.PathDaemon, a sandbox run's channel) it answers "absent"
// even though the daemon host carries Observer's registration: the host's
// Copilot home says nothing about the run's, so the replay is judged.
func TestOwnGateRegisteredProbeRelayAnswersAbsent(t *testing.T) {
	copilotRegisteredHome(t)
	probe := ownGateRegisteredProbe("")

	hookctx.SetProcess(nil)
	t.Cleanup(func() { hookctx.SetProcess(nil) })
	if !probe("copilot-cli", "PreToolUse") {
		t.Fatal("host path: the registration in the hook process's home reads as absent")
	}

	relay := hookctx.Daemon(context.Background(), hookctx.Request{Tool: "claude-code", Event: "pre-tool"},
		hookctx.Channel{RunID: "run-1", Env: map[string]string{"COPILOT_CLI": "1", "COPILOT_HOOK_DIR": "/box/.copilot/hooks", "HOME": os.Getenv("HOME")}},
		hookctx.DaemonProviders{})
	hookctx.SetProcess(relay)
	if probe("copilot-cli", "PreToolUse") {
		t.Fatal("relay path: the daemon host's registration answered for the run")
	}
}

// TestHookProcessHome: the home is the variable os.UserHomeDir reads on
// each OS, taken from the hook context.
func TestHookProcessHome(t *testing.T) {
	hc := hookctx.Daemon(context.Background(), hookctx.Request{}, hookctx.Channel{Env: map[string]string{"HOME": "/h", "USERPROFILE": `C:\Users\u`}}, hookctx.DaemonProviders{})
	if got := hookProcessHome(hc, "linux"); got != "/h" {
		t.Errorf("linux home %q", got)
	}
	if got := hookProcessHome(hc, "windows"); got != `C:\Users\u` {
		t.Errorf("windows home %q", got)
	}
}
