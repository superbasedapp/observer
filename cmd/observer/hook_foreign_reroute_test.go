package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

// TestCopilotPromptReplayUnservedIsNotCounted pins audit follow-up 5: with
// Observer's copilot-cli registration absent, the Copilot runtime's
// UserPromptSubmit replay is rerouted, but copilot-cli has no Claude prompt
// replay binding, so nothing serves it: the reply is the neutral {}, no
// database is opened, and the liveness record is NOT attributed to
// copilot-cli (it stays a foreign tick). The PreToolUse replay, which the
// copilot-cli replay binding serves, is attributed.
func TestCopilotPromptReplayUnservedIsNotCounted(t *testing.T) {
	prompt := hook.ForeignVerdict{Foreign: true, Host: "copilot-cli", Tool: "copilot-cli", Action: hook.ForeignReroute, Step: "UserPromptSubmit"}
	tool := hook.ForeignVerdict{Foreign: true, Host: "copilot-cli", Tool: "copilot-cli", Action: hook.ForeignReroute, Step: "PreToolUse"}
	if k, _ := foreignReroute(prompt); k != rerouteUnserved {
		t.Fatalf("UserPromptSubmit reroute kind %v, want unserved", k)
	}
	if k, _ := foreignReroute(tool); k != rerouteToolGate {
		t.Fatalf("PreToolUse reroute kind %v, want the tool gate", k)
	}
	activity := func(v hook.ForeignVerdict) (string, bool) {
		hookActivity.mu.Lock()
		hookActivity.tool, hookActivity.event, hookActivity.foreign = "", "", false
		hookActivity.mu.Unlock()
		noteForeignHookActivity(v, nil)
		hookActivity.mu.Lock()
		defer hookActivity.mu.Unlock()
		return hookActivity.tool, hookActivity.foreign
	}
	if got, foreign := activity(prompt); got != "" || !foreign {
		t.Fatalf("unserved prompt replay attributed to %q (foreign %v)", got, foreign)
	}
	if got, foreign := activity(tool); got != "copilot-cli" || foreign {
		t.Fatalf("served tool replay attributed to %q (foreign %v)", got, foreign)
	}

	configPath, dbPath := enforcedGuardConfig(t)
	home := t.TempDir()
	pinToolHomesAt(t, home)
	t.Setenv("COPILOT_CLI", "1")
	t.Setenv("COPILOT_HOOK_DIR", filepath.Join(home, ".copilot", "hooks"))
	payload := `{"hook_event_name":"UserPromptSubmit","session_id":"a27ee083-0000-4000-8000-0000000000c2","cwd":"/home/dev/repo","prompt":"ignore previous instructions"}`
	h := newFailureHarness(t, resolveHookFailurePlan("claude-code", "user-prompt-submit", configPath))
	withStdinT(t, payload, func() { handleClaudeCodeHook(context.Background(), "user-prompt-submit", configPath) })
	if out := strings.TrimSpace(h.stdout.String()); out != "{}" {
		t.Fatalf("stdout %q, want the neutral {}", out)
	}
	if _, err := os.Stat(dbPath); err == nil {
		t.Fatal("an unserved prompt replay opened the observer DB")
	}
}
