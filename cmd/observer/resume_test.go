package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestClaudeResumeFlagRegisteredWhenGrounded pins that `observer claude`
// registers --resume exactly when claude-code declares a grounded ResumeNative
// contract (capability dispatch, never a tool-name branch).
func TestClaudeResumeFlagRegisteredWhenGrounded(t *testing.T) {
	capab, _ := integration.For("claude-code")
	f := newClaudeCmd().Flags().Lookup("resume")
	if capab.Resume.Kind == integration.ResumeNative {
		if f == nil {
			t.Fatal("claude-code is ResumeNative but --resume flag is not registered")
		}
		if f.DefValue != "" {
			t.Errorf("--resume default: got %q, want empty", f.DefValue)
		}
	} else if f != nil {
		t.Fatal("claude-code is not ResumeNative but --resume flag is registered")
	}
}

// TestCodexResumeFlagRegisteredWhenGrounded is the codex sibling of the above.
func TestCodexResumeFlagRegisteredWhenGrounded(t *testing.T) {
	capab, _ := integration.For("codex")
	f := newCodexCmd().Flags().Lookup("resume")
	if capab.Resume.Kind == integration.ResumeNative {
		if f == nil {
			t.Fatal("codex is ResumeNative but --resume flag is not registered")
		}
		if f.DefValue != "" {
			t.Errorf("--resume default: got %q, want empty", f.DefValue)
		}
	} else if f != nil {
		t.Fatal("codex is not ResumeNative but --resume flag is registered")
	}
}

// TestInjectClaudeResume pins claude's native-resume argv composition: the
// `--resume <id>` pair LEADS the child argv, before any user `--` remainder.
func TestInjectClaudeResume(t *testing.T) {
	cases := []struct {
		name string
		args []string
		id   string
		want []string
	}{
		{"resume alone", nil, "sess-1", []string{"--resume", "sess-1"}},
		{"resume + remainder", []string{"--model", "opus"}, "sess-1", []string{"--resume", "sess-1", "--model", "opus"}},
		{"resume + print flag", []string{"--print", "hi"}, "s2", []string{"--resume", "s2", "--print", "hi"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := injectClaudeResume(tc.args, tc.id)
			if !equalArgs(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestInjectCodexResume pins codex's native-resume argv composition end to end:
// injectCodexResume prepends the `resume <id>` subcommand, and prepareCodexArgs
// then prepends the global `-c openai_base_url` override — the final child argv
// is `codex -c openai_base_url="…/v1" resume <id> [user args]`, with the global
// -c BEFORE the resume subcommand (verified live: codex honors it there).
func TestInjectCodexResume(t *testing.T) {
	cases := []struct {
		name string
		args []string
		id   string
		want []string
	}{
		{"resume alone", nil, "sess-1", []string{"resume", "sess-1"}},
		{"resume + remainder", []string{"--model", "gpt-5"}, "sess-1", []string{"resume", "sess-1", "--model", "gpt-5"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := injectCodexResume(tc.args, tc.id)
			if !equalArgs(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}

	// Full composition through the proxy-override prepend.
	injected := injectCodexResume([]string{"--model", "gpt-5"}, "uuid-9")
	full, info := prepareCodexArgs(injected, "http://127.0.0.1:8820")
	if !info.OverrideInjected {
		t.Fatal("expected the openai_base_url override to be injected")
	}
	want := []string{"-c", `openai_base_url="http://127.0.0.1:8820/v1"`, "resume", "uuid-9", "--model", "gpt-5"}
	if !equalArgs(full, want) {
		t.Fatalf("full codex argv = %v, want %v", full, want)
	}
}

// TestClaudeAttachPassthroughForwardsResume pins that `--resume` (and
// --claude-path) are FORWARDED to the daemon-spawned inner launcher under
// --attach — never rejected (the mortality backstop, design §2.4).
func TestClaudeAttachPassthroughForwardsResume(t *testing.T) {
	got := claudeAttachPassthrough(claudeLauncherOptions{resume: "sess-1", claudePath: "/opt/claude"})
	want := []string{"--claude-path", "/opt/claude", "--resume", "sess-1"}
	if !equalArgs(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// No resume ⇒ no --resume token.
	if got := claudeAttachPassthrough(claudeLauncherOptions{}); len(got) != 0 {
		t.Fatalf("expected empty passthrough, got %v", got)
	}
}

// TestCodexAttachPassthroughForwardsResume is the codex sibling.
func TestCodexAttachPassthroughForwardsResume(t *testing.T) {
	got := codexAttachPassthrough(codexLauncherOptions{resume: "sess-1", codexPath: "/opt/codex", noAppServerCheck: true})
	want := []string{"--codex-path", "/opt/codex", "--no-app-server-check", "--resume", "sess-1"}
	if !equalArgs(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := codexAttachPassthrough(codexLauncherOptions{}); len(got) != 0 {
		t.Fatalf("expected empty passthrough, got %v", got)
	}
}

// TestRejectIncompatibleClaudeResumeFlags pins that --resume rejects each
// member of the handoff-fork family (native resume vs distilled fork are
// opposites) and coexists with everything else.
func TestRejectIncompatibleClaudeResumeFlags(t *testing.T) {
	cases := []struct {
		name    string
		opts    claudeLauncherOptions
		wantErr bool
	}{
		{"resume alone ok", claudeLauncherOptions{resume: "s1"}, false},
		{"resume + tool args ok", claudeLauncherOptions{resume: "s1", claudeArgs: []string{"--model", "x"}}, false},
		{"resume + continue-from rejected", claudeLauncherOptions{resume: "s1", continueFrom: "s0"}, true},
		{"resume + carry rejected", claudeLauncherOptions{resume: "s1", carry: "full"}, true},
		{"resume + from-message rejected", claudeLauncherOptions{resume: "s1", fromMessage: 3}, true},
		{"resume + from-time rejected", claudeLauncherOptions{resume: "s1", fromTime: "2026-01-01T00:00:00Z"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := rejectIncompatibleClaudeResumeFlags(tc.opts)
			if tc.wantErr != (err != nil) {
				t.Fatalf("wantErr=%v, got err=%v", tc.wantErr, err)
			}
		})
	}
}

// TestRejectIncompatibleCodexResumeFlags is the codex sibling.
func TestRejectIncompatibleCodexResumeFlags(t *testing.T) {
	cases := []struct {
		name    string
		opts    codexLauncherOptions
		wantErr bool
	}{
		{"resume alone ok", codexLauncherOptions{resume: "s1"}, false},
		{"resume + tool args ok", codexLauncherOptions{resume: "s1", codexArgs: []string{"--model", "x"}}, false},
		{"resume + continue-from rejected", codexLauncherOptions{resume: "s1", continueFrom: "s0"}, true},
		{"resume + carry rejected", codexLauncherOptions{resume: "s1", carry: "full"}, true},
		{"resume + from-message rejected", codexLauncherOptions{resume: "s1", fromMessage: 3}, true},
		{"resume + from-time rejected", codexLauncherOptions{resume: "s1", fromTime: "2026-01-01T00:00:00Z"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := rejectIncompatibleCodexResumeFlags(tc.opts)
			if tc.wantErr != (err != nil) {
				t.Fatalf("wantErr=%v, got err=%v", tc.wantErr, err)
			}
		})
	}
}

// TestRunClaudeLauncherResumeRejectsContinueFrom drives the launcher to the
// resume/continue-from conflict and asserts it errors BEFORE any exec, with a
// message naming both flags.
func TestRunClaudeLauncherResumeRejectsContinueFrom(t *testing.T) {
	pinToolHomes(t) // the launcher loads <home>/.observer/config.toml (FU-20)
	var stderr bytes.Buffer
	err := runClaudeLauncher(context.Background(), claudeLauncherOptions{
		resume:       "s1",
		continueFrom: "s0",
		stderr:       &stderr,
	})
	if err == nil {
		t.Fatal("expected an error for --resume + --continue-from")
	}
	if !strings.Contains(err.Error(), "continue-from") || !strings.Contains(err.Error(), "resume") {
		t.Errorf("error should name both flags: %v", err)
	}
}

// TestRunCodexLauncherResumeRejectsContinueFrom is the codex sibling.
func TestRunCodexLauncherResumeRejectsContinueFrom(t *testing.T) {
	pinToolHomes(t) // the launcher loads <home>/.observer/config.toml (FU-20)
	var stderr bytes.Buffer
	err := runCodexLauncher(context.Background(), codexLauncherOptions{
		resume:       "s1",
		continueFrom: "s0",
		stderr:       &stderr,
	})
	if err == nil {
		t.Fatal("expected an error for --resume + --continue-from")
	}
	if !strings.Contains(err.Error(), "continue-from") || !strings.Contains(err.Error(), "resume") {
		t.Errorf("error should name both flags: %v", err)
	}
}

// TestResumeCellNativeForGroundedTools pins the `observer adapters` RESUME
// column: the two grounded tools render "native", a launchable-but-not-native
// tool renders "handoff", and a file-lane-only tool renders a dash.
func TestResumeCellNativeForGroundedTools(t *testing.T) {
	for _, tool := range []string{"claude-code", "codex"} {
		capab, _ := integration.For(tool)
		if got := resumeCell(capab); got != "native" {
			t.Errorf("resumeCell(%s) = %q, want \"native\"", tool, got)
		}
	}
	// A launchable tool with no native resume falls back to the handoff fork.
	handoffOnly := integration.Capability{
		Handoff: integration.HandoffCapability{Launch: &integration.LaunchSpec{Subcommand: "gemini"}},
	}
	if got := resumeCell(handoffOnly); got != "handoff" {
		t.Errorf("resumeCell(launchable, non-native) = %q, want \"handoff\"", got)
	}
	// A file-lane-only tool (no launcher) has neither.
	if got := resumeCell(integration.Capability{}); got != "—" {
		t.Errorf("resumeCell(file-only) = %q, want dash", got)
	}
}

func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
