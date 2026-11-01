// SPDX-License-Identifier: BUSL-1.1
//
// Copyright (c) 2026 Marmut App

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// claudeArgvTempConfig writes a throwaway observer config.toml (mirrors the
// muse/primeagent full-CLI test pattern) so runClaudeLauncher's config.Load
// never touches the operator's real ~/.observer/config.toml.
func claudeArgvTempConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

// isolateClaudeArgvSettings points CLAUDE_CONFIG_DIR at a fresh empty temp
// dir (reusing the writeClaudeSettingsFixture seam from
// claude_proxy_route_test.go) so resolveClaudeEffectiveRoute never reads the
// operator's real ~/.claude/settings.json — which, on this dev host, bakes in
// an observer proxy route and would otherwise send these hermetic full-CLI
// tests down the persistent-route bypass-settings branch instead of the
// plain direct-exec path the assertions below pin.
func isolateClaudeArgvSettings(t *testing.T) {
	t.Helper()
	writeClaudeSettingsFixture(t, "")
}

// TestClaudeArgvWrapperFlagsConsumedForwardedInOrder pins the DisableFlagParsing
// wiring end to end: wrapper flags (--claude-path, --no-proxy-route) are
// consumed by the shared launcherArgsOrDone split, and an unrecognized flag
// (--model, not one of this launcher's own flags) passes straight through
// together with its value and the trailing positional, in original order.
func TestClaudeArgvWrapperFlagsConsumedForwardedInOrder(t *testing.T) {
	isolateClaudeArgvSettings(t)
	cfgPath := claudeArgvTempConfig(t)
	bin, argsFile := writeRecordingClaudeBin(t)

	cmd := newClaudeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--claude-path", bin,
		"--no-proxy-route",
		"--model", "sonnet",
		"hello",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute: %v (stderr=%q)", err, out.String())
	}

	got := recordedArgv(t, argsFile)
	want := []string{"--model", "sonnet", "hello"}
	if !equalArgs(got, want) {
		t.Fatalf("recorded argv = %v, want %v", got, want)
	}
}

// TestClaudeArgvPositionalFirstAccidentalPassthroughPreserved pins the
// ruling: when the operator's own positional prompt happens to lead, the
// unrecognized flag/value pair that follows it is preserved byte-identically
// in original order — the wrapper never reorders or reinterprets tokens it
// doesn't own.
func TestClaudeArgvPositionalFirstAccidentalPassthroughPreserved(t *testing.T) {
	isolateClaudeArgvSettings(t)
	cfgPath := claudeArgvTempConfig(t)
	bin, argsFile := writeRecordingClaudeBin(t)

	cmd := newClaudeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--claude-path", bin,
		"--no-proxy-route",
		"fix bug",
		"--model", "sonnet",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute: %v (stderr=%q)", err, out.String())
	}

	got := recordedArgv(t, argsFile)
	want := []string{"fix bug", "--model", "sonnet"}
	if !equalArgs(got, want) {
		t.Fatalf("recorded argv = %v, want %v", got, want)
	}
}

// TestClaudeArgvDoubleDashPassthroughPreserved pins "--" end-of-options
// semantics: everything after a bare "--" is unconditional passthrough
// (even tokens that would otherwise look like this launcher's own flags),
// and the "--" token itself is dropped.
func TestClaudeArgvDoubleDashPassthroughPreserved(t *testing.T) {
	isolateClaudeArgvSettings(t)
	cfgPath := claudeArgvTempConfig(t)
	bin, argsFile := writeRecordingClaudeBin(t)

	cmd := newClaudeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--claude-path", bin,
		"--no-proxy-route",
		"--",
		"--model", "sonnet",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute: %v (stderr=%q)", err, out.String())
	}

	got := recordedArgv(t, argsFile)
	want := []string{"--model", "sonnet"}
	if !equalArgs(got, want) {
		t.Fatalf("recorded argv = %v, want %v", got, want)
	}
}

// TestClaudeArgvUnknownFlagNoLongerErrors pins the headline behavior change:
// before DisableFlagParsing, an unrecognized flag like --model tripped
// cobra's own "unknown flag" parse error. It must not anymore — the launcher
// forwards it to claude instead of refusing to launch.
func TestClaudeArgvUnknownFlagNoLongerErrors(t *testing.T) {
	isolateClaudeArgvSettings(t)
	cfgPath := claudeArgvTempConfig(t)
	bin, _ := writeRecordingClaudeBin(t)

	cmd := newClaudeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--claude-path", bin,
		"--no-proxy-route",
		"--model", "sonnet",
	})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("--model must no longer produce an unknown-flag error: %v (stderr=%q)", err, out.String())
	}
	if strings.Contains(strings.ToLower(out.String()), "unknown flag") {
		t.Fatalf("stderr must not mention an unknown-flag error: %q", out.String())
	}
}

// TestClaudeArgvHelpShowsHelpNoExec pins the -h contract under
// DisableFlagParsing: splitLauncherArgs still recognizes this launcher's own
// help flag (reservedLauncherFlags derives it live from cmd.Flags(), which
// includes cobra's InitDefaultHelpFlag), prints help, and returns cleanly
// WITHOUT ever reaching runClaudeLauncher — so the claude binary is never
// resolved or executed. --claude-path points at a path that does not exist
// to prove that: if help handling regressed into an actual exec attempt,
// this test would fail on binary resolution instead of asserting the
// (never-created) argv file is absent.
func TestClaudeArgvHelpShowsHelpNoExec(t *testing.T) {
	dir := t.TempDir()
	neverSpawned := filepath.Join(dir, "stub-never-spawned")

	cmd := newClaudeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--claude-path", neverSpawned, "-h"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("-h must return a nil error, got: %v", err)
	}
	if !strings.Contains(out.String(), "claude") {
		t.Fatalf("help text must mention claude, got: %q", out.String())
	}
	if _, statErr := os.Stat(neverSpawned); statErr == nil {
		t.Fatal("the claude stub path must not have been created/executed")
	}
}
