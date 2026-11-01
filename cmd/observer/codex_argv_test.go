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

// codexArgvTempConfig writes a throwaway observer config.toml (mirrors the
// muse/primeagent full-CLI test pattern) so runCodexLauncher's config.Load
// never touches the operator's real ~/.observer/config.toml.
func codexArgvTempConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

// isolateCodexArgvHome points CODEX_HOME at a fresh empty temp dir so
// codexConfigsRoutingToProxy / findCodexConfigMisconfigs never read the
// operator's real ~/.codex/config.toml — which, on this dev host, routes via
// `model_provider = "openai-observer"` -> `[model_providers.openai-observer]
// base_url = "http://127.0.0.1:8820/v1"`. Left unisolated, that persistent
// route would (a) be undetectable by --no-proxy-route (codex has no
// CLI-scope override lever, unlike claude's --settings) and (b) FAIL CLOSED
// the launch entirely once decideProxyFallback sees a blocking persistent
// route, breaking every assertion below.
func isolateCodexArgvHome(t *testing.T) {
	t.Helper()
	t.Setenv("CODEX_HOME", t.TempDir())
}

// writeRecordingCodexBin writes a fake `codex` executable that records its
// argv (one token per line) to argsFile and exits 0. Mirrors
// writeRecordingClaudeBin (claude_proxy_route_test.go) for the codex launcher.
func writeRecordingCodexBin(t *testing.T) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "argv.txt")
	bin = filepath.Join(dir, "codex")
	script := "#!/bin/sh\n: > " + stubShPath(argsFile) + "\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> " + stubShPath(argsFile) + "\ndone\nexit 0\n"
	return writeShellStub(t, bin, script), argsFile
}

// codexRecordedArgv reads back the argv writeRecordingCodexBin captured.
// Duplicated (not shared with recordedArgv) only in name — same shape,
// kept local to this file per the task's file-ownership boundary.
func codexRecordedArgv(t *testing.T, argsFile string) []string {
	t.Helper()
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read recorded argv: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

// argvContains reports whether argv has tok as an exact element anywhere.
func argvContains(argv []string, tok string) bool {
	for _, a := range argv {
		if a == tok {
			return true
		}
	}
	return false
}

// argvContainsSubstring reports whether any element of argv contains sub as
// a substring.
func argvContainsSubstring(argv []string, sub string) bool {
	for _, a := range argv {
		if strings.Contains(a, sub) {
			return true
		}
	}
	return false
}

// TestCodexArgvWrapperFlagsConsumedForwardedInOrder pins the
// DisableFlagParsing wiring end to end for the codex launcher: wrapper flags
// (--codex-path, --config, --proxy, --no-app-server-check) are consumed by
// the shared launcherArgsOrDone split and never leak into the child argv,
// while an unrecognized flag (--model, not one of this launcher's own flags)
// and the trailing positional pass straight through in original order. The
// proxy is deliberately unreachable (closedProxyURL) so decideProxyFallback
// neutralizes to a plain pass-through launch (no `-c openai_base_url`
// injection to additionally account for), keeping the assertion focused on
// the argv-splitting contract this task wires.
func TestCodexArgvWrapperFlagsConsumedForwardedInOrder(t *testing.T) {
	isolateCodexArgvHome(t)
	cfgPath := codexArgvTempConfig(t)
	bin, argsFile := writeRecordingCodexBin(t)
	proxyURL := closedProxyURL(t)

	cmd := newCodexCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--codex-path", bin,
		"--proxy", proxyURL,
		"--no-app-server-check",
		"--model", "gpt-5",
		"task",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute: %v (stderr=%q)", err, out.String())
	}

	got := codexRecordedArgv(t, argsFile)
	if !argvHasPair(got, "--model", "gpt-5") {
		t.Fatalf("recorded argv %v missing forwarded --model gpt-5 pair", got)
	}
	if !argvContains(got, "task") {
		t.Fatalf("recorded argv %v missing forwarded positional task", got)
	}
	// Wrapper flags/values must never leak into the child argv.
	for _, wrapperTok := range []string{"--codex-path", bin, "--config", cfgPath, "--proxy", "--no-app-server-check"} {
		if argvContains(got, wrapperTok) {
			t.Errorf("recorded argv %v leaked wrapper token %q", got, wrapperTok)
		}
	}
	// --model must lead task in the recorded argv (order preserved).
	modelIdx, taskIdx := -1, -1
	for i, a := range got {
		if a == "--model" {
			modelIdx = i
		}
		if a == "task" {
			taskIdx = i
		}
	}
	if modelIdx < 0 || taskIdx < 0 || modelIdx > taskIdx {
		t.Fatalf("expected --model before task, got %v", got)
	}
}

// TestCodexArgvNativeShortFlagPassesThroughUntouched pins that a
// codex-native short flag NOT reserved by this launcher (-c, codex's own
// -c key=value config override — the codex launcher itself never registers
// a "-c" shorthand) passes through byte-identically.
func TestCodexArgvNativeShortFlagPassesThroughUntouched(t *testing.T) {
	isolateCodexArgvHome(t)
	cfgPath := codexArgvTempConfig(t)
	bin, argsFile := writeRecordingCodexBin(t)
	proxyURL := closedProxyURL(t)

	cmd := newCodexCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--codex-path", bin,
		"--proxy", proxyURL,
		"--no-app-server-check",
		"-c", "mymodel=x",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute: %v (stderr=%q)", err, out.String())
	}

	got := codexRecordedArgv(t, argsFile)
	want := []string{"-c", "mymodel=x"}
	if !equalArgs(got, want) {
		t.Fatalf("recorded argv = %v, want %v", got, want)
	}
}

// TestCodexArgvUserBaseURLOverrideSkipsWrapperInjection mirrors
// TestPrepareCodexArgs_RespectsUserBaseURLOverride (codex_test.go) but drives
// it through the FULL CLI path: a forwarded `-c openai_base_url=...` must
// cause codexLaunchArgs -> prepareCodexArgs's own `-c openai_base_url`
// injection to be skipped. Requires an actually-reachable proxy
// (reachableProxyURL) so the launch reaches the proxyRouteProceed branch
// that calls prepareCodexArgs at all — an unreachable proxy neutralizes to a
// no-injection pass-through instead, which would pass trivially without
// exercising the "user wins" skip logic this test targets.
func TestCodexArgvUserBaseURLOverrideSkipsWrapperInjection(t *testing.T) {
	isolateCodexArgvHome(t)
	cfgPath := codexArgvTempConfig(t)
	bin, argsFile := writeRecordingCodexBin(t)
	proxyURL := reachableProxyURL(t)

	cmd := newCodexCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--codex-path", bin,
		"--proxy", proxyURL,
		"--no-app-server-check",
		"-c", "openai_base_url=http://mine",
		"task",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute: %v (stderr=%q)", err, out.String())
	}

	got := codexRecordedArgv(t, argsFile)
	if !argvHasPair(got, "-c", "openai_base_url=http://mine") {
		t.Fatalf("recorded argv %v missing forwarded user override pair", got)
	}
	if !argvContains(got, "task") {
		t.Fatalf("recorded argv %v missing forwarded positional task", got)
	}
	// The wrapper's own injection (a -c pair whose value embeds the proxy URL)
	// must be ABSENT — proof prepareCodexArgs took the OverrideAlreadyPresent
	// branch instead of prepending its own override.
	strippedProxyHost := strings.TrimPrefix(strings.TrimPrefix(proxyURL, "http://"), "https://")
	if argvContainsSubstring(got, strippedProxyHost) {
		t.Fatalf("recorded argv %v unexpectedly contains the proxy host %q - wrapper injected despite user override", got, strippedProxyHost)
	}
	// Exactly one "-c" flag: the user's, not a second wrapper-injected one.
	count := 0
	for _, a := range got {
		if a == "-c" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one -c flag (the user's), got %d in %v", count, got)
	}
}
