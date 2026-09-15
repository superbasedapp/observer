// SPDX-License-Identifier: BUSL-1.1
//
// Copyright (c) 2026 Marmut App

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// reachableProxyURL starts a loopback TCP listener kept open for the test's
// lifetime and returns its http URL, so proxyReachable(url) → true.
func reachableProxyURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return "http://" + ln.Addr().String()
}

// closedProxyURL binds then immediately releases a loopback port, returning an
// http URL that is (almost certainly) unreachable, so proxyReachable(url) → false.
func closedProxyURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return "http://" + addr
}

// writeRecordingClaudeBin writes a fake `claude` executable that records its argv
// (one token per line) to argsFile and exits 0. The exec is unix (the daemon's
// Linux/WSL OS, where the suite runs); the file compiles on every platform.
func writeRecordingClaudeBin(t *testing.T) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "argv.txt")
	bin = filepath.Join(dir, "claude")
	script := "#!/bin/sh\n: > " + argsFile + "\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> " + argsFile + "; done\nexit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake claude bin: %v", err)
	}
	return bin, argsFile
}

// recordedArgv reads back the argv writeRecordingClaudeBin captured.
func recordedArgv(t *testing.T, argsFile string) []string {
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

// argvHasPair reports whether argv contains flag immediately followed by value.
func argvHasPair(argv []string, flag, value string) bool {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) && argv[i+1] == value {
			return true
		}
	}
	return false
}

// writeClaudeSettingsFixture writes a settings.json into a fresh temp
// CLAUDE_CONFIG_DIR and points the env override at it, so claudeSettingsPath /
// claudeConfigRoutesToProxy resolve the fixture exactly as the real launcher
// would resolve the operator's ~/.claude/settings.json.
func writeClaudeSettingsFixture(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if body != "" {
		if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(body), 0o600); err != nil {
			t.Fatalf("write settings.json: %v", err)
		}
	}
	t.Setenv("CLAUDE_CONFIG_DIR", dir)
	t.Setenv("ANTHROPIC_CONFIG_DIR", "")
	return dir
}

const claudeTestProxyURL = "http://127.0.0.1:8820"

// TestClaudeConfigRoutesToProxy_Detects pins the persistent-route detector
// against every shape that decides fail-closed vs neutralize: an observer
// loopback route (all the equivalent spellings), a third-party gateway (NOT an
// observer route — must be honored, not clobbered), a different port, a missing
// key, a missing file, and malformed JSON (best-effort → false).
func TestClaudeConfigRoutesToProxy_Detects(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"observer 127.0.0.1 v1", `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820/v1"}}`, true},
		{"observer 127.0.0.1 no suffix", `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`, true},
		{"observer localhost", `{"env":{"ANTHROPIC_BASE_URL":"http://localhost:8820"}}`, true},
		{"observer ipv6 loopback", `{"env":{"ANTHROPIC_BASE_URL":"http://[::1]:8820"}}`, true},
		{"third-party gateway", `{"env":{"ANTHROPIC_BASE_URL":"https://gw.example.com"}}`, false},
		{"different port", `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:9999"}}`, false},
		{"no base url key", `{"env":{"OTHER":"x"}}`, false},
		{"no env block", `{"model":"opus"}`, false},
		{"malformed json", `{not json`, false},
		{"empty file", ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeClaudeSettingsFixture(t, tc.body)
			routed, path := claudeConfigRoutesToProxy(claudeTestProxyURL)
			if routed != tc.want {
				t.Fatalf("claudeConfigRoutesToProxy routed=%v, want %v (body=%s)", routed, tc.want, tc.body)
			}
			if !strings.HasSuffix(filepath.ToSlash(path), "settings.json") {
				t.Errorf("settings path should end in settings.json, got %q", path)
			}
		})
	}
}

// TestClaudeConfigRoutesToProxy_MissingFile: a CLAUDE_CONFIG_DIR with no
// settings.json is a clean, non-routed host (fresh install) — never fail-closed.
func TestClaudeConfigRoutesToProxy_MissingFile(t *testing.T) {
	writeClaudeSettingsFixture(t, "") // dir exists, no settings.json written
	if routed, _ := claudeConfigRoutesToProxy(claudeTestProxyURL); routed {
		t.Fatal("a missing settings.json must not be treated as a proxy route")
	}
}

// TestClaudeArgsHaveSettings pins the operator-own---settings detector (which
// gates canNeutralizePersistent): both `--settings X` and `--settings=X` forms
// count; a `--settings` AFTER a bare `--` is positional prompt text, not the
// flag; absence returns false.
func TestClaudeArgsHaveSettings(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"space form", []string{"--settings", "my.json"}, true},
		{"equals form", []string{"--settings=my.json"}, true},
		{"amid other flags", []string{"--model", "opus", "--settings", "x"}, true},
		{"none", []string{"--model", "opus"}, false},
		{"empty", nil, false},
		{"after bare -- is positional", []string{"--", "--settings", "hi"}, false},
		{"real flag before bare --", []string{"--settings", "x", "--", "prompt"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := claudeArgsHaveSettings(tc.args); got != tc.want {
				t.Fatalf("claudeArgsHaveSettings(%v)=%v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

// TestWriteClaudeBypassSettings pins the one-shot override file: valid JSON, the
// provider default pinned as env.ANTHROPIC_BASE_URL, and a real removable path.
func TestWriteClaudeBypassSettings(t *testing.T) {
	// Finding 6: keep the minted file INSIDE the test's temp dir so the test
	// never strands an observer-claude-bypass-*.json in the real TMPDIR.
	// os.CreateTemp("") honors $TMPDIR on this platform.
	t.Setenv("TMPDIR", t.TempDir())
	path, err := writeClaudeBypassSettings()
	if err != nil {
		t.Fatalf("writeClaudeBypassSettings: %v", err)
	}
	defer os.Remove(path)
	if filepath.Dir(path) != filepath.Clean(os.Getenv("TMPDIR")) {
		t.Errorf("bypass file %q not under the test TMPDIR %q", path, os.Getenv("TMPDIR"))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read override: %v", err)
	}
	var doc struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("override is not valid JSON: %v\n%s", err, raw)
	}
	if doc.Env["ANTHROPIC_BASE_URL"] != anthropicDefaultBaseURL {
		t.Errorf("override ANTHROPIC_BASE_URL=%q, want %q", doc.Env["ANTHROPIC_BASE_URL"], anthropicDefaultBaseURL)
	}
	if !strings.HasSuffix(path, ".json") {
		t.Errorf("override path should end in .json, got %q", path)
	}
}

// TestSweepStaleBypassFiles pins the finding-6 reaper: only bypassFilePrefix
// *.json files OLDER than maxAge are removed; recent bypass files, non-matching
// names, and non-json files are all left untouched, and an unreadable dir is a
// silent no-op.
func TestSweepStaleBypassFiles(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, ageHours int) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		mt := time.Now().Add(-time.Duration(ageHours) * time.Hour)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stale := mk(bypassFilePrefix+"old.json", 48)
	fresh := mk(bypassFilePrefix+"new.json", 1)
	otherPrefix := mk("something-else-old.json", 48)
	notJSON := mk(bypassFilePrefix+"old.txt", 48)

	sweepStaleBypassFiles(dir, 24*time.Hour)

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale bypass file should be removed, stat err=%v", err)
	}
	for _, keep := range []string{fresh, otherPrefix, notJSON} {
		if _, err := os.Stat(keep); err != nil {
			t.Errorf("file %q should be kept, got stat err=%v", keep, err)
		}
	}
	// Unreadable/missing dir is a silent no-op (must not panic).
	sweepStaleBypassFiles(filepath.Join(dir, "does-not-exist"), 24*time.Hour)
}

// TestNeutralizeBypassEnv pins finding 2: on a non-persistent-route bypass, an
// observer-proxy process-env value is stripped+pinned to the provider default;
// a third-party gateway is preserved verbatim; and an absent value is pinned.
func TestNeutralizeBypassEnv(t *testing.T) {
	baseURLOf := func(env []string) (string, bool) { return lookupEnvValue(env, "ANTHROPIC_BASE_URL") }

	t.Run("observer-proxy env → strip + pin default", func(t *testing.T) {
		in := []string{"PATH=/bin", "ANTHROPIC_BASE_URL=" + claudeTestProxyURL + "/v1"}
		out := neutralizeBypassEnv(in, claudeTestProxyURL)
		v, ok := baseURLOf(out)
		if !ok || v != anthropicDefaultBaseURL {
			t.Fatalf("observer-proxy env: base=%q ok=%v, want %q", v, ok, anthropicDefaultBaseURL)
		}
		// Exactly one ANTHROPIC_BASE_URL entry (stripped, then re-appended).
		count := 0
		for _, kv := range out {
			if strings.HasPrefix(kv, "ANTHROPIC_BASE_URL=") {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("want exactly 1 ANTHROPIC_BASE_URL entry, got %d", count)
		}
	})

	t.Run("third-party gateway env → preserved verbatim", func(t *testing.T) {
		in := []string{"PATH=/bin", "ANTHROPIC_BASE_URL=https://gw.example.com"}
		out := neutralizeBypassEnv(in, claudeTestProxyURL)
		v, ok := baseURLOf(out)
		if !ok || v != "https://gw.example.com" {
			t.Fatalf("gateway env must be untouched, got base=%q ok=%v", v, ok)
		}
	})

	t.Run("no env value → pin default", func(t *testing.T) {
		in := []string{"PATH=/bin"}
		out := neutralizeBypassEnv(in, claudeTestProxyURL)
		v, ok := baseURLOf(out)
		if !ok || v != anthropicDefaultBaseURL {
			t.Fatalf("absent env: base=%q ok=%v, want %q", v, ok, anthropicDefaultBaseURL)
		}
	})
}

// TestClaudeNeutralizeNotice pins the honest bypass copy: the overriding-a-route
// variant names the --settings override + the settings file; the clean variant
// does not; both always say "NOT captured" and the proxy-down variant names
// `observer start`.
func TestClaudeNeutralizeNotice(t *testing.T) {
	sp := "/home/u/.claude/settings.json"
	// Overriding a baked-in route.
	over := claudeNeutralizeNotice(reasonProxyDownClean, claudeTestProxyURL, sp, true, false)
	for _, want := range []string{"--settings override", sp, "NOT captured", "observer start", "unreachable"} {
		if !strings.Contains(over, want) {
			t.Errorf("overriding proxy-down notice missing %q:\n%s", want, over)
		}
	}
	overNPR := claudeNeutralizeNotice(reasonNoProxyRouteClean, claudeTestProxyURL, sp, true, false)
	for _, want := range []string{"--settings override", sp, "--no-proxy-route", "NOT captured"} {
		if !strings.Contains(overNPR, want) {
			t.Errorf("overriding no-proxy-route notice missing %q:\n%s", want, overNPR)
		}
	}
	// Clean bypass (no route being overridden) must NOT mention the override file.
	clean := claudeNeutralizeNotice(reasonProxyDownClean, claudeTestProxyURL, sp, false, false)
	if strings.Contains(clean, "--settings") || strings.Contains(clean, sp) {
		t.Errorf("clean notice should not mention --settings/override file:\n%s", clean)
	}
	if !strings.Contains(clean, "NOT captured") || !strings.Contains(clean, "observer start") {
		t.Errorf("clean proxy-down notice missing NOT-captured / observer start:\n%s", clean)
	}
	// Condensed proxy-down variants (attach layer already said "unreachable"):
	// the redundant unreachable-prefix is dropped, the capture-loss half survives.
	for _, tc := range []struct {
		name       string
		overriding bool
	}{
		{"condensed-overriding", true},
		{"condensed-clean", false},
	} {
		got := claudeNeutralizeNotice(reasonProxyDownClean, claudeTestProxyURL, sp, tc.overriding, true)
		if strings.Contains(got, "unreachable") || strings.Contains(got, claudeTestProxyURL) {
			t.Errorf("%s: condensed notice restates unreachability:\n%s", tc.name, got)
		}
		if !strings.Contains(got, "NOT captured") || !strings.Contains(got, "observer start") {
			t.Errorf("%s: condensed notice lost the capture-loss half or the `observer start` remedy:\n%s", tc.name, got)
		}
		if tc.overriding != strings.Contains(got, "--settings override") {
			t.Errorf("%s: override-file mention wrong (want %v):\n%s", tc.name, tc.overriding, got)
		}
	}
	// attachNoticed must not alter the --no-proxy-route variants (no redundancy
	// there — that notice never mentions reachability).
	if a, b := claudeNeutralizeNotice(reasonNoProxyRouteClean, claudeTestProxyURL, sp, true, true),
		claudeNeutralizeNotice(reasonNoProxyRouteClean, claudeTestProxyURL, sp, true, false); a != b {
		t.Errorf("no-proxy-route notice must ignore attachNoticed:\n%s\nvs\n%s", a, b)
	}
}

// TestClaudeProxyFailClosedMsg_NoProxyRouteConflict: the residual --no-proxy-route
// fail-closed (operator passed their own --settings) names the settings.json
// file, the settings-wins reason, the --settings block, and the fixes.
func TestClaudeProxyFailClosedMsg_NoProxyRouteConflict(t *testing.T) {
	msg := claudeProxyFailClosedMsg(reasonNoProxyRouteConflict, claudeTestProxyURL, "/home/u/.claude/settings.json", blockOwnSettings, false)
	for _, want := range []string{
		"/home/u/.claude/settings.json",
		"--no-proxy-route",
		"observer init --claude-code --skip-proxy-route",
		"settings.json env WINS",
		"--settings",
		"refusing to launch",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("no-proxy-route conflict msg missing %q:\n%s", want, msg)
		}
	}
}

// TestClaudeProxyFailClosedMsg_ProxyDownConflict: the residual daemon-down
// fail-closed (operator passed their own --settings) offers all three fixes —
// start the daemon, drop --settings, or strip the baked-in route — and names the
// dead proxy + the settings file.
func TestClaudeProxyFailClosedMsg_ProxyDownConflict(t *testing.T) {
	msg := claudeProxyFailClosedMsg(reasonProxyDownConflict, claudeTestProxyURL, "/home/u/.claude/settings.json", blockOwnSettings, false)
	for _, want := range []string{
		claudeTestProxyURL,
		"/home/u/.claude/settings.json",
		"observer start",
		"observer init --claude-code --skip-proxy-route",
		"--settings",
		"unreachable",
		"refusing to launch",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("proxy-down conflict msg missing %q:\n%s", want, msg)
		}
	}
}

// TestClaudeProxyFailClosedMsg_Managed pins the finding-1 managed-scope copy:
// both reasons name the managed file, say managed settings outrank other scopes,
// and do NOT advise a --settings override (which cannot defeat managed) — the
// proxy-down variant still offers `observer start`.
func TestClaudeProxyFailClosedMsg_Managed(t *testing.T) {
	const managed = "/etc/claude-code/managed-settings.json"
	npr := claudeProxyFailClosedMsg(reasonNoProxyRouteConflict, claudeTestProxyURL, managed, blockManaged, false)
	for _, want := range []string{managed, "--no-proxy-route", "managed", "OUTRANK", "refusing to launch"} {
		if !strings.Contains(npr, want) {
			t.Errorf("managed no-proxy-route msg missing %q:\n%s", want, npr)
		}
	}
	if strings.Contains(npr, "--settings override") {
		t.Errorf("managed copy must NOT suggest a --settings override (managed beats CLI):\n%s", npr)
	}
	down := claudeProxyFailClosedMsg(reasonProxyDownConflict, claudeTestProxyURL, managed, blockManaged, false)
	for _, want := range []string{managed, "observer start", "managed", "unreachable", "refusing to launch"} {
		if !strings.Contains(down, want) {
			t.Errorf("managed proxy-down msg missing %q:\n%s", want, down)
		}
	}
	// Condensed proxy-down refusals (attach layer already said "unreachable"):
	// no restated unreachability, remedies survive, no-proxy-route variants
	// unaffected by the flag (they never mention reachability).
	for _, tc := range []struct {
		name  string
		cause claudeBlockCause
	}{
		{"own-settings", blockOwnSettings},
		{"managed", blockManaged},
	} {
		got := claudeProxyFailClosedMsg(reasonProxyDownConflict, claudeTestProxyURL, managed, tc.cause, true)
		if strings.Contains(got, "unreachable") || strings.Contains(got, claudeTestProxyURL) {
			t.Errorf("condensed %s refusal restates unreachability:\n%s", tc.name, got)
		}
		for _, want := range []string{managed, "observer start", "refusing to launch", "dead proxy"} {
			if !strings.Contains(got, want) {
				t.Errorf("condensed %s refusal missing %q:\n%s", tc.name, want, got)
			}
		}
	}
	if a, b := claudeProxyFailClosedMsg(reasonNoProxyRouteConflict, claudeTestProxyURL, managed, blockManaged, true),
		claudeProxyFailClosedMsg(reasonNoProxyRouteConflict, claudeTestProxyURL, managed, blockManaged, false); a != b {
		t.Errorf("no-proxy-route refusal must ignore attachNoticed:\n%s\nvs\n%s", a, b)
	}
}

// TestResolveClaudeEffectiveRoute_ScopePrecedence pins finding 1's scope × route-
// owner matrix: which scope wins, and how each effective value classifies
// (observer / third-party / none). It writes real settings files into a temp
// CLAUDE_CONFIG_DIR (user scope) and a temp cwd (.claude project/local), and
// passes a --settings arg for CLI scope. Managed scope is not writable in a unit
// test (absolute OS path), so it is exercised only by absence here.
func TestResolveClaudeEffectiveRoute_ScopePrecedence(t *testing.T) {
	writeJSON := func(t *testing.T, path, baseURL string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		body := `{"env":{"ANTHROPIC_BASE_URL":"` + baseURL + `"}}`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const observerURL = "http://127.0.0.1:8820"
	const gatewayURL = "https://gw.example.com"

	t.Run("user scope only → observer, neutralizable", func(t *testing.T) {
		cfgDir := t.TempDir()
		t.Setenv("CLAUDE_CONFIG_DIR", cfgDir)
		t.Setenv("ANTHROPIC_CONFIG_DIR", "")
		writeJSON(t, filepath.Join(cfgDir, "settings.json"), observerURL)
		cwd := t.TempDir()
		r := resolveClaudeEffectiveRoute(claudeTestProxyURL, cwd, nil)
		if r.class != claudeRouteObserver || r.scope != claudeScopeUser {
			t.Fatalf("got class=%d scope=%d, want observer/user", r.class, r.scope)
		}
	})

	t.Run("project scope wins over user (higher precedence)", func(t *testing.T) {
		cfgDir := t.TempDir()
		t.Setenv("CLAUDE_CONFIG_DIR", cfgDir)
		t.Setenv("ANTHROPIC_CONFIG_DIR", "")
		writeJSON(t, filepath.Join(cfgDir, "settings.json"), gatewayURL) // user=gateway
		cwd := t.TempDir()
		writeJSON(t, filepath.Join(cwd, ".claude", "settings.json"), observerURL) // project=observer
		r := resolveClaudeEffectiveRoute(claudeTestProxyURL, cwd, nil)
		if r.class != claudeRouteObserver || r.scope != claudeScopeProject {
			t.Fatalf("got class=%d scope=%d, want observer/project", r.class, r.scope)
		}
	})

	t.Run("local scope wins over project", func(t *testing.T) {
		cfgDir := t.TempDir()
		t.Setenv("CLAUDE_CONFIG_DIR", cfgDir)
		t.Setenv("ANTHROPIC_CONFIG_DIR", "")
		cwd := t.TempDir()
		writeJSON(t, filepath.Join(cwd, ".claude", "settings.json"), observerURL)      // project
		writeJSON(t, filepath.Join(cwd, ".claude", "settings.local.json"), gatewayURL) // local=gateway
		r := resolveClaudeEffectiveRoute(claudeTestProxyURL, cwd, nil)
		if r.class != claudeRouteThirdParty || r.scope != claudeScopeLocal {
			t.Fatalf("got class=%d scope=%d, want thirdParty/local", r.class, r.scope)
		}
	})

	t.Run("CLI --settings wins over local/project/user", func(t *testing.T) {
		cfgDir := t.TempDir()
		t.Setenv("CLAUDE_CONFIG_DIR", cfgDir)
		t.Setenv("ANTHROPIC_CONFIG_DIR", "")
		writeJSON(t, filepath.Join(cfgDir, "settings.json"), gatewayURL)
		cwd := t.TempDir()
		cliFile := filepath.Join(t.TempDir(), "cli.json")
		writeJSON(t, cliFile, observerURL)
		r := resolveClaudeEffectiveRoute(claudeTestProxyURL, cwd, []string{"--settings", cliFile})
		if r.class != claudeRouteObserver || r.scope != claudeScopeCLI {
			t.Fatalf("got class=%d scope=%d, want observer/CLI", r.class, r.scope)
		}
	})

	t.Run("empty value at winning scope → empty-unset (acts as unset, distinct from none)", func(t *testing.T) {
		cfgDir := t.TempDir()
		t.Setenv("CLAUDE_CONFIG_DIR", cfgDir)
		t.Setenv("ANTHROPIC_CONFIG_DIR", "")
		writeJSON(t, filepath.Join(cfgDir, "settings.json"), observerURL) // user=observer
		cwd := t.TempDir()
		writeJSON(t, filepath.Join(cwd, ".claude", "settings.json"), "") // project="" (unset, wins)
		r := resolveClaudeEffectiveRoute(claudeTestProxyURL, cwd, nil)
		// Finding N3: a winning empty value is a DISTINCT outcome (not none) so the
		// routed path knows the process-env injection would be defeated.
		if r.class != claudeRouteEmptyUnset || r.scope != claudeScopeProject {
			t.Fatalf("got class=%d scope=%d, want empty-unset/project", r.class, r.scope)
		}
	})

	t.Run("no scope sets the key → none", func(t *testing.T) {
		cfgDir := t.TempDir()
		t.Setenv("CLAUDE_CONFIG_DIR", cfgDir)
		t.Setenv("ANTHROPIC_CONFIG_DIR", "")
		cwd := t.TempDir()
		r := resolveClaudeEffectiveRoute(claudeTestProxyURL, cwd, nil)
		if r.class != claudeRouteNone {
			t.Fatalf("got class=%d, want none", r.class)
		}
	})
}

// TestClaudeArgsSettingsFile pins the CLI --settings value extractor used for the
// CLI scope: both forms, stop at bare --, absent → "".
func TestClaudeArgsSettingsFile(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--settings", "x.json"}, "x.json"},
		{[]string{"--settings=y.json"}, "y.json"},
		{[]string{"--model", "opus", "--settings", "z.json"}, "z.json"},
		{[]string{"--", "--settings", "hi"}, ""},
		{[]string{"--model", "opus"}, ""},
		{nil, ""},
	}
	for _, tc := range cases {
		if got := claudeArgsSettingsFile(tc.args); got != tc.want {
			t.Errorf("claudeArgsSettingsFile(%v)=%q, want %q", tc.args, got, tc.want)
		}
	}
}

// TestReadClaudeSettingsBaseURL_BestEffort pins the direct reader's best-effort
// contract: present key returned verbatim; missing file / bad JSON / absent key
// all yield "" with no panic.
func TestReadClaudeSettingsBaseURL_BestEffort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if got := readClaudeSettingsBaseURL(path); got != "" {
		t.Errorf("missing file should yield empty, got %q", got)
	}
	if got := readClaudeSettingsBaseURL(""); got != "" {
		t.Errorf("empty path should yield empty, got %q", got)
	}
	if err := os.WriteFile(path, []byte(`{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readClaudeSettingsBaseURL(path); got != "http://127.0.0.1:8820" {
		t.Errorf("present key mis-read: %q", got)
	}
	if err := os.WriteFile(path, []byte(`{broken`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readClaudeSettingsBaseURL(path); got != "" {
		t.Errorf("malformed json should yield empty, got %q", got)
	}
}

// TestClaudeProxyBackendProven pins the budget-admission guard around Claude
// Code's native cloud providers. ANTHROPIC_BASE_URL can remain present while
// Bedrock, Vertex, or Foundry is selected through process env or settings, so
// those launches must not receive positive proxy evidence.
func TestClaudeProxyBackendProven(t *testing.T) {
	proxyEnv := func() []string { return []string{"HOME=" + t.TempDir()} }
	cases := []struct {
		name       string
		env        func() []string
		settings   string
		cliSetting string
		want       bool
	}{
		{name: "no native backend selector", env: proxyEnv, want: true},
		{name: "bedrock process selector", env: func() []string { return []string{"HOME=" + t.TempDir(), "CLAUDE_CODE_USE_BEDROCK=1"} }, want: false},
		{name: "vertex process selector", env: func() []string { return []string{"HOME=" + t.TempDir(), "CLAUDE_CODE_USE_VERTEX=true"} }, want: false},
		{name: "foundry process selector", env: func() []string { return []string{"HOME=" + t.TempDir(), "CLAUDE_CODE_USE_FOUNDRY=1"} }, want: false},
		{name: "explicit false process selector", env: func() []string { return []string{"HOME=" + t.TempDir(), "CLAUDE_CODE_USE_VERTEX=false"} }, want: true},
		{name: "bedrock user setting", env: proxyEnv, settings: `{"env":{"CLAUDE_CODE_USE_BEDROCK":"true"}}`, want: false},
		{name: "disabled vertex user setting", env: proxyEnv, settings: `{"env":{"CLAUDE_CODE_USE_VERTEX":"0"}}`, want: true},
		{name: "bedrock inline cli setting", env: proxyEnv, cliSetting: `{"env":{"CLAUDE_CODE_USE_BEDROCK":"on"}}`, want: false},
		{name: "malformed user settings", env: proxyEnv, settings: `{not-json`, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgDir := t.TempDir()
			t.Setenv("CLAUDE_CONFIG_DIR", cfgDir)
			t.Setenv("ANTHROPIC_CONFIG_DIR", "")
			if tc.settings != "" {
				if err := os.WriteFile(filepath.Join(cfgDir, "settings.json"), []byte(tc.settings), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			args := []string(nil)
			if tc.cliSetting != "" {
				args = []string{"--settings", tc.cliSetting}
			}
			got := claudeProxyBackendProven(tc.env(), t.TempDir(), args)
			if got != tc.want {
				t.Fatalf("claudeProxyBackendProven()=%v, want %v", got, tc.want)
			}
		})
	}
}

// TestReadClaudeCLISettingsBaseURL pins finding N1: claude's `--settings` accepts
// EITHER a file path OR an inline JSON literal, and an unreadable/unparseable
// value must be flagged (never silently absent).
func TestReadClaudeCLISettingsBaseURL(t *testing.T) {
	dir := t.TempDir()
	fileWith := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	filePath := fileWith("present.json", `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`)
	fileNoKey := fileWith("nokey.json", `{"env":{"OTHER":"x"}}`)

	cases := []struct {
		name     string
		val      string
		wantVal  string
		wantPres bool
		wantUnrd bool
	}{
		{"inline json observer route", `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`, "http://127.0.0.1:8820", true, false},
		{"inline json empty value", `{"env":{"ANTHROPIC_BASE_URL":""}}`, "", true, false},
		{"inline json no key", `{"env":{"OTHER":"x"}}`, "", false, false},
		{"inline json unparseable", `{not json`, "", false, true},
		{"path form present", filePath, "http://127.0.0.1:8820", true, false},
		{"path form no key", fileNoKey, "", false, false},
		{"path form unreadable", filepath.Join(dir, "does-not-exist.json"), "", false, true},
		{"empty value (no --settings)", "", "", false, false},
		{"whitespace with leading brace still inline", ` {"env":{"ANTHROPIC_BASE_URL":"x"}}`, "x", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, pres, unrd := readClaudeCLISettingsBaseURL(tc.val, "")
			if v != tc.wantVal || pres != tc.wantPres || unrd != tc.wantUnrd {
				t.Fatalf("got (%q,%v,%v), want (%q,%v,%v)", v, pres, unrd, tc.wantVal, tc.wantPres, tc.wantUnrd)
			}
		})
	}
}

// TestResolveClaudeEffectiveRoute_CLIInlineJSON pins finding N1's attack scenario:
// an inline-JSON `--settings` routing to the observer proxy MUST classify as an
// observer route at CLI scope (NOT silently missed as no-route). Also pins the
// third-party and empty-unset inline shapes, and the unreadable classification.
func TestResolveClaudeEffectiveRoute_CLIInlineJSON(t *testing.T) {
	// Isolate: no managed/user/project/local route interferes.
	cfgDir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", cfgDir)
	t.Setenv("ANTHROPIC_CONFIG_DIR", "")
	cwd := t.TempDir()

	t.Run("inline JSON routing to proxy → observer/CLI (the attack)", func(t *testing.T) {
		args := []string{"--no-proxy-route-noise", "--settings", `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`}
		r := resolveClaudeEffectiveRoute(claudeTestProxyURL, cwd, args)
		if r.class != claudeRouteObserver || r.scope != claudeScopeCLI {
			t.Fatalf("got class=%d scope=%d, want observer/CLI (inline JSON must not be missed)", r.class, r.scope)
		}
	})
	t.Run("inline JSON third-party → thirdParty/CLI", func(t *testing.T) {
		args := []string{"--settings=" + `{"env":{"ANTHROPIC_BASE_URL":"https://gw.example.com"}}`}
		r := resolveClaudeEffectiveRoute(claudeTestProxyURL, cwd, args)
		if r.class != claudeRouteThirdParty || r.scope != claudeScopeCLI {
			t.Fatalf("got class=%d scope=%d, want thirdParty/CLI", r.class, r.scope)
		}
	})
	t.Run("inline JSON empty value → empty-unset/CLI", func(t *testing.T) {
		args := []string{"--settings", `{"env":{"ANTHROPIC_BASE_URL":""}}`}
		r := resolveClaudeEffectiveRoute(claudeTestProxyURL, cwd, args)
		if r.class != claudeRouteEmptyUnset || r.scope != claudeScopeCLI {
			t.Fatalf("got class=%d scope=%d, want empty-unset/CLI", r.class, r.scope)
		}
	})
	t.Run("unreadable path → cliUnreadable flag set", func(t *testing.T) {
		args := []string{"--settings", filepath.Join(cwd, "no-such-file.json")}
		r := resolveClaudeEffectiveRoute(claudeTestProxyURL, cwd, args)
		if !r.cliUnreadable {
			t.Fatalf("unreadable --settings must set cliUnreadable, got %+v", r)
		}
	})
	t.Run("inline JSON with no base-url key → falls through to none", func(t *testing.T) {
		args := []string{"--settings", `{"env":{"OTHER":"x"}}`}
		r := resolveClaudeEffectiveRoute(claudeTestProxyURL, cwd, args)
		if r.class != claudeRouteNone {
			t.Fatalf("got class=%d, want none (CLI key absent falls through, clean host)", r.class)
		}
	})
}

// TestClaudeRouteCwd_ContinueFrom pins finding N2: the route is resolved against
// the directory the child ACTUALLY runs in — the --continue-from source project
// root when set — so a source-project .claude/settings.json observer route is
// DETECTED, not missed. It exercises the exact seam (claudeRouteCwd feeding
// resolveClaudeEffectiveRoute) the launcher uses.
func TestClaudeRouteCwd_ContinueFrom(t *testing.T) {
	// A clean launcher cwd with NO route (user scope empty too).
	cfgDir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", cfgDir)
	t.Setenv("ANTHROPIC_CONFIG_DIR", "")
	launchCwd := t.TempDir()

	// A DIFFERENT source project (the --continue-from destination) that DOES bake
	// an observer route into its project settings.
	sourceDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sourceDir, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, ".claude", "settings.json"),
		[]byte(`{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Resolving against the LAUNCH cwd misses it (the pre-fix bug).
	missed := resolveClaudeEffectiveRoute(claudeTestProxyURL, claudeRouteCwd(launchCwd, ""), nil)
	if missed.class != claudeRouteNone {
		t.Fatalf("clean launch cwd should see no route, got class=%d", missed.class)
	}
	// Resolving against the CONTINUE-FROM dir DETECTS it (the fix).
	seen := resolveClaudeEffectiveRoute(claudeTestProxyURL, claudeRouteCwd(launchCwd, sourceDir), nil)
	if seen.class != claudeRouteObserver || seen.scope != claudeScopeProject {
		t.Fatalf("continue-from dir route must be detected, got class=%d scope=%d", seen.class, seen.scope)
	}
}

// TestResolveClaudeEffectiveRoute_RelativeCLISettingsMirrorsChildDir pins F1: a
// RELATIVE operator `--settings` PATH is resolved against the dir the claude
// child will ACTUALLY run in (claudeRouteCwd's continue-from dir), NOT the
// wrapper's own cwd. Both dirs hold a differently-routed settings file at the
// same relative name; the classification must match the CHILD-dir file. Without
// the fix the wrapper-cwd file would be read, inverting the verdict.
func TestResolveClaudeEffectiveRoute_RelativeCLISettingsMirrorsChildDir(t *testing.T) {
	// Isolate every other scope (no managed/user/project/local interference).
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	t.Setenv("ANTHROPIC_CONFIG_DIR", "")

	const observerURL = "http://127.0.0.1:8820"
	const gatewayURL = "https://gw.example.com"
	const rel = "route.json"

	// The wrapper's own cwd carries a THIRD-PARTY route at rel.
	wrapperCwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(wrapperCwd, rel),
		[]byte(`{"env":{"ANTHROPIC_BASE_URL":"`+gatewayURL+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// The child's run dir (the --continue-from source root) carries an OBSERVER
	// route at the SAME relative name.
	childDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(childDir, rel),
		[]byte(`{"env":{"ANTHROPIC_BASE_URL":"`+observerURL+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Put the process cwd at the wrapper dir so a wrapper-cwd read (the pre-fix
	// bug) would resolve rel to the third-party file.
	t.Chdir(wrapperCwd)

	// Resolve against the CHILD dir (what claudeRouteCwd(launchCwd, continueDir)
	// yields when --continue-from is set) with the relative --settings arg.
	r := resolveClaudeEffectiveRoute(claudeTestProxyURL, childDir, []string{"--settings", rel})
	if r.class != claudeRouteObserver || r.scope != claudeScopeCLI {
		t.Fatalf("relative --settings must classify against the child-dir file (observer/CLI), got class=%d scope=%d value=%q", r.class, r.scope, r.value)
	}

	// Sanity: resolving against the WRAPPER dir would (correctly) see third-party
	// — proves the two files really differ and the child-dir choice is load-bearing.
	rw := resolveClaudeEffectiveRoute(claudeTestProxyURL, wrapperCwd, []string{"--settings", rel})
	if rw.class != claudeRouteThirdParty {
		t.Fatalf("wrapper-dir file should be the third-party route, got class=%d", rw.class)
	}
}

// TestDecideClaudeEmptyUnset pins finding N3's action matrix (INTENT × reachability
// × scope-outrankable × own-settings → action).
func TestDecideClaudeEmptyUnset(t *testing.T) {
	cases := []struct {
		name                                       string
		noProxyRoute, proxyUp, outrankable, ownSet bool
		want                                       claudeEmptyUnsetAction
	}{
		{"bypass intent → direct-satisfied", true, false, true, false, emptyUnsetDirectSatisfied},
		{"bypass intent even if outrankable", true, true, true, false, emptyUnsetDirectSatisfied},
		{"routed, proxy down → direct-satisfied", false, false, true, false, emptyUnsetDirectSatisfied},
		{"routed, up, user/project/local → pin proxy", false, true, true, false, emptyUnsetPinProxy},
		{"routed, up, managed scope → warn direct", false, true, false, false, emptyUnsetWarnDirect},
		{"routed, up, own --settings → warn direct", false, true, true, true, emptyUnsetWarnDirect},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideClaudeEmptyUnset(tc.noProxyRoute, tc.proxyUp, tc.outrankable, tc.ownSet); got != tc.want {
				t.Fatalf("decideClaudeEmptyUnset=%d, want %d", got, tc.want)
			}
		})
	}
}

// TestClaudeEmptyUnsetNotice pins finding N3's honest copy: pin-proxy says capture
// IS restored + names the proxy; warn-direct says capture DISABLED + NOT captured;
// direct-satisfied branches proxy-down (observer start) vs no-proxy-route.
func TestClaudeEmptyUnsetNotice(t *testing.T) {
	const sf = "project settings"
	pin := claudeEmptyUnsetNotice(emptyUnsetPinProxy, reasonRouteHealthy, claudeTestProxyURL, sf)
	for _, w := range []string{"unsets ANTHROPIC_BASE_URL", claudeTestProxyURL, "captured", "--settings"} {
		if !strings.Contains(pin, w) {
			t.Errorf("pin notice missing %q:\n%s", w, pin)
		}
	}
	warn := claudeEmptyUnsetNotice(emptyUnsetWarnDirect, reasonRouteHealthy, claudeTestProxyURL, sf)
	for _, w := range []string{"DISABLED", "NOT captured"} {
		if !strings.Contains(warn, w) {
			t.Errorf("warn notice missing %q:\n%s", w, warn)
		}
	}
	down := claudeEmptyUnsetNotice(emptyUnsetDirectSatisfied, reasonProxyDownClean, claudeTestProxyURL, sf)
	if !strings.Contains(down, "observer start") || !strings.Contains(down, "NOT captured") {
		t.Errorf("proxy-down direct notice missing observer start / NOT captured:\n%s", down)
	}
	npr := claudeEmptyUnsetNotice(emptyUnsetDirectSatisfied, reasonNoProxyRouteClean, claudeTestProxyURL, sf)
	if !strings.Contains(npr, "--no-proxy-route") || !strings.Contains(npr, "NOT captured") {
		t.Errorf("no-proxy-route direct notice missing bits:\n%s", npr)
	}
}

// TestFileOwnedByCurrentUser pins finding N6's ownership gate for the same-uid
// case: a file the test process creates is owned by it, so the reaper is allowed
// to delete it (a foreign-uid file can't be faked portably in a unit test).
func TestFileOwnedByCurrentUser(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mine.json")
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !fileOwnedByCurrentUser(info) {
		t.Fatal("a file created by this process must be reported as owned by it")
	}
}

// TestEmptyUnsetNoticeRedundant pins F3(a)'s dedup rule: the empty-unset direct
// notice is suppressed ONLY for the proxy-down direct-satisfied row when the
// attach layer already printed its daemon-unreachable notice; every other
// combination still prints.
func TestEmptyUnsetNoticeRedundant(t *testing.T) {
	cases := []struct {
		name           string
		attachNoticed  bool
		action         claudeEmptyUnsetAction
		reason         proxyFallbackReason
		wantSuppressed bool
	}{
		{"proxy-down direct + attach noticed → suppress", true, emptyUnsetDirectSatisfied, reasonProxyDownClean, true},
		{"proxy-down direct, attach NOT noticed → print", false, emptyUnsetDirectSatisfied, reasonProxyDownClean, false},
		{"no-proxy-route direct + attach noticed → print", true, emptyUnsetDirectSatisfied, reasonNoProxyRouteClean, false},
		{"pin-proxy + attach noticed → print", true, emptyUnsetPinProxy, reasonProxyDownClean, false},
		{"warn-direct + attach noticed → print", true, emptyUnsetWarnDirect, reasonProxyDownClean, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := emptyUnsetNoticeRedundant(tc.attachNoticed, tc.action, tc.reason); got != tc.wantSuppressed {
				t.Fatalf("emptyUnsetNoticeRedundant=%v, want %v", got, tc.wantSuppressed)
			}
		})
	}
}

// TestRunClaudeEmptyUnset_DaemonDownSingleNotice pins F3(a)+round-5 end-to-end:
// on a daemon-down empty-unset launch where the attach layer ALREADY printed its
// daemon-unreachable notice (attachDownNoticed=true), runClaudeEmptyUnset prints
// exactly one CONDENSED line — no restated "unreachable", but the capture-loss
// half and the `observer start` remedy survive (full silence lost the only
// actionable hint). With attachDownNoticed=false the full informative line is
// printed.
func TestRunClaudeEmptyUnset_DaemonDownSingleNotice(t *testing.T) {
	bin, _ := writeRecordingClaudeBin(t)
	proxyURL := closedProxyURL(t) // proxy DOWN → proxyReachable=false → direct-satisfied
	route := claudeRouteResolution{class: claudeRouteEmptyUnset, scope: claudeScopeUser, file: "user settings"}
	cfgPath, _ := writeGuardTestConfig(t)

	t.Run("attach already noticed → one condensed notice", func(t *testing.T) {
		var stderr bytes.Buffer
		opts := claudeLauncherOptions{configPath: cfgPath, stderr: &stderr, claudeArgs: []string{"--model", "opus"}}
		if err := runClaudeEmptyUnset(opts, bin, proxyURL, route, opts.claudeArgs, "", true); err != nil {
			t.Fatalf("runClaudeEmptyUnset: %v", err)
		}
		lines := strings.Split(strings.TrimRight(stderr.String(), "\n"), "\n")
		if len(lines) != 1 {
			t.Fatalf("expected exactly one condensed notice, got %d line(s):\n%s", len(lines), stderr.String())
		}
		if strings.Contains(lines[0], "unreachable") || strings.Contains(lines[0], proxyURL) {
			t.Fatalf("condensed notice restates unreachability:\n%s", lines[0])
		}
		if !strings.Contains(lines[0], "NOT captured") || !strings.Contains(lines[0], "observer start") {
			t.Fatalf("condensed notice lost capture-loss half or `observer start` remedy:\n%s", lines[0])
		}
	})

	t.Run("attach NOT noticed → exactly one notice", func(t *testing.T) {
		var stderr bytes.Buffer
		opts := claudeLauncherOptions{configPath: cfgPath, stderr: &stderr, claudeArgs: []string{"--model", "opus"}}
		if err := runClaudeEmptyUnset(opts, bin, proxyURL, route, opts.claudeArgs, "", false); err != nil {
			t.Fatalf("runClaudeEmptyUnset: %v", err)
		}
		lines := strings.Split(strings.TrimRight(stderr.String(), "\n"), "\n")
		if len(lines) != 1 || !strings.Contains(lines[0], "NOT captured") {
			t.Fatalf("expected exactly one NOT-captured notice, got %d line(s):\n%s", len(lines), stderr.String())
		}
	})
}

// TestRunClaudeEmptyUnset_PinWriteFailNoCapturedClaim pins F3(b): when the
// capture-restoring --settings pin file CANNOT be written, no "turns ARE
// captured" claim is printed BEFORE the "NOT captured this run" fallback line —
// the success notice now lives inside the write closure, which never runs on a
// write failure.
func TestRunClaudeEmptyUnset_PinWriteFailNoCapturedClaim(t *testing.T) {
	bin, _ := writeRecordingClaudeBin(t) // captured under a valid TMPDIR first
	proxyURL := reachableProxyURL(t)     // proxy UP → pin-proxy action
	cfgPath, _ := writeGuardTestConfig(t)
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	t.Setenv("ANTHROPIC_CONFIG_DIR", "")
	// Point TMPDIR at a non-existent dir so os.CreateTemp (and thus the pin write)
	// fails → *bypassWriteError → direct fallback.
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does-not-exist"))

	route := claudeRouteResolution{class: claudeRouteEmptyUnset, scope: claudeScopeUser, file: "user settings"}
	var stderr bytes.Buffer
	opts := claudeLauncherOptions{configPath: cfgPath, stderr: &stderr, claudeArgs: []string{"--model", "opus"}}
	if err := runClaudeEmptyUnset(opts, bin, proxyURL, route, opts.claudeArgs, "", false); err != nil {
		t.Fatalf("runClaudeEmptyUnset: %v", err)
	}
	out := stderr.String()
	if !strings.Contains(out, "NOT captured this run") {
		t.Fatalf("expected the write-failure NOT-captured fallback, got:\n%s", out)
	}
	// The success claim ("turns ARE captured") must NOT appear — it would precede
	// and contradict the fallback line.
	if strings.Contains(out, "ARE captured") {
		t.Fatalf("a 'turns ARE captured' claim preceded a failed pin write:\n%s", out)
	}
}

// TestWriteClaudeSettingsPin_HolderSetBeforeWrite pins F4: the onCreate callback
// fires the INSTANT the temp file exists — before content is written — so a
// signal-visible holder is published while the file is still empty (0 bytes),
// closing the strand window. After the call the file carries its JSON body.
func TestWriteClaudeSettingsPin_HolderSetBeforeWrite(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	var (
		cbCalled bool
		cbPath   string
		cbSize   int64 = -1
	)
	path, err := writeClaudeSettingsPin(anthropicDefaultBaseURL, func(p string) {
		cbCalled = true
		cbPath = p
		if fi, e := os.Stat(p); e == nil {
			cbSize = fi.Size()
		}
	})
	if err != nil {
		t.Fatalf("writeClaudeSettingsPin: %v", err)
	}
	defer os.Remove(path)
	if !cbCalled {
		t.Fatal("onCreate must be invoked")
	}
	if cbPath != path {
		t.Fatalf("callback path %q != returned path %q", cbPath, path)
	}
	if cbSize != 0 {
		t.Fatalf("holder published AFTER content write (size=%d at callback), want 0 — F4 window not closed", cbSize)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read final pin file: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("final pin file must carry the JSON body")
	}
}
