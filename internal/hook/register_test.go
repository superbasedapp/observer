package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func setupRegistry(t *testing.T) *Registry {
	t.Helper()
	return setupRegistryWithConfig(t, "")
}

func setupRegistryWithConfig(t *testing.T, configPath string) *Registry {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		ConfigPath:    configPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRegisterClaudeCodeFreshInstall(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	res := r.Register("claude-code")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if len(res.HooksAdded) != len(claudeCodeEvents) {
		t.Errorf("added %d want %d", len(res.HooksAdded), len(claudeCodeEvents))
	}

	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(body, &settings); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, body)
	}
	hooksBlock, ok := settings["hooks"].(map[string]any)
	if !ok {
		t.Fatal("hooks block missing")
	}
	for _, event := range claudeCodeEvents {
		groups, ok := hooksBlock[event].([]any)
		if !ok || len(groups) == 0 {
			t.Errorf("event %s missing", event)
		}
	}

	// Checksum file should be written.
	csPath := filepath.Join(r.opts.HomeDir, ".observer", "hook_checksums.json")
	if _, err := os.Stat(csPath); err != nil {
		t.Errorf("checksum file not created: %v", err)
	}
}

func TestRegisterClaudeCodeIdempotent(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}
	res := r.Register("claude-code")
	if res.Error != nil {
		t.Fatalf("second: %v", res.Error)
	}
	if len(res.HooksAdded) != 0 {
		t.Errorf("second register added %d (want 0): %v", len(res.HooksAdded), res.HooksAdded)
	}
	if len(res.AlreadySet) != len(claudeCodeEvents) {
		t.Errorf("AlreadySet %d want %d", len(res.AlreadySet), len(claudeCodeEvents))
	}
}

func TestRegisterClaudeCodePreservesOtherKeys(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	// Write a settings.json with unrelated fields that we must not clobber.
	pre := `{"theme":"dark","permissions":{"allow":["bash"]}}`
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.Register("claude-code")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, _ := os.ReadFile(path)
	var got map[string]any
	_ = json.Unmarshal(body, &got)
	if got["theme"] != "dark" {
		t.Errorf("theme lost: %v", got["theme"])
	}
	if _, ok := got["permissions"]; !ok {
		t.Error("permissions lost")
	}
}

func TestRegisterClaudeCodeConflict(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	pre := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/other-hook"}]}]}}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	res := r.Register("claude-code")
	if res.Error == nil {
		t.Fatal("expected conflict error")
	}

	// With Force, should succeed and add our hook alongside.
	r.opts.Force = true
	res = r.Register("claude-code")
	if res.Error != nil {
		t.Fatalf("force register: %v", res.Error)
	}
}

// TestRegisterClaudeCodeQuotesWindowsBinaryPath pins the v1.8.2+
// Windows-shaped-path normalization: when BinaryPath contains
// backslashes (the canonical Windows shape, e.g.
// `D:\programsx\...\observer.exe`), the written command MUST emit
// the forward-slash equivalent (`D:/programsx/...\observer.exe`)
// so the path survives any shell wrapping the Claude Code harness
// applies. Background: the v1.6.25 fix at this site single-quoted
// the backslash path so Git Bash on Windows wouldn't strip
// backslashes as escape sequences (`\p` → `p`, `\s` → `s`, etc.).
// That worked when Claude Code spawned the hook directly. But the
// harness's per-tool-call Bash wrapper can strip the single quotes
// upstream, leaving the unquoted backslash path for bash to
// escape-strip — symptom is the canonical
// `D:programsxsuperbased-observerbinobserver-hermes.exe: command
// not found` 127 exit, sidecar stays empty, dashboard effort column
// never populates. Forward-slash normalization removes the only
// character any shell layer interprets specially, so the path
// arrives at exec unmodified regardless of how many wrappers
// stripped or re-quoted it. Bonus: still safe for paths with spaces
// (e.g. `C:/Program Files/observer/...`) — shellQuoteIfNeeded
// re-applies a quote there, but the path inside the quote no longer
// has backslashes to escape-strip.
func TestRegisterClaudeCodeQuotesWindowsBinaryPath(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:    `D:\programsx\superbased-observer\bin\observer.exe`,
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Parse the JSON and pull out the PreToolUse command so the
	// assertion is decoupled from JSON-escape details. Forward-slash
	// shape: no quoting (the path has no shell-special chars), no
	// backslashes (so no escape-stripping vulnerability).
	got := extractClaudeCommand(t, body, "PreToolUse")
	wantPrefix := `D:/programsx/superbased-observer/bin/observer.exe hook claude-code `
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("PreToolUse command = %q, want prefix %q", got, wantPrefix)
	}
	// Regression guard: no backslash from the original Windows path
	// must leak into the written command. If this fails, the
	// forward-slash normalization regressed and the harness-wrapper
	// 127 symptom will return.
	if strings.Contains(got, `\`) {
		t.Errorf("PreToolUse command leaks backslash: %q", got)
	}
}

// TestRegisterClaudeCodeForwardSlashesBothPaths explicitly pins
// that BOTH the binary path AND the --config path are emitted in
// forward-slash form when Windows-shaped. The bug this prevents:
// Claude Code's harness wrapping the hook command in `bash -c
// '<hook>; <user-cmd>'` and the inner single quote around the
// config path closes the outer single quote, leaving the inner
// backslash path for bash to escape-strip. Forward-slash config
// path means no backslashes can be escape-stripped no matter how
// many shell wrappers strip the quoting upstream.
func TestRegisterClaudeCodeForwardSlashesBothPaths(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:    `D:\programsx\superbased-observer\bin\observer.exe`,
		ConfigPath:    `C:\Users\marmu\.observer\config.toml`,
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := extractClaudeCommand(t, body, "PreToolUse")
	wantPrefix := `D:/programsx/superbased-observer/bin/observer.exe hook claude-code pre-tool --config 'C:/Users/marmu/.observer/config.toml'`
	if got != wantPrefix {
		t.Errorf("PreToolUse command = %q, want %q", got, wantPrefix)
	}
	// Anti-regression: zero backslashes anywhere in the command —
	// neither the binary nor the config path may carry a Windows
	// separator, since each one defeats the bash-escape-strip
	// invariant the v1.6.25 single-quote fix relied on (and which
	// some harness wrappers undo).
	if strings.Contains(got, `\`) {
		t.Errorf("PreToolUse command leaks backslash (v1.8.2+ regression): %q", got)
	}
}

// extractClaudeCommand decodes settings.json and returns the first
// hook command for the given event under the "*" matcher group.
// Test helper for the Windows-quoting assertions.
func extractClaudeCommand(t *testing.T, body []byte, event string) string {
	t.Helper()
	var s struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatalf("unmarshal settings.json: %v\n%s", err, body)
	}
	groups, ok := s.Hooks[event]
	if !ok || len(groups) == 0 {
		t.Fatalf("event %s missing in settings.json:\n%s", event, body)
	}
	for _, g := range groups {
		for _, h := range g.Hooks {
			if h.Type == "command" {
				return h.Command
			}
		}
	}
	t.Fatalf("event %s has no command-type hook:\n%s", event, body)
	return ""
}

// TestRegisterCursorQuotesWindowsBinaryPath mirrors the claude-code
// variant for cursor.
func TestRegisterCursorQuotesWindowsBinaryPath(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:    `D:\programsx\superbased-observer\bin\observer.exe`,
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Register("cursor"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, err := os.ReadFile(filepath.Join(home, ".cursor", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	// cursor hooks.json has shape: {"hooks": {<event>: [{"command": "..."}]}}
	var s struct {
		Hooks map[string][]struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatalf("unmarshal hooks.json: %v\n%s", err, body)
	}
	entries, ok := s.Hooks["beforeShellExecution"]
	if !ok || len(entries) == 0 {
		t.Fatalf("beforeShellExecution missing:\n%s", body)
	}
	// Forward-slash shape — mirrors TestRegisterClaudeCodeQuotesWindowsBinaryPath.
	// See forwardSlashPath in register.go for the rationale.
	wantPrefix := `D:/programsx/superbased-observer/bin/observer.exe hook cursor `
	if !strings.HasPrefix(entries[0].Command, wantPrefix) {
		t.Errorf("beforeShellExecution command = %q, want prefix %q", entries[0].Command, wantPrefix)
	}
	if strings.Contains(entries[0].Command, `\`) {
		t.Errorf("beforeShellExecution command leaks backslash: %q", entries[0].Command)
	}
}

// extractCodexCommand pulls the first command-type hook for the
// given event out of a codex hooks.json body. Helper for the
// codex-on-Windows quoting assertions below — decouples them from
// JSON-escape details (\\ vs \) by parsing first and comparing
// against the runtime string value.
func extractCodexCommand(t *testing.T, body []byte, event string) string {
	t.Helper()
	var s struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatalf("unmarshal hooks.json: %v\n%s", err, body)
	}
	groups, ok := s.Hooks[event]
	if !ok || len(groups) == 0 || len(groups[0].Hooks) == 0 {
		t.Fatalf("event %s missing in hooks.json:\n%s", event, body)
	}
	for _, g := range groups {
		for _, h := range g.Hooks {
			if h.Type == "command" {
				return h.Command
			}
		}
	}
	t.Fatalf("event %s has no command-type hook:\n%s", event, body)
	return ""
}

// TestRegisterCodexUsesCmdSafeQuotingForWindowsBinaryPath pins the
// v1.6.28 regression fix: Codex on Windows spawns hooks through
// cmd.exe, which interprets `'...'` literally — the v1.6.25
// single-quote shape made every codex hook fire exit 1 with the
// error `'C:\\...\\observer.exe' is not recognised as an internal
// or external command`. Operator-reported 2026-05-23 against npm
// @superbased/observer 1.6.27 + codex CLI 0.133.0 on Windows.
//
// Post-fix the codex registrar uses codexCmdQuoteIfNeeded — paths
// with backslash trigger the cmd.exe-safe double-quote variant,
// which wraps only when the path contains special characters
// (space, &, <, >, |, etc.). The user's reported path has no
// spaces, so the post-fix command is unquoted and runs cleanly
// under cmd.exe (verified workaround in the bug report).
//
// Anti-regression: must NOT contain `'D:\` anywhere (the old
// single-quote prefix), since that's what triggered exit 1.
func TestRegisterCodexUsesCmdSafeQuotingForWindowsBinaryPath(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:    `D:\programsx\superbased-observer\bin\observer.exe`,
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Register("codex"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, err := os.ReadFile(filepath.Join(home, ".codex", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := extractCodexCommand(t, body, "PreToolUse")
	// Path has no spaces / cmd.exe-special chars → unwrapped.
	wantPrefix := `D:\programsx\superbased-observer\bin\observer.exe hook codex `
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("PreToolUse command = %q, want prefix %q", got, wantPrefix)
	}
	// Anti-regression: no POSIX single-quote wrapper.
	if strings.Contains(got, `'D:\`) || strings.Contains(got, `'C:\`) {
		t.Errorf("codex command on Windows path still has POSIX single-quote wrapper (cmd.exe will misparse): %q", got)
	}
}

// TestRegisterCodexWrapsWindowsPathWithSpacesInDoubleQuotes pins the
// other half of the cmd.exe-safe quoter — paths with spaces (like
// `C:\Program Files\observer\observer.exe`) DO need quoting, but in
// cmd.exe-style double quotes rather than POSIX single quotes.
func TestRegisterCodexWrapsWindowsPathWithSpacesInDoubleQuotes(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:    `C:\Program Files\observer\observer.exe`,
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Register("codex"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, err := os.ReadFile(filepath.Join(home, ".codex", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := extractCodexCommand(t, body, "PreToolUse")
	wantPrefix := `"C:\Program Files\observer\observer.exe" hook codex `
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("PreToolUse command = %q, want prefix %q", got, wantPrefix)
	}
}

// TestRegisterCodexLinuxPathStaysPosixQuoted pins that Linux/macOS
// codex hooks keep the POSIX single-quote behaviour — codex on
// non-Windows hosts spawns hooks via /bin/sh, where `'...'` is the
// stricter no-expansion quoting we want. Path without special
// chars stays unwrapped (matching shellQuoteIfNeeded's behaviour);
// path with spaces gets single-quoted.
func TestRegisterCodexLinuxPathStaysPosixQuoted(t *testing.T) {
	t.Parallel()
	// Clean Linux path → unwrapped.
	{
		home := t.TempDir()
		if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
			t.Fatal(err)
		}
		r, err := NewRegistry(Options{
			BinaryPath:    "/usr/local/bin/observer",
			HomeDir:       home,
			ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if res := r.Register("codex"); res.Error != nil {
			t.Fatalf("Register: %v", res.Error)
		}
		body, _ := os.ReadFile(filepath.Join(home, ".codex", "hooks.json"))
		got := extractCodexCommand(t, body, "PreToolUse")
		wantPrefix := "/usr/local/bin/observer hook codex "
		if !strings.HasPrefix(got, wantPrefix) {
			t.Errorf("clean linux path: got %q want prefix %q", got, wantPrefix)
		}
	}
	// Linux path with space → POSIX single-quote.
	{
		home := t.TempDir()
		if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
			t.Fatal(err)
		}
		r, err := NewRegistry(Options{
			BinaryPath:    "/home/user/My Stuff/observer",
			HomeDir:       home,
			ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if res := r.Register("codex"); res.Error != nil {
			t.Fatalf("Register: %v", res.Error)
		}
		body, _ := os.ReadFile(filepath.Join(home, ".codex", "hooks.json"))
		got := extractCodexCommand(t, body, "PreToolUse")
		wantPrefix := `'/home/user/My Stuff/observer' hook codex `
		if !strings.HasPrefix(got, wantPrefix) {
			t.Errorf("linux path with space: got %q want prefix %q", got, wantPrefix)
		}
	}
}

// TestRegisterCodexHonoursCmdSafeConfigPath pins that the --config
// path embedded in the codex hook command ALSO uses cmd.exe-safe
// quoting when codex+config are on Windows-shaped paths. Pre-fix
// (and pre-v1.6.25, even) the config path was wrapped in POSIX
// single-quote via configFlagSuffix() which independently broke
// codex on Windows.
func TestRegisterCodexHonoursCmdSafeConfigPath(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:    `D:\bin\observer.exe`,
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		ConfigPath:    `C:\Users\Administrator\.observer\config.toml`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Register("codex"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, _ := os.ReadFile(filepath.Join(home, ".codex", "hooks.json"))
	got := extractCodexCommand(t, body, "PreToolUse")
	// Neither path has spaces → both should be unwrapped.
	wantSubstr := ` --config C:\Users\Administrator\.observer\config.toml`
	if !strings.Contains(got, wantSubstr) {
		t.Errorf("codex command = %q, want config substring %q", got, wantSubstr)
	}
	if strings.Contains(got, `'C:\`) {
		t.Errorf("config path still POSIX single-quoted (cmd.exe will misparse): %q", got)
	}
}

// TestRegisterClaudeCodeCrossBinaryPathRefresh pins the
// content-heuristic upgrade path: when settings.json holds an
// observer-shaped hook entry pointing at a DIFFERENT binary path
// (e.g. an npm-bundled observer in node_modules, a previous install
// under a renamed home dir), the next register pass should silently
// refresh the entry to the current binary path — NOT trip the
// conflict guard with "non-observer hook; pass --force." This is
// the bug class that surfaced when a user had Claude Code's hooks
// registered to a stale binary path and observer's v1.6.22 effort
// sidecar silently stayed empty because the registered (old) binary
// pre-dated the effort sidecar and never wrote to it. The Linux
// path-prefix detector (replaced by isObserverClaudeEntry) couldn't
// recognise the stale entry as ours; the content-heuristic does.
func TestRegisterClaudeCodeCrossBinaryPathRefresh(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}

	// First install: observer at /tmp/observer-A.
	first, err := NewRegistry(Options{
		BinaryPath:    "/tmp/observer-A",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := first.Register("claude-code"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}

	// Second install: SAME home dir, NEW binary path. Must silently
	// refresh — no Force, no conflict error.
	second, err := NewRegistry(Options{
		BinaryPath:    "/usr/local/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	res := second.Register("claude-code")
	if res.Error != nil {
		t.Fatalf("second (cross-binary refresh): %v", res.Error)
	}
	if len(res.HooksAdded) != len(claudeCodeEvents) {
		t.Errorf("HooksAdded = %d want %d (every event should be re-added)",
			len(res.HooksAdded), len(claudeCodeEvents))
	}

	// Verify the file ONLY references the new binary now.
	body, _ := os.ReadFile(res.ConfigPath)
	if strings.Contains(string(body), "/tmp/observer-A") {
		t.Errorf("stale binary path leaked into refreshed settings.json:\n%s", body)
	}
	if !strings.Contains(string(body), "/usr/local/bin/observer") {
		t.Errorf("new binary path missing from refreshed settings.json:\n%s", body)
	}
}

// TestUnregisterClaudeCodeRemovesCrossBinaryEntries pins the
// Unregister-side counterpart to the v1.6.25 register-side cross-
// binary refresh: when settings.json holds an observer-shaped hook
// entry pointing at a DIFFERENT binary path (e.g. npm-bundled
// observer in node_modules) and the user uninstalls from the
// current binary, filterClaudeGroupsRaw MUST recognise the stale
// entry as ours via isObserverClaudeEntry and remove it — NOT
// leave it orphaned because the byte-exact prefix-match misses.
func TestUnregisterClaudeCodeRemovesCrossBinaryEntries(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}

	first, err := NewRegistry(Options{
		BinaryPath:    "/tmp/observer-A",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := first.Register("claude-code"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}

	second, err := NewRegistry(Options{
		BinaryPath:    "/usr/local/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	res := second.Unregister("claude-code")
	if res.Error != nil {
		t.Fatalf("unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) != len(claudeCodeEvents) {
		t.Errorf("HooksRemoved = %d want %d (every cross-binary entry should be removed)",
			len(res.HooksRemoved), len(claudeCodeEvents))
	}

	body, _ := os.ReadFile(res.ConfigPath)
	if bytes.Contains(body, []byte("/tmp/observer-A")) {
		t.Errorf("stale observer-A entries left behind after cross-binary unregister:\n%s", body)
	}
}

func TestRegisterCursorFreshInstall(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	res := r.Register("cursor")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, body)
	}
	if got["version"] == nil {
		t.Error("cursor version missing")
	}
	hooks, ok := got["hooks"].(map[string]any)
	if !ok {
		t.Fatal("hooks block missing")
	}
	for _, event := range cursorEvents {
		if _, ok := hooks[event]; !ok {
			t.Errorf("event %s missing", event)
		}
	}
}

func TestRegisterCursorIdempotent(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	_ = r.Register("cursor")
	res := r.Register("cursor")
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	if len(res.HooksAdded) != 0 {
		t.Errorf("second add added %d", len(res.HooksAdded))
	}
}

// TestRegisterCursorCrossBinaryPathRefresh mirrors
// TestRegisterClaudeCodeCrossBinaryPathRefresh for the cursor
// registrar: a hooks.json carrying an observer-shaped entry that
// points at a different binary path must be recognised as ours via
// the ` hook cursor ` content-heuristic and silently refreshed, not
// flagged as a foreign-tool conflict.
func TestRegisterCursorCrossBinaryPathRefresh(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}

	first, err := NewRegistry(Options{
		BinaryPath:    "/tmp/observer-A",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := first.Register("cursor"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}

	second, err := NewRegistry(Options{
		BinaryPath:    "/usr/local/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	res := second.Register("cursor")
	if res.Error != nil {
		t.Fatalf("second (cross-binary refresh): %v", res.Error)
	}
	if len(res.HooksAdded) != len(cursorEvents) {
		t.Errorf("HooksAdded = %d want %d", len(res.HooksAdded), len(cursorEvents))
	}

	body, _ := os.ReadFile(res.ConfigPath)
	if strings.Contains(string(body), "/tmp/observer-A") {
		t.Errorf("stale binary path leaked into refreshed hooks.json:\n%s", body)
	}
	if !strings.Contains(string(body), "/usr/local/bin/observer") {
		t.Errorf("new binary path missing from refreshed hooks.json:\n%s", body)
	}
}

// TestUnregisterCursorRemovesCrossBinaryEntries mirrors the claude-
// code variant: cursor hooks.json carrying entries written by a
// different observer binary path must be cleaned up via the content-
// heuristic, not left behind because the byte-exact prefix-match
// missed.
func TestUnregisterCursorRemovesCrossBinaryEntries(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}

	first, err := NewRegistry(Options{
		BinaryPath:    "/tmp/observer-A",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := first.Register("cursor"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}

	second, err := NewRegistry(Options{
		BinaryPath:    "/usr/local/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	res := second.Unregister("cursor")
	if res.Error != nil {
		t.Fatalf("unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) == 0 {
		t.Errorf("HooksRemoved = 0; expected cross-binary entries to be removed")
	}
	if _, err := os.Stat(res.ConfigPath); err == nil {
		// File still exists — verify no observer-A entries remain.
		body, _ := os.ReadFile(res.ConfigPath)
		if bytes.Contains(body, []byte("/tmp/observer-A")) {
			t.Errorf("stale observer-A entries left behind after cross-binary unregister:\n%s", body)
		}
	}
}

func TestRegisterUnknownTool(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	res := r.Register("notarealthing")
	if res.Error == nil {
		t.Fatal("expected error for unknown tool")
	}
}

func TestDryRunDoesNotWrite(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	r.opts.DryRun = true
	res := r.Register("claude-code")
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	_, err := os.Stat(res.ConfigPath)
	if err == nil {
		t.Error("dry run wrote the config")
	}
	if !res.DryRun {
		t.Error("result should flag dry run")
	}
}

func TestInstalledDetectsDirs(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath: "/x",
		HomeDir:    home,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := r.Installed()
	// "claude-code" must be present (the .claude/ in HomeDir was the
	// signal). Other entries (notably "cursor-windows" on WSL hosts
	// where crossmount detects a Windows-side .cursor/) are platform-
	// dependent — the test only asserts the .claude/ trigger, not the
	// absence of cross-mount auto-detection.
	if !containsString(got, "claude-code") {
		t.Errorf("Installed = %v, want it to contain claude-code", got)
	}
}

func containsString(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func TestCommandContainsBinaryPath(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatal(res.Error)
	}
	body, _ := os.ReadFile(filepath.Join(r.opts.HomeDir, ".claude", "settings.json"))
	if !strings.Contains(string(body), r.opts.BinaryPath) {
		t.Errorf("binary path not in settings: %s", body)
	}
}

// TestRegisterClaudeCodeWithConfigPath pins the v1.4.43+ hook→DB-wiring
// fix: when Options.ConfigPath is set, every registered hook command
// gets `--config <path>` appended so the spawned hook handler reads
// the same DB the proxy writes to. Without this, /compact rows always
// land on ~/.observer/observer.db regardless of which proxy daemon
// fired the hook — D23's Injector then queries the proxy's DB and
// finds nothing. Surfaced 2026-05-08 dogfood.
func TestRegisterClaudeCodeWithConfigPath(t *testing.T) {
	t.Parallel()
	r := setupRegistryWithConfig(t, "/tmp/ab-claude/on/observer-config.toml")
	res := r.Register("claude-code")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	want := r.opts.BinaryPath + " hook claude-code pre-compact --config '/tmp/ab-claude/on/observer-config.toml'"
	if !strings.Contains(string(body), want) {
		t.Errorf("expected hook command to include --config; got:\n%s", body)
	}
}

// TestRegisterClaudeCodeRefreshesOnConfigPathChange pins that re-running
// init with a different config silently overwrites the registration
// instead of being treated as already-set. Without this, switching
// configs would leave the hook pointing at the old DB.
func TestRegisterClaudeCodeRefreshesOnConfigPathChange(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	first, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		ConfigPath:    "/tmp/old.toml",
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := first.Register("claude-code"); r.Error != nil {
		t.Fatalf("first: %v", r.Error)
	}

	second, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		ConfigPath:    "/tmp/new.toml",
	})
	if err != nil {
		t.Fatal(err)
	}
	res := second.Register("claude-code")
	if res.Error != nil {
		t.Fatalf("second: %v", res.Error)
	}
	if len(res.HooksAdded) == 0 {
		t.Fatal("expected refresh to re-add events with new config")
	}
	body, _ := os.ReadFile(res.ConfigPath)
	if strings.Contains(string(body), "/tmp/old.toml") {
		t.Errorf("old config path leaked into refreshed registration: %s", body)
	}
	if !strings.Contains(string(body), "/tmp/new.toml") {
		t.Errorf("new config path missing: %s", body)
	}
}

// TestRegisterCursorWindowsFreshInstall pins the wsl.exe-prefixed
// hook command shape against a fake Windows-side .cursor/. The
// resulting hooks.json must carry every cursorEvents entry, each
// shaped `wsl.exe -d <distro> -- <linux-bin> hook cursor <event>
// [--config ...]`. Tests the explicit-WindowsCursorHome path so the
// crossmount auto-detect doesn't depend on /mnt/c presence.
func TestRegisterCursorWindowsFreshInstall(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	cursorDir := filepath.Join(winHome, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:        "/home/marmutapp/superbased-observer/bin/observer",
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsCursorHome: winHome,
		WSLDistro:         "Ubuntu-20.04",
		ConfigPath:        "/home/marmutapp/.observer/config.toml",
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("cursor-windows")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if len(res.HooksAdded) != len(cursorEvents) {
		t.Errorf("HooksAdded count = %d want %d", len(res.HooksAdded), len(cursorEvents))
	}
	if res.ConfigPath != filepath.Join(cursorDir, "hooks.json") {
		t.Errorf("ConfigPath = %q want %q", res.ConfigPath, filepath.Join(cursorDir, "hooks.json"))
	}

	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(body, &settings); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, body)
	}
	hooksBlock, ok := settings["hooks"].(map[string]any)
	if !ok {
		t.Fatal("hooks block missing")
	}
	for _, event := range cursorEvents {
		entries, ok := hooksBlock[event].([]any)
		if !ok || len(entries) == 0 {
			t.Errorf("event %s missing", event)
			continue
		}
		first, _ := entries[0].(map[string]any)
		cmd, _ := first["command"].(string)
		// No MSYS_NO_PATHCONV=1 prefix: Cursor runs hooks via PowerShell,
		// where the bash env-prefix is invalid (see registerCursorWindows).
		wantPrefix := "wsl.exe -d Ubuntu-20.04 -- /home/marmutapp/superbased-observer/bin/observer hook cursor " + event
		if !strings.HasPrefix(cmd, wantPrefix) {
			t.Errorf("event %s cmd = %q want prefix %q", event, cmd, wantPrefix)
		}
		if strings.HasPrefix(cmd, "MSYS_NO_PATHCONV=1") {
			t.Errorf("event %s cmd still has the MSYS bash env-prefix (breaks under Cursor's PowerShell): %q", event, cmd)
		}
		if !strings.Contains(cmd, "--config '/home/marmutapp/.observer/config.toml'") {
			t.Errorf("event %s cmd missing --config: %q", event, cmd)
		}
	}
}

// TestRegisterCursorWindowsRequiresDistro pins the
// "missing distro" error path. Without a distro, `wsl.exe` would be
// ambiguous on a host with multiple WSL distros — better to fail
// loudly at install time than write a broken hooks.json.
func TestRegisterCursorWindowsRequiresDistro(t *testing.T) {
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	if err := os.MkdirAll(filepath.Join(winHome, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WSL_DISTRO_NAME", "")
	r, err := NewRegistry(Options{
		BinaryPath:        "/x",
		HomeDir:           wslHome,
		WindowsCursorHome: winHome,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("cursor-windows")
	if res.Error == nil {
		t.Fatal("expected error when distro unset, got nil")
	}
	if !strings.Contains(res.Error.Error(), "WSL distro unknown") {
		t.Errorf("error message = %q want it to mention 'WSL distro unknown'", res.Error)
	}
}

// TestRegisterCursorWindowsCrossBinaryPathRefresh pins the upgrade
// path: when a hooks.json was written by a previous observer
// install (different binary path), re-registering with a new
// binary should silently refresh the entries — not error with
// "non-observer hook" as if a foreign tool had written them. This
// is the staleness-detection bug that surfaced when the
// auto-register pass on `observer start` ran twice with different
// binary paths (e.g. /tmp smoke-test vs production install).
func TestRegisterCursorWindowsCrossBinaryPathRefresh(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	cursorDir := filepath.Join(winHome, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// First install: binary at /tmp/observer-A.
	first, err := NewRegistry(Options{
		BinaryPath:        "/tmp/observer-A",
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsCursorHome: winHome,
		WSLDistro:         "Ubuntu-20.04",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := first.Register("cursor-windows"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}

	// Second install: same registry, NEW binary path. Should
	// silently refresh, not error.
	second, err := NewRegistry(Options{
		BinaryPath:        "/usr/local/bin/observer",
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsCursorHome: winHome,
		WSLDistro:         "Ubuntu-20.04",
	})
	if err != nil {
		t.Fatal(err)
	}
	res := second.Register("cursor-windows")
	if res.Error != nil {
		t.Fatalf("second (cross-binary refresh): %v", res.Error)
	}
	if len(res.HooksAdded) != len(cursorEvents) {
		t.Errorf("HooksAdded = %d want %d", len(res.HooksAdded), len(cursorEvents))
	}

	// Verify the file ONLY references the new binary now.
	body, _ := os.ReadFile(res.ConfigPath)
	if strings.Contains(string(body), "/tmp/observer-A") {
		t.Errorf("stale binary path leaked into refreshed hooks.json:\n%s", body)
	}
	if !strings.Contains(string(body), "/usr/local/bin/observer") {
		t.Errorf("new binary path missing:\n%s", body)
	}
}

// TestRegisterCursorWindowsRespectsForeignEntry pins the
// safety-first behavior: a non-observer-shaped command (e.g. user
// has a different tool's hook wired in) must NOT be silently
// overwritten. Force=false → return error; Force=true → overwrite.
func TestRegisterCursorWindowsRespectsForeignEntry(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	cursorDir := filepath.Join(winHome, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Plant a foreign hook in beforeShellExecution.
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	foreign := `{"version":1,"hooks":{"beforeShellExecution":[{"command":"powershell.exe Write-Host hi"}]}}`
	if err := os.WriteFile(hooksPath, []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:        "/tmp/observer",
		HomeDir:           wslHome,
		WindowsCursorHome: winHome,
		WSLDistro:         "Ubuntu-20.04",
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("cursor-windows")
	if res.Error == nil {
		t.Fatal("expected error when foreign hook present, got nil")
	}
	if !strings.Contains(res.Error.Error(), "non-observer") {
		t.Errorf("error message = %q want it to mention 'non-observer'", res.Error)
	}
}

// TestRegisterCursorWindowsIdempotent re-runs registration on an
// already-installed hooks.json and asserts no events get re-added.
func TestRegisterCursorWindowsIdempotent(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	if err := os.MkdirAll(filepath.Join(winHome, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:        "/opt/observer/bin/observer",
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsCursorHome: winHome,
		WSLDistro:         "Ubuntu-22.04",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Register("cursor-windows"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}
	res := r.Register("cursor-windows")
	if res.Error != nil {
		t.Fatalf("second: %v", res.Error)
	}
	if len(res.HooksAdded) != 0 {
		t.Errorf("second register added %d (want 0): %v", len(res.HooksAdded), res.HooksAdded)
	}
	if len(res.AlreadySet) != len(cursorEvents) {
		t.Errorf("AlreadySet %d want %d", len(res.AlreadySet), len(cursorEvents))
	}
}

// TestIsDanglingObserverWindowsCursorShim table-tests the narrowed
// predicate (F2, docs/audits/cursor-windows-capture-diagnosis-2026-08-07.md
// §4) in isolation: it must recognise the operator's exact stale
// /tmp/cursor-tee-shim.sh entry as ours, but refuse to classify a
// merely wsl.exe-shaped foreign command (missing our config path, or
// missing the event token) as observer-owned.
func TestIsDanglingObserverWindowsCursorShim(t *testing.T) {
	t.Parallel()
	const ourConfig = "/home/marmutapp/.observer/config.toml"
	cases := []struct {
		name       string
		cmd        string
		event      string
		configPath string
		want       bool
	}{
		{
			name:       "operator's exact stale tee-shim entry",
			cmd:        `wsl.exe -d Ubuntu-20.04 -- /tmp/cursor-tee-shim.sh afterAgentResponse --config '/home/marmutapp/.observer/config.toml'`,
			event:      "afterAgentResponse",
			configPath: ourConfig,
			want:       true,
		},
		{
			name:       "wsl.exe shape but different event named",
			cmd:        `wsl.exe -d Ubuntu-20.04 -- /tmp/cursor-tee-shim.sh stop --config '/home/marmutapp/.observer/config.toml'`,
			event:      "afterAgentResponse",
			configPath: ourConfig,
			want:       false,
		},
		{
			name:       "wsl.exe shape but a DIFFERENT config path",
			cmd:        `wsl.exe -d Ubuntu-20.04 -- /tmp/some-other-tool.sh afterAgentResponse --config '/home/someone/else/config.toml'`,
			event:      "afterAgentResponse",
			configPath: ourConfig,
			want:       false,
		},
		{
			name:       "wsl.exe shape, no --config at all",
			cmd:        `wsl.exe -d Ubuntu-20.04 -- /some/other/script.sh afterAgentResponse`,
			event:      "afterAgentResponse",
			configPath: ourConfig,
			want:       false,
		},
		{
			name:       "not wsl.exe-shaped at all (real user hook)",
			cmd:        `powershell.exe -File C:\me\myhook.ps1`,
			event:      "afterAgentResponse",
			configPath: ourConfig,
			want:       false,
		},
		{
			name:       "registrar has no ConfigPath configured — never attributable",
			cmd:        `wsl.exe -d Ubuntu-20.04 -- /tmp/cursor-tee-shim.sh afterAgentResponse --config '/home/marmutapp/.observer/config.toml'`,
			event:      "afterAgentResponse",
			configPath: "",
			want:       false,
		},
		{
			name:       "legacy MSYS-prefixed shape also recognised",
			cmd:        `MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- /tmp/cursor-tee-shim.sh stop --config '/home/marmutapp/.observer/config.toml'`,
			event:      "stop",
			configPath: ourConfig,
			want:       true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := isDanglingObserverWindowsCursorShim(c.cmd, c.event, c.configPath); got != c.want {
				t.Errorf("isDanglingObserverWindowsCursorShim(%q, %q, %q) = %v want %v", c.cmd, c.event, c.configPath, got, c.want)
			}
		})
	}
}

// TestRegisterCursorWindowsSelfHealsStaleTeeShim is the F2 confirming
// evidence: the operator's EXACT stale hooks.json shape — every
// cursorEvents entry carrying BOTH the dead /tmp/cursor-tee-shim.sh
// debug entry AND the legacy MSYS_NO_PATHCONV=1-prefixed entry — must
// now self-heal under Force:false. Before F2 this aborted every
// event with "already has a non-observer hook" because
// isObserverWindowsCursorEntry didn't recognise the tee-shim shape.
// See docs/audits/cursor-windows-capture-diagnosis-2026-08-07.md §2.2/§4 F2.
func TestRegisterCursorWindowsSelfHealsStaleTeeShim(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	cursorDir := filepath.Join(winHome, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}

	const ourConfig = "/home/marmutapp/.observer/config.toml"
	hooks := map[string][]cursorHookEntry{}
	for _, event := range cursorEvents {
		hooks[event] = []cursorHookEntry{
			{Command: fmt.Sprintf(
				`wsl.exe -d Ubuntu-20.04 -- /tmp/cursor-tee-shim.sh %s --config '%s'`,
				event, ourConfig,
			)},
			{Command: fmt.Sprintf(
				`MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- /home/marmutapp/superbased-observer/bin/observer hook cursor %s`,
				event,
			)},
		}
	}
	body, err := json.Marshal(map[string]any{"version": 1, "hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, body, 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := NewRegistry(Options{
		BinaryPath:        "/home/marmutapp/superbased-observer/bin/observer",
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsCursorHome: winHome,
		WSLDistro:         "Ubuntu-20.04",
		ConfigPath:        ourConfig,
	})
	if err != nil {
		t.Fatal(err)
	}

	res := r.Register("cursor-windows")
	if res.Error != nil {
		t.Fatalf("Register (Force=false) on the exact stale operator file: %v", res.Error)
	}
	if len(res.HooksAdded) != len(cursorEvents) {
		t.Errorf("HooksAdded = %d want %d (%v)", len(res.HooksAdded), len(cursorEvents), res.HooksAdded)
	}

	written, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(written, &settings); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, written)
	}
	hooksBlock, ok := settings["hooks"].(map[string]any)
	if !ok {
		t.Fatal("hooks block missing")
	}
	for _, event := range cursorEvents {
		entries, ok := hooksBlock[event].([]any)
		if !ok {
			t.Errorf("event %s missing", event)
			continue
		}
		if len(entries) != 1 {
			t.Errorf("event %s has %d entries, want exactly 1 (self-heal should have dropped both stale entries): %v", event, len(entries), entries)
			continue
		}
		first, _ := entries[0].(map[string]any)
		cmd, _ := first["command"].(string)
		wantPrefix := "wsl.exe -d Ubuntu-20.04 -- /home/marmutapp/superbased-observer/bin/observer hook cursor " + event
		if !strings.HasPrefix(cmd, wantPrefix) {
			t.Errorf("event %s cmd = %q want prefix %q", event, cmd, wantPrefix)
		}
		if strings.Contains(cmd, "cursor-tee-shim") {
			t.Errorf("event %s: dead tee-shim entry survived self-heal: %q", event, cmd)
		}
	}
}

// TestRegisterCursorWindowsSelfHealPreservesGenuineForeignEntry pins
// the safety half of F2: a mixed file where one event ALSO carries a
// real user-authored hook (not wsl.exe-shaped, not ours by any
// predicate) must still refuse that event without --force — the
// narrowed self-heal predicate must never widen far enough to
// swallow a genuine foreign entry.
func TestRegisterCursorWindowsSelfHealPreservesGenuineForeignEntry(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	cursorDir := filepath.Join(winHome, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}

	const ourConfig = "/home/marmutapp/.observer/config.toml"
	hooks := map[string][]cursorHookEntry{}
	for _, event := range cursorEvents {
		hooks[event] = []cursorHookEntry{
			{Command: fmt.Sprintf(
				`wsl.exe -d Ubuntu-20.04 -- /tmp/cursor-tee-shim.sh %s --config '%s'`,
				event, ourConfig,
			)},
		}
	}
	// A real user-authored hook on ONE event, alongside the stale shim.
	hooks["beforeSubmitPrompt"] = append(hooks["beforeSubmitPrompt"], cursorHookEntry{
		Command: `powershell.exe -File C:\me\myhook.ps1`,
	})
	body, err := json.Marshal(map[string]any{"version": 1, "hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, body, 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := NewRegistry(Options{
		BinaryPath:        "/home/marmutapp/superbased-observer/bin/observer",
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsCursorHome: winHome,
		WSLDistro:         "Ubuntu-20.04",
		ConfigPath:        ourConfig,
	})
	if err != nil {
		t.Fatal(err)
	}

	res := r.Register("cursor-windows")
	if res.Error == nil {
		t.Fatal("expected error: beforeSubmitPrompt still carries a genuine foreign entry, self-heal must not silently overwrite it")
	}
	if !strings.Contains(res.Error.Error(), "non-observer") {
		t.Errorf("error message = %q want it to mention 'non-observer'", res.Error)
	}
	if !strings.Contains(res.Error.Error(), "beforeSubmitPrompt") {
		t.Errorf("error message = %q want it to name the offending event beforeSubmitPrompt", res.Error)
	}

	// Nothing should have been written — registerCursorWindows returns
	// before writing on the first conflicting event. Round-trip through
	// JSON (rather than a raw substring match) since json.Marshal
	// escapes the Windows path's backslashes.
	written, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(written, &settings); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, written)
	}
	hooksBlock, _ := settings["hooks"].(map[string]any)
	entries, _ := hooksBlock["beforeSubmitPrompt"].([]any)
	var foundForeign bool
	for _, e := range entries {
		m, _ := e.(map[string]any)
		if cmd, _ := m["command"].(string); cmd == `powershell.exe -File C:\me\myhook.ps1` {
			foundForeign = true
		}
	}
	if !foundForeign {
		t.Errorf("genuine foreign entry must be preserved on disk after a failed register attempt; beforeSubmitPrompt entries = %v", entries)
	}
}

// TestRecordAutoRegisterResult pins the F3 persistence contract:
// last_result/last_error land in hook_checksums.json for BOTH
// outcomes, an existing entry's sha256/registered/binary_path keys
// (written by a prior recordChecksum call) survive untouched, and a
// later success clears a previously-recorded last_error. See
// docs/audits/cursor-windows-capture-diagnosis-2026-08-07.md §4 F3.
func TestRecordAutoRegisterResult(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	csPath := filepath.Join(home, ".observer", "hook_checksums.json")
	r, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: csPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	const target = "/mnt/c/Users/tester/.cursor/hooks.json"

	// A prior successful write already recorded sha256/registered/
	// binary_path for this path (simulate recordChecksum's shape
	// directly rather than depending on it, to keep this test
	// focused on RecordAutoRegisterResult's own contract).
	seed := map[string]map[string]any{
		target: {
			"sha256":      "deadbeef",
			"registered":  "2026-08-01T00:00:00Z",
			"binary_path": "/opt/observer/bin/observer",
		},
	}
	seedBody, err := json.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(csPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(csPath, seedBody, 0o644); err != nil {
		t.Fatal(err)
	}

	readEntry := func() map[string]any {
		t.Helper()
		body, err := os.ReadFile(csPath)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("not valid JSON: %v\n%s", err, body)
		}
		entry, ok := m[target]
		if !ok {
			t.Fatalf("no entry for %s in %s", target, body)
		}
		return entry
	}

	// Failure path.
	regErr := errors.New("event afterAgentResponse already has a non-observer hook; pass --force to overwrite")
	if err := r.RecordAutoRegisterResult(target, regErr); err != nil {
		t.Fatalf("RecordAutoRegisterResult (failure): %v", err)
	}
	entry := readEntry()
	if entry["last_result"] != "error" {
		t.Errorf("last_result = %v want %q", entry["last_result"], "error")
	}
	if entry["last_error"] != regErr.Error() {
		t.Errorf("last_error = %v want %q", entry["last_error"], regErr.Error())
	}
	if entry["last_checked_at"] == nil || entry["last_checked_at"] == "" {
		t.Error("last_checked_at not set")
	}
	// Pre-existing keys from the earlier recordChecksum-shaped write
	// must survive untouched.
	if entry["sha256"] != "deadbeef" {
		t.Errorf("sha256 = %v, pre-existing key was clobbered", entry["sha256"])
	}
	if entry["registered"] != "2026-08-01T00:00:00Z" {
		t.Errorf("registered = %v, pre-existing key was clobbered", entry["registered"])
	}

	// Success path afterwards must clear last_error, not just leave it stale.
	if err := r.RecordAutoRegisterResult(target, nil); err != nil {
		t.Fatalf("RecordAutoRegisterResult (success): %v", err)
	}
	entry = readEntry()
	if entry["last_result"] != "ok" {
		t.Errorf("last_result = %v want %q", entry["last_result"], "ok")
	}
	if _, hasErr := entry["last_error"]; hasErr {
		t.Errorf("last_error still present after a successful re-register: %v", entry["last_error"])
	}
	if entry["sha256"] != "deadbeef" {
		t.Errorf("sha256 = %v, pre-existing key was clobbered on the success path", entry["sha256"])
	}
}

// TestRecordAutoRegisterResultEmptyPathNoop guards against writing a
// bogus "" key into hook_checksums.json when a registration attempt
// never got far enough to produce a ConfigPath.
func TestRecordAutoRegisterResultEmptyPathNoop(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	r, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RecordAutoRegisterResult("", errors.New("boom")); err != nil {
		t.Fatalf("RecordAutoRegisterResult(\"\", ...) = %v want nil", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".observer", "hook_checksums.json")); !os.IsNotExist(err) {
		t.Errorf("expected no hook_checksums.json to be written, stat err = %v", err)
	}
}

// TestShellQuoteEscapesSingleQuotes pins the shell-quoting helper so
// pathological config paths (with embedded ' or spaces) don't break
// the bash -c invocation Claude Code uses to run the hook command.
func TestShellQuoteEscapesSingleQuotes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"", "''"},
		{"/plain/path", "'/plain/path'"},
		{"/path with space", "'/path with space'"},
		{"/o'malley/x", `'/o'\''malley/x'`},
	}
	for _, c := range cases {
		if got := shellQuote(c.in); got != c.want {
			t.Errorf("shellQuote(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

// codexRegistry mirrors setupRegistry but seeds ~/.codex instead of
// ~/.claude / ~/.cursor so codex registration has a directory to scan.
func codexRegistry(t *testing.T) *Registry {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRegisterCodexFreshInstall(t *testing.T) {
	t.Parallel()
	r := codexRegistry(t)
	res := r.Register("codex")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if len(res.HooksAdded) != len(codexEvents) {
		t.Errorf("added %d want %d", len(res.HooksAdded), len(codexEvents))
	}
	if got, want := res.ConfigPath, filepath.Join(r.opts.HomeDir, ".codex", "hooks.json"); got != want {
		t.Errorf("ConfigPath=%q want %q", got, want)
	}

	// hooks.json shape: {"hooks": {<event>: [<group>...]}}
	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("hooks.json not valid JSON: %v\n%s", err, body)
	}
	hooks, ok := got["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("hooks.json missing top-level hooks block: %s", body)
	}
	for _, event := range codexEvents {
		groups, ok := hooks[event].([]any)
		if !ok || len(groups) == 0 {
			t.Errorf("event %s missing in hooks.json", event)
		}
	}

	// config.toml feature flag: [features].hooks = true must be present.
	cfgRaw, err := os.ReadFile(filepath.Join(r.opts.HomeDir, ".codex", "config.toml"))
	if err != nil {
		t.Fatalf("config.toml not written: %v", err)
	}
	if !bytes.Contains(cfgRaw, []byte("hooks = true")) {
		t.Errorf("config.toml missing hooks=true:\n%s", cfgRaw)
	}
}

func TestRegisterCodexIdempotent(t *testing.T) {
	t.Parallel()
	r := codexRegistry(t)
	if res := r.Register("codex"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}
	res := r.Register("codex")
	if res.Error != nil {
		t.Fatalf("second: %v", res.Error)
	}
	if len(res.HooksAdded) != 0 {
		t.Errorf("second register added %d (want 0)", len(res.HooksAdded))
	}
	if len(res.AlreadySet) != len(codexEvents) {
		t.Errorf("AlreadySet %d want %d", len(res.AlreadySet), len(codexEvents))
	}
}

func TestRegisterCodexPreservesExistingConfigToml(t *testing.T) {
	t.Parallel()
	r := codexRegistry(t)
	// Pre-existing config with unrelated keys our flag insert must
	// preserve. Mirrors a real ~/.codex/config.toml shape.
	pre := `personality = "pragmatic"

[projects."/tmp/foo"]
trust_level = "trusted"
`
	cfgPath := filepath.Join(r.opts.HomeDir, ".codex", "config.toml")
	if err := os.WriteFile(cfgPath, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	res := r.Register("codex")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	body, _ := os.ReadFile(cfgPath)
	if !bytes.Contains(body, []byte("personality")) {
		t.Errorf("personality lost from config.toml:\n%s", body)
	}
	if !bytes.Contains(body, []byte("/tmp/foo")) {
		t.Errorf("projects table lost from config.toml:\n%s", body)
	}
	if !bytes.Contains(body, []byte("hooks = true")) {
		t.Errorf("hooks=true not added:\n%s", body)
	}
}

func TestRegisterCodexConflict(t *testing.T) {
	t.Parallel()
	r := codexRegistry(t)
	// Pre-existing user-authored hook on PreToolUse — our register
	// must refuse without --force.
	hooksPath := filepath.Join(r.opts.HomeDir, ".codex", "hooks.json")
	pre := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/my-policy"}]}]}}`
	if err := os.WriteFile(hooksPath, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}
	res := r.Register("codex")
	if res.Error == nil {
		t.Fatalf("expected conflict error, got HooksAdded=%v", res.HooksAdded)
	}
	if !strings.Contains(res.Error.Error(), "non-observer hook") {
		t.Errorf("unexpected error: %v", res.Error)
	}
}

// TestRegisterCodexCrossBinaryPathRefresh mirrors
// TestRegisterClaudeCodeCrossBinaryPathRefresh for the codex
// registrar: a hooks.json carrying an observer-shaped entry that
// points at a different binary path must be recognised as ours via
// the ` hook codex ` content-heuristic and silently refreshed.
func TestRegisterCodexCrossBinaryPathRefresh(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}

	first, err := NewRegistry(Options{
		BinaryPath:    "/tmp/observer-A",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := first.Register("codex"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}

	second, err := NewRegistry(Options{
		BinaryPath:    "/usr/local/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	res := second.Register("codex")
	if res.Error != nil {
		t.Fatalf("second (cross-binary refresh): %v", res.Error)
	}
	if len(res.HooksAdded) != len(codexEvents) {
		t.Errorf("HooksAdded = %d want %d", len(res.HooksAdded), len(codexEvents))
	}

	body, _ := os.ReadFile(res.ConfigPath)
	if strings.Contains(string(body), "/tmp/observer-A") {
		t.Errorf("stale binary path leaked into refreshed hooks.json:\n%s", body)
	}
	if !strings.Contains(string(body), "/usr/local/bin/observer") {
		t.Errorf("new binary path missing from refreshed hooks.json:\n%s", body)
	}
}

func TestUnregisterCodexRemovesObserverEntries(t *testing.T) {
	t.Parallel()
	r := codexRegistry(t)
	if res := r.Register("codex"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	res := r.Unregister("codex")
	if res.Error != nil {
		t.Fatalf("Unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) != len(codexEvents) {
		t.Errorf("removed %d want %d", len(res.HooksRemoved), len(codexEvents))
	}
	body, _ := os.ReadFile(res.ConfigPath)
	if bytes.Contains(body, []byte("/opt/observer/bin/observer")) {
		t.Errorf("observer entries still present after unregister:\n%s", body)
	}
}

// TestUnregisterCodexRemovesCrossBinaryEntries mirrors the claude-
// code variant: a codex hooks.json carrying entries from a
// different observer binary path must be cleaned up via the
// content-heuristic.
func TestUnregisterCodexRemovesCrossBinaryEntries(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}

	first, err := NewRegistry(Options{
		BinaryPath:    "/tmp/observer-A",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := first.Register("codex"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}

	second, err := NewRegistry(Options{
		BinaryPath:    "/usr/local/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	res := second.Unregister("codex")
	if res.Error != nil {
		t.Fatalf("unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) != len(codexEvents) {
		t.Errorf("HooksRemoved = %d want %d (every cross-binary entry should be removed)",
			len(res.HooksRemoved), len(codexEvents))
	}

	body, _ := os.ReadFile(res.ConfigPath)
	if bytes.Contains(body, []byte("/tmp/observer-A")) {
		t.Errorf("stale observer-A entries left behind after cross-binary unregister:\n%s", body)
	}
}

func TestInstalledDetectsCodex(t *testing.T) {
	t.Parallel()
	r := codexRegistry(t)
	got := r.Installed()
	found := false
	for _, t := range got {
		if t == "codex" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Installed()=%v does not include codex", got)
	}
}

// TestObserverEntryHeuristicsAreOneWay pins the contract between the
// Linux/default and Windows-bridge ownership heuristics. It is
// deliberately ASYMMETRIC (it was symmetric — and named
// TestObserverEntryHeuristicsAreDisjoint — until the class-C2 fix in
// docs/plans/ide-surface-capture-remediation-plan-2026-09-02.md §1):
//
//   - the NATIVE heuristics (isObserverClaudeEntry /
//     isObserverCursorEntry) still REJECT wsl.exe-wrapped commands.
//     That is the load-bearing direction, added in v1.6.26: if both
//     registrar paths write the same settings.json (possible after
//     switching observer modes on one host), the native refresh path
//     must not rewrite the bridge's entries into native shape.
//   - the WINDOWS heuristics now ACCEPT the native shape as ours, so
//     the bridge can REPLACE a stale native `observer.exe hook <tool>`
//     entry — written by an earlier Windows-native npm install — without
//     --force. Before this, that entry read as a foreign third-party
//     hook, registration errored, and the stale native entry kept
//     writing the stranded Windows DB (audit IDE-11 / the split-brain
//     class in CLAUDE.md).
//
// Conversion is therefore one-way: native → bridge, never the reverse.
func TestObserverEntryHeuristicsAreOneWay(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		cmd         string
		wantNative  bool // Linux/default heuristic
		wantWindows bool // Windows-target heuristic (bridge OR native)
	}{
		{
			// C2: ours on BOTH targets. The native registrar refreshes
			// it in place; the Windows registrar replaces it with the
			// bridge command.
			name:        "claude native",
			cmd:         "/usr/local/bin/observer hook claude-code pre-tool",
			wantNative:  true,
			wantWindows: true,
		},
		{
			name:        "claude wsl bare",
			cmd:         "wsl.exe -d Ubuntu -- /home/u/observer hook claude-code pre-tool",
			wantNative:  false,
			wantWindows: true,
		},
		{
			name:        "claude wsl with msys prefix",
			cmd:         "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -- /home/u/observer hook claude-code pre-tool",
			wantNative:  false,
			wantWindows: true,
		},
		{
			name:        "claude foreign",
			cmd:         "/usr/local/bin/other-tool --flag value",
			wantNative:  false,
			wantWindows: false,
		},
	}
	for _, c := range cases {
		t.Run("claude:"+c.name, func(t *testing.T) {
			t.Parallel()
			if got := isObserverClaudeEntry(c.cmd); got != c.wantNative {
				t.Errorf("isObserverClaudeEntry(%q) = %v, want %v", c.cmd, got, c.wantNative)
			}
			if got := isObserverWindowsClaudeEntry(c.cmd); got != c.wantWindows {
				t.Errorf("isObserverWindowsClaudeEntry(%q) = %v, want %v", c.cmd, got, c.wantWindows)
			}
		})
	}

	cursorCases := []struct {
		name        string
		cmd         string
		wantNative  bool
		wantWindows bool
	}{
		{
			// C2: ours on BOTH targets — see the claude row above.
			name:        "cursor native",
			cmd:         "/usr/local/bin/observer hook cursor beforeShellExecution",
			wantNative:  true,
			wantWindows: true,
		},
		{
			// A third-party binary invoked with our argument shape. The
			// NATIVE heuristic is a deliberately loose substring test and
			// accepts it (the documented trade-off in
			// isObserverClaudeEntry); the widened WINDOWS heuristic is
			// TOKEN-based and does not — argv[0] must name an observer
			// binary. So C2 made the Windows side stricter here, not
			// looser.
			name:        "cursor third-party binary with our argument shape",
			cmd:         "/opt/acme/acme hook cursor beforeShellExecution",
			wantNative:  true,
			wantWindows: false,
		},
		{
			name:        "cursor wsl bare",
			cmd:         "wsl.exe -d Ubuntu -- /home/u/observer hook cursor beforeShellExecution",
			wantNative:  false,
			wantWindows: true,
		},
		{
			name:        "cursor wsl with msys prefix",
			cmd:         "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -- /home/u/observer hook cursor beforeShellExecution",
			wantNative:  false,
			wantWindows: true,
		},
	}
	for _, c := range cursorCases {
		t.Run("cursor:"+c.name, func(t *testing.T) {
			t.Parallel()
			if got := isObserverCursorEntry(c.cmd); got != c.wantNative {
				t.Errorf("isObserverCursorEntry(%q) = %v, want %v", c.cmd, got, c.wantNative)
			}
			if got := isObserverWindowsCursorEntry(c.cmd); got != c.wantWindows {
				t.Errorf("isObserverWindowsCursorEntry(%q) = %v, want %v", c.cmd, got, c.wantWindows)
			}
		})
	}
}

// TestRegisterClaudeCodeWindowsFreshInstall pins the wsl.exe-prefixed
// hook command shape against a fake Windows-side .claude/. Every entry
// in claudeCodeEvents must land in <home>/.claude/settings.json with
// the shape `wsl.exe -d <distro> -- <linux-bin> hook claude-code
// <event-arg> [--config <wsl-path>]`. The explicit
// WindowsClaudeHome option exercises the path that doesn't depend on
// /mnt/c presence at test time.
func TestRegisterClaudeCodeWindowsFreshInstall(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	claudeDir := filepath.Join(winHome, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:        "/home/marmutapp/superbased-observer/bin/observer",
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsClaudeHome: winHome,
		WSLDistro:         "Ubuntu-20.04",
		ConfigPath:        "/home/marmutapp/.observer/config.toml",
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("claude-code-windows")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if len(res.HooksAdded) != len(claudeCodeEvents) {
		t.Errorf("HooksAdded count = %d want %d", len(res.HooksAdded), len(claudeCodeEvents))
	}
	if res.ConfigPath != filepath.Join(claudeDir, "settings.json") {
		t.Errorf("ConfigPath = %q want %q", res.ConfigPath, filepath.Join(claudeDir, "settings.json"))
	}

	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(body, &settings); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, body)
	}
	hooksBlock, ok := settings["hooks"].(map[string]any)
	if !ok {
		t.Fatal("hooks block missing")
	}
	for _, event := range claudeCodeEvents {
		groups, ok := hooksBlock[event].([]any)
		if !ok || len(groups) == 0 {
			t.Errorf("event %s missing", event)
			continue
		}
		first, _ := groups[0].(map[string]any)
		hooks, _ := first["hooks"].([]any)
		if len(hooks) == 0 {
			t.Errorf("event %s has empty hooks slice", event)
			continue
		}
		hook0, _ := hooks[0].(map[string]any)
		cmd, _ := hook0["command"].(string)
		wantPrefix := "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- /home/marmutapp/superbased-observer/bin/observer hook claude-code " + hookEventArg(event)
		if !strings.HasPrefix(cmd, wantPrefix) {
			t.Errorf("event %s cmd = %q want prefix %q", event, cmd, wantPrefix)
		}
		if !strings.Contains(cmd, "--config '/home/marmutapp/.observer/config.toml'") {
			t.Errorf("event %s cmd missing --config: %q", event, cmd)
		}
	}
}

// TestRegisterClaudeCodeWindowsRequiresDistro pins the "missing distro"
// error path — without one, the wsl.exe wrapper would be ambiguous on
// a host with multiple distros and we'd write a broken settings.json.
func TestRegisterClaudeCodeWindowsRequiresDistro(t *testing.T) {
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	if err := os.MkdirAll(filepath.Join(winHome, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WSL_DISTRO_NAME", "")
	r, err := NewRegistry(Options{
		BinaryPath:        "/x",
		HomeDir:           wslHome,
		WindowsClaudeHome: winHome,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("claude-code-windows")
	if res.Error == nil {
		t.Fatal("expected error when distro unset, got nil")
	}
	if !strings.Contains(res.Error.Error(), "WSL distro unknown") {
		t.Errorf("error = %q want it to mention 'WSL distro unknown'", res.Error)
	}
}

// TestRegisterClaudeCodeWindowsIdempotent pins re-register safety: a
// second Register("claude-code-windows") with the same Options must
// surface every event as AlreadySet and NOT duplicate entries in the
// settings.json. Counts post-register groups under each event.
func TestRegisterClaudeCodeWindowsIdempotent(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	if err := os.MkdirAll(filepath.Join(winHome, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		BinaryPath:        "/bin/observer",
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsClaudeHome: winHome,
		WSLDistro:         "u20",
	}
	r1, _ := NewRegistry(opts)
	if res := r1.Register("claude-code-windows"); res.Error != nil {
		t.Fatalf("first: %v", res.Error)
	}
	r2, _ := NewRegistry(opts)
	res := r2.Register("claude-code-windows")
	if res.Error != nil {
		t.Fatalf("second: %v", res.Error)
	}
	if len(res.HooksAdded) != 0 {
		t.Errorf("second Register added %d hooks, want 0 (all should be AlreadySet)", len(res.HooksAdded))
	}
	if len(res.AlreadySet) != len(claudeCodeEvents) {
		t.Errorf("AlreadySet = %d want %d", len(res.AlreadySet), len(claudeCodeEvents))
	}
	body, _ := os.ReadFile(res.ConfigPath)
	var settings map[string]any
	_ = json.Unmarshal(body, &settings)
	hooks, _ := settings["hooks"].(map[string]any)
	for _, event := range claudeCodeEvents {
		groups, _ := hooks[event].([]any)
		if len(groups) != 1 {
			t.Errorf("event %s: got %d groups after idempotent re-register, want 1", event, len(groups))
		}
	}
}

// TestRegisterClaudeCodeWindowsConflictGuard pins the user-hook
// protection: a pre-existing non-observer command on any event causes
// Register to fail loudly (no --force). User's hook is left untouched.
func TestRegisterClaudeCodeWindowsConflictGuard(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	claudeDir := filepath.Join(winHome, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(claudeDir, "settings.json")
	prior := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"C:\\Users\\me\\my-hook.exe"}]}]}}`
	if err := os.WriteFile(settingsPath, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}
	r, _ := NewRegistry(Options{
		BinaryPath:        "/bin/observer",
		HomeDir:           wslHome,
		WindowsClaudeHome: winHome,
		WSLDistro:         "u20",
	})
	res := r.Register("claude-code-windows")
	if res.Error == nil {
		t.Fatal("expected conflict error, got nil")
	}
	if !strings.Contains(res.Error.Error(), "non-observer hook") {
		t.Errorf("error = %q want it to mention 'non-observer hook'", res.Error)
	}
	// User's hook must still be there — Register should not partial-
	// write before refusing.
	body, _ := os.ReadFile(settingsPath)
	if !strings.Contains(string(body), "my-hook.exe") {
		t.Errorf("user hook lost after conflict-guard failure: %s", body)
	}
}

// TestUnregisterClaudeCodeWindowsRoundTrip pins the install → uninstall
// cycle. After Unregister, observer entries are gone, user-authored
// entries on other events survive, and the checksum guard accepts the
// matched-checksum case.
func TestUnregisterClaudeCodeWindowsRoundTrip(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	claudeDir := filepath.Join(winHome, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(claudeDir, "settings.json")
	// Pre-existing user hook on PreCompact — observer skips it via the
	// matcher and our event-list, so this entry must survive both
	// Register and Unregister.
	prior := `{"hooks":{"FileChanged":[{"matcher":"*","hooks":[{"type":"command","command":"C:\\my-user-hook.exe"}]}]}}`
	if err := os.WriteFile(settingsPath, []byte(prior), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		BinaryPath:        "/bin/observer",
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsClaudeHome: winHome,
		WSLDistro:         "u20",
	}
	reg, _ := NewRegistry(opts)
	if res := reg.Register("claude-code-windows"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}

	unreg, _ := NewRegistry(opts)
	ures := unreg.Unregister("claude-code-windows")
	if ures.Error != nil {
		t.Fatalf("Unregister: %v", ures.Error)
	}
	if len(ures.HooksRemoved) != len(claudeCodeEvents) {
		t.Errorf("HooksRemoved = %d want %d", len(ures.HooksRemoved), len(claudeCodeEvents))
	}
	body, _ := os.ReadFile(settingsPath)
	if !strings.Contains(string(body), "my-user-hook.exe") {
		t.Errorf("user hook lost during Unregister: %s", body)
	}
	if strings.Contains(string(body), "hook claude-code") {
		t.Errorf("observer entry survived Unregister: %s", body)
	}
}

// TestInstalledClaudeCodeWindows pins the auto-detect contract:
// Installed() includes "claude-code-windows" once
// WindowsClaudeHome resolves to an existing directory. The explicit
// option path is exercised so the test doesn't depend on /mnt/c.
func TestInstalledClaudeCodeWindows(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	if err := os.MkdirAll(filepath.Join(winHome, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, _ := NewRegistry(Options{
		BinaryPath:        "/bin/observer",
		HomeDir:           wslHome,
		WindowsClaudeHome: winHome,
	})
	got := r.Installed()
	found := false
	for _, tool := range got {
		if tool == "claude-code-windows" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Installed()=%v does not include claude-code-windows", got)
	}
}

// --- Statusline registration tests (docs/plans/observer-statusline-plan-2026-07-30.md §5.1/§7) ---

// readStatuslineEntry reads back the "statusLine" key from path as a
// claudeStatuslineEntry, failing the test if it's missing or malformed.
func readStatuslineEntry(t *testing.T, path string) claudeStatuslineEntry {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(body, &settings); err != nil {
		t.Fatalf("parse %s: %v\n%s", path, err, body)
	}
	raw, ok := settings["statusLine"]
	if !ok {
		t.Fatalf("%s has no \"statusLine\" key", path)
	}
	var entry claudeStatuslineEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Fatalf("statusLine value not the expected shape: %v\n%s", err, raw)
	}
	return entry
}

func TestRegisterClaudeCodeStatuslineFreshInstall(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	res := r.RegisterClaudeCodeStatusline()
	if res.Error != nil {
		t.Fatalf("RegisterClaudeCodeStatusline: %v", res.Error)
	}
	if len(res.HooksAdded) != 1 || res.HooksAdded[0] != "statusLine" {
		t.Errorf("HooksAdded=%v want [statusLine]", res.HooksAdded)
	}

	entry := readStatuslineEntry(t, res.ConfigPath)
	if entry.Type != "command" {
		t.Errorf("type=%q want command", entry.Type)
	}
	if entry.Padding != 0 {
		t.Errorf("padding=%d want 0", entry.Padding)
	}
	if !strings.Contains(entry.Command, r.opts.BinaryPath) || !strings.HasSuffix(entry.Command, " statusline") {
		t.Errorf("command=%q does not look like <bin> statusline", entry.Command)
	}

	// The "hooks" key must not exist — this registration path never
	// touches it.
	body, _ := os.ReadFile(res.ConfigPath)
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(body, &settings)
	if _, ok := settings["hooks"]; ok {
		t.Error("statusline registration wrote a \"hooks\" key — it must never touch hooks")
	}

	// Checksum file should be written (recordChecksum is reused unchanged).
	csPath := filepath.Join(r.opts.HomeDir, ".observer", "hook_checksums.json")
	if _, err := os.Stat(csPath); err != nil {
		t.Errorf("checksum file not created: %v", err)
	}
}

// TestRegisterClaudeCodeStatuslineLeavesHooksUntouched registers hooks
// first, then statusline, and asserts the "hooks" block written by
// registerClaudeCode is byte-for-byte the same afterwards — the
// statusline registrar patches a sibling top-level key, never the
// "hooks" map itself.
func TestRegisterClaudeCodeStatuslineLeavesHooksUntouched(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	hookRes := r.Register("claude-code")
	if hookRes.Error != nil {
		t.Fatalf("Register(claude-code): %v", hookRes.Error)
	}
	before, err := os.ReadFile(hookRes.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var beforeSettings map[string]json.RawMessage
	if err := json.Unmarshal(before, &beforeSettings); err != nil {
		t.Fatal(err)
	}

	slRes := r.RegisterClaudeCodeStatusline()
	if slRes.Error != nil {
		t.Fatalf("RegisterClaudeCodeStatusline: %v", slRes.Error)
	}

	after, err := os.ReadFile(slRes.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var afterSettings map[string]json.RawMessage
	if err := json.Unmarshal(after, &afterSettings); err != nil {
		t.Fatal(err)
	}
	if string(beforeSettings["hooks"]) != string(afterSettings["hooks"]) {
		t.Errorf("\"hooks\" key changed after statusline registration:\nbefore=%s\nafter=%s", beforeSettings["hooks"], afterSettings["hooks"])
	}
	if _, ok := afterSettings["statusLine"]; !ok {
		t.Error("statusLine key missing after registration")
	}
}

func TestRegisterClaudeCodeStatuslineConflictBlocksWithoutForce(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	pre := `{"statusLine":{"type":"command","command":"/usr/local/bin/ccstatusline","padding":0}}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.RegisterClaudeCodeStatusline()
	if res.Error == nil {
		t.Fatal("expected conflict error for a foreign statusLine entry")
	}
	if !strings.Contains(res.Error.Error(), "ccstatusline") {
		t.Errorf("error %q does not name the existing foreign command", res.Error)
	}
	// The foreign entry must survive untouched.
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "ccstatusline") {
		t.Error("foreign statusLine entry was clobbered without --force")
	}

	// With --force, it overwrites.
	r.opts.Force = true
	res = r.RegisterClaudeCodeStatusline()
	if res.Error != nil {
		t.Fatalf("force register: %v", res.Error)
	}
	entry := readStatuslineEntry(t, path)
	if strings.Contains(entry.Command, "ccstatusline") {
		t.Error("--force did not overwrite the foreign entry")
	}
	if !strings.Contains(entry.Command, "statusline") {
		t.Errorf("forced entry does not look like ours: %+v", entry)
	}
}

// TestRegisterClaudeCodeStatuslineRefreshesStaleBinaryPath pins the
// refresh-on-drift behaviour: an existing entry recognised as
// observer-written (by isObserverStatuslineEntry) but pointing at a
// stale binary path is silently rewritten — no --force needed, unlike
// a genuinely foreign entry.
func TestRegisterClaudeCodeStatuslineRefreshesStaleBinaryPath(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	stale := `{"statusLine":{"type":"command","command":"/old/path/observer statusline","padding":0}}`
	if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.RegisterClaudeCodeStatusline()
	if res.Error != nil {
		t.Fatalf("RegisterClaudeCodeStatusline: %v", res.Error)
	}
	if len(res.AlreadySet) != 0 {
		t.Errorf("AlreadySet=%v want none — a stale binary path must refresh, not short-circuit", res.AlreadySet)
	}
	entry := readStatuslineEntry(t, path)
	if strings.Contains(entry.Command, "/old/path/") {
		t.Errorf("stale observer entry was not refreshed: %+v", entry)
	}
	if !strings.Contains(entry.Command, r.opts.BinaryPath) {
		t.Errorf("refreshed entry does not carry the current binary path: %+v", entry)
	}
}

// TestRegisterClaudeCodeStatuslineIdempotent pins BOTH the AlreadySet
// signal AND the "no needless rewrite" contract: a second identical
// run must not touch the file on disk (mtime unchanged) and must not
// re-record the checksum.
func TestRegisterClaudeCodeStatuslineIdempotent(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	first := r.RegisterClaudeCodeStatusline()
	if first.Error != nil {
		t.Fatalf("first: %v", first.Error)
	}

	fi1, err := os.Stat(first.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	csPath := filepath.Join(r.opts.HomeDir, ".observer", "hook_checksums.json")
	csBefore, err := os.ReadFile(csPath)
	if err != nil {
		t.Fatal(err)
	}

	// Sleep isn't reliable in CI; instead assert via content-equality AND
	// that no HooksAdded/error occurred, which is the behavioural contract
	// that implies "we returned before any write call".
	second := r.RegisterClaudeCodeStatusline()
	if second.Error != nil {
		t.Fatalf("second: %v", second.Error)
	}
	if len(second.HooksAdded) != 0 {
		t.Errorf("second run added %v — want no-op", second.HooksAdded)
	}
	if len(second.AlreadySet) != 1 || second.AlreadySet[0] != "statusLine" {
		t.Errorf("AlreadySet=%v want [statusLine]", second.AlreadySet)
	}

	fi2, err := os.Stat(first.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Errorf("settings.json mtime changed on idempotent re-run: %v -> %v", fi1.ModTime(), fi2.ModTime())
	}
	csAfter, err := os.ReadFile(csPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(csBefore) != string(csAfter) {
		t.Error("checksum file rewritten on idempotent re-run")
	}
}

func TestRegisterClaudeCodeStatuslinePreservesUnknownKeys(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	pre := `{"theme":"dark","permissions":{"allow":["bash"]},"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/other-hook"}]}]}}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.RegisterClaudeCodeStatusline()
	if res.Error != nil {
		t.Fatalf("RegisterClaudeCodeStatusline: %v", res.Error)
	}
	body, _ := os.ReadFile(path)
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["theme"] != "dark" {
		t.Errorf("theme lost: %v", got["theme"])
	}
	if _, ok := got["permissions"]; !ok {
		t.Error("permissions lost")
	}
	hooksBlock, ok := got["hooks"].(map[string]any)
	if !ok {
		t.Fatal("hooks block lost")
	}
	preHook, ok := hooksBlock["PreToolUse"].([]any)
	if !ok || len(preHook) == 0 {
		t.Fatal("PreToolUse hook group lost")
	}
	if _, ok := got["statusLine"]; !ok {
		t.Error("statusLine key missing")
	}
}

func TestUnregisterClaudeCodeStatuslineRemovesKeyEntirely(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	// Seed an unrelated key first so the file survives the unregister
	// (isolating "the key is removed entirely" from "the whole file is
	// removed when it becomes empty", which is covered separately by
	// TestUnregisterClaudeCodeStatuslineNoopWhenAbsent / the empty-file
	// removal branch exercised implicitly by the fresh-install-only case
	// below).
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	if err := os.WriteFile(path, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	regRes := r.RegisterClaudeCodeStatusline()
	if regRes.Error != nil {
		t.Fatalf("register: %v", regRes.Error)
	}

	unregRes := r.UnregisterClaudeCodeStatusline()
	if unregRes.Error != nil {
		t.Fatalf("UnregisterClaudeCodeStatusline: %v", unregRes.Error)
	}
	if len(unregRes.HooksRemoved) != 1 || unregRes.HooksRemoved[0] != "statusLine" {
		t.Errorf("HooksRemoved=%v want [statusLine]", unregRes.HooksRemoved)
	}

	body, err := os.ReadFile(regRes.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(body, &settings); err != nil {
		t.Fatal(err)
	}
	if settings["theme"] == nil || string(settings["theme"]) != `"dark"` {
		t.Errorf("unrelated \"theme\" key lost during unregister: %v", settings["theme"])
	}
	if _, ok := settings["statusLine"]; ok {
		t.Error("\"statusLine\" key still present after unregister — must be removed entirely, not blanked")
	}
}

// TestUnregisterClaudeCodeStatuslinePreservesHooksAndForeignEntry
// covers two things in one settings.json: unregistering statusline
// must (a) leave a co-resident "hooks" block untouched, and (b) never
// touch a FOREIGN "statusLine" belonging to another tool.
func TestUnregisterClaudeCodeStatuslinePreservesHooksAndForeignEntry(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	hookRes := r.Register("claude-code")
	if hookRes.Error != nil {
		t.Fatalf("Register(claude-code): %v", hookRes.Error)
	}
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	// Hand-inject a foreign statusLine into the same file after the hook
	// registration (simulating a user who wrote their own before ever
	// running `observer init --statusline`).
	body, _ := os.ReadFile(path)
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(body, &settings)
	settings["statusLine"] = json.RawMessage(`{"type":"command","command":"/usr/local/bin/ccstatusline","padding":0}`)
	patched, _ := json.Marshal(settings)
	if err := os.WriteFile(path, patched, 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.UnregisterClaudeCodeStatusline()
	if res.Error != nil {
		t.Fatalf("UnregisterClaudeCodeStatusline: %v", res.Error)
	}
	if !res.Skipped {
		t.Error("expected Skipped=true for a foreign statusLine entry")
	}
	if len(res.HooksKept) != 1 || res.HooksKept[0] != "statusLine" {
		t.Errorf("HooksKept=%v want [statusLine]", res.HooksKept)
	}

	after, _ := os.ReadFile(path)
	if !strings.Contains(string(after), "ccstatusline") {
		t.Error("foreign statusLine entry was removed — must be left untouched")
	}
	var afterSettings map[string]json.RawMessage
	if err := json.Unmarshal(after, &afterSettings); err != nil {
		t.Fatal(err)
	}
	if _, ok := afterSettings["hooks"]; !ok {
		t.Error("hooks block lost during statusline unregister")
	}
}

// TestUnregisterClaudeCodeStatuslineRemovesEmptyFile covers the other
// half of "removed entirely, not blanked": when statusLine was the
// ONLY top-level key, unregister removes settings.json rather than
// leaving an empty "{}" file behind.
func TestUnregisterClaudeCodeStatuslineRemovesEmptyFile(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	regRes := r.RegisterClaudeCodeStatusline()
	if regRes.Error != nil {
		t.Fatalf("register: %v", regRes.Error)
	}

	unregRes := r.UnregisterClaudeCodeStatusline()
	if unregRes.Error != nil {
		t.Fatalf("UnregisterClaudeCodeStatusline: %v", unregRes.Error)
	}
	if _, err := os.Stat(regRes.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("settings.json should be removed once empty, got err=%v", err)
	}
}

func TestUnregisterClaudeCodeStatuslineNoopWhenAbsent(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	// No file at all.
	res := r.UnregisterClaudeCodeStatusline()
	if res.Error != nil {
		t.Fatalf("unexpected error: %v", res.Error)
	}
	if !res.Skipped {
		t.Error("expected Skipped=true when settings.json doesn't exist")
	}

	// File exists but has no "statusLine" key.
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	if err := os.WriteFile(path, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res = r.UnregisterClaudeCodeStatusline()
	if res.Error != nil {
		t.Fatalf("unexpected error: %v", res.Error)
	}
	if !res.Skipped {
		t.Error("expected Skipped=true when \"statusLine\" key is absent")
	}
	if len(res.HooksRemoved) != 0 {
		t.Errorf("HooksRemoved=%v want none", res.HooksRemoved)
	}
}

// TestUnregisterClaudeCodeStatuslineChecksumDriftGuard pins the
// checksum-mismatch guard: once the file has been hand-edited since
// install (checksum mismatch), unregister refuses without --force and
// succeeds with it — mirroring unregisterClaudeCode's own guard.
func TestUnregisterClaudeCodeStatuslineChecksumDriftGuard(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	regRes := r.RegisterClaudeCodeStatusline()
	if regRes.Error != nil {
		t.Fatalf("register: %v", regRes.Error)
	}

	// Hand-edit the file (append an unrelated key) so its hash no longer
	// matches the recorded checksum, without touching "statusLine" itself.
	body, _ := os.ReadFile(regRes.ConfigPath)
	var settings map[string]json.RawMessage
	_ = json.Unmarshal(body, &settings)
	settings["theme"] = json.RawMessage(`"dark"`)
	patched, _ := json.Marshal(settings)
	if err := os.WriteFile(regRes.ConfigPath, patched, 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.UnregisterClaudeCodeStatusline()
	if res.Error == nil {
		t.Fatal("expected checksum-mismatch error without --force")
	}
	if res.ChecksumMatch {
		t.Error("ChecksumMatch=true but the file was hand-edited")
	}

	r.opts.Force = true
	res = r.UnregisterClaudeCodeStatusline()
	if res.Error != nil {
		t.Fatalf("force unregister: %v", res.Error)
	}
	if len(res.HooksRemoved) != 1 {
		t.Errorf("HooksRemoved=%v want [statusLine]", res.HooksRemoved)
	}
}

// TestObserverStatuslineEntryHeuristic pins isObserverStatuslineEntry's
// recognition contract directly (independent of the full read-modify-
// write path above).
func TestObserverStatuslineEntryHeuristic(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	cmd := shellQuoteIfNeeded(forwardSlashPath(r.opts.BinaryPath)) + " statusline"
	if !isObserverStatuslineEntry(cmd) {
		t.Errorf("isObserverStatuslineEntry(%q)=false, want true", cmd)
	}
	if isObserverStatuslineEntry("/usr/local/bin/ccstatusline") {
		t.Error("isObserverStatuslineEntry matched a foreign command with no \" statusline\" substring")
	}
	if isObserverStatuslineEntry("/usr/bin/faststatusline") {
		t.Error("isObserverStatuslineEntry matched a substring without the required leading space")
	}
}

// TestRegisterUnregisterClaudeCodeStatuslineDryRun pins the --dry-run
// contract: nothing is written to disk, but the result still reports
// what WOULD happen.
func TestRegisterUnregisterClaudeCodeStatuslineDryRun(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	r.opts.DryRun = true
	res := r.RegisterClaudeCodeStatusline()
	if res.Error != nil {
		t.Fatalf("RegisterClaudeCodeStatusline dry-run: %v", res.Error)
	}
	if len(res.HooksAdded) != 1 {
		t.Errorf("HooksAdded=%v want [statusLine]", res.HooksAdded)
	}
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	if _, err := os.ReadFile(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run wrote settings.json (err=%v) — must not write", err)
	}

	// Seed a real file, then dry-run an unregister and confirm the key
	// survives.
	r.opts.DryRun = false
	realRes := r.RegisterClaudeCodeStatusline()
	if realRes.Error != nil {
		t.Fatalf("register: %v", realRes.Error)
	}
	r.opts.DryRun = true
	unregRes := r.UnregisterClaudeCodeStatusline()
	if unregRes.Error != nil {
		t.Fatalf("UnregisterClaudeCodeStatusline dry-run: %v", unregRes.Error)
	}
	if len(unregRes.HooksRemoved) != 1 {
		t.Errorf("HooksRemoved=%v want [statusLine] reported even in dry-run", unregRes.HooksRemoved)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("dry-run unregister deleted the file: %v", err)
	}
	if !strings.Contains(string(body), "statusLine") {
		t.Error("dry-run unregister actually removed the key from disk — must not write")
	}
}

// --- Settings-writer hardening tests (adversarial review F7-F11) ---
//
// These pin the read-preserve-write contract of the SHARED
// settings.json machinery (readSettingsFile / decodeSettingsObject /
// writeJSONIndented) that the hooks, MCP and statusline registrars all
// funnel through — the statusline registrar merely made the pre-existing
// classes visible.

// TestSettingsJSONNullRefused pins F7(a): a settings.json whose whole
// body is the JSON literal `null` unmarshals a map to NIL, so the next
// `settings[key] = ...` used to PANIC ("assignment to entry in nil
// map"). It must instead be refused with an error naming the file — an
// explicit null is not a settings object, so treating it as {} and
// overwriting it would be a silent data decision we have no right to
// make.
func TestSettingsJSONNullRefused(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		run  func(r *Registry) error
	}{
		{"statusline-register", func(r *Registry) error { return r.RegisterClaudeCodeStatusline().Error }},
		{"statusline-unregister", func(r *Registry) error { return r.UnregisterClaudeCodeStatusline().Error }},
		{"hooks-register", func(r *Registry) error { return r.Register("claude-code").Error }},
		{"hooks-unregister", func(r *Registry) error { return r.Unregister("claude-code").Error }},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := setupRegistry(t)
			path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
			if err := os.WriteFile(path, []byte("null\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			err := tc.run(r) // must not panic
			if err == nil {
				t.Fatal("expected an error for a settings.json containing JSON null")
			}
			if !strings.Contains(err.Error(), "JSON null") || !strings.Contains(err.Error(), path) {
				t.Errorf("error %q does not name the malformed file and the null shape", err)
			}
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if strings.TrimSpace(string(body)) != "null" {
				t.Errorf("refused run mutated the file: %q", body)
			}
		})
	}
}

// TestSettingsJSONDuplicateTopLevelKeyRefused pins F7(b): duplicate
// top-level keys are silently collapsed to the LAST one by
// encoding/json, so a read-modify-write would destroy whichever copy
// another tool was reading. Detected by token-walking the top level and
// refused by name.
func TestSettingsJSONDuplicateTopLevelKeyRefused(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	pre := `{"theme":"dark","permissions":{"allow":["bash"]},"theme":"light"}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.RegisterClaudeCodeStatusline()
	if res.Error == nil {
		t.Fatal("expected an error for duplicate top-level keys")
	}
	if !strings.Contains(res.Error.Error(), `"theme"`) || !strings.Contains(res.Error.Error(), "duplicate") {
		t.Errorf("error %q does not name the duplicated key", res.Error)
	}
	body, _ := os.ReadFile(path)
	if string(body) != pre {
		t.Errorf("refused run mutated the file:\n got %s\nwant %s", body, pre)
	}

	// The hooks registrar shares the reader, so it refuses identically.
	hookRes := r.Register("claude-code")
	if hookRes.Error == nil || !strings.Contains(hookRes.Error.Error(), "duplicate") {
		t.Errorf("hooks registrar error=%v, want a duplicate-key refusal", hookRes.Error)
	}

	// A single occurrence of the same key is of course fine.
	if err := os.WriteFile(path, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := r.RegisterClaudeCodeStatusline(); res.Error != nil {
		t.Fatalf("well-formed file refused: %v", res.Error)
	}
}

// TestSettingsWriterPreservesUnrelatedValuesLosslessly pins F7(c): the
// shared writer re-indents unrelated top-level values from their RAW
// bytes (json.Indent) instead of decoding them through `any`. Decoding
// mangled every one of these: 2^53+1 through float64, number
// formatting, and \u-escaping of HTML-ish characters inside strings.
// Exercised through BOTH the statusline and the hooks registrar,
// because they share writeJSONIndented.
func TestSettingsWriterPreservesUnrelatedValuesLosslessly(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		run  func(r *Registry) error
	}{
		{"statusline", func(r *Registry) error { return r.RegisterClaudeCodeStatusline().Error }},
		{"hooks", func(r *Registry) error { return r.Register("claude-code").Error }},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := setupRegistry(t)
			path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
			pre := `{"bigInt":9007199254740993,"exact":1.500,"exp":1e3,"html":"a<b&c>d","nested":{"id":12345678901234567890}}`
			if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := tc.run(r); err != nil {
				t.Fatalf("register: %v", err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got := string(body)
			for _, want := range []string{
				"9007199254740993",     // not ...992
				"1.500",                // not 1.5 / 1
				"1e3",                  // not 1000
				"a<b&c>d",              // not a\u003cb\u0026c\u003ed
				"12345678901234567890", // beyond float64 entirely
			} {
				if !strings.Contains(got, want) {
					t.Errorf("value %q did not round-trip losslessly:\n%s", want, got)
				}
			}
			// And the result is still valid JSON with our key added.
			var settings map[string]json.RawMessage
			if err := json.Unmarshal(body, &settings); err != nil {
				t.Fatalf("writer produced invalid JSON: %v\n%s", err, got)
			}
			if len(settings) != 6 {
				t.Errorf("top-level key count=%d want 6 (5 preserved + ours): %v", len(settings), got)
			}
		})
	}
}

// TestObserverStatuslineEntryOwnership pins F8: " statusline" as a bare
// substring is not an ownership signal. Ours = an observer-basename
// executable whose FIRST argument is exactly "statusline".
func TestObserverStatuslineEntryOwnership(t *testing.T) {
	t.Parallel()
	ours := []string{
		"/opt/observer/bin/observer statusline",
		"observer statusline",
		"'/home/u/My Stuff/observer' statusline",
		`D:/programsx/superbased-observer/bin/observer.exe statusline`,
		`"C:/Program Files/observer/observer.exe" statusline`,
		"/usr/local/bin/observer-v1.8.3 statusline",
		"/tmp/observer-A statusline",
		"/opt/bin/superbased statusline",
		"/opt/observer/bin/observer statusline --theme compact", // future flag-carrying variant of OUR command
	}
	for _, cmd := range ours {
		if !isObserverStatuslineEntry(cmd) {
			t.Errorf("isObserverStatuslineEntry(%q)=false, want true (ours)", cmd)
		}
	}
	foreign := []string{
		"node /opt/acme statusline --theme compact", // the F8 report case
		"/usr/local/bin/ccstatusline",
		"/usr/bin/faststatusline",
		"/usr/local/bin/ccstatusline statusline",
		"python3 -m ccstatusline statusline",
		"/opt/acme/observer-ish/bin/acme statusline", // observer only in a DIRECTORY name
		"/opt/observer/bin/observer hook claude-code session-start",
		"/opt/observer/bin/observer status --statusline",
		"bash -c 'observer statusline'", // wrapper shape we never write
		"",
		"'/opt/observer/bin/observer statusline", // unbalanced quote ⇒ ambiguous ⇒ foreign
	}
	for _, cmd := range foreign {
		if isObserverStatuslineEntry(cmd) {
			t.Errorf("isObserverStatuslineEntry(%q)=true, want false (foreign)", cmd)
		}
	}
}

// TestRegisterClaudeCodeStatuslineForeignStatuslineSubcommandBlocks is
// the F8 end-to-end: a third-party statusline tool invoked as
// `<exe> statusline ...` is FOREIGN — register blocks without --force
// and unregister leaves it alone.
func TestRegisterClaudeCodeStatuslineForeignStatuslineSubcommandBlocks(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	pre := `{"statusLine":{"type":"command","command":"node /opt/acme statusline --theme compact","padding":0}}`
	if err := os.WriteFile(path, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}

	res := r.RegisterClaudeCodeStatusline()
	if res.Error == nil {
		t.Fatal("expected a conflict error for a foreign `<exe> statusline` command")
	}
	if !strings.Contains(res.Error.Error(), "/opt/acme") || !strings.Contains(res.Error.Error(), "--force") {
		t.Errorf("error %q should name the foreign command and the --force escape", res.Error)
	}
	body, _ := os.ReadFile(path)
	if string(body) != pre {
		t.Errorf("foreign statusLine was rewritten:\n%s", body)
	}

	// Uninstall must not adopt-and-delete it either.
	unreg := r.UnregisterClaudeCodeStatusline()
	if unreg.Error != nil {
		t.Fatalf("unregister: %v", unreg.Error)
	}
	if len(unreg.HooksKept) != 1 || unreg.HooksKept[0] != "statusLine" {
		t.Errorf("HooksKept=%v want [statusLine] — a foreign statusline must be kept", unreg.HooksKept)
	}
	body, _ = os.ReadFile(path)
	if !strings.Contains(string(body), "/opt/acme") {
		t.Error("uninstall removed a foreign statusline entry")
	}
}

// TestRegisterClaudeCodeStatuslineRefreshesOtherObserverPath is F8's
// other half: OUR entry written by a differently-installed observer
// binary (different directory, suffixed name) still refreshes silently.
func TestRegisterClaudeCodeStatuslineRefreshesOtherObserverPath(t *testing.T) {
	t.Parallel()
	for _, stale := range []string{
		"/usr/lib/node_modules/@superbased/observer/bin/observer statusline",
		"/usr/local/bin/observer-v1.8.3 statusline",
		`'C:/Program Files/observer/observer.exe' statusline`,
	} {
		stale := stale
		t.Run(stale, func(t *testing.T) {
			t.Parallel()
			r := setupRegistry(t)
			path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
			body, err := json.Marshal(map[string]any{
				"statusLine": map[string]any{"type": "command", "command": stale, "padding": 0},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			res := r.RegisterClaudeCodeStatusline()
			if res.Error != nil {
				t.Fatalf("a differently-installed observer entry should refresh, got: %v", res.Error)
			}
			entry := readStatuslineEntry(t, path)
			if !strings.Contains(entry.Command, r.opts.BinaryPath) {
				t.Errorf("entry not refreshed to the current binary: %+v", entry)
			}
		})
	}
}

// TestSettingsWriterUsesUniqueTempAndLeavesNoArtifacts pins F9(a): the
// writer must not use a FIXED `settings.json.tmp` (two observer
// processes would splice each other's half-written body), and must
// leave neither temp nor lock files behind on success.
func TestSettingsWriterUsesUniqueTempAndLeavesNoArtifacts(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	dir := filepath.Join(r.opts.HomeDir, ".claude")
	path := filepath.Join(dir, "settings.json")

	if res := r.Register("claude-code"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if res := r.RegisterClaudeCodeStatusline(); res.Error != nil {
		t.Fatalf("RegisterClaudeCodeStatusline: %v", res.Error)
	}

	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("fixed-name temp file %s exists (err=%v) — temp names must be unique", path+".tmp", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "settings.json" {
			continue
		}
		t.Errorf("leftover artifact in %s: %s (temp/lock files must be cleaned up)", dir, e.Name())
	}

	// Mutation-detecting half: OCCUPY the old fixed temp name with a
	// DIRECTORY. A writer that still used `<path>.tmp` cannot write
	// there and would fail; a unique os.CreateTemp name is unaffected.
	blocker := path + ".tmp"
	if err := os.Mkdir(blocker, 0o755); err != nil {
		t.Fatal(err)
	}
	r.opts.BinaryPath = "/opt/observer3/bin/observer" // force a real rewrite
	if res := r.RegisterClaudeCodeStatusline(); res.Error != nil {
		t.Fatalf("write failed with %s occupied — the temp name is not unique: %v", blocker, res.Error)
	}
	entry := readStatuslineEntry(t, path)
	if !strings.Contains(entry.Command, "/opt/observer3/") {
		t.Errorf("refresh did not land: %+v", entry)
	}
	if fi, err := os.Stat(blocker); err != nil || !fi.IsDir() {
		t.Errorf("the occupied fixed temp name was disturbed (err=%v)", err)
	}
}

// TestSettingsWriterRereadsBeforeMutating pins F9(c): every
// registration takes the lock and then reads a FRESH snapshot, so a
// key another process added between our two write windows is preserved
// rather than clobbered by a stale in-memory copy.
func TestSettingsWriterRereadsBeforeMutating(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")

	if res := r.RegisterClaudeCodeStatusline(); res.Error != nil {
		t.Fatalf("first register: %v", res.Error)
	}

	// Simulate another process editing the file between our locked
	// windows (the lock is released when the call returns).
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var external map[string]json.RawMessage
	if err := json.Unmarshal(body, &external); err != nil {
		t.Fatal(err)
	}
	external["externalKey"] = json.RawMessage(`{"added":"by-another-process"}`)
	patched, err := json.Marshal(external)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, patched, 0o600); err != nil {
		t.Fatal(err)
	}

	// A second registration that actually rewrites the file (binary path
	// drifted, so it's a refresh, not a no-op).
	r.opts.BinaryPath = "/opt/observer2/bin/observer"
	if res := r.RegisterClaudeCodeStatusline(); res.Error != nil {
		t.Fatalf("second register: %v", res.Error)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(after, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["externalKey"]; !ok {
		t.Errorf("externally-added key lost by the second registration:\n%s", after)
	}
	entry := readStatuslineEntry(t, path)
	if !strings.Contains(entry.Command, "/opt/observer2/") {
		t.Errorf("second registration did not refresh the command: %+v", entry)
	}
}

// TestConcurrentSettingsWritersDoNotCorrupt exercises F9(b) under
// -race: many observer processes-worth of registrars hammering ONE
// settings.json must each complete without error and leave a valid,
// complete file (never a spliced temp body, never a lost unrelated
// key).
//
// Each registry gets its OWN ChecksumsPath: hook_checksums.json is a
// separate unsynchronized read-modify-write (a pre-existing race
// outside this file-set's five findings), and sharing it here would
// test that instead of what this test is about.
func TestConcurrentSettingsWritersDoNotCorrupt(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.WriteFile(path, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	const writers = 8
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := NewRegistry(Options{
				BinaryPath:    fmt.Sprintf("/opt/observer-%d/bin/observer", i),
				HomeDir:       home,
				ChecksumsPath: filepath.Join(home, fmt.Sprintf(".observer-%d", i), "hook_checksums.json"),
			})
			if err != nil {
				errs[i] = err
				return
			}
			errs[i] = r.RegisterClaudeCodeStatusline().Error
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("writer %d: %v", i, err)
		}
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("settings.json corrupted by concurrent writers: %v\n%s", err, body)
	}
	if string(got["theme"]) != `"dark"` {
		t.Errorf("unrelated key lost: theme=%s", got["theme"])
	}
	entry := readStatuslineEntry(t, path)
	if !isObserverStatuslineEntry(entry.Command) {
		t.Errorf("final statusLine is not a well-formed observer entry: %+v", entry)
	}
}

// TestSettingsWriterFollowsSymlink pins F10: a dotfile-manager setup
// where ~/.claude/settings.json is a SYMLINK into a tracked repo must
// keep its link — we rewrite the TARGET, not replace the link with a
// regular file.
func TestSettingsWriterFollowsSymlink(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	dotfiles := t.TempDir()
	target := filepath.Join(dotfiles, "claude-settings.json")
	if err := os.WriteFile(target, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".claude", "settings.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this platform/privilege level: %v", err)
	}

	r, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.RegisterClaudeCodeStatusline(); res.Error != nil {
		t.Fatalf("RegisterClaudeCodeStatusline: %v", res.Error)
	}

	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("settings.json is no longer a symlink — the link was replaced by a regular file")
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("symlink target is not valid JSON: %v\n%s", err, body)
	}
	if _, ok := got["statusLine"]; !ok {
		t.Errorf("symlink TARGET did not receive the statusLine key:\n%s", body)
	}
	if string(got["theme"]) != `"dark"` {
		t.Errorf("target's existing key lost: theme=%s", got["theme"])
	}
	// No temp file stranded in the target's directory.
	entries, err := os.ReadDir(dotfiles)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(target) {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("temp artifacts left beside the symlink target: %v", names)
	}
}

// TestSettingsFileOverSizeCapRefused pins F11: settings.json is read
// with a 5 MiB cap checked via Stat BEFORE the read; an over-cap file is
// refused with no mutation rather than slurped into memory.
func TestSettingsFileOverSizeCapRefused(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")

	pad := bytes.Repeat([]byte("a"), int(maxSettingsFileBytes))
	body := append(append([]byte(`{"pad":"`), pad...), []byte(`"}`)...)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() <= maxSettingsFileBytes {
		t.Fatalf("test fixture is %d bytes, not over the %d-byte cap", fi.Size(), maxSettingsFileBytes)
	}

	res := r.RegisterClaudeCodeStatusline()
	if res.Error == nil {
		t.Fatal("expected an error for an over-cap settings.json")
	}
	if !strings.Contains(res.Error.Error(), "limit") || !strings.Contains(res.Error.Error(), path) {
		t.Errorf("error %q should name the file and the size limit", res.Error)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != fi.Size() {
		t.Errorf("over-cap file was mutated: %d -> %d bytes", fi.Size(), after.Size())
	}

	// The hooks registrar shares the reader — same refusal.
	if hookRes := r.Register("claude-code"); hookRes.Error == nil || !strings.Contains(hookRes.Error.Error(), "limit") {
		t.Errorf("hooks registrar error=%v, want a size-cap refusal", hookRes.Error)
	}

	// Just UNDER the cap is read normally.
	small := append(append([]byte(`{"pad":"`), bytes.Repeat([]byte("a"), 1024)...), []byte(`"}`)...)
	if err := os.WriteFile(path, small, 0o600); err != nil {
		t.Fatal(err)
	}
	if res := r.RegisterClaudeCodeStatusline(); res.Error != nil {
		t.Fatalf("under-cap file refused: %v", res.Error)
	}
}

// TestLockSettingsFileBreaksStaleLock pins the stale-lock escape hatch:
// a lock file left behind by a crashed observer must not wedge
// registration forever.
func TestLockSettingsFileBreaksStaleLock(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")
	lockPath := path + settingsLockSuffix
	if err := os.WriteFile(lockPath, []byte("pid=999999 acquired=whenever\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-2 * settingsLockStale)
	if err := os.Chtimes(lockPath, stale, stale); err != nil {
		t.Fatal(err)
	}

	res := r.RegisterClaudeCodeStatusline()
	if res.Error != nil {
		t.Fatalf("a stale lock must be broken, got: %v", res.Error)
	}
	if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("lock file not released after registration (err=%v)", err)
	}
	readStatuslineEntry(t, path) // and the write actually happened
}

// TestLockSettingsFileHeldBlocksSecondWriter pins that a live lock is
// respected: while one writer holds it, another times out with an
// actionable error instead of racing the read-modify-write.
func TestLockSettingsFileHeldBlocksSecondWriter(t *testing.T) {
	t.Parallel()
	r := setupRegistry(t)
	path := filepath.Join(r.opts.HomeDir, ".claude", "settings.json")

	unlock, err := lockSettingsFile(path)
	if err != nil {
		t.Fatal(err)
	}

	res := r.RegisterClaudeCodeStatusline()
	if res.Error == nil {
		t.Fatal("expected a lock-timeout error while the lock is held")
	}
	if !strings.Contains(res.Error.Error(), "waiting for") {
		t.Errorf("error %q does not explain the lock wait", res.Error)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("blocked registration still wrote settings.json (err=%v)", err)
	}

	unlock()
	if res := r.RegisterClaudeCodeStatusline(); res.Error != nil {
		t.Fatalf("registration after release: %v", res.Error)
	}
	readStatuslineEntry(t, path)
}
