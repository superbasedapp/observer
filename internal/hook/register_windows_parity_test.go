package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// --- Class C2: cross-OS hook-bridge ownership parity -------------------------
//
// docs/plans/ide-surface-capture-remediation-plan-2026-09-02.md §1 C2 /
// audit finding IDE-11. The `*-windows` registrars used to classify a
// NATIVE `observer.exe hook <tool> …` entry (written by an earlier
// Windows-native npm `observer init`) as a FOREIGN hook: the bridge
// registration errored without --force and the stale native entry kept
// writing the stranded Windows DB. These tests pin the widened ownership
// predicate — native entries are OURS on the Windows targets and get
// replaced by the bridge command, while genuinely foreign hooks still
// conflict.

// TestIsObserverAnyHookEntry is the unit table for the shared ownership
// predicate every `*-windows` registrar now consults. One row per
// command shape that shows up in a real config file.
func TestIsObserverAnyHookEntry(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cmd  string
		tool string
		want bool
	}{
		{
			name: "native windows exe, forward slashes, bare",
			cmd:  "C:/Users/u/AppData/Roaming/npm/node_modules/@superbased/observer-win32-x64/bin/observer.exe hook cursor stop --config C:/Users/u/.observer/config.toml",
			tool: "cursor",
			want: true,
		},
		{
			name: "native windows exe, back slashes, bare",
			cmd:  `C:\Users\u\AppData\Roaming\npm\observer.exe hook cursor stop --config C:\Users\u\.observer\config.toml`,
			tool: "cursor",
			want: true,
		},
		{
			name: "native windows exe, single-quoted back-slash path (v1.6.25 shape)",
			cmd:  `'D:\programsx\superbased-observer\bin\observer.exe' hook claude-code post-tool-use`,
			tool: "claude-code",
			want: true,
		},
		{
			name: "native windows exe, double-quoted forward-slash path",
			cmd:  `"C:/Users/u/AppData/Roaming/npm/node_modules/@superbased/observer-win32-x64/bin/observer.exe" hook claude-code PostToolUse`,
			tool: "claude-code",
			want: true,
		},
		{
			name: "native linux binary",
			cmd:  "/home/u/superbased-observer/bin/observer hook codex SessionStart",
			tool: "codex",
			want: true,
		},
		{
			name: "suffixed binary name (versioned / A-B build)",
			cmd:  "/tmp/observer-A hook cursor stop",
			tool: "cursor",
			want: true,
		},
		{
			name: "wsl.exe bridge wrapper",
			cmd:  "wsl.exe -d Ubuntu-20.04 -- /home/u/bin/observer hook cursor stop --config '/home/u/.observer/config.toml'",
			tool: "cursor",
			want: true,
		},
		{
			name: "MSYS-prefixed wsl.exe bridge wrapper",
			cmd:  "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- /home/u/bin/observer hook claude-code session-start",
			tool: "claude-code",
			want: true,
		},
		{
			name: "cmd.exe-quoted bridge wrapper (codex-windows shape)",
			cmd:  `wsl.exe -d Ubuntu-20.04 -- "/home/u/my dir/observer" hook codex SessionStart`,
			tool: "codex",
			want: true,
		},
		{
			name: "tool mismatch: cursor entry probed as claude-code",
			cmd:  "/home/u/bin/observer hook cursor stop",
			tool: "claude-code",
			want: false,
		},
		{
			name: "tool mismatch: claude-code entry probed as cursor",
			cmd:  "wsl.exe -d Ubuntu -- /home/u/bin/observer hook claude-code stop",
			tool: "cursor",
			want: false,
		},
		{
			name: "foreign command",
			cmd:  "powershell.exe Write-Host hi",
			tool: "cursor",
			want: false,
		},
		{
			name: "foreign binary that merely mentions the hook vocabulary",
			cmd:  `/opt/acme/audit --note "run hook cursor stop"`,
			tool: "cursor",
			want: false,
		},
		{
			name: "foreign binary invoked with our argument shape",
			cmd:  "/opt/acme/acme hook cursor stop",
			tool: "cursor",
			want: false,
		},
		{
			name: "bridge wrapper with no -- separator is not understood",
			cmd:  "wsl.exe /home/u/bin/observer hook cursor stop",
			tool: "cursor",
			want: false,
		},
		{
			name: "empty command",
			cmd:  "",
			tool: "cursor",
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := isObserverAnyHookEntry(c.cmd, c.tool); got != c.want {
				t.Errorf("isObserverAnyHookEntry(%q, %q) = %v, want %v", c.cmd, c.tool, got, c.want)
			}
		})
	}
}

// nativeCursorHooksJSON is a Windows-side ~/.cursor/hooks.json holding a
// NATIVE observer entry per event — exactly what a Windows-native npm
// `observer init --cursor` leaves behind, and what audit IDE-11 found on
// the live box.
func nativeCursorHooksJSON(t *testing.T, binary string) []byte {
	t.Helper()
	hooks := map[string][]cursorHookEntry{}
	for _, event := range cursorEvents {
		hooks[event] = []cursorHookEntry{{
			Command: binary + " hook cursor " + event + ` --config C:/Users/u/.observer/config.toml`,
		}}
	}
	body, err := json.Marshal(map[string]any{"version": 1, "hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestRegisterCursorWindowsReplacesNativeObserverEntry is the C2
// regression pin for cursor: a hooks.json whose entries are native
// `observer.exe hook cursor <event>` commands must register WITHOUT
// --force, and each event must end up with exactly ONE entry — the
// wsl.exe bridge command. A leftover native entry would keep firing the
// Windows binary against the stranded Windows DB (split-brain).
func TestRegisterCursorWindowsReplacesNativeObserverEntry(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome)
	cursorDir := filepath.Join(winHome, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	nativeBin := `C:/Users/u/AppData/Roaming/npm/node_modules/@superbased/observer-win32-x64/bin/observer.exe`
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := os.WriteFile(hooksPath, nativeCursorHooksJSON(t, nativeBin), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := NewRegistry(Options{
		BinaryPath:        "/home/u/superbased-observer/bin/observer",
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsCursorHome: winHome,
		WSLDistro:         "Ubuntu-20.04",
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("cursor-windows") // NO Force
	if res.Error != nil {
		t.Fatalf("Register(cursor-windows) over a native observer entry: %v", res.Error)
	}
	if len(res.HooksAdded) != len(cursorEvents) {
		t.Errorf("HooksAdded = %d want %d", len(res.HooksAdded), len(cursorEvents))
	}

	entries := readCursorHookEntries(t, hooksPath)
	for _, event := range cursorEvents {
		got := entries[event]
		if len(got) != 1 {
			t.Errorf("event %s has %d entries, want exactly 1 (the bridge command): %v", event, len(got), got)
			continue
		}
		if !strings.HasPrefix(got[0], "wsl.exe -d Ubuntu-20.04 -- /home/u/superbased-observer/bin/observer hook cursor "+event) {
			t.Errorf("event %s cmd = %q, want the wsl.exe bridge command", event, got[0])
		}
	}
	if body, _ := os.ReadFile(hooksPath); strings.Contains(string(body), nativeBin) {
		t.Errorf("stale native observer entry survived the refresh:\n%s", body)
	}
}

// TestRegisterCursorWindowsForeignEntryStillConflicts is the negative
// half of the C2 widening: broadening "ours" to native observer entries
// must NOT broaden it to a third-party command that merely resembles
// one. Both a plain foreign hook and a foreign binary invoked with our
// argument shape must still refuse without --force.
func TestRegisterCursorWindowsForeignEntryStillConflicts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		command string
	}{
		{"plain foreign hook", "powershell.exe Write-Host hi"},
		{"foreign binary with our argument shape", "C:/Program Files/acme/acme.exe hook cursor stop"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			wslHome := t.TempDir()
			winHome := nestedWinHome(t, wslHome)
			cursorDir := filepath.Join(winHome, ".cursor")
			if err := os.MkdirAll(cursorDir, 0o755); err != nil {
				t.Fatal(err)
			}
			hooksPath := filepath.Join(cursorDir, "hooks.json")
			body, err := json.Marshal(map[string]any{
				"version": 1,
				"hooks":   map[string][]cursorHookEntry{"stop": {{Command: c.command}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(hooksPath, body, 0o644); err != nil {
				t.Fatal(err)
			}
			r, err := NewRegistry(Options{
				BinaryPath:        "/home/u/bin/observer",
				HomeDir:           wslHome,
				ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
				WindowsCursorHome: winHome,
				WSLDistro:         "Ubuntu-20.04",
			})
			if err != nil {
				t.Fatal(err)
			}
			res := r.Register("cursor-windows")
			if res.Error == nil {
				t.Fatalf("Register(cursor-windows) silently overwrote a foreign hook %q", c.command)
			}
			if !strings.Contains(res.Error.Error(), "non-observer") {
				t.Errorf("error = %q, want it to mention 'non-observer'", res.Error)
			}
		})
	}
}

// TestUnregisterCursorWindowsRemovesBridgeEntry pins FIX cluster item
// 7b: Register's switch has had a "cursor-windows" case since the
// bridge was built, but Unregister's switch never got the matching
// case (and no unregisterCursorWindows existed at all) — so
// `observer uninstall --cursor` (which resolves through Unregister)
// could never remove what registerCursorWindows had written. Seeds a
// registered bridge alongside an unrelated top-level key, an
// unrelated event, and a foreign entry sharing the SAME event as
// observer's own — asserts the bridge entry is gone and every other
// byte survives untouched, mirroring B5's raw-preservation style
// (register_b5_raw_preservation_test.go).
func TestUnregisterCursorWindowsRemovesBridgeEntry(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome)
	cursorDir := filepath.Join(winHome, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}

	r, err := NewRegistry(Options{
		BinaryPath:        "/home/u/superbased-observer/bin/observer",
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsCursorHome: winHome,
		WSLDistro:         "Ubuntu-20.04",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Register("cursor-windows"); res.Error != nil {
		t.Fatalf("Register(cursor-windows): %v", res.Error)
	}

	hooksPath := filepath.Join(cursorDir, "hooks.json")

	// Splice in an unrelated top-level key, an unrelated event untouched
	// by this registrar, and a foreign entry sharing the SAME event
	// ("stop") as observer's own bridge entry.
	raw, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["some_other_extension_key"] = json.RawMessage(`{"kept":true}`)
	var hooks map[string][]cursorHookEntry
	if err := json.Unmarshal(doc["hooks"], &hooks); err != nil {
		t.Fatal(err)
	}
	hooks["unrelatedEvent"] = []cursorHookEntry{{Command: "powershell.exe some-other-tool.exe"}}
	hooks["stop"] = append(hooks["stop"], cursorHookEntry{Command: "powershell.exe acme-policy.exe stop"})
	hooksJSON, err := json.Marshal(hooks)
	if err != nil {
		t.Fatal(err)
	}
	doc["hooks"] = hooksJSON
	spliced, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hooksPath, spliced, 0o644); err != nil {
		t.Fatal(err)
	}
	// The registrar's own checksum was recorded against the PRE-splice
	// content, so bring it forward the same way an operator's own
	// hand-edit would legitimately need --force for on a real drift —
	// use --force here purely to get past that guard and isolate the
	// removal-and-preservation behavior under test.
	forced, err := NewRegistry(Options{
		BinaryPath:        r.opts.BinaryPath,
		HomeDir:           wslHome,
		ChecksumsPath:     r.opts.ChecksumsPath,
		WindowsCursorHome: winHome,
		WSLDistro:         "Ubuntu-20.04",
		Force:             true,
	})
	if err != nil {
		t.Fatal(err)
	}

	res := forced.Unregister("cursor-windows")
	if res.Error != nil {
		t.Fatalf("Unregister(cursor-windows): %v", res.Error)
	}
	if len(res.HooksRemoved) == 0 {
		t.Fatal("HooksRemoved is empty, want at least the bridge-covered events")
	}

	entries := readCursorHookEntries(t, hooksPath)
	for event, cmds := range entries {
		for _, cmd := range cmds {
			if strings.Contains(cmd, "hook cursor "+event) && strings.HasPrefix(cmd, "wsl.exe") {
				t.Errorf("event %s still carries the observer bridge command: %q", event, cmd)
			}
		}
	}
	if got := entries["unrelatedEvent"]; len(got) != 1 || got[0] != "powershell.exe some-other-tool.exe" {
		t.Errorf("unrelatedEvent survivors = %v, want the untouched foreign entry preserved", got)
	}
	if got := entries["stop"]; !slices.Contains(got, "powershell.exe acme-policy.exe stop") {
		t.Errorf("stop survivors = %v, want the foreign sibling entry preserved", got)
	}

	body, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	var final map[string]json.RawMessage
	if err := json.Unmarshal(body, &final); err != nil {
		t.Fatal(err)
	}
	// writeJSONIndented re-serializes with indentation (like every other
	// writer in this file), so compare the VALUE, not raw bytes — the
	// key's content must survive untouched even though whitespace does not.
	var kept struct {
		Kept bool `json:"kept"`
	}
	if err := json.Unmarshal(final["some_other_extension_key"], &kept); err != nil || !kept.Kept {
		t.Errorf("unrelated top-level key not preserved: %s (err=%v)", final["some_other_extension_key"], err)
	}
}

// readCursorHookEntries decodes a cursor hooks.json into
// event → []command.
func readCursorHookEntries(t *testing.T, path string) map[string][]string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings struct {
		Hooks map[string][]cursorHookEntry `json:"hooks"`
	}
	if err := json.Unmarshal(body, &settings); err != nil {
		t.Fatalf("hooks.json is not valid JSON: %v\n%s", err, body)
	}
	out := map[string][]string{}
	for event, entries := range settings.Hooks {
		for _, e := range entries {
			out[event] = append(out[event], e.Command)
		}
	}
	return out
}

// nativeClaudeSettingsJSON is a Windows-side ~/.claude/settings.json
// whose hook groups hold NATIVE `"<...>/observer.exe" hook claude-code
// <event>` commands — the shape a Windows-native npm `observer init
// --claude-code` writes.
func nativeClaudeSettingsJSON(t *testing.T, binary string) []byte {
	t.Helper()
	hooks := map[string][]claudeHookGroup{}
	for _, event := range claudeCodeEvents {
		hooks[event] = []claudeHookGroup{{
			Matcher: "*",
			Hooks: []claudeHookCommand{{
				Type:    "command",
				Command: `"` + binary + `" hook claude-code ` + hookEventArg(event) + ` --config "C:/Users/u/.observer/config.toml"`,
			}},
		}}
	}
	body, err := json.Marshal(map[string]any{"hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestRegisterClaudeCodeWindowsReplacesNativeObserverEntry is the C2
// regression pin for claude-code: native observer hook groups in the
// Windows-side settings.json are OURS, so the bridge replaces them
// without --force and leaves exactly one group per event.
func TestRegisterClaudeCodeWindowsReplacesNativeObserverEntry(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome)
	claudeDir := filepath.Join(winHome, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	nativeBin := `C:/Users/u/AppData/Roaming/npm/node_modules/@superbased/observer-win32-x64/bin/observer.exe`
	settingsPath := filepath.Join(claudeDir, "settings.json")
	if err := os.WriteFile(settingsPath, nativeClaudeSettingsJSON(t, nativeBin), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := NewRegistry(Options{
		BinaryPath:        "/home/u/superbased-observer/bin/observer",
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsClaudeHome: winHome,
		WSLDistro:         "Ubuntu-20.04",
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("claude-code-windows") // NO Force
	if res.Error != nil {
		t.Fatalf("Register(claude-code-windows) over a native observer entry: %v", res.Error)
	}
	if len(res.HooksAdded) != len(claudeCodeEvents) {
		t.Errorf("HooksAdded = %d want %d", len(res.HooksAdded), len(claudeCodeEvents))
	}

	groups := readClaudeHookGroups(t, settingsPath)
	for _, event := range claudeCodeEvents {
		got := groups[event]
		if len(got) != 1 {
			t.Errorf("event %s has %d groups, want exactly 1 (the bridge command): %v", event, len(got), got)
			continue
		}
		want := "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- /home/u/superbased-observer/bin/observer hook claude-code " + hookEventArg(event)
		if got[0] != want {
			t.Errorf("event %s cmd = %q, want %q", event, got[0], want)
		}
	}
	if body, _ := os.ReadFile(settingsPath); strings.Contains(string(body), nativeBin) {
		t.Errorf("stale native observer entry survived the refresh:\n%s", body)
	}
}

// TestRegisterClaudeCodeWindowsForeignEntryStillConflicts pins that the
// C2 widening did not weaken the claude-code-windows conflict guard.
func TestRegisterClaudeCodeWindowsForeignEntryStillConflicts(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome)
	claudeDir := filepath.Join(winHome, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"hooks": map[string][]claudeHookGroup{
			"SessionStart": {{
				Matcher: "*",
				Hooks:   []claudeHookCommand{{Type: "command", Command: "C:/tools/acme.exe hook claude-code session-start"}},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:        "/home/u/bin/observer",
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsClaudeHome: winHome,
		WSLDistro:         "Ubuntu-20.04",
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("claude-code-windows")
	if res.Error == nil {
		t.Fatal("Register(claude-code-windows) silently overwrote a foreign hook")
	}
	if !strings.Contains(res.Error.Error(), "non-observer") {
		t.Errorf("error = %q, want it to mention 'non-observer'", res.Error)
	}
}

// TestUnregisterClaudeCodeWindowsRemovesNativeObserverEntry pins the
// uninstall half of C2: a stale NATIVE observer entry in the
// Windows-side settings.json is ours, so `Unregister` must take it out
// too — leaving it behind would leave the exact process that was
// writing the stranded Windows DB still wired.
func TestUnregisterClaudeCodeWindowsRemovesNativeObserverEntry(t *testing.T) {
	t.Parallel()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome)
	claudeDir := filepath.Join(winHome, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(claudeDir, "settings.json")
	nativeBin := `C:/Users/u/AppData/Roaming/npm/observer.exe`
	if err := os.WriteFile(settingsPath, nativeClaudeSettingsJSON(t, nativeBin), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:        "/home/u/bin/observer",
		HomeDir:           wslHome,
		ChecksumsPath:     filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsClaudeHome: winHome,
		WSLDistro:         "Ubuntu-20.04",
		Force:             true, // the file was hand-planted: no install-time checksum
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Unregister("claude-code-windows")
	if res.Error != nil {
		t.Fatalf("Unregister(claude-code-windows): %v", res.Error)
	}
	if len(res.HooksRemoved) != len(claudeCodeEvents) {
		t.Errorf("HooksRemoved = %d want %d", len(res.HooksRemoved), len(claudeCodeEvents))
	}
	if body, err := os.ReadFile(settingsPath); err == nil && strings.Contains(string(body), nativeBin) {
		t.Errorf("native observer entry survived unregister:\n%s", body)
	}
}

// readClaudeHookGroups decodes a claude settings.json into
// event → []command (one per hook inside each group).
func readClaudeHookGroups(t *testing.T, path string) map[string][]string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings struct {
		Hooks map[string][]claudeHookGroup `json:"hooks"`
	}
	if err := json.Unmarshal(body, &settings); err != nil {
		t.Fatalf("settings.json is not valid JSON: %v\n%s", err, body)
	}
	out := map[string][]string{}
	for event, groups := range settings.Hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				out[event] = append(out[event], h.Command)
			}
		}
	}
	return out
}

// --- codex-windows: the new cross-OS hook target ------------------------------

// newCodexWindowsRegistry builds a registry wired at a fake Windows-side
// .codex under a sandboxed WSL home, and returns it plus that .codex dir.
func newCodexWindowsRegistry(t *testing.T, binary string, mutate func(*Options)) (*Registry, string) {
	t.Helper()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	codexDir := filepath.Join(winHome, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		BinaryPath:       binary,
		HomeDir:          wslHome,
		ChecksumsPath:    filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsCodexHome: winHome,
		WSLDistro:        "Ubuntu-20.04",
	}
	if mutate != nil {
		mutate(&opts)
	}
	r, err := NewRegistry(opts)
	if err != nil {
		t.Fatal(err)
	}
	return r, codexDir
}

// readCodexHookCommands decodes a codex hooks.json into
// event → []command.
func readCodexHookCommands(t *testing.T, path string) map[string][]string {
	t.Helper()
	cfg, err := readCodexHooks(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for event, groups := range cfg.Hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				out[event] = append(out[event], h.Command)
			}
		}
	}
	return out
}

// TestRegisterCodexWindowsFreshInstall pins the wsl.exe-bridged command
// shape the new codex-windows target writes into a Windows-side
// .codex/hooks.json, plus the [features].hooks flag it must set in the
// WINDOWS-side config.toml (codex reads hooks.json but never dispatches
// without that flag).
func TestRegisterCodexWindowsFreshInstall(t *testing.T) {
	t.Parallel()
	r, codexDir := newCodexWindowsRegistry(t, "/home/u/superbased-observer/bin/observer", func(o *Options) {
		o.ConfigPath = "/home/u/.observer/config.toml"
	})
	res := r.Register("codex-windows")
	if res.Error != nil {
		t.Fatalf("Register(codex-windows): %v", res.Error)
	}
	if res.Tool != "codex-windows" {
		t.Errorf("Tool = %q, want codex-windows", res.Tool)
	}
	if want := filepath.Join(codexDir, codexHooksFile); res.ConfigPath != want {
		t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, want)
	}
	if len(res.HooksAdded) != len(codexEvents) {
		t.Errorf("HooksAdded = %d want %d", len(res.HooksAdded), len(codexEvents))
	}

	got := readCodexHookCommands(t, res.ConfigPath)
	for _, event := range codexEvents {
		cmds := got[event]
		if len(cmds) != 1 {
			t.Errorf("event %s has %d commands, want 1: %v", event, len(cmds), cmds)
			continue
		}
		want := "wsl.exe -d Ubuntu-20.04 -- /home/u/superbased-observer/bin/observer hook codex " + event +
			" --config /home/u/.observer/config.toml"
		if cmds[0] != want {
			t.Errorf("event %s cmd = %q, want %q", event, cmds[0], want)
		}
		// cmd.exe is the shell codex spawns hooks through on Windows: a
		// bash env-prefix is not a command there, and POSIX single
		// quotes are literal argument text.
		if strings.HasPrefix(cmds[0], "MSYS_NO_PATHCONV=1") {
			t.Errorf("event %s carries the bash MSYS env-prefix (breaks under cmd.exe): %q", event, cmds[0])
		}
		if strings.Contains(cmds[0], "'") {
			t.Errorf("event %s uses POSIX single quotes (literal under cmd.exe): %q", event, cmds[0])
		}
	}

	cfgTOML, err := os.ReadFile(filepath.Join(codexDir, "config.toml"))
	if err != nil {
		t.Fatalf("windows-side config.toml not written: %v", err)
	}
	if !strings.Contains(string(cfgTOML), "hooks = true") {
		t.Errorf("config.toml missing [features].hooks = true:\n%s", cfgTOML)
	}
}

// TestRegisterCodexWindowsQuotesPathsWithSpaces pins the cmd.exe quoter:
// only a token that actually needs it is wrapped, and in DOUBLE quotes.
func TestRegisterCodexWindowsQuotesPathsWithSpaces(t *testing.T) {
	t.Parallel()
	r, _ := newCodexWindowsRegistry(t, "/home/u/my builds/observer", func(o *Options) {
		o.ConfigPath = "/home/u/my configs/config.toml"
	})
	res := r.Register("codex-windows")
	if res.Error != nil {
		t.Fatalf("Register(codex-windows): %v", res.Error)
	}
	got := readCodexHookCommands(t, res.ConfigPath)
	cmds := got["SessionStart"]
	if len(cmds) != 1 {
		t.Fatalf("SessionStart commands = %v, want 1", cmds)
	}
	want := `wsl.exe -d Ubuntu-20.04 -- "/home/u/my builds/observer" hook codex SessionStart --config "/home/u/my configs/config.toml"`
	if cmds[0] != want {
		t.Errorf("cmd = %q, want %q", cmds[0], want)
	}
}

// TestRegisterCodexWindowsIdempotent re-runs registration against an
// already-wired hooks.json: every event reports AlreadySet and nothing
// is re-added.
func TestRegisterCodexWindowsIdempotent(t *testing.T) {
	t.Parallel()
	r, _ := newCodexWindowsRegistry(t, "/home/u/bin/observer", nil)
	if res := r.Register("codex-windows"); res.Error != nil {
		t.Fatalf("first Register: %v", res.Error)
	}
	res := r.Register("codex-windows")
	if res.Error != nil {
		t.Fatalf("second Register: %v", res.Error)
	}
	if len(res.HooksAdded) != 0 {
		t.Errorf("HooksAdded = %v, want none on the idempotent re-run", res.HooksAdded)
	}
	if len(res.AlreadySet) != len(codexEvents) {
		t.Errorf("AlreadySet = %d want %d", len(res.AlreadySet), len(codexEvents))
	}
}

// TestRegisterCodexWindowsRefreshesOnBinaryDrift pins the upgrade path:
// a hooks.json written by a previous install (different binary path) is
// silently refreshed, not reported as a foreign conflict.
func TestRegisterCodexWindowsRefreshesOnBinaryDrift(t *testing.T) {
	t.Parallel()
	first, codexDir := newCodexWindowsRegistry(t, "/tmp/observer-A", nil)
	if res := first.Register("codex-windows"); res.Error != nil {
		t.Fatalf("first Register: %v", res.Error)
	}
	winHome := filepath.Dir(codexDir)
	second, err := NewRegistry(Options{
		BinaryPath:       "/usr/local/bin/observer",
		HomeDir:          first.opts.HomeDir,
		ChecksumsPath:    first.opts.ChecksumsPath,
		WindowsCodexHome: winHome,
		WSLDistro:        "Ubuntu-20.04",
	})
	if err != nil {
		t.Fatal(err)
	}
	res := second.Register("codex-windows")
	if res.Error != nil {
		t.Fatalf("second Register (cross-binary refresh): %v", res.Error)
	}
	if len(res.HooksAdded) != len(codexEvents) {
		t.Errorf("HooksAdded = %d want %d", len(res.HooksAdded), len(codexEvents))
	}
	body, _ := os.ReadFile(res.ConfigPath)
	if strings.Contains(string(body), "/tmp/observer-A") {
		t.Errorf("stale binary path leaked into the refreshed hooks.json:\n%s", body)
	}
	if !strings.Contains(string(body), "/usr/local/bin/observer") {
		t.Errorf("new binary path missing:\n%s", body)
	}
}

// TestRegisterCodexWindowsRespectsForeignEntry pins the safety-first
// guard: a non-observer command is never silently overwritten.
func TestRegisterCodexWindowsRespectsForeignEntry(t *testing.T) {
	t.Parallel()
	r, codexDir := newCodexWindowsRegistry(t, "/home/u/bin/observer", nil)
	foreign := `{"hooks":{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"C:\\tools\\acme.exe audit"}]}]}}`
	if err := os.WriteFile(filepath.Join(codexDir, codexHooksFile), []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}
	res := r.Register("codex-windows")
	if res.Error == nil {
		t.Fatal("expected a conflict error for a foreign codex hook, got nil")
	}
	if !strings.Contains(res.Error.Error(), "non-observer") {
		t.Errorf("error = %q, want it to mention 'non-observer'", res.Error)
	}
	if !strings.Contains(res.Error.Error(), "hook.registerCodexWindows") {
		t.Errorf("error = %q, want it to name the codex-windows registrar", res.Error)
	}
}

// newCodexCollisionRegistry builds a Registry whose native `.codex`
// (HomeDir + "/.codex") and cross-OS bridge `.codex` (WindowsCodexHome +
// "/.codex") resolve to the EXACT SAME directory — the collision
// codexHookTarget.matchMine's B4 fix exists for. An explicit
// WindowsCodexHome override bypasses crossmount's ownership-detection
// (detectWindowsHome's override branch wins unconditionally), so this
// needs no crossmount faking to construct deterministically.
func newCodexCollisionRegistry(t *testing.T) (*Registry, string) {
	t.Helper()
	tmp := t.TempDir()
	r, err := NewRegistry(Options{
		BinaryPath:       "/home/u/bin/observer",
		HomeDir:          tmp,
		ChecksumsPath:    filepath.Join(tmp, ".observer", "hook_checksums.json"),
		WindowsCodexHome: tmp,
		WSLDistro:        "Ubuntu-20.04",
	})
	if err != nil {
		t.Fatal(err)
	}
	return r, filepath.Join(tmp, ".codex", codexHooksFile)
}

// TestCodexNativeWindowsSameFileFlipFlop is the B4 regression pin for
// codex's native/bridge predicate split (codexHookTarget.matchMine):
// before the split, registerCodexAt recognised BOTH the native and the
// wsl.exe-bridge command shapes as "already ours" via the single
// permissive isObserverCodexEntry, so a native `Register("codex")`
// re-run against a hooks.json that already held bridge entries would
// find no exact string match, treat the difference as ordinary
// cross-binary drift, and silently rewrite every event's bridge command
// into native form with NO --force — discarding the cross-OS wiring
// the operator's `codex-windows` registration had put there. Table-
// driven per CLAUDE.md rule 5: each case exercises one direction of the
// two targets sharing one file.
func TestCodexNativeWindowsSameFileFlipFlop(t *testing.T) {
	t.Run("bridge re-registered against itself is idempotent", func(t *testing.T) {
		t.Parallel()
		r, hooksPath := newCodexCollisionRegistry(t)
		if res := r.Register("codex-windows"); res.Error != nil {
			t.Fatalf("first Register(codex-windows): %v", res.Error)
		}
		res := r.Register("codex-windows")
		if res.Error != nil {
			t.Fatalf("second Register(codex-windows): %v", res.Error)
		}
		if len(res.HooksAdded) != 0 {
			t.Errorf("HooksAdded = %v, want none on the idempotent re-run", res.HooksAdded)
		}
		if len(res.AlreadySet) != len(codexEvents) {
			t.Errorf("AlreadySet = %d, want %d", len(res.AlreadySet), len(codexEvents))
		}
		body, err := os.ReadFile(hooksPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "wsl.exe -d Ubuntu-20.04 --") {
			t.Errorf("bridge command missing after idempotent re-run:\n%s", body)
		}
	})

	t.Run("native register refuses to clobber an existing bridge entry", func(t *testing.T) {
		t.Parallel()
		r, hooksPath := newCodexCollisionRegistry(t)
		if res := r.Register("codex-windows"); res.Error != nil {
			t.Fatalf("Register(codex-windows): %v", res.Error)
		}
		before, err := os.ReadFile(hooksPath)
		if err != nil {
			t.Fatal(err)
		}

		res := r.Register("codex") // NO --force
		if res.Error == nil {
			t.Fatalf("Register(codex) silently overwrote the existing bridge entries; result=%+v", res)
		}
		if !strings.Contains(res.Error.Error(), "non-observer") {
			t.Errorf("error = %q, want it to mention 'non-observer' (an existing bridge entry must read as foreign to the NATIVE target)", res.Error)
		}
		after, err := os.ReadFile(hooksPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Errorf("hooks.json changed despite the conflict error:\nbefore: %s\nafter:  %s", before, after)
		}
	})

	t.Run("native register still succeeds with --force", func(t *testing.T) {
		// --force unblocks the conflict the way it does for every other
		// registrar in this package (see TestRegisterClaudeCodeConflict's
		// "should succeed and add our hook alongside") — it does not
		// retroactively delete the foreign/bridge entry, it just stops
		// refusing to add the new one next to it.
		t.Parallel()
		r, hooksPath := newCodexCollisionRegistry(t)
		if res := r.Register("codex-windows"); res.Error != nil {
			t.Fatalf("Register(codex-windows): %v", res.Error)
		}
		r.opts.Force = true
		res := r.Register("codex")
		if res.Error != nil {
			t.Fatalf("Register(codex) --force: %v", res.Error)
		}
		if len(res.HooksAdded) != len(codexEvents) {
			t.Errorf("HooksAdded = %d, want %d", len(res.HooksAdded), len(codexEvents))
		}
		got := readCodexHookCommands(t, hooksPath)
		cmds := got["SessionStart"]
		var hasBridge, hasNative bool
		for _, c := range cmds {
			if strings.HasPrefix(c, "wsl.exe ") {
				hasBridge = true
			} else if strings.HasPrefix(c, "/home/u/bin/observer ") {
				hasNative = true
			}
		}
		if !hasBridge {
			t.Errorf("bridge command lost after a --force native register (force should add alongside, not delete): %v", cmds)
		}
		if !hasNative {
			t.Errorf("native command missing after --force register: %v", cmds)
		}
	})

	t.Run("bridge register still converts a stale native entry without --force (asymmetry preserved)", func(t *testing.T) {
		t.Parallel()
		r, hooksPath := newCodexCollisionRegistry(t)
		if res := r.Register("codex"); res.Error != nil { // native first
			t.Fatalf("Register(codex): %v", res.Error)
		}
		res := r.Register("codex-windows") // NO --force
		if res.Error != nil {
			t.Fatalf("Register(codex-windows) over a native entry: %v", res.Error)
		}
		if len(res.HooksAdded) != len(codexEvents) {
			t.Errorf("HooksAdded = %d, want %d", len(res.HooksAdded), len(codexEvents))
		}
		body, err := os.ReadFile(hooksPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "wsl.exe -d Ubuntu-20.04 --") {
			t.Errorf("bridge command missing after converting the native entry:\n%s", body)
		}
	})
}

// TestRegisterCodexWindowsRequiresDistro pins the missing-distro error:
// without one, `wsl.exe` is ambiguous on a multi-distro host and we must
// fail loudly rather than write a broken hooks.json.
func TestRegisterCodexWindowsRequiresDistro(t *testing.T) {
	t.Setenv("WSL_DISTRO_NAME", "")
	r, codexDir := newCodexWindowsRegistry(t, "/home/u/bin/observer", func(o *Options) {
		o.WSLDistro = ""
	})
	res := r.Register("codex-windows")
	if res.Error == nil {
		t.Fatal("expected an error when the distro is unknown, got nil")
	}
	if !strings.Contains(res.Error.Error(), "WSL distro unknown") {
		t.Errorf("error = %q, want it to mention 'WSL distro unknown'", res.Error)
	}
	if _, err := os.Stat(filepath.Join(codexDir, codexHooksFile)); err == nil {
		t.Error("hooks.json was written despite the distro error")
	}
}

// TestRegisterCodexWindowsDryRun pins that --dry-run touches nothing:
// neither hooks.json nor the Windows-side config.toml.
func TestRegisterCodexWindowsDryRun(t *testing.T) {
	t.Parallel()
	r, codexDir := newCodexWindowsRegistry(t, "/home/u/bin/observer", func(o *Options) {
		o.DryRun = true
	})
	res := r.Register("codex-windows")
	if res.Error != nil {
		t.Fatalf("Register(codex-windows) dry run: %v", res.Error)
	}
	if !res.DryRun {
		t.Error("result does not flag DryRun")
	}
	if len(res.HooksAdded) != len(codexEvents) {
		t.Errorf("HooksAdded = %d want %d (a dry run still reports what it would do)", len(res.HooksAdded), len(codexEvents))
	}
	if _, err := os.Stat(filepath.Join(codexDir, codexHooksFile)); err == nil {
		t.Error("dry run wrote hooks.json")
	}
	if _, err := os.Stat(filepath.Join(codexDir, "config.toml")); err == nil {
		t.Error("dry run wrote config.toml")
	}
}

// TestUnregisterCodexWindowsRemovesOnlyObserverEntries pins the
// uninstall path: observer's own bridged entries go, a user-authored
// hook in the same file stays.
func TestUnregisterCodexWindowsRemovesOnlyObserverEntries(t *testing.T) {
	t.Parallel()
	r, codexDir := newCodexWindowsRegistry(t, "/home/u/bin/observer", nil)
	if res := r.Register("codex-windows"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	hooksPath := filepath.Join(codexDir, codexHooksFile)

	// Add a user-authored hook alongside ours.
	cfg, err := readCodexHooks(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Hooks["Stop"] = append(cfg.Hooks["Stop"], codexHookGroup{
		Matcher: "*",
		Hooks:   []claudeHookCommand{{Type: "command", Command: "C:/tools/acme.exe audit"}},
	})
	if err := writeCodexHooks(codexDir, pinWriteTarget(hooksPath), cfg); err != nil {
		t.Fatal(err)
	}

	unreg, err := NewRegistry(Options{
		BinaryPath:       "/home/u/bin/observer",
		HomeDir:          r.opts.HomeDir,
		ChecksumsPath:    r.opts.ChecksumsPath,
		WindowsCodexHome: filepath.Dir(codexDir),
		WSLDistro:        "Ubuntu-20.04",
		Force:            true, // the hand-edit above drifts the install checksum
	})
	if err != nil {
		t.Fatal(err)
	}
	res := unreg.Unregister("codex-windows")
	if res.Error != nil {
		t.Fatalf("Unregister(codex-windows): %v", res.Error)
	}
	if res.Tool != "codex-windows" {
		t.Errorf("Tool = %q, want codex-windows", res.Tool)
	}
	if len(res.HooksRemoved) != len(codexEvents) {
		t.Errorf("HooksRemoved = %d want %d", len(res.HooksRemoved), len(codexEvents))
	}
	got := readCodexHookCommands(t, hooksPath)
	for _, event := range codexEvents {
		for _, cmd := range got[event] {
			if strings.Contains(cmd, " hook codex ") {
				t.Errorf("event %s still carries an observer entry: %q", event, cmd)
			}
		}
	}
	if len(got["Stop"]) != 1 || got["Stop"][0] != "C:/tools/acme.exe audit" {
		t.Errorf("user-authored hook not preserved: %v", got["Stop"])
	}
}

// TestUnregisterCodexWindowsSkipsWithoutWindowsHome pins the no-op:
// a host with no Windows-side .codex has nothing to clean, which is a
// Skip, not an error.
func TestUnregisterCodexWindowsSkipsWithoutWindowsHome(t *testing.T) {
	t.Parallel()
	forceHookCrossmount(t, nil, map[string]bool{})
	r, err := NewRegistry(Options{BinaryPath: "/home/u/bin/observer", HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Unregister("codex-windows")
	if res.Error != nil {
		t.Fatalf("Unregister(codex-windows) with no Windows home: %v", res.Error)
	}
	if !res.Skipped {
		t.Errorf("result = %+v, want Skipped", res)
	}
	if res.ConfigPath != "" {
		t.Errorf("ConfigPath = %q, want empty", res.ConfigPath)
	}
}

// TestInstalledSurfacesCodexWindows pins discovery: an owned,
// auto-detected Windows home carrying .codex/ surfaces the new target in
// Installed() (and an unowned one does not — the R1 ownership guard is
// shared with the other cross-OS targets).
func TestInstalledSurfacesCodexWindows(t *testing.T) {
	cases := []struct {
		name  string
		owned bool
		want  bool
	}{
		{name: "owned home surfaces the target", owned: true, want: true},
		{name: "unowned home is refused", owned: false, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			winHome := mkWinConfigHome(t, ".codex")
			forceHookCrossmount(
				t,
				[]crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winHome}},
				map[string]bool{winHome: c.owned},
			)
			r, err := NewRegistry(Options{BinaryPath: "/home/u/bin/observer", HomeDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			r = clearSandboxPin(r) // fakes installed; exercise the auto-detect branch
			if got := containsString(r.Installed(), "codex-windows"); got != c.want {
				t.Errorf("Installed() = %v, want codex-windows present=%v", r.Installed(), c.want)
			}
		})
	}
}

// TestRegisterCodexWindowsSandboxSkip pins that the cross-OS sandbox
// gate covers the new target exactly like the other two: a caller that
// pinned HomeDir without naming WindowsCodexHome gets an explicit SKIP
// with no write path, and --force does not lift it (incident
// 2026-07-31, crossmount.AutoDetectSuppressed).
func TestRegisterCodexWindowsSandboxSkip(t *testing.T) {
	winCodex := mkWinConfigHome(t, ".codex")
	forceHookCrossmount(
		t,
		[]crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winCodex}},
		map[string]bool{winCodex: true},
	)
	sandbox := t.TempDir()
	for _, force := range []bool{false, true} {
		r, err := NewRegistry(Options{
			BinaryPath:    "/home/u/bin/observer",
			HomeDir:       sandbox,
			ChecksumsPath: filepath.Join(sandbox, ".observer", "hook_checksums.json"),
			WSLDistro:     "Ubuntu",
			Force:         force,
		})
		if err != nil {
			t.Fatal(err)
		}
		if containsString(r.Installed(), "codex-windows") {
			t.Errorf("force=%v Installed() = %v, must not surface codex-windows under a pinned home", force, r.Installed())
		}
		res := r.Register("codex-windows")
		if res.Error != nil {
			t.Errorf("force=%v Register(codex-windows) errored instead of skipping: %v", force, res.Error)
		}
		if !res.Skipped {
			t.Errorf("force=%v Register(codex-windows) = %+v, want Skipped", force, res)
		}
		if res.ConfigPath != "" {
			t.Errorf("force=%v Register(codex-windows) exposed a write path %q", force, res.ConfigPath)
		}
		if !strings.Contains(res.SkipReason, "2026-07-31") {
			t.Errorf("force=%v SkipReason should name the incident, got %q", force, res.SkipReason)
		}
		if res.SkipAdvice == "" {
			t.Errorf("force=%v skip carries no advice", force)
		}
	}
}

// --- Part B item 1/2 cross-OS bridges: gemini-cli-windows / -----------------
// qwen-code-windows / droid-windows / qoder-windows / poolside-windows /
// command-code-windows -------------------------------------------------------
//
// Six long-tail vendors' own cross-OS bridge targets, added alongside
// registerGeminiCLIWindows et al. Windsurf/Devin Desktop Cascade is
// deliberately absent — its only grounded install channel is the macOS
// Homebrew cask (internal/integration's devin row), so there is nothing
// to bridge to on Windows.

// newVendorWindowsRegistry builds a registry wired at a fake Windows-side
// config dir for one of these six vendors, under a sandboxed WSL home
// (mirrors newCodexWindowsRegistry). subdir is relative to the Windows
// home (e.g. ".gemini", filepath.Join(".config","poolside")).
// setWindowsHome assigns the resolved Windows home to the vendor's own
// Options field (each vendor has its own field name, so this is a small
// per-call closure rather than a shared field).
func newVendorWindowsRegistry(t *testing.T, binary, subdir string, setWindowsHome func(*Options, string)) (*Registry, string) {
	t.Helper()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome) // must live UNDER the pinned HomeDir
	dir := filepath.Join(winHome, subdir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		BinaryPath:    binary,
		HomeDir:       wslHome,
		ChecksumsPath: filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WSLDistro:     "Ubuntu-20.04",
	}
	setWindowsHome(&opts, winHome)
	r, err := NewRegistry(opts)
	if err != nil {
		t.Fatal(err)
	}
	return r, dir
}

// readGenericSettingsHookCommands decodes a settings.json's "hooks"
// block into event → []command — the settings.json counterpart of
// readCodexHookCommands, for the four genericSettingsHookTarget-shaped
// vendors (gemini-cli, qwen-code, qoder — droid uses hooks.json, read
// via readCodexHookCommands like codex/factory-droid already do).
func readGenericSettingsHookCommands(t *testing.T, path string) map[string][]string {
	t.Helper()
	raw, err := readSettingsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := decodeSettingsObject(path, raw)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	existing, ok := settings["hooks"]
	if !ok {
		return out
	}
	var hooks map[string][]claudeHookGroup
	if err := json.Unmarshal(existing, &hooks); err != nil {
		t.Fatal(err)
	}
	for event, groups := range hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				out[event] = append(out[event], h.Command)
			}
		}
	}
	return out
}

// jsonHooksWindowsVendor is one table row for the settings.json/hooks.json
// -shaped *-windows targets (everything except poolside's YAML and
// command-code's TS mod, which get their own tests below).
type jsonHooksWindowsVendor struct {
	tool         string // e.g. "gemini-cli-windows"
	subdir       string // e.g. ".gemini"
	configFile   string // "settings.json" or "hooks.json"
	event        string
	dispatchTool string // the base-tool token embedded in the command, e.g. "gemini-cli"
	setHome      func(*Options, string)
}

func jsonHooksWindowsVendors() []jsonHooksWindowsVendor {
	return []jsonHooksWindowsVendor{
		{
			tool: "gemini-cli-windows", subdir: ".gemini", configFile: "settings.json",
			event: "BeforeAgent", dispatchTool: "gemini-cli",
			setHome: func(o *Options, h string) { o.WindowsGeminiHome = h },
		},
		{
			tool: "qwen-code-windows", subdir: ".qwen", configFile: "settings.json",
			event: "UserPromptSubmit", dispatchTool: "qwen-code",
			setHome: func(o *Options, h string) { o.WindowsQwenHome = h },
		},
		{
			tool: "qoder-windows", subdir: ".qoder", configFile: "settings.json",
			event: "UserPromptSubmit", dispatchTool: "qoder",
			setHome: func(o *Options, h string) { o.WindowsQoderHome = h },
		},
		{
			tool: "droid-windows", subdir: ".factory", configFile: "hooks.json",
			event: "UserPromptSubmit", dispatchTool: "droid",
			setHome: func(o *Options, h string) { o.WindowsFactoryHome = h },
		},
	}
}

// readHooksCommands dispatches to the right reader for v.configFile.
func (v jsonHooksWindowsVendor) readHooksCommands(t *testing.T, path string) map[string][]string {
	t.Helper()
	if v.configFile == "hooks.json" {
		return readCodexHookCommands(t, path)
	}
	return readGenericSettingsHookCommands(t, path)
}

// TestRegisterJSONHooksWindowsVendors_FreshInstall pins the wsl.exe
// bridge command shape each of the four settings.json/hooks.json
// *-windows targets writes — same Git-Bash MSYS_NO_PATHCONV=1 wrapper
// registerClaudeCodeWindows/registerCursorWindows already established,
// naming the BASE tool (never "*-windows") in the dispatch vocabulary.
func TestRegisterJSONHooksWindowsVendors_FreshInstall(t *testing.T) {
	for _, v := range jsonHooksWindowsVendors() {
		t.Run(v.tool, func(t *testing.T) {
			t.Parallel()
			r, dir := newVendorWindowsRegistry(t, "/home/u/superbased-observer/bin/observer", v.subdir, v.setHome)
			res := r.Register(v.tool)
			if res.Error != nil {
				t.Fatalf("Register(%s): %v", v.tool, res.Error)
			}
			if res.Tool != v.tool {
				t.Errorf("Tool = %q, want %q", res.Tool, v.tool)
			}
			wantPath := filepath.Join(dir, v.configFile)
			if res.ConfigPath != wantPath {
				t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, wantPath)
			}
			if len(res.HooksAdded) != 1 || res.HooksAdded[0] != v.event {
				t.Errorf("HooksAdded = %v, want [%s]", res.HooksAdded, v.event)
			}
			cmds := v.readHooksCommands(t, res.ConfigPath)[v.event]
			if len(cmds) != 1 {
				t.Fatalf("%s commands = %v, want 1", v.event, cmds)
			}
			want := "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- /home/u/superbased-observer/bin/observer hook " +
				v.dispatchTool + " " + v.event
			if cmds[0] != want {
				t.Errorf("cmd = %q, want %q", cmds[0], want)
			}
		})
	}
}

// TestRegisterJSONHooksWindowsVendors_Idempotent re-runs registration
// against an already-wired config: AlreadySet, nothing re-added.
func TestRegisterJSONHooksWindowsVendors_Idempotent(t *testing.T) {
	for _, v := range jsonHooksWindowsVendors() {
		t.Run(v.tool, func(t *testing.T) {
			t.Parallel()
			r, _ := newVendorWindowsRegistry(t, "/home/u/bin/observer", v.subdir, v.setHome)
			if res := r.Register(v.tool); res.Error != nil {
				t.Fatalf("first Register(%s): %v", v.tool, res.Error)
			}
			res := r.Register(v.tool)
			if res.Error != nil {
				t.Fatalf("second Register(%s): %v", v.tool, res.Error)
			}
			if len(res.HooksAdded) != 0 {
				t.Errorf("HooksAdded = %v, want none on the idempotent re-run", res.HooksAdded)
			}
			if len(res.AlreadySet) != 1 || res.AlreadySet[0] != v.event {
				t.Errorf("AlreadySet = %v, want [%s]", res.AlreadySet, v.event)
			}
		})
	}
}

// TestRegisterJSONHooksWindowsVendors_RequiresDistro pins the
// missing-distro error shared with codex-windows.
func TestRegisterJSONHooksWindowsVendors_RequiresDistro(t *testing.T) {
	t.Setenv("WSL_DISTRO_NAME", "")
	for _, v := range jsonHooksWindowsVendors() {
		t.Run(v.tool, func(t *testing.T) {
			wslHome := t.TempDir()
			winHome := nestedWinHome(t, wslHome)
			if err := os.MkdirAll(filepath.Join(winHome, v.subdir), 0o755); err != nil {
				t.Fatal(err)
			}
			opts := Options{BinaryPath: "/home/u/bin/observer", HomeDir: wslHome}
			v.setHome(&opts, winHome)
			r, err := NewRegistry(opts)
			if err != nil {
				t.Fatal(err)
			}
			res := r.Register(v.tool)
			if res.Error == nil {
				t.Fatalf("expected an error when the distro is unknown, got nil")
			}
			if !strings.Contains(res.Error.Error(), "WSL distro unknown") {
				t.Errorf("error = %q, want it to mention 'WSL distro unknown'", res.Error)
			}
		})
	}
}

// TestUnregisterJSONHooksWindowsVendors_RemovesOnlyObserverEntries pins
// the uninstall path: observer's own bridged entry goes, a
// user-authored hook on a DIFFERENT event in the same file stays.
func TestUnregisterJSONHooksWindowsVendors_RemovesOnlyObserverEntries(t *testing.T) {
	for _, v := range jsonHooksWindowsVendors() {
		t.Run(v.tool, func(t *testing.T) {
			t.Parallel()
			r, dir := newVendorWindowsRegistry(t, "/home/u/bin/observer", v.subdir, v.setHome)
			if res := r.Register(v.tool); res.Error != nil {
				t.Fatalf("Register(%s): %v", v.tool, res.Error)
			}
			path := filepath.Join(dir, v.configFile)

			res := r.Unregister(v.tool)
			if res.Error != nil {
				t.Fatalf("Unregister(%s): %v", v.tool, res.Error)
			}
			if res.Tool != v.tool {
				t.Errorf("Tool = %q, want %q", res.Tool, v.tool)
			}
			if len(res.HooksRemoved) != 1 {
				t.Errorf("HooksRemoved = %v, want one entry", res.HooksRemoved)
			}
			cmds := v.readHooksCommands(t, path)[v.event]
			for _, cmd := range cmds {
				if strings.Contains(cmd, " hook "+v.dispatchTool+" ") {
					t.Errorf("event %s still carries an observer entry: %q", v.event, cmd)
				}
			}
		})
	}
}

// TestUnregisterJSONHooksWindowsVendors_SkipsWithoutWindowsHome pins the
// no-op: a host with no Windows-side config dir has nothing to clean.
func TestUnregisterJSONHooksWindowsVendors_SkipsWithoutWindowsHome(t *testing.T) {
	forceHookCrossmount(t, nil, map[string]bool{})
	for _, v := range jsonHooksWindowsVendors() {
		t.Run(v.tool, func(t *testing.T) {
			r, err := NewRegistry(Options{BinaryPath: "/home/u/bin/observer", HomeDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			res := r.Unregister(v.tool)
			if res.Error != nil {
				t.Fatalf("Unregister(%s) with no Windows home: %v", v.tool, res.Error)
			}
			if !res.Skipped {
				t.Errorf("result = %+v, want Skipped", res)
			}
		})
	}
}

// TestInstalledSurfacesJSONHooksWindowsVendors pins discovery: an
// owned, auto-detected Windows home carrying the vendor's subdir
// surfaces the *-windows target in Installed().
func TestInstalledSurfacesJSONHooksWindowsVendors(t *testing.T) {
	for _, v := range jsonHooksWindowsVendors() {
		t.Run(v.tool, func(t *testing.T) {
			winHome := mkWinConfigHome(t, v.subdir)
			forceHookCrossmount(
				t,
				[]crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winHome}},
				map[string]bool{winHome: true},
			)
			r, err := NewRegistry(Options{BinaryPath: "/home/u/bin/observer", HomeDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			r = clearSandboxPin(r)
			if !containsString(r.Installed(), v.tool) {
				t.Errorf("Installed() = %v, want it to include %s", r.Installed(), v.tool)
			}
		})
	}
}

// TestRegisterJSONHooksWindowsVendors_SandboxSkip pins that the
// cross-OS sandbox gate covers all four new targets, same as
// codex-windows: a caller that pinned HomeDir without naming the
// vendor's own WindowsXHome gets an explicit SKIP, and --force does
// not lift it.
func TestRegisterJSONHooksWindowsVendors_SandboxSkip(t *testing.T) {
	for _, v := range jsonHooksWindowsVendors() {
		t.Run(v.tool, func(t *testing.T) {
			winHome := mkWinConfigHome(t, v.subdir)
			forceHookCrossmount(
				t,
				[]crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winHome}},
				map[string]bool{winHome: true},
			)
			sandbox := t.TempDir()
			r, err := NewRegistry(Options{
				BinaryPath:    "/home/u/bin/observer",
				HomeDir:       sandbox,
				ChecksumsPath: filepath.Join(sandbox, ".observer", "hook_checksums.json"),
				WSLDistro:     "Ubuntu",
				Force:         true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if containsString(r.Installed(), v.tool) {
				t.Errorf("Installed() = %v, must not surface %s under a pinned home", r.Installed(), v.tool)
			}
			res := r.Register(v.tool)
			if res.Error != nil {
				t.Errorf("Register(%s) errored instead of skipping: %v", v.tool, res.Error)
			}
			if !res.Skipped {
				t.Errorf("Register(%s) = %+v, want Skipped", v.tool, res)
			}
			if res.ConfigPath != "" {
				t.Errorf("Register(%s) exposed a write path %q", v.tool, res.ConfigPath)
			}
		})
	}
}

// --- poolside-windows: the YAML target --------------------------------------

// TestRegisterPoolsideWindows_FreshInstall pins the wsl.exe-bridged
// command shape written into a Windows-side settings.yaml.
func TestRegisterPoolsideWindows_FreshInstall(t *testing.T) {
	t.Parallel()
	r, dir := newVendorWindowsRegistry(t, "/home/u/bin/observer", filepath.Join(".config", "poolside"),
		func(o *Options, h string) { o.WindowsPoolsideHome = h })
	res := r.Register("poolside-windows")
	if res.Error != nil {
		t.Fatalf("Register(poolside-windows): %v", res.Error)
	}
	wantPath := filepath.Join(dir, "settings.yaml")
	if res.ConfigPath != wantPath {
		t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, wantPath)
	}
	if len(res.HooksAdded) != 1 || res.HooksAdded[0] != "UserPromptSubmit" {
		t.Errorf("HooksAdded = %v, want [UserPromptSubmit]", res.HooksAdded)
	}
	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- /home/u/bin/observer hook poolside UserPromptSubmit"
	if !strings.Contains(string(body), want) {
		t.Errorf("settings.yaml missing bridge command %q: %s", want, body)
	}
}

// TestUnregisterPoolsideWindows_RoundTrip pins the uninstall path.
func TestUnregisterPoolsideWindows_RoundTrip(t *testing.T) {
	t.Parallel()
	r, dir := newVendorWindowsRegistry(t, "/home/u/bin/observer", filepath.Join(".config", "poolside"),
		func(o *Options, h string) { o.WindowsPoolsideHome = h })
	if res := r.Register("poolside-windows"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	res := r.Unregister("poolside-windows")
	if res.Error != nil {
		t.Fatalf("Unregister(poolside-windows): %v", res.Error)
	}
	if len(res.HooksRemoved) != 1 {
		t.Errorf("HooksRemoved = %v, want one entry", res.HooksRemoved)
	}
	body, _ := os.ReadFile(filepath.Join(dir, "settings.yaml"))
	if strings.Contains(string(body), "hook poolside") {
		t.Errorf("observer entry still present after unregister: %s", body)
	}
}

// TestUnregisterPoolsideWindows_SkipsWithoutWindowsHome mirrors the
// JSON-hooks vendors' no-op skip.
func TestUnregisterPoolsideWindows_SkipsWithoutWindowsHome(t *testing.T) {
	forceHookCrossmount(t, nil, map[string]bool{})
	r, err := NewRegistry(Options{BinaryPath: "/home/u/bin/observer", HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Unregister("poolside-windows")
	if res.Error != nil {
		t.Fatalf("Unregister(poolside-windows) with no Windows home: %v", res.Error)
	}
	if !res.Skipped {
		t.Errorf("result = %+v, want Skipped", res)
	}
}

// --- command-code-windows: the TS mod target --------------------------------

// TestRegisterCommandCodeWindows_FreshInstall pins the go:embed'd
// observer-guard.ts's OBSERVER_WSL_BIN/WSL_DISTRO substitution — the
// bridge decision is baked into the mod's OWN runtime (resolveExec()),
// not a static shell command like every other *-windows target.
func TestRegisterCommandCodeWindows_FreshInstall(t *testing.T) {
	t.Parallel()
	r, dir := newVendorWindowsRegistry(t, "/home/u/superbased-observer/bin/observer", ".commandcode",
		func(o *Options, h string) { o.WindowsCommandCodeHome = h })
	res := r.Register("command-code-windows")
	if res.Error != nil {
		t.Fatalf("Register(command-code-windows): %v", res.Error)
	}
	if res.Tool != "command-code-windows" {
		t.Errorf("Tool = %q, want command-code-windows", res.Tool)
	}
	wantPath := filepath.Join(dir, "mods", "observer-guard.ts")
	if res.ConfigPath != wantPath {
		t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, wantPath)
	}
	if len(res.HooksAdded) != 1 || res.HooksAdded[0] != "transformInput" {
		t.Errorf("HooksAdded = %v, want [transformInput]", res.HooksAdded)
	}
	body, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	ts := string(body)
	if !strings.Contains(ts, `const OBSERVER_WSL_BIN = "/home/u/superbased-observer/bin/observer";`) {
		t.Errorf("observer-guard.ts missing baked-in OBSERVER_WSL_BIN: %s", ts)
	}
	if !strings.Contains(ts, `const WSL_DISTRO = "Ubuntu-20.04";`) {
		t.Errorf("observer-guard.ts missing baked-in WSL_DISTRO: %s", ts)
	}
	if strings.Contains(ts, "{{OBSERVER_WSL_BIN}}") || strings.Contains(ts, "{{WSL_DISTRO}}") {
		t.Errorf("placeholder leaked into rendered file: %s", ts)
	}
}

// TestRegisterCommandCodeWindows_Idempotent mirrors the native writer's
// own idempotent-reinstall contract.
func TestRegisterCommandCodeWindows_Idempotent(t *testing.T) {
	t.Parallel()
	r, _ := newVendorWindowsRegistry(t, "/home/u/bin/observer", ".commandcode",
		func(o *Options, h string) { o.WindowsCommandCodeHome = h })
	if res := r.Register("command-code-windows"); res.Error != nil {
		t.Fatalf("first Register: %v", res.Error)
	}
	res := r.Register("command-code-windows")
	if res.Error != nil {
		t.Fatalf("second Register: %v", res.Error)
	}
	if len(res.HooksAdded) != 0 {
		t.Errorf("second register added %v, want none", res.HooksAdded)
	}
	if len(res.AlreadySet) != 1 {
		t.Errorf("AlreadySet = %v, want one entry", res.AlreadySet)
	}
}

// TestUnregisterCommandCodeWindows_RoundTrip pins the uninstall path.
func TestUnregisterCommandCodeWindows_RoundTrip(t *testing.T) {
	t.Parallel()
	r, dir := newVendorWindowsRegistry(t, "/home/u/bin/observer", ".commandcode",
		func(o *Options, h string) { o.WindowsCommandCodeHome = h })
	if res := r.Register("command-code-windows"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	res := r.Unregister("command-code-windows")
	if res.Error != nil {
		t.Fatalf("Unregister(command-code-windows): %v", res.Error)
	}
	if len(res.HooksRemoved) != 1 {
		t.Errorf("HooksRemoved = %v, want one entry", res.HooksRemoved)
	}
	if _, err := os.Stat(filepath.Join(dir, "mods", "observer-guard.ts")); !os.IsNotExist(err) {
		t.Errorf("observer-guard.ts still present after unregister (err=%v)", err)
	}
}

// TestUnregisterCommandCodeWindows_SkipsWithoutWindowsHome mirrors the
// other five vendors' no-op skip.
func TestUnregisterCommandCodeWindows_SkipsWithoutWindowsHome(t *testing.T) {
	forceHookCrossmount(t, nil, map[string]bool{})
	r, err := NewRegistry(Options{BinaryPath: "/home/u/bin/observer", HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Unregister("command-code-windows")
	if res.Error != nil {
		t.Fatalf("Unregister(command-code-windows) with no Windows home: %v", res.Error)
	}
	if !res.Skipped {
		t.Errorf("result = %+v, want Skipped", res)
	}
}

// TestInstalledSurfacesPoolsideAndCommandCodeWindows pins discovery for
// the two non-JSON-hooks-shaped vendors (not covered by
// TestInstalledSurfacesJSONHooksWindowsVendors above).
func TestInstalledSurfacesPoolsideAndCommandCodeWindows(t *testing.T) {
	cases := []struct {
		tool   string
		subdir string
	}{
		{"poolside-windows", filepath.Join(".config", "poolside")},
		{"command-code-windows", ".commandcode"},
	}
	for _, c := range cases {
		t.Run(c.tool, func(t *testing.T) {
			winHome := mkWinConfigHome(t, c.subdir)
			forceHookCrossmount(
				t,
				[]crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winHome}},
				map[string]bool{winHome: true},
			)
			r, err := NewRegistry(Options{BinaryPath: "/home/u/bin/observer", HomeDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			r = clearSandboxPin(r)
			if !containsString(r.Installed(), c.tool) {
				t.Errorf("Installed() = %v, want it to include %s", r.Installed(), c.tool)
			}
		})
	}
}
