package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

// B4 (review finding): checkHookRegistration only ever asked
// hook.Registry about the BASE tool id, never its "-windows" cross-OS
// bridge variant — so on a WSL daemon whose AI tool runs Windows-native
// (the shape this repo's own dev box runs, and the one CLAUDE.md's
// "Don't try to bridge cross-OS hook capture at the storage layer"
// describes), `observer guard prompt status` and `observer doctor
// <tool> --probe-hook` could only ever see the native config location
// and would misreport a correctly-wired tool as NOT REGISTERED or
// CONFLICT. checkHookRegistrationHomes (probehook.go) is the fix: it
// asks about BOTH homes and reports per-home state.
//
// These tests build fixtures modeled on the REAL, live
// C:\Users\<user>\.cursor\hooks.json / .codex\hooks.json /
// .claude\settings.json bridge command shapes on this dev box (read
// read-only for reference — never written to by any test), rather than
// a guessed shape:
//
//	cursor:      wsl.exe -d Ubuntu -- <bin> hook cursor beforeSubmitPrompt
//	codex:       wsl.exe -d Ubuntu -- <bin> hook codex UserPromptSubmit
//	claude-code: MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -- <bin> hook claude-code user-prompt-submit
//
// hook.Registry's cross-OS auto-detection only ever succeeds from
// INSIDE WSL (internal/platform/crossmount.WindowsUserName shells out
// to the Windows-side cmd.exe over the WSL interop bind — always ""
// on a native Windows or Linux process), so a native-Windows test
// process (this repo's own dev box) cannot drive the real thing. These
// tests instead use hookRegistrationOptions — probehook.go's test seam
// — to inject explicit HomeDir/WindowsClaudeHome/WindowsCursorHome/
// WindowsCodexHome/WSLDistro overrides, exactly the way `observer
// doctor <tool> --probe-hook --windows-cursor-home <dir>` style
// explicit overrides already work in production; DryRun stays
// hardcoded true regardless of what the seam injects.
// nestedWinHome creates a Windows-side home NESTED UNDER sandboxHome,
// mirroring internal/hook's own nestedWinHome test helper: once
// Options.HomeDir is pinned, a Windows-home override is honoured only
// if it resolves UNDER that pinned home (crossmount.AutoDetectSuppressed
// / PathUnder, the sandbox gate from incident 2026-07-31) — two
// independent t.TempDir() roots are the exact shape that gate exists to
// refuse, so a fixture with a genuinely-separate wslHome/winHome pair
// must nest one inside the other, not place them as siblings.
func nestedWinHome(t *testing.T, sandboxHome string) string {
	t.Helper()
	dir := filepath.Join(sandboxHome, "mnt", "c", "Users", "tester")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func withHookRegistrationOptions(t *testing.T, wslHome, winHome string) {
	t.Helper()
	orig := hookRegistrationOptions
	t.Cleanup(func() { hookRegistrationOptions = orig })
	hookRegistrationOptions = func(binary, configPath string) hook.Options {
		return hook.Options{
			BinaryPath:        binary,
			ConfigPath:        configPath,
			DryRun:            true,
			HomeDir:           wslHome,
			WindowsClaudeHome: winHome,
			WindowsCursorHome: winHome,
			WindowsCodexHome:  winHome,
			WSLDistro:         "Ubuntu",
		}
	}
}

func TestCheckHookRegistrationHomes_RealBridgeFixtures(t *testing.T) {
	const binary = "/mnt/d/programsx/superbased-observer/bin/observer"
	const distro = "Ubuntu"

	cases := []struct {
		tool          string
		registryEvent string
		configDir     string // subdir under the fake Windows home
		fileName      string
		fixture       string
	}{
		{
			tool: "cursor", registryEvent: "beforeSubmitPrompt",
			configDir: ".cursor", fileName: "hooks.json",
			fixture: `{"hooks":{"beforeSubmitPrompt":[{"command":"wsl.exe -d ` + distro + ` -- ` + binary + ` hook cursor beforeSubmitPrompt"}]},"version":1}`,
		},
		{
			tool: "codex", registryEvent: "UserPromptSubmit",
			configDir: ".codex", fileName: "hooks.json",
			fixture: `{"hooks":{"UserPromptSubmit":[{"matcher":"*","hooks":[{"type":"command","command":"wsl.exe -d ` + distro + ` -- ` + binary + ` hook codex UserPromptSubmit"}]}]}}`,
		},
		{
			tool: "claude-code", registryEvent: "UserPromptSubmit",
			configDir: ".claude", fileName: "settings.json",
			fixture: `{"hooks":{"UserPromptSubmit":[{"matcher":"*","hooks":[{"type":"command","command":"MSYS_NO_PATHCONV=1 wsl.exe -d ` + distro + ` -- ` + binary + ` hook claude-code user-prompt-submit"}]}]}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			// Not t.Parallel(): hookRegistrationOptions is a shared
			// package var mutated by withHookRegistrationOptions.
			wslHome := t.TempDir()               // native side — deliberately empty
			winHome := nestedWinHome(t, wslHome) // separate, nested Windows-side home
			cfgDir := filepath.Join(winHome, tc.configDir)
			if err := os.MkdirAll(cfgDir, 0o755); err != nil {
				t.Fatal(err)
			}
			cfgPath := filepath.Join(cfgDir, tc.fileName)
			if err := os.WriteFile(cfgPath, []byte(tc.fixture), 0o644); err != nil {
				t.Fatal(err)
			}
			withHookRegistrationOptions(t, wslHome, winHome)

			before, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}

			homes := checkHookRegistrationHomes(binary, "", tc.tool, tc.registryEvent)

			// Part (d): a read-only probe must never write to the
			// vendor config file, even when it walks the bridge home.
			after, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatalf("checkHookRegistrationHomes MODIFIED the config file — DryRun invariant violated:\nbefore: %s\nafter:  %s", before, after)
			}
			// The native side must also stay untouched — its own
			// config dir (HomeDir/.claude etc, distinct from the nested
			// winHome fixture) must never have been created.
			if _, err := os.Stat(filepath.Join(wslHome, tc.configDir)); !os.IsNotExist(err) {
				t.Errorf("native config dir %s was created during a read-only probe (err=%v)", filepath.Join(wslHome, tc.configDir), err)
			}

			// Part (b): both homes must be present.
			var native, bridge *hookHomeCheck
			for i := range homes {
				switch homes[i].home {
				case "native":
					native = &homes[i]
				case "bridge":
					bridge = &homes[i]
				}
			}
			if native == nil {
				t.Fatalf("no native home checked: %+v", homes)
			}
			if bridge == nil {
				t.Fatalf("bridge home was never checked — the real-world regression this test pins (tool=%s): %+v", tc.tool, homes)
			}
			if bridge.tool != tc.tool+"-windows" {
				t.Errorf("bridge.tool = %q, want %q", bridge.tool, tc.tool+"-windows")
			}

			// The bridge command in the fixture must read as
			// REGISTERED — this is the exact false-negative B4 fixes.
			if bridge.err != nil {
				t.Fatalf("bridge home errored: %v", bridge.err)
			}
			if bridge.state != hookRegRegistered {
				t.Fatalf("bridge home state = %v, want hookRegRegistered (detail=%q)", bridge.state, bridge.detail)
			}
			verdict := formatHookHomeVerdict(*bridge)
			if !strings.Contains(verdict, "REGISTERED (bridge)") {
				t.Errorf("bridge verdict = %q, want it to say REGISTERED (bridge)", verdict)
			}
			if !strings.Contains(verdict, cfgPath) {
				t.Errorf("bridge verdict = %q, want it to name the Windows-side config path %q", verdict, cfgPath)
			}

			// The native home (empty HomeDir, no config file at all)
			// must genuinely report NOT REGISTERED — never collapse
			// into the bridge's REGISTERED verdict.
			if native.err == nil && native.state == hookRegRegistered {
				t.Errorf("native home reported REGISTERED with no native config file at all (detail=%q)", native.detail)
			}

			// The overall (single-verdict) resolver used by
			// runProbeHook must side with the good news: registered on
			// EITHER home is genuinely registered.
			winner := hookHomeOverallState(homes)
			if winner.state != hookRegRegistered || winner.home != "bridge" {
				t.Errorf("hookHomeOverallState = %+v, want the bridge home to win", winner)
			}

			summary := hookHomesSummary(homes)
			if !strings.Contains(summary, "bridge: REGISTERED (bridge)") {
				t.Errorf("hookHomesSummary = %q, want it to mention the bridge REGISTERED verdict", summary)
			}
			t.Logf("homes for %s: %s", tc.tool, summary)
		})
	}
}

// TestCheckHookRegistrationHomes_NativeConflictsWithExistingBridgeEntry
// pins the OTHER half of the B4/register.go fix end to end, through
// THIS package's own probe path (not just internal/hook's unit tests):
// when native and bridge collapse onto the SAME directory (an
// operator-supplied --windows-cursor-home that happens to equal
// HomeDir, or any other coincidence), the native home's checker must
// see the existing bridge command as a FOREIGN entry (CONFLICT), never
// silently read it as its own — matching
// internal/hook.TestCodexNativeWindowsSameFileFlipFlop's "native
// register refuses to clobber an existing bridge entry" pin, but
// exercised at the checkHookRegistration layer instead of Register
// itself.
func TestCheckHookRegistrationHomes_NativeConflictsWithExistingBridgeEntry(t *testing.T) {
	const binary = "/mnt/d/programsx/superbased-observer/bin/observer"
	same := t.TempDir()
	cursorDir := filepath.Join(same, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fixture := `{"hooks":{"beforeSubmitPrompt":[{"command":"wsl.exe -d Ubuntu -- ` + binary + ` hook cursor beforeSubmitPrompt"}]},"version":1}`
	if err := os.WriteFile(filepath.Join(cursorDir, "hooks.json"), []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	withHookRegistrationOptions(t, same, same) // native == bridge directory

	homes := checkHookRegistrationHomes(binary, "", "cursor", "beforeSubmitPrompt")
	var native, bridge *hookHomeCheck
	for i := range homes {
		switch homes[i].home {
		case "native":
			native = &homes[i]
		case "bridge":
			bridge = &homes[i]
		}
	}
	if native == nil || bridge == nil {
		t.Fatalf("expected both homes checked: %+v", homes)
	}
	if native.state != hookRegConflict {
		t.Errorf("native.state = %v, want hookRegConflict (a bridge command must read as foreign to the native predicate)", native.state)
	}
	if bridge.state != hookRegRegistered {
		t.Errorf("bridge.state = %v, want hookRegRegistered", bridge.state)
	}
	// The overall verdict must still side with the bridge's good news.
	if winner := hookHomeOverallState(homes); winner.state != hookRegRegistered {
		t.Errorf("hookHomeOverallState = %+v, want Registered (the bridge home)", winner)
	}
}

// TestFormatHookHomeVerdict_HomeDistinguishesBridgeFromNative pins part
// (b)'s formatting contract directly (no filesystem involved): the
// SAME state+detail must render distinctly depending on which home
// produced it.
func TestFormatHookHomeVerdict_HomeDistinguishesBridgeFromNative(t *testing.T) {
	native := hookHomeCheck{home: "native", tool: "cursor", state: hookRegRegistered, detail: "/home/u/.cursor/hooks.json"}
	bridge := hookHomeCheck{home: "bridge", tool: "cursor-windows", state: hookRegRegistered, detail: "/mnt/c/Users/u/.cursor/hooks.json"}

	nativeVerdict := formatHookHomeVerdict(native)
	bridgeVerdict := formatHookHomeVerdict(bridge)

	if strings.Contains(nativeVerdict, "bridge") {
		t.Errorf("native verdict = %q, must not mention bridge", nativeVerdict)
	}
	if !strings.Contains(bridgeVerdict, "REGISTERED (bridge)") {
		t.Errorf("bridge verdict = %q, want REGISTERED (bridge)", bridgeVerdict)
	}
	if nativeVerdict == bridgeVerdict {
		t.Errorf("native and bridge verdicts must not collapse to the same text: %q", nativeVerdict)
	}
}

// TestCheckHookRegistrationHomes_RegistryEventScoping is part (c)'s
// pin: checkHookRegistrationHomes (via checkHookRegistration) must
// judge registration by the registryEvent slot it was asked about —
// never SessionStart or any other event — even once results are
// merged across homes. A fixture that is fully wired for SessionStart
// but carries NOTHING for UserPromptSubmit must report NOT REGISTERED
// for UserPromptSubmit.
func TestCheckHookRegistrationHomes_RegistryEventScoping(t *testing.T) {
	home := probeHookSetupHome(t) // fresh, isolated HOME (see probehook_test.go)
	binary := "/home/u/bin/observer"
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Wired for SessionStart only — UserPromptSubmit deliberately absent.
	fixture := fmt.Sprintf(`{"hooks":{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":%q}]}]}}`,
		binary+" hook claude-code session-start")
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}

	homes := checkHookRegistrationHomes(binary, "", "claude-code", "UserPromptSubmit")
	winner := hookHomeOverallState(homes)
	if winner.err != nil {
		t.Fatalf("unexpected error: %v", winner.err)
	}
	if winner.state != hookRegNotRegistered {
		t.Errorf("state = %v, want hookRegNotRegistered — a SessionStart-only fixture must not satisfy a UserPromptSubmit check", winner.state)
	}

	// Now wire UserPromptSubmit too and confirm it flips to Registered —
	// proving the scoping is live, not just "always NotRegistered".
	fixture2 := fmt.Sprintf(`{"hooks":{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":%q}]}],"UserPromptSubmit":[{"matcher":"*","hooks":[{"type":"command","command":%q}]}]}}`,
		binary+" hook claude-code session-start",
		binary+" hook claude-code user-prompt-submit")
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(fixture2), 0o644); err != nil {
		t.Fatal(err)
	}
	homes2 := checkHookRegistrationHomes(binary, "", "claude-code", "UserPromptSubmit")
	winner2 := hookHomeOverallState(homes2)
	if winner2.state != hookRegRegistered {
		t.Errorf("state = %v, want hookRegRegistered once UserPromptSubmit is actually wired", winner2.state)
	}
}

// TestCheckHookRegistrationHomes_DryRunNeverWrites is part (d)'s pin:
// every hook.Registry constructed along this probe path — including
// windowsHookHomeDetected's own registry, used purely to call
// Installed() — must be DryRun, so no vendor config file is ever
// created or modified by a probe/status call, even when a bridge home
// is detected and walked. This drives the SAME hookRegistrationOptions
// seam as the fixture tests above, and asserts the seam's own DryRun
// field can never be forced false by anything except editing this
// file's source.
func TestCheckHookRegistrationHomes_DryRunNeverWrites(t *testing.T) {
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome)
	withHookRegistrationOptions(t, wslHome, winHome)

	if !hookRegistrationOptions("/mnt/d/bin/observer", "").DryRun {
		t.Fatal("hookRegistrationOptions seam did not carry DryRun:true — test setup is broken")
	}

	// Deliberately create NEITHER .cursor nor .claude nor .codex under
	// EITHER home — a completely fresh pair. A DryRun that behaved
	// like a real write would create these directories/files as part
	// of "registering".
	_ = checkHookRegistrationHomes("/mnt/d/bin/observer", "", "cursor", "beforeSubmitPrompt")
	_ = checkHookRegistrationHomes("/mnt/d/bin/observer", "", "codex", "UserPromptSubmit")
	_ = checkHookRegistrationHomes("/mnt/d/bin/observer", "", "claude-code", "UserPromptSubmit")

	// winHome is the leaf directory nestedWinHome created for the
	// fixture — nothing should have been added inside it.
	entries, err := os.ReadDir(winHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("a supposedly read-only probe created filesystem entries under the Windows home %s: %v", winHome, names)
	}
	// wslHome itself legitimately contains the nested mnt/c/Users/tester
	// chain nestedWinHome created — what must NOT exist is a native
	// config dir alongside it.
	for _, subdir := range []string{".claude", ".cursor", ".codex"} {
		if _, err := os.Stat(filepath.Join(wslHome, subdir)); !os.IsNotExist(err) {
			t.Errorf("native config dir %s was created during a read-only probe (err=%v)", filepath.Join(wslHome, subdir), err)
		}
	}
}
