package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// xcodeCallerHomes are the Xcode agent homes under a user home (the
// catalogued darwin directory rows, spelled here only to build the fixture).
var xcodeCallerHomes = map[string]string{
	"claude-code-xcode": filepath.Join("Library", "Developer", "Xcode", "CodingAssistant", "ClaudeAgentConfig"),
	"codex-xcode":       filepath.Join("Library", "Developer", "Xcode", "CodingAssistant", "codex"),
	"gemini-cli-xcode":  filepath.Join("Library", "Developer", "Xcode", "CodingAssistant", "gemini", ".gemini"),
}

// xcodeTargets lists every Xcode agent-home target with its base tool.
func xcodeTargets(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, tool := range integration.Tools() {
		for _, target := range hook.XcodeTargetsFor(tool) {
			out[target] = tool
		}
	}
	if len(out) == 0 {
		t.Fatal("no Xcode agent-home target")
	}
	return out
}

// TestXcodeTargetsReachTheCallers pins FU-145's predicate half: a
// switched-on Xcode target is a hook target of its base tool for every
// caller (init / uninstall selection, observer start's decision, the
// component gate), never an MCP or route target; a gated one
// (gemini-cli-xcode, off on LCR-91's finding: no BeforeTool, FU-195) stays refused.
func TestXcodeTargetsReachTheCallers(t *testing.T) {
	for target, base := range xcodeTargets(t) {
		_, gated := hook.LiveCheckGate(target)
		if got := hookSupported(target); got == gated {
			t.Errorf("%s: hookSupported = %v with gated = %v", target, got, gated)
		}
		if mcpSupported(target) || routeSupported(target) || routeProbeSupported(target) {
			t.Errorf("%s: an Xcode target must be a hook target only", target)
		}
		if !hookRemovable(target) {
			t.Errorf("%s: not removable", target)
		}
		if adapterBaseTool(target) != base {
			t.Errorf("%s: adapterBaseTool = %q, want %q", target, adapterBaseTool(target), base)
		}
		if gated {
			if autoInitSupported(target) || autoRegisterDecision(target, true) {
				t.Errorf("%s: a gated target is selectable or auto-registered", target)
			}
			continue
		}
		if !autoInitSupported(target) {
			t.Errorf("%s: not selectable by init / uninstall", target)
		}
		if got, want := autoRegisterDecision(target, true), autoRegisterDecision(base, true); got != want {
			t.Errorf("%s: autoRegisterDecision = %v, its base %s = %v", target, got, base, want)
		}
	}
	if _, gated := hook.LiveCheckGate("gemini-cli-xcode"); !gated || hookSupported("gemini-cli-xcode") {
		t.Error("gemini-cli-xcode must stay refused (LCR-91 found no BeforeTool)")
	}
}

// TestInitAndUninstallSelectTheXcodeTargetWithItsBase: an explicit base
// selector selects its detected, switched-on Xcode target in init and
// uninstall alike; --all selects every switched-on one; a gated one is never
// selected, even when listed.
func TestInitAndUninstallSelectTheXcodeTargetWithItsBase(t *testing.T) {
	installed := []string{"claude-code", "codex", "gemini-cli"}
	for target := range xcodeTargets(t) {
		installed = append(installed, target)
	}
	sorted := func(s []string) []string { slices.Sort(s); return s }
	if got := sorted(selectToolsForInit(false, aliasTools([]bool{true}, nil), installed)); !slices.Equal(got, []string{"claude-code", "claude-code-xcode"}) {
		t.Errorf("init --claude-code selected %v", got)
	}
	if got := sorted(selectTools(false, false, true, false, false, installed)); !slices.Equal(got, []string{"codex", "codex-xcode"}) {
		t.Errorf("uninstall --codex selected %v", got)
	}
	all := selectToolsForInit(true, nil, installed)
	for target := range xcodeTargets(t) {
		_, gated := hook.LiveCheckGate(target)
		if slices.Contains(all, target) == gated {
			t.Errorf("init --all: %s selected = %v with gated = %v (%v)", target, slices.Contains(all, target), gated, all)
		}
	}
	// Not detected: nothing beyond the base.
	if got := selectToolsForInit(false, aliasTools([]bool{true}, nil), []string{"claude-code"}); !slices.Equal(got, []string{"claude-code"}) {
		t.Errorf("init --claude-code without an Xcode home selected %v", got)
	}
}

// xcodeCallerFixture is a home with ~/.claude and every Xcode agent home
// (folders only, as Xcode creates them), plus an empty config.
func xcodeCallerFixture(t *testing.T) (home, cfg string) {
	t.Helper()
	home = t.TempDir()
	pinToolHomesAt(t, home)
	t.Setenv(crossmount.EnvDisableForeignHomes, "1")
	dirs := []string{".claude", ".codex", ".observer"}
	for _, rel := range xcodeCallerHomes {
		dirs = append(dirs, rel)
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg = filepath.Join(home, ".observer", "config.toml")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return home, cfg
}

// TestStartRegistersTheXcodeHomes (FU-145): on macOS `observer start`'s
// auto-registration writes Observer's hooks into Xcode's Claude Agent and
// Codex homes where those folders exist, and never into the gated Gemini
// home; the dashboard's install path (autoRegisterInstalledTool) registers a
// tool's Xcode home with it; on another OS nothing lands in Library.
func TestStartRegistersTheXcodeHomes(t *testing.T) {
	// Registration runs only for active adapters; a stamped edition that
	// leaves them inactive by default (minimal, managed) registers nothing
	// (RB1 gate: these failed under the minimal edition's tag set).
	requireActiveAdapters(t, "claude-code", "codex", "gemini-cli")
	read := func(home, rel string) string {
		b, _ := os.ReadFile(filepath.Join(home, rel))
		return string(b)
	}
	claudeSettings := filepath.Join(xcodeCallerHomes["claude-code-xcode"], "settings.json")
	codexHooks := filepath.Join(xcodeCallerHomes["codex-xcode"], "hooks.json")
	geminiSettings := filepath.Join(xcodeCallerHomes["gemini-cli-xcode"], "settings.json")

	t.Run("darwin", func(t *testing.T) {
		home, cfg := xcodeCallerFixture(t)
		prev := autoRegisterGOOS
		autoRegisterGOOS = "darwin"
		t.Cleanup(func() { autoRegisterGOOS = prev })
		var out, errb bytes.Buffer
		autoRegisterHooks(&out, &errb, cfg, true)
		if got := read(home, claudeSettings); !strings.Contains(got, "hook claude-code") {
			t.Errorf("ClaudeAgentConfig/settings.json has no Observer hook:\n%s\nstdout:\n%s\nstderr:\n%s", got, out.String(), errb.String())
		}
		if got := read(home, codexHooks); !strings.Contains(got, "hook codex") {
			t.Errorf("codex/hooks.json has no Observer hook:\n%s\nstderr:\n%s", got, errb.String())
		}
		if _, err := os.Stat(filepath.Join(home, geminiSettings)); !os.IsNotExist(err) {
			t.Errorf("the gated gemini-cli-xcode home was written (stat err %v)", err)
		}
	})
	t.Run("dashboard install path", func(t *testing.T) {
		home, cfg := xcodeCallerFixture(t)
		prev := autoRegisterGOOS
		autoRegisterGOOS = "darwin"
		t.Cleanup(func() { autoRegisterGOOS = prev })
		var out, errb bytes.Buffer
		autoRegisterInstalledTool(&out, &errb, cfg, true, "claude-code")
		if got := read(home, claudeSettings); !strings.Contains(got, "hook claude-code") {
			t.Errorf("installing claude-code did not register its Xcode home:\n%s\nstderr:\n%s", got, errb.String())
		}
		if _, err := os.Stat(filepath.Join(home, codexHooks)); !os.IsNotExist(err) {
			t.Errorf("installing claude-code wrote the codex Xcode home (stat err %v)", err)
		}
	})
	t.Run("not macOS", func(t *testing.T) {
		home, cfg := xcodeCallerFixture(t)
		prev := autoRegisterGOOS
		autoRegisterGOOS = "linux"
		t.Cleanup(func() { autoRegisterGOOS = prev })
		var out, errb bytes.Buffer
		autoRegisterHooks(&out, &errb, cfg, true)
		for _, rel := range []string{claudeSettings, codexHooks, geminiSettings} {
			if _, err := os.Stat(filepath.Join(home, rel)); !os.IsNotExist(err) {
				t.Errorf("%s written off macOS (stat err %v)", rel, err)
			}
		}
	})
}

// TestHookDoctorReadsTheXcodeHome (FU-145): the hook doctor reports the
// Xcode Claude Agent home on its own: a WARN while Observer's bindings are
// missing there, OK once the target is registered.
func TestHookDoctorReadsTheXcodeHome(t *testing.T) {
	home, _ := xcodeCallerFixture(t)
	const bin = "/opt/observer/bin/observer"
	opts := func(dry bool) hook.Options {
		return hook.Options{BinaryPath: bin, DryRun: dry, KeepEquivalentHooks: true, HomeDir: home, GOOS: "darwin", Getenv: func(string) string { return "" }}
	}
	prev := hookRegistrationOptions
	hookRegistrationOptions = func(string, string) hook.Options { return opts(true) }
	t.Cleanup(func() { hookRegistrationOptions = prev })

	c, _ := integration.For("claude-code")
	var mine []integration.HookBinding
	for _, b := range c.Hook.Bindings {
		if b.Registered || b.Wired {
			mine = append(mine, b)
		}
	}
	o := hookDoctorOptions{Binary: bin}
	checks := xcodeHookChecks(o, c, "claude-code", mine)
	if len(checks) != 1 || checks[0].Name != "hook.bindings:claude-code-xcode" || checks[0].Status != diag.StatusWarn {
		t.Fatalf("before registering: %+v, want one WARN for claude-code-xcode", checks)
	}
	reg, err := hook.NewRegistry(opts(false))
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("claude-code-xcode"); res.Error != nil || res.Skipped {
		t.Fatalf("Register: %+v", res)
	}
	checks = xcodeHookChecks(o, c, "claude-code", mine)
	if len(checks) != 1 || checks[0].Status != diag.StatusOK || !strings.Contains(checks[0].Message, "ClaudeAgentConfig") {
		t.Fatalf("after registering: %+v, want one OK naming the Xcode home", checks)
	}
	if got := xcodeHookChecks(o, mustCap(t, "gemini-cli"), "gemini-cli", nil); len(got) != 0 {
		t.Errorf("the gated Gemini Xcode home was reported: %+v", got)
	}
}

func mustCap(t *testing.T, tool string) integration.Capability {
	t.Helper()
	c, ok := integration.For(tool)
	if !ok {
		t.Fatalf("no registry row %s", tool)
	}
	return c
}
