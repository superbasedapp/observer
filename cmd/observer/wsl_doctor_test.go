package main

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestHookDoctorReadsTheWSLTwins (FU-211): the hook doctor reports a
// switched-on "-wsl" twin's home as it reports the Xcode homes (FU-145): a
// WARN while Observer's bindings are missing there, OK once registered; a
// gated twin is shown as gated with its gate text; the twin's file is a
// stale-entry candidate. With no WSL home (not a Windows host with a running
// distro's home) there is no row at all. The WSL home is a fixture under the
// test HOME, injected where production reads crossmount's running-distro
// list (FU-189); no real \\wsl.localhost\ path is touched.
func TestHookDoctorReadsTheWSLTwins(t *testing.T) {
	wsl, _ := wslCallerFixture(t)
	opts := func(dry bool, wslHome string) hook.Options {
		return hook.Options{
			BinaryPath: wslCallerWindowsBinary, DryRun: dry, KeepEquivalentHooks: true,
			HomeDir: filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(wsl)))), WSLUserHome: wslHome,
			Getenv: func(string) string { return "" },
		}
	}
	prev := hookRegistrationOptions
	t.Cleanup(func() { hookRegistrationOptions = prev })
	o := hookDoctorOptions{Binary: wslCallerWindowsBinary}
	mine := func(tool string) []integration.HookBinding {
		var out []integration.HookBinding
		for _, b := range mustCap(t, tool).Hook.Bindings {
			if b.Registered || b.Wired {
				out = append(out, b)
			}
		}
		return out
	}

	hookRegistrationOptions = func(string, string) hook.Options { return opts(true, "") }
	if got := wslHookChecks(o, mustCap(t, "cursor"), "cursor", mine("cursor")); len(got) != 0 {
		t.Fatalf("no WSL home here, yet the doctor reported a twin: %+v", got)
	}

	hookRegistrationOptions = func(string, string) hook.Options { return opts(true, wsl) }
	checks := wslHookChecks(o, mustCap(t, "cursor"), "cursor", mine("cursor"))
	if len(checks) != 1 || checks[0].Name != "hook.bindings:cursor-wsl" || checks[0].Status != diag.StatusWarn {
		t.Fatalf("before registering: %+v, want one WARN for cursor-wsl", checks)
	}
	reg, err := hook.NewRegistry(opts(false, wsl))
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("cursor-wsl"); res.Error != nil || res.Skipped {
		t.Fatalf("Register: %+v", res)
	}
	hooksFile := filepath.Join(wsl, ".cursor", "hooks.json")
	checks = wslHookChecks(o, mustCap(t, "cursor"), "cursor", mine("cursor"))
	if len(checks) != 1 || checks[0].Status != diag.StatusOK || !strings.Contains(checks[0].Message, "the WSL home "+hooksFile) {
		t.Fatalf("after registering: %+v, want one OK naming %s", checks, hooksFile)
	}
	if files := staleHookConfigFiles(wslCallerWindowsBinary, "", []string{"cursor"}); !slices.Contains(files, hooksFile) {
		t.Errorf("the WSL twin's file is not a stale-entry candidate: %v", files)
	}

	gate, gated := hook.LiveCheckGate("claude-code-wsl")
	if !gated {
		t.Skip("claude-code-wsl is switched on; no gated twin left to show")
	}
	checks = wslHookChecks(o, mustCap(t, "claude-code"), "claude-code", mine("claude-code"))
	if len(checks) != 1 || checks[0].Name != "hook.bindings:claude-code-wsl" || checks[0].Status != diag.StatusWarn ||
		!strings.Contains(checks[0].Message, "gated: ") || !strings.Contains(checks[0].Message, gate) {
		t.Fatalf("gated twin: %+v, want one WARN shown as gated with %s", checks, gate)
	}
}

// TestFU214StartPassesTheRunningBinaryToTheTwins: `observer start`'s
// registration options name the running observer binary for the "-wsl"
// twins (on an npm or pip install BinaryPath is the launcher), and so do
// the hook doctor's, so the doctor reads the twin's entry as registered.
func TestFU214StartPassesTheRunningBinaryToTheTwins(t *testing.T) {
	home := t.TempDir()
	pinToolHomesAt(t, home)
	cfg := filepath.Join(home, ".observer", "config.toml")
	bin, err := absoluteBinaryPath()
	if err != nil {
		t.Fatal(err)
	}
	opts, err := autoRegisterOptions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := registrationWSLTwinBinary(bin); got != bin {
		t.Errorf("registrationWSLTwinBinary(%q) = %q, want the running binary", bin, got)
	}
	if opts.WSLTwinBinaryPath != bin {
		t.Errorf("autoRegisterOptions WSLTwinBinaryPath = %q, want %q", opts.WSLTwinBinaryPath, bin)
	}
	if got := hookRegistrationOptions(bin, cfg).WSLTwinBinaryPath; got != bin {
		t.Errorf("the hook doctor's WSLTwinBinaryPath = %q, want %q", got, bin)
	}
}
