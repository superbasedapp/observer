package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// FU-197: the Windows to WSL "-wsl" hook twins reach their callers the way
// the Xcode agent homes do (FU-145): observer start, observer init, the
// dashboard's install path and observer uninstall. Only a twin whose live
// gate is off (today cursor-wsl) is written; every gated twin stays refused.
// No test touches a real \\wsl.localhost\ path: the WSL home is a fixture
// under the test HOME, injected where production reads crossmount.

const (
	wslCallerWindowsBinary = `C:\Users\me\AppData\Local\observer\observer.exe`
	wslCallerInterop       = "/mnt/c/Users/me/AppData/Local/observer/observer.exe"
)

// wslTwinTargets lists every twin with its base tool.
func wslTwinTargets(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, tool := range integration.Tools() {
		for _, target := range hook.WSLTwinsFor(tool) {
			out[target] = tool
		}
	}
	if len(out) == 0 {
		t.Fatal("no WSL twin")
	}
	return out
}

// TestWSLTwinsReachTheCallers: a switched-on twin is a hook target of its
// base tool for every caller (init / uninstall selection, observer start's
// decision, the component gate), never an MCP or route target; a gated one
// stays refused.
func TestWSLTwinsReachTheCallers(t *testing.T) {
	on := 0
	for target, base := range wslTwinTargets(t) {
		_, gated := hook.LiveCheckGate(target)
		if mcpSupported(target) || routeSupported(target) || routeProbeSupported(target) {
			t.Errorf("%s: a WSL twin must be a hook target only", target)
		}
		if adapterBaseTool(target) != base {
			t.Errorf("%s: adapterBaseTool = %q, want %q", target, adapterBaseTool(target), base)
		}
		if gated || !hookSupported(base) {
			if hookSupported(target) || autoInitSupported(target) || autoRegisterDecision(target, true) {
				t.Errorf("%s: a gated twin is supported, selectable or auto-registered", target)
			}
			continue
		}
		on++
		if !hookSupported(target) || !autoInitSupported(target) || !hookRemovable(target) {
			t.Errorf("%s: switched on but not a hook target of the callers", target)
		}
		if got, want := autoRegisterDecision(target, true), autoRegisterDecision(base, true); got != want {
			t.Errorf("%s: autoRegisterDecision = %v, its base %s = %v", target, got, base, want)
		}
	}
	if on == 0 || !hookSupported("cursor-wsl") {
		t.Error("cursor-wsl (WSL-5 passed) does not reach the callers")
	}
}

// TestInitAndUninstallSelectTheWSLTwinWithItsBase: an explicit base selector
// selects its detected, switched-on twin in init and uninstall alike; --all
// selects every switched-on one; a gated twin is never selected, even when
// listed.
func TestInitAndUninstallSelectTheWSLTwinWithItsBase(t *testing.T) {
	installed := []string{"claude-code", "cursor", "codex"}
	for target := range wslTwinTargets(t) {
		installed = append(installed, target)
	}
	sorted := func(s []string) []string { slices.Sort(s); return s }
	if got := sorted(selectToolsForInit(false, aliasTools([]bool{false, false, true}, nil), installed)); !slices.Equal(got, []string{"cursor", "cursor-wsl"}) {
		t.Errorf("init --cursor selected %v", got)
	}
	if got := sorted(selectTools(false, false, false, true, false, installed)); !slices.Equal(got, []string{"cursor", "cursor-wsl"}) {
		t.Errorf("uninstall --cursor selected %v", got)
	}
	if got := sorted(selectToolsForInit(false, aliasTools([]bool{true}, nil), installed)); !slices.Equal(got, []string{"claude-code"}) {
		t.Errorf("init --claude-code selected %v (claude-code-wsl waits on WSL-4)", got)
	}
	all := selectToolsForInit(true, nil, installed)
	for target := range wslTwinTargets(t) {
		_, gated := hook.LiveCheckGate(target)
		if slices.Contains(all, target) && gated {
			t.Errorf("init --all selected the gated twin %s", target)
		}
	}
	if !slices.Contains(all, "cursor-wsl") {
		t.Errorf("init --all missed cursor-wsl: %v", all)
	}
	// Not detected: nothing beyond the base.
	if got := selectToolsForInit(false, aliasTools([]bool{false, false, true}, nil), []string{"cursor"}); !slices.Equal(got, []string{"cursor"}) {
		t.Errorf("init --cursor without a WSL home selected %v", got)
	}
	if !clientwire.Removable("cursor-wsl", clientwire.PartHooks) || clientwire.Removable("cursor-wsl", clientwire.PartMCP) {
		t.Error("uninstall's remover must remove cursor-wsl's hooks and nothing else")
	}
}

// wslCallerFixture is a Windows observer's view of one WSL home (inside the
// test HOME) where Cursor and Claude Code are installed, plus an empty
// config. The seam stands in for what crossmount finds on a Windows host.
func wslCallerFixture(t *testing.T) (wsl, cfg string) {
	t.Helper()
	home := t.TempDir()
	pinToolHomesAt(t, home)
	t.Setenv(crossmount.EnvDisableForeignHomes, "1")
	wsl = filepath.Join(home, "wsl", "Ubuntu", "home", "me")
	for _, d := range []string{filepath.Join(wsl, ".cursor"), filepath.Join(wsl, ".claude"), filepath.Join(home, ".observer")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg = filepath.Join(home, ".observer", "config.toml")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	prev := autoRegisterWSLHost
	autoRegisterWSLHost = func(o *hook.Options) {
		o.BinaryPath = wslCallerWindowsBinary
		o.WSLTwinBinaryPath = wslCallerWindowsBinary
		o.WSLUserHome = wsl
	}
	t.Cleanup(func() { autoRegisterWSLHost = prev })
	return wsl, cfg
}

// TestStartRegistersTheWSLTwin: `observer start`'s auto-registration and the
// dashboard's install path write Observer's Cursor hooks into the WSL home
// (the interop spelling of the Windows observer.exe), never the gated
// Claude Code twin; the FU-192 rule holds through the new caller (a foreign
// binary in Observer's shape is kept and refused).
func TestStartRegistersTheWSLTwin(t *testing.T) {
	// Registration runs only for active adapters; a stamped edition that
	// leaves them inactive by default (minimal, managed) registers nothing
	// (RB1 gate: these failed under the minimal edition's tag set).
	requireActiveAdapters(t, "claude-code", "cursor")
	read := func(p string) string {
		b, _ := os.ReadFile(p)
		return string(b)
	}
	t.Run("observer start", func(t *testing.T) {
		wsl, cfg := wslCallerFixture(t)
		var out, errb bytes.Buffer
		autoRegisterHooks(&out, &errb, cfg, true)
		hooks := filepath.Join(wsl, ".cursor", "hooks.json")
		if got := read(hooks); !strings.Contains(got, wslCallerInterop+" hook cursor ") {
			t.Fatalf("the WSL home's hooks.json has no Observer hook:\n%s\nstdout:\n%s\nstderr:\n%s", got, out.String(), errb.String())
		}
		if _, err := os.Stat(filepath.Join(wsl, ".claude", "settings.json")); !os.IsNotExist(err) {
			t.Errorf("the gated claude-code-wsl home was written (stat err %v)", err)
		}

		// FU-192 through the new caller: a foreign binary in Observer's
		// shape is kept byte for byte and the refusal names the reason.
		planted := strings.ReplaceAll(read(hooks), wslCallerInterop, "/opt/lc/lc-hook.sh")
		if err := os.WriteFile(hooks, []byte(planted), 0o600); err != nil {
			t.Fatal(err)
		}
		out.Reset()
		errb.Reset()
		autoRegisterHooks(&out, &errb, cfg, true)
		if got := read(hooks); got != planted {
			t.Errorf("start rewrote a foreign binary's entry in the WSL home:\n%s", got)
		}
		if !strings.Contains(errb.String(), "WARN auto-register cursor-wsl:") || !strings.Contains(errb.String(), "the entry runs a binary that is not an observer binary") {
			t.Errorf("start does not report cursor-wsl's refusal with the reason:\n%s", errb.String())
		}
	})
	t.Run("dashboard install path", func(t *testing.T) {
		wsl, cfg := wslCallerFixture(t)
		var out, errb bytes.Buffer
		autoRegisterInstalledTool(&out, &errb, cfg, true, "cursor")
		if got := read(filepath.Join(wsl, ".cursor", "hooks.json")); !strings.Contains(got, wslCallerInterop+" hook cursor ") {
			t.Errorf("installing cursor did not register its WSL twin:\n%s\nstderr:\n%s", got, errb.String())
		}
		autoRegisterInstalledTool(&out, &errb, cfg, true, "claude-code")
		if _, err := os.Stat(filepath.Join(wsl, ".claude", "settings.json")); !os.IsNotExist(err) {
			t.Errorf("installing claude-code wrote the gated claude-code-wsl home (stat err %v)", err)
		}
	})
}
