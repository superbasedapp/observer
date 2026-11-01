package proxyroute

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// forceWSLRouteHost pins the route twins' seams: a Windows host that sees
// the given WSL homes with a fixed ownership verdict.
func forceWSLRouteHost(t *testing.T, windows bool, owned map[string]bool, homes ...string) {
	t.Helper()
	var roots []crossmount.HomeRoot
	for _, h := range homes {
		roots = append(roots, crossmount.HomeRoot{Path: h, OS: crossmount.OSLinux, Origin: "wslhost:Ubuntu/" + filepath.Base(h)})
	}
	prevWin, prevHomes, prevOwned := isWindowsHost, allHomes, wslHomeOwned
	isWindowsHost = func() bool { return windows }
	allHomes = func() []crossmount.HomeRoot { return roots }
	wslHomeOwned = func(h string) bool { return owned[h] }
	t.Cleanup(func() { isWindowsHost, allHomes, wslHomeOwned = prevWin, prevHomes, prevOwned })
}

func mkWSLRouteHome(t *testing.T, subdirs ...string) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "me")
	for _, s := range subdirs {
		if err := os.MkdirAll(filepath.Join(home, s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func newWSLRouteRegistrar(t *testing.T) *Registrar {
	t.Helper()
	r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r.homeOverride = "" // the crossmount seams are fakes
	return r
}

// TestWSLRouteTwinsAreGated pins DEC-12: both route twins write nothing and
// name their live check while gated.
func TestWSLRouteTwinsAreGated(t *testing.T) {
	home := mkWSLRouteHome(t, ".claude", ".codex")
	forceWSLRouteHost(t, true, map[string]bool{home: true}, home)
	r := newWSLRouteRegistrar(t)
	for name, fn := range map[string]func() RegistrationResult{
		"claude-code-wsl": r.RegisterClaudeCodeWSL,
		"codex-wsl":       r.RegisterCodexWSL,
	} {
		res := fn()
		if res.Error != nil || !res.ConfigMissing || !strings.Contains(res.SkipReason, "built, waiting on live check WSL-4") {
			t.Errorf("%s gated result = %+v", name, res)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Errorf("gated twin wrote settings.json (%v)", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "config.toml")); !os.IsNotExist(err) {
		t.Errorf("gated twin wrote config.toml (%v)", err)
	}
	got := r.WSLRouteGatedTargets()
	if len(got) != 2 || got[0][0] != "claude-code-wsl" || got[1][0] != "codex-wsl" || got[0][1] != "WSL-4" {
		t.Errorf("WSLRouteGatedTargets = %v", got)
	}
}

// TestWSLRouteTwinsWrite runs both writers below the gate.
func TestWSLRouteTwinsWrite(t *testing.T) {
	home := mkWSLRouteHome(t, ".claude", ".codex")
	forceWSLRouteHost(t, true, map[string]bool{home: true}, home)
	r := newWSLRouteRegistrar(t)

	c := r.registerClaudeCodeWSL()
	if c.Error != nil || !c.Added || c.Tool != "claude-code-wsl" || c.BaseURL != "http://localhost:8820" {
		t.Fatalf("claude twin = %+v", c)
	}
	raw, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if !strings.Contains(string(raw), "http://localhost:8820") {
		t.Errorf("settings.json = %s", raw)
	}

	x := r.registerCodexWSL()
	if x.Error != nil || !x.Added || x.Tool != "codex-wsl" || x.BaseURL != "http://localhost:8820/v1" {
		t.Fatalf("codex twin = %+v", x)
	}
	raw, _ = os.ReadFile(filepath.Join(home, ".codex", "config.toml"))
	if !strings.Contains(string(raw), "http://localhost:8820/v1") || !strings.Contains(string(raw), ProviderName) {
		t.Errorf("config.toml = %s", raw)
	}
}

// TestWSLRouteHomeResolution walks the home rules.
func TestWSLRouteHomeResolution(t *testing.T) {
	t.Run("not a windows host", func(t *testing.T) {
		home := mkWSLRouteHome(t, ".codex")
		forceWSLRouteHost(t, false, map[string]bool{home: true}, home)
		res := newWSLRouteRegistrar(t).registerCodexWSL()
		if res.Error != nil || !res.ConfigMissing {
			t.Errorf("off Windows = %+v, want a benign skip", res)
		}
	})
	t.Run("unowned home is refused with candidates", func(t *testing.T) {
		home := mkWSLRouteHome(t, ".codex")
		forceWSLRouteHost(t, true, nil, home)
		res := newWSLRouteRegistrar(t).registerCodexWSL()
		if res.Error == nil || !strings.Contains(res.Error.Error(), "WSLUserHome") {
			t.Errorf("unowned = %+v", res)
		}
	})
	t.Run("two homes are refused", func(t *testing.T) {
		a, b := mkWSLRouteHome(t, ".codex"), mkWSLRouteHome(t, ".codex")
		forceWSLRouteHost(t, true, map[string]bool{a: true, b: true}, a, b)
		if res := newWSLRouteRegistrar(t).registerCodexWSL(); res.Error == nil {
			t.Errorf("two homes = %+v, want a refusal", res)
		}
	})
	t.Run("nothing detected", func(t *testing.T) {
		forceWSLRouteHost(t, true, nil)
		if res := newWSLRouteRegistrar(t).registerCodexWSL(); res.Error == nil || !strings.Contains(res.Error.Error(), "no WSL-side") {
			t.Errorf("none = %+v", res)
		}
	})
	t.Run("a native linux home never counts", func(t *testing.T) {
		home := mkWSLRouteHome(t, ".codex")
		forceWSLRouteHost(t, true, map[string]bool{home: true})
		prev := allHomes
		allHomes = func() []crossmount.HomeRoot {
			return []crossmount.HomeRoot{{Path: home, OS: crossmount.OSLinux, Origin: "native"}}
		}
		t.Cleanup(func() { allHomes = prev })
		if res := newWSLRouteRegistrar(t).registerCodexWSL(); res.Error == nil {
			t.Errorf("native home = %+v, want not detected", res)
		}
	})
	t.Run("a pinned sandbox skips", func(t *testing.T) {
		home := mkWSLRouteHome(t, ".codex")
		forceWSLRouteHost(t, true, map[string]bool{home: true}, home)
		r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		res := r.registerCodexWSL()
		if res.Error != nil || !res.ConfigMissing || res.SkipReason == "" {
			t.Errorf("sandboxed = %+v, want the sandbox skip", res)
		}
	})
	t.Run("explicit WSLUserHome", func(t *testing.T) {
		home := mkWSLRouteHome(t, ".codex")
		forceWSLRouteHost(t, true, nil)
		r := newWSLRouteRegistrar(t)
		r.opts.WSLUserHome = home
		if res := r.registerCodexWSL(); res.Error != nil || !res.Added {
			t.Errorf("override = %+v", res)
		}
	})
}
