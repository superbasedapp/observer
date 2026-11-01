package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
)

// TestRemoveProxyRoute: `observer uninstall` removes this install's proxy
// route through clientwire's Remover (the seam the dashboard's undo and
// Connected tools Remove step share), only for the tools that have a
// removable route, and a dry run writes nothing.
func TestRemoveProxyRoute(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`
	if err := os.WriteFile(settings, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	rem := func(dry bool) *clientwire.Remover {
		r, err := clientwire.NewRemover(clientwire.RemoveOptions{BinaryPath: "/opt/observer", ProxyPort: 8820, HomeDir: home, DryRun: dry})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	var out bytes.Buffer
	m := rem(true).Remove("claude-code", clientwire.PartRoute)
	if m.Route == nil || printProxyRouteRemoval(&out, "claude-code", *m.Route, true) {
		t.Fatalf("dry run route=%v", m.Route)
	}
	if b, _ := os.ReadFile(settings); string(b) != seed {
		t.Fatalf("dry run wrote the file: %s", b)
	}
	if m := rem(false).Remove("cursor", clientwire.PartRoute); m.Route != nil {
		t.Error("cursor has no removable proxy route; it must not be handled")
	}
	m = rem(false).Remove("claude-code", clientwire.PartRoute)
	if m.Route == nil || printProxyRouteRemoval(&out, "claude-code", *m.Route, false) {
		t.Fatalf("removal route=%v", m.Route)
	}
	if b, _ := os.ReadFile(settings); strings.Contains(string(b), "ANTHROPIC_BASE_URL") {
		t.Errorf("route still present: %s", b)
	}
	if !strings.Contains(out.String(), "removed proxy route") {
		t.Errorf("output does not report the removal:\n%s", out.String())
	}
}

// TestSelectTools_UninstallKeepsBaseOnlyScope pins F3: the cross-OS
// "<base>-windows" union is init-ONLY. `observer uninstall --claude-code`
// resolves through the shared selectTools (base-only), so it must NOT widen to
// claude-code-windows — silently stripping the Windows-side profile on an
// uninstall would be a destructive scope change. The init path
// (selectToolsForInit) still unions the detected Windows target.
func TestSelectTools_UninstallKeepsBaseOnlyScope(t *testing.T) {
	// Both the base tool and its detected cross-OS virtual target are present.
	installed := []string{"claude-code", "claude-code-windows"}

	// Uninstall path: explicit --claude-code, base-only.
	got := selectTools(false, true, false, false, false, installed)
	if slices.Contains(got, "claude-code-windows") {
		t.Errorf("selectTools(--claude-code) = %v, must NOT include claude-code-windows (uninstall scope)", got)
	}
	if !slices.Contains(got, "claude-code") {
		t.Errorf("selectTools(--claude-code) = %v, want it to include claude-code", got)
	}

	// Init path: the same explicit selector DOES union the Windows target.
	gotInit := selectToolsForInit(false, aliasTools([]bool{true}, nil), installed)
	if !slices.Contains(gotInit, "claude-code-windows") {
		t.Errorf("selectToolsForInit(--claude-code) = %v, want it to include claude-code-windows", gotInit)
	}
	if !slices.Contains(gotInit, "claude-code") {
		t.Errorf("selectToolsForInit(--claude-code) = %v, want it to include claude-code", gotInit)
	}
}
