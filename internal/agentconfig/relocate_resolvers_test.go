package agentconfig_test

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// TestARuleAddedToFileRelocationsMovesEveryResolver is the surface-gap
// Wave 4 acceptance pin for the shared path resolvers: a relocation rule
// added to agentconfig's fileRelocations (the one owner) moves the file in
// the route inspector (proxyroute.InspectRoutesWith), the MCP locator
// (internal/mcp/locate) and the MCP registrar (internal/mcpregister) with no
// edit in any of them. The rule here names a variable no vendor reads, on
// codex/user-config (served by all three) and on cursor/user-mcp (a row with
// no rule today, served by the locator and the registrar). Before Wave 4
// the three hard-coded ~/.codex and ~/.cursor, so nothing moved.
//
// Not parallel: it swaps a package-level table and restores it.
func TestARuleAddedToFileRelocationsMovesEveryResolver(t *testing.T) {
	const env = "OBSERVER_TEST_RELOCATION_HOME"
	moved := filepath.Join(t.TempDir(), "relocated")
	home := t.TempDir()
	getenv := func(k string) string {
		if k == env {
			return moved
		}
		return ""
	}
	rule := func(anchor string) []agentconfig.Relocation {
		return []agentconfig.Relocation{{Env: env, Semantics: agentconfig.RelocExactDir, Anchor: anchor}}
	}
	defer agentconfig.SetRelocationsForTest("codex/user-config", rule("~/.codex"))()
	defer agentconfig.SetRelocationsForTest("cursor/user-mcp", rule("~/.cursor"))()

	codexWant := filepath.Join(moved, "config.toml")
	cursorWant := filepath.Join(moved, "mcp.json")

	// 1. The route inspector.
	found := false
	for _, rs := range proxyroute.InspectRoutesWith(home, proxyroute.InspectOptions{Getenv: getenv}) {
		if rs.Tool == "codex" {
			found = true
			if rs.ConfigPath != codexWant {
				t.Errorf("InspectRoutesWith codex ConfigPath = %q, want %q", rs.ConfigPath, codexWant)
			}
		}
	}
	if !found {
		t.Error("InspectRoutesWith has no codex row")
	}

	// 2. The MCP locator.
	for client, want := range map[string]string{"codex": codexWant, "cursor": cursorWant} {
		loc, ok := locate.ForClientEnv(client, home, getenv)
		if !ok || loc.Path != want || loc.InstallDir != moved {
			t.Errorf("locate %s = %+v, want Path %q InstallDir %q", client, loc, want, moved)
		}
	}

	// 3. The MCP registrar (a dry run writes nothing).
	r, err := mcpregister.NewRegistrar(mcpregister.RegisterOptions{
		BinaryPath: "/usr/local/bin/observer", HomeDir: home, DryRun: true, Getenv: getenv,
	})
	if err != nil {
		t.Fatal(err)
	}
	for client, want := range map[string]string{"codex": codexWant, "cursor": cursorWant} {
		if res := r.Register(client); res.Error != nil || res.ConfigPath != want {
			t.Errorf("mcpregister Register(%s) = %+v, want ConfigPath %q", client, res, want)
		}
	}

	// Without the variable every resolver keeps the vendor default.
	if loc, _ := locate.ForClientEnv("codex", home, nil); loc.Path != filepath.Join(home, ".codex", "config.toml") {
		t.Errorf("unset: locate codex = %q", loc.Path)
	}
}
