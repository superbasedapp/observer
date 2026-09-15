package kilocode

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestLegacy_StampsIDESurfaceWithHostFromPath pins the surface
// pass-through (audit IDE-05 + IDE-14). The wrapped cline parser
// stamps models.SurfaceIDE unconditionally and derives the host from
// the VS Code-family product the task path lives under, so a Kilo task
// inside Cursor stamps "cursor" and one inside upstream Code stamps
// "vscode". The retag loop must not disturb the stamp — a
// models.SessionSurface is session-scoped and carries no Tool field.
func TestLegacy_StampsIDESurfaceWithHostFromPath(t *testing.T) {
	cases := []struct {
		name     string
		product  string
		wantHost string
	}{
		{name: "upstream_code", product: "Code", wantHost: "vscode"},
		{name: "cursor_fork", product: "Cursor", wantHost: "cursor"},
		{name: "windsurf_fork", product: "Windsurf", wantHost: "windsurf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			tasksRoot := filepath.Join(home, tc.product, "User", "globalStorage",
				legacyExtensionID, "tasks")
			taskDir := filepath.Join(tasksRoot, "task-surface")
			if err := os.MkdirAll(taskDir, 0o755); err != nil {
				t.Fatal(err)
			}
			cwdInJSON := filepath.ToSlash(home)
			body := `[
				{"role":"user","ts":1700000000000,"content":[{"type":"text","text":"<environment_details>\n# Current Working Directory (` + cwdInJSON + `) Files\nREADME.md\n</environment_details>"}]},
				{"role":"assistant","ts":1700000010000,"model":"claude-haiku-4-5","content":[
					{"type":"tool_use","id":"toolu_1","name":"read_file","input":{"path":"README.md"}}
				]}
			]`
			apiPath := filepath.Join(taskDir, "api_conversation_history.json")
			if err := os.WriteFile(apiPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			a := NewLegacyWithOptions(nil, []string{tasksRoot})
			res, err := a.ParseSessionFile(context.Background(), apiPath, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			if len(res.SessionSurfaces) != 1 {
				t.Fatalf("surfaces = %d want 1", len(res.SessionSurfaces))
			}
			s := res.SessionSurfaces[0]
			if s.SessionID != "task-surface" {
				t.Errorf("surface session = %q", s.SessionID)
			}
			if s.Surface != models.SurfaceIDE {
				t.Errorf("surface = %q want %q", s.Surface, models.SurfaceIDE)
			}
			if s.SurfaceHost != tc.wantHost {
				t.Errorf("surface host = %q want %q", s.SurfaceHost, tc.wantHost)
			}
		})
	}
}

// TestLegacy_DefaultRootsEnumerateForkHosts pins that defaultRoots now
// walks EVERY VS Code-family product via internal/platform/vscodehost
// (audit IDE-14), not just upstream Code + .vscode-server. Skips on a
// runner with no detected crossmount homes.
func TestLegacy_DefaultRootsEnumerateForkHosts(t *testing.T) {
	roots := NewLegacy().WatchPaths()
	if len(roots) == 0 {
		t.Skip("no crossmount homes detected on this runner")
	}
	var haveCursor, haveInsiders, haveRemote bool
	for _, r := range roots {
		slash := filepath.ToSlash(r)
		if !strings.HasSuffix(slash, "/"+legacyExtensionID+"/tasks") {
			t.Errorf("unexpected root shape: %q", r)
		}
		switch {
		case strings.Contains(slash, "/Cursor/User/globalStorage/"):
			haveCursor = true
		case strings.Contains(slash, "/Code - Insiders/User/globalStorage/"):
			haveInsiders = true
		case strings.Contains(slash, "/.vscode-server/data/User/globalStorage/"):
			haveRemote = true
		}
	}
	if !haveCursor {
		t.Error("no Cursor root — fork hosts must be enumerated")
	}
	if !haveInsiders {
		t.Error("no Code - Insiders root")
	}
	if !haveRemote {
		t.Error("no .vscode-server root")
	}
}
