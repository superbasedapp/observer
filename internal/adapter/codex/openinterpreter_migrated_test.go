package codex

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// oiMigrationMarker is the file Open Interpreter desktop 0.0.56 leaves in
// ~/.openinterpreter after moving its runtime home there from the
// Electron userData codex-home (FU-94, observed 2026-10-26). The adapter
// never reads it; the test writes it only to model the migrated layout.
const oiMigrationMarker = ".workstation-runtime-home-migrated-v1"

// TestOpenInterpreterMigratedDesktopHomeCapturedOnce pins FU-94: after
// the desktop app migrates its runtime home into ~/.openinterpreter, its
// rollouts (originator codex_ui, source vscode) land in the SAME
// ~/.openinterpreter/sessions root the CLI already uses. They must be
// claimed by exactly one watch root (no second root was added for the
// migrated home), still stamp desktop/open-interpreter, stay unclaimed by
// codex proper, and the old codex-home rung must stay listed for
// unmigrated installs.
func TestOpenInterpreterMigratedDesktopHomeCapturedOnce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	// On Windows the desktop rung resolves under %APPDATA%; pin it under
	// the temp home so the rung is the home's own, not the real profile's.
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("INTERPRETER_HOME", "")
	t.Setenv("CODEX_HOME", "")

	oiHome := filepath.Join(home, ".openinterpreter")
	dayDir := filepath.Join(oiHome, "sessions", "2026", "10", "26")
	if err := os.MkdirAll(dayDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(oiHome, oiMigrationMarker), nil, 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	body, err := os.ReadFile(oiDesktopFixturePath(t))
	if err != nil {
		t.Fatalf("read desktop fixture: %v", err)
	}
	rollout := filepath.Join(dayDir, filepath.Base(oiDesktopFixturePath(t)))
	if err := os.WriteFile(rollout, body, 0o600); err != nil {
		t.Fatalf("write rollout: %v", err)
	}

	a := NewOpenInterpreter()
	roots := a.WatchPaths()

	cliRoot := filepath.Join(oiHome, "sessions")
	var cliRoots, claiming int
	var sawDesktopRung bool
	for _, r := range roots {
		if r == cliRoot {
			cliRoots++
		}
		if isOIDesktopRoot(r) && strings.HasPrefix(r, home) {
			sawDesktopRung = true
		}
		if rel, err := filepath.Rel(r, rollout); err == nil && !strings.HasPrefix(rel, "..") {
			claiming++
		}
	}
	if cliRoots != 1 {
		t.Errorf("roots equal to %s = %d, want exactly 1; roots %v", cliRoot, cliRoots, roots)
	}
	if claiming != 1 {
		t.Errorf("roots containing the migrated rollout = %d, want exactly 1; roots %v", claiming, roots)
	}
	if !sawDesktopRung {
		t.Errorf("old codex-home desktop rung missing for the home %s (unmigrated installs need it); roots %v", home, roots)
	}

	if !a.IsSessionFile(rollout) {
		t.Fatalf("IsSessionFile(%q) = false, want true", rollout)
	}
	if New().IsSessionFile(rollout) {
		t.Errorf("codex proper claimed the migrated Open Interpreter rollout %q", rollout)
	}

	res, err := a.ParseSessionFile(context.Background(), rollout, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) == 0 {
		t.Fatal("no ToolEvents parsed from the migrated rollout")
	}
	for i, e := range res.ToolEvents {
		if e.Tool != models.ToolOpenInterpreter {
			t.Errorf("ToolEvents[%d].Tool = %q, want %q", i, e.Tool, models.ToolOpenInterpreter)
		}
	}
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("SessionSurfaces = %+v; want exactly 1", res.SessionSurfaces)
	}
	if got := res.SessionSurfaces[0]; got.Surface != models.SurfaceDesktop || got.SurfaceHost != models.ToolOpenInterpreter {
		t.Errorf("surface = %s/%s; want %s/%s (codex_ui overrides source vscode)",
			got.Surface, got.SurfaceHost, models.SurfaceDesktop, models.ToolOpenInterpreter)
	}
}
