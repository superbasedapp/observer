package clinecli

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestSurfaceForSource pins ONE ROW PER VALUE of Cline's
// sessions.source enum, plus the honest-zero cases. The enum is the
// vendor's, so a new Cline source value must land here deliberately
// rather than silently defaulting to a guessed surface.
func TestSurfaceForSource(t *testing.T) {
	t.Parallel()
	cases := []struct {
		source   string
		wantOK   bool
		wantKind string
		wantHost string
	}{
		{"cli", true, models.SurfaceCLI, "cline-cli"},
		{"core", true, models.SurfaceCLI, "cline-core"},
		{"subagent", true, models.SurfaceCLI, "cline-subagent"},
		{"vscode", true, models.SurfaceIDE, "vscode"},
		{"jetbrains", true, models.SurfaceIDE, "jetbrains"},
		{"neovim", true, models.SurfaceIDE, "neovim"},
		{"ide", true, models.SurfaceIDE, "ide"},
		{"desktop", true, models.SurfaceDesktop, "cline-desktop"},
		{"web", true, models.SurfaceWeb, "cline-web"},
		{"kanban", true, models.SurfaceWeb, "cline-kanban"},
		{"api", true, models.SurfaceSDK, "cline-api"},
		{"enterprise", true, models.SurfaceSDK, "cline-enterprise"},
		// Honest zero — Cline's own "unknown" sentinel, the empty
		// column, and any future value we have not grounded.
		{"unknown", false, "", ""},
		{"", false, "", ""},
		{"holodeck", false, "", ""},
	}
	for _, tc := range cases {
		got, ok := surfaceForSource(tc.source)
		if ok != tc.wantOK {
			t.Errorf("surfaceForSource(%q) ok = %v, want %v", tc.source, ok, tc.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if got.Surface != tc.wantKind || got.SurfaceHost != tc.wantHost {
			t.Errorf("surfaceForSource(%q) = {%q,%q}, want {%q,%q}",
				tc.source, got.Surface, got.SurfaceHost, tc.wantKind, tc.wantHost)
		}
	}
}

// TestSurfaceKindsAreVocabularyConstants pins that every row of the
// table emits a kind the store will accept — an out-of-vocabulary kind
// is refused at the store seam, so a typo here would silently drop the
// stamp in production.
func TestSurfaceKindsAreVocabularyConstants(t *testing.T) {
	t.Parallel()
	for source, s := range surfaceBySource {
		if !models.KnownSurface(s.Surface) {
			t.Errorf("surfaceBySource[%q].Surface = %q is not a Surface* constant", source, s.Surface)
		}
		if s.SurfaceHost == "" {
			t.Errorf("surfaceBySource[%q] has an empty host token", source)
		}
		if s.SessionID != "" {
			t.Errorf("surfaceBySource[%q] must not pre-fill SessionID", source)
		}
	}
}

// TestBuildSessionSurfaces covers the per-session emission: mapped
// sources stamp, unmapped sources contribute nothing, and an id-less
// row is skipped.
func TestBuildSessionSurfaces(t *testing.T) {
	t.Parallel()
	sessions := []sessionRow{
		{ID: "s-cli", Source: "cli"},
		{ID: "s-vscode", Source: "vscode"},
		{ID: "s-unknown", Source: "unknown"},
		{ID: "s-blank", Source: ""},
		{ID: "", Source: "cli"},
	}
	got := buildSessionSurfaces(sessions)
	if len(got) != 2 {
		t.Fatalf("surfaces: %d want 2 (%+v)", len(got), got)
	}
	if got[0].SessionID != "s-cli" || got[0].Surface != models.SurfaceCLI {
		t.Errorf("surface[0] = %+v", got[0])
	}
	if got[1].SessionID != "s-vscode" || got[1].Surface != models.SurfaceIDE || got[1].SurfaceHost != "vscode" {
		t.Errorf("surface[1] = %+v", got[1])
	}
}
