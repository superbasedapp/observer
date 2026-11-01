package integration

import (
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestHookSurfacesAreRegistryRows: every key is a registry tool with a hook
// mechanism, and the registry row carries exactly the declared rows.
func TestHookSurfacesAreRegistryRows(t *testing.T) {
	for tool, rows := range hookSurfaces {
		c, ok := For(tool)
		if !ok {
			t.Errorf("hookSurfaces[%q] has no registry row", tool)
			continue
		}
		if c.Hook.Mechanism == HookNone {
			t.Errorf("%s: hook surfaces on a row with no hook mechanism", tool)
		}
		if !slices.Equal(c.Hook.Surfaces, rows) {
			t.Errorf("%s: registry row does not carry its hook Surfaces column", tool)
		}
	}
	for _, c := range Capabilities() {
		if _, declared := hookSurfaces[c.Tool]; !declared && len(c.Hook.Surfaces) != 0 {
			t.Errorf("%s: carries hook Surfaces the hookSurfaces table does not declare", c.Tool)
		}
	}
}

// TestHookSurfaceRowsWellFormed checks every row against the closed
// vocabularies and the honesty rule.
func TestHookSurfaceRowsWellFormed(t *testing.T) {
	for tool, rows := range hookSurfaces {
		seen := map[[2]string]bool{}
		for _, r := range rows {
			where := tool + "[" + r.Kind + "/" + r.Host + "]"
			if !models.KnownSurface(r.Kind) {
				t.Errorf("%s: kind is not a models.Surface* kind", where)
			}
			if r.Host != "" && !surfaceHostToken.MatchString(r.Host) {
				t.Errorf("%s: host is not a bounded lowercase token", where)
			}
			key := [2]string{r.Kind, r.Host}
			if seen[key] {
				t.Errorf("%s: duplicate (kind, host)", where)
			}
			seen[key] = true
			if !r.Runs.Known() {
				t.Errorf("%s: undeclared HookSurfaceRun %q", where, r.Runs)
			}
			if r.Note == "" || r.Grounding == "" {
				t.Errorf("%s: a row needs a Note and a Grounding", where)
			}
			if r.Runs == HookSurfaceUnknown && r.LiveCheck == "" {
				t.Errorf("%s: an unknown row names no live check", where)
			}
		}
	}
}

// TestHookSurfaceFor has one row per match rule.
func TestHookSurfaceFor(t *testing.T) {
	ide := HookSurface{Kind: models.SurfaceIDE, Runs: HookSurfaceSkipped}
	ideJB := HookSurface{Kind: models.SurfaceIDE, Host: "jetbrains", Runs: HookSurfaceRuns}
	h := HookSpec{Surfaces: []HookSurface{ide, ideJB}}
	cases := []struct {
		name       string
		kind, host string
		want       HookSurface
		match      SurfaceMatch
	}{
		{"exact host beats a kind row listed first", models.SurfaceIDE, "jetbrains", ideJB, SurfaceMatchExact},
		{"kind row", models.SurfaceIDE, "vscode", ide, SurfaceMatchKind},
		{"no row", models.SurfaceCLI, "", HookSurface{Kind: models.SurfaceCLI}, SurfaceMatchTool},
		{"empty kind", "", "x", HookSurface{Host: "x"}, SurfaceMatchTool},
	}
	for _, tc := range cases {
		got, m := h.SurfaceFor(tc.kind, tc.host)
		if got != tc.want || m != tc.match {
			t.Errorf("%s: got %+v %s, want %+v %s", tc.name, got, m, tc.want, tc.match)
		}
	}
}

// TestHookSurfaceCaveat: the caveat joins the notes of the surfaces that do
// not run the hooks, in order, and is empty when all of them do.
func TestHookSurfaceCaveat(t *testing.T) {
	cases := []struct {
		name string
		rows []HookSurface
		want string
	}{
		{"none declared", nil, ""},
		{"all run", []HookSurface{{Kind: models.SurfaceCLI, Runs: HookSurfaceRuns, Note: "cli"}}, ""},
		{"skipped and unknown", []HookSurface{
			{Kind: models.SurfaceCLI, Runs: HookSurfaceRuns, Note: "cli"},
			{Kind: models.SurfaceIDE, Runs: HookSurfaceSkipped, Note: "IDE skips."},
			{Kind: models.SurfaceSDK, Note: "SDK unknown."},
		}, "IDE skips. SDK unknown."},
	}
	for _, tc := range cases {
		if got := (HookSpec{Surfaces: tc.rows}).SurfaceCaveat(); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestHookSurfaceGroundedRows pins CX-1 and W-5: the Codex desktop and IDE
// cores run no hooks.json, Junie and Poolside gate only their CLI, and the
// Claude Desktop Code tab does run the hooks.
func TestHookSurfaceGroundedRows(t *testing.T) {
	cases := []struct {
		tool, kind, host string
		want             HookSurfaceRun
	}{
		{"codex", models.SurfaceCLI, "codex-cli", HookSurfaceRuns},
		{"codex", models.SurfaceDesktop, "codex-desktop", HookSurfaceSkipped},
		{"codex", models.SurfaceIDE, "vscode", HookSurfaceSkipped},
		{"codex", models.SurfaceIDE, "jetbrains-idea", HookSurfaceSkipped},
		{"claude-code", models.SurfaceDesktop, "claude-desktop", HookSurfaceRuns},
		{"claude-code", models.SurfaceSDK, "ts", HookSurfaceUnknown},
		{"junie", models.SurfaceIDE, "jetbrains", HookSurfaceSkipped},
		{"poolside", models.SurfaceIDE, "jetbrains-idea", HookSurfaceUnknown},
	}
	for _, tc := range cases {
		c, _ := For(tc.tool)
		got, m := c.Hook.SurfaceFor(tc.kind, tc.host)
		if got.Runs != tc.want || m == SurfaceMatchTool {
			t.Errorf("%s %s/%s: Runs %q (match %s), want %q from a declared row", tc.tool, tc.kind, tc.host, got.Runs, m, tc.want)
		}
	}
}

// TestHookSurfaceCaveatReplacesAdminCaveat (W-5): the Junie and Poolside
// "CLI only" statement now comes from the hook surface rows, and no binding
// repeats it as an AdminCaveat (one statement, never two).
func TestHookSurfaceCaveatReplacesAdminCaveat(t *testing.T) {
	for _, tool := range []string{"junie", "poolside"} {
		c, _ := For(tool)
		cav := c.Hook.SurfaceCaveat()
		if !strings.Contains(cav, "CLI only") {
			t.Errorf("%s: SurfaceCaveat %q does not carry the CLI-only scope", tool, cav)
		}
		for _, b := range c.Hook.Bindings {
			if b.AdminCaveat != "" && strings.Contains(b.AdminCaveat, "CLI only") {
				t.Errorf("%s %s: AdminCaveat repeats the surface scope", tool, b.NativeEvent)
			}
		}
	}
}
