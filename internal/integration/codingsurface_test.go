package integration

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestCodingSurfacesWellFormed pins the table's shape and its honesty rules
// (codingsurface.go): closed vocabularies, a live check on every cell that
// waits on one, a grounding run on every row that has such a cell, and a
// covered cell only where a registry writer or adapter covers it.
func TestCodingSurfacesWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range CodingSurfaces() {
		where := s.ID
		if s.ID == "" || !surfaceHostToken.MatchString(s.ID) {
			t.Errorf("%q: id is not a bounded lowercase token", s.ID)
		}
		if seen[s.ID] {
			t.Errorf("%s: duplicate id", where)
		}
		seen[s.ID] = true
		if s.Label == "" || s.Grounding == "" || s.OS == "" {
			t.Errorf("%s: needs a Label, an OS and a Grounding", where)
		}
		if !models.KnownSurface(s.Kind) {
			t.Errorf("%s: kind %q is not a models.Surface* kind", where, s.Kind)
		}
		if s.Host != "" && !surfaceHostToken.MatchString(s.Host) {
			t.Errorf("%s: host %q is not a bounded lowercase token", where, s.Host)
		}
		c, hasRow := For(s.Tool)
		if s.Tool != "" && !hasRow {
			t.Errorf("%s: tool %q is not a registry row", where, s.Tool)
		}
		if s.NewTool != "" {
			if _, exists := For(s.NewTool); exists {
				t.Errorf("%s: NewTool %q is already a registry row", where, s.NewTool)
			}
			if _, isProduct := productLifecycles[s.NewTool]; isProduct {
				t.Errorf("%s: NewTool %q is a lifecycle alias or retag identity, pick a fresh id", where, s.NewTool)
			}
		}
		if s.Tool == "" && s.NewTool == "" && !s.HostRow {
			t.Errorf("%s: a row needs a Tool, a NewTool, or HostRow", where)
		}
		if s.HostRow && s.Host == "" {
			t.Errorf("%s: a host row needs a Host", where)
		}
		probeCell := false
		for _, cell := range s.Cells() {
			cw := where + " " + cell.Name
			st := cell.Cell.State
			if !st.Known() {
				t.Errorf("%s: state %q is not a SurfaceCoverage", cw, st)
				continue
			}
			if cell.Cell.Note == "" {
				t.Errorf("%s: no Note", cw)
			}
			for _, ref := range LiveCheckRefs(cell.Cell.LiveCheck) {
				if !surfaceCheckRef(ref) {
					t.Errorf("%s: live check %q is not a tracker id", cw, ref)
				}
			}
			if (st == SurfaceProbeRequired || st == SurfaceCoverageGated) && cell.Cell.LiveCheck == "" {
				t.Errorf("%s: %s names no live check", cw, st)
			}
			if st == SurfaceProbeRequired {
				probeCell = true
			}
			if st == SurfaceCovered && s.Tool == "" && !s.HostRow {
				t.Errorf("%s: covered with no registry row to cover it", cw)
			}
		}
		if probeCell && s.GroundingRun == "" {
			t.Errorf("%s: a probe_required cell needs a GroundingRun", where)
		}
		if !hasRow {
			continue
		}
		if s.Hooks.State == SurfaceCovered && !c.Hook.AutoWiredNow() {
			t.Errorf("%s: hooks covered but %s registers no hook today", where, s.Tool)
		}
		if s.MCP.State == SurfaceCovered && c.MCP == nil {
			t.Errorf("%s: MCP covered but %s has no MCP writer", where, s.Tool)
		}
		if s.Route.State == SurfaceCovered && c.Proxy == nil {
			t.Errorf("%s: route covered but %s has no verified route", where, s.Tool)
		}
	}
}

// TestCodingSurfacesAnswerFU57: every row of the vendor inventory's section 6
// (pending tracker FU-57, rows 1 to 30) is answered by a table row or by a
// named place elsewhere, and nothing names a row that does not exist.
func TestCodingSurfacesAnswerFU57(t *testing.T) {
	answered := map[int]bool{}
	for _, s := range CodingSurfaces() {
		for _, n := range s.FU57 {
			if n < 1 || n > 30 {
				t.Errorf("%s: FU-57 row %d does not exist", s.ID, n)
			}
			answered[n] = true
		}
	}
	for n, where := range FU57Elsewhere() {
		if n < 1 || n > 30 || where == "" {
			t.Errorf("FU57Elsewhere[%d] = %q is not a real row with a place", n, where)
		}
		answered[n] = true
	}
	for n := 1; n <= 30; n++ {
		if !answered[n] {
			t.Errorf("FU-57 row %d is answered nowhere", n)
		}
	}
}

// TestCodingSurfacesRecordProvenNegatives: the surfaces MAC-5 / LC15 proved
// run none of Observer's hooks are recorded as vendor_none with the live
// check named, never as covered (the lane brief's rule).
func TestCodingSurfacesRecordProvenNegatives(t *testing.T) {
	for id, check := range map[string]string{
		"claude-agent-jetbrains": "MAC-5",
		"junie-ide-plugin":       "MAC-5",
		"trae":                   "MAC-5",
		"cortex-code-desktop":    "LC18",
	} {
		var row *CodingSurface
		for _, s := range CodingSurfaces() {
			if s.ID == id {
				row = &s
				break
			}
		}
		if row == nil {
			t.Errorf("%s: no row", id)
			continue
		}
		if row.Hooks.State != SurfaceVendorNone || !strings.Contains(row.Hooks.LiveCheck, check) {
			t.Errorf("%s: hooks %q (%q), want vendor_none naming %s", id, row.Hooks.State, row.Hooks.LiveCheck, check)
		}
	}
}

// TestKiroIDEDoctorHint (FU-153): the Kiro IDE row is no longer a proven
// negative, and its doctor line tells the developer to trust the folder and
// reload the window.
func TestKiroIDEDoctorHint(t *testing.T) {
	for _, s := range CodingSurfacesFor("kiro-cli") {
		if s.ID != "kiro-ide" {
			continue
		}
		if s.Hooks.State != SurfaceProbeRequired {
			t.Errorf("kiro-ide hooks %q, want probe_required", s.Hooks.State)
		}
		line := s.Line()
		for _, want := range []string{"hooks probe_required (LC15)", "trust the folder", "Developer: Reload Window"} {
			if !strings.Contains(line, want) {
				t.Errorf("kiro-ide doctor line %q lacks %q", line, want)
			}
		}
		return
	}
	t.Fatal("no kiro-ide row")
}

// TestSurfaceCheckRef: a surface cell accepts exactly the live-check id
// shape plus a completed MAC round.
func TestSurfaceCheckRef(t *testing.T) {
	for ref, ok := range map[string]bool{
		"LC34": true, "LC26b": true, "LCR-89": true, "MAC-5": true,
		"LCX-5": false, "LC13-W": false, "MAC-": false, "mac-5": false, "LC0": false,
	} {
		if got := surfaceCheckRef(ref); got != ok {
			t.Errorf("surfaceCheckRef(%q) = %v, want %v", ref, got, ok)
		}
	}
}

// TestCodingSurfaceLine pins the doctor wording of one row.
func TestCodingSurfaceLine(t *testing.T) {
	s := CodingSurface{
		Label: "Goose for VS Code", Kind: models.SurfaceIDE, Host: "vscode",
		Capture: probe("LCR-62", "x"), Hooks: probe("LCR-62", "x"), Route: notCovered("x"), MCP: vendorNone("", "x"),
	}
	want := "Goose for VS Code (ide/vscode): capture probe_required (LCR-62); hooks probe_required (LCR-62); route not_covered; MCP vendor_none"
	if got := s.Line(); got != want {
		t.Errorf("Line() =\n %q\nwant\n %q", got, want)
	}
	if s.FullyCovered() {
		t.Error("a row with a probe cell is not fully covered")
	}
	s.NewTool = "goose-vscode"
	if !strings.HasSuffix(s.Line(), "; would be registry id goose-vscode") {
		t.Errorf("Line() with a NewTool = %q", s.Line())
	}
}

// TestCodingSurfacesForGroups: every row is reachable through its group.
func TestCodingSurfacesForGroups(t *testing.T) {
	n := 0
	groups := map[string]bool{}
	for _, s := range CodingSurfaces() {
		groups[s.Group()] = true
	}
	for g := range groups {
		n += len(CodingSurfacesFor(g))
	}
	if n != len(CodingSurfaces()) {
		t.Errorf("groups reach %d rows, table has %d", n, len(CodingSurfaces()))
	}
}

// TestXcodeAgentsAreHookCovered pins the Xcode agent rows. Xcode's Claude
// Agent and Codex read only their own CodingAssistant homes (2026-10-28
// MAC-1 read), so the hooks Observer writes to ~/.claude and ~/.codex never
// reach them; the FU-145 writers for those homes passed LCR-89 and LCR-90
// on 2026-10-28 (Mac round 5b), so the hook cells are covered and their
// grounding cites that run.
func TestXcodeAgentsAreHookCovered(t *testing.T) {
	want := map[string]string{"claude-agent-xcode": "LCR-89", "codex-xcode": "LCR-90"}
	for _, s := range CodingSurfaces() {
		check, ok := want[s.ID]
		if !ok {
			continue
		}
		delete(want, s.ID)
		if s.Hooks.State != SurfaceCovered || !strings.Contains(s.Hooks.Note, "passed") || !strings.Contains(s.Grounding, "round 5b") {
			t.Errorf("%s: hooks %q (%q), want covered and grounded in Mac round 5b", s.ID, s.Hooks.State, s.Hooks.Note)
		}
		// FU-150 / FU-193: MAC-6 saw the session land stamped ide/xcode,
		// filed under Xcode's agent cwd; where Xcode names the open
		// project is owed on MAC-7, so probe_required on that run.
		if s.Capture.State != SurfaceProbeRequired || s.Capture.LiveCheck != "MAC-7" || !strings.Contains(s.Capture.Note, "Xcode (project unknown)") {
			t.Errorf("%s: capture %q (%q), want probe_required naming MAC-7 and the project-unknown answer", s.ID, s.Capture.State, s.Capture.LiveCheck)
		}
		if s.Route.State != SurfaceProbeRequired || s.Route.LiveCheck != check {
			t.Errorf("%s: route %q (%q), want probe_required naming %s", s.ID, s.Route.State, s.Route.LiveCheck, check)
		}
	}
	for id := range want {
		t.Errorf("%s: no row", id)
	}
}

// TestCodingSurfaceExtensionIDs (FU-152): only publisher.name Detect entries
// are extension ids, lowercase, with a trailing note ignored.
func TestCodingSurfaceExtensionIDs(t *testing.T) {
	s := CodingSurface{Detect: []string{
		"block.vscode-goose", "Kimchidev.kimchi-vscode (unconfirmed)", "acp registry goose",
		"JetBrains plugin 28247", "~/.aider-desk", "Electron userData aider-desk", "Coding-Aider (mimoccc)",
	}}
	got := s.ExtensionIDs()
	want := []string{"block.vscode-goose", "kimchidev.kimchi-vscode"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ExtensionIDs = %v, want %v", got, want)
	}
}
