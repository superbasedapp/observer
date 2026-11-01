package diag

import (
	"strings"
	"testing"
)

// TestSurfaceCoverageRowsScopeByTool: the coding-surface rows are named
// "<tool>.surfaces", so `observer doctor goose` keeps goose's row, and the
// details carry the live check that decides each cell.
func TestSurfaceCoverageRowsScopeByTool(t *testing.T) {
	rep := Report{}
	for _, c := range surfaceCoverageChecks(surfaceOSLetters("linux", true)) {
		rep.add(c)
		if c.Status != StatusOK || len(c.Details) == 0 || !strings.HasSuffix(c.Name, ".surfaces") {
			t.Errorf("%s: status %q with %d details", c.Name, c.Status, len(c.Details))
		}
	}
	goose := rep.Filter("goose")
	if goose.Matched() != 1 {
		t.Fatalf("doctor goose kept %d surface rows, want 1", goose.Matched())
	}
	joined := strings.Join(goose.Checks[0].Details, "\n")
	for _, want := range []string{"Goose for VS Code (ide/vscode)", "LCR-62", "JetBrains ACP agent goose"} {
		if !strings.Contains(joined, want) {
			t.Errorf("goose surface row lacks %q:\n%s", want, joined)
		}
	}
	// The archived Kimi CLI has no adapter, so it gets a row of its own.
	if rep.Filter("acp-kimi").Matched() != 1 {
		t.Error("no row for the uncaptured registry kimi agent")
	}
}

// TestSurfaceCoverageFiltersByOS: a Mac never sees the Visual Studio row,
// Windows never sees the Xcode rows, a WSL daemon sees the Windows rows, and
// a row whose platforms are unverified shows everywhere.
func TestSurfaceCoverageFiltersByOS(t *testing.T) {
	has := func(checks []Check, label string) bool {
		for _, c := range checks {
			for _, d := range c.Details {
				if strings.HasPrefix(d, label) {
					return true
				}
			}
		}
		return false
	}
	vs := "GitHub Copilot in Visual Studio"
	xcode := "Codex in Xcode"
	muse := "Muse community surfaces"
	cases := []struct {
		name                 string
		letters              map[string]bool
		wantVS, wantX, wantM bool
	}{
		{"macOS", surfaceOSLetters("darwin", false), false, true, true},
		{"Windows", surfaceOSLetters("windows", false), true, false, true},
		{"Linux", surfaceOSLetters("linux", false), false, false, true},
		{"WSL", surfaceOSLetters("linux", true), true, false, true},
	}
	for _, tc := range cases {
		checks := surfaceCoverageChecks(tc.letters)
		if has(checks, vs) != tc.wantVS || has(checks, xcode) != tc.wantX || has(checks, muse) != tc.wantM {
			t.Errorf("%s: visual studio %v (want %v), xcode %v (want %v), unverified muse %v (want %v)",
				tc.name, has(checks, vs), tc.wantVS, has(checks, xcode), tc.wantX, has(checks, muse), tc.wantM)
		}
	}
}

// TestSurfaceCoverageKiroIDEHint (FU-153): `observer doctor kiro-cli` carries
// the Kiro IDE trust hint on every OS the IDE ships on.
func TestSurfaceCoverageKiroIDEHint(t *testing.T) {
	for _, letter := range []string{"W", "M", "L"} {
		var row *Check
		for _, c := range surfaceCoverageChecks(map[string]bool{letter: true}) {
			if c.Name == "kiro-cli.surfaces" {
				row = &c
				break
			}
		}
		if row == nil {
			t.Fatalf("%s: no kiro-cli.surfaces row", letter)
		}
		found := false
		for _, d := range row.Details {
			found = found || (strings.HasPrefix(d, "Kiro IDE (ide/kiro)") && strings.Contains(d, "trust the folder, then run Developer: Reload Window"))
		}
		if !found {
			t.Errorf("%s: kiro-cli.surfaces details %q lack the Kiro IDE trust hint", letter, row.Details)
		}
	}
}
