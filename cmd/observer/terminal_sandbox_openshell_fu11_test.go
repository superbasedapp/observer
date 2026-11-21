//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// TestOpenShellUnitAnswerRows is one case per reading of a show answer
// (tracker F-036): a failed show is unknown (loaded, no config), never
// "not loaded".
func TestOpenShellUnitAnswerRows(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ok         bool
		out        string
		wantCfg    string
		wantLoaded bool
	}{
		{"failed show: unknown", false, "", "", true},
		{"failed show with output: still unknown", false, "{ path=/x ; argv[]=/x --config /c.toml ; }", "", true},
		{"answer naming no start command: not loaded", true, "\n", "", false},
		{"answer with a --config: loaded", true, "{ path=/bin/gw ; argv[]=/bin/gw --config /s/gateway.toml ; }", "/s/gateway.toml", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, loaded := openShellUnitAnswer(tc.ok, tc.out)
			if cfg != tc.wantCfg || loaded != tc.wantLoaded {
				t.Fatalf("openShellUnitAnswer = %q %v, want %q %v", cfg, loaded, tc.wantCfg, tc.wantLoaded)
			}
		})
	}
}

// TestOpenShellLegacyUnitOursRows is one case per row of
// openShellLegacyUnitOurs, the unknown row the F-036 fix.
func TestOpenShellLegacyUnitOursRows(t *testing.T) {
	const legacyID = "0123456789abcdef"
	gid, err := sandboxopenshell.IdentityFor(legacyID)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	own := openShellLayoutConfigPath(dir, gid)
	for _, tc := range []struct {
		name   string
		cfg    string
		loaded bool
		want   bool
	}{
		{"not loaded: ours", "", false, true},
		{"unknown (a failed show): not ours", "", true, false},
		{"runs this dir's config: ours", own, true, true},
		{"runs another dir's config: not ours", filepath.Join(t.TempDir(), "gateway", "gateway.toml"), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := openShellLegacyUnitOurs(dir, legacyID, func(string) (string, bool) { return tc.cfg, tc.loaded })
			if got != tc.want {
				t.Fatalf("openShellLegacyUnitOurs = %v, want %v", got, tc.want)
			}
		})
	}
}
