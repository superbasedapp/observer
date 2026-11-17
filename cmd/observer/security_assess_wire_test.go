//go:build !sbo_omit_security

package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// TestDashboardRuleRelaxationAnswersFromTheGuard: the seam the assessments'
// consent table reads answers from a guard built the way the daemon builds
// one, in the mode the config sets, and knows no rule that does not exist.
func TestDashboardRuleRelaxationAnswersFromTheGuard(t *testing.T) {
	cases := []struct {
		name         string
		guard        string
		wantDecision string
	}{
		{"enforce: the scanner rule asks", "[guard]\nenabled = true\nmode = \"enforce\"\n", "ask"},
		{"observe: the scanner rule only flags", "[guard]\nenabled = true\nmode = \"observe\"\n", "flag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.toml")
			// org_bundle names an absent file: no bundle, so no org lock.
			writeFileT(t, cfgPath, tc.guard+"[guard.rules]\norg_bundle = \""+filepath.ToSlash(filepath.Join(dir, "org-policy-bundle.json"))+"\"\n")
			seam := dashboardRuleRelaxation(cfgPath, nil)
			got := seam(context.Background(), dir, []string{secassess.RuleScanner, "R-9999"})
			scan, ok := got[secassess.RuleScanner]
			if !ok || !scan.Known || scan.Decision != tc.wantDecision {
				t.Fatalf("scanner rule = %+v ok=%v, want decision %q", scan, ok, tc.wantDecision)
			}
			// No org bundle is in force here, so nothing locks the rule: the
			// lock with a bundle is pinned by the guard's own RuleRelaxation
			// tests.
			if scan.Lock != "untouched" {
				t.Errorf("lock = %q with no bundle, want untouched", scan.Lock)
			}
			if unknown := got["R-9999"]; unknown.Known {
				t.Errorf("a rule that does not exist is known: %+v", unknown)
			}
		})
	}
}
