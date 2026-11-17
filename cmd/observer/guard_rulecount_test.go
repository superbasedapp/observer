package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
)

// TestGuardRulesStatusLine pins demo bug #12: `observer guard status` leads
// with the distinct-rule count the dashboard's Rules tab shows, and labels
// the row count beside it instead of printing only "N active rows".
func TestGuardRulesStatusLine(t *testing.T) {
	cases := []struct {
		rules, rows int
		want        string
	}{
		{81, 131, "Rules:        81 active rules (131 rule rows: a rule can match several event kinds)"},
		{12, 12, "Rules:        12 active rules"},
		{0, 0, "Rules:        0 active rules"},
	}
	for _, c := range cases {
		if got := guardRulesStatusLine(c.rules, c.rows); got != c.want {
			t.Errorf("guardRulesStatusLine(%d, %d) = %q, want %q", c.rules, c.rows, got, c.want)
		}
	}
}

// TestGuardRuleIDCountMatchesTheRulesTab: the CLI's lead number is the
// distinct ids of the effective rules, the set the Rules tab counts, and the
// row count is never smaller.
func TestGuardRuleIDCountMatchesTheRulesTab(t *testing.T) {
	cfg := config.Default().Guard
	cfg.Enabled = true
	g, err := guard.New(guard.Options{Config: cfg, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range g.EffectiveRules() {
		ids[r.ID] = true
	}
	if g.RuleIDCount() != len(ids) || g.RuleIDCount() == 0 {
		t.Fatalf("RuleIDCount = %d, distinct effective ids %d", g.RuleIDCount(), len(ids))
	}
	if g.RuleCount() < g.RuleIDCount() {
		t.Fatalf("rows %d < rules %d", g.RuleCount(), g.RuleIDCount())
	}
}
