package secrules

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
)

// TestTrustGroupsCoverTheCodeTable: every untrusted-level reason code of
// the trust check (and every repository-run code) belongs to exactly one of
// S-701 to S-704, and no group names a code outside the table.
func TestTrustGroupsCoverTheCodeTable(t *testing.T) {
	owner := map[string]string{}
	for id, codes := range TrustRuleCodes() {
		for _, c := range codes {
			if prev, ok := owner[c]; ok {
				t.Errorf("code %s in both %s and %s", c, prev, id)
			}
			owner[c] = id
		}
	}
	known := map[string]bool{}
	for _, row := range sectrust.Codes() {
		known[row.Code] = true
		if row.Level == sectrust.LevelUntrusted && owner[row.Code] == "" {
			t.Errorf("untrusted code %s has no trust rule", row.Code)
		}
		if row.RepositoryRun && owner[row.Code] != "S-701" {
			t.Errorf("repository-run code %s is not S-701's", row.Code)
		}
	}
	for c := range owner {
		if !known[c] {
			t.Errorf("trust rule code %s is not in the trust check's table", c)
		}
	}
}

// TestTrustRulesThroughTheEngine: the rows compose into a real engine
// through Config.ExtraRules (the JSP-7 launch probe) and decide per mode.
func TestTrustRulesThroughTheEngine(t *testing.T) {
	cases := []struct {
		name            string
		sec             *policy.Security
		wantRule        string
		observe, enforc policy.Decision
	}{
		{"no security facts", nil, "", policy.DecisionAllow, policy.DecisionAllow},
		{"clean", &policy.Security{Trust: policy.TrustClean}, "", policy.DecisionAllow, policy.DecisionAllow},
		{"repository command", &policy.Security{Trust: policy.TrustUntrusted, TrustReasons: []string{"mcp_server_command"}}, "S-701", policy.DecisionFlag, policy.DecisionAsk},
		{"api redirect", &policy.Security{Trust: policy.TrustUntrusted, TrustReasons: []string{"base_url_override"}}, "S-702", policy.DecisionFlag, policy.DecisionDeny},
		{"hooks off", &policy.Security{Trust: policy.TrustUntrusted, TrustReasons: []string{"hooks_off_switch"}}, "S-703", policy.DecisionFlag, policy.DecisionDeny},
		{"hidden unicode", &policy.Security{Trust: policy.TrustUntrusted, TrustReasons: []string{"hidden_unicode_tag"}}, "S-704", policy.DecisionFlag, policy.DecisionAsk},
		{"mixed: the strictest wins", &policy.Security{Trust: policy.TrustUntrusted, TrustReasons: []string{"hook_command", "auto_approve"}}, "S-703", policy.DecisionFlag, policy.DecisionDeny},
		{"flagged", &policy.Security{Trust: policy.TrustFlagged, TrustReasons: []string{"hook_command"}}, "S-705", policy.DecisionFlag, policy.DecisionFlag},
		{"unknown verdict raises nothing", &policy.Security{Trust: policy.TrustUnknown}, "", policy.DecisionAllow, policy.DecisionAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := policy.Event{Kind: policy.KindAgentLaunch, Tool: "claude-code", Target: "/p", ProjectRoot: "/p", Security: tc.sec}
			for _, m := range []struct {
				mode policy.Mode
				want policy.Decision
			}{{policy.ModeObserve, tc.observe}, {policy.ModeEnforce, tc.enforc}} {
				e, err := policy.New(policy.Config{Mode: m.mode, ExtraRules: TrustRules()})
				if err != nil {
					t.Fatal(err)
				}
				v := e.Evaluate(ev)
				if v.Decision != m.want || v.RuleID != tc.wantRule {
					t.Fatalf("%s: %s/%s (%q), want %s/%s", m.mode, v.RuleID, v.Decision, v.Reason, tc.wantRule, m.want)
				}
			}
		})
	}
}

// TestTrustRowsAreWellFormed: ids in the trust range, the pillar's
// category and source, agent_launch only.
func TestTrustRowsAreWellFormed(t *testing.T) {
	var ids []string
	for _, r := range TrustRules() {
		ids = append(ids, r.ID)
		if !strings.HasPrefix(r.ID, policy.SecurityRuleIDPrefix) || r.ID > "S-719" {
			t.Errorf("%s outside the trust range S-701 to S-719", r.ID)
		}
		if r.Category != policy.CategoryCodeSecurity || r.Source != policy.SourcePackSecurity {
			t.Errorf("%s: category %s source %s", r.ID, r.Category, r.Source)
		}
		if !slices.Equal(r.AppliesTo, []policy.EventKind{policy.KindAgentLaunch}) {
			t.Errorf("%s applies to %v", r.ID, r.AppliesTo)
		}
	}
	sort.Strings(ids)
	if !slices.Equal(ids, []string{"S-701", "S-702", "S-703", "S-704", "S-705"}) {
		t.Errorf("ids %v", ids)
	}
}
