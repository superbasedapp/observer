package policy

import (
	"strings"
	"testing"
)

// TestSelfApprovalCLIParityL4 pins the cli-parity L4 rows of R-165 (plan
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md): the [guard.cloud]
// consent card's write (B-G5, decision P-2) and the audit chain repair,
// through its dashboard route and its CLI verbs (B-G8), are the developer's
// actions. Reads and dry runs stay allowed.
func TestSelfApprovalCLIParityL4(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		// The consent card's route: every write matches, the GET is a read.
		sh("PUT the guard cloud consent", `curl -X PUT -H 'X-Observer-Confirm: t' -H 'Content-Type: application/json' http://127.0.0.1:8821/api/guard/cloud -d '{"cloud_enabled":true,"reputation_enabled":true}'`, "R-165", DecisionDeny),
		sh("PUT turning the judge on", `curl -X PUT http://localhost:8821/api/guard/cloud -d '{"llm_judge":{"enabled":true,"endpoint":"https://x.example/v1"}}'`, "R-165", DecisionDeny),
		sh("PUT the guard cloud dry run", `curl -X PUT 'http://127.0.0.1:8821/api/guard/cloud?dry_run=1' -d '{"cloud_enabled":true}'`, "R-165", DecisionDeny),
		sh("POST to the guard cloud route", `curl -X POST http://127.0.0.1:8821/api/guard/cloud -d '{}'`, "R-165", DecisionDeny),
		sh("GET the guard cloud state is a read", `curl http://127.0.0.1:8821/api/guard/cloud`, "", 0),
		// The chain repair route: every write matches (an apply rewrites
		// guard_events rows), the GET is a read.
		sh("POST a chain repair apply", `curl -X POST -H 'X-Observer-Confirm: t' http://127.0.0.1:8821/api/guard/jobs/chain -d '{"kind":"relink-gaps-apply"}'`, "R-165", DecisionDeny),
		sh("POST a chain repair dry run", `curl -X POST http://127.0.0.1:8821/api/guard/jobs/chain -d '{"kind":"dedup-events"}'`, "R-165", DecisionDeny),
		sh("GET the chain repair kinds is a read", `curl http://127.0.0.1:8821/api/guard/jobs/chain`, "", 0),
		// The CLI verbs: an apply rewrites the chain, a report does not.
		sh("guard repair-anchors --apply", `observer guard repair-anchors --apply`, "R-165", DecisionDeny),
		sh("guard dedup-events --apply", `observer guard dedup-events --apply --keep-hashes`, "R-165", DecisionDeny),
		sh("guard relink-gaps --apply", `observer guard relink-gaps --apply`, "R-165", DecisionDeny),
		sh("guard relink-gaps --apply=false still matches (deny-biased)", `observer guard relink-gaps --apply=false`, "R-165", DecisionDeny),
		sh("guard repair-anchors through npx", `npx -y @superbased/observer guard repair-anchors --apply --radius 0`, "R-165", DecisionDeny),
		sh("guard repair-anchors dry run is a read", `observer guard repair-anchors --radius 0`, "", 0),
		sh("guard dedup-events dry run is a read", `observer guard dedup-events`, "", 0),
		sh("guard relink-gaps dry run is a read", `observer guard relink-gaps`, "", 0),
		sh("guard verify-audit is a read", `observer guard verify-audit`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}

// TestCLIParityL4AdviceNamesTheDashboard pins the rule advice rewording (plan
// section 3): advice the dashboard shows as a rule tooltip, and an agent or
// the CLI reads, names the dashboard place first and keeps the CLI twin.
func TestCLIParityL4AdviceNamesTheDashboard(t *testing.T) {
	t.Parallel()
	advice := map[string][]string{}
	for _, r := range builtinRules() {
		advice[r.ID] = append(advice[r.ID], r.Advice)
	}
	cases := []struct {
		rule      string
		dashboard string
		cli       string
	}{
		{"R-301", "Security > MCP", "observer guard mcp approve"},
		{"R-302", "Security > MCP", "observer guard mcp approve"},
		{"R-305", "Security > MCP", "observer guard mcp approve"},
		{"T-505", "Security > MCP", "observer guard mcp approve"},
		{"R-204", "Apply policy changes", "observer guard compile"},
		{"B-601", "Security > Budgets", "[guard.budget].session_usd"},
		{"B-602", "Security > Budgets", "[guard.budget].daily_usd"},
		{"B-603", "Settings > Guard", "[guard.budget].monthly_usd"},
		{"B-604", "Settings > Guard", "[guard.budget].weekly_usd"},
		{"B-621", "Settings > Guard", "[guard.budget].session_tokens"},
		{"B-622", "Settings > Guard", "[guard.budget].daily_tokens"},
		{"B-623", "Settings > Guard", "[guard.budget].monthly_tokens"},
		{"B-624", "Settings > Guard", "[guard.budget].weekly_tokens"},
		{"R-150", "Settings > Guard", "[guard.boundary] allow_paths"},
		{"T-502", "Settings > Guard", "[guard.boundary].allow_paths"},
		{"R-111", "Settings > Guard", "[guard.boundary]"},
		{"R-172", "Settings > Guard", "[guard."},
		{"R-190", "Settings > Guard", "[guard.prompt] allow"},
	}
	for _, tc := range cases {
		rows, ok := advice[tc.rule]
		if !ok {
			t.Errorf("%s: no such rule in the built-in table", tc.rule)
			continue
		}
		// A rule may carry several advice rows (R-172 has three); a row that
		// names no CLI or config twin at all (e.g. "pass credentials via
		// files") has nothing to order. Every row that names the twin must
		// name the dashboard place first, and at least one row must name it.
		checked := 0
		for _, a := range rows {
			d, c := strings.Index(a, tc.dashboard), strings.Index(a, tc.cli)
			if c < 0 {
				continue
			}
			checked++
			if d < 0 || c < d {
				t.Errorf("%s advice must name %q before %q: %q", tc.rule, tc.dashboard, tc.cli, a)
			}
		}
		if checked == 0 {
			t.Errorf("%s: no advice row names %q any more", tc.rule, tc.cli)
		}
	}
}
