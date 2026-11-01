package guard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestExplainDegradedAsk is the section 5.7 decision table for a deny-only
// seam (T-052), one case per row: only an enforced ASK that the channel had
// to turn into a deny gains the confirm sentence; the command is printed
// only when a session id can scope it.
func TestExplainDegradedAsk(t *testing.T) {
	denyOnly := policy.Capabilities{PreExecution: true, CanBlock: true}
	canAsk := policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}
	verdict := func(d policy.Decision) ActionVerdict {
		return ActionVerdict{Kind: policy.KindFileAccess, Verdict: policy.Verdict{Decision: d, RuleID: "R-110", Reason: "sensitive path."}}
	}
	for _, tc := range []struct {
		name       string
		av         ActionVerdict
		caps       policy.Capabilities
		session    string
		wantPrefix string // "" = reason unchanged
	}{
		{
			"enforced ask on a deny-only seam, session known", verdict(policy.DecisionAsk), denyOnly, "s1",
			"observer: R-110 needs your confirmation before this file access runs, and this tool cannot ask you, so it was blocked. To allow it, the developer (not the agent) runs `observer guard approve R-110 --session s1` (or approves it on the Observer dashboard Security page), then lets the agent retry the identical call. ",
		},
		{
			"enforced ask on a deny-only seam, no session id", verdict(policy.DecisionAsk), denyOnly, "",
			"observer: R-110 needs your confirmation before this file access runs, and this tool cannot ask you, so it was blocked. This tool reported no session id, so the developer (not the agent) approves R-110 on the Observer dashboard Security page, then lets the agent retry the identical call. ",
		},
		{"enforced ask on an ask-capable seam asks natively", verdict(policy.DecisionAsk), canAsk, "s1", ""},
		{"enforced deny is a plain deny", verdict(policy.DecisionDeny), denyOnly, "s1", ""},
		{"flag is an allow", verdict(policy.DecisionFlag), denyOnly, "s1", ""},
		{"org-overridable deny keeps the org sentence instead", func() ActionVerdict {
			v := verdict(policy.DecisionDeny)
			v.Verdict.Overridable, v.Overridable = true, true
			return v
		}(), denyOnly, "s1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			em := ResolveEmission(tc.av.Verdict, tc.caps)
			before := em.Reason
			got := ExplainDegradedAsk(em, tc.av, tc.session)
			if tc.wantPrefix == "" {
				if got != em {
					t.Errorf("emission changed: %+v -> %+v", em, got)
				}
				return
			}
			if got.Reason != tc.wantPrefix+before || got.Permission != "deny" || !got.Enforced {
				t.Errorf("reason = %q\nwant     %q", got.Reason, tc.wantPrefix+before)
			}
			if strings.Contains(got.Reason, "—") {
				t.Error("em dash in a terminal-facing reason")
			}
		})
	}
}
