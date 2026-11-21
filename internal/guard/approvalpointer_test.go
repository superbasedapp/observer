package guard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestApprovalPointerFollowsSecurityVisibility pins CG-16: every block text
// that tells the developer where to approve a call names the dashboard
// Security page only while that page is shown on this machine. Hidden (the
// managed default), the text names a CLI command that works without it.
func TestApprovalPointerFollowsSecurityVisibility(t *testing.T) {
	av := func(hidden, overridable bool) ActionVerdict {
		return ActionVerdict{
			Kind:               policy.KindFileAccess,
			Verdict:            policy.Verdict{Decision: policy.DecisionAsk, RuleID: "R-110", Reason: "sensitive path."},
			Overridable:        overridable,
			ApprovalPageHidden: hidden,
		}
	}
	type render func(ActionVerdict, string) string
	cases := []struct {
		name        string
		text        render
		overridable bool
		session     string
		hidden      bool
		want        []string
		notWant     []string
	}{
		{"confirm, session, shown", ConfirmBlockLine, false, "s-1", false, []string{"observer guard approve R-110 --session s-1", "Security page"}, nil},
		{"confirm, session, hidden", ConfirmBlockLine, false, "s-1", true, []string{"observer guard approve R-110 --session s-1"}, []string{"Security page"}},
		{"confirm, no session, shown", ConfirmBlockLine, false, "", false, []string{"approves R-110 on the Observer dashboard Security page"}, []string{"--global"}},
		{"confirm, no session, hidden", ConfirmBlockLine, false, "", true, []string{"observer guard approve R-110 --global --ttl 15m"}, []string{"Security page"}},
		{"override, session, shown", HumanBlockLine, true, "s-1", false, []string{"observer guard approve R-110 --session s-1"}, nil},
		{"override, session, hidden", HumanBlockLine, true, "s-1", true, []string{"observer guard approve R-110 --session s-1"}, []string{"Security page"}},
		{"override, no session, shown", HumanBlockLine, true, "", false, []string{"Security page"}, []string{"--global"}},
		{"override, no session, hidden", HumanBlockLine, true, "", true, []string{"observer guard approve R-110 --global --ttl 15m"}, []string{"Security page"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.text(av(tc.hidden, tc.overridable), tc.session)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("text %q lacks %q", got, w)
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(got, nw) {
					t.Errorf("text %q still names %q", got, nw)
				}
			}
			if strings.ContainsAny(got, "–—") {
				t.Errorf("text %q uses an em or en dash", got)
			}
		})
	}
}

// TestStampApprovalPageHiddenOnlyOnBlockingVerdicts pins that the lookup is
// asked for a blocking verdict only (it may open the database on the hook
// path), and that its answer lands on the verdict.
func TestStampApprovalPageHiddenOnlyOnBlockingVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		decision  policy.Decision
		wantAsked bool
	}{
		{"flag is not asked", policy.DecisionFlag, false},
		{"ask is asked", policy.DecisionAsk, true},
		{"deny is asked", policy.DecisionDeny, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := New(Options{Home: t.TempDir()})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			asked := false
			g.SetApprovalPageHidden(func() bool { asked = true; return true })
			av := ActionVerdict{Verdict: policy.Verdict{Decision: tc.decision, RuleID: "R-110"}}
			g.stampOrgOverrideAt(g.set.Load(), &av, "")
			if asked != tc.wantAsked {
				t.Fatalf("lookup asked = %v, want %v", asked, tc.wantAsked)
			}
			if av.ApprovalPageHidden != tc.wantAsked {
				t.Fatalf("ApprovalPageHidden = %v, want %v", av.ApprovalPageHidden, tc.wantAsked)
			}
		})
	}
}
