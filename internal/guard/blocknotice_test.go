package guard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestSandboxBlockNotice pins the notice table (blocknotice.go): one case per
// notice and rule source. A sandbox notice leads every blocking verdict with
// whose policy it is and how to change it, and never with the node-local
// request, approve or dashboard pointer; the zero notice keeps the node-local
// wording byte for byte.
func TestSandboxBlockNotice(t *testing.T) {
	never := []string{"request access", "Requests page", "dashboard", "guard approve", "organization locks", "Ask your admin"}
	cases := []struct {
		name     string
		av       ActionVerdict
		want     []string
		wantNone bool
		// node is the exact node-local line (the zero notice).
		node string
	}{
		{
			name: "node origin, committed rule",
			av:   sandboxVerdict(BlockNoticeSandboxNode, "U-901", policy.SourceOrg, policy.DecisionDeny),
			want: []string{"observer: U-901 blocked this command.", "committed cloud-session policy", "the developer's own guard policy", "re-run `observer cloud-session init --guard`", "commit"},
		},
		{
			name: "node origin, built-in rule",
			av:   sandboxVerdict(BlockNoticeSandboxNode, "R-101", policy.SourceBuiltin, policy.DecisionDeny),
			want: []string{"observer: R-101 blocked this command.", "built-in Observer rule", "the developer's own guard policy", "node that signed"},
		},
		{
			name: "org origin, committed rule",
			av:   sandboxVerdict(BlockNoticeSandboxOrg, "U-901", policy.SourceOrg, policy.DecisionDeny),
			want: []string{"U-901 is a rule in this repository's committed cloud-session policy (the organization's guard policy).", "ask an org admin"},
		},
		{
			name: "org origin, built-in rule",
			av:   sandboxVerdict(BlockNoticeSandboxOrg, "R-101", policy.SourceBuiltin, policy.DecisionAsk),
			want: []string{"built-in Observer rule", "the organization's guard policy", "ask an org admin"},
		},
		{
			name: "project layer rule",
			av:   sandboxVerdict(BlockNoticeSandboxNode, "P-1", "project", policy.DecisionDeny),
			want: []string{"own project guard policy file", "edit that file in the repository"},
		},
		{
			name: "pack rule reads as built-in",
			av:   sandboxVerdict(BlockNoticeSandboxOrg, "S-701", policy.SourcePackSecurity, policy.DecisionDeny),
			want: []string{"built-in Observer rule"},
		},
		{
			name:     "a flag is not a block",
			av:       sandboxVerdict(BlockNoticeSandboxNode, "U-901", policy.SourceOrg, policy.DecisionFlag),
			wantNone: true,
		},
		{
			name:     "no rule",
			av:       sandboxVerdict(BlockNoticeSandboxNode, "", policy.SourceOrg, policy.DecisionDeny),
			wantNone: true,
		},
		{
			name: "node-local org lock unchanged",
			av:   sandboxVerdict(BlockNoticeNode, "U-901", policy.SourceOrg, policy.DecisionDeny),
			node: "observer: U-901 blocked this command; your organization locks this rule. Ask your admin: Observer dashboard, Requests page, or run `observer request access --rule U-901 \"<reason>\"`.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := HumanBlockLine(tc.av, "s-1")
			if tc.node != "" {
				if got != tc.node {
					t.Fatalf("node-local line changed:\n got %q\nwant %q", got, tc.node)
				}
				return
			}
			if tc.wantNone {
				if got != "" {
					t.Fatalf("line for a non-block: %q", got)
				}
				return
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("line lacks %q: %q", w, got)
				}
			}
			for _, n := range never {
				if strings.Contains(got, n) {
					t.Errorf("sandbox line points at %q: %q", n, got)
				}
			}
			if strings.Contains(got, "—") {
				t.Errorf("em-dash in %q", got)
			}
		})
	}
}

// TestSandboxBlockNoticeDegradedAskAndPrompt: under a sandbox notice the
// degraded-ask sentence (an `observer guard approve` pointer) is not added,
// and a blocked prompt's hint is the sandbox line, even when the rule is not
// org-locked.
func TestSandboxBlockNoticeDegradedAskAndPrompt(t *testing.T) {
	av := sandboxVerdict(BlockNoticeSandboxNode, "R-110", policy.SourceBuiltin, policy.DecisionAsk)
	av.OrgLocked = false
	em := Emission{Enforced: true, Permission: "deny", DegradedFrom: policy.DecisionAsk.String(), Reason: "rule reason"}
	if got := ExplainDegradedAsk(em, av, "s-1"); got.Reason != "rule reason" {
		t.Fatalf("degraded-ask sentence added in the sandbox: %q", got.Reason)
	}
	av.BlockNotice = BlockNoticeNode
	if got := ExplainDegradedAsk(em, av, "s-1"); !strings.Contains(got.Reason, "guard approve") {
		t.Fatalf("node-local degraded-ask sentence lost: %q", got.Reason)
	}

	pv := PromptVerdict{
		Outcome:     PromptOutcomeBlocked,
		BlockNotice: BlockNoticeSandboxOrg,
		Verdict:     policy.Verdict{RuleID: "R-190", Decision: policy.DecisionDeny, Source: policy.SourceBuiltin},
	}
	got := PromptRequestAccessHint(pv, "s-1")
	if !strings.HasPrefix(got, "R-190 blocked this prompt.") || !strings.Contains(got, "ask an org admin") || strings.Contains(got, "request access") {
		t.Fatalf("sandbox prompt hint = %q", got)
	}
	pv.BlockNotice = BlockNoticeNode
	if got := PromptRequestAccessHint(pv, "s-1"); got != "" {
		t.Fatalf("node-local hint for a rule that is not org-locked: %q", got)
	}
}

// TestBlockNoticeStampedFromOptions: the guard copies Options.BlockNotice
// onto every verdict it stamps, beside RequestBase.
func TestBlockNoticeStampedFromOptions(t *testing.T) {
	g, err := New(Options{BlockNotice: BlockNoticeSandboxNode})
	if err != nil {
		t.Fatal(err)
	}
	av := ActionVerdict{Verdict: policy.Verdict{RuleID: "R-101", Decision: policy.DecisionDeny}}
	g.stampOrgOverrideAt(g.set.Load(), &av, "")
	if av.BlockNotice != BlockNoticeSandboxNode {
		t.Fatalf("BlockNotice = %q", av.BlockNotice)
	}
}

func sandboxVerdict(n BlockNotice, rule, source string, d policy.Decision) ActionVerdict {
	return ActionVerdict{
		Kind:        policy.KindShellExec,
		Verdict:     policy.Verdict{RuleID: rule, Decision: d, Source: source},
		OrgLocked:   true,
		BlockNotice: n,
	}
}
