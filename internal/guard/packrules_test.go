package guard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// packRule is an S-7xx-shaped pack row that fires on any commit.
func packRule() policy.Rule {
	return policy.Rule{
		ID: "S-791", Category: policy.CategoryCodeSecurity, Severity: policy.SeverityHigh,
		AppliesTo: []policy.EventKind{policy.KindShellExec},
		Match: func(ctx *policy.MatchContext) (bool, string) {
			return len(policy.GatedGitWrites(ctx)) > 0, "agent commit"
		},
		Observe: policy.DecisionFlag, Enforce: policy.DecisionAsk, Source: policy.SourcePackSecurity,
		Doc: "agent commit (test pack row)",
	}
}

// TestBrokenPackIsDroppedNotFatal: a pack that does not build is dropped
// with an issue and guard keeps its built-ins.
func TestBrokenPackIsDroppedNotFatal(t *testing.T) {
	t.Parallel()
	bad := packRule()
	bad.Doc = ""
	g, err := New(Options{Config: guardCfg(), Home: "/home/u", PackRules: []policy.Rule{bad}, ReadFile: fsMap(nil)})
	if err != nil {
		t.Fatalf("a broken pack must not fail guard: %v", err)
	}
	if !strings.Contains(strings.Join(g.LoadIssues(), "\n"), "rule pack dropped") {
		t.Fatalf("issues = %v", g.LoadIssues())
	}
}

// TestOverrideOnUnloadedPackRuleIsALoadIssue (security pillar plan
// section 4.7 item 1, acceptance A): with the security module skipped, a
// user override naming an S-7xx rule is dropped with a load issue, never a
// construction error, and the rest of the user layer still loads.
func TestOverrideOnUnloadedPackRuleIsALoadIssue(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, guardCfg(), map[string]string{
		"/home/u/.observer/guard-policy.toml": "[[override]]\nrule = 'S-721'\ndecision = 'deny'\n\n[[override]]\nrule = 'R-110'\ndecision = 'deny'\nenforce = true\n",
	})
	issues := strings.Join(g.LoadIssues(), "\n")
	if !strings.Contains(issues, "rule S-721 is not loaded: Code security is not active") {
		t.Fatalf("load issues = %q, want the not-loaded issue", issues)
	}
	if strings.Contains(issues, "user policy layer dropped") {
		t.Fatalf("the user layer must survive: %q", issues)
	}
	v, _ := g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "git push --force origin main", ProjectRoot: "/home/u/proj"})
	if v.RuleID != "R-110" || v.Decision != policy.DecisionDeny {
		t.Fatalf("the user layer's other override must apply: %+v", v)
	}
}

// TestPackRulesAreTunedLikeBuiltins: a loaded pack row fires with its
// pack source, and a user override may tune it.
func TestPackRulesAreTunedLikeBuiltins(t *testing.T) {
	t.Parallel()
	g, err := New(Options{
		Config: guardCfg(), Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
		PackRules: []policy.Rule{packRule()},
		ReadFile: fsMap(map[string]string{
			"/home/u/.observer/guard-policy.toml": "[[override]]\nrule = 'S-791'\ndecision = 'deny'\nenforce = true\n",
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if issues := g.LoadIssues(); len(issues) != 0 {
		t.Fatalf("unexpected issues: %v", issues)
	}
	v, _ := g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "git commit -m x", ProjectRoot: "/home/u/proj"})
	if v.RuleID != "S-791" || v.Decision != policy.DecisionDeny {
		t.Fatalf("pack rule with the user override = %+v, want S-791 deny", v)
	}
	g2, err := New(Options{Config: guardCfg(), Home: "/home/u", PackRules: []policy.Rule{packRule()}, ReadFile: fsMap(nil)})
	if err != nil {
		t.Fatal(err)
	}
	v, _ = g2.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "git commit -m x", ProjectRoot: "/home/u/proj"})
	if v.RuleID != "S-791" || v.Decision != policy.DecisionFlag || v.Source != policy.SourcePackSecurity {
		t.Fatalf("pack rule verdict = %+v, want S-791 flag from %s", v, policy.SourcePackSecurity)
	}
}

// TestProjectLayerMayOnlyEscalatePackRules: the project layer is the least
// trusted; it cannot relax a pack row.
func TestProjectLayerMayOnlyEscalatePackRules(t *testing.T) {
	t.Parallel()
	_, _, _, issues := mergeLayersWithPack([]policy.Rule{packRule()}, nil, nil, &policyFile{
		overrides: []rawOverride{{Layer: layerProject, RuleID: "S-791", HasDec: true, Decision: policy.DecisionAllow}},
	}, nil)
	if len(issues) != 1 || !strings.Contains(issues[0], "project override on S-791 dropped") {
		t.Fatalf("issues = %v, want the project relaxation dropped", issues)
	}
}
