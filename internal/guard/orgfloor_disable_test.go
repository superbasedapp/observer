package guard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestOrgRuleNotDisabledByLocalConfig (OSH-R-014): a local
// `[guard.rules] disable` cannot remove a rule the organization's signed
// policy tunes or defines. The org-tuned built-in still blocks in enforce
// mode, the org-defined rule still fires, the drop is reported as a load
// issue, and a rule the org did not touch stays disable-able.
func TestOrgRuleNotDisabledByLocalConfig(t *testing.T) {
	t.Parallel()
	const orgBody = "[[override]]\nrule = \"R-101\"\ndecision = \"deny\"\n" +
		"[[rule]]\nid = \"U-991\"\ncategory = \"destructive\"\nseverity = \"high\"\ndecision = \"deny\"\n" +
		"[rule.match]\nkind = \"shell\"\ncommand_regex = \"^touch /tmp/org-floor$\"\n"
	env, pin := signedEnvelope(t, 510, orgBody)
	cfg := guardCfgOrg()
	cfg.Mode = "enforce"
	cfg.Rules.Disable = []string{"R-101", "U-991", "R-102"}
	g, err := New(Options{
		Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
		ReadFile: fsMap(map[string]string{orgBundlePath: env}), OrgKeyPinHash: pin,
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	eval := func(cmd string) policy.Verdict {
		t.Helper()
		v, gerr := g.Evaluate(policy.Event{
			Kind: policy.KindShellExec, ActionType: "run_command",
			Target: cmd, Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj",
		})
		if gerr != nil {
			t.Fatalf("Evaluate: %v", gerr)
		}
		return v
	}
	if v := eval("rm -rf ~/projects"); v.RuleID != "R-101" || v.Decision != policy.DecisionDeny {
		t.Fatalf("org-tuned R-101 after a local disable: %s %s, want R-101 deny (issues %v)", v.RuleID, v.Decision, g.LoadIssues())
	}
	if v := eval("touch /tmp/org-floor"); v.RuleID != "U-991" || v.Decision != policy.DecisionDeny {
		t.Fatalf("org rule U-991 after a local disable: %s %s, want U-991 deny (issues %v)", v.RuleID, v.Decision, g.LoadIssues())
	}
	issues := strings.Join(g.LoadIssues(), "\n")
	for _, id := range []string{"R-101", "U-991"} {
		if !strings.Contains(issues, "disable of "+id+" ignored") {
			t.Errorf("no load issue for the ignored disable of %s:\n%s", id, issues)
		}
	}
	if strings.Contains(issues, "disable of R-102 ignored") {
		t.Errorf("a rule the org did not touch was reported as floored:\n%s", issues)
	}
}
