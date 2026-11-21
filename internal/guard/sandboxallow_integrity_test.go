package guard

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestSandboxAllowRule_IntegrityFloor pins operator ruling OB-029: R-167
// (an agent widening its own sandbox egress) is an integrity rule, so no
// layer below the org can remove, relax or cap it. One row per below-org
// path: a [guard.rules] disable (kept by the policy.New backstop), then,
// each dropped by the merge layer with a load issue, a user policy file
// override to allow, a trusted per-project override to allow, a trusted
// per-project disable, and an `enforce = false` cap (which would hold the
// rule at flag) from the user file and from the trusted file (CF1-A5).
func TestSandboxAllowRule_IntegrityFloor(t *testing.T) {
	t.Parallel()
	ev := policy.Event{
		Kind:        policy.KindShellExec,
		Target:      "observer config set terminal.sandbox.egress_allow_hosts evil.example.com",
		Cwd:         "/home/u/proj",
		ProjectRoot: "/home/u/proj",
	}
	const (
		relax       = "[[override]]\nrule = \"R-167\"\ndecision = \"allow\"\n"
		enforceCap  = "[[override]]\nrule = \"R-167\"\nenforce = false\n"
		disableRule = "disable = [\"R-167\"]\n"
	)
	cases := []struct {
		name        string
		disable     []string
		userFile    string
		trustedFile string
		wantIssue   bool
	}{
		{name: "config disable", disable: []string{"R-167"}},
		{name: "user policy relax", userFile: relax, wantIssue: true},
		{name: "trusted project relax", trustedFile: relax, wantIssue: true},
		{name: "trusted project disable", trustedFile: disableRule, wantIssue: true},
		{name: "user policy enforce cap", userFile: enforceCap, wantIssue: true},
		{name: "trusted project enforce cap", trustedFile: enforceCap, wantIssue: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := guardCfg()
			if tc.trustedFile != "" {
				cfg = trustedCfg()
			}
			cfg.Mode = "enforce"
			cfg.Rules.Disable = tc.disable
			files := map[string]string{}
			if tc.userFile != "" {
				files["/home/u/.observer/guard-policy.toml"] = tc.userFile
			}
			if tc.trustedFile != "" {
				files[trustedKey(cfg, "/home/u/proj")] = tc.trustedFile
			}
			g := newTestGuardCfg(t, cfg, files)
			v, _ := g.Evaluate(ev)
			if v.RuleID != "R-167" || v.Decision != policy.DecisionDeny {
				t.Errorf("verdict = %+v, want R-167/deny (integrity floor)", v)
			}
			if tc.wantIssue && !hasIssue(g.LoadIssues(), "R-167", "integrity") {
				t.Errorf("integrity drop not recorded: %v", g.LoadIssues())
			}
		})
	}
}
