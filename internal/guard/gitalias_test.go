package guard

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestGitAliasLookupReachesTheEngine pins the injected alias table (R-112,
// D-761): wired after construction, it reaches the engine already built, so
// `git ci` is judged as the `commit -n` it runs; unwired, the alias is not
// resolved.
func TestGitAliasLookupReachesTheEngine(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	ev := policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command", Target: "git ci -m wip",
		Cwd: "/home/u/proj/src", ProjectRoot: "/home/u/proj",
	}
	if v, err := g.Evaluate(ev); err != nil || v.RuleID == "R-112" {
		t.Fatalf("no table: verdict %s/%s err %v, want no R-112", v.RuleID, v.Decision, err)
	}
	var asked string
	g.SetGitAliasLookup(func(dir string) (map[string]string, bool) {
		asked = dir
		return map[string]string{"ci": "commit -n"}, true
	})
	v, err := g.Evaluate(ev)
	if err != nil || v.RuleID != "R-112" || v.Decision != policy.DecisionDeny {
		t.Fatalf("with table: verdict %s/%s err %v, want R-112/deny", v.RuleID, v.Decision, err)
	}
	if asked != "/home/u/proj/src" {
		t.Errorf("lookup asked for %q, want the event's working directory", asked)
	}
	g.SetGitAliasLookup(nil)
	if v, _ := g.Evaluate(ev); v.RuleID == "R-112" {
		t.Fatal("cleared table still resolved the alias")
	}
}
