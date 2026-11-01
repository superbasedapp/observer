package guard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestProjectOnlyRuleIsOrgLockedOnAnIndividualNode extends audit finding 3
// (closed at the SEC-P merge) to a rule the project section DEFINES: on an
// individual node, a local approval cannot pass PRJ-X1 inside a root matching
// X, and nothing locks it elsewhere (it does not exist there).
func TestProjectOnlyRuleIsOrgLockedOnAnIndividualNode(t *testing.T) {
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX})
	f.match("/home/u/x", "X")
	cfg := guardCfgOrg()
	cfg.Mode = "enforce"
	cfg.Rules.ProjectPolicy = ""
	g, err := New(Options{
		Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/x"},
		ReadFile: fsMap(f.files), ManagedTenancy: func() bool { return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	g.SetApprovalLookup(func(string, string, string) bool { return true })
	av, _ := g.EvaluateHook(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command", Target: "curl https://billing.internal/x",
		SessionID: "s", ProjectRoot: "/home/u/x", Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	})
	if av.Verdict.RuleID != "PRJ-X1" || av.Verdict.Decision != policy.DecisionDeny || !av.OrgLocked || av.DegradedFrom == "approved" {
		t.Fatalf("a local approval passed the project-only rule: %+v locked=%v degraded=%q", av.Verdict, av.OrgLocked, av.DegradedFrom)
	}
}

// TestHookBuildsOneEngine is P-052 finding 5: a hook process (New, then one
// evaluation) under a v3 org layer builds ONE policy engine, whether its root
// matched a project (the folded engine only) or not (the base only); a plain
// v2 bundle still builds one.
func TestHookBuildsOneEngine(t *testing.T) {
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX})
	f.match("/home/u/x", "X")
	f.match("/home/u/none")
	for _, row := range []struct{ name, root, cmd, rule string }{
		{"matched root", "/home/u/x", "curl https://billing.internal/x", "PRJ-X1"},
		{"unmatched root", "/home/u/none", "curl https://billing.internal/x", ""},
	} {
		before := engineBuilds.Load()
		g := f.guard(false)
		av, _ := g.EvaluateHook(shellHookEvent(row.root, row.cmd))
		if built := engineBuilds.Load() - before; built != 1 {
			t.Errorf("%s: %d engine builds, want 1", row.name, built)
		}
		if av.Verdict.RuleID != row.rule && !(row.rule == "" && !strings.HasPrefix(av.Verdict.RuleID, "PRJ-")) {
			t.Errorf("%s: verdict %+v", row.name, av.Verdict)
		}
	}
	env, _ := signedEnvelope(t, 4, orgFloor)
	cfg := guardCfgOrg()
	cfg.Rules.ProjectPolicy = ""
	before := engineBuilds.Load()
	g, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: fsMap(map[string]string{orgBundlePath: env})})
	if err != nil {
		t.Fatal(err)
	}
	g.EvaluateHook(shellHookEvent("/home/u/x", "true"))
	if built := engineBuilds.Load() - before; built != 1 {
		t.Errorf("v2 bundle: %d engine builds, want 1", built)
	}
}

// TestProjectMatchChangeInvalidatesTheCachedEngine: a long-lived guard (the
// daemon's) notices a root's new match record, and a missing envelope that
// arrives, without a new bundle or an org reload.
func TestProjectMatchChangeInvalidatesTheCachedEngine(t *testing.T) {
	saved := projectRecheckEvery
	projectRecheckEvery = 0
	t.Cleanup(func() { projectRecheckEvery = saved })
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX})
	f.match("/home/u/x") // matched nothing yet
	g := f.guard(false)
	eval := func() string {
		v, _ := g.Evaluate(shell("/home/u/x", "curl https://billing.internal/x"))
		return v.RuleID
	}
	if r := eval(); r == "PRJ-X1" {
		t.Fatal("an unmatched root loaded X")
	}
	f.match("/home/u/x", "X")
	if r := eval(); r != "PRJ-X1" {
		t.Fatalf("after the match changed the cached engine stayed: %q", r)
	}
	f.match("/home/u/x")
	if r := eval(); r == "PRJ-X1" {
		t.Fatal("after the match was withdrawn X still applied")
	}
	// A matched project whose envelope is missing, then arrives.
	envPath := f.layout.EnvelopePath("X")
	envBody := f.files[envPath]
	delete(f.files, envPath)
	f.match("/home/u/x", "X")
	if r := eval(); r == "PRJ-X1" {
		t.Fatal("a missing envelope loaded")
	}
	f.files[envPath] = envBody
	if r := eval(); r != "PRJ-X1" {
		t.Fatalf("the arrived envelope was not picked up: %q", r)
	}
	// With the default interval a hot evaluation does not re-read the
	// record (one check per interval).
	projectRecheckEvery = saved
	f.match("/home/u/x")
	if r := eval(); r != "PRJ-X1" {
		t.Fatalf("inside the interval the cached engine should stand: %q", r)
	}
}

func shellHookEvent(root, cmd string) policy.Event {
	return policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command", Target: cmd, SessionID: "s", ProjectRoot: root,
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	}
}
