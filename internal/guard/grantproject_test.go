package guard

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestGrantProjectResolution pins grantProject's ordered table (GRANT-20):
// the root the grant matcher hashes is the root the audit row records, one
// row per case, and the matcher's hash is always the recorded root's hash.
func TestGrantProjectResolution(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		nilEvent    bool
		projectRoot string
		lookupRoot  string
		sessionID   string
		resolver    SessionProjectRootLookup
		wantRoot    string
	}{
		{name: "1 host-named root", projectRoot: "/r/host", lookupRoot: "/r/cwd", sessionID: "s", resolver: func(string) string { return "/r/session" }, wantRoot: "/r/host"},
		{name: "2 boundary-derived root", lookupRoot: "/r/cwd", sessionID: "s", resolver: func(string) string { return "/r/session" }, wantRoot: "/r/cwd"},
		{name: "3 session resolver", sessionID: "s", resolver: func(string) string { return "/r/session" }, wantRoot: "/r/session"},
		{name: "3 resolver wired but no session", resolver: func(string) string { return "/r/session" }, wantRoot: ""},
		{name: "4 nothing", sessionID: "s", wantRoot: ""},
		{name: "nil event", nilEvent: true, resolver: func(string) string { return "/r/session" }, wantRoot: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := newTestGuard(t, guardCfg(), nil)
			if tc.resolver != nil {
				g.SetSessionProjectRootLookup(tc.resolver)
			}
			var ev *policy.Event
			if !tc.nilEvent {
				ev = &policy.Event{ProjectRoot: tc.projectRoot, ProjectLookupRoot: tc.lookupRoot, SessionID: tc.sessionID}
			}
			got := g.grantProject(ev)
			if got.Root != tc.wantRoot || got.Hash != HashProjectRoot(tc.wantRoot) {
				t.Errorf("grantProject = %+v, want root %q hash %q", got, tc.wantRoot, HashProjectRoot(tc.wantRoot))
			}
			if !tc.nilEvent {
				if h := g.approvalProjectRootHash(ev); h != got.Hash {
					t.Errorf("matcher hash %q != recorded hash %q", h, got.Hash)
				}
			}
		})
	}
}

// TestStampGrantProjectOnlyOnRecordedVerdicts: a verdict that is never
// written (below flag, no guard error) is left alone and pays no session
// read; a recorded one carries the project.
func TestStampGrantProjectOnlyOnRecordedVerdicts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		decision  policy.Decision
		guardErr  bool
		wantRoot  string
		wantReads int
	}{
		{name: "allow is not recorded", decision: policy.DecisionAllow, wantRoot: "", wantReads: 0},
		{name: "allow guard error is recorded", decision: policy.DecisionAllow, guardErr: true, wantRoot: "/r/session", wantReads: 1},
		{name: "flag", decision: policy.DecisionFlag, wantRoot: "/r/session", wantReads: 1},
		{name: "deny", decision: policy.DecisionDeny, wantRoot: "/r/session", wantReads: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := newTestGuard(t, guardCfg(), nil)
			reads := 0
			g.SetSessionProjectRootLookup(func(string) string { reads++; return "/r/session" })
			av := ActionVerdict{Verdict: policy.Verdict{Decision: tc.decision}, GuardError: tc.guardErr}
			g.stampGrantProject(&av, &policy.Event{SessionID: "s"})
			if av.GrantProject.Root != tc.wantRoot || reads != tc.wantReads {
				t.Errorf("GrantProject = %+v after %d reads, want root %q after %d", av.GrantProject, reads, tc.wantRoot, tc.wantReads)
			}
		})
	}
}

// TestGrantProjectStampedOnEachLane: the hook gate, the watcher and the
// proxy each record the project their grant question was asked under.
// The hook case is the GRANT-20 report: a session whose project is the
// parent folder, a call whose cwd is another repository; the row must
// name the repository the call ran in.
func TestGrantProjectStampedOnEachLane(t *testing.T) {
	t.Parallel()
	const sessionRoot, repo = "/home/u", "/home/u/other-repo"
	resolver := func(string) string { return sessionRoot }

	t.Run("hook: the cwd-derived repository, not the session's project", func(t *testing.T) {
		t.Parallel()
		cfg := guardCfg()
		cfg.Mode = "enforce"
		g := newTestGuard(t, cfg, nil)
		g.SetSessionProjectRootLookup(resolver)
		var asked string
		g.SetApprovalLookup(func(_, _, h string) (bool, error) { asked = h; return false, nil })
		v, worthy := g.EvaluateHook(policy.Event{
			Kind: policy.KindShellExec, ActionType: "run_command", Target: "rm -rf ~",
			SessionID: "sA", ProjectLookupRoot: repo,
			Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
		})
		if !worthy || v.Verdict.Decision < policy.DecisionAsk {
			t.Fatalf("verdict = %+v, want a recorded block", v.Verdict)
		}
		if v.GrantProject.Root != repo || v.GrantProject.Hash != asked {
			t.Errorf("GrantProject = %+v, matcher asked %q; want root %q and the matcher's hash", v.GrantProject, asked, repo)
		}
	})

	t.Run("watcher: the action's project root", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, guardCfg(), nil)
		g.SetSessionProjectRootLookup(resolver)
		out := g.EvaluateActions([]ActionInput{{
			ActionID: 1, SessionID: "sA", ProjectRoot: repo, Tool: "claude-code",
			ActionType: "run_command", Target: "rm -rf ~", Timestamp: time.Now().UTC(),
		}})
		if len(out) == 0 {
			t.Fatal("no verdict for rm -rf ~")
		}
		if out[0].GrantProject.Root != repo || out[0].GrantProject.Hash != HashProjectRoot(repo) {
			t.Errorf("GrantProject = %+v, want %q", out[0].GrantProject, repo)
		}
	})

	t.Run("proxy: the session's project", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, budgetCfg("enforce", true), nil)
		g.SetSessionProjectRootLookup(resolver)
		g.SetBudgetLookup(func(string) (BudgetSnapshot, bool) { return BudgetSnapshot{SessionUSD: 9.0}, true })
		res := g.ScanProxyRequest("anthropic", []byte(`{"model":"claude-x","messages":[]}`), "s1", time.Now().UTC())
		if len(res.Verdicts) != 1 {
			t.Fatalf("verdicts = %+v", res.Verdicts)
		}
		if got := res.Verdicts[0].GrantProject; got.Root != sessionRoot || got.Hash != HashProjectRoot(sessionRoot) {
			t.Errorf("GrantProject = %+v, want %q", got, sessionRoot)
		}
	})
}

// TestPromptBridgeCarriesGrantProject: the ONE PromptVerdict -> ActionVerdict
// bridge keeps the prompt's grant project for the audit row.
func TestPromptBridgeCarriesGrantProject(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, guardCfg(), nil)
	gp := GrantProject{Root: "/r/repo", Hash: HashProjectRoot("/r/repo")}
	av := g.ActionVerdictFromPrompt(PromptVerdict{
		Verdict:      policy.Verdict{RuleID: "R-172", Decision: policy.DecisionAsk},
		GrantProject: gp,
	}, Emission{Permission: "ask"}, ActionInput{SessionID: "s"})
	if av.GrantProject != gp {
		t.Errorf("bridged GrantProject = %+v, want %+v", av.GrantProject, gp)
	}
}
