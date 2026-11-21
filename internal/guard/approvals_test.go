package guard

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestApprovals pins the §6.3 integration: an active grant downgrades
// a blocking verdict to flag with the exception RECORDED
// (degraded_from="approved" + reason suffix); flag verdicts never
// consult the lookup; lookup absence/refusal enforces.
func TestApprovals(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	mk := func(lookup ApprovalLookup) *Guard {
		g, err := New(Options{
			Config: cfg, Home: "/home/u",
			ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		})
		if err != nil {
			t.Fatalf("guard.New: %v", err)
		}
		g.SetApprovalLookup(lookup)
		return g
	}
	denyEvent := policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "rm -rf ~", SessionID: "sA", ProjectRoot: "/home/u/proj",
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	}

	t.Run("grant downgrades and records", func(t *testing.T) {
		t.Parallel()
		var askedRule, askedSession, askedHash string
		g := mk(func(ruleID, sessionID, rootHash string) (bool, error) {
			askedRule, askedSession, askedHash = ruleID, sessionID, rootHash
			return true, nil
		})
		v, worthy := g.EvaluateHook(denyEvent)
		if !worthy || v.Verdict.Decision != policy.DecisionFlag {
			t.Fatalf("verdict = %+v, want approved-downgrade to flag", v.Verdict)
		}
		if v.DegradedFrom != "approved" {
			t.Errorf("DegradedFrom = %q, want approved (the §14.4 exception register marker)", v.DegradedFrom)
		}
		if !strings.Contains(v.Verdict.Reason, "approved") {
			t.Errorf("reason lacks the approval note: %q", v.Verdict.Reason)
		}
		if askedRule != "R-101" || askedSession != "sA" || askedHash != HashProjectRoot("/home/u/proj") {
			t.Errorf("lookup args = (%s, %s, %s)", askedRule, askedSession, askedHash)
		}
	})

	t.Run("no grant enforces", func(t *testing.T) {
		t.Parallel()
		g := mk(func(string, string, string) (bool, error) { return false, nil })
		if v, _ := g.EvaluateHook(denyEvent); v.Verdict.Decision != policy.DecisionDeny {
			t.Errorf("verdict = %v, want deny when no grant covers it", v.Verdict.Decision)
		}
	})

	t.Run("nil lookup enforces", func(t *testing.T) {
		t.Parallel()
		g := mk(nil)
		if v, _ := g.EvaluateHook(denyEvent); v.Verdict.Decision != policy.DecisionDeny {
			t.Errorf("verdict = %v, want deny with no lookup wired", v.Verdict.Decision)
		}
	})

	t.Run("flag verdicts never consult the lookup", func(t *testing.T) {
		t.Parallel()
		calls := 0
		g := mk(func(string, string, string) (bool, error) { calls++; return true, nil })
		flagEvent := denyEvent
		flagEvent.Target = "git push --force origin feature-x" // near-miss: no rule
		_, _ = g.EvaluateHook(flagEvent)
		obs := guardCfg() // observe mode: rm -rf ~ is a flag verdict
		gObs, err := New(Options{
			Config: obs, Home: "/home/u",
			ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		})
		if err != nil {
			t.Fatal(err)
		}
		gObs.SetApprovalLookup(func(string, string, string) (bool, error) { calls++; return true, nil })
		_, _ = gObs.EvaluateHook(denyEvent)
		if calls != 0 {
			t.Errorf("lookup ran %d times for non-blocking verdicts — it must only pay on ask/deny", calls)
		}
	})
}

// TestApprovalProjectRootAndLookupFailure pins P-232 as an ordered table:
// the project hash the grant lookup is asked with (ProjectRoot, else the
// boundary's derived ProjectLookupRoot, else the session resolver), and a
// lookup that fails leaves the verdict blocking with the failure recorded
// in its reason, never a silent "no grant".
func TestApprovalProjectRootAndLookupFailure(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	const repo = "/home/u/proj"
	grantHash := HashProjectRoot(repo)
	base := policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "rm -rf ~", SessionID: "sA",
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	}
	cases := []struct {
		name        string
		projectRoot string
		lookupRoot  string
		resolver    SessionProjectRootLookup
		lookupErr   error
		wantHash    string
		wantDec     policy.Decision
		wantReason  string
	}{
		{name: "host root matches the project grant", projectRoot: repo, wantHash: grantHash, wantDec: policy.DecisionFlag, wantReason: "[approved"},
		{name: "cwd-only hook: derived root matches the project grant", lookupRoot: repo, wantHash: grantHash, wantDec: policy.DecisionFlag, wantReason: "[approved"},
		{name: "host root wins over the derived root", projectRoot: repo, lookupRoot: "/other", wantHash: grantHash, wantDec: policy.DecisionFlag, wantReason: "[approved"},
		{name: "derived root wins over the session resolver", lookupRoot: repo, resolver: func(string) string { return "/other" }, wantHash: grantHash, wantDec: policy.DecisionFlag, wantReason: "[approved"},
		{name: "no root at all: the session resolver answers", resolver: func(string) string { return repo }, wantHash: grantHash, wantDec: policy.DecisionFlag, wantReason: "[approved"},
		{name: "another project: no match", lookupRoot: "/other", wantHash: HashProjectRoot("/other"), wantDec: policy.DecisionDeny},
		{name: "nothing known: empty hash", wantHash: "", wantDec: policy.DecisionDeny},
		{name: "lookup failed: blocks and records why", lookupRoot: repo, lookupErr: errors.New("database is locked"), wantHash: grantHash, wantDec: policy.DecisionDeny, wantReason: "[approval lookup failed: database is locked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g, err := New(Options{
				Config: cfg, Home: "/home/u",
				ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
			})
			if err != nil {
				t.Fatal(err)
			}
			var asked string
			g.SetApprovalLookup(func(_, _, rootHash string) (bool, error) {
				asked = rootHash
				if tc.lookupErr != nil {
					return false, tc.lookupErr
				}
				return rootHash != "" && rootHash == grantHash, nil
			})
			if tc.resolver != nil {
				g.SetSessionProjectRootLookup(tc.resolver)
			}
			ev := base
			ev.ProjectRoot, ev.ProjectLookupRoot = tc.projectRoot, tc.lookupRoot
			v, _ := g.EvaluateHook(ev)
			if asked != tc.wantHash {
				t.Errorf("lookup asked with hash %q, want %q", asked, tc.wantHash)
			}
			if v.Verdict.Decision != tc.wantDec {
				t.Errorf("decision = %v, want %v (reason %q)", v.Verdict.Decision, tc.wantDec, v.Verdict.Reason)
			}
			if tc.wantReason != "" && !strings.Contains(v.Verdict.Reason, tc.wantReason) {
				t.Errorf("reason %q lacks %q", v.Verdict.Reason, tc.wantReason)
			}
			if tc.lookupErr != nil && v.DegradedFrom != "" {
				t.Errorf("DegradedFrom = %q on a failed lookup, want empty (nothing was downgraded)", v.DegradedFrom)
			}
		})
	}
}
