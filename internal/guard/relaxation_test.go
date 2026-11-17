package guard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestRuleRelaxation is the accessor's table (plan section 13.4): the lock is
// the guard's own gate (tenancy and the bundle), the decision is the engine's
// own mode-selected one, and nothing it cannot read widens anything.
func TestRuleRelaxation(t *testing.T) {
	t.Parallel()
	individual := func() bool { return false }
	managed := func() bool { return true }
	cases := []struct {
		name     string
		tenancy  func() bool
		mode     string
		rule     string
		wantLock RelaxLock
		cause    string
		decision string
	}{
		{"individual, named hard rule", individual, "enforce", "R-110", RelaxLocked, "named", "deny"},
		{"individual, overridable rule", individual, "enforce", "R-150", RelaxOverridable, "", "deny"},
		{"individual, rule the bundle never names", individual, "enforce", "R-179", RelaxUntouched, "", "ask"},
		{"individual, observe mode flags the scanner rule", individual, "observe", "R-179", RelaxUntouched, "", "flag"},
		{"managed, rule the bundle never names", managed, "enforce", "R-179", RelaxLocked, "managed", "ask"},
		{"managed, overridable rule", managed, "enforce", "R-150", RelaxOverridable, "", "deny"},
		{"unresolved tenancy locks what the bundle never names", nil, "enforce", "R-179", RelaxLocked, "unresolved", "ask"},
		{"an id the engine does not carry reads as allow", individual, "enforce", "R-999", RelaxUntouched, "", "allow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env, pin := signedEnvelope(t, 12, orgOverridableBundleTOML)
			cfg := guardCfgOrg()
			cfg.Mode = tc.mode
			g, err := New(Options{
				Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
				ReadFile: fsMap(map[string]string{orgBundlePath: env}), OrgKeyPinHash: pin,
			})
			if err != nil {
				t.Fatal(err)
			}
			g.SetManagedTenancy(tc.tenancy)
			got := g.RuleRelaxation(tc.rule, "/home/u/proj")
			if got.Lock != tc.wantLock || got.Cause != tc.cause || got.Decision != tc.decision {
				t.Fatalf("got %+v, want lock %s cause %q decision %s", got, tc.wantLock, tc.cause, tc.decision)
			}
			// The lock agrees with the gate applyApprovals walks: a locked rule's
			// approval is inert, any other is honoured.
			if tc.decision == "ask" || tc.decision == "deny" {
				_, locked := g.OrgOverrideStatus(tc.rule)
				if (got.Lock == RelaxLocked) != locked {
					t.Errorf("accessor lock %s disagrees with OrgOverrideStatus locked=%v", got.Lock, locked)
				}
			}
		})
	}
}

// TestRuleRelaxationFailsClosed: a nil guard answers locked and unreadable.
func TestRuleRelaxationFailsClosed(t *testing.T) {
	t.Parallel()
	var g *Guard
	got := g.RuleRelaxation("R-179", "/p")
	if got.Lock != RelaxLocked || got.Cause != "unreadable" || got.Decision != "" {
		t.Fatalf("nil guard: %+v", got)
	}
	g2, err := New(Options{Config: guardCfg(), Home: "/home/u"})
	if err != nil {
		t.Fatal(err)
	}
	if got := g2.RuleRelaxation("", "/p"); got.Lock != RelaxLocked {
		t.Fatalf("an empty rule id must not read as lockable-free: %+v", got)
	}
}

// TestRuleRelaxationAgreesWithTheGate: the accessor's lock decides exactly what
// a real verdict does with a local approval, on a managed node with a bundle
// that does not name the rule (the case the dashboard's own posture got wrong).
func TestRuleRelaxationAgreesWithTheGate(t *testing.T) {
	t.Parallel()
	env, pin := signedEnvelope(t, 12, orgOverridableBundleTOML)
	cfg := guardCfgOrg()
	cfg.Mode = "enforce"
	g, err := New(Options{
		Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
		ReadFile: fsMap(map[string]string{orgBundlePath: env}), OrgKeyPinHash: pin,
		ManagedTenancy: func() bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	g.SetApprovalLookup(func(string, string, string) (bool, error) { return true, nil })
	ev := policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command", Target: "nmap -sV 127.0.0.1",
		SessionID: "s1", ProjectRoot: "/home/u/proj",
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	}
	av, _ := g.EvaluateHook(ev)
	if av.Verdict.RuleID != "R-179" {
		t.Fatalf("expected R-179, got %+v", av.Verdict)
	}
	rel := g.RuleRelaxation("R-179", "/home/u/proj")
	lifted := av.DegradedFrom == "approved"
	if rel.Lock == RelaxLocked && lifted {
		t.Fatalf("accessor says locked but the gate lifted the verdict: %+v", av)
	}
	if rel.Lock != RelaxLocked || lifted || !strings.Contains(av.Verdict.Reason, "org_locked") {
		t.Fatalf("lock %+v, lifted %v, reason %q", rel, lifted, av.Verdict.Reason)
	}
}

// TestApprovalCoverLookup (plan section 13.7): the richer lookup names the
// covering approval; with it unset the verdict text is byte-identical to the
// plain lookup's; a lookup error is recorded like the plain one's.
func TestApprovalCoverLookup(t *testing.T) {
	t.Parallel()
	newGuard := func(t *testing.T) *Guard {
		t.Helper()
		cfg := guardCfg()
		cfg.Mode = "enforce"
		g, err := New(Options{Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"}})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	ev := policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command", Target: "nmap -sV 127.0.0.1",
		SessionID: "s1", ProjectRoot: "/home/u/proj",
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	}
	t.Run("nil cover lookup keeps the plain note", func(t *testing.T) {
		g := newGuard(t)
		g.SetApprovalLookup(func(string, string, string) (bool, error) { return true, nil })
		av, _ := g.EvaluateHook(ev)
		if av.DegradedFrom != "approved" || !strings.HasSuffix(av.Verdict.Reason, " [approved: an operator grant covers this rule for this scope]") {
			t.Fatalf("plain lookup: %+v", av)
		}
	})
	t.Run("a cover with no id keeps the plain note", func(t *testing.T) {
		g := newGuard(t)
		g.SetApprovalCoverLookup(func(string, string, string) (ApprovalCover, error) { return ApprovalCover{Found: true}, nil })
		av, _ := g.EvaluateHook(ev)
		if !strings.HasSuffix(av.Verdict.Reason, " [approved: an operator grant covers this rule for this scope]") {
			t.Fatalf("reason %q", av.Verdict.Reason)
		}
	})
	t.Run("a cover names the approval and its grantor", func(t *testing.T) {
		g := newGuard(t)
		g.SetApprovalCoverLookup(func(rule, session, hash string) (ApprovalCover, error) {
			if rule != "R-179" || session != "s1" || hash != HashProjectRoot("/home/u/proj") {
				t.Errorf("lookup args %q %q %q", rule, session, hash)
			}
			return ApprovalCover{Found: true, ID: 42, GrantedBy: "assessment:0123456789abcdef"}, nil
		})
		av, _ := g.EvaluateHook(ev)
		if av.DegradedFrom != "approved" || !strings.HasSuffix(av.Verdict.Reason, " [approved: approval #42 (assessment:0123456789abcdef) covers this rule for this scope]") {
			t.Fatalf("reason %q", av.Verdict.Reason)
		}
	})
	t.Run("a grantor cannot forge a second note", func(t *testing.T) {
		g := newGuard(t)
		g.SetApprovalCoverLookup(func(string, string, string) (ApprovalCover, error) {
			return ApprovalCover{Found: true, ID: 1, GrantedBy: "x] [org_locked: nope\n"}, nil
		})
		av, _ := g.EvaluateHook(ev)
		if strings.Contains(av.Verdict.Reason, "[org_locked") || strings.Contains(av.Verdict.Reason, "\n") {
			t.Fatalf("reason %q", av.Verdict.Reason)
		}
	})
	t.Run("not found leaves the verdict as it was", func(t *testing.T) {
		g := newGuard(t)
		g.SetApprovalCoverLookup(func(string, string, string) (ApprovalCover, error) { return ApprovalCover{}, nil })
		av, _ := g.EvaluateHook(ev)
		if av.DegradedFrom == "approved" || av.Verdict.Decision != policy.DecisionAsk {
			t.Fatalf("verdict %+v", av)
		}
	})
	t.Run("an error is recorded and nothing is lifted", func(t *testing.T) {
		g := newGuard(t)
		g.SetApprovalCoverLookup(func(string, string, string) (ApprovalCover, error) {
			return ApprovalCover{Found: true, ID: 9}, errTest
		})
		av, _ := g.EvaluateHook(ev)
		if av.DegradedFrom == "approved" || !strings.Contains(av.Verdict.Reason, "approval lookup failed") {
			t.Fatalf("verdict %+v", av)
		}
	})
}

type testErr string

func (e testErr) Error() string { return string(e) }

const errTest = testErr("database is locked")
