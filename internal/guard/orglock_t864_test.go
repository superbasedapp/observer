package guard

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestOrgBundleDeletionFailsClosed pins T-864 gap 1 (re-test row b1): a
// DELETED org bundle on a node that had accepted one is a tamper exactly like
// an edited one. Every row has a local approval for every rule (the
// developer's `observer guard approve R-101 --global`).
func TestOrgBundleDeletionFailsClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		lock         func(env, pin string) config.GuardOrgLock
		tenancy      func() bool
		expected     bool
		wantDecision policy.Decision
		wantLocked   bool
		wantLKG      bool
		wantTampered bool
	}{
		{"managed lock: the last verified copy enforces", managedLock, nil, false, policy.DecisionDeny, true, true, true},
		{"bundle and lock deleted, the posture anchor says org expected: every rule locked", anchoredTamperedLock, nil, false, policy.DecisionDeny, true, false, true},
		{"daemon store says a bundle was accepted, managed: every rule locked", noLock, func() bool { return true }, true, policy.DecisionDeny, true, false, true},
		{"individual lock: a deletion is the developer's call", individualLock, nil, false, policy.DecisionFlag, false, false, false},
		{"never accepted a bundle: nothing to fail closed on", noLock, func() bool { return true }, false, policy.DecisionFlag, false, false, false},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env, pin := signedEnvelope(t, int64(970+i), orgOverridableBundleTOML)
			cfg := guardCfgOrg()
			cfg.Mode = "enforce"
			cfg.Lock = tc.lock(env, pin)
			g, err := New(Options{
				Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
				ReadFile:          fsMap(map[string]string{}), // the bundle file is gone
				ManagedTenancy:    tc.tenancy,
				OrgBundleExpected: tc.expected,
			})
			if err != nil {
				t.Fatalf("guard.New: %v", err)
			}
			g.SetApprovalLookup(func(string, string, string) (bool, error) { return true, nil })
			av, _ := g.EvaluateHook(rmRfEvent())
			if av.Verdict.Decision != tc.wantDecision {
				t.Fatalf("rm -rf / = %v (%s), want %v (issues %v)", av.Verdict.Decision, av.Verdict.Reason, tc.wantDecision, g.LoadIssues())
			}
			if _, locked := g.OrgOverrideStatus("R-101"); locked != tc.wantLocked {
				t.Fatalf("OrgOverrideStatus(R-101) locked = %v, want %v (the CLI approve refusal reads it)", locked, tc.wantLocked)
			}
			st := g.OrgLockStatus()
			if st.LastVerifiedInUse != tc.wantLKG || st.BundleTampered != tc.wantTampered {
				t.Fatalf("OrgLockStatus = %+v, want LKG=%v tampered=%v", st, tc.wantLKG, tc.wantTampered)
			}
		})
	}
}

// anchoredTamperedLock is config.Load's reading when the lock and the bundle
// were deleted together and the daemon's MAC'd posture says a managed node
// with an org layer: no tenancy, no copy, but an org is expected.
func anchoredTamperedLock(string, string) config.GuardOrgLock {
	return config.GuardOrgLock{State: "tampered", Detail: "org lock missing", OrgExpected: true}
}

// TestReloadOverADeletedBundleKeepsTheOrgLayer: the daemon's live guard keeps
// its org layer when the cached file is deleted, records the tamper, and
// reports the deletion as a file issue for the posture loop (T-864 gap 1).
func TestReloadOverADeletedBundleKeepsTheOrgLayer(t *testing.T) {
	t.Parallel()
	env, pin := signedEnvelope(t, 990, orgOverridableBundleTOML)
	files := map[string]string{orgBundlePath: env}
	cfg := guardCfgOrg()
	cfg.Mode = "enforce"
	g, err := New(Options{
		Config: cfg, Home: "/home/u", OrgKeyPinHash: pin, OrgBundleExpected: true,
		ReadFile:       func(p string) ([]byte, error) { return fsMap(files)(p) },
		ManagedTenancy: func() bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	delete(files, orgBundlePath)
	if err := g.ReloadOrgLayer(context.Background()); err == nil {
		t.Fatal("reload over a deleted bundle returned nil")
	}
	if issue, _ := g.OrgBundleFileIssue(); issue == "" {
		t.Fatal("OrgBundleFileIssue is silent about a deleted bundle")
	}
	if _, locked := g.OrgOverrideStatus("R-101"); !locked {
		t.Fatal("the live guard dropped the org lock")
	}
	if !g.OrgLockStatus().BundleTampered {
		t.Fatal("the deletion was not recorded as a tamper")
	}
}
