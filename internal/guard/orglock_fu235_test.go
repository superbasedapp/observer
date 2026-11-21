package guard

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestOrgLockReachFollowsResolvedTenancy pins FU-235 (a): how far the org
// lock reaches in a process that builds its guard from config alone (a hook)
// is decided by the tenancy the daemon's MAC'd records resolved, in EVERY
// lock state that resolved one. An individual node never locks a rule its
// org bundle does not name; the conservative "lock every rule" reading stays
// only where the tenancy is genuinely unknown and an org layer is present.
//
// The bundle names R-110 and R-150 and never mentions R-101, so R-101's lock
// is the blast-radius probe and R-110's lock the always-locked control.
func TestOrgLockReachFollowsResolvedTenancy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		lock      func(env, pin string) config.GuardOrgLock
		bundle    bool
		wantR101  bool
		wantR110  bool
		wantEvery bool
	}{
		{
			name: "tampered lock vouched individual by the posture: only named rules lock (the fix)",
			lock: func(string, string) config.GuardOrgLock {
				return config.GuardOrgLock{State: "tampered", TenancyKnown: true}
			},
			bundle: true, wantR101: false, wantR110: true, wantEvery: false,
		},
		{
			name: "tampered lock with an organization expected: every rule locks",
			lock: func(string, string) config.GuardOrgLock {
				return config.GuardOrgLock{State: "tampered", OrgExpected: true}
			},
			bundle: true, wantR101: true, wantR110: true, wantEvery: true,
		},
		{
			name:   "tampered lock with no tenancy, org layer present: conservative, every rule locks",
			lock:   func(string, string) config.GuardOrgLock { return config.GuardOrgLock{State: "tampered"} },
			bundle: true, wantR101: true, wantR110: true, wantEvery: true,
		},
		{
			name:   "valid individual lock: only named rules lock",
			lock:   individualLock,
			bundle: true, wantR101: false, wantR110: true, wantEvery: false,
		},
		{
			name:   "valid managed lock: every rule locks",
			lock:   managedLock,
			bundle: true, wantR101: true, wantR110: true, wantEvery: true,
		},
		{
			name:   "no lock, org layer present, tenancy unknown: conservative, every rule locks",
			lock:   noLock,
			bundle: true, wantR101: true, wantR110: true, wantEvery: true,
		},
		{
			name:   "no lock, no org bundle (an unenrolled node): nothing locks",
			lock:   noLock,
			bundle: false, wantR101: false, wantR110: false, wantEvery: false,
		},
		{
			name: "valid individual lock, no org bundle: nothing locks",
			lock: func(string, string) config.GuardOrgLock {
				return config.GuardOrgLock{State: "valid", TenancyKnown: true}
			},
			bundle: false, wantR101: false, wantR110: false, wantEvery: false,
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env, pin := signedEnvelope(t, int64(2350+i), orgOverridableBundleTOML)
			files := map[string]string{}
			if tc.bundle {
				files[orgBundlePath] = env
			}
			cfg := guardCfgOrg()
			cfg.Lock = tc.lock(env, pin)
			if !tc.bundle {
				cfg.Lock.Bundle = ""
			}
			g, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: fsMap(files)})
			if err != nil {
				t.Fatalf("guard.New: %v", err)
			}
			p := g.OrgOverridePosture()
			if _, locked := p.For("R-101"); locked != tc.wantR101 {
				t.Errorf("R-101 (unnamed) locked = %v, want %v", locked, tc.wantR101)
			}
			if _, locked := p.For("R-110"); locked != tc.wantR110 {
				t.Errorf("R-110 (named) locked = %v, want %v", locked, tc.wantR110)
			}
			if p.LocksEveryRule != tc.wantEvery {
				t.Errorf("LocksEveryRule = %v, want %v", p.LocksEveryRule, tc.wantEvery)
			}
		})
	}
}
