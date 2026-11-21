//go:build !sbo_omit_terminals_sandbox_landlock && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
)

// sandbox_setup_fix5_test.go pins fix round 5 (D-R4-2, second half): the
// daemon's cached sandbox probe is dropped when a setup record settles, so
// the next probe reads the host again within the 60 s TTL.

// TestSandboxProbeFresh is one case per shape of the cache rule.
func TestSandboxProbeFresh(t *testing.T) {
	now := time.Now()
	gen := sandboxProbeGeneration()
	cases := []struct {
		name string
		at   time.Time
		gen  uint64
		want bool
	}{
		{"never probed", time.Time{}, gen, false},
		{"within the TTL, same generation", now.Add(-time.Second), gen, true},
		{"past the TTL", now.Add(-2 * sandboxProbeTTL), gen, false},
		{"an older generation", now.Add(-time.Second), gen - 1, false},
	}
	for _, tc := range cases {
		if got := sandboxProbeFresh(tc.at, tc.gen, now); got != tc.want {
			t.Errorf("%s: fresh = %v, want %v", tc.name, got, tc.want)
		}
	}
	dropSandboxProbeCache()
	if sandboxProbeFresh(now.Add(-time.Second), gen, now) {
		t.Fatal("a probe taken before a drop is still served")
	}
}

// TestSandboxProbeReadsAgainAfterASettle: a probe cached under one host
// answer keeps it within the TTL, then a setup record that settles drops it
// and the next probe (the runtime's and the driver's) reads the host again,
// well within the TTL, and the hook names the record's backend.
func TestSandboxProbeReadsAgainAfterASettle(t *testing.T) {
	reads := fakeLandlockABI(t, 9)
	rt := landlockTestRuntime(t, landlockTestConfig(t, true, "process_lite"))
	ctx := context.Background()
	_ = rt.ProbeSandbox(ctx)
	first := reads.Load()
	if first == 0 {
		t.Fatal("the first probe read nothing")
	}
	_ = rt.ProbeSandbox(ctx)
	if reads.Load() != first {
		t.Fatalf("a probe within the TTL read the host again (%d reads)", reads.Load())
	}

	r := newSetupRig(t, setupBaseConfig)
	var backends []string
	r.svc.run.refreshProbe = func(ctx context.Context, backend string) string {
		backends = append(backends, backend)
		return sandboxProbeRefreshFor("dashboard", "")(ctx, backend)
	}
	id, err := r.ledger.BeginSandboxOp(ctx, sandboxInstallRecord{Name: "landlock-abi", Backend: sandboxbackend.BackendProcessLite, Channel: string(sandboxsetup.ChPinned), Argv: []string{"x"}, Display: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ledger.FinishSandboxOp(ctx, id, sandboxOpOutcome{}, func() string { return "found" }); err != nil {
		t.Fatal(err)
	}
	if len(backends) != 1 || backends[0] != sandboxbackend.BackendProcessLite {
		t.Fatalf("the settle hook ran for %v, want [%s]", backends, sandboxbackend.BackendProcessLite)
	}
	_ = rt.ProbeSandbox(ctx)
	if reads.Load() == first {
		t.Fatal("the probe after a settle served the cached answer")
	}
}

// TestSandboxApplyLiveDropsTheProbeCache: a live apply (Enable, a Settings
// save, the apply route) drops the probe cache as well as rebuilding.
func TestSandboxApplyLiveDropsTheProbeCache(t *testing.T) {
	gen := sandboxProbeGeneration()
	applySandboxConfigLive()
	if sandboxProbeGeneration() == gen {
		t.Fatal("ApplyLive left the probe cache in place")
	}
}
