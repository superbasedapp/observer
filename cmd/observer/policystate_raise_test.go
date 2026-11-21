package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/govern"
)

// TestPolicyStateReportingEnabled_OrgRaise pins D-DEMO-13 (demo estate,
// 2026-09-21) as the 2026-11-12 ruling extends it: a managed node always
// reports (the share switch gates individual nodes only), and an individual
// node that did not opt in stays silent even though its reporter loop runs.
func TestPolicyStateReportingEnabled_OrgRaise(t *testing.T) {
	t.Parallel()
	raised := govern.Effective{
		Managed:   true,
		Authority: []string{govern.AuthorityExtractPolicyState},
		Share:     map[string]any{"policy_state": true},
	}
	lowered := govern.Effective{
		Managed:   true,
		Authority: []string{govern.AuthorityExtractPolicyState},
		Share:     map[string]any{"policy_state": false},
	}
	cases := []struct {
		name  string
		local bool
		eff   govern.Effective
		want  bool
	}{
		// 2026-11-12 ruling (managed policy visibility G1): a managed node
		// reports whatever its share switch, its grant tokens or a
		// directive say; the switch gates individual nodes only.
		{"managed, local off, org raises under extract.policy_state", false, raised, true},
		{"managed, local off, no directive", false, govern.Effective{Managed: true}, true},
		{"managed, local off, directive but authority not granted", false, govern.Effective{Managed: true, Share: map[string]any{"policy_state": true}}, true},
		{"managed, local on, org lowers", true, lowered, true},
		{"individual, local off, directive", false, govern.Effective{Managed: false, Authority: []string{govern.AuthorityExtractPolicyState}, Share: map[string]any{"policy_state": true}}, false},
		{"individual, local on, org lowers", true, govern.Effective{Share: map[string]any{"policy_state": false}}, false},
		{"individual, local on, no directive", true, govern.Effective{}, true},
		{"individual, local off, no directive", false, govern.Effective{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := policyStateReportingEnabled(tc.local, tc.eff); got != tc.want {
				t.Fatalf("policyStateReportingEnabled(local=%v) = %v, want %v", tc.local, got, tc.want)
			}
		})
	}
}

// TestPolicyStateReporter_RunIsDormantWhenNotEnabled pins the other half of
// D-DEMO-13: the run loop no longer short-circuits on the local opt-in (the
// org may raise it later), so a reporter with the opt-in off and no
// governance handle must loop WITHOUT posting anything.
func TestPolicyStateReporter_RunIsDormantWhenNotEnabled(t *testing.T) {
	t.Parallel()
	fp := &fakePoster{}
	// Fully assembled (readers, seq counter, logger) so a regressed gate
	// FAILS on the post count instead of nil-panicking inside report().
	rep := &policyStateReporter{
		poster: fp, enabled: false, notifier: newPolicyStateNotifier(),
		readers: fourReaders(), seq: seqCounter(t), logger: slog.Default(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rep.run(ctx, 5*time.Millisecond) }()
	rep.notifier.Poke()
	time.Sleep(60 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop on ctx cancel")
	}
	if n := fp.callCount(); n != 0 {
		t.Fatalf("dormant reporter posted %d snapshot(s), want 0", n)
	}
}
