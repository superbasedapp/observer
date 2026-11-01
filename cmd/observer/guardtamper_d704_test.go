package main

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policystate"
)

// TestReporter_UnreadableBundleStillReports pins D-704 fix 1: a bundle path
// the node cannot read (the on-disk check now answers "missing" for it, see
// orgclient.VerifyCachedPolicyBundle) no longer suppresses the snapshot. The
// whole report is posted, the guard row carries the missing integrity and
// the repaired-tamper record, it never reads effective, and the poll is
// kicked to restore the bundle.
func TestReporter_UnreadableBundleStillReports(t *testing.T) {
	readers := fourReaders()
	v := &fakeBundleVerifier{check: orgclient.CachedBundleCheck{Integrity: orgcontract.BundleIntegrityMissing}}
	tamper := &orgcontract.GuardTamperReport{Repairs: 3, LastAt: "2026-10-17T00:01:34Z", LastKind: orgcontract.GuardTamperOrgBundle}
	readers[policystate.PointGuard] = withGuardTamper(newGuardPointReader(
		guardBundleCheckFrom(v, "/x/org-policy-bundle.json"),
		func() guardRunning { return guardRunning{RunningVersion: 1, EffectiveHash: psHex64, Mode: "enforce"} },
		func() orgclient.GuardFetchOutcome { return orgclient.GuardFetchOutcome{} },
		nil, time.Now,
	), func(context.Context) *orgcontract.GuardTamperReport { return tamper })
	fp := &fakePoster{}
	rep := newPolicyStateReporter(fp, readers, seqCounter(t), "v", true, nil)
	rep.report(context.Background())
	if fp.callCount() != 1 || rep.incomplete.Load() {
		t.Fatalf("posts = %d incomplete = %v, want one complete snapshot posted", fp.callCount(), rep.incomplete.Load())
	}
	var row *orgcontract.PolicyStateRow
	for i := range fp.last.Rows {
		if fp.last.Rows[i].EnforcementPoint == policystate.PointGuard {
			row = &fp.last.Rows[i]
		}
	}
	if row == nil || row.BundleIntegrity != orgcontract.BundleIntegrityMissing || row.Status == orgcontract.StatusEffective || row.GuardTamper == nil || row.GuardTamper.Repairs != 3 {
		t.Fatalf("guard row = %+v, want missing integrity, not effective, the tamper record carried", row)
	}
	if v.kicks != 1 {
		t.Fatalf("poll kicks = %d, want 1", v.kicks)
	}
}

// TestReporter_IncompleteSnapshotBacksOff pins D-704's bounded retry: a
// reader that keeps failing is retried on the backoff timer, not on every
// poke. A storm of pokes inside the first backoff re-reads nothing, and the
// timer's own fire is the next attempt.
func TestReporter_IncompleteSnapshotBacksOff(t *testing.T) {
	readers := fourReaders()
	var reads atomic.Int32
	readers[policystate.PointGuard] = func(context.Context) (policystate.PointFacts, error) {
		reads.Add(1)
		return policystate.PointFacts{}, errors.New("guard cached version: disk fault")
	}
	fp := &fakePoster{}
	rep := newPolicyStateReporter(fp, readers, seqCounter(t), "v", true, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = rep.run(ctx, time.Hour)
	}()
	defer func() {
		cancel()
		<-done
	}()
	deadline := time.Now().Add(policyStateRetryFirst / 2)
	for time.Now().Before(deadline) {
		rep.notifier.Poke()
		time.Sleep(2 * time.Millisecond)
	}
	if got := reads.Load(); got != 1 {
		t.Fatalf("guard reader ran %d times during the first backoff, want 1 (the startup emit only)", got)
	}
	waitFor := time.Now().Add(policyStateRetryFirst * 3)
	for reads.Load() < 2 && time.Now().Before(waitFor) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := reads.Load(); got != 2 {
		t.Fatalf("guard reader ran %d times after the first backoff, want 2 (the timer's retry)", got)
	}
	if fp.callCount() != 0 {
		t.Fatalf("posted %d incomplete snapshots, want 0", fp.callCount())
	}
}

// TestNextPolicyStateRetry pins the retry schedule, one row per step.
func TestNextPolicyStateRetry(t *testing.T) {
	for _, tc := range []struct {
		name            string
		prev, heartbeat time.Duration
		want            time.Duration
	}{
		{"first skip", 0, 5 * time.Minute, time.Second},
		{"doubles", 4 * time.Second, 5 * time.Minute, 8 * time.Second},
		{"capped at a minute", 50 * time.Second, 5 * time.Minute, time.Minute},
		{"capped at a short heartbeat", 20 * time.Second, 30 * time.Second, 30 * time.Second},
		{"heartbeat under the first step", 0, 500 * time.Millisecond, 500 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextPolicyStateRetry(tc.prev, tc.heartbeat); got != tc.want {
				t.Fatalf("nextPolicyStateRetry(%v, %v) = %v, want %v", tc.prev, tc.heartbeat, got, tc.want)
			}
		})
	}
}

// TestNoteBundleRepair pins the one-event-per-incident rule for the fetch's
// move-aside repair (D-704), one row per order of discovery.
func TestNoteBundleRepair(t *testing.T) {
	for _, tc := range []struct {
		name            string
		postureReported bool
		wantEvents      int
	}{
		{"the posture loop reported the incident first: the repair adds nothing", true, 0},
		{"the reporter's kick repaired it first: the repair is the record", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &guardPostureWriter{}
			if tc.postureReported {
				w.bundleTamperSeen("org bundle ~/.observer/org-policy-bundle.json: read: is a directory", nil)
			}
			detail, ok := bundleRepairDetail(bundleRepair{res: orgclient.PolicyResult{
				Status:        orgclient.PolicyApplied,
				RepairedCache: orgclient.CacheRepairMissing,
				DisplacedTo:   "/x/org-policy-bundle.json.displaced-20261017T000134.000000000Z",
			}, deletionIsTamper: true})
			if !ok {
				t.Fatal("a displaced entry repaired by the poll must be a tamper detail")
			}
			w.noteBundleRepair(detail)
			got := w.takeExtraTampers()
			if len(got) != tc.wantEvents {
				t.Fatalf("events = %+v, want %d", got, tc.wantEvents)
			}
			for _, e := range got {
				if e.kind != tamperOrgBundle || !strings.Contains(e.detail, "moved it aside") {
					t.Fatalf("event = %+v, want an org bundle tamper naming the move", e)
				}
			}
		})
	}
}
