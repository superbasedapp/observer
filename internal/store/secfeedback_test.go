//go:build !sbo_omit_security

package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// TestTakeSecFeedback (lane sec-h): the session's open, new,
// high-confidence, unexcepted findings come out once, most severe first,
// and each is recorded with a feedback_sent event naming the session.
func TestTakeSecFeedback(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	mk := func(key string, sev policy.FindingSeverity, mutate func(f *secfinding.Finding)) string {
		f := secFinding("p1", key)
		f.Severity = sev
		if mutate != nil {
			mutate(&f)
		}
		id, _, err := s.UpsertSecFinding(ctx, f, t0)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	high := mk("high", policy.FindingSeverityHigh, nil)
	crit := mk("crit", policy.FindingSeverityCritical, nil)
	mk("other-session", policy.FindingSeverityCritical, func(f *secfinding.Finding) { f.Lineage.SessionID = "s2" })
	mk("low-confidence", policy.FindingSeverityCritical, func(f *secfinding.Finding) { f.Confidence = policy.FindingConfidenceMedium })
	mk("pre-existing", policy.FindingSeverityCritical, func(f *secfinding.Finding) { f.Baseline = policy.FindingBaselinePreExisting })
	excepted := mk("excepted", policy.FindingSeverityCritical, nil)
	if err := s.SetSecFindingStatus(ctx, excepted, policy.FindingStatusSuppressed, "ex-1", t0); err != nil {
		t.Fatal(err)
	}

	got, err := s.TakeSecFeedback(ctx, SecFeedbackQuery{ProjectRootHash: "p1", SessionID: "s1"}, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != crit || got[1].ID != high {
		t.Fatalf("took %+v, want crit then high", got)
	}
	if got[0].Message != "" || got[0].FixHint != "" || got[0].EvidenceRedacted != "" {
		t.Fatalf("rule data only: %+v", got[0])
	}
	again, err := s.TakeSecFeedback(ctx, SecFeedbackQuery{ProjectRootHash: "p1", SessionID: "s1"}, t0.Add(2*time.Minute))
	if err != nil || len(again) != 0 {
		t.Fatalf("each finding once: %+v %v", again, err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sec_finding_events WHERE kind = 'feedback_sent' AND detail = 's1'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("feedback_sent events = %d %v", n, err)
	}
	if got, _ := s.TakeSecFeedback(ctx, SecFeedbackQuery{ProjectRootHash: "p1"}, t0); got != nil {
		t.Fatal("no session, no findings")
	}
}

// TestTakeSecFeedbackLease (lane sec-polish, audit finding F3): a leased
// take records nothing, so the line is offered again until it is
// acknowledged; Exclude leaves out the caller's leased findings; the
// acknowledgement (IDs) records only the named findings, and never one
// closed since it was leased.
func TestTakeSecFeedbackLease(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	mk := func(key string, sev policy.FindingSeverity) string {
		f := secFinding("p1", key)
		f.Severity = sev
		id, _, err := s.UpsertSecFinding(ctx, f, t0)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	crit := mk("crit", policy.FindingSeverityCritical)
	high := mk("high", policy.FindingSeverityHigh)
	med := mk("med", policy.FindingSeverityMedium)
	q := SecFeedbackQuery{ProjectRootHash: "p1", SessionID: "s1", Lease: true}
	sent := func() int {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sec_finding_events WHERE kind = 'feedback_sent'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	got, err := s.TakeSecFeedback(ctx, q, t0)
	if err != nil || len(got) != 3 || got[0].ID != crit {
		t.Fatalf("leased take: %+v %v", got, err)
	}
	if sent() != 0 {
		t.Fatal("a leased take recorded feedback_sent")
	}
	// Unacknowledged, the same lines come back on the next take.
	if again, _ := s.TakeSecFeedback(ctx, q, t0); len(again) != 3 {
		t.Fatalf("an unacknowledged line was lost: %+v", again)
	}
	// Exclude leaves out what is under a lease.
	q.Exclude = []string{crit, high}
	if got, _ := s.TakeSecFeedback(ctx, q, t0); len(got) != 1 || got[0].ID != med {
		t.Fatalf("exclude: %+v", got)
	}
	// The acknowledgement records exactly the named findings; one closed
	// since it was leased is neither returned nor recorded.
	if err := s.SetSecFindingStatus(ctx, high, policy.FindingStatusNotReproduced, "", t0); err != nil {
		t.Fatal(err)
	}
	acked, err := s.TakeSecFeedback(ctx, SecFeedbackQuery{ProjectRootHash: "p1", SessionID: "s1", IDs: []string{crit, high}}, t0)
	if err != nil || len(acked) != 1 || acked[0].ID != crit || sent() != 1 {
		t.Fatalf("ack: %+v %v, sent %d", acked, err, sent())
	}
	// A sent line is never offered again; the medium one still is.
	if got, _ := s.TakeSecFeedback(ctx, SecFeedbackQuery{ProjectRootHash: "p1", SessionID: "s1", Lease: true}, t0); len(got) != 1 || got[0].ID != med {
		t.Fatalf("after the ack: %+v", got)
	}
	// An empty, non-nil IDs takes nothing (never the whole session).
	if got, _ := s.TakeSecFeedback(ctx, SecFeedbackQuery{ProjectRootHash: "p1", SessionID: "s1", IDs: []string{}}, t0); got != nil || sent() != 1 {
		t.Fatalf("empty IDs took %+v", got)
	}
}
