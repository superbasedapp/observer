package store

import (
	"context"
	"testing"
	"time"
)

// TestCloudSyncLastTokenBudgets pins migration 254's columns on the
// cloud_sync_last singleton: the token windows round-trip and are rewritten
// (unknown after a run that read no usage), while the evidence budget is
// LAST-KNOWN: a run that did not read it keeps the stored value, and a read
// 0 ("no budget on this plan") is stored as known.
func TestCloudSyncLastTokenBudgets(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

	if _, known, err := s.LastKnownCloudEvidenceTokenBudget(ctx); err != nil || known {
		t.Fatalf("no row: known=%v err=%v, want unknown", known, err)
	}
	// A run with no usage read: the row exists, the budget is still unknown.
	if err := s.RecordCloudSyncLast(ctx, CloudSyncLast{StartedAt: at, FinishedAt: at, OK: true}); err != nil {
		t.Fatal(err)
	}
	if _, known, err := s.LastKnownCloudEvidenceTokenBudget(ctx); err != nil || known {
		t.Fatalf("never read: known=%v err=%v, want unknown", known, err)
	}

	evidence := 12000
	session, dUsed, dBudget, mUsed, mBudget := int64(200000), int64(1500), int64(1000000), int64(9000), int64(15000000)
	if err := s.RecordCloudSyncLast(ctx, CloudSyncLast{
		StartedAt: at, FinishedAt: at, OK: true, PlanName: "plus_beta",
		BudgetUnit: "tokens", EnrichmentTier: "paid", EvidenceTokenBudget: &evidence,
		SessionTokenBudget: &session, DailyTokensUsed: &dUsed, DailyTokenBudget: &dBudget,
		MonthlyTokensUsed: &mUsed, MonthlyTokenBudget: &mBudget,
	}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetCloudSyncLast(ctx)
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.BudgetUnit != "tokens" || got.EnrichmentTier != "paid" || got.EvidenceTokenBudget == nil || *got.EvidenceTokenBudget != 12000 ||
		got.SessionTokenBudget == nil || *got.SessionTokenBudget != session ||
		got.DailyTokensUsed == nil || *got.DailyTokensUsed != dUsed || got.DailyTokenBudget == nil || *got.DailyTokenBudget != dBudget ||
		got.MonthlyTokensUsed == nil || *got.MonthlyTokensUsed != mUsed || got.MonthlyTokenBudget == nil || *got.MonthlyTokenBudget != mBudget {
		t.Fatalf("round trip = %+v", got)
	}

	// A later run whose usage read failed: the windows read unknown, the
	// evidence budget the builder needs survives.
	if err := s.RecordCloudSyncLast(ctx, CloudSyncLast{StartedAt: at, FinishedAt: at.Add(time.Hour), OK: false}); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.GetCloudSyncLast(ctx)
	if got.BudgetUnit != "" || got.DailyTokensUsed != nil || got.MonthlyTokenBudget != nil || got.SessionTokenBudget != nil {
		t.Fatalf("windows after a failed read = %+v, want unknown", got)
	}
	if b, known, err := s.LastKnownCloudEvidenceTokenBudget(ctx); err != nil || !known || b != 12000 {
		t.Fatalf("evidence budget after a failed read = %d known=%v err=%v, want the last-known 12000", b, known, err)
	}

	// A read 0 (a count plan sets no evidence budget) is known, not unknown.
	zero := 0
	if err := s.RecordCloudSyncLast(ctx, CloudSyncLast{StartedAt: at, FinishedAt: at, OK: true, BudgetUnit: "count", EvidenceTokenBudget: &zero}); err != nil {
		t.Fatal(err)
	}
	if b, known, err := s.LastKnownCloudEvidenceTokenBudget(ctx); err != nil || !known || b != 0 {
		t.Fatalf("read zero = %d known=%v err=%v, want known 0", b, known, err)
	}
}
