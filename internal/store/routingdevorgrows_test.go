package store

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestSelectRoutingDevRows_Aggregates proves the W2.3 per-developer wire
// row groups/sums router_decisions exactly like SelectRoutingDetail (same
// GROUP BY dimensions), with Switched counting only the rows where the
// router actually rewrote the model (Applied=true), mirroring how
// RoutingDetailRow.Applied is COALESCE(SUM(applied),0).
func TestSelectRoutingDevRows_Aggregates(t *testing.T) {
	t.Parallel()
	st, ctx := openRoutingTestStore(t)

	turnID, err := st.InsertAPITurn(ctx, models.APITurn{
		SessionID: "sess-1", Provider: "anthropic", Model: "claude-opus-4-8",
		Timestamp: time.Date(2026, 6, 10, 11, 59, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("InsertAPITurn: %v", err)
	}

	ts := time.Now().UTC().Add(-2 * time.Hour)
	// The three decisions span two minutes and must share one UTC day bucket;
	// run just after 02:00 UTC they would straddle midnight (gate flake
	// 2026-11-14), so step back to the same day.
	if ts.Add(2*time.Minute).YearDay() != ts.YearDay() {
		ts = ts.Add(-5 * time.Minute)
	}
	rows := []RouterDecisionRow{
		{
			APITurnID: &turnID, SessionID: "sess-1", Timestamp: ts,
			Mode: "advise", Channel: "B",
			OriginalModel: "claude-opus-4-8", SelectedModel: "claude-haiku-4-5",
			TurnKind: "read_only", PolicyHash: "h1",
			EstSavingsUSD: 0.40, CacheForfeitUSD: 0.01, Applied: true,
		},
		{
			APITurnID: &turnID, SessionID: "sess-1", Timestamp: ts.Add(time.Minute),
			Mode: "advise", Channel: "B",
			OriginalModel: "claude-opus-4-8", SelectedModel: "claude-haiku-4-5",
			TurnKind: "read_only", PolicyHash: "h1",
			EstSavingsUSD: 0.20, CacheForfeitUSD: 0.00, Applied: false,
		},
		{
			// Distinct turn_kind — must land in a separate bucket.
			APITurnID: &turnID, SessionID: "sess-1", Timestamp: ts.Add(2 * time.Minute),
			Mode: "enforce", Channel: "B",
			OriginalModel: "claude-opus-4-8", SelectedModel: "claude-sonnet-5",
			TurnKind: "edit", PolicyHash: "h1",
			EstSavingsUSD: 0.10, CacheForfeitUSD: 0.02, Applied: true,
		},
	}
	if err := st.InsertRouterDecisions(ctx, rows); err != nil {
		t.Fatalf("InsertRouterDecisions: %v", err)
	}

	got, err := st.SelectRoutingDevRows(ctx)
	if err != nil {
		t.Fatalf("SelectRoutingDevRows: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 buckets (read_only + edit), got %+v", len(got), got)
	}

	var readOnly, edit *orgcontract.RoutingDevRow
	for i := range got {
		switch got[i].TurnKind {
		case "read_only":
			readOnly = &got[i]
		case "edit":
			edit = &got[i]
		}
	}
	if readOnly == nil || edit == nil {
		t.Fatalf("missing expected buckets: %+v", got)
	}

	if readOnly.Decisions != 2 {
		t.Errorf("read_only Decisions = %d, want 2", readOnly.Decisions)
	}
	if readOnly.Switched != 1 {
		t.Errorf("read_only Switched = %d, want 1 (only the Applied row)", readOnly.Switched)
	}
	if !near(readOnly.EstSavingsUSD, 0.60) {
		t.Errorf("read_only EstSavingsUSD = %v, want 0.60", readOnly.EstSavingsUSD)
	}
	if !near(readOnly.CacheForfeitUSD, 0.01) {
		t.Errorf("read_only CacheForfeitUSD = %v, want 0.01", readOnly.CacheForfeitUSD)
	}
	if readOnly.OriginalModel != "claude-opus-4-8" || readOnly.SelectedModel != "claude-haiku-4-5" {
		t.Errorf("read_only models = %s/%s, unexpected", readOnly.OriginalModel, readOnly.SelectedModel)
	}

	if edit.Decisions != 1 || edit.Switched != 1 {
		t.Errorf("edit Decisions/Switched = %d/%d, want 1/1", edit.Decisions, edit.Switched)
	}
	if edit.SelectedModel != "claude-sonnet-5" {
		t.Errorf("edit SelectedModel = %s, want claude-sonnet-5", edit.SelectedModel)
	}
}

// TestSelectRoutingDevRows_WindowExcludesOldDecisions proves the trailing
// window (routingDevWindowDays) excludes decisions logged well before it,
// keeping the push payload bounded like SelectRoutingDetail.
func TestSelectRoutingDevRows_WindowExcludesOldDecisions(t *testing.T) {
	t.Parallel()
	st, ctx := openRoutingTestStore(t)

	old := time.Now().UTC().AddDate(0, 0, -(routingDevWindowDays + 30))
	rows := []RouterDecisionRow{
		{
			SessionID: "sess-old", Timestamp: old, Mode: "advise", Channel: "A",
			OriginalModel: "claude-opus-4-8", SelectedModel: "claude-opus-4-8",
			TurnKind: "unknown", PolicyHash: "h1",
		},
	}
	if err := st.InsertRouterDecisions(ctx, rows); err != nil {
		t.Fatalf("InsertRouterDecisions: %v", err)
	}

	got, err := st.SelectRoutingDevRows(ctx)
	if err != nil {
		t.Fatalf("SelectRoutingDevRows: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected the old decision to be excluded by the trailing window, got %+v", got)
	}
}

// near reports whether a and b agree within a small float tolerance —
// local to this file (rollup_test.go's near helper lives in a different
// package).
func near(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-9
}
