package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestIngestBudgetUsageBootstrapsAndPreservesOrdinaryCapture(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, database := newTestStore(t)
	at := time.Now().UTC()
	events := []models.ToolEvent{{
		SessionID: "budget-session", ProjectRoot: t.TempDir(), Tool: "muse",
		Timestamp: at, ActionType: models.ActionReadFile, Target: "source.go", SourceFile: "native-source", SourceEventID: "action-1",
	}}
	// The token has no root. The real parser's tool event must still be able
	// to bootstrap its session even though budget catchup writes no action.
	tokens := []models.TokenEvent{{
		SessionID: "budget-session", Tool: "muse", Model: "fixture-model",
		Timestamp: at, SourceFile: "native-source", SourceEventID: "usage-1", InputTokens: 100,
		EstimatedCostUSD: 0.25, Source: "jsonl",
	}}
	for pass := 0; pass < 2; pass++ {
		result, err := st.IngestBudgetUsage(ctx, events, tokens, nil)
		if err != nil || result.TokensInserted != 1 || result.ActionsInserted != 0 {
			t.Fatalf("budget pass %d: result=%+v err=%v", pass, result, err)
		}
	}
	var actions, usage int
	var usd float64
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions`).Scan(&actions); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*), SUM(estimated_cost_usd) FROM token_usage`).Scan(&usage, &usd); err != nil {
		t.Fatal(err)
	}
	if actions != 0 || usage != 1 || usd != 0.25 {
		t.Fatalf("budget capture replayed actions or duplicated usage: actions=%d usage=%d usd=%v", actions, usage, usd)
	}
	if _, err := st.Ingest(ctx, events, tokens, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions`).Scan(&actions); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*), SUM(estimated_cost_usd) FROM token_usage`).Scan(&usage, &usd); err != nil {
		t.Fatal(err)
	}
	if actions != 1 || usage != 1 || usd != 0.25 {
		t.Fatalf("ordinary capture after catchup: actions=%d usage=%d usd=%v", actions, usage, usd)
	}
}

func TestIngestBudgetUsageRejectsDroppedTokens(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		partial      bool
		emptySession bool
	}{
		{"no session", false, true},
		{"unknown session without bootstrap", false, false},
		{"partial batch", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, _ := newTestStore(t)
			bad := models.TokenEvent{
				SessionID: "unattachable", Tool: "muse", Timestamp: time.Now().UTC(),
				SourceFile: "native-source", SourceEventID: "bad", InputTokens: 100,
			}
			if tc.emptySession {
				bad.SessionID = ""
			}
			tokens := []models.TokenEvent{bad}
			wantAccepted := 0
			if tc.partial {
				good := bad
				good.SessionID, good.SourceEventID, good.ProjectRoot = "valid", "good", t.TempDir()
				tokens = append(tokens, good)
				wantAccepted = 1
			}
			result, err := st.IngestBudgetUsage(context.Background(), nil, tokens, nil)
			if err == nil || !strings.Contains(err.Error(), "accounting is incomplete") || result.TokensInserted != wantAccepted {
				t.Fatalf("unattachable usage accepted: result=%+v err=%v", result, err)
			}
		})
	}
}

// TestIngestBudgetUsageToleratesDroppedZeroUsageTokens pins R10 of the
// accounting-readiness correction (2026-09-14). An adapter that emits an empty
// usage event with no session id has the ingest owner drop it by construction.
// That hides no spend, so it must not mark the tool's accounting unavailable -
// which, on a managed node, stopped that tool's processes forever.
func TestIngestBudgetUsageToleratesDroppedZeroUsageTokens(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		empty        models.TokenEvent
		withBillable bool
		wantAccepted int
	}{
		{
			name:         "zero usage alone",
			empty:        models.TokenEvent{Tool: "muse", Timestamp: time.Now().UTC(), SourceFile: "native-source", SourceEventID: "empty"},
			wantAccepted: 0,
		},
		{
			name:         "zero usage beside billable usage",
			empty:        models.TokenEvent{Tool: "muse", Timestamp: time.Now().UTC(), SourceFile: "native-source", SourceEventID: "empty"},
			withBillable: true,
			wantAccepted: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, _ := newTestStore(t)
			tokens := []models.TokenEvent{tc.empty}
			if tc.withBillable {
				good := tc.empty
				good.SessionID, good.SourceEventID, good.ProjectRoot, good.InputTokens = "valid", "good", t.TempDir(), 100
				tokens = append(tokens, good)
			}
			result, err := st.IngestBudgetUsage(context.Background(), nil, tokens, nil)
			if err != nil {
				t.Fatalf("dropped zero-usage event reported as incomplete accounting: %v", err)
			}
			if result.TokensInserted != tc.wantAccepted {
				t.Fatalf("accepted %d token events, want %d", result.TokensInserted, tc.wantAccepted)
			}
		})
	}
}
