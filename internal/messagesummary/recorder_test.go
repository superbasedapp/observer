package messagesummary

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// storeWriter is the CallRowWriter cmd/observer wires: the store's
// summary_calls seam over database.
func storeWriter(database *sql.DB) CallRowWriter {
	st := store.New(database)
	return func(ctx context.Context, row CallRow) error {
		return st.InsertSummaryCall(ctx, store.SummaryCallRow{
			SessionID: row.SessionID, At: row.At, Model: row.Model,
			InputTokens: row.InputTokens, OutputTokens: row.OutputTokens,
			CacheReadTokens: row.CacheReadTokens, CacheCreationTokens: row.CacheCreationTokens,
			CostUSD: row.CostUSD,
		})
	}
}

// stubPricing returns fixed rates for testing the cost computation.
type stubPricing struct{}

func (stubPricing) Lookup(model string) (Pricing, bool) {
	if model == "claude-haiku-4-5" {
		return Pricing{Input: 0.80, Output: 4.00, CacheRead: 0.08, CacheCreation: 1.00}, true
	}
	return Pricing{}, false
}

// TestDBRecorder_RecordsRow pins the round-trip: a SummaryCall lands
// one row in summary_calls with cost_usd computed from the pricing
// lookup.
func TestDBRecorder_RecordsRow(t *testing.T) {
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "r.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	r := NewDBRecorder(storeWriter(database), stubPricing{})
	err = r.Record(context.Background(), SummaryCall{
		SessionID:    "sX",
		Model:        "claude-haiku-4-5",
		InputTokens:  1000,
		OutputTokens: 200,
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	var n int
	var sessionID, model string
	var inputT, outputT int64
	var cost float64
	if err := database.QueryRow(
		`SELECT COUNT(*), session_id, model, input_tokens, output_tokens, cost_usd FROM summary_calls`,
	).Scan(&n, &sessionID, &model, &inputT, &outputT, &cost); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("count: %d", n)
	}
	if sessionID != "sX" {
		t.Errorf("session_id: %q", sessionID)
	}
	if inputT != 1000 || outputT != 200 {
		t.Errorf("tokens: in=%d out=%d", inputT, outputT)
	}
	// cost = 1000 × 0.80 / 1M + 200 × 4.00 / 1M = 0.0008 + 0.0008 = 0.0016
	want := 0.0016
	if cost < want-0.00001 || cost > want+0.00001 {
		t.Errorf("cost_usd: %v, want %v", cost, want)
	}
}

// TestDBRecorder_NilSafe pins that nil receiver / nil writer are no-ops.
func TestDBRecorder_NilSafe(t *testing.T) {
	var r *DBRecorder
	if err := r.Record(context.Background(), SummaryCall{}); err != nil {
		t.Errorf("nil-recv Record: %v", err)
	}
	r2 := NewDBRecorder(nil, stubPricing{})
	if err := r2.Record(context.Background(), SummaryCall{}); err != nil {
		t.Errorf("nil-writer Record: %v", err)
	}
}

// TestDBRecorder_UnknownModelZeroCost pins the safety: when the
// pricing lookup misses, cost_usd lands 0 rather than panicking or
// erroring (the dashboard surfaces this as "missing pricing").
func TestDBRecorder_UnknownModelZeroCost(t *testing.T) {
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "r.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	r := NewDBRecorder(storeWriter(database), stubPricing{})
	err = r.Record(context.Background(), SummaryCall{
		Model:        "claude-future-9000",
		InputTokens:  1000,
		OutputTokens: 200,
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	var cost float64
	if err := database.QueryRow(`SELECT cost_usd FROM summary_calls`).Scan(&cost); err != nil {
		t.Fatal(err)
	}
	if cost != 0 {
		t.Errorf("cost should be 0 for unknown model, got %v", cost)
	}
}
