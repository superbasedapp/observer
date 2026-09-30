package store

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestInsertAPITurn_PersistsRequestClass pins the store half of migration
// 144: the proxy's request class lands in api_turns.request_class, and an
// absent one is NULL (unknown stays unknown).
func TestInsertAPITurn_PersistsRequestClass(t *testing.T) {
	st := newPredictTestStore(t)
	ctx := context.Background()
	seedShapeSession(t, st, "sess-rc", "", nil, nil)
	classes := []string{models.APIRequestClassSubagent, ""}
	for i, rc := range classes {
		if _, err := st.InsertAPITurn(ctx, models.APITurn{
			SessionID: "sess-rc", Timestamp: time.Date(2026, 9, 28, 12, 0, i, 0, time.UTC),
			Provider: "anthropic", Model: "claude-sonnet-5", RequestID: "req-rc-" + rc,
			InputTokens: 10, OutputTokens: 2, RequestClass: rc,
		}); err != nil {
			t.Fatalf("InsertAPITurn: %v", err)
		}
	}
	rows, err := st.db.QueryContext(ctx, `SELECT request_class FROM api_turns WHERE session_id = 'sess-rc' ORDER BY id`)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	defer rows.Close()
	var got []sql.NullString
	for rows.Next() {
		var v sql.NullString
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("rows = %d, want 2", len(got))
	}
	if !got[0].Valid || got[0].String != models.APIRequestClassSubagent {
		t.Errorf("classified turn request_class = %+v, want %q", got[0], models.APIRequestClassSubagent)
	}
	if got[1].Valid {
		t.Errorf("unclassified turn request_class = %q, want NULL", got[1].String)
	}
}

// TestRequestClassShipsOnTheWire pins the lane G-WIRE2 change to the old
// node-local posture: api_turns.request_class now ships on the org push
// (orgcontract.APITurnRow.RequestClass, server migration 188 / pg 0054), a
// closed enum that rides every posture like route. The payload assertion is
// tests/invariant/privacy_test.go's canary; this pins the store seam's own
// half - SelectUnpushedSince carries the stored class, and a NULL class
// ships as the empty (omitted) value, never a guess.
func TestRequestClassShipsOnTheWire(t *testing.T) {
	st := newPredictTestStore(t)
	ctx := context.Background()
	seedShapeSession(t, st, "sess-rcw", "", nil, nil)
	for i, rc := range []string{models.APIRequestClassCompaction, ""} {
		if _, err := st.InsertAPITurn(ctx, models.APITurn{
			SessionID: "sess-rcw", Timestamp: time.Date(2026, 8, 28, 9, 0, i, 0, time.UTC),
			Provider: "anthropic", Model: "claude-sonnet-5", RequestID: "req-rcw-" + strings.Repeat("x", i+1),
			InputTokens: 10, OutputTokens: 2, RequestClass: rc,
		}); err != nil {
			t.Fatalf("InsertAPITurn: %v", err)
		}
	}
	batch, err := st.SelectUnpushedSince(ctx, PushCursor{}, 1<<24, "org-x", "dev@example.com", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	got := map[string]string{}
	for _, r := range batch.APITurns {
		got[r.RequestID] = r.RequestClass
	}
	if got["req-rcw-x"] != models.APIRequestClassCompaction {
		t.Errorf("classified turn shipped class %q, want %q", got["req-rcw-x"], models.APIRequestClassCompaction)
	}
	if c, ok := got["req-rcw-xx"]; !ok || c != "" {
		t.Errorf("unclassified turn shipped class %q (present=%v), want empty", c, ok)
	}
	src, err := os.ReadFile("orgpush.go")
	if err != nil {
		t.Fatalf("read orgpush.go: %v", err)
	}
	if !strings.Contains(string(src), "request_class") {
		t.Error("orgpush.go no longer selects request_class")
	}
}
