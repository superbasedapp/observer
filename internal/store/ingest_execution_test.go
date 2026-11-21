package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestIngestAppliesSessionExecutions pins the Ingest plumbing for the
// cloud-execution stamp (cloud-agents lane CA-B4): a stamp passed through
// IngestOptions lands on the upserted session through SetSessionExecution;
// an entry with no session id is skipped; an out-of-vocabulary location or
// a malformed reference is BEST-EFFORT (the ingest succeeds, the columns
// stay empty, the skip is counted); and with nothing passed the columns stay
// NULL (byte-identical to the pre-arc ingest).
func TestIngestAppliesSessionExecutions(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		stamps      []models.SessionExecution
		wantLoc     string
		wantRef     string
		wantSkipped int
	}{
		{"none", nil, "", "", 0},
		{"vendor cloud with reference", []models.SessionExecution{
			{SessionID: "s", ExecutionLocation: models.ExecutionVendorCloud, VendorSessionRef: "cse_abc"},
			{SessionID: ""},
		}, models.ExecutionVendorCloud, "cse_abc", 0},
		{"unknown location", []models.SessionExecution{{SessionID: "s", ExecutionLocation: "cloudish"}}, "", "", 1},
		{"malformed reference", []models.SessionExecution{{SessionID: "s", ExecutionLocation: models.ExecutionVendorCloud, VendorSessionRef: "a b"}}, "", "", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, _ := newTestStore(t)
			ctx := context.Background()
			ev := models.ToolEvent{
				SourceFile: "/tmp/x.jsonl", SourceEventID: "e1", SessionID: "s",
				ProjectRoot: "/tmp/ing", Timestamp: ts, Tool: models.ToolClaudeCode,
				ActionType: models.ActionUserPrompt, Target: "hi", Success: true,
			}
			res, err := s.Ingest(ctx, []models.ToolEvent{ev}, nil, IngestOptions{SessionExecutions: tc.stamps})
			if err != nil {
				t.Fatalf("Ingest: %v", err)
			}
			if res.ActionsInserted != 1 || res.SessionExecutionsSkipped != tc.wantSkipped {
				t.Fatalf("result = %+v; want 1 action, %d skipped", res, tc.wantSkipped)
			}
			got, err := s.LoadSessionExecution(ctx, "s")
			if err != nil {
				t.Fatal(err)
			}
			if got.ExecutionLocation != tc.wantLoc || got.VendorSessionRef != tc.wantRef {
				t.Errorf("stored = %+v; want %q / %q", got, tc.wantLoc, tc.wantRef)
			}
		})
	}
}
