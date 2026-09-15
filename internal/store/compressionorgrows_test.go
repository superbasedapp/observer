package store

import (
	"context"
	"testing"
	"time"
)

// seedCompressionEvent inserts one api_turns row (compression_events has an
// FK on api_turn_id) and one compression_events row referencing it, using the
// same shape store.go::InsertAPITurn writes.
func seedCompressionEvent(t *testing.T, s *Store, ts time.Time, mechanism string, originalBytes, compressedBytes int64) {
	t.Helper()
	ctx := context.Background()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO api_turns (timestamp, provider, model, input_tokens, output_tokens) VALUES (?, ?, ?, ?, ?)`,
		timestamp(ts), "anthropic", "claude-sonnet-5", 100, 50)
	if err != nil {
		t.Fatalf("seed api_turns: %v", err)
	}
	turnID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("seed api_turns last insert id: %v", err)
	}
	if _, err := s.db.ExecContext(
		ctx,
		`INSERT INTO compression_events (api_turn_id, timestamp, mechanism, original_bytes, compressed_bytes) VALUES (?, ?, ?, ?, ?)`,
		turnID, timestamp(ts), mechanism, originalBytes, compressedBytes,
	); err != nil {
		t.Fatalf("seed compression_events: %v", err)
	}
}

// TestSelectCompressionStatRows_AggregatesByDayMechanism seeds a mix of
// genuinely-compressing and lossy ("drop") events across two days and two
// mechanisms and asserts the (day, mechanism) bucketing plus the
// honesty-preserving split: a real mechanism's SavedBytes/SavedTokensEst are
// populated and EvictedBytes stays 0; a lossy mechanism's EvictedBytes equals
// the full original size and SavedBytes/SavedTokensEst stay 0.
func TestSelectCompressionStatRows_AggregatesByDayMechanism(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	// Anchor to TODAY's midday UTC (not raw time.Now) so the sub-hour
	// relative offsets below never straddle UTC midnight — the documented
	// "pin a midday anchor" fix for the UTC-midnight test class. Still a real
	// today so the 7-day recompute-window filter keeps the recent events and
	// excludes the -30-day one.
	n := time.Now().UTC()
	now := time.Date(n.Year(), n.Month(), n.Day(), 12, 0, 0, 0, time.UTC)

	// Two "json" events same day — must collapse into one bucket with
	// Events=2 and summed bytes.
	seedCompressionEvent(t, s, now.Add(-time.Hour), "json", 1000, 400)
	seedCompressionEvent(t, s, now.Add(-30*time.Minute), "json", 2000, 800)
	// A "drop" (lossy) event same day — distinct bucket from "json".
	seedCompressionEvent(t, s, now.Add(-20*time.Minute), "drop", 500, 0)
	// Outside the 7-day recompute window — must be excluded entirely.
	seedCompressionEvent(t, s, now.AddDate(0, 0, -30), "json", 9999, 1)

	got, err := s.SelectCompressionStatRows(context.Background())
	if err != nil {
		t.Fatalf("SelectCompressionStatRows: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2 (one json bucket + one drop bucket); rows=%+v", len(got), got)
	}

	var jsonRow, dropRow *struct {
		Events                                   int64
		OriginalBytes, CompressedBytes           int64
		SavedBytes, EvictedBytes, SavedTokensEst int64
		Lossy                                    bool
	}
	for _, r := range got {
		row := &struct {
			Events                                   int64
			OriginalBytes, CompressedBytes           int64
			SavedBytes, EvictedBytes, SavedTokensEst int64
			Lossy                                    bool
		}{r.Events, r.OriginalBytes, r.CompressedBytes, r.SavedBytes, r.EvictedBytes, r.SavedTokensEst, r.Lossy}
		switch r.Mechanism {
		case "json":
			jsonRow = row
		case "drop":
			dropRow = row
		default:
			t.Errorf("unexpected mechanism %q in results", r.Mechanism)
		}
	}

	if jsonRow == nil {
		t.Fatal("no json bucket found")
	}
	if jsonRow.Events != 2 || jsonRow.OriginalBytes != 3000 || jsonRow.CompressedBytes != 1200 {
		t.Errorf("json row = %+v, want Events=2 OriginalBytes=3000 CompressedBytes=1200", *jsonRow)
	}
	if jsonRow.SavedBytes != 1800 {
		t.Errorf("json SavedBytes = %d, want 1800 (3000-1200)", jsonRow.SavedBytes)
	}
	if jsonRow.SavedTokensEst != 450 {
		t.Errorf("json SavedTokensEst = %d, want 450 (1800/4)", jsonRow.SavedTokensEst)
	}
	if jsonRow.EvictedBytes != 0 || jsonRow.Lossy {
		t.Errorf("json row must not be marked lossy/evicted: %+v", *jsonRow)
	}

	if dropRow == nil {
		t.Fatal("no drop bucket found")
	}
	if !dropRow.Lossy {
		t.Error("drop row must be marked Lossy=true")
	}
	if dropRow.EvictedBytes != 500 {
		t.Errorf("drop EvictedBytes = %d, want 500 (the full original size)", dropRow.EvictedBytes)
	}
	if dropRow.SavedBytes != 0 || dropRow.SavedTokensEst != 0 {
		t.Errorf("drop row must never report savings: %+v", *dropRow)
	}
}

// TestSelectCompressionStatRows_NoEvents returns an empty (never nil) slice
// when compression_events is empty.
func TestSelectCompressionStatRows_NoEvents(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)

	got, err := s.SelectCompressionStatRows(context.Background())
	if err != nil {
		t.Fatalf("SelectCompressionStatRows: %v", err)
	}
	if got == nil {
		t.Error("got nil slice, want empty non-nil slice")
	}
	if len(got) != 0 {
		t.Errorf("got %d rows, want 0", len(got))
	}
}
