package store

import (
	"context"
	"testing"
	"time"
)

// TestCloudEnrichSkipBackoffTable pins the exact exponential-backoff
// schedule: 1h * 2^(attempts-1), capped at 7 days.
func TestCloudEnrichSkipBackoffTable(t *testing.T) {
	cases := []struct {
		attempts int
		want     time.Duration
	}{
		{attempts: 0, want: time.Hour}, // clamped up to attempts=1.
		{attempts: 1, want: time.Hour},
		{attempts: 2, want: 2 * time.Hour},
		{attempts: 3, want: 4 * time.Hour},
		{attempts: 4, want: 8 * time.Hour},
		{attempts: 5, want: 16 * time.Hour},
		{attempts: 6, want: 32 * time.Hour},
		{attempts: 7, want: 64 * time.Hour},
		{attempts: 8, want: 128 * time.Hour},
		{attempts: 9, want: cloudEnrichSkipMaxBackoff}, // 256h would exceed 168h cap.
		{attempts: 100, want: cloudEnrichSkipMaxBackoff},
	}
	for _, c := range cases {
		if got := cloudEnrichSkipBackoff(c.attempts); got != c.want {
			t.Errorf("cloudEnrichSkipBackoff(%d) = %s, want %s", c.attempts, got, c.want)
		}
	}
}

// TestRecordCloudEnrichSkipRoundTrip pins insert, exponential re-record, and
// GetCloudEnrichSkip's not-found case.
func TestRecordCloudEnrichSkipRoundTrip(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	if _, ok, err := s.GetCloudEnrichSkip(ctx, "sess-1"); err != nil || ok {
		t.Fatalf("precondition: no row expected, ok=%v err=%v", ok, err)
	}

	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	if err := s.RecordCloudEnrichSkip(ctx, "sess-1", "consent_spawn_failed", now); err != nil {
		t.Fatalf("RecordCloudEnrichSkip: %v", err)
	}
	got, ok, err := s.GetCloudEnrichSkip(ctx, "sess-1")
	if err != nil || !ok {
		t.Fatalf("GetCloudEnrichSkip after first record: ok=%v err=%v", ok, err)
	}
	if got.Attempts != 1 || got.LastErrorClass != "consent_spawn_failed" {
		t.Fatalf("got = %+v, want attempts=1 class=consent_spawn_failed", got)
	}
	wantNext := now.Add(time.Hour)
	if !got.NextAt.Equal(wantNext) {
		t.Errorf("NextAt = %s, want %s", got.NextAt, wantNext)
	}
	if !got.UpdatedAt.Equal(now) {
		t.Errorf("UpdatedAt = %s, want %s", got.UpdatedAt, now)
	}

	// A second failure increments attempts and doubles the backoff, and
	// overwrites the error class rather than appending a history row.
	later := now.Add(2 * time.Hour)
	if err := s.RecordCloudEnrichSkip(ctx, "sess-1", "spawn_timeout", later); err != nil {
		t.Fatalf("RecordCloudEnrichSkip (second): %v", err)
	}
	got2, ok, err := s.GetCloudEnrichSkip(ctx, "sess-1")
	if err != nil || !ok {
		t.Fatalf("GetCloudEnrichSkip after second record: ok=%v err=%v", ok, err)
	}
	if got2.Attempts != 2 || got2.LastErrorClass != "spawn_timeout" {
		t.Fatalf("got2 = %+v, want attempts=2 class=spawn_timeout", got2)
	}
	if want := later.Add(2 * time.Hour); !got2.NextAt.Equal(want) {
		t.Errorf("NextAt (second) = %s, want %s", got2.NextAt, want)
	}

	// ClearCloudEnrichSkip removes the row; clearing an already-absent
	// session is not an error.
	if err := s.ClearCloudEnrichSkip(ctx, "sess-1"); err != nil {
		t.Fatalf("ClearCloudEnrichSkip: %v", err)
	}
	if _, ok, err := s.GetCloudEnrichSkip(ctx, "sess-1"); err != nil || ok {
		t.Fatalf("after clear: ok=%v err=%v, want no row", ok, err)
	}
	if err := s.ClearCloudEnrichSkip(ctx, "sess-never-existed"); err != nil {
		t.Fatalf("ClearCloudEnrichSkip on absent session: %v", err)
	}
}
