package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestIntegrityVerdictRoundTrip is the RES-3 persistence pin (codebase audit
// 2026-09-16): the background `PRAGMA quick_check`'s verdict must survive in
// schema_meta so `observer status` and the dashboard can show a corrupt
// database without the operator running `observer doctor`.
//
// Three properties, in one table: a never-probed DB reports ABSENT (not
// "corrupt", which would mark every fresh install damaged); each closed-
// vocabulary status round-trips with its timestamp and message; and a later
// verdict REPLACES the earlier one rather than accumulating, since the
// question is "what is the state now".
func TestIntegrityVerdictRoundTrip(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = database.Close() }()

	if _, ok, err := LastIntegrityVerdict(ctx, database); err != nil || ok {
		t.Fatalf("fresh DB: got ok=%v err=%v, want a clean ABSENT verdict — "+
			"a never-probed database must not read as checked, let alone as damaged", ok, err)
	}

	for _, tc := range []struct {
		name    string
		status  string
		message string
		wantOK  bool
	}{
		{"clean probe", IntegrityOK, "", true},
		{"damage found", IntegrityCorrupt, "*** in database main\nPage 42: btreeInitPage() returns error code 11", false},
		{"probe could not complete", IntegrityError, "context deadline exceeded", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := time.Now().UTC().Truncate(time.Second)
			if err := recordIntegrityVerdict(ctx, database, IntegrityVerdict{
				CheckedAt: at, Status: tc.status, Message: tc.message,
			}); err != nil {
				t.Fatalf("recordIntegrityVerdict: %v", err)
			}
			got, ok, err := LastIntegrityVerdict(ctx, database)
			if err != nil {
				t.Fatalf("LastIntegrityVerdict: %v", err)
			}
			if !ok {
				t.Fatal("verdict missing after being recorded")
			}
			if got.Status != tc.status {
				t.Errorf("status = %q, want %q", got.Status, tc.status)
			}
			if got.Message != tc.message {
				t.Errorf("message = %q, want %q", got.Message, tc.message)
			}
			if !got.CheckedAt.Equal(at) {
				t.Errorf("checked_at = %v, want %v", got.CheckedAt, at)
			}
			if got.OK() != tc.wantOK {
				t.Errorf("OK() = %v, want %v for status %q", got.OK(), tc.wantOK, tc.status)
			}
		})
	}

	// Last write wins — the table above already overwrote twice, so assert
	// the final state explicitly rather than trusting iteration order.
	final, ok, err := LastIntegrityVerdict(ctx, database)
	if err != nil || !ok {
		t.Fatalf("final read: ok=%v err=%v", ok, err)
	}
	if final.Status != IntegrityError {
		t.Errorf("final status = %q, want %q — a verdict must REPLACE its predecessor", final.Status, IntegrityError)
	}
}

// TestIntegrityCheckRecordsCleanVerdict pins that the PROBE ITSELF records,
// not just the helper: running the real quick_check path on a healthy database
// must leave an "ok" verdict behind. Mutation: drop the record() call from
// integrityCheck's success branch → no verdict is stored and this FAILS.
func TestIntegrityCheckRecordsCleanVerdict(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = database.Close() }()

	before := time.Now().UTC().Add(-time.Second)
	if err := RunStartupMaintenance(ctx, database); err != nil {
		t.Fatalf("RunStartupMaintenance: %v", err)
	}
	got, ok, err := LastIntegrityVerdict(ctx, database)
	if err != nil {
		t.Fatalf("LastIntegrityVerdict: %v", err)
	}
	if !ok {
		t.Fatal("the startup probe recorded no verdict — a healthy result must be persisted too, " +
			"otherwise 'never probed' and 'probed clean' are indistinguishable on the status surface")
	}
	if !got.OK() {
		t.Errorf("status = %q (%q), want ok on a freshly created database", got.Status, got.Message)
	}
	if got.CheckedAt.Before(before) {
		t.Errorf("checked_at = %v, want a timestamp from this run (after %v)", got.CheckedAt, before)
	}
}
