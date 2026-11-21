package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
)

const apiTurnsPlaneALegacyFile = "256_api_turns_planea_legacy.sql"

// TestMigration256RelocatesPlaneATurns grades the W1d-1 step (lead ruling
// option (a)): legacy Plane A rows (source otlp_trace / sdk_otlp) move
// verbatim into api_turns_planea_legacy, a reference to one is cleared, the
// delete is tombstoned for the org above the enrolment floor, and every other
// api_turns row is untouched.
func TestMigration256RelocatesPlaneATurns(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "observer.db")
	database, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(30000)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer database.Close()
	if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, lineageWithout(t, apiTurnsPlaneALegacyFile), lateSteps); err != nil {
		t.Fatalf("migrate to the step before 256: %v", err)
	}
	// An enrolled node: rows above the floor are tombstoned on delete.
	if _, err := database.ExecContext(ctx, `INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('org_push_floor_api_turns', '0')`); err != nil {
		t.Fatalf("seed floor: %v", err)
	}
	for _, r := range []struct{ req, src string }{
		{"req-proxy", "proxy"}, {"req-otlp", "otlp_trace"}, {"req-sdk", "sdk_otlp"}, {"req-legacy", ""},
	} {
		if _, err := database.ExecContext(ctx, `INSERT INTO api_turns (timestamp, provider, model, request_id, input_tokens, output_tokens, source)
			VALUES ('2026-11-18T00:00:00Z', 'anthropic', 'm', ?, 7, 1, NULLIF(?, ''))`, r.req, r.src); err != nil {
			t.Fatalf("seed %s: %v", r.req, err)
		}
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO guard_events (ts, rule_id, chain_prev, chain_hash, api_turn_id)
		VALUES ('2026-11-18T00:00:00Z', 'S-1', '', 'h1', (SELECT id FROM api_turns WHERE request_id = 'req-otlp'))`); err != nil {
		t.Fatalf("seed guard event: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO guard_events (ts, rule_id, chain_prev, chain_hash, api_turn_id)
		VALUES ('2026-11-18T00:00:01Z', 'S-2', 'h1', 'h2', (SELECT id FROM api_turns WHERE request_id = 'req-proxy'))`); err != nil {
		t.Fatalf("seed proxy guard event: %v", err)
	}

	if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, migrations.Files, lateSteps); err != nil {
		t.Fatalf("migrate through 256: %v", err)
	}

	count := func(q string) int {
		t.Helper()
		var n int
		if err := database.QueryRowContext(ctx, q).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	if got := count(`SELECT COUNT(*) FROM api_turns WHERE request_id IN ('req-proxy', 'req-legacy')`); got != 2 {
		t.Errorf("Plane B rows kept = %d, want 2", got)
	}
	if got := count(`SELECT COUNT(*) FROM api_turns WHERE request_id IN ('req-otlp', 'req-sdk')`); got != 0 {
		t.Errorf("Plane A rows left in api_turns = %d, want 0", got)
	}
	if got := count(`SELECT COUNT(*) FROM api_turns_planea_legacy WHERE request_id IN ('req-otlp', 'req-sdk') AND input_tokens = 7 AND relocated_at IS NOT NULL`); got != 2 {
		t.Errorf("relocated rows = %d, want 2 verbatim copies", got)
	}
	if got := count(`SELECT COUNT(*) FROM guard_events WHERE rule_id = 'S-1' AND api_turn_id IS NULL`); got != 1 {
		t.Errorf("guard event reference not cleared")
	}
	if got := count(`SELECT COUNT(*) FROM guard_events WHERE rule_id = 'S-2' AND api_turn_id = (SELECT id FROM api_turns WHERE request_id = 'req-proxy')`); got != 1 {
		t.Errorf("a Plane B row's guard event reference was cleared")
	}
	if got := count(`SELECT COUNT(*) FROM org_push_deletions WHERE tbl = 'api_turns' AND k2 IN ('req-otlp', 'req-sdk')`); got != 2 {
		t.Errorf("org tombstones = %d, want 2", got)
	}
}

// TestMigration256NoPlaneARowsTouchesNothing (review R-A11): on a node with
// no Plane A rows the step creates the empty recovery table and changes
// nothing else; a reference to a Plane B row survives and the temp id table
// is gone.
func TestMigration256NoPlaneARowsTouchesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "observer.db")
	database, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(30000)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, lineageWithout(t, apiTurnsPlaneALegacyFile), lateSteps); err != nil {
		t.Fatalf("migrate to the step before 256: %v", err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO api_turns (timestamp, provider, model, request_id, input_tokens, output_tokens, source)
		VALUES ('2026-11-18T00:00:00Z', 'anthropic', 'm', 'req-proxy', 7, 1, 'proxy')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO guard_events (ts, rule_id, chain_prev, chain_hash, api_turn_id)
		VALUES ('2026-11-18T00:00:00Z', 'S-1', '', 'h1', (SELECT id FROM api_turns WHERE request_id = 'req-proxy'))`); err != nil {
		t.Fatal(err)
	}
	if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, migrations.Files, lateSteps); err != nil {
		t.Fatalf("migrate through 256: %v", err)
	}
	for q, want := range map[string]int{
		`SELECT COUNT(*) FROM api_turns`:                                         1,
		`SELECT COUNT(*) FROM api_turns_planea_legacy`:                           0,
		`SELECT COUNT(*) FROM guard_events WHERE api_turn_id IS NOT NULL`:        1,
		`SELECT COUNT(*) FROM org_push_deletions WHERE tbl = 'api_turns'`:        0,
		`SELECT COUNT(*) FROM sqlite_temp_master WHERE name = 'planea_turn_ids'`: 0,
	} {
		var n int
		if err := database.QueryRowContext(ctx, q).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if n != want {
			t.Errorf("%s = %d, want %d", q, n, want)
		}
	}
}
