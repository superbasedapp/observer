package sqliteledger

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/migplan"
)

// Queryer is the read surface planning needs; *sql.DB, *sql.Conn and *sql.Tx
// all satisfy it.
type Queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Execer is the write surface Apply needs; *sql.Conn and *sql.Tx satisfy it.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// ledgerQuery reads only the keys the ledger owns. The step records are a
// key range ("migration:" up to, not including, "migration;", the next byte),
// so the read walks the schema_meta primary key index instead of the table,
// whatever else the database keeps there.
const ledgerQuery = `SELECT key, value FROM schema_meta
	WHERE key IN (?, ?) OR (key >= ? AND key < ?)`

// stepKeyRangeEnd is the first key after every migplan.StepKeyPrefix key.
const stepKeyRangeEnd = "migration;"

// ReadLedger loads the ledger keys of schema_meta. A database without a
// schema_meta table (no runner has touched it) is an empty ledger. A malformed
// value under a ledger key is an error, never a silent zero.
func ReadLedger(ctx context.Context, q Queryer) (migplan.Ledger, error) {
	var tables int
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta'`,
	).Scan(&tables); err != nil {
		return migplan.Ledger{}, fmt.Errorf("sqliteledger.ReadLedger: inspect schema_meta: %w", err)
	}
	kv := map[string]string{}
	if tables > 0 {
		rows, err := q.QueryContext(ctx, ledgerQuery,
			migplan.VersionKey, migplan.HorizonKey, migplan.StepKeyPrefix, stepKeyRangeEnd)
		if err != nil {
			return migplan.Ledger{}, fmt.Errorf("sqliteledger.ReadLedger: read schema_meta: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				return migplan.Ledger{}, fmt.Errorf("sqliteledger.ReadLedger: read schema_meta: %w", err)
			}
			kv[k] = v
		}
		if err := rows.Err(); err != nil {
			return migplan.Ledger{}, fmt.Errorf("sqliteledger.ReadLedger: read schema_meta: %w", err)
		}
	}
	ledger, err := migplan.ParseLedger(kv)
	if err != nil {
		return migplan.Ledger{}, fmt.Errorf("sqliteledger.ReadLedger: %w", err)
	}
	return ledger, nil
}

// AppliedCount reports how many steps carry an applied record: steps a
// runner EXECUTED on this database, never ones it adopted. Recording a ledger
// (adopting) leaves it unchanged and running any step, including a late one
// numbered below the version, raises it, so a before/after difference tells
// whether a binary changed the schema when the version record cannot.
func AppliedCount(ctx context.Context, q Queryer) (int, error) {
	ledger, err := ReadLedger(ctx, q)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, rec := range ledger.Steps {
		if rec == migplan.RecordApplied {
			n++
		}
	}
	return n, nil
}

// ProbeLate runs the column probe of every late step whose version embedded
// contains and reports whether its column is present. Steps the lineage does
// not embed are not probed (and so are not late steps to Decide).
func ProbeLate(ctx context.Context, q Queryer, late []migplan.LateStep, embedded []int) (map[int]bool, error) {
	if len(late) == 0 {
		return nil, nil
	}
	have := make(map[int]bool, len(embedded))
	for _, v := range embedded {
		have[v] = true
	}
	present := map[int]bool{}
	for _, s := range late {
		if !have[s.Version] {
			continue
		}
		var n int
		if err := q.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, s.Table, s.Column,
		).Scan(&n); err != nil {
			return nil, fmt.Errorf("sqliteledger.ProbeLate: probe late step %d: %w", s.Version, err)
		}
		present[s.Version] = n > 0
	}
	return present, nil
}

// Plan reads the ledger and the late-step probes through q and returns what
// the runner must do with the embedded lineage (versions strictly ascending).
// It only reads, so a doctor or preflight surface can call it on a plain
// handle and report exactly the plan the runner would execute.
func Plan(ctx context.Context, q Queryer, embedded []int, late []migplan.LateStep) (migplan.Plan, error) {
	ledger, err := ReadLedger(ctx, q)
	if err != nil {
		return migplan.Plan{}, err
	}
	present, err := ProbeLate(ctx, q, late, embedded)
	if err != nil {
		return migplan.Plan{}, err
	}
	plan, err := migplan.Decide(migplan.Input{Embedded: embedded, Ledger: ledger, Late: present})
	if err != nil {
		return migplan.Plan{}, fmt.Errorf("sqliteledger.Plan: %w", err)
	}
	return plan, nil
}

// Apply executes plan through x, inside the caller's transaction: it forgets
// voided records, stores the horizon, then walks the steps in order, calling
// run for each ActionRun step before recording it, and finally stores the
// version record. run's error is returned unwrapped so the runner keeps its
// own context (file name, step); the caller rolls back on any error.
func Apply(ctx context.Context, x Execer, plan migplan.Plan, run func(version int) error) error {
	for _, v := range plan.Forget {
		if _, err := x.ExecContext(ctx, `DELETE FROM schema_meta WHERE key = ?`, migplan.StepKey(v)); err != nil {
			return fmt.Errorf("sqliteledger.Apply: forget step record %d: %w", v, err)
		}
	}
	if plan.WriteHorizon {
		if err := upsert(ctx, x, migplan.HorizonKey, strconv.Itoa(plan.Horizon)); err != nil {
			return fmt.Errorf("sqliteledger.Apply: record ledger horizon: %w", err)
		}
	}
	for _, step := range plan.Steps {
		if step.Action == migplan.ActionRun {
			if err := run(step.Version); err != nil {
				return err
			}
		}
		if err := upsert(ctx, x, migplan.StepKey(step.Version), step.Action.Record()); err != nil {
			return fmt.Errorf("sqliteledger.Apply: record step %d: %w", step.Version, err)
		}
	}
	if plan.WriteVersion {
		if err := upsert(ctx, x, migplan.VersionKey, strconv.Itoa(plan.Version)); err != nil {
			return fmt.Errorf("sqliteledger.Apply: record version %d: %w", plan.Version, err)
		}
	}
	return nil
}

// upsert writes one schema_meta key.
func upsert(ctx context.Context, x Execer, key, value string) error {
	_, err := x.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value)
	return err
}
