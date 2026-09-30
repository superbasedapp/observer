package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/reprice"
)

// Re-pricing of stored costs (gap PRICE-REPRICE-1, agent migration 145,
// docs/pricing.md "Re-pricing stored costs"). This file is the ONE store seam
// for reprice_runs / reprice_changes and for the cost_usd_captured /
// cost_repriced_run columns on api_turns and summary_calls. The decisions are
// internal/reprice's (pure); this file only loads rows with their provenance
// resolved into plain flags, and writes the planner's decisions back as
// compare-and-swap updates with a change log a revert can replay.

// Re-price run kinds and statuses, as stored in reprice_runs.
const (
	RepriceKindApply  = "apply"
	RepriceKindRevert = "revert"

	RepriceStatusRunning  = "running"
	RepriceStatusApplied  = "applied"
	RepriceStatusPartial  = "partial"
	RepriceStatusReverted = "reverted"
)

// repriceBatchSize bounds the rows one write transaction touches, so a
// re-price over months of history never holds the daemon's writers (the
// proxy, the watcher) off the database for longer than one small batch.
const repriceBatchSize = 1000

// Typed refusals of RevertReprice.
var (
	// ErrRepriceRunNotFound is returned when the named run does not exist.
	ErrRepriceRunNotFound = errors.New("re-price run not found")
	// ErrRepriceRunReverted is returned when the run was already reverted.
	ErrRepriceRunReverted = errors.New("re-price run was already reverted")
	// ErrRepriceRunIsRevert is returned when the named run is itself a revert
	// (undo a revert by re-pricing again, not by reverting the revert).
	ErrRepriceRunIsRevert = errors.New("re-price run is itself a revert")
	// ErrRepriceRunSuperseded is matched by [RepriceSupersededError]: a LATER
	// apply run that is not reverted holds some of the run's rows, so that
	// run must be reverted first (runs are undone newest first).
	ErrRepriceRunSuperseded = errors.New("re-price run was superseded by a later run")
	// ErrRepriceRunRunning is returned when the named run is still running
	// (its apply has not finished writing, so its change log is incomplete).
	ErrRepriceRunRunning = errors.New("re-price run is still running")
	// ErrRepriceBusy is matched by [RepriceBusyError]: another re-price or
	// revert run holds this database's one run claim.
	ErrRepriceBusy = errors.New("another re-price run is in progress")
)

// RepriceSupersededError refuses a revert whose rows a later, non-reverted
// apply run holds. Reverting out of order would restore the run's recorded
// old cost under a marker the later run's revert then puts back, stranding
// the row on a reverted run's price with no path to its captured cost
// (PRICE-REPRICE-1 review finding 2). LaterRunID is the newest such run.
type RepriceSupersededError struct {
	RunID      int64
	LaterRunID int64
}

func (e *RepriceSupersededError) Error() string {
	return fmt.Sprintf("re-price run %d cannot be reverted yet: run %d re-priced some of its rows since; revert run %d first",
		e.RunID, e.LaterRunID, e.LaterRunID)
}

// Is makes errors.Is(err, ErrRepriceRunSuperseded) match.
func (e *RepriceSupersededError) Is(target error) bool { return target == ErrRepriceRunSuperseded }

// RepriceBusyError refuses a new run while another holds the claim.
type RepriceBusyError struct {
	RunningRunID int64
}

func (e *RepriceBusyError) Error() string {
	return fmt.Sprintf("re-price run %d is still in progress on this database; wait for it to finish", e.RunningRunID)
}

// Is makes errors.Is(err, ErrRepriceBusy) match.
func (e *RepriceBusyError) Is(target error) bool { return target == ErrRepriceBusy }

// RepriceClaimLease bounds how long a run left 'running' holds the one run
// claim. A run's writes take seconds; a 'running' row older than this is one
// whose process died mid-way, and the next claim marks it partial (its
// committed batches stay committed and revertable) instead of blocking every
// later run forever.
const RepriceClaimLease = time.Hour

// apiTurnSourceReported maps api_turns.source to "the stored cost_usd is the
// capture source's OWN figure". It is a DATA TABLE (CLAUDE.md #3/#5): a
// source string becomes a flag here, at the boundary, and internal/reprice
// never sees it.
//
//   - false: the node's cost engine stamped the cost when the row landed (the
//     proxy intercept, the legacy empty/NULL source that every pre-047 row
//     carries, and the proxy-turn rail's synthesized span). Re-pricing
//     replaces an engine's own earlier answer with its corrected one.
//   - true: the cost came WITH the observation (Claude Code's native
//     telemetry, a JSONL usage envelope, an SDK / OTLP span's stated cost).
//     Re-pricing never overwrites a figure the source stated.
//
// A source missing from this table is treated as source-reported: a figure
// whose provenance cannot be classified is kept, never replaced.
var apiTurnSourceReported = map[string]bool{
	"":              false,
	SourceProxy:     false,
	SourceProxyTurn: false,
	SourceCCOTel:    true,
	SourceJSONL:     true,
	SourceObsSDK:    true,
	SourceObsOTLP:   true,
}

// apiTurnCostIsSourceReported resolves one api_turns.source through
// [apiTurnSourceReported].
func apiTurnCostIsSourceReported(source string) bool {
	v, ok := apiTurnSourceReported[source]
	if !ok {
		return true
	}
	return v
}

// RepriceFilter bounds a re-price scan. Zero times are unbounded; Until is
// exclusive. Model, when set, is an exact match on the stored model id.
type RepriceFilter struct {
	Since time.Time
	Until time.Time
	Model string
}

// where renders the filter as a SQL predicate over a table's own
// timestamp / model columns, plus its bound args.
func (f RepriceFilter) where() (string, []any) {
	clause := ""
	var args []any
	if !f.Since.IsZero() {
		clause += " AND timestamp >= ?"
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	if !f.Until.IsZero() {
		clause += " AND timestamp < ?"
		args = append(args, f.Until.UTC().Format(time.RFC3339Nano))
	}
	if f.Model != "" {
		clause += " AND model = ?"
		args = append(args, f.Model)
	}
	return clause, args
}

// repriceScanner loads one table's candidate rows. The table list is data:
// adding a spend table is one more row, not another branch.
type repriceScanner struct {
	table string
	// query is the SELECT with the filter predicate appended by scan; it must
	// end in "WHERE 1=1" so the predicate can be appended.
	query string
	scan  func(rows *sql.Rows) (reprice.Row, error)
}

var repriceScanners = []repriceScanner{
	{
		// api_turns: every row. Reasoning stays 0 - the proxy's output_tokens
		// already includes it, exactly as the capture-time stamp priced it.
		table: "api_turns",
		query: `SELECT id, COALESCE(model, ''), COALESCE(timestamp, ''),
		               COALESCE(input_tokens, 0), COALESCE(output_tokens, 0),
		               COALESCE(cache_read_tokens, 0), COALESCE(cache_creation_tokens, 0),
		               COALESCE(cache_creation_1h_tokens, 0), COALESCE(web_search_requests, 0),
		               COALESCE(fast, 0), cost_usd, COALESCE(source, '')
		          FROM api_turns WHERE 1=1`,
		scan: func(rows *sql.Rows) (reprice.Row, error) {
			r := reprice.Row{Table: "api_turns"}
			var fast int
			var stored sql.NullFloat64
			var source string
			if err := rows.Scan(&r.ID, &r.Model, &r.Timestamp,
				&r.Tokens.Input, &r.Tokens.Output, &r.Tokens.CacheRead, &r.Tokens.CacheCreation,
				&r.Tokens.CacheCreation1h, &r.Tokens.WebSearchRequests, &fast, &stored, &source); err != nil {
				return r, err
			}
			r.Tokens.Fast = fast != 0
			r.Stored = floatPtr(stored)
			r.SourceReported = apiTurnCostIsSourceReported(source)
			return r, nil
		},
	},
	{
		// summary_calls: every row; the rolling summariser's recorder priced
		// it through the node's cost engine at insert time.
		table: "summary_calls",
		query: `SELECT id, COALESCE(model, ''), COALESCE(timestamp, ''),
		               COALESCE(input_tokens, 0), COALESCE(output_tokens, 0),
		               COALESCE(cache_read_tokens, 0), COALESCE(cache_creation_tokens, 0),
		               cost_usd
		          FROM summary_calls WHERE 1=1`,
		scan: func(rows *sql.Rows) (reprice.Row, error) {
			r := reprice.Row{Table: "summary_calls"}
			var stored sql.NullFloat64
			if err := rows.Scan(&r.ID, &r.Model, &r.Timestamp,
				&r.Tokens.Input, &r.Tokens.Output, &r.Tokens.CacheRead, &r.Tokens.CacheCreation, &stored); err != nil {
				return r, err
			}
			r.Stored = floatPtr(stored)
			return r, nil
		},
	},
	{
		// token_usage: ONLY rows carrying a stored figure. On the node the
		// engine never stamps token_usage (the push-time pricer prices the
		// WIRE copy, not the row), so every stored figure here came from the
		// adapter - the tool's own stated cost - and is source-reported. The
		// rows are scanned only so a dry run can say how many such figures
		// were kept. A row stored at 0 is priced at READ time by the
		// dashboard at the rate in force for its timestamp already, so there
		// is nothing to re-price and it is not scanned.
		table: "token_usage",
		query: `SELECT id, COALESCE(model, ''), COALESCE(timestamp, ''), estimated_cost_usd
		          FROM token_usage WHERE estimated_cost_usd > 0`,
		scan: func(rows *sql.Rows) (reprice.Row, error) {
			r := reprice.Row{Table: "token_usage", SourceReported: true}
			var stored sql.NullFloat64
			if err := rows.Scan(&r.ID, &r.Model, &r.Timestamp, &stored); err != nil {
				return r, err
			}
			r.Stored = floatPtr(stored)
			return r, nil
		},
	},
}

func floatPtr(v sql.NullFloat64) *float64 {
	if !v.Valid {
		return nil
	}
	f := v.Float64
	return &f
}

func nullableFloat(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullableRun(run int64) any {
	if run == 0 {
		return nil
	}
	return run
}

// ScanRepriceRows streams every candidate row under f to fn, table by table
// in id order, with provenance already resolved into reprice.Row flags. It
// holds one read cursor per table and never writes; fn must not write to the
// database either (it is handed rows while the cursor is open).
func (s *Store) ScanRepriceRows(ctx context.Context, f RepriceFilter, fn func(reprice.Row) error) error {
	pred, args := f.where()
	for _, sc := range repriceScanners {
		if err := s.scanRepriceTable(ctx, sc, pred, args, fn); err != nil {
			return fmt.Errorf("store.ScanRepriceRows: %s: %w", sc.table, err)
		}
	}
	return nil
}

func (s *Store) scanRepriceTable(ctx context.Context, sc repriceScanner, pred string, args []any, fn func(reprice.Row) error) error {
	//nolint:gosec // G202: query and predicate are compile-time constant SQL; values bind via args.
	rows, err := s.db.QueryContext(ctx, sc.query+pred+" ORDER BY id", args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := sc.scan(rows)
		if err != nil {
			return err
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

// repriceTarget is the per-table SQL a write uses. Only tables carrying the
// migration-145 marker columns can be written; token_usage is never among
// them (its stored figures are source-reported by construction).
type repriceTarget struct {
	// current reads (cost, marker, session_id) for one id.
	current string
	// apply is the compare-and-swap re-price: args (new, run, id, old).
	apply string
	// restore is the compare-and-swap revert: args (restore, marker,
	// marker-for-captured, id, expected cost, expected marker).
	restore string
	// laterHolder finds the newest LATER, non-reverted apply run holding a row
	// of a run's change log: args (run, run). No row = none.
	laterHolder string
}

// laterHolderSQL renders a target's laterHolder query over its own table.
func laterHolderSQL(table string) string {
	return `SELECT t.cost_repriced_run
	          FROM reprice_changes c
	          JOIN ` + table + ` t ON t.id = c.row_id
	          JOIN reprice_runs r ON r.id = t.cost_repriced_run
	         WHERE c.run_id = ? AND c.tbl = '` + table + `'
	           AND t.cost_repriced_run > ?
	           AND r.kind = 'apply' AND r.reverted_by_run IS NULL AND r.status <> 'reverted'
	         ORDER BY t.cost_repriced_run DESC
	         LIMIT 1`
}

var repriceTargets = map[string]repriceTarget{
	"api_turns": {
		current: `SELECT cost_usd, cost_repriced_run, COALESCE(session_id, '') FROM api_turns WHERE id = ?`,
		apply: `UPDATE api_turns
		           SET cost_usd = ?,
		               cost_usd_captured = CASE WHEN cost_repriced_run IS NULL THEN cost_usd ELSE cost_usd_captured END,
		               cost_repriced_run = ?
		         WHERE id = ? AND cost_usd IS ?`,
		restore: `UPDATE api_turns
		             SET cost_usd = ?,
		                 cost_repriced_run = ?,
		                 cost_usd_captured = CASE WHEN ? IS NULL THEN NULL ELSE cost_usd_captured END
		           WHERE id = ? AND cost_usd IS ? AND cost_repriced_run IS ?`,
		laterHolder: laterHolderSQL("api_turns"),
	},
	"summary_calls": {
		current: `SELECT cost_usd, cost_repriced_run, COALESCE(session_id, '') FROM summary_calls WHERE id = ?`,
		apply: `UPDATE summary_calls
		           SET cost_usd = ?,
		               cost_usd_captured = CASE WHEN cost_repriced_run IS NULL THEN cost_usd ELSE cost_usd_captured END,
		               cost_repriced_run = ?
		         WHERE id = ? AND cost_usd IS ?`,
		restore: `UPDATE summary_calls
		             SET cost_usd = ?,
		                 cost_repriced_run = ?,
		                 cost_usd_captured = CASE WHEN ? IS NULL THEN NULL ELSE cost_usd_captured END
		           WHERE id = ? AND cost_usd IS ? AND cost_repriced_run IS ?`,
		laterHolder: laterHolderSQL("summary_calls"),
	},
}

// repriceTargetTables is repriceTargets' keys in a fixed order.
var repriceTargetTables = []string{"api_turns", "summary_calls"}

// arenaRollupTable is the one table whose rows feed a derived SUM
// (arena_candidates.cost_usd = SUM(api_turns.cost_usd) over the candidate's
// sessions, internal/arena rollupUsage). A write to it collects the touched
// session so the rollup is refreshed afterwards.
const arenaRollupTable = "api_turns"

// orgParityTable is the one re-priceable table on the org push wire (and
// under the migration-142 re-send trigger). summary_calls never leaves the
// node.
const orgParityTable = "api_turns"

// RepriceRunMeta is what the caller knows about a run before any row is
// written: the plan's filter, rule version, pricing and scan counts.
type RepriceRunMeta struct {
	Actor          string
	Since          string
	Until          string
	Model          string
	RuleVersion    int
	PricingSource  string
	PricingVersion int64
	// Scanned is the plan's scanned count; TableScanned its per-table split.
	Scanned      int
	TableScanned map[string]int
	// Skipped is the plan's skipped-by-reason counts.
	Skipped map[string]int
}

// RepriceRunSummary is reprice_runs.summary_json: the skipped-by-reason
// counts and the per-table / per-model breakdown over the rows the run
// actually wrote (Scanned per table comes from the plan).
type RepriceRunSummary struct {
	Skipped map[string]int         `json:"skipped,omitempty"`
	Tables  []reprice.TableSummary `json:"tables,omitempty"`
	Models  []reprice.ModelSummary `json:"models,omitempty"`
}

// RepriceRun is one reprice_runs row.
type RepriceRun struct {
	ID             int64
	Kind           string
	CreatedAt      string
	Actor          string
	Since          string
	Until          string
	Model          string
	RuleVersion    int
	PricingSource  string
	PricingVersion int64
	Scanned        int
	Changed        int
	Filled         int
	CASMissed      int
	OldUSD         float64
	NewUSD         float64
	DeltaUSD       float64
	RevertsRun     int64
	RevertedByRun  int64
	Status         string
	Summary        RepriceRunSummary
	// Warnings are non-fatal follow-up failures of this call (an arena
	// rollup that could not be refreshed). Not persisted.
	Warnings []string
}

// repriceTally accumulates what a run actually wrote.
type repriceTally struct {
	changed, filled, casMissed int
	oldUSD, newUSD             float64
	tables                     map[string]*reprice.TableSummary
	models                     map[string]*reprice.ModelSummary
	skipped                    map[string]int
	sessions                   map[string]struct{}
}

func newRepriceTally() *repriceTally {
	return &repriceTally{
		tables:   map[string]*reprice.TableSummary{},
		models:   map[string]*reprice.ModelSummary{},
		skipped:  map[string]int{},
		sessions: map[string]struct{}{},
	}
}

func (t *repriceTally) wrote(table, model string, oldCost, newCost *float64) {
	o, n := derefCost(oldCost), derefCost(newCost)
	t.changed++
	if oldCost == nil {
		t.filled++
	}
	t.oldUSD += o
	t.newUSD += n
	ts := t.tables[table]
	if ts == nil {
		ts = &reprice.TableSummary{Table: table}
		t.tables[table] = ts
	}
	ts.Changed++
	ts.OldUSD += o
	ts.NewUSD += n
	if model == "" {
		return
	}
	ms := t.models[model]
	if ms == nil {
		ms = &reprice.ModelSummary{Model: model}
		t.models[model] = ms
	}
	ms.Changed++
	ms.OldUSD += o
	ms.NewUSD += n
}

func derefCost(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// summary renders the tally, folding in the plan's per-table scan counts and
// skip reasons. Models are capped at the 20 with the largest |delta|.
func (t *repriceTally) summary(tableScanned map[string]int, planSkipped map[string]int) RepriceRunSummary {
	out := RepriceRunSummary{Skipped: map[string]int{}}
	for k, v := range planSkipped {
		out.Skipped[k] += v
	}
	for k, v := range t.skipped {
		out.Skipped[k] += v
	}
	if len(out.Skipped) == 0 {
		out.Skipped = nil
	}
	seen := map[string]bool{}
	for name, ts := range t.tables {
		row := *ts
		row.Scanned = tableScanned[name]
		out.Tables = append(out.Tables, row)
		seen[name] = true
	}
	for name, n := range tableScanned {
		if !seen[name] {
			out.Tables = append(out.Tables, reprice.TableSummary{Table: name, Scanned: n})
		}
	}
	sortTableSummaries(out.Tables)
	for _, m := range t.models {
		out.Models = append(out.Models, *m)
	}
	out.Models = topModelSummaries(out.Models, 20)
	return out
}

func sortTableSummaries(ts []reprice.TableSummary) {
	sort.Slice(ts, func(i, j int) bool { return ts[i].Table < ts[j].Table })
}

// topModelSummaries sorts by |delta| descending then model name, and caps.
func topModelSummaries(ms []reprice.ModelSummary, limit int) []reprice.ModelSummary {
	sort.Slice(ms, func(i, j int) bool {
		a, b := math.Abs(ms[i].DeltaUSD()), math.Abs(ms[j].DeltaUSD())
		if a != b {
			return a > b
		}
		return ms[i].Model < ms[j].Model
	})
	if len(ms) > limit {
		ms = ms[:limit]
	}
	return ms
}

// ApplyReprice writes the planner's update decisions as one apply run.
//
// The run row is created FIRST (status running), so a crash mid-way leaves an
// honest record. Decisions are written in batches of [repriceBatchSize] rows,
// one transaction each; every write is a compare-and-swap on the planned old
// cost, and every successful write records its change-log row in the same
// transaction. A row that no longer holds the planned old cost (a capture
// path rewrote it since the plan) or no longer exists is counted in
// cas_missed and left alone. The run row is finalized with totals over the
// rows ACTUALLY written: status applied, or partial when a batch failed or
// ctx was cancelled (the rows already committed stay committed and are
// revertable).
//
// Afterwards the arena rollups over any touched session are refreshed; a
// failure there is reported in RepriceRun.Warnings, not as an error.
func (s *Store) ApplyReprice(ctx context.Context, meta RepriceRunMeta, updates []reprice.Decision) (RepriceRun, error) {
	for _, d := range updates {
		if d.Action != reprice.ActionUpdate || d.New == nil {
			return RepriceRun{}, fmt.Errorf("store.ApplyReprice: %s %d is not an update decision", d.Table, d.ID)
		}
		if _, ok := repriceTargets[d.Table]; !ok {
			return RepriceRun{}, fmt.Errorf("store.ApplyReprice: table %q carries no re-price columns", d.Table)
		}
	}
	runID, err := s.claimRepriceRun(ctx, RepriceKindApply, meta, 0, nil)
	if err != nil {
		return RepriceRun{}, fmt.Errorf("store.ApplyReprice: %w", err)
	}
	tally := newRepriceTally()
	var runErr error
	for start := 0; start < len(updates) && runErr == nil; start += repriceBatchSize {
		if err := ctx.Err(); err != nil {
			runErr = err
			break
		}
		end := start + repriceBatchSize
		if end > len(updates) {
			end = len(updates)
		}
		runErr = s.applyRepriceBatch(ctx, runID, updates[start:end], tally)
	}
	status := RepriceStatusApplied
	if runErr != nil {
		status = RepriceStatusPartial
	}
	sum := tally.summary(meta.TableScanned, meta.Skipped)
	// Finalize on a context that survives the caller's cancel: the committed
	// batches are real, so the run row must say so.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := s.finalizeRepriceRun(fctx, runID, status, tally, sum); err != nil {
		return RepriceRun{}, fmt.Errorf("store.ApplyReprice: finalize: %w", errors.Join(err, runErr))
	}
	run, err := s.RepriceRunByID(fctx, runID)
	if err != nil {
		return RepriceRun{}, fmt.Errorf("store.ApplyReprice: %w", errors.Join(err, runErr))
	}
	if werr := s.refreshArenaCostsForSessions(fctx, tally.sessions); werr != nil {
		run.Warnings = append(run.Warnings, "arena cost rollups were not refreshed: "+werr.Error())
	}
	if runErr != nil {
		return run, fmt.Errorf("store.ApplyReprice: %w", runErr)
	}
	return run, nil
}

func (s *Store) applyRepriceBatch(ctx context.Context, runID int64, batch []reprice.Decision, tally *repriceTally) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	local := newRepriceTally()
	for _, d := range batch {
		tgt := repriceTargets[d.Table]
		var cur sql.NullFloat64
		var marker sql.NullInt64
		var session string
		err := tx.QueryRowContext(ctx, tgt.current, d.ID).Scan(&cur, &marker, &session)
		if errors.Is(err, sql.ErrNoRows) {
			local.casMissed++
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s %d: %w", d.Table, d.ID, err)
		}
		res, err := tx.ExecContext(ctx, tgt.apply, *d.New, runID, d.ID, nullableFloat(d.Old))
		if err != nil {
			return fmt.Errorf("update %s %d: %w", d.Table, d.ID, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			local.casMissed++
			continue
		}
		var prev any
		if marker.Valid {
			prev = marker.Int64
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO reprice_changes (run_id, tbl, row_id, old_cost, new_cost, prev_run) VALUES (?, ?, ?, ?, ?, ?)`,
			runID, d.Table, d.ID, nullableFloat(d.Old), *d.New, prev); err != nil {
			return fmt.Errorf("log %s %d: %w", d.Table, d.ID, err)
		}
		local.wrote(d.Table, d.Model, d.Old, d.New)
		if d.Table == arenaRollupTable && session != "" {
			local.sessions[session] = struct{}{}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	tally.merge(local)
	return nil
}

// merge folds a committed batch's tally into the run's.
func (t *repriceTally) merge(o *repriceTally) {
	t.changed += o.changed
	t.filled += o.filled
	t.casMissed += o.casMissed
	t.oldUSD += o.oldUSD
	t.newUSD += o.newUSD
	for k, v := range o.tables {
		ts := t.tables[k]
		if ts == nil {
			ts = &reprice.TableSummary{Table: k}
			t.tables[k] = ts
		}
		ts.Changed += v.Changed
		ts.OldUSD += v.OldUSD
		ts.NewUSD += v.NewUSD
	}
	for k, v := range o.models {
		ms := t.models[k]
		if ms == nil {
			ms = &reprice.ModelSummary{Model: k}
			t.models[k] = ms
		}
		ms.Changed += v.Changed
		ms.OldUSD += v.OldUSD
		ms.NewUSD += v.NewUSD
	}
	for k, v := range o.skipped {
		t.skipped[k] += v
	}
	for k := range o.sessions {
		t.sessions[k] = struct{}{}
	}
}

// claimRepriceRun creates a run row in status running, which is this
// database's ONE run claim: a CLI `observer reprice --apply` and the daemon's
// Settings card (or two CLIs) can never write two runs at once, and a revert
// never interleaves with an apply (PRICE-REPRICE-1 review finding 4).
//
// In one write transaction (SQLite serialises writers, so the check and the
// insert cannot be split by another process): a run left running longer than
// [RepriceClaimLease] is marked partial (a crashed process; its committed
// batches stay revertable), then check - when non-nil - runs its refusals
// against the same snapshot, then the insert happens only when no other run is
// running. A held claim is a *RepriceBusyError naming the running run.
func (s *Store) claimRepriceRun(ctx context.Context, kind string, meta RepriceRunMeta, revertsRun int64, check func(context.Context, *sql.Tx) error) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("claim run: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	// The reclaim is a write, so it takes the write lock before the reads.
	if _, err := tx.ExecContext(ctx,
		`UPDATE reprice_runs SET status = ? WHERE status = ? AND created_at < ?`,
		RepriceStatusPartial, RepriceStatusRunning, now.Add(-RepriceClaimLease).Format(time.RFC3339Nano)); err != nil {
		return 0, fmt.Errorf("claim run: reclaim stale: %w", err)
	}
	if check != nil {
		if err := check(ctx, tx); err != nil {
			return 0, err
		}
	}
	var running int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM reprice_runs WHERE status = ? ORDER BY id LIMIT 1`, RepriceStatusRunning).Scan(&running)
	switch {
	case err == nil:
		return 0, &RepriceBusyError{RunningRunID: running}
	case !errors.Is(err, sql.ErrNoRows):
		return 0, fmt.Errorf("claim run: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO reprice_runs (kind, created_at, actor, since, until, model, rule_version,
		    pricing_source, pricing_version, scanned, reverts_run, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		kind, now.Format(time.RFC3339Nano), meta.Actor, meta.Since, meta.Until, meta.Model,
		meta.RuleVersion, meta.PricingSource, meta.PricingVersion, meta.Scanned, nullableRun(revertsRun),
		RepriceStatusRunning)
	if err != nil {
		return 0, fmt.Errorf("insert run: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("insert run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("claim run: commit: %w", err)
	}
	return id, nil
}

func (s *Store) finalizeRepriceRun(ctx context.Context, runID int64, status string, t *repriceTally, sum RepriceRunSummary) error {
	js, err := json.Marshal(sum)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		UPDATE reprice_runs
		   SET changed = ?, filled = ?, cas_missed = ?, old_usd = ?, new_usd = ?, delta_usd = ?,
		       status = ?, summary_json = ?
		 WHERE id = ?`,
		t.changed, t.filled, t.casMissed, t.oldUSD, t.newUSD, t.newUSD-t.oldUSD, status, string(js), runID)
	return err
}

const repriceRunColumns = `id, kind, created_at, actor, since, until, model, rule_version,
	pricing_source, pricing_version, scanned, changed, filled, cas_missed, old_usd, new_usd,
	delta_usd, COALESCE(reverts_run, 0), COALESCE(reverted_by_run, 0), status, summary_json`

func scanRepriceRun(sc interface{ Scan(...any) error }) (RepriceRun, error) {
	var r RepriceRun
	var js string
	err := sc.Scan(&r.ID, &r.Kind, &r.CreatedAt, &r.Actor, &r.Since, &r.Until, &r.Model, &r.RuleVersion,
		&r.PricingSource, &r.PricingVersion, &r.Scanned, &r.Changed, &r.Filled, &r.CASMissed,
		&r.OldUSD, &r.NewUSD, &r.DeltaUSD, &r.RevertsRun, &r.RevertedByRun, &r.Status, &js)
	if err != nil {
		return r, err
	}
	if js != "" {
		_ = json.Unmarshal([]byte(js), &r.Summary) // a malformed summary never hides the run itself
	}
	return r, nil
}

// RepriceRunByID returns one run, or ErrRepriceRunNotFound.
func (s *Store) RepriceRunByID(ctx context.Context, id int64) (RepriceRun, error) {
	//nolint:gosec // G202: repriceRunColumns is a compile-time constant.
	r, err := scanRepriceRun(s.db.QueryRowContext(ctx, `SELECT `+repriceRunColumns+` FROM reprice_runs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return RepriceRun{}, ErrRepriceRunNotFound
	}
	if err != nil {
		return RepriceRun{}, fmt.Errorf("store.RepriceRunByID: %w", err)
	}
	return r, nil
}

// ListRepriceRuns returns up to limit runs, newest first (limit <= 0 = 20).
func (s *Store) ListRepriceRuns(ctx context.Context, limit int) ([]RepriceRun, error) {
	if limit <= 0 {
		limit = 20
	}
	//nolint:gosec // G202: repriceRunColumns is a compile-time constant.
	rows, err := s.db.QueryContext(ctx, `SELECT `+repriceRunColumns+` FROM reprice_runs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListRepriceRuns: %w", err)
	}
	defer rows.Close()
	var out []RepriceRun
	for rows.Next() {
		r, err := scanRepriceRun(rows)
		if err != nil {
			return nil, fmt.Errorf("store.ListRepriceRuns: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListRepriceRuns: %w", err)
	}
	return out, nil
}

// RevertReprice undoes apply run runID, row by row, through
// reprice.EvaluateRevert: a row is restored to the run's recorded old cost
// and marker only when it still holds exactly what the run wrote; a row a
// later run re-priced, a capture path rewrote, or retention removed is
// skipped (counted by reason in the revert run's summary). Restoring the
// marker to "never re-priced" also clears cost_usd_captured.
//
// It records its own revert run (kind revert, reverts_run = runID, its own
// change log) and, once every batch is written, marks runID reverted. It
// refuses, with the typed errors above: an unknown run, a run already
// reverted, a revert run, a run still running (its change log is not
// complete), and a run any of whose rows a LATER non-reverted apply run holds
// (*RepriceSupersededError naming it: runs are undone newest first, so no row
// is ever stranded on a reverted run's price). The refusals are checked in the
// same write transaction that claims the revert's run row.
func (s *Store) RevertReprice(ctx context.Context, runID int64, actor string) (RepriceRun, error) {
	target, err := s.RepriceRunByID(ctx, runID)
	if err != nil {
		if errors.Is(err, ErrRepriceRunNotFound) {
			return RepriceRun{}, fmt.Errorf("store.RevertReprice: run %d: %w", runID, ErrRepriceRunNotFound)
		}
		return RepriceRun{}, fmt.Errorf("store.RevertReprice: %w", err)
	}
	var scanned int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reprice_changes WHERE run_id = ?`, runID).Scan(&scanned); err != nil {
		return RepriceRun{}, fmt.Errorf("store.RevertReprice: count changes: %w", err)
	}
	meta := RepriceRunMeta{
		Actor: actor, Since: target.Since, Until: target.Until, Model: target.Model,
		RuleVersion: reprice.RuleVersion, PricingSource: target.PricingSource,
		PricingVersion: target.PricingVersion, Scanned: scanned,
	}
	revID, err := s.claimRepriceRun(ctx, RepriceKindRevert, meta, runID, func(ctx context.Context, tx *sql.Tx) error {
		return revertRefusal(ctx, tx, runID)
	})
	if err != nil {
		return RepriceRun{}, fmt.Errorf("store.RevertReprice: %w", err)
	}
	tally := newRepriceTally()
	tableScanned := map[string]int{}
	var runErr error
	cursorTbl, cursorID := "", int64(0)
	for runErr == nil {
		if err := ctx.Err(); err != nil {
			runErr = err
			break
		}
		changes, err := s.loadRepriceChanges(ctx, runID, cursorTbl, cursorID, repriceBatchSize)
		if err != nil {
			runErr = err
			break
		}
		if len(changes) == 0 {
			break
		}
		for _, c := range changes {
			tableScanned[c.change.Table]++
		}
		last := changes[len(changes)-1]
		cursorTbl, cursorID = last.change.Table, last.change.ID
		runErr = s.revertRepriceBatch(ctx, runID, revID, changes, tally)
	}
	status := RepriceStatusApplied
	if runErr != nil {
		status = RepriceStatusPartial
	}
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := s.finalizeRepriceRun(fctx, revID, status, tally, tally.summary(tableScanned, nil)); err != nil {
		return RepriceRun{}, fmt.Errorf("store.RevertReprice: finalize: %w", errors.Join(err, runErr))
	}
	if runErr == nil {
		if _, err := s.db.ExecContext(fctx,
			`UPDATE reprice_runs SET reverted_by_run = ?, status = ? WHERE id = ? AND reverted_by_run IS NULL`,
			revID, RepriceStatusReverted, runID); err != nil {
			return RepriceRun{}, fmt.Errorf("store.RevertReprice: mark reverted: %w", err)
		}
	}
	run, err := s.RepriceRunByID(fctx, revID)
	if err != nil {
		return RepriceRun{}, fmt.Errorf("store.RevertReprice: %w", errors.Join(err, runErr))
	}
	if werr := s.refreshArenaCostsForSessions(fctx, tally.sessions); werr != nil {
		run.Warnings = append(run.Warnings, "arena cost rollups were not refreshed: "+werr.Error())
	}
	if runErr != nil {
		return run, fmt.Errorf("store.RevertReprice: %w", runErr)
	}
	return run, nil
}

// revertRefusal re-reads the target run inside the claim transaction and
// returns the typed refusal that applies, or nil.
func revertRefusal(ctx context.Context, tx *sql.Tx, runID int64) error {
	//nolint:gosec // G202: repriceRunColumns is a compile-time constant.
	target, err := scanRepriceRun(tx.QueryRowContext(ctx, `SELECT `+repriceRunColumns+` FROM reprice_runs WHERE id = ?`, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("run %d: %w", runID, ErrRepriceRunNotFound)
	}
	if err != nil {
		return fmt.Errorf("read run %d: %w", runID, err)
	}
	switch {
	case target.Kind == RepriceKindRevert:
		return fmt.Errorf("run %d: %w", runID, ErrRepriceRunIsRevert)
	case target.RevertedByRun != 0 || target.Status == RepriceStatusReverted:
		return fmt.Errorf("run %d: %w", runID, ErrRepriceRunReverted)
	case target.Status == RepriceStatusRunning:
		return fmt.Errorf("run %d: %w", runID, ErrRepriceRunRunning)
	}
	var later int64
	for _, table := range repriceTargetTables {
		var held int64
		err := tx.QueryRowContext(ctx, repriceTargets[table].laterHolder, runID, runID).Scan(&held)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("find later runs over %s: %w", table, err)
		}
		if held > later {
			later = held
		}
	}
	if later != 0 {
		return &RepriceSupersededError{RunID: runID, LaterRunID: later}
	}
	return nil
}

// loggedChange is one reprice_changes row read back for a revert.
type loggedChange struct {
	change reprice.Change
}

func (s *Store) loadRepriceChanges(ctx context.Context, runID int64, afterTbl string, afterID int64, limit int) ([]loggedChange, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT tbl, row_id, old_cost, new_cost, COALESCE(prev_run, 0)
		  FROM reprice_changes
		 WHERE run_id = ? AND (tbl > ? OR (tbl = ? AND row_id > ?))
		 ORDER BY tbl, row_id
		 LIMIT ?`, runID, afterTbl, afterTbl, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("load changes: %w", err)
	}
	defer rows.Close()
	var out []loggedChange
	for rows.Next() {
		var c reprice.Change
		var oldC, newC sql.NullFloat64
		if err := rows.Scan(&c.Table, &c.ID, &oldC, &newC, &c.PrevRun); err != nil {
			return nil, fmt.Errorf("scan change: %w", err)
		}
		c.Old, c.New = floatPtr(oldC), floatPtr(newC)
		out = append(out, loggedChange{change: c})
	}
	return out, rows.Err()
}

func (s *Store) revertRepriceBatch(ctx context.Context, runID, revID int64, batch []loggedChange, tally *repriceTally) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	local := newRepriceTally()
	for _, lc := range batch {
		c := lc.change
		tgt, ok := repriceTargets[c.Table]
		if !ok {
			local.skipped[string(reprice.ReasonRowGone)]++
			continue
		}
		var cur sql.NullFloat64
		var marker sql.NullInt64
		var session string
		cr := reprice.Current{Found: true}
		err := tx.QueryRowContext(ctx, tgt.current, c.ID).Scan(&cur, &marker, &session)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			cr.Found = false
		case err != nil:
			return fmt.Errorf("read %s %d: %w", c.Table, c.ID, err)
		default:
			cr.Cost = floatPtr(cur)
			if marker.Valid {
				cr.Run = marker.Int64
			}
		}
		d := reprice.EvaluateRevert(c, cr, runID)
		if d.Action != reprice.ActionUpdate {
			local.skipped[string(d.Reason)]++
			continue
		}
		restore := nullableFloat(d.Restore)
		mk := nullableRun(d.Run)
		res, err := tx.ExecContext(ctx, tgt.restore, restore, mk, mk, c.ID, nullableFloat(cr.Cost), nullableRun(cr.Run))
		if err != nil {
			return fmt.Errorf("restore %s %d: %w", c.Table, c.ID, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			local.casMissed++
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO reprice_changes (run_id, tbl, row_id, old_cost, new_cost, prev_run) VALUES (?, ?, ?, ?, ?, ?)`,
			revID, c.Table, c.ID, nullableFloat(cr.Cost), restore, nullableRun(cr.Run)); err != nil {
			return fmt.Errorf("log %s %d: %w", c.Table, c.ID, err)
		}
		// A revert changes a cost back; its "filled" count stays 0 (it never
		// prices an unpriced row), so tally with a non-nil old.
		local.changed++
		o, n := derefCost(cr.Cost), derefCost(d.Restore)
		local.oldUSD += o
		local.newUSD += n
		ts := local.tables[c.Table]
		if ts == nil {
			ts = &reprice.TableSummary{Table: c.Table}
			local.tables[c.Table] = ts
		}
		ts.Changed++
		ts.OldUSD += o
		ts.NewUSD += n
		if c.Table == arenaRollupTable && session != "" {
			local.sessions[session] = struct{}{}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	tally.merge(local)
	return nil
}

// refreshArenaCostsForSessions recomputes arena_candidates.cost_usd for every
// candidate whose session_ids include a touched session. The column is a
// derived SUM over api_turns (internal/arena rollupUsage via
// ArenaUsageBySessions), so a re-priced turn must not leave it stale. Only
// the cost column is rewritten - the token sums cannot change under a
// re-price, and updated_at is the runner's lifecycle clock, not ours.
func (s *Store) refreshArenaCostsForSessions(ctx context.Context, touched map[string]struct{}) error {
	if len(touched) == 0 {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, session_ids FROM arena_candidates WHERE session_ids <> '[]' AND session_ids <> ''`)
	if err != nil {
		return fmt.Errorf("list arena candidates: %w", err)
	}
	type cand struct {
		id       string
		sessions []string
	}
	var hit []cand
	for rows.Next() {
		var id, js string
		if err := rows.Scan(&id, &js); err != nil {
			rows.Close()
			return fmt.Errorf("scan arena candidate: %w", err)
		}
		var ids []string
		if json.Unmarshal([]byte(js), &ids) != nil {
			continue
		}
		for _, sid := range ids {
			if _, ok := touched[sid]; ok {
				hit = append(hit, cand{id: id, sessions: ids})
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("list arena candidates: %w", err)
	}
	rows.Close()
	for _, c := range hit {
		_, _, costUSD, err := s.ArenaUsageBySessions(ctx, c.sessions)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE arena_candidates SET cost_usd = ? WHERE id = ?`, costUSD, c.id); err != nil {
			return fmt.Errorf("update arena candidate %s: %w", c.id, err)
		}
	}
	return nil
}

// RepriceOrgParity is how a set of changed api_turns rows will reach the org.
type RepriceOrgParity struct {
	// Enrolled is true when this node has an org enrolment.
	Enrolled bool
	// Tracked is true when org re-send tracking is set up (the
	// org_push_floor_api_turns floor exists); without it no change re-sends.
	Tracked bool
	// Queued counts rows above the floor: the migration-142 trigger re-queues
	// each one for the org by itself when its cost changes.
	Queued int
	// BelowFloor counts rows at or below the floor (or all rows when
	// untracked): they need `observer org resync` to lower the floor first.
	BelowFloor int
	// OldestBelowFloor is the earliest timestamp among BelowFloor rows, for
	// sizing the resync window ("" when none).
	OldestBelowFloor string
}

// RepriceOrgParityFor classifies the api_turns decisions in changes against
// the org re-send floor. Read-only: it never writes org_push_changes (the
// trigger and EnqueuePushResync remain that queue's only writers).
func (s *Store) RepriceOrgParityFor(ctx context.Context, changes []reprice.Decision) (RepriceOrgParity, error) {
	var out RepriceOrgParity
	enr, err := s.LoadEnrolment(ctx)
	if err != nil {
		return out, fmt.Errorf("store.RepriceOrgParityFor: %w", err)
	}
	out.Enrolled = enr != nil
	if !out.Enrolled {
		return out, nil
	}
	v, err := s.readMeta(ctx, "org_push_floor_api_turns")
	if err != nil {
		return out, fmt.Errorf("store.RepriceOrgParityFor: %w", err)
	}
	floor := int64(-1)
	if v != "" {
		f, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return out, fmt.Errorf("store.RepriceOrgParityFor: floor %q: %w", v, err)
		}
		floor = f
		out.Tracked = true
	}
	var oldest time.Time
	for _, d := range changes {
		if d.Table != orgParityTable || d.Action != reprice.ActionUpdate {
			continue
		}
		if out.Tracked && d.ID > floor {
			out.Queued++
			continue
		}
		out.BelowFloor++
		if at, ok := reprice.ParseTimestamp(d.Timestamp); ok && (oldest.IsZero() || at.Before(oldest)) {
			oldest = at
		}
	}
	if !oldest.IsZero() {
		out.OldestBelowFloor = oldest.UTC().Format(time.RFC3339)
	}
	return out, nil
}
