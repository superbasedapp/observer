package store

import (
	"context"
	"database/sql"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/reprice"
)

// TestRepriceSourceTableCoversEverySourceConstant parses merge.go and fails
// when a new api_turns Source* constant lands without a row in
// apiTurnSourceReported: an unclassified source would silently fall to the
// "keep it" default, which is safe but must be a decision, not an accident.
func TestRepriceSourceTableCoversEverySourceConstant(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "merge.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Source") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, _ := strconv.Unquote(lit.Value)
				found++
				if _, ok := apiTurnSourceReported[v]; !ok {
					t.Errorf("api_turns source constant %s = %q has no row in apiTurnSourceReported", name.Name, v)
				}
			}
		}
	}
	if found < 6 {
		t.Fatalf("found only %d Source* constants in merge.go; the parse is broken", found)
	}
	if _, ok := apiTurnSourceReported[""]; !ok {
		t.Fatal("the legacy empty source must be classified")
	}
}

func TestRepriceSourceReportedTable(t *testing.T) {
	cases := []struct {
		source string
		want   bool
	}{
		{"", false},
		{SourceProxy, false},
		{SourceProxyTurn, false},
		{SourceCCOTel, true},
		{SourceJSONL, true},
		{SourceObsSDK, true},
		{SourceObsOTLP, true},
		{"some_future_source", true}, // unknown provenance is kept
	}
	for _, tc := range cases {
		if got := apiTurnCostIsSourceReported(tc.source); got != tc.want {
			t.Errorf("source %q: got %v want %v", tc.source, got, tc.want)
		}
	}
}

// repriceFixture is a node DB with a few spend rows.
type repriceFixture struct {
	s  *Store
	db *sql.DB
}

func newRepriceFixture(t *testing.T) repriceFixture {
	t.Helper()
	s, database := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/reprice", "")
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, database, `INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('s1', ?, 'claude-code', '2026-09-01T00:00:00Z')`, pid)
	return repriceFixture{s: s, db: database}
}

func mustExec(t *testing.T, database *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := database.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func (f repriceFixture) turn(t *testing.T, ts, model, source string, input int64, cost any) int64 {
	t.Helper()
	res, err := f.db.ExecContext(context.Background(), `
		INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd, source)
		VALUES ('s1', ?, 'anthropic', ?, ?, 0, ?, ?)`, ts, model, input, cost, source)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

type repriceRowState struct {
	cost     *float64
	captured *float64
	run      int64
}

func (f repriceFixture) state(t *testing.T, table string, id int64) repriceRowState {
	t.Helper()
	var c, cap sql.NullFloat64
	var run sql.NullInt64
	if err := f.db.QueryRowContext(context.Background(),
		`SELECT cost_usd, cost_usd_captured, cost_repriced_run FROM `+table+` WHERE id = ?`, id).Scan(&c, &cap, &run); err != nil {
		t.Fatal(err)
	}
	return repriceRowState{cost: floatPtr(c), captured: floatPtr(cap), run: run.Int64}
}

// perInput prices a known model at rate USD per input token; other models
// have no price.
func perInput(model string, rate float64) reprice.PriceFunc {
	return func(m string, _ time.Time, tk reprice.Tokens) reprice.Quote {
		if m != model {
			return reprice.Quote{}
		}
		return reprice.Quote{USD: float64(tk.Input) * rate, OK: true, Source: "seed"}
	}
}

func (f repriceFixture) plan(t *testing.T, price reprice.PriceFunc, filter RepriceFilter) (*reprice.Planner, RepriceRunMeta) {
	t.Helper()
	p := reprice.NewPlanner(price)
	if err := f.s.ScanRepriceRows(context.Background(), filter, func(r reprice.Row) error { p.Add(r); return nil }); err != nil {
		t.Fatal(err)
	}
	sum := p.Summary()
	meta := RepriceRunMeta{
		Actor: "test", RuleVersion: reprice.RuleVersion, PricingSource: "seed", Scanned: sum.Scanned,
		TableScanned: map[string]int{}, Skipped: map[string]int{},
	}
	for _, ts := range sum.Tables {
		meta.TableScanned[ts.Table] = ts.Scanned
	}
	for k, v := range sum.Skipped {
		meta.Skipped[string(k)] = v
	}
	return p, meta
}

func (f repriceFixture) apply(t *testing.T, price reprice.PriceFunc) RepriceRun {
	t.Helper()
	p, meta := f.plan(t, price, RepriceFilter{})
	run, err := f.s.ApplyReprice(context.Background(), meta, p.Updates())
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func costIs(p *float64, want float64) bool { return p != nil && math.Abs(*p-want) < 1e-12 }

func TestRepriceApplyAndRevertRoundTrip(t *testing.T) {
	f := newRepriceFixture(t)
	ctx := context.Background()
	priced := f.turn(t, "2026-09-02T10:00:00Z", "m", SourceProxy, 1000, 1.0)
	unpriced := f.turn(t, "2026-09-02T11:00:00Z", "m", "", 500, nil)
	native := f.turn(t, "2026-09-02T12:00:00Z", "m", SourceCCOTel, 1000, 5.0)
	unknown := f.turn(t, "2026-09-02T13:00:00Z", "no-such-model", SourceProxy, 1000, nil)
	mustExec(t, f.db, `INSERT INTO summary_calls (session_id, timestamp, model, input_tokens, cost_usd) VALUES ('s1', '2026-09-02T14:00:00Z', 'm', 200, 0.5)`)
	mustExec(t, f.db, `INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, estimated_cost_usd, source) VALUES ('s1', '2026-09-02T15:00:00Z', 'codex', 'm', 10, 3.0, 'jsonl')`)
	mustExec(t, f.db, `INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, estimated_cost_usd, source) VALUES ('s1', '2026-09-02T15:00:01Z', 'codex', 'm', 10, 0, 'jsonl')`)

	price := perInput("m", 0.002) // priced: 2.0, unpriced: 1.0, summary: 0.4
	p, meta := f.plan(t, price, RepriceFilter{})
	sum := p.Summary()
	if sum.Scanned != 6 { // 4 turns + 1 summary call + 1 stated token_usage (the $0 row is not scanned)
		t.Fatalf("scanned %d, want 6", sum.Scanned)
	}
	if sum.Changed != 3 || sum.Filled != 1 {
		t.Fatalf("plan changed=%d filled=%d, want 3/1", sum.Changed, sum.Filled)
	}
	if sum.Skipped[reprice.ReasonSourceReported] != 2 || sum.Skipped[reprice.ReasonNoPrice] != 1 {
		t.Fatalf("skipped %+v", sum.Skipped)
	}
	run, err := f.s.ApplyReprice(ctx, meta, p.Updates())
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != RepriceStatusApplied || run.Changed != 3 || run.Filled != 1 || run.CASMissed != 0 {
		t.Fatalf("run %+v", run)
	}
	if math.Abs(run.OldUSD-1.5) > 1e-9 || math.Abs(run.NewUSD-3.4) > 1e-9 || math.Abs(run.DeltaUSD-1.9) > 1e-9 {
		t.Fatalf("run totals old=%v new=%v delta=%v", run.OldUSD, run.NewUSD, run.DeltaUSD)
	}
	if run.Summary.Skipped["source_reported"] != 2 || len(run.Summary.Tables) != 3 {
		t.Fatalf("run summary %+v", run.Summary)
	}

	st := f.state(t, "api_turns", priced)
	if !costIs(st.cost, 2.0) || !costIs(st.captured, 1.0) || st.run != run.ID {
		t.Fatalf("priced row after apply %+v", st)
	}
	st = f.state(t, "api_turns", unpriced)
	if !costIs(st.cost, 1.0) || st.captured != nil || st.run != run.ID {
		t.Fatalf("filled row after apply: cost %v captured %v run %d", st.cost, st.captured, st.run)
	}
	if st := f.state(t, "api_turns", native); !costIs(st.cost, 5.0) || st.run != 0 {
		t.Fatalf("source-reported row was touched: %+v", st)
	}
	if st := f.state(t, "api_turns", unknown); st.cost != nil || st.run != 0 {
		t.Fatalf("unpriced-model row changed: %+v", st)
	}
	if st := f.state(t, "summary_calls", 1); !costIs(st.cost, 0.4) || !costIs(st.captured, 0.5) {
		t.Fatalf("summary call after apply %+v", st)
	}
	var tuCost float64
	if err := f.db.QueryRow(`SELECT estimated_cost_usd FROM token_usage WHERE estimated_cost_usd > 0`).Scan(&tuCost); err != nil || tuCost != 3.0 {
		t.Fatalf("tool-stated token_usage cost changed: %v %v", tuCost, err)
	}

	// Idempotent: a second apply at the same prices changes nothing.
	second := f.apply(t, price)
	if second.Changed != 0 || second.Status != RepriceStatusApplied {
		t.Fatalf("second apply %+v", second)
	}
	if st := f.state(t, "api_turns", priced); st.run != run.ID {
		t.Fatalf("an unchanged row got a new marker: %+v", st)
	}

	// Revert restores the exact captured values, NULL included.
	rev, err := f.s.RevertReprice(ctx, run.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if rev.Kind != RepriceKindRevert || rev.RevertsRun != run.ID || rev.Changed != 3 || rev.Status != RepriceStatusApplied {
		t.Fatalf("revert run %+v", rev)
	}
	st = f.state(t, "api_turns", priced)
	if !costIs(st.cost, 1.0) || st.captured != nil || st.run != 0 {
		t.Fatalf("priced row after revert %+v", st)
	}
	st = f.state(t, "api_turns", unpriced)
	if st.cost != nil || st.captured != nil || st.run != 0 {
		t.Fatalf("filled row after revert: cost %v captured %v run %d", st.cost, st.captured, st.run)
	}
	if st := f.state(t, "summary_calls", 1); !costIs(st.cost, 0.5) || st.captured != nil || st.run != 0 {
		t.Fatalf("summary call after revert %+v", st)
	}
	orig, err := f.s.RepriceRunByID(ctx, run.ID)
	if err != nil || orig.Status != RepriceStatusReverted || orig.RevertedByRun != rev.ID {
		t.Fatalf("reverted run %+v %v", orig, err)
	}

	// Refusals.
	if _, err := f.s.RevertReprice(ctx, run.ID, "test"); !errors.Is(err, ErrRepriceRunReverted) {
		t.Fatalf("second revert: %v", err)
	}
	if _, err := f.s.RevertReprice(ctx, rev.ID, "test"); !errors.Is(err, ErrRepriceRunIsRevert) {
		t.Fatalf("revert of a revert: %v", err)
	}
	if _, err := f.s.RevertReprice(ctx, 9999, "test"); !errors.Is(err, ErrRepriceRunNotFound) {
		t.Fatalf("unknown run: %v", err)
	}
	runs, err := f.s.ListRepriceRuns(ctx, 10)
	if err != nil || len(runs) != 3 || runs[0].ID != rev.ID {
		t.Fatalf("runs %+v %v", runs, err)
	}
}

// TestRepriceRevertSkipsRowSupersededByLaterRun pins the revert ORDER
// contract (PRICE-REPRICE-1 review finding 2): a run whose rows a LATER,
// non-reverted apply run holds is REFUSED with a typed error naming that run,
// so runs are undone newest first and no row is ever stranded on a reverted
// run's price. Reverting both in order restores the captured cost.
func TestRepriceRevertSkipsRowSupersededByLaterRun(t *testing.T) {
	f := newRepriceFixture(t)
	ctx := context.Background()
	id := f.turn(t, "2026-09-02T10:00:00Z", "m", SourceProxy, 1000, 1.0)
	first := f.apply(t, perInput("m", 0.002))  // 1.0 -> 2.0
	second := f.apply(t, perInput("m", 0.003)) // 2.0 -> 3.0
	if second.Changed != 1 {
		t.Fatalf("second run %+v", second)
	}
	st := f.state(t, "api_turns", id)
	if !costIs(st.cost, 3.0) || !costIs(st.captured, 1.0) || st.run != second.ID {
		t.Fatalf("after two runs %+v (the captured cost must survive a second re-price)", st)
	}
	_, err := f.s.RevertReprice(ctx, first.ID, "test")
	var sup *RepriceSupersededError
	if !errors.As(err, &sup) || !errors.Is(err, ErrRepriceRunSuperseded) || sup.LaterRunID != second.ID || sup.RunID != first.ID {
		t.Fatalf("revert of a superseded run = %v, want *RepriceSupersededError naming run %d", err, second.ID)
	}
	if st := f.state(t, "api_turns", id); !costIs(st.cost, 3.0) || st.run != second.ID {
		t.Fatalf("a refused revert changed the row: %+v", st)
	}
	if r, _ := f.s.RepriceRunByID(ctx, first.ID); r.Status != RepriceStatusApplied || r.RevertedByRun != 0 {
		t.Fatalf("a refused revert touched the run: %+v", r)
	}
	runs, _ := f.s.ListRepriceRuns(ctx, 10)
	if len(runs) != 2 {
		t.Fatalf("a refused revert recorded a run: %d runs", len(runs))
	}
	// Reverting the later run restores the first run's figure and marker, and
	// keeps the originally captured cost.
	if _, err := f.s.RevertReprice(ctx, second.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if st := f.state(t, "api_turns", id); !costIs(st.cost, 2.0) || !costIs(st.captured, 1.0) || st.run != first.ID {
		t.Fatalf("after reverting the later run %+v", st)
	}
	// Now the first run reverts, and the row is back at its captured cost.
	if _, err := f.s.RevertReprice(ctx, first.ID, "test"); err != nil {
		t.Fatalf("revert of the first run once the later one is reverted: %v", err)
	}
	if st := f.state(t, "api_turns", id); !costIs(st.cost, 1.0) || st.captured != nil || st.run != 0 {
		t.Fatalf("after reverting both runs in order %+v, want the captured 1.0 with no marker", st)
	}
}

// A row a CAPTURE path rewrote after a run (not a later run) keeps today's
// changed_since skip: the revert proceeds and leaves the newer figure.
func TestRepriceRevertSkipsRowChangedByCapture(t *testing.T) {
	f := newRepriceFixture(t)
	ctx := context.Background()
	id := f.turn(t, "2026-09-02T10:00:00Z", "m", SourceProxy, 1000, 1.0)
	kept := f.turn(t, "2026-09-02T10:01:00Z", "m", SourceProxy, 1000, 1.0)
	run := f.apply(t, perInput("m", 0.002))
	mustExec(t, f.db, `UPDATE api_turns SET cost_usd = 9.0 WHERE id = ?`, id)
	rev, err := f.s.RevertReprice(ctx, run.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if rev.Changed != 1 || rev.Summary.Skipped[string(reprice.ReasonChangedSince)] != 1 {
		t.Fatalf("revert %+v", rev)
	}
	if st := f.state(t, "api_turns", id); !costIs(st.cost, 9.0) {
		t.Fatalf("a capture-rewritten row was reverted: %+v", st)
	}
	if st := f.state(t, "api_turns", kept); !costIs(st.cost, 1.0) || st.run != 0 {
		t.Fatalf("the untouched row was not restored: %+v", st)
	}
}

// TestRepriceRunClaim pins review finding 4: one run at a time per database.
// A run still running is not revertable, a second apply or revert is refused
// while one is running, and a run left running past the lease (a crashed
// process) is marked partial by the next claim instead of blocking forever.
func TestRepriceRunClaim(t *testing.T) {
	f := newRepriceFixture(t)
	ctx := context.Background()
	f.turn(t, "2026-09-02T10:00:00Z", "m", SourceProxy, 1000, 1.0)
	done := f.apply(t, perInput("m", 0.002))

	// A live run in progress (another process): created now, status running.
	mustExec(t, f.db, `INSERT INTO reprice_runs (kind, created_at, actor, status) VALUES ('apply', ?, 'other', 'running')`,
		time.Now().UTC().Format(time.RFC3339Nano))
	var live int64
	if err := f.db.QueryRow(`SELECT MAX(id) FROM reprice_runs`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RevertReprice(ctx, live, "test"); !errors.Is(err, ErrRepriceRunRunning) {
		t.Fatalf("revert of a running run = %v, want ErrRepriceRunRunning", err)
	}
	p, meta := f.plan(t, perInput("m", 0.003), RepriceFilter{})
	_, err := f.s.ApplyReprice(ctx, meta, p.Updates())
	var busy *RepriceBusyError
	if !errors.As(err, &busy) || busy.RunningRunID != live || !errors.Is(err, ErrRepriceBusy) {
		t.Fatalf("apply while a run is running = %v, want *RepriceBusyError naming %d", err, live)
	}
	if _, err := f.s.RevertReprice(ctx, done.ID, "test"); !errors.Is(err, ErrRepriceBusy) {
		t.Fatalf("revert while a run is running = %v, want ErrRepriceBusy", err)
	}

	// The same run, but started longer ago than the lease: a crashed process.
	mustExec(t, f.db, `UPDATE reprice_runs SET created_at = ? WHERE id = ?`,
		time.Now().UTC().Add(-RepriceClaimLease-time.Minute).Format(time.RFC3339Nano), live)
	run, err := f.s.ApplyReprice(ctx, meta, p.Updates())
	if err != nil || run.Changed != 1 {
		t.Fatalf("apply after the stale run's lease = %+v, %v", run, err)
	}
	if r, _ := f.s.RepriceRunByID(ctx, live); r.Status != RepriceStatusPartial {
		t.Fatalf("stale running run status %q, want partial", r.Status)
	}
}

func TestRepriceApplyCASMissWhenRowChangedSincePlan(t *testing.T) {
	f := newRepriceFixture(t)
	id := f.turn(t, "2026-09-02T10:00:00Z", "m", SourceProxy, 1000, 1.0)
	other := f.turn(t, "2026-09-02T10:01:00Z", "m", SourceProxy, 1000, 1.0)
	p, meta := f.plan(t, perInput("m", 0.002), RepriceFilter{})
	// A capture path rewrites one row between the dry run and the apply.
	mustExec(t, f.db, `UPDATE api_turns SET cost_usd = 7.0 WHERE id = ?`, id)
	run, err := f.s.ApplyReprice(context.Background(), meta, p.Updates())
	if err != nil {
		t.Fatal(err)
	}
	if run.Changed != 1 || run.CASMissed != 1 {
		t.Fatalf("run %+v", run)
	}
	if st := f.state(t, "api_turns", id); !costIs(st.cost, 7.0) || st.run != 0 || st.captured != nil {
		t.Fatalf("the newer capture was overwritten: %+v", st)
	}
	if st := f.state(t, "api_turns", other); !costIs(st.cost, 2.0) {
		t.Fatalf("the untouched row was not re-priced: %+v", st)
	}
	var logged int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM reprice_changes WHERE run_id = ?`, run.ID).Scan(&logged)
	if logged != 1 {
		t.Fatalf("change log rows %d, want 1", logged)
	}
}

func TestRepriceRevertSkipsRowChangedSince(t *testing.T) {
	f := newRepriceFixture(t)
	id := f.turn(t, "2026-09-02T10:00:00Z", "m", SourceProxy, 1000, 1.0)
	run := f.apply(t, perInput("m", 0.002))
	mustExec(t, f.db, `UPDATE api_turns SET cost_usd = 9.0 WHERE id = ?`, id)
	rev, err := f.s.RevertReprice(context.Background(), run.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if rev.Changed != 0 || rev.Summary.Skipped[string(reprice.ReasonChangedSince)] != 1 {
		t.Fatalf("revert %+v", rev)
	}
	if st := f.state(t, "api_turns", id); !costIs(st.cost, 9.0) {
		t.Fatalf("a newer figure was destroyed by the revert: %+v", st)
	}
}

func TestRepriceFilterWindowAndModel(t *testing.T) {
	f := newRepriceFixture(t)
	f.turn(t, "2026-08-31T23:59:59Z", "m", SourceProxy, 1000, 1.0)
	in := f.turn(t, "2026-09-01T00:00:00Z", "m", SourceProxy, 1000, 1.0)
	f.turn(t, "2026-09-02T00:00:00Z", "m", SourceProxy, 1000, 1.0) // until is exclusive
	f.turn(t, "2026-09-01T12:00:00Z", "other", SourceProxy, 1000, 1.0)
	filter := RepriceFilter{
		Since: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Until: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC),
		Model: "m",
	}
	var ids []int64
	if err := f.s.ScanRepriceRows(context.Background(), filter, func(r reprice.Row) error {
		ids = append(ids, r.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != in {
		t.Fatalf("scanned %v, want [%d]", ids, in)
	}
}

func TestRepriceRefreshesArenaRollup(t *testing.T) {
	f := newRepriceFixture(t)
	ctx := context.Background()
	f.turn(t, "2026-09-02T10:00:00Z", "m", SourceProxy, 1000, 1.0)
	mustExec(t, f.db, `INSERT INTO arena_runs (id, project_root, base_branch, base_sha, prompt, created_at, updated_at)
		VALUES ('r1', '/tmp/reprice', 'main', 'abc', 'p', '2026-09-02T00:00:00Z', '2026-09-02T00:00:00Z')`)
	mustExec(t, f.db, `INSERT INTO arena_candidates (id, run_id, tool, seq, cost_usd, session_ids, updated_at)
		VALUES ('c1', 'r1', 'claude-code', 1, 1.0, '["s1"]', '2026-09-02T00:00:00Z')`)
	mustExec(t, f.db, `INSERT INTO arena_candidates (id, run_id, tool, seq, cost_usd, session_ids, updated_at)
		VALUES ('c2', 'r1', 'codex', 2, 0.25, '["s-other"]', '2026-09-02T00:00:00Z')`)
	run := f.apply(t, perInput("m", 0.002))
	if len(run.Warnings) != 0 {
		t.Fatalf("warnings %v", run.Warnings)
	}
	var c1, c2 float64
	_ = f.db.QueryRowContext(ctx, `SELECT cost_usd FROM arena_candidates WHERE id = 'c1'`).Scan(&c1)
	_ = f.db.QueryRowContext(ctx, `SELECT cost_usd FROM arena_candidates WHERE id = 'c2'`).Scan(&c2)
	if math.Abs(c1-2.0) > 1e-9 || c2 != 0.25 {
		t.Fatalf("arena rollups c1=%v (want 2.0) c2=%v (want untouched 0.25)", c1, c2)
	}
	if _, err := f.s.RevertReprice(ctx, run.ID, "test"); err != nil {
		t.Fatal(err)
	}
	_ = f.db.QueryRowContext(ctx, `SELECT cost_usd FROM arena_candidates WHERE id = 'c1'`).Scan(&c1)
	if math.Abs(c1-1.0) > 1e-9 {
		t.Fatalf("arena rollup after revert %v, want 1.0", c1)
	}
}

func TestRepriceOrgParity(t *testing.T) {
	f := newRepriceFixture(t)
	ctx := context.Background()
	old := f.turn(t, "2026-08-01T10:00:00Z", "m", SourceProxy, 1000, 1.0)
	newer := f.turn(t, "2026-09-02T10:00:00Z", "m", SourceProxy, 1000, 1.0)
	p, _ := f.plan(t, perInput("m", 0.002), RepriceFilter{})

	par, err := f.s.RepriceOrgParityFor(ctx, p.Updates())
	if err != nil || par.Enrolled {
		t.Fatalf("unenrolled parity %+v %v", par, err)
	}
	mustExec(t, f.db, `INSERT INTO org_enrolment (id, org_id, org_name, org_server_url, user_id, user_email, enrolled_at, bearer_key_id)
		VALUES (1, 'o', 'Org', 'https://org.example', 'u', 'u@example.com', '2026-08-15T00:00:00Z', 'k')`)
	par, err = f.s.RepriceOrgParityFor(ctx, p.Updates())
	if err != nil || !par.Enrolled || par.Tracked || par.BelowFloor != 2 {
		t.Fatalf("untracked parity %+v %v", par, err)
	}
	mustExec(t, f.db, `INSERT INTO schema_meta (key, value) VALUES ('org_push_floor_api_turns', ?)`, strconv.FormatInt(old, 10))
	par, err = f.s.RepriceOrgParityFor(ctx, p.Updates())
	if err != nil || !par.Tracked || par.Queued != 1 || par.BelowFloor != 1 || par.OldestBelowFloor != "2026-08-01T10:00:00Z" {
		t.Fatalf("tracked parity %+v %v", par, err)
	}
	// The migration-142 trigger really does re-queue the row above the floor.
	if _, err := f.s.ApplyReprice(ctx, RepriceRunMeta{Actor: "t"}, p.Updates()); err != nil {
		t.Fatal(err)
	}
	var queued int
	_ = f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_push_changes WHERE tbl = 'api_turns' AND row_id = ?`, newer).Scan(&queued)
	if queued != 1 {
		t.Fatalf("the re-priced row above the floor was not re-queued (%d)", queued)
	}
	_ = f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM org_push_changes WHERE tbl = 'api_turns' AND row_id = ?`, old).Scan(&queued)
	if queued != 0 {
		t.Fatalf("a row at the floor was queued (%d)", queued)
	}
}
