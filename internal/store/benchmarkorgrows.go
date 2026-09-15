package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/benchmark"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// benchmarkorgrows.go is the W3.4 org-wire seam for the node's benchmark
// harness (docs/plans/org-parity-full-depth-plan-2026-08-24.md §4 "W3.4").
// It OWNS the benchmark_runs / benchmark_attempts / benchmark_scores read for
// the org-push path — orgpush.go deliberately never names those tables (the
// privacy sentinel forbids it); the push composes rows via a function call
// into this file, exactly like every other session-scoped W2/W3 sibling
// (verbosityorgrows.go, processorgrows.go).
//
// Unlike internal/store/benchmark.go (the node's CLI-report substrate, which
// this file calls into for cost/token derivation rather than duplicating that
// join), this file additionally recovers the RAW columns the CLI report never
// needed: repo path + task prompt (parsed out of benchmark_runs.spec_json,
// since internal/benchmark.Task.Repo/Prompt are not their own columns),
// judge rationale, final-answer excerpt, and per-attempt timing. Per §0 of
// the org-parity plan (enterprise-first), these ship RAW — not hashed — under
// ShareOptions.shipsRawContent(), exactly like SessionProcessRow (W2.2).

// benchmarkOrgRowsWindowDays bounds the recompute to runs started within the
// trailing window. Benchmark runs are a periodic/deliberate activity (a
// developer or CI job invoking `observer benchmark run`), not everyday
// session traffic, so the window is wider than the 7-day session-scoped
// siblings (verbositySummaryWindowDays / sessionProcessWindowDays) — 30 days
// comfortably covers a sprint's worth of comparison runs while still bounding
// the recompute. The server upserts by natural key (org_id, user_email,
// run_key / attempt_key), so re-pushing a window is idempotent.
const benchmarkOrgRowsWindowDays = 30

// benchmarkAttemptRunCap bounds how many of the windowed runs get their
// per-attempt rows shipped, keeping the MOST RECENT runs (by started_at).
// BenchmarkRunRow is cheap (one row per run x config, no prompt/rationale
// text) and is computed for every run in the window; BenchmarkAttemptRow
// carries raw prompts/rationales/excerpts per attempt and can be large for a
// wide matrix (tasks x configs x repeats), so it is capped at the RUN
// boundary rather than a flat per-run attempt count (unlike
// sessionProcessRunCap, which caps per-session because a single session's
// process fan-out is the pathological case here; a benchmark run's attempt
// count is bounded by its own spec's matrix size, so the risk is many runs
// accumulating in one window, not one run alone). 20 comfortably covers a
// day's worth of comparison runs; older runs in the window still get a
// BenchmarkRunRow (so the leaderboard/config identity stays complete) but no
// per-attempt drill-down until they age back into the cap on a later push.
const benchmarkAttemptRunCap = 20

// benchmarkFactKey is the (task, config, repeat) identity LoadBenchmarkFacts
// groups by — used here to merge the cost/token facts back onto the raw
// attempt rows this file reads independently.
type benchmarkFactKey struct {
	TaskID    string
	ConfigID  string
	RepeatIdx int
}

// SelectBenchmarkOrgRows recomputes the W3.4 wire rows for every benchmark
// run started within the trailing window: a BenchmarkRunRow per (run,
// config) for every windowed run, and BenchmarkAttemptRow per terminal
// attempt for the benchmarkAttemptRunCap most recent of those runs. Returning
// both from one function avoids re-querying LoadBenchmarkRun/LoadBenchmarkFacts/
// spec_json per run twice.
func (s *Store) SelectBenchmarkOrgRows(ctx context.Context) ([]orgcontract.BenchmarkRunRow, []orgcontract.BenchmarkAttemptRow, error) {
	since := time.Now().UTC().AddDate(0, 0, -benchmarkOrgRowsWindowDays)
	runIDs, err := s.listBenchmarkRunIDsSince(ctx, since)
	if err != nil {
		return nil, nil, fmt.Errorf("store.SelectBenchmarkOrgRows: %w", err)
	}

	runRows := []orgcontract.BenchmarkRunRow{}
	attemptRows := []orgcontract.BenchmarkAttemptRow{}

	for i, runID := range runIDs {
		run, ok, err := s.LoadBenchmarkRun(ctx, runID)
		if err != nil {
			return nil, nil, fmt.Errorf("store.SelectBenchmarkOrgRows: %s: %w", runID, err)
		}
		if !ok {
			continue // raced with a delete/prune between the list and the load
		}

		taskCount, repoPathsJSON, promptByTask, err := parseBenchmarkSpecJSON(run.SpecJSON)
		if err != nil {
			return nil, nil, fmt.Errorf("store.SelectBenchmarkOrgRows: %s: spec_json: %w", runID, err)
		}

		facts, err := s.LoadBenchmarkFacts(ctx, runID)
		if err != nil {
			return nil, nil, fmt.Errorf("store.SelectBenchmarkOrgRows: %s: facts: %w", runID, err)
		}

		runRows = append(runRows, buildBenchmarkRunRows(run, taskCount, repoPathsJSON, facts)...)

		// Attempt rows only for the most recent benchmarkAttemptRunCap runs
		// (runIDs is ordered most-recent-first — see listBenchmarkRunIDsSince).
		if i >= benchmarkAttemptRunCap {
			continue
		}
		raw, err := s.loadBenchmarkAttemptRawFields(ctx, runID)
		if err != nil {
			return nil, nil, fmt.Errorf("store.SelectBenchmarkOrgRows: %s: raw attempts: %w", runID, err)
		}
		scores, err := s.loadBenchmarkAttemptScores(ctx, runID)
		if err != nil {
			return nil, nil, fmt.Errorf("store.SelectBenchmarkOrgRows: %s: scores: %w", runID, err)
		}
		factByKey := make(map[benchmarkFactKey]benchmark.AttemptFact, len(facts))
		for _, f := range facts {
			factByKey[benchmarkFactKey{f.TaskID, f.ConfigID, f.RepeatIdx}] = f
		}
		for _, r := range raw {
			key := benchmarkFactKey{r.taskID, r.configID, r.repeatIdx}
			f, ok := factByKey[key]
			if !ok {
				continue // terminal-attempt selection disagreed (race with a live run); skip rather than ship a half row
			}
			sc := scores[r.attemptID]
			attemptRows = append(attemptRows, buildBenchmarkAttemptRow(runID, r, f, sc, promptByTask[r.taskID]))
		}
	}
	return runRows, attemptRows, nil
}

// listBenchmarkRunIDsSince returns run ids started at/after since, most
// recent first (so the attempt-row cap keeps the newest runs).
func (s *Store) listBenchmarkRunIDsSince(ctx context.Context, since time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT run_id FROM benchmark_runs WHERE started_at >= ? ORDER BY started_at DESC, run_id DESC`,
		timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("listBenchmarkRunIDsSince: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("listBenchmarkRunIDsSince: scan: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// parseBenchmarkSpecJSON recovers the task count, the distinct RAW repo
// paths (JSON-encoded array, sorted for a stable diff), and a task_id ->
// RAW prompt map from a run's spec_json — Task.Repo/Task.Prompt are not
// their own columns (internal/benchmark/spec.go), only reachable this way.
// An empty/unparseable spec_json degrades to zero task count + no repos/
// prompts rather than erroring the whole push (an old run predating a
// spec_json format change should not block every other row).
func parseBenchmarkSpecJSON(specJSON string) (taskCount int64, repoPathsJSON string, promptByTask map[string]string, err error) {
	promptByTask = map[string]string{}
	if specJSON == "" {
		empty, mErr := json.Marshal([]string{})
		return 0, string(empty), promptByTask, mErr
	}
	var spec benchmark.Spec
	if jsonErr := json.Unmarshal([]byte(specJSON), &spec); jsonErr != nil {
		empty, mErr := json.Marshal([]string{})
		if mErr != nil {
			return 0, "", promptByTask, mErr
		}
		return 0, string(empty), promptByTask, nil
	}
	repoSet := map[string]bool{}
	for _, t := range spec.Tasks {
		if t.Repo != "" {
			repoSet[t.Repo] = true
		}
		promptByTask[t.ID] = t.Prompt
	}
	repos := make([]string, 0, len(repoSet))
	for r := range repoSet {
		repos = append(repos, r)
	}
	sort.Strings(repos)
	b, mErr := json.Marshal(repos)
	if mErr != nil {
		return 0, "", promptByTask, mErr
	}
	return int64(len(spec.Tasks)), string(b), promptByTask, nil
}

// buildBenchmarkRunRows groups a run's facts by ConfigID into one
// BenchmarkRunRow per config, aggregating executed/scored/passed cell counts
// and cost from the SAME LoadBenchmarkFacts substrate the node's own CLI
// report uses.
func buildBenchmarkRunRows(run benchmark.RunRecord, taskCount int64, repoPathsJSON string, facts []benchmark.AttemptFact) []orgcontract.BenchmarkRunRow {
	type agg struct {
		harness, model           string
		executed, scored, passed int64
		spend                    float64
	}
	byConfig := map[string]*agg{}
	order := []string{}
	for _, f := range facts {
		a, ok := byConfig[f.ConfigID]
		if !ok {
			a = &agg{harness: f.Harness, model: f.Model}
			byConfig[f.ConfigID] = a
			order = append(order, f.ConfigID)
		}
		a.executed++
		if f.Scored {
			a.scored++
		}
		if f.Passed {
			a.passed++
		}
		a.spend += f.CostUSD
	}
	sort.Strings(order)

	out := make([]orgcontract.BenchmarkRunRow, 0, len(order))
	for _, configID := range order {
		a := byConfig[configID]
		out = append(out, orgcontract.BenchmarkRunRow{
			RunKey:         run.RunID + ":" + configID,
			RunID:          run.RunID,
			ConfigID:       configID,
			Harness:        a.harness,
			ModelRequested: a.model,
			ConfigHash:     benchmarkConfigHash(a.harness, a.model, configID),
			SpecName:       run.SpecName,
			SpecHash:       run.SpecHash,
			RepoPathsJSON:  repoPathsJSON,
			TaskCount:      taskCount,
			ExecutedCells:  a.executed,
			ScoredCells:    a.scored,
			PassedCells:    a.passed,
			SpendUSD:       a.spend,
			Status:         run.Status,
			StartedAt:      timestamp(run.StartedAt),
			FinishedAt:     nullTimeString(run.FinishedAt),
		})
	}
	return out
}

// benchmarkConfigHash derives a stable cross-run/cross-fleet identity for a
// config, mirroring rollup.ProjectID's sha256-truncation pattern
// (internal/orgserver/rollup/cost.go) — 8 bytes (16 hex chars) of
// sha256("harness|model|config_id"), a hash of real node fields, not
// invented data.
func benchmarkConfigHash(harness, model, configID string) string {
	sum := sha256.Sum256([]byte(harness + "|" + model + "|" + configID))
	return hex.EncodeToString(sum[:8])
}

// benchmarkAttemptRaw is the RAW-column subset of one terminal
// benchmark_attempts row that LoadBenchmarkFacts does not select (it only
// selects the derivation inputs), read independently by
// loadBenchmarkAttemptRawFields using the identical terminal-attempt
// selection (MAX(attempt_no) per task/config/repeat cell).
type benchmarkAttemptRaw struct {
	attemptID          int64
	taskID, configID   string
	repeatIdx          int
	attemptNo          int
	workspacePath      string
	exitCode           sql.NullInt64
	finalAnswerExcerpt string
	startedAt          string
	finishedAt         string
}

// loadBenchmarkAttemptRawFields reads the terminal attempt per
// (task_id, config_id, repeat_idx) cell for a run — same dedup subquery
// idiom as internal/store/benchmark.go::LoadBenchmarkFacts, applied to the
// raw columns that query does not select (workspace_path, exit_code,
// final_answer_excerpt, started_at, finished_at).
func (s *Store) loadBenchmarkAttemptRawFields(ctx context.Context, runID string) ([]benchmarkAttemptRaw, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.task_id, a.config_id, a.repeat_idx, a.attempt_no,
		       COALESCE(a.workspace_path, ''), a.exit_code,
		       COALESCE(a.final_answer_excerpt, ''),
		       a.started_at, COALESCE(a.finished_at, '')
		  FROM benchmark_attempts a
		  JOIN (
		         SELECT task_id, config_id, repeat_idx, MAX(attempt_no) AS mx
		           FROM benchmark_attempts
		          WHERE run_id = ?
		          GROUP BY task_id, config_id, repeat_idx
		       ) latest
		    ON latest.task_id = a.task_id AND latest.config_id = a.config_id
		   AND latest.repeat_idx = a.repeat_idx AND latest.mx = a.attempt_no
		 WHERE a.run_id = ?
		 ORDER BY a.id`, runID, runID)
	if err != nil {
		return nil, fmt.Errorf("loadBenchmarkAttemptRawFields: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []benchmarkAttemptRaw
	for rows.Next() {
		var r benchmarkAttemptRaw
		if err := rows.Scan(&r.attemptID, &r.taskID, &r.configID, &r.repeatIdx, &r.attemptNo,
			&r.workspacePath, &r.exitCode, &r.finalAnswerExcerpt, &r.startedAt, &r.finishedAt); err != nil {
			return nil, fmt.Errorf("loadBenchmarkAttemptRawFields: scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// benchmarkAttemptScore is the scorer verdict picked for one attempt: the
// row with a non-empty rationale when more than one scorer ran on it (v1
// tasks declare a single primary scorer per internal/store/benchmark.go's
// own comment, so this is the pre-registered primary outcome in practice).
type benchmarkAttemptScore struct {
	score      float64
	judgeModel string
	rationale  string
}

// loadBenchmarkAttemptScores reads benchmark_scores for a run, keyed by
// attempt_id, preferring the row with a non-empty rationale so multi-scorer
// attempts still resolve to one wire-row's worth of judge detail.
func (s *Store) loadBenchmarkAttemptScores(ctx context.Context, runID string) (map[int64]benchmarkAttemptScore, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT attempt_id, score, COALESCE(judge_model, ''), COALESCE(rationale, '')
		  FROM benchmark_scores WHERE run_id = ?`, runID)
	if err != nil {
		return nil, fmt.Errorf("loadBenchmarkAttemptScores: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[int64]benchmarkAttemptScore{}
	for rows.Next() {
		var attemptID int64
		var sc benchmarkAttemptScore
		if err := rows.Scan(&attemptID, &sc.score, &sc.judgeModel, &sc.rationale); err != nil {
			return nil, fmt.Errorf("loadBenchmarkAttemptScores: scan: %w", err)
		}
		if existing, ok := out[attemptID]; !ok || (existing.rationale == "" && sc.rationale != "") {
			out[attemptID] = sc
		}
	}
	return out, rows.Err()
}

// buildBenchmarkAttemptRow assembles one wire row from the raw attempt
// columns, its merged cost/token fact, its picked scorer verdict, and the
// task's RAW prompt recovered from spec_json.
func buildBenchmarkAttemptRow(runID string, r benchmarkAttemptRaw, f benchmark.AttemptFact, sc benchmarkAttemptScore, prompt string) orgcontract.BenchmarkAttemptRow {
	return orgcontract.BenchmarkAttemptRow{
		RunKey:     runID + ":" + r.configID,
		AttemptKey: fmt.Sprintf("%s:%s:%s:%d:%d", runID, r.taskID, r.configID, r.repeatIdx, r.attemptNo),
		RunID:      runID,
		TaskID:     r.taskID,
		ConfigID:   r.configID,
		RepeatIdx:  int64(r.repeatIdx),
		AttemptNo:  int64(r.attemptNo),

		Harness:        f.Harness,
		ModelRequested: f.Model,
		TaskPrompt:     prompt,

		Status: string(f.Status),
		Scored: f.Scored,
		Passed: f.Passed,
		Score:  sc.score,

		JudgeModel:         sc.judgeModel,
		JudgeRationale:     sc.rationale,
		FinalAnswerExcerpt: r.finalAnswerExcerpt,

		SpendUSD:        f.CostUSD,
		WallMS:          f.WallMS,
		Turns:           int64(f.Turns),
		InputTokens:     f.InputTokens,
		OutputTokens:    f.OutputTokens,
		CacheReadTokens: f.CacheReadTokens,

		StartedAt:   r.startedAt,
		FinishedAt:  r.finishedAt,
		ExitCode:    r.exitCode.Int64,
		HasExitCode: r.exitCode.Valid,
	}
}

// nullTimeString formats a possibly-zero time.Time as an RFC3339 timestamp,
// or "" when zero — the wire-row analog of nullTime (which returns a driver
// value for a SQL bind, not a string).
func nullTimeString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return timestamp(t)
}

// probeBenchmarks is the Track R2 change-detection probe for the benchmark
// wire (both BenchmarkRuns and BenchmarkAttempts, which one Select produces).
// It lives here — with the wire's own SQL — so orgsnapgate.go and orgpush.go
// stay free of the table names.
//
// PROBE: per table, (MAX(rowid|id), COUNT(*)) plus COUNT(finished_at) on the
// two tables that are MUTATED in place. Benchmark tables are the smallest
// substrate in the snapshot family — a benchmark run is an explicit, rare
// operator action, not a per-turn event — so a full count on each is
// negligible.
//
// WHY finished_at IS IN THE PROBE: benchmark_runs and benchmark_attempts are
// the clearest UPDATE-in-place families here. A run is INSERTed when it starts
// and later UPDATEd with its manifest, status, spend and finished_at; an
// attempt's status/error_class is UPDATEd on completion. An id/count-only probe
// would ship every run as perpetually "running", so the count of finished rows
// is folded in — that is the transition an admin actually watches for.
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: a status transition between two
// non-terminal states, or a spend/notes revision on an already-finished run,
// moves nothing in the probe; snapGate's maxSkipAge recomputes within the hour.
func (s *Store) probeBenchmarks(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `
		SELECT 'br' || (SELECT COALESCE(MAX(rowid), 0) || '/' || COUNT(*) || '/' || COUNT(finished_at)
		                  FROM benchmark_runs) ||
		       ':ba' || (SELECT COALESCE(MAX(id), 0) || '/' || COUNT(*) || '/' || COUNT(finished_at)
		                   FROM benchmark_attempts) ||
		       ':bs' || (SELECT COALESCE(MAX(id), 0) || '/' || COUNT(*) FROM benchmark_scores)`)
}
