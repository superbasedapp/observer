package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/benchmark"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// --- fakes (no real sessions, no spend) ---

type fakeProvisioner struct{}

func (fakeProvisioner) Provision(_ context.Context, _ benchmark.Task, attemptDir string) (string, error) {
	ws := filepath.Join(attemptDir, "repo")
	return ws, nil // the runner made attemptDir; a real clone would land here
}

type fakeScorer struct{ pass bool }

func (f fakeScorer) Score(_ context.Context, in scoreInput) ([]benchmark.ScoreRecord, error) {
	score := 0.0
	if f.pass {
		score = 1
	}
	return []benchmark.ScoreRecord{{
		AttemptID: in.AttemptID, RunID: in.RunID, Scorer: "tests_pass",
		Passed: f.pass, Score: score,
	}}, nil
}

// simDriver simulates the proxy+watcher ingestion: on Drive it seeds a session
// rooted at the workspace + one billed api_turn, then returns the minted id.
type simDriver struct {
	name    string
	db      *sql.DB
	exit    int
	timeout bool
	orphan  bool // return an id that will never resolve
	cost    float64
}

func (d simDriver) Name() string { return d.name }

func (d simDriver) Drive(_ context.Context, req DriveRequest) (DriveResult, error) {
	id := "sess-" + filepath.Base(filepath.Dir(req.WorkspaceDir)) // attemptDir basename, unique per cell
	if d.orphan {
		return DriveResult{ExitCode: d.exit, WallMS: 1200, SessionIDs: []string{id + "-ghost"}, FinalAnswer: "x"}, nil
	}
	ctx := context.Background()
	_, _ = d.db.ExecContext(ctx, `INSERT INTO projects (id, root_path, created_at) VALUES (NULL, ?, ?)`,
		req.WorkspaceDir, time.Now().UTC().Format(time.RFC3339))
	var pid int64
	_ = d.db.QueryRowContext(ctx, `SELECT id FROM projects WHERE root_path = ?`, req.WorkspaceDir).Scan(&pid)
	_, _ = d.db.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, model, started_at) VALUES (?, ?, ?, ?, ?)`,
		id, pid, d.name, req.Model, time.Now().UTC().Format(time.RFC3339))
	_, _ = d.db.ExecContext(ctx, `INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cache_read_tokens, cost_usd, http_status)
	          VALUES (?, ?, 'openai', ?, 1000, 100, 500, ?, NULL)`,
		id, time.Now().UTC().Format(time.RFC3339), req.Model, d.cost)
	return DriveResult{ExitCode: d.exit, TimedOut: d.timeout, WallMS: 1500, SessionIDs: []string{id}, FinalAnswer: "final answer text"}, nil
}

func newRunnerStore(t *testing.T) (*store.Store, *sql.DB) {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "runner.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database), database
}

func mkRunner(st *store.Store, database *sql.DB, driver HarnessDriver, scorer attemptScorer) *benchmarkRunner {
	drivers := map[string]HarnessDriver{driver.Name(): driver}
	return &benchmarkRunner{
		store:           st,
		drivers:         drivers,
		provisioner:     fakeProvisioner{},
		scorer:          scorer,
		estimateTurnUSD: func(context.Context, string) (float64, bool) { return 0.01, true },
		pricingSnapshot: func([]string) (string, error) { return `{"table_hash":"test"}`, nil },
		now:             func() time.Time { return time.Now().UTC() },
		out:             testWriter{t: nil},
	}
}

type testWriter struct{ t *testing.T }

func (testWriter) Write(p []byte) (int, error) { return len(p), nil }

func specTOML(t *testing.T, body string) benchmark.Spec {
	t.Helper()
	s, err := benchmark.ParseSpec(body)
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	return s
}

const runnerSpec = `
name = "e2e"
repeats = 2
[budget]
  max_total_usd = 100.0
  max_cell_usd = 10.0
[analysis]
  baseline_config = "codex"
  noninferiority_margin = 0.1
  min_sample = 1
[[tasks]]
  id = "t1"
  repo = "https://x/y.git"
  ref = "abc123"
  prompt = "do the thing"
  [tasks.success]
    scorer = "tests_pass"
    cmd = "true"
[[configs]]
  id = "codex"
  harness = "codex"
  model = "gpt-5.6-sol"
`

func TestRunnerHappyPath(t *testing.T) {
	t.Parallel()
	st, database := newRunnerStore(t)
	runner := mkRunner(st, database, simDriver{name: "codex", db: database, cost: 0.03}, fakeScorer{pass: true})
	spec := specTOML(t, runnerSpec)

	runID, err := runner.Run(context.Background(), spec, RunOptions{
		Confirmed: true, RootDir: t.TempDir(), ObserverVersion: "test",
		ResolveAttempts: 3, ResolveDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if runID == "" {
		t.Fatal("expected a run id")
	}

	facts, err := st.LoadBenchmarkFacts(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadBenchmarkFacts: %v", err)
	}
	if len(facts) != 2 {
		t.Fatalf("want 2 attempts, got %d", len(facts))
	}
	for _, f := range facts {
		if f.Status != benchmark.StatusOK {
			t.Errorf("status = %q, want ok", f.Status)
		}
		if !f.Scored || !f.Passed {
			t.Errorf("attempt not scored/passed: %+v", f)
		}
		if f.Sessions != 1 {
			t.Errorf("sessions = %d, want 1", f.Sessions)
		}
		if f.CostUSD < 0.029 || f.CostUSD > 0.031 {
			t.Errorf("cost = %v, want ~0.03", f.CostUSD)
		}
	}

	run, ok, _ := st.LoadBenchmarkRun(context.Background(), runID)
	if !ok || run.Status != "completed" {
		t.Errorf("run status = %q ok=%v", run.Status, ok)
	}
	if run.ManifestJSON == "" || run.PricingSnapshotJSON == "" {
		t.Error("manifest/pricing snapshot not persisted at finalization")
	}
	if run.CompletedCells != 2 {
		t.Errorf("completed cells = %d", run.CompletedCells)
	}
}

func TestRunnerDryRunPersistsNothing(t *testing.T) {
	t.Parallel()
	st, database := newRunnerStore(t)
	runner := mkRunner(st, database, simDriver{name: "codex", db: database, cost: 0.03}, fakeScorer{pass: true})
	spec := specTOML(t, runnerSpec)

	runID, err := runner.Run(context.Background(), spec, RunOptions{DryRun: true, RootDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Run(dry): %v", err)
	}
	if runID != "" {
		t.Errorf("dry run should not create a run, got %q", runID)
	}
	runs, _ := st.ListBenchmarkRuns(context.Background(), 10)
	if len(runs) != 0 {
		t.Errorf("dry run persisted %d runs", len(runs))
	}
}

func TestRunnerOrphanedOnUnresolvableSession(t *testing.T) {
	t.Parallel()
	st, database := newRunnerStore(t)
	runner := mkRunner(st, database, simDriver{name: "codex", db: database, orphan: true, cost: 0.03}, fakeScorer{pass: true})
	spec := specTOML(t, runnerSpec)

	runID, err := runner.Run(context.Background(), spec, RunOptions{
		Confirmed: true, RootDir: t.TempDir(), ResolveAttempts: 2, ResolveDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	facts, _ := st.LoadBenchmarkFacts(context.Background(), runID)
	for _, f := range facts {
		if f.Status != benchmark.StatusOrphaned {
			t.Errorf("status = %q, want orphaned", f.Status)
		}
	}
}

func TestRunnerModelFailOnNonZeroExit(t *testing.T) {
	t.Parallel()
	st, database := newRunnerStore(t)
	runner := mkRunner(st, database, simDriver{name: "codex", db: database, exit: 1, cost: 0}, fakeScorer{pass: true})
	spec := specTOML(t, runnerSpec)
	runID, err := runner.Run(context.Background(), spec, RunOptions{
		Confirmed: true, RootDir: t.TempDir(), ResolveAttempts: 2, ResolveDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	facts, _ := st.LoadBenchmarkFacts(context.Background(), runID)
	for _, f := range facts {
		if f.Status != benchmark.StatusModelFail {
			t.Errorf("status = %q, want model_fail", f.Status)
		}
		if f.Scored { // model_fail is never scored
			t.Errorf("model_fail should not be scored")
		}
	}
}

func TestRunnerBudgetStop(t *testing.T) {
	t.Parallel()
	st, database := newRunnerStore(t)
	// Each attempt costs $0.60; max_total_usd $1.0 → the 2nd cell trips the cap.
	spec := specTOML(t, `
name = "bud"
repeats = 3
[budget]
  max_total_usd = 1.0
  max_cell_usd = 10.0
[analysis]
  baseline_config = "codex"
  min_sample = 1
[[tasks]]
  id = "t1"
  repo = "r"
  prompt = "p"
  [tasks.success]
    scorer = "tests_pass"
    cmd = "true"
[[configs]]
  id = "codex"
  harness = "codex"
  model = "m"
`)
	runner := mkRunner(st, database, simDriver{name: "codex", db: database, cost: 0.60}, fakeScorer{pass: true})
	runID, err := runner.Run(context.Background(), spec, RunOptions{
		Confirmed: true, RootDir: t.TempDir(), ResolveAttempts: 2, ResolveDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	facts, _ := st.LoadBenchmarkFacts(context.Background(), runID)
	var stops, oks int
	for _, f := range facts {
		switch f.Status {
		case benchmark.StatusBudgetStop:
			stops++
		case benchmark.StatusOK:
			oks++
		}
	}
	if stops == 0 {
		t.Errorf("expected at least one budget_stop, got facts %+v", facts)
	}
	run, _, _ := st.LoadBenchmarkRun(context.Background(), runID)
	if run.Status != "budget_stop" {
		t.Errorf("run status = %q, want budget_stop", run.Status)
	}
}

// TestRunnerClaudeCodeNotIsolatedFailsPreflight pins the isolated-daemon gate
// at the RUNNER level: a spec asking for claude-code against the operator's
// default DB path fails the whole run in preflight — before any provisioning,
// launch, or spend (re-spike §6.3).
func TestRunnerClaudeCodeNotIsolatedFailsPreflight(t *testing.T) {
	t.Parallel()
	st, _ := newRunnerStore(t)
	def, err := defaultObserverDBPath()
	if err != nil {
		t.Fatalf("defaultObserverDBPath: %v", err)
	}
	drivers := map[string]HarnessDriver{"claude-code": newClaudeCodeDriver("", def)}
	runner := &benchmarkRunner{
		store: st, drivers: drivers, provisioner: fakeProvisioner{},
		now: func() time.Time { return time.Now().UTC() }, out: testWriter{},
	}
	spec := specTOML(t, `
name = "cc"
[budget]
  unlimited = true
[analysis]
  baseline_config = "cc"
  min_sample = 1
[[tasks]]
  id = "t1"
  repo = "r"
  prompt = "p"
  [tasks.success]
    scorer = "tests_pass"
    cmd = "true"
[[configs]]
  id = "cc"
  harness = "claude-code"
  model = "sonnet"
`)
	_, err = runner.Run(context.Background(), spec, RunOptions{Confirmed: true, RootDir: t.TempDir()})
	if err == nil || !errors.Is(err, ErrClaudeCodeNotIsolated) {
		t.Fatalf("expected ErrClaudeCodeNotIsolated, got %v", err)
	}
}

// flakyProvisioner fails its first `failFirst` calls (setup_error → infra
// retry) then succeeds, to exercise the retry→attempt_no path (#3).
type flakyProvisioner struct{ failFirst *int }

func (f flakyProvisioner) Provision(_ context.Context, _ benchmark.Task, attemptDir string) (string, error) {
	if *f.failFirst > 0 {
		*f.failFirst--
		return "", fmt.Errorf("simulated clone failure")
	}
	return filepath.Join(attemptDir, "repo"), nil
}

// alwaysFailProvisioner always setup_errors — for the workspace-retention test.
type alwaysFailProvisioner struct{}

func (alwaysFailProvisioner) Provision(_ context.Context, _ benchmark.Task, _ string) (string, error) {
	return "", fmt.Errorf("simulated clone failure")
}

const retrySpec = `
name = "retry"
repeats = 1
[budget]
  max_total_usd = 100.0
  max_cell_usd = 10.0
[retry]
  infra_retries = 2
[analysis]
  baseline_config = "codex"
  min_sample = 1
[[tasks]]
  id = "t1"
  repo = "https://x/y.git"
  ref = "abc123"
  prompt = "do the thing"
  [tasks.success]
    scorer = "tests_pass"
    cmd = "true"
[[configs]]
  id = "codex"
  harness = "codex"
  model = "gpt-5.6-sol"
`

// TestRunnerRetryPersistsDistinctAttempts pins #3: a cell whose first
// provisioning fails (infra) and second succeeds persists TWO physical rows
// (attempt_no 0 + 1) instead of colliding on the old uniqueness key, and
// LoadBenchmarkFacts collapses to the ONE terminal (successful) attempt.
func TestRunnerRetryPersistsDistinctAttempts(t *testing.T) {
	t.Parallel()
	st, database := newRunnerStore(t)
	failFirst := 1
	runner := &benchmarkRunner{
		store:           st,
		drivers:         map[string]HarnessDriver{"codex": simDriver{name: "codex", db: database, cost: 0.03}},
		provisioner:     flakyProvisioner{failFirst: &failFirst},
		scorer:          fakeScorer{pass: true},
		estimateTurnUSD: func(context.Context, string) (float64, bool) { return 0.01, true },
		pricingSnapshot: func([]string) (string, error) { return `{}`, nil },
		now:             func() time.Time { return time.Now().UTC() },
		out:             testWriter{},
	}
	runID, err := runner.Run(context.Background(), specTOML(t, retrySpec), RunOptions{
		Confirmed: true, RootDir: t.TempDir(), ResolveAttempts: 3, ResolveDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Two physical rows persisted for the one logical cell: attempt_no 0 + 1.
	rows, err := database.QueryContext(context.Background(),
		`SELECT attempt_no, status FROM benchmark_attempts WHERE run_id = ? ORDER BY attempt_no`, runID)
	if err != nil {
		t.Fatalf("query attempts: %v", err)
	}
	defer rows.Close()
	var got []struct {
		no     int
		status string
	}
	for rows.Next() {
		var r struct {
			no     int
			status string
		}
		if err := rows.Scan(&r.no, &r.status); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, r)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 physical attempts (retry retained), got %d: %+v", len(got), got)
	}
	if got[0].no != 0 || got[0].status != string(benchmark.StatusSetupError) {
		t.Errorf("attempt 0 = %+v, want no=0 setup_error", got[0])
	}
	if got[1].no != 1 || got[1].status != string(benchmark.StatusOK) {
		t.Errorf("attempt 1 = %+v, want no=1 ok", got[1])
	}

	// Downstream: LoadBenchmarkFacts collapses to the ONE terminal attempt.
	facts, err := st.LoadBenchmarkFacts(context.Background(), runID)
	if err != nil {
		t.Fatalf("LoadBenchmarkFacts: %v", err)
	}
	if len(facts) != 1 {
		t.Fatalf("want 1 fact (terminal attempt per cell), got %d", len(facts))
	}
	if facts[0].Status != benchmark.StatusOK || !facts[0].Passed {
		t.Errorf("terminal fact = %+v, want ok+passed", facts[0])
	}
}

// TestRunnerRefusesUnknownPrice pins #5: a config whose model has no billed
// history (estimateTurnUSD ok=false) must not be estimated as $0 — the run
// REFUSES to spend without --allow-unpriced, and the dry run surfaces
// "unknown — cannot estimate".
func TestRunnerRefusesUnknownPrice(t *testing.T) {
	t.Parallel()
	st, database := newRunnerStore(t)
	var buf bytes.Buffer
	mk := func() *benchmarkRunner {
		return &benchmarkRunner{
			store:           st,
			drivers:         map[string]HarnessDriver{"codex": simDriver{name: "codex", db: database, cost: 0.03}},
			provisioner:     fakeProvisioner{},
			scorer:          fakeScorer{pass: true},
			estimateTurnUSD: func(context.Context, string) (float64, bool) { return 0, false }, // price unknown
			pricingSnapshot: func([]string) (string, error) { return `{}`, nil },
			now:             func() time.Time { return time.Now().UTC() },
			out:             &buf,
		}
	}
	spec := specTOML(t, runnerSpec)

	// Dry run surfaces "unknown", never $0.00 for the cell.
	buf.Reset()
	if _, err := mk().Run(context.Background(), spec, RunOptions{DryRun: true, RootDir: t.TempDir()}); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !strings.Contains(buf.String(), "unknown") {
		t.Errorf("dry-run output should flag unknown price, got:\n%s", buf.String())
	}

	// Spend without override → refused.
	buf.Reset()
	if _, err := mk().Run(context.Background(), spec, RunOptions{
		Confirmed: true, RootDir: t.TempDir(), ResolveAttempts: 2, ResolveDelay: time.Millisecond,
	}); err == nil || !strings.Contains(err.Error(), "refusing to spend") {
		t.Fatalf("want refusal on unknown price, got %v", err)
	}

	// Spend WITH override → proceeds.
	buf.Reset()
	runID, err := mk().Run(context.Background(), spec, RunOptions{
		Confirmed: true, AllowUnpriced: true, RootDir: t.TempDir(), ResolveAttempts: 3, ResolveDelay: time.Millisecond,
	})
	if err != nil || runID == "" {
		t.Fatalf("with --allow-unpriced the run should proceed, got runID=%q err=%v", runID, err)
	}
}

// TestRunnerRetainsFailedWorkspace pins #11: a failed attempt's workspace is
// kept (not RemoveAll'd) and its path is printed so the failure is inspectable.
func TestRunnerRetainsFailedWorkspace(t *testing.T) {
	t.Parallel()
	st, database := newRunnerStore(t)
	var buf bytes.Buffer
	root := t.TempDir()
	runner := &benchmarkRunner{
		store:           st,
		drivers:         map[string]HarnessDriver{"codex": simDriver{name: "codex", db: database, cost: 0.03}},
		provisioner:     alwaysFailProvisioner{},
		scorer:          fakeScorer{pass: true},
		estimateTurnUSD: func(context.Context, string) (float64, bool) { return 0.01, true },
		pricingSnapshot: func([]string) (string, error) { return `{}`, nil },
		now:             func() time.Time { return time.Now().UTC() },
		out:             &buf,
	}
	// repeats=1, no [retry] → a single setup_error attempt (a0).
	spec := specTOML(t, `
name = "keepws"
repeats = 1
[budget]
  max_total_usd = 100.0
  max_cell_usd = 10.0
[analysis]
  baseline_config = "codex"
  min_sample = 1
[[tasks]]
  id = "t1"
  repo = "r"
  prompt = "p"
  [tasks.success]
    scorer = "tests_pass"
    cmd = "true"
[[configs]]
  id = "codex"
  harness = "codex"
  model = "m"
`)
	runID, err := runner.Run(context.Background(), spec, RunOptions{
		Confirmed: true, RootDir: root, ResolveAttempts: 1, ResolveDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	wsDir := filepath.Join(root, runID, "t1__codex__0__a0")
	if _, statErr := os.Stat(wsDir); statErr != nil {
		t.Errorf("failed attempt workspace should be retained at %s, stat err: %v", wsDir, statErr)
	}
	if !strings.Contains(buf.String(), "workspace retained") || !strings.Contains(buf.String(), wsDir) {
		t.Errorf("expected retained-workspace path printed, got:\n%s", buf.String())
	}
}
