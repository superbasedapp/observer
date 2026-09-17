package main

import (
	"bytes"
	"context"
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

func benchTempConfig(t *testing.T) (cfgPath, dbPath string) {
	t.Helper()
	dir := t.TempDir()
	dbPath = filepath.Join(dir, "o.db")
	cfgPath = filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = " + fmt.Sprintf("%q", filepath.ToSlash(dbPath)) + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath, dbPath
}

func seedCLIRun(t *testing.T, dbPath string) string {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)

	spec, err := benchmark.ParseSpec(runnerSpec)
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	specJSON, _ := spec.CanonicalJSON()
	runID := "bench-cli-1"
	if err := st.InsertBenchmarkRun(ctx, benchmark.RunRecord{
		RunID: runID, SpecName: spec.Name, SpecHash: spec.SpecHash(), SpecJSON: specJSON,
		StartedAt: time.Now().UTC(), Status: "completed", PlannedCells: 2, CompletedCells: 2,
		SpendUSD: 0.06,
	}); err != nil {
		t.Fatalf("InsertBenchmarkRun: %v", err)
	}
	// One attempt with a session + billed turn + a pass.
	if _, err := database.ExecContext(ctx, `INSERT INTO projects (id, root_path, created_at) VALUES (5, '/tmp/ws', ?)`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, model, started_at) VALUES ('s-cli', 5, 'codex', 'gpt-5.6-sol', ?)`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cache_read_tokens, cost_usd) VALUES ('s-cli', ?, 'openai', 'gpt-5.6-sol', 1000, 100, 500, 0.06)`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	aid, err := st.InsertBenchmarkAttempt(ctx, benchmark.AttemptRecord{
		RunID: runID, TaskID: "t1", ConfigID: "codex", Harness: "codex",
		ModelRequested: "gpt-5.6-sol", RepeatIdx: 0, Status: benchmark.StatusOK,
		StartedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = st.InsertBenchmarkSessionMembers(ctx, []benchmark.SessionMember{{AttemptID: aid, RunID: runID, SessionID: "s-cli", Role: benchmark.RolePrimary}})
	_ = st.InsertBenchmarkScores(ctx, []benchmark.ScoreRecord{{AttemptID: aid, RunID: runID, Scorer: "tests_pass", Passed: true, Score: 1}})
	return runID
}

func runBenchCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newBenchmarkCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func TestBenchmarkCLIListReportExportDelete(t *testing.T) {
	cfg, dbPath := benchTempConfig(t)
	runID := seedCLIRun(t, dbPath)

	// list
	out, err := runBenchCmd(t, "list", "--config", cfg)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, runID) {
		t.Errorf("list missing run id: %s", out)
	}

	// report
	out, err = runBenchCmd(t, "report", runID, "--config", cfg)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if !strings.Contains(out, "SUCCESS") || !strings.Contains(out, "codex") {
		t.Errorf("report missing matrix: %s", out)
	}
	if !strings.Contains(out, priceDisclaimer) {
		t.Errorf("report missing price disclaimer: %s", out)
	}

	// export (canonical JSON, allowlisted)
	out, err = runBenchCmd(t, "export", runID, "--config", cfg)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.Contains(out, benchmarkExportSchema) || !strings.Contains(out, priceDisclaimer) {
		t.Errorf("export missing schema/disclaimer: %s", out)
	}
	// The prompt text must NOT appear in the export (redaction allowlist).
	if strings.Contains(out, "do the thing") {
		t.Errorf("export leaked the task prompt: %s", out)
	}

	// delete
	if _, err := runBenchCmd(t, "delete", runID, "--config", cfg); err != nil {
		t.Fatalf("delete: %v", err)
	}
	out, _ = runBenchCmd(t, "list", "--config", cfg)
	if strings.Contains(out, runID) {
		t.Errorf("run not deleted: %s", out)
	}
}

func TestBenchmarkCLIDryRun(t *testing.T) {
	cfg, dbPath := benchTempConfig(t)
	// migrate the DB so loadConfigAndDB opens a real schema.
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	_ = database.Close()

	specPath := filepath.Join(t.TempDir(), "spec.toml")
	if err := os.WriteFile(specPath, []byte(runnerSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runBenchCmd(t, "run", specPath, "--config", cfg)
	if err != nil {
		t.Fatalf("run (dry): %v", err)
	}
	if !strings.Contains(out, "DRY RUN") || !strings.Contains(out, "estimated matrix cost") {
		t.Errorf("dry run output unexpected: %s", out)
	}
	// Nothing persisted.
	runs, _ := runBenchCmd(t, "list", "--config", cfg)
	if strings.Contains(runs, "bench-") {
		t.Errorf("dry run persisted a run: %s", runs)
	}
}
