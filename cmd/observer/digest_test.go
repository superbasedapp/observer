package main

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	notifydigest "github.com/marmutapp/superbased-observer/internal/notify/digest"
	"github.com/marmutapp/superbased-observer/internal/notify/email"
)

// nodeFixedNow is a Wednesday; the completed weekly window is Mon 2026-06-29 →
// Sun 2026-07-05 (end 2026-07-06), the prior week 2026-06-22 → 2026-06-29.
var nodeFixedNow = time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)

func seedDigestDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "node.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO projects (id, root_path, created_at) VALUES (1,'/r','2026-01-01T00:00:00Z')`,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('s1',1,'claude-code','2026-06-30T09:00:00Z')`,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('s2',1,'claude-code','2026-06-23T09:00:00Z')`,
		// current-week spend
		`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, estimated_cost_usd, source, reliability, source_file, source_event_id)
		 VALUES ('s1','2026-06-30T10:00:00Z','claude-code','claude-opus',100,50,5.0,'jsonl','approximate','f','e1')`,
		// prior-week spend
		`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, estimated_cost_usd, source, reliability, source_file, source_event_id)
		 VALUES ('s2','2026-06-23T10:00:00Z','claude-code','claude-opus',100,50,3.0,'jsonl','approximate','f','e2')`,
	}
	for _, s := range stmts {
		if _, err := database.ExecContext(ctx, s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	return dbPath
}

func openDigestDB(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func testRunner(t *testing.T, database *sql.DB, rec *[]email.Message) *nodeDigestRunner {
	t.Helper()
	cfg := config.Default()
	cfg.Digest = notifydigest.Config{Enabled: true, Frequency: "weekly", SendHour: 8}
	r := newNodeDigestRunner(cfg, database, nil, newLogger("error"))
	r.now = func() time.Time { return nodeFixedNow }
	r.send = func(_ context.Context, m email.Message) { *rec = append(*rec, m) }
	return r
}

func TestNodeAssembleHasBreakdowns(t *testing.T) {
	database := openDigestDB(t, seedDigestDB(t))
	var rec []email.Message
	r := testRunner(t, database, &rec)
	period, _ := notifydigest.DuePeriod(notifydigest.Weekly, 8, nodeFixedNow)
	data, err := r.assemble(context.Background(), period)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(data.Breakdowns) == 0 {
		t.Fatalf("expected breakdowns")
	}
	if !data.HasPrior {
		t.Errorf("expected HasPrior")
	}
	// Alert table absent on a fresh node db → alert count omitted.
	if data.HasAlertCount {
		t.Errorf("expected no alert count when obs_alert_events absent")
	}
}

func TestNodeTickSendsOncePerPeriod(t *testing.T) {
	database := openDigestDB(t, seedDigestDB(t))
	var rec []email.Message
	r := testRunner(t, database, &rec)
	ctx := context.Background()
	r.tick(ctx)
	r.tick(ctx)
	if len(rec) != 1 {
		t.Fatalf("sends = %d, want 1", len(rec))
	}
	var got string
	if err := database.QueryRowContext(ctx, `SELECT last_period FROM digest_state WHERE kind='node'`).Scan(&got); err != nil {
		t.Fatalf("marker: %v", err)
	}
	if got == "" {
		t.Errorf("marker not persisted")
	}
}

func TestNodeDigestSendDryRunCLI(t *testing.T) {
	// The CLI builds its own runner with no now-injection point; pin the
	// package clock to nodeFixedNow so the completed-week window lines up with
	// the fixed seed dates (otherwise the window drifts with wall-clock time
	// and the seeded spend falls out of period).
	prevClock := digestClock
	digestClock = func() time.Time { return nodeFixedNow }
	defer func() { digestClock = prevClock }()

	dbPath := seedDigestDB(t)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+dbPath+"\"\n\n[digest]\nenabled = true\nfrequency = \"weekly\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newDigestCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"send", "--config", cfgPath, "--dry-run"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := out.String()
	for _, want := range []string{"Subject:", "cost digest", "Observed spend", "Spend by tool"} {
		if !strings.Contains(got, want) {
			t.Errorf("dry-run output missing %q\n---\n%s", want, got)
		}
	}
	if strings.Contains(got, "digest sent") {
		t.Errorf("dry-run must not send")
	}
}
