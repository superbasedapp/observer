package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	notifydigest "github.com/marmutapp/superbased-observer/internal/notify/digest"
)

// private strings that a fixture DB carries in project_root / source_file /
// git columns. The share card is aggregate-only and must NEVER surface any.
var reportPrivateStrings = []string{
	"/home/alice/private-client-project",
	"acme-merger-ticket-4471",
	"session-transcript-CONFIDENTIAL.jsonl",
	"feature/project-titan",
}

func seedReportDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "node.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	// Window: DuePeriod(week) as of reportFixedNow → Mon 2026-06-29 .. 2026-07-06.
	stmts := []string{
		`INSERT INTO projects (id, root_path, git_remote, created_at) VALUES (1,'/home/alice/private-client-project','git@github.com:acme-merger-ticket-4471.git','2026-01-01T00:00:00Z')`,
		`INSERT INTO sessions (id, project_id, tool, started_at, git_branch)
		 VALUES ('s1',1,'claude-code','2026-06-30T09:00:00Z','feature/project-titan')`,
		`INSERT INTO sessions (id, project_id, tool, started_at)
		 VALUES ('s2',1,'codex','2026-06-30T09:00:00Z')`,
		`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens, estimated_cost_usd, source, reliability, source_file, source_event_id)
		 VALUES ('s1','2026-06-30T10:00:00Z','claude-code','claude-opus-4-8',1000,500,4000,42.50,'jsonl','approximate','session-transcript-CONFIDENTIAL.jsonl','e1')`,
		`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens, estimated_cost_usd, source, reliability, source_file, source_event_id)
		 VALUES ('s2','2026-07-01T10:00:00Z','codex','gpt-5.6',800,300,1200,11.25,'jsonl','approximate','/home/alice/private-client-project/notes.md','e2')`,
	}
	for _, s := range stmts {
		if _, err := database.ExecContext(ctx, s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	return dbPath
}

// TestReportShare_AggregatesOnly_NoLeaks is the privacy guard: the rendered SVG
// and Markdown must contain the aggregates (spend, model ids, tool names, cache
// %) but NONE of the project-root / source-file / branch / remote strings the
// fixture DB carries.
func TestReportShare_AggregatesOnly_NoLeaks(t *testing.T) {
	database := openDigestDB(t, seedReportDB(t))
	engine := cost.NewEngine(config.Default().Intelligence)
	// A completed week that contains the seeded 2026-06-30/07-01 rows.
	now := time.Date(2026, 7, 8, 15, 0, 0, 0, time.UTC)
	p, _ := notifydigest.DuePeriod(notifydigest.Weekly, 0, now)

	data, err := assembleShareData(context.Background(), engine, database, p, "week")
	if err != nil {
		t.Fatalf("assembleShareData: %v", err)
	}

	svg := data.SVG()
	md := data.Markdown()

	// Positive: aggregates present.
	if data.TotalUSD <= 0 {
		t.Fatalf("expected positive total spend, got %v", data.TotalUSD)
	}
	if !strings.Contains(svg, "claude-opus-4-8") || !strings.Contains(md, "claude-opus-4-8") {
		t.Errorf("expected model id in artifacts")
	}
	if !data.HasCacheShare || data.CacheReadShare <= 0 {
		t.Errorf("expected a non-zero cache-read share, got %+v", data)
	}

	// Negative: no private path/branch/remote string leaks into either artifact.
	for _, needle := range reportPrivateStrings {
		if strings.Contains(svg, needle) {
			t.Errorf("SVG leaked private string %q", needle)
		}
		if strings.Contains(md, needle) {
			t.Errorf("Markdown leaked private string %q", needle)
		}
	}
}
