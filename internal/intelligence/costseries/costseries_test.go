package costseries

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/timebucket"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "o.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func seed(t *testing.T, database *sql.DB, now time.Time) {
	t.Helper()
	ctx := context.Background()
	stamp := now.Format(time.RFC3339Nano)
	res, err := database.ExecContext(ctx, `INSERT INTO projects (root_path, created_at) VALUES ('/p', ?)`, stamp)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := res.LastInsertId()
	for _, s := range []struct{ id, tool string }{{"s1", "claude-code"}, {"s2", "codex"}} {
		if _, err := database.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`, s.id, pid, s.tool, stamp); err != nil {
			t.Fatal(err)
		}
	}
	turns := []struct {
		sid, model string
		ago        time.Duration
		in, out    int64
		cr, cc     int64
	}{
		{"s1", "claude-sonnet-4-5", 50 * time.Hour, 1000, 200, 8000, 1000},
		{"s1", "claude-opus-4-1", 49 * time.Hour, 500, 100, 0, 0},
		{"s2", "gpt-5", 2 * time.Hour, 3000, 300, 1000, 0},
	}
	for i, tr := range turns {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model,
				input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, request_id)
			 VALUES (?, ?, ?, 'anthropic', ?, ?, ?, ?, ?, ?)`,
			tr.sid, pid, now.Add(-tr.ago).Format(time.RFC3339Nano), tr.model, tr.in, tr.out, tr.cr, tr.cc,
			"req-"+string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
}

func query(t *testing.T, now time.Time, tool string) Query {
	t.Helper()
	since := now.Add(-4 * 24 * time.Hour)
	spec, err := timebucket.Resolve(timebucket.Request{Gran: "1d", TZ: "UTC", Since: since, Until: now, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return Query{Spec: spec, Days: 4, Since: since, Until: now, Tool: tool}
}

func TestCostZeroFillsAndSums(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	database := openDB(t)
	seed(t, database, now)
	eng := cost.NewEngine(config.IntelligenceConfig{})
	cases := []struct {
		name       string
		tool       string
		wantTokens int64
		wantTurns  int
	}{
		{"all tools", "", 1000 + 200 + 8000 + 1000 + 500 + 100 + 3000 + 300 + 1000, 3},
		{"tool filter", "codex", 3000 + 300 + 1000, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buckets, err := Cost(context.Background(), eng, database, query(t, now, c.tool))
			if err != nil {
				t.Fatal(err)
			}
			if len(buckets) != 5 {
				t.Fatalf("got %d buckets, want 5 (4 days zero-filled plus today)", len(buckets))
			}
			var tokens int64
			var turns int
			for i, b := range buckets {
				if i > 0 && !b.T.After(buckets[i-1].T) {
					t.Errorf("buckets not ordered at %d", i)
				}
				if b.Key == "" {
					t.Errorf("bucket %d has no key", i)
				}
				tokens += TotalTokens(b.Row.Tokens)
				turns += b.Row.TurnCount
			}
			if tokens != c.wantTokens || turns != c.wantTurns {
				t.Errorf("tokens=%d turns=%d, want %d %d", tokens, turns, c.wantTokens, c.wantTurns)
			}
		})
	}
}

func TestTokensByModelOrderAndGrid(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	database := openDB(t)
	seed(t, database, now)
	eng := cost.NewEngine(config.IntelligenceConfig{})
	points, grid, err := TokensByModel(context.Background(), eng, database, query(t, now, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(grid) != 5 {
		t.Fatalf("grid %d, want 5", len(grid))
	}
	want := []struct{ bucket, model string }{
		{"2026-10-08", "claude-opus-4-1"},
		{"2026-10-08", "claude-sonnet-4-5"},
		{"2026-10-10", "gpt-5"},
	}
	if len(points) != len(want) {
		t.Fatalf("points %+v", points)
	}
	for i, w := range want {
		if points[i].Bucket != w.bucket || points[i].Model != w.model {
			t.Errorf("point %d: %s/%s want %s/%s", i, points[i].Bucket, points[i].Model, w.bucket, w.model)
		}
	}
}

func TestNilEngine(t *testing.T) {
	if _, err := Cost(context.Background(), nil, nil, Query{}); err == nil {
		t.Error("Cost: want error for nil engine")
	}
	if _, _, err := TokensByModel(context.Background(), nil, nil, Query{}); err == nil {
		t.Error("TokensByModel: want error for nil engine")
	}
}
