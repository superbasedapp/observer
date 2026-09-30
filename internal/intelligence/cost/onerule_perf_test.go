package cost

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/spendverdict"
)

// TestPerfSpendLoad times the engine's windowed spend read (TurnRows and a
// GroupByModel Summary over 30 days) on a synthetic ~180k-row corpus shaped
// like a proxied node: claude-code sessions whose transcript ids equal the
// proxy request ids, codex sessions whose twins match by shape only (with a
// reasoning split), and transcript-only sessions.
//
// It is a MEASUREMENT, not a gate: it runs only when ONERULE_PERF_DB names a
// database path (created and seeded on first use, reused afterwards), and
// logs min/median timings of five uncached runs each.
func TestPerfSpendLoad(t *testing.T) {
	path := os.Getenv("ONERULE_PERF_DB")
	if path == "" {
		t.Skip("set ONERULE_PERF_DB to a scratch database path to run the spend-load timing")
	}
	ctx := context.Background()
	_, statErr := os.Stat(path)
	database, err := db.Open(ctx, db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	if os.IsNotExist(statErr) {
		if err := seedPerfCorpus(ctx, database, now); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	var nAPI, nTU int
	_ = database.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM api_turns), (SELECT COUNT(*) FROM token_usage)`).Scan(&nAPI, &nTU)
	t.Logf("corpus: %d api_turns, %d token_usage", nAPI, nTU)

	// The one-time verdict backfill (every candidate session derived and
	// stored), timed on its own so the read timings below exclude it.
	start := time.Now()
	n, err := spendverdict.Refresh(ctx, database, spendverdict.Options{})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	t.Logf("verdict backfill: %d sessions in %.1f ms", n, ms(time.Since(start)))

	e := NewEngine(config.IntelligenceConfig{})
	since := now.Add(-30 * 24 * time.Hour)
	opts := Options{Since: since, Source: SourceAuto, Now: func() time.Time { return now }}
	// One warm-up read so the page cache is hot for every timed run.
	if _, err := e.TurnRows(ctx, database, opts); err != nil {
		t.Fatal(err)
	}
	timeIt := func(name string, fn func() error) {
		var ds []time.Duration
		for i := 0; i < 5; i++ {
			start := time.Now()
			if err := fn(); err != nil {
				t.Fatal(err)
			}
			ds = append(ds, time.Since(start))
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		t.Logf("%-28s min %8.1f ms  median %8.1f ms", name, ms(ds[0]), ms(ds[2]))
	}
	var turns int
	timeIt("TurnRows 30d", func() error {
		r, err := e.TurnRows(ctx, database, opts)
		turns = len(r)
		return err
	})
	t.Logf("TurnRows rows after dedup: %d", turns)
	timeIt("Summary 30d GroupByModel", func() error {
		o := opts
		o.GroupBy = GroupByModel
		_, err := e.Summary(ctx, database, o)
		return err
	})
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// seedPerfCorpus writes the synthetic corpus in one transaction.
func seedPerfCorpus(ctx context.Context, database *sql.DB, now time.Time) error {
	r := rand.New(rand.NewSource(20260928))
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO projects (root_path, created_at) VALUES ('/perf/proj', ?)`, now.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	pid, _ := res.LastInsertId()
	insSess, err := tx.PrepareContext(ctx, `INSERT INTO sessions (id, project_id, tool, model, started_at) VALUES (?,?,?,?,?)`)
	if err != nil {
		return err
	}
	insAPI, err := tx.PrepareContext(ctx, `INSERT INTO api_turns (session_id, project_id, timestamp, provider, model,
		input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, cost_usd, request_id,
		time_to_first_token_ms, total_response_ms, stop_reason)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	insTU, err := tx.PrepareContext(ctx, `INSERT INTO token_usage (session_id, timestamp, tool, model,
		input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, reasoning_tokens,
		source, reliability, source_file, source_event_id, message_id, turn_id, source_file_hash)
		VALUES (?,?,?,?,?,?,?,?,?,'jsonl','accurate',?,?,?,?,?)`)
	if err != nil {
		return err
	}
	const sessions = 1500
	const turnsPer = 70
	for s := 0; s < sessions; s++ {
		sid := fmt.Sprintf("perf-%05d", s)
		kind := s % 10 // 0-3 claude-code proxied, 4-6 codex proxied, 7-9 transcript-only
		tool, model := "claude-code", "claude-sonnet-4-5"
		if kind >= 4 && kind <= 6 {
			tool, model = "codex", "gpt-5"
		}
		start := now.Add(-time.Duration(r.Intn(29*24)) * time.Hour)
		if _, err := insSess.ExecContext(ctx, sid, pid, tool, model, start.Format(time.RFC3339Nano)); err != nil {
			return err
		}
		file := "/perf/" + sid + ".jsonl"
		for k := 0; k < turnsPer; k++ {
			at := start.Add(time.Duration(k*40+r.Intn(10)) * time.Second)
			in := int64(100 + r.Intn(5000))
			out := int64(20 + r.Intn(2000))
			reason := int64(0)
			if tool == "codex" {
				reason = int64(r.Intn(500))
			}
			cr := int64(k * 1500)
			cc := int64(r.Intn(3000))
			req := fmt.Sprintf("msg_%s_%d", sid, k)
			evt := req
			if tool == "codex" {
				evt = fmt.Sprintf("tk:%s:%d", sid, k)
			}
			if kind <= 6 {
				if _, err := insAPI.ExecContext(ctx, sid, pid, at.Format(time.RFC3339Nano), "anthropic", model,
					in, out+reason, cr, cc, 0.01, req, 300, 4000, "end_turn"); err != nil {
					return err
				}
			}
			if _, err := insTU.ExecContext(ctx, sid, at.Add(2*time.Second).Format(time.RFC3339Nano), tool, model,
				in, out, cr, cc, reason, file, evt, req, fmt.Sprintf("turn-%s-%d", sid, k),
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
