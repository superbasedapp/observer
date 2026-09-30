package cost

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

type rowCacheCase struct {
	name string
	opts Options
}

// TestRowCacheSummaryMatchesUncached is the equivalence proof for the
// 2026-09-27 raw-row cache (optimization review finding N4): for every
// group-by, filter and window, a Summary / TurnRows served through the cache
// — including windows answered by FILTERING a wider cached read — is deeply
// equal to the same call read straight from the database.
func TestRowCacheSummaryMatchesUncached(t *testing.T) {
	ctx := context.Background()
	for seed := int64(1); seed <= 3; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			database := openTestDB(t)
			rng := rand.New(rand.NewSource(seed))
			base := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
			now := base.Add(48 * time.Hour)
			fa := seedSession(t, database, "/p/a", "sa1", "claude-code")
			fa2 := seedSessionInProject(t, database, fa, "sa2", "codex")
			fb := seedSession(t, database, "/p/b", "sb1", "claude-code")
			fixtures := []fixture{fa, fa2, fb}
			models := []string{"claude-sonnet-4-5", "claude-opus-4-1", "gpt-5"}
			for i := 0; i < 240; i++ {
				f := fixtures[rng.Intn(len(fixtures))]
				ts := base.Add(time.Duration(rng.Intn(40*60)) * time.Minute)
				model := models[rng.Intn(len(models))]
				in, out := int64(100+rng.Intn(50)), int64(10+rng.Intn(20))
				tool := "claude-code"
				if f.sessionID == "sa2" {
					tool = "codex"
				}
				switch rng.Intn(4) {
				case 0: // proxy + JSONL twin sharing the request id
					id := fmt.Sprintf("msg_%d", i)
					insertAPITurnWithRequestID(t, database, f, ts, model, in, out, id)
					insertTokenUsageWithEventID(t, database, f, ts, tool, model, in, out, "accurate", id)
				case 1: // proxy + JSONL twin matched only by shape
					insertAPITurnWithRequestID(t, database, f, ts, model, in, out, fmt.Sprintf("resp_%d", i))
					insertTokenUsageWithEventID(t, database, f, ts, tool, model, in, out, "accurate", fmt.Sprintf("tk:%d", i))
				case 2: // JSONL only
					insertTokenUsageWithEventID(t, database, f, ts, tool, model, in, out, "approximate", fmt.Sprintf("j%d", i))
				default: // proxy only
					insertAPITurnWithRequestID(t, database, f, ts, model, in, out, fmt.Sprintf("p%d", i))
				}
			}
			if _, err := database.ExecContext(ctx, `UPDATE token_usage SET fast = 1 WHERE tool = 'codex' AND rowid % 3 = 0`); err != nil {
				t.Fatal(err)
			}

			e := NewEngine(config.IntelligenceConfig{})
			clock := func() time.Time { return now }
			cases := []rowCacheCase{}
			windows := []struct {
				name         string
				since, until time.Time
			}{
				{"wide", base.Add(-time.Hour), time.Time{}},
				{"narrow", base.Add(20 * time.Hour), time.Time{}},
				{"narrower", base.Add(30*time.Hour + 7*time.Minute), time.Time{}},
				{"all-time", time.Time{}, time.Time{}},
				{"bounded", base.Add(10 * time.Hour), base.Add(25 * time.Hour)},
			}
			filters := []struct {
				name string
				set  func(*Options)
			}{
				{"none", func(*Options) {}},
				{"project-root", func(o *Options) { o.ProjectRoot = "/p/a" }},
				{"project-id", func(o *Options) { o.ProjectID = fb.projectID }},
				{"tool", func(o *Options) { o.Tool = "codex" }},
			}
			groups := []GroupBy{GroupByModel, GroupByDay, GroupBySession, GroupByProject, GroupByTool, GroupByDayModel}
			for _, w := range windows {
				for _, f := range filters {
					for _, g := range groups {
						o := Options{Since: w.since, Until: w.until, GroupBy: g, Limit: 500, Now: clock}
						f.set(&o)
						cases = append(cases, rowCacheCase{name: w.name + "/" + f.name + "/" + string(g), opts: o})
					}
				}
			}
			cached := WithRowCache(ctx)
			// Two passes: the first populates (wide windows first, so the
			// narrower ones are answered by filtering), the second re-reads
			// every shape from a warm cache — which also proves a caller's
			// in-place mutation of its rows never reaches the cache.
			for pass := 0; pass < 2; pass++ {
				for _, c := range cases {
					want, err := e.Summary(ctx, database, c.opts)
					if err != nil {
						t.Fatal(err)
					}
					got, err := e.Summary(cached, database, c.opts)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("pass %d %s: cached Summary differs\n got=%+v\nwant=%+v", pass, c.name, got, want)
					}
					wantTurns, err := e.TurnRows(ctx, database, c.opts)
					if err != nil {
						t.Fatal(err)
					}
					gotTurns, err := e.TurnRows(cached, database, c.opts)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(gotTurns, wantTurns) {
						t.Fatalf("pass %d %s: cached TurnRows differ", pass, c.name)
					}
				}
			}
		})
	}
}

// TestRowCacheFreshness pins the freshness contract: an insert invalidates at
// once (fingerprint), an in-place UPDATE is invisible for at most rowCacheTTL,
// a narrower window is served from a wider entry without a read, and a wider
// window than the entry holds is a miss.
func TestRowCacheFreshness(t *testing.T) {
	ctx := WithRowCache(context.Background())
	database := openTestDB(t)
	base := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)
	f := seedSession(t, database, "/p/a", "s1", "claude-code")
	insertAPITurnWithRequestID(t, database, f, base, "claude-sonnet-4-5", 1000, 100, "r1")

	e := NewEngine(config.IntelligenceConfig{})
	var mu sync.Mutex
	clock := base.Add(time.Hour)
	e.rows.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	e.rows.afterFunc = func(time.Duration, func()) *time.Timer { return nil }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
	opts := Options{Since: base.Add(-time.Hour), GroupBy: GroupByNone, Source: SourceProxy, Now: func() time.Time { return base.Add(time.Hour) }}
	total := func() int64 {
		t.Helper()
		s, err := e.Summary(ctx, database, opts)
		if err != nil {
			t.Fatal(err)
		}
		return s.TotalTokens.Input
	}
	if got := total(); got != 1000 {
		t.Fatalf("input = %d, want 1000", got)
	}
	// Insert: fingerprint moves, visible immediately.
	insertAPITurnWithRequestID(t, database, f, base.Add(time.Minute), "claude-sonnet-4-5", 500, 50, "r2")
	if got := total(); got != 1500 {
		t.Fatalf("after insert input = %d, want 1500 (an insert must invalidate the cache at once)", got)
	}
	// In-place UPDATE: invisible inside the TTL, visible after it.
	if _, err := database.ExecContext(context.Background(), `UPDATE api_turns SET input_tokens = 2000 WHERE request_id = 'r1'`); err != nil {
		t.Fatal(err)
	}
	if got := total(); got != 1500 {
		t.Fatalf("within TTL after UPDATE input = %d, want the cached 1500", got)
	}
	advance(rowCacheTTL)
	if got := total(); got != 2500 {
		t.Fatalf("after TTL input = %d, want 2500", got)
	}
	// A narrower window is a filter of the wide entry; a wider one is a miss
	// that re-reads (observable because it sees an UPDATE the entry predates).
	opts.Since = base.Add(30 * time.Second)
	if got := total(); got != 500 {
		t.Fatalf("narrow window input = %d, want 500", got)
	}
	if _, err := database.ExecContext(context.Background(), `UPDATE api_turns SET input_tokens = 3000 WHERE request_id = 'r1'`); err != nil {
		t.Fatal(err)
	}
	opts.Since = base.Add(-2 * time.Hour)
	if got := total(); got != 3500 {
		t.Fatalf("wider-than-cached window input = %d, want 3500 (a fresh read)", got)
	}
	// Without the context mark the cache is never consulted.
	if _, err := database.ExecContext(context.Background(), `UPDATE api_turns SET input_tokens = 4000 WHERE request_id = 'r1'`); err != nil {
		t.Fatal(err)
	}
	s, err := e.Summary(context.Background(), database, opts)
	if err != nil {
		t.Fatal(err)
	}
	if s.TotalTokens.Input != 4500 {
		t.Fatalf("unmarked context input = %d, want 4500 (uncached read)", s.TotalTokens.Input)
	}
}
