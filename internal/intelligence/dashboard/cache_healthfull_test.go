package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// seedCacheHealthCorpus writes a small two-session corpus: session "a"
// has one mispredict and one inconsistent rewrite (read 900 vs write 100),
// session "b" only hits and system_changed rewrites (predicted hit, so
// bucket mismatches), plus one zero-usage mispredict.
func seedCacheHealthCorpus(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()
	database, err := openTestDB(ctx, db.Options{Path: filepath.Join(t.TempDir(), "hf.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	insert := func(sid, ts, kind, cause, predicted string, read, written int64) {
		t.Helper()
		if _, err := database.ExecContext(ctx,
			`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, cause, predicted_kind, tokens_read, tokens_written)
			 VALUES (?, 'proxy', ?, 'claude-opus-4-8', ?, ?, ?, ?, ?)`,
			sid, ts, kind, cause, predicted, read, written); err != nil {
			t.Fatal(err)
		}
	}
	insert("a", "2026-11-01T00:00:00Z", "hit", "suffix_growth", "hit", 1000, 0)
	insert("a", "2026-11-01T00:01:00Z", "mispredict", "unknown", "hit", 50, 0)
	insert("a", "2026-11-01T00:02:00Z", "expiry_rewrite", "ttl_expired", "hit", 900, 100)
	insert("a", "2026-11-01T00:03:00Z", "mispredict", "unknown", "hit", 0, 0)
	for i := 0; i < 3; i++ {
		insert("b", "2026-11-01T01:00:00Z", "invalidation_rewrite", "system_changed", "hit", 0, 500)
	}
	insert("b", "2026-11-01T01:05:00Z", "hit", "suffix_growth", "hit", 800, 0)
	return database
}

// TestLoadCacheHealthFullReport: the full report carries the per-session
// rows (worst first), the cause breakdown, the mispredict events (the
// zero-usage one listed but flagged), the inconsistent rewrite and the
// per-session bucket mismatches, and the slim summary is unchanged by it.
func TestLoadCacheHealthFullReport(t *testing.T) {
	t.Parallel()
	database := seedCacheHealthCorpus(t)
	ctx := context.Background()

	slim, err := loadCacheHealthSummary(ctx, database, "")
	if err != nil {
		t.Fatal(err)
	}
	if slim.Full != nil {
		t.Fatal("the slim summary must not carry the full report")
	}
	got, err := loadCacheHealth(ctx, database, "", defaultCacheHealthThresholds(), true)
	if err != nil {
		t.Fatal(err)
	}
	full := got.Full
	if full == nil {
		t.Fatal("full=true returned no full report")
	}
	got.Full = nil
	if got != slim {
		t.Errorf("the summary changed with full=true:\n got %+v\nwant %+v", got, slim)
	}

	if full.PerSessionTotal != 2 || len(full.PerSession) != 2 || full.PerSession[0].SessionID != "a" || full.PerSession[0].Mispredicts != 1 {
		t.Errorf("per_session = %+v (want a first with 1 counted mispredict)", full.PerSession)
	}
	if len(full.CauseBreakdown) == 0 || full.CauseBreakdown[0].Cause != "system_changed" || full.CauseBreakdown[0].Count != 3 {
		t.Errorf("cause_breakdown = %+v, want system_changed=3 first", full.CauseBreakdown)
	}
	if full.MispredictEventsTotal != 2 || len(full.MispredictEvents) != 2 || full.MispredictEvents[0].ZeroUsage || !full.MispredictEvents[1].ZeroUsage {
		t.Errorf("mispredict_events = %+v", full.MispredictEvents)
	}
	if full.InconsistentRewriteEventsTotal != 1 || full.InconsistentRewriteEvents[0].SessionID != "a" || full.InconsistentRewriteEvents[0].Ratio != 9 {
		t.Errorf("inconsistent_rewrite_events = %+v", full.InconsistentRewriteEvents)
	}
	if len(full.BucketMispredictsPerSession) == 0 || full.BucketMispredictsPerSession[0].SessionID != "b" || full.BucketMispredictsPerSession[0].BucketMispredicts != 3 {
		t.Errorf("bucket_mispredicts_per_session = %+v, want b=3 first", full.BucketMispredictsPerSession)
	}
	if full.MaxRewriteReadRatio != 3 || full.MaxCauseShare != 0.8 {
		t.Errorf("thresholds echoed = %v / %v", full.MaxRewriteReadRatio, full.MaxCauseShare)
	}
}

// TestCacheHealthThresholdsMoveTheVerdicts: the four thresholds change the
// gate, the inconsistency count and the dominant cause exactly as the
// command's flags do.
func TestCacheHealthThresholdsMoveTheVerdicts(t *testing.T) {
	t.Parallel()
	database := seedCacheHealthCorpus(t)
	ctx := context.Background()

	def, err := loadCacheHealthSummary(ctx, database, "")
	if err != nil {
		t.Fatal(err)
	}
	if def.GatePassed || def.InconsistentRewriteCount != 1 {
		t.Fatalf("defaults: %+v", def)
	}
	// 7 graded events, 1 counted mispredict: rate 1/7.
	loose := CacheHealthThresholds{MinEvents: 5, MaxRate: 0.2, MaxRewriteReadRatio: 10, MaxCauseShare: 0.4}
	got, err := loadCacheHealth(ctx, database, "", loose, false)
	if err != nil {
		t.Fatal(err)
	}
	if !got.GatePassed || got.MinEvents != 5 || got.MaxRate != 0.2 {
		t.Errorf("a looser gate should pass: %+v", got)
	}
	if got.InconsistentRewriteCount != 0 {
		t.Errorf("ratio 10 should clear the 9:1 rewrite, got %d", got.InconsistentRewriteCount)
	}
	if got.DominantCause == nil || got.DominantCause.Cause != "system_changed" {
		t.Errorf("share 0.4 should flag system_changed (3/7), got %+v", got.DominantCause)
	}
}

// TestCacheHealthThresholdParams: one row per query parameter rule
// (default, override, clamp, garbage ignored).
func TestCacheHealthThresholdParams(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		query string
		want  CacheHealthThresholds
	}{
		{"", defaultCacheHealthThresholds()},
		{"min_events=50&max_rate=0.1", CacheHealthThresholds{MinEvents: 50, MaxRate: 0.1, MaxRewriteReadRatio: 3, MaxCauseShare: 0.8}},
		{"max_rewrite_read_ratio=5&max_cause_share=0.5", CacheHealthThresholds{MinEvents: 200, MaxRate: 0.05, MaxRewriteReadRatio: 5, MaxCauseShare: 0.5}},
		{"min_events=0&max_rate=3&max_cause_share=-1", CacheHealthThresholds{MinEvents: 1, MaxRate: 1, MaxRewriteReadRatio: 3, MaxCauseShare: 0}},
		{"min_events=abc&max_rate=NaN", defaultCacheHealthThresholds()},
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/cache/health?"+tc.query, nil)
		if got := cacheHealthThresholdsFrom(r); got != tc.want {
			t.Errorf("%q: got %+v, want %+v", tc.query, got, tc.want)
		}
	}
}

// TestHandleCacheHealthFull: the route adds the full report only on full=1.
func TestHandleCacheHealthFull(t *testing.T) {
	t.Parallel()
	database := seedCacheHealthCorpus(t)
	s := &Server{opts: Options{DB: database}}
	for _, tc := range []struct {
		query    string
		wantFull bool
	}{
		{"", false},
		{"?full=1&min_events=5", true},
		{"?full=true", true},
		{"?full=0", false},
	} {
		rec := httptest.NewRecorder()
		s.handleCacheHealth(rec, httptest.NewRequest(http.MethodGet, "/api/cache/health"+tc.query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%q: %d %s", tc.query, rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if _, ok := body["full"]; ok != tc.wantFull {
			t.Errorf("%q: full present = %v, want %v", tc.query, ok, tc.wantFull)
		}
	}
}
