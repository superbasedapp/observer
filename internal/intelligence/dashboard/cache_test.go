package dashboard

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
)

func testCtx(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}

func ev(kind, cause string, read, write int64, ts string) SessionCacheEvent {
	return SessionCacheEvent{
		Timestamp: ts, Tier: "proxy", Model: "claude-opus-4-8",
		Kind: kind, Cause: cause, TokensRead: read, TokensWritten: write,
	}
}

// TestBuildCacheTimeline_BaselineAggregation pins operator UI
// steer #1: a long run of suffix_growth events is collapsed into
// ONE roll-up entry; only anomalies are itemized. Without this,
// a 141-baseline-event session would render 141 timeline rows.
func TestBuildCacheTimeline_BaselineAggregation(t *testing.T) {
	t.Parallel()
	events := []SessionCacheEvent{
		ev("hit", "suffix_growth", 10000, 0, "2026-06-09T00:00:00Z"),
		ev("write", "suffix_growth", 9000, 200, "2026-06-09T00:00:10Z"),
		ev("hit", "suffix_growth", 9100, 0, "2026-06-09T00:00:20Z"),
		ev("write", "suffix_growth", 9200, 250, "2026-06-09T00:00:30Z"),
	}
	tl := buildCacheTimeline(events)
	if len(tl) != 1 {
		t.Fatalf("got %d timeline items, want 1 (all baseline → single roll-up)", len(tl))
	}
	item := tl[0]
	if item.Kind != "baseline" {
		t.Errorf("Kind = %q, want baseline", item.Kind)
	}
	if item.Count != 4 {
		t.Errorf("Count = %d, want 4", item.Count)
	}
	if item.BaselineReadSum != 37300 || item.BaselineWriteSum != 450 {
		t.Errorf("token sums = (%d,%d), want (37300,450)", item.BaselineReadSum, item.BaselineWriteSum)
	}
	if item.FirstAt != "2026-06-09T00:00:00Z" || item.LastAt != "2026-06-09T00:00:30Z" {
		t.Errorf("timestamps = (%s,%s), want first/last", item.FirstAt, item.LastAt)
	}
}

// TestBuildCacheTimeline_AnomalyBreaksRun pins the contiguous-
// run semantics: an anomaly between two baseline runs SPLITS the
// timeline into baseline-run, anomaly, baseline-run.
func TestBuildCacheTimeline_AnomalyBreaksRun(t *testing.T) {
	t.Parallel()
	events := []SessionCacheEvent{
		ev("hit", "suffix_growth", 10000, 0, "2026-06-09T00:00:00Z"),
		ev("write", "suffix_growth", 9000, 200, "2026-06-09T00:00:10Z"),
		ev("invalidation_rewrite", "system_changed", 1500, 8000, "2026-06-09T00:00:20Z"),
		ev("hit", "suffix_growth", 11000, 0, "2026-06-09T00:00:30Z"),
		ev("write", "suffix_growth", 11500, 250, "2026-06-09T00:00:40Z"),
	}
	tl := buildCacheTimeline(events)
	if len(tl) != 3 {
		t.Fatalf("got %d timeline items, want 3 (baseline + anomaly + baseline)", len(tl))
	}
	if tl[0].Kind != "baseline" || tl[0].Count != 2 {
		t.Errorf("item 0: %+v, want baseline count=2", tl[0])
	}
	if tl[1].Kind != "anomaly" || tl[1].Event == nil {
		t.Fatalf("item 1: %+v, want anomaly", tl[1])
	}
	if tl[1].Event.Cause != "system_changed" {
		t.Errorf("anomaly cause = %q, want system_changed", tl[1].Event.Cause)
	}
	if tl[1].Flagged {
		t.Errorf("system_changed should NOT be flagged (it's a real invalidation when it fires)")
	}
	if tl[2].Kind != "baseline" || tl[2].Count != 2 {
		t.Errorf("item 2: %+v, want baseline count=2", tl[2])
	}
}

// TestBuildCacheTimeline_FlaggedCause pins operator UI steer #2:
// tools_changed is a known-limitation flagged cause — the
// timeline marks it Flagged=true so the frontend renders a
// neutral pill rather than alarm-red. system_changed (and other
// "real" causes) stay unflagged.
func TestBuildCacheTimeline_FlaggedCause(t *testing.T) {
	t.Parallel()
	events := []SessionCacheEvent{
		ev("invalidation_rewrite", "tools_changed", 39056, 5400, "2026-06-09T00:00:00Z"),
		ev("invalidation_rewrite", "system_changed", 1500, 8000, "2026-06-09T00:00:10Z"),
	}
	tl := buildCacheTimeline(events)
	if len(tl) != 2 {
		t.Fatalf("got %d items, want 2", len(tl))
	}
	if !tl[0].Flagged {
		t.Errorf("tools_changed must be Flagged=true per docs/cache-tracking.md")
	}
	if tl[1].Flagged {
		t.Errorf("system_changed must NOT be flagged (real invalidation)")
	}
}

// TestBuildCacheTimeline_ZeroUsageMispredictItemized pins that
// zero-usage mispredicts (KindMispredict + zero tokens) land in
// the timeline as anomalies — they're diagnostic-relevant even
// though the rate excludes them. The frontend uses
// event.zero_usage to render the [zero-usage, excluded from
// rate] marker.
func TestBuildCacheTimeline_ZeroUsageMispredictItemized(t *testing.T) {
	t.Parallel()
	events := []SessionCacheEvent{
		ev("hit", "suffix_growth", 10000, 0, "2026-06-09T00:00:00Z"),
		{
			Timestamp: "2026-06-09T00:00:10Z", Tier: "proxy", Model: "claude-opus-4-8",
			Kind: "mispredict", Cause: "unknown", TokensRead: 0, TokensWritten: 0, ZeroUsage: true,
		},
		ev("hit", "suffix_growth", 10000, 0, "2026-06-09T00:00:20Z"),
	}
	tl := buildCacheTimeline(events)
	if len(tl) != 3 {
		t.Fatalf("got %d items, want 3 (baseline + anomaly + baseline)", len(tl))
	}
	if tl[1].Kind != "anomaly" || tl[1].Event == nil {
		t.Fatalf("item 1 not an anomaly: %+v", tl[1])
	}
	if !tl[1].Event.ZeroUsage {
		t.Errorf("event.zero_usage must be propagated to the timeline item")
	}
}

// TestBuildCacheEfficiency rolls token counts + ratio.
func TestBuildCacheEfficiency(t *testing.T) {
	t.Parallel()
	events := []SessionCacheEvent{
		ev("hit", "suffix_growth", 10000, 0, "2026-06-09T00:00:00Z"),
		ev("write", "suffix_growth", 9000, 200, "2026-06-09T00:00:10Z"),
		ev("invalidation_rewrite", "system_changed", 0, 5000, "2026-06-09T00:00:20Z"),
	}
	eff := buildCacheEfficiency(events)
	if eff.ReadTokens != 19000 || eff.WrittenTokens != 5200 {
		t.Errorf("tokens = (%d,%d), want (19000,5200)", eff.ReadTokens, eff.WrittenTokens)
	}
	wantRatio := 19000.0 / 5200.0
	if eff.Ratio < wantRatio-1e-6 || eff.Ratio > wantRatio+1e-6 {
		t.Errorf("ratio = %v, want %v", eff.Ratio, wantRatio)
	}
}

// TestBuildCacheEfficiency_NoWritesNoRatio pins the divide-by-
// zero guard: a corpus with reads but zero writes returns
// Ratio=0 rather than +Inf.
func TestBuildCacheEfficiency_NoWritesNoRatio(t *testing.T) {
	t.Parallel()
	events := []SessionCacheEvent{
		ev("hit", "suffix_growth", 10000, 0, "2026-06-09T00:00:00Z"),
		ev("hit", "suffix_growth", 9500, 0, "2026-06-09T00:00:10Z"),
	}
	eff := buildCacheEfficiency(events)
	if eff.Ratio != 0 {
		t.Errorf("ratio with zero writes = %v, want 0 (divide-by-zero guard)", eff.Ratio)
	}
}

// TestBuildCacheOverview rolls a mixed corpus into all four
// dimensions (global, per-model, per-project, top-causes,
// worst-sessions). Pins the deterministic sort order and the
// tools_changed flagged convention on the cause histogram.
func TestBuildCacheOverview(t *testing.T) {
	t.Parallel()
	events := []overviewEvent{
		// Project A — session sA on opus: 5 baseline, 3 rewrites. All "proxy" tier.
		{SessionID: "sA", Model: "claude-opus-4-8", Tier: "proxy", Kind: "hit", Cause: "suffix_growth", Tokens: tokenPair{Read: 10000}, ProjectID: 1, ProjectRoot: "/a"},
		{SessionID: "sA", Model: "claude-opus-4-8", Tier: "proxy", Kind: "write", Cause: "suffix_growth", Tokens: tokenPair{Read: 9000, Written: 200}, ProjectID: 1, ProjectRoot: "/a"},
		{SessionID: "sA", Model: "claude-opus-4-8", Tier: "proxy", Kind: "invalidation_rewrite", Cause: "system_changed", Tokens: tokenPair{Written: 5000}, ProjectID: 1, ProjectRoot: "/a"},
		{SessionID: "sA", Model: "claude-opus-4-8", Tier: "proxy", Kind: "invalidation_rewrite", Cause: "tools_changed", Tokens: tokenPair{Read: 30000, Written: 5000}, ProjectID: 1, ProjectRoot: "/a"},
		{SessionID: "sA", Model: "claude-opus-4-8", Tier: "proxy", Kind: "expiry_rewrite", Cause: "ttl_expired", Tokens: tokenPair{Written: 8000}, ProjectID: 1, ProjectRoot: "/a"},
		// Project B — session sB on haiku: 2 baseline, 1 rewrite. Tier=transcript on hits, proxy on the rewrite → should collapse to "mixed" on the worst-sessions row.
		{SessionID: "sB", Model: "claude-haiku-4-5-20251001", Tier: "transcript", Kind: "hit", Cause: "suffix_growth", Tokens: tokenPair{Read: 5000}, ProjectID: 2, ProjectRoot: "/b"},
		{SessionID: "sB", Model: "claude-haiku-4-5-20251001", Tier: "transcript", Kind: "write", Cause: "suffix_growth", Tokens: tokenPair{Read: 4500, Written: 100}, ProjectID: 2, ProjectRoot: "/b"},
		{SessionID: "sB", Model: "claude-haiku-4-5-20251001", Tier: "proxy", Kind: "invalidation_rewrite", Cause: "system_changed", Tokens: tokenPair{Written: 3000}, ProjectID: 2, ProjectRoot: "/b"},
	}
	got := buildCacheOverview(events)

	// Global rollup.
	if got.Global.EventCount != 8 || got.Global.SessionCount != 2 {
		t.Errorf("global counts = (events=%d, sessions=%d), want (8,2)", got.Global.EventCount, got.Global.SessionCount)
	}

	// Per-model: opus has 5 events, haiku has 3 → opus first.
	if len(got.PerModel) != 2 {
		t.Fatalf("PerModel = %d rows, want 2", len(got.PerModel))
	}
	if got.PerModel[0].Model != "claude-opus-4-8" || got.PerModel[0].EventCount != 5 {
		t.Errorf("PerModel[0] = %+v, want opus first with 5", got.PerModel[0])
	}

	// Per-project: A has 5, B has 3 → A first.
	if len(got.PerProject) != 2 {
		t.Fatalf("PerProject = %d rows, want 2", len(got.PerProject))
	}
	if got.PerProject[0].ProjectRoot != "/a" {
		t.Errorf("PerProject[0] = %+v, want /a first", got.PerProject[0])
	}

	// Top causes: suffix_growth (4) > system_changed (2) > tools_changed (1) = ttl_expired (1).
	if len(got.TopCauses) < 3 {
		t.Fatalf("TopCauses = %d rows, want ≥3", len(got.TopCauses))
	}
	if got.TopCauses[0].Cause != "suffix_growth" || got.TopCauses[0].Count != 4 {
		t.Errorf("TopCauses[0] = %+v, want suffix_growth count=4", got.TopCauses[0])
	}
	// Find tools_changed in the histogram; assert Flagged=true.
	var foundFlagged bool
	for _, c := range got.TopCauses {
		if c.Cause == "tools_changed" {
			if !c.Flagged {
				t.Errorf("tools_changed must be Flagged=true (operator UI steer #2)")
			}
			foundFlagged = true
		}
		if c.Cause == "system_changed" && c.Flagged {
			t.Errorf("system_changed must NOT be flagged")
		}
	}
	if !foundFlagged {
		t.Errorf("tools_changed missing from top causes")
	}

	// Worst sessions: sA has 3 rewrites, sB has 1 → sA first.
	if len(got.WorstSessions) != 2 {
		t.Fatalf("WorstSessions = %d rows, want 2", len(got.WorstSessions))
	}
	if got.WorstSessions[0].SessionID != "sA" || got.WorstSessions[0].RewriteCount != 3 {
		t.Errorf("WorstSessions[0] = %+v, want sA count=3", got.WorstSessions[0])
	}
	// sA's top rewrite cause: system_changed (1), tools_changed (1), ttl_expired (1).
	// All tied at 1; lexicographic tiebreak → system_changed.
	if got.WorstSessions[0].TopCause != "system_changed" {
		t.Errorf("sA top cause = %q, want system_changed (lex tiebreak)", got.WorstSessions[0].TopCause)
	}
	// Tier propagation: sA's rewrites are all "proxy" → uniform.
	if got.WorstSessions[0].Tier != "proxy" {
		t.Errorf("sA tier = %q, want proxy (uniform)", got.WorstSessions[0].Tier)
	}
	// sB has only 1 rewrite event and it's tier=proxy. Even though
	// the baseline hit/write events are transcript-tier, only
	// rewrite-kinded events fold into the worst-sessions tier set,
	// so sB's tier is uniform "proxy" (not "mixed"). This is the
	// right semantics: worst-sessions ranks BY rewrite count, so
	// the tier label answers "where did the rewrites come from?"
	// not "what tier captured the session as a whole."
	if got.WorstSessions[1].SessionID != "sB" || got.WorstSessions[1].Tier != "proxy" {
		t.Errorf("sB tier = %q, want proxy (only rewrite event was proxy)", got.WorstSessions[1].Tier)
	}
}

// TestBuildCacheOverview_EmptyCorpus pins the no-events case:
// every slice is non-nil (so the JSON response carries [], not
// null) and rollup counts are zero.
func TestBuildCacheOverview_EmptyCorpus(t *testing.T) {
	t.Parallel()
	got := buildCacheOverview(nil)
	if got.PerModel == nil || got.PerProject == nil || got.TopCauses == nil || got.WorstSessions == nil {
		t.Errorf("empty corpus must return non-nil slices for JSON shape stability: %+v", got)
	}
	if got.Global.EventCount != 0 || got.Global.SessionCount != 0 {
		t.Errorf("global counts must be 0 on empty corpus: %+v", got.Global)
	}
}

// TestBuildCacheOverview_WorstSessionsCap pins the 10-row cap.
func TestBuildCacheOverview_WorstSessionsCap(t *testing.T) {
	t.Parallel()
	events := []overviewEvent{}
	for i := 0; i < 25; i++ {
		sid := fmt.Sprintf("s%02d", i)
		events = append(events, overviewEvent{
			SessionID: sid, Model: "m", Kind: "invalidation_rewrite", Cause: "system_changed",
			Tokens: tokenPair{Written: 1000},
		})
	}
	got := buildCacheOverview(events)
	if len(got.WorstSessions) != 10 {
		t.Errorf("WorstSessions = %d rows, want 10 (cap)", len(got.WorstSessions))
	}
}

// TestLoadCacheAnnotationsByKey_UnsupportedColumn pins the
// guardrail: only "session_id" and "model" are valid. Anything
// else returns an error so a typo in a handler can't silently
// produce empty annotations.
func TestLoadCacheAnnotationsByKey_UnsupportedColumn(t *testing.T) {
	t.Parallel()
	_, err := loadCacheAnnotationsByKey(testCtx(t), nil, "project_id", []string{"x"})
	if err == nil {
		t.Errorf("expected error for unsupported keyColumn")
	}
}

// TestLoadCacheAnnotationsByKey_EmptyKeys pins the no-query-on-
// empty-input contract: zero keys returns an empty map without
// touching the DB. Keeps the cost handler's enrichment path
// fast on empty windows.
func TestLoadCacheAnnotationsByKey_EmptyKeys(t *testing.T) {
	t.Parallel()
	got, err := loadCacheAnnotationsByKey(testCtx(t), nil, "session_id", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d, want empty map", len(got))
	}
}

// TestLoadCacheAnnotationsByKey_AggregatesPerKey seeds a mixed
// corpus of cache_events across two sessions and confirms the
// per-key aggregation is correct: hit/write/rewrite/mispredict
// counts add up, tokens roll, ratio finalizes, has_flagged_rewrites
// fires on tools_changed, and the tier collapses per-key (not
// across keys). Operator-relevant invariant: the keyset bound at
// the cost handler determines which sessions/models get
// annotations; rows beyond the keyset don't leak in.
func TestLoadCacheAnnotationsByKey_AggregatesPerKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := openTestDB(ctx, db.Options{Path: filepath.Join(t.TempDir(), "cost.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	insert := func(sid, kind, cause string, read, written int64) {
		t.Helper()
		_, err := database.ExecContext(ctx,
			`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, cause, tokens_read, tokens_written)
			 VALUES (?, 'proxy', '2026-06-09T00:00:00Z', 'claude-opus-4-8', ?, ?, ?, ?)`,
			sid, kind, cause, read, written)
		if err != nil {
			t.Fatal(err)
		}
	}
	// sA: 5 hits + 2 writes + 1 system_changed rewrite + 1 tools_changed rewrite + 1 zero-usage mispredict.
	for i := 0; i < 5; i++ {
		insert("sA", "hit", "suffix_growth", 10000, 0)
	}
	for i := 0; i < 2; i++ {
		insert("sA", "write", "suffix_growth", 9000, 200)
	}
	insert("sA", "invalidation_rewrite", "system_changed", 0, 5000)
	insert("sA", "invalidation_rewrite", "tools_changed", 30000, 5000)
	insert("sA", "mispredict", "unknown", 0, 0)
	// sB: 3 hits only.
	for i := 0; i < 3; i++ {
		insert("sB", "hit", "suffix_growth", 5000, 0)
	}
	// sC: events that should be IGNORED by the keyset filter.
	insert("sC", "write", "suffix_growth", 1000, 50)

	got, err := loadCacheAnnotationsByKey(ctx, database, "session_id", []string{"sA", "sB"})
	if err != nil {
		t.Fatal(err)
	}

	a, ok := got["sA"]
	if !ok {
		t.Fatalf("sA missing from annotations: %+v", got)
	}
	if a.HitCount != 5 || a.WriteCount != 2 || a.RewriteCount != 2 || a.MispredictCount != 1 || a.ZeroUsageCount != 1 {
		t.Errorf("sA counts mismatch: %+v", a)
	}
	if !a.HasFlaggedRewrites {
		t.Errorf("sA must surface HasFlaggedRewrites=true (tools_changed present)")
	}
	if a.Tier != "proxy" {
		t.Errorf("sA tier = %q, want proxy", a.Tier)
	}
	// Ratio = (5*10000 + 2*9000 + 0 + 30000) / (2*200 + 5000 + 5000)
	//      = (50000+18000+30000) / (400+10000)
	//      = 98000 / 10400 ≈ 9.42×
	if a.Ratio < 9.0 || a.Ratio > 10.0 {
		t.Errorf("sA ratio = %v, want ~9.4", a.Ratio)
	}

	b, ok := got["sB"]
	if !ok {
		t.Fatalf("sB missing: %+v", got)
	}
	if b.HitCount != 3 || b.RewriteCount != 0 {
		t.Errorf("sB counts mismatch: %+v", b)
	}
	if b.HasFlaggedRewrites {
		t.Errorf("sB must NOT have flagged rewrites")
	}

	// sC is NOT in the keyset; its row must be filtered out.
	if _, ok := got["sC"]; ok {
		t.Errorf("sC leaked into annotations despite not being in keyset: %+v", got)
	}
}

// TestCollapseTier pins the proxy/transcript/mixed/none label
// produced from the event stream.
func TestCollapseTier(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		events []SessionCacheEvent
		want   string
	}{
		{"empty → none", nil, "none"},
		{"proxy only", []SessionCacheEvent{{Tier: "proxy"}, {Tier: "proxy"}}, "proxy"},
		{"transcript only", []SessionCacheEvent{{Tier: "transcript"}}, "transcript"},
		{"mixed proxy+transcript", []SessionCacheEvent{{Tier: "proxy"}, {Tier: "transcript"}}, "mixed"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := collapseTier(tt.events)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestLoadOverviewEvents_FiltersScopeRows seeds a small mixed
// corpus and confirms days / tool / project query params each
// scope the cache_events ⨝ sessions ⨝ projects join the same way
// handleStatusScoped + handleCost do. The Cache page must agree
// with every other dashboard surface when the operator scopes the
// TopBar — pre-fix it ignored filters and silently showed
// all-corpus data even when project was scoped.
func TestLoadOverviewEvents_FiltersScopeRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := openTestDB(ctx, db.Options{Path: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Two projects, three sessions across two tools, mixed timestamps.
	var pidA, pidB int64
	if err := database.QueryRowContext(
		ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/repo/a', '2026-06-09T00:00:00Z') RETURNING id`,
	).Scan(&pidA); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(
		ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/repo/b', '2026-06-09T00:00:00Z') RETURNING id`,
	).Scan(&pidB); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	day := func(d int) string { return now.Add(time.Duration(d) * 24 * time.Hour).Format(time.RFC3339Nano) }
	insertSession := func(id, tool string, projectID int64) {
		t.Helper()
		_, err := database.ExecContext(ctx,
			`INSERT INTO sessions (id, tool, project_id, model, started_at) VALUES (?, ?, ?, 'claude-opus-4-8', ?)`,
			id, tool, projectID, day(-1))
		if err != nil {
			t.Fatal(err)
		}
	}
	insertSession("s-cc-a", "claude-code", pidA)
	insertSession("s-cx-a", "codex", pidA)
	insertSession("s-cc-b", "claude-code", pidB)

	insertEvent := func(sessionID, ts string) {
		t.Helper()
		_, err := database.ExecContext(ctx,
			`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, tokens_read, tokens_written)
			 VALUES (?, 'proxy', ?, 'claude-opus-4-8', 'hit', 100, 0)`,
			sessionID, ts)
		if err != nil {
			t.Fatal(err)
		}
	}
	insertEvent("s-cc-a", day(-2))   // claude-code, project A, 2 days ago
	insertEvent("s-cc-a", day(-40))  // claude-code, project A, 40 days ago
	insertEvent("s-cx-a", day(-3))   // codex, project A, 3 days ago
	insertEvent("s-cc-b", day(-1))   // claude-code, project B, 1 day ago
	insertEvent("s-cc-b", day(-100)) // claude-code, project B, 100 days ago

	cases := []struct {
		name string
		q    cacheOverviewQuery
		want int
	}{
		{"no filter — full corpus", cacheOverviewQuery{}, 5},
		{"days=7 only", cacheOverviewQuery{Days: 7}, 3},
		{"days=7 + offset=7 (events 2–14d ago excluded if <2d, included if 2–14d)", cacheOverviewQuery{Days: 7, PeriodOffsetDays: 7}, 0},
		{"days=30 + offset=30 (40d-old event sits in [30d, 60d) window)", cacheOverviewQuery{Days: 30, PeriodOffsetDays: 30}, 1},
		{"days=30 (excludes 40+100 day-old events)", cacheOverviewQuery{Days: 30}, 3},
		{"tool=claude-code", cacheOverviewQuery{Tool: "claude-code"}, 4},
		{"tool=codex", cacheOverviewQuery{Tool: "codex"}, 1},
		{"project=/repo/a", cacheOverviewQuery{Project: "/repo/a"}, 3},
		{"project=/repo/b", cacheOverviewQuery{Project: "/repo/b"}, 2},
		{"days=7 AND tool=claude-code AND project=/repo/a", cacheOverviewQuery{Days: 7, Tool: "claude-code", Project: "/repo/a"}, 1},
		{"project=/repo/nonexistent", cacheOverviewQuery{Project: "/repo/nonexistent"}, 0},
	}
	// Sub-tests share the DB and the parent's defer — do NOT mark them
	// parallel or the parent returns + Close() races subtests.
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadOverviewEvents(ctx, database, tc.q)
			if err != nil {
				t.Fatalf("loadOverviewEvents: %v", err)
			}
			if len(got) != tc.want {
				t.Errorf("filter %+v → %d events, want %d", tc.q, len(got), tc.want)
			}
		})
	}
}

// TestLoadCacheEvents_PagesAndFilters seeds a few events across
// two sessions + projects and confirms pagination + filter
// scope hold. Order is by id DESC (newest-first) so the front-
// end can read insertion order directly.
func TestLoadCacheEvents_PagesAndFilters(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := openTestDB(ctx, db.Options{Path: filepath.Join(t.TempDir(), "ev.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	var pidA, pidB int64
	if err := database.QueryRowContext(
		ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/r/a', '2026-06-09T00:00:00Z') RETURNING id`,
	).Scan(&pidA); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(
		ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/r/b', '2026-06-09T00:00:00Z') RETURNING id`,
	).Scan(&pidB); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(
		ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at) VALUES ('sA', 'claude-code', ?, 'm', '2026-06-09T00:00:00Z'), ('sB', 'codex', ?, 'm', '2026-06-09T00:00:00Z')`,
		pidA, pidB,
	); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := database.ExecContext(
			ctx,
			`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, tokens_read, tokens_written)
			 VALUES ('sA', 'proxy', '2026-06-09T00:00:00Z', 'm', 'hit', 100, 0)`,
		); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := database.ExecContext(
			ctx,
			`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, tokens_read, tokens_written)
			 VALUES ('sB', 'transcript', '2026-06-09T00:00:00Z', 'm', 'hit', 200, 0)`,
		); err != nil {
			t.Fatal(err)
		}
	}

	rows, total, err := loadCacheEvents(ctx, database, cacheOverviewQuery{}, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 8 {
		t.Errorf("total = %d, want 8", total)
	}
	if len(rows) != 8 {
		t.Errorf("rows = %d, want 8", len(rows))
	}
	// Newest first → IDs DESC.
	for i := 0; i < len(rows)-1; i++ {
		if rows[i].ID < rows[i+1].ID {
			t.Errorf("rows not DESC by id: %d %d", rows[i].ID, rows[i+1].ID)
		}
	}

	// Pagination.
	page1, total, err := loadCacheEvents(ctx, database, cacheOverviewQuery{}, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	page2, _, _ := loadCacheEvents(ctx, database, cacheOverviewQuery{}, 3, 3)
	if total != 8 || len(page1) != 3 || len(page2) != 3 {
		t.Errorf("paging mismatch: total=%d page1=%d page2=%d", total, len(page1), len(page2))
	}

	// Tool filter scopes to codex (sB only, 3 events).
	rows, total, err = loadCacheEvents(ctx, database, cacheOverviewQuery{Tool: "codex"}, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(rows) != 3 {
		t.Errorf("tool filter mismatch: total=%d rows=%d", total, len(rows))
	}
}

// TestLoadCacheEntryStates_GroupsByState seeds cache_entries rows
// in three different states and confirms the histogram groups
// cleanly with the total summed correctly.
func TestLoadCacheEntryStates_GroupsByState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := openTestDB(ctx, db.Options{Path: filepath.Join(t.TempDir(), "es.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	insert := func(state string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := database.ExecContext(
				ctx,
				`INSERT INTO cache_entries (created_at, last_refresh_at, expires_at, model, cache_scope, prefix_hash, state, token_count, tier)
				 VALUES (?, ?, ?, 'm', 'default', ?, ?, 100, 'proxy')`,
				"2026-06-09T00:00:00Z",
				"2026-06-09T00:00:00Z",
				"2026-06-09T01:00:00Z",
				fmt.Sprintf("%s-%d", state, i),
				state,
			); err != nil {
				t.Fatal(err)
			}
		}
	}
	insert("live", 5)
	insert("unverified", 2)
	insert("expired", 1)

	rows, total, err := loadCacheEntryStates(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	if total != 8 {
		t.Errorf("total = %d, want 8", total)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	// Alphabetical order: expired, live, unverified.
	got := map[string]int64{}
	for _, r := range rows {
		got[r.State] = r.Count
	}
	if got["live"] != 5 || got["unverified"] != 2 || got["expired"] != 1 {
		t.Errorf("state breakdown mismatch: %+v", got)
	}
	if rows[0].State != "expired" {
		t.Errorf("rows[0].State = %q, want expired (alphabetical first)", rows[0].State)
	}
}

// TestLoadCacheHealthSummary_HeadlineSignals seeds a corpus that
// exercises every WARN path the dashboard surface reads: a
// dominant non-baseline cause, an inconsistent rewrite (read >>
// write), a bucket-mismatch (predicted=hit observed=write), and
// a non-baseline mispredict. Confirms the slim summary the tile +
// banner consume matches the cache-health CLI's math.
func TestLoadCacheHealthSummary_HeadlineSignals(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := openTestDB(ctx, db.Options{Path: filepath.Join(t.TempDir(), "h.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	insert := func(kind, cause, predicted string, read, written int64) {
		t.Helper()
		_, err := database.ExecContext(ctx,
			`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, cause, predicted_kind, tokens_read, tokens_written)
			 VALUES ('s', 'proxy', '2026-06-09T00:00:00Z', 'claude-opus-4-8', ?, ?, ?, ?, ?)`,
			kind, cause, predicted, read, written)
		if err != nil {
			t.Fatal(err)
		}
	}
	// 16 system_changed events — dominant cause once we set the
	// rest of the corpus up. Each is an invalidation_rewrite with
	// predicted=hit, so each also fires BucketMispredicts.
	for i := 0; i < 16; i++ {
		insert("invalidation_rewrite", "system_changed", "hit", 100, 50)
	}
	// 1 hit event so the corpus has a baseline non-mispredict.
	insert("hit", "suffix_growth", "hit", 1000, 0)
	// 1 inconsistent rewrite: read=900 vs write=100 (9:1 > 3:1)
	insert("expiry_rewrite", "ttl_expired", "hit", 900, 100)
	// 1 mispredict (non-zero usage → counted in numerator AND
	// denominator per cachetrack.MispredictRateGraded post-C9 fix).
	insert("mispredict", "unknown", "hit", 50, 0)

	summary, err := loadCacheHealthSummary(ctx, database)
	if err != nil {
		t.Fatal(err)
	}

	// Denominator: 16 invalidation_rewrite + 1 hit + 1 expiry_rewrite
	// + 1 mispredict = 19 graded (reanchor / below_min / compaction_reset
	// would be excluded; we seeded none).
	if summary.GradedEvents != 19 {
		t.Errorf("GradedEvents = %d, want 19", summary.GradedEvents)
	}
	if summary.Mispredicts != 1 {
		t.Errorf("Mispredicts = %d, want 1", summary.Mispredicts)
	}
	if summary.GatePassed {
		t.Errorf("GatePassed should be false (19 events < 200 min)")
	}
	// All 17 rewrite events had predicted=hit observed!=hit → bucket mismatch.
	if summary.BucketMispredicts != 17 {
		t.Errorf("BucketMispredicts = %d, want 17", summary.BucketMispredicts)
	}
	// expiry_rewrite (900,100) ratio = 9 > defaultMaxRewriteRR=3 → 1 inconsistent
	if summary.InconsistentRewriteCount != 1 {
		t.Errorf("InconsistentRewriteCount = %d, want 1", summary.InconsistentRewriteCount)
	}
	// system_changed share = 16/19 = 0.842 > 0.80 → dominant
	if summary.DominantCause == nil {
		t.Fatalf("DominantCause not surfaced; expected system_changed at >80%% share. summary=%+v", summary)
	}
	if summary.DominantCause.Cause != "system_changed" {
		t.Errorf("DominantCause.Cause = %q, want system_changed", summary.DominantCause.Cause)
	}
	if summary.DominantCause.Count != 16 {
		t.Errorf("DominantCause.Count = %d, want 16", summary.DominantCause.Count)
	}
}

// TestLoadCacheHealthSummary_UntrackedProvider pins the new
// "we saw codex but didn't grade it" visibility surface. Seeds 3
// codex turns (openai provider) across 2 sessions + 1 anthropic
// turn over the 7-day window, plus an older codex turn (10d ago)
// that should fall outside. Confirms the counters land where
// the Cache page banner expects them.
func TestLoadCacheHealthSummary_UntrackedProvider(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := openTestDB(ctx, db.Options{Path: filepath.Join(t.TempDir(), "up.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// Seed projects + sessions so the per-tool lookup works.
	var pid int64
	if err := database.QueryRowContext(
		ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/r/x', '2026-06-09T00:00:00Z') RETURNING id`,
	).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"s-codex-1", "s-codex-2", "s-claude-1"} {
		tool := "codex"
		if sid == "s-claude-1" {
			tool = "claude-code"
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO sessions (id, tool, project_id, model, started_at) VALUES (?, ?, ?, ?, '2026-06-09T00:00:00Z')`,
			sid, tool, pid, "m"); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now().UTC()
	insertAPITurn := func(sid, provider string, offset time.Duration) {
		t.Helper()
		ts := now.Add(-offset).Format(time.RFC3339Nano)
		if _, err := database.ExecContext(ctx,
			`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model,
				input_tokens, output_tokens) VALUES (?, ?, ?, ?, 'm', 100, 50)`,
			sid, pid, ts, provider); err != nil {
			t.Fatal(err)
		}
	}
	insertAPITurn("s-codex-1", "openai", 1*time.Hour)
	insertAPITurn("s-codex-1", "openai", 2*time.Hour)
	insertAPITurn("s-codex-2", "openai", 3*time.Hour)
	insertAPITurn("s-claude-1", "anthropic", 4*time.Hour) // excluded
	insertAPITurn("s-codex-1", "openai", 10*24*time.Hour) // outside 7d window

	summary, err := loadCacheHealthSummary(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	if summary.UntrackedProviderTurns != 3 {
		t.Errorf("UntrackedProviderTurns = %d, want 3 (codex turns in last 7d; anthropic + 10d-old excluded)", summary.UntrackedProviderTurns)
	}
	if summary.UntrackedProviderSessions != 2 {
		t.Errorf("UntrackedProviderSessions = %d, want 2", summary.UntrackedProviderSessions)
	}
	if summary.UntrackedProviderTopTool != "codex" {
		t.Errorf("UntrackedProviderTopTool = %q, want codex", summary.UntrackedProviderTopTool)
	}
}

// TestLoadCacheTimeseries_BucketsByDay seeds events across three
// distinct dates and confirms loadCacheTimeseries buckets cleanly
// by ISO date, sums read/written tokens, counts events, and
// surfaces rewrite_count from the non-baseline kinds. Honors the
// same days / tool / project filter shape as loadOverviewEvents.
func TestLoadCacheTimeseries_BucketsByDay(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := openTestDB(ctx, db.Options{Path: filepath.Join(t.TempDir(), "ts.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	var pid int64
	if err := database.QueryRowContext(
		ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/repo/x', '2026-06-09T00:00:00Z') RETURNING id`,
	).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(
		ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at) VALUES ('s1','claude-code',?,'claude-opus-4-8','2026-06-09T00:00:00Z')`,
		pid,
	); err != nil {
		t.Fatal(err)
	}

	insert := func(kind, ts string, read, written int64) {
		t.Helper()
		_, err := database.ExecContext(ctx,
			`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, tokens_read, tokens_written)
			 VALUES ('s1', 'proxy', ?, 'claude-opus-4-8', ?, ?, ?)`,
			ts, kind, read, written)
		if err != nil {
			t.Fatal(err)
		}
	}
	// Day 1: 2 hits + 1 write
	insert("hit", "2026-06-07T10:00:00Z", 1000, 0)
	insert("hit", "2026-06-07T11:00:00Z", 2000, 0)
	insert("write", "2026-06-07T12:00:00Z", 1500, 500)
	// Day 2: 1 hit + 1 invalidation_rewrite
	insert("hit", "2026-06-08T10:00:00Z", 800, 0)
	insert("invalidation_rewrite", "2026-06-08T11:00:00Z", 0, 4000)
	// Day 3: 1 expiry_rewrite
	insert("expiry_rewrite", "2026-06-09T10:00:00Z", 0, 3000)

	got, err := loadCacheTimeseries(ctx, database, cacheOverviewQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d buckets, want 3", len(got))
	}

	want := []CacheTimeseriesPoint{
		{Bucket: "2026-06-07", ReadTokens: 4500, WrittenTokens: 500, EventCount: 3, RewriteCount: 0},
		{Bucket: "2026-06-08", ReadTokens: 800, WrittenTokens: 4000, EventCount: 2, RewriteCount: 1},
		{Bucket: "2026-06-09", ReadTokens: 0, WrittenTokens: 3000, EventCount: 1, RewriteCount: 1},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("bucket[%d]: got %+v, want %+v", i, got[i], w)
		}
	}

	// Project filter zeroes the corpus when no match.
	filtered, err := loadCacheTimeseries(ctx, database, cacheOverviewQuery{Project: "/repo/nonexistent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 0 {
		t.Errorf("project-mismatch filter → %d buckets, want 0", len(filtered))
	}
}

// TestLoadCacheHealthSummary_ImplicitCache pins the §15.3 separate
// surface: implicit-cache events tallied separately, the
// consistency rate computed via cachetrack.ImplicitCacheConsistency,
// the prefix-churn rate as hits / (hits + misses). The Anthropic
// gate (Rate / Mispredicts / GradedEvents) MUST stay byte-identical
// to what an Anthropic-only seed would produce.
func TestLoadCacheHealthSummary_ImplicitCache(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := openTestDB(ctx, db.Options{Path: filepath.Join(t.TempDir(), "impl.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	insert := func(kind, cause, predicted string, read, written int64) {
		t.Helper()
		_, err := database.ExecContext(ctx,
			`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, cause, predicted_kind, tokens_read, tokens_written)
			 VALUES ('s', 'proxy', '2026-06-10T00:00:00Z', 'gpt-5', ?, ?, ?, ?, ?)`,
			kind, cause, predicted, read, written)
		if err != nil {
			t.Fatal(err)
		}
	}

	// 3 implicit_hit events (predicted=implicit_hit — consistent).
	for i := 0; i < 3; i++ {
		insert("implicit_hit", "implicit_hit", "implicit_hit", 4096, 0)
	}
	// 1 implicit_hit where prediction was below_min (inconsistent —
	// the prefix grew past min before the engine knew).
	insert("implicit_hit", "implicit_hit", "below_min", 4096, 0)
	// 1 implicit_miss (predicted=implicit_hit — inconsistent).
	insert("implicit_miss", "prefix_churn", "implicit_hit", 0, 0)
	// 1 implicit_write bootstrap (excluded from consistency graded).
	insert("implicit_write", "reanchor", "implicit_write", 0, 0)
	// 1 Anthropic hit so the gate has Anthropic data to grade.
	insert("hit", "suffix_growth", "hit", 1000, 0)

	summary, err := loadCacheHealthSummary(ctx, database)
	if err != nil {
		t.Fatal(err)
	}

	// §15.3 implicit-cache surface.
	if summary.ImplicitCacheEvents != 6 {
		t.Errorf("ImplicitCacheEvents = %d, want 6", summary.ImplicitCacheEvents)
	}
	if summary.ImplicitCacheHits != 4 {
		t.Errorf("ImplicitCacheHits = %d, want 4", summary.ImplicitCacheHits)
	}
	if summary.ImplicitCacheMisses != 1 {
		t.Errorf("ImplicitCacheMisses = %d, want 1", summary.ImplicitCacheMisses)
	}
	if summary.ImplicitCacheWrites != 1 {
		t.Errorf("ImplicitCacheWrites = %d, want 1", summary.ImplicitCacheWrites)
	}
	// Consistency graded: 5 (the bootstrap implicit_write is excluded
	// per the cachetrack metric's reanchor-shape skip). Consistent: 3
	// (the 3 implicit_hit/predicted=implicit_hit rows). Rate = 3/5 = 0.6.
	if summary.ImplicitCacheConsistencyDenom != 5 {
		t.Errorf("ImplicitCacheConsistencyDenom = %d, want 5", summary.ImplicitCacheConsistencyDenom)
	}
	if summary.ImplicitCacheConsistencyRate != 0.6 {
		t.Errorf("ImplicitCacheConsistencyRate = %v, want 0.6", summary.ImplicitCacheConsistencyRate)
	}
	// Prefix-churn: hits/(hits+misses) = 4/(4+1) = 0.8.
	if summary.ImplicitCachePrefixChurnRate != 0.8 {
		t.Errorf("ImplicitCachePrefixChurnRate = %v, want 0.8", summary.ImplicitCachePrefixChurnRate)
	}

	// §5 guardrail at the dashboard layer: the Anthropic gate
	// sees ONLY the 1 anthropic hit event. Implicit events MUST
	// NOT enter GradedEvents / Mispredicts / Rate / BucketMispredicts.
	if summary.GradedEvents != 1 {
		t.Errorf("GradedEvents = %d, want 1 (the lone anthropic hit) — implicit events leaked into the gate", summary.GradedEvents)
	}
	if summary.Mispredicts != 0 {
		t.Errorf("Mispredicts = %d, want 0", summary.Mispredicts)
	}
	if summary.Rate != 0.0 {
		t.Errorf("Rate = %v, want 0.0", summary.Rate)
	}
	if summary.BucketMispredicts != 0 {
		t.Errorf("BucketMispredicts = %d, want 0 — implicit predicted_kind mismatches MUST NOT count against the Anthropic G2 gate", summary.BucketMispredicts)
	}
}

// TestLoadSessionCacheEvents_ZeroUsageAndCostDelta pins two things the
// per-event loader is responsible for at the DB boundary: the ZeroUsage flag
// is cachetrack.IsZeroUsage (a mispredict with a zero token pair — a 0/0 hit
// is NOT vacant), and the nullable cost_delta_usd is carried through as a
// pointer (nil when the column is NULL, the value when set).
func TestLoadSessionCacheEvents_ZeroUsageAndCostDelta(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := openTestDB(ctx, db.Options{Path: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	// A 0/0 hit (NULL cost delta), a 0/0 mispredict (NULL cost delta), and a
	// write carrying a real cost delta.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, cause, tokens_read, tokens_written)
		 VALUES ('s1', 'proxy', '2026-06-09T00:00:00Z', 'm', 'hit', 'suffix_growth', 0, 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, cause, tokens_read, tokens_written)
		 VALUES ('s1', 'proxy', '2026-06-09T00:00:10Z', 'm', 'mispredict', 'unknown', 0, 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, cause, tokens_read, tokens_written, cost_delta_usd)
		 VALUES ('s1', 'proxy', '2026-06-09T00:00:20Z', 'm', 'invalidation_rewrite', 'system_changed', 0, 8000, 0.15)`); err != nil {
		t.Fatal(err)
	}

	events, err := loadSessionCacheEvents(ctx, database, "s1")
	if err != nil {
		t.Fatalf("loadSessionCacheEvents: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("events = %d, want 3", len(events))
	}
	// [0] hit 0/0 — NOT vacant, NULL cost delta.
	if events[0].Kind != "hit" || events[0].ZeroUsage {
		t.Errorf("event[0] = %+v, want a hit with ZeroUsage=false (a 0/0 hit is a real event)", events[0])
	}
	if events[0].CostDeltaUSD != nil {
		t.Errorf("event[0].CostDeltaUSD = %v, want nil (NULL column)", *events[0].CostDeltaUSD)
	}
	// [1] mispredict 0/0 — vacant.
	if events[1].Kind != "mispredict" || !events[1].ZeroUsage {
		t.Errorf("event[1] = %+v, want a mispredict with ZeroUsage=true", events[1])
	}
	// [2] rewrite with a real cost delta — carried through as a non-nil 0.15.
	if events[2].CostDeltaUSD == nil || *events[2].CostDeltaUSD < 0.15-1e-9 || *events[2].CostDeltaUSD > 0.15+1e-9 {
		t.Errorf("event[2].CostDeltaUSD = %v, want a non-nil 0.15", events[2].CostDeltaUSD)
	}
	if events[2].ZeroUsage {
		t.Errorf("event[2] rewrite must not be ZeroUsage")
	}

	// The efficiency tile folds the non-baseline positive delta.
	eff := buildCacheEfficiency(events)
	if eff.AvoidableUSD < 0.15-1e-9 || eff.AvoidableUSD > 0.15+1e-9 {
		t.Errorf("AvoidableUSD = %v, want 0.15 (the rewrite's delta; the hit/mispredict carry none)", eff.AvoidableUSD)
	}
}
