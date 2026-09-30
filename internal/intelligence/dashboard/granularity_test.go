package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Chart time granularity (docs/plans/chart-time-granularity-plan-2026-09-29.md):
// per-endpoint pins that a sub-day window gets sub-day, zero-filled buckets
// (never 30 days), that hour and day totals over one day agree, that the
// viewer zone moves the bucket boundaries, and that an over-cap request is a
// typed 400.

// granFixture seeds, relative to now: an api_turn + a compression event, a
// JSONL token row, an action, a cache event and a pattern 20 minutes ago,
// and the same set 10 days ago (outside a 1h window).
func granFixture(t *testing.T) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	ctx := context.Background()
	st := store.New(database)
	root := t.TempDir()
	now := time.Now().UTC()
	for i, at := range []time.Time{now.Add(-20 * time.Minute), now.Add(-10 * 24 * time.Hour)} {
		sid := fmt.Sprintf("g%d", i)
		if _, err := st.Ingest(ctx, []models.ToolEvent{{
			SourceFile: "f", SourceEventID: "e" + sid, SessionID: sid,
			ProjectRoot: root, Timestamp: at, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		}}, nil, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.InsertAPITurn(ctx, models.APITurn{
			SessionID: sid, Timestamp: at, Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: 1000, OutputTokens: 100, CacheReadTokens: 5000,
			CompressionEvents: []models.CompressionEvent{
				{Mechanism: "json", Timestamp: at, OriginalBytes: 4000, CompressedBytes: 1000},
			},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, tokens_read, tokens_written)
			 VALUES (?, 'proxy', ?, 'claude-sonnet-4-6', 'hit', 100, 0)`, sid, at.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO project_patterns (project_id, pattern_type, pattern_data, last_reinforced_at)
			 VALUES ((SELECT id FROM projects LIMIT 1), 'hot_file', '{}', ?)`, at.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func getJSON(t *testing.T, srv *Server, url string) (int, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, url, nil))
	var got map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	return rr.Code, got
}

// timeSeriesEndpoints lists every node time-series endpoint on the shared
// bucket, with the response field holding its points and the per-point
// field that is non-zero for a bucket holding the fixture's recent row.
var timeSeriesEndpoints = []struct {
	path   string
	points string
	metric string
}{
	{"/api/timeseries/cost", "series", "turn_count"},
	{"/api/timeseries/actions", "series", "total"},
	{"/api/compression/timeseries", "series", "total_count"},
	{"/api/cache/timeseries", "series", "event_count"},
	{"/api/analysis/cache-savings-trend", "points", "cache_read_tokens"},
	{"/api/patterns/timeseries", "points", "total"},
}

// TestTimeseriesOneHourWindowIsSubDayZeroFilled pins the operator report's
// fix: a 1h window returns 5-minute buckets across that hour only (12-13,
// zero-filled), never 30 days, on every time-series endpoint.
func TestTimeseriesOneHourWindowIsSubDayZeroFilled(t *testing.T) {
	srv := granFixture(t)
	for _, ep := range timeSeriesEndpoints {
		code, got := getJSON(t, srv, ep.path+"?hours=1")
		if code != 200 {
			t.Fatalf("%s: status %d %v", ep.path, code, got)
		}
		if got["bucket"] != "5m" || got["bucket_ms"] != float64(300000) || got["tz"] != "UTC" || got["gran_auto"] != true {
			t.Errorf("%s: meta bucket=%v bucket_ms=%v tz=%v auto=%v", ep.path, got["bucket"], got["bucket_ms"], got["tz"], got["gran_auto"])
		}
		if got["since"] == "" || got["until"] == "" {
			t.Errorf("%s: since/until not echoed: %v %v", ep.path, got["since"], got["until"])
		}
		pts, _ := got[ep.points].([]any)
		if n := len(pts); n < 12 || n > 13 {
			t.Errorf("%s: %d buckets for a 1h window, want 12-13 zero-filled 5m buckets", ep.path, n)
			continue
		}
		nonZero := 0
		var prevT float64
		for i, p := range pts {
			m := p.(map[string]any)
			tv, _ := m["t"].(float64)
			if i > 0 && tv-prevT != 300000 {
				t.Errorf("%s: bucket %d is %vms after the previous, want 300000", ep.path, i, tv-prevT)
			}
			prevT = tv
			if v, _ := m[ep.metric].(float64); v > 0 {
				nonZero++
			}
		}
		if nonZero != 1 {
			t.Errorf("%s: %d non-empty buckets, want exactly the one 20-minute-old row (the 10-day-old row must be outside the window)", ep.path, nonZero)
		}
	}
	// The multi-key endpoints carry the zero-fill grid separately.
	for _, p := range []string{"/api/timeseries/tokens-by-model", "/api/analysis/trend"} {
		code, got := getJSON(t, srv, p+"?hours=1")
		if code != 200 {
			t.Fatalf("%s: status %d", p, code)
		}
		grid, _ := got["grid"].([]any)
		series, _ := got["series"].([]any)
		if got["bucket"] != "5m" || len(grid) < 12 || len(grid) > 13 || len(series) != 1 {
			t.Errorf("%s: bucket=%v grid=%d series=%d, want 5m / 12-13 / 1", p, got["bucket"], len(grid), len(series))
		}
	}
}

// TestTimeseriesHourAndDayTotalsAgree pins finding 5's fix: the hour view
// is the SAME cost-engine substrate and pricing as the day view (proxy AND
// JSONL rows), so their totals over one day are equal.
func TestTimeseriesHourAndDayTotalsAgree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	ctx := context.Background()
	st := store.New(database)
	day := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	for i, h := range []int{0, 3, 3, 11, 17, 23} {
		at := day.Add(time.Duration(h)*time.Hour + time.Duration(i)*7*time.Minute)
		if _, err := st.InsertAPITurn(ctx, models.APITurn{
			SessionID: fmt.Sprintf("p%d", i), Timestamp: at, Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: int64(1000 * (i + 1)), OutputTokens: 200, CacheReadTokens: 3000,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// JSONL-only rows (a different session, no proxy twin) - the old raw
	// api_turns hour query dropped these.
	if _, err := st.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "t.jsonl", SourceEventID: "a", SessionID: "j",
		ProjectRoot: t.TempDir(), Timestamp: day.Add(time.Hour), Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertTokenEvents(ctx, []models.TokenEvent{
		{
			SourceFile: "t.jsonl", SourceEventID: "j1", SessionID: "j", Timestamp: day.Add(5 * time.Hour), Tool: models.ToolClaudeCode,
			Model: "claude-sonnet-4-6", InputTokens: 7000, OutputTokens: 900, Source: "jsonl", Reliability: "approximate",
		},
		{
			SourceFile: "t.jsonl", SourceEventID: "j2", SessionID: "j", Timestamp: day.Add(22 * time.Hour), Tool: models.ToolClaudeCode,
			Model: "claude-sonnet-4-6", InputTokens: 3000, OutputTokens: 100, Source: "jsonl", Reliability: "approximate",
		},
	}); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	window := "since=2026-04-10T00:00:00Z&until=2026-04-11T00:00:00Z"
	type totals struct {
		cost                 float64
		in, out, read, turns float64
		buckets              int
	}
	sum := func(gran string) totals {
		code, got := getJSON(t, srv, "/api/timeseries/cost?"+window+"&gran="+gran)
		if code != 200 {
			t.Fatalf("gran=%s: status %d %v", gran, code, got)
		}
		var tt totals
		for _, p := range got["series"].([]any) {
			m := p.(map[string]any)
			tt.cost += m["cost_usd"].(float64)
			tt.in += m["input"].(float64)
			tt.out += m["output"].(float64)
			tt.read += m["cache_read"].(float64)
			tt.turns += m["turn_count"].(float64)
			tt.buckets++
		}
		return tt
	}
	d, h, m5 := sum("1d"), sum("1h"), sum("5m")
	if d.buckets != 1 || h.buckets != 24 || m5.buckets != 288 {
		t.Errorf("buckets: day=%d hour=%d 5m=%d, want 1/24/288", d.buckets, h.buckets, m5.buckets)
	}
	if d.turns != 8 || d.cost <= 0 {
		t.Fatalf("day totals look wrong: %+v", d)
	}
	for _, other := range []totals{h, m5} {
		if math.Abs(other.cost-d.cost) > 1e-9 || other.in != d.in || other.out != d.out || other.read != d.read || other.turns != d.turns {
			t.Errorf("sub-day totals %+v != day totals %+v", other, d)
		}
	}
}

// TestTimeseriesViewerZoneShiftsBuckets pins viewer-local buckets: a row at
// 20:00Z is on the NEXT calendar day in IST (+5:30), and IST hour buckets
// start at :30 UTC.
func TestTimeseriesViewerZoneShiftsBuckets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	at := time.Date(2026, 4, 10, 20, 0, 0, 0, time.UTC)
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e", SessionID: "s",
		ProjectRoot: t.TempDir(), Timestamp: at, Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	window := "since=2026-04-09T00:00:00Z&until=2026-04-13T00:00:00Z"
	nonEmpty := func(url string) []string {
		code, got := getJSON(t, srv, url)
		if code != 200 {
			t.Fatalf("%s: %d %v", url, code, got)
		}
		var keys []string
		for _, p := range got["series"].([]any) {
			m := p.(map[string]any)
			if m["total"].(float64) > 0 {
				keys = append(keys, m["bucket"].(string))
			}
		}
		return keys
	}
	if got := nonEmpty("/api/timeseries/actions?" + window + "&gran=1d"); len(got) != 1 || got[0] != "2026-04-10" {
		t.Errorf("UTC day = %v, want [2026-04-10]", got)
	}
	if got := nonEmpty("/api/timeseries/actions?" + window + "&gran=1d&tz=Asia/Kolkata"); len(got) != 1 || got[0] != "2026-04-11" {
		t.Errorf("IST day = %v, want [2026-04-11]", got)
	}
	if got := nonEmpty("/api/timeseries/actions?" + window + "&gran=1h&tz=Asia/Kolkata"); len(got) != 1 || got[0] != "2026-04-11T01:00:00+05:30" {
		t.Errorf("IST hour = %v, want [2026-04-11T01:00:00+05:30]", got)
	}
	_, got := getJSON(t, srv, "/api/timeseries/actions?"+window+"&gran=1d&tz=Not/AZone")
	if got["tz"] != "UTC" || got["tz_fallback"] != true {
		t.Errorf("unknown tz: tz=%v tz_fallback=%v, want UTC/true", got["tz"], got["tz_fallback"])
	}
	// cost-by-hour honours the zone: 20:00Z is 01:00 IST.
	_, byHour := getJSON(t, srv, "/api/analysis/cost-by-hour?"+window+"&tz=Asia/Kolkata")
	if byHour["timezone"] != "Asia/Kolkata" {
		t.Errorf("cost-by-hour timezone = %v", byHour["timezone"])
	}
}

// TestTimeseriesOverCapIsTyped400 pins "never silently coarsen".
func TestTimeseriesOverCapIsTyped400(t *testing.T) {
	srv := granFixture(t)
	for _, ep := range append([]string{"/api/timeseries/tokens-by-model", "/api/analysis/trend"}, func() []string {
		var out []string
		for _, e := range timeSeriesEndpoints {
			out = append(out, e.path)
		}
		return out
	}()...) {
		code, got := getJSON(t, srv, ep+"?days=30&gran=5m")
		if code != http.StatusBadRequest || got["code"] != "granularity" {
			t.Errorf("%s 5m over 30d: status %d body %v, want 400 code=granularity", ep, code, got)
		}
		if msg, _ := got["error"].(string); !strings.Contains(msg, "2000") {
			t.Errorf("%s: error %q does not name the cap", ep, msg)
		}
		code, _ = getJSON(t, srv, ep+"?days=30&gran=2h")
		if code != http.StatusBadRequest {
			t.Errorf("%s unknown gran: status %d, want 400", ep, code)
		}
	}
}

// TestWindowedAnalysisEndpointsHonourHours pins finding 3: endpoints that
// used to read `days` only now serve the global window (a 1h window no
// longer silently serves 30 days).
func TestWindowedAnalysisEndpointsHonourHours(t *testing.T) {
	srv := granFixture(t)
	count := func(url, field, metric string) float64 {
		code, got := getJSON(t, srv, url)
		if code != 200 {
			t.Fatalf("%s: %d %v", url, code, got)
		}
		var n float64
		for _, p := range got[field].([]any) {
			n += p.(map[string]any)[metric].(float64)
		}
		return n
	}
	if n := count("/api/analysis/cost-by-hour?hours=1", "buckets", "turn_count"); n != 1 {
		t.Errorf("cost-by-hour hours=1: %v turns, want 1 (30-day read would give 2)", n)
	}
	if n := count("/api/analysis/cost-by-dow-hour?hours=1", "cells", "turn_count"); n != 1 {
		t.Errorf("cost-by-dow-hour hours=1: %v turns, want 1", n)
	}
	if n := count("/api/analysis/cost-by-hour?days=30", "buckets", "turn_count"); n != 2 {
		t.Errorf("cost-by-hour days=30: %v turns, want 2", n)
	}
}

// TestAnalyticsCacheKeyCoversGranularity pins that the SWR analytics cache
// keys on gran / tz / bucket (they are query params, and the key is the
// canonical query), so an hour view is never served a day view's bytes.
func TestAnalyticsCacheKeyCoversGranularity(t *testing.T) {
	srv := granFixture(t)
	keys := map[string]string{}
	for _, q := range []string{"days=7", "days=7&gran=1h", "days=7&gran=1d", "days=7&gran=1h&tz=Asia/Kolkata", "days=7&bucket=hour"} {
		r := httptest.NewRequest(http.MethodGet, "/api/timeseries/cost?"+q, nil)
		k, ok := srv.analyticsCacheKey(r)
		if !ok {
			t.Fatalf("%s: not cacheable", q)
		}
		if prev, dup := keys[k]; dup {
			t.Errorf("%q and %q share a cache key", q, prev)
		}
		keys[k] = q
	}
}

// TestTimeseriesDSTDayBucketsAgreeAcrossSeries is the regression for the
// SQL offset-at-until approximation: the SQL-grouped node series (actions,
// compression, cache, patterns, and the lossy-eviction join the cost series
// nets out) used the zone offset at `until` for every row, so across a DST
// change a row near midnight landed on a different local day than the
// Go-bucketed cost series put the SAME timestamp on. Every series now
// groups by exact UTC slots re-floored in the viewer zone, so each series'
// per-bucket counts equal the cost series' turn counts.
func TestTimeseriesDSTDayBucketsAgreeAcrossSeries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	ctx := context.Background()
	st := store.New(database)
	root := t.TempDir()
	// The window starts at 2026-11-01 00:00 EDT (04:00Z) and ends at
	// 2026-11-05 00:00 EST (05:00Z); the offset at until is -5h.
	stamps := []time.Time{
		time.Date(2026, 11, 1, 4, 30, 0, 0, time.UTC), // Nov 1 00:30 EDT -> Nov 1 (at -5h: Oct 31)
		time.Date(2026, 11, 3, 3, 30, 0, 0, time.UTC), // Nov 2 22:30 EST -> Nov 2
		time.Date(2026, 11, 1, 3, 30, 0, 0, time.UTC), // Oct 31 23:30 EDT -> outside the window
		time.Date(2026, 11, 1, 5, 10, 0, 0, time.UTC), // Nov 1 01:10 EDT -> Nov 1
	}
	for i, at := range stamps {
		sid := fmt.Sprintf("s%d", i)
		if _, err := st.Ingest(ctx, []models.ToolEvent{{
			SourceFile: "f", SourceEventID: "e" + sid, SessionID: sid,
			ProjectRoot: root, Timestamp: at, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		}}, nil, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.InsertAPITurn(ctx, models.APITurn{
			SessionID: sid, Timestamp: at, Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: 1000, OutputTokens: 100,
			CompressionEvents: []models.CompressionEvent{
				{Mechanism: "drop", Timestamp: at, OriginalBytes: 500, CompressedBytes: 0},
			},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, tokens_read, tokens_written)
			 VALUES (?, 'proxy', ?, 'claude-sonnet-4-6', 'hit', 100, 0)`, sid, at.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO project_patterns (project_id, pattern_type, pattern_data, last_reinforced_at)
			 VALUES ((SELECT id FROM projects LIMIT 1), ?, '{}', ?)`, fmt.Sprintf("p%d", i), at.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	q := "?since=2026-11-01T04:00:00Z&until=2026-11-05T05:00:00Z&gran=1d&tz=America/New_York"
	byT := func(url, points, metric string) map[float64]float64 {
		code, got := getJSON(t, srv, url+q)
		if code != 200 {
			t.Fatalf("%s: status %d %v", url, code, got)
		}
		out := map[float64]float64{}
		for _, p := range got[points].([]any) {
			m := p.(map[string]any)
			if v, _ := m[metric].(float64); v != 0 {
				out[m["t"].(float64)] += v
			}
		}
		return out
	}
	cost := byT("/api/timeseries/cost", "series", "turn_count")
	want := map[float64]float64{
		float64(time.Date(2026, 11, 1, 4, 0, 0, 0, time.UTC).UnixMilli()): 2, // Nov 1 00:00 EDT
		float64(time.Date(2026, 11, 2, 5, 0, 0, 0, time.UTC).UnixMilli()): 1, // Nov 2 00:00 EST
	}
	if fmt.Sprint(cost) != fmt.Sprint(want) {
		t.Fatalf("cost turn_count by bucket = %v, want %v", cost, want)
	}
	for _, ep := range []struct{ path, points, metric string }{
		{"/api/timeseries/actions", "series", "total"},
		{"/api/compression/timeseries", "series", "total_count"},
		{"/api/cache/timeseries", "series", "event_count"},
		{"/api/patterns/timeseries", "points", "total"},
	} {
		if got := byT(ep.path, ep.points, ep.metric); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: %s by bucket = %v, want the cost series' %v", ep.path, ep.metric, got, want)
		}
	}
	// The eviction join is keyed like the cost rows: every bucket's
	// evicted bytes are its own turns' drop events.
	evicted := byT("/api/timeseries/cost", "series", "compression_evicted_bytes")
	for k, n := range want {
		if evicted[k] != 500*n {
			t.Errorf("evicted bytes at %v = %v, want %v (eviction join keyed on a different day)", k, evicted[k], 500*n)
		}
	}
}

// TestAnalysisAndCacheEndpointsHonourWindow pins that the endpoints beside
// the window-honouring charts serve the global window too: a 1h window
// never serves 30 days (analysis headline / movers / top-sessions /
// routing-suggestions) or all time (cache overview / events), while
// `days` keeps working and days=0 stays the Cache page's all-time sentinel.
func TestAnalysisAndCacheEndpointsHonourWindow(t *testing.T) {
	srv := granFixture(t)
	// An Opus session 10 days ago with a trivially small profile: the one
	// routing suggestion a 30-day read finds and a 1h read must not.
	st := store.New(srv.db())
	old := time.Now().UTC().Add(-10 * 24 * time.Hour)
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "opus-old", Timestamp: old, Provider: models.ProviderAnthropic,
		Model: "claude-opus-4-1", InputTokens: 20000, OutputTokens: 2000,
	}); err != nil {
		t.Fatal(err)
	}
	get := func(url string) map[string]any {
		t.Helper()
		code, got := getJSON(t, srv, url)
		if code != 200 {
			t.Fatalf("%s: status %d %v", url, code, got)
		}
		return got
	}
	num := func(m map[string]any, path ...string) float64 {
		var v any = m
		for _, p := range path {
			v = v.(map[string]any)[p]
		}
		f, _ := v.(float64)
		return f
	}
	list := func(m map[string]any, k string) []any { l, _ := m[k].([]any); return l }

	// Headline: the period is the window.
	h1 := num(get("/api/analysis/headline?hours=1"), "period", "cost_usd")
	h30 := num(get("/api/analysis/headline?days=30"), "period", "cost_usd")
	if h1 <= 0 || h1 >= h30 {
		t.Errorf("headline period cost hours=1 %v vs days=30 %v: the 1h period must hold only the recent turn", h1, h30)
	}
	// Movers: the current period is the window (every model is a new
	// entrant here; the 1h current spend is the recent turn only).
	entrantUSD := func(url string) float64 {
		var tot float64
		for _, e := range list(get(url), "new_entrants") {
			tot += e.(map[string]any)["current_usd"].(float64)
		}
		return tot
	}
	if m1, m30 := entrantUSD("/api/analysis/movers?hours=1"), entrantUSD("/api/analysis/movers?days=30"); m1 <= 0 || m1 >= m30 {
		t.Errorf("movers current spend hours=1 %v vs days=30 %v", m1, m30)
	}
	// Top sessions: only the session active in the window.
	if n1, n30 := len(list(get("/api/analysis/top-sessions?hours=1"), "sessions")), len(list(get("/api/analysis/top-sessions?days=30"), "sessions")); n1 != 1 || n30 != 3 {
		t.Errorf("top-sessions hours=1 = %d sessions (want 1), days=30 = %d (want 3)", n1, n30)
	}
	// Routing suggestions: the 10-day-old Opus session is outside 1h.
	if n30 := len(list(get("/api/analysis/routing-suggestions?days=30"), "suggestions")); n30 != 1 {
		t.Fatalf("routing-suggestions days=30 = %d, want the Opus session (fixture precondition)", n30)
	}
	if n1 := len(list(get("/api/analysis/routing-suggestions?hours=1"), "suggestions")); n1 != 0 {
		t.Errorf("routing-suggestions hours=1 = %d, want 0 (a 30-day read)", n1)
	}
	// Cache overview + events: 1h is the recent event only; days=0 and no
	// window param stay all time.
	for _, c := range []struct {
		q    string
		want float64
	}{{"hours=1", 1}, {"days=30", 2}, {"days=0", 2}, {"", 2}} {
		if got := num(get("/api/cache/overview?"+c.q), "global", "event_count"); got != c.want {
			t.Errorf("cache/overview?%s event_count = %v, want %v", c.q, got, c.want)
		}
		if got := num(get("/api/cache/events?"+c.q), "total"); got != c.want {
			t.Errorf("cache/events?%s total = %v, want %v", c.q, got, c.want)
		}
	}
	// A custom window (since/until) bounds both ends.
	since := time.Now().UTC().Add(-11 * 24 * time.Hour).Format(time.RFC3339)
	until := time.Now().UTC().Add(-9 * 24 * time.Hour).Format(time.RFC3339)
	if got := num(get("/api/cache/overview?since="+since+"&until="+until), "global", "event_count"); got != 1 {
		t.Errorf("cache/overview custom window event_count = %v, want the 10-day-old event only", got)
	}
}
