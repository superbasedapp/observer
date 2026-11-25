package dashboard

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/intelligence/costseries"
	"github.com/marmutapp/superbased-observer/internal/modelfilter"
	"github.com/marmutapp/superbased-observer/internal/timebucket"
)

// lossyEvictedBytesByBucket sums, per spec bucket, the original_bytes that
// lossy-eviction mechanisms (drop; see lossyEvictionMechanismList — the
// ONE owner) removed. Those bytes shrink a turn's
// compression_compressed_bytes and therefore inflate the turn-level
// SavedBytesSigned, but they are evicted content (recoverable only via
// the search_past_outputs / stash markers), not a compression saving.
// The since/until + tool/project filters mirror the cost-engine window
// so the subtraction only nets bytes attributable to the same rows.
// Keys are spec.Key bucket keys (the same keys the cost engine's
// BucketKey produces).
func (s *Server) lossyEvictedBytesByBucket(ctx context.Context, spec timebucket.Spec, since, until time.Time, tool, project, model string) (map[string]int64, error) {
	lossy := dashapi.LossyEvictionMechanismList()
	if len(lossy) == 0 {
		return map[string]int64{}, nil
	}
	slot := spec.Slot()
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(lossy)), ",")
	where := []string{"ce.mechanism IN (" + placeholders + ")", "ce.timestamp >= ?"}
	args := []any{}
	for _, m := range lossy {
		args = append(args, m)
	}
	args = append(args, since.Format(time.RFC3339Nano))
	if !until.IsZero() {
		where = append(where, "ce.timestamp < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if project != "" {
		where = append(where, "at.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	if tool != "" {
		where = append(where, "(SELECT tool FROM sessions WHERE id = at.session_id) = ?")
		args = append(args, tool)
	}
	if frag, margs := modelfilter.RowIs("at.model", model); frag != "" {
		where = append(where, frag)
		args = append(args, margs...)
	}
	rows, err := s.db().QueryContext(ctx, //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		//nolint:gosec // G202: SQL structure (the bucket expression is rendered by internal/timebucket from code constants; WHERE fragments + the IN placeholder list likewise); all values are bound via ? args.
		`SELECT `+slot.SQLiteExpr("ce.timestamp")+` AS bucket, COALESCE(SUM(ce.original_bytes), 0)
		 FROM compression_events ce
		 LEFT JOIN api_turns at ON at.id = ce.api_turn_id
		 WHERE `+strings.Join(where, " AND ")+`
		 GROUP BY bucket`,
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var label sql.NullInt64
		var evicted int64
		if err := rows.Scan(&label, &evicted); err != nil {
			return nil, err
		}
		if b, ok := slot.IndexBucket(label.Int64, label.Valid); ok {
			out[spec.Key(b)] += evicted
		}
	}
	return out, rows.Err()
}

// handleTimeseriesCost serves /api/timeseries/cost — one point per bucket
// (gran=auto|5m|1h|1d|1w, tz=<IANA>; legacy bucket=day|hour) with token
// totals, cost and the compression-savings estimates. EVERY granularity
// comes from the cost engine (GroupByDay + a timebucket BucketKey), so hour
// and day views of one window read the same substrate (proxy ∪ JSONL,
// deduped) and the same per-row pricing and their totals agree. The grid is
// zero-filled; each point carries `t` (bucket start, epoch ms).
func (s *Server) handleTimeseriesCost(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	since, until := windowRange(r, 30, 1, 36500)
	spec, err := bucketSpec(r, since, until)
	if err != nil {
		writeBucketErr(w, err)
		return
	}

	type point struct {
		Bucket                        string  `json:"bucket"`
		T                             int64   `json:"t"`
		Input                         int64   `json:"input"`
		Output                        int64   `json:"output"`
		CacheRead                     int64   `json:"cache_read"`
		CacheCreation                 int64   `json:"cache_creation"`
		CostUSD                       float64 `json:"cost_usd"`
		TurnCount                     int     `json:"turn_count"`
		CompBytesSaved                int64   `json:"compression_bytes_saved"`
		CompTokensSaved               int64   `json:"compression_tokens_saved_est"`
		CompCostUSDSaved              float64 `json:"compression_cost_saved_usd_est"`
		CompCostUSDSavedInputTier     float64 `json:"compression_cost_saved_usd_est_input_tier"`
		CompCostUSDSavedCacheReadTier float64 `json:"compression_cost_saved_usd_est_cache_read_tier"`
		CompTurns                     int     `json:"compression_turns"`
		// CompEvictedBytes is the per-bucket byte volume that lossy-eviction
		// mechanisms removed. It has ALREADY been subtracted out of
		// CompBytesSaved / CompTokensSaved / the CompCostUSD* fields (so
		// those report genuine, retrievable compression only) and is
		// surfaced here additively so the UI can show eviction without
		// conflating it with savings.
		CompEvictedBytes int64 `json:"compression_evicted_bytes"`
	}

	// Lean on the cost engine (through costseries, the one owner shared
	// with `observer chart`) so pricing stays consistent with /api/cost.
	buckets, err := costseries.Cost(r.Context(), s.opts.CostEngine, s.db(), costseries.Query{
		Spec: spec, Days: days, Since: since, Until: until,
		Tool: tool, Project: project, Model: modelParam(r),
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	// Lossy-eviction bytes (drops) shrink a turn's compressed_bytes and
	// so inflate SavedBytesSigned; subtract them per bucket so the cost
	// timeseries reports genuine, retrievable compression only. Same
	// window/tool/project filters as the cost summary above.
	evictedByBucket, err := s.lossyEvictedBytesByBucket(r.Context(), spec, since, until, tool, project, modelParam(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	series := make([]point, 0, len(buckets))
	for _, b := range buckets {
		if !b.HasData {
			series = append(series, point{Bucket: b.Key, T: millis(b.T)})
			continue
		}
		row := b.Row
		gross := row.Compression.SavedBytesSigned()
		evicted := evictedByBucket[row.Key]
		bytesSaved := gross
		tokensSaved := row.Compression.TokensSavedEst
		usdSaved := row.Compression.CostSavedUSDEst
		usdInputTier := row.Compression.CostSavedUSDEstInputTier
		usdCacheTier := row.Compression.CostSavedUSDEstCacheReadTier
		if gross > 0 && evicted > 0 {
			net := gross - evicted
			if net < 0 {
				net = 0
			}
			// Tokens/USD are linear in saved bytes, so scale the
			// cost-engine estimates by the net/gross ratio rather than
			// re-deriving pricing here (keeps the cost engine the one
			// owner of the byte→token→USD conversion).
			factor := float64(net) / float64(gross)
			bytesSaved = net
			tokensSaved = int64(float64(tokensSaved) * factor)
			usdSaved *= factor
			usdInputTier *= factor
			usdCacheTier *= factor
		}
		series = append(series, point{
			Bucket:                        row.Key,
			T:                             millis(b.T),
			Input:                         row.Tokens.Input,
			Output:                        row.Tokens.Output,
			CacheRead:                     row.Tokens.CacheRead,
			CacheCreation:                 row.Tokens.CacheCreation,
			CostUSD:                       row.CostUSD,
			TurnCount:                     row.TurnCount,
			CompBytesSaved:                bytesSaved,
			CompTokensSaved:               tokensSaved,
			CompCostUSDSaved:              usdSaved,
			CompCostUSDSavedInputTier:     usdInputTier,
			CompCostUSDSavedCacheReadTier: usdCacheTier,
			CompTurns:                     row.Compression.Turns,
			CompEvictedBytes:              evicted,
		})
	}
	writeJSON(w, withBucketMeta(spec, map[string]any{
		"metric": "cost",
		"days":   days,
		"series": series,
	}))
}

// handleTimeseriesTokensByModel serves /api/timeseries/tokens-by-model
// ?days=N&project=PATH&gran=&tz=. Returns one point per (bucket, model)
// pair so the Cost tab can render a stacked-bar chart of tokens per bucket
// with each model as its own series, plus `grid` (every bucket of the
// window, zero-fill order) so an empty bucket still takes its slot on the
// axis. Tokens, cost, and turn counts come from the cost engine in
// SourceAuto mode (proxy preferred, JSONL fallback) so the dedup/
// reliability semantics match /api/cost and /api/timeseries/cost exactly.
func (s *Server) handleTimeseriesTokensByModel(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	projectFilter := r.URL.Query().Get("project")
	toolFilter := r.URL.Query().Get("tool")

	type point struct {
		Bucket        string  `json:"bucket"`
		T             int64   `json:"t"`
		Model         string  `json:"model"`
		Input         int64   `json:"input"`
		Output        int64   `json:"output"`
		CacheRead     int64   `json:"cache_read"`
		CacheCreation int64   `json:"cache_creation"`
		TotalTokens   int64   `json:"total_tokens"`
		CostUSD       float64 `json:"cost_usd"`
		TurnCount     int     `json:"turn_count"`
	}

	since, until := windowRange(r, 30, 1, 36500)
	spec, err := bucketSpec(r, since, until)
	if err != nil {
		writeBucketErr(w, err)
		return
	}
	// costseries is the one owner of this series (shared with `observer
	// chart models`): SourceAuto rows, chronological then by model.
	points, grid, err := costseries.TokensByModel(r.Context(), s.opts.CostEngine, s.db(), costseries.Query{
		Spec: spec, Days: days, Since: since, Until: until,
		Tool: toolFilter, Project: projectFilter, Model: modelParam(r),
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	series := make([]point, 0, len(points))
	for _, p := range points {
		row := p.Row
		series = append(series, point{
			Bucket:        p.Bucket,
			T:             millis(p.T),
			Model:         p.Model,
			Input:         row.Tokens.Input,
			Output:        row.Tokens.Output,
			CacheRead:     row.Tokens.CacheRead,
			CacheCreation: row.Tokens.CacheCreation,
			TotalTokens:   costseries.TotalTokens(row.Tokens),
			CostUSD:       row.CostUSD,
			TurnCount:     row.TurnCount,
		})
	}
	writeJSON(w, withBucketMeta(spec, map[string]any{
		"metric": "tokens_by_model",
		"days":   days,
		"series": series,
		"grid":   gridJSON(grid),
	}))
}

// gridPoint is one entry of a multi-key response's `grid` (the zero-fill
// order a stacked chart seeds its rows from).
type gridPoint struct {
	Bucket string `json:"bucket"`
	T      int64  `json:"t"`
}

func gridJSON(slots []bucketSlot) []gridPoint {
	out := make([]gridPoint, 0, len(slots))
	for _, sl := range slots {
		out = append(out, gridPoint{Bucket: sl.Key, T: millis(sl.T)})
	}
	return out
}

// handleTimeseriesActions serves /api/timeseries/actions?days=N&gran=&tz=
// (legacy bucket=day|hour). Returns one point per bucket (zero-filled) with
// action counts (total, failed) and a per-tool breakdown so charts can
// stack by tool.
//
// Honors ?project=<root_path> to scope to a single project (mirrors the
// filter applied to /api/sessions and /api/actions). Without the
// filter, cross-project actions are summed.
func (s *Server) handleTimeseriesActions(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	since, until := windowRange(r, 30, 1, 36500)
	spec, err := bucketSpec(r, since, until)
	if err != nil {
		writeBucketErr(w, err)
		return
	}
	slot := spec.Slot()
	project := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")
	args := []any{since.Format(time.RFC3339Nano)}
	extra := ""
	if !until.IsZero() {
		extra += " AND timestamp < ?"
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if project != "" {
		extra += " AND project_id = (SELECT id FROM projects WHERE root_path = ?)"
		args = append(args, project)
	}
	if tool != "" {
		extra += " AND tool = ?"
		args = append(args, tool)
	}
	mExtra, mArgs := modelfilter.AndSessionsUsing("session_id", modelParam(r))
	extra, args = extra+mExtra, append(args, mArgs...)
	rows, err := s.db().QueryContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		//nolint:gosec // G202: SQL structure (the timebucket-rendered bucket expression and WHERE fragments) is built from code constants; all values are bound via ? args.
		`SELECT `+slot.SQLiteExpr("timestamp")+` AS bucket, tool,
		        COUNT(*),
		        SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END)
		 FROM actions
		 WHERE timestamp >= ?`+extra+`
		 GROUP BY bucket, tool`,
		args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()

	type point struct {
		Bucket   string         `json:"bucket"`
		T        int64          `json:"t"`
		Total    int            `json:"total"`
		Failures int            `json:"failures"`
		ByTool   map[string]int `json:"by_tool"`
	}
	byBucket := map[string]*point{}
	starts := map[string]time.Time{}
	for rows.Next() {
		var label sql.NullInt64
		var tool string
		var n, fails int
		if err := rows.Scan(&label, &tool, &n, &fails); err != nil {
			writeErr(w, err)
			return
		}
		b, ok := slot.IndexBucket(label.Int64, label.Valid)
		if !ok {
			continue
		}
		key := spec.Key(b)
		p, ok := byBucket[key]
		if !ok {
			p = &point{Bucket: key, ByTool: map[string]int{}}
			byBucket[key] = p
			starts[key] = b
		}
		p.Total += n
		p.Failures += fails
		p.ByTool[tool] += n
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	slots := bucketSlots(spec, starts)
	series := make([]point, 0, len(slots))
	for _, sl := range slots {
		p := byBucket[sl.Key]
		if p == nil {
			p = &point{Bucket: sl.Key, ByTool: map[string]int{}}
		}
		p.T = millis(sl.T)
		series = append(series, *p)
	}
	writeJSON(w, withBucketMeta(spec, map[string]any{
		"metric": "actions",
		"days":   days,
		"series": series,
	}))
}
