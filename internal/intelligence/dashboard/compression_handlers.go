package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/intelligence/learn"
	"github.com/marmutapp/superbased-observer/internal/modelfilter"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/stash"
)

// handleProjects serves /api/projects — every project root the observer
// knows about, sorted by recent activity. Used by the dashboard toolbar
// to populate the project filter so users can scope Sessions / Actions /
// Cost / Discover queries to one project root.
// handleCompressionEvents serves /api/compression/events?days=N&page=&limit=
// — paginated per-event compression detail joined back to api_turns
// for model + session context. Driven by the compression_events table
// (migration 009). Mechanism is one of json/code/logs/text/diff/html
// (per-content-type compressor) or 'drop' (low-importance message
// replaced by a marker). Honors ?mechanism= and ?model= for narrowing.
func (s *Server) handleCompressionEvents(w http.ResponseWriter, r *http.Request) {
	page := intArg(r, "page", 1, 1, 1_000_000)
	limit := intArg(r, "limit", 50, 1, 500)
	offset := (page - 1) * limit
	mechanism := r.URL.Query().Get("mechanism")
	// `model` predates the global Model filter and already meant "this
	// turn's model"; the global filter reuses the same param and grain.
	model := modelParam(r)
	project := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")
	since, until := windowRange(r, 30, 1, 36500)

	where := []string{"ce.timestamp >= ?"}
	args := []any{since.Format(time.RFC3339Nano)}
	if !until.IsZero() {
		where = append(where, "ce.timestamp < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if mechanism != "" {
		where = append(where, "ce.mechanism = ?")
		args = append(args, mechanism)
	}
	if model != "" {
		where = append(where, "at.model = ?")
		args = append(args, model)
	}
	if project != "" {
		where = append(where, "at.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	if tool != "" {
		where = append(where, "(SELECT tool FROM sessions WHERE id = at.session_id) = ?")
		args = append(args, tool)
	}
	whereClause := "WHERE " + strings.Join(where, " AND ")

	var total int
	if err := s.db().QueryRowContext(
		r.Context(),
		`SELECT COUNT(*) FROM compression_events ce
		 LEFT JOIN api_turns at ON at.id = ce.api_turn_id `+whereClause,
		args...,
	).Scan(&total); err != nil {
		writeErr(w, err)
		return
	}

	// is_subagent_runtime is derived per-row by correlating against
	// actions: an api_turn whose session_id has any sidechain (Agent
	// runtime) action within ±2 minutes of the turn's timestamp is
	// almost certainly a sub-agent's API call. EXISTS subquery on the
	// indexed (session_id, timestamp, is_sidechain) columns is fast
	// enough to compute inline at query time.
	rows, err := s.db().QueryContext(r.Context(),
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT ce.id, ce.api_turn_id, ce.timestamp, ce.mechanism,
		        ce.original_bytes, ce.compressed_bytes,
		        COALESCE(ce.msg_index, -1), COALESCE(ce.importance_score, 0),
		        COALESCE(at.model, ''), COALESCE(at.session_id, ''),
		        COALESCE(at.request_id, ''),
		        EXISTS (
		          SELECT 1 FROM actions a
		          WHERE a.session_id = at.session_id
		            AND a.is_sidechain = 1
		            AND ABS(strftime('%s', a.timestamp) - strftime('%s', ce.timestamp)) <= 120
		        ) AS is_subagent
		 FROM compression_events ce
		 LEFT JOIN api_turns at ON at.id = ce.api_turn_id
		 `+whereClause+`
		 ORDER BY ce.timestamp DESC, ce.id DESC
		 LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()

	type eventRow struct {
		ID              int64  `json:"id"`
		APITurnID       int64  `json:"api_turn_id"`
		Timestamp       string `json:"timestamp"`
		Mechanism       string `json:"mechanism"`
		OriginalBytes   int64  `json:"original_bytes"`
		CompressedBytes int64  `json:"compressed_bytes"`
		SavedBytes      int64  `json:"saved_bytes"`
		// Token estimates derived from bytes via the 4 chars/token rule
		// of thumb (matches cost.CompressionStats.TokensSavedEst).
		// Same heuristic used by the cost engine's compression rollup
		// so the dashboard's per-event view stays consistent with the
		// summary numbers above the table.
		OriginalTokensEst   int64 `json:"original_tokens_est"`
		CompressedTokensEst int64 `json:"compressed_tokens_est"`
		SavedTokensEst      int64 `json:"saved_tokens_est"`
		// SavedUSDEst is saved_tokens_est × the row's model input rate.
		// Same formula as cost.Engine.Summary's per-row CostSavedUSDEst,
		// just applied per-event. Zero when the model is unrecognized.
		SavedUSDEst     float64 `json:"saved_usd_est"`
		MsgIndex        int     `json:"msg_index"`
		ImportanceScore float64 `json:"importance_score"`
		Model           string  `json:"model"`
		SessionID       string  `json:"session_id"`
		// MessageID is the upstream Anthropic msg_xxx id (sourced from
		// api_turns.request_id — same column the proxy populates). Lets
		// the UI link compression events to the same message thread on
		// the per-message timeline modal.
		MessageID string `json:"message_id"`
		// IsSubagentRuntime is true when the api_turn that produced
		// this event came from a sub-agent runtime — derived by
		// finding any sidechain action in the same session within
		// ±2 minutes of the turn's timestamp. Surfaces as a "Source"
		// pill on the events table so users can spot which mechanism
		// activity is attributable to delegated work.
		IsSubagentRuntime bool `json:"is_subagent_runtime"`
		// Lossy marks an eviction mechanism (mechanismIsLossy). For
		// these rows OriginalBytes was EVICTED, not compressed —
		// SavedBytes/SavedTokensEst/SavedUSDEst are forced to 0 and the
		// bytes surface as EvictedBytes so the UI never renders a fake
		// "100% saved" or prices evicted content as dollars saved.
		Lossy        bool  `json:"lossy"`
		EvictedBytes int64 `json:"evicted_bytes"`
	}
	out := []eventRow{}
	for rows.Next() {
		var er eventRow
		var isSubInt int
		if err := rows.Scan(&er.ID, &er.APITurnID, &er.Timestamp, &er.Mechanism,
			&er.OriginalBytes, &er.CompressedBytes,
			&er.MsgIndex, &er.ImportanceScore,
			&er.Model, &er.SessionID, &er.MessageID, &isSubInt); err != nil {
			writeErr(w, err)
			return
		}
		er.OriginalTokensEst = er.OriginalBytes / 4
		er.CompressedTokensEst = er.CompressedBytes / 4
		if mechanismIsLossy(er.Mechanism) {
			// Evicted content: report bytes as evicted, never as saved
			// and never priced. Saved* stay at their zero value.
			er.Lossy = true
			er.EvictedBytes = er.OriginalBytes
		} else {
			er.SavedBytes = er.OriginalBytes - er.CompressedBytes
			er.SavedTokensEst = er.SavedBytes / 4
			if er.Model != "" {
				if pricing, ok := s.opts.CostEngine.Lookup(er.Model); ok && pricing.Input > 0 {
					er.SavedUSDEst = float64(er.SavedTokensEst) * pricing.Input / 1_000_000
				}
			}
		}
		er.IsSubagentRuntime = isSubInt != 0
		out = append(out, er)
	}
	writeJSON(w, map[string]any{
		"rows":  out,
		"page":  page,
		"limit": limit,
		"total": total,
	})
}

// handleCompressionByModel serves /api/compression/by-model?days=N —
// per-model rollup of compression savings. One row per (model, mechanism)
// pair with event count, original/compressed bytes, saved bytes, and a
// best-effort $ estimate computed by pricing saved_bytes/4 tokens at the
// model's input rate (same convention as handleCompressionTimeseries).
//
// Drives the Compression tab's "Per-model breakdown" table (audit §3.7
// Cp11 / §4.7 dCp3). Sorted by saved_bytes DESC so the heaviest
// compressors lead.
func (s *Server) handleCompressionByModel(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	project := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")
	since, until := windowRange(r, 30, 1, 36500)
	where := []string{"ce.timestamp >= ?"}
	args := []any{since.Format(time.RFC3339Nano)}
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
	// Model filter (turn grain): the compressed turn's own model.
	if frag, margs := modelfilter.RowIs("at.model", modelParam(r)); frag != "" {
		where = append(where, frag)
		args = append(args, margs...)
	}
	rows, err := s.db().QueryContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT COALESCE(at.model, '(unknown)') AS model,
		        ce.mechanism,
		        COUNT(*) AS events,
		        SUM(ce.original_bytes) AS orig,
		        SUM(ce.compressed_bytes) AS comp
		 FROM compression_events ce
		 LEFT JOIN api_turns at ON at.id = ce.api_turn_id
		 WHERE `+strings.Join(where, " AND ")+`
		 GROUP BY model, ce.mechanism
		 ORDER BY (SUM(ce.original_bytes) - SUM(ce.compressed_bytes)) DESC`,
		args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()

	type row struct {
		Model           string  `json:"model"`
		Mechanism       string  `json:"mechanism"`
		Events          int     `json:"events"`
		OriginalBytes   int64   `json:"original_bytes"`
		CompressedBytes int64   `json:"compressed_bytes"`
		SavedBytes      int64   `json:"saved_bytes"`
		SavedTokensEst  int64   `json:"saved_tokens_est"`
		SavedUSDEst     float64 `json:"saved_usd_est"`
		// Lossy marks an eviction mechanism (mechanismIsLossy). For
		// these rows OriginalBytes was EVICTED, not compressed:
		// SavedBytes/SavedTokensEst/SavedUSDEst are forced to 0 and the
		// bytes surface as EvictedBytes so the UI never renders them as
		// savings (or prices them as dollars saved).
		Lossy        bool  `json:"lossy"`
		EvictedBytes int64 `json:"evicted_bytes"`
	}
	out := []row{}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.Model, &r.Mechanism, &r.Events, &r.OriginalBytes, &r.CompressedBytes); err != nil {
			writeErr(w, err)
			return
		}
		if mechanismIsLossy(r.Mechanism) {
			// Evicted content has no compressed form — report it as
			// evicted and never price it as a saving. SavedBytes,
			// SavedTokensEst and SavedUSDEst stay at their zero value.
			r.Lossy = true
			r.EvictedBytes = r.OriginalBytes
			out = append(out, r)
			continue
		}
		r.SavedBytes = r.OriginalBytes - r.CompressedBytes
		// 4 bytes/token is the same lossy conversion handleCompression
		// Timeseries uses. Good enough for "savings" framing.
		r.SavedTokensEst = r.SavedBytes / 4
		if p, ok := s.opts.CostEngine.Lookup(r.Model); ok && r.SavedTokensEst > 0 {
			r.SavedUSDEst = (float64(r.SavedTokensEst) / 1_000_000) * p.Input
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"days": days,
		"rows": out,
	})
}

// handleCompressionTimeseries serves /api/compression/timeseries?days=N&gran=&tz=
// (legacy bucket=day|hour) — per-bucket (zero-filled) savings split by mechanism for the "Savings by mechanism"
// chart. Returns one point per day with by_mechanism map of
// {mechanism: {count, original_bytes, compressed_bytes, saved_bytes,
// saved_usd_est}}.
//
// Per-mechanism $ is computed by joining compression_events back to
// api_turns for model context, looking up each model's input rate via
// the cost engine, and pricing (saved_bytes / 4) tokens at that rate.
// Models without pricing contribute to bytes/tokens but not to $ —
// matches the per-model breakdown in cost.Engine.Summary.
func (s *Server) handleCompressionTimeseries(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	project := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")
	since, until := windowRange(r, 30, 1, 36500)
	spec, err := bucketSpec(r, since, until)
	if err != nil {
		writeBucketErr(w, err)
		return
	}
	slot := spec.Slot()
	where := []string{"ce.timestamp >= ?"}
	args := []any{since.Format(time.RFC3339Nano)}
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
	if frag, margs := modelfilter.RowIs("at.model", modelParam(r)); frag != "" {
		where = append(where, frag)
		args = append(args, margs...)
	}
	rows, err := s.db().QueryContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		//nolint:gosec // G202: SQL structure (the timebucket-rendered bucket expression, WHERE/JOIN/scope fragments) is built from code constants; all values are bound via ? args.
		`SELECT `+slot.SQLiteExpr("ce.timestamp")+` AS bucket,
		        ce.mechanism,
		        COALESCE(at.model, '') AS model,
		        COUNT(*),
		        COALESCE(SUM(ce.original_bytes), 0),
		        COALESCE(SUM(ce.compressed_bytes), 0)
		 FROM compression_events ce
		 LEFT JOIN api_turns at ON at.id = ce.api_turn_id
		 WHERE `+strings.Join(where, " AND ")+`
		 GROUP BY bucket, ce.mechanism, model`,
		args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	type mechStats struct {
		Count           int     `json:"count"`
		OriginalBytes   int64   `json:"original_bytes"`
		CompressedBytes int64   `json:"compressed_bytes"`
		SavedBytes      int64   `json:"saved_bytes"`
		SavedUSDEst     float64 `json:"saved_usd_est"`
		// Lossy marks an eviction mechanism (mechanismIsLossy). Its
		// bytes are reported as EvictedBytes, and SavedBytes/
		// SavedUSDEst stay 0 so the savings chart/donut and the point
		// totals never count evicted content as a saving.
		Lossy        bool  `json:"lossy"`
		EvictedBytes int64 `json:"evicted_bytes"`
	}
	type point struct {
		Bucket      string                `json:"bucket"`
		T           int64                 `json:"t"`
		ByMechanism map[string]*mechStats `json:"by_mechanism"`
		TotalSaved  int64                 `json:"total_saved_bytes"`
		TotalUSD    float64               `json:"total_saved_usd_est"`
		TotalCount  int                   `json:"total_count"`
		// TotalEvicted is the byte volume removed by lossy-eviction
		// mechanisms in this bucket — surfaced separately so the UI can
		// show it without conflating it with total_saved_bytes.
		TotalEvicted int64 `json:"total_evicted_bytes"`
	}
	idx := map[string]*point{}
	starts := map[string]time.Time{}
	for rows.Next() {
		var label sql.NullInt64
		var mech, model string
		var n int
		var orig, comp int64
		if err := rows.Scan(&label, &mech, &model, &n, &orig, &comp); err != nil {
			writeErr(w, err)
			return
		}
		bt, ok := slot.IndexBucket(label.Int64, label.Valid)
		if !ok {
			continue
		}
		b := spec.Key(bt)
		p, ok := idx[b]
		if !ok {
			p = &point{Bucket: b, ByMechanism: map[string]*mechStats{}}
			idx[b] = p
			starts[b] = bt
		}
		ms, exists := p.ByMechanism[mech]
		if !exists {
			ms = &mechStats{}
			p.ByMechanism[mech] = ms
		}
		ms.Count += n
		p.TotalCount += n
		if mechanismIsLossy(mech) {
			// Evicted content: track bytes as evicted, never as saved
			// and never priced.
			ms.Lossy = true
			ms.OriginalBytes += orig
			ms.CompressedBytes += comp
			ms.EvictedBytes += orig
			p.TotalEvicted += orig
			continue
		}
		saved := orig - comp
		// Price savings at the model's input rate (matches
		// cost.Engine.Summary's CostSavedUSDEst formula). Unknown
		// models contribute 0 to $ but still show up in bytes/tokens.
		var savedUSD float64
		if model != "" {
			if pricing, ok := s.opts.CostEngine.Lookup(model); ok && pricing.Input > 0 {
				tokens := float64(saved) / 4
				savedUSD = tokens * pricing.Input / 1_000_000
			}
		}
		ms.OriginalBytes += orig
		ms.CompressedBytes += comp
		ms.SavedBytes += saved
		ms.SavedUSDEst += savedUSD
		p.TotalSaved += saved
		p.TotalUSD += savedUSD
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	slots := bucketSlots(spec, starts)
	series := make([]point, 0, len(slots))
	for _, sl := range slots {
		p := idx[sl.Key]
		if p == nil {
			p = &point{Bucket: sl.Key, ByMechanism: map[string]*mechStats{}}
		}
		p.T = millis(sl.T)
		series = append(series, *p)
	}
	writeJSON(w, withBucketMeta(spec, map[string]any{
		"metric": "compression_events",
		"days":   days,
		"series": series,
	}))
}

// handleCompressionRetrieval serves /api/compression/retrieval?days=N —
// the K43 / Tier 3 self-learning feedback loop measurement: how many
// stashed bodies were actually retrieved and which shapes / actions
// the model returns to most often. Pairs with the G31 (CCR / stash)
// mechanism — `retrieve_rate` is the load-bearing dogfood metric for
// the strategic moat.
func (s *Server) handleCompressionRetrieval(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 7, 1, 365)
	// The global window, including a closed range's until (REVIEW-3 P3-19).
	since, until := windowRange(r, 7, 1, 365)
	days = windowSpanDays(since, until, days)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")

	model := modelParam(r)
	rep, err := learn.NewPatternMiner(s.db()).Report(r.Context(), learn.ReportOptions{
		Days: days, Since: since, Until: until, Tool: tool, Project: project, Model: model,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("retrieval report: %v", err), http.StatusInternalServerError)
		return
	}

	// Mirror the prior shape so existing JS consumers don't break.
	// retrieve_rate can exceed 1.0 when the model retrieves the same
	// sha multiple times — we surface the raw ratio and let the UI
	// render "% retrieves per stash" so > 100% reads naturally.
	type shaCount struct {
		Sha   string `json:"sha"`
		Count int    `json:"count"`
	}
	type actionCount struct {
		ActionID int64 `json:"action_id"`
		Count    int   `json:"count"`
	}
	out := struct {
		Days               int                   `json:"days"`
		StashRetrievals    int                   `json:"stash_retrievals"`
		SearchHits         int                   `json:"search_hits"`
		TotalStashes       int                   `json:"total_stashes"`
		RetrieveRate       float64               `json:"retrieve_rate"`
		TopRetrievedShas   []shaCount            `json:"top_retrieved_shas"`
		TopSearchedActions []actionCount         `json:"top_searched_actions"`
		StashedSamples     []stashedSample       `json:"stashed_samples"`
		Hints              []learn.ThresholdHint `json:"hints"`
	}{
		Days:               days,
		StashRetrievals:    rep.StashRetrievals,
		SearchHits:         rep.SearchHits,
		TotalStashes:       rep.TotalStashes,
		RetrieveRate:       rep.RetrieveRate,
		TopRetrievedShas:   make([]shaCount, 0, len(rep.TopRetrievedShas)),
		TopSearchedActions: make([]actionCount, 0, len(rep.TopSearchedActions)),
		StashedSamples:     s.loadStashedSamples(r.Context(), since, until, dashapi.SpendScope{Tool: tool, Project: project, Model: model}, rep.TopRetrievedShas),
		Hints:              rep.Hints,
	}
	if out.Hints == nil {
		out.Hints = []learn.ThresholdHint{}
	}
	for _, sc := range rep.TopRetrievedShas {
		out.TopRetrievedShas = append(out.TopRetrievedShas, shaCount{Sha: sc.Sha, Count: sc.Count})
	}
	for _, ac := range rep.TopSearchedActions {
		out.TopSearchedActions = append(out.TopSearchedActions, actionCount{ActionID: ac.ActionID, Count: ac.Count})
	}
	writeJSON(w, out)
}

// stashedSample is one entry in the "what's getting stashed" preview: a short
// scrubbed snippet of a stashed body, with how many times it was stashed and
// (when applicable) retrieved. Replaces the opaque "top retrieved SHAs" list.
type stashedSample struct {
	Sha            string `json:"sha"`
	Snippet        string `json:"snippet"`
	Bytes          int64  `json:"bytes"`
	Count          int    `json:"count"`
	RetrievedCount int    `json:"retrieved_count"`
}

// loadStashedSamples returns up to 8 recent distinct stashed bodies with a
// scrubbed content snippet, so the SROD panel shows what the proxy is actually
// offloading instead of raw SHAs. body_hash on a stash compression_event IS
// the stash sha, so we read each from the stash dir (best-effort — LRU-evicted
// shas are skipped). Returns an empty slice when no stash dir is wired or
// nothing readable remains, never an error (the panel degrades to counts).
func (s *Server) loadStashedSamples(ctx context.Context, since, until time.Time, scope dashapi.SpendScope, retrieved []learn.ShaCount) []stashedSample {
	tool, project := scope.Tool, scope.Project
	empty := []stashedSample{}
	if s.opts.StashDir == "" {
		return empty
	}
	st, err := stash.New(stash.Options{Dir: s.opts.StashDir})
	if err != nil {
		return empty
	}
	retrievedCount := make(map[string]int, len(retrieved))
	for _, x := range retrieved {
		retrievedCount[x.Sha] = x.Count
	}

	join, where := "", ""
	var args []any
	var bounds string
	if !since.IsZero() {
		bounds += " AND ce.timestamp >= ?"
		args = append(args, since.UTC().Format(time.RFC3339Nano))
	}
	if !until.IsZero() {
		bounds += " AND ce.timestamp < ?"
		args = append(args, until.UTC().Format(time.RFC3339Nano))
	}
	if tool != "" || project != "" || scope.Model != "" {
		join = ` LEFT JOIN api_turns at ON at.id = ce.api_turn_id
		         LEFT JOIN sessions ss ON ss.id = at.session_id
		         LEFT JOIN projects p ON p.id = ss.project_id`
		mWhere, mArgs := modelfilter.AndRowIs("at.model", scope.Model)
		where += mWhere
		args = append(args, mArgs...)
		if tool != "" {
			where += " AND ss.tool = ?"
			args = append(args, tool)
		}
		if project != "" {
			where += " AND p.root_path = ?"
			args = append(args, project)
		}
	}
	//nolint:gosec // G202: join/where are code-constant fragments; all values are bound via ? args.
	q := `SELECT ce.body_hash, COUNT(*), MAX(COALESCE(ce.original_bytes, 0))
	        FROM compression_events ce` + join + `
	       WHERE ce.mechanism = 'stash' AND ce.body_hash IS NOT NULL AND ce.body_hash != ''
	        ` + bounds + where + `
	       GROUP BY ce.body_hash
	       ORDER BY MAX(ce.timestamp) DESC
	       LIMIT 24`
	rows, err := s.db().QueryContext(ctx, q, args...)
	if err != nil {
		return empty
	}
	defer rows.Close()

	scr := scrub.New()
	samples := empty
	for rows.Next() {
		var sha string
		var count int
		var bytes int64
		if err := rows.Scan(&sha, &count, &bytes); err != nil {
			return samples
		}
		content, rerr := st.Read(sha)
		if rerr != nil {
			continue // evicted / missing / corrupt → skip
		}
		snip := makeStashSnippet(scr, content, 160)
		if snip == "" {
			continue
		}
		samples = append(samples, stashedSample{
			Sha:            sha,
			Snippet:        snip,
			Bytes:          bytes,
			Count:          count,
			RetrievedCount: retrievedCount[sha],
		})
		if len(samples) >= 8 {
			break
		}
	}
	return samples
}

// makeStashSnippet scrubs a stashed body and renders a single-line preview of
// at most n runes. The body is the model's raw (pre-scrub) tool output, so the
// scrub pass is load-bearing for display safety even on the local dashboard.
func makeStashSnippet(scr *scrub.Scrubber, body []byte, n int) string {
	s := string(body)
	if len(s) > 4096 {
		s = s[:4096] // bound scrub work — we only need the head
	}
	if scr != nil {
		s = scr.String(s)
	}
	s = strings.Join(strings.Fields(s), " ") // collapse newlines/runs to single spaces
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// handleCompactionEvents serves /api/compaction/events?days=N — the
// D23 / Tier 3 compaction-survival visibility surface. Counts
// compaction_events rows (one per /compact in the window), surfaces
// how many had post-compact recovery context injected, and lists the
// recent events with session_id + ghost-files-after count parsed out
// of the JSON snapshot.
func (s *Server) handleCompactionEvents(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 7, 1, 365)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	sinceT, until := windowRange(r, 7, 1, 365)
	since := sinceT.Format(time.RFC3339Nano)

	type eventRow struct {
		ID                int64  `json:"id"`
		SessionID         string `json:"session_id"`
		Timestamp         string `json:"timestamp"`
		Tool              string `json:"tool"`
		PreActionCount    int    `json:"pre_action_count"`
		InjectedAt        string `json:"injected_at,omitempty"`
		GhostFilesAfter   int    `json:"ghost_files_after_count"`
		FileSnapshotCount int    `json:"file_snapshot_count"`
	}
	out := struct {
		Days             int        `json:"days"`
		Count            int        `json:"count"`
		SessionsAffected int        `json:"sessions_affected"`
		InjectionsFired  int        `json:"injections_fired"`
		Events           []eventRow `json:"events"`
	}{Days: days, Events: []eventRow{}}

	// compaction_events has direct tool + project_id columns — no
	// joins needed for filtering. Project lookup via projects table.
	whereExtra := ""
	args := []any{since}
	if !until.IsZero() {
		whereExtra += " AND timestamp < ?"
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if tool != "" {
		whereExtra += " AND tool = ?"
		args = append(args, tool)
	}
	if project != "" {
		whereExtra += " AND project_id = (SELECT id FROM projects WHERE root_path = ?)"
		args = append(args, project)
	}
	mExtra, mArgs := modelfilter.AndSessionsUsing("session_id", modelParam(r))
	whereExtra, args = whereExtra+mExtra, append(args, mArgs...)

	_ = s.db().QueryRowContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		`SELECT COUNT(*), COUNT(DISTINCT session_id),
		        COALESCE(SUM(CASE WHEN injected_at IS NOT NULL THEN 1 ELSE 0 END), 0)
		 FROM compaction_events WHERE timestamp >= ?`+whereExtra,
		args...).Scan(&out.Count, &out.SessionsAffected, &out.InjectionsFired)

	rows, err := s.db().QueryContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT id, session_id, timestamp, COALESCE(tool, ''),
		        COALESCE(pre_action_count, 0),
		        COALESCE(injected_at, ''),
		        COALESCE(ghost_files_after, ''),
		        COALESCE(file_state_snapshot, '')
		 FROM compaction_events
		 WHERE timestamp >= ?`+whereExtra+`
		 ORDER BY timestamp DESC LIMIT 50`,
		args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var e eventRow
		var ghostsJSON, snapJSON string
		if err := rows.Scan(&e.ID, &e.SessionID, &e.Timestamp, &e.Tool,
			&e.PreActionCount, &e.InjectedAt, &ghostsJSON, &snapJSON); err != nil {
			writeErr(w, err)
			return
		}
		// Count ghost files (a JSON array of paths) without
		// unmarshalling — substring count of `","` + 1 if non-empty.
		// Cheap heuristic; defensible when the field is "[]" or empty.
		if ghostsJSON != "" && ghostsJSON != "[]" && ghostsJSON != "null" {
			var ghosts []string
			if err := json.Unmarshal([]byte(ghostsJSON), &ghosts); err == nil {
				e.GhostFilesAfter = len(ghosts)
			}
		}
		if snapJSON != "" && snapJSON != "null" {
			var snap struct {
				FileCount int `json:"file_count"`
			}
			if err := json.Unmarshal([]byte(snapJSON), &snap); err == nil {
				e.FileSnapshotCount = snap.FileCount
			}
		}
		out.Events = append(out.Events, e)
	}
	writeJSON(w, out)
}

// handleCompressionRollingCost serves /api/compression/rolling-cost?days=N
// — the D20 cost-net surface. Anthropic Haiku summary calls go directly
// to api.anthropic.com (NOT through our proxy), so api_turns doesn't
// see them. We instead read the dedicated `summary_calls` table
// populated by [messagesummary.AnthropicSummarizer] and join against
// `compression_events.mechanism = 'rolling_summary'` to estimate the
// net delta (savings on cache_creation - Haiku spend).
func (s *Server) handleCompressionRollingCost(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 7, 1, 365)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	sinceT, until := windowRange(r, 7, 1, 365)
	since := sinceT.Format(time.RFC3339Nano)

	out := struct {
		Days                     int     `json:"days"`
		SummaryCalls             int     `json:"summary_calls"`
		SummaryInputTokens       int64   `json:"summary_input_tokens"`
		SummaryOutputTokens      int64   `json:"summary_output_tokens"`
		SummaryCostUSD           float64 `json:"summary_cost_usd"`
		RollingSavingsBytes      int64   `json:"rolling_savings_bytes"`
		RollingSavingsTokensEst  int64   `json:"rolling_savings_tokens_est"`
		RollingSavingsCostUSDEst float64 `json:"rolling_savings_cost_usd_est"`
		NetDeltaUSD              float64 `json:"net_delta_usd"`
	}{Days: days}

	// Build optional tool/project filter clauses for summary_calls
	// (joins through sessions → projects) and compression_events
	// (joins through api_turns → sessions → projects).
	scJoin, scWhere, scArgs := "", "", []any{since}
	if !until.IsZero() {
		scWhere += " AND sc.timestamp < ?"
		scArgs = append(scArgs, until.Format(time.RFC3339Nano))
	}
	if tool != "" || project != "" {
		scJoin = ` LEFT JOIN sessions s ON s.id = sc.session_id
		           LEFT JOIN projects p ON p.id = s.project_id`
		if tool != "" {
			scWhere += " AND s.tool = ?"
			scArgs = append(scArgs, tool)
		}
		if project != "" {
			scWhere += " AND p.root_path = ?"
			scArgs = append(scArgs, project)
		}
	}
	// Model filter: this is a spend surface, so it narrows to the model's
	// OWN rows (D-070), never to whole sessions that used it (Sol A3-05: a
	// mixed-model session put the other models' summaries and savings under
	// the selected one). A summary call is the summarizer model's own spend
	// (summary_calls.model, the attribution the Cost page already uses); a
	// rolling_summary event belongs to the turn it compressed (at.model).
	model := modelParam(r)
	mWhere, mArgs := modelfilter.AndRowIs("sc.model", model)
	scWhere, scArgs = scWhere+mWhere, append(scArgs, mArgs...)
	_ = s.db().QueryRowContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		`SELECT COUNT(*),
		        COALESCE(SUM(sc.input_tokens), 0),
		        COALESCE(SUM(sc.output_tokens), 0),
		        COALESCE(SUM(sc.cost_usd), 0)
		 FROM summary_calls sc`+scJoin+
			` WHERE sc.timestamp >= ?`+scWhere,
		scArgs...).Scan(&out.SummaryCalls, &out.SummaryInputTokens, &out.SummaryOutputTokens, &out.SummaryCostUSD)

	ceJoin, ceWhere, ceArgs := "", "", []any{since}
	if !until.IsZero() {
		ceWhere += " AND ce.timestamp < ?"
		ceArgs = append(ceArgs, until.Format(time.RFC3339Nano))
	}
	if tool != "" || project != "" {
		ceJoin = ` LEFT JOIN sessions s ON s.id = at.session_id
		           LEFT JOIN projects p ON p.id = s.project_id`
		if tool != "" {
			ceWhere += " AND s.tool = ?"
			ceArgs = append(ceArgs, tool)
		}
		if project != "" {
			ceWhere += " AND p.root_path = ?"
			ceArgs = append(ceArgs, project)
		}
	}
	mWhere, mArgs = modelfilter.AndRowIs("at.model", model)
	ceWhere, ceArgs = ceWhere+mWhere, append(ceArgs, mArgs...)
	rows, err := s.db().QueryContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT COALESCE(at.model, ''),
		        COALESCE(SUM(ce.original_bytes - ce.compressed_bytes), 0)
		 FROM compression_events ce
		 LEFT JOIN api_turns at ON at.id = ce.api_turn_id`+ceJoin+
			` WHERE ce.mechanism = 'rolling_summary' AND ce.timestamp >= ?`+ceWhere+`
		 GROUP BY at.model`,
		ceArgs...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var model string
			var saved int64
			if err := rows.Scan(&model, &saved); err != nil {
				continue
			}
			out.RollingSavingsBytes += saved
			tokens := saved / 4
			out.RollingSavingsTokensEst += tokens
			if model != "" {
				if pricing, ok := s.opts.CostEngine.Lookup(model); ok && pricing.CacheCreation > 0 {
					// rolling_summary saves bytes that would otherwise
					// be cache_creation tokens (the conversation
					// prefix would have to be re-cached on the next
					// turn without the summary). Price at the
					// CacheCreation rate, not Input.
					out.RollingSavingsCostUSDEst += float64(tokens) * pricing.CacheCreation / 1_000_000
				}
			}
		}
	}
	out.NetDeltaUSD = out.RollingSavingsCostUSDEst - out.SummaryCostUSD
	writeJSON(w, out)
}
