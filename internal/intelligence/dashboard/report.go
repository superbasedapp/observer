package dashboard

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// lossyEvictedBytesTotal sums original_bytes removed by lossy-eviction
// mechanisms (see lossyEvictionMechanismList — the ONE owner) over the
// [since, until) window, optionally scoped to one project. Those bytes
// inflate the turn-level compression saving but are evicted content
// (recoverable only via markers), not a compression saving, so callers
// subtract them before reporting "trimmed" bytes. The project filter
// mirrors the report's projects.root_path join.
func (s *Server) lossyEvictedBytesTotal(ctx context.Context, since, until time.Time, project string) (int64, error) {
	lossy := lossyEvictionMechanismList()
	if len(lossy) == 0 || s.db() == nil {
		return 0, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(lossy)), ",")
	where := []string{"ce.mechanism IN (" + placeholders + ")", "ce.timestamp >= ?", "ce.timestamp < ?"}
	args := make([]any, 0, len(lossy)+3)
	for _, m := range lossy {
		args = append(args, m)
	}
	args = append(args, since.Format(time.RFC3339Nano), until.Format(time.RFC3339Nano))
	if project != "" {
		where = append(where, "at.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	var evicted int64
	//nolint:gosec // G202: WHERE fragments + IN placeholder list are code constants; values bound via args.
	err := s.db().QueryRowContext(ctx,
		`SELECT COALESCE(SUM(ce.original_bytes), 0)
		 FROM compression_events ce
		 LEFT JOIN api_turns at ON at.id = ce.api_turn_id
		 WHERE `+strings.Join(where, " AND "),
		args...).Scan(&evicted)
	return evicted, err
}

// Monthly cost statement (usability arc P6.6 / review §8.2): one
// endpoint returning everything the printable statement renders —
// totals, spend by model / tool / project, savings telemetry, and the
// most expensive sessions, for one calendar month and (optionally)
// one project. The web page renders it as a clean document; printing
// to PDF is the browser's job. Read-only, computed on demand.

type reportRow struct {
	Key      string  `json:"key"`
	CostUSD  float64 `json:"cost_usd"`
	Turns    int64   `json:"turns"`
	Sessions int     `json:"sessions,omitempty"`
}

type reportSession struct {
	ID        string  `json:"id"`
	Tool      string  `json:"tool"`
	Project   string  `json:"project,omitempty"`
	StartedAt string  `json:"started_at"`
	CostUSD   float64 `json:"cost_usd"`
	Turns     int64   `json:"turns"`
}

// handleReportMonthly serves GET /api/report/monthly?month=YYYY-MM
// [&project=<root>]. month defaults to the current calendar month;
// an unparseable month is a 400.
func (s *Server) handleReportMonthly(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now().UTC()
	monthStr := r.URL.Query().Get("month")
	if monthStr == "" {
		monthStr = now.Format("2006-01")
	}
	month, err := time.Parse("2006-01", monthStr)
	if err != nil {
		http.Error(w, "month must be YYYY-MM", http.StatusBadRequest)
		return
	}
	project := r.URL.Query().Get("project")
	start := time.Date(month.Year(), month.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	startArg := start.Format(time.RFC3339Nano)
	endArg := end.Format(time.RFC3339Nano)

	resp := map[string]any{
		"month":        monthStr,
		"project":      project,
		"generated_at": now.Format(time.RFC3339),
	}
	if s.db() == nil {
		writeJSON(w, resp)
		return
	}

	// The month's spend rows: the node's deduped substrate (spendTurns —
	// the one session dedup rule, sessionmsg.DeriveVerdicts, applied by the
	// cost engine), project-scoped the way the engine scopes every surface.
	turns, err := s.spendTurns(r.Context(), start, end, "", project, nil)
	if err != nil {
		writeErr(w, err)
		return
	}
	// Tool and start time come from each row's session, so both arms bucket
	// identically (a transcript row's own tool column is not consulted).
	sessionIDs := make([]string, 0, len(turns))
	seenSession := map[string]bool{}
	for _, t := range turns {
		if t.SessionID != "" && !seenSession[t.SessionID] {
			seenSession[t.SessionID] = true
			sessionIDs = append(sessionIDs, t.SessionID)
		}
	}
	meta, err := s.reportSessionMeta(r.Context(), sessionIDs)
	if err != nil {
		writeErr(w, err)
		return
	}
	// Compression telemetry is a property of the proxy rows alone (never
	// deduped away), so it is summed straight off api_turns.
	compSavedTotal, err := s.reportCompressionSaved(r.Context(), startArg, endArg, project)
	if err != nil {
		writeErr(w, err)
		return
	}

	type tot struct {
		cost                                 float64
		turns                                int64
		input, output, cacheRead, cacheWrite int64
		compSaved                            int64
	}
	totals := tot{compSaved: compSavedTotal}
	byModel := map[string]*reportRow{}
	byTool := map[string]*reportRow{}
	byProject := map[string]*reportRow{}
	type sessAgg struct {
		tool, project, started string
		cost                   float64
		turns                  int64
	}
	bySession := map[string]*sessAgg{}

	for _, t := range turns {
		sid, root, model, bundle := t.SessionID, t.ProjectPath, t.Model, t.Bundle
		tool, started := meta[sid].tool, meta[sid].started
		// The engine's price: a recorded cost (ground truth from the proxy
		// or JSONL backfill) always wins; a row with no recorded cost is
		// priced at the rate in force on its OWN timestamp.
		rowCost := t.CostUSD
		totals.cost += rowCost
		totals.turns++
		totals.input += bundle.Input
		totals.output += bundle.Output
		totals.cacheRead += bundle.CacheRead
		totals.cacheWrite += bundle.CacheCreation + bundle.CacheCreation1h
		bump := func(m map[string]*reportRow, key string) {
			if key == "" {
				key = "(unattributed)"
			}
			row := m[key]
			if row == nil {
				row = &reportRow{Key: key}
				m[key] = row
			}
			row.CostUSD += rowCost
			row.Turns++
		}
		bump(byModel, model)
		bump(byTool, tool)
		bump(byProject, root)
		if sid != "" {
			sa := bySession[sid]
			if sa == nil {
				sa = &sessAgg{tool: tool, project: root, started: started}
				bySession[sid] = sa
			}
			sa.cost += rowCost
			sa.turns++
		}
	}

	// Session counts per tool/project ride the per-session aggregation.
	for _, sa := range bySession {
		key := sa.tool
		if key == "" {
			key = "(unattributed)"
		}
		if row := byTool[key]; row != nil {
			row.Sessions++
		}
		key = sa.project
		if key == "" {
			key = "(unattributed)"
		}
		if row := byProject[key]; row != nil {
			row.Sessions++
		}
	}

	flat := func(m map[string]*reportRow) []reportRow {
		out := make([]reportRow, 0, len(m))
		for _, r := range m {
			out = append(out, *r)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].CostUSD > out[j].CostUSD })
		return out
	}
	topSessions := make([]reportSession, 0, len(bySession))
	for id, sa := range bySession {
		topSessions = append(topSessions, reportSession{
			ID: id, Tool: sa.tool, Project: sa.project,
			StartedAt: sa.started, CostUSD: sa.cost, Turns: sa.turns,
		})
	}
	sort.Slice(topSessions, func(i, j int) bool { return topSessions[i].CostUSD > topSessions[j].CostUSD })
	if len(topSessions) > 25 {
		topSessions = topSessions[:25]
	}

	resp["totals"] = map[string]any{
		"cost_usd": totals.cost,
		"sessions": len(bySession),
		"turns":    totals.turns,
		"tokens": map[string]int64{
			"input": totals.input, "output": totals.output,
			"cache_read": totals.cacheRead, "cache_write": totals.cacheWrite,
		},
	}
	resp["by_model"] = flat(byModel)
	resp["by_tool"] = flat(byTool)
	if project == "" {
		resp["by_project"] = flat(byProject)
	}
	// Lossy-eviction (drop) bytes inflate the turn-level compSaved because
	// dropping content shrinks compression_compressed_bytes. Subtract them
	// so "compression trimmed" reports genuine, retrievable compression
	// only, and surface the evicted volume additively (evicted content is
	// recoverable via search_past_outputs / stash markers, not a saving).
	evicted, err := s.lossyEvictedBytesTotal(r.Context(), start, end, project)
	if err != nil {
		writeErr(w, err)
		return
	}
	compTrimmed := totals.compSaved - evicted
	if compTrimmed < 0 {
		compTrimmed = 0
	}
	resp["savings"] = map[string]any{
		"compression_bytes":         compTrimmed,
		"compression_tokens":        compTrimmed / 4,
		"compression_evicted_bytes": evicted,
		"cache_read_tokens":         totals.cacheRead,
	}
	resp["top_sessions"] = topSessions
	writeJSON(w, resp)
}

// reportSessionTool is one session's tool and start time for the monthly
// report's attribution.
type reportSessionTool struct {
	tool, started string
}

// reportSessionMeta resolves tool + started_at for the given session ids,
// chunked under the SQLite bind-variable ceiling.
func (s *Server) reportSessionMeta(ctx context.Context, ids []string) (map[string]reportSessionTool, error) {
	out := make(map[string]reportSessionTool, len(ids))
	for start := 0; start < len(ids); start += cost.MaxSessionIDsPerScope {
		end := start + cost.MaxSessionIDsPerScope
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		//nolint:gosec // G202: only a ?-placeholder list is interpolated; ids bind via args.
		rows, err := s.db().QueryContext(ctx,
			`SELECT id, COALESCE(tool, ''), COALESCE(started_at, '') FROM sessions WHERE id IN (`+
				strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var m reportSessionTool
			if err := rows.Scan(&id, &m.tool, &m.started); err != nil {
				rows.Close()
				return nil, err
			}
			out[id] = m
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// reportCompressionSaved sums the proxy's compression saving (original -
// compressed bytes) over the month's non-error api_turns rows, scoped to one
// project through the row's session when project is set.
func (s *Server) reportCompressionSaved(ctx context.Context, startArg, endArg, project string) (int64, error) {
	q := `SELECT COALESCE(SUM(COALESCE(at.compression_original_bytes, 0) - COALESCE(at.compression_compressed_bytes, 0)), 0)
		FROM api_turns at
		LEFT JOIN sessions s ON s.id = at.session_id
		LEFT JOIN projects p ON p.id = s.project_id
		WHERE at.timestamp >= ? AND at.timestamp < ?
		  AND (at.error_class IS NULL OR at.error_class = '')`
	args := []any{startArg, endArg}
	if project != "" {
		q += ` AND COALESCE(p.root_path, '') = ?`
		args = append(args, project)
	}
	var saved int64
	err := s.db().QueryRowContext(ctx, q, args...).Scan(&saved)
	return saved, err
}
