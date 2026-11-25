package dashboard

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/modelfilter"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// handleModels serves /api/models?days=N — per-model breakdown over the
// window. Same shape as /api/cost but always group_by=model and JSON only.
func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	since, until := windowRange(r, 30, 1, 36500)
	summary, err := s.opts.CostEngine.Summary(r.Context(), s.db(), cost.Options{
		Days: days, Since: since, Until: until, GroupBy: cost.GroupByModel, Source: cost.SourceAuto, Limit: 50,
		Tool: tool, ProjectRoot: project, Model: modelParam(r),
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	// Spec §13 cost-view annotation: attach per-model cache
	// annotations. Same shape as /api/cost?group_by=model so the
	// frontend's Cost page can render the same cache pill on
	// whichever endpoint it consumes.
	keys := make([]string, 0, len(summary.Rows))
	for _, row := range summary.Rows {
		keys = append(keys, row.Key)
	}
	if ann, derr := loadCacheAnnotationsByKey(r.Context(), s.db(), "model", keys); derr == nil && len(ann) > 0 {
		writeJSON(w, costSummaryWithCache{Summary: summary, CacheByKey: ann})
		return
	}
	writeJSON(w, summary)
}

// handleTools serves /api/tools?days=N — per-tool action volume + success
// rate over the window. Source: actions table.
func (s *Server) handleTools(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	project := r.URL.Query().Get("project")
	since, until := windowRange(r, 30, 1, 36500)
	args := []any{since.Format(time.RFC3339Nano)}
	where := []string{"timestamp >= ?"}
	if !until.IsZero() {
		where = append(where, "timestamp < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if project != "" {
		where = append(where, "project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	if frag, margs := modelfilter.SessionsUsing("session_id", modelParam(r)); frag != "" {
		where = append(where, frag)
		args = append(args, margs...)
	}
	//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
	q := `SELECT tool, COUNT(*),
	             SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END),
	             COUNT(DISTINCT session_id),
	             MIN(timestamp), MAX(timestamp)
	      FROM actions
	      WHERE ` + strings.Join(where, " AND ") + `
	      GROUP BY tool
	      ORDER BY COUNT(*) DESC`
	rows, err := s.db().QueryContext(r.Context(), q, args...) //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	type toolRow struct {
		Tool         string  `json:"tool"`
		ActionCount  int     `json:"action_count"`
		FailureCount int     `json:"failure_count"`
		SuccessRate  float64 `json:"success_rate"`
		SessionCount int     `json:"session_count"`
		FirstSeen    string  `json:"first_seen"`
		LastSeen     string  `json:"last_seen"`
	}
	out := []toolRow{}
	for rows.Next() {
		var tr toolRow
		if err := rows.Scan(&tr.Tool, &tr.ActionCount, &tr.FailureCount,
			&tr.SessionCount, &tr.FirstSeen, &tr.LastSeen); err != nil {
			writeErr(w, err)
			return
		}
		if tr.ActionCount > 0 {
			tr.SuccessRate = 1 - float64(tr.FailureCount)/float64(tr.ActionCount)
		}
		out = append(out, tr)
	}
	writeJSON(w, map[string]any{
		"days":  days,
		"since": since.Format(time.RFC3339),
		"tools": out,
	})
}

// handleToolsBreakdown serves /api/tools/breakdown?days=N — per-tool
// action_type counts over the window. Powers the Tools tab's "what
// each AI client actually does" stacked bar (one row per tool, segments
// per action type). Honors ?project= and ?tool= filters.
func (s *Server) handleToolsBreakdown(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	since, until := windowRange(r, 30, 1, 36500)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	args := []any{since.Format(time.RFC3339Nano)}
	where := []string{"timestamp >= ?"}
	if !until.IsZero() {
		where = append(where, "timestamp < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if tool != "" {
		where = append(where, "tool = ?")
		args = append(args, tool)
	}
	if project != "" {
		where = append(where, "project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	if frag, margs := modelfilter.SessionsUsing("session_id", modelParam(r)); frag != "" {
		where = append(where, frag)
		args = append(args, margs...)
	}
	whereClause := strings.Join(where, " AND ")
	acc := newBreakdownAccumulator()

	// Two scans, both folded incrementally — nothing is retained per
	// group, so this handler's memory is bounded by the taxonomy
	// (tools × action types, tools × surfaces) and not by the corpus.
	//
	// Pass 1 is the SURFACE attribution. tooltax.Resolve needs the native
	// name (action_type alone cannot say whether a run_command came from
	// a builtin Bash tool or from an MCP server's shell), but
	// raw_tool_name is unrestricted free text, so the group count is
	// O(vocabulary) only by observation — a corpus with a unique name per
	// action would make it O(actions). The LIMIT is the actual bound; it
	// orders by COUNT(*) DESC so the mass of the corpus is what survives,
	// and whatever the cap excludes is reconciled into the `unresolved`
	// surface bucket by the accumulator's remainder (sum(by_surface) ==
	// total stays true). Native names never leave this function — the
	// response carries counts, not names.
	//
	// It runs BEFORE the totals pass so that concurrent ingest between
	// the two scans can only make the totals larger, never the surface
	// sum larger than the total.
	if err := s.foldBreakdownSurfaces(r.Context(), acc, whereClause, args); err != nil {
		writeErr(w, err)
		return
	}

	// Pass 2 is the exact, UNCAPPED totals: (tool, action_type) is
	// bounded by the taxonomy itself (~30 tools × ~50 action types), so
	// total / by_type / by_category stay exact — the pre-WP-T5 contract
	// is untouched by the cap above.
	//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
	q := `SELECT tool, action_type, COUNT(*)
	      FROM actions
	      WHERE ` + whereClause + `
	      GROUP BY tool, action_type
	      ORDER BY tool, COUNT(*) DESC`
	rows, err := s.db().QueryContext(r.Context(), q, args...) //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var t, atype string
		var n int
		if err := rows.Scan(&t, &atype, &n); err != nil {
			writeErr(w, err)
			return
		}
		acc.AddActionTypeCount(t, atype, n)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"days": days,
		// The canonical key spaces, so the client renders both new
		// dimensions in tooltax's display order instead of its own.
		"categories": tooltax.Categories(),
		"surfaces":   breakdownSurfaceKeys(),
		"tools":      acc.Rows(),
	})
}

// foldBreakdownSurfaces runs /api/tools/breakdown's capped native-name
// pass, streaming each (tool, raw_tool_name) group straight into the
// accumulator. It is a separate function so the cursor is closed by
// defer on every path, and so the handler reads as two passes.
//
// A row a cloud-agent connector wrote also groups by its source_file (one
// value per connector; every other row groups under the empty string),
// because the vocabulary its native name belongs to is the connector's,
// not always the tool's: Cline Cloud lands under cline while its calls
// carry cline-cli's names. cloudagents.VocabularyForSource reads that
// from the connector table, the same answer MapActivity used at capture.
func (s *Server) foldBreakdownSurfaces(ctx context.Context, acc *breakdownAccumulator, whereClause string, args []any) error {
	//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
	q := `SELECT tool,
	             CASE WHEN substr(source_file, 1, ?) = ? THEN source_file ELSE '' END AS connector_source,
	             COALESCE(raw_tool_name, ''), COUNT(*)
	      FROM actions
	      WHERE ` + whereClause + `
	      GROUP BY tool, connector_source, raw_tool_name
	      ORDER BY COUNT(*) DESC
	      LIMIT ?`
	qArgs := make([]any, 0, len(args)+3)
	qArgs = append(qArgs, len(cloudagents.SourceFilePrefix), cloudagents.SourceFilePrefix)
	qArgs = append(qArgs, args...)
	qArgs = append(qArgs, breakdownNativeGroupCap)
	rows, err := s.db().QueryContext(ctx, q, qArgs...) //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var tool, origin, rawName string
		var n int
		if err := rows.Scan(&tool, &origin, &rawName, &n); err != nil {
			return err
		}
		acc.AddNativeCountIn(tool, cloudagents.VocabularyForSource(tool, origin), rawName, n)
	}
	return rows.Err()
}
