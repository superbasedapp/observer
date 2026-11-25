package dashboard

import (
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

func (s *Server) handleCost(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	groupBy := r.URL.Query().Get("group_by")
	if groupBy == "" {
		groupBy = "model"
	}
	proj := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "auto"
	}
	since, until := windowRange(r, 30, 1, 36500)
	summary, err := s.opts.CostEngine.Summary(r.Context(), s.db(), cost.Options{
		Days:        days,
		Since:       since,
		Until:       until,
		GroupBy:     cost.GroupBy(groupBy),
		Source:      cost.Source(source),
		ProjectRoot: proj,
		Tool:        tool,
		Model:       modelParam(r),
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	// Spec §13 cost-view annotation: when the rollup keys on a
	// dimension the cache engine indexes (session_id or model),
	// attach per-row cache annotations via the shared
	// loadCacheAnnotationsByKey helper. Empty for other groupings
	// (project / tool) — cache_events doesn't carry those columns
	// natively; the /api/cache/overview endpoint serves the cross-
	// session per-project rollup operators need.
	if column := costAnnotationColumn(groupBy); column != "" {
		keys := make([]string, 0, len(summary.Rows))
		for _, row := range summary.Rows {
			keys = append(keys, row.Key)
		}
		if ann, derr := loadCacheAnnotationsByKey(r.Context(), s.db(), column, keys); derr == nil && len(ann) > 0 {
			writeJSON(w, costSummaryWithCache{Summary: summary, CacheByKey: ann})
			return
		}
	}
	writeJSON(w, summary)
}

// costSummaryWithCache wraps cost.Summary with the per-row cache
// annotation map. The embedded Summary keeps the existing JSON
// shape intact (backward-compat for clients that don't read
// cache_by_key); cache_by_key is the new field that the Cost
// page reads to render the per-row cache pill.
type costSummaryWithCache struct {
	cost.Summary
	CacheByKey map[string]*SessionCacheAnnotation `json:"cache_by_key,omitempty"`
}

// costAnnotationColumn maps cost group_by values to the
// cache_events column they correspond to. Returns "" when the
// grouping isn't directly indexable by cache_events (project /
// tool / pricing_source — for those, the Cache overview page
// serves the cross-session rollup operators need).
func costAnnotationColumn(groupBy string) string {
	switch groupBy {
	case "session":
		return "session_id"
	case "model":
		return "model"
	}
	return ""
}
