package dashboard

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/suggest"
	"github.com/marmutapp/superbased-observer/internal/modelfilter"
)

// handlePatterns serves /api/patterns?page=N&limit=M. Returns a paged
// {rows, page, limit, total} envelope mirroring /api/sessions and
// /api/actions. Patterns are ordered by confidence DESC (the user's
// "what's most reliable to act on first" view).
func (s *Server) handlePatterns(w http.ResponseWriter, r *http.Request) {
	limit := intArg(r, "limit", 20, 1, 200)
	page := intArg(r, "page", 1, 1, 1_000_000)
	offset := (page - 1) * limit
	project := r.URL.Query().Get("project")
	tool := r.URL.Query().Get("tool")

	countArgs := []any{}
	listArgs := []any{}
	where := []string{}
	if project != "" {
		where = append(where, "pp.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		countArgs = append(countArgs, project)
		listArgs = append(listArgs, project)
	}
	// Patterns are mined per-project; tool-scoping restricts to projects
	// whose actions table has at least one row for the requested tool.
	// IN with a derived DISTINCT set scans actions once and hash-joins —
	// avoids the EXISTS-per-pattern quadratic risk the v1.6.2 ship hit on
	// crossToolFiles (handover §4d).
	if tool != "" {
		where = append(where, "pp.project_id IN (SELECT DISTINCT project_id FROM actions WHERE tool = ?)")
		countArgs = append(countArgs, tool)
		listArgs = append(listArgs, tool)
	}
	// Model filter: the same per-project rule as tool - projects with at
	// least one session that used the model.
	if frag, margs := modelfilter.ProjectsUsing("pp.project_id", modelParam(r)); frag != "" {
		where = append(where, frag)
		countArgs = append(countArgs, margs...)
		listArgs = append(listArgs, margs...)
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + joinStrings(where, " AND ")
	}

	var total int
	if err := s.db().QueryRowContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		`SELECT COUNT(*) FROM project_patterns pp`+whereSQL, countArgs...).Scan(&total); err != nil {
		writeErr(w, err)
		return
	}
	listArgs = append(listArgs, limit, offset)
	rows, err := s.db().QueryContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT COALESCE(p.root_path, ''), pattern_type, pattern_data,
		        COALESCE(confidence, 0), COALESCE(observation_count, 0)
		 FROM project_patterns pp
		 LEFT JOIN projects p ON p.id = pp.project_id`+whereSQL+`
		 ORDER BY confidence DESC
		 LIMIT ? OFFSET ?`, listArgs...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	type patternRow struct {
		Project          string  `json:"project"`
		PatternType      string  `json:"pattern_type"`
		Data             string  `json:"data"`
		Confidence       float64 `json:"confidence"`
		ObservationCount int     `json:"observation_count"`
	}
	out := []patternRow{}
	for rows.Next() {
		var pr patternRow
		if err := rows.Scan(&pr.Project, &pr.PatternType, &pr.Data, &pr.Confidence, &pr.ObservationCount); err != nil {
			writeErr(w, err)
			return
		}
		out = append(out, pr)
	}
	writeJSON(w, map[string]any{
		"rows":  out,
		"page":  page,
		"limit": limit,
		"total": total,
	})
}

// handlePatternsTimeseries serves /api/patterns/timeseries?days=N|hours=|
// since=&until=&gran=&tz= — one bucket per granularity step (zero-filled)
// in the global window with the number of patterns reinforced in it, split
// by pattern_type. Drives the "Pattern discovery over time" chart on the
// Patterns tab. `day` keeps its historical field name and holds the bucket
// key (a UTC day key is byte-identical to before); `t` is the bucket start.
//
// Aggregation uses last_reinforced_at (the column the patterns engine
// touches on every observation). Patterns whose last_reinforced_at is
// NULL (legacy rows) skip; they'd otherwise pile onto epoch.
func (s *Server) handlePatternsTimeseries(w http.ResponseWriter, r *http.Request) {
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

	args := []any{since.Format(time.RFC3339Nano)}
	projClause := ""
	if !until.IsZero() {
		projClause += " AND last_reinforced_at < ?"
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if project != "" {
		projClause += " AND project_id = (SELECT id FROM projects WHERE root_path = ?)"
		args = append(args, project)
	}
	if tool != "" {
		projClause += " AND project_id IN (SELECT DISTINCT project_id FROM actions WHERE tool = ?)"
		args = append(args, tool)
	}
	if frag, margs := modelfilter.ProjectsUsing("project_id", modelParam(r)); frag != "" {
		projClause += " AND " + frag
		args = append(args, margs...)
	}
	rows, err := s.db().QueryContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		//nolint:gosec // G202: SQL structure (the timebucket-rendered bucket expression, WHERE/scope fragments) is built from code constants; all values are bound via ? args.
		`SELECT `+slot.SQLiteExpr("last_reinforced_at")+` AS bucket, pattern_type, COUNT(*) AS c
		 FROM project_patterns
		 WHERE last_reinforced_at IS NOT NULL AND last_reinforced_at >= ?`+projClause+`
		 GROUP BY bucket, pattern_type`,
		args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()

	type point struct {
		Day    string         `json:"day"`
		T      int64          `json:"t"`
		Total  int            `json:"total"`
		ByType map[string]int `json:"by_type"`
	}
	byKey := make(map[string]*point)
	starts := map[string]time.Time{}
	for rows.Next() {
		var label sql.NullInt64
		var pt string
		var c int
		if err := rows.Scan(&label, &pt, &c); err != nil {
			writeErr(w, err)
			return
		}
		b, ok := slot.IndexBucket(label.Int64, label.Valid)
		if !ok {
			continue
		}
		key := spec.Key(b)
		p, ok := byKey[key]
		if !ok {
			p = &point{Day: key, ByType: map[string]int{}}
			byKey[key] = p
			starts[key] = b
		}
		p.ByType[pt] += c
		p.Total += c
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}

	slots := bucketSlots(spec, starts)
	out := make([]*point, 0, len(slots))
	for _, sl := range slots {
		p := byKey[sl.Key]
		if p == nil {
			p = &point{Day: sl.Key, ByType: map[string]int{}}
		}
		p.T = millis(sl.T)
		out = append(out, p)
	}
	writeJSON(w, withBucketMeta(spec, map[string]any{
		"days":   days,
		"points": out,
	}))
}

// handleSuggestPreview serves POST /api/suggest — given a project root
// + window, returns the rendered CLAUDE.md / AGENTS.md / .cursorrules
// bodies derived from the project's mined patterns. Does NOT write any
// files; preview only.
//
// Request body: {"project_root": string, "days": int}
// Response: {"markdown": "...", "cursorrules": "...", "input": Input}
func (s *Server) handleSuggestPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ProjectRoot string `json:"project_root"`
		Days        int    `json:"days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ProjectRoot == "" {
		http.Error(w, "project_root required", http.StatusBadRequest)
		return
	}
	if req.Days <= 0 {
		req.Days = 30
	}
	in, err := suggest.Load(r.Context(), s.db(), suggest.Options{
		ProjectRoot: req.ProjectRoot,
		Days:        req.Days,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	now := time.Now().UTC()
	writeJSON(w, map[string]any{
		"project_root": req.ProjectRoot,
		"days":         req.Days,
		"markdown":     suggest.RenderMarkdown(in, now),
		"cursorrules":  suggest.RenderCursorRules(in, now),
		"input":        in,
	})
}

// handleSuggestWrite serves POST /api/suggest/write — same render
// pipeline as preview, then actually persists the result to a file
// in the project root. The target chooses between CLAUDE.md (default),
// AGENTS.md, and .cursorrules; the file is created if missing and
// over-written between observer-managed delimiters when present.
//
// Request body: {"project_root": string, "days": int, "target": "claude"|"agents"|"cursor"}
// Response: {"path": string, "changed": bool, "body": string}
func (s *Server) handleSuggestWrite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ProjectRoot string `json:"project_root"`
		Days        int    `json:"days"`
		Target      string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ProjectRoot == "" {
		http.Error(w, "project_root required", http.StatusBadRequest)
		return
	}
	if req.Days <= 0 {
		req.Days = 30
	}
	target := req.Target
	if target == "" {
		target = "claude"
	}
	var (
		filename string
		body     string
	)
	in, err := suggest.Load(r.Context(), s.db(), suggest.Options{
		ProjectRoot: req.ProjectRoot,
		Days:        req.Days,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	now := time.Now().UTC()
	switch target {
	case "claude":
		filename = "CLAUDE.md"
		body = suggest.RenderMarkdown(in, now)
	case "agents":
		filename = "AGENTS.md"
		body = suggest.RenderMarkdown(in, now)
	case "cursor":
		filename = ".cursorrules"
		body = suggest.RenderCursorRules(in, now)
	default:
		http.Error(w, "target must be one of claude|agents|cursor", http.StatusBadRequest)
		return
	}
	path := req.ProjectRoot
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	path += filename
	// W5.1 org-governed feature gate: node.features.patterns_write.
	// Fail-open (nil FeatureGate, or no accepted policy) — see
	// dashboard.Options.FeatureGate.
	if s.opts.FeatureGate != nil {
		if allowed, reason := s.opts.FeatureGate(nodeFeaturePatternsWrite); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}
	changed, err := suggest.Apply(path, body)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"path":    path,
		"changed": changed,
		"target":  target,
		"body":    body,
	})
}
