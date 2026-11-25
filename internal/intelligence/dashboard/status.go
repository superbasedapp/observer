package dashboard

import (
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/modelfilter"
)

// processStartedAt approximates the daemon's start time — the dashboard
// server is constructed once inside `observer start` / `observer
// dashboard`, so package-init time is the serving process's start. The
// restart-pending banner compares config-save timestamps against this
// to auto-clear once the operator has restarted.
var processStartedAt = time.Now().UTC()

// handleStatus serves GET /api/status — the daemon's own state (row counts,
// schema version, last-seen-per-tool, DB size).
//
// The snapshot comes from statusSnapshot, NOT straight from diag.Snapshot:
// the scan is an unfiltered COUNT(*) over a dozen tables and the SPA polls
// this endpoint from three places at once, so it is memoized per
// statusSnapshotTTL with singleflight on a miss (status_cache.go). The
// cached scan also carries the counts only the dashboard can compute
// (scanStatus: the open security issues behind the Code security badge).
//
// Version / StartedAt / UptimeSeconds are stamped AFTER cache retrieval and
// are deliberately outside the cache: they describe THIS process at THIS
// instant, and uptime in particular is the one field on this endpoint a human
// watches move. Freezing it for the TTL would be the exact dishonesty the
// cache is not allowed to introduce. The value returned by statusSnapshot is
// a copy, so stamping mutates only this request's snapshot.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	snap, err := s.statusSnapshot(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	snap.Version = s.opts.Version
	snap.StartedAt = processStartedAt
	snap.UptimeSeconds = int64(time.Since(processStartedAt).Seconds())
	writeJSON(w, snap)
}

// handleStatusScoped serves /api/status/scoped?days=&tool=&project= — the
// window/tool/project-scoped equivalent of /api/status's `counts` block.
// Drives the Overview + Analysis headline tiles that previously sourced
// from the global lifetime counts and showed the same number regardless
// of filter — a "window 30d" chip over an all-time value.
//
// Returned counts:
//   - sessions: distinct session IDs touched in the window
//   - api_turns: api_turns rows in the window (the proxy-accurate source)
//   - token_usage: token_usage rows in the window (the JSONL fallback)
//   - actions: actions rows in the window
//
// All counts honor the same `tool` + `project` filters as the rest of
// the dashboard so the surface stays internally consistent.
func (s *Server) handleStatusScoped(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 36500)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")

	// since/hours/days all resolve through the shared helper; `until`
	// (when resolved) is applied as an exclusive upper bound to every
	// subquery so a bounded window (e.g. a Calendar day-click that sends
	// since+until) counts only in-window rows. `days` is still echoed
	// verbatim below.
	sinceT, untilT := windowRange(r, 30, 1, 36500)
	since := sinceT.Format(time.RFC3339Nano)
	// upper builds the "< ?" upper-bound fragment (empty when no until)
	// against the given timestamp column, appending the bound value to
	// the caller's arg slice.
	upper := func(col string, args []any) (string, []any) {
		if untilT.IsZero() {
			return "", args
		}
		return " AND " + col + " < ?", append(args, untilT.Format(time.RFC3339Nano))
	}

	// Helper: append the tool+project filter to a query whose primary
	// table is aliased `x` and has `x.session_id` + `x.project_id`
	// (api_turns) — or to one that has only `x.session_id` so we walk
	// through sessions for project (token_usage / sessions / actions).
	scoped := func(viaSession bool) (extra string, args []any) {
		if project != "" {
			// Identical whether reached via session_id or project_id: both
			// query paths expose project_id on the aliased table x.
			extra += " AND project_id IN (SELECT id FROM projects WHERE root_path = ?)"
			args = append(args, project)
		}
		if tool != "" {
			if viaSession {
				extra += " AND tool = ?"
			} else {
				extra += " AND session_id IN (SELECT id FROM sessions WHERE tool = ?)"
			}
			args = append(args, tool)
		}
		return
	}

	type counts struct {
		Days       int   `json:"days"`
		Sessions   int64 `json:"sessions"`
		APITurns   int64 `json:"api_turns"`
		TokenUsage int64 `json:"token_usage"`
		Actions    int64 `json:"actions"`
	}
	out := counts{Days: days}

	// sessions: ACTIVE in the window (started in it, or any action / api
	// turn / token row in it), the same sessionActiveInWindow predicate the
	// Sessions list uses, so the two numbers agree for the same window
	// (T-803: Overview said 1,861 and the Sessions table 1,871 over 30 days,
	// because this count used started_at alone). Marker-only probe sessions
	// are excluded so this stat agrees with the Sessions list.
	// Model filter: sessions and actions are session grain (sessions that
	// used the model); api_turns and token_usage carry their own model
	// column (turn grain), like every spend surface.
	model := modelParam(r)
	sExtra, sArgs := scoped(true) // sessions has tool + project_id directly
	mExtra, mArgs := modelfilter.AndSessionsUsing("id", model)
	sExtra, sArgs = sExtra+mExtra, append(sArgs, mArgs...)
	winPred, winArgs := sessionActiveInWindow("sessions", sinceT, untilT)
	sQ := `SELECT COUNT(*) FROM sessions WHERE ` + winPred + ` AND ` +
		nonEmptySessionPredicateSessions + sExtra
	_ = s.db().QueryRowContext(r.Context(), sQ, append(winArgs, sArgs...)...).Scan(&out.Sessions)

	// api_turns
	atExtra, atArgs := scoped(false) // api_turns: project_id direct, tool via session
	mExtra, mArgs = modelfilter.AndRowIs("model", model)
	atExtra, atArgs = atExtra+mExtra, append(atArgs, mArgs...)
	atUpper, atArgs := upper("timestamp", atArgs)
	atQ := `SELECT COUNT(*) FROM api_turns WHERE timestamp >= ?` + atExtra + atUpper
	_ = s.db().QueryRowContext(r.Context(), atQ, append([]any{since}, atArgs...)...).Scan(&out.APITurns) //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg

	// token_usage: no project_id column → walk through sessions for project
	tuExtra := ""
	tuArgs := []any{}
	if project != "" {
		tuExtra += " AND session_id IN (SELECT id FROM sessions WHERE project_id = (SELECT id FROM projects WHERE root_path = ?))"
		tuArgs = append(tuArgs, project)
	}
	if tool != "" {
		tuExtra += " AND session_id IN (SELECT id FROM sessions WHERE tool = ?)"
		tuArgs = append(tuArgs, tool)
	}
	mExtra, mArgs = modelfilter.AndRowIs("model", model)
	tuExtra, tuArgs = tuExtra+mExtra, append(tuArgs, mArgs...)
	tuUpper, tuArgs := upper("timestamp", tuArgs)
	tuQ := `SELECT COUNT(*) FROM token_usage WHERE timestamp >= ?` + tuExtra + tuUpper
	_ = s.db().QueryRowContext(r.Context(), tuQ, append([]any{since}, tuArgs...)...).Scan(&out.TokenUsage) //nolint:gosec // G701: fixed SQL fragments with ? placeholders; values bind as args

	// actions: project_id direct, tool direct
	aExtra := ""
	aArgs := []any{}
	if project != "" {
		aExtra += " AND project_id = (SELECT id FROM projects WHERE root_path = ?)"
		aArgs = append(aArgs, project)
	}
	if tool != "" {
		aExtra += " AND tool = ?"
		aArgs = append(aArgs, tool)
	}
	mExtra, mArgs = modelfilter.AndSessionsUsing("session_id", model)
	aExtra, aArgs = aExtra+mExtra, append(aArgs, mArgs...)
	aUpper, aArgs := upper("timestamp", aArgs)
	aQ := `SELECT COUNT(*) FROM actions WHERE timestamp >= ?` + aExtra + aUpper
	_ = s.db().QueryRowContext(r.Context(), aQ, append([]any{since}, aArgs...)...).Scan(&out.Actions) //nolint:gosec // G701: fixed SQL fragments with ? placeholders; values bind as args

	writeJSON(w, out)
}
