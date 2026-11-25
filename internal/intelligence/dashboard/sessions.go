package dashboard

import (
	"database/sql"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/modelfilter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// emptySessionMarkers are the lifecycle / meta action types that a hook
// fires for an empty Windows-CC probe session (CLAUDE.md loaded, settings
// touched, session opened then closed) WITHOUT any real work. A session
// whose only rows are these — and which has no token_usage / api_turns —
// is contentless and must not surface on the dashboard. They slip past
// store.Ingest's session_end bootstrap guard because they can legitimately
// PRECEDE a real session (instructions_loaded / config_change fire at
// session start, before the watcher parses the transcript), so dropping
// them at ingestion would strip them from real sessions too. Filtering at
// the read layer — where a session's emptiness is finally knowable — keeps
// the markers on real sessions while hiding the probes.
const emptySessionMarkers = `'instructions_loaded','config_change','session_start','session_end','setup','notification'`

// nonEmptySessionPredicate{S,Sessions} are SQL boolean expressions (no
// bound args) that are true only for sessions with real content: at least
// one substantive action, or any token_usage / api_turns row. They are
// compile-time constants (string-literal + const concat) so they fold to
// a single constant and never trip gosec's G202 SQL-concat taint check.
// Two variants because the enclosing queries use different sessions-table
// aliases: "s" for handleSessions' joined query, "sessions" for the
// unaliased overview / calendar counts.
const nonEmptySessionPredicateS = `(EXISTS (SELECT 1 FROM actions a WHERE a.session_id = s.id` +
	` AND a.action_type NOT IN (` + emptySessionMarkers + `))` +
	` OR EXISTS (SELECT 1 FROM token_usage tu WHERE tu.session_id = s.id)` +
	` OR EXISTS (SELECT 1 FROM api_turns t WHERE t.session_id = s.id))`

const nonEmptySessionPredicateSessions = `(EXISTS (SELECT 1 FROM actions a WHERE a.session_id = sessions.id` +
	` AND a.action_type NOT IN (` + emptySessionMarkers + `))` +
	` OR EXISTS (SELECT 1 FROM token_usage tu WHERE tu.session_id = sessions.id)` +
	` OR EXISTS (SELECT 1 FROM api_turns t WHERE t.session_id = sessions.id))`

// sessionActiveInWindow is the ONE "this session belongs to the window"
// predicate: it started in [since, until) OR it has any action, api turn or
// token row in it. The Sessions list (its rows, total and scored_count) and
// the Overview Sessions tile (/api/status/scoped) both use it, so the two
// numbers agree for the same window. q is the sessions table's name or
// alias in the caller's FROM. A zero since means no lower bound (only the
// started_at upper bound applies, with no activity branches); a zero until
// means no upper bound. Both zero returns a tautology.
func sessionActiveInWindow(q string, since, until time.Time) (string, []any) {
	if since.IsZero() {
		if until.IsZero() {
			return "1=1", nil
		}
		return q + ".started_at < ?", []any{until.Format(time.RFC3339Nano)}
	}
	sinceStr := since.Format(time.RFC3339Nano)
	if !until.IsZero() {
		untilStr := until.Format(time.RFC3339Nano)
		return `((` + q + `.started_at >= ? AND ` + q + `.started_at < ?)
				OR EXISTS (SELECT 1 FROM actions a2 WHERE a2.session_id = ` + q + `.id AND a2.timestamp >= ? AND a2.timestamp < ?)
				OR EXISTS (SELECT 1 FROM api_turns at2 WHERE at2.session_id = ` + q + `.id AND at2.timestamp >= ? AND at2.timestamp < ?)
				OR EXISTS (SELECT 1 FROM token_usage tu2 WHERE tu2.session_id = ` + q + `.id AND tu2.timestamp >= ? AND tu2.timestamp < ?))`,
			[]any{sinceStr, untilStr, sinceStr, untilStr, sinceStr, untilStr, sinceStr, untilStr}
	}
	return `(` + q + `.started_at >= ?
				OR EXISTS (SELECT 1 FROM actions a2 WHERE a2.session_id = ` + q + `.id AND a2.timestamp >= ?)
				OR EXISTS (SELECT 1 FROM api_turns at2 WHERE at2.session_id = ` + q + `.id AND at2.timestamp >= ?)
				OR EXISTS (SELECT 1 FROM token_usage tu2 WHERE tu2.session_id = ` + q + `.id AND tu2.timestamp >= ?))`,
		[]any{sinceStr, sinceStr, sinceStr, sinceStr}
}

// parseSessionsSortParams reads sort_by / sort_dir from the request, clamping
// sort_by to a fixed allow-list (defaulting to started_at) so the value is
// never interpolated unchecked into SQL. Direction defaults to descending; only
// the literal "asc" flips it.
func parseSessionsSortParams(r *http.Request) (sortBy string, desc bool) {
	sortBy = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort_by")))
	switch sortBy {
	case "session", "tool", "project", "started_at", "elapsed", "actions",
		"input", "cache_r", "cache_w", "output", "cost", "quality",
		"errors", "redundancy", "favorite", "rating", "ai_code_lines":
	default:
		sortBy = "started_at"
	}
	desc = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort_dir"))) != "asc"
	return sortBy, desc
}

// sessionsSortRequiresInMemory reports whether a sort column is computed in Go
// (elapsed) or via the cost engine (token/cost buckets) and therefore needs the
// full filtered set loaded before paging, rather than an SQL ORDER BY + LIMIT.
func sessionsSortRequiresInMemory(sortBy string) bool {
	switch sortBy {
	// ai_code_lines is a CORRELATED SUBQUERY over file_changes, not a
	// stored column. Putting it in the SQL ORDER BY would make the
	// database evaluate that subquery for every session in the corpus
	// just to page twenty rows; sorting the already-loaded filtered set
	// in Go costs the same subqueries the SELECT already ran.
	case "elapsed", "input", "cache_r", "cache_w", "output", "cost", "ai_code_lines":
		return true
	}
	return false
}

// sessionsSortRequiresCost reports whether the sort column needs the cost
// engine rollup attached before sorting (the token/cost buckets). "elapsed" is
// in-memory but does NOT need cost, so it is excluded here.
func sessionsSortRequiresCost(sortBy string) bool {
	switch sortBy {
	case "input", "cache_r", "cache_w", "output", "cost":
		return true
	}
	return false
}

// sessionsSQLOrderClause maps an allow-listed sort column to a SQL ORDER BY
// fragment (used only for the cheap, SQL-sortable columns). The sort column is
// never interpolated directly — it selects a fixed expression. A stable
// tiebreak on started_at DESC, id ASC keeps pagination deterministic.
func sessionsSQLOrderClause(sortBy string, desc bool) string {
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	expr := "s.started_at"
	switch sortBy {
	case "session":
		expr = "s.id"
	case "tool":
		expr = "s.tool"
	case "project":
		expr = "COALESCE(p.root_path, '')"
	case "actions":
		expr = "total_actions"
	case "quality":
		expr = "COALESCE(s.quality_score, -1.0)"
	case "errors":
		expr = "COALESCE(s.error_rate, -1.0)"
	case "redundancy":
		expr = "COALESCE(s.redundancy_ratio, -1.0)"
	case "favorite":
		// EXISTS rather than a LEFT JOIN so the shared FROM clause (and every
		// caller of it — data / total / scored_count) stays untouched; a
		// session with no annotation row sorts as 0. Default direction is DESC,
		// so `sort_by=favorite` alone means "starred first".
		expr = "(SELECT COUNT(*) FROM session_annotations sa" +
			" WHERE sa.session_id = s.id AND sa.favorite = 1)"
	case "rating":
		// Scalar subquery, same shape as favorite: an unrated session (no row,
		// or rating 0) sorts as 0. Default direction is DESC, so
		// `sort_by=rating` alone means "highest-rated first"; sort_dir=asc
		// surfaces the worst-rated sessions (rating 0/unrated sink to the top).
		expr = "COALESCE((SELECT sa.rating FROM session_annotations sa" +
			" WHERE sa.session_id = s.id), 0)"
	}
	if expr == "s.started_at" {
		// The default sort IS the tiebreak's first term: repeating it
		// ("s.started_at DESC, s.started_at DESC, s.id ASC") orders rows
		// identically but stops SQLite from walking idx_sessions_started,
		// so every page SCANned all sessions and evaluated each row's
		// correlated action subqueries before the LIMIT (468 ms warm on the
		// 4.3k-session node, tens of seconds on a cold page cache; 1 ms
		// with the index). Plan pinned by TestSessionsDefaultOrderUsesIndex.
		return expr + " " + dir + ", s.id ASC"
	}
	return expr + " " + dir + ", s.started_at DESC, s.id ASC"
}

// maxSurfaceHostFilterLen bounds the `surface_host` list filter. Host
// tokens adapters mint are short lowercase identifiers ("vscode",
// "jetbrains-idea", "freebuff-desktop"); anything longer is not a token
// the store could hold and is dropped rather than bound into the query.
const maxSurfaceHostFilterLen = 64

// sessionSurfaceFilter resolves the `surface=<kind>` query param of
// GET /api/sessions to a value safe to bind as an exact match, or "" for
// "no filter". Only the closed models.Surface* vocabulary passes
// (models.KnownSurface is the single authority on it); an unknown or
// empty value FAILS OPEN to no filter — a stale bookmark must still
// render the list, and the closed vocabulary means a typo can never be a
// legitimate "match nothing". Matching is case-insensitive on input; the
// stored kind is lowercase by construction (SetSessionSurface validates).
func sessionSurfaceFilter(r *http.Request) string {
	kind := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("surface")))
	if kind == "" || !models.KnownSurface(kind) {
		return ""
	}
	return kind
}

// sessionSurfaceHostFilter resolves the `surface_host=<token>` query
// param to a lowercase token safe to bind as an exact match, or "" for
// "no filter". The host vocabulary is deliberately OPEN (each adapter
// mints its own token, so there is no table to validate against); the
// only shape rule is "one bare token": whitespace inside the value or a
// length past maxSurfaceHostFilterLen fails open to no filter.
func sessionSurfaceHostFilter(r *http.Request) string {
	host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("surface_host")))
	if host == "" || len(host) > maxSurfaceHostFilterLen || strings.ContainsAny(host, " \t\r\n") {
		return ""
	}
	return host
}

//nolint:gocyclo // moved unchanged out of dashboard.go, which .golangci.yml exempts from gocyclo; splitting this handler is INTEL-02.
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	limit := intArg(r, "limit", 20, 1, 500)
	page := intArg(r, "page", 1, 1, 1_000_000)
	offset := (page - 1) * limit
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	// days=0 (or missing) means "no time filter" — preserves the prior
	// behaviour for callers that haven't been updated. Frontend always
	// passes the global window; CLI / older API consumers may not. The
	// shared windowRange helper resolves since/hours/days (and an
	// optional `until` upper bound) with the same fail-open precedence;
	// a zero `since` means "no lower bound".
	since, until := windowRange(r, 0, 0, 36500)
	// Echo the literal `days` param for response-shape compat (the
	// frontend reads it back). It stays independent of the resolved
	// window: an hours=/since= request echoes days as its default 0 —
	// the closest legacy equivalent — while the actual filtering uses
	// since/until above.
	days := intArg(r, "days", 0, 0, 36500)
	// from_date / to_date — YYYY-MM-DD prefix filter against
	// substr(s.started_at, 1, 10). Mirrors the /api/actions params so
	// the Sessions Calendar day-click can server-side scope to that
	// day's sessions instead of substring-filtering the loaded page
	// (which silently dropped any day outside the page-50 slice and
	// produced a misleading "No sessions match" empty state for any
	// day older than the loaded rows).
	fromDate := r.URL.Query().Get("from_date")
	toDate := r.URL.Query().Get("to_date")

	// Server-side sort. Cheap columns sort in SQL; columns computed in Go
	// (elapsed) or via the cost engine (token/cost buckets) need the full
	// filtered set attached + sorted before paging — otherwise the page-local
	// client sort surfaces "the most expensive of the visible 20", not the
	// most expensive session overall.
	sortBy, sortDesc := parseSessionsSortParams(r)
	inMemorySort := sessionsSortRequiresInMemory(sortBy)
	costSort := sessionsSortRequiresCost(sortBy)

	// Build optional WHERE clause over sessions + a project-id lookup.
	var where []string
	var args []any
	if tool != "" {
		where = append(where, "s.tool = ?")
		args = append(args, tool)
	}
	if project != "" {
		where = append(where, "s.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	// Model filter (session grain): sessions that used the model. Each row's
	// metrics stay whole-session, exactly as under a tool filter.
	if frag, margs := modelfilter.SessionsUsing("s.id", modelParam(r)); frag != "" {
		where = append(where, frag)
		args = append(args, margs...)
	}
	// Session-classification filters (plan §4). `tag` is REPEATABLE with AND
	// semantics — one EXISTS subquery per tag — and `favorite=1` is an EXISTS on
	// session_annotations. Both land in the SHARED `where` slice so the data
	// query, the pagination `total`, and `scored_count` all agree on which
	// sessions exist (the coherence rule the window predicate already follows).
	// A malformed tag is a 400 rather than a silent no-match: returning the
	// unfiltered list under a filter the user asked for would lie.
	//
	// The repeatable param is DEDUPED (after normalization) and CAPPED at
	// maxSessionTagFilters: each accepted tag appends a correlated EXISTS
	// subquery to a WHERE clause that also drives the `total` COUNT and
	// scored_count, so an unbounded `?tag=` list is an authenticated
	// amplification lever (one cheap request → an arbitrarily long EXISTS
	// chain executed three times). Duplicates are dropped rather than rejected:
	// `?tag=x&tag=X` is the same filter written twice, and answering it is more
	// useful than 400-ing it.
	seenTags := make(map[string]struct{}, 4)
	for _, raw := range r.URL.Query()["tag"] {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		tag, err := store.NormalizeTag(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, dup := seenTags[tag]; dup {
			continue
		}
		if len(seenTags) >= maxSessionTagFilters {
			http.Error(w, fmt.Sprintf("too many tag filters: at most %d distinct tags per request", maxSessionTagFilters),
				http.StatusBadRequest)
			return
		}
		seenTags[tag] = struct{}{}
		where = append(where, "EXISTS (SELECT 1 FROM session_tags st WHERE st.session_id = s.id AND st.tag = ?)")
		args = append(args, tag)
	}
	if v := strings.TrimSpace(r.URL.Query().Get("favorite")); v == "1" || strings.EqualFold(v, "true") {
		where = append(where, "EXISTS (SELECT 1 FROM session_annotations sa WHERE sa.session_id = s.id AND sa.favorite = 1)")
	}
	// Capture-surface filters (migration 107, node-local). `surface` is an
	// exact match on the closed models.Surface* vocabulary; a value outside
	// it is IGNORED (fail-open: no filter), never a 400 and never a no-match
	// — an old bookmark carrying a kind that was later retired should still
	// show the list. `surface_host` is a free-form token by design (adapters
	// mint their own), so it is matched verbatim after lowercasing; the
	// stored token is lowercase by convention. Both go into the SHARED
	// `where` slice so total / scored_count agree with the page.
	if kind := sessionSurfaceFilter(r); kind != "" {
		where = append(where, "s.surface = ?")
		args = append(args, kind)
	}
	if host := sessionSurfaceHostFilter(r); host != "" {
		where = append(where, "s.surface_host = ?")
		args = append(args, host)
	}
	// Where it ran (agent migration 240, cloud-agents lane CA-B5): a fixed
	// fragment from executionFilterSQL (cloudlane.go), "unknown" = the NULL
	// column, anything else fails open to no filter. Shared `where`, so the
	// total and scored_count agree with the page.
	if frag := sessionExecutionFilter(r); frag != "" {
		where = append(where, frag)
	}
	if !since.IsZero() {
		// Reconcile the Sessions window with the cost engine. /api/cost and
		// /api/models window by turn/token TIMESTAMP (cost/summary.go), so a
		// long-running session that STARTED before the window but has RECENT
		// turns contributes there. Windowing on started_at alone would exclude
		// it here, making the Sessions tab under-count vs the Cost tab. Include
		// a session if it started in-window OR has any in-window activity
		// (action / api_turn / token_usage). The shared `where` slice carries
		// this predicate into the pagination `total` COUNT and scored_count too,
		// so the page math stays coherent. (A row dated >N days ago can thus
		// surface in an N-day view; its metadata reflects the whole session,
		// its cost is windowed — consistent with /api/cost.)
		//
		// When `until` is set, every branch is a COMPLETE [since, until)
		// test: the started_at bound and each activity EXISTS carries the
		// same exclusive upper bound, so a bounded window (e.g. a Calendar
		// day-click) can't leak a session whose only in-window activity is
		// actually AFTER `until`.
		pred, pArgs := sessionActiveInWindow("s", since, until)
		where = append(where, pred)
		args = append(args, pArgs...)
	} else if !until.IsZero() {
		// No lower bound: window has only an upper bound. There are no
		// activity-EXISTS branches to reconcile (those exist solely to
		// pull in sessions that STARTED before `since`), so a plain
		// started_at upper bound is the complete test.
		where = append(where, "s.started_at < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	// from_date / to_date stay day-grained (substr) for compat, but the
	// genuinely-new sub-day params win when both are present: skip the
	// legacy lower/upper bound only if since/hours (resp. until) actually
	// RESOLVED. A present-but-malformed `until` (or `since`/`hours`) fails
	// open in windowRange, so keying suppression off resolution — not raw
	// presence — means the legacy param still applies in that case.
	// Legacy `days`+from_date keeps its historical AND behavior because
	// `days` is not one of the "new" params gated here.
	newLower, newUpper := windowBoundsResolved(r)
	if fromDate != "" && !newLower {
		where = append(where, "substr(s.started_at, 1, 10) >= ?")
		args = append(args, fromDate)
	}
	if toDate != "" && !newUpper {
		where = append(where, "substr(s.started_at, 1, 10) <= ?")
		args = append(args, toDate)
	}
	// Hide contentless probe sessions (marker-only, no tokens/turns). Added
	// to the shared `where` so the data query, the pagination `total`, and
	// the `scored_count` all agree on which sessions exist.
	where = append(where, nonEmptySessionPredicateS)
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Total row count for pagination. Must share the same WHERE as the
	// data query so page math stays coherent.
	var total int
	countArgs := append([]any{}, args...)
	if err := s.db().QueryRowContext( //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		r.Context(),
		"SELECT COUNT(*) FROM sessions s "+whereClause, countArgs...,
	).Scan(&total); err != nil {
		writeErr(w, err)
		return
	}

	// scored_count tells the frontend whether to render the Quality /
	// Errors / Redundancy columns. None of those fields are populated
	// unless `observer score` has run — pre-fix the columns rendered
	// dashes for every row, wasting horizontal space and misleading
	// users into thinking scoring is unsupported. Same WHERE as `total`
	// so the count is consistent with the visible filter.
	var scoredCount int
	_ = s.db().QueryRowContext( //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		r.Context(),
		"SELECT COUNT(*) FROM sessions s "+whereClause+
			func() string {
				if whereClause == "" {
					return "WHERE s.quality_score IS NOT NULL"
				}
				return " AND s.quality_score IS NOT NULL"
			}(),
		countArgs...,
	).Scan(&scoredCount)

	// total_actions is computed live; the sessions.total_actions stored
	// column is never advanced past 0 by any writer (UpsertSession's MAX
	// merge keeps it at whatever the first batch wrote, scoring computes
	// len(actions) only into a transient struct). Subquery is cheap at
	// LIMIT 20 and avoids a stale-column class of bug.
	dataArgs := append([]any{}, args...)
	// Cheap columns sort + page in SQL. In-memory columns (elapsed / token /
	// cost buckets) load the FULL filtered set ordered by started_at and are
	// sorted + paginated in Go below, after the per-session cost/tokens attach.
	orderAndLimit := "ORDER BY " + sessionsSQLOrderClause(sortBy, sortDesc) + " LIMIT ? OFFSET ?"
	if inMemorySort {
		orderAndLimit = "ORDER BY s.started_at DESC, s.id ASC"
	} else {
		dataArgs = append(dataArgs, limit, offset)
	}
	// last_seen falls back to MAX(actions.timestamp) when ended_at is
	// NULL (open session) so DurationSeconds is still meaningful for
	// in-flight sessions. Subqueries are cheap at LIMIT 20.
	rows, err := s.db().QueryContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments, ORDER BY column from a fixed allow-list, and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT s.id, s.tool, COALESCE(p.root_path, ''), s.started_at,
		        COALESCE(s.ended_at,
		                 (SELECT MAX(a.timestamp) FROM actions a WHERE a.session_id = s.id),
		                 '') AS last_seen_at,
		        (SELECT COUNT(*) FROM actions a WHERE a.session_id = s.id) AS total_actions,
		        (SELECT COUNT(*) FROM actions a WHERE a.session_id = s.id AND a.is_sidechain = 1) AS sidechain_actions,
		        -- Lines-of-code authorship (migration 103) is NOT selected
		        -- here. It is attached below from the store seam
		        -- (store.LoadSessionLOCLines), because internal/store owns
		        -- file_changes and this was the only raw read of that table
		        -- outside it. The two copies of the collapse rule drifted:
		        -- the card summed each digest group's MIN(id) representative
		        -- while this query took the group's MAX line count, so a
		        -- codex invocation/executor pair whose executor landed at
		        -- the lower id made the list and the card report different
		        -- numbers for one session. One owner, one rule.
		        s.quality_score, s.error_rate, s.redundancy_ratio,
		        s.redundancy_ratio_wasteful, s.stale_reads_wasteful, s.stale_reads_necessary,
		        -- Capture surface (migration 107): plain columns on the row,
		        -- read in the same pass as the rest — no per-row
		        -- store.LoadSessionSurface round trip. '' = unstamped.
		        COALESCE(s.surface, ''), COALESCE(s.surface_host, ''),
		        -- Captured tool/CLI version (migration 125): same plain-column
		        -- read; '' = unstamped (honest unknown, never fabricated).
		        COALESCE(s.tool_version, ''),
		        -- Where it ran (migration 240): '' = unstamped (unknown,
		        -- never a defaulted "local").
		        COALESCE(s.execution_location, ''), COALESCE(s.vendor_session_ref, '')
		 FROM sessions s
		 LEFT JOIN projects p ON p.id = s.project_id
		 `+whereClause+` `+orderAndLimit, dataArgs...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	type sessRow struct {
		ID        string `json:"id"`
		Tool      string `json:"tool"`
		Project   string `json:"project"`
		StartedAt string `json:"started_at"`
		// LastSeenAt is COALESCE(ended_at, MAX(actions.timestamp)). Drives
		// DurationSeconds for both closed and still-open sessions.
		LastSeenAt string `json:"last_seen_at,omitempty"`
		// DurationSeconds = LastSeenAt - StartedAt, computed server-side
		// so the frontend formatter doesn't need to parse timestamps.
		// Zero when LastSeenAt is empty (no actions yet) or when start
		// is unparseable. Surfaced as "Elapsed" in the Sessions table.
		DurationSeconds int64 `json:"duration_seconds"`
		TotalActions    int   `json:"total_actions"`
		// SidechainActionCount is the count of actions emitted inside
		// any sub-agent runtime spawned by this session (Claude Code's
		// `Agent` tool). Sub-agents share the parent's session_id;
		// this is the only structural marker. > 0 implies the session
		// fanned out work to sub-agents — surfaced as a "sidechain N"
		// pill on the Sessions tab.
		SidechainActionCount int `json:"sidechain_action_count"`
		// AICodeLines is the agent-authored CODE lines this session
		// touched: added + modified, comments / blanks / whitespace-only
		// reflows excluded, deduplicated across the codex
		// invocation/executor pair. Deleted lines are deliberately not in
		// it — deleting code is real work, but it is not lines written,
		// and summing the two would let a delete-heavy refactor outscore
		// a feature.
		//
		// SCOPE: it is every AI row stored under THIS session id - main
		// line AND inline sub-agent (sidechain) edits together - but NOT a
		// sub-agent child session, which is listed as its own row. The
		// session card instead splits main from sidechain and folds child
		// sessions in, so this number equals the card's "AI code lines"
		// plus "Subagent code lines" only when the session has no child
		// sessions (it never double-counts across list rows).
		//
		// HumanCodeLines is its editor-reported counterpart and is 0
		// unless an editor is reporting saves. The UI must NOT derive an
		// "AI share" from these two on their own: with no editor capture
		// the human side is unmeasured, not zero, and a share would read
		// as 100% AI. /api/loc/summary carries the capture flag that
		// makes a share legitimate.
		//
		// Both carry omitempty so a corpus that has never run
		// `observer backfill --loc` emits the byte-identical payload it
		// did before this feature existed (tests/invariant/golden/sessions.json).
		AICodeLines    int `json:"ai_code_lines,omitempty"`
		HumanCodeLines int `json:"human_code_lines,omitempty"`
		// AISplit is the code-vs-comment split of the same AI rows
		// AICodeLines sums (internal/loc.SplitAuthored; code = added +
		// modified, comment = added comment lines). Nil - and so absent on
		// the wire - when the session has no AI code or comment lines, so
		// an uncounted corpus stays byte-identical.
		AISplit         *authoredSplit `json:"ai_split,omitempty"`
		QualityScore    *float64       `json:"quality_score,omitempty"`
		ErrorRate       *float64       `json:"error_rate,omitempty"`
		RedundancyRatio *float64       `json:"redundancy_ratio,omitempty"`
		// Spec §14.1 wasteful-subset (nil when the session has
		// no cache_events).
		RedundancyRatioWasteful *float64 `json:"redundancy_ratio_wasteful,omitempty"`
		StaleReadsWasteful      *int     `json:"stale_reads_wasteful,omitempty"`
		StaleReadsNecessary     *int     `json:"stale_reads_necessary,omitempty"`
		// Token breakdown — attached post-scan from the cost engine's
		// GroupBySession rollup so dedup (proxy preferred, JSONL
		// fallback) matches /api/cost exactly. v1.4.51 surfaces all
		// four billable buckets separately so the Sessions table can
		// show Input / Cache R / Cache W / Output as distinct columns.
		// TotalTokens is the sum for backwards compatibility with
		// older callers; the Sessions table doesn't render it as of
		// v1.4.51.
		InputTokens         int64 `json:"input_tokens"`
		OutputTokens        int64 `json:"output_tokens"`
		CacheReadTokens     int64 `json:"cache_read_tokens"`
		CacheCreationTokens int64 `json:"cache_creation_tokens"`
		// CacheCreation1hTokens is the 1h-ephemeral-tier subset of
		// CacheCreationTokens (the rest is implicitly 5m-tier).
		// Surfaced so the Sessions table's "Cache W" column can show
		// the per-row 5m/1h split as a hover tooltip — visualisation
		// of why a session billed at the higher-tier cache-write rate.
		// Anthropic-only field; non-Anthropic providers always emit 0.
		CacheCreation1hTokens int64 `json:"cache_creation_1h_tokens"`
		ReasoningTokens       int64 `json:"reasoning_tokens,omitempty"`
		WebSearchRequests     int64 `json:"web_search_requests,omitempty"`
		TotalTokens           int64 `json:"total_tokens"`
		// CostUSD is the legacy total; AICostUSD + ToolCostUSD split
		// it so the Sessions table can show "API cost vs tool cost vs
		// total" separately. CostUSD == AICostUSD + ToolCostUSD.
		CostUSD     float64 `json:"cost_usd"`
		AICostUSD   float64 `json:"ai_cost_usd"`
		ToolCostUSD float64 `json:"tool_cost_usd"`
		// CostReliability is the worst-case reliability across the
		// rows that fed this session's totals. Surfaces as a pill on
		// the Sessions table so users know which numbers to trust.
		CostReliability string `json:"cost_reliability,omitempty"`
		// Models is the distinct set of model identifiers seen across
		// this session's api_turns + token_usage rows, ordered by turn
		// count (heaviest first). Enables the Sessions table's Model(s)
		// column to render a primary chip + "+N more" affordance and
		// the Overview Recent sessions list to show which model the
		// session leaned on. Empty when no proxy/JSONL rows captured
		// a model (rare; usually means scraped fallback).
		Models []string `json:"models,omitempty"`
		// Session classification (plan §4), attached post-scan from the two
		// batched store loads (one query each per page — never per row).
		// HasNote is a flag, not the note itself: the list renders a marker and
		// the detail panel fetches the text. ALL THREE carry omitempty so an
		// unclassified corpus emits the byte-identical payload it did before
		// tags existed (the pinned tests/invariant/golden/sessions.json).
		Tags     []string `json:"tags,omitempty"`
		Favorite bool     `json:"favorite,omitempty"`
		HasNote  bool     `json:"has_note,omitempty"`
		// Rating is the 1-10 overall score (0 = unrated). omitempty for the
		// same golden-payload-stability reason as the three above.
		Rating int `json:"rating,omitempty"`
		// Title is the developer's OWN session title (migration 116) —
		// distinct from CloudTitle below (the AI-generated one) and always
		// wins over it wherever the frontend renders an "effective title".
		// omitempty for the same golden-payload-stability reason as Rating.
		Title string `json:"title,omitempty"`
		// CloudEnriched/CloudTitle surface the cloud-intelligence enrichment
		// state (node-local cloud_results, migration 097) attached
		// post-scan from the same batched-per-page pattern as the
		// classification fields above. CloudEnriched is true when a
		// non-superseded cloud_results row exists for the session;
		// CloudTitle is that row's AI-generated title, or "" when none.
		// Both carry omitempty/zero-value defaults so an unenriched corpus
		// emits the byte-identical payload it did before cloud-intelligence
		// existed.
		CloudEnriched   bool                           `json:"cloud_enriched,omitempty"`
		CloudTitle      string                         `json:"cloud_title,omitempty"`
		CloudEnrichment *store.CloudEnrichmentProgress `json:"cloud_enrichment,omitempty"`
		// OrgTitle is the newest org-plane AI title the node pulled back for
		// the session (node-local org_intel_cache). The frontend's effective
		// title is Title > CloudTitle > OrgTitle. omitempty for the same
		// golden-payload-stability reason as the cloud fields.
		OrgTitle string `json:"org_title,omitempty"`
		// EnrichPlane is "org" when the session carries the org data-authority
		// stamp, so the list's Enrich button opens the org plane (ruling Q3);
		// absent otherwise (the personal plane). Withheld with OrgTitle when
		// the organization hid the `intel` subsection.
		EnrichPlane string `json:"enrich_plane,omitempty"`
		// Surface / SurfaceHost are the capture-surface attribution
		// (migration 107, NODE-LOCAL): the closed kind vocabulary
		// (models.SurfaceCLI..SurfaceWeb) and the free-form host token
		// ("vscode", "claude-desktop", "jetbrains-idea", ...). Both carry
		// omitempty and ABSENT MEANS UNSTAMPED — the list never fabricates
		// a "cli" default; the SurfaceBadge renders nothing for it. Same
		// two fields the detail response exposes, so list and slide-over
		// cannot disagree about one session.
		Surface     string `json:"surface,omitempty"`
		SurfaceHost string `json:"surface_host,omitempty"`
		// ToolVersion is the captured tool/CLI version (migration 125,
		// NODE-LOCAL). omitempty + ABSENT MEANS UNSTAMPED — the list never
		// fabricates a version. Same field the detail response exposes.
		ToolVersion string `json:"tool_version,omitempty"`
		// ExecutionLocation is where the session's agent ran (migration
		// 240): local | vendor_cloud | customer_worker. VendorSessionRef is
		// the vendor's second native session id used to join capture rails.
		// Both omitempty and ABSENT MEANS UNKNOWN: the list never fabricates
		// "local", and an unstamped corpus emits the byte-identical payload
		// it did before the columns existed. Same two fields the detail
		// response exposes.
		ExecutionLocation string `json:"execution_location,omitempty"`
		VendorSessionRef  string `json:"vendor_session_ref,omitempty"`
	}
	var out []sessRow
	for rows.Next() {
		var sr sessRow
		var q, er, rr sql.NullFloat64
		var rrWasteful sql.NullFloat64
		var stWasteful, stNecessary sql.NullInt64
		if err := rows.Scan(&sr.ID, &sr.Tool, &sr.Project, &sr.StartedAt, &sr.LastSeenAt,
			&sr.TotalActions, &sr.SidechainActionCount,
			&q, &er, &rr,
			&rrWasteful, &stWasteful, &stNecessary,
			&sr.Surface, &sr.SurfaceHost, &sr.ToolVersion,
			&sr.ExecutionLocation, &sr.VendorSessionRef); err != nil {
			writeErr(w, err)
			return
		}
		if sr.LastSeenAt != "" {
			start, sErr := time.Parse(time.RFC3339Nano, sr.StartedAt)
			end, eErr := time.Parse(time.RFC3339Nano, sr.LastSeenAt)
			if sErr == nil && eErr == nil && end.After(start) {
				sr.DurationSeconds = int64(end.Sub(start).Seconds())
			}
		}
		if q.Valid {
			v := q.Float64
			sr.QualityScore = &v
		}
		if er.Valid {
			v := er.Float64
			sr.ErrorRate = &v
		}
		if rr.Valid {
			v := rr.Float64
			sr.RedundancyRatio = &v
		}
		if rrWasteful.Valid {
			v := rrWasteful.Float64
			sr.RedundancyRatioWasteful = &v
		}
		if stWasteful.Valid {
			v := int(stWasteful.Int64)
			sr.StaleReadsWasteful = &v
		}
		if stNecessary.Valid {
			v := int(stNecessary.Int64)
			sr.StaleReadsNecessary = &v
		}
		out = append(out, sr)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	if out == nil {
		out = []sessRow{}
	}

	// Attach lines-of-code authorship through the store seam — ONE batched
	// query per 400 sessions, deduplicated by the same collapse rule the
	// session card reads through, so the two surfaces can never report
	// different numbers for one session.
	//
	// It runs HERE, before the in-memory sort, because ai_code_lines is a
	// sortable column and that sort covers the whole filtered set, not just
	// the page. A failure degrades the page to "no LOC shown" rather than
	// 500ing the list — same posture as tags/annotations/cloud below.
	if len(out) > 0 {
		locIDs := make([]string, len(out))
		for i := range out {
			locIDs[i] = out[i].ID
		}
		if locLines, lErr := store.New(s.db()).LoadSessionLOCLines(r.Context(), locIDs); lErr == nil {
			for i := range out {
				lines := locLines[out[i].ID]
				out[i].AICodeLines = lines.AICodeLines
				out[i].HumanCodeLines = lines.HumanCodeLines
				out[i].AISplit = sessionRowAISplit(lines)
			}
		} else {
			s.opts.Logger.Warn("sessions: per-session LOC load failed", "err", lErr)
		}
	}

	// Attach per-session token totals + cost from the cost engine, then (for
	// in-memory sort columns) sort the full filtered set and slice to the page.
	//
	// The window matches the days query param so the Sessions-page per-session
	// cost sum equals the Cost-page /api/models total (the v1.6.3 → v1.6.4
	// reconciliation fix). When days=0 (no time filter) the cost rollup spans
	// full history (Days=36500), keeping CLI callers correct.
	// Window the per-session cost rollup to match the list. When no
	// lower bound was requested (since zero), fall back to the all-time
	// window (costDays=36500) exactly as before; otherwise the cost
	// engine honors Since/Until (Since overrides Days when non-zero).
	costDays := 0
	if since.IsZero() {
		costDays = 36500
	}

	// attachCost rolls up per-session cost + tokens and stamps them onto rows.
	// scopeIDs limits the engine to those session_ids (the cheap page-scoped
	// path); pass nil to roll up the whole window — needed when a cost/token
	// sort column requires the full filtered set BEFORE paging, since the byID
	// map then filters the rollup back to the rows we hold.
	attachCost := func(rows []sessRow, scopeIDs []string) {
		if len(rows) == 0 {
			return
		}
		costSummary, err := s.opts.CostEngine.Summary(r.Context(), s.db(), cost.Options{
			Days:        costDays,
			Since:       since,
			Until:       until,
			GroupBy:     cost.GroupBySession,
			Source:      cost.SourceAuto,
			ProjectRoot: project,
			Tool:        tool,
			SessionIDs:  scopeIDs,
			Limit:       1_000_000,
		})
		if err != nil {
			s.opts.Logger.Warn("sessions: per-session cost rollup failed", "err", err)
			return
		}
		byID := make(map[string]cost.Row, len(costSummary.Rows))
		for _, row := range costSummary.Rows {
			byID[row.Key] = row
		}
		for i := range rows {
			row, ok := byID[rows[i].ID]
			if !ok {
				continue
			}
			rows[i].InputTokens = row.Tokens.Input
			rows[i].OutputTokens = row.Tokens.Output
			rows[i].CacheReadTokens = row.Tokens.CacheRead
			rows[i].CacheCreationTokens = row.Tokens.CacheCreation
			rows[i].CacheCreation1hTokens = row.Tokens.CacheCreation1h
			rows[i].ReasoningTokens = row.Tokens.Reasoning
			rows[i].WebSearchRequests = row.Tokens.WebSearchRequests
			rows[i].TotalTokens = row.Tokens.Input + row.Tokens.Output +
				row.Tokens.CacheRead + row.Tokens.CacheCreation
			rows[i].CostUSD = row.CostUSD
			rows[i].AICostUSD = row.AICostUSD
			rows[i].ToolCostUSD = row.ToolCostUSD
			rows[i].CostReliability = row.Reliability
		}
	}

	costAttached := false
	if inMemorySort {
		if costSort {
			// Cost/token columns: roll up the WHOLE filtered set so the sort is
			// global, not page-local.
			attachCost(out, nil)
			costAttached = true
		}
		// Sort the full filtered set in Go. Numeric key per column; stable
		// tiebreak on started_at DESC, id ASC mirrors the SQL clause so paging
		// is deterministic.
		sortKey := func(sr sessRow) float64 {
			switch sortBy {
			case "elapsed":
				return float64(sr.DurationSeconds)
			case "input":
				return float64(sr.InputTokens)
			case "cache_r":
				return float64(sr.CacheReadTokens)
			case "cache_w":
				return float64(sr.CacheCreationTokens)
			case "output":
				return float64(sr.OutputTokens)
			case "cost":
				return sr.CostUSD
			case "ai_code_lines":
				return float64(sr.AICodeLines)
			}
			return 0
		}
		sort.SliceStable(out, func(i, j int) bool {
			ki, kj := sortKey(out[i]), sortKey(out[j])
			if ki != kj {
				if sortDesc {
					return ki > kj
				}
				return ki < kj
			}
			if out[i].StartedAt != out[j].StartedAt {
				return out[i].StartedAt > out[j].StartedAt
			}
			return out[i].ID < out[j].ID
		})
		// Slice to the requested page.
		start := offset
		if start > len(out) {
			start = len(out)
		}
		end := start + limit
		if end > len(out) {
			end = len(out)
		}
		out = out[start:end]
	}

	pageIDs := make([]string, len(out))
	for i, sr := range out {
		pageIDs[i] = sr.ID
	}
	if !costAttached {
		// Cheap-SQL-sort and elapsed-sort pages: attach cost scoped to the
		// page's session_ids (no whole-window rollup needed).
		attachCost(out, pageIDs)
	}

	// Attach per-session model list for the page — one query batches across the
	// page's session IDs and unions api_turns + token_usage. Models are ordered
	// by turn count desc so out[i].Models[0] is the session's "primary" model
	// (heaviest by count). Both source tables index session_id; cheap at
	// LIMIT ≤ 500.
	if len(out) > 0 {
		ids := make([]any, 0, len(pageIDs))
		for _, id := range pageIDs {
			ids = append(ids, id)
		}
		placeholders := strings.Repeat("?,", len(ids))
		placeholders = strings.TrimRight(placeholders, ",")
		modelArgs := append(append([]any{}, ids...), ids...)
		modelRows, mErr := s.db().QueryContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
			//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
			`SELECT session_id, model, SUM(c) AS turns FROM (
				SELECT session_id, COALESCE(model, '') AS model, COUNT(*) AS c
				 FROM api_turns
				 WHERE session_id IN (`+placeholders+`) AND COALESCE(model, '') != ''
				 GROUP BY session_id, model
				UNION ALL
				SELECT session_id, COALESCE(model, '') AS model, COUNT(*) AS c
				 FROM token_usage
				 WHERE session_id IN (`+placeholders+`) AND COALESCE(model, '') != ''
				 GROUP BY session_id, model
			) GROUP BY session_id, model ORDER BY session_id, turns DESC, model ASC`,
			modelArgs...)
		if mErr == nil {
			modelsBySession := make(map[string][]string, len(out))
			for modelRows.Next() {
				var sid, model string
				var turns int64
				if err := modelRows.Scan(&sid, &model, &turns); err != nil {
					continue
				}
				modelsBySession[sid] = append(modelsBySession[sid], model)
			}
			_ = modelRows.Close()
			for i, sr := range out {
				if ms, ok := modelsBySession[sr.ID]; ok {
					out[i].Models = ms
				}
			}
		} else {
			s.opts.Logger.Warn("sessions: per-session model list failed", "err", mErr)
		}
	}

	// Attach session classification for the page: exactly TWO batched store
	// queries (tags + annotations), both scoped to the page's session ids. A
	// failure degrades the page to "no classification shown" rather than 500ing
	// the whole list — tags are an annotation layer, not the data.
	if len(pageIDs) > 0 {
		st := store.New(s.db())
		if tagsBySession, tErr := st.ListSessionTags(r.Context(), pageIDs); tErr == nil {
			for i := range out {
				out[i].Tags = tagsBySession[out[i].ID]
			}
		} else {
			s.opts.Logger.Warn("sessions: per-session tag load failed", "err", tErr)
		}
		if annots, aErr := st.ListAnnotations(r.Context(), pageIDs); aErr == nil {
			for i := range out {
				a := annots[out[i].ID]
				out[i].Favorite = a.Favorite
				out[i].HasNote = a.Note != ""
				out[i].Rating = a.Rating
				out[i].Title = a.Title
			}
		} else {
			s.opts.Logger.Warn("sessions: per-session annotation load failed", "err", aErr)
		}

		progress := s.cloudListEnrichmentProgress(r.Context(), st, pageIDs)
		for i := range out {
			out[i].CloudEnrichment = progress[out[i].ID]
		}

		// Attach cloud-intelligence enrichment state: ONE batched query over
		// the page's session ids through the store seam
		// (internal/store/cloudlocal_enriched.go::LoadCloudEnrichedTitles),
		// scoped to the current (non-superseded) result per session. A
		// failure degrades to "no enrichment shown" rather than 500ing the
		// list — same posture as tags/annotations above.
		if titleBySession, cErr := st.LoadCloudEnrichedTitles(r.Context(), pageIDs); cErr == nil {
			for i := range out {
				if title, ok := titleBySession[out[i].ID]; ok {
					out[i].CloudEnriched = true
					out[i].CloudTitle = title
				}
			}
		} else {
			s.opts.Logger.Warn("sessions: per-session cloud-enrichment load failed", "err", cErr)
		}

		// The org-plane AI title (parity phase 3), the third title source
		// after the developer's own and the personal-plane AI title. Withheld
		// when the organization hid the `intel` subsection, so a hidden
		// org-plane section never reappears as list text.
		if !s.hiddenSettingsSet(r.Context())["intel"] {
			if orgTitles, oErr := st.LoadOrgIntelTitles(r.Context(), pageIDs); oErr == nil {
				for i := range out {
					out[i].OrgTitle = orgTitles[out[i].ID]
				}
			} else {
				s.opts.Logger.Warn("sessions: per-session org-enrichment load failed", "err", oErr)
			}
			if orgOwned, oErr := st.LoadOrgAuthoritySessions(r.Context(), pageIDs); oErr == nil {
				for i := range out {
					if orgOwned[out[i].ID] {
						out[i].EnrichPlane = "org"
					}
				}
			} else {
				s.opts.Logger.Warn("sessions: per-session authority load failed", "err", oErr)
			}
		}
	}

	// Page footer totals so the frontend footer reconciles with the visible
	// rows even when the global sort surfaced a different slice.
	var pageCost, pageAICost, pageToolCost float64
	for _, sr := range out {
		pageCost += sr.CostUSD
		pageAICost += sr.AICostUSD
		pageToolCost += sr.ToolCostUSD
	}
	sortDir := "asc"
	if sortDesc {
		sortDir = "desc"
	}

	writeJSON(w, map[string]any{
		"rows":               out,
		"page":               page,
		"limit":              limit,
		"total":              total,
		"scored_count":       scoredCount,
		"days":               days,
		"sort_by":            sortBy,
		"sort_dir":           sortDir,
		"page_cost_usd":      pageCost,
		"page_ai_cost_usd":   pageAICost,
		"page_tool_cost_usd": pageToolCost,
	})
}

// handleSessionsCalendar — GET /api/sessions/calendar?days=N
//
// Returns one row per day across the window: {day, session_count,
// cost_usd}. Dashboard's Calendar view consumes this so the grid
// spans the full Window with real per-day distribution instead of
// the most recent page-50 slice. Session counts come from a GROUP
// BY date(started_at) over sessions; costs come from the cost engine
// rolled up GroupByDay over the same window.
func (s *Server) handleSessionsCalendar(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 365)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	since, until := windowRange(r, 30, 1, 365)

	// Session count per day.
	var where []string
	args := []any{since.Format(time.RFC3339Nano)}
	where = append(where, "started_at >= ?")
	if !until.IsZero() {
		where = append(where, "started_at < ?")
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
	model := modelParam(r)
	if frag, margs := modelfilter.SessionsUsing("id", model); frag != "" {
		where = append(where, frag)
		args = append(args, margs...)
	}
	rows, err := s.db().QueryContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT substr(started_at, 1, 10) AS day, COUNT(*) AS n
		   FROM sessions
		  WHERE `+strings.Join(where, " AND ")+` AND `+nonEmptySessionPredicateSessions+`
		  GROUP BY day
		  ORDER BY day`, args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()

	type cell struct {
		Day          string  `json:"day"`
		SessionCount int     `json:"session_count"`
		CostUSD      float64 `json:"cost_usd"`
	}
	byDay := map[string]*cell{}
	order := []string{}
	for rows.Next() {
		var day string
		var n int
		if err := rows.Scan(&day, &n); err != nil {
			writeErr(w, err)
			return
		}
		byDay[day] = &cell{Day: day, SessionCount: n}
		order = append(order, day)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}

	// Cost per day — cost.Summary with GroupByDay covers turn-date
	// bucketing across the same window, joined back onto the session
	// day map. A session that ran across midnight will have its turns
	// land on multiple days; that's expected behaviour and matches
	// the daily cost shown on /cost.
	costSummary, err := s.opts.CostEngine.Summary(r.Context(), s.db(), cost.Options{
		Days:        days,
		Since:       since, // window the cost rollup exactly like the session count above
		Until:       until, // (hours=1 must return 1h costs, not the 30d default window)
		GroupBy:     cost.GroupByDay,
		Source:      cost.SourceAuto,
		ProjectRoot: project,
		Tool:        tool, // align per-day cost with the tool-filtered session count above
		Model:       model,
		Limit:       365,
	})
	if err == nil {
		for _, row := range costSummary.Rows {
			c, ok := byDay[row.Key]
			if !ok {
				c = &cell{Day: row.Key}
				byDay[row.Key] = c
				order = append(order, row.Key)
			}
			c.CostUSD = row.CostUSD
		}
	} else {
		s.opts.Logger.Warn("sessions calendar: cost rollup failed", "err", err)
	}

	out := make([]cell, 0, len(order))
	seen := map[string]bool{}
	for _, k := range order {
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, *byDay[k])
	}
	// Stable sort by day ascending so the frontend can iterate the
	// returned slice in order regardless of insertion order.
	sort.Slice(out, func(i, j int) bool { return out[i].Day < out[j].Day })
	writeJSON(w, map[string]any{
		"days":  days,
		"cells": out,
	})
}
