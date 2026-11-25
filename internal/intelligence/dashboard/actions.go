package dashboard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/modelfilter"
)

// loadActionExcerpts fetches the first action_excerpts.excerpt for each
// id, truncated to maxBytes when > 0. Returns map[action_id] -> excerpt.
//
// action_excerpts is an FTS5 virtual table with action_id declared
// UNINDEXED, so a direct `WHERE action_id IN (...)` is a FULL scan of every
// excerpt (450k rows / 351 MB on the 2026-09-29 reference node — half the
// CPU of a session Messages poll). Instead the ids are resolved to FTS
// rowids through the ordinary shadow table action_excerpts_content, whose
// c0 column holds action_id and is indexed by agent migration 147
// (idx_action_excerpts_content_c0), and the virtual table then answers by
// rowid equality lookups. Without that index the query is still correct,
// just a scan of the shadow table.
//
// "First" means the lowest FTS rowid per action_id — the row the previous
// full-scan form (which iterated in rowid order) kept — so the map
// preserves the `LIMIT 1`/`COALESCE(ae.excerpt, ”)` behavior of the
// original correlated queries (action_excerpts can hold multiple rows per
// action_id when the same action was re-indexed). The rowid is selected and
// compared explicitly rather than trusting the rowid-IN iteration order.
// Ids are chunked (idQueryChunk per statement) so a large session never
// approaches SQLite's host-parameter limit.
func loadActionExcerpts(ctx context.Context, db *sql.DB, ids []int64, maxBytes int) (map[int64]string, error) {
	out := make(map[int64]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	col := "excerpt"
	if maxBytes > 0 {
		col = fmt.Sprintf("substr(excerpt, 1, %d)", maxBytes)
	}
	firstRowid := make(map[int64]int64, len(ids))
	err := forEachIDChunk(uniqueIDs(ids), idQueryChunk, func(chunk []int64) error {
		placeholders, args := idPlaceholders(chunk)
		//nolint:gosec // G202: col is one of two code-built expressions (maxBytes is an int) and the IN list is "?" placeholders; every value is bound.
		q := "SELECT rowid, action_id, " + col + " FROM action_excerpts" +
			" WHERE rowid IN (SELECT id FROM action_excerpts_content WHERE c0 IN (" + placeholders + "))"
		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rowid, id int64
			var excerpt string
			if err := rows.Scan(&rowid, &id, &excerpt); err != nil {
				return err
			}
			if prev, ok := firstRowid[id]; !ok || rowid < prev {
				firstRowid[id] = rowid
				out[id] = excerpt
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("dashboard.loadActionExcerpts: %w", err)
	}
	return out, nil
}

func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	limit := intArg(r, "limit", 50, 1, 500)
	page := intArg(r, "page", 1, 1, 1_000_000)
	offset := (page - 1) * limit
	tool := r.URL.Query().Get("tool")
	sessionID := r.URL.Query().Get("session_id")
	actionType := r.URL.Query().Get("action_type")
	project := r.URL.Query().Get("project")
	// v1.4.48: metadata filters land on the migration-017 actions.metadata
	// JSON column via SQLite's json_extract (no JSON1 dependency added —
	// modernc.org/sqlite ships it). Empty params skip the filter entirely
	// so the legacy /api/actions surface is unchanged for callers that
	// don't pass them.
	effortLevel := r.URL.Query().Get("effort_level")
	permissionMode := r.URL.Query().Get("permission_mode")
	isInterrupt := r.URL.Query().Get("is_interrupt")
	// v1.4.49: assistant_text filter surfaces "what did the AI say to the
	// user?" rows from any adapter. The multi-pattern OR-chain
	// accommodates the RawToolName convention drift documented in
	// docs/handover-v1.4.49 — new wirings use `<source>.assistant_text`,
	// legacy precedents stay as-is (Pi's `message.assistant.<stopReason>`,
	// Copilot's `agent_response`, Antigravity's `structured.assistant_text`,
	// openclaw's `message.assistant.stop`).
	assistantText := r.URL.Query().Get("assistant_text")
	// Date filters — accept YYYY-MM-DD prefix matching against
	// substr(a.timestamp, 1, 10). The Timeline view passes from_date
	// = to_date when the user picks a single day from the day strip.
	fromDate := r.URL.Query().Get("from_date")
	toDate := r.URL.Query().Get("to_date")
	// Window filter — same `days` contract as /api/sessions and
	// /api/status/scoped (0 = absent = no filter, so legacy callers
	// keep the unwindowed firehose). The header's 7d/14d/… selector
	// was a no-op on this page until this landed.
	since, until := windowRange(r, 0, 0, 36500)

	var where []string
	var args []any
	if !since.IsZero() {
		where = append(where, "a.timestamp >= ?")
		args = append(args, since.Format(time.RFC3339Nano))
	}
	if !until.IsZero() {
		where = append(where, "a.timestamp < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if tool != "" {
		where = append(where, "a.tool = ?")
		args = append(args, tool)
	}
	if sessionID != "" {
		where = append(where, "a.session_id = ?")
		args = append(args, sessionID)
	}
	if actionType != "" {
		where = append(where, "a.action_type = ?")
		args = append(args, actionType)
	}
	if project != "" {
		where = append(where, "a.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	// Model filter (session grain): actions of sessions that used the model.
	if frag, margs := modelfilter.SessionsUsing("a.session_id", modelParam(r)); frag != "" {
		where = append(where, frag)
		args = append(args, margs...)
	}
	// from_date / to_date stay day-grained (substr) for compat; the
	// genuinely-new sub-day params win when both are present — but only
	// when they actually RESOLVED (a malformed until/since/hours fails
	// open in windowRange, so the legacy param must still apply). Legacy
	// `days`+from_date keeps its historical AND behavior (`days` is not
	// gated here).
	newLower, newUpper := windowBoundsResolved(r)
	if fromDate != "" && !newLower {
		where = append(where, "substr(a.timestamp, 1, 10) >= ?")
		args = append(args, fromDate)
	}
	if toDate != "" && !newUpper {
		where = append(where, "substr(a.timestamp, 1, 10) <= ?")
		args = append(args, toDate)
	}
	if effortLevel != "" {
		where = append(where, "json_extract(a.metadata, '$.effort_level') = ?")
		args = append(args, effortLevel)
	}
	if permissionMode != "" {
		where = append(where, "json_extract(a.metadata, '$.permission_mode') = ?")
		args = append(args, permissionMode)
	}
	if isInterrupt == "1" {
		// SQLite's json_extract on a JSON boolean returns 1/0 (integer)
		// — compare against 1 not "true". Rows where metadata is NULL or
		// is_interrupt is absent return NULL from json_extract, which
		// fails the equality and is correctly excluded.
		where = append(where, "json_extract(a.metadata, '$.is_interrupt') = 1")
	}
	if assistantText == "1" {
		// `<source>.assistant_text` covers new wirings (codex / cline /
		// roo-code / claudecode / cursor / gemini / opencode / openclaw).
		// `structured.assistant_text` is Antigravity's pre-existing
		// RawToolName. `message.assistant.<stopReason>` is Pi.
		// `message.assistant.stop` is OpenClaw's legacy marker row.
		// `agent_response` is Copilot's pre-existing RawToolName. All
		// four legacy names are left alone per the v1.4.49 convention
		// decision to avoid SourceEventID dedup churn.
		where = append(where, `(
			a.raw_tool_name LIKE '%.assistant_text'
			OR a.raw_tool_name LIKE 'message.assistant.%'
			OR a.raw_tool_name = 'agent_response'
		)`)
	}
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	var total int
	countArgs := append([]any{}, args...)
	if err := s.db().QueryRowContext( //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		r.Context(),
		"SELECT COUNT(*) FROM actions a "+whereClause, countArgs...,
	).Scan(&total); err != nil {
		writeErr(w, err)
		return
	}

	dataArgs := append([]any{}, args...)
	dataArgs = append(dataArgs, limit, offset)
	// Excerpt is loaded in a second batch query — see loadActionExcerpts
	// for why an inline subquery is O(N×M) on the FTS5 action_excerpts
	// table.
	rows, err := s.db().QueryContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT a.id, a.timestamp, a.tool, a.session_id,
		        COALESCE(p.root_path, ''), a.action_type,
		        COALESCE(a.raw_tool_name, ''), COALESCE(a.target, ''),
		        COALESCE(a.success, 1), COALESCE(a.error_message, ''),
		        COALESCE(a.message_id, ''),
		        COALESCE(json_extract(a.metadata, '$.permission_mode'), '') AS permission_mode,
		        COALESCE(json_extract(a.metadata, '$.effort_level'), '') AS effort_level,
		        COALESCE(json_extract(a.metadata, '$.is_interrupt'), 0) AS is_interrupt,
		        COALESCE(json_extract(a.metadata, '$.stop_reason'), '') AS stop_reason,
		        COALESCE(json_extract(a.metadata, '$.service_tier'), '') AS service_tier,
		        COALESCE(a.source_file, ''),
		        COALESCE(a.source_event_id, '')
		 FROM actions a
		 LEFT JOIN projects p ON p.id = a.project_id
		 `+whereClause+`
		 ORDER BY a.timestamp DESC, a.id DESC LIMIT ? OFFSET ?`, dataArgs...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()
	type actionRow struct {
		ID           int64  `json:"id"`
		Timestamp    string `json:"timestamp"`
		Tool         string `json:"tool"`
		SessionID    string `json:"session_id"`
		Project      string `json:"project"`
		ActionType   string `json:"action_type"`
		RawToolName  string `json:"raw_tool_name"`
		Target       string `json:"target"`
		Success      bool   `json:"success"`
		ErrorMessage string `json:"error_message,omitempty"`
		// MessageID is the upstream Anthropic msg_xxx id for the API
		// turn that produced this action (populated by the claudecode
		// adapter, the message-id backfill, and the api_error path).
		// For user_prompt rows it carries the synthesized "user:<id>"
		// form; for tool_use rows the parent assistant message's id.
		// Lets the Actions tab link a row back to the per-message
		// timeline modal via the same id surfaced on the Compression
		// events table.
		MessageID string `json:"message_id"`
		// Per-event metadata extracted from actions.metadata JSON
		// (migration 017). Empty / false when the row pre-dates
		// the migration or the source adapter didn't emit the
		// field. omitempty keeps the response payload lean.
		PermissionMode string `json:"permission_mode,omitempty"`
		EffortLevel    string `json:"effort_level,omitempty"`
		IsInterrupt    bool   `json:"is_interrupt,omitempty"`
		// StopReason — why the assistant turn ended (end_turn / max_tokens
		// / tool_use / stop_sequence / refusal). ServiceTier — the served
		// capacity tier (standard / priority / batch). Both per-message,
		// captured from the transcript (claude-code, cowork). Empty for
		// rows that pre-date capture or adapters that don't emit them.
		StopReason  string `json:"stop_reason,omitempty"`
		ServiceTier string `json:"service_tier,omitempty"`
		// SourceFile / SourceEventID — provenance for this row. Tells
		// the user which JSONL or proxy capture produced the event.
		// SourceFile may be empty for synthesized rows (e.g. hook
		// closures) where the adapter doesn't track a file origin.
		SourceFile    string `json:"source_file,omitempty"`
		SourceEventID string `json:"source_event_id,omitempty"`
		// Excerpt — first 280 chars of the action's indexed body from
		// action_excerpts. Lets the Actions table surface "what did
		// the tool actually do" inline without a row-expand click;
		// the full text remains retrievable via /api/actions/<id> when
		// that endpoint lands.
		Excerpt string `json:"excerpt,omitempty"`
	}
	var out []actionRow
	for rows.Next() {
		var ar actionRow
		var isInterrupt int
		if err := rows.Scan(&ar.ID, &ar.Timestamp, &ar.Tool, &ar.SessionID, &ar.Project,
			&ar.ActionType, &ar.RawToolName, &ar.Target, &ar.Success, &ar.ErrorMessage,
			&ar.MessageID, &ar.PermissionMode, &ar.EffortLevel, &isInterrupt,
			&ar.StopReason, &ar.ServiceTier,
			&ar.SourceFile, &ar.SourceEventID); err != nil {
			writeErr(w, err)
			return
		}
		ar.IsInterrupt = isInterrupt != 0
		out = append(out, ar)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	if out == nil {
		out = []actionRow{}
	}
	ids := make([]int64, len(out))
	for i, r := range out {
		ids[i] = r.ID
	}
	excerpts, err := loadActionExcerpts(r.Context(), s.db(), ids, 280)
	if err != nil {
		writeErr(w, err)
		return
	}
	for i := range out {
		out[i].Excerpt = excerpts[out[i].ID]
	}
	writeJSON(w, map[string]any{
		"rows":  out,
		"page":  page,
		"limit": limit,
		"total": total,
	})
}

// handleActionsDayCounts — GET /api/actions/day-counts?days=N
//
// fullTextInlineMax is the per-row preview cap embedded in
// /api/session/<id>/messages. Anything longer is truncated to this
// length and surfaced with full_text_elided=true so the frontend
// knows to fetch the untruncated body via /api/action/<id>/full_text
// only when the operator actually clicks copy / view. Keeps the
// timeline payload bounded regardless of how large any single row's
// raw_tool_input grows post-migration-027.
const fullTextInlineMax = 4000

// handleActionDetail handles /api/action/<id>/<sub>. The only currently
// supported sub-resource is `full_text`, which returns the untruncated
// raw_tool_input + raw_tool_output for an action so the dashboard's
// copy and view-full-text buttons can fetch on demand instead of
// embedding multi-MB blobs in every /messages response.
//
// Bounded by the adapter-side internal/contentcap.DefaultMaxBytes
// (1 MiB per column); rows that overflowed adapter capture carry the
// trailing "…(content truncated at N bytes)…" marker so the operator
// can tell the served body is itself a truncation.
func (s *Server) handleActionDetail(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/action/")
	if !strings.HasSuffix(rest, "/full_text") {
		http.Error(w, "unsupported action sub-resource", http.StatusNotFound)
		return
	}
	idStr := strings.TrimSuffix(rest, "/full_text")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "missing or invalid action id", http.StatusBadRequest)
		return
	}
	var (
		actionType string
		target     string
		rawInput   sql.NullString
		rawOutput  sql.NullString
	)
	err = s.db().QueryRowContext(
		r.Context(),
		`SELECT action_type, COALESCE(target, ''), raw_tool_input, raw_tool_output
		   FROM actions WHERE id = ?`, id,
	).Scan(&actionType, &target, &rawInput, &rawOutput)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "action not found", http.StatusNotFound)
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	fullInput := rawInput.String
	if actionType == "run_command" && fullInput != "" {
		fullInput = decodeCommandInput(fullInput)
	}
	type resp struct {
		ActionID      int64  `json:"action_id"`
		ActionType    string `json:"action_type"`
		Target        string `json:"target,omitempty"`
		RawToolInput  string `json:"raw_tool_input,omitempty"`
		RawToolOutput string `json:"raw_tool_output,omitempty"`
	}
	writeJSON(w, resp{
		ActionID:      id,
		ActionType:    actionType,
		Target:        target,
		RawToolInput:  fullInput,
		RawToolOutput: rawOutput.String,
	})
}

// Returns one row per day in the window: {day, count}. Drives the
// Actions Timeline view's day strip so every day in the configured
// Window is selectable even when it lies outside the most-recent
// page-500 slice. Honors the same tool/project filters as
// /api/actions so the strip aligns with whatever's filtered.
func (s *Server) handleActionsDayCounts(w http.ResponseWriter, r *http.Request) {
	days := intArg(r, "days", 30, 1, 365)
	tool := r.URL.Query().Get("tool")
	project := r.URL.Query().Get("project")
	since, until := windowRange(r, 30, 1, 365)

	where := []string{"a.timestamp >= ?"}
	args := []any{since.Format(time.RFC3339Nano)}
	if !until.IsZero() {
		where = append(where, "a.timestamp < ?")
		args = append(args, until.Format(time.RFC3339Nano))
	}
	if tool != "" {
		where = append(where, "a.tool = ?")
		args = append(args, tool)
	}
	if project != "" {
		where = append(where, "a.project_id = (SELECT id FROM projects WHERE root_path = ?)")
		args = append(args, project)
	}
	if frag, margs := modelfilter.SessionsUsing("a.session_id", modelParam(r)); frag != "" {
		where = append(where, frag)
		args = append(args, margs...)
	}
	rows, err := s.db().QueryContext(r.Context(), //nolint:gosec // G701: the query text is code constants plus constant-column fragments (modelfilter, timebucket); every request value is a bound ? arg
		//nolint:gosec // G202: SQL structure (WHERE/JOIN/scope fragments and any IN placeholder list) is built from code constants; all values are bound via ? args.
		`SELECT substr(a.timestamp, 1, 10) AS day, COUNT(*) AS n
		   FROM actions a
		  WHERE `+strings.Join(where, " AND ")+`
		  GROUP BY day
		  ORDER BY day`, args...)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer rows.Close()

	type cell struct {
		Day   string `json:"day"`
		Count int    `json:"count"`
	}
	out := []cell{}
	for rows.Next() {
		var c cell
		if err := rows.Scan(&c.Day, &c.Count); err != nil {
			writeErr(w, err)
			return
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"days":  days,
		"cells": out,
	})
}
