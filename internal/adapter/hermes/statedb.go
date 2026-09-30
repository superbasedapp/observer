package hermes

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// sessionRow is the subset of the sessions-table columns the adapter
// reads. Schema v14 reference: testdata/hermes/schema-sessions.sql.
//
// Notable deltas vs. the original plan §3.1 (captured in the
// 2026-06-05 reality check, docs/hermes-adapter-plan.md §17.1):
//   - cwd: documented as missing; actually present. Drives project
//     root resolution without any inference.
//   - handoffState / handoffPlatform / handoffError / rewindCount /
//     archived: schema-v14 additions not in the original plan;
//     surfaced into metadata when non-default.
type sessionRow struct {
	ID               string
	Source           string
	Model            string
	CWD              string
	SystemPrompt     string
	StartedAt        float64
	EndedAt          sql.NullFloat64
	EndReason        sql.NullString
	MessageCount     int64
	ToolCallCount    int64
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
	ReasoningTokens  int64
	EstimatedCostUSD sql.NullFloat64
	ActualCostUSD    sql.NullFloat64
	APICallCount     int64
	HandoffState     sql.NullString
	HandoffPlatform  sql.NullString
	RewindCount      int64
	Archived         int64
	ParentSessionID  sql.NullString
	// AuxUsage carries the session's AUXILIARY-call spend rows from
	// session_model_usage (task != ''): vision, compression,
	// title_generation, background_review, ... Hermes records those
	// calls ONLY there - record_auxiliary_usage writes "WITHOUT
	// touching the sessions summary row" (hermes_state_usage.py,
	// v2026.9.24, issue #23270) - so the aggregate columns above never
	// include them. Empty on a pre-session_model_usage schema (the
	// grounded v16 store has no such table).
	AuxUsage []auxUsageRow
}

// auxUsageRow is one session_model_usage row with a non-empty task.
// The table's primary key is (session_id, model, billing_provider,
// billing_base_url, billing_mode, task); every counter is an
// ACCUMULATED per-call delta sum (the upsert adds excluded.* onto the
// row), so it only ever grows - the same monotonic shape the session
// aggregate has, which keeps the store's MAX-upgrade conflict path
// correct on re-emit.
type auxUsageRow struct {
	Model            string
	BillingProvider  string
	BillingBaseURL   string
	BillingMode      string
	Task             string
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
	ReasoningTokens  int64
	EstimatedCostUSD float64
	ActualCostUSD    float64
	LastSeen         sql.NullFloat64
}

// messageRow is the subset of the messages-table columns the adapter
// reads. Filtered to active=1 at query time per the §17.1 reality
// check — active=0 marks rewound or compressed-out rows that must
// not produce events.
type messageRow struct {
	ID           int64
	SessionID    string
	Role         string
	Content      sql.NullString
	ToolCallID   sql.NullString
	ToolCalls    sql.NullString
	ToolName     sql.NullString
	Timestamp    float64
	TokenCount   sql.NullInt64
	FinishReason sql.NullString
	// Reasoning / ReasoningContent carry the model's chain-of-thought
	// text (messages.reasoning / messages.reasoning_content, schema-v14).
	// Both are populated identically in the live corpus; we prefer
	// reasoning_content and fall back to reasoning. Distinct from the
	// session-level reasoning_tokens COUNT.
	Reasoning         sql.NullString
	ReasoningContent  sql.NullString
	PlatformMessageID sql.NullString
}

// toolCallWrapper matches the tool_calls JSON shape Hermes writes into
// messages.tool_calls. Schema-v14 reality (see
// testdata/hermes/reality-check.txt) carries:
//
//	[{"id": "call_xxx",
//	  "call_id": "call_xxx",
//	  "response_item_id": "fc_xxx",
//	  "type": "function",
//	  "function": {"name": "...", "arguments": "{...JSON-encoded...}"}}]
//
// We extract only what we need (id + function.name + function.arguments)
// and tolerate the call_id / response_item_id / type extras the plan
// §11.3 missed. arguments is a JSON-encoded STRING (not a child object).
type toolCallWrapper struct {
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// scanStateDB opens state.db read-only, reads all messages with id
// strictly greater than fromMessageID (and active=1), reads the
// session metadata for every session referenced by those messages,
// and returns both row sets plus the largest message id seen (used
// by the watcher as the next cursor).
//
// The DSN matches cursor adapter's storedb.go pattern: mode=ro,
// query_only(1), and a 2-second busy_timeout so concurrent Hermes
// writers don't make us hang. MaxOpenConns(1) prevents accidental
// concurrent reads from a single Adapter instance — same belt-AND-
// braces cursor uses.
//
// Idempotency: messages.id is AUTOINCREMENT, so the returned maxID
// is a deterministic, monotonically-increasing watermark suitable
// for the watcher's parse_cursors row. Re-running with the same
// fromMessageID returns the same result set bytewise (modulo
// concurrent Hermes activity).
func scanStateDB(ctx context.Context, dbPath string, fromMessageID int64) (map[string]sessionRow, []messageRow, int64, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)",
		sqlitedsn.Escape(dbPath))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, nil, fromMessageID, fmt.Errorf("hermes.scanStateDB: open: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// Verify the schema is something we understand. We accept any
	// version >= 11 (the plan's original target) — newer versions
	// add columns but the columns we read remain backward-compatible
	// per Hermes's documented stability promise on the public plugin
	// + schema surfaces.
	if v, ok := readSchemaVersion(ctx, db); ok && v < 11 {
		return nil, nil, fromMessageID, fmt.Errorf("hermes.scanStateDB: schema version %d below supported floor 11", v)
	}

	messages, maxID, err := readMessages(ctx, db, fromMessageID)
	if err != nil {
		return nil, nil, fromMessageID, fmt.Errorf("hermes.scanStateDB: messages: %w", err)
	}
	if len(messages) == 0 {
		return map[string]sessionRow{}, nil, maxID, nil
	}

	// Collect distinct session IDs from the new messages; read those
	// sessions only. Avoids scanning sessions we have no new activity
	// for.
	wantSessions := map[string]struct{}{}
	for _, m := range messages {
		wantSessions[m.SessionID] = struct{}{}
	}
	sessions, err := readSessions(ctx, db, wantSessions)
	if err != nil {
		return nil, nil, maxID, fmt.Errorf("hermes.scanStateDB: sessions: %w", err)
	}
	if err := readAuxUsage(ctx, db, sessions); err != nil {
		return nil, nil, maxID, fmt.Errorf("hermes.scanStateDB: aux usage: %w", err)
	}
	return sessions, messages, maxID, nil
}

// readAuxUsage attaches each session's auxiliary-call usage rows
// (session_model_usage rows with a non-empty task) onto sessions[id].AuxUsage. A store
// without the table (every schema before the per-model usage split)
// is a silent no-op, never an error. Main-loop rows (empty task) are
// NOT read: they are the same spend the sessions aggregate already
// carries, split per model, so reading them too would double-count.
func readAuxUsage(ctx context.Context, db *sql.DB, sessions map[string]sessionRow) error {
	if len(sessions) == 0 || !tableExists(ctx, db, "session_model_usage") {
		return nil
	}
	ids := make([]any, 0, len(sessions))
	placeholders := make([]byte, 0, len(sessions)*2)
	for id := range sessions {
		if len(placeholders) > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		ids = append(ids, id)
	}
	/* #nosec G202 -- placeholders is literal '?,' built from the sessions count above; ids bind as positional params */
	query := `
		SELECT session_id, COALESCE(model, ''), COALESCE(billing_provider, ''),
		       COALESCE(billing_base_url, ''), COALESCE(billing_mode, ''), task,
		       COALESCE(input_tokens, 0), COALESCE(output_tokens, 0),
		       COALESCE(cache_read_tokens, 0), COALESCE(cache_write_tokens, 0),
		       COALESCE(reasoning_tokens, 0),
		       COALESCE(estimated_cost_usd, 0), COALESCE(actual_cost_usd, 0),
		       last_seen
		  FROM session_model_usage
		 WHERE task IS NOT NULL AND task != ''
		   AND session_id IN (` + string(placeholders) + `)
	  ORDER BY session_id, task, model, billing_provider, billing_base_url, billing_mode`
	rows, err := db.QueryContext(ctx, query, ids...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var sid string
		var r auxUsageRow
		if err := rows.Scan(&sid, &r.Model, &r.BillingProvider, &r.BillingBaseURL, &r.BillingMode, &r.Task,
			&r.InputTokens, &r.OutputTokens, &r.CacheReadTokens, &r.CacheWriteTokens, &r.ReasoningTokens,
			&r.EstimatedCostUSD, &r.ActualCostUSD, &r.LastSeen); err != nil {
			return err
		}
		s, ok := sessions[sid]
		if !ok {
			continue
		}
		s.AuxUsage = append(s.AuxUsage, r)
		sessions[sid] = s
	}
	return rows.Err()
}

// tableExists reports whether the named table is present. False on any
// query error - callers treat an unreadable catalogue as "absent".
func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// readSchemaVersion returns the integer in schema_version. False ok
// means the table is missing or unreadable — we treat that as
// "unknown" rather than fatal so a stripped-down test fixture without
// the version table still parses.
func readSchemaVersion(ctx context.Context, db *sql.DB) (int, bool) {
	var v int
	if err := db.QueryRowContext(ctx, "SELECT version FROM schema_version LIMIT 1").Scan(&v); err != nil {
		return 0, false
	}
	return v, true
}

// readMessages pulls messages with id > fromMessageID, active=1,
// ordered by id ascending. The 13-column projection matches
// messageRow; null-tolerant columns use sql.Null* types.
//
// Note: archived=1 sessions are NOT filtered at the messages layer —
// the messageRow set goes through the sessions filter downstream
// (parse.go), which can elect to drop archived sessions entirely.
func readMessages(ctx context.Context, db *sql.DB, fromMessageID int64) ([]messageRow, int64, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, session_id, role, content, tool_call_id, tool_calls,
		       tool_name, timestamp, token_count, finish_reason,
		       reasoning, reasoning_content, platform_message_id
		  FROM messages
		 WHERE id > ?
		   AND active = 1
	  ORDER BY id ASC`, fromMessageID)
	if err != nil {
		return nil, fromMessageID, err
	}
	defer rows.Close()

	var out []messageRow
	maxID := fromMessageID
	for rows.Next() {
		var m messageRow
		if err := rows.Scan(
			&m.ID, &m.SessionID, &m.Role, &m.Content, &m.ToolCallID, &m.ToolCalls,
			&m.ToolName, &m.Timestamp, &m.TokenCount, &m.FinishReason,
			&m.Reasoning, &m.ReasoningContent, &m.PlatformMessageID,
		); err != nil {
			return nil, maxID, err
		}
		if m.ID > maxID {
			maxID = m.ID
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, maxID, err
	}
	return out, maxID, nil
}

// readSessions pulls every row in wantIDs from the sessions table.
// Uses a single SELECT … IN (?, ?, …) so the round-trip is one
// statement regardless of how many sessions the message batch
// touched.
func readSessions(ctx context.Context, db *sql.DB, wantIDs map[string]struct{}) (map[string]sessionRow, error) {
	if len(wantIDs) == 0 {
		return map[string]sessionRow{}, nil
	}
	ids := make([]any, 0, len(wantIDs))
	placeholders := make([]byte, 0, len(wantIDs)*2-1)
	for id := range wantIDs {
		if len(placeholders) > 0 {
			placeholders = append(placeholders, ',')
		}
		placeholders = append(placeholders, '?')
		ids = append(ids, id)
	}
	// placeholders is built from literal '?' and ',' only (see the
	// loop above); ids are bound as positional parameters via
	// QueryContext below. No user input enters the SQL string —
	// the gosec G202 finding is a false positive for this
	// safe-by-construction WHERE-IN pattern.
	/* #nosec G202 -- placeholders is literal '?,' built from the wantIDs count above; ids bind as positional params */
	query := `
		SELECT id, source, model, cwd, system_prompt, started_at, ended_at, end_reason,
		       message_count, tool_call_count, input_tokens, output_tokens,
		       cache_read_tokens, cache_write_tokens, reasoning_tokens,
		       estimated_cost_usd, actual_cost_usd, api_call_count,
		       handoff_state, handoff_platform, rewind_count, archived,
		       parent_session_id
		  FROM sessions
		 WHERE id IN (` + string(placeholders) + `)`
	rows, err := db.QueryContext(ctx, query, ids...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]sessionRow{}
	for rows.Next() {
		var s sessionRow
		var cwd, source, model, systemPrompt sql.NullString
		if err := rows.Scan(
			&s.ID, &source, &model, &cwd, &systemPrompt, &s.StartedAt, &s.EndedAt, &s.EndReason,
			&s.MessageCount, &s.ToolCallCount, &s.InputTokens, &s.OutputTokens,
			&s.CacheReadTokens, &s.CacheWriteTokens, &s.ReasoningTokens,
			&s.EstimatedCostUSD, &s.ActualCostUSD, &s.APICallCount,
			&s.HandoffState, &s.HandoffPlatform, &s.RewindCount, &s.Archived,
			&s.ParentSessionID,
		); err != nil {
			return nil, err
		}
		s.Source = source.String
		s.Model = model.String
		s.CWD = cwd.String
		s.SystemPrompt = systemPrompt.String
		out[s.ID] = s
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// parseToolCalls deserialises a messages.tool_calls JSON array. The
// wrapper struct only extracts id + function.name + function.arguments;
// the call_id / response_item_id / type extras Hermes adds beyond the
// plan's documented shape are ignored silently. Returns nil on
// invalid JSON (the caller logs a warning and skips the row).
func parseToolCalls(raw string) ([]toolCallWrapper, error) {
	if raw == "" {
		return nil, nil
	}
	var out []toolCallWrapper
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}
