package clinecli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// sessionRow is the subset of the 28-column sessions table the adapter
// reads. Schema reference: testdata/clinecli/schema-sessions.sql,
// schema v1 (Cline CLI 3.0.20).
//
// Notable points captured during Phase 0:
//
//   - `cwd` is always populated for CLI sessions — drives ProjectRoot
//     resolution directly (no env-details scan needed, unlike the
//     cline-vscode V1 fix).
//   - `metadata_json` carries the cost / usage / checkpoint history
//     blob; we parse it into sessionMetadata at scan time.
//   - `messages_path` is the absolute path to the paired
//     <id>.messages.json on the writer-host's filesystem. Cross-mount-
//     translated before any os.Open call so a Windows-side session
//     read from a WSL2 observer resolves correctly.
//   - `parent_session_id` / `parent_agent_id` / `agent_id` /
//     `is_subagent` underpin the subagent linkage commit (Phase 2
//     commit 7 of the plan).
type sessionRow struct {
	ID              string
	Source          string
	PID             int64
	StartedAt       string // ISO 8601
	EndedAt         sql.NullString
	ExitCode        sql.NullInt64
	Status          string
	Interactive     int64
	Provider        string
	Model           string
	CWD             string
	WorkspaceRoot   string
	TeamName        sql.NullString
	EnableTools     int64
	EnableSpawn     int64
	EnableTeams     int64
	ParentSessionID sql.NullString
	ParentAgentID   sql.NullString
	AgentID         sql.NullString
	ConversationID  sql.NullString
	IsSubagent      int64
	Prompt          sql.NullString
	MetadataJSON    sql.NullString
	MessagesPath    sql.NullString
	UpdatedAt       string // ISO 8601 — used as the parse cursor

	// Derived after scan:
	Metadata sessionMetadata // parsed from MetadataJSON
	Messages messagesDoc     // parsed from MessagesPath file (if reachable)
}

// sessionMetadata is the shape of sessions.metadata_json — Cline CLI
// rewrites the whole blob on every persist. Captured from a live
// session: testdata/clinecli/sample-session-meta.json.
//
// `usage` is the session's own roll-up. `aggregateUsage` adds child
// subagent totals — for v1 we trust both as Cline-self-reported (Tier
// 2 approximate per plan §7). Per-message attribution lives in the
// messages.json metrics blocks (Phase 0 reality-check find).
type sessionMetadata struct {
	Title                string         `json:"title,omitempty"`
	TotalCost            float64        `json:"totalCost,omitempty"`
	AggregatedAgentsCost float64        `json:"aggregatedAgentsCost,omitempty"`
	Usage                metadataUsage  `json:"usage"`
	AggregateUsage       metadataUsage  `json:"aggregateUsage"`
	Checkpoint           map[string]any `json:"checkpoint,omitempty"`
}

type metadataUsage struct {
	InputTokens      int64   `json:"inputTokens,omitempty"`
	OutputTokens     int64   `json:"outputTokens,omitempty"`
	CacheReadTokens  int64   `json:"cacheReadTokens,omitempty"`
	CacheWriteTokens int64   `json:"cacheWriteTokens,omitempty"`
	TotalCost        float64 `json:"totalCost,omitempty"`
}

// messagesDoc is the top level of the per-session
// <id>.messages.json file. Captured from a live session:
// testdata/clinecli/sample-session-messages.json.
type messagesDoc struct {
	Version   int             `json:"version"`
	UpdatedAt string          `json:"updated_at"`
	Agent     string          `json:"agent"`
	SessionID string          `json:"sessionId"`
	Messages  []messageRecord `json:"messages"`
}

// messageRecord is one top-level message inside messages.json.
// Anthropic-shaped: role + ts + content blocks.
//
// modelInfo + metrics are populated on assistant rows only —
// per-message Tier 2 token capture from the Phase 0 reality-check
// upgrade (plan §7 originally said session-aggregate only).
type messageRecord struct {
	ID        string             `json:"id"`
	Role      string             `json:"role"`
	Ts        int64              `json:"ts"`
	Content   []messageBlock     `json:"content"`
	ModelInfo *messageModelInfo  `json:"modelInfo,omitempty"`
	Metrics   *messageUsageBlock `json:"metrics,omitempty"`
}

// messageBlock is one Anthropic-style content block. Discriminated
// union; only fields matching the block's `type` are populated.
type messageBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	Thinking  string          `json:"thinking,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
	// For tool_result rows the content is a structured LIST of
	// {query, result, success} dicts (per Phase 0 reality-check) —
	// kept as RawMessage and decoded by parse.go via a typed slice.
	Content json.RawMessage `json:"content,omitempty"`
}

type messageModelInfo struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Family   string `json:"family,omitempty"`
}

type messageUsageBlock struct {
	InputTokens      int64   `json:"inputTokens"`
	OutputTokens     int64   `json:"outputTokens"`
	CacheReadTokens  int64   `json:"cacheReadTokens"`
	CacheWriteTokens int64   `json:"cacheWriteTokens"`
	Cost             float64 `json:"cost"`
}

// scanStateDB opens sessions.db read-only, reads every session row
// with `updated_at > fromOffset` (encoded as ISO 8601), then attempts
// to read each session's paired messages.json file from disk
// (cross-mount-translated). Returns the populated session set plus
// the largest updated_at seen (UnixMilli) for the watcher's cursor.
//
// DSN matches the hermes adapter's pattern: mode=ro, query_only(1),
// busy_timeout(2000). MaxOpenConns(1) prevents accidental concurrent
// reads from a single Adapter instance.
//
// Idempotency: every emitted row's SourceEventID is content-derivable
// (see parse.go::buildEvents), so a full rescan from offset 0 is safe
// — the store layer's UNIQUE(source_file, source_event_id) dedup
// drops the re-emits. The watermark is purely an optimisation to
// avoid re-reading messages.json files we've already processed.
func scanStateDB(ctx context.Context, dbPath string, fromOffset int64) ([]sessionRow, int64, error) {
	// Cross-mount stage: when sessions.db lives on a foreign mount
	// (e.g. /mnt/c/Users/<u>/.cline/data/db/sessions.db read by a
	// WSL2 observer), copy the SQLite trio to a local mirror first
	// — modernc.org/sqlite hits SQLITE_IOERR_SEEK (4618) against
	// /mnt/c paths while the Windows cline process holds the WAL
	// open. Native paths pass through unchanged with no overhead.
	actual, err := stageMirrorIfForeign(dbPath)
	if err != nil {
		return nil, fromOffset, fmt.Errorf("clinecli.scanStateDB: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)",
		sqlitedsn.Escape(actual))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fromOffset, fmt.Errorf("clinecli.scanStateDB: open: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// Cline CLI's sessions.db doesn't carry a schema_version table —
	// it uses inline ALTER TABLE migrations applied by the
	// @cline/shared loader against legacy DBs. Schema-shape
	// validation is via PRAGMA table_info(sessions) at parse time;
	// for now trust the projection below to fail loudly if a
	// required column is missing.

	sessions, maxOffset, err := readSessions(ctx, db, fromOffset)
	if err != nil {
		return nil, fromOffset, fmt.Errorf("clinecli.scanStateDB: %w", err)
	}

	// Decode metadata_json + load each session's messages.json from
	// disk. Best-effort: a missing or malformed file leaves
	// Messages.Messages = nil; parse.go emits whatever's available.
	rootDir := deriveRootDir(dbPath)
	for i := range sessions {
		decodeSessionMetadata(&sessions[i])
		loadMessagesJSON(&sessions[i], rootDir)
	}
	return sessions, maxOffset, nil
}

// readSessions pulls all 28 columns from sessions WHERE updated_at >
// fromOffset (ISO 8601). The fromOffset int64 is UnixMilli; we
// re-format to ISO 8601 with millisecond precision before binding so
// the TEXT comparison is lexicographically correct (ISO 8601 is
// chronologically-ordered as a string).
//
// fromOffset == 0 disables the filter so a backfill / first scan
// pulls every session.
func readSessions(ctx context.Context, db *sql.DB, fromOffset int64) ([]sessionRow, int64, error) {
	var (
		rows *sql.Rows
		err  error
	)
	const cols = `session_id, source, pid, started_at, ended_at, exit_code, status,
	              interactive, provider, model, cwd, workspace_root, team_name,
	              enable_tools, enable_spawn, enable_teams, parent_session_id,
	              parent_agent_id, agent_id, conversation_id, is_subagent,
	              prompt, metadata_json, messages_path, updated_at`
	if fromOffset > 0 {
		watermark := time.UnixMilli(fromOffset).UTC().Format("2006-01-02T15:04:05.000Z")
		rows, err = db.QueryContext(ctx, "SELECT "+cols+" FROM sessions WHERE updated_at > ? ORDER BY updated_at ASC", watermark)
	} else {
		rows, err = db.QueryContext(ctx, "SELECT "+cols+" FROM sessions ORDER BY updated_at ASC")
	}
	if err != nil {
		return nil, fromOffset, fmt.Errorf("readSessions: query: %w", err)
	}
	defer rows.Close()

	var out []sessionRow
	maxOffset := fromOffset
	for rows.Next() {
		var s sessionRow
		if err := rows.Scan(
			&s.ID, &s.Source, &s.PID, &s.StartedAt, &s.EndedAt, &s.ExitCode, &s.Status,
			&s.Interactive, &s.Provider, &s.Model, &s.CWD, &s.WorkspaceRoot, &s.TeamName,
			&s.EnableTools, &s.EnableSpawn, &s.EnableTeams, &s.ParentSessionID,
			&s.ParentAgentID, &s.AgentID, &s.ConversationID, &s.IsSubagent,
			&s.Prompt, &s.MetadataJSON, &s.MessagesPath, &s.UpdatedAt,
		); err != nil {
			return nil, maxOffset, fmt.Errorf("readSessions: scan: %w", err)
		}
		out = append(out, s)
		if ms, ok := parseISO8601ms(s.UpdatedAt); ok && ms > maxOffset {
			maxOffset = ms
		}
	}
	if err := rows.Err(); err != nil {
		return nil, maxOffset, fmt.Errorf("readSessions: iterate: %w", err)
	}
	return out, maxOffset, nil
}

// decodeSessionMetadata parses sessions.metadata_json into the typed
// sessionMetadata. Best-effort — invalid JSON leaves Metadata zero-
// valued; parse.go can still emit session_start / session_end +
// content-block events using just the sessionRow columns.
func decodeSessionMetadata(s *sessionRow) {
	if !s.MetadataJSON.Valid || s.MetadataJSON.String == "" {
		return
	}
	_ = json.Unmarshal([]byte(s.MetadataJSON.String), &s.Metadata)
}

// loadMessagesJSON reads <id>.messages.json into the session's
// Messages field. Three resolution strategies, in order:
//
//  1. sessions.messages_path column (cross-mount-translated).
//  2. <rootDir>/sessions/<id>/<id>.messages.json (derived from the
//     sessions.db path).
//  3. Skip if neither works — parse.go emits session-level rows only.
//
// Strategy 2 catches the common case where messages_path was recorded
// on a Windows host but the file is being read from WSL2 (cross-mount
// translation handles strategy 1 in most cases, but a session whose
// messages_path was recorded with a CLINE_SESSION_DATA_DIR override
// may not resolve cleanly without the derived fallback).
func loadMessagesJSON(s *sessionRow, rootDir string) {
	candidates := make([]string, 0, 2)
	if s.MessagesPath.Valid && s.MessagesPath.String != "" {
		candidates = append(candidates, crossmount.TranslateForeignPath(s.MessagesPath.String))
	}
	if rootDir != "" {
		candidates = append(candidates, filepath.Join(rootDir, "sessions", s.ID, s.ID+".messages.json"))
	}
	for _, p := range candidates {
		body, err := os.ReadFile(p) //nolint:gosec // path derives from validated DB columns + watch root
		if err != nil {
			continue
		}
		var doc messagesDoc
		if err := json.Unmarshal(body, &doc); err != nil {
			continue
		}
		s.Messages = doc
		return
	}
}

// deriveRootDir returns the parent of `.../db/sessions.db`, which is the
// cline data dir (`<CLINE_DIR>/data`, or a relocated $CLINE_DATA_DIR of any
// name, FU-30). Used as the fallback when sessions.messages_path doesn't
// resolve.
func deriveRootDir(dbPath string) string {
	abs := filepath.ToSlash(dbPath)
	idx := strings.LastIndex(abs, "/db/sessions.db")
	if idx <= 0 || idx+len("/db/sessions.db") != len(abs) {
		return ""
	}
	return filepath.FromSlash(abs[:idx])
}

// parseISO8601ms converts an ISO 8601 timestamp to UnixMilli for
// watermark storage. Cline CLI writes "2026-06-05T23:28:30.654Z"
// (millisecond precision, UTC). Returns (0, false) on parse error so
// the caller leaves the cursor unchanged.
func parseISO8601ms(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil {
		// Tolerate variants — sub-second precision can be higher or
		// lower than 3 digits. Fall through to RFC3339Nano.
		t, err = time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return 0, false
		}
	}
	return t.UnixMilli(), true
}
