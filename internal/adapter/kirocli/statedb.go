package kirocli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// sqliteConv is the decoded `value` JSON of a conversations_v2 row.
type sqliteConv struct {
	ConversationID string          `json:"conversation_id"`
	History        []sqliteHistory `json:"history"`
}

type sqliteHistory struct {
	User      sqliteUser      `json:"user"`
	Assistant sqliteAssistant `json:"assistant"`
	Request   sqliteReqMeta   `json:"request_metadata"`
}

type sqliteUser struct {
	EnvContext struct {
		EnvState struct {
			CurrentWorkingDirectory string `json:"current_working_directory"`
		} `json:"env_state"`
	} `json:"env_context"`
	Content   sqliteUserContent `json:"content"`
	Timestamp *string           `json:"timestamp"`
}

type sqliteUserContent struct {
	Prompt *struct {
		Prompt string `json:"prompt"`
	} `json:"Prompt"`
	ToolUseResults *struct {
		ToolUseResults []sqliteToolResult `json:"tool_use_results"`
	} `json:"ToolUseResults"`
}

type sqliteToolResult struct {
	ToolUseID string            `json:"tool_use_id"`
	Content   []json.RawMessage `json:"content"`
	Status    string            `json:"status"`
}

type sqliteAssistant struct {
	ToolUse  *sqliteToolUse  `json:"ToolUse"`
	Response *sqliteResponse `json:"Response"`
}

type sqliteToolUse struct {
	MessageID string              `json:"message_id"`
	Content   string              `json:"content"`
	ToolUses  []sqliteToolUseItem `json:"tool_uses"`
}

type sqliteToolUseItem struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args"`
}

type sqliteResponse struct {
	MessageID string `json:"message_id"`
	Content   string `json:"content"`
}

// sqliteReqMeta is the per-turn request_metadata. Token fields are
// pointers so "present and 0" is distinguished from "absent/null";
// every capture to date has them null → no token event emitted.
type sqliteReqMeta struct {
	RequestID               string `json:"request_id"`
	MessageID               string `json:"message_id"`
	ModelID                 string `json:"model_id"`
	RequestStartTimestampMs int64  `json:"request_start_timestamp_ms"`
	TotalTokens             *int64 `json:"total_tokens"`
	UncachedInputTokens     *int64 `json:"uncached_input_tokens"`
	OutputTokens            *int64 `json:"output_tokens"`
	CacheReadInputTokens    *int64 `json:"cache_read_input_tokens"`
	CacheWriteInputTokens   *int64 `json:"cache_write_input_tokens"`
}

// toolResult is a normalized tool_use result, keyed by tool_use_id.
type toolResult struct {
	output  string
	success bool
}

// parseStateDB parses the non-interactive SQLite conversations_v2
// store. The trigger may be data.sqlite3 or a -wal/-shm sidecar; the
// open always targets data.sqlite3 and events are emitted under that
// canonical SourceFile. fromOffset is a UnixMilli watermark on
// conversations_v2.updated_at.
func (a *Adapter) parseStateDB(ctx context.Context, trigger string, fromOffset int64) (adapter.ParseResult, error) {
	res := adapter.ParseResult{NewOffset: fromOffset}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	canonical := canonicalDBPath(trigger)

	staged, err := stageMirrorIfForeign(canonical)
	if err != nil {
		return res, fmt.Errorf("kirocli.parseStateDB: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)",
		sqlitedsn.Escape(staged))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return res, fmt.Errorf("kirocli.parseStateDB: open: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// Never read auth_kv / state / conversations(v1) / history — only
	// conversations_v2 is enumerated (package doc "Security"). Tolerate
	// its absence (fresh install) rather than erroring.
	if ok, err := tableExists(ctx, db, "conversations_v2"); err != nil {
		return res, fmt.Errorf("kirocli.parseStateDB: %w", err)
	} else if !ok {
		return res, nil
	}

	rows, maxOffset, err := readConversations(ctx, db, fromOffset)
	if err != nil {
		return res, fmt.Errorf("kirocli.parseStateDB: %w", err)
	}
	res.NewOffset = maxOffset

	for _, r := range rows {
		var conv sqliteConv
		if err := json.Unmarshal([]byte(r.value), &conv); err != nil {
			warnf(&res, "kirocli: conversations_v2 %s: malformed value JSON: %v", r.conversationID, err)
			continue
		}
		sessionID := conv.ConversationID
		if sessionID == "" {
			sessionID = r.conversationID
		}
		a.emitConversation(&res, canonical, sessionID, r.key, conv)
		// Surface stamp: conversations_v2 is written only by
		// `--no-interactive` runs of the terminal binary, so the layout
		// IS the discriminator (see layoutSurfaces).
		res.SessionSurfaces = append(res.SessionSurfaces, surfaceFor(layoutSQLite, sessionID))
	}
	return res, nil
}

// convRow is one conversations_v2 row's read-projection.
type convRow struct {
	key            string
	conversationID string
	value          string
	updatedAt      int64
}

// readConversations pulls (key, conversation_id, value, updated_at) for
// every row with updated_at > fromOffset. fromOffset == 0 disables the
// filter (full backfill). Returns the rows plus the max updated_at seen.
func readConversations(ctx context.Context, db *sql.DB, fromOffset int64) ([]convRow, int64, error) {
	var (
		rows *sql.Rows
		err  error
	)
	const cols = `key, conversation_id, value, updated_at`
	if fromOffset > 0 {
		rows, err = db.QueryContext(ctx,
			"SELECT "+cols+" FROM conversations_v2 WHERE updated_at > ? ORDER BY updated_at ASC", fromOffset)
	} else {
		rows, err = db.QueryContext(ctx,
			"SELECT "+cols+" FROM conversations_v2 ORDER BY updated_at ASC")
	}
	if err != nil {
		return nil, fromOffset, fmt.Errorf("readConversations: query: %w", err)
	}
	defer rows.Close()

	out := []convRow{}
	maxOffset := fromOffset
	for rows.Next() {
		var r convRow
		if err := rows.Scan(&r.key, &r.conversationID, &r.value, &r.updatedAt); err != nil {
			return nil, maxOffset, fmt.Errorf("readConversations: scan: %w", err)
		}
		out = append(out, r)
		if r.updatedAt > maxOffset {
			maxOffset = r.updatedAt
		}
	}
	if err := rows.Err(); err != nil {
		return nil, maxOffset, fmt.Errorf("readConversations: iterate: %w", err)
	}
	return out, maxOffset, nil
}

// emitConversation walks one conversation's history[] and appends its
// tool / prompt / assistant / token events.
func (a *Adapter) emitConversation(res *adapter.ParseResult, sourceFile, sessionID, rawKey string, conv sqliteConv) {
	// cwd: the row KEY is the authoritative raw cwd string; fall back to
	// the first turn's env_context.
	cwd := strings.TrimSpace(rawKey)
	if cwd == "" && len(conv.History) > 0 {
		cwd = conv.History[0].User.EnvContext.EnvState.CurrentWorkingDirectory
	}
	projectRoot, gitBranch, gitRemote, projectIdentity := resolveProjectRoot(cwd)
	// Snapshot append points so the identity backfill below touches only
	// the events THIS conversation contributes to the shared res — a
	// conversations_v2 file can hold several conversations with distinct
	// cwds, each calling emitConversation against the same *ParseResult.
	toolStart, tokenStart := len(res.ToolEvents), len(res.TokenEvents)
	defer func() {
		scoped := adapter.ParseResult{ToolEvents: res.ToolEvents[toolStart:], TokenEvents: res.TokenEvents[tokenStart:]}
		adapter.ApplyProjectIdentity(&scoped, projectIdentity)
	}()

	// Pre-index every tool_use result so a tool_use event can attach its
	// output + success in one pass.
	results := indexToolResults(conv)

	// A conversations_v2 row is a WHOLE-ROW REWRITE (its `value` JSON
	// carries the FULL history array, not a delta since the last poll —
	// see parseStateDB's fromOffset comment), so a fresh per-conversation
	// accumulator, rebuilt from history[0] every call, reproduces the same
	// block chain each time: the R3 byte-stability invariant holds for
	// free here, unlike an incrementally-parsed producer (junie, cline,
	// cowork), which must track drain-state across calls.
	cacheAcc := cacheobs.New(MaxBlocksPerSession)

	for i, h := range conv.History {
		model := h.Request.ModelID
		ts := entryTimestamp(h)

		if h.User.Content.Prompt != nil {
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile:    sourceFile,
				SourceEventID: promptEventID(h, i),
				SessionID:     sessionID,
				ProjectRoot:   projectRoot,
				GitBranch:     gitBranch,
				GitRemote:     gitRemote,
				Timestamp:     ts,
				TurnIndex:     i,
				Model:         model,
				Tool:          models.ToolKiroCLI,
				ActionType:    models.ActionUserPrompt,
				Target:        a.scrubber.String(h.User.Content.Prompt.Prompt),
				Success:       true,
				MessageID:     h.Request.MessageID,
			})
		}

		switch {
		case h.Assistant.ToolUse != nil:
			for _, tu := range h.Assistant.ToolUse.ToolUses {
				action, target, contentBytes := normalizeTool(tu.Name, tu.Args)
				rr, hasResult := results[tu.ID]
				ev := models.ToolEvent{
					SourceFile:    sourceFile,
					SourceEventID: tu.ID,
					SessionID:     sessionID,
					ProjectRoot:   projectRoot,
					GitBranch:     gitBranch,
					GitRemote:     gitRemote,
					Timestamp:     ts,
					TurnIndex:     i,
					Model:         model,
					Tool:          models.ToolKiroCLI,
					ActionType:    action,
					Target:        a.scrubber.String(target),
					RawToolName:   tu.Name,
					RawToolInput:  a.scrubber.String(contentcap.Cap(string(tu.Args), contentcap.DefaultMaxBytes)),
					ContentBytes:  contentBytes,
					Success:       true,
					MessageID:     h.Assistant.ToolUse.MessageID,
				}
				if hasResult {
					ev.Success = rr.success
					ev.ToolOutput = a.scrubber.String(contentcap.Cap(rr.output, contentcap.DefaultMaxBytes))
					if !rr.success {
						ev.ErrorMessage = a.scrubber.String(rr.output)
					}
				}
				res.ToolEvents = append(res.ToolEvents, ev)
			}
		case h.Assistant.Response != nil:
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile:    sourceFile,
				SourceEventID: h.Assistant.Response.MessageID + ":resp",
				SessionID:     sessionID,
				ProjectRoot:   projectRoot,
				GitBranch:     gitBranch,
				GitRemote:     gitRemote,
				Timestamp:     ts,
				TurnIndex:     i,
				Model:         model,
				Tool:          models.ToolKiroCLI,
				ActionType:    models.ActionAssistantMessage,
				Target:        a.scrubber.String(contentcap.Cap(h.Assistant.Response.Content, contentcap.DefaultMaxBytes)),
				Success:       true,
				MessageID:     h.Assistant.Response.MessageID,
			})
		}

		// Token event — only when at least one token field is non-null.
		// Every capture to date has them null (server-side accounting on
		// SigV4 endpoints, no proxy tier). uncached_input_tokens is NET
		// non-cached (the name is explicit), so no gross→net subtraction
		// is needed.
		if te, ok := a.tokenEvent(h, sourceFile, sessionID, projectRoot, gitBranch, gitRemote, ts); ok {
			res.TokenEvents = append(res.TokenEvents, te)
		}

		// Cache observation — this turn's user+assistant content joins
		// the running accumulator first, then (like the token event
		// above) only actually emits when request_metadata carries a
		// non-null, non-zero cache/token field.
		accumulateTurnCache(cacheAcc, h)
		msgID := h.Request.MessageID
		if msgID == "" {
			msgID = h.Request.RequestID
		}
		if obs := emitCacheObservation(cacheAcc, sourceFile, sessionID, msgID+":tok", model, ts, h.Request); obs != nil {
			res.CacheObservations = append(res.CacheObservations, *obs)
		}
	}
}

// tokenEvent builds a TokenEvent from request_metadata when any token
// field is present. Returns ok=false when all are null.
func (a *Adapter) tokenEvent(h sqliteHistory, sourceFile, sessionID, projectRoot, gitBranch, gitRemote string, ts time.Time) (models.TokenEvent, bool) {
	m := h.Request
	if m.TotalTokens == nil && m.UncachedInputTokens == nil && m.OutputTokens == nil &&
		m.CacheReadInputTokens == nil && m.CacheWriteInputTokens == nil {
		return models.TokenEvent{}, false
	}
	msgID := m.MessageID
	if msgID == "" {
		msgID = m.RequestID
	}
	return models.TokenEvent{
		SourceFile:          sourceFile,
		SourceEventID:       msgID + ":tok",
		SessionID:           sessionID,
		ProjectRoot:         projectRoot,
		GitBranch:           gitBranch,
		GitRemote:           gitRemote,
		Timestamp:           ts,
		Tool:                models.ToolKiroCLI,
		Model:               m.ModelID,
		InputTokens:         deref(m.UncachedInputTokens),
		OutputTokens:        deref(m.OutputTokens),
		CacheReadTokens:     deref(m.CacheReadInputTokens),
		CacheCreationTokens: deref(m.CacheWriteInputTokens),
		Source:              "jsonl",
		Reliability:         "approximate",
		MessageID:           msgID,
	}, true
}

// indexToolResults maps tool_use_id → normalized result across every
// history entry's ToolUseResults carrier.
func indexToolResults(conv sqliteConv) map[string]toolResult {
	out := map[string]toolResult{}
	for _, h := range conv.History {
		if h.User.Content.ToolUseResults == nil {
			continue
		}
		for _, r := range h.User.Content.ToolUseResults.ToolUseResults {
			out[r.ToolUseID] = toolResult{
				output:  toolResultText(r.Content),
				success: strings.EqualFold(r.Status, "Success"),
			}
		}
	}
	return out
}

// toolResultText flattens the tool_use result content blocks. Each
// block is a single-key object: {"Text":"…"} or {"Json":{…}}.
func toolResultText(blocks []json.RawMessage) string {
	var sb strings.Builder
	for _, raw := range blocks {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			continue
		}
		if t, ok := obj["Text"]; ok {
			var s string
			if json.Unmarshal(t, &s) == nil {
				sb.WriteString(s)
				continue
			}
		}
		if j, ok := obj["Json"]; ok {
			sb.Write(j)
		}
	}
	return sb.String()
}

// promptEventID derives a deterministic id for a user prompt turn.
func promptEventID(h sqliteHistory, idx int) string {
	if h.Request.MessageID != "" {
		return h.Request.MessageID + ":prompt"
	}
	return fmt.Sprintf("u%d:prompt", idx)
}

// entryTimestamp resolves a history entry's timestamp: the user.
// timestamp (RFC3339) when present, else request_start_timestamp_ms.
func entryTimestamp(h sqliteHistory) time.Time {
	if h.User.Timestamp != nil && *h.User.Timestamp != "" {
		if t := parseRFC3339(*h.User.Timestamp); !t.IsZero() {
			return t
		}
	}
	if h.Request.RequestStartTimestampMs > 0 {
		return time.UnixMilli(h.Request.RequestStartTimestampMs).UTC()
	}
	return time.Time{}
}

// canonicalDBPath collapses a data.sqlite3-wal / -shm trigger to the
// main .db path.
func canonicalDBPath(trigger string) string {
	base := filepath.Base(trigger)
	switch {
	case strings.HasSuffix(base, "-wal"):
		return strings.TrimSuffix(trigger, "-wal")
	case strings.HasSuffix(base, "-shm"):
		return strings.TrimSuffix(trigger, "-shm")
	default:
		return trigger
	}
}

// tableExists reports whether a table is present, via sqlite_master.
func tableExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var found string
	err := db.QueryRowContext(ctx,
		"SELECT name FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&found)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, fmt.Errorf("tableExists(%s): %w", name, err)
	default:
		return true, nil
	}
}

func deref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
