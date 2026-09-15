package opencode

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter parses OpenCode's SQLite state store. OpenCode persists user
// messages, tool calls, and assistant completions in opencode.db, which gives
// us richer capture than the coarse desktop snapshot files.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with platform-specific default roots.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots()}
}

// NewWithOptions customizes scrubber and/or roots for tests.
func NewWithOptions(s *scrub.Scrubber, roots []string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{scrubber: s, roots: roots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolOpenCode }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Matches OpenCode's SQLite
// state store and WAL sibling. The under-WatchPaths constraint
// enforces the v1.4.51 dispatch contract — basename-only predicates
// can't accidentally claim foreign opencode.db files (e.g. a copy
// archived elsewhere on disk).
func (a *Adapter) IsSessionFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base != "opencode.db" && base != "opencode.db-wal" {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// ParseSessionFile implements adapter.Adapter.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	dbPath := resolveDBPath(path)
	latest, err := latestWatermark(ctx, dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("opencode.ParseSessionFile: latest watermark: %w", err)
	}
	res := adapter.ParseResult{NewOffset: latest}
	if latest <= fromOffset {
		return res, nil
	}

	database, err := openReadOnlyDB(dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("opencode.ParseSessionFile: open: %w", err)
	}
	defer database.Close()

	rootCache := map[string]projectGitInfo{}
	// Resolve reasoning → successor assignment BEFORE any emitter runs,
	// so the threading can't depend on loader order (see
	// loadReasoningIndex). Reasoning parts are never rows of their own.
	reasoning, err := a.loadReasoningIndex(ctx, database, fromOffset)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("opencode.ParseSessionFile: reasoning index: %w", err)
	}
	prompts, err := a.loadUserPromptEvents(ctx, database, dbPath, fromOffset, rootCache)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("opencode.ParseSessionFile: prompts: %w", err)
	}
	tools, err := a.loadToolEvents(ctx, database, dbPath, fromOffset, rootCache, reasoning)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("opencode.ParseSessionFile: tools: %w", err)
	}
	completions, err := a.loadCompletionEvents(ctx, database, dbPath, fromOffset, rootCache)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("opencode.ParseSessionFile: completions: %w", err)
	}
	assistantTexts, err := a.loadAssistantTextEvents(ctx, database, dbPath, fromOffset, rootCache, reasoning)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("opencode.ParseSessionFile: assistant_text: %w", err)
	}
	subtasks, err := a.loadSubtaskEvents(ctx, database, dbPath, fromOffset, rootCache)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("opencode.ParseSessionFile: subtasks: %w", err)
	}
	stepFinishes, err := a.loadStepFinishEvents(ctx, database, dbPath, fromOffset, rootCache)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("opencode.ParseSessionFile: step_finish: %w", err)
	}
	todos, err := a.loadTodoEvents(ctx, database, dbPath, fromOffset, rootCache)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("opencode.ParseSessionFile: todos: %w", err)
	}
	tokens, err := a.loadTokenEvents(ctx, database, dbPath, fromOffset, rootCache)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("opencode.ParseSessionFile: tokens: %w", err)
	}
	lineages, err := a.loadSessionLineages(ctx, database)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("opencode.ParseSessionFile: session lineages: %w", err)
	}
	// §14.3 Tier-2 cache observation. Volatile-element exclusion
	// (wall-clock fields inside tool/reasoning/subtask part bodies)
	// is documented in docs/audits/cachetrack-opencode-tier2-audit-
	// 2026-06-09.md and enforced by the struct-based canonical
	// marshallers in cachetrack.go (R3 byte-stability guard).
	cacheObservations, err := a.loadCacheObservations(ctx, database, dbPath, fromOffset)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("opencode.ParseSessionFile: cache_observations: %w", err)
	}
	res.ToolEvents = append(res.ToolEvents, prompts...)
	res.ToolEvents = append(res.ToolEvents, tools...)
	res.ToolEvents = append(res.ToolEvents, completions...)
	res.ToolEvents = append(res.ToolEvents, assistantTexts...)
	res.ToolEvents = append(res.ToolEvents, subtasks...)
	res.ToolEvents = append(res.ToolEvents, stepFinishes...)
	res.ToolEvents = append(res.ToolEvents, todos...)
	res.TokenEvents = append(res.TokenEvents, tokens...)
	res.CacheObservations = append(res.CacheObservations, cacheObservations...)
	res.SessionLineages = append(res.SessionLineages, lineages...)
	adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
	return res, nil
}

type messageRow struct {
	ID         string
	SessionID  string
	Directory  string
	TimeCreate int64
	TimeUpdate int64
	Data       string
}

type partRow struct {
	ID         string
	MessageID  string
	SessionID  string
	Directory  string
	TimeCreate int64
	TimeUpdate int64
	Data       string
	Message    string
}

type messageData struct {
	Role  string `json:"role"`
	Agent string `json:"agent"`
	Model struct {
		ProviderID string `json:"providerID"`
		ModelID    string `json:"modelID"`
	} `json:"model"`
	ModelID    string `json:"modelID"`
	ProviderID string `json:"providerID"`
	Path       struct {
		Cwd string `json:"cwd"`
	} `json:"path"`
	Time struct {
		Created   int64 `json:"created"`
		Completed int64 `json:"completed"`
	} `json:"time"`
	Finish string `json:"finish"`
	// Variant is OpenCode's per-message effort selector. Confirmed
	// against the sst/opencode CLI runtime: the user picks an effort
	// per (provider, model) in ~/.local/state/opencode/model.json under
	// `variant.<provider>/<model>`, and the CLI stamps the chosen level
	// onto every assistant message's `variant` JSON field ("low",
	// "medium", "high"). The Windows Desktop variant does NOT stamp it
	// (verified 2026-05-21 against an active Desktop session); only the
	// CLI emits it today. Maps to ActionMetadata.EffortLevel on
	// assistant-side rows.
	Variant string `json:"variant"`
	// Tokens + Cost are populated on assistant messages by OpenCode's
	// session writer, mirroring the upstream provider's usage envelope.
	// Confirmed against the InfoData zod schema in opencode's
	// packages/opencode/src/session/message.ts:
	//   tokens: { input, output, reasoning, cache: { read, write } }
	//   cost:   number (USD)
	// All zero when the message hasn't completed (assistant Finish=="")
	// or the role isn't assistant — feeds the loadTokenEvents emitter.
	Tokens struct {
		Input     int64 `json:"input"`
		Output    int64 `json:"output"`
		Reasoning int64 `json:"reasoning"`
		Cache     struct {
			Read  int64 `json:"read"`
			Write int64 `json:"write"`
		} `json:"cache"`
	} `json:"tokens"`
	Cost float64 `json:"cost"`
}

type textPartData struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolPartData struct {
	Type   string `json:"type"`
	Tool   string `json:"tool"`
	CallID string `json:"callID"`
	State  struct {
		Status   string          `json:"status"`
		Input    json.RawMessage `json:"input"`
		Output   string          `json:"output"`
		Metadata struct {
			Output      string `json:"output"`
			Exit        int    `json:"exit"`
			Description string `json:"description"`
			FilePath    string `json:"filepath"`
			Truncated   bool   `json:"truncated"`
		} `json:"metadata"`
		Title string `json:"title"`
		Time  struct {
			Start int64 `json:"start"`
			End   int64 `json:"end"`
		} `json:"time"`
	} `json:"state"`
}

// subtaskPartData mirrors OpenCode's SubtaskPart schema (per
// packages/opencode/src/session/message-v2.ts:228–240). Emitted by
// the parent's message when it invokes a subagent — the prompt,
// description, agent name, and optional model for the spawned
// subagent. The actual sub-agent runs in a child session linked
// via session.parent_id (captured by loadSessionLineages).
type subtaskPartData struct {
	Type        string `json:"type"`
	Prompt      string `json:"prompt"`
	Description string `json:"description"`
	Agent       string `json:"agent"`
	Model       struct {
		ProviderID string `json:"providerID"`
		ModelID    string `json:"modelID"`
	} `json:"model"`
	Command string `json:"command"`
	Time    struct {
		Created int64 `json:"created"`
	} `json:"time"`
}

type toolInput struct {
	Command  string `json:"command"`
	FilePath string `json:"filePath"`
}

func (a *Adapter) loadUserPromptEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]projectGitInfo) ([]models.ToolEvent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT m.id, m.session_id, COALESCE(s.directory, ''), m.time_created, m.time_updated, m.data
		  FROM message m
		  LEFT JOIN session s ON s.id = m.session_id
		 WHERE m.time_updated > ?
		   AND json_extract(m.data, '$.role') = 'user'
		 ORDER BY m.time_updated ASC, m.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.ToolEvent
	for rows.Next() {
		var row messageRow
		if err := rows.Scan(&row.ID, &row.SessionID, &row.Directory, &row.TimeCreate, &row.TimeUpdate, &row.Data); err != nil {
			return nil, err
		}
		ev, ok, err := a.userPromptEvent(ctx, db, sourceFile, row, rootCache)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

func (a *Adapter) userPromptEvent(ctx context.Context, db *sql.DB, sourceFile string, row messageRow, rootCache map[string]projectGitInfo) (models.ToolEvent, bool, error) {
	var msg messageData
	if err := json.Unmarshal([]byte(row.Data), &msg); err != nil {
		return models.ToolEvent{}, false, nil
	}

	partRows, err := db.QueryContext(ctx, `
		SELECT data
		  FROM part
		 WHERE message_id = ?
		 ORDER BY time_created ASC, id ASC`, row.ID)
	if err != nil {
		return models.ToolEvent{}, false, err
	}
	defer partRows.Close()

	var promptParts []string
	for partRows.Next() {
		var raw string
		if err := partRows.Scan(&raw); err != nil {
			return models.ToolEvent{}, false, err
		}
		var part textPartData
		if err := json.Unmarshal([]byte(raw), &part); err != nil {
			continue
		}
		if part.Type == "text" && strings.TrimSpace(part.Text) != "" {
			promptParts = append(promptParts, part.Text)
		}
	}
	if err := partRows.Err(); err != nil {
		return models.ToolEvent{}, false, err
	}

	prompt := strings.TrimSpace(strings.Join(promptParts, "\n"))
	if prompt == "" {
		return models.ToolEvent{}, false, nil
	}
	when := millisToTime(msg.Time.Created)
	if when.IsZero() {
		when = millisToTime(row.TimeCreate)
	}
	cwd := firstNonEmpty(msg.Path.Cwd, row.Directory)
	project := a.resolveProjectRoot(cwd, rootCache)
	remote := a.resolveProjectRemote(cwd, rootCache)
	model := firstNonEmpty(msg.Model.ModelID, msg.ModelID, msg.Agent)
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      "message:" + row.ID,
		SessionID:          row.SessionID,
		ProjectRoot:        project,
		GitRemote:          remote,
		Timestamp:          chooseTime(when, time.Time{}, 0),
		Model:              model,
		Tool:               models.ToolOpenCode,
		ActionType:         models.ActionUserPrompt,
		Target:             truncate(prompt, 200),
		Success:            true,
		PrecedingReasoning: truncate(prompt, 200),
		RawToolName:        "chat.message",
		RawToolInput:       a.scrubber.String(prompt),
		MessageID:          "user:" + row.ID,
	}, true, nil
}

// reasoningIndex maps a part id to the chain-of-thought body that
// immediately precedes that part inside the SAME message — the
// assignment computed once by loadReasoningIndex, then read by the
// per-row emitters.
type reasoningIndex map[string]string

// loadReasoningIndex resolves which successor part each `reasoning`
// part belongs to, so the body can be threaded onto that successor's
// PrecedingReasoning instead of minting a row of its own (B3
// convergence — docs/plans/b3-reasoning-convergence-plan-2026-07-31.md
// §1). Semantics match grok's reference shape:
//
//   - CONSUMED-ONCE: a reasoning body is threaded onto exactly ONE
//     successor — the first `tool` or `text` part after it. Two tool
//     calls following one thought do NOT both claim it (that is
//     cline/cowork's deliberate fan-out, not opencode's: OpenCode
//     stores every part separately and in order, so the real successor
//     is knowable here and guessing wider would be invention).
//   - LAST-WINS: consecutive reasoning parts with no successor between
//     them collapse; the newest is the one threaded.
//   - TURN BOUNDARY: the walk is partitioned by message id, so a
//     thought can never leak past its own assistant turn.
//
// The assignment is computed in ONE ordered pass here rather than
// inside the individual loaders precisely so it can't depend on the
// order the loaders happen to run in.
//
// The window is widened from the incremental `time_updated > ?` slice
// to every part of the messages that slice touches: a poll tick can
// land between a reasoning part and its successor, and the successor's
// batch would otherwise see no reasoning at all. Parts of earlier
// batches that the widening pulls in are harmless — nothing re-emits
// them.
func (a *Adapter) loadReasoningIndex(ctx context.Context, db *sql.DB, fromOffset int64) (reasoningIndex, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.message_id, json_extract(p.data, '$.type'), COALESCE(json_extract(p.data, '$.text'), '')
		  FROM part p
		 WHERE p.message_id IN (SELECT message_id FROM part WHERE time_updated > ?)
		   AND json_extract(p.data, '$.type') IN ('reasoning', 'tool', 'text')
		 ORDER BY p.message_id ASC, p.time_created ASC, p.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	idx := reasoningIndex{}
	var curMessage, pending string
	for rows.Next() {
		var partID, messageID, partType, text string
		if err := rows.Scan(&partID, &messageID, &partType, &text); err != nil {
			return nil, err
		}
		if messageID != curMessage {
			curMessage, pending = messageID, ""
		}
		if partType == "reasoning" {
			if body := strings.TrimSpace(text); body != "" {
				pending = body
			}
			continue
		}
		if pending != "" {
			idx[partID] = pending
			pending = ""
		}
	}
	return idx, rows.Err()
}

// threaded returns the reasoning body assigned to a part, or "" when
// none was.
func (r reasoningIndex) threaded(partID string) string { return r[partID] }

func (a *Adapter) loadToolEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]projectGitInfo, reasoning reasoningIndex) ([]models.ToolEvent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.message_id, p.session_id, COALESCE(s.directory, ''), p.time_created, p.time_updated, p.data, m.data
		  FROM part p
		  JOIN message m ON m.id = p.message_id
		  LEFT JOIN session s ON s.id = p.session_id
		 WHERE p.time_updated > ?
		   AND json_extract(p.data, '$.type') = 'tool'
		 ORDER BY p.time_updated ASC, p.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.ToolEvent
	for rows.Next() {
		var row partRow
		if err := rows.Scan(&row.ID, &row.MessageID, &row.SessionID, &row.Directory, &row.TimeCreate, &row.TimeUpdate, &row.Data, &row.Message); err != nil {
			return nil, err
		}
		ev, ok := a.toolEvent(sourceFile, row, rootCache, reasoning)
		if ok {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

func (a *Adapter) toolEvent(sourceFile string, row partRow, rootCache map[string]projectGitInfo, reasoning reasoningIndex) (models.ToolEvent, bool) {
	var msg messageData
	if err := json.Unmarshal([]byte(row.Message), &msg); err != nil {
		return models.ToolEvent{}, false
	}
	var part toolPartData
	if err := json.Unmarshal([]byte(row.Data), &part); err != nil {
		return models.ToolEvent{}, false
	}
	if part.Type != "tool" {
		return models.ToolEvent{}, false
	}

	actionType, target, success, errMsg := mapTool(part)
	when := millisToTime(part.State.Time.Start)
	if when.IsZero() {
		when = millisToTime(row.TimeCreate)
	}
	cwd := firstNonEmpty(msg.Path.Cwd, row.Directory)
	project := a.resolveProjectRoot(cwd, rootCache)
	remote := a.resolveProjectRemote(cwd, rootCache)
	// Drop msg.Agent as a model fallback — `agent` is the OpenCode
	// agent identity (build / plan / explore / build-subagent / etc.),
	// NOT a model name. Letting it leak into the model column polluted
	// rollups for system messages where modelID was empty.
	model := firstNonEmpty(msg.ModelID, msg.Model.ModelID)

	rawInput := string(part.State.Input)
	if a.scrubber != nil {
		rawInput = a.scrubber.RawJSON(part.State.Input)
	}
	// ToolOutput: capture the tool result body for every tool, not only
	// failed bash commands. State.Output is OpenCode's canonical output
	// slot; Metadata.Output is the bash-specific stdout/stderr fallback.
	output := firstNonEmpty(part.State.Output, part.State.Metadata.Output)
	if a.scrubber != nil {
		output = a.scrubber.String(output)
	}
	// DurationMs: derive from the part's own start/end timestamps when
	// both are present. Source carries epoch-millis so this is an exact
	// subtract.
	var durationMs int64
	if part.State.Time.Start > 0 && part.State.Time.End > part.State.Time.Start {
		durationMs = part.State.Time.End - part.State.Time.Start
	}
	// PRECEDENCE: the chain-of-thought body assigned by
	// loadReasoningIndex WINS over the part's own `title`. The title is
	// OpenCode's one-line UI label for the call ("Run npm start"), not
	// reasoning — it was only ever occupying this column because nothing
	// better reached it. The title stays as the fallback so calls in
	// messages with no reasoning part are unchanged.
	preReason := truncate(strings.TrimSpace(part.State.Title), 200)
	if body := reasoning.threaded(row.ID); body != "" {
		preReason = truncate(body, 200)
		if a.scrubber != nil {
			preReason = a.scrubber.String(preReason)
		}
	}
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      "part:" + row.ID,
		SessionID:          row.SessionID,
		ProjectRoot:        project,
		GitRemote:          remote,
		Timestamp:          chooseTime(when, time.Time{}, 0),
		Model:              model,
		Tool:               models.ToolOpenCode,
		ActionType:         actionType,
		Target:             truncate(target, 200),
		Success:            success,
		ErrorMessage:       truncate(errMsg, 500),
		DurationMs:         durationMs,
		PrecedingReasoning: preReason,
		RawToolName:        part.Tool,
		RawToolInput:       rawInput,
		ToolOutput:         output,
		MessageID:          row.MessageID,
		Metadata:           effortMetadata(msg.Variant),
	}, true
}

func (a *Adapter) loadCompletionEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]projectGitInfo) ([]models.ToolEvent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT m.id, m.session_id, COALESCE(s.directory, ''), m.time_created, m.time_updated, m.data
		  FROM message m
		  LEFT JOIN session s ON s.id = m.session_id
		 WHERE m.time_updated > ?
		   AND json_extract(m.data, '$.role') = 'assistant'
		   AND json_extract(m.data, '$.finish') = 'stop'
		 ORDER BY m.time_updated ASC, m.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.ToolEvent
	for rows.Next() {
		var row messageRow
		if err := rows.Scan(&row.ID, &row.SessionID, &row.Directory, &row.TimeCreate, &row.TimeUpdate, &row.Data); err != nil {
			return nil, err
		}
		ev, ok := a.completionEvent(sourceFile, row, rootCache)
		if ok {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

func (a *Adapter) completionEvent(sourceFile string, row messageRow, rootCache map[string]projectGitInfo) (models.ToolEvent, bool) {
	var msg messageData
	if err := json.Unmarshal([]byte(row.Data), &msg); err != nil {
		return models.ToolEvent{}, false
	}
	cwd := firstNonEmpty(msg.Path.Cwd, row.Directory)
	project := a.resolveProjectRoot(cwd, rootCache)
	remote := a.resolveProjectRemote(cwd, rootCache)
	// Drop msg.Agent as a model fallback — `agent` is the OpenCode
	// agent identity (build / plan / explore / build-subagent / etc.),
	// NOT a model name. Letting it leak into the model column polluted
	// rollups for system messages where modelID was empty.
	model := firstNonEmpty(msg.ModelID, msg.Model.ModelID)
	when := millisToTime(msg.Time.Completed)
	if when.IsZero() {
		when = millisToTime(row.TimeUpdate)
	}
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: "complete:" + row.ID,
		SessionID:     row.SessionID,
		ProjectRoot:   project,
		GitRemote:     remote,
		Timestamp:     chooseTime(when, time.Time{}, 0),
		Model:         model,
		Tool:          models.ToolOpenCode,
		ActionType:    models.ActionTaskComplete,
		Target:        firstNonEmpty(msg.Finish, "stop"),
		Success:       true,
		RawToolName:   "assistant.stop",
		MessageID:     row.ID,
		// Stamp the source finish reason into the canonical
		// Metadata.StopReason column (the per-message terminal reason
		// surfaced in session review, matching claudecode/cowork/pi) in
		// addition to the Target preview. OpenCode's `finish` is the
		// OpenAI-shaped vocabulary (stop / length / tool_calls / …);
		// stored source-native.
		Metadata: withStopReason(effortMetadata(msg.Variant), firstNonEmpty(msg.Finish, "stop")),
	}, true
}

// withStopReason stamps a terminal stop reason onto an ActionMetadata,
// allocating one when meta is nil. Empty reason is a no-op so the column
// stays NULL for rows that carry no finish signal.
func withStopReason(meta *models.ActionMetadata, reason string) *models.ActionMetadata {
	if strings.TrimSpace(reason) == "" {
		return meta
	}
	if meta == nil {
		meta = &models.ActionMetadata{}
	}
	meta.StopReason = reason
	return meta
}

// loadAssistantTextEvents reads the assistant's natural-language text
// parts from OpenCode's `part` table (where parts of type=text belong
// to messages with role=assistant). Each non-empty text part emits an
// ActionTaskComplete row with RawToolName="opencode.assistant_text",
// following the cross-adapter convention. The existing
// loadCompletionEvents path remains as the lifecycle marker — it
// emits a single `assistant.stop` row per turn-completion that
// carries no body. This loader complements it by surfacing the
// actual text content. No token/cost fields are set; token usage
// flows through loadTokenEvents.
func (a *Adapter) loadAssistantTextEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]projectGitInfo, reasoning reasoningIndex) ([]models.ToolEvent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.message_id, p.session_id, COALESCE(s.directory, ''), p.time_created, p.time_updated, p.data, m.data
		  FROM part p
		  JOIN message m ON m.id = p.message_id
		  LEFT JOIN session s ON s.id = p.session_id
		 WHERE p.time_updated > ?
		   AND json_extract(p.data, '$.type') = 'text'
		   AND json_extract(m.data, '$.role') = 'assistant'
		 ORDER BY p.time_updated ASC, p.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.ToolEvent
	for rows.Next() {
		var row partRow
		if err := rows.Scan(&row.ID, &row.MessageID, &row.SessionID, &row.Directory, &row.TimeCreate, &row.TimeUpdate, &row.Data, &row.Message); err != nil {
			return nil, err
		}
		ev, ok := a.assistantTextEvent(sourceFile, row, rootCache, reasoning)
		if ok {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

func (a *Adapter) assistantTextEvent(sourceFile string, row partRow, rootCache map[string]projectGitInfo, reasoning reasoningIndex) (models.ToolEvent, bool) {
	var msg messageData
	if err := json.Unmarshal([]byte(row.Message), &msg); err != nil {
		return models.ToolEvent{}, false
	}
	var part textPartData
	if err := json.Unmarshal([]byte(row.Data), &part); err != nil {
		return models.ToolEvent{}, false
	}
	body := strings.TrimSpace(part.Text)
	if body == "" {
		return models.ToolEvent{}, false
	}
	cwd := firstNonEmpty(msg.Path.Cwd, row.Directory)
	project := a.resolveProjectRoot(cwd, rootCache)
	remote := a.resolveProjectRemote(cwd, rootCache)
	model := firstNonEmpty(msg.ModelID, msg.Model.ModelID)
	when := millisToTime(row.TimeCreate)
	preview := truncate(body, 200)
	output := contentcap.Cap(body, contentcap.DefaultMaxBytes)
	if a.scrubber != nil {
		preview = a.scrubber.String(preview)
		output = a.scrubber.String(output)
	}
	// The chain-of-thought that preceded this text part wins over the
	// legacy self-preview (the row's own body echoed into its reasoning
	// column, which told a reader nothing).
	preReason := preview
	if rb := reasoning.threaded(row.ID); rb != "" {
		preReason = truncate(rb, 200)
		if a.scrubber != nil {
			preReason = a.scrubber.String(preReason)
		}
	}
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      "asst:" + row.ID,
		SessionID:          row.SessionID,
		ProjectRoot:        project,
		GitRemote:          remote,
		Timestamp:          chooseTime(when, time.Time{}, 0),
		Model:              model,
		Tool:               models.ToolOpenCode,
		ActionType:         models.ActionAssistantMessage,
		Target:             preview,
		Success:            true,
		PrecedingReasoning: preReason,
		RawToolName:        "opencode.assistant_text",
		ToolOutput:         output,
		MessageID:          row.MessageID,
		Metadata:           effortMetadata(msg.Variant),
	}, true
}

// reasoningPartData mirrors the shape of OpenCode's `reasoning` part
// (per packages/opencode/src/session/message-v2.ts ReasoningPart):
// the model's chain-of-thought body that precedes a tool call or a
// final answer. Empirically present on the Desktop variant (verified
// 2026-05-21 — 11 reasoning parts across a single Desktop session);
// the CLI also emits these on models that surface their reasoning.
// `time.{start,end}` is epoch-millis matching toolPartData; the
// `metadata.<provider>` block carries provider-specific identifiers
// (OpenAI's encrypted reasoning content; Anthropic's signature) that
// we discard — only the visible text is captured.
type reasoningPartData struct {
	Type string `json:"type"`
	Text string `json:"text"`
	Time struct {
		Start int64 `json:"start"`
		End   int64 `json:"end"`
	} `json:"time"`
}

// stepFinishPartData mirrors OpenCode's `step-finish` part: a
// per-step token + cost snapshot emitted between assistant
// reasoning/tool steps within a single message. The message-level
// `data.tokens` is the SUM across every step-finish in that message
// (verified 2026-05-21 against a live Desktop session: ten
// step-finish parts summed to the message's tokens bundle), so we
// surface step-finish as observability ToolEvents only — emitting
// TokenEvents from it would double-count against loadTokenEvents.
type stepFinishPartData struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
	Tokens struct {
		Input     int64 `json:"input"`
		Output    int64 `json:"output"`
		Reasoning int64 `json:"reasoning"`
		Total     int64 `json:"total"`
		Cache     struct {
			Read  int64 `json:"read"`
			Write int64 `json:"write"`
		} `json:"cache"`
	} `json:"tokens"`
	Cost float64 `json:"cost"`
}

// loadStepFinishEvents surfaces OpenCode `step-finish` parts as
// observability ToolEvents. Each step-finish carries the model's
// per-step token + cost slice; summed across every step-finish
// within a message, the totals equal the message-level token bundle
// (so emitting TokenEvents from step-finish would double-count
// against loadTokenEvents — we deliberately do NOT do that). The
// row's Target carries the finish reason ("stop" / "tool-calls"),
// RawToolInput carries the verbatim step-finish JSON (tokens +
// cost) so the dashboard can render per-step cost histograms once
// the UI lands.
func (a *Adapter) loadStepFinishEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]projectGitInfo) ([]models.ToolEvent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.message_id, p.session_id, COALESCE(s.directory, ''), p.time_created, p.time_updated, p.data, m.data
		  FROM part p
		  JOIN message m ON m.id = p.message_id
		  LEFT JOIN session s ON s.id = p.session_id
		 WHERE p.time_updated > ?
		   AND json_extract(p.data, '$.type') = 'step-finish'
		 ORDER BY p.time_updated ASC, p.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.ToolEvent
	for rows.Next() {
		var row partRow
		if err := rows.Scan(&row.ID, &row.MessageID, &row.SessionID, &row.Directory, &row.TimeCreate, &row.TimeUpdate, &row.Data, &row.Message); err != nil {
			return nil, err
		}
		ev, ok := a.stepFinishEvent(sourceFile, row, rootCache)
		if ok {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

func (a *Adapter) stepFinishEvent(sourceFile string, row partRow, rootCache map[string]projectGitInfo) (models.ToolEvent, bool) {
	var msg messageData
	if err := json.Unmarshal([]byte(row.Message), &msg); err != nil {
		return models.ToolEvent{}, false
	}
	var part stepFinishPartData
	if err := json.Unmarshal([]byte(row.Data), &part); err != nil {
		return models.ToolEvent{}, false
	}
	if part.Type != "step-finish" {
		return models.ToolEvent{}, false
	}
	cwd := firstNonEmpty(msg.Path.Cwd, row.Directory)
	project := a.resolveProjectRoot(cwd, rootCache)
	remote := a.resolveProjectRemote(cwd, rootCache)
	model := firstNonEmpty(msg.ModelID, msg.Model.ModelID)
	when := millisToTime(row.TimeCreate)
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: "step:" + row.ID,
		SessionID:     row.SessionID,
		ProjectRoot:   project,
		GitRemote:     remote,
		Timestamp:     chooseTime(when, time.Time{}, 0),
		Model:         model,
		Tool:          models.ToolOpenCode,
		// tooltax/table.go:345 ratifies "opencode.step_finish" as
		// ActionHarnessCall (WP-T4; backfilled by migration 077) — this
		// emit site must agree, or every NEW row drifts back to
		// unknown (WP-T6 finding B4).
		ActionType:   models.ActionHarnessCall,
		Target:       firstNonEmpty(part.Reason, "step-finish"),
		Success:      true,
		RawToolName:  "opencode.step_finish",
		RawToolInput: row.Data,
		MessageID:    row.MessageID,
		Metadata:     effortMetadata(msg.Variant),
	}, true
}

// loadTokenEvents reads OpenCode's per-message token usage from the
// assistant rows in the message table and emits one TokenEvent per
// assistant message. The token counts live in the JSON data blob —
// confirmed against OpenCode's InfoData zod schema in
// packages/opencode/src/session/message.ts:
//
//	tokens: { input, output, reasoning, cache: { read, write } }
//	cost:   number (USD)
//
// Skips rows where assistant hasn't finished (finish != 'stop') or
// no tokens are present (zero across the bundle) — those are still
// in-progress turns.
func (a *Adapter) loadTokenEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]projectGitInfo) ([]models.TokenEvent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT m.id, m.session_id, COALESCE(s.directory, ''), m.time_created, m.time_updated, m.data
		  FROM message m
		  LEFT JOIN session s ON s.id = m.session_id
		 WHERE m.time_updated > ?
		   AND json_extract(m.data, '$.role') = 'assistant'
		 ORDER BY m.time_updated ASC, m.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.TokenEvent
	for rows.Next() {
		var row messageRow
		if err := rows.Scan(&row.ID, &row.SessionID, &row.Directory, &row.TimeCreate, &row.TimeUpdate, &row.Data); err != nil {
			return nil, err
		}
		ev, ok := a.tokenEvent(sourceFile, row, rootCache)
		if ok {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

// tokenEvent extracts a TokenEvent from one assistant message row.
// Returns ok=false when the row carries no token data — early
// in-progress turns, or non-assistant rows that slipped past the
// SQL filter.
func (a *Adapter) tokenEvent(sourceFile string, row messageRow, rootCache map[string]projectGitInfo) (models.TokenEvent, bool) {
	var msg messageData
	if err := json.Unmarshal([]byte(row.Data), &msg); err != nil {
		return models.TokenEvent{}, false
	}
	// Skip if no token data — in-progress turn or empty assistant slot.
	if msg.Tokens.Input == 0 && msg.Tokens.Output == 0 &&
		msg.Tokens.Cache.Read == 0 && msg.Tokens.Cache.Write == 0 &&
		msg.Tokens.Reasoning == 0 {
		return models.TokenEvent{}, false
	}
	cwd := firstNonEmpty(msg.Path.Cwd, row.Directory)
	project := a.resolveProjectRoot(cwd, rootCache)
	remote := a.resolveProjectRemote(cwd, rootCache)
	// Drop msg.Agent as a model fallback — `agent` is the OpenCode
	// agent identity (build / plan / explore / build-subagent / etc.),
	// NOT a model name. Letting it leak into the model column polluted
	// rollups for system messages where modelID was empty.
	model := firstNonEmpty(msg.ModelID, msg.Model.ModelID)
	when := millisToTime(msg.Time.Completed)
	if when.IsZero() {
		when = millisToTime(row.TimeUpdate)
	}
	return models.TokenEvent{
		SourceFile:          sourceFile,
		SourceEventID:       "tokens:" + row.ID,
		SessionID:           row.SessionID,
		ProjectRoot:         project,
		GitRemote:           remote,
		Timestamp:           when,
		Tool:                models.ToolOpenCode,
		Model:               model,
		InputTokens:         msg.Tokens.Input,
		OutputTokens:        msg.Tokens.Output,
		CacheReadTokens:     msg.Tokens.Cache.Read,
		CacheCreationTokens: msg.Tokens.Cache.Write,
		ReasoningTokens:     msg.Tokens.Reasoning,
		EstimatedCostUSD:    msg.Cost,
		// Source/Reliability: OpenCode persists the upstream provider's
		// usage envelope verbatim (no streaming-placeholder hack like
		// Claude Code's JSONL has), so the data is more trustworthy than
		// `unreliable` but still hasn't been verified against an upstream
		// invoice — call it `approximate`.
		Source:      models.TokenSourceJSONL,
		Reliability: models.ReliabilityApproximate,
		MessageID:   row.ID,
	}, true
}

// loadSubtaskEvents reads OpenCode's `subtask` parts and emits one
// ActionSpawnSubagent per — the parent message invoked a sub-agent.
// The actual sub-agent runs in a child session linked via
// session.parent_id; that linkage is captured by loadSessionLineages.
// Surfacing the parent-side spawn lets the dashboard count fan-out
// the same way Claude Code's Agent tool does.
func (a *Adapter) loadSubtaskEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]projectGitInfo) ([]models.ToolEvent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.message_id, p.session_id, COALESCE(s.directory, ''),
		       p.time_created, p.time_updated, p.data, m.data
		  FROM part p
		  JOIN message m ON m.id = p.message_id
		  LEFT JOIN session s ON s.id = p.session_id
		 WHERE p.time_updated > ?
		   AND json_extract(p.data, '$.type') = 'subtask'
		 ORDER BY p.time_updated ASC, p.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ToolEvent
	for rows.Next() {
		var row partRow
		if err := rows.Scan(&row.ID, &row.MessageID, &row.SessionID, &row.Directory, &row.TimeCreate, &row.TimeUpdate, &row.Data, &row.Message); err != nil {
			return nil, err
		}
		var msg messageData
		if err := json.Unmarshal([]byte(row.Message), &msg); err != nil {
			continue
		}
		var sub subtaskPartData
		if err := json.Unmarshal([]byte(row.Data), &sub); err != nil {
			continue
		}
		if sub.Type != "subtask" {
			continue
		}
		// Target is the spawned agent name (Build/Plan/Explore/custom).
		// RawToolName captures the description so the Actions table
		// shows what the parent asked the subagent to do.
		cwd := firstNonEmpty(msg.Path.Cwd, row.Directory)
		project := a.resolveProjectRoot(cwd, rootCache)
		remote := a.resolveProjectRemote(cwd, rootCache)
		// Prefer the spawned subagent's model when set; falls back to
		// the parent message's model.
		model := firstNonEmpty(sub.Model.ModelID, msg.ModelID, msg.Model.ModelID)
		target := firstNonEmpty(sub.Agent, "subagent")
		when := millisToTime(sub.Time.Created)
		if when.IsZero() {
			when = millisToTime(row.TimeCreate)
		}
		out = append(out, models.ToolEvent{
			SourceFile:    sourceFile,
			SourceEventID: "subtask:" + row.ID,
			SessionID:     row.SessionID,
			ProjectRoot:   project,
			GitRemote:     remote,
			Timestamp:     when,
			Model:         model,
			Tool:          models.ToolOpenCode,
			ActionType:    models.ActionSpawnSubagent,
			Target:        target,
			Success:       true,
			RawToolName:   "subtask",
			RawToolInput:  contentcap.Cap(firstNonEmpty(sub.Description, sub.Prompt), contentcap.DefaultMaxBytes),
			MessageID:     row.MessageID,
			Metadata:      effortMetadata(msg.Variant),
		})
	}
	return out, rows.Err()
}

// loadSessionLineages reads OpenCode's session.parent_id links — the
// upstream sub-agent child-session pointer (the v2 Session.subagent
// surface spawns a child with parentID set; root list queries filter
// IS NULL(parent_id), so children never pollute top-level lists) — and
// emits one models.SessionLineage per linked child so the observer's
// generic migration-069 lineage columns (forked_from_id /
// parent_thread_id / thread_source) carry the parent→child link for
// opencode too, not just codex. The read model is already tool-agnostic:
// LoadSessionLineage feeds the session-detail payload and LineageBanner
// regardless of sessions.tool.
//
// Emitted on EVERY parse that opens the DB (the pair set is small — one
// indexed query over session — and SetSessionLineage is an idempotent,
// COALESCE-preserving upsert that no-ops on unchanged values), so both
// incremental polls and full re-parses (`observer scan --force`) converge
// without dedicated watermark state. A child whose sessions row does not
// exist yet is a silent store-side no-op; the next parse that ingests its
// events stamps it. ThreadSource is "subagent": opencode uses parent_id
// exclusively for spawned sub-agent children.
func (a *Adapter) loadSessionLineages(ctx context.Context, db *sql.DB) ([]models.SessionLineage, error) {
	// Older opencode schemas predate parent_id entirely; treat them as
	// "no linkage available" rather than failing the whole parse.
	var parentCol int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM pragma_table_info('session') WHERE name = 'parent_id'`,
	).Scan(&parentCol); err != nil {
		return nil, err
	}
	if parentCol == 0 {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, parent_id FROM session WHERE parent_id IS NOT NULL AND parent_id != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.SessionLineage
	for rows.Next() {
		var id, parent string
		if err := rows.Scan(&id, &parent); err != nil {
			return nil, err
		}
		out = append(out, models.SessionLineage{
			SessionID:      id,
			ParentThreadID: parent,
			ThreadSource:   "subagent",
		})
	}
	return out, rows.Err()
}

// loadTodoEvents reads the `todo` table — each row is one entry in
// the agent's structured task list (status: pending/in_progress/
// completed). Emits one ActionTodoUpdate per row that has changed
// since fromOffset, mirroring how Claude Code's TaskCreate /
// TaskUpdate / TaskList tools are tagged in the claudecode adapter.
//
// The todo table has a composite PK of (session_id, position), no
// stable id; we synthesize a deterministic SourceEventID from
// session_id + position so re-ingest is INSERT-OR-IGNORE-safe.
//
// Tolerant of older OpenCode schemas that lack the todo table —
// the SQL error gets swallowed and the function returns an empty
// slice rather than failing the whole parse pass.
func (a *Adapter) loadTodoEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]projectGitInfo) ([]models.ToolEvent, error) {
	if !tableExists(ctx, db, "todo") {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT t.session_id, t.position, t.content, t.status, t.priority,
		       t.time_created, t.time_updated, COALESCE(s.directory, '')
		  FROM todo t
		  LEFT JOIN session s ON s.id = t.session_id
		 WHERE t.time_updated > ?
		 ORDER BY t.time_updated ASC, t.position ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ToolEvent
	for rows.Next() {
		var sessionID, content, status, priority, dir string
		var position int
		var tCreated, tUpdated int64
		if err := rows.Scan(&sessionID, &position, &content, &status, &priority, &tCreated, &tUpdated, &dir); err != nil {
			return nil, err
		}
		when := millisToTime(tUpdated)
		if when.IsZero() {
			when = millisToTime(tCreated)
		}
		eventID := fmt.Sprintf("todo:%s:%d:%d", sessionID, position, tUpdated)
		out = append(out, models.ToolEvent{
			SourceFile:    sourceFile,
			SourceEventID: eventID,
			SessionID:     sessionID,
			ProjectRoot:   a.resolveProjectRoot(dir, rootCache),
			GitRemote:     a.resolveProjectRemote(dir, rootCache),
			Timestamp:     when,
			Tool:          models.ToolOpenCode,
			ActionType:    models.ActionTodoUpdate,
			// Target carries the status so dashboards can filter by
			// pending vs completed without having to parse RawToolInput.
			Target:       status,
			Success:      true,
			RawToolName:  "todo." + status,
			RawToolInput: contentcap.Cap(content, contentcap.DefaultMaxBytes),
		})
	}
	return out, rows.Err()
}

func mapTool(part toolPartData) (actionType, target string, success bool, errMsg string) {
	var input toolInput
	_ = json.Unmarshal(part.State.Input, &input)

	actionType = models.ActionUnknown
	target = firstNonEmpty(input.Command, input.FilePath, part.State.Metadata.FilePath, part.State.Title, part.Tool)
	success = part.State.Status == "" || strings.EqualFold(part.State.Status, "completed")
	if part.Tool == "bash" {
		success = success && part.State.Metadata.Exit == 0
		if !success {
			errMsg = firstNonEmpty(part.State.Output, part.State.Metadata.Output)
		}
	}

	switch strings.ToLower(strings.TrimSpace(part.Tool)) {
	case "bash", "shell", "command",
		"powershell", "pwsh", "cmd", "cmd.exe":
		actionType = models.ActionRunCommand
		target = firstNonEmpty(input.Command, part.State.Title, part.Tool)
	case "read", "cat", "view":
		actionType = models.ActionReadFile
		target = firstNonEmpty(input.FilePath, part.State.Metadata.FilePath, part.State.Title, part.Tool)
	case "write", "create":
		actionType = models.ActionWriteFile
		target = firstNonEmpty(input.FilePath, part.State.Metadata.FilePath, part.State.Title, part.Tool)
	case "edit", "patch", "replace", "multiedit", "applypatch", "apply_patch":
		actionType = models.ActionEditFile
		target = firstNonEmpty(input.FilePath, part.State.Metadata.FilePath, part.State.Title, part.Tool)
	case "grep", "search", "rg":
		actionType = models.ActionSearchText
	case "glob", "find", "ls":
		actionType = models.ActionSearchFiles
	case "webfetch", "fetch", "http":
		actionType = models.ActionWebFetch
		target = firstNonEmpty(part.State.Title, part.Tool)
	case "websearch":
		actionType = models.ActionWebSearch
		target = firstNonEmpty(part.State.Title, part.Tool)
	case "task", "agent", "subagent":
		// OpenCode's Task tool launches a subagent; same semantic as
		// Claude Code's Agent tool. Tag spawn_subagent so the dashboard
		// counts fan-out separately from regular tool work.
		actionType = models.ActionSpawnSubagent
		target = firstNonEmpty(part.State.Title, part.Tool)
	case "todoread", "todowrite", "todo":
		// Mirrors Claude Code's TaskCreate/TaskUpdate todo-list tools
		// (mapped to ActionTodoUpdate in the claudecode adapter).
		actionType = models.ActionTodoUpdate
		target = firstNonEmpty(part.State.Title, part.Tool)
	default:
		if strings.Contains(strings.ToLower(part.Tool), "mcp") {
			actionType = models.ActionMCPCall
		}
	}
	return actionType, target, success, errMsg
}

// resolveProjectRoot turns an OpenCode-recorded cwd (or session.directory)
// into a stable project root. Mirrors the codex adapter's pattern:
//
//   - empty cwd → "[opencode]" placeholder (matches pre-parity behavior so
//     existing "[opencode]" rows continue to coalesce).
//   - real cwd inside a git working tree → the git root (so a session that
//     started in a subdirectory groups under the same project as one that
//     started at the repo root).
//   - real cwd outside any git tree → the cwd itself (post-symlink).
//
// The cache lives for one ParseSessionFile call; same cwd resolves once.
// projectGitInfo is the per-cwd cache entry for resolveProjectRoot /
// resolveProjectRemote: the resolved project root and its normalized
// "origin" remote, captured together from a single git.ResolveIdentity
// call so the two never drift and the filesystem walk never happens
// twice for the same cwd. Identity carries the fuller Project Identity
// Resolver v2 bundle from the same call.
type projectGitInfo struct {
	Root     string
	Remote   string
	Identity git.Identity
}

func (a *Adapter) resolveProjectRoot(cwd string, cache map[string]projectGitInfo) string {
	if cwd == "" {
		return "[opencode]"
	}
	// OpenCode Desktop on Windows records cwd as a Windows-style path
	// (e.g. "C:\programsx\superbased-observer"). When that DB is read
	// by an observer running in WSL2, filepath.Abs treats the string
	// as relative because Linux doesn't recognise the drive prefix —
	// which prepends the observer's CWD and then git.Resolve walks UP
	// looking for .git, landing on observer's own repo and misfiling
	// every Windows-side Desktop session under observer's project.
	// Translate to the WSL2 mount equivalent ("/mnt/c/programsx/...")
	// so git.Resolve operates on the actual cross-mount path. Mirrors
	// claudecode adapter.go:1055 and codex adapter.go:2494
	// ([[feedback-foreign-path-git-resolve]]).
	cwd = crossmount.TranslateForeignPath(cwd)
	if info, ok := cache[cwd]; ok {
		return info.Root
	}
	// RootCommit is left nil: the lazy, cached root-commit exec belongs
	// only in the store-side path (Store.maybeRunLazyRootCommit), never
	// on a per-row adapter hot path.
	info, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		cache[cwd] = projectGitInfo{Root: cwd}
		return cwd
	}
	// info.Remote is already NormalizeRemote'd by ResolveIdentity.
	cache[cwd] = projectGitInfo{Root: info.Root, Remote: info.Remote, Identity: info}
	return info.Root
}

// resolveProjectRemote returns the normalized git remote for cwd, cached
// alongside the project root by resolveProjectRoot. OpenCode never
// carries a remote (or a branch) in its own SQLite rows, so this is
// the adapter's only remote source. Callers must invoke
// resolveProjectRoot for the same cwd first so the cache entry exists
// — this never triggers its own git.Resolve call, to avoid resolving
// the same cwd twice.
func (a *Adapter) resolveProjectRemote(cwd string, cache map[string]projectGitInfo) string {
	if cwd == "" {
		return ""
	}
	cwd = crossmount.TranslateForeignPath(cwd)
	return cache[cwd].Remote
}

// identitiesByRoot flattens a per-cwd projectGitInfo cache into a
// per-root git.Identity map suitable for
// adapter.ApplyProjectIdentityByRoot. Multiple cwds resolving to the
// same repo root collapse to one entry (they carry identical
// identity, since ResolveIdentity is keyed off the discovered root).
func identitiesByRoot(cache map[string]projectGitInfo) map[string]git.Identity {
	out := make(map[string]git.Identity, len(cache))
	for _, entry := range cache {
		if entry.Root == "" {
			continue
		}
		out[entry.Root] = entry.Identity
	}
	return out
}

func latestWatermark(ctx context.Context, path string) (int64, error) {
	db, err := openReadOnlyDB(path)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	var latest int64
	row := db.QueryRowContext(ctx, `
		SELECT MAX(v) FROM (
			SELECT COALESCE(MAX(time_updated), 0) AS v FROM message
			UNION ALL
			SELECT COALESCE(MAX(time_updated), 0) AS v FROM part
			UNION ALL
			SELECT COALESCE(MAX(time_updated), 0) AS v FROM session
		)`)
	if err := row.Scan(&latest); err != nil {
		return 0, err
	}
	return latest, nil
}

func openReadOnlyDB(path string) (*sql.DB, error) {
	actual, err := stageMirrorIfForeign(path)
	if err != nil {
		return nil, fmt.Errorf("opencode.stageMirror: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)", sqlitedsn.Escape(actual))
	return sql.Open("sqlite", dsn)
}

// stageMirrorIfForeign returns the source path unchanged when it's
// native. For foreign-mount sources (e.g. /mnt/c/Users/<u>/.local/share/
// opencode/opencode.db on a WSL2 Linux host reading the Windows-side
// OpenCode Desktop store) it stages a local mirror — copying the
// SQLite trio (.db + -wal + -shm) into a per-source cache dir under
// mirrorbase.Base() (the single-owner seam over os.UserCacheDir(),
// overridable per-process for one-shot lifecycles) and returning the
// path to the mirrored .db.
//
// Why the mirror is load-bearing on /mnt/c: modernc.org/sqlite returns
// SQLITE_IOERR_SHORT_READ (4618) when opening the foreign-mount path
// while Windows is actively writing the WAL. Verified 2026-05-21 with
// a live Desktop session reproduced via the adapter's exact DSN —
// the disk-I/O error blocked ingestion of every Windows Desktop
// session until this mirror was wired in.
//
// Refresh policy: skip the copy when every source file is older than
// (or matches) the mirror sibling. WAL is the fast-moving signal —
// its mtime advances faster than the main .db file as Windows
// appends pages. Same applies for the reverse direction (Windows
// host reading \\wsl.localhost\<distro>\… would hit the same race
// on a sufficiently loaded Linux writer).
func stageMirrorIfForeign(srcDB string) (string, error) {
	if !isForeignMountPath(srcDB) {
		return srcDB, nil
	}
	base, err := mirrorbase.Base()
	if err != nil || base == "" {
		base = filepath.Join(os.TempDir(), "superbased-observer")
	}
	sum := sha256.Sum256([]byte(srcDB))
	mirrorDir := filepath.Join(base, "opencode-mirror", hex.EncodeToString(sum[:8]))
	if err := os.MkdirAll(mirrorDir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir mirror: %w", err)
	}
	dstDB := filepath.Join(mirrorDir, "opencode.db")
	if mirrorUpToDate(srcDB, dstDB) {
		return dstDB, nil
	}
	// Copy the trio. Main .db is the primary; -wal carries pages the
	// writer hasn't checkpointed yet; -shm is the shared-memory index
	// of the WAL (32 KB, regenerable but matching siblings keeps SQLite
	// from re-deriving it on open). Missing siblings are removed from
	// the mirror so a stale -wal doesn't shadow a freshly-checkpointed
	// source.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		src := srcDB + suffix
		dst := dstDB + suffix
		data, err := os.ReadFile(src)
		if err != nil {
			if os.IsNotExist(err) {
				_ = os.Remove(dst)
				continue
			}
			return "", fmt.Errorf("read %s: %w", src, err)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return "", fmt.Errorf("write %s: %w", dst, err)
		}
	}
	return dstDB, nil
}

// mirrorUpToDate reports whether the mirror trio is at least as fresh
// as the source trio. Uses (size, mtime) per sibling — the size guard
// catches an in-flight truncate/realloc that mtime alone misses
// (occasionally seen on /mnt/c when Windows checkpoints the WAL).
// Returns false on any stat error so a fresh copy gets attempted.
func mirrorUpToDate(srcDB, dstDB string) bool {
	if !filesMatch(srcDB, dstDB) {
		return false
	}
	// WAL is the fast-moving signal — its mtime ticks every flush.
	if sw, err := os.Stat(srcDB + "-wal"); err == nil {
		if !filesMatchInfo(sw, dstDB+"-wal") {
			return false
		}
	}
	return true
}

func filesMatch(src, dst string) bool {
	s, err := os.Stat(src)
	if err != nil {
		return false
	}
	return filesMatchInfo(s, dst)
}

func filesMatchInfo(srcInfo os.FileInfo, dst string) bool {
	d, err := os.Stat(dst)
	if err != nil {
		return false
	}
	if srcInfo.Size() != d.Size() {
		return false
	}
	return !srcInfo.ModTime().After(d.ModTime())
}

// allHomesFunc is the test seam over crossmount.AllHomes — tests
// override it to assert foreign-mount detection without depending on
// the host's filesystem layout.
var allHomesFunc = crossmount.AllHomes

// isForeignMountPath reports whether path lives under a
// crossmount-detected non-native home. Both directions are covered:
// /mnt/c/Users/<u>/… on a WSL2 Linux host, and
// \\wsl.localhost\<distro>\home\<u>\… on a Windows host. The watcher
// dispatches both native and foreign-mount homes into the same
// adapter; only the foreign ones need the mirror.
func isForeignMountPath(path string) bool {
	for _, h := range allHomesFunc() {
		if h.Origin == "native" {
			continue
		}
		// Accept both the OS-native separator and forward slash —
		// /mnt/c uses forward slashes regardless of the foreign OS.
		sep := string(filepath.Separator)
		if strings.HasPrefix(path, h.Path+sep) || strings.HasPrefix(path, h.Path+"/") {
			return true
		}
	}
	return false
}

func resolveDBPath(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == "opencode.db-wal" || base == "opencode.db-shm" {
		return filepath.Join(filepath.Dir(path), "opencode.db")
	}
	return path
}

func millisToTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func chooseTime(primary, fallback time.Time, delta time.Duration) time.Time {
	if !primary.IsZero() {
		return primary
	}
	if fallback.IsZero() {
		return time.Now().UTC().Add(delta)
	}
	return fallback.Add(delta)
}

// defaultRoots covers both OpenCode variants in the wild today:
//
//   - sst/opencode (opencode.ai) — current canonical CLI; stores at
//     ~/.opencode/opencode.db. This is the path the upstream docs and
//     the `opencode stats` CLI advertise.
//   - ai.opencode.desktop — the older desktop app variant; per-OS
//     XDG-ish paths kept for back-compat with installs that haven't
//     migrated.
//   - ~/.local/share/opencode — XDG_DATA_HOME fallback used by some
//     packagings of either variant.
//
// Roots are emitted under every cross-mount-resolved $HOME so observer
// in WSL2 picks up an OpenCode install on the Windows side (and
// vice-versa). The desktop-variant subpath branches on h.OS because
// each platform has a different conventional location. The canonical
// ".opencode" and XDG ".local/share/opencode" are emitted for every
// home — they're tolerated even on Windows installs that don't use
// them (the IsSessionFile check ignores absent files).
func defaultRoots() []string {
	var roots []string
	for _, h := range crossmount.AllHomes() {
		roots = append(
			roots,
			filepath.Join(h.Path, ".opencode"),
			filepath.Join(h.Path, ".local", "share", "opencode"),
		)
		switch h.OS {
		case crossmount.OSWindows:
			roots = append(roots, filepath.Join(h.Path, "AppData", "Roaming", "ai.opencode.desktop"))
		case crossmount.OSDarwin:
			roots = append(roots, filepath.Join(h.Path, "Library", "Application Support", "ai.opencode.desktop"))
		case crossmount.OSLinux:
			roots = append(roots, filepath.Join(h.Path, ".config", "ai.opencode.desktop"))
		}
	}
	return roots
}

// tableExists returns true when the given table is present in the
// SQLite database. Used by loadTodoEvents (and similar future
// optional-table queries) to degrade gracefully on OpenCode schemas
// that don't have every table.
func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// effortMetadata returns an ActionMetadata pointer carrying the
// effort level when variant is non-empty, or nil to leave the action
// row's metadata column NULL. OpenCode CLI sets `variant` to "low",
// "medium", or "high" on every assistant message; the Desktop variant
// doesn't stamp it. Mirrors claudecode.stampEffortFromSidecar /
// codex withEffort behavior so dashboards can group by effort across
// adapters.
func effortMetadata(variant string) *models.ActionMetadata {
	v := strings.TrimSpace(variant)
	if v == "" {
		return nil
	}
	return &models.ActionMetadata{EffortLevel: v}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
