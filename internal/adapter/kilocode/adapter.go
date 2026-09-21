package kilocode

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

// CLIAdapter parses the Kilo Code CLI's SQLite state store at
// ~/.local/share/kilo/kilo.db. Kilo CLI is a fork of sst/opencode and
// the schema is OpenCode-shaped — `session`/`message`/`part`/`todo`
// tables behave the same way — with Kilo-specific extensions
// (`project` table providing worktree metadata, `workspace`/`account`/
// `event`/`session_message`/`permission`/`session_share` tables not
// parsed for v1 because they're unpopulated on every install captured).
//
// Per-message authoritative tokens land on `message.data.tokens =
// {total, input, output, reasoning, cache: {read, write}}` — mirror of
// the OpenCode invariant. `step-finish` parts carry per-step slices
// summing to the message total, so loadTokenEvents extracts from
// messages only and skips step-finish to avoid double-counting.
type CLIAdapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// NewCLI returns a CLIAdapter with default scrubber and cross-mount-aware
// roots.
func NewCLI() *CLIAdapter {
	return &CLIAdapter{scrubber: scrub.New(), roots: defaultCLIRoots()}
}

// NewCLIWithOptions customizes scrubber and/or roots for tests.
func NewCLIWithOptions(s *scrub.Scrubber, roots []string) *CLIAdapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultCLIRoots()
	}
	return &CLIAdapter{scrubber: s, roots: roots}
}

// Name implements adapter.Adapter.
func (*CLIAdapter) Name() string { return models.ToolKiloCodeCLI }

// WatchPaths implements adapter.Adapter.
func (a *CLIAdapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Matches Kilo's SQLite
// trio inside one of this adapter's WatchPaths. The under-WatchPaths
// constraint avoids accidentally claiming an archived `kilo.db` copy
// living elsewhere on disk.
func (a *CLIAdapter) IsSessionFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base != "kilo.db" && base != "kilo.db-wal" {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// ParseSessionFile implements adapter.Adapter.
func (a *CLIAdapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	dbPath := resolveDBPath(path)
	latest, err := latestWatermark(ctx, dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kilocode.ParseSessionFile: latest watermark: %w", err)
	}
	res := adapter.ParseResult{NewOffset: latest}
	if latest <= fromOffset {
		return res, nil
	}

	database, err := openReadOnlyDB(dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kilocode.ParseSessionFile: open: %w", err)
	}
	defer database.Close()

	rootCache := map[string]kiloResolvedRoot{}
	// Resolve reasoning -> successor assignment BEFORE any emitter runs,
	// so the threading can't depend on loader order (see
	// loadReasoningIndex). Reasoning parts are never rows of their own.
	reasoning, err := a.loadReasoningIndex(ctx, database, fromOffset)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kilocode.ParseSessionFile: reasoning index: %w", err)
	}
	prompts, err := a.loadUserPromptEvents(ctx, database, dbPath, fromOffset, rootCache)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kilocode.ParseSessionFile: prompts: %w", err)
	}
	tools, err := a.loadToolEvents(ctx, database, dbPath, fromOffset, rootCache, reasoning)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kilocode.ParseSessionFile: tools: %w", err)
	}
	completions, err := a.loadCompletionEvents(ctx, database, dbPath, fromOffset, rootCache)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kilocode.ParseSessionFile: completions: %w", err)
	}
	assistantTexts, err := a.loadAssistantTextEvents(ctx, database, dbPath, fromOffset, rootCache, reasoning)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kilocode.ParseSessionFile: assistant_text: %w", err)
	}
	subtasks, err := a.loadSubtaskEvents(ctx, database, dbPath, fromOffset, rootCache)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kilocode.ParseSessionFile: subtasks: %w", err)
	}
	stepFinishes, err := a.loadStepFinishEvents(ctx, database, dbPath, fromOffset, rootCache)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kilocode.ParseSessionFile: step_finish: %w", err)
	}
	todos, err := a.loadTodoEvents(ctx, database, dbPath, fromOffset, rootCache)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kilocode.ParseSessionFile: todos: %w", err)
	}
	tokens, err := a.loadTokenEvents(ctx, database, dbPath, fromOffset, rootCache)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kilocode.ParseSessionFile: tokens: %w", err)
	}
	// §14.3 Tier-2 cache observation. Volatile-element exclusion
	// (wall-clock fields inside tool/reasoning/subtask part bodies)
	// is documented in docs/audits/cachetrack-kilo-cli-tier2-audit-
	// 2026-06-09.md and enforced by struct-based canonical
	// marshallers in cachetrack.go (R3 byte-stability guard).
	cacheObservations, err := a.loadCacheObservations(ctx, database, dbPath, fromOffset)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kilocode.ParseSessionFile: cache_observations: %w", err)
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
	// Issue 2: the Kilo CLI build version rides on the `session` row
	// (session.version, e.g. "7.3.40"). Stamp it node-local for the
	// sessions this slice touched. Store write is first-wins-unless-empty
	// + bounded-token validated.
	touched := map[string]bool{}
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SessionID != "" {
			touched[res.ToolEvents[i].SessionID] = true
		}
	}
	for i := range res.TokenEvents {
		if res.TokenEvents[i].SessionID != "" {
			touched[res.TokenEvents[i].SessionID] = true
		}
	}
	res.SessionToolVersions = append(res.SessionToolVersions, a.loadSessionToolVersions(ctx, database, touched)...)
	// Project Identity Resolver v2 (2026-09-06, §3.1 / W1): rootCache
	// already carries one git.Identity per distinct cwd this parse
	// touched (a kilo-cli db can span multiple sessions/projects), keyed
	// by the resolved root — exactly what ApplyProjectIdentityByRoot
	// wants.
	identitiesByRoot := make(map[string]git.Identity, len(rootCache))
	for _, resolved := range rootCache {
		if resolved.root != "" {
			identitiesByRoot[resolved.root] = resolved.identity
		}
	}
	adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot)
	return res, nil
}

// kiloSessionDirectory carries the per-session worktree fallback chain.
// Populated once per ParseSessionFile by sessionDirectoryCache, joined to
// each row via session_id.
type kiloSessionDirectory struct {
	Directory       string // session.directory column
	ProjectWorktree string // JOIN project.worktree via session.project_id
}

func (k kiloSessionDirectory) Fallback() string {
	if k.Directory != "" {
		return k.Directory
	}
	return k.ProjectWorktree
}

type messageRow struct {
	ID         string
	SessionID  string
	TimeCreate int64
	TimeUpdate int64
	Data       string
}

type partRow struct {
	ID         string
	MessageID  string
	SessionID  string
	TimeCreate int64
	TimeUpdate int64
	Data       string
	Message    string
}

// messageData mirrors the JSON shape of `message.data` confirmed live
// against a 2026-06-06 capture (both Windows and WSL).
//
// User message:
//
//	{role:"user", time:{created}, agent, model:{providerID, modelID},
//	 summary:{diffs:[]}}
//
// Assistant message:
//
//	{parentID, role:"assistant", mode, agent, path:{cwd, root}, cost,
//	 tokens:{total, input, output, reasoning, cache:{write, read}},
//	 modelID, providerID, time:{created, completed}, finish}
type messageData struct {
	Role     string `json:"role"`
	Agent    string `json:"agent"`
	Mode     string `json:"mode"`
	ParentID string `json:"parentID"`
	Model    struct {
		ProviderID string `json:"providerID"`
		ModelID    string `json:"modelID"`
	} `json:"model"`
	ModelID    string `json:"modelID"`
	ProviderID string `json:"providerID"`
	Path       struct {
		Cwd  string `json:"cwd"`
		Root string `json:"root"`
	} `json:"path"`
	Time struct {
		Created   int64 `json:"created"`
		Completed int64 `json:"completed"`
	} `json:"time"`
	Finish string `json:"finish"`
	Tokens struct {
		Total     int64 `json:"total"`
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

// textPartData covers `{"type":"text","text":"…"}` parts (both user
// prompts and assistant text).
type textPartData struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// toolPartData mirrors the confirmed live shape of tool-typed parts.
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
	Metadata struct {
		OpenRouter struct {
			ReasoningDetails []struct {
				Type   string `json:"type"`
				Text   string `json:"text"`
				Format string `json:"format"`
				Index  int    `json:"index"`
			} `json:"reasoning_details"`
		} `json:"openrouter"`
	} `json:"metadata"`
}

// subtaskPartData mirrors OpenCode's subtask shape (a subagent spawn
// embedded in the parent's message).
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

// reasoningPartData mirrors the `reasoning` part shape. Kilo wraps the
// model's chain-of-thought identically to OpenCode.
type reasoningPartData struct {
	Type string `json:"type"`
	Text string `json:"text"`
	Time struct {
		Start int64 `json:"start"`
		End   int64 `json:"end"`
	} `json:"time"`
}

// stepFinishPartData mirrors `step-finish` parts — per-step token + cost
// slice that sums to the message-level token bundle. We surface as a
// ToolEvent for dashboard observability but NEVER as TokenEvents (would
// double-count against loadTokenEvents).
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

type toolInput struct {
	Command   string `json:"command"`
	FilePath  string `json:"filePath"`
	WorkDir   string `json:"workdir"`
	Query     string `json:"query"`
	URL       string `json:"url"`
	Path      string `json:"path"`
	Pattern   string `json:"pattern"`
	Regex     string `json:"regex"`
	NumResult int    `json:"numResults"`
}

// loadSessionDirectories prebuilds the per-session worktree fallback
// chain (session.directory → project.worktree). One small query, used
// to avoid N round-trips when resolving cwds across hundreds of rows.
func (a *CLIAdapter) loadSessionDirectories(ctx context.Context, db *sql.DB) (map[string]kiloSessionDirectory, error) {
	hasProject := tableExists(ctx, db, "project")
	out := map[string]kiloSessionDirectory{}
	var query string
	if hasProject {
		query = `SELECT s.id, COALESCE(s.directory, ''), COALESCE(p.worktree, '')
			  FROM session s
			  LEFT JOIN project p ON p.id = s.project_id`
	} else {
		query = `SELECT id, COALESCE(directory, ''), '' FROM session`
	}
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, dir, worktree string
		if err := rows.Scan(&id, &dir, &worktree); err != nil {
			return nil, err
		}
		out[id] = kiloSessionDirectory{Directory: dir, ProjectWorktree: worktree}
	}
	return out, rows.Err()
}

// loadSessionToolVersions reads the per-session `version` column — the
// Kilo CLI build that produced the session ("7.3.40") — for Issue 2
// tool-version capture (migration 125). Only sessions in `touched`
// (those with new rows this slice) get a stamp, so an incremental poll
// re-stamps just the active sessions; the store's first-wins write makes
// a repeat harmless anyway. The `version` column is absent on older Kilo
// schemas, so a query error is TOLERATED (returns nil) rather than
// failing the whole parse — the tableExists-tolerant posture the rest of
// this adapter uses.
func (a *CLIAdapter) loadSessionToolVersions(ctx context.Context, db *sql.DB, touched map[string]bool) []models.SessionToolVersion {
	if len(touched) == 0 {
		return nil
	}
	rows, err := db.QueryContext(ctx, `SELECT id, COALESCE(version, '') FROM session`)
	if err != nil {
		return nil // older schema without a version column — tolerate.
	}
	defer rows.Close()
	var out []models.SessionToolVersion
	for rows.Next() {
		var id, ver string
		if err := rows.Scan(&id, &ver); err != nil {
			return out
		}
		if ver == "" || !touched[id] {
			continue
		}
		out = append(out, models.SessionToolVersion{SessionID: id, Version: ver})
	}
	return out
}

func (a *CLIAdapter) loadUserPromptEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]kiloResolvedRoot) ([]models.ToolEvent, error) {
	sessDirs, err := a.loadSessionDirectories(ctx, db)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT m.id, m.session_id, m.time_created, m.time_updated, m.data
		  FROM message m
		 WHERE m.time_updated > ?
		   AND json_valid(m.data)
		   AND json_extract(m.data, '$.role') = 'user'
		 ORDER BY m.time_updated ASC, m.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.ToolEvent
	for rows.Next() {
		var row messageRow
		if err := rows.Scan(&row.ID, &row.SessionID, &row.TimeCreate, &row.TimeUpdate, &row.Data); err != nil {
			return nil, err
		}
		ev, ok, err := a.userPromptEvent(ctx, db, sourceFile, row, sessDirs, rootCache)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

func (a *CLIAdapter) userPromptEvent(ctx context.Context, db *sql.DB, sourceFile string, row messageRow, sessDirs map[string]kiloSessionDirectory, rootCache map[string]kiloResolvedRoot) (models.ToolEvent, bool, error) {
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
	project, remote := a.resolveProjectRoot(a.cwdFor(msg, sessDirs[row.SessionID]), rootCache)
	model := firstNonEmpty(msg.Model.ModelID, msg.ModelID)
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      "message:" + row.ID,
		SessionID:          row.SessionID,
		ProjectRoot:        project,
		GitRemote:          remote,
		Timestamp:          chooseTime(when, time.Time{}, 0),
		Model:              model,
		Tool:               models.ToolKiloCodeCLI,
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
// §1). Kept deliberately symmetric with the OpenCode adapter's function
// of the same name (this adapter is a structural transposition of it);
// semantics match grok's reference shape:
//
//   - CONSUMED-ONCE: a reasoning body is threaded onto exactly ONE
//     successor — the first `tool` or `text` part after it.
//   - LAST-WINS: consecutive reasoning parts with no successor between
//     them collapse; the newest is the one threaded.
//   - TURN BOUNDARY: the walk is partitioned by message id, so a
//     thought can never leak past its own assistant turn.
//
// Computed in ONE ordered pass before any emitter runs, so the result
// cannot depend on the order the loaders happen to run in. The window
// is widened from the incremental `time_updated > ?` slice to every
// part of the messages that slice touches, because a poll tick can land
// between a reasoning part and its successor.
func (a *CLIAdapter) loadReasoningIndex(ctx context.Context, db *sql.DB, fromOffset int64) (reasoningIndex, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.message_id, json_extract(p.data, '$.type'), COALESCE(json_extract(p.data, '$.text'), '')
		  FROM part p
		 WHERE p.message_id IN (SELECT message_id FROM part WHERE time_updated > ?)
		   AND json_valid(p.data)
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

func (a *CLIAdapter) loadToolEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]kiloResolvedRoot, reasoning reasoningIndex) ([]models.ToolEvent, error) {
	sessDirs, err := a.loadSessionDirectories(ctx, db)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.message_id, p.session_id, p.time_created, p.time_updated, p.data, m.data
		  FROM part p
		  JOIN message m ON m.id = p.message_id
		 WHERE p.time_updated > ?
		   AND json_valid(p.data) AND json_valid(m.data)
		   AND json_extract(p.data, '$.type') = 'tool'
		 ORDER BY p.time_updated ASC, p.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.ToolEvent
	for rows.Next() {
		var row partRow
		if err := rows.Scan(&row.ID, &row.MessageID, &row.SessionID, &row.TimeCreate, &row.TimeUpdate, &row.Data, &row.Message); err != nil {
			return nil, err
		}
		ev, ok := a.toolEvent(sourceFile, row, sessDirs, rootCache, reasoning)
		if ok {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

func (a *CLIAdapter) toolEvent(sourceFile string, row partRow, sessDirs map[string]kiloSessionDirectory, rootCache map[string]kiloResolvedRoot, reasoning reasoningIndex) (models.ToolEvent, bool) {
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
	project, remote := a.resolveProjectRoot(a.cwdFor(msg, sessDirs[row.SessionID]), rootCache)
	model := firstNonEmpty(msg.ModelID, msg.Model.ModelID)

	rawInput := string(part.State.Input)
	if a.scrubber != nil {
		rawInput = a.scrubber.RawJSON(part.State.Input)
	}
	output := firstNonEmpty(part.State.Output, part.State.Metadata.Output)
	if a.scrubber != nil {
		output = a.scrubber.String(output)
	}
	var durationMs int64
	if part.State.Time.Start > 0 && part.State.Time.End > part.State.Time.Start {
		durationMs = part.State.Time.End - part.State.Time.Start
	}
	// PRECEDENCE: the chain-of-thought body assigned by
	// loadReasoningIndex WINS over the part's own `title` and over the
	// OpenRouter reasoning-detail metadata. The title is Kilo's one-line
	// UI label for the call, not reasoning — it was only ever occupying
	// this column because nothing better reached it. Both older sources
	// stay as fallbacks, in their existing order, for calls in messages
	// with no reasoning part.
	preReason := strings.TrimSpace(part.State.Title)
	if rd := firstOpenRouterReasoning(part); rd != "" && preReason == "" {
		preReason = rd
	}
	if body := reasoning.threaded(row.ID); body != "" {
		preReason = body
	}
	if a.scrubber != nil && preReason != "" {
		preReason = a.scrubber.String(preReason)
	}
	if a.scrubber != nil && errMsg != "" {
		errMsg = a.scrubber.String(errMsg)
	}
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      "part:" + row.ID,
		SessionID:          row.SessionID,
		ProjectRoot:        project,
		GitRemote:          remote,
		Timestamp:          chooseTime(when, time.Time{}, 0),
		Model:              model,
		Tool:               models.ToolKiloCodeCLI,
		ActionType:         actionType,
		Target:             truncate(target, 200),
		Success:            success,
		ErrorMessage:       truncate(errMsg, 500),
		DurationMs:         durationMs,
		PrecedingReasoning: truncate(preReason, 200),
		RawToolName:        part.Tool,
		RawToolInput:       rawInput,
		ToolOutput:         output,
		MessageID:          row.MessageID,
	}, true
}

func (a *CLIAdapter) loadCompletionEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]kiloResolvedRoot) ([]models.ToolEvent, error) {
	sessDirs, err := a.loadSessionDirectories(ctx, db)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT m.id, m.session_id, m.time_created, m.time_updated, m.data
		  FROM message m
		 WHERE m.time_updated > ?
		   AND json_valid(m.data)
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
		if err := rows.Scan(&row.ID, &row.SessionID, &row.TimeCreate, &row.TimeUpdate, &row.Data); err != nil {
			return nil, err
		}
		ev, ok := a.completionEvent(sourceFile, row, sessDirs, rootCache)
		if ok {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

func (a *CLIAdapter) completionEvent(sourceFile string, row messageRow, sessDirs map[string]kiloSessionDirectory, rootCache map[string]kiloResolvedRoot) (models.ToolEvent, bool) {
	var msg messageData
	if err := json.Unmarshal([]byte(row.Data), &msg); err != nil {
		return models.ToolEvent{}, false
	}
	project, remote := a.resolveProjectRoot(a.cwdFor(msg, sessDirs[row.SessionID]), rootCache)
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
		Tool:          models.ToolKiloCodeCLI,
		ActionType:    models.ActionTaskComplete,
		Target:        firstNonEmpty(msg.Finish, "stop"),
		Success:       true,
		RawToolName:   "assistant.stop",
		MessageID:     row.ID,
		// Stamp the source finish reason into the canonical
		// Metadata.StopReason column (per-message terminal reason
		// surfaced in session review, matching opencode/cowork/pi) in
		// addition to the Target preview. Kilo's `finish` is the
		// OpenCode-shaped OpenAI vocabulary; stored source-native.
		Metadata: withStopReason(firstNonEmpty(msg.Finish, "stop")),
	}, true
}

// withStopReason builds an ActionMetadata carrying a terminal stop
// reason, or nil when the reason is empty so the column stays NULL.
func withStopReason(reason string) *models.ActionMetadata {
	if strings.TrimSpace(reason) == "" {
		return nil
	}
	return &models.ActionMetadata{StopReason: reason}
}

func (a *CLIAdapter) loadAssistantTextEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]kiloResolvedRoot, reasoning reasoningIndex) ([]models.ToolEvent, error) {
	sessDirs, err := a.loadSessionDirectories(ctx, db)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.message_id, p.session_id, p.time_created, p.time_updated, p.data, m.data
		  FROM part p
		  JOIN message m ON m.id = p.message_id
		 WHERE p.time_updated > ?
		   AND json_valid(p.data) AND json_valid(m.data)
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
		if err := rows.Scan(&row.ID, &row.MessageID, &row.SessionID, &row.TimeCreate, &row.TimeUpdate, &row.Data, &row.Message); err != nil {
			return nil, err
		}
		ev, ok := a.assistantTextEvent(sourceFile, row, sessDirs, rootCache, reasoning)
		if ok {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

func (a *CLIAdapter) assistantTextEvent(sourceFile string, row partRow, sessDirs map[string]kiloSessionDirectory, rootCache map[string]kiloResolvedRoot, reasoning reasoningIndex) (models.ToolEvent, bool) {
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
	project, remote := a.resolveProjectRoot(a.cwdFor(msg, sessDirs[row.SessionID]), rootCache)
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
		SourceFile:    sourceFile,
		SourceEventID: "asst:" + row.ID,
		SessionID:     row.SessionID,
		ProjectRoot:   project,
		GitRemote:     remote,
		Timestamp:     chooseTime(when, time.Time{}, 0),
		Model:         model,
		Tool:          models.ToolKiloCodeCLI,
		// One row per `text` part — per-message assistant text, matching
		// opencode (this adapter is a structural transposition of it).
		// The turn terminus is the separate `assistant.stop` row above.
		ActionType:         models.ActionAssistantMessage,
		Target:             preview,
		Success:            true,
		PrecedingReasoning: preReason,
		RawToolName:        "kilo-code-cli.assistant_text",
		ToolOutput:         output,
		MessageID:          row.MessageID,
	}, true
}

// loadStepFinishEvents surfaces `step-finish` parts as observability
// ToolEvents. NEVER emit TokenEvents from them (per-step counts sum to
// the message-level token bundle that loadTokenEvents already extracts —
// emitting both double-counts). Skips step-start parts entirely (no
// signal, no tokens, no cost — would 12× the per-turn row count on a
// long turn without adding any analytical value).
func (a *CLIAdapter) loadStepFinishEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]kiloResolvedRoot) ([]models.ToolEvent, error) {
	sessDirs, err := a.loadSessionDirectories(ctx, db)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.message_id, p.session_id, p.time_created, p.time_updated, p.data, m.data
		  FROM part p
		  JOIN message m ON m.id = p.message_id
		 WHERE p.time_updated > ?
		   AND json_valid(p.data) AND json_valid(m.data)
		   AND json_extract(p.data, '$.type') = 'step-finish'
		 ORDER BY p.time_updated ASC, p.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.ToolEvent
	for rows.Next() {
		var row partRow
		if err := rows.Scan(&row.ID, &row.MessageID, &row.SessionID, &row.TimeCreate, &row.TimeUpdate, &row.Data, &row.Message); err != nil {
			return nil, err
		}
		ev, ok := a.stepFinishEvent(sourceFile, row, sessDirs, rootCache)
		if ok {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

func (a *CLIAdapter) stepFinishEvent(sourceFile string, row partRow, sessDirs map[string]kiloSessionDirectory, rootCache map[string]kiloResolvedRoot) (models.ToolEvent, bool) {
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
	project, remote := a.resolveProjectRoot(a.cwdFor(msg, sessDirs[row.SessionID]), rootCache)
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
		Tool:          models.ToolKiloCodeCLI,
		// tooltax/table.go:641 ratifies "kilo-code-cli.step_finish" as
		// ActionHarnessCall (WP-T4; backfilled by migration 077) — this
		// emit site must agree, or every NEW row drifts back to
		// unknown (WP-T6 finding B4).
		ActionType:   models.ActionHarnessCall,
		Target:       firstNonEmpty(part.Reason, "step-finish"),
		Success:      true,
		RawToolName:  "kilo-code-cli.step_finish",
		RawToolInput: row.Data,
		MessageID:    row.MessageID,
	}, true
}

// loadTokenEvents reads Kilo's per-message token usage from assistant
// rows. The token counts live in the JSON data blob, identical to
// OpenCode's invariant; Kilo's `tokens.total` field is supplied but
// the cost engine doesn't use it (we send input/output/reasoning/
// cache.read/cache.write individually). Skips rows where the bundle
// is all-zero (in-progress turns).
func (a *CLIAdapter) loadTokenEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]kiloResolvedRoot) ([]models.TokenEvent, error) {
	sessDirs, err := a.loadSessionDirectories(ctx, db)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT m.id, m.session_id, m.time_created, m.time_updated, m.data
		  FROM message m
		 WHERE m.time_updated > ?
		   AND json_valid(m.data)
		   AND json_extract(m.data, '$.role') = 'assistant'
		 ORDER BY m.time_updated ASC, m.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.TokenEvent
	for rows.Next() {
		var row messageRow
		if err := rows.Scan(&row.ID, &row.SessionID, &row.TimeCreate, &row.TimeUpdate, &row.Data); err != nil {
			return nil, err
		}
		ev, ok := a.tokenEvent(sourceFile, row, sessDirs, rootCache)
		if ok {
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}

func (a *CLIAdapter) tokenEvent(sourceFile string, row messageRow, sessDirs map[string]kiloSessionDirectory, rootCache map[string]kiloResolvedRoot) (models.TokenEvent, bool) {
	var msg messageData
	if err := json.Unmarshal([]byte(row.Data), &msg); err != nil {
		return models.TokenEvent{}, false
	}
	if msg.Tokens.Input == 0 && msg.Tokens.Output == 0 &&
		msg.Tokens.Cache.Read == 0 && msg.Tokens.Cache.Write == 0 &&
		msg.Tokens.Reasoning == 0 {
		return models.TokenEvent{}, false
	}
	project, remote := a.resolveProjectRoot(a.cwdFor(msg, sessDirs[row.SessionID]), rootCache)
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
		Tool:                models.ToolKiloCodeCLI,
		Model:               model,
		InputTokens:         msg.Tokens.Input,
		OutputTokens:        msg.Tokens.Output,
		CacheReadTokens:     msg.Tokens.Cache.Read,
		CacheCreationTokens: msg.Tokens.Cache.Write,
		ReasoningTokens:     msg.Tokens.Reasoning,
		EstimatedCostUSD:    msg.Cost,
		Source:              models.TokenSourceJSONL,
		Reliability:         models.ReliabilityApproximate,
		MessageID:           row.ID,
	}, true
}

// loadSubtaskEvents reads `subtask` parts and emits one
// ActionSpawnSubagent per — same shape as OpenCode. Not observed in
// the live capture (the v1 session didn't spawn a subagent) but the
// part type exists in Kilo's source and we surface it for forward
// compatibility.
func (a *CLIAdapter) loadSubtaskEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]kiloResolvedRoot) ([]models.ToolEvent, error) {
	sessDirs, err := a.loadSessionDirectories(ctx, db)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.message_id, p.session_id, p.time_created, p.time_updated, p.data, m.data
		  FROM part p
		  JOIN message m ON m.id = p.message_id
		 WHERE p.time_updated > ?
		   AND json_valid(p.data) AND json_valid(m.data)
		   AND json_extract(p.data, '$.type') = 'subtask'
		 ORDER BY p.time_updated ASC, p.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ToolEvent
	for rows.Next() {
		var row partRow
		if err := rows.Scan(&row.ID, &row.MessageID, &row.SessionID, &row.TimeCreate, &row.TimeUpdate, &row.Data, &row.Message); err != nil {
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
		project, remote := a.resolveProjectRoot(a.cwdFor(msg, sessDirs[row.SessionID]), rootCache)
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
			Tool:          models.ToolKiloCodeCLI,
			ActionType:    models.ActionSpawnSubagent,
			Target:        target,
			Success:       true,
			RawToolName:   "subtask",
			RawToolInput:  contentcap.Cap(firstNonEmpty(sub.Description, sub.Prompt), contentcap.DefaultMaxBytes),
			MessageID:     row.MessageID,
		})
	}
	return out, rows.Err()
}

// loadTodoEvents reads the `todo` table — each row is one entry in the
// agent's structured task list. Tolerant of older Kilo schemas that
// might lack the table (every capture so far has it but the
// __drizzle_migrations stack is still growing).
func (a *CLIAdapter) loadTodoEvents(ctx context.Context, db *sql.DB, sourceFile string, fromOffset int64, rootCache map[string]kiloResolvedRoot) ([]models.ToolEvent, error) {
	if !tableExists(ctx, db, "todo") {
		return nil, nil
	}
	sessDirs, err := a.loadSessionDirectories(ctx, db)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT t.session_id, t.position, t.content, t.status, t.priority,
		       t.time_created, t.time_updated
		  FROM todo t
		 WHERE t.time_updated > ?
		 ORDER BY t.time_updated ASC, t.position ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ToolEvent
	for rows.Next() {
		var sessionID, content, status, priority string
		var position int
		var tCreated, tUpdated int64
		if err := rows.Scan(&sessionID, &position, &content, &status, &priority, &tCreated, &tUpdated); err != nil {
			return nil, err
		}
		when := millisToTime(tUpdated)
		if when.IsZero() {
			when = millisToTime(tCreated)
		}
		eventID := fmt.Sprintf("todo:%s:%d:%d", sessionID, position, tUpdated)
		todoRoot, todoRemote := a.resolveProjectRoot(sessDirs[sessionID].Fallback(), rootCache)
		out = append(out, models.ToolEvent{
			SourceFile:    sourceFile,
			SourceEventID: eventID,
			SessionID:     sessionID,
			ProjectRoot:   todoRoot,
			GitRemote:     todoRemote,
			Timestamp:     when,
			Tool:          models.ToolKiloCodeCLI,
			ActionType:    models.ActionTodoUpdate,
			Target:        status,
			Success:       true,
			RawToolName:   "todo." + status,
			RawToolInput:  contentcap.Cap(content, contentcap.DefaultMaxBytes),
		})
	}
	return out, rows.Err()
}

// cwdFor implements the per-row cwd priority chain confirmed from the
// live capture:
//
//  1. message.path.cwd (always set on assistant rows when known)
//  2. session.directory (worktree at session start)
//  3. project.worktree (JOIN via session.project_id)
//
// path.root is NOT trusted as a project root — the WSL capture
// surfaced path.root = "/" on a non-repo session, which would
// misattribute every row to the FS root.
func (a *CLIAdapter) cwdFor(msg messageData, dir kiloSessionDirectory) string {
	return firstNonEmpty(msg.Path.Cwd, dir.Directory, dir.ProjectWorktree)
}

// resolveProjectRoot turns a Kilo-recorded cwd (or session/project
// fallback) into a stable project root. Mirrors the OpenCode adapter's
// pattern with a [kilo-code-cli] placeholder for missing cwd:
//
//   - empty cwd → "[kilo-code-cli]" placeholder (so historical rows
//     coalesce under one synthetic project until a real cwd surfaces).
//   - real cwd inside a git working tree → the git root.
//   - real cwd outside any git tree → the cwd itself (post-symlink).
//
// Foreign paths (Windows-style cwd read by a WSL observer) translate
// via crossmount.TranslateForeignPath BEFORE git.Resolve, so e.g.
// "D:\programsx\..." resolves to /mnt/d/programsx/... instead of
// CWD-prefixing the observer's own .git
// (memory feedback_foreign_path_git_resolve).
func (a *CLIAdapter) resolveProjectRoot(cwd string, cache map[string]kiloResolvedRoot) (root, remote string) {
	if cwd == "" {
		return "[kilo-code-cli]", ""
	}
	cwd = crossmount.TranslateForeignPath(cwd)
	if resolved, ok := cache[cwd]; ok {
		return resolved.root, resolved.remote
	}
	id, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		cache[cwd] = kiloResolvedRoot{root: cwd}
		return cwd, ""
	}
	// id.Remote is already NormalizeRemote'd by ResolveIdentity.
	remote = id.Remote
	cache[cwd] = kiloResolvedRoot{root: id.Root, remote: remote, identity: id}
	return id.Root, remote
}

// kiloResolvedRoot is the resolveProjectRoot cache entry: the git
// working-tree root (or the bare cwd when it isn't inside one) plus
// the normalized git remote, cached together per-cwd so repeated
// lookups for the same directory across event types share one
// git.Resolve call.
type kiloResolvedRoot struct {
	root   string
	remote string
	// identity is the Project Identity Resolver v2 bundle (2026-09-06,
	// §3.1 / W1) resolved alongside root/remote, applied to every event
	// whose ProjectRoot matches via adapter.ApplyProjectIdentityByRoot.
	identity git.Identity
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
		return nil, fmt.Errorf("kilocode.stageMirror: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)", sqlitedsn.Escape(actual))
	return sql.Open("sqlite", dsn)
}

// stageMirrorIfForeign mirrors the opencode adapter's pattern verbatim:
// foreign-mount kilo.db reads via /mnt/c on WSL2 (or via
// \\wsl.localhost\... on Windows) need a local mirror because
// modernc.org/sqlite returns SQLITE_IOERR_SHORT_READ when the source
// is actively being written across the mount boundary. Stages the
// trio (.db + -wal + -shm) into a per-source cache dir under
// mirrorbase.Base().
func stageMirrorIfForeign(srcDB string) (string, error) {
	if !isForeignMountPath(srcDB) {
		return srcDB, nil
	}
	base, err := mirrorbase.Base()
	if err != nil || base == "" {
		base = filepath.Join(os.TempDir(), "superbased-observer")
	}
	sum := sha256.Sum256([]byte(srcDB))
	mirrorDir := filepath.Join(base, "kilocode-mirror", hex.EncodeToString(sum[:8]))
	if err := os.MkdirAll(mirrorDir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir mirror: %w", err)
	}
	dstDB := filepath.Join(mirrorDir, "kilo.db")
	if mirrorUpToDate(srcDB, dstDB) {
		return dstDB, nil
	}
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

func mirrorUpToDate(srcDB, dstDB string) bool {
	if !filesMatch(srcDB, dstDB) {
		return false
	}
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

// allHomesFunc is the test seam over crossmount.AllHomes.
var allHomesFunc = crossmount.AllHomes

// isForeignMountPath reports whether path lives under a non-native
// home returned by crossmount. Both directions are covered:
// /mnt/c/Users/<u>/.local/share/kilo/kilo.db on a WSL2 Linux host and
// \\wsl.localhost\<distro>\home\<u>\.local\share\kilo\kilo.db on a
// Windows host.
func isForeignMountPath(path string) bool {
	for _, h := range allHomesFunc() {
		if h.Origin == "native" {
			continue
		}
		sep := string(filepath.Separator)
		if strings.HasPrefix(path, h.Path+sep) || strings.HasPrefix(path, h.Path+"/") {
			return true
		}
	}
	return false
}

func resolveDBPath(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == "kilo.db-wal" || base == "kilo.db-shm" {
		return filepath.Join(filepath.Dir(path), "kilo.db")
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

// defaultCLIRoots returns the canonical Kilo CLI data dir under every
// cross-mount-resolved $HOME. Confirmed from a 2026-06-06 live capture:
// the path is `<home>/.local/share/kilo/` on Linux, macOS, AND Windows
// (Kilo intentionally mirrors XDG everywhere — it does NOT use
// %APPDATA%/%LOCALAPPDATA% on Windows). XDG_DATA_HOME would shift it
// but the capture didn't exercise that path.
func defaultCLIRoots() []string {
	var roots []string
	for _, h := range crossmount.AllHomes() {
		roots = append(roots, filepath.Join(h.Path, ".local", "share", "kilo"))
	}
	return roots
}

// tableExists returns true when the given table is present in the
// SQLite database. Used by loadTodoEvents (and loadSessionDirectories
// for the `project` JOIN) to degrade gracefully on Kilo schemas that
// haven't applied every migration.
func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

func firstOpenRouterReasoning(part toolPartData) string {
	for _, rd := range part.Metadata.OpenRouter.ReasoningDetails {
		if rd.Text != "" {
			return rd.Text
		}
	}
	return ""
}

// mapTool translates Kilo tool names onto our normalized action
// taxonomy. Surface is OpenCode-compatible; the four tools confirmed
// live in the 2026-06-06 capture (read/write/bash/websearch) all land
// on canonical action types. Names beyond the live-confirmed set are
// taken from the upstream OpenCode source + Kilo's bundled tool
// definitions; they're inert until the model emits them.
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
		target = firstNonEmpty(input.Pattern, input.Regex, input.Query, part.State.Title)
	case "glob", "find", "ls", "list":
		actionType = models.ActionSearchFiles
		target = firstNonEmpty(input.Path, input.Pattern, part.State.Title, part.Tool)
	case "webfetch", "fetch", "http":
		actionType = models.ActionWebFetch
		target = firstNonEmpty(input.URL, part.State.Title, part.Tool)
	case "websearch":
		actionType = models.ActionWebSearch
		target = firstNonEmpty(input.Query, part.State.Title, part.Tool)
	case "task", "agent", "subagent":
		actionType = models.ActionSpawnSubagent
		target = firstNonEmpty(part.State.Title, part.Tool)
	case "todoread", "todowrite", "todo":
		actionType = models.ActionTodoUpdate
		target = firstNonEmpty(part.State.Title, part.Tool)
	default:
		if strings.Contains(strings.ToLower(part.Tool), "mcp") {
			actionType = models.ActionMCPCall
		}
	}
	return actionType, target, success, errMsg
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
