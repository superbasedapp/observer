package openclaw

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter parses OpenClaw's local task/session state. OpenClaw stores durable
// CLI/agent work in ~/.openclaw/tasks/runs.sqlite and keeps a session index
// under ~/.openclaw/agents/<agent>/sessions/sessions.json.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with platform defaults.
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
func (*Adapter) Name() string { return models.ToolOpenClaw }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Matches OpenClaw's
// runs.sqlite / sessions.json index, plus any per-session `.jsonl`
// under its tasks/agents roots, plus the OpenClaw 2.0 per-agent store
// `agents/<agentId>/agent/openclaw-agent.sqlite` (and its `-wal`
// sidecar — a trigger only; parsing always opens the main file). The
// under-WatchPaths constraint enforces the v1.4.51 dispatch contract —
// without it the bare `.jsonl` branch would collide alphabetically with
// claude-code, codex, etc.
func (a *Adapter) IsSessionFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	shapeOK := base == "runs.sqlite" || base == "runs.sqlite-wal" ||
		base == "sessions.json" || filepath.Ext(base) == ".jsonl" ||
		isAgentDBPath(path)
	if !shapeOK {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// ParseSessionFile implements adapter.Adapter.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case base == "runs.sqlite" || base == "runs.sqlite-wal":
		return a.parseTaskRuns(ctx, resolveRunsDB(path), fromOffset)
	case isAgentDBPath(path):
		// OpenClaw 2.0 moved live sessions + transcripts into a
		// per-agent SQLite store; the legacy `sessions/` tree becomes an
		// archive that `openclaw doctor --fix` imports. See agentdb.go.
		return a.parseAgentDB(ctx, path, fromOffset)
	case base == "sessions.json":
		return a.parseSessionsIndex(path, fromOffset)
	case strings.HasSuffix(base, ".trajectory.jsonl"):
		// The per-session `<id>.trajectory.jsonl` trace carries an
		// accurate per-call usage record (model.completed →
		// data.promptCache.lastCallUsage) for the LAST model call of a
		// run. The sibling plain `<id>.jsonl` message log carries the
		// same provider-reported numbers for EVERY call — except where a
		// gateway backend injected the turn (model="gateway-injected",
		// usage all 0 → the zero-guard in parseMessageLine skips it),
		// where the trajectory is the only real token source. The two
		// overlap by construction, so parseTrajectoryJSONL suppresses a
		// call the message log already covers. See doc.go §Tokens.
		return a.parseTrajectoryJSONL(ctx, path, fromOffset)
	default:
		return a.parseSessionJSONL(ctx, path, fromOffset)
	}
}

type taskRun struct {
	TaskID          string
	Runtime         string
	SourceID        string
	RequesterKey    string
	OwnerKey        string
	ChildSessionKey string
	AgentID         string
	RunID           string
	Label           string
	Task            string
	Status          string
	CreatedAt       int64
	StartedAt       sql.NullInt64
	EndedAt         sql.NullInt64
	LastEventAt     sql.NullInt64
	Error           sql.NullString
	ProgressSummary sql.NullString
	TerminalSummary sql.NullString
	TerminalOutcome sql.NullString
}

func (a *Adapter) parseTaskRuns(ctx context.Context, dbPath string, fromOffset int64) (adapter.ParseResult, error) {
	latest, err := latestTaskWatermark(ctx, dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("openclaw.ParseSessionFile: latest task watermark: %w", err)
	}
	res := adapter.ParseResult{NewOffset: latest}
	db, err := openReadOnlyDB(dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("openclaw.ParseSessionFile: open task DB: %w", err)
	}
	defer db.Close()

	// Lineage upserts can be a no-op when the task row arrives before the child
	// session row. Re-emit every durable task link on every parse so a later
	// child-session ingest converges even when the task watermark did not move.
	res.SessionLineages, err = loadTaskRunLineages(ctx, db)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("openclaw.ParseSessionFile: task lineages: %w", err)
	}
	if latest <= fromOffset {
		return res, nil
	}

	sessionAliases := loadSessionAliases(filepath.Join(filepath.Dir(filepath.Dir(dbPath)), "agents"))

	rows, err := db.QueryContext(ctx, `
		SELECT task_id, runtime, COALESCE(source_id, ''), COALESCE(requester_session_key, ''),
		       owner_key, COALESCE(child_session_key, ''), COALESCE(agent_id, ''),
		       COALESCE(run_id, ''), COALESCE(label, ''), task, status, created_at,
		       started_at, ended_at, last_event_at, error, progress_summary,
		       terminal_summary, terminal_outcome
		  FROM task_runs
		 WHERE COALESCE(last_event_at, ended_at, started_at, created_at) > ?
		 ORDER BY COALESCE(last_event_at, ended_at, started_at, created_at) ASC, task_id ASC`, fromOffset)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("openclaw.ParseSessionFile: query task_runs: %w", err)
	}
	defer rows.Close()

	rootCache := map[string]projectGitInfo{}
	for rows.Next() {
		var tr taskRun
		if err := rows.Scan(
			&tr.TaskID, &tr.Runtime, &tr.SourceID, &tr.RequesterKey, &tr.OwnerKey,
			&tr.ChildSessionKey, &tr.AgentID, &tr.RunID, &tr.Label, &tr.Task, &tr.Status,
			&tr.CreatedAt, &tr.StartedAt, &tr.EndedAt, &tr.LastEventAt, &tr.Error,
			&tr.ProgressSummary, &tr.TerminalSummary, &tr.TerminalOutcome,
		); err != nil {
			adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
			return res, err
		}
		if suppressTaskRun(tr, sessionAliases) {
			continue
		}
		alias, _ := findTaskAlias(tr, sessionAliases)
		res.ToolEvents = append(res.ToolEvents, a.taskPromptEvent(dbPath, tr, alias, rootCache))
		if isTerminalStatus(tr.Status) {
			res.ToolEvents = append(res.ToolEvents, a.taskCompleteEvent(dbPath, tr, alias, rootCache))
		}
	}
	adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
	return res, rows.Err()
}

func loadTaskRunLineages(ctx context.Context, db *sql.DB) ([]models.SessionLineage, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT COALESCE(requester_session_key, ''), owner_key,
		       COALESCE(child_session_key, '')
		  FROM task_runs
		 WHERE COALESCE(child_session_key, '') <> ''
		 ORDER BY task_id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.SessionLineage
	seen := map[models.SessionLineage]bool{}
	for rows.Next() {
		var tr taskRun
		if err := rows.Scan(&tr.RequesterKey, &tr.OwnerKey, &tr.ChildSessionKey); err != nil {
			return nil, err
		}
		lin, ok := taskRunLineage(tr)
		if !ok || seen[lin] {
			continue
		}
		seen[lin] = true
		out = append(out, lin)
	}
	return out, rows.Err()
}

// taskRunLineage projects a spawned child session's parent linkage into
// the generic migration-069 lineage columns (forked_from_id /
// parent_thread_id / thread_source) so openclaw sub-agents light up the
// same LineageBanner / children[] read model codex and opencode already
// feed — closing the capture gap the 2026-08-22 cross-adapter audit
// flagged (task_runs carries requester_session_key / owner_key /
// child_session_key but they were only ever used for identity and
// duplicate suppression). Parent preference: the requesting session (the
// conversation that asked for the task), falling back to the owner key.
// Self-runs (child == parent, e.g. agent main-tasking itself with no
// distinct child key) emit nothing.
func taskRunLineage(tr taskRun) (models.SessionLineage, bool) {
	if tr.ChildSessionKey == "" {
		return models.SessionLineage{}, false
	}
	parent := firstNonEmpty(tr.RequesterKey, tr.OwnerKey)
	if parent == "" || parent == tr.ChildSessionKey {
		return models.SessionLineage{}, false
	}
	return models.SessionLineage{
		SessionID:      tr.ChildSessionKey,
		ParentThreadID: parent,
		ThreadSource:   "subagent",
	}, true
}

// findTaskAlias mirrors suppressTaskRun's key-priority chain but
// returns the matched alias so callers can lift Model / Provider /
// WorkspaceDir off it. Returns (zero, false) when no key matches —
// callers should fall back to "[openclaw]" / empty model.
func findTaskAlias(tr taskRun, aliases map[string]sessionIndexEntry) (sessionIndexEntry, bool) {
	for _, key := range []string{tr.ChildSessionKey, tr.OwnerKey, tr.RequesterKey, tr.RunID, tr.SourceID} {
		if entry, ok := aliases[key]; ok {
			return entry, true
		}
	}
	return sessionIndexEntry{}, false
}

// aliasModel projects a sessionIndexEntry's provider+model into the
// `provider/model` composite that modelName() emits for jsonl rows.
// Empty when the alias has no model fields. Used by sqlite + sessions.json
// paths to stop emitting `Model: ""` on every task_runs / sessions row.
func aliasModel(alias sessionIndexEntry) string {
	provider := firstNonEmpty(alias.ModelProvider, alias.SystemPromptReport.Provider)
	model := firstNonEmpty(alias.Model, alias.SystemPromptReport.Model)
	if provider != "" && model != "" {
		return provider + "/" + model
	}
	return model
}

func (a *Adapter) taskPromptEvent(sourceFile string, tr taskRun, alias sessionIndexEntry, rootCache map[string]projectGitInfo) models.ToolEvent {
	prompt := stripTaskTimestamp(tr.Task)
	root, remote := a.resolveProjectRoot(alias.SystemPromptReport.WorkspaceDir, rootCache)
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      "task:" + tr.TaskID + ":prompt",
		SessionID:          sessionID(tr),
		ProjectRoot:        root,
		GitRemote:          remote,
		Timestamp:          millisToTime(tr.CreatedAt),
		Model:              aliasModel(alias),
		Tool:               models.ToolOpenClaw,
		ActionType:         models.ActionUserPrompt,
		Target:             truncate(prompt, 200),
		Success:            true,
		PrecedingReasoning: truncate(prompt, 200),
		RawToolName:        "task_runs.task",
		RawToolInput:       a.scrubber.String(prompt),
		MessageID:          "user:task:" + tr.TaskID,
	}
}

func (a *Adapter) taskCompleteEvent(sourceFile string, tr taskRun, alias sessionIndexEntry, rootCache map[string]projectGitInfo) models.ToolEvent {
	success := strings.EqualFold(tr.Status, "succeeded")
	errMsg := ""
	if !success {
		errMsg = firstNonEmpty(nullString(tr.Error), nullString(tr.TerminalOutcome), nullString(tr.TerminalSummary))
	}
	summary := firstNonEmpty(nullString(tr.ProgressSummary), nullString(tr.TerminalSummary), nullString(tr.TerminalOutcome))
	root, remote := a.resolveProjectRoot(alias.SystemPromptReport.WorkspaceDir, rootCache)
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      "task:" + tr.TaskID + ":complete",
		SessionID:          sessionID(tr),
		ProjectRoot:        root,
		GitRemote:          remote,
		Timestamp:          taskEndTime(tr),
		Model:              aliasModel(alias),
		Tool:               models.ToolOpenClaw,
		ActionType:         models.ActionTaskComplete,
		Target:             tr.Status,
		Success:            success,
		ErrorMessage:       truncate(errMsg, 500),
		DurationMs:         durationMs(tr),
		PrecedingReasoning: truncate(summary, 200),
		RawToolName:        "task_runs.status",
		RawToolInput:       a.scrubber.String(firstNonEmpty(tr.Status, errMsg)),
		ToolOutput:         a.scrubber.String(summary),
		MessageID:          "assistant:task:" + tr.TaskID,
	}
}

type sessionsIndex map[string]sessionIndexEntry

type sessionIndexEntry struct {
	SessionID          string `json:"sessionId"`
	UpdatedAt          int64  `json:"updatedAt"`
	Status             string `json:"status"`
	StartedAt          int64  `json:"startedAt"`
	EndedAt            int64  `json:"endedAt"`
	RuntimeMs          int64  `json:"runtimeMs"`
	ModelProvider      string `json:"modelProvider"`
	Model              string `json:"model"`
	SessionFile        string `json:"sessionFile"`
	SystemPromptReport struct {
		WorkspaceDir string `json:"workspaceDir"`
		SessionKey   string `json:"sessionKey"`
		Provider     string `json:"provider"`
		Model        string `json:"model"`
	} `json:"systemPromptReport"`
}

func (a *Adapter) parseSessionsIndex(path string, fromOffset int64) (adapter.ParseResult, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("openclaw.ParseSessionFile: read sessions index: %w", err)
	}
	var idx sessionsIndex
	if err := json.Unmarshal(body, &idx); err != nil {
		return adapter.ParseResult{}, fmt.Errorf("openclaw.ParseSessionFile: parse sessions index: %w", err)
	}
	var latest int64
	res := adapter.ParseResult{}
	rootCache := map[string]projectGitInfo{}
	for key, sess := range idx {
		if sess.UpdatedAt > latest {
			latest = sess.UpdatedAt
		}
		if sess.UpdatedAt <= fromOffset || !isTerminalStatus(sess.Status) || strings.TrimSpace(sess.SessionFile) != "" {
			continue
		}
		root, remote := a.resolveProjectRoot(sess.SystemPromptReport.WorkspaceDir, rootCache)
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile:    path,
			SourceEventID: "session:" + key + ":complete",
			SessionID:     canonicalSessionID(sess, key),
			ProjectRoot:   root,
			GitRemote:     remote,
			Timestamp:     millisToTime(firstNonZero(sess.EndedAt, sess.UpdatedAt)),
			Model:         modelName(&sessionContext{Provider: firstNonEmpty(sess.ModelProvider, sess.SystemPromptReport.Provider), Model: firstNonEmpty(sess.Model, sess.SystemPromptReport.Model)}),
			Tool:          models.ToolOpenClaw,
			ActionType:    models.ActionTaskComplete,
			Target:        sess.Status,
			Success:       strings.EqualFold(sess.Status, "succeeded"),
			DurationMs:    sess.RuntimeMs,
			RawToolName:   "sessions.status",
			MessageID:     "assistant:session:" + key,
		})
	}
	res.NewOffset = latest
	adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
	return res, nil
}

type jsonlLine struct {
	Type       string          `json:"type"`
	ID         string          `json:"id"`
	Timestamp  string          `json:"timestamp"`
	Cwd        string          `json:"cwd"`
	Provider   string          `json:"provider"`
	ModelID    string          `json:"modelId"`
	Message    openclawMessage `json:"message"`
	CustomType string          `json:"customType"`
	Data       json.RawMessage `json:"data"`
}

type openclawMessage struct {
	Role         string             `json:"role"`
	Content      messageContentList `json:"content"`
	StopReason   string             `json:"stopReason"`
	API          string             `json:"api"`
	Provider     string             `json:"provider"`
	Model        string             `json:"model"`
	Usage        tokenUsage         `json:"usage"`
	Timestamp    int64              `json:"timestamp"`
	ToolCallID   string             `json:"toolCallId"`
	ToolName     string             `json:"toolName"`
	IsError      bool               `json:"isError"`
	ErrorMessage string             `json:"errorMessage"`
}

type messageContent struct {
	Type      string         `json:"type"`
	Text      string         `json:"text"`
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// messageContentList is an OpenClaw message body, which is EITHER a plain
// string (the shape user turns use) OR an array of typed content blocks
// (assistant turns, tool calls, tool results). Grounded against a live
// openclaw@2026.8.2 per-agent store (testdata/openclaw/agentdb) where
// user messages carry string content while assistant messages carry
// []{type,text}; the pre-2.0 `<id>.jsonl` message log shares the type and
// the same duality. A bare string decodes to a single text block so every
// consumer (messageText, the tool-call scan) sees one uniform shape and no
// user turn is reported as a malformed event.
type messageContentList []messageContent

func (m *messageContentList) UnmarshalJSON(b []byte) error {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		*m = nil
		return nil
	}
	switch trimmed[0] {
	case '"':
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		*m = messageContentList{{Type: "text", Text: s}}
		return nil
	case '[':
		var arr []messageContent
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return err
		}
		*m = messageContentList(arr)
		return nil
	default:
		return fmt.Errorf("openclaw: message content is neither a string nor an array")
	}
}

type tokenUsage struct {
	Input       int64 `json:"input"`
	Output      int64 `json:"output"`
	CacheRead   int64 `json:"cacheRead"`
	CacheWrite  int64 `json:"cacheWrite"`
	TotalTokens int64 `json:"totalTokens"`
}

type sessionContext struct {
	SessionID     string
	ProjectRoot   string
	ProjectRemote string
	Provider      string
	Model         string
}

func (a *Adapter) parseSessionJSONL(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return adapter.ParseResult{}, err
	}
	defer f.Close()

	if fromOffset > 0 {
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return adapter.ParseResult{}, fmt.Errorf("openclaw.ParseSessionFile: seek: %w", err)
		}
	}

	res := adapter.ParseResult{NewOffset: fromOffset}
	state := sessionContext{
		SessionID:   strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
		ProjectRoot: "[openclaw]",
	}
	applySessionAlias(path, &state, state.SessionID)
	rootCache := map[string]projectGitInfo{}
	// Resolve any aliased ProjectRoot the alias lookup just installed so
	// downstream events get the same git-root treatment as freshly-set cwds.
	if state.ProjectRoot != "" && state.ProjectRoot != "[openclaw]" {
		state.ProjectRoot, state.ProjectRemote = a.resolveProjectRoot(state.ProjectRoot, rootCache)
	}
	pending := map[string]int{}
	// Lazily-read harness prompt preamble for this run (WP-T6 O2). Only a
	// user message that already carries the "[Bootstrap pending]" marker
	// pays for the sibling-trace read, and only once per parse call.
	tracePrefix := ""
	tracePrefixLoaded := false
	bootstrapPrefix := func() string {
		if !tracePrefixLoaded {
			tracePrefixLoaded = true
			tracePrefix = bootstrapPrefixFromTrace(path)
		}
		return tracePrefix
	}
	// seenSystemPrompts dedups ActionSystemPrompt rows by content hash.
	// OpenClaw bootstrap-context:full events can be re-emitted on
	// resume; same content → one row.
	seenSystemPrompts := map[string]bool{}
	// cacheAcc accumulates content-block deltas across the message log —
	// see cachetrack.go for why only this file (not the trajectory) is
	// wired.
	cacheAcc := cacheobs.New(MaxBlocksPerSession)

	sc := &transcriptScope{
		sourceFile:        path,
		state:             state,
		pending:           pending,
		rootCache:         rootCache,
		seenSystemPrompts: seenSystemPrompts,
		cacheAcc:          cacheAcc,
		bootstrapPrefix:   bootstrapPrefix,
	}

	scanner := bufio.NewScanner(f)
	const maxLine = 16 * 1024 * 1024
	scanner.Buffer(make([]byte, 64*1024), maxLine)

	var bytesRead int64 = fromOffset
	lineNum := 0
	for scanner.Scan() {
		if ctx.Err() != nil {
			adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
			return res, ctx.Err()
		}
		raw := scanner.Bytes()
		bytesRead += int64(len(raw) + 1)
		lineNum++
		if len(raw) == 0 {
			continue
		}

		var line jsonlLine
		if err := json.Unmarshal(raw, &line); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
			res.NewOffset = bytesRead
			continue
		}
		res.NewOffset = bytesRead
		a.handleTranscriptEntry(sc, line, lineNum, parseTimestamp(line.Timestamp), &res)
	}
	if err := scanner.Err(); err != nil {
		adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
		return res, fmt.Errorf("openclaw.ParseSessionFile: scan: %w", err)
	}
	adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
	return res, nil
}

// transcriptScope is the per-session mutable state one transcript entry
// stream is parsed against.
//
// It exists so the pre-2.0 `<id>.jsonl` message log and the 2.0
// per-agent SQLite store (agentdb.go, `transcript_events.event_json`)
// run through ONE entry handler. The two layouts carry the SAME entry
// shape — 2.0 moved the bytes, not the schema — so duplicating the
// switch would let the layouts silently drift in what they extract.
type transcriptScope struct {
	// sourceFile is the path stamped on every emitted event, and the
	// path the sibling sessions.json alias / trajectory preamble are
	// resolved relative to. For the SQLite layout it is deliberately
	// NOT the DB path but the canonical legacy message-log path — see
	// legacySourceFile in agentdb.go.
	sourceFile string
	state      sessionContext
	// pending maps a tool-call id to its index in res.ToolEvents so a
	// later toolResult can back-fill the output. Per session.
	pending           map[string]int
	rootCache         map[string]projectGitInfo
	seenSystemPrompts map[string]bool
	cacheAcc          *cacheobs.Accumulator
	bootstrapPrefix   func() string
}

// handleTranscriptEntry folds ONE decoded transcript entry into the
// scope and appends whatever it produces to res. lineNum is the entry's
// ordinal within its stream — the 1-based file line for the JSONL
// layout, `transcript_events.seq` for the SQLite one — and is only ever
// used to synthesize a SourceEventID for an entry that carries no id of
// its own.
func (a *Adapter) handleTranscriptEntry(sc *transcriptScope, line jsonlLine, lineNum int, ts time.Time, res *adapter.ParseResult) {
	switch line.Type {
	case "session":
		if line.ID != "" {
			sc.state.SessionID = line.ID
			applySessionAlias(sc.sourceFile, &sc.state, line.ID)
			if sc.state.ProjectRoot != "" && sc.state.ProjectRoot != "[openclaw]" {
				sc.state.ProjectRoot, sc.state.ProjectRemote = a.resolveProjectRoot(sc.state.ProjectRoot, sc.rootCache)
			}
		}
		if line.Cwd != "" {
			sc.state.ProjectRoot, sc.state.ProjectRemote = a.resolveProjectRoot(line.Cwd, sc.rootCache)
		}
	case "model_change":
		sc.state.Provider = line.Provider
		sc.state.Model = line.ModelID
	case "message":
		a.parseMessageLine(sc.sourceFile, line, lineNum, ts, &sc.state, sc.pending, sc.bootstrapPrefix, sc.cacheAcc, res)
	case "custom":
		// OpenClaw emits typed `custom` events for runtime
		// notifications. customType="model-snapshot" is redundant
		// with the model_change handler above, so it's a no-op.
		// customType="openclaw:bootstrap-context:full" marks a
		// bootstrap-context load — pre-v1.4.23 silently dropped.
		// Per user direction (2026-05-01): capture event/action
		// info even when no rich body is in the payload. Emit a
		// minimal ActionSystemPrompt row carrying the data field
		// JSON so analysts can detect bootstrap activity.
		a.bootstrapContextEvent(sc, line, lineNum, ts, res)
	}
}

// bootstrapContextEvent emits the deduped ActionSystemPrompt row for an
// `openclaw:bootstrap-context:full` custom entry. Split out of
// handleTranscriptEntry purely to keep that switch flat.
func (a *Adapter) bootstrapContextEvent(sc *transcriptScope, line jsonlLine, lineNum int, ts time.Time, res *adapter.ParseResult) {
	if line.CustomType != "openclaw:bootstrap-context:full" || len(line.Data) == 0 {
		return
	}
	body := strings.TrimSpace(string(line.Data))
	if body == "" || body == "null" {
		return
	}
	hash := openclawShortHash("bootstrap:" + body)
	if sc.seenSystemPrompts[hash] {
		return
	}
	sc.seenSystemPrompts[hash] = true
	preview := "bootstrap-context: " + truncate(body, 180)
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    sc.sourceFile,
		SourceEventID: fmt.Sprintf("sysprompt:bootstrap:%s:L%d", hash, lineNum),
		SessionID:     sc.state.SessionID,
		ProjectRoot:   sc.state.ProjectRoot,
		GitRemote:     sc.state.ProjectRemote,
		Timestamp:     ts,
		Model:         modelName(&sc.state),
		Tool:          models.ToolOpenClaw,
		ActionType:    models.ActionSystemPrompt,
		Target:        truncate(preview, 200),
		Success:       true,
		RawToolName:   "system_prompt.bootstrap",
		RawToolInput:  a.scrubber.String(body),
		MessageID:     "system:" + hash,
	})
}

// trajLine is the subset of an OpenClaw trajectory event we read. Only
// `model.completed` events carry token usage; the per-call breakdown lives
// in data.promptCache.lastCallUsage and is already NET (verified
// 2026-06-26: input + output + cacheRead == total — cacheRead is broken
// out, NOT folded into input), so it maps straight through with no
// gross-vs-cached netting. data.usage is a running session total and is
// deliberately ignored.
//
// SessionKey / WorkspaceDir are stamped on EVERY trajectory event by
// OpenClaw itself (live traces 2026-07-31 carry
// sessionKey="agent:main:explicit:wpt6probe" and
// sessionKey="agent:main:main"). SessionKey is exactly the sessions.json
// map key that applySessionAlias resolves for the message-log path, so it
// is the grounded way to land both halves of one run on ONE observer
// session id (WP-T6 finding O1).
//
// data.messagesSnapshot is the full message array as of completion; its
// LAST usage-bearing assistant entry is the call lastCallUsage describes,
// and its `timestamp` is the same epoch-ms value the message log records
// as message.timestamp. That equality is the dedup join key — see
// trajectoryCallTimestamp.
type trajLine struct {
	Type         string `json:"type"`
	Timestamp    string `json:"ts"`
	SessionID    string `json:"sessionId"`
	SessionKey   string `json:"sessionKey"`
	RunID        string `json:"runId"`
	Provider     string `json:"provider"`
	ModelID      string `json:"modelId"`
	WorkspaceDir string `json:"workspaceDir"`
	Data         struct {
		PromptCache struct {
			LastCallUsage    tokenUsage `json:"lastCallUsage"`
			LastCacheTouchAt int64      `json:"lastCacheTouchAt"`
		} `json:"promptCache"`
		MessagesSnapshot []trajSnapshotMessage `json:"messagesSnapshot"`
	} `json:"data"`
}

// trajSnapshotMessage is the subset of a data.messagesSnapshot entry the
// dedup join needs: which role it is, when it landed, and whether it
// carries usage.
type trajSnapshotMessage struct {
	Role      string     `json:"role"`
	Timestamp int64      `json:"timestamp"`
	Usage     tokenUsage `json:"usage"`
}

// parseTrajectoryJSONL extracts accurate per-call token usage from a
// `<id>.trajectory.jsonl` trace. Each `model.completed` event becomes one
// TokenEvent from its lastCallUsage. The SourceEventID is anchored on the
// line's start byte offset (globally stable across incremental re-parses,
// unlike a line counter), since seq is reused across turns.
func (a *Adapter) parseTrajectoryJSONL(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return adapter.ParseResult{}, err
	}
	defer f.Close()

	if fromOffset > 0 {
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return adapter.ParseResult{}, fmt.Errorf("openclaw.parseTrajectoryJSONL: seek: %w", err)
		}
	}

	res := adapter.ParseResult{NewOffset: fromOffset}
	fallbackSession := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(path), ".jsonl"), ".trajectory")
	state := sessionContext{SessionID: fallbackSession, ProjectRoot: "[openclaw]"}
	applySessionAlias(path, &state, fallbackSession)
	rootCache := map[string]projectGitInfo{}
	if state.ProjectRoot != "" && state.ProjectRoot != "[openclaw]" {
		state.ProjectRoot, state.ProjectRemote = a.resolveProjectRoot(state.ProjectRoot, rootCache)
	}
	aliasCache := map[string]string{}
	// Lazily-loaded set of message-log calls that already have a
	// TokenEvent (see messageLogUsageCalls). Loaded at most once,
	// and only if a usage-bearing model.completed actually shows up.
	var covered messageLogCoverage
	coveredLoaded := false
	coveredCalls := func() messageLogCoverage {
		if !coveredLoaded {
			coveredLoaded = true
			covered = messageLogUsageCalls(filepath.Join(filepath.Dir(path), fallbackSession+".jsonl"))
		}
		return covered
	}

	scanner := bufio.NewScanner(f)
	const maxLine = 16 * 1024 * 1024
	scanner.Buffer(make([]byte, 64*1024), maxLine)

	bytesRead := fromOffset
	lineNum := 0
	for scanner.Scan() {
		if ctx.Err() != nil {
			adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
			return res, ctx.Err()
		}
		lineStart := bytesRead
		raw := scanner.Bytes()
		bytesRead += int64(len(raw) + 1)
		res.NewOffset = bytesRead
		lineNum++
		if len(raw) == 0 {
			continue
		}
		var line trajLine
		if err := json.Unmarshal(raw, &line); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
			continue
		}
		if line.Type != "model.completed" {
			continue
		}
		u := line.Data.PromptCache.LastCallUsage
		if !hasUsage(u) {
			continue
		}
		// WP-T6 O1 — one turn, one row. The message log records this very
		// call's provider usage under its own (source_file,
		// source_event_id) key, which UNIQUE() can never collapse against
		// ours. Suppress here rather than there: the message log covers
		// EVERY call of the run while a model.completed carries only the
		// last one (1 event vs 5 rows on the 2026-07-31 live probe), so
		// deferring the other way would drop 4 of 5 turns. The check reads
		// the sibling file from DISK, so it does not depend on which of
		// the two files the watcher happens to parse first.
		callTS := trajectoryCallTimestamp(line)
		if callTS > 0 && coveredCalls().covers(callTS, u) {
			continue
		}
		sessionID := trajectorySessionID(path, line, state, fallbackSession, aliasCache)
		projectRoot := state.ProjectRoot
		projectRemote := state.ProjectRemote
		if projectRoot == "" || projectRoot == "[openclaw]" {
			if wd := strings.TrimSpace(line.WorkspaceDir); wd != "" {
				projectRoot, projectRemote = a.resolveProjectRoot(wd, rootCache)
			}
		}
		res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
			SourceFile: path,
			// Keyed on the FILE stem, not the resolved session id: the
			// stem is what `<sessionId>.trajectory.jsonl` is named after
			// and never changes, so a rescan after the O1 alias fix
			// MAX-upgrades the pre-fix row in place instead of inserting
			// a second one under the new id.
			SourceEventID:       fmt.Sprintf("traj:%s:%d", fallbackSession, lineStart),
			SessionID:           sessionID,
			ProjectRoot:         projectRoot,
			GitRemote:           projectRemote,
			Timestamp:           parseTimestamp(line.Timestamp),
			Tool:                models.ToolOpenClaw,
			Model:               line.ModelID,
			InputTokens:         u.Input,
			OutputTokens:        u.Output,
			CacheReadTokens:     u.CacheRead,
			CacheCreationTokens: u.CacheWrite,
			Source:              models.TokenSourceJSONL,
			Reliability:         models.ReliabilityAccurate,
			MessageID:           firstNonEmpty(line.RunID, sessionID),
		})
	}
	if err := scanner.Err(); err != nil {
		adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
		return res, fmt.Errorf("openclaw.parseTrajectoryJSONL: scan: %w", err)
	}
	adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
	return res, nil
}

// hasUsage is the ONE predicate deciding whether a usage record is worth a
// TokenEvent. Both emit paths (message log + trajectory) and the dedup
// coverage scan share it, so "the message log covers this call" can never
// mean something different from "the message log emitted a row for it" —
// notably gateway-injected turns (model="gateway-injected", every field 0)
// are uncovered on both sides, leaving the trajectory as their sole source.
func hasUsage(u tokenUsage) bool {
	return u.Input != 0 || u.Output != 0 || u.CacheRead != 0 || u.CacheWrite != 0
}

// trajectoryCallTimestamp returns the epoch-ms timestamp of the single model
// call that a `model.completed` event's promptCache.lastCallUsage describes.
//
// Grounded on the live 2026-07-31 traces: data.messagesSnapshot's last
// usage-bearing assistant entry carries EXACTLY lastCallUsage's numbers and
// a `timestamp` identical to the message log's message.timestamp for the same
// message (1785498625318 on wpt6probe; 1782552263070 on the older
// agent:main:main trace). data.promptCache.lastCacheTouchAt held the same
// value on both traces and is the fallback for events that ship no snapshot.
// Returns 0 when neither is available — callers then emit unconditionally
// (better a duplicate than a silently dropped turn).
func trajectoryCallTimestamp(line trajLine) int64 {
	snap := line.Data.MessagesSnapshot
	for i := len(snap) - 1; i >= 0; i-- {
		if snap[i].Role == "assistant" && hasUsage(snap[i].Usage) && snap[i].Timestamp > 0 {
			return snap[i].Timestamp
		}
	}
	return line.Data.PromptCache.LastCacheTouchAt
}

// messageLogCall is the exact-usage join key used ONLY to disambiguate
// two message-log calls that share one epoch-ms timestamp.
//
// The model id is deliberately NOT part of it: the two files spell it
// differently in places (OpenRouter `:suffix` tails).
type messageLogCall struct {
	TS         int64
	Input      int64
	Output     int64
	CacheRead  int64
	CacheWrite int64
}

// callKeyFor builds the exact-usage key for one usage record at ts.
func callKeyFor(ts int64, u tokenUsage) messageLogCall {
	return messageLogCall{
		TS:         ts,
		Input:      u.Input,
		Output:     u.Output,
		CacheRead:  u.CacheRead,
		CacheWrite: u.CacheWrite,
	}
}

// messageLogCoverage answers "does the message log already emit a
// TokenEvent for this call?".
//
// The TIMESTAMP is the key. The usage counts are a TIEBREAK, consulted
// only when the same epoch-ms carries more than one message-log call
// (parallel sub-agent runs, a retried call) and the join is therefore
// genuinely ambiguous. Making usage part of the primary key instead
// would trade a rare false-suppression for a SYSTEMATIC duplicate token
// row the day the two files disagree on one count — and a duplicate is
// the failure this suppression exists to prevent.
type messageLogCoverage struct {
	countByTS map[int64]int
	exact     map[messageLogCall]bool
}

// covers reports whether the message log already emitted a row for the
// call at ts with usage u. An unambiguous ts (exactly one message-log
// call) suppresses on the timestamp alone.
func (c messageLogCoverage) covers(ts int64, u tokenUsage) bool {
	switch c.countByTS[ts] {
	case 0:
		return false
	case 1:
		return true
	default:
		return c.exact[callKeyFor(ts, u)]
	}
}

// messageLogUsageCalls scans a sibling `<id>.jsonl` message log and
// returns the coverage of every assistant message that carries usage —
// i.e. exactly the set of calls parseSessionJSONL emits a TokenEvent
// for. A missing/unreadable/rotated log yields the zero value, which
// suppresses nothing.
func messageLogUsageCalls(msgLogPath string) messageLogCoverage {
	f, err := os.Open(msgLogPath)
	if err != nil {
		return messageLogCoverage{}
	}
	defer f.Close()

	covered := messageLogCoverage{
		countByTS: map[int64]int{},
		exact:     map[messageLogCall]bool{},
	}
	scanner := bufio.NewScanner(f)
	const maxLine = 16 * 1024 * 1024
	scanner.Buffer(make([]byte, 64*1024), maxLine)
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var line jsonlLine
		if err := json.Unmarshal(raw, &line); err != nil {
			continue
		}
		if line.Type != "message" || line.Message.Role != "assistant" {
			continue
		}
		if line.Message.Timestamp > 0 && hasUsage(line.Message.Usage) {
			covered.countByTS[line.Message.Timestamp]++
			covered.exact[callKeyFor(line.Message.Timestamp, line.Message.Usage)] = true
		}
	}
	return covered
}

// trajectorySessionID resolves a trajectory event onto the SAME canonical
// session id the message-log path produces, closing WP-T6 finding O1 (one
// OpenClaw run landing as two observer sessions).
//
// Priority:
//  1. the event's own `sessionKey` — OpenClaw stamps the sessions.json map
//     key onto every trajectory event, which is precisely what
//     lookupSessionAlias returns for the message log.
//  2. a per-event `sessionId` that differs from the file stem, canonicalized
//     through applySessionAlias — the SAME sessions.json owner, not a copy
//     of the aliasing logic. Memoized per parse call.
//  3. the file-level state, already aliased when the file was opened.
func trajectorySessionID(path string, line trajLine, state sessionContext, fileStem string, cache map[string]string) string {
	if key := strings.TrimSpace(line.SessionKey); key != "" {
		return key
	}
	raw := strings.TrimSpace(line.SessionID)
	if raw == "" || raw == fileStem {
		return state.SessionID
	}
	if v, ok := cache[raw]; ok {
		return v
	}
	alias := sessionContext{SessionID: raw}
	applySessionAlias(path, &alias, raw)
	cache[raw] = alias.SessionID
	return alias.SessionID
}

// openclawBootstrapPrefixMarker is the first line of every harness bootstrap
// preamble OpenClaw prepends to a user prompt.
const openclawBootstrapPrefixMarker = "[Bootstrap pending]\n"

// splitBootstrapPrompt separates OpenClaw's harness bootstrap preamble from
// the operator's own words (WP-T6 finding O2). GROUNDED verbatim in
// OpenClaw's own producer code, not a byte offset:
//
//	// dist/selection-*.js — embedded-runner prompt assembly
//	if (userPromptPrefixText) effectivePrompt = `${userPromptPrefixText}\n\n${effectivePrompt}`;
//
//	// dist/system-prompt-*.js — buildAgentUserPromptPrefix
//	return ["[Bootstrap pending]", ...buildFullBootstrapPromptLines({...})].join("\n");
//	return ["[Bootstrap pending]", ...buildLimitedBootstrapPromptLines({...})].join("\n");
//
// The marker alone is only a PRE-FILTER. A human prompt that happens to open
// with "[Bootstrap pending]" and contain a blank line would otherwise lose
// its first paragraph to the marker+first-"\n\n" heuristic, so the boundary
// is CORROBORATED against the run's own prefix string whenever tracePrefix
// yields one: OpenClaw echoes the exact text it prepended into the sibling
// trajectory as trace.metadata data.prompting.userPromptPrefixText (present
// on both live 2026-07-31 traces). With that in hand the split point is not a
// guess at all — the text must literally start with `prefix + "\n\n"`, and a
// human prompt that merely mimics the preamble is left untouched.
//
// FALLBACK, stated honestly: when no trajectory sits beside the message log
// (rotated away, OPENCLAW_TRAJECTORY=0, or a pre-metadata OpenClaw build) the
// prefix is unavailable and the original heuristic stands — marker + FIRST
// "\n\n". Both shipped prefix flavours are a "\n"-join of non-empty
// single-sentence lines, so a real preamble provably contains no blank line
// and that first join point is the harness's own; the residual false-positive
// is exactly the mimicking human prompt, which only affects the 200-char
// preview (RawToolInput always keeps the full text).
//
// Returns (humanPrompt, true) only when the marker is present, the boundary
// is established, and something non-empty follows it; otherwise the caller
// leaves the text untouched.
func splitBootstrapPrompt(text string, tracePrefix func() string) (string, bool) {
	if !strings.HasPrefix(text, openclawBootstrapPrefixMarker) {
		return "", false
	}
	if tracePrefix != nil {
		if prefix := tracePrefix(); prefix != "" {
			join := prefix + "\n\n"
			if !strings.HasPrefix(text, join) {
				// The trace names the preamble this run actually
				// prepended and this text does not carry it — a human
				// prompt that only LOOKS like one. Leave it whole.
				return "", false
			}
			human := strings.TrimSpace(text[len(join):])
			if human == "" {
				return "", false
			}
			return human, true
		}
	}
	i := strings.Index(text, "\n\n")
	if i < 0 {
		return "", false
	}
	human := strings.TrimSpace(text[i+2:])
	if human == "" {
		return "", false
	}
	return human, true
}

// trajMetaLine is the sliver of a `trace.metadata` trajectory event that
// carries the run's harness prompt preamble. Kept separate from trajLine so
// scanning for it never unmarshals the event's very large sibling fields
// (systemPrompt, skills, config).
type trajMetaLine struct {
	Type string `json:"type"`
	Data struct {
		Prompting struct {
			UserPromptPrefixText string `json:"userPromptPrefixText"`
		} `json:"prompting"`
	} `json:"data"`
}

// bootstrapPrefixFromTrace returns the verbatim harness preamble OpenClaw
// prepended to this run's user prompt, read from the sibling
// `<stem>.trajectory.jsonl`'s `trace.metadata` event
// (data.prompting.userPromptPrefixText — present on both live 2026-07-31
// traces, emitted right after session.started). Returns "" when there is no
// trajectory, no such event, or the field is empty; splitBootstrapPrompt then
// falls back to its documented heuristic.
func bootstrapPrefixFromTrace(msgLogPath string) string {
	stem := strings.TrimSuffix(filepath.Base(msgLogPath), filepath.Ext(msgLogPath))
	f, err := os.Open(filepath.Join(filepath.Dir(msgLogPath), stem+".trajectory.jsonl"))
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	const maxLine = 16 * 1024 * 1024
	scanner.Buffer(make([]byte, 64*1024), maxLine)
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 || !bytes.Contains(raw, []byte(`"trace.metadata"`)) {
			continue
		}
		var meta trajMetaLine
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}
		if meta.Type != "trace.metadata" {
			continue
		}
		return meta.Data.Prompting.UserPromptPrefixText
	}
	return ""
}

func (a *Adapter) parseMessageLine(
	sourceFile string,
	line jsonlLine,
	lineNum int,
	ts time.Time,
	state *sessionContext,
	pending map[string]int,
	bootstrapPrefix func() string,
	cacheAcc *cacheobs.Accumulator,
	res *adapter.ParseResult,
) {
	msg := line.Message
	if msg.Provider != "" {
		state.Provider = msg.Provider
	}
	if msg.Model != "" {
		state.Model = msg.Model
	}
	if msg.Timestamp > 0 {
		ts = millisToTime(msg.Timestamp)
	}

	switch msg.Role {
	case "user":
		text := messageText(msg.Content)
		if text == "" {
			return
		}
		// WP-T6 O2 — a bootstrap-pending run arrives as one text part:
		// ~700 chars of harness preamble, then "\n\n", then the operator's
		// prompt. Surfaces that read actions.target (dashboard timeline,
		// prompt analytics) would otherwise show harness boilerplate.
		// Preview on the human half; RawToolInput keeps the full text so
		// the preamble is never lost. The boundary is corroborated against
		// the run's own trace-declared preamble where available, so a
		// human prompt that merely mimics one is not truncated.
		preview := text
		if human, ok := splitBootstrapPrompt(text, bootstrapPrefix); ok {
			preview = human
		}
		scrubbedText := a.scrubber.String(text)
		accumulateUserTextCache(cacheAcc, scrubbedText)
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile:         sourceFile,
			SourceEventID:      firstNonEmpty(line.ID, fmt.Sprintf("user:L%d", lineNum)),
			SessionID:          state.SessionID,
			ProjectRoot:        state.ProjectRoot,
			GitRemote:          state.ProjectRemote,
			Timestamp:          ts,
			Model:              modelName(state),
			Tool:               models.ToolOpenClaw,
			ActionType:         models.ActionUserPrompt,
			Target:             truncate(preview, 200),
			Success:            true,
			PrecedingReasoning: truncate(preview, 200),
			RawToolName:        "message.user",
			RawToolInput:       scrubbedText,
			MessageID:          userMessageID(line.ID, lineNum),
		})
	case "assistant":
		assistantMessageID := assistantMessageID(line.ID, lineNum)
		// Track the most recent assistant text/thinking part so each tool
		// call inherits the preamble that introduced it. Mirrors
		// claudecode's per-turn reasoning capture and pi's
		// `messageThinking`.
		//
		// Threading semantics (SHARED-PREAMBLE, deliberately NOT the
		// consumed-once grok default — preserved verbatim through the
		// B3 convergence): when multiple tool calls share one preamble
		// they ALL carry the same reasoning string, and a later
		// text/thinking part replaces it for the calls that follow.
		// Scope is one assistant message.
		var preceding string
		for partIdx, content := range msg.Content {
			switch content.Type {
			case "text", "thinking":
				body := strings.TrimSpace(content.Text)
				if body != "" {
					preceding = body
				}
				// Per-text-part row — matches the cross-adapter
				// convention. `text` parts emit an assistant_message row.
				//
				// `thinking` parts emit NOTHING (B3, 2026-07-31): they
				// briefly minted a standalone `openclaw.reasoning`
				// task_complete row, which is a phantom action for
				// something the model never did. The chain-of-thought
				// still reaches the timeline — it is the `preceding`
				// preamble threaded onto this message's tool calls
				// below (and, unchanged, every tool call that shares
				// one preamble carries the same string).
				if body != "" && content.Type == "text" {
					preview := truncate(a.scrubber.String(body), 200)
					cappedBody := a.scrubber.String(contentcap.Cap(body, contentcap.DefaultMaxBytes))
					accumulateAssistantTextCache(cacheAcc, cappedBody)
					res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
						SourceFile:         sourceFile,
						SourceEventID:      assistantTextEventID(line.ID, lineNum, partIdx, body),
						SessionID:          state.SessionID,
						ProjectRoot:        state.ProjectRoot,
						GitRemote:          state.ProjectRemote,
						Timestamp:          ts,
						Model:              modelName(state),
						Tool:               models.ToolOpenClaw,
						ActionType:         models.ActionAssistantMessage,
						Target:             preview,
						Success:            true,
						PrecedingReasoning: preview,
						RawToolName:        "openclaw.assistant_text",
						ToolOutput:         cappedBody,
						MessageID:          assistantMessageID,
					})
				}
			case "toolCall":
				ev := a.toolCallEvent(sourceFile, line, lineNum, ts, *state, content, assistantMessageID, preceding)
				accumulateToolCallCache(cacheAcc, content.Name, ev.RawToolInput)
				pending[content.ID] = len(res.ToolEvents)
				res.ToolEvents = append(res.ToolEvents, ev)
			}
		}
		text := messageText(msg.Content)
		if text != "" && msg.StopReason == "stop" {
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile:         sourceFile,
				SourceEventID:      firstNonEmpty("complete:"+line.ID, fmt.Sprintf("complete:L%d", lineNum)),
				SessionID:          state.SessionID,
				ProjectRoot:        state.ProjectRoot,
				GitRemote:          state.ProjectRemote,
				Timestamp:          ts,
				Model:              modelName(state),
				Tool:               models.ToolOpenClaw,
				ActionType:         models.ActionTaskComplete,
				Target:             "stop",
				Success:            true,
				PrecedingReasoning: truncate(text, 200),
				RawToolName:        "message.assistant.stop",
				ToolOutput:         a.scrubber.String(text),
				MessageID:          assistantMessageID,
				// Stamp the canonical per-message terminal reason
				// (matches claudecode/cowork/opencode) alongside the
				// RawToolName/Target marker. OpenClaw's stop vocabulary
				// is "stop"/"error"; the error case is emitted as a
				// distinct ActionAPIError row below.
				Metadata: &models.ActionMetadata{StopReason: msg.StopReason},
			})
		}
		if msg.StopReason == "error" {
			// Upstream API failure: provider rejected the request (model
			// doesn't support tools, rate limit, malformed body, etc.).
			// Pre-v1.4.22 these were silently dropped because the
			// stop-reason gate above only fired for "stop". errorMessage
			// is the verbatim provider response (e.g. `400 {"error":"..."}`).
			errBody := strings.TrimSpace(msg.ErrorMessage)
			if errBody == "" {
				errBody = "(no error message)"
			}
			class := openclawErrorClass(errBody)
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile:    sourceFile,
				SourceEventID: firstNonEmpty("error:"+line.ID, fmt.Sprintf("error:L%d", lineNum)),
				SessionID:     state.SessionID,
				ProjectRoot:   state.ProjectRoot,
				GitRemote:     state.ProjectRemote,
				Timestamp:     ts,
				Model:         modelName(state),
				Tool:          models.ToolOpenClaw,
				ActionType:    models.ActionAPIError,
				Target:        truncate(class, 200),
				Success:       false,
				ErrorMessage:  truncate(a.scrubber.String(errBody), 2048),
				RawToolName:   class,
				MessageID:     assistantMessageID,
			})
		}
		if hasUsage(msg.Usage) {
			usageSourceEventID := firstNonEmpty("usage:"+line.ID, fmt.Sprintf("usage:L%d", lineNum))
			if obs := emitCacheObservation(cacheAcc, sourceFile, state.SessionID, usageSourceEventID, modelName(state), ts, msg.Usage); obs != nil {
				res.CacheObservations = append(res.CacheObservations, *obs)
			}
			res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
				SourceFile:          sourceFile,
				SourceEventID:       usageSourceEventID,
				SessionID:           state.SessionID,
				ProjectRoot:         state.ProjectRoot,
				GitRemote:           state.ProjectRemote,
				Timestamp:           ts,
				Tool:                models.ToolOpenClaw,
				Model:               modelName(state),
				InputTokens:         msg.Usage.Input,
				OutputTokens:        msg.Usage.Output,
				CacheReadTokens:     msg.Usage.CacheRead,
				CacheCreationTokens: msg.Usage.CacheWrite,
				Source:              models.TokenSourceJSONL,
				// Provider-reported per-call usage, NOT a derivation —
				// same tier as the trajectory's lastCallUsage. Grounded
				// on the 2026-07-31 live capture: for the one call both
				// files describe, the two records are byte-identical
				// (368/542/14848/0), and the message log's five per-call
				// records sum EXACTLY to the trajectory's session total
				// data.usage (16139 in / 1076 out / 58368 cacheRead).
				// They are the same usage object read at two points, so
				// labelling one 'accurate' and its byte-identical twin
				// 'approximate' was incoherent (WP-T6 O1). The message
				// log's real limitation is COVERAGE, not precision:
				// gateway-injected turns arrive all-zero and the
				// hasUsage gate above drops them, which is exactly where
				// the trajectory remains the only source.
				Reliability: models.ReliabilityAccurate,
				MessageID:   assistantMessageID,
			})
		}
	case "toolResult":
		idx, ok := pending[msg.ToolCallID]
		if !ok {
			return
		}
		output := messageText(msg.Content)
		scrubbedOutput := a.scrubber.String(output)
		accumulateToolResultCache(cacheAcc, scrubbedOutput)
		res.ToolEvents[idx].ToolOutput = scrubbedOutput
		res.ToolEvents[idx].Success = !msg.IsError
		if msg.IsError {
			res.ToolEvents[idx].ErrorMessage = truncate(output, 500)
		}
	}
}

func (a *Adapter) toolCallEvent(sourceFile string, line jsonlLine, lineNum int, ts time.Time, state sessionContext, content messageContent, messageID, preceding string) models.ToolEvent {
	raw, _ := json.Marshal(content.Arguments)
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      firstNonEmpty(content.ID, fmt.Sprintf("tool:%s:L%d", content.Name, lineNum)),
		SessionID:          state.SessionID,
		ProjectRoot:        state.ProjectRoot,
		GitRemote:          state.ProjectRemote,
		Timestamp:          ts,
		Model:              modelName(&state),
		Tool:               models.ToolOpenClaw,
		ActionType:         mapToolName(content.Name),
		Target:             truncate(targetFromArgs(content.Arguments, content.Name), 200),
		Success:            true,
		PrecedingReasoning: truncate(preceding, 500),
		RawToolName:        content.Name,
		RawToolInput:       a.scrubber.RawJSON(raw),
		MessageID:          messageID,
	}
}

func applySessionAlias(path string, state *sessionContext, sessionID string) {
	if state == nil {
		return
	}
	alias, ok := lookupSessionAlias(path, sessionID)
	if !ok {
		return
	}
	if alias.SessionID != "" {
		state.SessionID = alias.SessionID
	}
	if alias.ProjectRoot != "" {
		state.ProjectRoot = alias.ProjectRoot
	}
	if alias.Provider != "" {
		state.Provider = alias.Provider
	}
	if alias.Model != "" {
		state.Model = alias.Model
	}
}

func lookupSessionAlias(path string, sessionID string) (sessionContext, bool) {
	indexPath := filepath.Join(filepath.Dir(path), "sessions.json")
	body, err := os.ReadFile(indexPath)
	if err != nil {
		return sessionContext{}, false
	}
	var idx sessionsIndex
	if err := json.Unmarshal(body, &idx); err != nil {
		return sessionContext{}, false
	}
	// sessions.json's `sessionFile` only ever names the MESSAGE LOG. A
	// `<id>.trajectory.jsonl` trace sits beside `<id>.jsonl`, so normalize
	// the trace name onto its message-log sibling before comparing —
	// otherwise the trajectory path can only ever match on the sessionId /
	// map-key arms and loses the alias whenever those disagree.
	base := filepath.Base(path)
	base = strings.TrimSuffix(strings.TrimSuffix(base, ".jsonl"), ".trajectory") + ".jsonl"
	for key, sess := range idx {
		if filepath.Base(sess.SessionFile) == base || sess.SessionID == sessionID || key == sessionID {
			return sessionContext{
				SessionID:   firstNonEmpty(key, sess.SystemPromptReport.SessionKey, sess.SessionID),
				ProjectRoot: firstNonEmpty(sess.SystemPromptReport.WorkspaceDir),
				Provider:    firstNonEmpty(sess.ModelProvider, sess.SystemPromptReport.Provider),
				Model:       firstNonEmpty(sess.Model, sess.SystemPromptReport.Model),
			}, true
		}
	}
	return sessionContext{}, false
}

func loadSessionAliases(agentsRoot string) map[string]sessionIndexEntry {
	aliases := map[string]sessionIndexEntry{}
	entries, err := filepath.Glob(filepath.Join(agentsRoot, "*", "sessions", "sessions.json"))
	if err != nil {
		return aliases
	}
	for _, indexPath := range entries {
		body, err := os.ReadFile(indexPath)
		if err != nil {
			continue
		}
		var idx sessionsIndex
		if err := json.Unmarshal(body, &idx); err != nil {
			continue
		}
		for key, entry := range idx {
			aliases[key] = entry
			if entry.SessionID != "" {
				aliases[entry.SessionID] = entry
			}
		}
	}
	return aliases
}

func suppressTaskRun(tr taskRun, aliases map[string]sessionIndexEntry) bool {
	for _, key := range []string{tr.ChildSessionKey, tr.OwnerKey, tr.RequesterKey, tr.RunID, tr.SourceID} {
		if entry, ok := aliases[key]; ok && strings.TrimSpace(entry.SessionFile) != "" {
			return true
		}
	}
	return false
}

func messageText(contents []messageContent) string {
	var parts []string
	for _, c := range contents {
		if c.Type == "text" && strings.TrimSpace(c.Text) != "" {
			parts = append(parts, c.Text)
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

// openclawShortHash returns a short hex digest of s for use in
// SourceEventID / MessageID prefixes. Matches the cursor /
// claudecode adapters' shortHash convention (12 hex chars).
func openclawShortHash(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

// openclawErrorClass extracts a short discriminator from an
// errorMessage body. Matches "<status_code> ..." prefixes (e.g.
// "400 {...}" → "http_400") and falls back to "api_error" otherwise.
// Mirrors claudecode / codex api_error class conventions so dashboards
// can group related failure classes across adapters.
func openclawErrorClass(body string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return "api_error"
	}
	// Try "NNN ..." status-code prefix.
	if i := strings.IndexByte(body, ' '); i > 0 && i <= 4 {
		prefix := body[:i]
		allDigits := true
		for _, r := range prefix {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return "http_" + prefix
		}
	}
	return "api_error"
}

func mapToolName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "read", "cat", "view":
		return models.ActionReadFile
	case "write", "create":
		return models.ActionWriteFile
	case "edit", "patch", "replace":
		return models.ActionEditFile
	case "exec", "bash", "shell", "command",
		"powershell", "pwsh", "cmd", "cmd.exe":
		return models.ActionRunCommand
	case "web_fetch":
		return models.ActionWebFetch
	case "browser":
		return models.ActionBrowserAction
	case "memory_search":
		return models.ActionSearchText
	case "process":
		return models.ActionRunCommand
	// sessions_spawn launches a sub-agent — semantically equivalent to
	// Claude Code's Agent tool. Was bucketed with the other sessions_*
	// MCP-style tools by mistake; the name "spawn" is the giveaway.
	// Promoting it to ActionSpawnSubagent so dashboard fan-out counts
	// pick it up the same way they pick up claudecode's Agent and
	// opencode's `task`/`agent`/`subagent` tools.
	case "sessions_spawn":
		return models.ActionSpawnSubagent
	case "canvas", "cron", "gateway", "memory_get", "message", "nodes",
		"session_status", "sessions_history", "sessions_list", "sessions_send",
		"sessions_yield", "subagents", "tts", "agents_list":
		return models.ActionMCPCall
	default:
		// A real external MCP tool arrives as mcp__<server>__<tool>;
		// classify it as MCP so the dashboard labels it (identity stays
		// in the raw tool name).
		if models.IsMCPToolName(name) {
			return models.ActionMCPCall
		}
		return models.ActionUnknown
	}
}

// projectGitInfo pairs a resolved project root with its git remote (when
// the cwd sat inside a real git working tree), so one resolveProjectRoot
// call — and one cache entry — carries both together.
type projectGitInfo struct {
	Root   string
	Remote string
	// Identity is the Project Identity Resolver v2 bundle (2026-09-06,
	// §3.1 / W1) resolved alongside Root/Remote, zero-valued on every
	// branch that doesn't run git.ResolveIdentity (an honest gap, never
	// a fabricated value). Applied at the end of each parse entry point
	// via adapter.ApplyProjectIdentityByRoot, keyed by Root.
	Identity git.Identity
}

// resolveProjectRoot turns a recorded cwd into a stable project root plus
// its normalized git remote. Mirrors the codex / opencode pattern: empty
// input yields the "[openclaw]" placeholder so historical rows continue to
// coalesce; real paths inside a git working tree resolve to the repo root
// and its remote. The cache lives for one parse call.
func (a *Adapter) resolveProjectRoot(cwd string, cache map[string]projectGitInfo) (string, string) {
	if cwd == "" {
		return "[openclaw]", ""
	}
	if info, ok := cache[cwd]; ok {
		return info.Root, info.Remote
	}
	translated := crossmount.TranslateForeignPath(cwd)
	if _, err := os.Stat(translated); err == nil {
		if id, err := git.ResolveIdentity(translated, git.IdentityOptions{}); err == nil && id.IsGit {
			// id.Remote is already NormalizeRemote'd by ResolveIdentity.
			cache[cwd] = projectGitInfo{Root: id.Root, Remote: id.Remote, Identity: id}
			return id.Root, id.Remote
		}
		cache[cwd] = projectGitInfo{Root: translated}
		return translated, ""
	}
	cache[cwd] = projectGitInfo{Root: cwd}
	return cwd, ""
}

// identitiesByRoot collapses a per-cwd projectGitInfo cache into a
// per-root git.Identity map, for adapter.ApplyProjectIdentityByRoot.
func identitiesByRoot(cache map[string]projectGitInfo) map[string]git.Identity {
	out := make(map[string]git.Identity, len(cache))
	for _, info := range cache {
		if info.Root != "" {
			out[info.Root] = info.Identity
		}
	}
	return out
}

func targetFromArgs(args map[string]any, fallback string) string {
	for _, key := range []string{"path", "file", "filePath", "command", "cmd", "url", "query", "sessionId"} {
		if v, ok := args[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return fallback
}

func modelName(state *sessionContext) string {
	if state == nil {
		return ""
	}
	if state.Provider != "" && state.Model != "" {
		return state.Provider + "/" + state.Model
	}
	return state.Model
}

func latestTaskWatermark(ctx context.Context, path string) (int64, error) {
	db, err := openReadOnlyDB(path)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var latest int64
	row := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(COALESCE(last_event_at, ended_at, started_at, created_at)), 0) FROM task_runs`)
	if err := row.Scan(&latest); err != nil {
		return 0, err
	}
	return latest, nil
}

func openReadOnlyDB(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)", sqlitedsn.Escape(path))
	return sql.Open("sqlite", dsn)
}

func resolveRunsDB(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == "runs.sqlite-wal" || base == "runs.sqlite-shm" {
		return filepath.Join(filepath.Dir(path), "runs.sqlite")
	}
	return path
}

// defaultRoots returns OpenClaw's tasks + agents dirs under every
// cross-mount-resolved $HOME so observer in WSL2 picks up data from
// /mnt/c/Users/<u>/.openclaw (and vice-versa). Subpaths are uniform
// across OSes — OpenClaw uses ~/.openclaw on every host.
func defaultRoots() []string {
	var roots []string
	for _, h := range crossmount.AllHomes() {
		roots = append(
			roots,
			filepath.Join(h.Path, ".openclaw", "tasks"),
			filepath.Join(h.Path, ".openclaw", "agents"),
		)
	}
	return roots
}

var taskPrefixRE = regexp.MustCompile(`^\[[^\]]+\]\s*`)

func stripTaskTimestamp(s string) string {
	return strings.TrimSpace(taskPrefixRE.ReplaceAllString(s, ""))
}

func sessionID(tr taskRun) string {
	return firstNonEmpty(tr.ChildSessionKey, tr.OwnerKey, tr.RequesterKey, tr.RunID, tr.SourceID, tr.TaskID)
}

func canonicalSessionID(sess sessionIndexEntry, fallbackKey string) string {
	return firstNonEmpty(
		strings.TrimSpace(sess.SystemPromptReport.SessionKey),
		strings.TrimSpace(fallbackKey),
		strings.TrimSpace(sess.SessionID),
	)
}

func taskEndTime(tr taskRun) time.Time {
	return millisToTime(firstNonZero(nullInt(tr.EndedAt), nullInt(tr.LastEventAt), nullInt(tr.StartedAt), tr.CreatedAt))
}

func durationMs(tr taskRun) int64 {
	start := nullInt(tr.StartedAt)
	end := firstNonZero(nullInt(tr.EndedAt), nullInt(tr.LastEventAt))
	if start <= 0 || end <= start {
		return 0
	}
	return end - start
}

func isTerminalStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "succeeded", "failed", "timed_out", "cancelled", "lost":
		return true
	default:
		return false
	}
}

func nullInt(v sql.NullInt64) int64 {
	if v.Valid {
		return v.Int64
	}
	return 0
}

func nullString(v sql.NullString) string {
	if v.Valid {
		return v.String
	}
	return ""
}

func millisToTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func parseTimestamp(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	return time.Time{}
}

func firstNonZero(values ...int64) int64 {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func userMessageID(id string, lineNum int) string {
	return "user:" + firstNonEmpty(id, fmt.Sprintf("L%d", lineNum))
}

func assistantMessageID(id string, lineNum int) string {
	return firstNonEmpty(id, fmt.Sprintf("assistant:L%d", lineNum))
}

// assistantTextEventID builds the SourceEventID for one assistant TEXT
// part. It deliberately does NOT include the entry's file position when
// the entry carries its own id (O1).
//
// The two capture paths for one OpenClaw session number entries
// differently: the pre-2.0 message log counts LINES (1-based, assigned
// by the scanner) while the 2.0 store carries `transcript_events.seq`
// (whatever the writer put there — 0-based on the builds we have, and
// not a contract either way). Every other row in this file already
// tolerates that, because they reach for the ordinal only through
// firstNonEmpty(line.ID, "…L%d") — an entry with an id never sees it.
// This row alone interpolated the ordinal UNCONDITIONALLY, so a session
// migrated by `openclaw doctor --fix` and then re-read out of the store
// produced `asst:<id>:L0:P0:<hash>` against the log's
// `asst:<id>:L1:P0:<hash>` — two different keys for one row, defeating
// the UNIQUE(source_file, source_event_id) dedup that
// legacySourceFile() exists to arm, and double-ingesting every assistant
// message.
//
// entryID + partIdx + contentHash is sufficient on its own: partIdx
// separates the parts within one entry, the hash separates two parts
// that happen to share an index across a re-write, and the entry id
// separates entries. Only when the entry has NO id does the ordinal come
// back as the last-resort discriminator — matching every sibling row's
// scheme exactly, and no worse than they already are.
//
// ⚠️ MIGRATION NOTE: this CHANGES the id for assistant-text rows already
// ingested from a legacy `.jsonl`. Steady-state watching is unaffected
// (those rows are long past their watermark), but an explicit
// `observer scan --force` / `backfill` over an old message log will
// re-insert each assistant_message row ONCE under the new key, next to
// the old one. That is a one-time, bounded, assistant-text-only
// duplicate. It is the honest trade: the alternative — keeping the
// ordinal and teaching the SQLite path to synthesize the same
// 1-based line number — would have to assume a `seq` contract OpenClaw
// does not publish, and would silently re-introduce the double-ingest
// the moment a build numbered `seq` differently.
func assistantTextEventID(entryID string, lineNum, partIdx int, body string) string {
	return fmt.Sprintf("asst:%s:P%d:%s",
		firstNonEmpty(entryID, fmt.Sprintf("L%d", lineNum)), partIdx, openclawShortHash(body))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
