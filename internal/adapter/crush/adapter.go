package crush

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

// Adapter parses Charm Crush's per-project SQLite store (crush.db). Crush
// keeps no central session directory, so the watch roots are the Crush
// global state dirs plus every project data dir enumerated from
// projects.json at construction time. See the package doc for the store
// shape.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter whose roots are discovered from the Crush global
// state files (projects.json) across every cross-mount-resolved home.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: discoverRoots()}
}

// NewWithOptions customizes scrubber and/or roots for tests. A nil
// scrubber falls back to the default; empty roots fall back to discovery.
func NewWithOptions(s *scrub.Scrubber, roots []string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = discoverRoots()
	}
	return &Adapter{scrubber: s, roots: roots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolCrush }

// WatchPaths implements adapter.Adapter. The roots are a snapshot taken at
// construction: the Crush global state dirs plus the project data dirs
// (<project>/.crush) read from projects.json. A project created AFTER the
// daemon started is not watched until the next daemon restart or an
// `observer backfill` run — Crush's project-local store model has no
// central directory the watcher could recursively cover, and this package
// does not reach into the watcher to re-derive roots dynamically.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Matches a Crush per-project
// store crush.db (and its -wal sibling) whose immediate parent directory
// is ".crush" and which lives under one of the watch roots. The
// parent-dir guard keeps a stray crush.db archived elsewhere from being
// claimed, and lets a broad global-state root (which contains no crush.db
// of its own) coexist with the tight .crush data-dir roots.
func (a *Adapter) IsSessionFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base != "crush.db" && base != "crush.db-wal" {
		return false
	}
	if !strings.EqualFold(filepath.Base(filepath.Dir(path)), ".crush") {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.roots)
}

// ParseSessionFile implements adapter.Adapter. It performs a watermark
// incremental read of the crush.db at path: rows whose updated_at exceeds
// fromOffset (Unix seconds) are re-read, everything else is skipped.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	dbPath := resolveDBPath(path)
	latest, err := latestWatermark(ctx, dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("crush.ParseSessionFile: latest watermark: %w", err)
	}
	res := adapter.ParseResult{NewOffset: latest}
	if latest <= fromOffset {
		return res, nil
	}

	database, err := openReadOnlyDB(dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("crush.ParseSessionFile: open: %w", err)
	}
	defer database.Close()

	projectRoot, gitRemote, projectIdentity := a.resolveProjectRoot(dbPath)

	tools, err := a.loadMessageEvents(ctx, database, dbPath, projectRoot, gitRemote, fromOffset)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("crush.ParseSessionFile: messages: %w", err)
	}
	tokens, err := a.loadTokenEvents(ctx, database, dbPath, projectRoot, gitRemote, fromOffset)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("crush.ParseSessionFile: tokens: %w", err)
	}
	res.ToolEvents = append(res.ToolEvents, tools...)
	res.TokenEvents = append(res.TokenEvents, tokens...)
	adapter.ApplyProjectIdentity(&res, projectIdentity)
	return res, nil
}

// messageRow is one row of the crush.db `messages` table.
type messageRow struct {
	ID         string
	SessionID  string
	Role       string
	Parts      string
	Model      string
	Provider   string
	CreatedAt  int64
	UpdatedAt  int64
	FinishedAt int64
}

// crushPart is a single element of a message's `parts` JSON array. Every
// part carries a discriminating `type` and a `data` object whose shape
// depends on the type.
type crushPart struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type crushTextData struct {
	Text string `json:"text"`
}

type crushReasoningData struct {
	Thinking   string `json:"thinking"`
	StartedAt  int64  `json:"started_at"`
	FinishedAt int64  `json:"finished_at"`
}

type crushToolCallData struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Input            string `json:"input"`
	ProviderExecuted bool   `json:"provider_executed"`
	Finished         bool   `json:"finished"`
}

type crushToolResultData struct {
	ToolCallID string `json:"tool_call_id"`
	Name       string `json:"name"`
	Content    string `json:"content"`
	Metadata   string `json:"metadata"`
	IsError    bool   `json:"is_error"`
}

// crushToolInput is the (JSON-string-encoded) argument object of a
// tool_call. Only the fields we map onto the action taxonomy are decoded.
type crushToolInput struct {
	FilePath   string `json:"file_path"`
	Path       string `json:"path"`
	Command    string `json:"command"`
	Query      string `json:"query"`
	Pattern    string `json:"pattern"`
	URL        string `json:"url"`
	WorkingDir string `json:"working_dir"`
}

// toolResult is the paired result of a tool_call, extracted from a
// role="tool" message's tool_result part.
type toolResult struct {
	Content string
	IsError bool
}

// loadMessageEvents reads every message whose updated_at exceeds
// fromOffset, pairs tool_call parts with their tool_result siblings, and
// emits one ToolEvent per user-prompt / assistant-text / tool-call part.
// tool_result parts are consumed into the pairing map and never emitted
// on their own; `reasoning` parts never mint a row of their own either —
// they ride the next event as PrecedingReasoning (see threadState).
func (a *Adapter) loadMessageEvents(ctx context.Context, db *sql.DB, sourceFile, projectRoot, gitRemote string, fromOffset int64) ([]models.ToolEvent, error) {
	if !tableExists(ctx, db, "messages") {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, session_id, role, parts,
		       COALESCE(model, ''), COALESCE(provider, ''),
		       created_at, updated_at, COALESCE(finished_at, 0)
		  FROM messages
		 WHERE updated_at > ?
		 ORDER BY created_at ASC, id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var msgs []messageRow
	for rows.Next() {
		var m messageRow
		if err := rows.Scan(&m.ID, &m.SessionID, &m.Role, &m.Parts, &m.Model, &m.Provider,
			&m.CreatedAt, &m.UpdatedAt, &m.FinishedAt); err != nil {
			return nil, err
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	results := collectToolResults(msgs)

	var out []models.ToolEvent
	var pending threadState
	for _, m := range msgs {
		var parts []crushPart
		if err := json.Unmarshal([]byte(m.Parts), &parts); err != nil {
			continue // malformed parts blob — skip, don't fail the batch
		}
		out = append(out, a.eventsForMessage(sourceFile, projectRoot, gitRemote, m, parts, results, &pending)...)
	}
	return out, nil
}

// threadState carries the reasoning text a `reasoning` part produced
// until the next assistant-text / tool-call event consumes it.
//
// Semantics (grok-style, adopted by B3 — see the package doc):
//
//   - CONSUMED-ONCE: the first successor event to carry it clears it, so
//     one block of thinking is never stamped onto a whole session.
//
//   - LAST-WINS: a second `reasoning` part before any successor replaces
//     the first (Crush emits interleaved reasoning/tool_call parts, and
//     the nearest thinking is the one that introduced the call).
//
//   - TURN-BOUNDARY DISCARD: a user prompt clears it — reasoning never
//     crosses into the next user turn.
//
//   - SESSION-SCOPED: one crush.db holds every session of a project and
//     the message scan orders by created_at across all of them, so two
//     sessions can interleave. Reasoning never crosses a session id.
//
// The state lives for one ParseSessionFile call and spans messages,
// because Crush's reasoning part and the tool_call it introduces can
// land on different `messages` rows.
type threadState struct {
	sessionID string
	text      string
}

// set records a reasoning body for a session (last-wins).
func (t *threadState) set(sessionID, body string) {
	t.sessionID, t.text = sessionID, body
}

// clear drops any pending reasoning (turn boundary).
func (t *threadState) clear() { t.sessionID, t.text = "", "" }

// take returns the pending reasoning and consumes it, or "" when the
// pending reasoning belongs to a different session. Scrubbing + capping
// happen HERE (at flush), not at capture, so the 200-char preview
// convention the retired `crush.reasoning` row used is preserved
// byte-for-byte on the successor's PrecedingReasoning.
func (t *threadState) take(a *Adapter, sessionID string) string {
	if t.text == "" || t.sessionID != sessionID {
		return ""
	}
	out := a.scrub(truncate(t.text, 200))
	t.clear()
	return out
}

// collectToolResults walks every role="tool" message's tool_result parts
// and returns a map keyed by tool_call id.
func collectToolResults(msgs []messageRow) map[string]toolResult {
	out := map[string]toolResult{}
	for _, m := range msgs {
		if !strings.EqualFold(m.Role, "tool") {
			continue
		}
		var parts []crushPart
		if err := json.Unmarshal([]byte(m.Parts), &parts); err != nil {
			continue
		}
		for _, p := range parts {
			if p.Type != "tool_result" {
				continue
			}
			var d crushToolResultData
			if err := json.Unmarshal(p.Data, &d); err != nil {
				continue
			}
			if d.ToolCallID == "" {
				continue
			}
			out[d.ToolCallID] = toolResult{Content: d.Content, IsError: d.IsError}
		}
	}
	return out
}

// eventsForMessage converts one message's parts into ToolEvents.
// `pending` carries reasoning across parts AND across messages; see
// threadState for the consumption semantics.
func (a *Adapter) eventsForMessage(sourceFile, projectRoot, gitRemote string, m messageRow, parts []crushPart, results map[string]toolResult, pending *threadState) []models.ToolEvent {
	var out []models.ToolEvent
	when := secondsToTime(m.CreatedAt)
	for i, p := range parts {
		switch p.Type {
		case "text":
			var d crushTextData
			if err := json.Unmarshal(p.Data, &d); err != nil {
				continue
			}
			body := strings.TrimSpace(d.Text)
			if body == "" {
				continue
			}
			if strings.EqualFold(m.Role, "user") {
				out = append(out, a.userPromptEvent(sourceFile, projectRoot, gitRemote, m, i, body, pending))
			} else if strings.EqualFold(m.Role, "assistant") {
				out = append(out, a.assistantTextEvent(sourceFile, projectRoot, gitRemote, m, i, body, pending))
			}
		case "reasoning":
			// B3: a reasoning part mints NO action row of its own. Its
			// body is held and threaded onto the next assistant-text /
			// tool-call event as PrecedingReasoning.
			var d crushReasoningData
			if err := json.Unmarshal(p.Data, &d); err != nil {
				continue
			}
			if body := strings.TrimSpace(d.Thinking); body != "" {
				pending.set(m.SessionID, body)
			}
		case "tool_call":
			var d crushToolCallData
			if err := json.Unmarshal(p.Data, &d); err != nil {
				continue
			}
			out = append(out, a.toolCallEvent(sourceFile, projectRoot, gitRemote, m, when, d, results, pending))
		}
	}
	return out
}

// userPromptEvent emits the operator's prompt. A user turn is a reasoning
// boundary: any thinking still pending from the previous turn is dropped
// rather than stamped onto the new turn's rows.
func (a *Adapter) userPromptEvent(sourceFile, projectRoot, gitRemote string, m messageRow, idx int, body string, pending *threadState) models.ToolEvent {
	pending.clear()
	preview := a.scrub(truncate(body, 500))
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: fmt.Sprintf("prompt:%s:%d", m.ID, idx),
		SessionID:     m.SessionID,
		ProjectRoot:   projectRoot,
		GitRemote:     gitRemote,
		Timestamp:     secondsToTime(m.CreatedAt),
		Tool:          models.ToolCrush,
		ActionType:    models.ActionUserPrompt,
		Target:        truncate(preview, 200),
		Success:       true,
		RawToolName:   "crush.user_prompt",
		MessageID:     m.ID,
	}
}

func (a *Adapter) assistantTextEvent(sourceFile, projectRoot, gitRemote string, m messageRow, idx int, body string, pending *threadState) models.ToolEvent {
	preview := a.scrub(truncate(body, 200))
	output := a.scrub(contentcap.Cap(body, contentcap.DefaultMaxBytes))
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: fmt.Sprintf("text:%s:%d", m.ID, idx),
		SessionID:     m.SessionID,
		ProjectRoot:   projectRoot,
		GitRemote:     gitRemote,
		Timestamp:     secondsToTime(m.CreatedAt),
		Model:         m.Model,
		Tool:          models.ToolCrush,
		// One row per text part of a message — per-message assistant
		// text, not a turn terminus.
		ActionType:         models.ActionAssistantMessage,
		Target:             preview,
		Success:            true,
		PrecedingReasoning: pending.take(a, m.SessionID),
		RawToolName:        "crush.assistant_text",
		ToolOutput:         output,
		MessageID:          m.ID,
	}
}

// Crush stores no reasoning TOKEN count (its token bundle is
// session-cumulative prompt/completion only), so a `reasoning` part is
// pure text. Pre-B3 it minted its own ActionTaskComplete row
// (`crush.reasoning`) — a phantom action for something the model never
// did. It is now threaded onto the successor event instead (threadState).
func (a *Adapter) toolCallEvent(sourceFile, projectRoot, gitRemote string, m messageRow, when time.Time, d crushToolCallData, results map[string]toolResult, pending *threadState) models.ToolEvent {
	actionType, target := mapTool(d.Name, []byte(d.Input))

	success := true
	var errMsg, output string
	if res, ok := results[d.ID]; ok {
		success = !res.IsError
		output = a.scrub(contentcap.Cap(res.Content, contentcap.DefaultMaxBytes))
		if res.IsError {
			errMsg = res.Content
		}
	}

	rawInput := a.scrubRaw([]byte(d.Input))
	sourceID := "tool:" + d.ID
	if d.ID == "" {
		// Extremely rare: a tool_call with no id. Fall back to a
		// message-scoped id so re-parse stays idempotent.
		sourceID = "tool:" + m.ID + ":" + d.Name
	}
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      sourceID,
		SessionID:          m.SessionID,
		ProjectRoot:        projectRoot,
		GitRemote:          gitRemote,
		Timestamp:          when,
		Model:              m.Model,
		Tool:               models.ToolCrush,
		ActionType:         actionType,
		Target:             truncate(target, 200),
		Success:            success,
		ErrorMessage:       a.scrub(truncate(errMsg, 500)),
		PrecedingReasoning: pending.take(a, m.SessionID),
		RawToolName:        d.Name,
		RawToolInput:       rawInput,
		ToolOutput:         output,
		MessageID:          m.ID,
	}
}

// loadTokenEvents emits one TokenEvent per session whose updated_at
// exceeds fromOffset. Crush stores token counts and its own dollar cost
// at the SESSION level (cumulative), not per message, so the SourceEventID
// is stable across parses and the store's MAX-upgrade ON CONFLICT keeps
// the monotonically-growing counts correct. Model+provider come from the
// newest assistant message in the session (so a provider-failover session
// reports the provider that finished the turn).
func (a *Adapter) loadTokenEvents(ctx context.Context, db *sql.DB, sourceFile, projectRoot, gitRemote string, fromOffset int64) ([]models.TokenEvent, error) {
	if !tableExists(ctx, db, "sessions") {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, prompt_tokens, completion_tokens, cost, updated_at, created_at
		  FROM sessions
		 WHERE updated_at > ?
		 ORDER BY updated_at ASC, id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type sessionRow struct {
		ID         string
		Prompt     int64
		Completion int64
		Cost       float64
		UpdatedAt  int64
	}
	var sessions []sessionRow
	for rows.Next() {
		var s sessionRow
		var created int64
		if err := rows.Scan(&s.ID, &s.Prompt, &s.Completion, &s.Cost, &s.UpdatedAt, &created); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var out []models.TokenEvent
	for _, s := range sessions {
		// Skip observationally-vacant sessions (no tokens, no cost) —
		// a fresh session with nothing but a title.
		if s.Prompt == 0 && s.Completion == 0 && s.Cost == 0 {
			continue
		}
		model, _ := newestAssistantModel(ctx, db, s.ID)
		out = append(out, models.TokenEvent{
			SourceFile:       sourceFile,
			SourceEventID:    "tokens:" + s.ID,
			SessionID:        s.ID,
			ProjectRoot:      projectRoot,
			GitRemote:        gitRemote,
			Timestamp:        secondsToTime(s.UpdatedAt),
			Tool:             models.ToolCrush,
			Model:            model,
			InputTokens:      s.Prompt,
			OutputTokens:     s.Completion,
			EstimatedCostUSD: s.Cost,
			// Crush persists the upstream usage envelope + its own cost
			// into the session store; trustworthy but not invoice-
			// verified — approximate, JSONL-class source.
			Source:      models.TokenSourceJSONL,
			Reliability: models.ReliabilityApproximate,
		})
	}
	return out, nil
}

// newestAssistantModel returns the model (and provider) of the most
// recent assistant message in a session. Empty strings when the session
// has no assistant message yet.
func newestAssistantModel(ctx context.Context, db *sql.DB, sessionID string) (model, provider string) {
	if !tableExists(ctx, db, "messages") {
		return "", ""
	}
	row := db.QueryRowContext(ctx, `
		SELECT COALESCE(model, ''), COALESCE(provider, '')
		  FROM messages
		 WHERE session_id = ? AND role = 'assistant'
		 ORDER BY created_at DESC, id DESC
		 LIMIT 1`, sessionID)
	_ = row.Scan(&model, &provider)
	return model, provider
}

// mapTool resolves a Crush built-in tool name onto the normalized action
// taxonomy, deriving a display target from the decoded input arguments.
// Crush's built-in tool set (charmbracelet/crush): bash, view, ls, glob,
// grep, edit, multiedit, write, fetch, download, sourcegraph, diagnostics,
// agent, plus MCP tools.
func mapTool(name string, input []byte) (actionType, target string) {
	var in crushToolInput
	_ = json.Unmarshal(input, &in)
	fallback := firstNonEmpty(in.Command, in.FilePath, in.Path, in.Pattern, in.Query, in.URL, name)

	switch strings.ToLower(strings.TrimSpace(name)) {
	case "bash", "shell", "cmd", "powershell", "pwsh":
		return models.ActionRunCommand, firstNonEmpty(in.Command, name)
	case "view", "read", "cat":
		return models.ActionReadFile, firstNonEmpty(in.FilePath, in.Path, name)
	case "write", "create":
		return models.ActionWriteFile, firstNonEmpty(in.FilePath, in.Path, name)
	case "edit", "multiedit", "patch", "replace":
		return models.ActionEditFile, firstNonEmpty(in.FilePath, in.Path, name)
	case "ls", "glob", "find":
		return models.ActionSearchFiles, firstNonEmpty(in.Path, in.Pattern, name)
	case "grep", "rg", "search":
		return models.ActionSearchText, firstNonEmpty(in.Pattern, in.Query, name)
	case "fetch", "download", "http":
		return models.ActionWebFetch, firstNonEmpty(in.URL, name)
	case "sourcegraph", "websearch":
		return models.ActionWebSearch, firstNonEmpty(in.Query, name)
	case "agent", "task", "subagent":
		return models.ActionSpawnSubagent, firstNonEmpty(in.Query, name)
	default:
		if strings.Contains(strings.ToLower(name), "mcp") {
			return models.ActionMCPCall, fallback
		}
		return models.ActionUnknown, fallback
	}
}

// resolveProjectRoot turns the crush.db path into a stable project root.
// The DB's grandparent directory IS the project (…/<project>/.crush/
// crush.db) — Crush does not store cwd anywhere. Foreign-mount Windows
// paths are translated to their /mnt/c equivalent before git.Resolve so a
// Windows-side project doesn't misfile under the observer's own repo.
// Returns (root, gitRemote); gitRemote is "" when the project isn't
// inside a git repo.
func (a *Adapter) resolveProjectRoot(dbPath string) (root, gitRemote string, id git.Identity) {
	proj := filepath.Dir(filepath.Dir(dbPath))
	if proj == "" || proj == "." || proj == string(filepath.Separator) {
		return "[crush]", "", git.Identity{}
	}
	proj = crossmount.TranslateForeignPath(proj)
	identity, err := git.ResolveIdentity(proj, git.IdentityOptions{})
	if err != nil {
		return proj, "", git.Identity{}
	}
	// identity.Remote is already NormalizeRemote'd by ResolveIdentity.
	return identity.Root, identity.Remote, identity
}

// scrub applies the plaintext scrubber, tolerating a nil scrubber.
func (a *Adapter) scrub(v string) string {
	if a.scrubber == nil {
		return v
	}
	return a.scrubber.String(v)
}

// scrubRaw applies the JSON-structure-safe scrubber to a raw JSON blob,
// tolerating a nil scrubber and empty input.
func (a *Adapter) scrubRaw(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if a.scrubber == nil {
		return string(raw)
	}
	return a.scrubber.RawJSON(raw)
}

// latestWatermark returns the largest updated_at across the sessions and
// messages tables (Unix seconds). Missing tables contribute 0 so a
// partial/foreign schema degrades gracefully.
func latestWatermark(ctx context.Context, path string) (int64, error) {
	db, err := openReadOnlyDB(path)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	var latest int64
	for _, tbl := range []string{"sessions", "messages"} {
		if !tableExists(ctx, db, tbl) {
			continue
		}
		var v int64
		//nolint:gosec // table name is from a fixed allow-list, never user input
		q := fmt.Sprintf(`SELECT COALESCE(MAX(updated_at), 0) FROM %s`, tbl)
		if err := db.QueryRowContext(ctx, q).Scan(&v); err != nil {
			return 0, err
		}
		if v > latest {
			latest = v
		}
	}
	return latest, nil
}

func openReadOnlyDB(path string) (*sql.DB, error) {
	actual, err := stageMirrorIfForeign(path)
	if err != nil {
		return nil, fmt.Errorf("crush.stageMirror: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)", sqlitedsn.Escape(actual))
	return sql.Open("sqlite", dsn)
}

// allHomesFunc is the test seam over crossmount.AllHomes.
var allHomesFunc = crossmount.AllHomes

// stageMirrorIfForeign returns the source path unchanged when native. For
// a foreign-mount source (e.g. /mnt/c/programsx/<proj>/.crush/crush.db on a
// WSL2 host reading the Windows-side store) it stages a local mirror of
// the SQLite trio, because modernc.org/sqlite fails with a disk-I/O error
// when opening a DrvFs path that Windows is actively writing. Structurally
// mirrors the opencode adapter's staging (the internals are unexported
// there, so the pattern is copied rather than imported).
func stageMirrorIfForeign(srcDB string) (string, error) {
	if !isForeignMountPath(srcDB) {
		return srcDB, nil
	}
	base, err := mirrorbase.Base()
	if err != nil || base == "" {
		base = filepath.Join(os.TempDir(), "superbased-observer")
	}
	sum := sha256.Sum256([]byte(srcDB))
	mirrorDir := filepath.Join(base, "crush-mirror", hex.EncodeToString(sum[:8]))
	if err := os.MkdirAll(mirrorDir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir mirror: %w", err)
	}
	dstDB := filepath.Join(mirrorDir, "crush.db")
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

// mirrorUpToDate reports whether the mirror trio is at least as fresh as
// the source, using (size, mtime) per sibling. WAL is the fast-moving
// signal, so it is checked explicitly. Any stat error returns false so a
// fresh copy is attempted.
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

// isForeignMountPath reports whether path lives under a crossmount-detected
// non-native home. Covers both bridge directions (/mnt/c on WSL2, and
// \\wsl.localhost\ on Windows).
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

// resolveDBPath maps a -wal/-shm sibling event back to the main crush.db.
func resolveDBPath(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == "crush.db-wal" || base == "crush.db-shm" {
		return filepath.Join(filepath.Dir(path), "crush.db")
	}
	return path
}

// tableExists reports whether the named table is present.
func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// secondsToTime converts a Crush Unix-SECONDS timestamp (the schema
// comment claiming milliseconds is wrong — the update trigger writes
// strftime('%s','now')) into a UTC time. Zero/negative yields the zero
// time.
func secondsToTime(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
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
