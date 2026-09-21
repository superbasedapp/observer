package pi

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter parses Pi session JSONL files under ~/.pi/agent/sessions.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with default Pi roots.
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
func (*Adapter) Name() string { return models.ToolPi }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Pi writes session
// transcripts as `.jsonl` files under ~/.pi/agent/sessions. The
// under-WatchPaths constraint enforces the v1.4.51 dispatch contract
// — without it the bare-extension match would collide alphabetically
// with claude-code, openclaw, and codex.
func (a *Adapter) IsSessionFile(path string) bool {
	if !strings.HasSuffix(strings.ToLower(path), ".jsonl") {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

type rawLine struct {
	Type      string    `json:"type"`
	ID        string    `json:"id"`
	ParentID  *string   `json:"parentId"`
	Timestamp string    `json:"timestamp"`
	Cwd       string    `json:"cwd"`
	Provider  string    `json:"provider"`
	ModelID   string    `json:"modelId"`
	Message   piMessage `json:"message"`
}

// piMessage carries Pi's AgentMessage union — every role (user, assistant,
// toolResult, bashExecution, custom, branchSummary, compactionSummary)
// arrives nested under the same "message" field of a top-level
// {"type":"message",...} entry. We decode the superset here and switch on
// Role downstream. See pi-coding-agent docs/session-format.md for the
// authoritative schema.
type piMessage struct {
	Role         string        `json:"role"`
	Content      []contentPart `json:"content"`
	API          string        `json:"api"`
	Provider     string        `json:"provider"`
	Model        string        `json:"model"`
	StopReason   string        `json:"stopReason"`
	ErrorMessage string        `json:"errorMessage"`
	Timestamp    int64         `json:"timestamp"`
	Usage        tokenUsage    `json:"usage"`
	ToolCallID   string        `json:"toolCallId"`
	ToolName     string        `json:"toolName"`
	IsError      bool          `json:"isError"`
	// bashExecution-only fields. Pi emits a separate message-role per
	// shell command (whether or not an LLM tool call invoked it) so users
	// can re-run from the TUI; exitCode is undefined while the command is
	// still running.
	Command   string `json:"command"`
	Output    string `json:"output"`
	ExitCode  *int   `json:"exitCode"`
	Cancelled bool   `json:"cancelled"`
	Truncated bool   `json:"truncated"`
}

type contentPart struct {
	Type              string         `json:"type"`
	Text              string         `json:"text"`
	Thinking          string         `json:"thinking"`
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Arguments         map[string]any `json:"arguments"`
	ThinkingSignature string         `json:"thinkingSignature"`
}

type tokenUsage struct {
	Input       int64 `json:"input"`
	Output      int64 `json:"output"`
	CacheRead   int64 `json:"cacheRead"`
	CacheWrite  int64 `json:"cacheWrite"`
	TotalTokens int64 `json:"totalTokens"`
	// Cost is Pi's per-message USD breakdown (per docs/session-format.md
	// Usage interface). Total is the canonical $ figure for the turn —
	// providers fold cache reads, prompt/output, and any reasoning fee
	// into it. We capture the breakdown so future dashboards can split
	// cache-read savings out, but only Total feeds EstimatedCostUSD today.
	Cost struct {
		Input      float64 `json:"input"`
		Output     float64 `json:"output"`
		CacheRead  float64 `json:"cacheRead"`
		CacheWrite float64 `json:"cacheWrite"`
		Total      float64 `json:"total"`
	} `json:"cost"`
}

type sessionContext struct {
	SessionID   string
	ProjectRoot string
	Provider    string
	Model       string
	// GitBranch / GitIdentity are resolved once from the `session` line's
	// cwd (see applySessionCwd) — pure file reads via git.ResolveIdentity,
	// never a forked git process (RootCommit stays nil, matching every
	// other hot-path adapter — goose, crush, primeagent). Empty/zero when
	// the cwd isn't inside a git working tree, exactly like every field
	// on git.Identity. GitIdentity.Remote already carries the normalized
	// "origin" remote (see stampToolEventIdentity's GitRemote sibling)
	// and is applied to every emitted event via adapter.ApplyProjectIdentity
	// before ParseSessionFile returns.
	GitBranch   string
	GitIdentity git.Identity
}

// applySessionCwd records cwd as the session's project root and resolves
// its git identity (branch + the full Project Identity Resolver v2
// bundle), used both by the main scan loop's `session` line and by
// recoverSessionState's pre-scan of an incremental reparse's already-
// consumed prefix — the ONLY two places Pi's `session` line is observed.
func applySessionCwd(cwd string, state *sessionContext) {
	if cwd == "" {
		return
	}
	state.ProjectRoot = cwd
	id := resolveGitIdentity(cwd)
	state.GitIdentity = id
	state.GitBranch = id.Branch
}

// resolveGitIdentity resolves the git project identity for a Pi session's
// raw cwd. Mirrors goose.Adapter.resolveProjectRoot / crush.Adapter.
// resolveProjectRoot: translate a foreign-mount path first, stat-gate it
// (a foreign path that isn't locally reachable is left alone — git.
// ResolveIdentity's internal filepath.Abs would otherwise CWD-prefix the
// observer's own repo onto it), then resolve. RootCommit stays nil: this
// runs on the hot parse path and must never fork a git process. Returns
// a zero Identity (never fabricated) when cwd is empty, unreachable, or
// not inside a git working tree.
func resolveGitIdentity(cwd string) git.Identity {
	wd := strings.TrimSpace(cwd)
	if wd == "" {
		return git.Identity{}
	}
	wd = crossmount.TranslateForeignPath(wd)
	if _, err := os.Stat(wd); err != nil {
		return git.Identity{}
	}
	identity, err := git.ResolveIdentity(wd, git.IdentityOptions{})
	if err != nil {
		return git.Identity{}
	}
	return identity
}

// ParseSessionFile implements adapter.Adapter.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("pi.ParseSessionFile: open %s: %w", path, err)
	}
	defer f.Close()

	if fromOffset > 0 {
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return adapter.ParseResult{}, fmt.Errorf("pi.ParseSessionFile: seek: %w", err)
		}
	}

	res := adapter.ParseResult{NewOffset: fromOffset}
	state := sessionContext{
		SessionID:   canonicalSessionID(path),
		ProjectRoot: "[pi]",
	}
	// On an incremental re-parse (fromOffset > 0) the `session` and
	// `model_change` header lines — which establish ProjectRoot, Provider and
	// Model — sit before fromOffset and the scanner seeks past them, stranding
	// every appended turn under the "[pi]" placeholder root (and, before
	// SessionID became path-derived, under a second filename-keyed session).
	// Recover that state from the already-consumed prefix first.
	if fromOffset > 0 {
		recoverSessionState(path, fromOffset, &state)
	}
	pending := map[string]int{}

	scanner := bufio.NewScanner(f)
	const maxLine = 16 * 1024 * 1024
	scanner.Buffer(make([]byte, 64*1024), maxLine)

	var bytesRead int64 = fromOffset
	lineNum := 0
	for scanner.Scan() {
		if ctx.Err() != nil {
			adapter.ApplyProjectIdentity(&res, state.GitIdentity)
			return res, ctx.Err()
		}
		raw := scanner.Bytes()
		bytesRead += int64(len(raw) + 1)
		lineNum++
		if len(raw) == 0 {
			continue
		}
		var line rawLine
		if err := json.Unmarshal(raw, &line); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
			res.NewOffset = bytesRead
			continue
		}
		res.NewOffset = bytesRead
		ts := parseTimestamp(line.Timestamp)

		switch line.Type {
		case "session":
			// SessionID is path-derived (canonicalSessionID) so it stays
			// stable across incremental re-parses that seek past this line —
			// do NOT adopt line.ID here. It equals the path's UUID anyway, and
			// adopting it is exactly what split appended turns into a second
			// filename-keyed session.
			applySessionCwd(line.Cwd, &state)
		case "model_change":
			state.Provider = line.Provider
			state.Model = line.ModelID
		case "message":
			a.parseMessageLine(path, line, lineNum, ts, &state, pending, &res)
		}
	}
	if err := scanner.Err(); err != nil {
		adapter.ApplyProjectIdentity(&res, state.GitIdentity)
		return res, fmt.Errorf("pi.ParseSessionFile: scan: %w", err)
	}
	adapter.ApplyProjectIdentity(&res, state.GitIdentity)
	return res, nil
}

func (a *Adapter) parseMessageLine(sourceFile string, line rawLine, lineNum int, ts time.Time, state *sessionContext, pending map[string]int, res *adapter.ParseResult) {
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
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile:         sourceFile,
			SourceEventID:      firstNonEmpty(line.ID, fmt.Sprintf("user:L%d", lineNum)),
			SessionID:          state.SessionID,
			ProjectRoot:        state.ProjectRoot,
			GitBranch:          state.GitBranch,
			GitRemote:          state.GitIdentity.Remote,
			Timestamp:          ts,
			Model:              modelName(state),
			Tool:               models.ToolPi,
			ActionType:         models.ActionUserPrompt,
			Target:             truncate(text, 200),
			Success:            true,
			PrecedingReasoning: truncate(text, 200),
			RawToolName:        "message.user",
			RawToolInput:       a.scrubber.String(text),
			MessageID:          userMessageID(line.ID, lineNum),
		})
	case "assistant":
		// REASONING SEMANTICS (B3 convergence, 2026-07-31): the model's
		// thinking is carried ONLY as PrecedingReasoning on the events it
		// precedes — the tool calls below and the terminal
		// `message.assistant.<stop>` row. It is deliberately NOT emitted as
		// a standalone task_complete row of its own: a reasoning block is
		// not an action, and the phantom rows it minted polluted every
		// action aggregate (see docs/plans/b3-reasoning-convergence-plan-
		// 2026-07-31.md §1). Pi's threading is FAN-OUT within the message:
		// one thinking block reaches every tool call of that assistant
		// message plus its terminus, because Pi carries the whole turn in
		// one record and there is no ordering between the blocks to
		// consume against.
		reasoning := messageThinking(msg.Content)
		assistantMessageID := assistantMessageID(line.ID, lineNum)
		for _, content := range msg.Content {
			if content.Type != "toolCall" {
				continue
			}
			ev := a.toolCallEvent(sourceFile, line, lineNum, ts, *state, content, reasoning, assistantMessageID)
			pending[content.ID] = len(res.ToolEvents)
			res.ToolEvents = append(res.ToolEvents, ev)
		}
		// Emit a task_complete for every TERMINAL stopReason — stop /
		// length / error / aborted. We deliberately skip "toolUse"
		// because that's a mid-turn pause to wait for a tool result, not
		// a turn end. Without this, dashboards saw zero failures even
		// when Pi spent tokens hitting a context-length cap or bailing
		// on a provider error. success = stopReason ∈ {stop, length}
		// since length is a non-error truncation; error/aborted are
		// failures.
		text := messageText(msg.Content)
		if isTerminalStopReason(msg.StopReason) {
			success := msg.StopReason == "stop" || msg.StopReason == "length"
			if msg.ErrorMessage != "" {
				success = false
			}
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile:         sourceFile,
				SourceEventID:      firstNonEmpty("complete:"+line.ID, fmt.Sprintf("complete:L%d", lineNum)),
				SessionID:          state.SessionID,
				ProjectRoot:        state.ProjectRoot,
				GitBranch:          state.GitBranch,
				GitRemote:          state.GitIdentity.Remote,
				Timestamp:          ts,
				Model:              modelName(state),
				Tool:               models.ToolPi,
				ActionType:         models.ActionTaskComplete,
				Target:             msg.StopReason,
				Success:            success,
				ErrorMessage:       truncate(msg.ErrorMessage, 500),
				PrecedingReasoning: truncate(firstNonEmpty(reasoning, text), 200),
				RawToolName:        "message.assistant." + msg.StopReason,
				ToolOutput:         a.scrubber.String(text),
				MessageID:          assistantMessageID,
			})
		}
		if msg.Usage.Input != 0 || msg.Usage.Output != 0 || msg.Usage.CacheRead != 0 || msg.Usage.CacheWrite != 0 {
			res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
				SourceFile:          sourceFile,
				SourceEventID:       firstNonEmpty("usage:"+line.ID, fmt.Sprintf("usage:L%d", lineNum)),
				SessionID:           state.SessionID,
				ProjectRoot:         state.ProjectRoot,
				GitBranch:           state.GitBranch,
				GitRemote:           state.GitIdentity.Remote,
				Timestamp:           ts,
				Tool:                models.ToolPi,
				Model:               modelName(state),
				InputTokens:         msg.Usage.Input,
				OutputTokens:        msg.Usage.Output,
				CacheReadTokens:     msg.Usage.CacheRead,
				CacheCreationTokens: msg.Usage.CacheWrite,
				EstimatedCostUSD:    msg.Usage.Cost.Total,
				Source:              models.TokenSourceJSONL,
				Reliability:         models.ReliabilityApproximate,
				MessageID:           assistantMessageID,
			})
		}
	case "toolResult":
		idx, ok := pending[msg.ToolCallID]
		if !ok {
			return
		}
		output := messageText(msg.Content)
		res.ToolEvents[idx].ToolOutput = a.scrubber.String(output)
		res.ToolEvents[idx].Success = !msg.IsError
		if msg.IsError {
			res.ToolEvents[idx].ErrorMessage = truncate(output, 500)
		}
	case "bashExecution":
		res.ToolEvents = append(res.ToolEvents, a.bashExecutionEvent(sourceFile, line, lineNum, ts, *state, msg))
	}
}

func (a *Adapter) toolCallEvent(sourceFile string, line rawLine, lineNum int, ts time.Time, state sessionContext, content contentPart, reasoning string, messageID string) models.ToolEvent {
	raw, _ := json.Marshal(content.Arguments)
	return models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      firstNonEmpty(content.ID, fmt.Sprintf("tool:%s:L%d", content.Name, lineNum)),
		SessionID:          state.SessionID,
		ProjectRoot:        state.ProjectRoot,
		GitBranch:          state.GitBranch,
		GitRemote:          state.GitIdentity.Remote,
		Timestamp:          ts,
		Model:              modelName(&state),
		Tool:               models.ToolPi,
		ActionType:         mapToolName(content.Name),
		Target:             truncate(targetFromArgs(content.Arguments, content.Name), 200),
		Success:            true,
		PrecedingReasoning: truncate(reasoning, 200),
		RawToolName:        content.Name,
		RawToolInput:       a.scrubber.RawJSON(raw),
		MessageID:          messageID,
	}
}

// bashExecutionEvent translates Pi's `bashExecution` message role (per
// docs/session-format.md BashExecutionMessage) into a ToolEvent. Note
// these messages can come from either the assistant calling the bash
// tool *or* the user running !-prefixed shell commands directly — both
// are surfaced as run_command actions. Cancelled commands are tagged
// failed even when exitCode is nil.
func (a *Adapter) bashExecutionEvent(sourceFile string, line rawLine, lineNum int, ts time.Time, state sessionContext, msg piMessage) models.ToolEvent {
	success := !msg.Cancelled && (msg.ExitCode == nil || *msg.ExitCode == 0)
	errMsg := ""
	switch {
	case msg.Cancelled:
		errMsg = "cancelled"
	case !success:
		errMsg = truncate(msg.Output, 500)
	}
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: firstNonEmpty("bash:"+line.ID, fmt.Sprintf("bash:L%d", lineNum)),
		SessionID:     state.SessionID,
		ProjectRoot:   state.ProjectRoot,
		GitBranch:     state.GitBranch,
		GitRemote:     state.GitIdentity.Remote,
		Timestamp:     ts,
		Model:         modelName(&state),
		Tool:          models.ToolPi,
		ActionType:    models.ActionRunCommand,
		Target:        truncate(msg.Command, 200),
		Success:       success,
		ErrorMessage:  errMsg,
		RawToolName:   "message.bashExecution",
		RawToolInput:  a.scrubber.String(msg.Command),
		ToolOutput:    a.scrubber.String(msg.Output),
		MessageID:     assistantMessageID(line.ID, lineNum),
	}
}

func messageText(contents []contentPart) string {
	var parts []string
	for _, c := range contents {
		if c.Type == "text" && strings.TrimSpace(c.Text) != "" {
			parts = append(parts, c.Text)
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func messageThinking(contents []contentPart) string {
	var parts []string
	for _, c := range contents {
		if c.Type == "thinking" && strings.TrimSpace(c.Thinking) != "" {
			parts = append(parts, c.Thinking)
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func mapToolName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "read", "cat", "view", "read_file", "open_file":
		return models.ActionReadFile
	case "write", "create", "write_file", "create_file":
		return models.ActionWriteFile
	case "edit", "patch", "replace", "apply_patch", "edit_file":
		return models.ActionEditFile
	case "bash", "shell", "command", "exec", "execute", "run",
		"powershell", "pwsh", "cmd", "cmd.exe":
		return models.ActionRunCommand
	case "grep", "search", "find_text", "find_in_files":
		return models.ActionSearchText
	case "find", "ls", "glob", "list_files", "file_search":
		return models.ActionSearchFiles
	case "web_search":
		return models.ActionWebSearch
	case "web_fetch", "fetch", "fetch_url":
		return models.ActionWebFetch
	default:
		// mcp__<server>__<tool> external MCP calls: label them MCP so the
		// dashboard surfaces them (identity stays in the raw tool name).
		if models.IsMCPToolName(name) {
			return models.ActionMCPCall
		}
		return models.ActionUnknown
	}
}

func targetFromArgs(args map[string]any, fallback string) string {
	for _, key := range []string{"path", "file", "filePath", "command", "cmd", "pattern"} {
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

// defaultRoots returns Pi's agent/sessions subpath under every
// cross-mount-resolved $HOME so observer in WSL2 picks up sessions
// from /mnt/c/Users/<u>/.pi (and vice-versa). The subpath is uniform
// across OSes.
func defaultRoots() []string {
	var roots []string
	for _, h := range crossmount.AllHomes() {
		roots = append(roots, filepath.Join(h.Path, ".pi", "agent", "sessions"))
	}
	return roots
}

// canonicalSessionID derives a stable session id from the Pi session file
// path. Pi names files "<timestamp>_<uuid>.jsonl" (e.g.
// "2026-06-26T21-09-23-295Z_019f05c4-10dc-72de-8382-4991c000af2d.jsonl"); the
// trailing UUID equals the `session` line's id. Deriving it from the path
// makes the id stable across incremental re-parses (which seek past the
// `session` line) instead of falling back to the full timestamp-prefixed
// basename — the cause of the duplicate "<ts>_<uuid>" session. Falls back to
// the full basename when the suffix is not a UUID.
func canonicalSessionID(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if i := strings.LastIndexByte(base, '_'); i >= 0 && i+1 < len(base) {
		if cand := base[i+1:]; looksLikeUUID(cand) {
			return cand
		}
	}
	return base
}

// looksLikeUUID reports whether s is a canonical 8-4-4-4-12 hex UUID
// (RFC 4122 / UUIDv7 layout — Pi uses UUIDv7 session ids).
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// recoverSessionState pre-scans the already-consumed prefix [0, until) of an
// incrementally-parsed Pi session file to recover the session-level state the
// header lines carry: the working directory (`session`.cwd → ProjectRoot,
// resolved to a git identity via applySessionCwd) and the active model
// (`model_change` → Provider/Model). Without it, turns appended after the
// first parse land under the "[pi]" placeholder root with no git identity.
// The scan stops at `until` so a model_change AFTER the cursor is left to
// the main loop (which applies it in order). Best-effort: any open/parse
// error leaves state at its defaults.
func recoverSessionState(path string, until int64, state *sessionContext) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	const maxLine = 16 * 1024 * 1024
	scanner.Buffer(make([]byte, 64*1024), maxLine)

	var pos int64
	for scanner.Scan() {
		raw := scanner.Bytes()
		pos += int64(len(raw) + 1)
		if len(raw) > 0 {
			var line rawLine
			if json.Unmarshal(raw, &line) == nil {
				switch line.Type {
				case "session":
					applySessionCwd(line.Cwd, state)
				case "model_change":
					state.Provider = line.Provider
					state.Model = line.ModelID
				}
			}
		}
		if pos >= until {
			break
		}
	}
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

// isTerminalStopReason reports whether the assistant's stopReason
// signals the turn has actually ended. "toolUse" is excluded because
// that's a mid-turn pause to await a tool result.
func isTerminalStopReason(reason string) bool {
	switch reason {
	case "stop", "length", "error", "aborted":
		return true
	default:
		return false
	}
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
