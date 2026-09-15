package grok

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Compile-time assertion that *Adapter satisfies the base adapter
// contract. The TranscriptReader / FullTranscriptReader capabilities
// (transcript.go) are dispatched by capability shape at the handoff
// boundary and asserted there.
var _ adapter.Adapter = (*Adapter)(nil)

// Adapter parses xAI's Grok Build terminal agent (binary `grok`,
// models.ToolGrok). See the package doc for the two-source capture model:
// the per-session ACP `updates.jsonl` stream yields ToolEvents, and the
// GLOBAL `logs/unified.jsonl` diagnostic log yields accurate per-request
// TokenEvents correlated to sessions by its `sid` key.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and platform-default
// cross-mount watch roots (~/.grok/sessions and ~/.grok/logs under every
// resolved $HOME).
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots()}
}

// NewWithOptions customizes the scrubber and/or watch roots for tests. A
// nil scrubber falls back to scrub.New(); no roots falls back to the
// platform defaults.
func NewWithOptions(s *scrub.Scrubber, roots ...string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{scrubber: s, roots: roots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolGrok }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// defaultRoots returns ~/.grok/sessions and ~/.grok/logs under every
// cross-mount-resolved $HOME, so a WSL2 observer picks up Windows-side
// sessions on /mnt/c/Users/<u>/.grok and vice versa.
func defaultRoots() []string {
	var roots []string
	for _, h := range crossmount.AllHomes() {
		roots = append(
			roots,
			filepath.Join(h.Path, ".grok", "sessions"),
			filepath.Join(h.Path, ".grok", "logs"),
		)
	}
	return roots
}

// IsSessionFile implements adapter.Adapter. Two file shapes qualify, each
// ANDed with under-watch-root (a shape match alone is not enough — the
// watcher dispatches by root):
//
//   - a session bundle's ACP stream `.grok/sessions/<enc-cwd>/<uuid>/updates.jsonl`
//     (the ToolEvent source; the sibling chat_history/events/summary files
//     are intentionally NOT claimed to avoid double-emitting), and
//   - the global `.grok/logs/unified.jsonl` (the TokenEvent source).
func (a *Adapter) IsSessionFile(path string) bool {
	if !matchesShape(path) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// matchesShape reports whether path is a grok updates.jsonl session stream
// or the global unified.jsonl log, independent of watch roots. Comparison
// is slash-normalized + lower-cased so Windows separators and
// case-insensitive mounts match too.
func matchesShape(path string) bool {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	base := filepath.Base(lower)
	if base == "updates.jsonl" {
		return strings.Contains(lower, "/.grok/sessions/")
	}
	if base == "unified.jsonl" {
		return strings.Contains(lower, "/.grok/logs/")
	}
	return false
}

// isUnifiedLog reports whether path is the global unified.jsonl token log.
func isUnifiedLog(path string) bool {
	return strings.EqualFold(filepath.Base(path), "unified.jsonl")
}

// ParseSessionFile implements adapter.Adapter. It dispatches on the file
// shape: unified.jsonl → TokenEvents (per-request splits keyed by sid);
// a session updates.jsonl → ToolEvents. Both stream from fromOffset to
// EOF via bufio.Reader.ReadString, advance the byte cursor past every
// fully terminated line (so a malformed line can't stall the poll loop),
// and defer a partial trailing line.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path) //nolint:gosec // path derives from a validated watch root
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("grok.ParseSessionFile: open %s: %w", path, err)
	}
	defer f.Close()

	if fromOffset > 0 {
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return adapter.ParseResult{}, fmt.Errorf("grok.ParseSessionFile: seek: %w", err)
		}
	}

	unified := isUnifiedLog(path)
	res := adapter.ParseResult{NewOffset: fromOffset}
	st := &parseState{
		adapter:     a,
		path:        path,
		firstOffset: fromOffset,
		metaCache:   map[string]*sessionMeta{},
	}
	if !unified {
		st.summary = a.loadSummary(path)
	}

	reader := bufio.NewReaderSize(f, 64*1024)
	bytesRead := fromOffset
	lineNum := 0
	for {
		if ctx.Err() != nil {
			st.applyIdentities(&res)
			return res, ctx.Err()
		}
		lineStr, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			st.applyIdentities(&res)
			return res, fmt.Errorf("grok.ParseSessionFile: read: %w", readErr)
		}
		hasNewline := strings.HasSuffix(lineStr, "\n")
		// A partial trailing line (no '\n' at EOF) is still being written:
		// defer it and do NOT advance the cursor past it.
		if !hasNewline && readErr == io.EOF {
			break
		}
		bytesRead += int64(len(lineStr))
		lineNum++
		// Commit the offset for every terminated line — even empty or
		// malformed — so the poll loop can't spin on a bad line.
		res.NewOffset = bytesRead

		raw := strings.TrimRight(lineStr, "\r\n")
		if raw == "" {
			if readErr == io.EOF {
				break
			}
			continue
		}
		if unified {
			a.handleUnified(st, raw, lineNum, &res)
		} else {
			a.handleUpdate(st, raw, lineNum, &res)
		}
		if readErr == io.EOF {
			break
		}
	}
	st.applyIdentities(&res)
	return res, nil
}

// applyIdentities backfills the Project Identity Resolver v2 bundle onto
// every event in res, keyed by resolved project root. A grok session
// carries at most one sessionMeta in the non-unified case (st.summary)
// but the unified log shape can multiplex several sessions (and thus
// several distinct project roots) into one file, hence metaCache.
func (st *parseState) applyIdentities(res *adapter.ParseResult) {
	byRoot := map[string]git.Identity{}
	if st.summary != nil && st.summary.projectRoot != "" {
		byRoot[st.summary.projectRoot] = st.summary.identity
	}
	for _, m := range st.metaCache {
		if m != nil && m.projectRoot != "" {
			byRoot[m.projectRoot] = m.identity
		}
	}
	adapter.ApplyProjectIdentityByRoot(res, byRoot)
}

// parseState carries the per-call mutable bookkeeping the handlers need.
type parseState struct {
	adapter     *Adapter
	path        string
	firstOffset int64

	// summary is the session bundle's summary.json (model / project-root /
	// branch seam), loaded once per updates.jsonl parse. Nil when absent.
	summary *sessionMeta

	// lastModel is the most recent model id seen on a user_message_chunk,
	// used to stamp assistant/tool events that omit it.
	lastModel string
	// pendingReasoning holds an agent_thought_chunk's text until the next
	// assistant message or tool call consumes it as PrecedingReasoning.
	pendingReasoning string
	// pendingCall maps a toolCallId to the index of its ToolEvent so a
	// later tool_call_update can stamp success/output onto it.
	pendingCall map[string]int
	// sessionStarted guards against emitting more than one session-start
	// marker per parse call.
	sessionStarted bool

	// metaCache memoizes sid → session metadata for the unified.jsonl path
	// (each inference_done record re-resolves the owning session).
	metaCache map[string]*sessionMeta
}

// sessionMeta is the resolved model + project-root + branch + remote for a
// session.
type sessionMeta struct {
	model       string
	projectRoot string
	gitBranch   string
	gitRemote   string
	// identity is the Project Identity Resolver v2 bundle (2026-09-06,
	// §3.1 / W1) resolved alongside gitBranch/gitRemote by
	// resolveProjectRoot, applied to every event in the ParseResult via
	// adapter.ApplyProjectIdentity before ParseSessionFile returns.
	identity git.Identity
	// effortLevel is the session's reasoning-effort SETTING
	// (summary.json's `reasoning_effort`, e.g. "low"/"medium"/"high") —
	// a session-wide config knob, not per-turn reasoning content.
	// Threaded into ActionMetadata.EffortLevel at every emission site,
	// mirroring how model/gitBranch/gitRemote already ride sessionMeta.
	effortLevel string
}

// loadSummary reads and resolves the summary.json sibling of an
// updates.jsonl path. Returns nil when the file is absent or unreadable —
// the parser still emits events with an empty project root rather than
// dropping them.
func (a *Adapter) loadSummary(updatesPath string) *sessionMeta {
	dir := filepath.Dir(updatesPath)
	return a.resolveMeta(filepath.Join(dir, "summary.json"))
}

// resolveMeta reads a summary.json and resolves its model + project root
// + branch. The project root prefers git_root_dir, falling back to the
// session cwd; foreign-OS paths are translated + stat-gated BEFORE
// git.Resolve so filepath.Abs never prefixes the observer's own repo.
func (a *Adapter) resolveMeta(summaryPath string) *sessionMeta {
	body, err := os.ReadFile(summaryPath) //nolint:gosec // path derives from a validated watch root
	if err != nil {
		return nil
	}
	var s sessionSummary
	if err := json.Unmarshal(body, &s); err != nil {
		return nil
	}
	m := &sessionMeta{model: s.CurrentModelID, gitBranch: s.HeadBranch, effortLevel: strings.TrimSpace(s.ReasoningEffort)}
	m.projectRoot, m.gitRemote, m.identity = resolveProjectRoot(s.GitRootDir, s.Info.Cwd)
	return m
}

// effortMetadata folds a session's reasoning-effort SETTING into an
// ActionMetadata, returning nil when the session never surfaced one (so
// rows from summary-less or effort-less sessions keep a NULL metadata
// column rather than an empty-but-allocated one).
func effortMetadata(effort string) *models.ActionMetadata {
	if effort == "" {
		return nil
	}
	return &models.ActionMetadata{EffortLevel: effort}
}

// resolveProjectRoot resolves a session's project root (and its normalized
// git remote) from its git_root_dir (primary) or cwd (fallback),
// translating a foreign-OS path and stat-gating it before git.Resolve.
func resolveProjectRoot(gitRootDir, cwd string) (root, remote string, id git.Identity) {
	candidate := strings.TrimSpace(gitRootDir)
	if candidate == "" {
		candidate = strings.TrimSpace(cwd)
	}
	if candidate == "" {
		return "", "", git.Identity{}
	}
	candidate = crossmount.TranslateForeignPath(candidate)
	if _, err := os.Stat(candidate); err != nil {
		// The path doesn't exist on this host (a foreign path we couldn't
		// translate): return it verbatim rather than letting git.Resolve
		// CWD-prefix the observer's own root onto it.
		return filepath.Clean(candidate), "", git.Identity{}
	}
	identity, err := git.ResolveIdentity(candidate, git.IdentityOptions{})
	if err != nil {
		return filepath.Clean(candidate), "", git.Identity{}
	}
	// identity.Remote is already NormalizeRemote'd by ResolveIdentity.
	return identity.Root, identity.Remote, identity
}

// meta returns the resolved metadata for the current updates.jsonl parse,
// or an empty struct when summary.json was absent.
func (st *parseState) meta() *sessionMeta {
	if st.summary != nil {
		return st.summary
	}
	return &sessionMeta{}
}

// modelFor prefers the per-turn model observed on the stream, falling back
// to the session summary's current model.
func (st *parseState) modelFor() string {
	if st.lastModel != "" {
		return st.lastModel
	}
	return st.meta().model
}

// handleUpdate decodes one updates.jsonl ACP line and dispatches it.
func (a *Adapter) handleUpdate(st *parseState, raw string, lineNum int, res *adapter.ParseResult) {
	var line acpLine
	if err := json.Unmarshal([]byte(raw), &line); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
		return
	}
	u := line.Params.Update
	if line.Params.SessionID == "" || u.SessionUpdate == "" {
		return
	}
	if u.Meta != nil && u.Meta.ModelID != "" {
		st.lastModel = u.Meta.ModelID
	}
	switch u.SessionUpdate {
	case "user_message_chunk":
		st.emitUserPrompt(&line, res)
	case "agent_thought_chunk":
		if t := u.Content.firstText(); t != "" {
			st.pendingReasoning = strings.TrimSpace(t)
		}
	case "agent_message_chunk":
		st.emitAssistantMessage(&line, res)
	case "tool_call":
		st.emitToolCall(&line, res)
	case "tool_call_update":
		st.applyToolUpdate(&line, res)
	}
}

// eventID returns grok's stable eventId, or a deterministic synthesized
// id (sessionId + line number) when a record omits it.
func (st *parseState) eventID(line *acpLine, lineNum int) string {
	if line.Params.Meta.EventID != "" {
		return line.Params.Meta.EventID
	}
	return line.Params.SessionID + ":L" + strconv.Itoa(lineNum)
}

// tsFor returns a record's wall-clock timestamp from agentTimestampMs,
// falling back to the outer unix-seconds `timestamp`.
func tsFor(line *acpLine) time.Time {
	if ms := line.Params.Meta.AgentTimestampMs; ms > 0 {
		return msToTime(ms)
	}
	if line.Timestamp > 0 {
		return msToTime(line.Timestamp * 1000)
	}
	return time.Time{}
}

// emitUserPrompt records a user prompt and, on the first user message of a
// freshly-parsed file, a session-start marker.
func (st *parseState) emitUserPrompt(line *acpLine, res *adapter.ParseResult) {
	m := st.meta()
	ts := tsFor(line)
	if st.firstOffset == 0 && !st.sessionStarted {
		st.sessionStarted = true
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile:    st.path,
			SourceEventID: "session_start:" + line.Params.SessionID,
			SessionID:     line.Params.SessionID,
			ProjectRoot:   m.projectRoot,
			Timestamp:     ts,
			GitBranch:     m.gitBranch,
			GitRemote:     m.gitRemote,
			Model:         st.modelFor(),
			Tool:          models.ToolGrok,
			ActionType:    models.ActionSessionStart,
			Target:        "startup",
			RawToolName:   "grok.session_start",
			Success:       true,
			Metadata:      effortMetadata(m.effortLevel),
		})
	}
	text := strings.TrimSpace(line.Params.Update.Content.firstText())
	if text == "" {
		return
	}
	scrubbed := st.adapter.scrubber.String(text)
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: st.eventID(line, 0),
		SessionID:     line.Params.SessionID,
		ProjectRoot:   m.projectRoot,
		Timestamp:     ts,
		GitBranch:     m.gitBranch,
		GitRemote:     m.gitRemote,
		Model:         st.modelFor(),
		Tool:          models.ToolGrok,
		ActionType:    models.ActionUserPrompt,
		Target:        truncate(scrubbed, 200),
		RawToolName:   "grok.user_prompt",
		RawToolInput:  scrubbed,
		Success:       true,
		Metadata:      effortMetadata(m.effortLevel),
	})
	// A new user turn clears any dangling reasoning from a prior turn.
	st.pendingReasoning = ""
}

// emitAssistantMessage records an agent_message_chunk as an assistant
// message, attaching any pending agent_thought_chunk as reasoning.
func (st *parseState) emitAssistantMessage(line *acpLine, res *adapter.ParseResult) {
	text := strings.TrimSpace(line.Params.Update.Content.firstText())
	if text == "" {
		return
	}
	m := st.meta()
	scrubbed := st.adapter.scrubber.String(text)
	ev := models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: st.eventID(line, 0),
		SessionID:     line.Params.SessionID,
		ProjectRoot:   m.projectRoot,
		Timestamp:     tsFor(line),
		GitBranch:     m.gitBranch,
		GitRemote:     m.gitRemote,
		Model:         st.modelFor(),
		Tool:          models.ToolGrok,
		ActionType:    models.ActionAssistantMessage,
		Target:        truncate(scrubbed, 200),
		RawToolName:   "grok.assistant_message",
		ToolOutput:    st.adapter.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes)),
		Success:       true,
		Metadata:      effortMetadata(m.effortLevel),
	}
	if st.pendingReasoning != "" {
		ev.PrecedingReasoning = st.adapter.scrubber.String(st.pendingReasoning)
		st.pendingReasoning = ""
	}
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitToolCall records a tool_call as a normalized ToolEvent. Success is
// optimistic until the paired tool_call_update stamps a terminal status.
func (st *parseState) emitToolCall(line *acpLine, res *adapter.ParseResult) {
	u := line.Params.Update
	m := st.meta()
	scrubbedInput := st.adapter.scrubber.RawJSON(u.RawInput)
	target := st.adapter.scrubber.String(targetFromRawInput(u.RawInput, u.Title))
	ev := models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: st.eventID(line, 0),
		SessionID:     line.Params.SessionID,
		ProjectRoot:   m.projectRoot,
		Timestamp:     tsFor(line),
		GitBranch:     m.gitBranch,
		GitRemote:     m.gitRemote,
		Model:         st.modelFor(),
		Tool:          models.ToolGrok,
		ActionType:    mapToolName(u.Title),
		Target:        target,
		RawToolName:   u.Title,
		RawToolInput:  scrubbedInput,
		Success:       true,
		Metadata:      effortMetadata(m.effortLevel),
	}
	if st.pendingReasoning != "" {
		ev.PrecedingReasoning = st.adapter.scrubber.String(st.pendingReasoning)
		st.pendingReasoning = ""
	}
	idx := len(res.ToolEvents)
	res.ToolEvents = append(res.ToolEvents, ev)
	if u.ToolCallID != "" {
		if st.pendingCall == nil {
			st.pendingCall = map[string]int{}
		}
		st.pendingCall[u.ToolCallID] = idx
	}
}

// applyToolUpdate stamps a terminal status and/or scrubbed output onto the
// ToolEvent its tool_call created. Grok emits several tool_call_update
// records per call (an in-progress title refinement, then a terminal
// status); only the status-bearing / output-bearing ones mutate the event.
func (st *parseState) applyToolUpdate(line *acpLine, res *adapter.ParseResult) {
	u := line.Params.Update
	if st.pendingCall == nil {
		return
	}
	idx, ok := st.pendingCall[u.ToolCallID]
	if !ok || idx >= len(res.ToolEvents) {
		// No cross-tick ActionOutcomeUpdate here, unlike the CC-shaped
		// adapters: a grok action's SourceEventID is the ACP line's
		// _meta.eventId (st.eventID(line, 0)), NOT the toolCallId, so
		// the update's (source_file, source_event_id) key cannot be
		// reconstructed from an update record alone. Exposure is low —
		// tool_call and its updates arrive milliseconds apart on the
		// same ACP stream, so a poll tick rarely splits them.
		return
	}
	ev := &res.ToolEvents[idx]
	if u.Status != "" {
		ev.Success = isSuccessStatus(u.Status)
	}
	// Prefer the array-shaped `content` output blocks (clean, pre-rendered
	// text — live shape 2026-07-09) and fall back to the rawOutput wrapper
	// (which on some tools is a raw byte array, not readable text).
	out := u.Content.joinedText()
	if out == "" {
		out = rawOutputText(u.RawOutput)
	}
	if out != "" {
		scrubbed := st.adapter.scrubber.String(contentcap.Cap(out, contentcap.DefaultMaxBytes))
		ev.ToolOutput = scrubbed
		if !ev.Success {
			ev.ErrorMessage = truncate(scrubbed, 500)
		}
	}
}

// isSuccessStatus maps grok's tool_call_update status vocabulary to a
// boolean. "completed" is success; "failed"/"cancelled"/"error" are not.
func isSuccessStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "success", "ok", "done":
		return true
	default:
		return false
	}
}

// handleUnified decodes one unified.jsonl line and, for an
// `shell.turn.inference_done` record, emits a TokenEvent correlated to its
// session by the `sid` key. Every other msg value is skipped silently
// (the log is dominated by unrelated diagnostics).
func (a *Adapter) handleUnified(st *parseState, raw string, _ int, res *adapter.ParseResult) {
	var line unifiedLine
	if err := json.Unmarshal([]byte(raw), &line); err != nil {
		// The diagnostic log carries many shapes; a decode miss on a
		// non-token line is expected noise, not a warning.
		return
	}
	if line.Msg != inferenceDoneMsg || line.Sid == "" {
		return
	}
	tp := tokenBundle(line.Ctx)
	if tp.inputNet == 0 && tp.output == 0 && tp.cacheRead == 0 && tp.reasoning == 0 {
		return
	}
	meta := st.unifiedMeta(line.Sid)
	res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
		SourceFile:      st.path,
		SourceEventID:   fmt.Sprintf("tok:%s:%s:%d", line.Sid, line.Ts, line.Ctx.LoopIndex),
		SessionID:       line.Sid,
		ProjectRoot:     meta.projectRoot,
		GitBranch:       meta.gitBranch,
		GitRemote:       meta.gitRemote,
		Timestamp:       parseUnifiedTS(line.Ts),
		Tool:            models.ToolGrok,
		Model:           meta.model,
		InputTokens:     tp.inputNet,
		OutputTokens:    tp.output,
		CacheReadTokens: tp.cacheRead,
		ReasoningTokens: tp.reasoning,
		Source:          models.TokenSourceJSONL,
		Reliability:     models.ReliabilityApproximate,
	})
}

// unifiedMeta resolves (model / project-root / branch) for a unified.jsonl
// sid by globbing the sibling session bundle's summary.json, memoized per
// sid. unified.jsonl carries no per-turn model, so the session-level model
// from summary.json is used for every token row of that session.
func (st *parseState) unifiedMeta(sid string) *sessionMeta {
	if m, ok := st.metaCache[sid]; ok {
		return m
	}
	m := st.adapter.summaryForSID(st.path, sid)
	if m == nil {
		m = &sessionMeta{}
	}
	st.metaCache[sid] = m
	return m
}

// summaryForSID locates a session's summary.json given a unified.jsonl
// path and the session id. grokHome is the unified log's grandparent
// (<home>/.grok/logs/unified.jsonl → <home>/.grok), so the glob stays on
// the same mount as the log being parsed. Returns nil when no bundle is
// found.
func (a *Adapter) summaryForSID(unifiedPath, sid string) *sessionMeta {
	grokHome := filepath.Dir(filepath.Dir(unifiedPath))
	matches, err := filepath.Glob(filepath.Join(grokHome, "sessions", "*", sid, "summary.json"))
	if err != nil || len(matches) == 0 {
		return nil
	}
	return a.resolveMeta(matches[0])
}
