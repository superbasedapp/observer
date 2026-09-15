package kimicode

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter parses Moonshot AI kimi-code CLI session traces under
// ~/.kimi-code/sessions/wd_<slug>_<hash>/session_<uuid>/agents/<name>/wire.jsonl.
// See the package doc for the wire-event shapes and the token /
// project-root resolution model.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and platform-default
// cross-mount watch roots (~/.kimi-code/sessions under every resolved
// $HOME).
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
func (*Adapter) Name() string { return models.ToolKimiCode }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. A path qualifies only when it
// is BOTH under one of this adapter's watch roots AND matches the
// kimi-code wire-trace shape (`.kimi-code/sessions/.../wire.jsonl`).
func (a *Adapter) IsSessionFile(path string) bool {
	if !matchesShape(path) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// matchesShape reports whether path has the kimi-code wire-trace shape,
// independent of watch roots. Comparison is on a slash-normalized,
// lower-cased copy so Windows separators and case-insensitive mounts
// match too.
func matchesShape(path string) bool {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	if filepath.Base(lower) != "wire.jsonl" {
		return false
	}
	// Structural shape `.../sessions/.../agents/<name>/wire.jsonl`. The
	// install root (~/.kimi-code/sessions) is enforced separately by
	// IsSessionFile's UnderAnyWatchRoot gate, so the shape need only
	// distinguish a wire trace from other files under the root.
	return strings.Contains(lower, "/sessions/") && strings.Contains(lower, "/agents/")
}

// defaultRoots returns ~/.kimi-code/sessions under every cross-mount-
// resolved $HOME so a WSL2 observer picks up Windows-side sessions on
// /mnt/c/Users/<u>/.kimi-code and vice versa. kimi-code uses the same
// ~/.kimi-code layout on every OS (not %APPDATA%).
//
// $KIMI_CODE_HOME wins on the native side when set: the kimi-code bundle
// resolves its own storage root from KIMI_CODE_HOME before falling back
// to os.homedir()/.kimi-code, so an operator who relocated the home sees
// their traces under $KIMI_CODE_HOME/sessions and nowhere else. Like
// clinecli's CLINE_DIR handling, the env var is only meaningful for THIS
// process's environment, so it is not re-resolved per cross-mount home —
// the per-home defaults below still contribute their own
// `.kimi-code/sessions` paths. The value is absolutized before use (see
// adapter.AbsEnvRoot) so a relative KIMI_CODE_HOME can never become a relative
// watch root. Empty/duplicate candidates are dropped so WatchPaths never
// carries the same directory twice.
func defaultRoots() []string {
	var roots []string
	seen := map[string]struct{}{}
	add := func(p string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		roots = append(roots, p)
	}

	if home := adapter.AbsEnvRoot("KIMI_CODE_HOME"); home != "" {
		add(filepath.Join(home, "sessions"))
	}
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(h.Path, ".kimi-code", "sessions"))
	}
	return roots
}

// ParseSessionFile implements adapter.Adapter. It streams the wire JSONL
// from fromOffset to EOF, emitting ToolEvents (a session-start marker,
// user prompts, assistant text, tool calls with their results) and
// TokenEvents (from usage.record events). Malformed lines are skipped
// with a warning; the byte cursor advances past every fully terminated
// line so repeated calls make progress.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path) //nolint:gosec // path is a watcher-supplied session file under a watch root
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("kimicode.ParseSessionFile: open %s: %w", path, err)
	}
	defer f.Close()

	if fromOffset > 0 {
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return adapter.ParseResult{}, fmt.Errorf("kimicode.ParseSessionFile: seek: %w", err)
		}
	}

	st := &parseState{
		adapter:     a,
		path:        path,
		sessionID:   sessionIDFromPath(path),
		isSidechain: agentNameFromPath(path) != "main" && agentNameFromPath(path) != "",
		firstOffset: fromOffset,
		pendingCall: map[string]int{},
	}

	res := adapter.ParseResult{NewOffset: fromOffset}

	// bufio.Reader.ReadString (not Scanner) so the byte cursor advances by
	// the exact terminator length including CRLF, and long tool-output
	// lines aren't capped by a token-size limit.
	reader := bufio.NewReaderSize(f, 64*1024)
	bytesRead := fromOffset
	lineNum := 0
	for {
		if ctx.Err() != nil {
			adapter.ApplyProjectIdentity(&res, st.identity)
			return res, ctx.Err()
		}
		lineStr, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			adapter.ApplyProjectIdentity(&res, st.identity)
			return res, fmt.Errorf("kimicode.ParseSessionFile: read: %w", readErr)
		}
		hasNewline := strings.HasSuffix(lineStr, "\n")
		// A partial trailing line (no '\n' at EOF) is a still-being-written
		// record: defer it, do NOT advance the cursor past it.
		if !hasNewline && readErr == io.EOF {
			break
		}
		bytesRead += int64(len(lineStr))
		lineNum++
		// Commit the offset for every terminated line, even empty/malformed
		// ones, so the poll loop can't spin on a bad line.
		res.NewOffset = bytesRead

		raw := strings.TrimRight(lineStr, "\r\n")
		if raw == "" {
			if readErr == io.EOF {
				break
			}
			continue
		}
		var line wireLine
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
			if readErr == io.EOF {
				break
			}
			continue
		}
		st.handle(&line, raw, &res)
		if readErr == io.EOF {
			break
		}
	}
	st.flagPendingOutcomes(&res)
	adapter.ApplyProjectIdentity(&res, st.identity)
	return res, nil
}

// flagPendingOutcomes marks every tool call still waiting for its result
// at EOF. Its Success=true is a placeholder, so the store holds
// failure-context bookkeeping for the row until the matching
// ActionOutcomeUpdate reports the real outcome.
func (st *parseState) flagPendingOutcomes(res *adapter.ParseResult) {
	for _, idx := range st.pendingCall {
		if idx < len(res.ToolEvents) {
			res.ToolEvents[idx].OutcomePending = true
		}
	}
}

// parseState carries the per-call mutable bookkeeping the line handler
// needs across lines.
type parseState struct {
	adapter     *Adapter
	path        string
	sessionID   string
	isSidechain bool
	firstOffset int64

	// lastModel is the most recently observed model id (from llm.request /
	// usage.record), stamped onto tool + token events that carry none of
	// their own.
	lastModel string
	// pendingCall maps a tool.call toolCallId to the index of its ToolEvent
	// in res.ToolEvents, so the later tool.result can stamp
	// success/output onto it.
	pendingCall map[string]int
	// sessionStarted guards against emitting more than one session-start
	// marker per parse call.
	sessionStarted bool

	// rootResolved memoizes the project-root/branch resolution (state.json
	// read + git.Resolve) so it runs at most once per parse call.
	rootResolved bool
	resolvedRoot string
	gitBranch    string
	gitRemote    string
	// identity is the Project Identity Resolver v2 bundle (2026-09-06,
	// §3.1 / W1) resolved alongside gitBranch/gitRemote, applied to
	// every event in the ParseResult via adapter.ApplyProjectIdentity
	// before ParseSessionFile returns.
	identity git.Identity
	// lastCwd is a project-root fallback lifted from a tool.call display
	// hint when the sibling state.json is unavailable.
	lastCwd string
}

// handle dispatches one wire line onto the appropriate emit path. raw is
// the exact line bytes (used to synthesize deterministic ids for events
// with no native id).
func (st *parseState) handle(line *wireLine, raw string, res *adapter.ParseResult) {
	switch line.Type {
	case "metadata":
		st.emitSessionStart(line, res)
	case "turn.prompt":
		st.emitUserPrompt(line, raw, res)
	case "llm.request":
		if m := normalizeModel(firstNonEmpty(line.Model, line.ModelAlias)); m != "" {
			st.lastModel = m
		}
	case "usage.record":
		if m := normalizeModel(line.Model); m != "" {
			st.lastModel = m
		}
		st.emitToken(line, raw, res)
	case "context.append_loop_event":
		st.handleLoopEvent(line, res)
	}
}

// handleLoopEvent dispatches the `event` body of a
// context.append_loop_event by its own type.
func (st *parseState) handleLoopEvent(line *wireLine, res *adapter.ParseResult) {
	if len(line.Event) == 0 {
		return
	}
	var ev loopEvent
	if err := json.Unmarshal(line.Event, &ev); err != nil {
		return
	}
	switch ev.Type {
	case "tool.call":
		st.emitToolCall(&ev, line.Time, res)
	case "tool.result":
		st.applyToolResult(&ev, res)
	case "content.part":
		st.emitAssistantText(&ev, line.Time, res)
		// step.begin / step.end are structural; step.end.usage duplicates
		// the usage.record line (same counts), so tokens are emitted only
		// from usage.record to avoid double-counting.
	}
}

// emitSessionStart records a session-start marker exactly once, only when
// parsing from the very top of the file (the metadata line is line 1).
func (st *parseState) emitSessionStart(line *wireLine, res *adapter.ParseResult) {
	if st.firstOffset != 0 || st.sessionStarted {
		return
	}
	st.sessionStarted = true
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: "session_start:" + st.sessionID,
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot(),
		GitBranch:     st.gitBranch,
		GitRemote:     st.gitRemote,
		Timestamp:     unixMillis(line.CreatedAt),
		Tool:          models.ToolKimiCode,
		ActionType:    models.ActionSessionStart,
		Target:        "startup",
		RawToolName:   models.ToolKimiCode + ".session_start",
		IsSidechain:   st.isSidechain,
		Success:       true,
	})
}

// emitUserPrompt records a real user prompt (origin.kind == "user"),
// skipping injected system-reminder prompts.
func (st *parseState) emitUserPrompt(line *wireLine, raw string, res *adapter.ParseResult) {
	if line.Origin != nil && line.Origin.Kind != "" && line.Origin.Kind != "user" {
		return
	}
	text := promptText(line.Input)
	if text == "" {
		return
	}
	scrubbed := st.adapter.scrubber.String(text)
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: "prompt:" + hashID(raw),
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot(),
		GitBranch:     st.gitBranch,
		GitRemote:     st.gitRemote,
		Timestamp:     unixMillis(line.Time),
		Tool:          models.ToolKimiCode,
		ActionType:    models.ActionUserPrompt,
		Target:        truncate(scrubbed, 200),
		RawToolName:   models.ToolKimiCode + ".user_prompt",
		RawToolInput:  scrubbed,
		IsSidechain:   st.isSidechain,
		Success:       true,
	})
}

// emitToolCall records a tool.call as an optimistic-success ToolEvent; the
// paired tool.result later stamps the real outcome.
func (st *parseState) emitToolCall(ev *loopEvent, ts int64, res *adapter.ParseResult) {
	if ev.Display != nil && strings.TrimSpace(ev.Display.Cwd) != "" {
		st.lastCwd = ev.Display.Cwd
	}
	scrubbedInput := st.adapter.scrubber.RawJSON(ev.Args)
	target := st.adapter.scrubber.String(targetFromArgs(ev.Args, ev.Name))
	idx := len(res.ToolEvents)
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: "tool:" + firstNonEmpty(ev.ToolCallID, ev.UUID),
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot(),
		GitBranch:     st.gitBranch,
		GitRemote:     st.gitRemote,
		Timestamp:     unixMillis(ts),
		Model:         st.lastModel,
		Tool:          models.ToolKimiCode,
		ActionType:    mapKimiTool(ev.Name),
		Target:        target,
		RawToolName:   ev.Name,
		RawToolInput:  scrubbedInput,
		ContentBytes:  authoredContentBytes(ev.Args),
		IsSidechain:   st.isSidechain,
		Success:       true,
	})
	if id := firstNonEmpty(ev.ToolCallID, ev.UUID); id != "" {
		st.pendingCall[id] = idx
	}
}

// applyToolResult stamps success + scrubbed output onto the ToolEvent the
// matching tool.call produced.
//
// When no pending call matches, the tool.call was emitted in an EARLIER
// parse window and its row is already persisted (optimistically
// successful): the outcome goes out as an ActionOutcomeUpdate keyed by
// the same "tool:<id>" SourceEventID emitToolCall built.
//
// Key caveat: the emit side keys on ToolCallID||UUID, the result side on
// ToolCallID||ParentUUID. They agree whenever ToolCallID is present; the
// ParentUUID fallback is the same call-UUID guess the in-window match
// already relies on, so cross-tick is exactly as accurate as in-window,
// no more.
func (st *parseState) applyToolResult(ev *loopEvent, res *adapter.ParseResult) {
	id := firstNonEmpty(ev.ToolCallID, ev.ParentUUID)
	output, success, errMsg := resultOutcome(ev.Result)
	idx, ok := st.pendingCall[id]
	if !ok || idx >= len(res.ToolEvents) {
		if id == "" {
			return
		}
		// DurationMs stays 0 — the call lived in the prior window and
		// UpdateActionOutcome no-ops a zero.
		up := models.ActionOutcomeUpdate{
			SourceFile:    st.path,
			SourceEventID: "tool:" + id,
			// resultOutcome always returns a verdict: a tool.result
			// with neither error nor isError IS the success signal.
			SuccessKnown: true,
			Success:      success,
		}
		if output != "" {
			up.ToolOutput = st.adapter.scrubber.String(contentcap.Cap(output, contentcap.DefaultMaxBytes))
		}
		if !success && errMsg != "" {
			up.ErrorMessage = truncate(st.adapter.scrubber.String(errMsg), 500)
		}
		res.OutcomeUpdates = append(res.OutcomeUpdates, up)
		return
	}
	te := &res.ToolEvents[idx]
	te.Success = success
	if output != "" {
		te.ToolOutput = st.adapter.scrubber.String(contentcap.Cap(output, contentcap.DefaultMaxBytes))
	}
	if !success && errMsg != "" {
		te.ErrorMessage = truncate(st.adapter.scrubber.String(errMsg), 500)
	}
	delete(st.pendingCall, id)
}

// emitAssistantText records the assistant's natural-language content part.
func (st *parseState) emitAssistantText(ev *loopEvent, ts int64, res *adapter.ParseResult) {
	if ev.Part == nil || ev.Part.Type != "text" || strings.TrimSpace(ev.Part.Text) == "" {
		return
	}
	scrubbed := st.adapter.scrubber.String(ev.Part.Text)
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: "assistant:" + firstNonEmpty(ev.UUID, hashID(ev.Part.Text)),
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot(),
		GitBranch:     st.gitBranch,
		GitRemote:     st.gitRemote,
		Timestamp:     unixMillis(ts),
		Model:         st.lastModel,
		Tool:          models.ToolKimiCode,
		ActionType:    models.ActionAssistantMessage,
		Target:        truncate(scrubbed, 200),
		RawToolName:   models.ToolKimiCode + ".assistant_text",
		ToolOutput:    st.adapter.scrubber.String(contentcap.Cap(ev.Part.Text, contentcap.DefaultMaxBytes)),
		IsSidechain:   st.isSidechain,
		Success:       true,
	})
}

// emitToken turns a usage.record into a NET-token TokenEvent. inputOther
// is already NET (see wireUsage), so it maps straight onto InputTokens; no
// reasoning field is present, so ReasoningTokens stays zero (honest gap).
func (st *parseState) emitToken(line *wireLine, raw string, res *adapter.ParseResult) {
	if line.Usage == nil {
		return
	}
	u := line.Usage
	if u.InputOther == 0 && u.Output == 0 && u.InputCacheRead == 0 && u.InputCacheCreation == 0 {
		return // observationally vacant — never persist a phantom zero row
	}
	res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
		SourceFile:          st.path,
		SourceEventID:       "tok:" + hashID(raw),
		SessionID:           st.sessionID,
		ProjectRoot:         st.projectRoot(),
		GitBranch:           st.gitBranch,
		GitRemote:           st.gitRemote,
		Timestamp:           unixMillis(line.Time),
		Tool:                models.ToolKimiCode,
		Model:               firstNonEmpty(normalizeModel(line.Model), st.lastModel),
		InputTokens:         u.InputOther,
		OutputTokens:        u.Output,
		CacheReadTokens:     u.InputCacheRead,
		CacheCreationTokens: u.InputCacheCreation,
		Source:              models.TokenSourceJSONL,
		Reliability:         models.ReliabilityApproximate,
	})
}

// projectRoot resolves (and memoizes) the session's project root and git
// branch. It reads the sibling session-root state.json for the workDir,
// falling back to a tool.call display cwd, then translates any foreign-OS
// path and runs git.Resolve.
func (st *parseState) projectRoot() string {
	if st.rootResolved {
		return st.resolvedRoot
	}
	cwd := st.workDirFromState()
	if cwd == "" {
		cwd = st.lastCwd
	}
	if cwd == "" {
		// Not memoized: a later tool.call display cwd may still resolve it.
		return ""
	}
	st.rootResolved = true
	cwd = crossmount.TranslateForeignPath(cwd)
	id, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		st.resolvedRoot = cwd
		return cwd
	}
	st.resolvedRoot = id.Root
	st.gitBranch = id.Branch
	// id.Remote is already NormalizeRemote'd by ResolveIdentity.
	st.gitRemote = id.Remote
	st.identity = id
	return id.Root
}

// workDirFromState reads the session-root state.json (two levels up from
// agents/<name>/wire.jsonl) and returns its workDir, or "" when the file
// is absent/unreadable. Only workDir is consumed; the file never carries
// credentials.
func (st *parseState) workDirFromState() string {
	statePath := stateJSONPath(st.path)
	if statePath == "" {
		return ""
	}
	b, err := os.ReadFile(statePath) //nolint:gosec // derived from the watched wire.jsonl path
	if err != nil {
		return ""
	}
	var s stateFile
	if json.Unmarshal(b, &s) != nil {
		return ""
	}
	return strings.TrimSpace(s.WorkDir)
}
