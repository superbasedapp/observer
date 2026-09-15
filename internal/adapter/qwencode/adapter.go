package qwencode

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

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter parses Qwen Code CLI session transcripts under
// ~/.qwen/projects/<slug>/chats/<uuid>.jsonl. See the package doc for
// the record shapes and the token/project-root resolution model.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and platform-default
// cross-mount watch roots (~/.qwen/projects under every resolved $HOME).
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
func (*Adapter) Name() string { return models.ToolQwenCode }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. A path qualifies only when it
// is BOTH under one of this adapter's watch roots AND matches the qwen
// transcript shape `<qwen-home>/projects/<slug>/chats/<uuid>.jsonl` (the
// companion `<uuid>.runtime.json`, the top-level `journal.jsonl`, and any
// other file are rejected).
func (a *Adapter) IsSessionFile(path string) bool {
	if !matchesShape(path) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// matchesShape reports whether path has the qwen chat-transcript shape,
// independent of watch roots. Comparison is on a slash-normalized,
// lower-cased copy so Windows separators and case-insensitive mounts
// match too.
//
// The shape deliberately does NOT hardcode the `.qwen` home segment: with
// $QWEN_HOME set, the very same transcript tree lives under an operator-
// chosen directory (`$QWEN_HOME/projects/<slug>/chats/`). The install root
// is enforced separately by IsSessionFile's UnderAnyWatchRoot gate (the
// same division of labour the kimicode adapter uses), so the shape need
// only distinguish a chat transcript from the other files under the root —
// notably the top-level `journal.jsonl`, which sits outside any `chats/`
// directory and is not a session log.
func matchesShape(path string) bool {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	if !strings.Contains(lower, "/projects/") {
		return false
	}
	if !strings.Contains(lower, "/chats/") {
		return false
	}
	base := filepath.Base(lower)
	if !strings.HasSuffix(base, ".jsonl") {
		return false
	}
	// Reject the sidecar `<uuid>.runtime.json` (already excluded by the
	// .jsonl suffix) and any `<uuid>.runtime.jsonl`-style companions.
	return !strings.HasSuffix(base, ".runtime.jsonl")
}

// defaultRoots returns ~/.qwen/projects under every cross-mount-resolved
// $HOME so a WSL2 observer picks up Windows-side sessions on
// /mnt/c/Users/<u>/.qwen and vice versa.
//
// $QWEN_HOME wins on the native side when set: the Qwen Code bundle
// resolves its own storage root from QWEN_HOME before falling back to
// os.homedir()/.qwen, so an operator who relocated the home sees their
// sessions under $QWEN_HOME/projects and nowhere else. Like clinecli's
// CLINE_DIR handling, the env var is only meaningful for THIS process's
// environment, so it is not re-resolved per cross-mount home — the
// per-home defaults below still contribute their own `.qwen/projects`
// paths. The value is absolutized before use (see adapter.AbsEnvRoot) so a
// relative QWEN_HOME can never become a relative watch root. Empty/
// duplicate candidates are dropped so WatchPaths never carries the same
// directory twice.
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

	if home := adapter.AbsEnvRoot("QWEN_HOME"); home != "" {
		add(filepath.Join(home, "projects"))
	}
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(h.Path, ".qwen", "projects"))
	}
	return roots
}

// ParseSessionFile implements adapter.Adapter. It streams the JSONL from
// fromOffset to EOF, emitting ToolEvents (tool calls, user prompts,
// assistant text, api errors, slash commands, a session-start marker) and
// TokenEvents (from ui_telemetry api_response records). Malformed lines
// are skipped with a warning; the byte cursor advances past every fully
// terminated line so repeated calls make progress.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("qwencode.ParseSessionFile: open %s: %w", path, err)
	}
	defer f.Close()

	if fromOffset > 0 {
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return adapter.ParseResult{}, fmt.Errorf("qwencode.ParseSessionFile: seek: %w", err)
		}
	}

	res := adapter.ParseResult{NewOffset: fromOffset}
	// On the first parse of a transcript, read the companion
	// <uuid>.runtime.json sidecar for a direct process-attribution
	// seed. Qwen writes the owning CLI process's real OS pid there; the
	// watcher (the daemon) reads it, so no ancestor-walk is needed. Only
	// at fromOffset==0 so steady-state polls don't re-stat the sidecar.
	if fromOffset == 0 {
		res.SessionProcessSeeds = runtimeSeeds(path)
	}
	st := &parseState{
		adapter:       a,
		path:          path,
		rootCache:     map[string]string{},
		remoteCache:   map[string]string{},
		identityCache: map[string]git.Identity{},
		pendingCall:   map[string]int{},
		byName:        map[string][]int{},
		firstOffset:   fromOffset,
	}

	// bufio.Reader.ReadString (not Scanner) so the byte cursor advances by
	// the exact terminator length including CRLF, and long tool-output
	// lines aren't capped by a token-size limit.
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
			return res, fmt.Errorf("qwencode.ParseSessionFile: read: %w", readErr)
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
		var rec rawRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
			if readErr == io.EOF {
				break
			}
			continue
		}
		st.handle(&rec, &res)
		if readErr == io.EOF {
			break
		}
	}
	st.flagPendingOutcomes(&res)
	st.applyIdentities(&res)
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

// applyIdentities backfills the Project Identity Resolver v2 bundle onto
// every event in res, keyed by resolved project root (a qwen-code
// transcript can carry more than one distinct cwd/root — see
// identityCache).
func (st *parseState) applyIdentities(res *adapter.ParseResult) {
	byRoot := make(map[string]git.Identity, len(st.identityCache))
	for cwd, root := range st.rootCache {
		if root != "" {
			byRoot[root] = st.identityCache[cwd]
		}
	}
	adapter.ApplyProjectIdentityByRoot(res, byRoot)
}

// runtimeSidecar is the shape of the `<uuid>.runtime.json` file qwen
// writes beside each transcript (pid / hostname / work_dir /
// qwen_version / session_id / started_at). Only the fields the
// attribution seed needs are decoded; unknown keys are ignored.
type runtimeSidecar struct {
	Hostname  string `json:"hostname"`
	PID       int    `json:"pid"`
	SessionID string `json:"session_id"`
	WorkDir   string `json:"work_dir"`
}

// runtimeSeeds reads the transcript's companion runtime.json sidecar and
// returns a single candidate (pid → session) attribution seed when the
// sidecar names THIS host (hostname match) and carries a plausible pid.
//
// The hostname gate is the native check: a foreign-host qwen process
// (Windows qwen read by a WSL2 observer) reports a different hostname,
// so its Windows pid — meaningless on the Linux daemon's /proc — is
// never seeded. The store re-validates liveness + identity ("qwen" in
// the process comm/cmdline) before writing, so a dead/recycled pid on
// this host is rejected too (a miss beats a wrong link).
//
// The sidecar is NOT a session file (qwencode.IsSessionFile rejects the
// .runtime.json suffix); this is a targeted read of the sibling, not a
// dispatch change.
func runtimeSeeds(transcriptPath string) []models.SessionProcessSeed {
	base := strings.TrimSuffix(transcriptPath, ".jsonl")
	if base == transcriptPath {
		return nil // not a .jsonl transcript
	}
	body, err := os.ReadFile(base + ".runtime.json") //nolint:gosec // path derives from a watched transcript
	if err != nil {
		return nil
	}
	var rt runtimeSidecar
	if err := json.Unmarshal(body, &rt); err != nil {
		return nil
	}
	if rt.PID <= 1 || rt.SessionID == "" {
		return nil
	}
	host, err := os.Hostname()
	if err != nil || host == "" || rt.Hostname == "" || !strings.EqualFold(host, rt.Hostname) {
		// Can't confirm the pid is local — don't seed.
		return nil
	}
	return []models.SessionProcessSeed{{
		PID:       rt.PID,
		SessionID: rt.SessionID,
		Tool:      models.ToolQwenCode,
		CWD:       rt.WorkDir,
		ExecHint:  "qwen",
	}}
}

// parseState carries the per-call mutable bookkeeping the record handler
// needs across lines.
type parseState struct {
	adapter *Adapter
	path    string
	// rootCache memoizes cwd → resolved project root (git.Resolve walks
	// the filesystem, and one session shares one cwd across many records).
	rootCache map[string]string
	// pendingCall maps a functionCall id to the index of its ToolEvent in
	// res.ToolEvents, so the later tool_result record can stamp
	// success/output onto it.
	pendingCall map[string]int
	// byName is a FIFO queue of pending ToolEvent indices keyed by raw tool
	// name, used to attach the ui_telemetry tool_call duration (which
	// carries no call id) to the matching call.
	byName map[string][]int
	// firstOffset is the fromOffset the parse started at; the session-start
	// marker is only emitted when parsing from the very top of the file.
	firstOffset int64
	// sessionStarted guards against emitting more than one session-start
	// marker per parse call.
	sessionStarted bool
	// lastCwd / lastBranch carry the most recent envelope context so
	// records that (rarely) omit them still resolve a project root.
	lastCwd    string
	lastBranch string
	// remoteCache memoizes cwd → normalized git remote (see projectRoot).
	// Unlike lastBranch, the record never states its own remote, so this
	// comes ONLY from git.Resolve.
	remoteCache map[string]string
	// identityCache memoizes cwd → the Project Identity Resolver v2
	// bundle (2026-09-06, §3.1 / W1) resolved alongside
	// rootCache/remoteCache. Applied at the end of ParseSessionFile via
	// adapter.ApplyProjectIdentityByRoot, keyed by resolved root.
	identityCache map[string]git.Identity
}

// handle dispatches one record onto the appropriate emit path.
func (st *parseState) handle(rec *rawRecord, res *adapter.ParseResult) {
	if rec.Cwd != "" {
		st.lastCwd = rec.Cwd
	}
	if rec.GitBranch != "" {
		st.lastBranch = rec.GitBranch
	}
	switch rec.Type {
	case "user":
		st.emitUserPrompt(rec, res)
	case "assistant":
		st.emitAssistant(rec, res)
	case "tool_result":
		st.applyToolResult(rec, res)
	case "system":
		st.emitSystem(rec, res)
	}
}

// projectRoot resolves the record cwd (translating a foreign-OS path
// before git.Resolve) and memoizes the result, along with its normalized
// git remote.
func (st *parseState) projectRoot() (root, remote string) {
	cwd := st.lastCwd
	if cwd == "" {
		return "", ""
	}
	cwd = crossmount.TranslateForeignPath(cwd)
	if root, ok := st.rootCache[cwd]; ok {
		return root, st.remoteCache[cwd]
	}
	id, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		st.rootCache[cwd] = cwd
		return cwd, ""
	}
	st.rootCache[cwd] = id.Root
	// id.Remote is already NormalizeRemote'd by ResolveIdentity.
	st.remoteCache[cwd] = id.Remote
	st.identityCache[cwd] = id
	return id.Root, st.remoteCache[cwd]
}

// emitUserPrompt records a user prompt, and (only when parsing from the
// top of the file, on the transcript root record) a session-start marker.
func (st *parseState) emitUserPrompt(rec *rawRecord, res *adapter.ParseResult) {
	root, remote := st.projectRoot()
	if st.firstOffset == 0 && !st.sessionStarted && rec.ParentUUID == nil {
		st.sessionStarted = true
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile:    st.path,
			SourceEventID: "session_start:" + rec.SessionID,
			SessionID:     rec.SessionID,
			ProjectRoot:   root,
			Timestamp:     parseTimestamp(rec.Timestamp),
			GitBranch:     st.lastBranch,
			GitRemote:     remote,
			Tool:          models.ToolQwenCode,
			ActionType:    models.ActionSessionStart,
			Target:        "startup",
			RawToolName:   "qwen-code.session_start",
			Success:       true,
		})
	}

	text := firstText(rec.Message)
	if text == "" {
		return
	}
	scrubbed := st.adapter.scrubber.String(text)
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: "prompt:" + rec.UUID,
		SessionID:     rec.SessionID,
		ProjectRoot:   root,
		Timestamp:     parseTimestamp(rec.Timestamp),
		GitBranch:     st.lastBranch,
		GitRemote:     remote,
		Tool:          models.ToolQwenCode,
		ActionType:    models.ActionUserPrompt,
		Target:        truncate(scrubbed, 200),
		RawToolName:   "qwen-code.user_prompt",
		RawToolInput:  scrubbed,
		Success:       true,
	})
}

// emitAssistant records the assistant turn's functionCall parts as tool
// events and any text part as an assistant-message event.
func (st *parseState) emitAssistant(rec *rawRecord, res *adapter.ParseResult) {
	if rec.Message == nil {
		return
	}
	root, remote := st.projectRoot()
	ts := parseTimestamp(rec.Timestamp)
	callIdx := 0
	for _, part := range rec.Message.Parts {
		switch {
		case part.FunctionCall != nil:
			fc := part.FunctionCall
			scrubbedInput := st.adapter.scrubber.RawJSON(fc.Args)
			target := st.adapter.scrubber.String(targetFromArgs(fc.Args, fc.Name))
			idx := len(res.ToolEvents)
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile:    st.path,
				SourceEventID: st.callEventID(fc.ID, rec.UUID, callIdx),
				SessionID:     rec.SessionID,
				ProjectRoot:   root,
				Timestamp:     ts,
				GitBranch:     st.lastBranch,
				GitRemote:     remote,
				Model:         rec.Model,
				Tool:          models.ToolQwenCode,
				ActionType:    mapToolName(fc.Name),
				Target:        target,
				RawToolName:   fc.Name,
				RawToolInput:  scrubbedInput,
				Success:       true, // optimistic; corrected by the paired tool_result
			})
			if fc.ID != "" {
				st.pendingCall[fc.ID] = idx
			}
			st.byName[fc.Name] = append(st.byName[fc.Name], idx)
			callIdx++
		case strings.TrimSpace(part.Text) != "":
			scrubbed := st.adapter.scrubber.String(part.Text)
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile:    st.path,
				SourceEventID: "assistant:" + rec.UUID,
				SessionID:     rec.SessionID,
				ProjectRoot:   root,
				Timestamp:     ts,
				GitBranch:     st.lastBranch,
				GitRemote:     remote,
				Model:         rec.Model,
				Tool:          models.ToolQwenCode,
				ActionType:    models.ActionAssistantMessage,
				Target:        truncate(scrubbed, 200),
				RawToolName:   models.ToolQwenCode + ".assistant_text",
				ToolOutput:    st.adapter.scrubber.String(contentcap.Cap(part.Text, contentcap.DefaultMaxBytes)),
				Success:       true,
			})
		}
	}
}

// callEventID builds a deterministic SourceEventID for a tool call,
// preferring the provider call id and falling back to the record uuid +
// position for the (unobserved) case of a missing id.
func (st *parseState) callEventID(callID, uuid string, pos int) string {
	if callID != "" {
		return "tool:" + callID
	}
	return "tool:" + uuid + ":" + strconv.Itoa(pos)
}

// applyToolResult stamps success + scrubbed output onto the ToolEvent the
// matching functionCall produced.
func (st *parseState) applyToolResult(rec *rawRecord, res *adapter.ParseResult) {
	// Prefer the structured toolCallResult (has callId + status); fall
	// back to the message functionResponse parts.
	if rec.ToolCallResult != nil {
		st.stampResult(rec.ToolCallResult.CallID, rec.ToolCallResult.Status,
			toolResultOutput(rec), res)
		return
	}
	if rec.Message == nil {
		return
	}
	for _, part := range rec.Message.Parts {
		if part.FunctionResponse == nil {
			continue
		}
		st.stampResult(part.FunctionResponse.ID, "",
			responseOutput(part.FunctionResponse.Response), res)
	}
}

// toolResultOutput prefers the human functionResponse.output text, then
// the toolCallResult.resultDisplay (string or object).
func toolResultOutput(rec *rawRecord) string {
	if rec.Message != nil {
		for _, part := range rec.Message.Parts {
			if part.FunctionResponse != nil {
				if out := responseOutput(part.FunctionResponse.Response); out != "" {
					return out
				}
			}
		}
	}
	if rec.ToolCallResult != nil && len(rec.ToolCallResult.ResultDisplay) > 0 {
		var s string
		if err := json.Unmarshal(rec.ToolCallResult.ResultDisplay, &s); err == nil {
			return s
		}
		return string(rec.ToolCallResult.ResultDisplay)
	}
	return ""
}

// stampResult finds the pending ToolEvent for callID and records its
// outcome. A non-empty status of anything other than "success" marks the
// event failed.
//
// When no pending call matches, the functionCall was emitted in an
// EARLIER parse window and its row is already persisted (optimistically
// successful): the outcome goes out as an ActionOutcomeUpdate keyed by
// the same "tool:<callID>" SourceEventID callEventID produced. Only a
// non-empty callID qualifies — the empty-id fallback id embeds the
// record uuid + position, neither of which the result record carries.
func (st *parseState) stampResult(callID, status, output string, res *adapter.ParseResult) {
	var scrubbed string
	if output != "" {
		scrubbed = st.adapter.scrubber.String(contentcap.Cap(output, contentcap.DefaultMaxBytes))
	}
	idx, ok := st.pendingCall[callID]
	if !ok || idx >= len(res.ToolEvents) {
		if callID == "" {
			return
		}
		// An absent status is NOT a verdict — in-window it leaves
		// Success untouched, and cross-tick it must do the same: the
		// persisted row may already read failed (a ui_telemetry
		// tool_call event in the earlier window stamps status), and
		// asserting success here would silently repair it. Output
		// still ships; an error message would be equally invented.
		// DurationMs stays 0 — the call is in the prior window and
		// UpdateActionOutcome no-ops a zero.
		up := models.ActionOutcomeUpdate{
			SourceFile:    st.path,
			SourceEventID: "tool:" + callID,
			SuccessKnown:  status != "",
			Success:       status == "success",
			ToolOutput:    scrubbed,
		}
		if up.SuccessKnown && !up.Success && scrubbed != "" {
			up.ErrorMessage = truncate(scrubbed, 500)
		}
		res.OutcomeUpdates = append(res.OutcomeUpdates, up)
		return
	}
	ev := &res.ToolEvents[idx]
	if status != "" {
		ev.Success = status == "success"
	}
	if scrubbed != "" {
		ev.ToolOutput = scrubbed
		if !ev.Success {
			ev.ErrorMessage = truncate(scrubbed, 500)
		}
	}
	delete(st.pendingCall, callID)
}

// emitSystem dispatches system records by subtype: ui_telemetry events
// (api_response → TokenEvent + tool_call enrichment + api_error →
// ActionAPIError) and slash_command → an ActionUserPromptExpansion row.
func (st *parseState) emitSystem(rec *rawRecord, res *adapter.ParseResult) {
	if rec.SystemPayload == nil {
		return
	}
	switch rec.Subtype {
	case "ui_telemetry":
		st.emitTelemetry(rec, res)
	case "slash_command":
		st.emitSlashCommand(rec, res)
	}
}

// emitTelemetry handles the three ui_telemetry event.name variants.
func (st *parseState) emitTelemetry(rec *rawRecord, res *adapter.ParseResult) {
	ev := rec.SystemPayload.UIEvent
	if ev == nil {
		return
	}
	switch ev.Name {
	case eventAPIResponse:
		st.emitTokenEvent(rec, ev, res)
	case eventToolCall:
		st.enrichToolCall(ev, res)
	case eventAPIError:
		st.emitAPIError(rec, ev, res)
	}
}

// emitTokenEvent turns an api_response event into a NET-token TokenEvent.
func (st *parseState) emitTokenEvent(rec *rawRecord, ev *rawUIEvent, res *adapter.ParseResult) {
	tp := tokenBundle(ev)
	root, remote := st.projectRoot()
	res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
		SourceFile:      st.path,
		SourceEventID:   "tok:" + rec.UUID,
		SessionID:       rec.SessionID,
		ProjectRoot:     root,
		GitBranch:       st.lastBranch,
		GitRemote:       remote,
		Timestamp:       parseTimestamp(firstNonEmpty(ev.Timestamp, rec.Timestamp)),
		Tool:            models.ToolQwenCode,
		Model:           ev.Model,
		InputTokens:     tp.inputNet,
		OutputTokens:    tp.output,
		CacheReadTokens: tp.cacheRead,
		ReasoningTokens: tp.reasoning,
		Source:          models.TokenSourceJSONL,
		Reliability:     models.ReliabilityApproximate,
		MessageID:       ev.ResponseID,
		TurnID:          ev.PromptID,
	})
}

// enrichToolCall attaches the tool_call event's duration/decision to the
// oldest pending ToolEvent of the same tool name (the telemetry event
// carries no call id, so matching is FIFO-by-name).
func (st *parseState) enrichToolCall(ev *rawUIEvent, res *adapter.ParseResult) {
	queue := st.byName[ev.FunctionName]
	if len(queue) == 0 {
		return
	}
	idx := queue[0]
	st.byName[ev.FunctionName] = queue[1:]
	if idx >= len(res.ToolEvents) {
		return
	}
	te := &res.ToolEvents[idx]
	if ev.DurationMs > 0 {
		te.DurationMs = ev.DurationMs
	}
	// The tool_result record is the authority on success; only downgrade
	// from the telemetry when it explicitly reports a non-success status.
	if ev.Success != nil && !*ev.Success {
		te.Success = false
	} else if ev.Status != "" && ev.Status != "success" {
		te.Success = false
	}
}

// emitAPIError records an upstream API error as an ActionAPIError event.
func (st *parseState) emitAPIError(rec *rawRecord, ev *rawUIEvent, res *adapter.ParseResult) {
	target := ev.Model
	if ev.StatusCode > 0 {
		target = fmt.Sprintf("%s (HTTP %d)", ev.Model, ev.StatusCode)
	}
	root, remote := st.projectRoot()
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: "api_error:" + rec.UUID,
		SessionID:     rec.SessionID,
		ProjectRoot:   root,
		Timestamp:     parseTimestamp(firstNonEmpty(ev.Timestamp, rec.Timestamp)),
		GitBranch:     st.lastBranch,
		GitRemote:     remote,
		Model:         ev.Model,
		Tool:          models.ToolQwenCode,
		ActionType:    models.ActionAPIError,
		Target:        target,
		RawToolName:   firstNonEmpty(ev.ErrorType, "api_error"),
		ErrorMessage:  st.adapter.scrubber.String(ev.ErrorMessage),
		DurationMs:    ev.DurationMs,
		Success:       false,
	})
}

// emitSlashCommand records a slash-command invocation as an
// ActionUserPromptExpansion row (only the initial invocation phase, to
// avoid noise): the user typed a `/command` shorthand that the CLI
// expands into the real prompt, the same family as claude-code's own
// slash-command expansion. Kept in sync with
// internal/tooltax/table.go's qwen-code "qwen-code.slash_command" row
// by internal/tooltax's TestStepFinishEmitSitesAgreeWithTooltax
// (WP-T6 finding — this site previously hardcoded ActionUnknown, which
// drifted against the tooltax table).
func (st *parseState) emitSlashCommand(rec *rawRecord, res *adapter.ParseResult) {
	cmd := strings.TrimSpace(rec.SystemPayload.RawCommand)
	if cmd == "" || (rec.SystemPayload.Phase != "" && rec.SystemPayload.Phase != "invocation") {
		return
	}
	scrubbed := st.adapter.scrubber.String(cmd)
	root, remote := st.projectRoot()
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: "slash:" + rec.UUID,
		SessionID:     rec.SessionID,
		ProjectRoot:   root,
		Timestamp:     parseTimestamp(rec.Timestamp),
		GitBranch:     st.lastBranch,
		GitRemote:     remote,
		Tool:          models.ToolQwenCode,
		ActionType:    models.ActionUserPromptExpansion,
		Target:        truncate(scrubbed, 200),
		RawToolName:   "qwen-code.slash_command",
		RawToolInput:  scrubbed,
		Success:       true,
	})
}

// firstNonEmpty returns the first non-blank string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
