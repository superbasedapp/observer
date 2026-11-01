package codebuddy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// headerScanLines / headerScanBytes bound the prescan that finds the
// session's first `cwd`. The session-meta line that opens every
// transcript carries no cwd; the first message line does, so the scan
// normally stops on line 2.
const (
	headerScanLines = 256
	headerScanBytes = 4 << 20
)

// Adapter parses CodeBuddy Code session transcripts under
// ~/.codebuddy/projects/<slug>/<session-id>.jsonl. See the package doc
// for the record shapes, the token rules and the off-limits file list.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and the
// platform-default watch roots (CODEBUDDY_CONFIG_DIR/projects when set,
// plus ~/.codebuddy/projects under every cross-mount-resolved $HOME).
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
func (*Adapter) Name() string { return models.ToolCodeBuddy }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. A path qualifies only when it
// is BOTH under one of this adapter's watch roots AND has the main
// transcript shape `projects/<slug>/<session-id>.jsonl` — exactly one
// directory level below `projects`. That rejects, by shape:
//
//   - `projects/<slug>/<session-id>/subagents/agent-<id>.jsonl` (sub-agent
//     and team-member transcripts; see the package doc's sub-agent note
//     for why they are not claimed in v1),
//   - `projects/<slug>/<session-id>/tool-results/…` (spilled tool output),
//   - `~/.codebuddy/history.jsonl` and `traces/<pid>/trace_*.jsonl`, which
//     are outside `projects/` anyway.
func (a *Adapter) IsSessionFile(p string) bool {
	if !matchesShape(p) {
		return false
	}
	return adapter.UnderAnyWatchRoot(p, a.WatchPaths())
}

// matchesShape reports whether p looks like a main CodeBuddy transcript,
// independent of watch roots: a `.jsonl` file whose grandparent
// directory is named `projects`. Comparison runs on a slash-normalized,
// lower-cased copy so Windows separators and case-insensitive mounts
// match too.
func matchesShape(p string) bool {
	lower := strings.ReplaceAll(strings.ToLower(p), `\`, "/")
	base := path.Base(lower)
	if !strings.HasSuffix(base, ".jsonl") || base == ".jsonl" {
		return false
	}
	slugDir := path.Dir(lower)
	if path.Base(slugDir) == "" || path.Base(slugDir) == "projects" {
		return false
	}
	return path.Base(path.Dir(slugDir)) == "projects"
}

// sessionIDFromPath returns the transcript's filename stem. It is the
// canonical session id: CodeBuddy names the file after the session, every
// line's `sessionId` repeats it (grounded on both OSes), and it is what
// `codebuddy --resume=<id>` accepts.
func sessionIDFromPath(p string) string {
	return strings.TrimSuffix(filepath.Base(p), ".jsonl")
}

// ParseSessionFile implements adapter.Adapter. It streams the JSONL from
// fromOffset to EOF, emitting ToolEvents (a session-start marker, user
// prompts, assistant text, upstream errors, tool calls stamped with their
// results) and TokenEvents (one per model generation carrying usage).
//
// A bounded prescan from byte 0 recovers the session's cwd first, so a
// resumed parse (and the session-start marker, which precedes the first
// cwd-bearing line) still resolves a project root. Malformed lines are
// skipped with a warning and the cursor advances past every fully
// terminated line; a partial trailing line is deferred. A tool result
// that lands in a later parse window than its call is delivered through
// OutcomeUpdates (its row's key is reconstructible from the result's
// `callId` alone); a call still unanswered at EOF is flagged
// OutcomePending.
func (a *Adapter) ParseSessionFile(ctx context.Context, p string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(p) //nolint:gosec // path comes from the watcher's own watch roots
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("codebuddy.ParseSessionFile: open %s: %w", p, err)
	}
	defer f.Close()

	st := &parseState{
		adapter:     a,
		path:        p,
		rootCache:   map[string]string{},
		toolIdx:     map[string]int{},
		callTime:    map[string]time.Time{},
		tokenIdx:    map[string]int{},
		unknownTool: map[string]bool{},
		unknownType: map[string]bool{},
		firstOffset: fromOffset,
		sessionID:   sessionIDFromPath(p),
		cacheAcc:    cacheobs.New(MaxBlocksPerSession),
	}
	if err := st.prescanCwd(f); err != nil {
		return adapter.ParseResult{}, err
	}
	if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
		return adapter.ParseResult{}, fmt.Errorf("codebuddy.ParseSessionFile: seek: %w", err)
	}

	res := adapter.ParseResult{NewOffset: fromOffset}
	reader := bufio.NewReaderSize(f, 64*1024)
	bytesRead := fromOffset
	lineNum := 0
	for {
		if ctx.Err() != nil {
			st.finish(&res)
			return res, ctx.Err()
		}
		lineStr, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			st.finish(&res)
			return res, fmt.Errorf("codebuddy.ParseSessionFile: read: %w", readErr)
		}
		hasNewline := strings.HasSuffix(lineStr, "\n")
		if !hasNewline && readErr == io.EOF {
			// Partial trailing line: a record still being written.
			break
		}
		lineStart := bytesRead
		bytesRead += int64(len(lineStr))
		lineNum++
		res.NewOffset = bytesRead

		raw := strings.TrimRight(lineStr, "\r\n")
		if strings.TrimSpace(raw) != "" {
			var rec rawLine
			if err := json.Unmarshal([]byte(raw), &rec); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
			} else {
				st.handle(&rec, lineStart, &res)
			}
		}
		if readErr == io.EOF {
			break
		}
	}
	st.applyLog(&res, fromOffset)
	st.finish(&res)
	return res, nil
}

// parseState carries the per-call mutable bookkeeping across lines.
type parseState struct {
	adapter *Adapter
	path    string
	// rootCache memoizes cwd → resolved project root.
	rootCache map[string]string
	// toolIdx maps a call id to its ToolEvent's index in res.ToolEvents
	// for a call parsed IN THIS window and still unanswered; callTime
	// holds the call's timestamp for the result's duration.
	toolIdx  map[string]int
	callTime map[string]time.Time
	// tokenIdx maps a token SourceEventID to its index in
	// res.TokenEvents, so two usage-bearing items of one generation
	// collapse onto one row (field-wise MAX, the store's own rule).
	tokenIdx map[string]int
	// unknownTool / unknownType dedupe the one-shot warnings.
	unknownTool map[string]bool
	unknownType map[string]bool
	// firstOffset is where this parse started; the session-start marker
	// is only emitted when parsing from the top of the file.
	firstOffset    int64
	sessionStarted bool
	sessionID      string
	// firstTS / lastTS bracket the session's activity (prescan's first
	// stamped line, then the newest line of this window): they pick the
	// day directories of CodeBuddy's diagnostic log to consult.
	firstTS, lastTS time.Time
	// cwd is the latest raw cwd seen (prescan, then every line).
	cwd    string
	branch string
	remote string
	// identity is the Project Identity Resolver v2 bundle, applied to
	// every event via adapter.ApplyProjectIdentity in finish.
	identity git.Identity
	// lastModel is the most recent model a model-produced item stated,
	// kept SEPARATELY for main-agent (false) and sub-agent-forwarded
	// (true) items, so a sub-agent's model is never stamped onto a
	// model-less main-agent item or vice versa (audit Check 6).
	lastModel [2]string
	// reasoning is the scrubbed text of the latest reasoning item,
	// carried onto the assistant/tool events that follow it and cleared
	// at the next user message.
	reasoning string
	// cacheAcc accumulates the Tier-2 content-block delta drained into
	// one CacheTurnObservation per usage-bearing generation.
	cacheAcc *cacheobs.Accumulator
}

// prescanCwd reads from byte 0 until the first line carrying a `cwd`
// (bounded by headerScanLines / headerScanBytes). A file with no cwd in
// that window simply leaves the project root empty until one appears.
func (st *parseState) prescanCwd(f *os.File) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("codebuddy.prescanCwd: seek: %w", err)
	}
	r := bufio.NewReaderSize(f, 64*1024)
	var read int
	for i := 0; i < headerScanLines && read < headerScanBytes; i++ {
		line, err := r.ReadString('\n')
		read += len(line)
		if err != nil && err != io.EOF {
			return fmt.Errorf("codebuddy.prescanCwd: read: %w", err)
		}
		if strings.HasSuffix(line, "\n") {
			var probe struct {
				Cwd       string `json:"cwd"`
				Timestamp msTime `json:"timestamp"`
			}
			if json.Unmarshal([]byte(strings.TrimRight(line, "\r\n")), &probe) == nil {
				if st.firstTS.IsZero() {
					st.firstTS = probe.Timestamp.t
				}
				if probe.Cwd != "" {
					st.cwd = probe.Cwd
					return nil
				}
			}
		}
		if err == io.EOF {
			return nil
		}
	}
	return nil
}

// finish runs the end-of-parse bookkeeping: a call still unanswered in
// this window is flagged OutcomePending (its Success=true is optimistic,
// not measured — the result, when it lands, arrives as an
// OutcomeUpdate), and the project identity is stamped on every event.
func (st *parseState) finish(res *adapter.ParseResult) {
	for _, idx := range st.toolIdx {
		if idx < len(res.ToolEvents) {
			res.ToolEvents[idx].OutcomePending = true
		}
	}
	adapter.ApplyProjectIdentity(res, st.identity)
}

// handle dispatches one decoded line, then turns any usage it carries
// into a TokenEvent.
func (st *parseState) handle(rec *rawLine, lineStart int64, res *adapter.ParseResult) {
	if rec.Cwd != "" {
		st.cwd = rec.Cwd
	}
	if ts := rec.Timestamp.t; !ts.IsZero() {
		if st.firstTS.IsZero() {
			st.firstTS = ts
		}
		if ts.After(st.lastTS) {
			st.lastTS = ts
		}
	}
	if m := modelOf(rec.ProviderData); m != "" {
		st.lastModel[sideIdx(rec.FromSubAgent)] = m
	}
	key := eventKey(rec, lineStart)
	// A headless (`-p`) session writes no session-meta line (grounded: 56
	// of the 58 sessions on both OSes), so its first record opens the
	// session. A later session-meta finds sessionStarted already set.
	if rec.Type != "session-meta" {
		st.emitSessionStart(rec, res)
	}
	switch rec.Type {
	case "session-meta":
		st.emitSessionStart(rec, res)
	case "message":
		st.emitMessage(rec, key, res)
	case "function_call":
		st.emitToolCall(rec, key, res)
	case "hosted_tool_call":
		st.emitHostedCall(rec, key, res)
	case "function_call_result":
		st.applyResult(rec, res)
	case "reasoning":
		st.noteReasoning(rec)
	case "summary":
		// "initial-user-message" is the session-title seed (LIVE); a
		// "pre-compact" / "periodic" summary is a context compaction
		// (vendor bundle saveSummary, not yet seen live).
		st.emitCompaction(rec, key, rec.ProviderData.sourceOf(), res)
	case "compaction":
		// The provider's opaque server-side compaction item (agents-core
		// "compaction"; encrypted_content is never read).
		st.emitCompaction(rec, key, "provider", res)
	case "file-history-snapshot", "ai-title", "":
		// Checkpoint bookkeeping, generated titles and untyped lines:
		// informational, skipped silently (§4.4e).
	default:
		if !st.unknownType[rec.Type] {
			st.unknownType[rec.Type] = true
			res.Warnings = append(res.Warnings, fmt.Sprintf("unhandled record type %q skipped", rec.Type))
		}
	}
	st.emitTokens(rec, key, res)
}

// eventKey is the line's deterministic identity: its UUIDv7 `id` when
// present (every grounded message line carries one), else the record's
// byte offset — stable across re-parses AND resume points.
func eventKey(rec *rawLine, lineStart int64) string {
	if rec.ID != "" {
		return rec.ID
	}
	return "@" + strconv.FormatInt(lineStart, 10)
}

// modelOf mirrors the vendor's readExecutedModelId: requestModelId,
// else model. LIVE field positions (hook probe, mock upstream: the value
// is the model the CLI requested, not a provider echo).
func modelOf(pd *rawProviderData) string {
	if pd == nil {
		return ""
	}
	if m := strings.TrimSpace(pd.RequestModelID); m != "" {
		return m
	}
	return strings.TrimSpace(pd.Model)
}

// itemModel is the model to stamp on a model-produced item: its own,
// else the session's latest.
func (st *parseState) itemModel(rec *rawLine) string {
	if m := modelOf(rec.ProviderData); m != "" {
		return m
	}
	return st.lastModel[sideIdx(rec.FromSubAgent)]
}

// sideIdx maps the sidechain flag onto lastModel's index.
func sideIdx(side bool) int {
	if side {
		return 1
	}
	return 0
}

// generationID returns providerData.messageId (one id per model
// generation), else "".
func generationID(rec *rawLine) string {
	if rec.ProviderData == nil {
		return ""
	}
	return rec.ProviderData.MessageID
}

// projectRoot resolves the current cwd and memoizes the result. The
// translation is UNCONDITIONAL: crossmount.TranslateForeignPath maps a
// Windows `c:\…` cwd (which a WSL2 observer sees for a Windows-side
// install) to its `/mnt/c/…` equivalent, so a drive-letter string never
// reaches git.Resolve. Same shape as commandcode / qwencode.
func (st *parseState) projectRoot() string {
	if st.cwd == "" {
		return ""
	}
	cwd := crossmount.TranslateForeignPath(st.cwd)
	if root, ok := st.rootCache[cwd]; ok {
		return root
	}
	id, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		st.rootCache[cwd] = cwd
		return cwd
	}
	st.rootCache[cwd] = id.Root
	st.branch = id.Branch
	st.remote = id.Remote
	st.identity = id
	return id.Root
}

// base returns a ToolEvent pre-filled with the per-line common fields.
func (st *parseState) base(rec *rawLine) models.ToolEvent {
	return models.ToolEvent{
		SourceFile:  st.path,
		SessionID:   st.sessionID,
		ProjectRoot: st.projectRoot(),
		Timestamp:   rec.Timestamp.t,
		GitBranch:   st.branch,
		GitRemote:   st.remote,
		Tool:        models.ToolCodeBuddy,
		IsSidechain: rec.FromSubAgent,
	}
}

// emitSessionStart records the transcript's opening `session-meta` line
// as a session-start marker, only when parsing from the top of the file.
// CodeBuddy re-appends session-meta lines later in the file when its
// metadata changes; those are not new sessions.
func (st *parseState) emitSessionStart(rec *rawLine, res *adapter.ParseResult) {
	if st.firstOffset != 0 || st.sessionStarted || st.sessionID == "" {
		return
	}
	st.sessionStarted = true
	ev := st.base(rec)
	ev.SourceEventID = "session_start:" + st.sessionID
	ev.ActionType = models.ActionSessionStart
	ev.Target = "startup"
	ev.RawToolName = models.ToolCodeBuddy + ".session_start"
	ev.Success = true
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitMessage handles a `message` item: a user prompt, assistant text,
// or an assistant-side upstream/auth error.
func (st *parseState) emitMessage(rec *rawLine, key string, res *adapter.ParseResult) {
	ps := parts(rec.Content)
	text := partsText(ps)
	switch rec.Role {
	case "user":
		st.emitUser(rec, key, ps, text, res)
	case "assistant":
		if rec.ProviderData != nil {
			if msg := errorMessage(rec.ProviderData.Error); msg != "" {
				st.emitAPIError(rec, key, msg, res)
				return
			}
			if rec.ProviderData.HookStatus == "blocked" {
				st.emitHookBlocked(rec, key, res)
				return
			}
		}
		st.emitAssistant(rec, key, text, res)
	}
	// system / developer messages are harness configuration, skipped.
}

// emitUser records a real operator prompt. Local slash-command
// bookkeeping (providerData.skipRun, GROUNDED) and harness-injected
// wrappers never become prompts.
func (st *parseState) emitUser(rec *rawLine, key string, ps []rawPart, text string, res *adapter.ParseResult) {
	st.reasoning = ""
	if rec.ProviderData != nil && rec.ProviderData.SkipRun {
		return
	}
	if isMetaUserText(text) {
		return
	}
	atts := userAttachments(ps)
	if strings.TrimSpace(text) == "" && len(atts) == 0 {
		return
	}
	scrubbed := st.adapter.scrubber.String(text)
	ev := st.base(rec)
	ev.SourceEventID = "prompt:" + key
	ev.ActionType = models.ActionUserPrompt
	ev.RawToolName = models.ToolCodeBuddy + ".user_prompt"
	ev.Target = truncate(scrubbed, 200)
	ev.RawToolInput = scrubbed
	ev.UserAttachments = atts
	ev.Success = true
	if scrubbed != "" {
		accumulateTextCache(st.cacheAcc, scrubbed, "user")
	}
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitAssistant records assistant output text.
func (st *parseState) emitAssistant(rec *rawLine, key, text string, res *adapter.ParseResult) {
	if strings.TrimSpace(text) == "" {
		return
	}
	scrubbed := st.adapter.scrubber.String(text)
	capped := st.adapter.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes))
	ev := st.base(rec)
	ev.SourceEventID = "assistant:" + key
	ev.ActionType = models.ActionAssistantMessage
	ev.RawToolName = models.ToolCodeBuddy + ".assistant_text"
	ev.Model = st.itemModel(rec)
	ev.Target = truncate(scrubbed, 200)
	ev.ToolOutput = capped
	ev.PrecedingReasoning = st.reasoning
	ev.MessageID = generationID(rec)
	ev.Success = true
	accumulateTextCache(st.cacheAcc, capped, "assistant")
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitAPIError records an assistant item that carries
// providerData.error — the GROUNDED shape of a turn that never reached
// a model ("Authentication required. Please use /login …", with
// status:"incomplete" and skipRun:true). Target is the turn id, joinable
// to the turn's other rows; RawToolName the error class from its flags.
func (st *parseState) emitAPIError(rec *rawLine, key, msg string, res *adapter.ParseResult) {
	ev := st.base(rec)
	ev.SourceEventID = "error:" + key
	ev.ActionType = models.ActionAPIError
	ev.RawToolName = errorClass(rec.ProviderData.Error)
	ev.Target = rec.ProviderData.ConversationRequestID
	ev.Model = st.itemModel(rec)
	ev.ErrorMessage = truncate(st.adapter.scrubber.String(msg), 500)
	ev.MessageID = generationID(rec)
	ev.Success = false
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitHookBlocked records a user prompt a UserPromptSubmit hook blocked.
// CodeBuddy persists the block as an assistant message (skipRun:true,
// hookStatus:"blocked", LIVE) carrying the hook's reason; the blocked prompt
// itself is NOT persisted (the live file holds only this one record). It is
// the host's policy layer refusing the turn,
// so it lands as permission_denied; Target is the hook event, ErrorMessage
// the hook-supplied reason (never the hook command, which holds paths).
func (st *parseState) emitHookBlocked(rec *rawLine, key string, res *adapter.ParseResult) {
	pd := rec.ProviderData
	var reasons []string
	for _, d := range pd.BlockingDetails {
		if r := strings.TrimSpace(d.Reason); r != "" {
			reasons = append(reasons, r)
		}
	}
	msg := strings.Join(reasons, "; ")
	if msg == "" {
		msg = partsText(parts(rec.Content))
	}
	ev := st.base(rec)
	ev.SourceEventID = "hookblock:" + key
	ev.ActionType = models.ActionPermissionDenied
	ev.RawToolName = models.ToolCodeBuddy + ".hook_blocked"
	ev.Target = pd.HookEvent
	if ev.Target == "" {
		ev.Target = "hook"
	}
	ev.ErrorMessage = truncate(st.adapter.scrubber.String(msg), 500)
	ev.Success = false
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitCompaction records a context compaction. A summary whose source is
// the session-title seed (or unstated) is not one. No summary text is kept.
func (st *parseState) emitCompaction(rec *rawLine, key, source string, res *adapter.ParseResult) {
	if source == "" || source == "initial-user-message" {
		return
	}
	ev := st.base(rec)
	ev.SourceEventID = "compaction:" + key
	ev.ActionType = models.ActionContextCompacted
	ev.RawToolName = models.ToolCodeBuddy + ".compaction"
	ev.Target = source
	ev.Success = true
	res.ToolEvents = append(res.ToolEvents, ev)
}

// noteReasoning stores a reasoning item's text for the events that
// follow it in the same generation.
func (st *parseState) noteReasoning(rec *rawLine) {
	text := partsText(parts(rec.Content))
	if strings.TrimSpace(text) == "" {
		text = partsText(parts(rec.RawContent))
	}
	if strings.TrimSpace(text) == "" {
		return
	}
	st.reasoning = st.adapter.scrubber.String(strings.TrimSpace(text))
}

// emitToolCall records a `function_call` item as a ToolEvent,
// optimistically successful until its function_call_result says
// otherwise.
func (st *parseState) emitToolCall(rec *rawLine, key string, res *adapter.ParseResult) {
	action, recognised := mapToolName(rec.Name)
	st.warnUnknownTool(rec.Name, action, recognised, res)
	input := argumentsJSON(rec.Arguments)
	var scrubbedInput string
	if input != nil {
		scrubbedInput = st.adapter.scrubber.RawJSON(input)
	} else if len(rec.Arguments) > 0 {
		scrubbedInput = st.adapter.scrubber.String(string(rec.Arguments))
	}
	accumulateToolCallCache(st.cacheAcc, rec.Name, scrubbedInput)

	callID := rec.CallID
	ev := st.base(rec)
	ev.SourceEventID = "tool:" + callKey(callID, key)
	ev.ActionType = action
	ev.Target = st.adapter.scrubber.String(targetFromInput(input, rec.Name))
	ev.RawToolName = rec.Name
	ev.RawToolInput = scrubbedInput
	ev.ContentBytes = authoredBytes(action, input)
	ev.Model = st.itemModel(rec)
	ev.PrecedingReasoning = st.reasoning
	ev.MessageID = generationID(rec)
	ev.Success = true
	if callID != "" {
		st.toolIdx[callID] = len(res.ToolEvents)
		st.callTime[callID] = rec.Timestamp.t
	}
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitHostedCall records a provider-hosted tool call (agents-core
// `hosted_tool_call`, output inline). UNVERIFIED: no such line captured
// (the probe's mock model never emitted a provider-hosted tool).
func (st *parseState) emitHostedCall(rec *rawLine, key string, res *adapter.ParseResult) {
	action, recognised := mapToolName(rec.Name)
	st.warnUnknownTool(rec.Name, action, recognised, res)
	input := argumentsJSON(rec.Arguments)
	ev := st.base(rec)
	ev.SourceEventID = "tool:" + callKey(rec.ID, key)
	ev.ActionType = action
	ev.Target = st.adapter.scrubber.String(targetFromInput(input, rec.Name))
	ev.RawToolName = rec.Name
	if input != nil {
		ev.RawToolInput = st.adapter.scrubber.RawJSON(input)
	}
	ev.Model = st.itemModel(rec)
	ev.MessageID = generationID(rec)
	if out := outputText(rec.Output); out != "" {
		ev.ToolOutput = st.adapter.scrubber.String(contentcap.Cap(out, contentcap.DefaultMaxBytes))
	}
	failed, msg := resultFailed(rec)
	ev.Success = !failed
	if failed {
		if msg == "" {
			msg = ev.ToolOutput
		}
		ev.ErrorMessage = truncate(st.adapter.scrubber.String(msg), 500)
	}
	res.ToolEvents = append(res.ToolEvents, ev)
}

// warnUnknownTool records the one-shot "unrecognised tool" warning.
func (st *parseState) warnUnknownTool(name, action string, recognised bool, res *adapter.ParseResult) {
	if recognised || st.unknownTool[name] {
		return
	}
	st.unknownTool[name] = true
	res.Warnings = append(res.Warnings,
		fmt.Sprintf("unrecognised tool name %q normalized to %q", name, action))
}

// callKey prefers the provider call id, falling back to the line key.
func callKey(callID, lineKey string) string {
	if callID != "" {
		return callID
	}
	return lineKey
}

// applyResult stamps a function_call_result's outcome onto the
// ToolEvent its call produced — directly when the call is in this parse
// window, otherwise as an OutcomeUpdate keyed `tool:<callId>`, the same
// key emitToolCall used.
func (st *parseState) applyResult(rec *rawLine, res *adapter.ParseResult) {
	if rec.CallID == "" {
		return
	}
	out := outputText(rec.Output)
	scrubbed := ""
	if out != "" {
		scrubbed = st.adapter.scrubber.String(contentcap.Cap(out, contentcap.DefaultMaxBytes))
		accumulateToolResultCache(st.cacheAcc, scrubbed)
	}
	failed, msg := resultFailed(rec)
	errMsg := ""
	if failed {
		if msg == "" {
			msg = scrubbed
		}
		errMsg = truncate(st.adapter.scrubber.String(msg), 500)
	}

	if idx, ok := st.toolIdx[rec.CallID]; ok && idx < len(res.ToolEvents) {
		ev := &res.ToolEvents[idx]
		if scrubbed != "" {
			ev.ToolOutput = scrubbed
		}
		if callTS := st.callTime[rec.CallID]; !callTS.IsZero() && rec.Timestamp.t.After(callTS) {
			ev.DurationMs = rec.Timestamp.t.Sub(callTS).Milliseconds()
		}
		if failed {
			ev.Success = false
			ev.ErrorMessage = errMsg
		}
		delete(st.toolIdx, rec.CallID)
		delete(st.callTime, rec.CallID)
		return
	}
	upd := models.ActionOutcomeUpdate{
		SourceFile:    st.path,
		SourceEventID: "tool:" + rec.CallID,
		SuccessKnown:  true,
		Success:       !failed,
		ErrorMessage:  errMsg,
		ToolOutput:    scrubbed,
	}
	res.OutcomeUpdates = append(res.OutcomeUpdates, upd)
}

// emitTokens turns an item's providerData.usage into a TokenEvent keyed
// by the model generation (providerData.messageId), so the several items
// of one generation can never mint more than one row. An absent or
// all-zero envelope emits nothing. The envelope shape is LIVE (hook probe)
// but its numbers were mock values — see tokenBundle.
func (st *parseState) emitTokens(rec *rawLine, key string, res *adapter.ParseResult) {
	pd := rec.ProviderData
	if pd == nil || (pd.Usage == nil && pd.RawUsage == nil) {
		return
	}
	tp := tokenBundle(pd.Usage, pd.RawUsage)
	if tp.isZero() {
		return
	}
	gen := pd.MessageID
	if gen == "" {
		gen = key
	}
	sourceEventID := "tok:" + gen
	if idx, ok := st.tokenIdx[sourceEventID]; ok && idx < len(res.TokenEvents) {
		mergeMax(&res.TokenEvents[idx], tp)
		return
	}
	model := st.itemModel(rec)
	ts := rec.Timestamp.t
	if obs := emitCacheObservation(st.cacheAcc, st.path, st.sessionID, sourceEventID, model, ts, tp); obs != nil {
		res.CacheObservations = append(res.CacheObservations, *obs)
	}
	st.tokenIdx[sourceEventID] = len(res.TokenEvents)
	res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
		SourceFile:          st.path,
		SourceEventID:       sourceEventID,
		SessionID:           st.sessionID,
		ProjectRoot:         st.projectRoot(),
		GitBranch:           st.branch,
		GitRemote:           st.remote,
		Timestamp:           ts,
		Tool:                models.ToolCodeBuddy,
		Model:               model,
		InputTokens:         tp.inputNet,
		OutputTokens:        tp.output,
		CacheReadTokens:     tp.cacheRead,
		CacheCreationTokens: tp.cacheWrit,
		ReasoningTokens:     tp.reasoning,
		Source:              models.TokenSourceJSONL,
		Reliability:         models.ReliabilityApproximate,
		MessageID:           pd.MessageID,
		TurnID:              pd.ConversationRequestID,
		IsSidechain:         rec.FromSubAgent,
	})
}

// mergeMax folds a second usage reading of the same generation into an
// existing row field-wise by MAX — the store's own conflict rule, applied
// in-parse so one parse never emits two rows under one key.
func mergeMax(ev *models.TokenEvent, tp tokenParts) {
	ev.InputTokens = max(ev.InputTokens, tp.inputNet)
	ev.OutputTokens = max(ev.OutputTokens, tp.output)
	ev.CacheReadTokens = max(ev.CacheReadTokens, tp.cacheRead)
	ev.CacheCreationTokens = max(ev.CacheCreationTokens, tp.cacheWrit)
	ev.ReasoningTokens = max(ev.ReasoningTokens, tp.reasoning)
}
