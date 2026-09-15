package poolside

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
	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// trajectoryDirName is the fixed subdirectory holding every trajectory
// file: <data-home>/poolside/trajectories/.
const trajectoryDirName = "trajectories"

// trajectoryPrefix / trajectorySuffix bound the session-log basename
// shape: trajectory-<agentId>_<sessionId>.ndjson.
const (
	trajectoryPrefix = "trajectory-"
	trajectorySuffix = ".ndjson"
)

// headerScanLines bounds the from-offset-0 re-read for session.start,
// which the live capture always places at line 1. A handful of lines is
// plenty; the bound exists so a corrupt or unexpectedly-shaped log can
// never turn the header read into a full-file scan on every poll tick.
const headerScanLines = 8

// Adapter parses Poolside trajectory logs. See the package doc for the
// record shapes, the GROSS-input token netting and the off-limits file
// list.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and platform-default
// watch roots.
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
func (*Adapter) Name() string { return models.ToolPoolside }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// appDataSpec declares Poolside's per-user data-home convention. Only
// ShapeWindowsLocal is grounded (the sole OS available on the grounding
// host); ShapeDarwinAppSupport is a documented, unverified guess on the
// strength of every other JetBrains-bundled ACP agent's OS-native (not
// XDG) data-home convention. No Linux shape is declared — see the
// package doc's "Storage layout" section for why.
var appDataSpec = adapter.AppDataSpec{
	Name:   "poolside",
	Shapes: adapter.ShapeWindowsLocal | adapter.ShapeDarwinAppSupport,
}

// defaultRoots returns every plausible Poolside trajectories directory.
func defaultRoots() []string {
	var roots []string
	for _, h := range crossmount.AllHomes() {
		// AppDataRoots already appends appDataSpec.Name ("poolside"), so the
		// base is <home>/<app-data>/poolside — only the trajectories subdir
		// is joined here. (Joining "poolside" again produced a doubled
		// segment .../poolside/poolside/trajectories that never existed.)
		for _, base := range adapter.AppDataRoots(h, appDataSpec) {
			roots = append(roots, filepath.Join(base, trajectoryDirName))
		}
	}
	return adapter.DedupRootsByIdentity(roots)
}

// IsSessionFile implements adapter.Adapter. A path qualifies only when it
// is BOTH under one of this adapter's watch roots AND has the trajectory
// basename shape.
func (a *Adapter) IsSessionFile(path string) bool {
	if !matchesShape(path) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// matchesShape reports whether path has the trajectory basename shape,
// independent of watch roots.
func matchesShape(path string) bool {
	base := filepath.Base(path)
	return strings.HasPrefix(base, trajectoryPrefix) && strings.HasSuffix(base, trajectorySuffix)
}

// sessionAndAgentFromPath recovers the canonical session id (and the
// agent id, unused today but kept for a future multi-agent-mode build)
// from the trajectory basename: trajectory-<agentId>_<sessionId>.ndjson.
// The session id is never stated inside the body, so the filename is the
// ONLY source — split on the LAST underscore so an agent id that itself
// contains one (none observed; "standalone" does not) still resolves the
// session id correctly, since a UUID never contains an underscore.
func sessionAndAgentFromPath(path string) (sessionID, agentID string) {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, trajectorySuffix)
	base = strings.TrimPrefix(base, trajectoryPrefix)
	idx := strings.LastIndex(base, "_")
	if idx < 0 {
		return base, ""
	}
	return base[idx+1:], base[:idx]
}

// ParseSessionFile implements adapter.Adapter. It streams the NDJSON from
// fromOffset to EOF, emitting ToolEvents (session start/end markers, the
// user prompt, the assistant reply, every tool call stamped with its
// outcome) and TokenEvents (one per tool_call.inference.end record, GROSS
// input netted against cache-read). See the package doc's "Cross-window
// tool outcomes" section for why no deferred-tail rewind is needed here.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from the watcher's own watch roots
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("poolside.ParseSessionFile: open %s: %w", path, err)
	}
	defer f.Close()

	sessionID, _ := sessionAndAgentFromPath(path)
	st := &parseState{
		adapter:       a,
		path:          path,
		sessionID:     sessionID,
		firstOffset:   fromOffset,
		toolIdx:       map[string]int{},
		modelByStep:   map[string]string{},
		thoughtByStep: map[string]string{},
		unknownTool:   map[string]bool{},
		cacheAcc:      cacheobs.New(MaxBlocksPerSession),
	}
	if err := st.readHeader(f); err != nil {
		return adapter.ParseResult{}, err
	}

	if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
		return adapter.ParseResult{}, fmt.Errorf("poolside.ParseSessionFile: seek: %w", err)
	}

	res := adapter.ParseResult{NewOffset: fromOffset}

	// bufio.Reader.ReadString (not Scanner) so the byte cursor advances by
	// the exact terminator length including CRLF.
	reader := bufio.NewReaderSize(f, 64*1024)
	bytesRead := fromOffset
	lineNum := 0
	for {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		lineStr, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			return res, fmt.Errorf("poolside.ParseSessionFile: read: %w", readErr)
		}
		hasNewline := strings.HasSuffix(lineStr, "\n")
		// A partial trailing line (no '\n' at EOF) is still being
		// written: defer it, do NOT advance the cursor past it.
		if !hasNewline && readErr == io.EOF {
			break
		}
		bytesRead += int64(len(lineStr))
		lineNum++
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
	return res, nil
}

// parseState carries the per-call mutable bookkeeping the record handler
// needs across lines.
type parseState struct {
	adapter *Adapter
	path    string
	// sessionID is the canonical session uuid, derived from the
	// trajectory FILENAME (the body never states it).
	sessionID string
	// firstOffset is the fromOffset the parse started at; the
	// session-start marker is only emitted when parsing from the very
	// top of the file.
	firstOffset int64
	// sessionStarted guards against emitting more than one session-start
	// marker per parse call.
	sessionStarted bool
	// cwd is the raw absolute workspace root stated by session.start.
	cwd string
	// rootResolved / root / branch / remote memoize the ONE project-root
	// resolution a session performs (a session log never changes cwd).
	rootResolved bool
	root         string
	branch       string
	remote       string
	// toolIdx maps a tool call's provider id to its ToolEvent's index in
	// res.ToolEvents, for a call parsed IN THIS SAME parse window. A call
	// whose approval/result arrives in a LATER window has no entry here,
	// so its outcome is emitted via OutcomeUpdates instead (see the
	// package doc's "Cross-window tool outcomes").
	toolIdx map[string]int
	// modelByStep tracks the model stated by tool_call.inference.start
	// for the step_id currently in flight, consumed by the paired
	// tool_call.inference.end and every tool call under that step.
	modelByStep map[string]string
	// thoughtByStep holds a step's reasoning text between thought.end and
	// the assistant_message.end (or first tool call) of the SAME step,
	// which consumes and clears it.
	thoughtByStep map[string]string
	// unknownTool dedupes the "unrecognised tool name" warning.
	unknownTool map[string]bool
	// cacheAcc accumulates this parse call's running Tier-2 content-block
	// delta, drained into one CacheTurnObservation per
	// tool_call.inference.end (see cachetrack.go).
	cacheAcc *cacheobs.Accumulator
}

// readHeader re-reads the top of the log (position 0, independent of the
// parse cursor) for session.start's working directory, so a resumed
// parse still resolves a project root.
func (st *parseState) readHeader(f *os.File) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("poolside.readHeader: seek: %w", err)
	}
	br := bufio.NewReaderSize(f, 64*1024)
	for i := 0; i < headerScanLines; i++ {
		line, err := br.ReadString('\n')
		raw := strings.TrimRight(line, "\r\n")
		if raw != "" {
			var rec rawRecord
			if jsonErr := json.Unmarshal([]byte(raw), &rec); jsonErr == nil &&
				rec.SessionStart != nil && len(rec.SessionStart.WorkingDirectories) > 0 {
				st.cwd = rec.SessionStart.WorkingDirectories[0]
				return nil
			}
		}
		if err != nil {
			return nil
		}
	}
	return nil
}

// projectRoot resolves the header workspace root once and memoizes it.
// The translation is UNCONDITIONAL: crossmount.TranslateForeignPath maps
// a foreign-OS root to its locally-visible equivalent, so a foreign path
// never reaches git.Resolve — where filepath.Abs would treat it as
// relative and CWD-prefix the observer's OWN .git onto every event.
func (st *parseState) projectRoot() string {
	if st.rootResolved {
		return st.root
	}
	st.rootResolved = true
	if st.cwd == "" {
		return ""
	}
	cwd := crossmount.TranslateForeignPath(st.cwd)
	info, err := git.Resolve(cwd)
	if err != nil {
		st.root = cwd
		return st.root
	}
	st.root = info.Root
	st.branch = info.Branch
	st.remote = git.NormalizeRemote(info.Remote)
	return st.root
}

// handle dispatches one decoded record onto the appropriate emit path.
func (st *parseState) handle(rec *rawRecord, res *adapter.ParseResult) {
	switch rec.Type {
	case typeSessionStart:
		if rec.SessionStart != nil && len(rec.SessionStart.WorkingDirectories) > 0 {
			st.cwd = rec.SessionStart.WorkingDirectories[0]
		}
		st.emitSessionStart(rec, res)
	case typeSessionInput:
		st.emitUserPrompt(rec, res)
	case typeThoughtEnd:
		if rec.ThoughtEnd != nil {
			st.thoughtByStep[rec.StepID] = rec.ThoughtEnd.Thought
		}
	case typeAssistantMessageEnd:
		st.emitAssistantMessage(rec, res)
	case typeToolCallInferenceStart:
		if rec.ToolCallInferenceStart != nil && rec.ToolCallInferenceStart.ChatCompletionRequest.Model != "" {
			st.modelByStep[rec.StepID] = rec.ToolCallInferenceStart.ChatCompletionRequest.Model
		}
	case typeToolCallInferenceEnd:
		st.emitTokens(rec, res)
	case typeToolCallParsed:
		st.emitToolCall(rec, res)
	case typeToolCallApproval:
		st.applyApproval(rec, res)
	case typeToolCallResult:
		st.applyResult(rec, res)
	case typeSessionExit:
		st.emitSessionEnd(rec, res)
	}
	// Every other type (tool_call.start, thought.start, assistant_message.
	// start, tool_call.approval.request, session.input.processed) is a
	// bookkeeping marker with no normalized-action counterpart.
}

// base builds the fields every emitted ToolEvent shares.
func (st *parseState) base(rec *rawRecord) models.ToolEvent {
	return models.ToolEvent{
		SourceFile:  st.path,
		SessionID:   st.sessionID,
		ProjectRoot: st.projectRoot(),
		Timestamp:   parseTimestamp(rec.Timestamp),
		GitBranch:   st.branch,
		GitRemote:   st.remote,
		Tool:        models.ToolPoolside,
		Success:     true,
	}
}

// emitSessionStart records the session-start marker, only when parsing
// from the very top of the file.
func (st *parseState) emitSessionStart(rec *rawRecord, res *adapter.ParseResult) {
	if st.firstOffset != 0 || st.sessionStarted || st.sessionID == "" {
		return
	}
	st.sessionStarted = true
	ev := st.base(rec)
	ev.SourceEventID = "session_start:" + st.sessionID
	ev.ActionType = models.ActionSessionStart
	ev.Target = "startup"
	ev.RawToolName = models.ToolPoolside + ".session_start"
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitSessionEnd records the session.exit marker.
func (st *parseState) emitSessionEnd(rec *rawRecord, res *adapter.ParseResult) {
	ev := st.base(rec)
	ev.SourceEventID = "session_end:" + eventKey(rec)
	ev.ActionType = models.ActionSessionEnd
	ev.RawToolName = models.ToolPoolside + ".session_end"
	ev.Target = "shutdown"
	if rec.SessionExit != nil && rec.SessionExit.Reason != "" {
		ev.Target = rec.SessionExit.Reason
	}
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitUserPrompt records one session.input turn.
func (st *parseState) emitUserPrompt(rec *rawRecord, res *adapter.ParseResult) {
	if rec.SessionInput == nil || strings.TrimSpace(rec.SessionInput.Prompt) == "" {
		return
	}
	scrubbed := st.adapter.scrubber.String(rec.SessionInput.Prompt)
	accumulateTextCache(st.cacheAcc, scrubbed, "user")
	ev := st.base(rec)
	ev.SourceEventID = "prompt:" + eventKey(rec)
	ev.ActionType = models.ActionUserPrompt
	ev.RawToolName = models.ToolPoolside + ".user_prompt"
	ev.Target = truncate(scrubbed, 200)
	ev.RawToolInput = scrubbed
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitAssistantMessage records the assistant's visible reply, with the
// same step's reasoning (if any) attached as PrecedingReasoning.
func (st *parseState) emitAssistantMessage(rec *rawRecord, res *adapter.ParseResult) {
	if rec.AssistantMessageEnd == nil || strings.TrimSpace(rec.AssistantMessageEnd.AssistantMessage) == "" {
		return
	}
	scrubbed := st.adapter.scrubber.String(rec.AssistantMessageEnd.AssistantMessage)
	ev := st.base(rec)
	ev.SourceEventID = "assistant:" + eventKey(rec)
	ev.ActionType = models.ActionAssistantMessage
	ev.RawToolName = models.ToolPoolside + ".assistant_message"
	ev.Model = st.modelByStep[rec.StepID]
	ev.Target = truncate(scrubbed, 200)
	capped := st.adapter.scrubber.String(contentcap.Cap(rec.AssistantMessageEnd.AssistantMessage, contentcap.DefaultMaxBytes))
	ev.ToolOutput = capped
	if reasoning, ok := st.thoughtByStep[rec.StepID]; ok {
		ev.PrecedingReasoning = truncate(st.adapter.scrubber.String(reasoning), 4000)
		delete(st.thoughtByStep, rec.StepID)
	}
	accumulateTextCache(st.cacheAcc, capped, "assistant")
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitToolCall records one tool_call.parsed as a ToolEvent, optimistically
// successful unless a validation_error says the call never ran.
func (st *parseState) emitToolCall(rec *rawRecord, res *adapter.ParseResult) {
	tc := rec.ToolCallParsed
	if tc == nil || tc.ID == "" {
		return
	}
	action, recognised := mapToolName(tc.Name)
	if !recognised && !st.unknownTool[tc.Name] {
		st.unknownTool[tc.Name] = true
		res.Warnings = append(res.Warnings, fmt.Sprintf("unrecognised tool name %q normalized to %q", tc.Name, action))
	}
	scrubbedInput := st.adapter.scrubber.String(contentcap.Cap(rawToolInput(tc), contentcap.DefaultMaxBytes))
	ev := st.base(rec)
	ev.SourceEventID = "tool:" + tc.ID
	ev.ActionType = action
	ev.RawToolName = tc.Name
	ev.Model = st.modelByStep[rec.StepID]
	ev.Target = st.adapter.scrubber.String(targetFromArgs(tc.Args, tc.Name))
	ev.RawToolInput = scrubbedInput
	ev.ContentBytes = authoredBytes(action, tc.Args)
	if reasoning, ok := st.thoughtByStep[rec.StepID]; ok {
		ev.PrecedingReasoning = truncate(st.adapter.scrubber.String(reasoning), 4000)
		delete(st.thoughtByStep, rec.StepID)
	}
	if tc.ValidationError != nil {
		ev.Success = false
		msg := tc.ValidationError.Detail
		if msg == "" {
			msg = tc.ValidationError.Kind
		}
		ev.ErrorMessage = truncate(msg, 500)
	}
	accumulateToolCallCache(st.cacheAcc, tc.Name, scrubbedInput)
	idx := len(res.ToolEvents)
	res.ToolEvents = append(res.ToolEvents, ev)
	st.toolIdx[tc.ID] = idx
}

// applyApproval stamps a denial onto the ToolEvent its call produced,
// whether the call landed in this same parse window (direct patch) or an
// earlier one (an OutcomeUpdate). An allow carries nothing to patch — the
// call stays optimistically successful pending its result.
func (st *parseState) applyApproval(rec *rawRecord, res *adapter.ParseResult) {
	ap := rec.ToolCallApproval
	if ap == nil || ap.ToolCallID == "" || !ap.Denied {
		return
	}
	reason := ap.Reason
	if reason == "" {
		reason = "tool call denied"
	}
	msg := truncate(reason, 500)
	if idx, ok := st.toolIdx[ap.ToolCallID]; ok && idx < len(res.ToolEvents) {
		res.ToolEvents[idx].Success = false
		res.ToolEvents[idx].ErrorMessage = msg
		return
	}
	res.OutcomeUpdates = append(res.OutcomeUpdates, models.ActionOutcomeUpdate{
		SourceFile:    st.path,
		SourceEventID: "tool:" + ap.ToolCallID,
		SuccessKnown:  true,
		Success:       false,
		ErrorMessage:  msg,
	})
}

// applyResult stamps a tool_call.result's outcome onto the ToolEvent its
// call produced, whether in this same parse window or an earlier one.
func (st *parseState) applyResult(rec *rawRecord, res *adapter.ParseResult) {
	r := rec.ToolCallResult
	if r == nil || r.ID == "" {
		return
	}
	output := st.adapter.scrubber.String(contentcap.Cap(r.Observation, contentcap.DefaultMaxBytes))
	successKnown, success := r.verdict()
	durationMs := r.ExecutionLatencyNanos / 1_000_000
	accumulateToolResultCache(st.cacheAcc, output)

	if idx, ok := st.toolIdx[r.ID]; ok && idx < len(res.ToolEvents) {
		ev := &res.ToolEvents[idx]
		if output != "" {
			ev.ToolOutput = output
		}
		ev.DurationMs = durationMs
		if successKnown && !success {
			ev.Success = false
			if ev.ErrorMessage == "" {
				ev.ErrorMessage = truncate(output, 500)
			}
		}
		return
	}
	upd := models.ActionOutcomeUpdate{
		SourceFile:    st.path,
		SourceEventID: "tool:" + r.ID,
		ToolOutput:    output,
		DurationMs:    durationMs,
	}
	if successKnown {
		upd.SuccessKnown = true
		upd.Success = success
		if !success {
			upd.ErrorMessage = truncate(output, 500)
		}
	}
	res.OutcomeUpdates = append(res.OutcomeUpdates, upd)
}

// emitTokens turns a tool_call.inference.end record into a TokenEvent. An
// absent or all-zero usage envelope emits nothing, so no phantom rows
// land.
func (st *parseState) emitTokens(rec *rawRecord, res *adapter.ParseResult) {
	if rec.ToolCallInferenceEnd.isZero() {
		return
	}
	model := st.modelByStep[rec.StepID]
	tp := tokenBundle(rec.ToolCallInferenceEnd)
	tokenSourceEventID := "tok:" + eventKey(rec)
	if obs := emitCacheObservation(st.cacheAcc, st.path, st.sessionID, tokenSourceEventID, model, parseTimestamp(rec.Timestamp), tp); obs != nil {
		res.CacheObservations = append(res.CacheObservations, *obs)
	}
	res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
		SourceFile:          st.path,
		SourceEventID:       tokenSourceEventID,
		SessionID:           st.sessionID,
		ProjectRoot:         st.projectRoot(),
		GitBranch:           st.branch,
		GitRemote:           st.remote,
		Timestamp:           parseTimestamp(rec.Timestamp),
		Tool:                models.ToolPoolside,
		Model:               model,
		InputTokens:         tp.inputNet,
		OutputTokens:        tp.outputNet,
		CacheReadTokens:     tp.cacheRead,
		CacheCreationTokens: tp.cacheWrit,
		// No EstimatedCostUSD: Observer ships no pricing entry for
		// poolside/laguna-* models, so the cost engine resolves these
		// rows as `unknown` rather than against an invented rate.
		Source:      models.TokenSourceJSONL,
		Reliability: models.ReliabilityApproximate,
	})
}

// eventKey returns the record's deterministic identity for SourceEventID
// construction — the record's own uuid, which is stable across re-parses.
func eventKey(rec *rawRecord) string { return rec.ID }

// truncate caps a preview string to n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// compile-time interface check.
var _ adapter.Adapter = (*Adapter)(nil)
