package kirocli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// ideSessionJSON is the sibling `session.json` of an IDE session dir
// (zod schema `hV` in the kiro.kiro-agent bundle). Only the fields the
// parser consults are typed; every other key is ignored, and EVERY
// field is optional — a live session's `session.json` may not have been
// flushed when `messages.jsonl` is first observed.
type ideSessionJSON struct {
	SchemaVersion  string   `json:"schemaVersion"`
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	AgentMode      string   `json:"agentMode"`
	WorkspacePaths []string `json:"workspacePaths"`
	RootPaths      []string `json:"rootPaths"`
	CreatedAt      string   `json:"createdAt"`
	LastModifiedAt string   `json:"lastModifiedAt"`
	ModelID        string   `json:"modelId"`
	EffortLevel    string   `json:"effortLevel"`
}

// ideRecord is one line of an IDE `messages.jsonl`. The discriminated
// union lives in `payload.type`; the payload's remaining keys are
// type-dependent, so every one of them is optional here and the record
// handlers read only what their own type guarantees.
type ideRecord struct {
	ID        string     `json:"id"`
	Timestamp string     `json:"timestamp"`
	Payload   idePayload `json:"payload"`
}

type idePayload struct {
	Type string `json:"type"`

	// session_start
	AgentType string `json:"agentType"`

	// session_start / user / assistant / tool_result all spell their
	// body `content`, but with DIFFERENT shapes (string vs content
	// blocks) — ideContent normalizes every observed shape (§4.4d).
	Content ideContent `json:"content"`

	// user
	Source string `json:"source"`

	// assistant
	OperationType string `json:"operationType"`
	ExecutionID   string `json:"executionId"`

	// tool_call
	ToolCallID string          `json:"toolCallId"`
	ToolName   string          `json:"toolName"`
	Args       json.RawMessage `json:"args"`
	Status     string          `json:"status"`

	// tool_result
	Success    *bool `json:"success"`
	DurationMs int64 `json:"durationMs"`

	// pending_interaction / interaction_resolved. Kiro IDE gates work
	// behind an approval prompt: `pending_interaction` poses it
	// (interactionType / question / options), and the matching
	// `interaction_resolved` reports which option the user picked. The
	// pair correlates on `toolCallId` — which is a fresh
	// `turn_approval_<ms>_<ms>_<rand>` id for a turn-scoped "Review
	// changes" prompt, but is the GATED CALL'S OWN `toolCallId` for a
	// per-tool prompt. The two id spaces therefore overlap, which is why
	// approvals get their own pending map and their own "perm:" event-id
	// prefix.
	InteractionType string          `json:"interactionType"`
	Question        string          `json:"question"`
	Options         json.RawMessage `json:"options"`
	Outcome         string          `json:"outcome"`
	SelectedOption  string          `json:"selectedOption"`

	// turn_end
	StopReason string `json:"stopReason"`
}

// ideInteractionOption is one choice offered by a pending_interaction.
// `kind` is the honest discriminator (observed: "allow_once" /
// "reject_once"); `optionId` is the id the resolution names back.
type ideInteractionOption struct {
	OptionID string `json:"optionId"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
}

// ideContent tolerates the three shapes a Kiro IDE `content` field is
// observed (and, per the zod schema, permitted) to take: a bare string,
// an array of content blocks, or a single content-block object. A
// strict `[]block` type would make the parser drop whole records — the
// Gemini trap in docs/new-adapter-checklist.md §4.4d.
type ideContent struct {
	Text string
}

// UnmarshalJSON implements json.Unmarshaler for the polymorphic shape.
// An unrecognised shape yields empty text rather than an error, so one
// odd content field can never sink the whole record.
func (c *ideContent) UnmarshalJSON(raw []byte) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	switch trimmed[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil //nolint:nilerr // tolerant by design (§4.4d)
		}
		c.Text = s
	case '[':
		var blocks []ideContentBlock
		if err := json.Unmarshal(raw, &blocks); err != nil {
			return nil //nolint:nilerr // tolerant by design (§4.4d)
		}
		c.Text = joinContentBlocks(blocks)
	case '{':
		var block ideContentBlock
		if err := json.Unmarshal(raw, &block); err != nil {
			return nil //nolint:nilerr // tolerant by design (§4.4d)
		}
		c.Text = joinContentBlocks([]ideContentBlock{block})
	}
	return nil
}

// ideContentBlock is one element of an array-shaped `content`.
type ideContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// joinContentBlocks concatenates the text of every text-bearing block.
func joinContentBlocks(blocks []ideContentBlock) string {
	var sb strings.Builder
	for _, b := range blocks {
		if b.Text == "" {
			continue
		}
		if b.Type != "" && b.Type != "text" {
			continue
		}
		sb.WriteString(b.Text)
	}
	return sb.String()
}

// ideParseState is the per-call mutable bookkeeping for one IDE
// messages.jsonl parse window.
type ideParseState struct {
	adapter     *Adapter
	sourceFile  string
	sessionID   string
	projectRoot string
	gitBranch   string
	gitRemote   string
	model       string
	effort      string

	// turnIndex / turnOpen bracket a turn. Kiro brackets a turn with
	// turn_start / turn_end, but the `user` record that triggered it is
	// written BEFORE turn_start, so either record may open the turn —
	// whichever lands first wins and turn_end closes it.
	turnIndex int
	turnOpen  bool

	// pendingCall maps a tool_call's toolCallId to the index of its
	// ToolEvent in this window, so a tool_result in the SAME window
	// stamps the row directly instead of going out as an
	// ActionOutcomeUpdate.
	pendingCall map[string]int

	// pendingInteraction is the same bookkeeping for approval rows, kept
	// SEPARATE from pendingCall because the two id spaces OVERLAP: a
	// turn-scoped approval carries its own `turn_approval_*` id, but a
	// per-tool approval reuses the very `toolCallId` of the call it
	// gates (live capture 2026-09-03), so one shared map would let an
	// approval and its tool call clobber each other's index.
	pendingInteraction map[string]int

	// interactionKinds remembers a pending_interaction's optionId → kind
	// table so the matching interaction_resolved can classify the choice
	// from the vendor's own discriminator rather than from the option
	// id's spelling. Empty across a window boundary, which is exactly
	// what the optionId fallback table exists for.
	interactionKinds map[string]map[string]string

	// pendingReasoning holds the most recent assistant
	// operationType="Reasoning" body; it rides the NEXT emitted event's
	// PrecedingReasoning and is consumed there (Kiro persists no
	// reasoning signature we could key a standalone row on).
	pendingReasoning string
}

// parseIDESession parses one Kiro IDE session's `messages.jsonl` from
// fromOffset to EOF, reading the sibling `session.json` best-effort for
// the project root / model / effort. The cursor is a byte offset that
// only ever advances past FULLY TERMINATED lines, so a record still
// being written is re-read whole on the next tick (checklist §4.1).
//
// Kiro IDE persists NO token counts anywhere (only
// `session_metadata{key:"contextUsage"}.value.usagePercentage`), so
// this layout emits NO TokenEvents at all — see the package doc's
// "Token honesty" section.
//
// A resume (fromOffset > 0) first replays the prefix through
// seedTurnState so TurnIndex counts turns from the START OF THE FILE
// rather than from the start of this window.
func (a *Adapter) parseIDESession(ctx context.Context, messagesPath string, fromOffset int64) (adapter.ParseResult, error) {
	res := adapter.ParseResult{NewOffset: fromOffset}
	if err := ctx.Err(); err != nil {
		return res, err
	}

	sessionDir := filepath.Dir(messagesPath)
	// §4.5a: the DIRECTORY name is the canonical session id. The
	// sibling session.json's `id` is expected to equal it; when it does
	// not, the directory wins (a re-keyed id orphans every row already
	// written under the path-derived id) and the divergence is warned.
	sessionID := filepath.Base(sessionDir)

	meta, metaOK := readIDESessionJSON(filepath.Join(sessionDir, ideSessionFileName))
	if metaOK && meta.ID != "" && meta.ID != sessionID {
		warnf(&res, "kirocli: IDE session %s: session.json id %q differs from the directory name; keeping the directory id",
			sessionID, meta.ID)
	}
	projectRoot, gitBranch, gitRemote, projectIdentity := resolveProjectRoot(ideWorkspacePath(meta))

	f, err := os.Open(messagesPath) //nolint:gosec // messagesPath derives from a validated watch-root trigger
	if err != nil {
		if os.IsNotExist(err) {
			return res, nil
		}
		return res, fmt.Errorf("kirocli.parseIDESession: open %s: %w", messagesPath, err)
	}
	defer f.Close()

	st := &ideParseState{
		adapter:            a,
		sourceFile:         messagesPath,
		sessionID:          sessionID,
		projectRoot:        projectRoot,
		gitBranch:          gitBranch,
		gitRemote:          gitRemote,
		model:              meta.ModelID,
		effort:             meta.EffortLevel,
		turnIndex:          -1,
		pendingCall:        map[string]int{},
		pendingInteraction: map[string]int{},
		interactionKinds:   map[string]map[string]string{},
	}

	if fromOffset > 0 {
		// TurnIndex must be an index into the WHOLE session, not into
		// this parse window — a byte-offset tail resumes mid-file, so a
		// window-local counter would restart at 0 and collide with the
		// turns emitted by earlier windows. Replay the prefix through
		// the same bracketing rules first, emitting nothing.
		if err := st.seedTurnState(ctx, io.LimitReader(f, fromOffset)); err != nil {
			return res, err
		}
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return res, fmt.Errorf("kirocli.parseIDESession: seek: %w", err)
		}
	}

	if err := st.consume(ctx, f, fromOffset, &res); err != nil {
		return res, err
	}
	st.flagPendingOutcomes(&res)
	adapter.ApplyProjectIdentity(&res, projectIdentity)
	res.SessionSurfaces = append(res.SessionSurfaces, surfaceFor(layoutIDE, sessionID))
	return res, nil
}

// ideSessionFileName is the sibling state file of an IDE session dir.
// It is read ONLY as a sibling — never accepted as a parse trigger (see
// classifyLayout).
const ideSessionFileName = "session.json"

// consume walks the JSONL from the seek position, advancing NewOffset
// past every fully terminated line (including blank and malformed ones,
// so the poll loop can never spin on a bad byte — §4.6).
func (st *ideParseState) consume(ctx context.Context, f *os.File, fromOffset int64, res *adapter.ParseResult) error {
	reader := bufio.NewReaderSize(f, 64*1024)
	bytesRead := fromOffset
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		lineStr, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			return fmt.Errorf("kirocli.parseIDESession: read: %w", readErr)
		}
		hasNewline := strings.HasSuffix(lineStr, "\n")
		// A partial trailing line is a record still being written:
		// defer it, do NOT advance the cursor past it.
		if !hasNewline && readErr == io.EOF {
			return nil
		}
		bytesRead += int64(len(lineStr))
		res.NewOffset = bytesRead

		raw := strings.TrimRight(lineStr, "\r\n")
		if strings.TrimSpace(raw) != "" {
			st.handleLine(raw, res)
		}
		if readErr == io.EOF {
			return nil
		}
	}
}

// seedTurnState replays the records BEFORE the resume offset through the
// turn-bracketing rules WITHOUT emitting anything, so st.turnIndex enters
// the emitting pass holding the count for the whole file.
//
// Why a re-read rather than a persisted counter: the watcher's cursor is
// a single int64 byte offset per file (adapter.ParseResult.NewOffset) —
// there is nowhere to stash a second number, and inventing per-adapter
// cursor state would be a watcher-API change for one field. The flat
// layout does not need this because it re-reads the whole bundle every
// tick (the `.json` is rewritten in place, so it has no resume point);
// the SQLite layout does not need it because its TurnIndex is the row's
// position within a single whole-conversation read. Only this tailing
// layout resumes mid-file, so only this layout pays the prefix scan —
// and it decodes each prefix line into a two-field struct, never
// materializing content or emitting rows.
func (st *ideParseState) seedTurnState(ctx context.Context, r io.Reader) error {
	reader := bufio.NewReaderSize(r, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		lineStr, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			return fmt.Errorf("kirocli.parseIDESession: seed turn state: %w", readErr)
		}
		if raw := strings.TrimSpace(lineStr); raw != "" {
			var probe struct {
				Payload struct {
					Type string `json:"type"`
				} `json:"payload"`
			}
			// A malformed prefix line is skipped silently: the emitting
			// pass already warned about it when it first went by, and
			// warning again on every subsequent window would flood.
			if json.Unmarshal([]byte(raw), &probe) == nil {
				st.applyTurnBracket(probe.Payload.Type)
			}
		}
		if readErr == io.EOF {
			return nil
		}
	}
}

// applyTurnBracket is THE turn-bracketing rule (CLAUDE.md #4 — one owner
// per piece of state): payload type in, st.turnIndex/st.turnOpen out. It
// is called from exactly two places — dispatch, before the emitters run,
// and seedTurnState's non-emitting prefix replay — which is what keeps
// the two passes' turn numbering identical by construction.
//
// `user` and `tool_call` open a turn as well as `turn_start` because
// either can be the first record of a turn (the `user` record is written
// BEFORE `turn_start`, and a bundle may omit the brackets entirely);
// openTurn is idempotent while a turn is open, so a steer message
// arriving mid-turn does not advance the counter.
func (st *ideParseState) applyTurnBracket(payloadType string) {
	switch payloadType {
	case "turn_start", "user", "tool_call":
		st.openTurn()
	case "turn_end":
		st.turnOpen = false
	}
}

// handleLine decodes and dispatches one record. The raw line rides
// along so a record with no `id` can still be given a CONTENT-derived
// (and therefore re-parse-stable) event id — §4.5 priority 2.
func (st *ideParseState) handleLine(raw string, res *adapter.ParseResult) {
	var rec ideRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		warnf(res, "kirocli: IDE session %s: malformed messages.jsonl line: %v", st.sessionID, err)
		return
	}
	st.dispatch(rec, raw, res)
}

// dispatch routes one decoded record by payload type. The record→row
// mapping is documented in docs/kiro-cli-adapter.md ("Layout 3").
//
// Types that carry no agent work — session_metadata (contextUsage
// percentages), session_event (pause markers), sub_agent_start,
// tombstone — are skipped SILENTLY per checklist §4.4e: warning on them
// would flood the watcher log on every session. Only a genuinely
// unknown TYPED payload warns, for forward-compat.
func (st *ideParseState) dispatch(rec ideRecord, raw string, res *adapter.ParseResult) {
	// Turn bracketing FIRST, through the one owner, so this pass and
	// seedTurnState's non-emitting replay can never diverge. Every
	// emitter below therefore sees the turn already opened.
	st.applyTurnBracket(rec.Payload.Type)

	switch rec.Payload.Type {
	case "session_start":
		st.emitSessionStart(rec, raw, res)
	case "user":
		st.emitUserPrompt(rec, raw, res)
	case "assistant":
		st.emitAssistant(rec, raw, res)
	case "tool_call":
		st.emitToolCall(rec, raw, res)
	case "tool_result":
		st.applyToolResult(rec, res)
	case "pending_interaction":
		st.emitPendingInteraction(rec, raw, res)
	case "interaction_resolved":
		st.applyInteractionResolved(rec, res)
	case "turn_start", "turn_end":
		// Bracketing only — handled by applyTurnBracket above.
		//
		// turn_end's stopReason is recorded nowhere: the package has no
		// lifecycle action type whose semantics the (ungrounded) Kiro
		// stop-reason vocabulary is known to match, and inventing one
		// would be a fabrication.
	case "session_metadata", "session_event", "sub_agent_start", "tombstone", "usage_summary":
		// Deliberate silent skip (§4.4e). sub_agent_start names a CHILD
		// session id; the package emits no SessionLineage rows, so
		// there is nowhere honest to put it yet.
		//
		// usage_summary is the ONLY per-turn accounting record Kiro IDE
		// writes, and it carries NO TOKENS — its
		// `promptTurnSummaries[].usage` is a Kiro CREDIT float
		// (`"unit":"credit"`), alongside `usedTools`, `elapsedTime`,
		// `status` and `requestIds`. Credits are neither tokens nor USD,
		// so storing them would fabricate a token tier; the flat layout
		// already refuses `metering_usage` for the same reason
		// (testdata/kirocli/README.md, reality-check find 3).
	case "":
		// Untyped noise line — silent (§4.4e).
	default:
		warnf(res, "kirocli: IDE session %s: unknown payload type %q", st.sessionID, rec.Payload.Type)
	}
}

// openTurn advances the turn counter unless a turn is already open. Call
// it only through applyTurnBracket — that is the rule table both the
// emitting and the seeding pass walk.
func (st *ideParseState) openTurn() {
	if st.turnOpen {
		return
	}
	st.turnIndex++
	st.turnOpen = true
}

// base builds the fields every emitted row shares.
func (st *ideParseState) base(rec ideRecord, eventID string) models.ToolEvent {
	ev := models.ToolEvent{
		SourceFile:    st.sourceFile,
		SourceEventID: eventID,
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot,
		GitBranch:     st.gitBranch,
		GitRemote:     st.gitRemote,
		Timestamp:     parseRFC3339(rec.Timestamp),
		TurnIndex:     max0(st.turnIndex),
		Model:         st.model,
		Tool:          models.ToolKiroCLI,
		Success:       true,
	}
	if st.effort != "" {
		ev.Metadata = &models.ActionMetadata{EffortLevel: st.effort}
	}
	if st.pendingReasoning != "" {
		ev.PrecedingReasoning = st.pendingReasoning
		st.pendingReasoning = ""
	}
	return ev
}

// emitSessionStart records the session's opening record. Target is the
// agent type (the honest identity of the run); "startup" is the
// fallback when the bundle wrote none. The record's `content` — which
// MAY be the seeding prompt — rides RawToolInput rather than a
// synthesized user_prompt row: a phantom prompt would double-count
// against the `user` record that normally follows (see the operator
// checklist in docs/kiro-cli-adapter.md).
func (st *ideParseState) emitSessionStart(rec ideRecord, raw string, res *adapter.ParseResult) {
	target := rec.Payload.AgentType
	if target == "" {
		target = "startup"
	}
	ev := st.base(rec, st.eventID(rec, "start", raw))
	ev.ActionType = models.ActionSessionStart
	ev.Target = target
	if body := rec.Payload.Content.Text; body != "" {
		ev.RawToolInput = st.adapter.scrubber.String(contentcap.Cap(body, contentcap.DefaultMaxBytes))
	}
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitUserPrompt records a user turn. A `source:"steer"` record is a
// mid-turn steering message — still a real user prompt, so it is
// emitted the same way; only the turn bracketing differs (a steer
// arrives inside an already-open turn and therefore does not advance
// the turn counter).
func (st *ideParseState) emitUserPrompt(rec ideRecord, raw string, res *adapter.ParseResult) {
	ev := st.base(rec, st.eventID(rec, "user", raw))
	ev.ActionType = models.ActionUserPrompt
	ev.Target = st.adapter.scrubber.String(contentcap.Cap(rec.Payload.Content.Text, contentcap.DefaultMaxBytes))
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitAssistant maps one assistant record by its operationType:
//
//	Say / Print → assistant_message
//	Summary     → context_compacted (Kiro's own compaction summary)
//	Reasoning   → NO row; the body is held and rides the next event's
//	              PrecedingReasoning
func (st *ideParseState) emitAssistant(rec ideRecord, raw string, res *adapter.ParseResult) {
	text := rec.Payload.Content.Text
	if rec.Payload.OperationType == "Reasoning" {
		if text != "" {
			st.pendingReasoning = st.adapter.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes))
		}
		return
	}
	action := models.ActionAssistantMessage
	if rec.Payload.OperationType == "Summary" {
		action = models.ActionContextCompacted
	}
	ev := st.base(rec, st.eventID(rec, "assistant", raw))
	ev.ActionType = action
	ev.Target = st.adapter.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes))
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitToolCall records a tool invocation through the SAME normalizeTool
// taxonomy the flat + SQLite layouts use, so one classifier owns the
// action mapping for every Kiro layout (CLAUDE.md #3/#5).
//
// The SourceEventID is "tool:<toolCallId>" — reconstructible from the
// LATER tool_result record alone, which is what lets a cross-window
// result land as an ActionOutcomeUpdate. Only when the bundle wrote no
// toolCallId does it fall back to the record id (and then no
// correlation is possible).
func (st *ideParseState) emitToolCall(rec ideRecord, raw string, res *adapter.ParseResult) {
	action, target, contentBytes := normalizeTool(rec.Payload.ToolName, rec.Payload.Args)
	if target == "" {
		target = genericToolTarget(rec.Payload.Args)
	}
	if target == "" {
		// Last resort: an UNMAPPED tool whose args expose no operand the
		// probe table recognises (the live `delete_file` shape before
		// this table existed: `targetFile` + `explanation`) used to land
		// a row with an EMPTY target, which reads as a blank line on
		// every surface. The raw tool name is the honest minimum — it
		// also rides actions.raw_tool_name below, but nothing forces a
		// surface to read that column, and a blank target is worse than
		// a redundant one.
		target = rec.Payload.ToolName
	}
	ev := st.base(rec, st.ideToolEventID(rec, raw))
	ev.ActionType = action
	ev.Target = st.adapter.scrubber.String(target)
	ev.RawToolName = rec.Payload.ToolName
	ev.ContentBytes = contentBytes
	if len(rec.Payload.Args) > 0 {
		ev.RawToolInput = st.adapter.scrubber.RawJSON(rec.Payload.Args)
	}
	idx := len(res.ToolEvents)
	res.ToolEvents = append(res.ToolEvents, ev)
	if rec.Payload.ToolCallID != "" {
		st.pendingCall[rec.Payload.ToolCallID] = idx
	}
}

// applyToolResult stamps the outcome onto its tool_call row. When the
// call was emitted in an EARLIER parse window its row is already
// persisted (optimistically successful), so the outcome goes out as an
// ActionOutcomeUpdate keyed by the same "tool:<toolCallId>" id the emit
// side built. The synthetic interrupted result
// ("<toolCallId>-result-synthetic", success:false) travels this exact
// path — it is an ordinary result record with a verdict.
func (st *ideParseState) applyToolResult(rec ideRecord, res *adapter.ParseResult) {
	callID := rec.Payload.ToolCallID
	if callID == "" {
		return
	}
	success := rec.Payload.Success == nil || *rec.Payload.Success
	output := st.adapter.scrubber.String(contentcap.Cap(rec.Payload.Content.Text, contentcap.DefaultMaxBytes))

	idx, ok := st.pendingCall[callID]
	if !ok || idx >= len(res.ToolEvents) {
		up := models.ActionOutcomeUpdate{
			SourceFile:    st.sourceFile,
			SourceEventID: "tool:" + callID,
			// `success` is always a verdict on a Kiro tool_result (the
			// synthetic interrupted record spells it false explicitly).
			SuccessKnown: true,
			Success:      success,
			ToolOutput:   output,
			DurationMs:   rec.Payload.DurationMs,
		}
		if !success && output != "" {
			up.ErrorMessage = truncate(output, 500)
		}
		res.OutcomeUpdates = append(res.OutcomeUpdates, up)
		return
	}
	ev := &res.ToolEvents[idx]
	ev.Success = success
	ev.DurationMs = rec.Payload.DurationMs
	if output != "" {
		ev.ToolOutput = output
		if !success {
			ev.ErrorMessage = truncate(output, 500)
		}
	}
	delete(st.pendingCall, callID)
}

// emitPendingInteraction records Kiro IDE's turn-approval prompt as an
// ActionPermissionRequest. The prompt itself always succeeded (it was
// asked); the USER'S ANSWER lands on the same row through
// applyInteractionResolved, which is why the row leaves here
// OutcomePending.
//
// Target is the question Kiro showed ("Review changes"), RawToolName the
// interactionType ("tool_approval"), and RawToolInput the options array
// verbatim — the approval is turn-scoped over a file list rather than
// scoped to one tool call, so there is no single tool name to put in
// Target the way the claude-code permission rows do.
func (st *ideParseState) emitPendingInteraction(rec ideRecord, raw string, res *adapter.ParseResult) {
	callID := rec.Payload.ToolCallID
	target := rec.Payload.Question
	if target == "" {
		target = rec.Payload.InteractionType
	}
	ev := st.base(rec, st.ideInteractionEventID(rec, raw))
	ev.ActionType = models.ActionPermissionRequest
	ev.Target = st.adapter.scrubber.String(contentcap.Cap(target, contentcap.DefaultMaxBytes))
	ev.RawToolName = rec.Payload.InteractionType
	if len(rec.Payload.Options) > 0 {
		ev.RawToolInput = st.adapter.scrubber.RawJSON(rec.Payload.Options)
	}
	idx := len(res.ToolEvents)
	res.ToolEvents = append(res.ToolEvents, ev)
	if callID == "" {
		return
	}
	st.pendingInteraction[callID] = idx
	var opts []ideInteractionOption
	if json.Unmarshal(rec.Payload.Options, &opts) == nil {
		kinds := make(map[string]string, len(opts))
		for _, o := range opts {
			kinds[o.OptionID] = o.Kind
		}
		st.interactionKinds[callID] = kinds
	}
}

// applyInteractionResolved stamps the user's answer onto its
// permission_request row, or — when the prompt was emitted in an EARLIER
// parse window — sends the verdict out as an ActionOutcomeUpdate keyed
// by the same "perm:<toolCallId>" id the emit side built.
func (st *ideParseState) applyInteractionResolved(rec ideRecord, res *adapter.ParseResult) {
	callID := rec.Payload.ToolCallID
	if callID == "" {
		return
	}
	granted := interactionGranted(st.interactionKinds[callID][rec.Payload.SelectedOption], rec.Payload)
	delete(st.interactionKinds, callID)

	idx, ok := st.pendingInteraction[callID]
	if !ok || idx >= len(res.ToolEvents) {
		up := models.ActionOutcomeUpdate{
			SourceFile:    st.sourceFile,
			SourceEventID: "perm:" + callID,
			SuccessKnown:  true,
			Success:       granted,
		}
		if !granted {
			up.ErrorMessage = interactionDenialMessage(rec.Payload)
		}
		res.OutcomeUpdates = append(res.OutcomeUpdates, up)
		return
	}
	ev := &res.ToolEvents[idx]
	ev.Success = granted
	if !granted {
		ev.ErrorMessage = interactionDenialMessage(rec.Payload)
	}
	delete(st.pendingInteraction, callID)
}

// interactionDenialMessage renders the refusal an interaction_resolved
// reports, naming the outcome and (when there was one) the option.
func interactionDenialMessage(p idePayload) string {
	if p.SelectedOption != "" {
		return "approval " + p.Outcome + ": " + p.SelectedOption
	}
	return "approval " + p.Outcome
}

// interactionGranted decides whether a resolved interaction authorized
// the work, from the vendor's own option `kind` first and the option id
// only as a same-window-less fallback.
//
// It is FAIL-OPEN by construction: an outcome vocabulary we have not
// grounded leaves the row successful rather than inventing a refusal.
// The rule set is a table walked top-down (CLAUDE.md #5).
func interactionGranted(optionKind string, p idePayload) bool {
	for _, rule := range interactionOutcomeRules {
		for _, candidate := range []string{optionKind, p.Outcome, p.SelectedOption} {
			if candidate != "" && strings.EqualFold(candidate, rule.token) {
				return rule.granted
			}
		}
	}
	return true
}

// interactionOutcomeRules is the ordered outcome table. Grounded values
// (live Kiro IDE 1.0.411, 2026-09-03): kinds "allow_once" / "reject_once",
// outcome "selected", selectedOption "accept" / "reject". The remaining
// spellings are the neighbouring vocabulary the same enum uses elsewhere
// in the approval UI and cost nothing to admit.
var interactionOutcomeRules = []struct {
	token   string
	granted bool
}{
	{"reject_once", false},
	{"reject_always", false},
	{"reject", false},
	{"deny", false},
	{"denied", false},
	{"cancelled", false},
	{"canceled", false},
	{"allow_once", true},
	{"allow_always", true},
	{"accept", true},
	{"allow", true},
	{"approve", true},
}

// ideInteractionEventID is the approval row's dedup id. Like the tool
// rows' id it MUST be rebuildable from the toolCallId alone so a
// cross-window interaction_resolved can address a row it no longer holds.
func (st *ideParseState) ideInteractionEventID(rec ideRecord, raw string) string {
	if rec.Payload.ToolCallID != "" {
		return "perm:" + rec.Payload.ToolCallID
	}
	return "perm:" + st.eventID(rec, "interaction", raw)
}

// flagPendingOutcomes marks every tool call still waiting for its
// result at EOF, so the store holds failure-context bookkeeping for the
// row until the matching ActionOutcomeUpdate reports the real outcome.
func (st *ideParseState) flagPendingOutcomes(res *adapter.ParseResult) {
	for _, pending := range []map[string]int{st.pendingCall, st.pendingInteraction} {
		for _, idx := range pending {
			if idx < len(res.ToolEvents) {
				res.ToolEvents[idx].OutcomePending = true
			}
		}
	}
}

// eventID returns the record's own id (deterministic, §4.5 priority 1),
// falling back to a CONTENT hash of the raw line (priority 2) when the
// bundle wrote none. A positional counter would NOT do: this parser
// resumes from an arbitrary byte offset, so the same record would get a
// different ordinal on a re-parse and defeat the
// (source_file, source_event_id) dedup.
func (st *ideParseState) eventID(rec ideRecord, kind, raw string) string {
	if rec.ID != "" {
		return rec.ID
	}
	return fmt.Sprintf("%s:%s:%s", st.sessionID, kind, lineDigest(raw))
}

// ideToolEventID is the tool row's dedup id. It MUST be derivable from
// the toolCallId alone so a later tool_result can address the row it no
// longer holds in memory; the id/content fallbacks exist only for the
// (unobserved) case of a tool_call with no toolCallId, which is then
// uncorrelatable by construction.
func (st *ideParseState) ideToolEventID(rec ideRecord, raw string) string {
	if rec.Payload.ToolCallID != "" {
		return "tool:" + rec.Payload.ToolCallID
	}
	return "tool:" + st.eventID(rec, "tool", raw)
}

// lineDigest is the first 16 hex chars of the line's SHA-256 — stable
// across re-parses and across parse windows.
func lineDigest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:16]
}

// genericToolTarget derives a display target from an unmapped tool's
// args by probing the arg key names Kiro's tool schemas use for a
// path-ish or command-ish primary operand. It never guesses an ACTION —
// normalizeTool stays the single owner of the action taxonomy — it only
// gives an unknown-action row something legible to show.
func genericToolTarget(rawArgs json.RawMessage) string {
	if len(rawArgs) == 0 {
		return ""
	}
	var probe map[string]any
	if err := json.Unmarshal(rawArgs, &probe); err != nil {
		return ""
	}
	for _, key := range genericTargetKeys {
		if s, ok := probe[key].(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// genericTargetKeys is the ordered probe table for genericToolTarget.
// `targetFile` joined the table from the live Kiro IDE 1.0.411 capture
// (2026-09-03) — `delete_file` names its operand that way, and its
// absence is why one live row landed with a blank target.
var genericTargetKeys = []string{
	"path", "file_path", "filePath", "targetFile", "command", "query", "url", "name",
}

// truncate caps a string to n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for len(cut) > 0 && !isUTF8Start(cut[len(cut)-1]) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

func isUTF8Start(b byte) bool { return b&0xC0 != 0x80 }

// readIDESessionJSON reads the sibling session.json best-effort. A
// missing or malformed file yields a zero value and false — the parse
// still runs (an IDE session's messages.jsonl may exist before the
// state flush), it just has no project root / model / effort.
func readIDESessionJSON(path string) (ideSessionJSON, bool) {
	body, err := os.ReadFile(path) //nolint:gosec // path derives from a validated watch-root trigger
	if err != nil {
		return ideSessionJSON{}, false
	}
	var meta ideSessionJSON
	if err := json.Unmarshal(body, &meta); err != nil {
		return ideSessionJSON{}, false
	}
	return meta, true
}

// ideWorkspacePath returns the session's primary workspace directory:
// workspacePaths[0], falling back to rootPaths[0]. Empty when the
// session has neither (a `global`-bucket session opened with no folder).
func ideWorkspacePath(meta ideSessionJSON) string {
	for _, list := range [][]string{meta.WorkspacePaths, meta.RootPaths} {
		for _, p := range list {
			if strings.TrimSpace(p) != "" {
				return p
			}
		}
	}
	return ""
}
