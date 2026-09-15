package primeagent

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
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// placeholderRoot is the synthetic project root used when the session
// header carries no cwd. store.Ingest promotes it via ON CONFLICT once a
// real cwd is observed.
const placeholderRoot = "[prime-agent]"

// targetMax / reasoningMax / errorMax bound the short display columns.
const (
	targetMax    = 200
	reasoningMax = 200
	errorMax     = 500
)

// Adapter parses Prime Agent session transcripts under
// ~/.prime/agent/sessions. See the package doc for the entry vocabulary,
// the NET-input evidence and the off-limits file list.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and the platform
// cross-mount watch roots.
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
func (*Adapter) Name() string { return models.ToolPrimeAgent }

// WatchPaths implements adapter.Adapter. One root per cross-mount-resolved
// $HOME: Prime Agent uses `<home>/.prime/agent/sessions` identically on
// Linux, macOS and native Windows (`%USERPROFILE%\.prime`), so a WSL2
// observer picks up Windows-side sessions from /mnt/c/Users/<u>/.prime
// and vice versa with no OS branching.
func (a *Adapter) WatchPaths() []string { return a.roots }

// defaultRoots returns ~/.prime/agent/sessions under every
// cross-mount-resolved $HOME.
func defaultRoots() []string {
	var roots []string
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" {
			continue
		}
		roots = append(roots, filepath.Join(h.Path, ".prime", "agent", "sessions"))
	}
	return roots
}

// IsSessionFile implements adapter.Adapter. Two predicates ANDed: the
// `.jsonl` extension, and under one of this adapter's own watch roots.
//
// The shape half deliberately does NOT bind a directory depth. Current
// releases write `sessions/<uuid>.jsonl` flat, but the vendor migrates
// older per-project subdirectories in place, and a `sessions/<slug>/…`
// leftover is still this adapter's file. The under-WatchPaths gate is the
// sole install-root authority — without it a bare `.jsonl` predicate
// would collide with claude-code, codex, pi and openclaw
// ([[feedback-watcher-dispatch]]).
func (a *Adapter) IsSessionFile(path string) bool {
	if !strings.HasSuffix(strings.ToLower(path), ".jsonl") {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// ParseSessionFile implements adapter.Adapter. It streams the JSONL from
// fromOffset to EOF, emitting ToolEvents (session start, user prompts,
// assistant messages, tool calls stamped with their paired results, shell
// executions, compactions) and TokenEvents (one per usage-bearing
// assistant message, plus MAX-upgrade rows for RLM child roll-ups).
//
// The header line is ALWAYS re-read, even on a resumed parse, because its
// `cwd` is the only statement of the project root and its `git.branch`
// the only statement of the branch — both sit behind the cursor once the
// session has any history.
//
// Malformed lines are warned about and skipped with the cursor advanced
// past them, so a bad line can never stall the poll loop. Two shapes are
// deliberately DEFERRED rather than consumed, so the next parse re-reads
// them whole: a partial trailing line (a record still being written), and
// a tool call whose `toolResult` has not landed yet (pending.go).
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from the watcher's own watch roots
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("primeagent.ParseSessionFile: open %s: %w", path, err)
	}
	defer f.Close()

	st := &parseState{
		adapter:     a,
		path:        path,
		sessionID:   sessionIDFromPath(path),
		rootCache:   map[string]string{},
		pendingCall: map[string]pendingMark{},
		seenMessage: map[string]messageMark{},
		firstOffset: fromOffset,
	}
	if err := st.readHeader(f); err != nil {
		return adapter.ParseResult{}, err
	}

	if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
		return adapter.ParseResult{}, fmt.Errorf("primeagent.ParseSessionFile: seek: %w", err)
	}

	res := adapter.ParseResult{NewOffset: fromOffset}

	// bufio.Reader.ReadString (not Scanner) so the cursor advances by the
	// exact terminator length including CRLF, and a long tool-output line
	// isn't capped by a token-size limit ([[feedback-jsonl-parser-cursor]]).
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
			return res, fmt.Errorf("primeagent.ParseSessionFile: read: %w", readErr)
		}
		hasNewline := strings.HasSuffix(lineStr, "\n")
		// A partial trailing line at EOF is a record still being written:
		// defer it and do NOT advance past it.
		if !hasNewline && readErr == io.EOF {
			break
		}
		lineStart := bytesRead
		bytesRead += int64(len(lineStr))
		lineNum++
		// Commit the offset for every terminated line — empty and
		// malformed included — so the poll loop can't spin on one line.
		res.NewOffset = bytesRead

		raw := strings.TrimRight(lineStr, "\r\n")
		if raw == "" {
			if readErr == io.EOF {
				break
			}
			continue
		}
		var rec rawLine
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
			if readErr == io.EOF {
				break
			}
			continue
		}
		st.handle(&rec, lineNum, lineStart, len(res.ToolEvents), len(res.TokenEvents), &res)
		if readErr == io.EOF {
			break
		}
	}
	st.deferUnpairedTail(&res)
	adapter.ApplyProjectIdentity(&res, st.identity)
	return res, nil
}

// parseState carries the per-call bookkeeping the entry handler needs
// across lines.
type parseState struct {
	adapter *Adapter
	path    string

	// sessionID is the filename stem — the UUIDv7 Prime Agent names the
	// file after, which equals the header's `id` by construction. It is
	// derived from the PATH and never re-keyed from the header, because a
	// resumed parse seeks past the header and a header-derived id would
	// split one session in two (§4.5a, the Gemini header-UUID trap).
	sessionID string
	// cwd is the raw absolute path from the header; branch comes from the
	// header's git block, refined by git.Resolve when it disagrees.
	cwd    string
	branch string
	// remote is the normalized git remote, resolved alongside the project
	// root (see projectRoot). Unlike branch, this comes ONLY from
	// git.Resolve, not the header's own git block.
	remote string
	// identity is the Project Identity Resolver v2 bundle (2026-09-06,
	// §3.1 / W1) resolved alongside branch/remote by projectRoot, applied
	// to every event in the ParseResult via adapter.ApplyProjectIdentity
	// before ParseSessionFile returns.
	identity git.Identity
	// rootCache memoizes cwd → resolved project root (git.Resolve walks
	// the filesystem and one transcript shares one cwd throughout).
	rootCache map[string]string

	// provider/model track the session's currently selected model, seeded
	// by `model_change` and by each assistant message's own inline fields.
	provider string
	model    string

	// pendingCall maps a toolCall id to its rewind coordinates so the
	// later toolResult can stamp the outcome onto the same event.
	pendingCall map[string]pendingMark
	// seenMessage maps an assistant entry id to the model + timestamp its
	// record carried, so a later child_usage_attributed entry targeting it
	// can emit a matching upgrade row.
	seenMessage map[string]messageMark

	firstOffset    int64
	sessionStarted bool
}

// messageMark is the minimum an assistant record leaves behind for a
// later child-usage roll-up: which model was billed and when.
type messageMark struct {
	model string
	ts    time.Time
}

// readHeader reads line 0 independently of the parse cursor and records
// the cwd + branch. A missing, empty or non-session first line is
// tolerated: the filename stem still supplies the session id and the
// project root falls back to the placeholder.
func (st *parseState) readHeader(f *os.File) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("primeagent.readHeader: seek: %w", err)
	}
	line, err := bufio.NewReaderSize(f, 64*1024).ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("primeagent.readHeader: read: %w", err)
	}
	raw := strings.TrimRight(line, "\r\n")
	if raw == "" {
		return nil
	}
	var rec rawLine
	if err := json.Unmarshal([]byte(raw), &rec); err != nil || rec.Type != typeSession {
		return nil
	}
	st.cwd = rec.Cwd
	if rec.Git != nil {
		st.branch = rec.Git.Branch
	}
	return nil
}

// handle dispatches one decoded entry. Every type the vendor documents
// but this adapter does not consume falls through the default arm
// SILENTLY (§4.4e) — agent_status alone outnumbered messages 3:1 in the
// grounding session, so warning on unconsumed entries would flood the
// watcher log on every poll.
func (st *parseState) handle(rec *rawLine, lineNum int, lineStart int64, toolLen, tokenLen int, res *adapter.ParseResult) {
	switch rec.Type {
	case typeSession:
		st.emitSessionStart(rec, res)
	case typeModelChange:
		if rec.Provider != "" {
			st.provider = rec.Provider
		}
		if rec.ModelID != "" {
			st.model = rec.ModelID
		}
	case typeMessage:
		if rec.Message != nil {
			st.emitMessage(rec, rec.Message, lineNum, lineStart, toolLen, tokenLen, res)
		}
	case typeCompaction:
		st.emitCompaction(rec, lineNum, res)
	case typeChildUsageAttr:
		st.emitChildUsage(rec, res)
	}
}

// emitSessionStart records the header as a session-start marker, only
// when parsing from the very top of the file.
func (st *parseState) emitSessionStart(rec *rawLine, res *adapter.ParseResult) {
	if st.firstOffset != 0 || st.sessionStarted || st.sessionID == "" {
		return
	}
	st.sessionStarted = true
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: "session_start:" + st.sessionID,
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot(),
		Timestamp:     parseTimestamp(rec.Timestamp),
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Tool:          models.ToolPrimeAgent,
		ActionType:    models.ActionSessionStart,
		Target:        "startup",
		RawToolName:   models.ToolPrimeAgent + ".session_start",
		Success:       true,
	})
}

// emitMessage walks one `message` entry into its rows.
func (st *parseState) emitMessage(rec *rawLine, msg *agentMessage, lineNum int, lineStart int64, toolLen, tokenLen int, res *adapter.ParseResult) {
	if msg.Provider != "" {
		st.provider = msg.Provider
	}
	if msg.Model != "" {
		st.model = msg.Model
	}
	ts := st.timestamp(rec, msg)

	switch msg.Role {
	case roleUser:
		st.emitUserPrompt(rec, msg, lineNum, ts, res)
	case roleAssistant:
		st.emitAssistant(rec, msg, lineNum, lineStart, toolLen, tokenLen, ts, res)
	case roleToolResult:
		st.stampToolResult(msg, res)
	case roleBashExecution:
		st.emitBashExecution(rec, msg, lineNum, ts, res)
	case roleCompactionSummary:
		st.emitCompactionSummaryMessage(rec, msg, lineNum, ts, res)
	}
	// branchSummary and custom messages are extension/branch bookkeeping
	// with no normalized action type; skipped silently.
}

func (st *parseState) emitUserPrompt(rec *rawLine, msg *agentMessage, lineNum int, ts time.Time, res *adapter.ParseResult) {
	text := msg.Content.text()
	if text == "" {
		return
	}
	scrubbed := st.adapter.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes))
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: st.eventID("user", rec.ID, lineNum),
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot(),
		Timestamp:     ts,
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Model:         st.modelString(msg),
		Tool:          models.ToolPrimeAgent,
		ActionType:    models.ActionUserPrompt,
		Target:        truncate(scrubbed, targetMax),
		Success:       true,
		RawToolName:   "message.user",
		RawToolInput:  scrubbed,
		MessageID:     messageID(rec.ID, lineNum),
	})
}

// emitAssistant produces, from one assistant record: a row per toolCall,
// an assistant_message row when the model said something, a terminal row
// for an error / abort stopReason, and the record's token row.
//
// The record's `thinking` blocks are carried ONLY as PrecedingReasoning
// on those rows — never as a standalone action. Reasoning is not an
// action, and minting a row for it pollutes every action aggregate (the
// B3 convergence pi already went through). Because Prime Agent carries
// the whole turn in one record with no ordering between blocks, the
// reasoning FANS OUT to every row the record produces.
func (st *parseState) emitAssistant(rec *rawLine, msg *agentMessage, lineNum int, lineStart int64, toolLen, tokenLen int, ts time.Time, res *adapter.ParseResult) {
	reasoning := st.adapter.scrubber.String(truncate(msg.Content.thinking(), reasoningMax))
	model := st.modelString(msg)
	msgID := messageID(rec.ID, lineNum)
	root := st.projectRoot()
	if rec.ID != "" {
		st.seenMessage[rec.ID] = messageMark{model: model, ts: ts}
	}

	for i, call := range msg.Content.toolCalls() {
		rawArgs, _ := json.Marshal(call.Arguments)
		ev := models.ToolEvent{
			SourceFile:         st.path,
			SourceEventID:      st.eventID(fmt.Sprintf("tool%d", i), call.ID, lineNum),
			SessionID:          st.sessionID,
			ProjectRoot:        root,
			Timestamp:          ts,
			GitBranch:          st.branch,
			GitRemote:          st.remote,
			Model:              model,
			Tool:               models.ToolPrimeAgent,
			ActionType:         mapToolName(call.Name),
			Target:             truncate(st.adapter.scrubber.String(targetFromArgs(call.Arguments, call.Name)), targetMax),
			Success:            true,
			PrecedingReasoning: reasoning,
			RawToolName:        call.Name,
			RawToolInput:       st.adapter.scrubber.RawJSON(rawArgs),
			ContentBytes:       authoredBytes(call),
			MessageID:          msgID,
			OutcomePending:     true,
		}
		if call.ID != "" {
			st.pendingCall[call.ID] = pendingMark{
				idx:       len(res.ToolEvents),
				lineStart: lineStart,
				toolLen:   toolLen,
				tokenLen:  tokenLen,
			}
		}
		res.ToolEvents = append(res.ToolEvents, ev)
	}

	if text := msg.Content.text(); text != "" {
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile:         st.path,
			SourceEventID:      st.eventID("assistant", rec.ID, lineNum),
			SessionID:          st.sessionID,
			ProjectRoot:        root,
			Timestamp:          ts,
			GitBranch:          st.branch,
			GitRemote:          st.remote,
			Model:              model,
			Tool:               models.ToolPrimeAgent,
			ActionType:         models.ActionAssistantMessage,
			Target:             truncate(st.adapter.scrubber.String(text), targetMax),
			Success:            true,
			PrecedingReasoning: reasoning,
			RawToolName:        "message.assistant",
			ToolOutput:         st.adapter.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes)),
			MessageID:          msgID,
		})
	}

	st.emitTerminal(rec, msg, lineNum, ts, model, root, reasoning, msgID, res)
	st.emitUsage(rec, msg, lineNum, ts, model, root, msgID, res)
}

// emitTerminal records a turn that ended badly. "stop" and "length" are
// ordinary completions already represented by the assistant_message row
// (length is a non-error truncation), and "toolUse" is a mid-turn pause
// awaiting a result — none of the three gets a row of its own.
func (st *parseState) emitTerminal(rec *rawLine, msg *agentMessage, lineNum int, ts time.Time, model, root, reasoning, msgID string, res *adapter.ParseResult) {
	var action string
	switch msg.StopReason {
	case "error":
		action = models.ActionAPIError
	case "aborted":
		action = models.ActionTurnAborted
	default:
		return
	}
	errMsg := st.adapter.scrubber.String(truncate(msg.ErrorMessage, errorMax))
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:         st.path,
		SourceEventID:      st.eventID(msg.StopReason, rec.ID, lineNum),
		SessionID:          st.sessionID,
		ProjectRoot:        root,
		Timestamp:          ts,
		GitBranch:          st.branch,
		GitRemote:          st.remote,
		Model:              model,
		Tool:               models.ToolPrimeAgent,
		ActionType:         action,
		Target:             truncate(firstNonEmpty(errMsg, msg.StopReason), targetMax),
		Success:            false,
		ErrorMessage:       errMsg,
		PrecedingReasoning: reasoning,
		RawToolName:        "message.assistant." + msg.StopReason,
		MessageID:          msgID,
	})
}

// emitUsage records the record's token envelope. An all-zero envelope —
// what a provider 401/402 leaves behind — produces nothing (§4.4b).
func (st *parseState) emitUsage(rec *rawLine, msg *agentMessage, lineNum int, ts time.Time, model, root, msgID string, res *adapter.ParseResult) {
	if msg.Usage.empty() {
		return
	}
	res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
		SourceFile:    st.path,
		SourceEventID: st.eventID("usage", rec.ID, lineNum),
		SessionID:     st.sessionID,
		ProjectRoot:   root,
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Timestamp:     ts,
		Tool:          models.ToolPrimeAgent,
		Model:         model,
		// NOT netted: Prime Agent's `input` already excludes the cached
		// prefix (totalTokens == input+output+cacheRead+cacheWrite holds
		// exactly on every observed row). See the package doc.
		InputTokens:         msg.Usage.Input,
		OutputTokens:        msg.Usage.Output,
		CacheReadTokens:     msg.Usage.CacheRead,
		CacheCreationTokens: msg.Usage.CacheWrite,
		// No reasoning-token field exists in this schema on either API
		// lane; the thinking TEXT is captured, the count is not published.
		EstimatedCostUSD: msg.Usage.Cost.Total,
		Source:           models.TokenSourceJSONL,
		Reliability:      models.ReliabilityApproximate,
		MessageID:        msgID,
	})
}

// emitChildUsage folds an RLM child run's usage into its parent assistant
// message by re-emitting the parent's token row with the AGGREGATE
// counts, under the SAME SourceEventID. store.InsertTokenEvents'
// ON CONFLICT MAX-upgrade (§8.2) then raises the stored row in place.
//
// Keying it to the parent is what stops the double count: the child's
// tokens are, by the vendor's own reload semantics, already destined to
// be part of the parent's total. It works whether or not the parent
// record was parsed in this same window — when it was, the remembered
// model/timestamp are reused; otherwise the session's current model and
// the entry's own timestamp stand in.
func (st *parseState) emitChildUsage(rec *rawLine, res *adapter.ParseResult) {
	if rec.TargetID == "" || rec.AggregateUsage.empty() {
		return
	}
	mark, ok := st.seenMessage[rec.TargetID]
	if !ok {
		mark = messageMark{model: st.modelString(nil), ts: parseTimestamp(rec.Timestamp)}
	}
	u := rec.AggregateUsage
	res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
		SourceFile:          st.path,
		SourceEventID:       "usage:" + rec.TargetID,
		SessionID:           st.sessionID,
		ProjectRoot:         st.projectRoot(),
		GitBranch:           st.branch,
		GitRemote:           st.remote,
		Timestamp:           mark.ts,
		Tool:                models.ToolPrimeAgent,
		Model:               mark.model,
		InputTokens:         u.Input,
		OutputTokens:        u.Output,
		CacheReadTokens:     u.CacheRead,
		CacheCreationTokens: u.CacheWrite,
		EstimatedCostUSD:    u.Cost.Total,
		Source:              models.TokenSourceJSONL,
		Reliability:         models.ReliabilityApproximate,
		MessageID:           rec.TargetID,
	})
}

// stampToolResult attaches a result to the call it answers. A result
// whose call is not in this window is dropped: the deferral in pending.go
// exists precisely so that cannot happen for a call observer emitted.
func (st *parseState) stampToolResult(msg *agentMessage, res *adapter.ParseResult) {
	mark, ok := st.pendingCall[msg.ToolCallID]
	if !ok || mark.idx >= len(res.ToolEvents) {
		return
	}
	delete(st.pendingCall, msg.ToolCallID)
	ev := &res.ToolEvents[mark.idx]
	output := msg.Content.text()
	ev.ToolOutput = st.adapter.scrubber.String(contentcap.Cap(output, contentcap.DefaultMaxBytes))
	ev.Success = !msg.IsError
	ev.OutcomePending = false
	if msg.IsError {
		ev.ErrorMessage = st.adapter.scrubber.String(truncate(output, errorMax))
	}
	if msg.Details != nil && msg.Details.DurationMs > 0 {
		ev.DurationMs = msg.Details.DurationMs
	}
}

// emitBashExecution records the `bashExecution` role. These come from
// EITHER the model calling a shell tool OR the operator running a
// !-prefixed command in the TUI; both are run_command. A cancelled
// command is a failure even though its exitCode is undefined.
func (st *parseState) emitBashExecution(rec *rawLine, msg *agentMessage, lineNum int, ts time.Time, res *adapter.ParseResult) {
	success := !msg.Cancelled && (msg.ExitCode == nil || *msg.ExitCode == 0)
	command := st.adapter.scrubber.String(msg.Command)
	output := st.adapter.scrubber.String(contentcap.Cap(msg.Output, contentcap.DefaultMaxBytes))
	errMsg := ""
	switch {
	case msg.Cancelled:
		errMsg = "cancelled"
	case !success:
		errMsg = truncate(output, errorMax)
	}
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: st.eventID("bash", rec.ID, lineNum),
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot(),
		Timestamp:     ts,
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Model:         st.modelString(msg),
		Tool:          models.ToolPrimeAgent,
		ActionType:    models.ActionRunCommand,
		Target:        truncate(command, targetMax),
		Success:       success,
		ErrorMessage:  errMsg,
		RawToolName:   "message.bashExecution",
		RawToolInput:  command,
		ToolOutput:    output,
		MessageID:     messageID(rec.ID, lineNum),
	})
}

// emitCompaction records a `compaction` ENTRY — the context-window
// summarisation the harness performs, with the pre-compaction token count
// it reclaimed.
func (st *parseState) emitCompaction(rec *rawLine, lineNum int, res *adapter.ParseResult) {
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: st.eventID("compaction", rec.ID, lineNum),
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot(),
		Timestamp:     parseTimestamp(rec.Timestamp),
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Model:         st.modelString(nil),
		Tool:          models.ToolPrimeAgent,
		ActionType:    models.ActionContextCompacted,
		Target:        truncate(fmt.Sprintf("%d tokens before compaction", rec.TokensBefore), targetMax),
		Success:       true,
		RawToolName:   "compaction",
		ToolOutput:    st.adapter.scrubber.String(contentcap.Cap(rec.Summary, contentcap.DefaultMaxBytes)),
		MessageID:     messageID(rec.ID, lineNum),
	})
}

// emitCompactionSummaryMessage records the compactionSummary MESSAGE role
// — the in-context form of the same event, produced by extensions that
// compact through the message stream rather than the entry stream.
func (st *parseState) emitCompactionSummaryMessage(rec *rawLine, msg *agentMessage, lineNum int, ts time.Time, res *adapter.ParseResult) {
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: st.eventID("compaction_summary", rec.ID, lineNum),
		SessionID:     st.sessionID,
		ProjectRoot:   st.projectRoot(),
		Timestamp:     ts,
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		Model:         st.modelString(msg),
		Tool:          models.ToolPrimeAgent,
		ActionType:    models.ActionContextCompacted,
		Target:        truncate(st.adapter.scrubber.String(msg.Summary), targetMax),
		Success:       true,
		RawToolName:   "message.compactionSummary",
		ToolOutput:    st.adapter.scrubber.String(contentcap.Cap(msg.Summary, contentcap.DefaultMaxBytes)),
		MessageID:     messageID(rec.ID, lineNum),
	})
}

// projectRoot resolves the header cwd to a git working-tree root.
//
// The crossmount translation is UNCONDITIONAL and happens BEFORE
// git.Resolve: a WSL2 observer reading a Windows-side install sees a
// `C:\...` cwd, and filepath.IsAbs treats that as RELATIVE on Linux, so
// git.Resolve would CWD-prefix the observer's own .git onto every event
// ([[feedback-foreign-path-git-resolve]]).
func (st *parseState) projectRoot() string {
	if st.cwd == "" {
		return placeholderRoot
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
	if id.Branch != "" {
		st.branch = id.Branch
	}
	// id.Remote is already NormalizeRemote'd by ResolveIdentity.
	st.remote = id.Remote
	st.identity = id
	return id.Root
}

// timestamp prefers the message's inner Unix-millisecond value and falls
// back to the entry envelope's ISO string.
func (st *parseState) timestamp(rec *rawLine, msg *agentMessage) time.Time {
	if msg != nil {
		if t := parseUnixMillis(msg.Timestamp); !t.IsZero() {
			return t
		}
	}
	return parseTimestamp(rec.Timestamp)
}

// modelString renders the billed model.
//
// `responseModel` is preferred when the record carries one: Prime Agent
// lets a session select an ALIAS (`~deepseek/deepseek-v4-flash-latest`)
// and the response reports the concrete model the alias resolved to
// (`deepseek/deepseek-v4-flash-0731`) — which is what was actually
// billed. The provider is always prefixed so the cost engine sees one
// stable spelling.
func (st *parseState) modelString(msg *agentMessage) string {
	provider, model := st.provider, st.model
	if msg != nil {
		if msg.Provider != "" {
			provider = msg.Provider
		}
		if msg.ResponseModel != "" {
			model = msg.ResponseModel
		} else if msg.Model != "" {
			model = msg.Model
		}
	}
	switch {
	case provider != "" && model != "":
		return provider + "/" + model
	default:
		return model
	}
}

// eventID builds a deterministic source event id: the native 8-hex entry
// (or toolCall) id when present, the line number otherwise. Re-parsing
// the same bytes must produce the same ids or the
// (source_file, source_event_id) dedup key stops deduping (§4.5).
func (st *parseState) eventID(kind, id string, lineNum int) string {
	if strings.TrimSpace(id) != "" {
		return kind + ":" + id
	}
	return fmt.Sprintf("%s:L%d", kind, lineNum)
}

// messageID identifies the API turn a row belongs to.
func messageID(id string, lineNum int) string {
	if strings.TrimSpace(id) != "" {
		return id
	}
	return fmt.Sprintf("L%d", lineNum)
}

// sessionIDFromPath recovers the session uuid from `<uuid>.jsonl`. It is
// the canonical id for every row of the file (§4.5a).
func sessionIDFromPath(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// mapToolName maps a native tool name onto a normalized action type.
//
// Prime Agent's ONE built-in tool is `ipython` — a persistent Python
// kernel the model drives to read files, edit code and run commands, so
// it is a run_command. `bash` and `edit` are the other two built-in names
// docs/extensions.md says an extension may override. Everything past
// those three is the conventional defensive vocabulary for custom
// extension tools.
//
// Every case label here has a matching row in internal/tooltax; the
// conformance test in this package pins both directions.
func mapToolName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ipython", "bash", "shell", "command", "exec", "execute", "run":
		return models.ActionRunCommand
	case "edit", "patch", "apply_patch", "edit_file":
		return models.ActionEditFile
	case "read", "cat", "view", "read_file":
		return models.ActionReadFile
	case "write", "create", "write_file", "create_file":
		return models.ActionWriteFile
	case "grep", "search", "search_text":
		return models.ActionSearchText
	case "glob", "find", "ls", "list_files":
		return models.ActionSearchFiles
	case "web_search", "websearch":
		return models.ActionWebSearch
	case "web_fetch", "fetch", "fetch_url":
		return models.ActionWebFetch
	default:
		// A custom extension tool CAN register an mcp__-prefixed name.
		// Prime Agent's own MCP integrations are reached from inside the
		// kernel (`integration.<tool>(…)`), so this arm is defensive.
		if models.IsMCPToolName(name) {
			return models.ActionMCPCall
		}
		return models.ActionUnknown
	}
}

// argTargetKeys is the ordered list of argument keys that can carry a
// tool call's display target. `code` leads because the built-in ipython
// tool's only argument is the Python source.
var argTargetKeys = []string{"code", "path", "file", "filePath", "command", "cmd", "pattern", "query", "url"}

// targetFromArgs picks the most descriptive argument for the Target
// column, falling back to the tool name.
func targetFromArgs(args map[string]any, fallback string) string {
	for _, key := range argTargetKeys {
		if v, ok := args[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return fallback
}

// authoredBytes is the §8.5 ContentBytes decision, made explicitly: an
// `ipython` call's `code` argument IS code the model authored, so its
// byte length is reported. Nothing else in Prime Agent's tool surface
// carries an authored body, so every other call reports zero rather than
// a fabricated count.
func authoredBytes(call contentPart) int64 {
	if !strings.EqualFold(strings.TrimSpace(call.Name), "ipython") {
		return 0
	}
	code, _ := call.Arguments["code"].(string)
	return int64(len(code))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// truncate cuts to at most n bytes without splitting the string mid-rune
// beyond what the display columns tolerate (the same byte-truncation
// every other adapter applies).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
