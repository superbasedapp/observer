package muse

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
	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// sessionLogName is the fixed basename of every Muse session log — the
// session UUID lives in the enclosing DIRECTORY, not the filename.
const sessionLogName = "session.jsonl"

// subagentDir is the directory a session's child-agent logs live under
// (`<session>/subagent/<child-uuid>/session.jsonl`).
const subagentDir = "subagent"

// headerScanLines bounds the from-offset-0 header re-read. The
// `runtime.session.metadata` record that states workspace_root is sequence
// 1 — the very first line — so a handful of lines is plenty; the bound
// exists so a corrupt or unexpectedly-shaped log can never turn the header
// read into a full-file scan on every poll tick.
const headerScanLines = 64

// Adapter parses Meta Muse Code session logs under
// ~/.local/share/muse/sessions/YYYY/MM/DD/<session-uuid>/session.jsonl.
// See the package doc for the record shapes, the two gross→net token
// corrections and the off-limits file list.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and platform-default
// cross-mount watch roots.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots()}
}

// NewWithOptions customizes the scrubber and/or watch roots for tests. A nil
// scrubber falls back to scrub.New(); no roots falls back to the platform
// defaults.
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
func (*Adapter) Name() string { return models.ToolMuse }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// defaultRoots returns every plausible Muse session tree.
//
// Muse is XDG-shaped on both platforms it ships for (Linux and macOS use
// `~/.local/share/muse` alike; there is no Windows build), so one join per
// cross-mount-resolved $HOME covers a WSL2 observer reading a foreign home
// as well. `$XDG_DATA_HOME` is honoured for the CURRENT process only — it
// is a per-host variable and inventing one for a foreign home would be a
// guess, not a capability.
func defaultRoots() []string {
	seen := map[string]bool{}
	var roots []string
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		roots = append(roots, p)
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); filepath.IsAbs(xdg) {
		add(filepath.Join(xdg, "muse", "sessions"))
	}
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(h.Path, ".local", "share", "muse", "sessions"))
	}
	return roots
}

// IsSessionFile implements adapter.Adapter. A path qualifies only when it is
// BOTH under one of this adapter's watch roots AND has the Muse session-log
// shape. The sibling `cron.db`, `.session.lock` and `tool-outputs/` entries
// are all rejected by the basename test; child-agent logs under
// `subagent/<uuid>/` are ACCEPTED (they carry tokens the parent log does
// not — see the package doc).
func (a *Adapter) IsSessionFile(path string) bool {
	if !matchesShape(path) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// matchesShape reports whether path has the Muse session-log shape,
// independent of watch roots. Comparison is on a slash-normalized,
// lower-cased copy so Windows separators and case-insensitive mounts match
// too.
func matchesShape(path string) bool {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	if filepath.Base(lower) != sessionLogName {
		return false
	}
	return strings.Contains(lower, "/muse/sessions/")
}

// ParseSessionFile implements adapter.Adapter. It streams the JSONL from
// fromOffset to EOF, emitting ToolEvents (session start/end markers, user
// prompts, assistant messages, tool calls stamped with their outcome and
// result body, aborted turns) and TokenEvents (one per model_completed
// record, with GROSS input netted against cache-read and GROSS output
// netted against reasoning).
//
// The header is ALWAYS re-read from offset 0, even on a resumed parse:
// `runtime.session.metadata.workspace_root` is the only statement of the
// project root anywhere in the tree, and the directory name is a UUID that
// carries none. Malformed lines are skipped with a warning and the byte
// cursor advances past every fully terminated line, so a bad line can't
// stall the poll loop. Two record shapes are deliberately deferred rather
// than consumed, so the next parse re-reads them whole: a partial trailing
// line (a record still being written) and a tool call whose result batch
// has not landed yet (see pending.go).
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from the watcher's own watch roots
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("muse.ParseSessionFile: open %s: %w", path, err)
	}
	defer f.Close()

	st := &parseState{
		adapter:     a,
		path:        path,
		rootCache:   map[string]string{},
		pendingCall: map[string]pendingMark{},
		toolIdx:     map[string]int{},
		unknownTool: map[string]bool{},
		firstOffset: fromOffset,
		sessionID:   sessionIDFromPath(path),
		isSubagent:  isSubagentLog(path),
		cacheAcc:    cacheobs.New(MaxBlocksPerSession),
	}
	if err := st.readHeader(f); err != nil {
		return adapter.ParseResult{}, err
	}

	if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
		return adapter.ParseResult{}, fmt.Errorf("muse.ParseSessionFile: seek: %w", err)
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
			return res, ctx.Err()
		}
		lineStr, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			return res, fmt.Errorf("muse.ParseSessionFile: read: %w", readErr)
		}
		hasNewline := strings.HasSuffix(lineStr, "\n")
		// A partial trailing line (no '\n' at EOF) is a still-being-written
		// record: defer it, do NOT advance the cursor past it, so the next
		// parse re-reads it whole.
		if !hasNewline && readErr == io.EOF {
			break
		}
		lineStart := bytesRead
		bytesRead += int64(len(lineStr))
		lineNum++
		// Commit the offset for every terminated line, even empty or
		// malformed ones, so the poll loop can't spin on a bad line.
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
		st.curLineStart = lineStart
		st.curToolLen = len(res.ToolEvents)
		st.curTokenLen = len(res.TokenEvents)
		st.handle(&rec, lineStart, &res)
		if readErr == io.EOF {
			break
		}
	}
	st.deferUnpairedTail(&res)
	return res, nil
}

// parseState carries the per-call mutable bookkeeping the record handler
// needs across lines.
type parseState struct {
	adapter *Adapter
	path    string
	// rootCache memoizes cwd → resolved project root (git.Resolve walks the
	// filesystem, and one session log shares one workspace root throughout).
	rootCache map[string]string
	// pendingCall maps a tool call_id to the rewind coordinates of the
	// record that produced its ToolEvent. An entry survives until the
	// matching tool_result_batch_committed lands; whatever is still pending
	// at EOF drives the tail deferral in pending.go.
	pendingCall map[string]pendingMark
	// toolIdx maps a tool call_id to its ToolEvent's index in
	// res.ToolEvents, so the later outcome + result records can stamp onto
	// it. Kept separate from pendingCall because the outcome record
	// (tool_batch.effect.terminal) arrives BEFORE the result batch that
	// resolves the pending entry.
	toolIdx map[string]int
	// curLineStart / curToolLen / curTokenLen are the rewind coordinates of
	// the record currently being handled, captured by the line loop before
	// dispatch.
	curLineStart int64
	curToolLen   int
	curTokenLen  int
	// unknownTool dedupes the "unrecognised tool name" warning so a long
	// session with many calls to one unmapped tool warns once.
	unknownTool map[string]bool
	// firstOffset is the fromOffset the parse started at; the session-start
	// marker is only emitted when parsing from the very top of the file.
	firstOffset int64
	// sessionStarted guards against emitting more than one session-start
	// marker per parse call.
	sessionStarted bool
	// sessionID is the canonical session uuid, always derived from the PATH
	// (§4.5a). For a child-agent log it is the PARENT's uuid, so sub-agent
	// work rolls up into the session the operator recognises.
	sessionID string
	// isSubagent marks a `subagent/<child>/session.jsonl` log; every event
	// it produces is flagged IsSidechain.
	isSubagent bool
	// cwd is the raw absolute workspace root stated by the log header.
	cwd string
	// branch is the git branch, resolved alongside the project root and
	// overridden by a `session.workspace_branch.observed` record when the
	// log states one (grounded data beats an inferred one).
	branch string
	// remote is the normalized git remote, resolved alongside the project
	// root (see projectRoot). Unlike branch, the log never states its own
	// remote, so this is git.Resolve's value unconditionally.
	remote string
	// identity is the Project Identity Resolver v2 bundle (2026-09-06,
	// §3.1 / W1) resolved alongside branch/remote.
	identity git.Identity
	// model is the most recent model id seen, used to stamp tool/message
	// events that carry no model of their own.
	model string
	// cacheAcc accumulates this parse call's running Tier-2
	// content-block delta (prompt / assistant messages / tool calls /
	// tool results, in wire order) and drains it into one
	// CacheTurnObservation per model_completed record (see
	// emitTokens / emitCacheObservation in cachetrack.go).
	cacheAcc *cacheobs.Accumulator
}

// sessionIDFromPath recovers the canonical session uuid from the log path.
//
//	…/sessions/YYYY/MM/DD/<uuid>/session.jsonl                     → <uuid>
//	…/sessions/YYYY/MM/DD/<uuid>/subagent/<child>/session.jsonl    → <uuid>
//
// A child log resolves to its PARENT's id deliberately: one canonical
// session id per session tree keeps sub-agent tokens and actions attached
// to the session the operator opened, the same way claudecode folds
// sidechain lines into the parent session.
func sessionIDFromPath(path string) string {
	segs := pathSegments(path)
	if len(segs) < 2 {
		return ""
	}
	// Drop the filename; the session dir is now the last segment.
	segs = segs[:len(segs)-1]
	if i := lastIndex(segs, subagentDir); i > 0 {
		return segs[i-1]
	}
	return segs[len(segs)-1]
}

// isSubagentLog reports whether path is a child-agent log.
func isSubagentLog(path string) bool {
	return lastIndex(pathSegments(path), subagentDir) > 0
}

// parentLogPath returns the parent session's log path for a child-agent
// log, or "" when path is not a child log. The path is DERIVED, never
// observed — readHeader refuses a symlink at the derived location so the
// sibling lookup can't be used to pull in a file this adapter promises
// never to read.
func parentLogPath(path string) string {
	segs := pathSegments(path)
	i := lastIndex(segs, subagentDir)
	if i <= 0 {
		return ""
	}
	parent := filepath.Join(segs[:i]...)
	if strings.HasPrefix(filepath.ToSlash(path), "/") {
		parent = string(filepath.Separator) + parent
	}
	return filepath.Join(parent, sessionLogName)
}

// pathSegments splits a path into its non-empty segments, normalising
// Windows separators first.
func pathSegments(path string) []string {
	norm := strings.ReplaceAll(path, `\`, "/")
	parts := strings.Split(norm, "/")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// lastIndex returns the index of the last occurrence of want in segs, or -1.
func lastIndex(segs []string, want string) int {
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i] == want {
			return i
		}
	}
	return -1
}

// readHeader re-reads the top of the log (position 0, independent of the
// parse cursor) for the workspace root, so a resumed parse still resolves a
// project root. A child-agent log carries no metadata record of its own, so
// the parent's log is read instead.
func (st *parseState) readHeader(f *os.File) error {
	if st.isSubagent {
		st.cwd = workspaceRootOf(parentLogPath(st.path))
		return nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("muse.readHeader: seek: %w", err)
	}
	st.cwd = scanWorkspaceRoot(f)
	return nil
}

// workspaceRootOf opens a DERIVED log path and returns the workspace root it
// states. Symlinks are refused outright: a real Muse install never writes
// one there, so the refusal costs nothing and keeps the package doc's
// "never reads" list true by construction. A missing or malformed file
// yields "" — the project root simply stays empty.
func workspaceRootOf(path string) string {
	if path == "" {
		return ""
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ""
	}
	f, err := os.Open(path) //nolint:gosec // derived from a watched log path; symlinks refused above
	if err != nil {
		return ""
	}
	defer f.Close()
	return scanWorkspaceRoot(f)
}

// scanWorkspaceRoot reads at most headerScanLines lines from r's current
// position and returns the first stated workspace_root.
func scanWorkspaceRoot(r io.Reader) string {
	br := bufio.NewReaderSize(r, 64*1024)
	for i := 0; i < headerScanLines; i++ {
		line, err := br.ReadString('\n')
		raw := strings.TrimRight(line, "\r\n")
		if raw != "" {
			var rec rawRecord
			if jsonErr := json.Unmarshal([]byte(raw), &rec); jsonErr == nil &&
				rec.Payload != nil && rec.Payload.Record != nil &&
				rec.Payload.Record.WorkspaceRoot != "" {
				return rec.Payload.Record.WorkspaceRoot
			}
		}
		if err != nil {
			return ""
		}
	}
	return ""
}

// handle dispatches one decoded record onto the appropriate emit path.
// lineStart is the record's byte offset in the file, used as a
// resume-independent fallback event id.
func (st *parseState) handle(rec *rawRecord, lineStart int64, res *adapter.ParseResult) {
	// A retained-marker tombstone records that an EPHEMERAL record was
	// deliberately not written durably. It is expected noise, not a
	// malformed line — skip it silently (§4.4e).
	if rec.isMarker() || rec.Payload == nil {
		return
	}
	switch rec.PayloadType {
	case ptSessionMeta:
		if r := rec.Payload.Record; r != nil && r.WorkspaceRoot != "" {
			st.cwd = r.WorkspaceRoot
		}
	case ptWorkspaceBranch:
		st.applyBranch(rec.Payload.Record)
	case ptRunModel:
		if r := rec.Payload.Record; r != nil && r.ModelID != "" {
			st.model = r.ModelID
		}
	case ptSessionOpened:
		st.emitSessionStart(rec, res)
	case ptSessionEnd:
		st.emitSessionEnd(rec, lineStart, res)
	case ptToolBatchTerm:
		st.applyOutcome(rec.Payload.Record, res)
	case ptRuntimeSession:
		st.handleSessionEvent(rec, lineStart, res)
	}
	// Any other payload_type is informational and skipped silently.
}

// applyBranch adopts the branch a workspace_branch record states. Only a
// `branch` reference is adopted: a detached HEAD reports a different kind,
// and recording its name as a branch would be a fabricated fact.
func (st *parseState) applyBranch(r *metaRecord) {
	if r == nil || r.Reference == nil {
		return
	}
	if r.Reference.Kind == "branch" && r.Reference.Name != "" {
		st.branch = r.Reference.Name
	}
	if r.WorkspaceRoot != "" && st.cwd == "" {
		st.cwd = r.WorkspaceRoot
	}
}

// handleSessionEvent dispatches the runtime.session record's inner event.
func (st *parseState) handleSessionEvent(rec *rawRecord, lineStart int64, res *adapter.ParseResult) {
	ev := rec.Payload.Event
	if ev == nil {
		return
	}
	switch ev.Kind {
	case evStarted:
		st.emitRunStart(rec, ev, lineStart, res)
	case evAssistantMsg:
		st.emitAssistantMessage(rec, ev, lineStart, res)
	case evToolCalls:
		st.emitToolCalls(rec, ev, lineStart, res)
	case evToolResults:
		st.applyToolResults(ev, res)
	case evModelCompleted:
		st.emitTokens(rec, ev, lineStart, res)
	case evTerminal:
		st.emitTurnTerminal(rec, ev, lineStart, res)
	}
	// Every other event kind is scheduler / reminder / diagnostic
	// bookkeeping with no normalized-action counterpart — skipped silently
	// so a long session doesn't flood the watcher log.
}

// projectRoot resolves the header workspace root and memoizes the result.
//
// The translation is UNCONDITIONAL: crossmount.TranslateForeignPath maps a
// foreign-OS root to its locally-visible equivalent, so a foreign path never
// reaches git.Resolve — where filepath.Abs would treat it as relative and
// CWD-prefix the observer's OWN .git onto every event.
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
	// The log's own workspace_branch record is authoritative when present;
	// git.ResolveIdentity only fills the gap before one is seen.
	if st.branch == "" {
		st.branch = id.Branch
	}
	// id.Remote is already NormalizeRemote'd by ResolveIdentity.
	st.remote = id.Remote
	st.identity = id
	return id.Root
}

// eventKey returns the record's deterministic identity for SourceEventID
// construction: the record's own uuid when present (it is written into the
// file, so it is stable across re-parses), otherwise the record's byte
// offset (stable across resume points, unlike a per-call line number).
func eventKey(rec *rawRecord, lineStart int64) string {
	if rec.ID != "" {
		return rec.ID
	}
	return "@" + strconv.FormatInt(lineStart, 10)
}

// base builds the fields every emitted ToolEvent shares.
func (st *parseState) base(rec *rawRecord) models.ToolEvent {
	return models.ToolEvent{
		SourceFile:         st.path,
		SessionID:          st.sessionID,
		ProjectRoot:        st.projectRoot(),
		Timestamp:          parseTimestamp(rec.RecordedAt),
		GitBranch:          st.branch,
		GitRemote:          st.remote,
		GitUpstreamRemote:  st.identity.UpstreamRemote,
		GitRemoteOwner:     st.identity.RemoteOwner,
		GitUpstreamOwner:   st.identity.UpstreamOwner,
		RootCommitSHA:      st.identity.RootCommitSHA,
		ContentFingerprint: st.identity.ContentFingerprint,
		Workspace:          st.identity.Workspace,
		IsWorktree:         st.identity.IsWorktree,
		Tool:               models.ToolMuse,
		IsSidechain:        st.isSubagent,
		Success:            true,
	}
}

// emitSessionStart records the session-opened observation as a session-start
// marker, only when parsing from the very top of the file.
func (st *parseState) emitSessionStart(rec *rawRecord, res *adapter.ParseResult) {
	if st.firstOffset != 0 || st.sessionStarted || st.sessionID == "" {
		return
	}
	st.sessionStarted = true
	ev := st.base(rec)
	ev.SourceEventID = "session_start:" + st.sessionID
	ev.ActionType = models.ActionSessionStart
	ev.Target = "startup"
	ev.RawToolName = models.ToolMuse + ".session_start"
	if r := rec.Payload.Record; r != nil && r.Resume {
		ev.Target = "resume"
	}
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitSessionEnd records the session-end observation.
func (st *parseState) emitSessionEnd(rec *rawRecord, lineStart int64, res *adapter.ParseResult) {
	ev := st.base(rec)
	ev.SourceEventID = "session_end:" + eventKey(rec, lineStart)
	ev.ActionType = models.ActionSessionEnd
	ev.RawToolName = models.ToolMuse + ".session_end"
	ev.Target = "shutdown"
	if r := rec.Payload.Record; r != nil && r.ExitReason != "" {
		ev.Target = r.ExitReason
		ev.Success = r.ExitReason == "clean"
	}
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitRunStart records a run-level `started` event's prompt. Task-level
// `started` events carry a task_id and no prompt and produce nothing.
//
// The action type branches on WHOSE run it is, and that distinction is
// load-bearing rather than cosmetic. In the parent log the prompt is what
// the operator typed → user_prompt. In a CHILD log it is the harness's own
// seed for a sub-agent ("You are a reminder observer for the main agent. Do
// not answer the user…") — machine-authored, never typed by anyone. The
// §21 live re-parse found 15 of these against 3 real prompts, so typing
// them as user_prompt would have inflated the session's prompt count 6×
// and, worse, corrupted every surface that counts user_prompt BOUNDARIES —
// including internal/predict's turns-per-message ladder, whose whole unit
// is "one user message". subagent_start is the accurate bucket and keeps
// the seed text queryable.
func (st *parseState) emitRunStart(rec *rawRecord, e *sessionEvent, lineStart int64, res *adapter.ParseResult) {
	if strings.TrimSpace(e.Prompt) == "" {
		return
	}
	scrubbed := st.adapter.scrubber.String(e.Prompt)
	accumulatePromptCache(st.cacheAcc, scrubbed)
	ev := st.base(rec)
	ev.Target = truncate(scrubbed, 200)
	ev.RawToolInput = scrubbed
	if st.isSubagent {
		ev.SourceEventID = "subagent_start:" + eventKey(rec, lineStart)
		ev.ActionType = models.ActionSubagentStart
		ev.RawToolName = models.ToolMuse + ".subagent_start"
	} else {
		ev.SourceEventID = "prompt:" + eventKey(rec, lineStart)
		ev.ActionType = models.ActionUserPrompt
		ev.RawToolName = models.ToolMuse + ".user_prompt"
	}
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitAssistantMessage records the assistant's visible reply.
func (st *parseState) emitAssistantMessage(rec *rawRecord, e *sessionEvent, lineStart int64, res *adapter.ParseResult) {
	if strings.TrimSpace(e.Text) == "" {
		return
	}
	scrubbed := st.adapter.scrubber.String(e.Text)
	ev := st.base(rec)
	ev.SourceEventID = "assistant:" + eventKey(rec, lineStart)
	ev.ActionType = models.ActionAssistantMessage
	ev.RawToolName = models.ToolMuse + ".assistant_message"
	ev.Model = st.model
	ev.MessageID = e.MessageID
	ev.Target = truncate(scrubbed, 200)
	capped := st.adapter.scrubber.String(contentcap.Cap(e.Text, contentcap.DefaultMaxBytes))
	ev.ToolOutput = capped
	accumulateAssistantMessageCache(st.cacheAcc, capped)
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitTurnTerminal records an ABORTED turn. A `completed` terminal is the
// normal path and produces nothing — the assistant message and token row
// already describe it.
func (st *parseState) emitTurnTerminal(rec *rawRecord, e *sessionEvent, lineStart int64, res *adapter.ParseResult) {
	if e.Terminal == "" || e.Terminal == "completed" {
		return
	}
	ev := st.base(rec)
	ev.SourceEventID = "abort:" + eventKey(rec, lineStart)
	ev.ActionType = models.ActionTurnAborted
	ev.RawToolName = models.ToolMuse + ".turn_" + e.Terminal
	ev.Model = st.model
	ev.Target = e.Terminal
	ev.Success = false
	ev.DurationMs = e.TurnDurationMs
	if e.Reason != "" {
		ev.ErrorMessage = truncate(st.adapter.scrubber.String(e.Reason), 500)
	}
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitToolCalls records every tool call committed on one assistant message,
// optimistically successful until the paired outcome record says otherwise.
func (st *parseState) emitToolCalls(rec *rawRecord, e *sessionEvent, lineStart int64, res *adapter.ParseResult) {
	key := eventKey(rec, lineStart)
	for pos, tc := range e.ToolCalls {
		action, recognised := mapToolName(tc.Name)
		if !recognised && !st.unknownTool[tc.Name] {
			st.unknownTool[tc.Name] = true
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("unrecognised tool name %q normalized to %q", tc.Name, action))
		}
		args := decodeArgs(tc.Args)
		ev := st.base(rec)
		ev.SourceEventID = "tool:" + toolEventKey(tc.CallID, key, pos)
		ev.ActionType = action
		ev.RawToolName = tc.Name
		ev.Model = st.model
		ev.MessageID = e.MessageID
		ev.Target = st.adapter.scrubber.String(targetFromArgs(args, tc.Name))
		scrubbedArgs := st.adapter.scrubber.String(contentcap.Cap(tc.Args, contentcap.DefaultMaxBytes))
		ev.RawToolInput = scrubbedArgs
		ev.ContentBytes = authoredBytes(action, args)
		accumulateToolCallCache(st.cacheAcc, tc.Name, scrubbedArgs)
		idx := len(res.ToolEvents)
		res.ToolEvents = append(res.ToolEvents, ev)
		if tc.CallID == "" {
			continue
		}
		st.toolIdx[tc.CallID] = idx
		st.pendingCall[tc.CallID] = pendingMark{
			lineStart: st.curLineStart,
			toolLen:   st.curToolLen,
			tokenLen:  st.curTokenLen,
		}
	}
}

// toolEventKey builds a deterministic per-call id, preferring the provider
// call id and falling back to the record key + position.
func toolEventKey(callID, recordKey string, pos int) string {
	if callID != "" {
		return callID
	}
	return recordKey + ":" + strconv.Itoa(pos)
}

// applyOutcome stamps the per-call verdict from a tool_batch.effect.terminal
// record onto the ToolEvent its call produced. This is the ONLY explicit
// success signal in the log — the result body is free-form per tool — and it
// arrives BEFORE the result batch, which is why the outcome index is kept
// separately from the pending map.
func (st *parseState) applyOutcome(r *metaRecord, res *adapter.ParseResult) {
	if r == nil || r.CallID == "" || r.Outcome == nil {
		return
	}
	idx, ok := st.toolIdx[r.CallID]
	if !ok || idx >= len(res.ToolEvents) {
		return
	}
	if failedOutcomes[r.Outcome.Kind] {
		res.ToolEvents[idx].Success = false
		res.ToolEvents[idx].ErrorMessage = "tool effect " + r.Outcome.Kind
	}
}

// applyToolResults stamps each result body onto the ToolEvent its call
// produced and clears the pending entry. A result whose call landed in an
// earlier parse chunk has no index and is skipped (the tool event itself was
// already persisted).
func (st *parseState) applyToolResults(e *sessionEvent, res *adapter.ParseResult) {
	for _, r := range e.Results {
		if r.ToolCallID == "" {
			continue
		}
		delete(st.pendingCall, r.ToolCallID)
		idx, ok := st.toolIdx[r.ToolCallID]
		if !ok || idx >= len(res.ToolEvents) {
			continue
		}
		if strings.TrimSpace(r.Text) == "" {
			continue
		}
		scrubbed := st.adapter.scrubber.String(contentcap.Cap(r.Text, contentcap.DefaultMaxBytes))
		ev := &res.ToolEvents[idx]
		ev.ToolOutput = scrubbed
		accumulateToolResultCache(st.cacheAcc, scrubbed)
		if !ev.Success && ev.ErrorMessage != "" {
			ev.ErrorMessage = truncate(scrubbed, 500)
		}
	}
}

// emitTokens turns a model_completed record into a TokenEvent with both
// GROSS fields netted (see tokenBundle). An absent or all-zero usage
// envelope emits nothing, so no phantom rows land.
func (st *parseState) emitTokens(rec *rawRecord, e *sessionEvent, lineStart int64, res *adapter.ParseResult) {
	if e.Usage.isZero() {
		return
	}
	if e.Model != "" {
		st.model = e.Model
	}
	tp := tokenBundle(e.Usage)
	tokenSourceEventID := "tok:" + eventKey(rec, lineStart)
	if obs := emitCacheObservation(st.cacheAcc, st.path, st.sessionID, tokenSourceEventID, st.model, parseTimestamp(rec.RecordedAt), tp); obs != nil {
		res.CacheObservations = append(res.CacheObservations, *obs)
	}
	res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
		SourceFile:          st.path,
		SourceEventID:       tokenSourceEventID,
		SessionID:           st.sessionID,
		ProjectRoot:         st.projectRoot(),
		GitBranch:           st.branch,
		GitRemote:           st.remote,
		GitUpstreamRemote:   st.identity.UpstreamRemote,
		GitRemoteOwner:      st.identity.RemoteOwner,
		GitUpstreamOwner:    st.identity.UpstreamOwner,
		RootCommitSHA:       st.identity.RootCommitSHA,
		ContentFingerprint:  st.identity.ContentFingerprint,
		Workspace:           st.identity.Workspace,
		IsWorktree:          st.identity.IsWorktree,
		Timestamp:           parseTimestamp(rec.RecordedAt),
		Tool:                models.ToolMuse,
		Model:               st.model,
		InputTokens:         tp.inputNet,
		OutputTokens:        tp.outputNet,
		CacheReadTokens:     tp.cacheRead,
		CacheCreationTokens: tp.cacheWrit,
		ReasoningTokens:     tp.reasoning,
		// No EstimatedCostUSD: Muse states no per-call cost and Meta
		// publishes no per-token rate card for the Muse subscription, so
		// the cost engine resolves these rows as `unknown` rather than
		// against an invented rate.
		Source:      models.TokenSourceJSONL,
		Reliability: models.ReliabilityApproximate,
		MessageID:   e.ResponseID,
	})
}

// compile-time interface check.
var _ adapter.Adapter = (*Adapter)(nil)
