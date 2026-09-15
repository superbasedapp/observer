package junie

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

// sessionLogName is the fixed basename of every Junie session log — the
// session id lives in the enclosing DIRECTORY, not the filename.
const sessionLogName = "events.jsonl"

// indexFileName is the sibling per-session summary file one level above
// the session directory (~/.junie/sessions/index.jsonl).
const indexFileName = "index.jsonl"

// headerScanLines bounds the from-offset-0 scan for the session's
// CurrentDirectoryUpdatedEvent. Unlike Muse's workspace_root (stated once,
// on line 1), Junie's first non-empty occurrence was observed at line 50
// of a 219-line fixture — roughly a quarter of the way in — so the bound
// is generous rather than tight; it exists only so a corrupt or
// unexpectedly-shaped log can't turn the header read into a full-file scan
// on every poll tick.
const headerScanLines = 2000

// Adapter parses JetBrains Junie session logs under
// ~/.junie/sessions/<session-id>/events.jsonl. See the package doc for the
// record shapes, the rebroadcast-after-terminal finding and the off-limits
// file list.
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
func (*Adapter) Name() string { return models.ToolJunie }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// defaultRoots returns every plausible Junie session tree.
//
// Junie stores directly under `~/.junie` on every platform it has been
// observed on (settings.json and sessions/ both live there, with no XDG
// split the way Muse uses on Linux/macOS) — so one join per cross-mount-
// resolved $HOME covers a WSL2 observer reading a foreign home as well.
//
// $JUNIE_HOME wins when set (the decompiled-jar finding behind the
// 2026-09-02 IDE audit's IDE-17 row: the plugin resolves its session
// store from `${JUNIE_HOME:-~/.junie}/sessions`, not a hardcoded
// `~/.junie`). It is only meaningful for THIS process's own environment
// — like clinecli's CLINE_DIR and qwencode's QWEN_HOME — so it is not
// re-resolved per cross-mount home; the per-home defaults below still
// contribute their own `.junie/sessions` paths alongside it. The value
// is absolutized before use (adapter.AbsEnvRoot) so a relative JUNIE_HOME can
// never become a relative watch root, and it is deduped against the
// per-home defaults (a relocated home that happens to equal one of the
// cross-mount defaults contributes only one root).
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
	if home := adapter.AbsEnvRoot("JUNIE_HOME"); home != "" {
		add(filepath.Join(home, "sessions"))
	}
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(h.Path, ".junie", "sessions"))
	}
	return roots
}

// IsSessionFile implements adapter.Adapter.
func (a *Adapter) IsSessionFile(path string) bool {
	if !matchesShape(path, a.WatchPaths()) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// matchesShape reports whether path has the Junie session-log shape,
// independent of watch-root MEMBERSHIP (that's UnderAnyWatchRoot's job,
// ANDed in by IsSessionFile above) but not independent of watch-root
// SHAPE: a JUNIE_HOME-relocated store carries no `.junie` path segment
// at all, so the default substring match can't see it. Comparison is on
// a slash-normalized, lower-cased copy so Windows separators and
// case-insensitive mounts match too.
//
// A path matches when its basename is events.jsonl AND either:
//   - it sits under a literal `.junie/sessions/` tree (the unrelocated
//     default), or
//   - it sits EXACTLY two path segments below one of roots, i.e.
//     `<root>/<session-id>/events.jsonl` — the shape every root in
//     WatchPaths() actually has, relocated or not.
//
// The exact-two-levels requirement (not just "somewhere under a root")
// is what keeps every off-limits sibling excluded even under a
// relocated root: index.jsonl and state.json fail the basename check
// first, and a hypothetical events.jsonl nested inside
// `task-*/.matterhorn/` would sit three-plus levels down and fail the
// depth check.
func matchesShape(path string, roots []string) bool {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	if filepath.Base(lower) != sessionLogName {
		return false
	}
	if strings.Contains(lower, "/.junie/sessions/") {
		return true
	}
	return sitsTwoLevelsBelowRoot(lower, roots)
}

// sitsTwoLevelsBelowRoot reports whether lowerPath (already
// slash-normalized and lower-cased by the caller) is exactly
// `<root>/<session-id>/events.jsonl` for one of roots. roots are
// expected to already be absolute (defaultRoots/adapter.AbsEnvRoot guarantee
// that), so this is a plain string-prefix check in the same
// slash-normalized, lower-cased space matchesShape already works in.
func sitsTwoLevelsBelowRoot(lowerPath string, roots []string) bool {
	for _, r := range roots {
		if r == "" {
			continue
		}
		lowerRoot := strings.TrimRight(strings.ReplaceAll(strings.ToLower(r), `\`, "/"), "/")
		rest := strings.TrimPrefix(lowerPath, lowerRoot+"/")
		if rest == lowerPath {
			continue // lowerPath does not sit under this root at all
		}
		parts := strings.Split(rest, "/")
		if len(parts) == 2 && parts[0] != "" && parts[1] == sessionLogName {
			return true
		}
	}
	return false
}

// ParseSessionFile implements adapter.Adapter. It streams the JSONL from
// fromOffset to EOF, emitting ToolEvents (a session-start marker, user
// prompts, Terminal/FileChanges/Result blocks collapsed by stepId) and
// TokenEvents (one per LlmResponseMetadataEvent.modelUsage entry).
//
// The project-root header is ALWAYS re-scanned from offset 0, even on a
// resumed parse (see readHeader) — Junie's own workspace-cwd statement
// doesn't arrive until partway through the file, so a resumed parse that
// only read forward from fromOffset could never resolve it. Malformed
// lines are skipped with a warning and the byte cursor advances past every
// fully terminated line, so a bad line can't stall the poll loop. A
// partial trailing line (a record still being written) is deferred
// without advancing the cursor, so the next parse re-reads it whole.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from the watcher's own watch roots
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("junie.ParseSessionFile: open %s: %w", path, err)
	}
	defer f.Close()

	st := &parseState{
		adapter:     a,
		path:        path,
		rootCache:   map[string]string{},
		stepIdx:     map[string]int{},
		firstOffset: fromOffset,
		sessionID:   sessionIDFromPath(path),
		cacheAcc:    cacheobs.New(MaxBlocksPerSession),
		cacheDone:   map[string]bool{},
	}
	if err := st.readHeader(f); err != nil {
		return adapter.ParseResult{}, err
	}

	if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
		return adapter.ParseResult{}, fmt.Errorf("junie.ParseSessionFile: seek: %w", err)
	}

	res := adapter.ParseResult{NewOffset: fromOffset}
	st.emitIDESurface(&res)

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
			return res, fmt.Errorf("junie.ParseSessionFile: read: %w", readErr)
		}
		hasNewline := strings.HasSuffix(lineStr, "\n")
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
		st.handle(&rec, lineStart, &res)
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
	// rootCache memoizes cwd → resolved project root (git.Resolve walks the
	// filesystem, and one session log shares one workspace root throughout).
	rootCache map[string]string
	// stepIdx maps a block's "step:"+stepId SourceEventID to its
	// ToolEvent's index in res.ToolEvents, so a later occurrence of the
	// SAME stepId within this parse window (IN_PROGRESS -> terminal
	// status -> the completion rebroadcast) updates the row in place
	// instead of appending a duplicate. A stepId whose earlier occurrence
	// landed in a PRIOR parse window is not in this map — its later
	// occurrence appends a new row, and the store's own
	// ON CONFLICT(source_file, source_event_id) upsert merges it with the
	// already-persisted one (see the package doc, "Why there is no
	// pending.go").
	stepIdx map[string]int
	// firstOffset is the fromOffset the parse started at; the
	// session-start marker only fires when parsing from the very top of
	// the file.
	firstOffset int64
	// sessionStarted guards against emitting more than one session-start
	// marker per parse call.
	sessionStarted bool
	// ideAttachmentSeen is set by readHeader when the session's first
	// UserPromptEvent carries the IDE-injected MCP-server wiring
	// attachment (see surface.go). Like cwd, this is resolved from a
	// from-offset-0 header scan on EVERY parse call, since the
	// attachment lives on line 1 and a resumed parse (fromOffset > 0)
	// would otherwise never see it.
	ideAttachmentSeen bool
	// surfaceStamped guards against emitting more than one
	// models.SessionSurface row per parse call (see emitIDESurface /
	// emitCLISurface).
	surfaceStamped bool
	// sessionID is the canonical session id, always derived from the
	// enclosing directory name.
	sessionID string
	// cwd is the workspace root resolved once by readHeader, from a
	// bounded from-offset-0 scan of the file's own
	// CurrentDirectoryUpdatedEvent occurrences, falling back to the
	// sibling index.jsonl's projectDir.
	cwd string
	// branch is the git branch, resolved alongside the project root by
	// git.Resolve. Junie's log states no branch of its own, unlike Muse's
	// workspace_branch record.
	branch string
	// remote is the normalized git remote, resolved alongside the project
	// root (see projectRoot).
	remote string
	// identity is the Project Identity Resolver v2 bundle (2026-09-06,
	// §3.1 / W1) resolved alongside branch/remote.
	identity git.Identity
	// model is the most recent model id seen (from
	// LlmResponseMetadataEvent), stamped onto the surrounding
	// Terminal/FileChanges/Result actions, which carry no model of their
	// own.
	model string
	// pendingReasoning buffers the most recent
	// AgentThoughtBlockUpdatedEvent's text. It is attached as
	// PrecedingReasoning to the next NEWLY CREATED block (not a repeat
	// update of an existing one, since a thought's own stepId never
	// matches the block it precedes) and cleared once consumed.
	pendingReasoning string
	// cacheAcc accumulates this parse call's running Tier-2
	// content-block delta for cachetrack observation, drained once per
	// LlmResponseMetadataEvent (see emitTokens / emitCacheObservations
	// in cachetrack.go). Scoped to a single ParseSessionFile call, like
	// every other incrementally-parsed Tier-2 producer (cline, cowork).
	cacheAcc *cacheobs.Accumulator
	// cacheDone guards Terminal/FileChanges/Thought block cache
	// accumulation against the completion rebroadcast (see the package
	// doc's rebroadcast-after-terminal finding), keyed by the same
	// "step:"+stepId string as stepIdx, so a block's content is fed into
	// cacheAcc exactly once.
	cacheDone map[string]bool
}

// sessionIDFromPath recovers the canonical session id from the log path:
// …/sessions/<session-id>/events.jsonl → <session-id>.
func sessionIDFromPath(path string) string {
	return filepath.Base(filepath.Dir(path))
}

// readHeader scans the top of the log (position 0, independent of the
// parse cursor) for the first non-empty CurrentDirectoryUpdatedEvent, so a
// resumed parse still resolves a project root, AND for the IDE-injected
// MCP-server wiring attachment (see surface.go) — both signals sit near
// the top of the file, so one bounded pass covers both. When the log
// never states a CurrentDirectoryUpdatedEvent within headerScanLines (an
// interrupted session with no terminal/file-change block, for instance),
// the sibling index.jsonl's projectDir is used instead.
func (st *parseState) readHeader(f *os.File) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("junie.readHeader: seek: %w", err)
	}
	cwd, ideAttachment := scanHeader(f)
	st.cwd = cwd
	if st.cwd == "" {
		st.cwd = indexProjectDir(st.path, st.sessionID)
	}
	st.ideAttachmentSeen = ideAttachment
	return nil
}

// scanHeader reads at most headerScanLines lines from r's current
// position and returns the first stated
// CurrentDirectoryUpdatedEvent.currentDirectory (empty if none), plus
// whether any UserPromptEvent in the same window carries the
// IDE-injected MCP-server wiring attachment (see surface.go). Both
// signals sit near the top of a real capture — the CWD statement
// roughly a quarter in per the Phase-0 fixture, the attachment on line
// 1 when present — so the scan continues until BOTH are resolved (or
// the bound is exhausted), rather than stopping at the first hit.
func scanHeader(r io.Reader) (cwd string, ideAttachment bool) {
	br := bufio.NewReaderSize(r, 64*1024)
	for i := 0; i < headerScanLines; i++ {
		line, err := br.ReadString('\n')
		raw := strings.TrimRight(line, "\r\n")
		if raw != "" {
			var rec rawRecord
			if jsonErr := json.Unmarshal([]byte(raw), &rec); jsonErr == nil {
				if cwd == "" && rec.Event != nil && rec.Event.AgentEvent != nil &&
					rec.Event.AgentEvent.Kind == agentKindCurrentDirectory &&
					rec.Event.AgentEvent.CurrentDirectory != "" {
					cwd = rec.Event.AgentEvent.CurrentDirectory
				}
				if !ideAttachment && rec.Kind == kindUserPrompt && hasIDEMCPAttachment(rec.ExtraAttachments) {
					ideAttachment = true
				}
			}
		}
		if cwd != "" && ideAttachment {
			return cwd, ideAttachment
		}
		if err != nil {
			return cwd, ideAttachment
		}
	}
	return cwd, ideAttachment
}

// indexProjectDir reads the sibling ~/.junie/sessions/index.jsonl for
// sessionID's projectDir. Symlinks are refused outright: a real Junie
// install never writes one there, so the refusal costs nothing and keeps
// the package doc's "never reads" list true by construction. A missing,
// malformed, or non-matching file yields "".
func indexProjectDir(sessionPath, sessionID string) string {
	if sessionID == "" {
		return ""
	}
	indexPath := filepath.Join(filepath.Dir(filepath.Dir(sessionPath)), indexFileName)
	info, err := os.Lstat(indexPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ""
	}
	f, err := os.Open(indexPath) //nolint:gosec // derived from a watched session path; symlinks refused above
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var row indexRow
		if err := json.Unmarshal([]byte(raw), &row); err != nil {
			continue
		}
		if row.SessionID == sessionID {
			return row.ProjectDir
		}
	}
	return ""
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
	if st.branch == "" {
		st.branch = id.Branch
	}
	// id.Remote is already NormalizeRemote'd by ResolveIdentity.
	st.remote = id.Remote
	st.identity = id
	return id.Root
}

// eventKey returns id when non-empty, otherwise the record's byte offset —
// stable across resume points, unlike a per-call line number.
func eventKey(id string, lineStart int64) string {
	if id != "" {
		return id
	}
	return "@" + strconv.FormatInt(lineStart, 10)
}

// base builds the fields every emitted ToolEvent shares.
func (st *parseState) base(rec *rawRecord) models.ToolEvent {
	return models.ToolEvent{
		SourceFile:         st.path,
		SessionID:          st.sessionID,
		ProjectRoot:        st.projectRoot(),
		Timestamp:          parseTimestamp(rec.TimestampMs),
		GitBranch:          st.branch,
		GitRemote:          st.remote,
		GitUpstreamRemote:  st.identity.UpstreamRemote,
		GitRemoteOwner:     st.identity.RemoteOwner,
		GitUpstreamOwner:   st.identity.UpstreamOwner,
		RootCommitSHA:      st.identity.RootCommitSHA,
		ContentFingerprint: st.identity.ContentFingerprint,
		Workspace:          st.identity.Workspace,
		IsWorktree:         st.identity.IsWorktree,
		Tool:               models.ToolJunie,
		Success:            true,
	}
}

// handle dispatches one decoded record onto the appropriate emit path.
// lineStart is the record's byte offset in the file, used as a
// resume-independent fallback event id.
func (st *parseState) handle(rec *rawRecord, lineStart int64, res *adapter.ParseResult) {
	switch rec.Kind {
	case kindUserPrompt:
		st.emitUserPrompt(rec, lineStart, res)
	case kindTaskStarted:
		st.emitSessionStart(rec, res)
	case kindSessionA2ux:
		st.handleSessionA2ux(rec, lineStart, res)
	case kindCostTrajectorySnapshot:
		st.emitCLISurface(res)
	}
	// kindMessagesCommitted correlates prompt ids already captured by
	// UserPromptEvent, and kindTaskState duplicates the completion the
	// matching ResultBlockUpdatedEvent already turns into an
	// ActionTaskComplete row (see the package doc) — both, and any
	// unrecognised kind, are skipped silently.
}

// emitIDESurface appends a self-reported IDE capture-surface stamp when
// readHeader found the IDE-injected MCP-server wiring attachment (see
// surface.go). Runs once per ParseSessionFile call, independent of
// fromOffset — the header scan that feeds ideAttachmentSeen already
// re-reads from byte 0 on every call.
//
// Because readHeader re-scans from byte 0 on EVERY call, a session
// already stamped by an earlier parse gets the identical
// models.SessionSurface row re-emitted on every later poll tick too —
// this is intentional and costs nothing: store.SetSessionSurface's
// WHERE guard only writes when the stored value actually differs
// (surface.go's "why the IDE self-stamp cannot fight the enricher"),
// so a repeat of the same self-report is a silent no-op UPDATE, not a
// flap or a duplicate row.
func (st *parseState) emitIDESurface(res *adapter.ParseResult) {
	if st.surfaceStamped || !st.ideAttachmentSeen || st.sessionID == "" {
		return
	}
	st.surfaceStamped = true
	res.SessionSurfaces = append(res.SessionSurfaces, junieIDESurface(st.sessionID))
}

// emitCLISurface appends a self-reported CLI capture-surface stamp the
// first time this parse call encounters the CLI's own
// SessionCostTrajectorySnapshotEvent (see surface.go). Guarded so at
// most one models.SessionSurface row is appended per parse call, and so
// it never fires alongside emitIDESurface (the two markers are mutually
// exclusive on every capture examined).
func (st *parseState) emitCLISurface(res *adapter.ParseResult) {
	if st.surfaceStamped || st.sessionID == "" {
		return
	}
	st.surfaceStamped = true
	res.SessionSurfaces = append(res.SessionSurfaces, junieCLISurface(st.sessionID))
}

// handleSessionA2ux dispatches SessionA2uxEvent.event.agentEvent — the
// real inner discriminated union, keyed by Kind.
func (st *parseState) handleSessionA2ux(rec *rawRecord, lineStart int64, res *adapter.ParseResult) {
	ev := rec.Event
	if ev == nil || ev.AgentEvent == nil {
		return
	}
	ae := ev.AgentEvent
	switch ae.Kind {
	case agentKindLlmResponseMeta:
		st.emitTokens(rec, ae, lineStart, res)
	case agentKindThoughtBlock:
		st.bufferReasoning(ae)
	case agentKindTerminalBlock:
		st.emitTerminalBlock(rec, ae, res)
	case agentKindFileChangesBlock:
		st.emitFileChangesBlock(rec, ae, res)
	case agentKindResultBlock:
		st.emitResultBlock(rec, ae, res)
	case agentKindMcpBlock:
		st.emitMCPBlock(rec, ae, res)
	case agentKindViewFilesBlock:
		st.emitViewFilesBlock(rec, ae, res)
	case agentKindToolBlock:
		// Deliberately no row — a generic "a tool is running" label
		// that always shares its stepId with a specialised block. The
		// case exists so the skip is explicit rather than a silent
		// fall-through (mcpblocks.go documents the grounding).
	}
	// agentKindCurrentDirectory is consumed entirely by the header scan
	// (readHeader), never live. agentKindToolBlock is deliberately NOT
	// mapped — it is a generic "a tool is running" label that always
	// shares its stepId with a specialised block (see mcpblocks.go).
	// The remaining 6 observed kinds
	// (AgentCurrentStatusUpdatedEvent, EnvironmentVariablesUpdatedEvent,
	// TipSuggestionCreatedEvent, AgentTaskNameUpdatedEvent,
	// ContextWindowReportEvent, AgentPatchCreatedEvent,
	// NextPromptSuggestionEvent) have no normalized-action counterpart and
	// are skipped silently.
	//
	// EnvironmentVariablesUpdatedEvent in particular carries the
	// operator's entire process environment: its `env` field is not even
	// declared on agentEventRaw, so no code path can persist or emit it.
	//
	// AgentPatchCreatedEvent restates the task's cumulative patch and was
	// observed EMPTY (`"patch": ""`) on the 2026-09-03 capture; the
	// per-call apply_patch MCP block already carries the real diff, so
	// mapping it would at best duplicate a row and at worst emit a blank
	// one.
}

// emitUserPrompt records the operator's verbatim prompt text.
func (st *parseState) emitUserPrompt(rec *rawRecord, lineStart int64, res *adapter.ParseResult) {
	if strings.TrimSpace(rec.Prompt) == "" {
		return
	}
	scrubbed := st.adapter.scrubber.String(rec.Prompt)
	accumulatePromptCache(st.cacheAcc, scrubbed)
	ev := st.base(rec)
	ev.SourceEventID = "prompt:" + eventKey(rec.RequestID, lineStart)
	ev.ActionType = models.ActionUserPrompt
	ev.RawToolName = models.ToolJunie + ".user_prompt"
	ev.Target = truncate(scrubbed, 200)
	ev.RawToolInput = scrubbed
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitSessionStart records the first TaskStartedEvent as a session-start
// marker, only when parsing from the very top of the file. A session can
// contain multiple tasks (turns); only the first one marks session start —
// later TaskStartedEvent occurrences are informational and skipped (see
// the package doc).
func (st *parseState) emitSessionStart(rec *rawRecord, res *adapter.ParseResult) {
	if st.firstOffset != 0 || st.sessionStarted || st.sessionID == "" {
		return
	}
	st.sessionStarted = true
	ev := st.base(rec)
	ev.SourceEventID = "session_start:" + st.sessionID
	ev.ActionType = models.ActionSessionStart
	ev.RawToolName = models.ToolJunie + ".session_start"
	ev.Target = "startup"
	res.ToolEvents = append(res.ToolEvents, ev)
}

// bufferReasoning stores the agent's narration for attachment onto the
// next newly-created block.
func (st *parseState) bufferReasoning(ae *agentEventRaw) {
	if strings.TrimSpace(ae.Text) == "" {
		return
	}
	st.pendingReasoning = st.adapter.scrubber.String(ae.Text)
	accumulateThoughtCache(st.cacheAcc, st.cacheDone, "thought:"+ae.StepID, st.pendingReasoning)
}

// takeReasoning returns and clears the buffered reasoning, for attachment
// onto a newly-created block.
func (st *parseState) takeReasoning() string {
	r := st.pendingReasoning
	st.pendingReasoning = ""
	return r
}

// emitTerminalBlock creates or updates the ActionRunCommand row for a
// Terminal block, keyed by its stepId.
func (st *parseState) emitTerminalBlock(rec *rawRecord, ae *agentEventRaw, res *adapter.ParseResult) {
	if ae.StepID == "" {
		return
	}
	key := "step:" + ae.StepID
	if idx, ok := st.stepIdx[key]; ok && idx < len(res.ToolEvents) {
		st.applyTerminalFields(&res.ToolEvents[idx], ae)
		accumulateTerminalCache(st.cacheAcc, st.cacheDone, key, ae)
		return
	}
	ev := st.base(rec)
	ev.SourceEventID = key
	ev.ActionType = models.ActionRunCommand
	ev.RawToolName = models.ToolJunie + ".terminal"
	ev.Model = st.model
	ev.PrecedingReasoning = st.takeReasoning()
	st.applyTerminalFields(&ev, ae)
	accumulateTerminalCache(st.cacheAcc, st.cacheDone, key, ae)
	idx := len(res.ToolEvents)
	res.ToolEvents = append(res.ToolEvents, ev)
	st.stepIdx[key] = idx
}

// applyTerminalFields stamps a Terminal block's command/output/status onto
// ev. Called both for the block's first occurrence and every later
// re-occurrence of the same stepId within this parse window.
func (st *parseState) applyTerminalFields(ev *models.ToolEvent, ae *agentEventRaw) {
	ev.Target = st.adapter.scrubber.String(truncate(ae.Command, 200))
	ev.RawToolInput = st.adapter.scrubber.String(ae.Command)
	if ae.Output != "" {
		ev.ToolOutput = st.adapter.scrubber.String(contentcap.Cap(ae.Output, contentcap.DefaultMaxBytes))
	}
	if ae.Status == blockStatusFailed {
		ev.Success = false
		msg := ae.Details
		if msg == "" {
			msg = ae.Output
		}
		ev.ErrorMessage = truncate(st.adapter.scrubber.String(msg), 500)
	} else if ae.Status == blockStatusCompleted {
		ev.Success = true
		ev.ErrorMessage = ""
	}
}

// emitFileChangesBlock creates or updates the ActionWriteFile /
// ActionEditFile row for a FileChanges block, keyed by its stepId. A
// change with no BeforeContent is a new file; one WITH BeforeContent is an
// edit of an existing one.
func (st *parseState) emitFileChangesBlock(rec *rawRecord, ae *agentEventRaw, res *adapter.ParseResult) {
	if ae.StepID == "" {
		return
	}
	key := "step:" + ae.StepID
	if idx, ok := st.stepIdx[key]; ok && idx < len(res.ToolEvents) {
		st.applyFileChangesFields(&res.ToolEvents[idx], ae)
		accumulateFileChangesCache(st.cacheAcc, st.cacheDone, key, ae)
		return
	}
	ev := st.base(rec)
	ev.SourceEventID = key
	ev.ActionType = models.ActionWriteFile
	if len(ae.Changes) > 0 && ae.Changes[0].BeforeContent != nil {
		ev.ActionType = models.ActionEditFile
	}
	ev.RawToolName = models.ToolJunie + ".file_changes"
	ev.Model = st.model
	ev.PrecedingReasoning = st.takeReasoning()
	st.applyFileChangesFields(&ev, ae)
	accumulateFileChangesCache(st.cacheAcc, st.cacheDone, key, ae)
	idx := len(res.ToolEvents)
	res.ToolEvents = append(res.ToolEvents, ev)
	st.stepIdx[key] = idx
}

// applyFileChangesFields stamps a FileChanges block's path/content/status
// onto ev.
func (st *parseState) applyFileChangesFields(ev *models.ToolEvent, ae *agentEventRaw) {
	if len(ae.Changes) > 0 {
		c := ae.Changes[0]
		path := c.AfterRelativePath
		if path == "" {
			path = c.BeforeRelativePath
		}
		ev.Target = st.adapter.scrubber.String(path)
		if c.AfterContent != nil {
			ev.RawToolInput = st.adapter.scrubber.String(contentcap.Cap(c.AfterContent.Text, contentcap.DefaultMaxBytes))
			ev.ContentBytes = int64(len(c.AfterContent.Text))
		}
	}
	if ae.Status == blockStatusFailed {
		ev.Success = false
		ev.ErrorMessage = truncate(st.adapter.scrubber.String(ae.Details), 500)
	} else if ae.Status == blockStatusCompleted {
		ev.Success = true
		ev.ErrorMessage = ""
	}
}

// emitMCPBlock creates or updates the row for an MCP tool call, keyed
// by its stepId — the same collapse the Terminal / FileChanges blocks
// use, so a block's IN_PROGRESS → COMPLETED → completion-rebroadcast
// occurrences all land on ONE action. The normalized action type and
// target come from the mcpToolRules table (mcpblocks.go), never from a
// switch on the vendor name.
//
// A block carrying an approvalRequest ALSO emits a separate
// ActionPermissionRequest row with its own deterministic
// SourceEventID — the prompt and the call it gated are two distinct
// facts, and the prompt fires only once per session while the call
// recurs.
func (st *parseState) emitMCPBlock(rec *rawRecord, ae *agentEventRaw, res *adapter.ParseResult) {
	if ae.StepID == "" {
		return
	}
	st.emitMCPApproval(rec, ae, res)
	key := "step:" + ae.StepID
	if idx, ok := st.stepIdx[key]; ok && idx < len(res.ToolEvents) {
		st.applyMCPFields(&res.ToolEvents[idx], ae)
		accumulateMCPCache(st.cacheAcc, st.cacheDone, key, ae)
		return
	}
	ev := st.base(rec)
	ev.SourceEventID = key
	ev.RawToolName = strings.TrimSpace(ae.ToolName)
	ev.Model = st.model
	ev.PrecedingReasoning = st.takeReasoning()
	st.applyMCPFields(&ev, ae)
	accumulateMCPCache(st.cacheAcc, st.cacheDone, key, ae)
	idx := len(res.ToolEvents)
	res.ToolEvents = append(res.ToolEvents, ev)
	st.stepIdx[key] = idx
}

// applyMCPFields stamps an MCP block's normalized action/target, its raw
// arguments and its terminal-status outcome onto ev. Called both for the
// block's first occurrence and every later re-occurrence of the same
// stepId within this parse window, so a row created at IN_PROGRESS is
// upgraded in place once the call completes.
func (st *parseState) applyMCPFields(ev *models.ToolEvent, ae *agentEventRaw) {
	norm := normalizeMCPCall(ae.ToolName, ae.Input)
	ev.ActionType = norm.ActionType
	ev.Target = truncate(st.adapter.scrubber.String(norm.Target), 200)
	if ae.Input != "" {
		ev.RawToolInput = st.adapter.scrubber.String(contentcap.Cap(ae.Input, contentcap.DefaultMaxBytes))
	}
	switch ae.Status {
	case blockStatusFailed:
		ev.Success = false
		ev.ErrorMessage = truncate(st.adapter.scrubber.String(ae.Details), 500)
	case blockStatusCompleted:
		ev.Success = true
		ev.ErrorMessage = ""
		// `details` mirrors `input` while the call is running and only
		// becomes the outcome summary at the terminal transition — so
		// it is adopted as output ONLY here, never at IN_PROGRESS,
		// where it would just duplicate RawToolInput.
		if ae.Details != "" {
			ev.ToolOutput = st.adapter.scrubber.String(contentcap.Cap(ae.Details, contentcap.DefaultMaxBytes))
		}
	}
}

// emitMCPApproval records the host's permission prompt for an MCP call
// as its own ActionPermissionRequest row, per the action type's
// contract: Target is the tool_name being asked about, RawToolInput the
// call's arguments, PrecedingReasoning the offered allow-list patterns.
// Keyed on the prompt's own id so a rebroadcast of the same block
// collapses onto one row.
func (st *parseState) emitMCPApproval(rec *rawRecord, ae *agentEventRaw, res *adapter.ParseResult) {
	ar := ae.ApprovalRequest
	if ar == nil || ar.ID == "" {
		return
	}
	key := "approval:" + ar.ID
	if _, seen := st.stepIdx[key]; seen {
		return
	}
	ev := st.base(rec)
	ev.SourceEventID = key
	ev.ActionType = models.ActionPermissionRequest
	ev.RawToolName = strings.TrimSpace(ae.ToolName)
	ev.Target = truncate(st.adapter.scrubber.String(ev.RawToolName), 200)
	ev.Model = st.model
	if ae.Input != "" {
		ev.RawToolInput = st.adapter.scrubber.String(contentcap.Cap(ae.Input, contentcap.DefaultMaxBytes))
	}
	if patterns := allowListPatterns(ar); patterns != "" {
		ev.PrecedingReasoning = patterns
	}
	st.stepIdx[key] = len(res.ToolEvents)
	res.ToolEvents = append(res.ToolEvents, ev)
}

// allowListPatterns renders an approval prompt's offered "always allow"
// patterns as a compact, deterministic comma-separated list. Returns ""
// when the prompt offered none.
func allowListPatterns(ar *approvalRequestRaw) string {
	var out []string
	for _, o := range ar.AllowListOptions {
		out = append(out, o.PatternsToAdd...)
	}
	return strings.Join(out, ", ")
}

// emitViewFilesBlock creates or updates the ActionReadFile row for a
// ViewFiles block — the agent opening/inspecting files through the
// host's own affordances rather than through MCP. Keyed by stepId like
// every other block. Multi-file blocks land on the FIRST path, matching
// applyFileChangesFields' existing "first entry" convention; the full
// set rides in RawToolInput so nothing is lost.
func (st *parseState) emitViewFilesBlock(rec *rawRecord, ae *agentEventRaw, res *adapter.ParseResult) {
	if ae.StepID == "" {
		return
	}
	key := "step:" + ae.StepID
	if idx, ok := st.stepIdx[key]; ok && idx < len(res.ToolEvents) {
		st.applyViewFilesFields(&res.ToolEvents[idx], ae)
		return
	}
	ev := st.base(rec)
	ev.SourceEventID = key
	ev.ActionType = models.ActionReadFile
	ev.RawToolName = models.ToolJunie + ".view_files"
	ev.Model = st.model
	ev.PrecedingReasoning = st.takeReasoning()
	st.applyViewFilesFields(&ev, ae)
	idx := len(res.ToolEvents)
	res.ToolEvents = append(res.ToolEvents, ev)
	st.stepIdx[key] = idx
}

// applyViewFilesFields stamps a ViewFiles block's paths and terminal
// status onto ev.
func (st *parseState) applyViewFilesFields(ev *models.ToolEvent, ae *agentEventRaw) {
	var paths []string
	for _, f := range ae.Files {
		if p := strings.TrimSpace(f.RelativePath); p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) > 0 {
		ev.Target = truncate(st.adapter.scrubber.String(paths[0]), 200)
		ev.RawToolInput = st.adapter.scrubber.String(strings.Join(paths, "\n"))
	}
	switch ae.Status {
	case blockStatusFailed:
		ev.Success = false
		ev.ErrorMessage = truncate(st.adapter.scrubber.String(ae.Details), 500)
	case blockStatusCompleted:
		ev.Success = true
		ev.ErrorMessage = ""
		if ae.Details != "" {
			ev.ToolOutput = st.adapter.scrubber.String(contentcap.Cap(ae.Details, contentcap.DefaultMaxBytes))
		}
	}
}

// emitResultBlock creates or updates the ActionTaskComplete row for a
// Result block, keyed by its stepId. Success/failure is derived from
// Cancelled alone — ErrorCode is deliberately not consulted (see the
// package doc).
func (st *parseState) emitResultBlock(rec *rawRecord, ae *agentEventRaw, res *adapter.ParseResult) {
	if ae.StepID == "" {
		return
	}
	key := "step:" + ae.StepID
	if idx, ok := st.stepIdx[key]; ok && idx < len(res.ToolEvents) {
		st.applyResultFields(&res.ToolEvents[idx], rec, ae)
		return
	}
	ev := st.base(rec)
	ev.SourceEventID = key
	ev.ActionType = models.ActionTaskComplete
	ev.RawToolName = models.ToolJunie + ".result"
	ev.Model = st.model
	st.applyResultFields(&ev, rec, ae)
	accumulateResultCache(st.cacheAcc, ae)
	idx := len(res.ToolEvents)
	res.ToolEvents = append(res.ToolEvents, ev)
	st.stepIdx[key] = idx
}

// applyResultFields stamps a Result block's title/result/cancellation/
// timing onto ev.
func (st *parseState) applyResultFields(ev *models.ToolEvent, rec *rawRecord, ae *agentEventRaw) {
	ev.Target = truncate(st.adapter.scrubber.String(ae.Title), 200)
	if ae.Result != "" {
		ev.ToolOutput = st.adapter.scrubber.String(contentcap.Cap(ae.Result, contentcap.DefaultMaxBytes))
	}
	ev.Success = !ae.Cancelled
	if ae.Cancelled {
		ev.ErrorMessage = "cancelled"
	} else {
		ev.ErrorMessage = ""
	}
	if rec.Completion != nil {
		if d := rec.Completion.EndedAtMs - rec.Completion.StartedAtMs; d > 0 {
			ev.DurationMs = d
		}
	}
}

// emitTokens turns a LlmResponseMetadataEvent into one TokenEvent per
// modelUsage entry. An all-zero entry emits nothing, so no phantom rows
// land.
func (st *parseState) emitTokens(rec *rawRecord, ae *agentEventRaw, lineStart int64, res *adapter.ParseResult) {
	for i, m := range ae.ModelUsage {
		if m.isZero() {
			continue
		}
		if m.Model != "" {
			st.model = m.Model
		}
		res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
			SourceFile:          st.path,
			SourceEventID:       fmt.Sprintf("llm:%d:%d", lineStart, i),
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
			Timestamp:           parseTimestamp(rec.TimestampMs),
			Tool:                models.ToolJunie,
			Model:               m.Model,
			InputTokens:         m.InputTokens,
			OutputTokens:        m.OutputTokens,
			CacheReadTokens:     m.CacheInputTokens,
			CacheCreationTokens: m.CacheCreateTokens,
			EstimatedCostUSD:    m.Cost,
			Source:              models.TokenSourceJSONL,
			Reliability:         models.ReliabilityAccurate,
		})
	}
	res.CacheObservations = append(res.CacheObservations,
		emitCacheObservations(st.cacheAcc, st.path, st.sessionID, lineStart, parseTimestamp(rec.TimestampMs), ae.ModelUsage)...)
}

// compile-time interface check.
var _ adapter.Adapter = (*Adapter)(nil)
