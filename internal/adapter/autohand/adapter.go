package autohand

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

const (
	conversationName = "conversation.jsonl"
	metadataName     = "metadata.json"

	maxTargetLen = 500
	maxErrorLen  = 500

	// maxLineBytes caps one transcript line. A tool result is flattened
	// into a single line, so one pathological result must cost one record,
	// not the session: a line past the cap is skipped, not left wedging
	// the cursor.
	maxLineBytes = 16 * 1024 * 1024

	// surfaceHost is the host token stamped on every captured session.
	surfaceHost = "autohand"

	// noProjectRoot is the placeholder project for a session whose
	// metadata names no project path.
	noProjectRoot = "[autohand]"
)

// clientSurfaces resolves metadata.json `client` (the vendor's
// AUTOHAND_CLIENT_NAME, default "terminal") onto the normalized surface
// vocabulary. Only values seen on disk are mapped; an unmapped client emits no
// stamp (the honest unknown) rather than a guess.
var clientSurfaces = map[string]string{
	"terminal": models.SurfaceCLI, // live-grounded, both OSes
}

// Adapter parses Autohand Code CLI session directories.
type Adapter struct {
	scrubber *scrub.Scrubber
	specs    []rootSpec
	roots    []string

	// mu guards the read-through caches of vendor housekeeping files.
	mu       sync.Mutex
	logCache map[string]logCacheItem
	pkgCache map[string]pkgCacheItem
}

// New returns an adapter with the default scrubber and platform-default
// cross-mount watch roots.
func New() *Adapter {
	return newWithSpecs(scrub.New(), defaultRootSpecs())
}

// NewWithOptions customizes the scrubber and/or watch roots for tests. A nil
// scrubber falls back to scrub.New(); no roots falls back to the platform
// defaults. Custom roots carry no home-OS, so synced-copy filtering is off for
// them.
func NewWithOptions(s *scrub.Scrubber, roots ...string) *Adapter {
	if len(roots) == 0 {
		return newWithSpecs(s, defaultRootSpecs())
	}
	specs := make([]rootSpec, 0, len(roots))
	for _, r := range roots {
		specs = append(specs, rootSpec{path: r})
	}
	return newWithSpecs(s, specs)
}

func newWithSpecs(s *scrub.Scrubber, specs []rootSpec) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	return &Adapter{scrubber: s, specs: specs, roots: rootPaths(specs)}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolAutohand }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. A path qualifies when it is a
// session directory's conversation.jsonl or metadata.json directly under a
// directory named "sessions" AND under a watch root. sessions/index.json, the
// optional state.json and every other data-home file are rejected.
func (a *Adapter) IsSessionFile(path string) bool {
	base := filepath.Base(path)
	if base != conversationName && base != metadataName {
		return false
	}
	if filepath.Base(filepath.Dir(filepath.Dir(path))) != sessionsDirName {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// CursorSemanticsFor implements adapter.CursorSemantics. conversation.jsonl is
// a byte-offset tail that the parser seeks into. metadata.json is rewritten
// whole on every save and only ever yields the session's token row, never an
// action, so the zero-action fingerprint must not apply to it.
func (*Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if filepath.Base(path) == metadataName {
		return adapter.FileCursorSemantics{
			Kind:   adapter.CursorNoActions,
			Detail: "session metadata (cumulative usage); rewritten whole, emits the session token row (and error.log api_error rows) only",
		}
	}
	return adapter.FileCursorSemantics{StreamsFromCursor: true}
}

// ParseSessionFile implements adapter.Adapter. It dispatches on the file's
// role in the session directory: metadata.json yields the token row,
// conversation.jsonl yields the actions (and the same token row, read from
// the sibling metadata, so either file alone is enough to land it).
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	if filepath.Base(path) == metadataName {
		return a.parseMetadataFile(ctx, path)
	}
	return a.parseConversation(ctx, path, fromOffset)
}

// sessionIDFor returns the canonical session id: metadata.json's sessionId,
// else the directory name (they are the same string on every observed
// session, and both equal the `autohand resume` argument).
func sessionIDFor(path string, m metadata) string {
	if m.SessionID != "" {
		return m.SessionID
	}
	return filepath.Base(filepath.Dir(path))
}

// resolveProject resolves the session's project root, branch and identity from
// metadata.projectPath. A path foreign to the running OS is translated and
// stat-gated before git sees it; anything that does not resolve to an
// existing local directory is carried verbatim, with no git lookup (a
// drive-letter path read on Linux must not be CWD-prefixed into the
// observer's own repository).
func resolveProject(raw string) (root, branch string, id git.Identity) {
	cwd := strings.TrimSpace(raw)
	if cwd == "" {
		return noProjectRoot, "", git.Identity{}
	}
	local := crossmount.TranslateForeignPath(cwd)
	if filepath.IsAbs(local) {
		if fi, err := os.Stat(local); err == nil && fi.IsDir() {
			ident, gerr := git.ResolveIdentity(local, git.IdentityOptions{})
			if gerr != nil {
				return local, "", git.Identity{}
			}
			return ident.Root, ident.Branch, ident
		}
	}
	return cwd, "", git.Identity{}
}

// sessionEnvelope assembles the per-session, non-event outputs shared by both
// file roles: surface attribution, branch lineage and project identity.
func (a *Adapter) sessionEnvelope(res *adapter.ParseResult, path, sessID string, m metadata, id git.Identity) {
	adapter.ApplyProjectIdentity(res, id)
	if sessID == "" {
		return
	}
	if kind, ok := clientSurfaces[m.Client]; ok {
		res.SessionSurfaces = append(res.SessionSurfaces, models.SessionSurface{
			SessionID:   sessID,
			Surface:     kind,
			SurfaceHost: surfaceHost,
		})
	}
	if m.Branch != nil && m.Branch.SourceSessionID != "" {
		res.SessionLineages = append(res.SessionLineages, models.SessionLineage{
			SessionID:    sessID,
			ForkedFromID: m.Branch.SourceSessionID,
			// A user-initiated `--fork` / clone, the codex "user" shape.
			ThreadSource: "user",
		})
	}

	dataHome := dataHomeFor(path)
	res.SessionToolVersions = append(res.SessionToolVersions,
		a.toolVersionStamp(sessID, dataHome, m, a.errorLog(dataHome))...)
	res.SessionProcessSeeds = append(res.SessionProcessSeeds, processSeeds(dataHome, sessID)...)
	res.ToolAccounts = append(res.ToolAccounts,
		accountObservations(readAccountID(dataHome), sessID, res.ToolEvents)...)
}

// dataHomeFor returns the vendor data home (the parent of the sessions
// directory) of a session file <home>/sessions/<id>/<file>.
func dataHomeFor(path string) string {
	return filepath.Dir(filepath.Dir(filepath.Dir(path)))
}

// parseMetadataFile handles metadata.json: the session's token row and
// envelope, no actions.
func (a *Adapter) parseMetadataFile(_ context.Context, path string) (adapter.ParseResult, error) {
	var res adapter.ParseResult
	if fi, err := os.Stat(path); err == nil {
		res.NewOffset = fi.Size()
	}
	m, found, err := readMetadata(path)
	if err != nil {
		return res, fmt.Errorf("autohand.parseMetadataFile: %w", err)
	}
	if !found {
		res.RetrySuggested = true
		return res, nil
	}
	sessID := sessionIDFor(path, m)
	if a.foreignCopy(path, m.ProjectPath) {
		return res, nil
	}
	root, branch, ident := resolveProject(m.ProjectPath)
	convPath := filepath.Join(filepath.Dir(path), conversationName)
	if u, ok, warn := sessionUsage(path, m); ok {
		res.TokenEvents = append(res.TokenEvents, tokenEvent(convPath, sessID, root, branch, ident.Remote, m, u))
	} else if warn != "" {
		res.Warnings = append(res.Warnings, warn)
	}
	a.errorEvents(&res, convPath, sessID, root, branch, ident.Remote, m)
	a.sessionEnvelope(&res, path, sessID, m, ident)
	return res, nil
}

// splitLinesKeepTerminator is bufio.ScanLines except the token retains its line
// terminator, so the caller advances the byte cursor by exactly the bytes
// consumed (CRLF included) and can tell a complete line from a half-written
// trailing one.
func splitLinesKeepTerminator(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i+1], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// skipOverlongLine returns the offset just past the newline that terminates
// the line starting at off, streaming through a small buffer so the line's
// size never enters the heap. When the line has no terminator yet it returns
// off unchanged.
func skipOverlongLine(f *os.File, off int64) (int64, error) {
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return off, fmt.Errorf("autohand.skipOverlongLine: seek: %w", err)
	}
	r := bufio.NewReaderSize(f, 64*1024)
	var skipped int64
	for {
		chunk, err := r.ReadSlice('\n')
		skipped += int64(len(chunk))
		switch {
		case err == nil:
			return off + skipped, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return off, nil
		default:
			return off, fmt.Errorf("autohand.skipOverlongLine: read: %w", err)
		}
	}
}

// readMessages reads complete transcript lines from fromOffset. A trailing
// partial line is deferred (the cursor stays before it). It returns the decoded
// messages, the new cursor and any warnings.
func readMessages(f *os.File, fromOffset int64) (msgs []message, newOffset int64, warnings []string, retry bool) {
	consumed := fromOffset
	for {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1024*1024), maxLineBytes)
		sc.Split(splitLinesKeepTerminator)
		partial := false
		for sc.Scan() {
			raw := sc.Bytes()
			if !bytes.HasSuffix(raw, []byte("\n")) {
				partial = true
				break
			}
			consumed += int64(len(raw))
			trimmed := bytes.TrimSpace(raw)
			if len(trimmed) == 0 {
				continue
			}
			var m message
			if err := json.Unmarshal(trimmed, &m); err != nil {
				warnings = append(warnings, fmt.Sprintf("offset %d: malformed line skipped: %v", consumed-int64(len(raw)), err))
				continue
			}
			msgs = append(msgs, m)
		}
		if partial {
			break
		}
		scanErr := sc.Err()
		if scanErr == nil {
			break
		}
		if !errors.Is(scanErr, bufio.ErrTooLong) {
			warnings = append(warnings, fmt.Sprintf("offset %d: scan: %v", consumed, scanErr))
			break
		}
		next, skipErr := skipOverlongLine(f, consumed)
		if skipErr != nil {
			warnings = append(warnings, fmt.Sprintf("offset %d: line exceeds the %d MiB cap and could not be skipped: %v",
				consumed, maxLineBytes/(1024*1024), skipErr))
			break
		}
		if next == consumed {
			retry = true
			break
		}
		warnings = append(warnings, fmt.Sprintf("offset %d: skipped a %d-byte line over the %d MiB cap",
			consumed, next-consumed, maxLineBytes/(1024*1024)))
		consumed = next
		if _, err := f.Seek(consumed, io.SeekStart); err != nil {
			warnings = append(warnings, fmt.Sprintf("offset %d: seek: %v", consumed, err))
			break
		}
	}
	return msgs, consumed, warnings, retry
}

// parseConversation handles conversation.jsonl from fromOffset.
func (a *Adapter) parseConversation(_ context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	var res adapter.ParseResult
	res.NewOffset = fromOffset

	metaPath := filepath.Join(filepath.Dir(path), metadataName)
	m, _, err := readMetadata(metaPath)
	if err != nil {
		return res, fmt.Errorf("autohand.parseConversation: %w", err)
	}
	sessID := sessionIDFor(path, m)

	f, err := os.Open(path) //nolint:gosec // watched session file
	if err != nil {
		return res, nil // vanished mid-poll; try later
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return res, nil
	}
	if a.foreignCopy(path, m.ProjectPath) {
		res.NewOffset = fi.Size()
		return res, nil
	}
	if fromOffset > fi.Size() {
		// The vendor rewrote the file shorter (replaceMessages): restart.
		fromOffset = 0
		res.NewOffset = 0
	}
	if fromOffset > 0 {
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return res, nil
		}
	}

	msgs, newOffset, warnings, retry := readMessages(f, fromOffset)
	res.NewOffset = newOffset
	res.Warnings = append(res.Warnings, warnings...)
	res.RetrySuggested = retry

	root, branch, ident := resolveProject(m.ProjectPath)
	st := &parseState{
		a: a, path: path, sessID: sessID, root: root, branch: branch, remote: ident.Remote, meta: m,
		cutoff: m.inheritedCutoff(), fallback: parseTime(m.CreatedAt),
		toolIdx: map[string]int{}, turn: -1,
	}
	if fromOffset > 0 {
		// TurnIndex indexes the WHOLE session: replay the already-consumed
		// prefix through the same prompt rules, emitting nothing.
		st.seedTurns(path, fromOffset)
	}
	for _, msg := range msgs {
		st.handle(msg, &res)
	}

	if u, ok, warn := sessionUsage(metaPath, m); ok {
		res.TokenEvents = append(res.TokenEvents, tokenEvent(path, sessID, root, branch, ident.Remote, m, u))
	} else if warn != "" {
		res.Warnings = append(res.Warnings, warn)
	}
	a.errorEvents(&res, path, sessID, root, branch, ident.Remote, m)
	a.sessionEnvelope(&res, path, sessID, m, ident)
	return res, nil
}

// parseState carries one parse window's context.
type parseState struct {
	a        *Adapter
	path     string
	sessID   string
	root     string
	branch   string
	remote   string
	meta     metadata
	cutoff   time.Time
	fallback time.Time
	// toolIdx maps a tool call id to its ToolEvent's index in this window.
	// A result whose call was parsed in an EARLIER window has no entry and
	// is emitted as an OutcomeUpdate instead.
	toolIdx map[string]int
	// turn is the 0-based index of the current user prompt within the whole
	// session (-1 before the first); incremented per real user prompt.
	turn int
}

// stamp returns a message's time, falling back to the session's creation.
func (st *parseState) stamp(msg message) time.Time {
	if t := parseTime(msg.Timestamp); !t.IsZero() {
		return t
	}
	return st.fallback
}

// inherited reports whether a line was copied in from a source session or tool
// (it predates the fork/import) and so belongs to someone else's capture.
func (st *parseState) inherited(ts time.Time) bool {
	return !st.cutoff.IsZero() && !ts.IsZero() && ts.Before(st.cutoff)
}

func (st *parseState) handle(msg message, res *adapter.ParseResult) {
	ts := st.stamp(msg)
	if st.inherited(ts) {
		return
	}
	switch msg.Role {
	case "user":
		st.userPrompt(msg, ts, res)
	case "assistant":
		st.assistant(msg, ts, res)
	case "tool":
		st.toolResult(msg, res)
	}
}

func (st *parseState) base(ts time.Time, eventID, action string) models.ToolEvent {
	return models.ToolEvent{
		SourceFile:    st.path,
		SourceEventID: eventID,
		SessionID:     st.sessID,
		ProjectRoot:   st.root,
		GitBranch:     st.branch,
		GitRemote:     st.remote,
		TurnIndex:     max(st.turn, 0),
		Timestamp:     ts,
		Tool:          models.ToolAutohand,
		Model:         st.meta.Model,
		ActionType:    action,
		Success:       true,
	}
}

func (st *parseState) userPrompt(msg message, ts time.Time, res *adapter.ParseResult) {
	if msg.Meta.injected() {
		return // harness-injected peer context, not typed by the operator
	}
	text := strings.TrimSpace(contentText(msg.Content))
	if text == "" {
		return
	}
	st.turn++
	ev := st.base(ts, "user:"+st.sessID+":"+messageKey(ts, text), models.ActionUserPrompt)
	ev.RawToolName = "autohand.user_prompt"
	ev.Target = truncate(st.a.scrubber.String(text), maxTargetLen)
	res.ToolEvents = append(res.ToolEvents, ev)
}

func (st *parseState) assistant(msg message, ts time.Time, res *adapter.ParseResult) {
	if text := strings.TrimSpace(contentText(msg.Content)); text != "" {
		ev := st.base(ts, "asst:"+st.sessID+":"+messageKey(ts, text), models.ActionAssistantMessage)
		ev.RawToolName = "autohand.assistant_text"
		ev.Target = truncate(st.a.scrubber.String(text), maxTargetLen)
		res.ToolEvents = append(res.ToolEvents, ev)
	}
	for i, tc := range msg.ToolCalls {
		if tc.Tool == "" {
			continue
		}
		id := "tool:" + st.sessID + ":" + tc.ID
		if tc.ID == "" {
			// No call id to pair a result with: anchor on the line and slot.
			id = "tool:" + st.sessID + ":" + strconv.FormatInt(ts.UnixMilli(), 10) + ":" + strconv.Itoa(i)
		}
		ev := st.base(ts, id, classifyTool(tc.Tool))
		ev.RawToolName = tc.Tool
		ev.RawToolInput = st.a.scrubber.RawJSON(tc.Args)
		ev.Target = truncate(st.a.scrubber.String(targetFromArgs(tc.Tool, tc.Args)), maxTargetLen)
		ev.ContentBytes = authoredBytes(tc.Tool, tc.Args)
		res.ToolEvents = append(res.ToolEvents, ev)
		if tc.ID != "" {
			st.toolIdx[tc.ID] = len(res.ToolEvents) - 1
		}
	}
}

func (st *parseState) toolResult(msg message, res *adapter.ParseResult) {
	if msg.Meta.streamChunk() || msg.ToolCallID == "" {
		return
	}
	text := stripANSI(contentText(msg.Content))
	idx, inWindow := st.toolIdx[msg.ToolCallID]
	inWindow = inWindow && idx < len(res.ToolEvents)
	tool := msg.Name
	if inWindow && res.ToolEvents[idx].RawToolName != "" {
		tool = res.ToolEvents[idx].RawToolName
	}
	failed := outputFailed(tool, text)
	out := st.a.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes))
	errMsg := ""
	if failed {
		errMsg = truncate(out, maxErrorLen)
	}
	if inWindow {
		ev := &res.ToolEvents[idx]
		ev.ToolOutput = out
		ev.Success = !failed
		ev.ErrorMessage = errMsg
		return
	}
	res.OutcomeUpdates = append(res.OutcomeUpdates, models.ActionOutcomeUpdate{
		SourceFile:    st.path,
		SourceEventID: "tool:" + st.sessID + ":" + msg.ToolCallID,
		SuccessKnown:  true,
		Success:       !failed,
		ErrorMessage:  errMsg,
		ToolOutput:    out,
	})
}
