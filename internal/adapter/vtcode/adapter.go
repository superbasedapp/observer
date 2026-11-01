package vtcode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter parses VT Code's per-workspace session event logs
// (`<workspace>/.vtcode/sessions/<session-id>/events.jsonl`) and uses the
// global session archive (`<state dir>/sessions/<session-id>.json`) both
// as a discovery seam and as a second trigger for the same parse. See the
// package doc for the store shape.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
	traj     *trajectoryCache
	arch     *archiveCache
	ver      *versionCache
}

// New returns an adapter whose roots are the global archive directories of
// every cross-mount-resolved home plus every workspace store those
// archives name (a construction-time snapshot).
func New() *Adapter {
	return newAdapter(scrub.New(), discoverRoots())
}

// NewWithOptions customizes the scrubber and/or roots for tests. A nil
// scrubber falls back to scrub.New(); no roots falls back to discovery.
// Given roots are used verbatim (no archive-driven discovery): pass both
// the archive dir and the workspace `.vtcode/sessions` dir a test needs.
func NewWithOptions(s *scrub.Scrubber, roots ...string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = discoverRoots()
	}
	return newAdapter(s, roots)
}

// newAdapter wires the per-file caches.
func newAdapter(s *scrub.Scrubber, roots []string) *Adapter {
	return &Adapter{scrubber: s, roots: roots, traj: &trajectoryCache{}, arch: &archiveCache{}, ver: &versionCache{}}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolVTCode }

// WatchPaths implements adapter.Adapter. See discoverRoots for the
// snapshot caveat on workspace roots.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Two shapes qualify, each ANDed
// with the watch-root check:
//
//   - a workspace event log: `.../.vtcode/sessions/<id>/events.jsonl`
//     where <id> is `session-*` (TUI, exec) or `auto-task-*` (--full-auto);
//   - a global archive JSON: `.../sessions/<id>.json` that does NOT
//     sit inside a `.vtcode` workspace store.
func (a *Adapter) IsSessionFile(path string) bool {
	if !isEventsShape(path) && !isArchiveShape(path) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.roots)
}

// isEventsShape reports whether path is
// `<x>/.vtcode/sessions/{session-*,auto-task-*}/events.jsonl`.
func isEventsShape(path string) bool {
	if !strings.EqualFold(filepath.Base(path), eventsFileName) {
		return false
	}
	sessDir := filepath.Dir(path)
	if !hasSessionIDPrefix(filepath.Base(sessDir)) {
		return false
	}
	return isWorkspaceSessionsRoot(filepath.Dir(sessDir))
}

// isArchiveShape reports whether path is a global archive JSON
// (`<state>/sessions/session-*.json`, never inside a `.vtcode` store).
func isArchiveShape(path string) bool {
	if !isArchiveName(filepath.Base(path)) {
		return false
	}
	dir := filepath.Dir(path)
	return strings.EqualFold(filepath.Base(dir), sessionsDirName) && !isWorkspaceSessionsRoot(dir)
}

// CursorSemanticsFor implements adapter.CursorSemantics. The event log is
// a byte-offset cursor over an append-only file, but every parse re-reads
// the whole file to rebuild turn / tool-call state (so it does NOT stream
// from the cursor); the archive JSON contributes rows attributed to its
// sibling event log, never to itself.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	switch {
	case !a.IsSessionFile(path):
		return adapter.FileCursorSemantics{}
	case isArchiveShape(path):
		return adapter.FileCursorSemantics{
			Kind:   adapter.CursorNoActions,
			Detail: "VT Code global session archive: a re-parse trigger whose rows land under the workspace .vtcode/sessions/<id>/events.jsonl",
		}
	default:
		return adapter.FileCursorSemantics{
			Detail: "byte offset; each parse re-reads the whole events.jsonl to rebuild turn and tool-call state and emits only records at or past the cursor",
		}
	}
}

// ParseSessionFile implements adapter.Adapter.
//
// For a workspace events.jsonl it re-reads the file, rebuilds turn and
// tool-call state from the top, and emits only the rows anchored at or
// past fromOffset; NewOffset is the end of the last complete line.
//
// For a global archive JSON it resolves the archived workspace's
// events.jsonl and parses it in full (rows carry the EVENT LOG as
// SourceFile and the same deterministic ids, so they dedupe against the
// live tail via (source_file, source_event_id)); NewOffset is the archive
// file's size.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	if isArchiveShape(path) {
		return a.parseArchive(ctx, path, fromOffset)
	}
	doc, root := a.archiveFor(sessionIDFromEventsPath(path))
	return a.parseEvents(ctx, path, fromOffset, doc, root)
}

// parseArchive handles the global archive JSON trigger.
func (a *Adapter) parseArchive(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("vtcode.ParseSessionFile: stat %s: %w", path, err)
	}
	res := adapter.ParseResult{NewOffset: fi.Size()}
	if fromOffset > 0 && fi.Size() == fromOffset {
		return res, nil
	}
	doc := a.arch.load(path)
	if doc == nil {
		res.Warnings = append(res.Warnings, "vtcode: archive JSON unreadable or malformed: "+filepath.Base(path))
		return res, nil
	}
	ws := resolveWorkspacePath(path, doc.file.Metadata.WorkspacePath)
	if ws == "" {
		return res, nil
	}
	sid := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	events := filepath.Join(ws, workspaceDirName, sessionsDirName, sid, eventsFileName)
	var sub adapter.ParseResult
	if _, err := os.Stat(events); err != nil {
		// The workspace store is gone (a deleted scratch dir, an
		// unmounted drive): the archive's own message history is the
		// only record left. See parseArchiveOnly.
		sub = a.parseArchiveOnly(ctx, path, events, ws, sid, doc)
	} else {
		sub, err = a.parseEvents(ctx, events, 0, doc, filepath.Dir(path))
		if err != nil {
			return res, err
		}
	}
	sub.NewOffset = res.NewOffset
	return sub, nil
}

// archiveFor finds the global archive JSON for sessionID under the
// adapter's archive roots and returns its decode plus the root it was
// found in ("" / nil when there is none, e.g. an auto-task run).
func (a *Adapter) archiveFor(sessionID string) (*archiveDoc, string) {
	if sessionID == "" {
		return nil, ""
	}
	for _, r := range a.roots {
		if isWorkspaceSessionsRoot(r) {
			continue
		}
		if d := a.arch.load(filepath.Join(r, sessionID+".json")); d != nil {
			return d, r
		}
	}
	return nil, ""
}

// sessionIDFromEventsPath returns the session id (the directory name,
// which equals thread.started's thread_id and is what `vtcode --resume`
// accepts).
func sessionIDFromEventsPath(path string) string {
	return filepath.Base(filepath.Dir(path))
}

// rawLine is one complete line of the event log and its start offset.
type rawLine struct {
	off  int64
	text []byte
}

// readLines reads every newline-terminated line of path. A trailing partial
// line (still being written) is excluded and end stops before it.
func readLines(path string) (lines []rawLine, end int64, err error) {
	b, err := os.ReadFile(path) //nolint:gosec // watcher-supplied session file under a watch root
	if err != nil {
		return nil, 0, err
	}
	var off int64
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			break
		}
		lines = append(lines, rawLine{off: off, text: b[:i]})
		off += int64(i + 1)
		b = b[i+1:]
	}
	return lines, off, nil
}

// parseEvents parses a workspace events.jsonl. doc (possibly nil) is the
// session's global archive (model fallback, effort setting, the model's
// reasoning); stateRoot is the archive dir it was found in ("" when none),
// which also locates the install's version file.
func (a *Adapter) parseEvents(ctx context.Context, path string, fromOffset int64, doc *archiveDoc, stateRoot string) (adapter.ParseResult, error) {
	lines, end, err := readLines(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("vtcode.ParseSessionFile: read %s: %w", path, err)
	}
	if fromOffset > end {
		// The file shrank under the cursor (rewritten or replaced): start
		// over; deterministic ids make the re-emission idempotent.
		fromOffset = 0
	}
	res := adapter.ParseResult{NewOffset: end}
	if fromOffset == end && fromOffset > 0 {
		return res, nil
	}

	sessDir := filepath.Dir(path)
	sid := sessionIDFromEventsPath(path)
	p := &parser{
		a:          a,
		path:       path,
		sessionID:  sid,
		threadID:   sid,
		emitFrom:   fromOffset,
		doc:        doc,
		turns:      a.traj.turns(filepath.Join(filepath.Dir(filepath.Dir(sessDir)), logsDirName), sid),
		calls:      map[string]*callState{},
		tokensDone: map[string]bool{},
		failedDone: map[string]bool{},
	}
	if doc != nil {
		p.meta = doc.file.Metadata
	}
	ws := filepath.Dir(filepath.Dir(filepath.Dir(sessDir)))
	p.resolveProject(ws)
	man := readManifest(filepath.Join(sessDir, "manifest.json"))
	p.startTime = parseTime(man.CreatedAt)

	for i, ln := range lines {
		if i%256 == 0 && ctx.Err() != nil {
			adapter.ApplyProjectIdentity(&res, p.identity)
			return res, ctx.Err()
		}
		raw := bytes.TrimSpace(ln.text)
		if len(raw) == 0 {
			continue
		}
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			if ln.off >= fromOffset {
				res.Warnings = append(res.Warnings, fmt.Sprintf("vtcode: line at offset %d: malformed JSON: %v", ln.off, err))
			}
			continue
		}
		p.handle(ln.off, string(raw), &env.Event, &res)
	}
	p.flushOrphanCalls(&res)
	a.sessionFacts(&res, sid, path, ws, man.Status, stateRoot)
	adapter.ApplyProjectIdentity(&res, p.identity)
	return res, nil
}

// sessionFacts appends the per-session side facts every parse restates
// (the store writes are idempotent): the tool version, the live process
// seed, and the surface for an autonomous run.
func (a *Adapter) sessionFacts(res *adapter.ParseResult, sid, eventsPath, cwd, manifestStatus, stateRoot string) {
	// Tool version (operator ruling 1, 2026-10-21): no VT Code store
	// records the build per session (events carry only the EVENT schema
	// version 0.18.0), so every session is stamped with the install-level
	// `last_seen_version` of the install whose archive dir it belongs to.
	if v := a.ver.version(versionFileForStateRoot(a.stateRootFor(eventsPath, stateRoot))); v != "" {
		res.SessionToolVersions = append(res.SessionToolVersions, models.SessionToolVersion{SessionID: sid, Version: v})
	}
	if eventsPath != "" {
		res.SessionProcessSeeds = append(res.SessionProcessSeeds, processSeeds(sid, eventsPath, cwd, manifestStatus)...)
	}
	// `auto-task-*` is written only by the autonomous `--auto` /
	// `--full-auto` CLI run. The `session-*` shape is shared by the TUI
	// and `vtcode exec` (and possibly `vtcode acp`), so it is not stamped.
	if strings.HasPrefix(strings.ToLower(sid), autoTaskPrefix) {
		res.SessionSurfaces = append(res.SessionSurfaces, models.SessionSurface{
			SessionID: sid, Surface: models.SurfaceCLI, SurfaceHost: "vtcode-auto",
		})
	}
}

// readManifest reads the session manifest (created_at is the only
// timestamp for thread.started; status gates process seeding).
func readManifest(path string) manifest {
	b, err := os.ReadFile(path) //nolint:gosec // sibling of a watched session file
	if err != nil {
		return manifest{}
	}
	var m manifest
	if json.Unmarshal(b, &m) != nil {
		return manifest{}
	}
	return m
}

// parser is the per-parse mutable state.
type parser struct {
	a         *Adapter
	path      string
	sessionID string
	// threadID is thread.started's thread_id (the primary agent's
	// actor_id); defaults to the directory name.
	threadID  string
	emitFrom  int64
	meta      archiveMeta
	doc       *archiveDoc
	turns     map[string]*turnTraj
	startTime time.Time

	projectRoot string
	gitBranch   string
	gitRemote   string
	identity    git.Identity

	curTurn       string
	lastTS        time.Time
	lastTermOff   int64
	pendingImages int
	calls         map[string]*callState
	callOrder     []string
	tokensDone    map[string]bool
	failedDone    map[string]bool
}

// callState pairs a tool call's invocation completion with its output.
type callState struct {
	firstTS   time.Time
	inv       *item
	invOff    int64
	out       *item
	outOff    int64
	turnID    string
	emitted   bool
	isPhantom bool
}

// resolveProject resolves the workspace (the directory holding `.vtcode`)
// to a git working-tree root + branch + remote. The event log path is
// already in this process's form, so no foreign-path translation applies.
func (p *parser) resolveProject(ws string) {
	p.projectRoot = ws
	id, err := git.ResolveIdentity(ws, git.IdentityOptions{})
	if err != nil {
		return
	}
	p.projectRoot = id.Root
	p.gitBranch = id.Branch
	p.gitRemote = id.Remote
	p.identity = id
}

// emits reports whether a row anchored at off belongs to this parse window.
func (p *parser) emits(off int64) bool { return off >= p.emitFrom }

// model returns the served model for a turn: the trajectory's record for
// that turn, else the archive's session-start model, else "".
func (p *parser) model(turnID string) string {
	if t := p.turns[turnID]; t != nil && t.model != "" {
		return t.model
	}
	return strings.TrimSpace(p.meta.Model)
}

// isSidechain reports whether an item was produced by an actor other than
// the session's primary agent (a delegated subagent).
func (p *parser) isSidechain(c *turnContext) bool {
	return c != nil && c.ActorID != "" && c.ActorID != p.sessionID && c.ActorID != p.threadID
}

// reasoningForCall returns the scrubbed model reasoning that preceded a
// tool call, from the archive (operator ruling 4, 2026-10-21). events.jsonl
// `reasoning` items are the harness's own failure diagnosis, never this.
func (p *parser) reasoningForCall(callID string) string {
	if p.doc == nil || callID == "" {
		return ""
	}
	return p.scrubReasoning(p.doc.reasoningByCall[callID])
}

// reasoningForText returns the reasoning of a text-only assistant message.
func (p *parser) reasoningForText(text string) string {
	if p.doc == nil {
		return ""
	}
	return p.scrubReasoning(p.doc.reasoningByText[strings.TrimSpace(text)])
}

func (p *parser) scrubReasoning(r string) string {
	if r == "" {
		return ""
	}
	return truncate(p.a.scrubber.String(r), reasoningCap)
}

// reasoningCap bounds PrecedingReasoning (the codex convention).
const reasoningCap = 500

// base returns a ToolEvent pre-filled with the session-wide fields.
func (p *parser) base(id string, ts time.Time, action string) models.ToolEvent {
	return models.ToolEvent{
		SourceFile:    p.path,
		SourceEventID: id,
		SessionID:     p.sessionID,
		ProjectRoot:   p.projectRoot,
		GitBranch:     p.gitBranch,
		GitRemote:     p.gitRemote,
		Timestamp:     ts,
		Tool:          models.ToolVTCode,
		ActionType:    action,
		Success:       true,
	}
}

// handle dispatches one decoded event.
func (p *parser) handle(off int64, raw string, ev *eventBody, res *adapter.ParseResult) {
	switch ev.Type {
	case "thread.started":
		if ev.ThreadID != "" {
			p.threadID = ev.ThreadID
		}
		p.emitSessionStart(off, res)
	case "turn.started":
		p.onTurnStarted(off, ev, res)
	case "item.started", "item.updated", "item.completed":
		p.onItem(off, ev, res)
	case "turn.completed", "turn.failed", "turn.blocked":
		p.onTurnEnd(off, raw, ev, res)
	case "thread.completed":
		p.emitSessionEnd(off, ev, res)
	case "interjected":
		// Raw composer input (slash commands included). Only the image
		// count is used: it rides onto the next user prompt.
		p.pendingImages = max(ev.ImageCount, 0)
	case "permission.resolved":
		p.emitPermission(off, ev, res)
	}
}

// emitSessionStart records the session-start marker.
func (p *parser) emitSessionStart(off int64, res *adapter.ParseResult) {
	if !p.emits(off) {
		return
	}
	ev := p.base("session_start:"+p.sessionID, p.startTime, models.ActionSessionStart)
	ev.Target = "startup"
	ev.RawToolName = models.ToolVTCode + ".session_start"
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitSessionEnd records thread.completed: subtype / outcome_code as the
// target, the provider stop reason and the session's provider-stated
// cost (`total_cost_usd`, session-level only) in the metadata. Its usage
// is the sum of the turns and is never re-emitted as tokens.
func (p *parser) emitSessionEnd(off int64, ev *eventBody, res *adapter.ParseResult) {
	if !p.emits(off) {
		return
	}
	ts := firstTime(parseTime(ev.CompletedAt), p.lastTS)
	te := p.base("session_end:"+p.sessionID, ts, models.ActionSessionEnd)
	te.Target = firstNonEmpty(ev.Subtype, ev.OutcomeCode, "completed")
	te.RawToolName = models.ToolVTCode + ".thread_completed"
	md := &models.ActionMetadata{StopReason: strings.TrimSpace(ev.StopReason)}
	if ev.TotalCostUSD != nil && *ev.TotalCostUSD > 0 {
		md.TotalCostUSD = *ev.TotalCostUSD
	}
	if md.StopReason != "" || md.TotalCostUSD != 0 {
		te.Metadata = md
	}
	res.ToolEvents = append(res.ToolEvents, te)
}

// emitPermission records an approval decision (`permission.resolved`:
// tool_name, decision, wait_ms; no call id). An allow is a
// permission_request row whose DurationMs is the time the approval waited;
// anything else is a permission_denied row.
func (p *parser) emitPermission(off int64, ev *eventBody, res *adapter.ParseResult) {
	if !p.emits(off) || strings.TrimSpace(ev.ToolName) == "" {
		return
	}
	decision := strings.ToLower(strings.TrimSpace(ev.Decision))
	action := models.ActionPermissionRequest
	if decision != "allow" {
		action = models.ActionPermissionDenied
	}
	te := p.base(fmt.Sprintf("permission:%d", off), p.lastTS, action)
	te.Target = ev.ToolName
	te.RawToolName = ev.ToolName
	te.MessageID = p.curTurn
	te.DurationMs = max(ev.WaitMs, 0)
	if action == models.ActionPermissionDenied {
		te.Success = false
		te.ErrorMessage = firstNonEmpty(decision, "denied")
	}
	res.ToolEvents = append(res.ToolEvents, te)
}

// onTurnStarted tracks the current turn and records a user prompt for a
// user-originated turn (a harness "continuation" turn is not a prompt).
func (p *parser) onTurnStarted(off int64, ev *eventBody, res *adapter.ParseResult) {
	c := ev.Context
	if c == nil {
		return
	}
	p.curTurn = c.TurnID
	ts := parseTime(c.Timestamp)
	p.noteTime(ts)
	p.lastTermOff = off
	images := p.pendingImages
	p.pendingImages = 0
	if c.Origin != "user" || strings.TrimSpace(c.Goal) == "" || !p.emits(off) {
		return
	}
	scrubbed := p.a.scrubber.String(c.Goal)
	te := p.base("prompt:"+firstNonEmpty(c.TurnID, hashID(c.Timestamp+c.Goal)), ts, models.ActionUserPrompt)
	te.Target = truncate(scrubbed, 200)
	te.RawToolName = models.ToolVTCode + ".user_prompt"
	te.RawToolInput = scrubbed
	te.Model = p.model(c.TurnID)
	te.IsSidechain = p.isSidechain(c)
	if effort := strings.TrimSpace(p.meta.ReasoningEffort); effort != "" {
		te.Metadata = &models.ActionMetadata{EffortLevel: effort}
	}
	// interjected.image_count is a COUNT with no media type: one
	// image-kind attachment per counted image.
	for i := 0; i < images && i < maxAttachments; i++ {
		te.UserAttachments = append(te.UserAttachments, models.UserAttachment{Kind: "image"})
	}
	res.ToolEvents = append(res.ToolEvents, te)
}

// maxAttachments caps attachments synthesized from a count.
const maxAttachments = 64

// noteTime keeps the earliest observed timestamp as a session-start
// fallback when the manifest is unreadable.
func (p *parser) noteTime(ts time.Time) {
	if ts.IsZero() {
		return
	}
	if p.startTime.IsZero() {
		p.startTime = ts
	}
	p.lastTS = ts
}

// onItem handles item.started / item.updated / item.completed.
func (p *parser) onItem(off int64, ev *eventBody, res *adapter.ParseResult) {
	it := ev.Item
	if it == nil {
		return
	}
	ts := parseTime(it.Context.Timestamp)
	p.noteTime(ts)
	switch it.Type {
	case "tool_invocation", "tool_output":
		p.onToolItem(off, ev.Type, it, ts, res)
	case "agent_message":
		if ev.Type == "item.completed" {
			p.emitAssistant(off, it, ts, res)
		}
	}
}

// onToolItem pairs a call's invocation completion with its output
// completion (keyed by tool_call_id) and emits the action once both are
// in, anchored at the later of the two lines.
func (p *parser) onToolItem(off int64, evType string, it *item, ts time.Time, res *adapter.ParseResult) {
	id := it.ToolCallID
	if id == "" {
		return
	}
	cs := p.calls[id]
	if cs == nil {
		cs = &callState{firstTS: ts, turnID: it.Context.TurnID}
		p.calls[id] = cs
		p.callOrder = append(p.callOrder, id)
	}
	if cs.firstTS.IsZero() {
		cs.firstTS = ts
	}
	if evType != "item.completed" {
		return
	}
	cpy := *it
	if it.Type == "tool_invocation" {
		cs.inv, cs.invOff = &cpy, off
		// A provider can stream a call header that never receives
		// arguments; VT Code closes it at turn end as status "failed",
		// outcome "cancelled" ("Tool call ended when the turn finished
		// before it could execute."). Nothing ran — not an action.
		cs.isPhantom = argsMap(it.Arguments) == nil && it.Outcome == "cancelled"
	} else {
		cs.out, cs.outOff = &cpy, off
	}
	if cs.inv != nil && cs.out != nil {
		p.emitCall(cs, max(cs.invOff, cs.outOff), res)
	}
}

// flushOrphanCalls emits invocations whose output never arrived but whose
// turn has since ended (a later turn boundary was seen), anchored at the
// invocation line.
//
// An orphan with NO arguments that VT Code closed as failed is a phantom
// header too: `vtcode exec` closes the streamed-but-never-filled headers
// (ids `call_function_<x>_<n>`, absent from the archive's tool_calls) as
// status "failed", outcome "error" rather than "cancelled" — 9 of 18
// invocations in the exec fixture. Nothing ran; no row.
func (p *parser) flushOrphanCalls(res *adapter.ParseResult) {
	for _, id := range p.callOrder {
		cs := p.calls[id]
		if cs.emitted || cs.inv == nil || cs.out != nil || cs.invOff >= p.lastTermOff {
			continue
		}
		if argsMap(cs.inv.Arguments) == nil && cs.inv.Status == "failed" {
			cs.emitted = true
			continue
		}
		p.emitCall(cs, cs.invOff, res)
	}
}

// emitCall builds the ToolEvent for a completed call.
func (p *parser) emitCall(cs *callState, anchor int64, res *adapter.ParseResult) {
	if cs.emitted {
		return
	}
	cs.emitted = true
	if cs.isPhantom || !p.emits(anchor) {
		return
	}
	inv := cs.inv
	m := argsMap(inv.Arguments)
	name := inv.ToolName
	te := p.base("tool:"+inv.ToolCallID, firstTime(cs.firstTS, parseTime(inv.Context.Timestamp)), mapVTCodeTool(name))
	te.Model = p.model(cs.turnID)
	te.MessageID = cs.turnID
	te.RawToolName = name
	te.Target = p.a.scrubber.String(toolTarget(name, inv.Arguments, m))
	te.RawToolInput = p.rawToolInput(name, inv.Arguments, m)
	if te.ActionType == models.ActionEditFile {
		te.ContentBytes = patchAddedBytes(patchText(inv.Arguments, m))
	}
	te.PrecedingReasoning = p.reasoningForCall(inv.ToolCallID)
	te.IsSidechain = p.isSidechain(&inv.Context)
	te.Success = inv.Status == "completed" && inv.Outcome != "error" && inv.Outcome != "cancelled"
	if out := cs.out; out != nil {
		if out.Status == "failed" || (out.ExitCode != nil && *out.ExitCode != 0) {
			te.Success = false
		}
		if out.Output != "" {
			te.ToolOutput = p.a.scrubber.String(contentcap.Cap(out.Output, contentcap.DefaultMaxBytes))
			if !te.Success {
				te.ErrorMessage = truncate(p.a.scrubber.String(out.Output), 500)
			}
		}
		if end := parseTime(out.Context.Timestamp); !end.IsZero() && !te.Timestamp.IsZero() && end.After(te.Timestamp) {
			te.DurationMs = end.Sub(te.Timestamp).Milliseconds()
		}
	}
	if !te.Success && te.ErrorMessage == "" {
		te.ErrorMessage = firstNonEmpty(inv.Outcome, inv.Status)
	}
	res.ToolEvents = append(res.ToolEvents, te)
}

// rawToolInput returns the stored tool input. An apply_patch call stores
// its bare `*** Begin Patch` envelope (the codex convention) rather than
// the `{"input": "..."}` JSON wrapper it arrives in (grounded live,
// `vtcode exec` 0.180.2), so internal/loc's Begin-Patch shape counts its
// lines; a wrapped or quoted patch would otherwise read as an
// unrecognized object or as whole-file plain content.
func (p *parser) rawToolInput(name string, raw json.RawMessage, m map[string]any) string {
	if mapVTCodeTool(name) == models.ActionEditFile {
		if patch := patchText(raw, m); strings.HasPrefix(strings.TrimSpace(patch), "*** Begin Patch") {
			return p.a.scrubber.String(patch)
		}
	}
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	return p.a.scrubber.RawJSON(raw)
}

// firstTime returns a unless it is zero, else b.
func firstTime(a, b time.Time) time.Time {
	if !a.IsZero() {
		return a
	}
	return b
}

// emitAssistant records a completed agent_message.
func (p *parser) emitAssistant(off int64, it *item, ts time.Time, res *adapter.ParseResult) {
	if strings.TrimSpace(it.Text) == "" || !p.emits(off) {
		return
	}
	scrubbed := p.a.scrubber.String(it.Text)
	te := p.base("assistant:"+firstNonEmpty(it.ID, hashID(it.Context.Timestamp+it.Text)), ts, models.ActionAssistantMessage)
	te.Model = p.model(it.Context.TurnID)
	te.MessageID = it.Context.TurnID
	te.Target = truncate(scrubbed, 200)
	te.RawToolName = models.ToolVTCode + ".assistant_text"
	te.ToolOutput = p.a.scrubber.String(contentcap.Cap(it.Text, contentcap.DefaultMaxBytes))
	te.PrecedingReasoning = p.reasoningForText(it.Text)
	te.IsSidechain = p.isSidechain(&it.Context)
	res.ToolEvents = append(res.ToolEvents, te)
}

// genTimingVersion is the gen-timing parser version (TokenEvent.GenTimingV).
const genTimingVersion = 1

// onTurnEnd handles a turn's terminal events. A turn can end with BOTH
// turn.failed and turn.blocked carrying the identical usage, so tokens are
// emitted once per turn (the first terminal event with non-zero usage),
// and a failed turn is recorded once as a turn_aborted row.
//
// Per-request data. The trajectory's `prompt_cache_metrics` records are
// the turn's individual requests. They feed:
//
//   - GenMs on the turn row (the sum of the requests' elapsed_ms, basis
//     native) — only when the requests sum EXACTLY to the turn's usage,
//     i.e. the trajectory provably saw every request;
//   - one implicit-cache observation per request (OpenAI-compatible
//     providers; keyed `<turn>#<n>` so a re-parse dedupes).
//
// The token COUNTS stay one row per turn, from events.jsonl. Splitting
// them into per-request rows would double-count: token_usage upserts are
// MAX-monotone on (source_file, source_event_id), the archive trigger
// re-parses the whole log, and the trajectory is rotated and pruned
// independently of the session — so a later parse could see fewer (or
// no) request records than an earlier one and would have to re-emit the
// turn total under a different id beside the per-request rows already
// stored.
func (p *parser) onTurnEnd(off int64, raw string, ev *eventBody, res *adapter.ParseResult) {
	p.lastTermOff = off
	ts := firstTime(parseTime(ev.CompletedAt), p.lastTS)
	turnKey := firstNonEmpty(p.curTurn, hashID(raw))

	if ev.Type == "turn.failed" && !p.failedDone[turnKey] {
		p.failedDone[turnKey] = true
		if p.emits(off) {
			msg := strings.TrimSpace(ev.Message)
			te := p.base("turn_failed:"+turnKey, ts, models.ActionTurnAborted)
			te.Target = msg
			te.RawToolName = models.ToolVTCode + ".turn_failed"
			te.Success = false
			te.ErrorMessage = truncate(p.a.scrubber.String(msg), 500)
			te.Model = p.model(p.curTurn)
			te.MessageID = p.curTurn
			res.ToolEvents = append(res.ToolEvents, te)
		}
	}

	u := ev.Usage
	if u.isZero() || p.tokensDone[turnKey] {
		return
	}
	p.tokensDone[turnKey] = true
	if !p.emits(off) {
		return
	}
	var reqs []trajRequest
	if t := p.turns[p.curTurn]; t != nil && p.curTurn != "" {
		reqs = t.requests
	}
	tok := models.TokenEvent{
		SourceFile:          p.path,
		SourceEventID:       "tok:" + turnKey,
		SessionID:           p.sessionID,
		ProjectRoot:         p.projectRoot,
		GitBranch:           p.gitBranch,
		GitRemote:           p.gitRemote,
		Timestamp:           ts,
		Tool:                models.ToolVTCode,
		Model:               p.model(p.curTurn),
		InputTokens:         u.netInput(),
		OutputTokens:        u.OutputTokens,
		CacheReadTokens:     u.CachedInputTokens,
		CacheCreationTokens: u.CacheCreationTokens,
		Source:              models.TokenSourceJSONL,
		Reliability:         models.ReliabilityApproximate,
		// One usage envelope per turn (the sum of the turn's requests), so
		// the turn id is both the message key and the turn key.
		MessageID: p.curTurn,
		TurnID:    p.curTurn,
	}
	if coversTurn(reqs, u) {
		if g := genMs(reqs); g > 0 {
			tok.GenMs, tok.GenBasis, tok.GenTimingV = g, models.GenBasisNative, genTimingVersion
		}
	}
	res.TokenEvents = append(res.TokenEvents, tok)
	p.emitCacheObservations(reqs, ts, res)
}

// emitCacheObservations turns a turn's trajectory requests into Tier-2
// implicit-cache observations. Only OpenAI-compatible providers qualify
// (implicit prefix caching, read count only); an Anthropic-direct or
// Anthropic-model request uses explicit cache_control, whose marker-aware
// path needs the block chain the trajectory does not carry, so it is
// skipped.
func (p *parser) emitCacheObservations(reqs []trajRequest, turnEnd time.Time, res *adapter.ParseResult) {
	for i, r := range reqs {
		if !implicitCacheProvider(r.provider, r.model) || r.input <= 0 {
			continue
		}
		id := fmt.Sprintf("cache:%s#%d", p.curTurn, i+1)
		net := r.input - r.cacheRead
		if net < 0 {
			net = 0
		}
		res.CacheObservations = append(res.CacheObservations, models.CacheTurnObservation{
			SourceFile:    p.path,
			SourceEventID: id,
			SessionID:     p.sessionID,
			MessageID:     fmt.Sprintf("%s#%d", p.curTurn, i+1),
			Timestamp:     firstTime(r.ts, turnEnd),
			Model:         firstNonEmpty(r.model, p.model(p.curTurn)),
			Usage: models.CacheUsage{
				NetInputTokens:      net,
				OutputTokens:        r.output,
				CacheReadTokens:     r.cacheRead,
				CacheCreationTokens: r.cacheWrite,
			},
			ImplicitCache: true,
		})
	}
}

// implicitCacheProvider reports whether a request went to an
// OpenAI-compatible provider with implicit prefix caching (OpenRouter,
// OpenAI, DeepSeek, ...) rather than to Anthropic's explicit cache.
func implicitCacheProvider(provider, model string) bool {
	pr := strings.ToLower(strings.TrimSpace(provider))
	mo := strings.ToLower(strings.TrimSpace(model))
	if pr == "" || pr == "anthropic" || strings.HasPrefix(mo, "anthropic/") || strings.HasPrefix(mo, "claude") {
		return false
	}
	return true
}
