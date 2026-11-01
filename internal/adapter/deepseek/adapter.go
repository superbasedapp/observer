package deepseek

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// sessionLogName is the original (unversioned) basename of a DeepSeek
// Harness session log. The session UUID lives in the enclosing DIRECTORY,
// not the filename (.../sessions/<cwd-slug>/session-<uuid>/session.jsonl.zstd).
// Newer Harness builds write a VERSIONED basename instead
// (session.v4.jsonl.zstd, observed live 2026-10-26, FU-93) with the same
// header keys and record types; sessionLogRank accepts both.
const sessionLogName = "session.jsonl.zstd"

// sessionLogForms is the closed table of accepted session-log basenames,
// walked top-down by sessionLogRank. Each row is a prefix and suffix; an
// unversioned row matches prefix+suffix exactly, a versioned row requires
// one or more decimal digits between them. Compared lower-cased.
var sessionLogForms = []struct {
	prefix, suffix string
	versioned      bool
}{
	{prefix: "session", suffix: ".jsonl.zstd", versioned: false},
	{prefix: "session.v", suffix: ".jsonl.zstd", versioned: true},
}

// maxVersionDigits caps the version number so a hostile or corrupt name
// cannot overflow strconv.Atoi.
const maxVersionDigits = 6

// unversionedRank is the rank of the original session.jsonl.zstd: lower
// than any explicit version, so session.v0.jsonl.zstd still beats it.
const unversionedRank = -1

// sessionLogRank reports whether base (a bare filename) is a DeepSeek
// session log and, if so, its version rank: unversionedRank for
// session.jsonl.zstd, N for session.v<N>.jsonl.zstd.
func sessionLogRank(base string) (int, bool) {
	lower := strings.ToLower(base)
	for _, f := range sessionLogForms {
		if !f.versioned {
			if lower == f.prefix+f.suffix {
				return unversionedRank, true
			}
			continue
		}
		if len(lower) <= len(f.prefix)+len(f.suffix) ||
			!strings.HasPrefix(lower, f.prefix) || !strings.HasSuffix(lower, f.suffix) {
			continue
		}
		digits := lower[len(f.prefix) : len(lower)-len(f.suffix)]
		if len(digits) > maxVersionDigits || strings.Trim(digits, "0123456789") != "" {
			continue
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			continue
		}
		return n, true
	}
	return 0, false
}

// supersedingSibling returns the basename of a session log in the same
// directory as path that has a STRICTLY higher version rank, or "" when
// path is the highest-versioned log there.
//
// The rule: one session directory is one session, so when an upgraded
// Harness leaves more than one log beside each other (for example the old
// session.jsonl.zstd next to a new session.v4.jsonl.zstd), only the
// highest version is parsed and every lower one yields no events. Rows
// dedup on (source_file, source_event_id), so parsing both files would
// store the same session twice under two source files. A directory read
// error is treated as "no sibling" so a transient failure never drops
// the file being parsed.
func supersedingSibling(path string) string {
	own, ok := sessionLogRank(filepath.Base(path))
	if !ok {
		return ""
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return ""
	}
	best, bestRank := "", own
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if r, ok := sessionLogRank(e.Name()); ok && r > bestRank {
			best, bestRank = e.Name(), r
		}
	}
	return best
}

// Adapter parses DeepSeek Harness session logs under
// ~/.dsh/sessions/<cwd-slug>/session-<uuid>/session[.v<N>].jsonl.zstd. See
// the package doc for the record shapes, the whole-file-rewrite storage
// semantics, and the off-limits file list.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and platform-default
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
func (*Adapter) Name() string { return models.ToolDeepSeek }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// defaultRoots returns every plausible DeepSeek Harness session tree.
// DeepSeek Harness is NOT XDG-shaped — the storage path is fixed to
// ~/.dsh on every platform it ships for, identical on WSL2 (~/.dsh) and
// native Windows (seen from WSL at /mnt/c/Users/<user>/.dsh). One join
// per crossmount.AllHomes() entry covers a WSL2 observer reading its own
// home AND any foreign Windows home in one pass — the same pattern
// internal/adapter/muse uses. Windows-side sessions are backfill-only
// (see the package doc): DrvFs inotify never fires for them, so listing
// the root here only helps `observer backfill`, not live capture.
func defaultRoots() []string {
	seen := map[string]bool{}
	var roots []string
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" || seen[h.Path] {
			continue
		}
		seen[h.Path] = true
		roots = append(roots, filepath.Join(h.Path, ".dsh", "sessions"))
	}
	return roots
}

// IsSessionFile implements adapter.Adapter. A path qualifies only when it
// is BOTH under one of this adapter's watch roots AND has the DeepSeek
// session-log shape. The sibling `.credentials.yaml` and `settings.yaml`
// files are rejected by the basename test alone, before the watch-root
// check ever runs.
func (a *Adapter) IsSessionFile(path string) bool {
	if !matchesShape(path) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// matchesShape reports whether path has the DeepSeek session-log shape,
// independent of watch roots. Comparison is on a slash-normalized,
// lower-cased copy so Windows separators and case-insensitive mounts
// match too.
func matchesShape(path string) bool {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	if _, ok := sessionLogRank(filepath.Base(lower)); !ok {
		return false
	}
	return strings.Contains(lower, "/.dsh/sessions/")
}

// maxDecodedBytes caps one session file's zstd-decoded size (the zstd
// default is 64 GiB, so a small file could exhaust memory). The zed
// adapter caps one thread blob the same way.
const maxDecodedBytes = 512 << 20

// ParseSessionFile implements adapter.Adapter.
//
// Unlike every append-only JSONL adapter in this codebase, DeepSeek
// Harness REWRITES session.jsonl.zstd WHOLE on every flush (a full
// recompress, not an append) — see the package doc. There is therefore
// no meaningful byte offset to resume from; ParseSessionFile follows the
// same whole-file-rescan contract internal/adapter/cursor uses for its
// store.db shape: NewOffset carries the file's current size purely as a
// change-detection watermark (an unchanged fromOffset==fi.Size() short-
// circuits with no work), and every changed poll re-decodes and
// re-parses the ENTIRE file from the top. A log that a higher-versioned
// sibling supersedes (see supersedingSibling) yields no events. Deterministic SourceEventIDs
// (built from each line's own `seq`, exactly mirroring muse's eventKey
// pattern) let the store's (source_file, source_event_id) UNIQUE index
// dedup the re-emitted rows — the correctness contract lives there, not
// in the offset value.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("deepseek.ParseSessionFile: stat %s: %w", path, err)
	}
	res := adapter.ParseResult{NewOffset: fi.Size()}
	if fi.Size() == 0 || fromOffset == fi.Size() {
		return res, nil
	}
	if sib := supersedingSibling(path); sib != "" {
		res.Warnings = append(res.Warnings, fmt.Sprintf("skipped: superseded by %s in the same session directory", sib))
		return res, nil
	}

	compressed, err := os.ReadFile(path) //nolint:gosec // path comes from the watcher's own watch roots
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("deepseek.ParseSessionFile: read %s: %w", path, err)
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(maxDecodedBytes))
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("deepseek.ParseSessionFile: new zstd reader: %w", err)
	}
	defer dec.Close()
	plain, err := dec.DecodeAll(compressed, nil)
	if errors.Is(err, zstd.ErrDecoderSizeExceeded) {
		// Over the cap: skipped until the file changes, never retried
		// every tick (RB1 sweep finding A3, a decompression bomb).
		res.Warnings = append(res.Warnings, fmt.Sprintf("skipped: the session decodes to more than %d bytes", int64(maxDecodedBytes)))
		return res, nil
	}
	if err != nil {
		// A session actively being flushed can be read mid-write; treat a
		// decode failure as transient rather than fatal, and ask the
		// watcher to retry on the next poll tick instead of dropping the
		// file.
		res.Warnings = append(res.Warnings, fmt.Sprintf("zstd decode failed (retrying): %v", err))
		res.RetrySuggested = true
		res.NewOffset = fromOffset
		return res, nil
	}

	if ctx.Err() != nil {
		return res, ctx.Err()
	}

	st := &parseState{
		adapter:     a,
		path:        path,
		rootCache:   map[string]string{},
		toolIdx:     map[string]int{},
		unknownTool: map[string]bool{},
		cacheAcc:    cacheobs.New(MaxBlocksPerSession),
	}

	scanner := bufio.NewScanner(bytes.NewReader(plain))
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	lineNum := 0
	for scanner.Scan() {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		lineNum++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		if lineNum == 1 && isHeader(raw) {
			var h sessionHeader
			if err := json.Unmarshal(raw, &h); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed header: %v", lineNum, err))
				continue
			}
			st.sessionID = h.ID
			st.cwd = h.Cwd
			continue
		}
		var env rawEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
			continue
		}
		st.handle(&env, &res)
	}
	if err := scanner.Err(); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("scan error: %v", err))
	}
	return res, nil
}

// parseState carries the per-call mutable bookkeeping the record handler
// needs across lines of one parse.
type parseState struct {
	adapter *Adapter
	path    string
	// rootCache memoizes cwd → resolved project root (git.Resolve walks
	// the filesystem, and one session log shares one workspace root
	// throughout).
	rootCache map[string]string
	// toolIdx maps a tool call_id to its ToolEvent's index in
	// res.ToolEvents, so the later tool/result record can stamp its
	// output onto it.
	toolIdx map[string]int
	// unknownTool dedupes the "unrecognised tool name" warning so a long
	// session with many calls to one unmapped tool warns once.
	unknownTool map[string]bool
	// sessionID is the canonical session uuid, taken from the header
	// line's own `id` (§4.5a).
	sessionID string
	// cwd is the raw absolute workspace root stated by the header.
	cwd string
	// branch is the git branch, resolved alongside the project root.
	branch string
	// remote is the normalized git remote, resolved alongside the
	// project root (see projectRoot).
	remote string
	// identity is the Project Identity Resolver v2 bundle (2026-09-06,
	// §3.1 / W1) resolved alongside branch/remote, stamped onto every
	// ToolEvent by base() and onto the TokenEvent literal below.
	identity git.Identity
	// model is the most recent model id seen (from assistant/message),
	// used to stamp tool events that carry no model of their own.
	model string
	// cacheAcc accumulates the session's running Tier-2 content-block
	// delta for cachetrack observation, drained on every assistant/
	// message's usage (see emitTokens). One accumulator per parse call
	// mirrors the whole-file-rescan contract: every changed poll
	// re-derives the same deterministic observations from the top.
	cacheAcc *cacheobs.Accumulator
}

// handle dispatches one decoded envelope onto the appropriate emit path.
// Every event type not named here is streaming/ephemeral noise or
// session/config informational and is skipped silently — see the
// package doc for the full inventory.
func (st *parseState) handle(env *rawEnvelope, res *adapter.ParseResult) {
	switch env.Type {
	case evUserMessage:
		st.emitUserMessage(env, res)
	case evAssistantMessage:
		st.emitAssistantMessage(env, res)
	case evToolResult:
		st.applyToolResult(env, res)
	case evTurnEnd:
		st.emitTurnEnd(env, res)
	}
}

// projectRoot resolves the header workspace root and memoizes the
// result.
//
// The translation is UNCONDITIONAL: crossmount.TranslateForeignPath maps
// a foreign-OS root to its locally-visible equivalent, so a foreign path
// never reaches git.Resolve — where filepath.Abs would treat it as
// relative and CWD-prefix the observer's OWN .git onto every event.
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
		// id.Remote is already NormalizeRemote'd by ResolveIdentity.
		st.remote = id.Remote
		st.identity = id
	}
	return id.Root
}

// base builds the fields every emitted ToolEvent shares.
func (st *parseState) base(env *rawEnvelope) models.ToolEvent {
	return models.ToolEvent{
		SourceFile:         st.path,
		SessionID:          st.sessionID,
		ProjectRoot:        st.projectRoot(),
		Timestamp:          parseTimestamp(env.Time),
		GitBranch:          st.branch,
		GitRemote:          st.remote,
		GitUpstreamRemote:  st.identity.UpstreamRemote,
		GitRemoteOwner:     st.identity.RemoteOwner,
		GitUpstreamOwner:   st.identity.UpstreamOwner,
		RootCommitSHA:      st.identity.RootCommitSHA,
		ContentFingerprint: st.identity.ContentFingerprint,
		Workspace:          st.identity.Workspace,
		IsWorktree:         st.identity.IsWorktree,
		Tool:               models.ToolDeepSeek,
		Success:            true,
	}
}

// emitUserMessage records a genuine user-authored prompt — ONLY when
// data.source.kind=="user". Every other source.kind (observed: "plugin")
// is harness-injected context riding the identical envelope shape and is
// skipped; see the package doc for why this filter is load-bearing.
func (st *parseState) emitUserMessage(env *rawEnvelope, res *adapter.ParseResult) {
	var d userMessageData
	if err := json.Unmarshal(env.Data, &d); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("seq %d: malformed user/message data: %v", env.Seq, err))
		return
	}
	if d.Source.Kind != sourceKindUser {
		return
	}
	st.cacheAcc.ObserveBlocks(accumulateCacheBlocks(d.Content, d.Role))
	text := joinText(d.Content)
	if strings.TrimSpace(text) == "" {
		return
	}
	scrubbed := st.adapter.scrubber.String(text)
	ev := st.base(env)
	ev.SourceEventID = "prompt:" + strconv.FormatInt(env.Seq, 10)
	ev.ActionType = models.ActionUserPrompt
	ev.RawToolName = models.ToolDeepSeek + ".user_prompt"
	ev.Target = truncate(scrubbed, 200)
	ev.RawToolInput = scrubbed
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitAssistantMessage records the assistant's visible reply, every
// tool-call block it carries, and (when data.usage is present) the
// TokenEvent for the model call that produced it.
func (st *parseState) emitAssistantMessage(env *rawEnvelope, res *adapter.ParseResult) {
	var d assistantMessageData
	if err := json.Unmarshal(env.Data, &d); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("seq %d: malformed assistant/message data: %v", env.Seq, err))
		return
	}
	if d.Message.Source.Model != "" {
		st.model = d.Message.Source.Model
	}

	st.cacheAcc.ObserveBlocks(accumulateCacheBlocks(d.Message.Content, d.Message.Role))

	text := joinText(d.Message.Content)
	if strings.TrimSpace(text) != "" {
		scrubbed := st.adapter.scrubber.String(text)
		ev := st.base(env)
		ev.SourceEventID = "assistant:" + strconv.FormatInt(env.Seq, 10)
		ev.ActionType = models.ActionAssistantMessage
		ev.RawToolName = models.ToolDeepSeek + ".assistant_message"
		ev.Model = st.model
		ev.MessageID = d.Message.ID
		ev.Target = truncate(scrubbed, 200)
		ev.ToolOutput = st.adapter.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes))
		res.ToolEvents = append(res.ToolEvents, ev)
	}

	for pos, block := range d.Message.Content {
		if block.Type != "tool-call" {
			continue
		}
		st.emitToolCall(env, block, pos, res)
	}

	st.emitTokens(env, d.Usage, res)
}

// emitToolCall records one tool-call block from an assistant/message.
func (st *parseState) emitToolCall(env *rawEnvelope, block contentBlock, pos int, res *adapter.ParseResult) {
	action, recognised := mapToolName(block.Name)
	if !recognised && !st.unknownTool[block.Name] {
		st.unknownTool[block.Name] = true
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("unrecognised tool name %q normalized to %q", block.Name, action))
	}
	args := decodeArgs(block.Arguments)
	ev := st.base(env)
	key := block.ID
	if key == "" {
		key = strconv.FormatInt(env.Seq, 10) + ":" + strconv.Itoa(pos)
	}
	ev.SourceEventID = "tool:" + key
	ev.ActionType = action
	ev.RawToolName = block.Name
	ev.Model = st.model
	ev.Target = st.adapter.scrubber.String(targetFromArgs(args, block.Name))
	ev.RawToolInput = st.adapter.scrubber.String(contentcap.Cap(block.Arguments, contentcap.DefaultMaxBytes))
	ev.ContentBytes = authoredBytes(action, args)
	idx := len(res.ToolEvents)
	res.ToolEvents = append(res.ToolEvents, ev)
	if block.ID != "" {
		st.toolIdx[block.ID] = idx
	}
}

// applyToolResult stamps each tool-result block's output onto the
// ToolEvent its call produced. A result whose call landed in an earlier
// parse chunk has no index and is skipped — the tool event itself was
// already persisted (or is being re-emitted this same pass, in which
// case the earlier emitToolCall in THIS pass already set toolIdx).
func (st *parseState) applyToolResult(env *rawEnvelope, res *adapter.ParseResult) {
	var d toolResultData
	if err := json.Unmarshal(env.Data, &d); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("seq %d: malformed tool/result data: %v", env.Seq, err))
		return
	}
	st.cacheAcc.ObserveBlocks(accumulateCacheBlocks(d.Message.Content, "tool"))
	for _, block := range d.Message.Content {
		if block.Type != "tool-result" || block.ToolCallID == "" {
			continue
		}
		idx, ok := st.toolIdx[block.ToolCallID]
		if !ok || idx >= len(res.ToolEvents) {
			continue
		}
		text := toolResultText(block)
		if strings.TrimSpace(text) == "" {
			continue
		}
		scrubbed := st.adapter.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes))
		ev := &res.ToolEvents[idx]
		ev.ToolOutput = scrubbed
		if block.IsError {
			ev.Success = false
			ev.ErrorMessage = truncate(scrubbed, 500)
		}
	}
}

// emitTurnEnd records an ABORTED turn. A "completed" reason is the normal
// path and produces nothing — the assistant message and token row
// already describe it.
func (st *parseState) emitTurnEnd(env *rawEnvelope, res *adapter.ParseResult) {
	var d turnEndData
	if err := json.Unmarshal(env.Data, &d); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("seq %d: malformed turn/end data: %v", env.Seq, err))
		return
	}
	if d.Reason.Kind == "" || d.Reason.Kind == turnEndCompleted {
		return
	}
	ev := st.base(env)
	ev.SourceEventID = "abort:" + strconv.FormatInt(env.Seq, 10)
	ev.ActionType = models.ActionTurnAborted
	ev.RawToolName = models.ToolDeepSeek + ".turn_" + d.Reason.Kind
	ev.Model = st.model
	ev.Target = d.Reason.Kind
	ev.Success = false
	res.ToolEvents = append(res.ToolEvents, ev)
}

// emitTokens turns an assistant/message's usage sibling into a
// TokenEvent. Direct field mapping, NO netting subtraction — see the
// package doc for the proof that inputTokens is already net of
// cacheReadTokens. An absent or all-zero usage envelope emits nothing.
func (st *parseState) emitTokens(env *rawEnvelope, u *assistantUsage, res *adapter.ParseResult) {
	if u.isZero() {
		return
	}
	res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
		SourceFile:         st.path,
		SourceEventID:      "tok:" + strconv.FormatInt(env.Seq, 10),
		SessionID:          st.sessionID,
		ProjectRoot:        st.projectRoot(),
		GitBranch:          st.branch,
		GitRemote:          st.remote,
		GitUpstreamRemote:  st.identity.UpstreamRemote,
		GitRemoteOwner:     st.identity.RemoteOwner,
		GitUpstreamOwner:   st.identity.UpstreamOwner,
		RootCommitSHA:      st.identity.RootCommitSHA,
		ContentFingerprint: st.identity.ContentFingerprint,
		Workspace:          st.identity.Workspace,
		IsWorktree:         st.identity.IsWorktree,
		Timestamp:          parseTimestamp(env.Time),
		Tool:               models.ToolDeepSeek,
		Model:              st.model,
		InputTokens:        u.InputTokens,
		OutputTokens:       u.OutputTokens,
		CacheReadTokens:    u.CacheReadTokens,
		// No EstimatedCostUSD: the cost engine resolves this from the
		// model string against internal/intelligence/cost's existing
		// deepseek/deepseek-v4-* OpenRouter-slug pricing entries.
		Source:      models.TokenSourceJSONL,
		Reliability: models.ReliabilityApproximate,
	})

	messageID := "tok:" + strconv.FormatInt(env.Seq, 10)
	if obs := emitCacheObservation(st.cacheAcc, st.path, st.sessionID, messageID, st.model, parseTimestamp(env.Time), u); obs != nil {
		res.CacheObservations = append(res.CacheObservations, *obs)
	}
}

// joinText concatenates every text-shaped block's text, in order.
func joinText(blocks []contentBlock) string {
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && strings.TrimSpace(b.Text) != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// compile-time interface check.
var _ adapter.Adapter = (*Adapter)(nil)
