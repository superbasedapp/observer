package cursor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter is the file-watcher implementation of the cursor adapter. It
// complements the hook-driven path (BuildEvent / BuildStopTokenEvent /
// BuildStopTranscriptEvents): when the live hook is not registered (or
// the host runs Cursor on a different OS than the observer — e.g.
// Cursor on Windows + observer in WSL — where the wsl.exe-launched hook
// either isn't installed or hasn't been wired yet), the watcher scans
// Cursor's on-disk transcripts under
// `<home>/.cursor/projects/<slug>/agent-transcripts/<conv>/<conv>.jsonl`
// and emits action rows derived from the assistant tool_use blocks +
// the opening user prompt of every turn.
//
// Coverage compared to the hook path:
//   - Activity (user prompts, every tool_use): covered.
//   - Token usage: transcripts have no usage fields. Headless CLI usage is
//     captured separately from its structured diagnostic logs; other surfaces
//     use stop / afterAgentResponse hooks.
//   - Real-time: lags by one assistant turn — Cursor flushes the JSONL
//     after the turn completes.
//
// Hook + watcher running in tandem produce two rows per turn (one from
// each path) sharing SessionID = conversation_id but with distinct
// MessageIDs (real generation_id vs the synthetic
// `transcript:<convID>:turn<N>` produced here). SourceFile distinguishes
// the rows: hook rows carry "cursor:hook"; watcher rows carry the real
// transcript file path.
// SessionHookChecker reports whether sessionID already has rows in
// the DB whose source_file is the cursor live-hook handler. The
// watcher consults this before emitting transcript-derived events
// for a session: if the live hook has already captured the session
// (which becomes true after the first beforeSubmitPrompt fires for
// the session), watcher emission would be pure duplication and is
// skipped. Returns (false, nil) on a missing/empty result.
type SessionHookChecker func(ctx context.Context, sessionID string) (bool, error)

type Adapter struct {
	scrubber  *scrub.Scrubber
	roots     []string
	hookCheck SessionHookChecker

	// rootRes carries the injectable filesystem seams used to turn a
	// projects/<slug>/ directory into a real, stat-able workspace
	// root. The zero value is valid — every seam falls back to the
	// real implementation (see projectRootResolver) so `&Adapter{}`
	// literals keep working.
	rootRes projectRootResolver
	// rootCache memoizes projects/<slug>/ dir → resolved workspace
	// root. ONLY exact (stat-confirmed) resolutions are cached:
	// caching a fallback would pin a wrong root forever if the
	// workspace directory appears later (mount comes up, repo is
	// cloned). Keyed on the slug dir, so two conversations under the
	// same workspace share one resolution.
	rootCache sync.Map
}

// New returns an Adapter with platform-default cross-mount roots.
// Mirrors antigravity.New(): on WSL2, every detected Windows-side
// $HOME-equivalent contributes a .cursor/projects root.
func New() *Adapter {
	return &Adapter{
		scrubber: scrub.New(),
		roots:    defaultRoots(),
	}
}

// NewWithOptions customises scrubber and roots for tests. Pass nil
// scrubber for the default; pass nil/empty roots for default
// platform discovery.
func NewWithOptions(s *scrub.Scrubber, roots ...string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{scrubber: s, roots: roots}
}

// WithSessionHookChecker injects the predicate the watcher uses to
// detect "this session already has live-hook rows; skip the
// transcript replay." A nil checker (the default) means always emit
// — appropriate for cold-start ingestion or environments without
// the live hook layer wired up. Returns the adapter for chaining.
func (a *Adapter) WithSessionHookChecker(check SessionHookChecker) *Adapter {
	a.hookCheck = check
	return a
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolCursor }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Matches Cursor agent
// transcripts: `.cursor/projects/<slug>/agent-transcripts/<conv>/<conv>.jsonl`.
// The double-uuid pattern (dir name == file basename) is what lets the
// matcher reject other JSONLs Cursor may grow under projects/ in
// future without enumerating an allowlist. Path separators are
// normalised to `/` so the matcher works against backslash-shaped
// strings even on Linux (where filepath.Base wouldn't split on `\`).
func (a *Adapter) IsSessionFile(path string) bool {
	if !matchesSessionShape(path) && !matchesStoreDBShape(path) && !matchesStateDBShape(path) && !matchesCLIUsageLog(path) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// matchesStoreDBShape returns true when path is a cursor-agent
// per-conversation blob store: `.cursor/chats/<workspace-hash>/<conv>/
// store.db`. Excludes the -wal / -shm sidecars (suffix is exactly
// `/store.db`). This is the system-prompt + prompt-budget source;
// watching it directly (rather than only reading it as a sibling of
// the transcript) means the rows are captured independent of
// transcript growth — the watcher's full-scan discovers existing
// store.db files as never-seen and backfills them, and new ones are
// picked up as they appear, on both WSL and Windows (/mnt/c) surfaces.
func matchesStoreDBShape(path string) bool {
	norm := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	return strings.HasSuffix(norm, "/store.db") &&
		strings.Contains(norm, "/.cursor/chats/")
}

// matchesSessionShape returns true when path looks like a Cursor agent
// transcript: `.cursor/projects/<slug>/agent-transcripts/<conv>/<conv>.jsonl`.
// Path-component string match, normalises backslashes so fixtures with
// foreign-OS separators still work on Linux CI.
func matchesSessionShape(path string) bool {
	norm := strings.ReplaceAll(path, `\`, "/")
	lower := strings.ToLower(norm)
	if !strings.HasSuffix(lower, ".jsonl") {
		return false
	}
	if !strings.Contains(lower, "/.cursor/projects/") {
		return false
	}
	if !strings.Contains(lower, "/agent-transcripts/") {
		return false
	}
	idx := strings.LastIndex(norm, "/")
	if idx < 0 {
		return false
	}
	base := norm[idx+1:]
	rest := norm[:idx]
	parentIdx := strings.LastIndex(rest, "/")
	if parentIdx < 0 {
		return false
	}
	parent := rest[parentIdx+1:]
	return base == parent+".jsonl"
}

// ParseSessionFile implements adapter.Adapter.
//
// Cursor transcript JSONL is small (one file per conversation; tens
// to low hundreds of lines in practice), so parseTranscriptTurns reads
// the whole file and the watcher relies on the (source_file,
// source_event_id) UNIQUE index for idempotency on re-scan rather
// than offset-based incremental parsing. NewOffset = file size at scan
// time, so the polling fallback only re-parses on file growth.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	// store.db blob stores carry the system prompt + prompt budget + native todos;
	// state.vscdb carries the global (cross-project, incl. empty-window)
	// conversation index; transcripts carry the per-turn activity.
	// Dispatch by shape — the same storeLayout key surfaceByLayout
	// (surface.go) maps to a capture surface, so the two never drift.
	layout := layoutFor(path)
	var (
		res adapter.ParseResult
		err error
	)
	switch layout {
	case layoutCLIUsage:
		res, err = a.parseCLIUsageLog(ctx, path, fromOffset)
	case layoutStoreDB:
		res, err = a.parseStoreDBFile(path, fromOffset)
	case layoutStateDB:
		res, err = a.parseStateDBFile(ctx, path, fromOffset)
	default:
		// layoutTranscript, plus layoutUnknown: a path the watcher
		// handed us that no matcher claims is parsed as a transcript
		// (the historical behaviour) and gets no surface stamp.
		res, err = a.parseTranscriptFile(ctx, path, fromOffset)
	}
	if err != nil {
		return adapter.ParseResult{}, err
	}
	stampSurfaces(&res, layout, sessionHintFor(layout, path))
	return res, nil
}

// parseTranscriptFile parses a Cursor agent-transcript JSONL
// (`.cursor/projects/<slug>/agent-transcripts/<conv>/<conv>.jsonl`)
// into per-turn activity rows. Split out of ParseSessionFile so the
// shape dispatch + surface stamping live in one place.
func (a *Adapter) parseTranscriptFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("cursor.parseTranscriptFile: stat: %w", err)
	}
	res := adapter.ParseResult{NewOffset: fi.Size()}
	if fi.Size() == 0 {
		return res, nil
	}
	if fromOffset == fi.Size() {
		return res, nil
	}

	turns, err := parseTranscriptTurns(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("cursor.parseTranscriptFile: parse: %w", err)
	}
	if len(turns) == 0 {
		return res, nil
	}

	convID := convIDFromPath(path)
	if convID == "" {
		res.Warnings = append(res.Warnings, fmt.Sprintf("cursor: cannot derive conversation_id from %s — skipping", path))
		return res, nil
	}
	slug := projectSlugFromPath(path)
	projectRoot := a.resolveProjectRoot(path)
	if projectRoot == "" {
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("cursor: cannot decode project slug %q for %s — emitting events with empty project_root", slug, path))
	}

	// Use file mtime as the per-turn timestamp. The transcript's
	// `<timestamp>` envelope on user lines is human-formatted and
	// fragile to parse; mtime is monotonic and good enough for
	// dashboard ordering.
	ts := fi.ModTime().UTC()

	// NOTE: the system prompt + prompt-budget rows are NOT emitted here.
	// They come from the sibling store.db, which the watcher now tracks
	// as its own session file (see parseStoreDBFile + matchesStoreDBShape).
	// Capturing them off the store.db rather than the transcript
	// decouples them from transcript growth — so already-parsed
	// sessions (transcript at EOF) still get the rows when the
	// watcher's full-scan discovers their never-seen store.db, and the
	// budget refreshes when the store.db grows.

	// Defer to the live hook when it's already captured this session.
	// The checker is set by the watcher constructor; nil means
	// "no hook layer running, emit unconditionally" (the cold-start
	// ingestion path). Note this only skips the per-turn ACTIVITY
	// rows below — the system prompt above is already appended because
	// the hook never captures it.
	if a.hookCheck != nil {
		hooked, err := a.hookCheck(ctx, convID)
		if err != nil {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("cursor: hook-check for %s failed (%v); falling back to watcher emission", convID, err))
		} else if hooked {
			return res, nil
		}
	}

	for i, turn := range turns {
		if ctx.Err() != nil {
			return adapter.ParseResult{}, ctx.Err()
		}
		// Synthetic generation_id, distinct from any real cursor
		// `generation_id` (which is a UUID). Stable across re-scans
		// because turn ordering in the JSONL is stable.
		genID := fmt.Sprintf("transcript:%s:turn%d", convID, i+1)
		// Watcher does NOT emit user_prompt rows: the live
		// beforeSubmitPrompt hook captures every user prompt with the
		// real generation_id, so a transcript-derived user_prompt
		// would be a pure duplicate (different MessageID, same
		// content, same SessionID). The hook fires synchronously when
		// the user submits, so coverage is reliable as long as the
		// hook is registered (which auto-register on `observer start`
		// guarantees). Cost: pre-install historical transcripts lose
		// user_prompt rows; the assistant tool_use rows that follow
		// still convey what the model did.
		toolEvs := buildTranscriptToolEvents(turn, convID, projectRoot, genID, path, ts, a.scrubber)
		res.ToolEvents = append(res.ToolEvents, toolEvs...)
	}
	return res, nil
}

// parseStoreDBFile handles a cursor-agent per-conversation blob store
// (`.cursor/chats/<ws-hash>/<conv>/store.db`). It emits the system-
// prompt content row, prompt-budget section rows, and successful native
// todo executions independently of the transcript. Native todo calls
// preserve vendor call IDs and completion timestamps. There is no
// session-wide hook-deferral gate for this authoritative store.
//
// NewOffset = file size so the poller only re-reads on store.db growth;
// the watcher's full-scan discovers never-seen store.db files (existing
// sessions) and parses them from offset 0, which is what backfills
// already-parsed conversations without a manual rescan.
func (a *Adapter) parseStoreDBFile(path string, fromOffset int64) (adapter.ParseResult, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("cursor.parseStoreDBFile: stat: %w", err)
	}
	res := adapter.ParseResult{NewOffset: fi.Size()}
	if fi.Size() == 0 || fromOffset == fi.Size() {
		return res, nil
	}
	convID := convIDFromStoreDBPath(path)
	if convID == "" {
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("cursor: cannot derive conversation_id from store.db %s", path))
		return res, nil
	}
	store, ok := scanStoreDB(path)
	if !ok {
		return res, nil
	}
	ts := fi.ModTime().UTC()
	// Project root: the store.db path (chats/<ws-hash>/) doesn't encode
	// the workspace, so resolve it from the sibling transcript's slug —
	// giving these rows the exact same project attribution as the
	// session's activity rows.
	projectRoot := a.projectRootForStoreDB(path, convID)
	res.ToolEvents = append(res.ToolEvents, a.todoEvents(store.Todos, convID, projectRoot, path)...)
	if store.SystemPrompt != "" {
		res.ToolEvents = append(res.ToolEvents,
			a.systemPromptEvent(store.SystemPrompt, convID, projectRoot, path, ts))
	}
	for _, sec := range store.Sections {
		if ev, ok := a.promptSectionEvent(sec, convID, projectRoot, path, ts); ok {
			res.ToolEvents = append(res.ToolEvents, ev)
		}
	}
	return res, nil
}

// convIDFromStoreDBPath extracts the conversation UUID from a store.db
// path `.cursor/chats/<ws-hash>/<conv>/store.db` — the parent directory
// name.
func convIDFromStoreDBPath(path string) string {
	return filepath.Base(filepath.Dir(path))
}

// projectRootForStoreDB resolves the workspace path for a store.db by
// finding the sibling agent-transcript for the same conversation (under
// .cursor/projects/<slug>/agent-transcripts/<conv>/) and resolving its
// slug through the same resolver the activity rows use, so the
// system-prompt / prompt-budget rows group under the same project.
// Returns "" when no sibling transcript exists (rare — the session row
// then keeps whatever project the hook/transcript already set).
func (a *Adapter) projectRootForStoreDB(storeDBPath, convID string) string {
	norm := strings.ReplaceAll(storeDBPath, `\`, "/")
	idx := strings.Index(strings.ToLower(norm), "/.cursor/")
	if idx < 0 {
		return ""
	}
	cursorRoot := norm[:idx+len("/.cursor")]
	matches, err := filepath.Glob(
		filepath.Join(cursorRoot, "projects", "*", "agent-transcripts", convID, convID+".jsonl"),
	)
	if err != nil || len(matches) == 0 {
		return ""
	}
	return a.resolveProjectRoot(matches[0])
}

// systemPromptEvent builds an ActionSystemPrompt row for the
// conversation's system prompt (extracted from the store.db blob
// store). Mirrors the codex systemPromptEvent shape: full scrubbed
// body in RawToolInput, a 200-char preview in Target, MessageID
// "system:<hash>" so the dashboard can group occurrences, and a
// content-hashed SourceEventID so re-scans dedup via the store's
// UNIQUE(source_file, source_event_id) index.
func (a *Adapter) systemPromptEvent(body, convID, projectRoot, sourceFile string, ts time.Time) models.ToolEvent {
	hash := shortHash(body)
	preview := body
	if len(preview) > 200 {
		preview = preview[:200]
	}
	// nil-safe scrub: NewWithOptions/New always set a scrubber, but the
	// &Adapter{} literal used in some tests doesn't — mirror the
	// nil-guard buildTranscriptToolEvents uses.
	scrubbed := func(s string) string {
		if a.scrubber == nil {
			return s
		}
		return a.scrubber.String(s)
	}
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: "cursor-sysprompt:" + convID + ":" + hash,
		SessionID:     convID,
		ProjectRoot:   projectRoot,
		Timestamp:     ts,
		Tool:          models.ToolCursor,
		ActionType:    models.ActionSystemPrompt,
		Target:        scrubbed(preview),
		Success:       true,
		RawToolName:   "system_prompt",
		RawToolInput:  scrubbed(body),
		MessageID:     "system:" + hash,
	}
}

// promptSectionEvent builds a zero-cost informational row for one
// cursor prompt-budget section (tools / rules / skills / subagents /
// …). cursor persists only the token+char count for these, not the
// content, so the row carries the counts in Target + a short
// explanatory body — no token_usage is emitted (the tokens are already
// billed inside each turn's input_tokens; a separate token row would
// double-count). Returns ok=false for sections already represented
// elsewhere (system_prompt has its own content row; conversation is the
// captured turns) and for empty sections.
//
// SourceEventID is keyed on the section name (stable, one per section
// per conversation) so re-scans dedup via the store's UNIQUE index;
// each section gets a distinct MessageID so it surfaces as its own row
// in the Messages table.
func (a *Adapter) promptSectionEvent(sec promptSection, convID, projectRoot, sourceFile string, ts time.Time) (models.ToolEvent, bool) {
	switch sec.Name {
	case "", "system_prompt", "conversation", "summarized_conversation":
		// system_prompt: own content row. conversation /
		// summarized_conversation: the actual (already-captured) turns.
		return models.ToolEvent{}, false
	}
	if sec.Tokens <= 0 && sec.Chars <= 0 {
		return models.ToolEvent{}, false
	}
	label := sec.DisplayName
	if label == "" {
		label = sec.Name
	}
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: "cursor-promptsection:" + convID + ":" + sec.Name,
		SessionID:     convID,
		ProjectRoot:   projectRoot,
		Timestamp:     ts,
		Tool:          models.ToolCursor,
		ActionType:    models.ActionPromptContext,
		Target:        fmt.Sprintf("%s — %d tokens, %d chars", label, sec.Tokens, sec.Chars),
		Success:       true,
		RawToolName:   "prompt_section." + sec.Name,
		RawToolInput: fmt.Sprintf(
			"Cursor prompt section %q (%s): %d tokens, %d chars.\n\nThese tokens are part of every turn's input but Cursor records only the budget — the section content is not persisted to disk. Shown to reconcile the per-turn input total.",
			sec.Name, label, sec.Tokens, sec.Chars,
		),
		MessageID: "promptsection:" + sec.Name + ":" + convID,
	}, true
}

// workspaceTrustedFile is the sibling marker Cursor writes into
// `.cursor/projects/<slug>/` the first time the user trusts a
// workspace. It is the ONLY artefact under projects/<slug>/ that
// carries the authoritative, un-slugified workspace path:
//
//	{"trustedAt":"2026-05-24T19:58:52.653Z",
//	 "workspacePath":"C:\\programsx\\superbased-observer"}
//
// The sibling repo.json carries ONLY an opaque `{"id":"<uuid>"}` with
// no path at all, so it is deliberately never consulted (verified
// against a live Cursor 3.14.27 install on both the Windows and the
// WSL side, 2026-08-07).
//
// It is present on trusted workspaces only — several live slug dirs
// have no `.workspace-trusted` — which is why the stat-gated
// candidate expansion below is still the workhorse and this file is
// an accuracy upgrade, not a replacement.
const workspaceTrustedFile = ".workspace-trusted"

// maxAmbiguousJoints bounds how many slug joints the candidate
// expansion is allowed to reinterpret as a literal `-`/`_` rather
// than a path separator. Every observed miss needs exactly one
// (`model-pricing` ← `model_pricing`, `superbased-observer`); two
// gives headroom for e.g. `my-repo/sub_dir` without the search
// becoming exponential (3^joints unbounded).
const maxAmbiguousJoints = 2

// maxRootCandidates hard-caps the number of paths the expansion will
// stat, independent of slug length. With maxAmbiguousJoints=2 a slug
// with j joints produces 1 + 2j + 2j(j-1) candidates, so this cap
// only bites past ~11 path components.
const maxRootCandidates = 256

// projectRootResolver bundles the filesystem seams used to turn a
// Cursor project slug into a real workspace root. House style: the
// I/O is injected so the decode logic is testable without touching
// the host filesystem. The zero value is valid — each accessor falls
// back to the real implementation — so `&Adapter{}` literals and
// tests that don't care keep working unchanged.
type projectRootResolver struct {
	stat      func(string) (os.FileInfo, error)
	readFile  func(string) ([]byte, error)
	translate func(string) string
}

func (r projectRootResolver) doStat(p string) (os.FileInfo, error) {
	if r.stat == nil {
		return os.Stat(p)
	}
	return r.stat(p)
}

func (r projectRootResolver) doReadFile(p string) ([]byte, error) {
	if r.readFile == nil {
		return os.ReadFile(p)
	}
	return r.readFile(p)
}

func (r projectRootResolver) doTranslate(p string) string {
	if p == "" {
		return ""
	}
	if r.translate == nil {
		return crossmount.TranslateForeignPath(p)
	}
	return r.translate(p)
}

// dirExists reports whether p names an existing directory through the
// injected stat seam.
func (r projectRootResolver) dirExists(p string) bool {
	if p == "" {
		return false
	}
	fi, err := r.doStat(p)
	return err == nil && fi.IsDir()
}

// withRootResolver overrides the filesystem seams used for project-root
// resolution. Test-only; production callers get the real filesystem via
// the zero value.
func (a *Adapter) withRootResolver(r projectRootResolver) *Adapter {
	a.rootRes = r
	a.rootCache = sync.Map{}
	return a
}

// resolveProjectRoot turns a transcript path
// (`…/.cursor/projects/<slug>/agent-transcripts/<conv>/<conv>.jsonl`)
// into the workspace root the events should be filed under.
//
// This is the watcher-path counterpart of the hook path's
// normalizeWorkspaceRoot (adapter.go): the returned root is ALWAYS
// routed through crossmount.TranslateForeignPath, so a Windows-side
// Cursor observed from a WSL daemon yields `/mnt/c/...` rather than a
// raw `C:\...` string that neither stats nor matches the shape every
// other observer path produces. Per
// docs/new-adapter-checklist.md §3.7 the translation + stat-gate must
// happen HERE, before the root reaches the store (and any downstream
// git resolution): an untranslated `C:\…` would be treated as a
// relative path and CWD-prefixed with the observer's own repo.
//
// Resolution order:
//  1. the slug dir's `.workspace-trusted` workspacePath, when it stats;
//  2. the first stat-able slug candidate (naive decode first, then the
//     hyphen/underscore re-joins — see projectRootCandidates);
//  3. the `.workspace-trusted` path even though it doesn't stat (it is
//     still exact, just not present on this host);
//  4. the naive decode, translated — i.e. pre-fix behaviour, so
//     off-host parses and fixtures are unchanged.
//
// Only outcomes 1 and 2 are memoized.
func (a *Adapter) resolveProjectRoot(transcriptPath string) string {
	slug := projectSlugFromPath(transcriptPath)
	if slug == "" {
		return ""
	}
	projectDir := projectDirFromPath(transcriptPath)
	if projectDir != "" {
		if cached, ok := a.rootCache.Load(projectDir); ok {
			return cached.(string)
		}
	}
	root, exact := a.rootRes.resolve(projectDir, slug)
	if exact && projectDir != "" {
		a.rootCache.Store(projectDir, root)
	}
	return root
}

// resolve implements the ordering documented on
// Adapter.resolveProjectRoot. exact reports whether the returned root
// was confirmed to exist on disk.
func (r projectRootResolver) resolve(projectDir, slug string) (root string, exact bool) {
	var authoritative string
	if projectDir != "" {
		if p := r.trustedWorkspacePath(projectDir); p != "" {
			authoritative = r.doTranslate(p)
			if r.dirExists(authoritative) {
				return authoritative, true
			}
		}
	}
	for _, cand := range projectRootCandidates(slug) {
		if translated := r.doTranslate(cand); r.dirExists(translated) {
			return translated, true
		}
	}
	if authoritative != "" {
		return authoritative, false
	}
	return r.doTranslate(DecodeProjectSlug(slug)), false
}

// trustedWorkspacePath reads `<projectDir>/.workspace-trusted` and
// returns its workspacePath field. Returns "" when the file is
// absent, unreadable, not JSON, or carries no path — every failure is
// a silent fall-through to the slug heuristic, never an error.
func (r projectRootResolver) trustedWorkspacePath(projectDir string) string {
	body, err := r.doReadFile(projectDir + "/" + workspaceTrustedFile)
	if err != nil || len(body) == 0 {
		return ""
	}
	var doc struct {
		WorkspacePath string `json:"workspacePath"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return ""
	}
	return strings.TrimSpace(doc.WorkspacePath)
}

// projectDirFromPath returns the `…/projects/<slug>` directory of a
// transcript path, forward-slash normalised (Go accepts `/` separators
// on every supported OS). Returns "" when the path isn't shaped like a
// Cursor transcript.
func projectDirFromPath(path string) string {
	norm := strings.ReplaceAll(path, `\`, "/")
	idx := strings.Index(norm, "/projects/")
	if idx < 0 {
		return ""
	}
	head := idx + len("/projects/")
	end := strings.Index(norm[head:], "/")
	if end < 0 {
		return ""
	}
	return norm[:head+end]
}

// projectRootCandidates returns the ordered set of workspace paths a
// Cursor project slug could have been produced from, most-likely
// first. The caller stat-gates them and takes the first that exists.
//
// Cursor's slug encoding collapses the path separator AND any literal
// `-`/`_` inside a component down to the same `-`, so
// `c-programsx-model-pricing` is a valid encoding of all of
// `C:\programsx\model\pricing`, `C:\programsx\model-pricing` and
// `C:\programsx\model_pricing` (the real directory is the last one).
// The naive all-separators decode is emitted first — when it stats,
// behaviour is exactly what it was before this expansion existed —
// followed by the re-joins, rightmost joint first (greedy longest
// trailing component, which is where repo names like
// `superbased-observer` and `model_pricing` actually sit), and `-`
// before `_` at each joint (the slug's own character wins ties).
//
// The search is bounded by maxAmbiguousJoints and maxRootCandidates;
// a Windows drive letter is never merged with the first component.
func projectRootCandidates(slug string) []string {
	if slug == "" {
		return nil
	}
	parts := strings.Split(slug, "-")
	prefix, sep := "/", "/"
	segs := parts
	if len(parts[0]) == 1 {
		prefix = strings.ToUpper(parts[0]) + `:\`
		sep = `\`
		segs = parts[1:]
	}
	if len(segs) == 0 {
		return []string{prefix}
	}
	naive := prefix + strings.Join(segs, sep)
	out := []string{naive}
	joints := len(segs) - 1
	if joints == 0 {
		return out
	}
	seen := map[string]bool{naive: true}
	for k := 1; k <= maxAmbiguousJoints && k <= joints && len(out) < maxRootCandidates; k++ {
		for _, combo := range jointCombinations(joints, k, maxRootCandidates) {
			for mask := 0; mask < 1<<k; mask++ {
				if len(out) >= maxRootCandidates {
					return out
				}
				cand := joinSegments(prefix, sep, segs, combo, mask)
				if !seen[cand] {
					seen[cand] = true
					out = append(out, cand)
				}
			}
		}
	}
	return out
}

// joinSegments renders one candidate: segs joined by sep, except at
// the joint indices in combo where a literal `-` (mask bit clear) or
// `_` (mask bit set) is emitted instead. Joint i sits between segs[i]
// and segs[i+1].
func joinSegments(prefix, sep string, segs []string, combo []int, mask int) string {
	merged := make(map[int]byte, len(combo))
	for j, idx := range combo {
		if mask&(1<<j) == 0 {
			merged[idx] = '-'
		} else {
			merged[idx] = '_'
		}
	}
	var b strings.Builder
	b.WriteString(prefix)
	b.WriteString(segs[0])
	for i := 1; i < len(segs); i++ {
		if c, ok := merged[i-1]; ok {
			b.WriteByte(c)
		} else {
			b.WriteString(sep)
		}
		b.WriteString(segs[i])
	}
	return b.String()
}

// jointCombinations enumerates every k-sized subset of the joint
// indices [0,n), highest index first so the rightmost (deepest) joints
// are probed before the leftmost ones. Generation stops once limit
// combinations have been produced, keeping a pathologically long slug
// from allocating a large combination set the caller would discard.
func jointCombinations(n, k, limit int) [][]int {
	if k <= 0 || k > n {
		return nil
	}
	out := make([][]int, 0, 8)
	cur := make([]int, 0, k)
	var rec func(hi int)
	rec = func(hi int) {
		if len(out) >= limit {
			return
		}
		if len(cur) == k {
			out = append(out, append([]int(nil), cur...))
			return
		}
		need := k - len(cur)
		for i := hi; i >= need-1; i-- {
			if len(out) >= limit {
				return
			}
			cur = append(cur, i)
			rec(i - 1)
			cur = cur[:len(cur)-1]
		}
	}
	rec(n - 1)
	return out
}

// DecodeProjectSlug reverses Cursor's projects/<slug>/ encoding into
// a workspace path string. Cursor encodes a Windows-style path like
// `C:\programsx\marmutmain` as `c-programsx-marmutmain`: drive letter
// (lowercase) + `-` + each path component joined by `-`. Linux/macOS
// paths get encoded without a leading drive letter, e.g.
// `/home/user/repo` → `home-user-repo`.
//
// The encoding is LOSSY: Cursor collapses the path separator and any
// literal `-`/`_` inside a component onto the same `-`, so this
// function ALWAYS reads every `-` as a separator. It is the pure,
// filesystem-free, worst-case decode — the naive candidate. Callers
// that want the real workspace root should use
// Adapter.resolveProjectRoot, which consults `.workspace-trusted`,
// stat-gates the projectRootCandidates expansion, and translates
// foreign-OS paths; this function stays as the never-fails fallback
// (and as the first candidate that expansion tries). It performs NO
// path translation: a Windows slug decodes to a raw `C:\…` string.
//
// Returns "" for an empty slug.
//
// Heuristic for Windows-vs-POSIX:
//   - First segment exactly 1 char → treat as Windows drive letter,
//     emit `<DRIVE>:\` joined by `\`.
//   - First segment 2+ chars → treat as POSIX, emit `/` joined by `/`.
func DecodeProjectSlug(slug string) string {
	if slug == "" {
		return ""
	}
	parts := strings.Split(slug, "-")
	if len(parts[0]) == 1 {
		drive := strings.ToUpper(parts[0])
		if len(parts) == 1 {
			return drive + `:\`
		}
		return drive + `:\` + strings.Join(parts[1:], `\`)
	}
	return "/" + strings.Join(parts, "/")
}

// convIDFromPath extracts the conversation UUID from a transcript
// path of shape `.../agent-transcripts/<conv>/<conv>.jsonl`. Returns
// "" when the shape doesn't match.
func convIDFromPath(path string) string {
	base := filepath.Base(path)
	if !strings.HasSuffix(base, ".jsonl") {
		return ""
	}
	conv := strings.TrimSuffix(base, ".jsonl")
	// Cross-check with the parent dir name; if they don't match, the
	// path isn't shaped the way IsSessionFile asserted.
	if filepath.Base(filepath.Dir(path)) != conv {
		return ""
	}
	return conv
}

// projectSlugFromPath extracts the projects/<slug>/ component from a
// transcript path. Returns "" when not found.
func projectSlugFromPath(path string) string {
	norm := strings.ReplaceAll(path, `\`, "/")
	idx := strings.Index(norm, "/projects/")
	if idx < 0 {
		return ""
	}
	rest := norm[idx+len("/projects/"):]
	end := strings.Index(rest, "/")
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// defaultRoots returns `<home>/.cursor/projects` under every cross-mount
// resolved $HOME. On WSL2 with Cursor running on Windows, this lights
// up `/mnt/c/Users/<u>/.cursor/projects` automatically.
func defaultRoots() []string {
	var roots []string
	homes := crossmount.AllHomes()
	for _, h := range homes {
		// projects/ → agent-transcripts (activity); chats/ → store.db
		// blob stores (system prompt + prompt budget). Both watched so
		// existing store.db files are discovered by the full-scan and
		// backfilled, on WSL and Windows (/mnt/c) alike.
		roots = append(roots, filepath.Join(h.Path, ".cursor", "projects"))
		roots = append(roots, filepath.Join(h.Path, ".cursor", "chats"))
		// globalStorage/state.vscdb → the ONLY on-disk record of an
		// empty-window / no-folder conversation (no projects/ or
		// chats/ entry exists for those at all). See statedb.go.
		//
		// The root is the FILE, not its globalStorage parent: other
		// adapters (cline, roo-code, kilo-code, copilot) legitimately
		// watch `<Cursor>/User/globalStorage/<ext>/...` for the same
		// extensions installed inside the Cursor host (vscodehost), and
		// the watcher's root-based dispatch requires cross-adapter roots
		// to be pairwise non-prefix. A file root is a first-class shape
		// (aider watches transcript files the same way): the scan walk
		// visits it directly and fsnotify watches the file itself; the
		// -wal/-shm sidecars are read through SQLite, never as triggers.
		if dir := cursorGlobalStorageDir(h); dir != "" {
			roots = append(roots, filepath.Join(dir, "state.vscdb"))
		}
	}
	return append(roots, cliUsageRoots(homes)...)
}
