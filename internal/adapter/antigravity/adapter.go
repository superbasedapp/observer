package antigravity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/oscrypt"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter parses Antigravity conversation files.
type Adapter struct {
	name     string
	scrubber *scrub.Scrubber
	roots    []string

	// NetworkRecovery selects the fallback when local decryption
	// fails. "" / "off" = pure-local; "local" = call running
	// language_server gRPC API. See AntigravityConfig docs.
	networkRecovery string

	// dumpShapeMismatchesDir, when non-empty, enables the Issue #5
	// follow-up debug dump: every GetCascadeTrajectory response that
	// is non-trivial (≥ 10 KiB) but extracts to zero tokens AND
	// empty model writes its raw bytes to <dir>/<conversation_id>.bin
	// so the operator can capture the wire shape for proto-path
	// investigation. Set via WithShapeMismatchDumpDir from the
	// [observer.antigravity] dump_shape_mismatches_dir config.
	dumpShapeMismatchesDir string

	// Process-wide secret cache. Decryption is expensive; the
	// underlying OSCrypt key doesn't change at runtime. Populated
	// lazily on first ParseSessionFile and zeroed on observer
	// shutdown via sync.Once-style behavior in Close (future).
	secretMu  sync.Mutex
	secret    oscrypt.Secret
	secretErr error

	// Index reader cache: keyed by absolute state.vscdb path.
	indexMu    sync.Mutex
	indexCache map[string]*indexCacheEntry

	// Cached language-server discovery — refreshed at most once
	// per scan via lsCacheValidUntil.
	lsMu              sync.Mutex
	lsCache           []LanguageServer
	lsCacheValidUntil int64 // unix nanos

	// Cached workspace_id → path resolution. The reverse-encoding walk
	// is depth-4 BFS over crossmount.AllHomes() — cheap once but not
	// per-conversation. Cache hits AND misses (an empty-string entry
	// is a recorded miss).
	wsResolveMu    sync.Mutex
	wsResolveCache map[string]string

	// Cached working endpoint per language_server. The Endpoints()
	// iteration tries up to 6 URLs (PreferredEndpoint + 2-3 ports * 2
	// protocols, deduped); the heuristic-derived first candidate is
	// often wrong (for one verified host, the heuristic-HTTP port was
	// actually TLS, costing a full ~5s timeout per conversation
	// before fall-through). Cache key is PID:CSRFToken — distinct
	// CSRF means a different language_server generation (process
	// restart), so stale cache entries naturally expire when a new
	// server replaces the old. Value is the URL that succeeded most
	// recently.
	endpointMu    sync.Mutex
	endpointCache map[string]string

	// Per-conversation bridge endpoint cache. Keyed by conversation
	// UUID; value is the (windows-side endpoint URL, csrf token) pair
	// that last successfully served this conversation. On WSL2, each
	// bridge invocation otherwise cold-starts powershell.exe + queries
	// WMI for ~17 candidate processes + serially fans out across each
	// server's endpoints (5s timeout per failed attempt). With
	// pollCursors firing every 2s on an actively-written conversation
	// .pb file, that 5-60s-per-file cost repeats indefinitely — the
	// "couple of minutes" capture latency the operator reported
	// 2026-05-24.
	//
	// On cache hit the adapter passes --endpoint+--csrf to the bridge,
	// which skips discover() entirely and POSTs directly to the known
	// server (~200-500ms). On cached-call failure the entry is
	// invalidated and the call retried without the pin (full
	// discovery). New entries are populated from the bridge's stderr
	// `bridge-endpoint=...` hint emitted on every successful call,
	// covering both cache-miss-cold-start and cache-hit paths
	// uniformly.
	convEndpointMu    sync.Mutex
	convEndpointCache map[string]bridgePin

	// Phase 3 originating-server cache: scanned cli-*.log files map
	// each conv UUID to the agy.exe PID + ports that hosted it. The
	// bridge then pins its first attempt to that endpoint, skipping
	// the PowerShell fan-out across every running language_server.
	// Keyed by absolute log-dir path; entries invalidate on
	// cliLogFreshnessUnix bump (matches the metadata_cli index cache
	// pattern). See log_scan.go::lookupOriginatingServer.
	origServerMu    sync.Mutex
	origServerCache map[string]*originatingServerCacheEntry

	// Persistent unrecoverable-file tracker. Injected by the caller
	// (cmd/observer/main.go wires a shim around store.Store's
	// LookupUnrecoverable / MarkUnrecoverable / ClearUnrecoverable
	// methods that scope all calls to adapter="antigravity"). nil =
	// no persistence; the adapter behaves as if the cache is always
	// a miss. Per CLAUDE.md, the adapter package doesn't depend on
	// store directly — the interface lets the dependency point the
	// right way.
	//
	// Lets the `observer backfill --all` CLI (operator's primary
	// case from the 2026-05-19 handover) short-circuit files that
	// already failed every recovery path on a prior run, instead
	// of re-attempting the ~30s-per-file decrypt+gRPC dance every
	// invocation. (Issue #4 follow-up; supersedes the v1.6.11 first-
	// pass in-memory cache, which only helped the long-running
	// daemon.)
	unrecoverableTracker UnrecoverableTracker

	// Persistent dedup-coverage reader for the plaintext-transcript
	// augmentation path. Populated by cmd/observer with a shim around
	// store.Store; tests + probe-cli leave nil and accept in-memory-
	// only dedup (which is the v1.6.29 baseline behaviour). See the
	// TargetCoverageReader docstring above for the bug it closes.
	targetCoverageReader TargetCoverageReader
}

// TargetCoverageReader returns the distinct Target strings already
// persisted for a given source_file, split by ActionType. Used by the
// plaintext-transcript augmentation path to dedup synthesized
// USER_INPUT / PLANNER_RESPONSE entries against rows from prior parse
// cycles — without it, a later parse cycle that reaches
// synthesizeTranscriptEvents with an empty in-memory `existing` slice
// (decrypt-fail → historyOnlyResult, or decrypt-success-with-zero-
// events) re-emits every transcript entry, landing duplicates in the
// DB because the structured side uses a different SourceEventID
// namespace and the UNIQUE constraint can't suppress them.
//
// Returned slices contain the raw Target column values; matching is
// byte-exact in the dedup logic (both struct and transcript Targets
// go through the same `truncate(scrubber.String(text), 200)` pipeline
// before being stored or compared, so no normalisation is needed).
//
// Defined here (not in internal/store) so the adapter package stays
// store-free per the dependency direction in CLAUDE.md's architecture
// quick reference. The concrete implementation in cmd/observer wraps
// *store.Store. nil reader is safe — the augmentation paths behave as
// before (in-memory dedup only).
type TargetCoverageReader interface {
	LoadActionTargets(ctx context.Context, sourceFile string) (userTargets, asstTargets []string, err error)
}

// UnrecoverableTracker is the persistent record of files for which
// BOTH local decrypt AND gRPC fallback have failed. The antigravity
// adapter consults it before doing the expensive recovery dance, and
// records failures (or clears them on success) afterwards.
//
// Defined here (not in internal/store) so the adapter package stays
// store-free per the dependency direction in CLAUDE.md's architecture
// quick reference. The concrete implementation in cmd/observer wraps
// *store.Store with adapter="antigravity" scoping.
type UnrecoverableTracker interface {
	// Lookup returns the prior failure reason when (sourceFile,
	// size, mtimeUnix) all match a persisted record. found=false
	// covers both "no record" and "record exists but file has
	// drifted" — caller should retry the full path in either case.
	Lookup(ctx context.Context, sourceFile string, size, mtimeUnix int64) (reason string, found bool, err error)
	// Mark upserts a failure record. Repeated marks on the same
	// path replace prior values (latest size/mtime/reason wins).
	Mark(ctx context.Context, sourceFile string, size, mtimeUnix int64, reason string) error
	// Clear removes the failure record. Called on successful parse
	// so the next file change doesn't get short-circuited by stale
	// state. Idempotent.
	Clear(ctx context.Context, sourceFile string) error
}

// indexCacheEntry holds a parsed trajectorySummaries map for a
// given state.vscdb path, plus the file's mtime at read time so we
// can detect staleness.
type indexCacheEntry struct {
	mtime   int64
	entries map[string]indexEntry
}

// New returns an adapter with platform-default cross-mount roots.
func New() *Adapter {
	return &Adapter{
		name:       models.ToolAntigravity,
		scrubber:   scrub.New(),
		roots:      defaultRootsForLayout("desktop"),
		indexCache: map[string]*indexCacheEntry{},
	}
}

// NewCLI returns an adapter for the agy CLI with platform-default cross-mount roots.
func NewCLI() *Adapter {
	return &Adapter{
		name:       models.ToolAntigravityCLI,
		scrubber:   scrub.New(),
		roots:      defaultRootsForLayout("cli"),
		indexCache: map[string]*indexCacheEntry{},
	}
}

// NewWithOptions customizes scrubber and roots for tests. Pass
// nil scrubber for the default; pass nil/empty roots for default
// platform discovery.
func NewWithOptions(s *scrub.Scrubber, roots ...string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{
		name:       models.ToolAntigravity,
		scrubber:   s,
		roots:      roots,
		indexCache: map[string]*indexCacheEntry{},
	}
}

// WithUnrecoverableTracker enables persistent skipping of files that
// already failed every recovery path. nil clears any previously-set
// tracker (i.e. the adapter behaves as cache-miss-always). Returns
// the adapter for chaining; mirrors the pattern used by
// WithNetworkRecovery + cursor.WithSessionHookChecker.
func (a *Adapter) WithUnrecoverableTracker(t UnrecoverableTracker) *Adapter {
	a.unrecoverableTracker = t
	return a
}

// WithTargetCoverageReader enables DB-aware dedup in the plaintext
// transcript augmentation path. nil clears the reader (in-memory-
// only dedup, the v1.6.29 baseline). Returns the adapter for chaining.
// See the TargetCoverageReader docstring for the bug it closes.
func (a *Adapter) WithTargetCoverageReader(r TargetCoverageReader) *Adapter {
	a.targetCoverageReader = r
	return a
}

// WithShapeMismatchDumpDir enables the Issue #5 debug dump. Pass an
// absolute directory; "" disables. The directory is created on first
// dump. Returns the adapter for chaining.
func (a *Adapter) WithShapeMismatchDumpDir(dir string) *Adapter {
	a.dumpShapeMismatchesDir = dir
	return a
}

// WithNetworkRecovery enables the local-language-server gRPC
// fallback. mode = "off" (default) or "local". Returns the adapter
// for chaining.
func (a *Adapter) WithNetworkRecovery(mode string) *Adapter {
	a.networkRecovery = mode
	return a
}

// WithName overrides the default tool name (models.ToolAntigravity).
func (a *Adapter) WithName(name string) *Adapter {
	a.name = name
	return a
}

// Name implements adapter.Adapter.
func (a *Adapter) Name() string {
	if a.name != "" {
		return a.name
	}
	return models.ToolAntigravity
}

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Matches conversation files
// under either the desktop or CLI Antigravity layout:
//
//	.gemini/antigravity/conversations/<uuid>.pb                                  (desktop, encrypted)
//	.gemini/antigravity/brain/<uuid>/.system_generated/logs/transcript.jsonl     (desktop, PLAINTEXT — see transcript.go)
//	.gemini/antigravity-cli/conversations/<uuid>.pb                              (older CLI: agy)
//	.gemini/antigravity-cli/conversations/<uuid>.db                              (newer CLI: agy — plaintext SQLite, see clidb.go)
//
// Path-component string match — foreign-OS separators are normalised
// so tests and WSL2 /mnt/c paths still match without host-OS
// dependence. Other Antigravity .pb subdirs (implicit/,
// user_settings.pb) are out of v1 scope, as are the transcript's
// siblings (`transcript_full.jsonl`, `chunks/*/00000000.jsonl`,
// `steps/<n>/output.txt`) — matching those would double-ingest the
// same steps. The under-WatchPaths constraint enforces the v1.4.51
// dispatch contract.
func (a *Adapter) IsSessionFile(path string) bool {
	layout := classifyLayout(path)
	if layout == LayoutUnknown {
		return false
	}
	if a.Name() == models.ToolAntigravityCLI {
		if layout != LayoutCLI && layout != LayoutCLIDB {
			return false
		}
	} else {
		if layout != LayoutDesktop && layout != LayoutDesktopTranscript && layout != LayoutDesktopDB {
			return false
		}
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// conversationOwner returns the plaintext sibling that pre-empts an
// encrypted `.pb` for its conversation, or "" when `path` is not an
// out-ranked file. The per-uuid model, in BOTH trees:
//
//	.db (agy plaintext SQLite)      → tokens + model id + surface, AND
//	                                  text + actions synthesized from
//	                                  the sibling transcript
//	brain/…/transcript.jsonl        → text + actions (always parsed
//	                                  when it is a session file)
//	conversations/<uuid>.pb         → out-ranked by either of the above
//
// The .db and the transcript are NOT mutually exclusive: both may
// synthesize the same text + action rows, but they key them
// IDENTICALLY — SourceFile = the transcript path, SourceEventID =
// "antigravity-transcript:<uuid>:step:<n>:<kind>" — so whichever lands
// first wins and the store's UNIQUE index absorbs the other, in either
// arrival order (the .db is born ~270 ms before the transcript on the
// live extension run; a late .db must not re-list the conversation).
// Only the .pb defers, and only to a sibling that exists on disk AND
// this adapter serves as a session file (IsSessionFile): an adapter
// whose watch roots exclude brain/ keeps the pre-cut-over behaviour,
// and the CLI tree's transcript (never a session file) pre-empts
// nothing.
func (a *Adapter) conversationOwner(path string) string {
	layout := classifyLayout(path)
	conversationID := uuidFromFilename(path)
	var candidates []string
	switch layout {
	case LayoutDesktop:
		candidates = append(candidates,
			desktopSiblingPath(path, conversationID, ".db"),
			transcriptPathFor(path, conversationID))
	case LayoutCLI:
		if cliRoot, _ := cliRootsFor(path); cliRoot != "" {
			candidates = append(candidates, filepath.Join(cliRoot, "conversations", conversationID+".db"))
		}
	}
	for _, c := range candidates {
		if c != "" && fileExists(c) && a.IsSessionFile(c) {
			return c
		}
	}
	return ""
}

// agyDBMainPath maps a .db / .db-wal / .db-shm path onto the main .db.
func agyDBMainPath(path string) string {
	switch {
	case strings.HasSuffix(strings.ToLower(path), "-wal"):
		return path[:len(path)-len("-wal")]
	case strings.HasSuffix(strings.ToLower(path), "-shm"):
		return path[:len(path)-len("-shm")]
	}
	return path
}

// agyDBWatermark is the cursor value for an agy .db: the max mtime
// (unix milliseconds) of the main file and its -wal sidecar. A WAL-mode
// turn bumps the -wal's mtime without touching the main file's size
// or mtime, so neither a size cursor nor the main file's mtime alone
// would re-fire the parse. Monotonic, so the store's MAX-cursor write
// is safe; ≥ 1 so a fresh file never collides with the "unparsed"
// zero.
func agyDBWatermark(mainPath string) int64 {
	var wm int64 = 1
	for _, p := range []string{mainPath, mainPath + "-wal"} {
		if fi, err := os.Stat(p); err == nil {
			if ms := fi.ModTime().UnixMilli(); ms > wm {
				wm = ms
			}
		}
	}
	return wm
}

// desktopSiblingPath returns <desktopRoot>/conversations/<uuid><ext> for
// any file under the desktop tree, or "" outside it.
func desktopSiblingPath(path, conversationID, ext string) string {
	desktopRoot, _ := desktopRootFor(path)
	if desktopRoot == "" {
		return ""
	}
	return filepath.Join(desktopRoot, "conversations", conversationID+ext)
}

// Layout identifies which Antigravity install shape a session file
// belongs to. Desktop and CLI write conversation .pb files to
// distinct subtrees under ~/.gemini and need different metadata
// resolution paths — CLI has no state.vscdb, only log + projects/
// JSON to lean on.
type Layout int

const (
	LayoutUnknown Layout = iota
	LayoutDesktop
	LayoutCLI
	// LayoutCLIDB is the newer Antigravity CLI conversation store: a
	// plaintext-protobuf SQLite DB at
	// .gemini/antigravity-cli/conversations/<uuid>.db (replacing the
	// per-conversation .pb). No OSCrypt decryption or gRPC bridge is
	// needed — the blobs are read directly (see clidb.go).
	LayoutCLIDB
	// LayoutDesktopTranscript is the desktop IDE's PLAINTEXT per-step
	// trace, .gemini/antigravity/brain/<uuid>/.system_generated/logs/
	// transcript.jsonl — a first-class session file since 2026-09-03
	// (live-grounded on the operator's Windows box, Antigravity IDE
	// signed in). It is the source of truth for a desktop conversation;
	// the encrypted sibling conversations/<uuid>.pb defers to it (see
	// parseSessionFile's guard). Parsed by transcript.go.
	LayoutDesktopTranscript
	// LayoutDesktopDB is an agy-backed conversation store in the DESKTOP
	// tree: .gemini/antigravity/conversations/<uuid>.db, a plaintext-
	// protobuf SQLite with the IDENTICAL schema to the CLI's .db
	// (live-grounded 2026-09-03: written by the VS Code extension
	// Google.google-antigravity, which bundles its own agy backend; the
	// standalone IDE build of the same day wrote only .pb + transcript).
	// Read by the same reader as LayoutCLIDB (clidb.go) — real tokens +
	// model id, text + actions from the sibling brain/ transcript, and
	// trajectory_meta.source as the surface discriminator. Takes
	// precedence over both the transcript and the .pb for its uuid.
	LayoutDesktopDB
)

// isAgyDBLayout reports whether a layout is one of the two plaintext
// SQLite stores the agy backend writes (CLI tree or desktop tree).
func isAgyDBLayout(l Layout) bool { return l == LayoutCLIDB || l == LayoutDesktopDB }

// desktopTranscriptRe matches exactly the desktop IDE's per-conversation
// transcript.jsonl on a lower-cased, forward-slashed path and captures
// the conversation UUID. Anchored on both ends of the tail so the
// siblings the IDE writes next to it (transcript_full.jsonl, the
// chunks/transcript/00000000.jsonl rotation copy, steps/<n>/output.txt)
// and the agy CLI's own brain/ tree (antigravity-cli/brain/…) never
// match.
var desktopTranscriptRe = regexp.MustCompile(
	`/\.gemini/antigravity/brain/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/\.system_generated/logs/transcript\.jsonl$`)

// desktopTranscriptConversationID returns the <uuid> segment of a
// LayoutDesktopTranscript path, or "" when the path is not one.
func desktopTranscriptConversationID(path string) string {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	m := desktopTranscriptRe.FindStringSubmatch(lower)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

// classifyLayout returns the Antigravity layout for a path. CLI is
// checked before desktop because the desktop substring
// "/.gemini/antigravity/" is also a prefix of the CLI substring
// "/.gemini/antigravity-cli/" — Contains() against the desktop form
// would otherwise match CLI paths too if the order were reversed.
func classifyLayout(path string) Layout {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	// Plaintext-protobuf SQLite conversation stores written by the agy
	// backend — the CLI tree (agy itself) and the desktop tree (the VS
	// Code extension's bundled agy). Same file shape, keyed on the tree
	// exactly as the .pb classifier below is.
	// The -wal / -shm sidecars are claimed too (the cline-cli precedent):
	// a WAL-mode turn lands in the -wal without touching the main file,
	// so the sidecar's fsnotify event is what re-fires the parse.
	// parseSessionFile maps them back onto the main .db.
	if strings.HasSuffix(lower, ".db") || strings.HasSuffix(lower, ".db-wal") || strings.HasSuffix(lower, ".db-shm") {
		switch {
		case strings.Contains(lower, "/.gemini/antigravity-cli/conversations/"):
			return LayoutCLIDB
		case strings.Contains(lower, "/.gemini/antigravity-acp/conversations/"):
			// agy backend driven by the JetBrains antigravity-acp agent;
			// identical .db schema, so it reuses the CLI-DB reader.
			return LayoutCLIDB
		case strings.Contains(lower, "/.gemini/antigravity/conversations/"):
			return LayoutDesktopDB
		}
	}
	// Desktop IDE plaintext per-step trace (exact tail match; the
	// `antigravity/brain/` segment cannot collide with the CLI's
	// `antigravity-cli/brain/`).
	if strings.HasSuffix(lower, "/transcript.jsonl") && desktopTranscriptRe.MatchString(lower) {
		return LayoutDesktopTranscript
	}
	if !strings.HasSuffix(lower, ".pb") {
		return LayoutUnknown
	}
	switch {
	case strings.Contains(lower, "/.gemini/antigravity-cli/conversations/"):
		return LayoutCLI
	case strings.Contains(lower, "/.gemini/antigravity/conversations/"):
		return LayoutDesktop
	}
	return LayoutUnknown
}

// matchesSessionShape reports whether path is a recognised
// Antigravity conversation .pb file (desktop or CLI layout).
func matchesSessionShape(path string) bool {
	return classifyLayout(path) != LayoutUnknown
}

// cliRetryWindow caps how long the watcher keeps a freshly-failed
// Antigravity-CLI file on the tight retry poll loop. The .pb file
// often lands on disk before the embedded agy gRPC server has
// finished booting — without retry the live recovery window is lost.
// Beyond this window we treat the file as historical and fall back
// to normal markUnrecoverable + cursor advance. 24h is long enough
// to cover an overnight reboot; short enough that one-off failed
// conversations don't burn poll budget forever.
const cliRetryWindow = 24 * time.Hour

// onUnrecoverableFailure is the single exit point used when both
// local decrypt AND gRPC recovery (where applicable) have failed.
//
// RetrySuggested is set ONLY when the failure could plausibly be
// transient — concretely, a WSL host calling out to Windows-side
// agy.exe through the antigravity-bridge. That hop has real
// transient modes: bridge process not started yet, agy.exe still
// booting, brief network blip across the WSL interop boundary. For
// those, holding the cursor at fromOffset and re-polling on the
// next tick lets the conversation surface as soon as the bridge
// recovers.
//
// Linux-side CLI files on WSL (/home/u/.gemini/antigravity-cli/...)
// short-circuit the Windows bridge — the only recovery route is a
// Linux-native agy process that happens to host the conversation.
// If that discovery has already run and every server rejected with
// trajectory_not_found, retrying won't change the outcome: the user
// has to start a fresh agy session for that workspace (which
// rewrites the file, advancing mtime, and re-arming the
// freshness-check). So those failures get marked unrecoverable
// straight away to avoid burning poll cycles on the same file
// every 2 seconds. (Closes the 2026-05-24 retry-loop noise.)
//
// Desktop CLI files and non-WSL hosts follow the same logic — if
// discovery has run and exhausted, retry doesn't help.
//
// Reason is the short machine-readable failure tag persisted into
// the unrecoverable cache; warning is the human-readable message
// surfaced to the operator via the watcher log.
//
// recoveryErr is the underlying error from recoverViaLocalGRPC (or
// nil when the failure happened on the decrypt-only path). It's
// inspected for ErrBridgeTransient — those wrappings indicate an
// environment problem (PowerShell missing from PATH, /mnt/c cache
// copy hitting an AV / file-lock race) that will likely self-heal on
// the next poll tick. Those paths must NOT write a marker; doing so
// strands the file at the current (size, mtime) until the .pb
// genuinely changes, even after the environment recovers.
func (a *Adapter) onUnrecoverableFailure(ctx context.Context, path string, fi os.FileInfo, fromOffset int64, reason, warning string, recoveryErr error) adapter.ParseResult {
	if errors.Is(recoveryErr, ErrBridgeTransient) {
		return adapter.ParseResult{
			NewOffset:      fromOffset,
			RetrySuggested: true,
			Warnings: []string{
				warning + " (transient bridge error; will retry on next watcher tick)",
			},
		}
	}
	if a.shouldRetryCLIFailure(path, fi) {
		return adapter.ParseResult{
			NewOffset:      fromOffset,
			RetrySuggested: true,
			Warnings: []string{
				warning + " (fresh CLI file; will retry on next watcher tick)",
			},
		}
	}
	a.markUnrecoverable(ctx, path, fi, reason)
	return adapter.ParseResult{
		NewOffset: fi.Size(),
		Warnings:  []string{warning},
	}
}

// shouldRetryCLIFailure reports whether a decrypt+gRPC miss on a
// CLI .pb has a plausible chance of succeeding on a later poll.
// True only for WSL → Windows-side .pb files (the bridge hop has
// real transient modes); everything else has already exhausted its
// recovery route by the time we get here.
func (a *Adapter) shouldRetryCLIFailure(path string, fi os.FileInfo) bool {
	if classifyLayout(path) != LayoutCLI {
		return false
	}
	if time.Since(fi.ModTime()) >= cliRetryWindow {
		return false
	}
	// WSL-side Linux paths route through Linux-native discovery,
	// which has already exhausted on first failure. Only the
	// Windows-side bridge path has retry value.
	if !isWSL() {
		return false
	}
	return strings.HasPrefix(path, "/mnt/")
}

// ParseSessionFile implements adapter.Adapter.
//
// Cursor semantics: the byte_offset stored in parse_cursors is the
// file size at last successful parse. A file size that hasn't grown
// past fromOffset is treated as "no work to do." Decryption +
// classification run on every size advance.
//
// Errors fall into three buckets:
//   - decryption failure (no validating plaintext): warning + advance
//     cursor so we don't retry forever on a permanently-bad file.
//   - secret retrieval failure: warning + DON'T advance cursor — the
//     OSCrypt key may become available later (e.g. user unlocks
//     keychain), in which case we want to retry.
//   - file system error: hard error returned to caller.
//
// This exported wrapper delegates to parseSessionFile and then re-tags
// every emitted event with THIS adapter's own tool name. The parse
// helpers (classify.go / structured.go / markdown.go / clidb.go /
// transcript_cli.go) all hardcode models.ToolAntigravity; the CLI
// adapter (NewCLI) must surface its rows under antigravity-cli so the
// desktop and CLI layouts stay distinct on the dashboard. No-op for the
// desktop adapter, where Name() == models.ToolAntigravity. Mirrors
// kilocode.LegacyAdapter's re-tag boundary (CLAUDE.md #2/#3).
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	res, err := a.parseSessionFile(ctx, path, fromOffset)
	name := a.Name()
	for i := range res.ToolEvents {
		res.ToolEvents[i].Tool = name
	}
	for i := range res.TokenEvents {
		res.TokenEvents[i].Tool = name
	}
	return res, err
}

func (a *Adapter) parseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	layout := classifyLayout(path)

	// agy plaintext-protobuf SQLite conversation store (CLI tree, or the
	// desktop tree when the VS Code extension's bundled agy wrote it),
	// reached through the main .db OR its -wal / -shm sidecar. The
	// cursor is a WATERMARK (max mtime of .db + .db-wal, unix ms), not a
	// size: WAL mode absorbs whole turns without growing the main file.
	// Parsed directly — none of the decrypt + gRPC-bridge machinery
	// below applies (that's for the opaque/encrypted .pb path).
	if isAgyDBLayout(layout) {
		main := agyDBMainPath(path)
		if _, err := os.Stat(main); err != nil {
			return adapter.ParseResult{}, fmt.Errorf("antigravity.ParseSessionFile: stat: %w", err)
		}
		watermark := agyDBWatermark(main)
		if fromOffset >= watermark {
			return adapter.ParseResult{NewOffset: fromOffset}, nil
		}
		return a.parseCLIDB(ctx, main, fromOffset, watermark)
	}

	fi, err := os.Stat(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("antigravity.ParseSessionFile: stat: %w", err)
	}
	res := adapter.ParseResult{NewOffset: fi.Size()}
	if fi.Size() == 0 {
		return res, nil
	}
	if fromOffset == fi.Size() {
		// Cursor already at current size; the watcher woke us with a
		// non-content event. No work.
		return res, nil
	}

	// Per-conversation ownership guard (.db > transcript.jsonl > .pb, in
	// both trees — see conversationOwner). A file that is out-ranked by
	// a sibling this adapter already ingests emits nothing: every
	// user_prompt / assistant_message / tool row it could produce — via
	// decrypt, the gRPC bridge, or the transcript augmentation — is
	// already emitted from the owner under a different source_file, and
	// the UNIQUE(source_file, source_event_id) index cannot suppress a
	// cross-file duplicate. Advance the cursor and stop; say so once.
	if owner := a.conversationOwner(path); owner != "" {
		res.NewOffset = fi.Size()
		if fromOffset == 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"antigravity: %s is out-ranked by its sibling %s; the sibling owns this conversation, file skipped",
				filepath.Base(path), filepath.Base(owner)))
		}
		return res, nil
	}

	// Desktop IDE plaintext per-step trace: parsed directly, no
	// decrypt, no bridge (transcript.go).
	if layout == LayoutDesktopTranscript {
		return a.parseDesktopTranscript(ctx, path, fi, fromOffset)
	}

	// Unrecoverable-file short-circuit. If this path's last full
	// attempt (decrypt + gRPC fallback) failed AND the file's
	// size+mtime are unchanged since, skip the entire ~30s dance.
	// Mirrors the documented Antigravity-on-WSL2 unrecoverable case:
	// Windows .pb files whose Linux-native language_server doesn't
	// host the conversation AND oscrypt can't decrypt (cipher mode
	// unknown). Cache is process-local (in-memory) — daemon
	// `observer start` benefits across triggered Rescans; one-shot
	// CLI invocations don't (process exits before re-visiting).
	// (Issue #4)
	if reason := a.lookupUnrecoverable(ctx, path, fi); reason != "" {
		return adapter.ParseResult{
			NewOffset: fi.Size(),
			Warnings: []string{
				fmt.Sprintf("antigravity: %s previously unrecoverable (%s); skipping retry until file changes",
					filepath.Base(path), reason),
			},
		}, nil
	}

	secret, err := a.lookupSecret()
	if err != nil {
		return adapter.ParseResult{
			NewOffset: fromOffset, // hold cursor — secret may come back
			Warnings: []string{
				fmt.Sprintf("antigravity: OSCrypt secret retrieval failed (%v); will retry on next event", err),
			},
		}, nil
	}

	body, err := os.ReadFile(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("antigravity.ParseSessionFile: read: %w", err)
	}

	plaintext, strategy, err := decryptOne(body, secret)
	if err != nil {
		// Local decrypt failed. If the user opted into
		// network_recovery="local", try the running
		// language_server's gRPC ConvertTrajectoryToMarkdown.
		if a.networkRecovery == "local" {
			if recRes, recWarn, recErr := a.recoverViaLocalGRPC(ctx, path, fi); recErr == nil {
				recRes.NewOffset = fi.Size()
				if recWarn != "" {
					recRes.Warnings = append(recRes.Warnings, recWarn)
				}
				// On success, clear any prior unrecoverable mark so
				// the file gets re-processed normally next time.
				a.clearUnrecoverable(ctx, path)
				// Plaintext-transcript augmentation: agy's gRPC
				// ConvertTrajectoryToMarkdown returns an unstable /
				// truncated view of the trajectory (verified
				// 2026-05-24); the desktop IDE bridge path has its own
				// gaps. Top up with any user_prompt / assistant-text
				// entries from the layout-appropriate brain/ trace
				// (CLI: transcript.jsonl; desktop: overview.txt) that
				// the bridge didn't already surface — handles both
				// "agy returned less than reality" (steady state) and
				// "agy returned everything" (no-op, dedup-by-Target
				// skips the merge).
				conversationID := uuidFromFilename(path)
				projectRoot := projectRootFromResult(&recRes, conversationID)
				gitRemote := gitRemoteFromResult(&recRes, conversationID)
				a.augmentResultFromHistory(path, conversationID, projectRoot, gitRemote, &recRes)
				return recRes, nil
			} else {
				// Recovery failed too. Before falling back to the
				// unrecoverable path, check whether history.jsonl
				// has user_prompt entries for this conversation that
				// we can surface — common on brand-new agy sessions
				// where the bridge hasn't yet caught up but the user
				// has already typed.
				if hist := a.historyOnlyResult(path, fi); hist != nil {
					return *hist, nil
				}
				// For fresh CLI files,
				// onUnrecoverableFailure holds the cursor + sets
				// RetrySuggested so the watcher polls again — the
				// embedded agy gRPC server may still be booting.
				// For everything else (desktop files, stale CLI),
				// markUnrecoverable + advance cursor so subsequent
				// Rescans short-circuit the ~30s decrypt+gRPC dance
				// until the file actually changes. (Issue #4)
				return a.onUnrecoverableFailure(
					ctx, path, fi, fromOffset,
					fmt.Sprintf("decrypt+grpc: %v / %v", err, recErr),
					fmt.Sprintf("antigravity: decrypt failed for %s (%v); language-server gRPC fallback also failed (%v). Skipping.",
						filepath.Base(path), err, recErr),
					recErr,
				), nil
			}
		}
		// Pure-local mode (default): same history.jsonl escape hatch
		// before falling back to the unrecoverable path.
		if hist := a.historyOnlyResult(path, fi); hist != nil {
			return *hist, nil
		}
		// For fresh CLI files, hold cursor + set RetrySuggested
		// (the operator may enable network_recovery later or the CLI
		// may come back online). For everything else, advance cursor
		// + mark unrecoverable.
		return a.onUnrecoverableFailure(
			ctx, path, fi, fromOffset,
			fmt.Sprintf("decrypt: %v (no network_recovery)", err),
			fmt.Sprintf("antigravity: decrypt failed for %s (%v); skipping. Set [observer.antigravity] network_recovery = \"local\" in config to fall back via the running language_server's gRPC API.", filepath.Base(path), err),
			nil, // no recovery attempt to flag transient
		), nil
	}
	// Successful decrypt — drop any prior unrecoverable mark since
	// the file is now readable (oscrypt key may have become
	// available, e.g. user unlocked keychain).
	a.clearUnrecoverable(ctx, path)

	conversationID := uuidFromFilename(path)
	indexEntry := a.lookupIndexEntry(path, conversationID)

	emitted, classifyWarnings, err := a.classify(path, conversationID, plaintext, indexEntry)
	if err != nil {
		return adapter.ParseResult{
			NewOffset: fi.Size(),
			Warnings: append(classifyWarnings,
				fmt.Sprintf("antigravity: classify failed for %s (%v) [strategy=%s]", filepath.Base(path), err, strategy)),
		}, nil
	}
	res.ToolEvents = emitted.ToolEvents
	res.TokenEvents = emitted.TokenEvents
	res.Warnings = append(res.Warnings, classifyWarnings...)
	if len(emitted.ToolEvents) == 0 && len(emitted.TokenEvents) == 0 {
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("antigravity: %s decrypted (strategy=%s, %d bytes plaintext) but no events extracted; classifier may need tuning",
				filepath.Base(path), strategy, len(plaintext)))
	}
	// Plaintext-transcript augmentation (symmetric with the recovery-
	// success branch above): if any user_prompt / assistant_text
	// entries in the layout-appropriate brain/ trace (CLI:
	// transcript.jsonl; desktop: overview.txt) aren't covered by what
	// the decrypt path emitted, surface them. Keeps the augmentation
	// logic at every event-producing exit so future flow refactors
	// don't silently lose it.
	projectRoot := projectRootFromResult(&res, conversationID)
	gitRemote := gitRemoteFromResult(&res, conversationID)
	a.augmentResultFromHistory(path, conversationID, projectRoot, gitRemote, &res)
	return res, nil
}

// recoverViaLocalGRPC tries the language_server's
// ConvertTrajectoryToMarkdown gRPC endpoint and parses the returned
// Markdown into events.
//
// On WSL2, the language_server is bound to Windows-side 127.0.0.1
// which isn't reachable from Linux. We delegate to the
// antigravity-bridge.exe helper (which runs Windows-side via
// powershell.exe) — it does the discovery + gRPC call and returns
// the Markdown via stdout. On native macOS / native Windows /
// non-WSL Linux, we make the call directly via Go's HTTP/2 client.
func (a *Adapter) recoverViaLocalGRPC(ctx context.Context, path string, fi os.FileInfo) (adapter.ParseResult, string, error) {
	conversationID := uuidFromFilename(path)
	idxEntry := a.lookupIndexEntry(path, conversationID)
	projectRoot, gitRemote, projectIdentity := "[antigravity]", "", git.Identity{}
	if idxEntry != nil && idxEntry.workspaceURI != "" {
		projectRoot, gitRemote, projectIdentity = decodeFileURIToRoot(idxEntry.workspaceURI)
	}
	ts := time.Now().UTC()
	if idxEntry != nil && !idxEntry.created.IsZero() {
		ts = idxEntry.created
	}

	wsl := isWSL()
	tracef("recover %s wsl=%v", conversationID, wsl)

	// On WSL2, language_server discovery yields Windows-side processes
	// listening on Windows loopback. Linux loopback is a different
	// network namespace, so dialing those endpoints from Linux always
	// fails with `connection refused`. Skip the dial loop entirely
	// and route through the Windows-side bridge, which runs its own
	// discovery and makes the gRPC call from where the ports are
	// actually reachable.
	//
	// Issue A fix: SOME conversations live on the Linux side
	// (~/.gemini/antigravity/conversations/<uuid>.pb) and are only
	// hosted by a Linux-native language_server — the Windows bridge
	// can't reach them. Try Linux-native discovery first; if a
	// Linux-native server has the conversation, use it. Fall through
	// to the bridge for everything else (Windows-side conversations,
	// or hosts where no Linux server is running).
	//
	// Path-based gating (added 2026-05-05 after a Run All trace
	// showed every conversation hitting Linux-native pid=2259 with
	// `broken pipe` / `unexpected EOF` and falling through to the
	// bridge anyway): only attempt Linux-native when the .pb file is
	// itself under /home/ — Windows-side .pb files (under /mnt/c/)
	// are guaranteed not to be hosted by a Linux-native server, so
	// the attempt is wasted overhead. This trims roughly one failed
	// 5s-timeout HTTP call per Windows-side conversation from the
	// backfill (~80% of conversations on a typical WSL2 host).
	if wsl && strings.HasPrefix(path, "/home/") {
		if linuxServers, _ := discoverNativeLinux(); len(linuxServers) > 0 {
			// Workspace matching: each language_server only hosts
			// conversations from ITS workspace. Talking to a non-
			// matching server returns an empty stub that produces 0
			// events — the symptom that prompted this fix
			// (2026-05-10). Sort matching servers first, fall through
			// to non-matchers as last resort with a warning.
			wantWS := ""
			if idxEntry != nil {
				wantWS = workspaceIDFromURI(idxEntry.workspaceURI)
			}
			ordered := sortServersByWorkspaceMatch(linuxServers, wantWS)
			for _, ls := range ordered {
				wsMatch := wantWS != "" && ls.WorkspaceID == wantWS
				md, useEndpoint, ok := a.tryConvertTrajectoryAcrossEndpoints(ctx, ls, conversationID, 5*time.Second)
				if !ok {
					continue
				}
				tracef("linux-native pid=%d %s OK (%d bytes, ws=%q match=%v)",
					ls.PID, useEndpoint, len(md), ls.WorkspaceID, wsMatch)
				enrichment := a.fetchStructuredEnrichmentNativeAt(ctx, ls, useEndpoint, conversationID, projectRoot, gitRemote, path)
				if !enrichment.StartedAt.IsZero() {
					ts = enrichment.StartedAt
				}
				skipInline := len(enrichment.ToolEvents) > 0
				skipUserInputs := hasStructuredUserPrompts(enrichment.ToolEvents)
				skipPlanner := structuredAssistantTextCoverage(enrichment) >= AssistantTextCoverageThreshold
				if isWrongWorkspaceStub(enrichment) {
					// Wrong-workspace stub guard. Checked BEFORE
					// parseMarkdownConversation runs because the stub
					// markdown still parses as a fake user_prompt
					// event — the pre-2026-05-19 guard checked the
					// merged result and missed this case (see
					// isWrongWorkspaceStub doc comment). Try the
					// next server.
					tracef("linux-native pid=%d returned wrong-workspace stub (no structured payload); trying next server", ls.PID)
					continue
				}
				res := parseMarkdownConversation(path, conversationID, projectRoot, gitRemote, ts, a.scrubber, md, skipInline, skipUserInputs, skipPlanner)
				adapter.ApplyProjectIdentity(&res, projectIdentity)
				applyStructuredEnrichment(&res, enrichment)
				// Project-root recovery: when idxEntry was nil
				// (live in-progress conversation not yet in
				// trajectorySummaries) but we have a workspace_id from
				// the language_server, invert the encoding to find a
				// real path and overwrite the "[antigravity]"
				// placeholder.
				if projectRoot == "[antigravity]" && ls.WorkspaceID != "" {
					if resolved := a.resolveWorkspaceIDToPathCached(ls.WorkspaceID); resolved != "" {
						tracef("linux-native pid=%d resolved workspace_id %q to path %q (idx miss; live conversation)",
							ls.PID, ls.WorkspaceID, resolved)
						applyResolvedProjectRoot(&res, resolved)
					}
				}
				tracef("linux-native pid=%d extracted %d tool(s), %d token row(s), model=%q",
					ls.PID, len(res.ToolEvents), len(res.TokenEvents), enrichment.Model)
				return res, "", nil
			}
		}
	}
	if wsl {
		// Linux-side conversations (~/.gemini/antigravity/conversations/
		// <uuid>.pb) are unreachable from the Windows-side bridge — the
		// bridge can't read files behind WSL's filesystem boundary.
		// Linux-native discovery above was the only viable path; if we
		// got here, a Linux-native language_server either isn't running
		// or doesn't host this conversation. Return a single-line hint
		// instead of burning ~3s on a guaranteed-to-fail bridge call
		// (the structured-recovery path tries the same dead bridge for
		// another ~3s, so each unrecoverable conversation costs ~6s on
		// a Run All — adds up fast at 24 of them).
		if strings.HasPrefix(path, "/home/") {
			tracef("skip wsl bridge for linux-side path %s", path)
			return adapter.ParseResult{}, "", fmt.Errorf(
				"no Linux-native language_server hosts this conversation; reopen the originating workspace in Antigravity to recover",
			)
		}
		bridgeBinary, locErr := locateBridgeBinary()
		if locErr != nil {
			tracef("bridge_locate_err=%v", locErr)
			return adapter.ParseResult{}, "", locErr
		}
		tracef("bridge=%s", bridgeBinary)
		md, err := a.callBridgeConvertCached(ctx, conversationID, path, 30*time.Second)
		if err != nil {
			tracef("bridge err: %v", err)
			return adapter.ParseResult{}, "", fmt.Errorf("bridge: %w", err)
		}
		tracef("bridge OK (%d bytes)", len(md))
		// Best-effort structured-trajectory enrichment. Per-conversation
		// fetch via the same bridge, ~250ms. On failure we keep the
		// markdown result unchanged — observer still records actions,
		// just without model attribution or token rows.
		enrichment := a.fetchStructuredEnrichmentWSL(ctx, conversationID, projectRoot, gitRemote, path)
		if !enrichment.StartedAt.IsZero() {
			tracef("structured ts override: %s -> %s", ts.Format(time.RFC3339), enrichment.StartedAt.Format(time.RFC3339))
			ts = enrichment.StartedAt
		}
		// Tier 1 dedup: when structured emits ToolEvents (artifact
		// edits, file views), suppress markdown's `*Edited file…*` /
		// `*Viewed…*` inline-tool extraction so the same edit doesn't
		// land twice. Tier 2 dedup: when structured emits
		// user_prompt rows, also suppress markdown's `### User Input`
		// turns. Tier 3 dedup: suppress markdown's `### Planner
		// Response` turns ONLY when structured assistant_text covers
		// >= AssistantTextCoverageThreshold of LLM calls — gemini
		// sessions emit far fewer 1.2.20 PLANNER_RESPONSE steps and
		// markdown carries the missing narrative. Below threshold,
		// keep markdown so the dashboard's per-token-row expand has
		// content to show.
		skipInline := len(enrichment.ToolEvents) > 0
		skipUserInputs := hasStructuredUserPrompts(enrichment.ToolEvents)
		skipPlanner := structuredAssistantTextCoverage(enrichment) >= AssistantTextCoverageThreshold
		res := parseMarkdownConversation(path, conversationID, projectRoot, gitRemote, ts, a.scrubber, md, skipInline, skipUserInputs, skipPlanner)
		adapter.ApplyProjectIdentity(&res, projectIdentity)
		applyStructuredEnrichment(&res, enrichment)
		return res, "", nil
	}

	// Native macOS / native Windows / non-WSL Linux: discover the
	// local language_servers and call them directly via Go's HTTP/2
	// client. The discovered endpoints are on the same loopback as
	// this process.
	servers, discoveryErr := a.discoverLanguageServersCached()
	if discoveryErr != nil {
		tracef("discovery_err=%v", discoveryErr)
		return adapter.ParseResult{}, "", fmt.Errorf("language-server discovery failed: %w", discoveryErr)
	}
	tracef("discovered %d server(s)", len(servers))
	for i, ls := range servers {
		tracef("  [%d] pid=%d http=%d https=%d workspace=%q endpoint=%q",
			i, ls.PID, ls.HTTPPort, ls.HTTPSPort, ls.WorkspaceID, ls.PreferredEndpoint())
	}
	wantWS := ""
	if idxEntry != nil {
		wantWS = workspaceIDFromURI(idxEntry.workspaceURI)
	}
	ordered := sortServersByWorkspaceMatch(servers, wantWS)
	var lastErr error
	for _, ls := range ordered {
		wsMatch := wantWS != "" && ls.WorkspaceID == wantWS
		md, useEndpoint, ok := a.tryConvertTrajectoryAcrossEndpoints(ctx, ls, conversationID, 15*time.Second)
		if !ok {
			lastErr = fmt.Errorf("all endpoints for pid=%d failed", ls.PID)
			continue
		}
		tracef("grpc pid=%d %s OK (%d bytes, ws=%q match=%v)", ls.PID, useEndpoint, len(md), ls.WorkspaceID, wsMatch)
		enrichment := a.fetchStructuredEnrichmentNativeAt(ctx, ls, useEndpoint, conversationID, projectRoot, gitRemote, path)
		if !enrichment.StartedAt.IsZero() {
			ts = enrichment.StartedAt
		}
		if isWrongWorkspaceStub(enrichment) {
			// Wrong-workspace stub guard (see isWrongWorkspaceStub
			// doc comment). Same fix as the linux-native loop above.
			tracef("grpc pid=%d returned wrong-workspace stub (no structured payload); trying next server", ls.PID)
			continue
		}
		skipInline := len(enrichment.ToolEvents) > 0
		skipUserInputs := hasStructuredUserPrompts(enrichment.ToolEvents)
		skipPlanner := structuredAssistantTextCoverage(enrichment) >= AssistantTextCoverageThreshold
		res := parseMarkdownConversation(path, conversationID, projectRoot, gitRemote, ts, a.scrubber, md, skipInline, skipUserInputs, skipPlanner)
		adapter.ApplyProjectIdentity(&res, projectIdentity)
		applyStructuredEnrichment(&res, enrichment)
		if projectRoot == "[antigravity]" && ls.WorkspaceID != "" {
			if resolved := a.resolveWorkspaceIDToPathCached(ls.WorkspaceID); resolved != "" {
				tracef("grpc pid=%d resolved workspace_id %q to path %q (idx miss; live conversation)",
					ls.PID, ls.WorkspaceID, resolved)
				applyResolvedProjectRoot(&res, resolved)
			}
		}
		tracef("grpc pid=%d extracted %d tool(s), %d token row(s), model=%q",
			ls.PID, len(res.ToolEvents), len(res.TokenEvents), enrichment.Model)
		return res, "", nil
	}
	if lastErr != nil {
		return adapter.ParseResult{}, "", fmt.Errorf("all %d language servers failed: %w", len(servers), lastErr)
	}
	return adapter.ParseResult{}, "", fmt.Errorf("no usable language_server endpoint")
}

// sortServersByWorkspaceMatch returns a copy of servers ordered with
// the wantWS-matching ones first, then the others. Used by
// recoverViaLocalGRPC to prefer the language_server that actually
// hosts the conversation. wantWS == "" returns the input unchanged
// (no matching info available, treat all servers equally).
func sortServersByWorkspaceMatch(servers []LanguageServer, wantWS string) []LanguageServer {
	if wantWS == "" || len(servers) == 0 {
		return servers
	}
	matches := make([]LanguageServer, 0, len(servers))
	others := make([]LanguageServer, 0, len(servers))
	for _, s := range servers {
		if s.WorkspaceID == wantWS {
			matches = append(matches, s)
		} else {
			others = append(others, s)
		}
	}
	return append(matches, others...)
}

// tryConvertTrajectoryAcrossEndpoints is the cache-aware variant.
// Looks up the cached working endpoint for ls (key: PID:CSRFToken);
// if hit, tries the cached endpoint FIRST. On cache-hit success,
// returns immediately — saves the ~5s timeout we'd otherwise pay on
// the heuristic-bad first candidate when PreferredEndpoint() is
// wrong (verified case: pid 694 had heuristic-HTTP=37933 but the
// actual TLS port; cache pin to 35989 saves the 5s burn per
// conversation).
//
// On cache-hit failure (e.g. server restarted, port changed), falls
// through to the full ls.Endpoints() iteration and updates the cache
// with the new working endpoint.
func (a *Adapter) tryConvertTrajectoryAcrossEndpoints(ctx context.Context, ls LanguageServer, conversationID string, timeout time.Duration) (string, string, bool) {
	cacheKey := endpointCacheKey(ls)
	if cached := a.cachedEndpoint(cacheKey); cached != "" {
		md, err := callConvertTrajectory(ctx, cached, ls.CSRFToken, conversationID, timeout)
		if err == nil {
			return md, cached, true
		}
		tracef("pid=%d cached endpoint %s err: %v (will re-iterate)", ls.PID, cached, err)
		a.invalidateEndpoint(cacheKey)
	}
	endpoints := ls.Endpoints()
	if len(endpoints) == 0 {
		tracef("pid=%d has no endpoints to try", ls.PID)
		return "", "", false
	}
	for _, endpoint := range endpoints {
		md, err := callConvertTrajectory(ctx, endpoint, ls.CSRFToken, conversationID, timeout)
		if err != nil {
			tracef("pid=%d %s err: %v", ls.PID, endpoint, err)
			continue
		}
		a.cacheEndpoint(cacheKey, endpoint)
		return md, endpoint, true
	}
	return "", "", false
}

// endpointCacheKey returns the per-server identity used to key the
// endpoint cache. PID alone isn't enough (PIDs are reused after
// restart); CSRFToken is generated fresh each language_server start
// and is the stable identity within a process generation.
func endpointCacheKey(ls LanguageServer) string {
	return fmt.Sprintf("%d:%s", ls.PID, ls.CSRFToken)
}

// lookupUnrecoverable consults the persistent tracker for path. When
// no tracker is wired (test paths, smoke runs) this is a no-op
// returning "". The tracker itself handles the size+mtime drift
// check internally — if the file changed, it returns found=false so
// the caller retries the full recovery path. (Issue #4)
func (a *Adapter) lookupUnrecoverable(ctx context.Context, path string, fi os.FileInfo) string {
	if a.unrecoverableTracker == nil {
		return ""
	}
	reason, found, err := a.unrecoverableTracker.Lookup(ctx, path, fi.Size(), fi.ModTime().Unix())
	if err != nil {
		// Soft-fail: a tracker error must not block parsing. Log via
		// tracef so it surfaces in debug logs without poisoning the
		// adapter's success path.
		tracef("unrecoverable_lookup_err path=%s err=%v", path, err)
		return ""
	}
	if !found {
		return ""
	}
	return reason
}

// markUnrecoverable persists a failure record. The tracker upserts
// the (path, size, mtime, reason) tuple so a re-failed-then-re-marked
// file pins to the latest content. No-op when no tracker is wired.
// (Issue #4)
func (a *Adapter) markUnrecoverable(ctx context.Context, path string, fi os.FileInfo, reason string) {
	if a.unrecoverableTracker == nil {
		return
	}
	if err := a.unrecoverableTracker.Mark(ctx, path, fi.Size(), fi.ModTime().Unix(), reason); err != nil {
		tracef("unrecoverable_mark_err path=%s err=%v", path, err)
	}
}

// clearUnrecoverable removes any persisted failure record for path.
// Idempotent. No-op when no tracker is wired. (Issue #4)
func (a *Adapter) clearUnrecoverable(ctx context.Context, path string) {
	if a.unrecoverableTracker == nil {
		return
	}
	if err := a.unrecoverableTracker.Clear(ctx, path); err != nil {
		tracef("unrecoverable_clear_err path=%s err=%v", path, err)
	}
}

func (a *Adapter) cachedEndpoint(key string) string {
	a.endpointMu.Lock()
	defer a.endpointMu.Unlock()
	return a.endpointCache[key]
}

func (a *Adapter) cacheEndpoint(key, endpoint string) {
	a.endpointMu.Lock()
	defer a.endpointMu.Unlock()
	if a.endpointCache == nil {
		a.endpointCache = make(map[string]string)
	}
	a.endpointCache[key] = endpoint
}

func (a *Adapter) invalidateEndpoint(key string) {
	a.endpointMu.Lock()
	defer a.endpointMu.Unlock()
	delete(a.endpointCache, key)
}

// cachedConvEndpoint returns the cached (endpoint, csrf) pin for a
// conversation, or an empty pin on miss. Empty pin signals the
// bridge wrapper to run full discovery.
func (a *Adapter) cachedConvEndpoint(conversationID string) bridgePin {
	a.convEndpointMu.Lock()
	defer a.convEndpointMu.Unlock()
	return a.convEndpointCache[conversationID]
}

// rememberConvEndpoint stores the working endpoint hint reported by
// the bridge for the next invocation. No-op when endpoint == "" (no
// hint) or conversationID == "". Repeated calls with the same conv
// overwrite — fine, because the bridge only ever emits the hint on
// success, and a server that hosts the conv now will continue to
// host it until restart.
func (a *Adapter) rememberConvEndpoint(conversationID, endpoint, csrf string) {
	if endpoint == "" || conversationID == "" {
		return
	}
	a.convEndpointMu.Lock()
	defer a.convEndpointMu.Unlock()
	if a.convEndpointCache == nil {
		a.convEndpointCache = make(map[string]bridgePin)
	}
	a.convEndpointCache[conversationID] = bridgePin{Endpoint: endpoint, CSRFToken: csrf}
}

// invalidateConvEndpoint clears the cached pin for a conversation.
// Called when a pinned bridge invocation fails — the server may have
// restarted, the workspace may have closed, etc. Next call falls
// back to full discovery.
func (a *Adapter) invalidateConvEndpoint(conversationID string) {
	a.convEndpointMu.Lock()
	defer a.convEndpointMu.Unlock()
	delete(a.convEndpointCache, conversationID)
}

// bridgeColdCallTimeout is the timeout for an unpinned bridge call —
// the first invocation for a conversation, when the bridge has to
// run its PowerShell discovery + serial fan-out across every
// candidate gRPC server. On a busy host (operator's machine has 17
// candidates: 3 agy.exe + 7 antigravity.exe + 7 language_server_*.
// exe) the worst-case fan-out is ~17 servers × ~2 endpoints × 5s
// per-failed-endpoint timeout ≈ 90s before the right server (or
// "all failed") is reached. The previous 30s timeout killed the
// invocation before any server could win, which meant no
// `bridge-endpoint=...` stderr hint ever landed, which meant the
// per-conversation endpoint cache stayed empty, which meant every
// future invocation paid the same full fan-out cost and timed out
// again — a tight no-progress loop.
//
// 90s is a one-time cost per conversation. Pinned invocations
// (cache hit) keep the original tighter timeout.
const bridgeColdCallTimeout = 90 * time.Second

// callBridgeConvertCached runs the bridge convert subcommand with the
// per-conversation pin (if any), invalidates+retries on cached-call
// failure, and persists the working endpoint on success. Returns the
// markdown body — keeps the call sites in recoverViaLocalGRPC short.
//
// `timeout` is the pinned (cache-hit) deadline; cold-cache calls fall
// back to the longer bridgeColdCallTimeout because the bridge's
// serial fan-out across every candidate gRPC server can take 60–90s
// on hosts with many language_server / agy.exe instances.
//
// Pin order (Phase 3 of the token-coverage design):
//
//  1. convEndpointCache — endpoint that succeeded for this conv before.
//  2. originating server (from cli-*.log) — the agy.exe PID + port
//     that hosted this conv when it was first created.
//  3. Cold-cache fan-out — bridge discovery across every running
//     language_server. Last resort because the PowerShell + WMI +
//     per-server-timeout cost runs into 60–90s on busy hosts.
func (a *Adapter) callBridgeConvertCached(ctx context.Context, conversationID, sessionPath string, timeout time.Duration) (string, error) {
	pin := a.cachedConvEndpoint(conversationID)
	if pin.Endpoint != "" {
		res, err := invokeBridgeFromWSLPinned(ctx, conversationID, timeout, pin)
		if err == nil {
			a.rememberConvEndpoint(conversationID, res.HitEndpoint, res.HitCSRF)
			return string(res.Stdout), nil
		}
		tracef("convert pinned endpoint %s failed for %s: %v (falling back to discovery)", pin.Endpoint, conversationID, err)
		a.invalidateConvEndpoint(conversationID)
	}
	for _, pinEndpoint := range a.originatingServerCandidates(sessionPath, conversationID) {
		res, err := invokeBridgeFromWSLPinned(ctx, conversationID, timeout, bridgePin{Endpoint: pinEndpoint})
		if err == nil {
			a.rememberConvEndpoint(conversationID, res.HitEndpoint, res.HitCSRF)
			tracef("convert originating-server pin %s OK for %s", pinEndpoint, conversationID)
			return string(res.Stdout), nil
		}
		tracef("convert originating-server pin %s failed for %s: %v", pinEndpoint, conversationID, err)
	}
	res, err := invokeBridgeFromWSLPinned(ctx, conversationID, bridgeColdCallTimeout, bridgePin{})
	if err != nil {
		return "", err
	}
	a.rememberConvEndpoint(conversationID, res.HitEndpoint, res.HitCSRF)
	return string(res.Stdout), nil
}

// callBridgeStructuredCached mirrors callBridgeConvertCached for the
// structured subcommand. Same cache, same invalidation contract,
// same pinned-vs-cold timeout split, same originating-server pin
// fallback: either the convert or structured call can populate /
// refresh the per-conversation pin, and both share the benefit on
// subsequent calls.
func (a *Adapter) callBridgeStructuredCached(ctx context.Context, conversationID, sessionPath string, timeout time.Duration) ([]byte, error) {
	pin := a.cachedConvEndpoint(conversationID)
	if pin.Endpoint != "" {
		res, err := invokeBridgeStructuredFromWSLPinned(ctx, conversationID, timeout, pin)
		if err == nil {
			a.rememberConvEndpoint(conversationID, res.HitEndpoint, res.HitCSRF)
			return res.Stdout, nil
		}
		tracef("structured pinned endpoint %s failed for %s: %v (falling back to discovery)", pin.Endpoint, conversationID, err)
		a.invalidateConvEndpoint(conversationID)
	}
	for _, pinEndpoint := range a.originatingServerCandidates(sessionPath, conversationID) {
		res, err := invokeBridgeStructuredFromWSLPinned(ctx, conversationID, timeout, bridgePin{Endpoint: pinEndpoint})
		if err == nil {
			a.rememberConvEndpoint(conversationID, res.HitEndpoint, res.HitCSRF)
			tracef("structured originating-server pin %s OK for %s", pinEndpoint, conversationID)
			return res.Stdout, nil
		}
		tracef("structured originating-server pin %s failed for %s: %v", pinEndpoint, conversationID, err)
	}
	res, err := invokeBridgeStructuredFromWSLPinned(ctx, conversationID, bridgeColdCallTimeout, bridgePin{})
	if err != nil {
		return nil, err
	}
	a.rememberConvEndpoint(conversationID, res.HitEndpoint, res.HitCSRF)
	return res.Stdout, nil
}

// originatingServerCandidates returns the log-derived endpoint URLs
// to try for this conversation. Returns nil for non-CLI sessionPath
// (no cli-*.log dir on desktop / unknown layouts) or when no log
// scan turned up the originating PID — both safe no-ops because the
// caller falls through to the existing cold-cache fan-out.
func (a *Adapter) originatingServerCandidates(sessionPath, conversationID string) []string {
	if classifyLayout(sessionPath) != LayoutCLI {
		return nil
	}
	cliRoot, _ := cliRootsFor(sessionPath)
	if cliRoot == "" {
		return nil
	}
	srv, ok := a.lookupOriginatingServer(cliRoot, conversationID)
	if !ok {
		return nil
	}
	return srv.EndpointCandidates()
}

// numEvents returns the total ToolEvent + TokenEvent count for a
// ParseResult. Retained for backwards compatibility; the per-loop
// stub guard now uses isWrongWorkspaceStub on the structured
// enrichment directly (see below for why).
func numEvents(res adapter.ParseResult) int {
	return len(res.ToolEvents) + len(res.TokenEvents)
}

// isWrongWorkspaceStub returns true when a structured-trajectory
// response carries no semantic payload — no model name, no per-turn
// token rows, no tool events. This is the wire signature of an
// Antigravity language_server that doesn't host the requested
// conversation: it returns a syntactically-valid but content-empty
// response (e.g. 430 KiB of envelope with zero `1.3` per-turn
// entries).
//
// Why this matters: the previous guard at the iteration sites
// checked `numEvents(res) == 0` on the MERGED result (markdown
// extraction + structured enrichment). But ConvertTrajectoryToMarkdown
// against a wrong-workspace server returns a tiny stub markdown
// (e.g. 244 bytes) that still parses as one user_prompt event, so
// numEvents = 1 and the guard never fired — the wrong server's
// stub was accepted as real and the correct server (with the actual
// token data) was never tried. The maintainer's e371fdb1 session
// surfaced this 2026-05-19: pid=1339 had wrong workspace and returned
// the stub; pid=1340 had the real 17-turn / 2,700+ token data.
//
// Treating the structured payload as the authoritative "is this a
// real response" signal eliminates the misclassification — a server
// that hosts the conversation always populates at least the model
// name (verified across the live corpus's 122 working sessions).
func isWrongWorkspaceStub(en StructuredEnrichment) bool {
	return en.Model == "" && len(en.TokenEvents) == 0 && len(en.ToolEvents) == 0
}

// resolveWorkspaceIDToPathCached looks up wsID in the adapter's cache;
// on miss, walks crossmount.AllHomes() roots via resolveWorkspaceIDToPath
// and stores the result (including empty-string misses, so subsequent
// lookups don't re-walk the FS for the same workspace_id).
//
// Used by recoverViaLocalGRPC to recover a project root for live
// in-progress conversations that aren't yet indexed in
// trajectorySummaries: the language_server has the workspace_id in
// its --workspace_id flag, and inverting that encoding by walking
// candidate home roots gives us a usable project path until
// Antigravity flushes the next checkpoint.
func (a *Adapter) resolveWorkspaceIDToPathCached(wsID string) string {
	if wsID == "" {
		return ""
	}
	a.wsResolveMu.Lock()
	defer a.wsResolveMu.Unlock()
	if a.wsResolveCache == nil {
		a.wsResolveCache = make(map[string]string)
	}
	if p, ok := a.wsResolveCache[wsID]; ok {
		return p
	}
	roots := make([]string, 0)
	for _, h := range crossmount.AllHomes() {
		if h.Path != "" {
			roots = append(roots, h.Path)
		}
	}
	resolved := resolveWorkspaceIDToPath(wsID, roots, 4)
	a.wsResolveCache[wsID] = resolved
	return resolved
}

// applyResolvedProjectRoot rewrites every ToolEvent/TokenEvent's
// ProjectRoot from the placeholder "[antigravity]" (or empty) to the
// resolved real path. Called from recoverViaLocalGRPC when idxEntry
// was nil but the language_server's workspace_id resolved to a real
// directory.
func applyResolvedProjectRoot(res *adapter.ParseResult, resolved string) {
	if resolved == "" {
		return
	}
	for i := range res.ToolEvents {
		if res.ToolEvents[i].ProjectRoot == "" || res.ToolEvents[i].ProjectRoot == "[antigravity]" {
			res.ToolEvents[i].ProjectRoot = resolved
		}
	}
	for i := range res.TokenEvents {
		if res.TokenEvents[i].ProjectRoot == "" || res.TokenEvents[i].ProjectRoot == "[antigravity]" {
			res.TokenEvents[i].ProjectRoot = resolved
		}
	}
}

// fetchStructuredEnrichmentWSL pulls the GetCascadeTrajectory payload
// via the Windows-side bridge and parses it. Errors are swallowed
// (logged as a trace line); callers must treat the returned
// enrichment as opportunistic.
//
// Phase 2 of docs/plans/antigravity-token-coverage-design-2026-05-24.md
// wires the snapshot reconciler in here. On bridge success the new
// payload is reconciled against any cached snapshot — whichever
// yields more TokenEvents wins; the loser is discarded. On bridge
// failure (originating agy.exe terminated, no live instance has
// this conv) we fall back to the snapshot when one exists so token
// rows that were ever captured stay visible across the gap.
func (a *Adapter) fetchStructuredEnrichmentWSL(ctx context.Context, conversationID, projectRoot, gitRemote, path string) StructuredEnrichment {
	raw, err := a.callBridgeStructuredCached(ctx, conversationID, path, 30*time.Second)
	if err != nil {
		tracef("structured bridge err: %v", err)
		if cached, ok := a.loadSnapshotEnrichment(conversationID, projectRoot, gitRemote, path); ok {
			return cached
		}
		return StructuredEnrichment{}
	}
	tracef("structured bridge OK (%d bytes)", len(raw))
	return a.reconcileWithSnapshot(conversationID, projectRoot, gitRemote, path, raw)
}

// fetchStructuredEnrichmentNativeAt is the endpoint-explicit variant
// of fetchStructuredEnrichmentNative. Callers that already iterated
// ls.Endpoints() to find a working URL pass it through here so the
// structured-trajectory call lands on the same endpoint that just
// succeeded for ConvertTrajectoryToMarkdown — avoids re-iterating
// failing protocols.
func (a *Adapter) fetchStructuredEnrichmentNativeAt(ctx context.Context, ls LanguageServer, endpoint, conversationID, projectRoot, gitRemote, path string) StructuredEnrichment {
	if endpoint == "" {
		return StructuredEnrichment{}
	}
	raw, err := callGetCascadeTrajectory(ctx, endpoint, ls.CSRFToken, conversationID, 30*time.Second)
	if err != nil {
		tracef("structured grpc pid=%d %s err: %v", ls.PID, endpoint, err)
		// Phase 2 snapshot fallback (same rationale as
		// fetchStructuredEnrichmentWSL): when the live gRPC call fails
		// — typically because the originating language_server has
		// terminated — surface the last successfully captured
		// trajectory so token rows persist across the gap.
		if cached, ok := a.loadSnapshotEnrichment(conversationID, projectRoot, gitRemote, path); ok {
			return cached
		}
		return StructuredEnrichment{}
	}
	en := a.reconcileWithSnapshot(conversationID, projectRoot, gitRemote, path, raw)
	tracef("structured grpc pid=%d %s OK (%d bytes, %d tools, %d tokens, model=%q)",
		ls.PID, endpoint, len(raw), len(en.ToolEvents), len(en.TokenEvents), en.Model)
	// Wire-shape mismatch warning (Issue #5). When the gRPC response
	// is non-trivial (≥ 10 KiB) but ParseStructuredTrajectory yields
	// zero token rows AND no model, the proto path mapping
	// (structured.go:122 et al.) likely doesn't match this response's
	// shape — newer Antigravity versions may have migrated fields,
	// or claude-vs-gemini variants may diverge on rare turns.
	// Verified case: maintainer session e371fdb1-… returned 430,202
	// bytes but extracted 0 tokens / model="". Surface as a tracef
	// so it shows up in observer logs without flooding successful
	// sessions; an operator can grep for "structured_shape_mismatch"
	// to find candidates for proto-path investigation.
	if len(raw) >= 10*1024 && len(en.TokenEvents) == 0 && en.Model == "" {
		tracef("structured_shape_mismatch pid=%d %s conversation=%s payload=%d_bytes — proto path mapping may need updating",
			ls.PID, endpoint, conversationID, len(raw))
		// Optional debug dump (Issue #5 follow-up). Operator sets
		// [observer.antigravity] dump_shape_mismatches_dir in
		// config.toml; on mismatch we write the raw bytes for
		// offline proto-path analysis. Soft-fail — a dump error
		// must not poison the extraction path (which has already
		// succeeded as a no-op).
		a.dumpShapeMismatchPayload(conversationID, raw)
	}
	return en
}

// dumpShapeMismatchPayload writes the raw GetCascadeTrajectory bytes
// to <dumpDir>/<conversationID>.bin so the operator can diff the wire
// shape between a known-working and known-broken session. No-op when
// the dump dir isn't configured. Issue #5 follow-up.
func (a *Adapter) dumpShapeMismatchPayload(conversationID string, raw []byte) {
	if a.dumpShapeMismatchesDir == "" || conversationID == "" || len(raw) == 0 {
		return
	}
	if err := os.MkdirAll(a.dumpShapeMismatchesDir, 0o755); err != nil {
		tracef("dump_shape_mismatch_mkdir_err dir=%s err=%v", a.dumpShapeMismatchesDir, err)
		return
	}
	out := filepath.Join(a.dumpShapeMismatchesDir, conversationID+".bin")
	if err := os.WriteFile(out, raw, 0o600); err != nil {
		tracef("dump_shape_mismatch_write_err path=%s err=%v", out, err)
		return
	}
	tracef("dump_shape_mismatch_written path=%s bytes=%d", out, len(raw))
}

// hasStructuredUserPrompts returns true when the structured
// enrichment surfaced at least one user_prompt ToolEvent (Tier 2
// extraction from 1.2.19.2). Caller uses this to decide whether to
// suppress markdown's `### User Input` rows so the same prompt
// doesn't land twice.
func hasStructuredUserPrompts(events []models.ToolEvent) bool {
	for _, e := range events {
		if e.RawToolName == "structured.user_prompt" {
			return true
		}
	}
	return false
}

// structuredAssistantTextCoverage returns the fraction of
// per-LLM-call token rows that have a corresponding
// `structured.assistant_text` ToolEvent. Used to decide whether
// markdown's `### Planner Response` rows can be safely suppressed:
// claude sessions hit ~58% coverage (15/26 on FB48) so dedup is
// safe; gemini sessions can drop to 2% (3/130 on 803add5e) where
// suppressing markdown loses 90%+ of the assistant narrative. The
// 0.5 cutoff in callers separates the two regimes.
func structuredAssistantTextCoverage(en StructuredEnrichment) float64 {
	if len(en.TokenEvents) == 0 {
		return 0
	}
	count := 0
	for _, e := range en.ToolEvents {
		if e.RawToolName == "structured.assistant_text" {
			count++
		}
	}
	return float64(count) / float64(len(en.TokenEvents))
}

// AssistantTextCoverageThreshold gates markdown.planner_response
// dedup. Below this fraction, structured assistant_text is sparse
// enough that markdown carries strictly more content and must be
// preserved. At/above, structured is authoritative and markdown is
// safely suppressed. Centralised so the live adapter and the
// backfill stay in lockstep.
const AssistantTextCoverageThreshold = 0.5

// applyStructuredEnrichment overlays model + per-turn token rows +
// per-step file-view tool rows on top of the markdown-derived
// ParseResult. Mutates res in place.
//
// Model attribution: we set Model on every emitted ToolEvent so the
// store layer's UpsertSession (called for the FIRST event of a new
// session) writes it into sessions.model. For sessions whose row
// already exists with model="" (re-ingest case), this still has no
// effect — that case is handled by the backfill mode which UPDATEs
// sessions.model directly.
//
// Structured tool events use a different SourceEventID prefix
// (`antigravity-struct-tool:`) than markdown inline-tool events
// (`antigravity-md-tool:` via stableMarkdownID), so the (source_file,
// source_event_id) UNIQUE constraint lets both coexist. The
// structured events carry real per-step timestamps + duration_ms +
// MessageIDs that join to the parent token row, so they're more
// useful for the dashboard's chronological view; markdown inline
// tools remain as a fallback for sessions where structured fetch
// fails.
func applyStructuredEnrichment(res *adapter.ParseResult, en StructuredEnrichment) {
	if en.Model != "" {
		for i := range res.ToolEvents {
			if res.ToolEvents[i].Model == "" {
				res.ToolEvents[i].Model = en.Model
			}
		}
	}
	if len(en.TokenEvents) > 0 {
		res.TokenEvents = append(res.TokenEvents, en.TokenEvents...)
	}
	if len(en.ToolEvents) > 0 {
		res.ToolEvents = append(res.ToolEvents, en.ToolEvents...)
	}
}

// tracef writes a verbose diagnostic line to stderr (the terminal).
// Kept separate from ParseResult.Warnings so the dashboard log panel
// stays light — heavy per-file traces stream to the terminal only.
// Format: `antigravity: <message>` so it's grep-able alongside slog
// output.
func tracef(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "antigravity: "+format+"\n", args...)
}

// discoverLanguageServersCached refreshes a in-memory cache of
// running language_server processes at most once every 30s. The
// underlying discovery shells out (PowerShell on WSL2; ps/lsof on
// macOS) and is too expensive to run per file.
func (a *Adapter) discoverLanguageServersCached() ([]LanguageServer, error) {
	a.lsMu.Lock()
	defer a.lsMu.Unlock()
	now := time.Now().UnixNano()
	if now < a.lsCacheValidUntil {
		return a.lsCache, nil
	}
	servers, err := discoverLanguageServers()
	if err != nil {
		return nil, err
	}
	a.lsCache = servers
	a.lsCacheValidUntil = now + int64(30*time.Second)
	return servers, nil
}

// lookupSecret returns the cached OSCrypt secret, fetching it on
// first call. Errors are also cached for the process lifetime —
// retrying a failed secret lookup on every file is expensive and
// usually pointless (keychain is unlocked once per session).
func (a *Adapter) lookupSecret() (oscrypt.Secret, error) {
	a.secretMu.Lock()
	defer a.secretMu.Unlock()
	if a.secret != nil {
		return a.secret, nil
	}
	if a.secretErr != nil {
		return nil, a.secretErr
	}
	cfg := oscrypt.AppKeyConfig{
		AppName:                "Antigravity",
		KeychainAccounts:       []string{"Antigravity Key", "Antigravity"},
		LinuxFallbackToPeanuts: true,
	}
	secret, err := oscrypt.RetrieveSecret(cfg)
	if err != nil {
		a.secretErr = err
		return nil, err
	}
	a.secret = secret
	return secret, nil
}

// uuidFromFilename returns the UUID portion of a conversations/<uuid>.pb
// path. Used as a stable identifier across sessions for the same
// conversation and as the join key against the state.vscdb index.
//
// Handles both native and foreign-OS path separators so the matcher
// works regardless of host OS (a Windows path like
// `C:\Users\u\.gemini\antigravity\conversations\X.pb` parsed on
// Linux still yields "X").
func uuidFromFilename(path string) string {
	normalized := strings.ReplaceAll(path, `\`, "/")
	base := filepath.Base(normalized)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// contentHash returns a stable per-event id derived from the
// session file path and an offset/marker. Used when we synthesize
// SourceEventIDs from heuristic-extracted text without a natural
// ID anchor in the proto.
func contentHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// defaultRoots returns the session-file directories for every
// Antigravity layout (desktop + CLI) under every cross-mount-resolved
// $HOME. Observer in WSL2 picks up Antigravity data on
// /mnt/c/Users/<u>/.gemini (and vice versa); the CLI shape uses the
// `antigravity-cli` subdir. The desktop layout has TWO roots: the
// encrypted conversations/ store and the plaintext brain/ tree that
// holds the per-conversation transcript.jsonl (LayoutDesktopTranscript).
func defaultRoots() []string {
	var roots []string
	for _, h := range crossmount.AllHomes() {
		roots = append(
			roots,
			filepath.Join(h.Path, ".gemini", "antigravity", "conversations"),
			filepath.Join(h.Path, ".gemini", "antigravity", "brain"),
			filepath.Join(h.Path, ".gemini", "antigravity-cli", "conversations"),
			filepath.Join(h.Path, ".gemini", "antigravity-acp", "conversations"),
		)
	}
	return roots
}

// defaultRootsForLayout returns the session-file directories for a
// specific Antigravity layout ("desktop" or "cli") under every
// cross-mount-resolved $HOME. "desktop" yields conversations/ AND
// brain/ (see defaultRoots).
func defaultRootsForLayout(layout string) []string {
	var roots []string
	for _, h := range crossmount.AllHomes() {
		if layout == "desktop" {
			roots = append(roots,
				filepath.Join(h.Path, ".gemini", "antigravity", "conversations"),
				filepath.Join(h.Path, ".gemini", "antigravity", "brain"),
			)
		} else {
			roots = append(roots,
				filepath.Join(h.Path, ".gemini", "antigravity-cli", "conversations"),
				// The JetBrains AI Assistant "antigravity-acp" agent drives
				// the agy backend but writes a THIRD tree with the same
				// plaintext-protobuf .db schema (grounded 2026-09-04:
				// trajectory_meta.cascade_id == the conversation uuid ==
				// the ACP pointer sid; source=0). Classified LayoutCLIDB.
				filepath.Join(h.Path, ".gemini", "antigravity-acp", "conversations"),
			)
		}
	}
	return roots
}

// _ keeps errors importable when the package is built standalone.
var _ = errors.New
