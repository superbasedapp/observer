package index

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse"
	"github.com/marmutapp/superbased-observer/internal/codeintel/semantic"
)

// Options configures an Indexer. The CLI/daemon maps [codeintel] config
// onto this at the boundary so the index package never imports
// internal/config (keeps the orchestrator config-shape-agnostic).
type Options struct {
	Store    codeintel.IndexStore
	Registry *parse.Registry
	// Languages, when non-empty, gates which languages are indexed
	// (subset of the registry). Empty = every registered language.
	Languages []codeintel.Language
	// MaxFileBytes skips files larger than this (0 = a 2 MiB default).
	MaxFileBytes int64
	// AutoIndexLimit consent-gates a NEW project whose candidate file
	// count exceeds it (0 = a 25,000 default). Explicit indexing
	// (force=true) bypasses the gate — the developer has consented.
	AutoIndexLimit int
	// ExtraIgnoreDirs are directory basenames to skip in addition to
	// the built-in set.
	ExtraIgnoreDirs []string
	// IgnoreRoots are project-root path prefixes the auto-indexer must
	// never index: a project at or under any of these is skipped when
	// force=false. Explicit indexing (force=true) bypasses them. Fed
	// from [codeintel].ignore_paths at the boundary.
	IgnoreRoots []string
	Logger      *slog.Logger
}

const (
	defaultMaxFileBytes   = 2 << 20 // 2 MiB
	defaultAutoIndexLimit = 25000
)

// defaultIgnoreDirs are directory basenames never walked. Source-tree
// indexing has different ignore needs than session-file ingestion, so
// this list is owned here (plan D9) rather than shared.
var defaultIgnoreDirs = map[string]struct{}{
	".git": {}, "node_modules": {}, "vendor": {}, ".venv": {}, "venv": {},
	"__pycache__": {}, "dist": {}, "build": {}, "target": {}, ".next": {},
	".idea": {}, ".vscode": {}, ".observer": {}, "bin": {}, "obj": {},
	".gradle": {}, ".cache": {}, ".gomodcache": {}, "testdata": {},
}

// Indexer walks a project's source tree and persists symbols through the
// store seam. It is codeintel's single writer (CLAUDE.md "one owner per
// table") and runs only at index time — never on the proxy hot path
// (ADR-0002).
type Indexer struct {
	opts   Options
	logger *slog.Logger
}

// Report summarizes one IndexProject pass.
type Report struct {
	Project      string
	Scanned      int  // candidate source files seen
	Indexed      int  // files (re)parsed and saved
	Unchanged    int  // skipped — content hash matched an indexed row
	Skipped      int  // skipped — too large / unreadable
	Failed       int  // parse/save errors
	NeedsConsent bool // candidate count exceeded AutoIndexLimit and force=false
	Ignored      bool // skipped — root is in [codeintel].ignore_paths (force=false)
	// StatFresh counts the subset of Unchanged that was resolved from the
	// stored mtime alone — the file was never opened or hashed this pass.
	StatFresh int
	// DerivedBuilt records that the (expensive, whole-project) FTS /
	// embedding rebuild ran this pass.
	DerivedBuilt bool
	// DerivedSkipped records that the rebuild was SKIPPED because the pass
	// changed no file and the derived rows already exist.
	DerivedSkipped bool
}

// New builds an Indexer, applying defaults.
func New(opts Options) *Indexer {
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = defaultMaxFileBytes
	}
	if opts.AutoIndexLimit <= 0 {
		opts.AutoIndexLimit = defaultAutoIndexLimit
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}
	return &Indexer{opts: opts, logger: opts.Logger}
}

// IndexProject indexes (or incrementally re-indexes) the source tree
// rooted at root. The project key is the absolute root path. When
// force is false and the project is new and larger than AutoIndexLimit,
// it returns Report{NeedsConsent:true} WITHOUT indexing (the §5b.4 DX
// guardrail); explicit `observer index <path>` passes force=true.
func (ix *Indexer) IndexProject(ctx context.Context, root string, force bool) (Report, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return Report{}, fmt.Errorf("index.IndexProject: abs %q: %w", root, err)
	}
	rep := Report{Project: absRoot}

	// Pathological-root guard: never AUTO-index a filesystem/drive root or a
	// user home directory / home container. These become project roots when a
	// session's project_root resolves to the home dir (e.g. a cursor/other
	// session with no git root); auto-indexing them walks the whole tree —
	// the /mnt/c/Users/<user> 384K-file bloat. An explicit `observer index`
	// (force=true) bypasses this: that's operator consent. The guard runs
	// BEFORE collectCandidates so a blocked root is neither walked nor
	// registered (the consent path below would otherwise persist a file row
	// per candidate).
	if !force && isAutoIndexBlocked(absRoot) {
		rep.NeedsConsent = true
		ix.logger.Info("codeintel: skipping auto-index of a home/root path (would walk the whole tree); run `observer index` to override",
			"project", absRoot)
		return rep, nil
	}

	// User-configured ignore list ([codeintel].ignore_paths): a project at
	// or under an ignored root is never AUTO-indexed. Runs before the walk
	// so nothing is registered. Explicit `observer index` (force=true)
	// bypasses this — the developer is asking for it directly.
	if !force && IsIgnored(absRoot, ix.opts.IgnoreRoots) {
		rep.Ignored = true
		ix.logger.Info("codeintel: skipping ignored project (in [codeintel].ignore_paths)",
			"project", absRoot)
		return rep, nil
	}

	candidates, err := ix.collectCandidates(absRoot)
	if err != nil {
		return rep, err
	}
	rep.Scanned = len(candidates)

	if !force && len(candidates) > ix.opts.AutoIndexLimit {
		// Consent gate: register the files as needs_consent so
		// `index status` shows the project, but index nothing.
		for _, c := range candidates {
			_ = ix.opts.Store.CodeIntelRegisterFile(ctx, absRoot, c.path, string(c.lang))
			_ = ix.opts.Store.CodeIntelSetFileStatus(ctx, absRoot, c.path, "needs_consent")
		}
		rep.NeedsConsent = true
		ix.logger.Info("codeintel: project exceeds auto_index_limit; awaiting consent",
			"project", absRoot, "files", len(candidates), "limit", ix.opts.AutoIndexLimit)
		return rep, nil
	}

	for _, c := range candidates {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		outcome, statOnly := ix.indexFile(ctx, absRoot, c)
		switch outcome {
		case outcomeIndexed:
			rep.Indexed++
		case outcomeUnchanged:
			rep.Unchanged++
			if statOnly {
				rep.StatFresh++
			}
		case outcomeSkipped:
			rep.Skipped++
		case outcomeFailed:
			rep.Failed++
		}
	}
	// Project-level name-matched CALLS resolution sweep — fills in the
	// cross-file forward references left unresolved at file-save time.
	// Only worth running when something was (re)indexed this pass.
	if rep.Indexed > 0 {
		if resolved, err := ix.opts.Store.CodeIntelResolveCalls(ctx, absRoot); err != nil {
			ix.logger.Warn("codeintel: call resolution failed", "project", absRoot, "err", err)
		} else {
			ix.logger.Debug("codeintel: resolved calls", "project", absRoot, "edges", resolved)
		}
		// Scoped upgrade pass (W2): bind bare/qualified calls within their
		// package/imports for languages with a scope rule set (Go today),
		// fixing cross-package over-link. Best-effort — a failure leaves the
		// name-matched edges intact.
		if upgraded, err := ix.opts.Store.CodeIntelResolveScoped(ctx, absRoot); err != nil {
			ix.logger.Warn("codeintel: scoped resolution failed", "project", absRoot, "err", err)
		} else {
			ix.logger.Debug("codeintel: scoped-upgraded calls", "project", absRoot, "edges", upgraded)
		}
	}
	// Tier C (Phase 6): rebuild the project's FTS / embedding rows from
	// the now-current nodes. This is a whole-project DELETE-then-reinsert
	// over an fts5 table — on a large project it dominates the cost of the
	// entire pass, so it runs only when it can change something:
	//
	//   - a file was (re)indexed this pass  -> rebuild (nodes moved)
	//   - nothing changed, derived rows present -> SKIP (the common
	//     `observer start` case: every boot re-walks every known project)
	//   - nothing changed, derived rows MISSING -> rebuild anyway, so a
	//     project whose derived rows were never built still self-heals
	//     instead of being locked out by the skip.
	//
	// The probe itself is a single rowid lookup (store.CodeIntelHasDerived);
	// a probe error falls through to rebuilding, never to skipping.
	ix.maybeBuildDerived(ctx, absRoot, &rep)
	ix.logger.Info("codeintel: indexed project",
		"project", absRoot, "indexed", rep.Indexed, "unchanged", rep.Unchanged,
		"stat_fresh", rep.StatFresh, "skipped", rep.Skipped, "failed", rep.Failed,
		"derived_rebuilt", rep.DerivedBuilt)
	return rep, nil
}

// maybeBuildDerived applies the change gate described at its call site and
// records the outcome on rep. Best-effort throughout: a failure leaves
// search/semantic degraded, it never aborts indexing.
func (ix *Indexer) maybeBuildDerived(ctx context.Context, project string, rep *Report) {
	if rep.Indexed == 0 {
		has, err := ix.opts.Store.CodeIntelHasDerived(ctx, project)
		if err != nil {
			ix.logger.Warn("codeintel: derived-rows probe failed; rebuilding", "project", project, "err", err)
		} else if has {
			rep.DerivedSkipped = true
			ix.logger.Debug("codeintel: no files changed and derived rows present — skipping search/semantic rebuild",
				"project", project, "unchanged", rep.Unchanged)
			return
		}
	}
	rep.DerivedBuilt = true
	if err := ix.opts.Store.CodeIntelBuildDerived(ctx, project); err != nil {
		ix.logger.Warn("codeintel: build derived (search/semantic) failed", "project", project, "err", err)
	}
}

// tempContainers are the shared scratch directories that are never a
// project in their own right. They are listed separately from the
// home/drive rules below because the reason differs: a temp root is not
// merely big, its contents CHURN — every build, every agent worktree,
// every editor swap file lands there, so an auto-index of the container
// finds changed files on literally every pass and re-runs the expensive
// whole-project derived rebuild forever. (Measured: `/tmp` adopted as a
// project root carried 110k files / 1.65M symbols and dominated
// index-on-start CPU.) A real project that happens to live UNDER a temp
// dir is unaffected — only the container itself is blocked.
var tempContainers = []string{"/tmp", "/var/tmp", "/dev/shm"}

// contentContainerNames are basenames of well-known user-content folders —
// Desktop, Downloads, Documents — that hold an arbitrarily wide fan-out of
// personal files, not a project. Adopting one directly as a project root has
// the same runaway-index shape as the temp-container case (measured:
// /mnt/c/Users/<user>/OneDrive/Desktop carried 2,090 files / 38k symbols,
// none of it a real project) even though the folder doesn't churn the way
// /tmp does. Matched case-insensitively; a real project living inside one
// (…/Desktop/myproject) is unaffected — only the container itself is
// blocked.
var contentContainerNames = map[string]bool{
	"desktop":   true,
	"downloads": true,
	"documents": true,
}

// isContentContainer reports whether segs (the '/'-split, non-empty path
// segments of an already-cleaned root) name a well-known user-content
// container directly under a home directory, in any shape codeintel sees
// roots arrive in:
//   - native home:      /home/<user>/Desktop, /Users/<user>/Desktop
//   - WSL drive mount:   /mnt/<drive>/Users/<user>/Desktop
//   - OneDrive redirect: …/<user>/OneDrive/Desktop (native or WSL-mounted;
//     OneDrive syncs Desktop/Downloads/Documents under itself on both
//     Windows and WSL-visible paths)
//
// The home/Users marker is required (rather than blocking any folder named
// "Desktop" anywhere) so a real project subdirectory that happens to share
// the name is never caught.
func isContentContainer(segs []string) bool {
	n := len(segs)
	if n < 2 || !contentContainerNames[strings.ToLower(segs[n-1])] {
		return false
	}
	// …/OneDrive/Desktop, in any mount shape — OneDrive is unambiguous on
	// its own, no Users/home marker needed above it.
	if strings.ToLower(segs[n-2]) == "onedrive" {
		return true
	}
	// …/Users/<name>/Desktop or …/home/<name>/Desktop, native or WSL-mounted.
	if n >= 3 {
		switch strings.ToLower(segs[n-3]) {
		case "users", "home":
			return true
		}
	}
	return false
}

// isAutoIndexBlocked reports whether a project root is one codeintel must not
// AUTO-index because walking it enumerates a whole home/drive/scratch/
// content tree: a filesystem root, the daemon's own home directory, a WSL
// drive mount (/mnt/<drive>), a home container whose parent segment is
// "Users"/"home" (…/Users/<name>, …/home/<name>), a system temp container
// (/tmp, /var/tmp, /dev/shm, os.TempDir()), or a well-known user-content
// container — Desktop, Downloads, Documents, and their OneDrive-redirected
// forms — directly under a home directory (see isContentContainer). A deeper
// folder under one of these (e.g. …/Users/<name>/OneDrive/Desktop/project,
// /tmp/my-scratch-repo) is NOT blocked — only the container itself. Explicit
// `observer index` (force=true) bypasses this.
func isAutoIndexBlocked(root string) bool {
	clean := filepath.Clean(root)
	if clean == "" || clean == "." || clean == string(filepath.Separator) {
		return true
	}
	if home, err := os.UserHomeDir(); err == nil && filepath.Clean(home) == clean {
		return true
	}
	if tmp := filepath.Clean(os.TempDir()); tmp != "" && tmp != "." && tmp == clean {
		return true
	}
	if slices.Contains(tempContainers, filepath.ToSlash(clean)) {
		return true
	}
	var segs []string
	for _, s := range strings.Split(filepath.ToSlash(clean), "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	n := len(segs)
	if n == 0 {
		return true // filesystem root
	}
	// WSL drive-mount root: /mnt/c, /mnt/d, …
	if n == 2 && segs[0] == "mnt" && len(segs[1]) <= 2 {
		return true
	}
	// Home container: the last segment is a user name directly under
	// Users/ or home/.
	if n >= 2 {
		switch strings.ToLower(segs[n-2]) {
		case "users", "home":
			return true
		}
	}
	// Well-known user-content container (Desktop/Downloads/Documents,
	// incl. OneDrive-redirected) directly under a home directory.
	if isContentContainer(segs) {
		return true
	}
	return false
}

// IsIgnored reports whether root is at or under any path in ignore. The
// match is on cleaned path boundaries, so an ignore entry "/a/b" covers
// "/a/b" and "/a/b/c" but never the sibling "/a/bc". Blank or "." ignore
// entries are skipped so a stray empty string never swallows the whole
// tree. Exported so the CLI can warn when an explicit `observer index`
// targets an ignored path (which force-indexes it anyway).
func IsIgnored(root string, ignore []string) bool {
	cleanRoot := filepath.Clean(root)
	for _, g := range ignore {
		cg := filepath.Clean(g)
		if cg == "" || cg == "." {
			continue
		}
		if cleanRoot == cg || strings.HasPrefix(cleanRoot, cg+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

type candidate struct {
	path string
	lang codeintel.Language
}

// collectCandidates walks the tree and returns every file with a
// supported, allow-listed extension, skipping ignored dirs and symlinks.
func (ix *Indexer) collectCandidates(absRoot string) ([]candidate, error) {
	var out []candidate
	walkErr := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable dir/file — skip it, don't abort the whole walk.
			return nil //nolint:nilerr // best-effort indexing
		}
		if d.IsDir() {
			if ix.ignoredDir(d.Name()) && path != absRoot {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // never follow symlinks (loop/escape safety)
		}
		lang, ok := parse.LanguageForPath(path)
		if !ok || !ix.langAllowed(lang) {
			return nil
		}
		out = append(out, candidate{path: path, lang: lang})
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("index.collectCandidates: walk %q: %w", absRoot, walkErr)
	}
	return out, nil
}

type indexOutcome int

const (
	outcomeIndexed indexOutcome = iota
	outcomeUnchanged
	outcomeSkipped
	outcomeFailed
)

func (ix *Indexer) indexFile(ctx context.Context, project string, c candidate) (indexOutcome, bool) {
	fi, err := os.Stat(c.path)
	if err != nil || fi.Size() > ix.opts.MaxFileBytes {
		return outcomeSkipped, false
	}

	prev, found, stateErr := ix.opts.Store.CodeIntelFileState(ctx, project, c.path)
	fresh := stateErr == nil && found && prev.Status == "indexed"

	// Stat-only fast path. Every known project is re-walked on every
	// `observer start`; without this, each pass opens and SHA-256s every
	// source file in the estate just to conclude nothing moved. An mtime
	// that still matches the one recorded at the last successful index
	// means the file has not been rewritten since — no read, no hash.
	//
	// The `prev.MTime < prev.IndexedAt` guard is git's racily-clean rule.
	// mtime is stored in whole seconds, so a file written twice inside the
	// second we indexed it would keep an mtime equal to the one we stored
	// while its content moved on. Requiring the recorded mtime to be
	// strictly OLDER than the index pass proves the file was already at
	// rest when we read it, which rules that race out. A file that fails
	// the guard just falls through to the hash comparison below — correct,
	// only not free.
	if fresh && prev.MTime > 0 && prev.MTime == fi.ModTime().Unix() && prev.MTime < prev.IndexedAt {
		return outcomeUnchanged, true
	}

	src, err := os.ReadFile(c.path)
	if err != nil {
		return outcomeSkipped, false
	}
	hash := hashBytes(src)

	// Incremental: an indexed row with the same content hash is fresh.
	if fresh && prev.ContentHash == hash {
		return outcomeUnchanged, false
	}

	parser, ok := ix.opts.Registry.For(c.lang)
	if !ok {
		return outcomeSkipped, false
	}
	_ = ix.opts.Store.CodeIntelSetFileStatus(ctx, project, c.path, "indexing")

	res, perr := parser.Parse(ctx, src, c.lang, c.path)
	if perr != nil && len(res.Nodes) == 0 {
		_ = ix.opts.Store.CodeIntelSetFileStatus(ctx, project, c.path, "failed")
		ix.logger.Debug("codeintel: parse failed", "file", c.path, "err", perr)
		return outcomeFailed, false
	}

	saveErr := ix.opts.Store.CodeIntelSaveFile(ctx, codeintel.FileResult{
		Project:     project,
		Path:        c.path,
		Lang:        c.lang,
		Parser:      res.Parser,
		ContentHash: hash,
		MTime:       fi.ModTime().Unix(),
		Nodes:       res.Nodes,
		Imports:     res.Imports,
		Calls:       res.Calls,
		BodyBuckets: bodyBuckets(src, res.Nodes),
	})
	if saveErr != nil {
		_ = ix.opts.Store.CodeIntelSetFileStatus(ctx, project, c.path, "failed")
		ix.logger.Warn("codeintel: save failed", "file", c.path, "err", saveErr)
		return outcomeFailed, false
	}
	return outcomeIndexed, false
}

func (ix *Indexer) ignoredDir(name string) bool {
	if _, ok := defaultIgnoreDirs[name]; ok {
		return true
	}
	return slices.Contains(ix.opts.ExtraIgnoreDirs, name)
}

func (ix *Indexer) langAllowed(lang codeintel.Language) bool {
	if len(ix.opts.Languages) == 0 {
		return true
	}
	return slices.Contains(ix.opts.Languages, lang)
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// bodyBuckets computes per-node body-shingle MinHash LSH buckets (W3
// near-clone) from the file content + each node's byte span. The body bytes
// stay HERE (only the band hashes are persisted, privacy). Returns a slice
// aligned with nodes; an entry is nil when the node has no usable byte span
// (so it contributes no clone signature).
func bodyBuckets(src []byte, nodes []codeintel.Node) [][]uint64 {
	if len(nodes) == 0 {
		return nil
	}
	out := make([][]uint64, len(nodes))
	for i, n := range nodes {
		if n.StartByte < 0 || n.EndByte <= n.StartByte || n.EndByte > len(src) {
			continue
		}
		out[i] = semantic.BodyShingleBuckets(string(src[n.StartByte:n.EndByte]))
	}
	return out
}
