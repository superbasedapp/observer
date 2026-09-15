package aider

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// historyFileName is the canonical Aider chat-transcript basename. Aider
// keeps one such file per git repository at the repo root.
const historyFileName = ".aider.chat.history.md"

// Adapter parses Aider's per-repo Markdown transcript
// (.aider.chat.history.md). Aider has no central session directory nor a
// global project index, so the watch roots are discovered by a bounded
// filesystem walk of the native home (see discover.go). Roots are the
// transcript FILE paths themselves, keeping the watch set disjoint from
// project-local adapters (e.g. crush) sharing the same repos.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// cachedDiscoveredRoots memoizes the discovery walk for the process
// lifetime: defaults.Adapters() is constructed many times per process
// (watcher build, dashboard health predicate, tests) and the walk must
// not be re-paid on each construction. Tests exercise discoverRoots()
// directly and are unaffected.
var (
	discoverOnce    sync.Once
	discoveredRoots []string
)

func cachedDiscoveredRoots() []string {
	discoverOnce.Do(func() { discoveredRoots = discoverRoots() })
	return discoveredRoots
}

// New returns an adapter whose watch roots are discovered from the
// filesystem (bounded walk of the NATIVE home for .aider.chat.history.md
// files, plus any AIDER_CHAT_HISTORY_FILE override). Discovery runs once
// per process; the result is cached.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: cachedDiscoveredRoots()}
}

// NewWithOptions customizes the scrubber and/or watch roots. A nil
// scrubber falls back to the default. When roots is non-empty, discovery
// is SKIPPED and the supplied roots are used verbatim — this is the seam
// tests and any future root-provider (e.g. the store's known project
// roots) use to avoid the filesystem walk. Injected roots may be either
// transcript file paths or repo directories.
func NewWithOptions(s *scrub.Scrubber, roots []string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = cachedDiscoveredRoots()
	}
	return &Adapter{scrubber: s, roots: roots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolAider }

// WatchPaths implements adapter.Adapter. The roots are a snapshot taken at
// first construction: the .aider.chat.history.md FILE paths discovered in
// the native home (plus AIDER_CHAT_HISTORY_FILE when set). A repo that
// gains its FIRST aider session AFTER the daemon started is not watched
// until the next daemon restart or an `observer scan`/`observer backfill`
// run — Aider exposes no central directory or index the watcher could
// cover, and this package does not reach into the watcher to re-derive
// roots dynamically. See docs/aider-adapter.md for the recommended
// shared-seam fix.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Matches a file named exactly
// .aider.chat.history.md under (or equal to) one of the watch roots, or a
// path exactly equal to an explicitly-configured root even when its
// basename differs (AIDER_CHAT_HISTORY_FILE allows a custom name). The
// sibling .aider.input.history and the .aider.tags.cache.v4/ repo-map
// cache are deliberately NOT matched.
func (a *Adapter) IsSessionFile(path string) bool {
	if !adapter.UnderAnyWatchRoot(path, a.roots) {
		return false
	}
	if strings.EqualFold(filepath.Base(path), historyFileName) {
		return true
	}
	clean := filepath.Clean(path)
	for _, r := range a.roots {
		if strings.EqualFold(clean, filepath.Clean(r)) {
			return true
		}
	}
	return false
}

// ParseSessionFile implements adapter.Adapter. Aider's transcript is an
// append-only Markdown file whose per-turn context (session header, model)
// lives positionally ABOVE each turn, so a mid-file byte resume would lose
// the owning session. The parser therefore re-reads the WHOLE file on
// every call and watermarks only on file size: when fromOffset already
// equals (or exceeds) the current size, nothing has been appended and the
// call returns immediately. Every emitted event carries a deterministic
// (sessionKey, sequence)-derived SourceEventID, so a full re-parse is
// idempotent at the store's (source_file, source_event_id) dedup key.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return adapter.ParseResult{NewOffset: fromOffset}, nil
	}
	size := info.Size()
	if size <= fromOffset {
		// Nothing appended since the last parse.
		return adapter.ParseResult{NewOffset: fromOffset}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return adapter.ParseResult{NewOffset: fromOffset}, nil
	}

	projectRoot, gitRemote, projectIdentity := a.resolveProjectRoot(path)
	tools, tokens := a.parseTranscript(ctx, data, path, projectRoot, gitRemote)

	res := adapter.ParseResult{
		ToolEvents:  tools,
		TokenEvents: tokens,
		NewOffset:   int64(len(data)),
	}
	adapter.ApplyProjectIdentity(&res, projectIdentity)
	return res, nil
}

// resolveProjectRoot turns the transcript path into a stable project root.
// The file lives AT the git repo root, so the project is the transcript's
// own directory. Foreign-mount (Windows) paths are translated to their
// /mnt/c equivalent and stat-gated before git.Resolve, so a Windows-side
// repo doesn't misfile under the observer's own repo.
// Returns (root, gitRemote); gitRemote is "" when the directory isn't
// inside a git repo.
func (a *Adapter) resolveProjectRoot(path string) (root, gitRemote string, id git.Identity) {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." || dir == string(filepath.Separator) {
		return "[aider]", "", git.Identity{}
	}
	if translated := crossmount.TranslateForeignPath(dir); translated != dir {
		if _, err := os.Stat(translated); err == nil {
			dir = translated
		}
	}
	identity, err := git.ResolveIdentity(dir, git.IdentityOptions{})
	if err != nil {
		return dir, "", git.Identity{}
	}
	// identity.Remote is already NormalizeRemote'd by ResolveIdentity.
	return identity.Root, identity.Remote, identity
}

// scrub applies the plaintext scrubber, tolerating a nil scrubber.
func (a *Adapter) scrub(v string) string {
	if a.scrubber == nil {
		return v
	}
	return a.scrubber.String(v)
}
