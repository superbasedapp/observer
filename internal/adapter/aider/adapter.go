package aider

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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
	// roots is set only when the caller injected roots (NewWithOptions);
	// it is then used verbatim and never re-discovered.
	roots []string
	// disc, when non-nil, supplies the discovered roots (New, or
	// NewWithOptions without roots). Shared process-wide.
	disc *discovery
}

// rediscoverInterval is how old the discovered root set may get before the
// next WatchPaths call starts a background re-walk (T-706). The watcher's
// root re-detector calls WatchPaths every 30 s and hot-adds any new root,
// so a repo whose FIRST aider session starts after the daemon is up is
// watched within about this interval plus one detector tick.
const rediscoverInterval = 2 * time.Minute

// discovery memoizes the bounded discovery walk and refreshes it in the
// background. defaults.Adapters() is constructed many times per process
// (watcher build, dashboard health predicate, tests), so the walk must not
// be paid per construction, and WatchPaths sits on the watcher's poll path,
// so a stale set must never make a caller wait for a walk: the first call
// walks synchronously (the startup behaviour this package always had), and
// every later stale call returns the current set at once and starts at most
// one background re-walk.
type discovery struct {
	walk     func() []string
	now      func() time.Time
	spawn    func(func())
	interval time.Duration

	mu      sync.Mutex
	roots   []string
	at      time.Time
	done    bool
	running bool
	// background makes the first call return the empty set at once and run
	// the first walk in the background (ConfigureDiscovery, D-MU1): the
	// daemon's listeners must never wait on a home walk, which on macOS can
	// block indefinitely on a privacy prompt.
	background bool
}

func (d *discovery) setBackground(on bool) {
	d.mu.Lock()
	d.background = on
	d.mu.Unlock()
}

// current returns the discovered roots, walking synchronously on first use
// (or, in background mode, starting the first walk and returning at once)
// and refreshing in the background once the set is older than interval.
func (d *discovery) current() []string {
	d.mu.Lock()
	if !d.done && d.background {
		out := d.roots
		if !d.running {
			d.running = true
			d.spawn(d.refresh)
		}
		d.mu.Unlock()
		return out
	}
	if !d.done {
		d.roots = d.walk()
		d.at = d.now()
		d.done = true
		out := d.roots
		d.mu.Unlock()
		return out
	}
	out := d.roots
	if !d.running && d.now().Sub(d.at) >= d.interval {
		d.running = true
		d.spawn(d.refresh)
	}
	d.mu.Unlock()
	return out
}

// refresh re-walks and swaps the root set in. The walk runs without the
// lock so concurrent WatchPaths calls keep returning the previous set.
func (d *discovery) refresh() {
	roots := d.walk()
	d.mu.Lock()
	d.roots = roots
	d.at = d.now()
	d.done = true
	d.running = false
	d.mu.Unlock()
}

// sharedDiscovery is the process-wide discovery every default-rooted
// adapter reads. Tests exercise discoverRoots() and their own discovery
// values directly.
var sharedDiscovery = &discovery{
	walk:     discoverRoots,
	now:      time.Now,
	spawn:    func(f func()) { go f() },
	interval: rediscoverInterval,
}

// New returns an adapter whose watch roots are discovered from the
// filesystem (bounded walk of the NATIVE home for .aider.chat.history.md
// files, plus any AIDER_CHAT_HISTORY_FILE override). The first discovery is
// shared process-wide and refreshed in the background (see discovery).
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), disc: sharedDiscovery}
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
		return &Adapter{scrubber: s, disc: sharedDiscovery}
	}
	return &Adapter{scrubber: s, roots: roots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolAider }

// WatchPaths implements adapter.Adapter. With discovered roots this is the
// .aider.chat.history.md FILE paths found in the native home (plus
// AIDER_CHAT_HISTORY_FILE when set), refreshed in the background every
// rediscoverInterval (T-706: before this, the set was a once-per-process
// snapshot, so a repo whose FIRST aider session started after the daemon
// was never watched until a restart or `observer scan`; on demo node 1
// every transcript of the operator's dashboard aider runs was in that
// state). The watcher's 30 s root re-detector picks up a new transcript
// from here, hot-adds it and walks it.
func (a *Adapter) WatchPaths() []string {
	if a.disc != nil {
		return a.disc.current()
	}
	return a.roots
}

// IsSessionFile implements adapter.Adapter. Matches a file named exactly
// .aider.chat.history.md under (or equal to) one of the watch roots, or a
// path exactly equal to an explicitly-configured root even when its
// basename differs (AIDER_CHAT_HISTORY_FILE allows a custom name). The
// sibling .aider.input.history and the .aider.tags.cache.v4/ repo-map
// cache are deliberately NOT matched.
func (a *Adapter) IsSessionFile(path string) bool {
	roots := a.WatchPaths()
	if !adapter.UnderAnyWatchRoot(path, roots) {
		return false
	}
	if strings.EqualFold(filepath.Base(path), historyFileName) {
		return true
	}
	clean := filepath.Clean(path)
	for _, r := range roots {
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
	// Lstat, not Stat: a transcript path that is a symlink (or any
	// non-regular file) is never read, whichever discovery path named it
	// (SEC-SWEEP, ledger AIDER-SYMLINK-1).
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
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
	p := a.parseTranscriptState(ctx, data, path, projectRoot, gitRemote)

	res := adapter.ParseResult{
		ToolEvents:          p.tools,
		TokenEvents:         p.tokens,
		SessionToolVersions: p.versions,
		NewOffset:           int64(len(data)),
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
