package aider

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/protectedhome"
)

// Discovery bounds. Aider has no project index, so New() finds watch roots
// by walking each cross-mount home for .aider.chat.history.md files. The
// walk is bounded on BOTH depth and total directories visited so a large
// home does not turn daemon startup into a full-disk crawl.
const (
	// maxWalkDepth caps how many directory levels below a home the walk
	// descends. A repo at ~/code/acme/service is depth 3.
	maxWalkDepth = 8
	// maxDirsVisited caps the total directories examined across all
	// homes; the walk stops early once it is hit.
	maxDirsVisited = 60000
	// maxRoots caps how many distinct repo roots are returned.
	maxRoots = 512
	// MaxKnownRoots caps how many already-known project roots one
	// discovery pass probes (see SetProjectRootSource). A probe is one
	// Lstat of <root>/.aider.chat.history.md, never a walk, so a pass
	// costs at most this many stats even over a foreign mount.
	MaxKnownRoots = 256
	// walkTimeout bounds one home walk in time, on top of the depth and
	// directory bounds (D-MU1). The walk stops at the deadline and returns
	// what it found so far.
	walkTimeout = 60 * time.Second
)

// allHomesFunc is the test seam over crossmount.AllHomes.
var allHomesFunc = crossmount.AllHomes

// goosFunc is the test seam over runtime.GOOS for the protected-folder table.
var goosFunc = func() string { return runtime.GOOS }

// DiscoveryOptions configures the process-wide discovery (D-MU1). The zero
// value is NOT the default; see defaultDiscoveryOptions.
type DiscoveryOptions struct {
	// Context cancels a walk in progress, so a daemon stop never waits on
	// one. nil means context.Background.
	Context context.Context
	// Background makes the first WatchPaths call return at once and run
	// the first walk in the background (the watcher's root re-detector
	// picks its result up). The daemon sets it so no listener waits on a
	// home walk; one-shot commands keep the synchronous first walk.
	Background bool
	// HomeWalk enables the bounded walk of the native home
	// ([observer.watch].home_walk). With it off, discovery uses only
	// AIDER_CHAT_HISTORY_FILE and the already-known project roots.
	HomeWalk bool
	// Active is false for an adapter the daemon does not watch (inactive
	// component, or not in enabled_adapters): discovery then does no I/O at
	// all and returns only AIDER_CHAT_HISTORY_FILE.
	Active bool
}

var defaultDiscoveryOptions = DiscoveryOptions{HomeWalk: true, Active: true}

var (
	optsMu sync.RWMutex
	opts   = defaultDiscoveryOptions
)

// ConfigureDiscovery installs the process-wide discovery options. The daemon
// calls it once, before anything reads WatchPaths.
func ConfigureDiscovery(o DiscoveryOptions) {
	optsMu.Lock()
	opts = o
	optsMu.Unlock()
	sharedDiscovery.setBackground(o.Background)
}

func discoveryOptions() DiscoveryOptions {
	optsMu.RLock()
	defer optsMu.RUnlock()
	return opts
}

var (
	knownMu  sync.RWMutex
	knownSrc func() []string
)

// SetProjectRootSource installs the process-wide source of project roots
// Observer already knows (the daemon passes the store's most recently
// active project roots). Every discovery pass, the startup one and each
// background refresh, probes <root>/.aider.chat.history.md for at most
// MaxKnownRoots of them, so a repo outside the home folder (for example
// C:\programsx\<repo> on Windows, or /mnt/c/programsx/<repo> from WSL,
// where the home walk deliberately never goes) is watched once any other
// tool has been used there. Roots in another OS's spelling are translated
// with crossmount.TranslateForeignPath. nil removes the source.
func SetProjectRootSource(fn func() []string) {
	knownMu.Lock()
	knownSrc = fn
	knownMu.Unlock()
}

func knownProjectRoots() []string {
	knownMu.RLock()
	fn := knownSrc
	knownMu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn()
}

// knownRootTranscripts returns the transcript path for every root (the
// first MaxKnownRoots) whose repo holds a REGULAR .aider.chat.history.md
// file; a symlink is skipped for the same reason the walk skips one
// (ledger AIDER-SYMLINK-1).
func knownRootTranscripts(roots []string) []string {
	var out []string
	for i, r := range roots {
		if i >= MaxKnownRoots {
			break
		}
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		p := filepath.Join(filepath.Clean(crossmount.TranslateForeignPath(r)), historyFileName)
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, p)
	}
	return out
}

// skipDirNames are directory names never worth descending into when
// hunting for an aider transcript: heavy build/vendor/cache trees that
// never hold a repo root, plus dot-directories (an aider repo root is a
// normal, non-hidden project directory). Compared case-insensitively.
var skipDirNames = map[string]bool{
	"node_modules":  true,
	"vendor":        true,
	"dist":          true,
	"build":         true,
	"target":        true,
	"__pycache__":   true,
	"site-packages": true,
	".git":          true,
}

// discoverRoots builds the watch-root set. Roots are the transcript FILE
// paths themselves (not repo directories): AIDER_CHAT_HISTORY_FILE when
// the env override is set, the transcript at each already-known project
// root (SetProjectRootSource; one Lstat per root, native or foreign),
// plus every .aider.chat.history.md found by a bounded walk of the
// NATIVE home. File-roots keep aider's watch set
// disjoint from any project-local adapter watching a subdir of the same
// repo (e.g. crush's <repo>/.crush) and avoid recursively watching whole
// repo trees.
//
// Each call is one walk. The adapter re-runs it in the background every
// rediscoverInterval (T-706), so a repo that gains its first aider session
// after the daemon starts is picked up by the watcher's root re-detector;
// see Adapter.WatchPaths and docs/aider-adapter.md.
func discoverRoots() []string {
	o := discoveryOptions()
	var roots []string
	seen := map[string]bool{}
	add := func(p string) bool {
		if p == "" || seen[p] {
			return true
		}
		if len(roots) >= maxRoots {
			return false
		}
		seen[p] = true
		roots = append(roots, p)
		return true
	}

	envFile := strings.TrimSpace(os.Getenv("AIDER_CHAT_HISTORY_FILE"))
	if envFile != "" {
		add(filepath.Clean(envFile))
	}
	if !o.Active {
		return roots
	}
	known := knownProjectRoots()
	for _, p := range knownRootTranscripts(known) {
		if !add(p) {
			break
		}
	}
	if !o.HomeWalk {
		return roots
	}
	// A guarded home folder is walked only when a configured or known
	// project root lives in it (protectedhome.SkipChild).
	keep := append([]string(nil), known...)
	if envFile != "" {
		keep = append(keep, filepath.Dir(envFile))
	}
	parent := o.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, walkTimeout)
	defer cancel()
	goos := goosFunc()

	budget := maxDirsVisited
	for _, h := range allHomesFunc() {
		if budget <= 0 || len(roots) >= maxRoots {
			break
		}
		// Foreign cross-mount homes are SKIPPED: walking a Windows home
		// over DrvFs/9P measured in MINUTES (vs ~1s native), which is an
		// unacceptable startup and test-suite cost. Windows-side aider
		// repos are the Windows daemon's job; a WSL daemon can still
		// reach one via a known project root (one stat, above),
		// AIDER_CHAT_HISTORY_FILE or injected roots.
		if h.Origin != "native" {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		home := h.Path
		skip := func(name string) bool { return protectedhome.SkipChild(goos, home, name, keep) }
		found, spent := walkHome(ctx, home, budget, skip)
		budget -= spent
		for _, d := range found {
			if !add(d) {
				break
			}
		}
	}
	return roots
}

// walkForAiderRoots walks root BREADTH-FIRST to a bounded depth,
// returning every .aider.chat.history.md file path found and the number
// of directories visited (charged against the caller's budget).
// Breadth-first matters: aider transcripts live at repo roots, which sit
// SHALLOW under a home (~depth 1–4), while a lexical depth-first walk can
// exhaust the whole budget inside one deep tree that sorts early (e.g.
// ~/go/pkg/mod) and never reach a repo that sorts later. Heavy/hidden
// directories are pruned. Best-effort: I/O errors on individual entries
// are skipped, never fatal.
func walkForAiderRoots(root string, budget int) (found []string, visited int) {
	return walkHome(context.Background(), root, budget, nil)
}

// walkHome is walkForAiderRoots with a stop context (checked before every
// directory, so a cancelled or timed-out walk returns what it found) and
// skipTop, which names folders directly under root the walk must not open
// (the OS-guarded home folders, D-MU1). nil skipTop skips nothing.
func walkHome(ctx context.Context, root string, budget int, skipTop func(name string) bool) (found []string, visited int) {
	root = filepath.Clean(root)
	seen := map[string]bool{}

	type qdir struct {
		path  string
		depth int
	}
	queue := []qdir{{root, 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if visited >= budget || ctx.Err() != nil {
			break
		}
		visited++
		entries, err := os.ReadDir(cur.path)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() {
				// Prune dot-dirs (an aider repo root is non-hidden) and
				// the heavy build/vendor trees.
				if strings.HasPrefix(name, ".") || skipDirNames[strings.ToLower(name)] {
					continue
				}
				if cur.depth == 0 && skipTop != nil && skipTop(name) {
					continue
				}
				if cur.depth+1 <= maxWalkDepth {
					queue = append(queue, qdir{filepath.Join(cur.path, name), cur.depth + 1})
				}
				continue
			}
			// Only a REGULAR file is a transcript (SEC-SWEEP, ledger
			// AIDER-SYMLINK-1): a committed symlink named like one
			// (".aider.chat.history.md -> ~/notes/private.md") would make the
			// daemon read its target, the SR27-A3 class.
			if strings.EqualFold(name, historyFileName) && e.Type().IsRegular() {
				p := filepath.Join(cur.path, name)
				if !seen[p] {
					seen[p] = true
					found = append(found, p)
				}
			}
		}
	}
	return found, visited
}
