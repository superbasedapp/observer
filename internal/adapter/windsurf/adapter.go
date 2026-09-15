package windsurf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// ToolName is the stable tool id this adapter will store in the `tool`
// column once it is registered.
//
// It deliberately lives here and NOT in internal/models: an unregistered
// skeleton has no rows to tag, and a models.Tool* constant that nothing
// writes reads as coverage that does not exist. On registration the id moves
// to models.ToolWindsurf and this constant is deleted (doc.go, "Wiring
// checklist"), so the id never exists in two spellings at once.
const ToolName = "windsurf"

// ungroundedWarning is the single Warning every ParseSessionFile returns.
// It names the fixture README so an operator who somehow reaches this code
// path lands on the step-in recipe rather than on a silent empty result.
const ungroundedWarning = "windsurf: store shape not yet grounded — no rows emitted; see testdata/windsurf/README.md (step-in P8)"

// Adapter is the Cascade skeleton adapter. It declares real watch roots and
// a real file-shape predicate, and parses nothing — see the package doc for
// what is grounded, what is not, and why it is unregistered.
type Adapter struct {
	// scrubber is held so the constructor signature and the injection
	// contract match every other adapter; nothing is scrubbed yet because
	// nothing is emitted yet.
	scrubber *scrub.Scrubber
	// roots are the watch roots returned by WatchPaths, in defaultRoots order.
	roots []string
}

// New returns an Adapter with platform-default cross-mount roots.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots()}
}

// NewWithOptions customises scrubber and roots for tests. Pass a nil
// scrubber for the default; pass no roots for default platform discovery.
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
func (*Adapter) Name() string { return ToolName }

// WatchPaths implements adapter.Adapter. Callers must not mutate the result.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Two shapes are claimed, both
// scoped to this adapter's own roots (adapter.UnderAnyWatchRoot):
//
//   - any regular file DIRECTLY under a `.../cascade` root, whatever its
//     extension. The permissiveness is deliberate and temporary: the file
//     format is undocumented and the bundle contains no `.jsonl` literal at
//     all, so an extension allow-list invented now would most likely reject
//     the real fixture. The predicate is narrowed to the observed shape in
//     the commit that lands testdata/windsurf/. Only direct children match,
//     so a future nested subtree needs an explicit decision rather than
//     being swept in.
//   - the `state.vscdb` FILE root itself, matched by exact path equality.
//     The `-wal` / `-shm` sidecars are NOT session files: SQLite reads them
//     itself, and they fall outside a file root by construction (see doc.go).
func (a *Adapter) IsSessionFile(path string) bool {
	if !a.matchesShape(path) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.roots)
}

// matchesShape reports whether path has one of the two claimed shapes
// RELATIVE to this adapter's roots. Root kind is decided by the root's own
// last segment (`cascade` = directory root, `state.vscdb` = file root), so a
// test that injects custom roots exercises exactly the production rule.
func (a *Adapter) matchesShape(path string) bool {
	if path == "" {
		return false
	}
	parent := filepath.Dir(path)
	for _, r := range a.roots {
		if r == "" {
			continue
		}
		switch filepath.Base(r) {
		case stateDBFileName:
			if samePath(path, r) {
				return true
			}
		case cascadeLeafDir:
			if samePath(parent, r) && !isDir(path) {
				return true
			}
		}
	}
	return false
}

// ParseSessionFile implements adapter.Adapter — honestly, by emitting
// nothing. The store shape is not grounded (no Windsurf install has ever
// been launched on a host this project can read), and a guessed parse would
// write rows that can never be corrected: the store's
// (source_file, source_event_id) UNIQUE index makes a wrong row permanent
// where a missing row is merely deferred.
//
// NewOffset is the file's current size so the watcher's byte-offset cursor
// reaches EOF and the file is not re-dispatched until it grows. That is the
// right default for an append-only text file and is REVISITED when the real
// parser lands: a SQLite store wants a watermark cursor plus an
// adapter.CursorSemantics declaration (doc.go, "Wiring checklist" step 5).
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	if err := ctx.Err(); err != nil {
		return adapter.ParseResult{NewOffset: fromOffset}, fmt.Errorf("windsurf.ParseSessionFile: %w", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return adapter.ParseResult{NewOffset: fromOffset}, fmt.Errorf("windsurf.ParseSessionFile: stat: %w", err)
	}
	size := fi.Size()
	if size < fromOffset {
		// Truncated / replaced in place: never move a cursor backwards.
		size = fromOffset
	}
	return adapter.ParseResult{
		NewOffset: size,
		Warnings:  []string{ungroundedWarning},
	}, nil
}

// samePath reports whether two paths denote the same location, reusing
// adapter.HasPathPrefix for absolute-path, Clean and case-folding
// normalisation. Prefix in both directions implies equality.
func samePath(a, b string) bool {
	return adapter.HasPathPrefix(a, b) && adapter.HasPathPrefix(b, a)
}

// isDir reports whether path is a directory. A stat error answers false:
// an fsnotify event for a file that has already been replaced or removed
// should stay claimable, and ParseSessionFile reports the stat failure with
// context if the path really is gone.
func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}
