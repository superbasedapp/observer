package deepagents

import (
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter parses LangChain Deep Agents Code's session store
// (`<home>/.deepagents/.state/sessions.db`, a LangGraph SQLite checkpointer).
// dcode keeps a single central store per home, so the watch roots are the
// per-home `.state` directories. See the package doc for the store shape.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter whose roots are discovered across every
// cross-mount-resolved home.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots()}
}

// NewWithOptions customizes scrubber and/or roots for tests. A nil scrubber
// falls back to the default; empty roots fall back to discovery.
func NewWithOptions(s *scrub.Scrubber, roots []string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{scrubber: s, roots: roots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolDeepAgentsCode }

// WatchPaths implements adapter.Adapter: the `.deepagents/.state` directory
// per cross-mount-resolved home (a snapshot taken at construction).
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. It matches the central store
// sessions.db (and its -wal/-shm siblings) whose immediate parent directory
// is `.state` and which lives under one of the watch roots. The parent-dir
// guard keeps a stray sessions.db elsewhere (goose also names its store
// sessions.db) from being claimed, and the sessions.db.owners/ lock files
// never match the basename.
func (a *Adapter) IsSessionFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base != "sessions.db" && base != "sessions.db-wal" && base != "sessions.db-shm" {
		return false
	}
	if filepath.Base(filepath.Dir(path)) != stateDirName {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.roots)
}

// scrub applies the plaintext scrubber, tolerating a nil scrubber.
func (a *Adapter) scrub(v string) string {
	if a.scrubber == nil {
		return v
	}
	return a.scrubber.String(v)
}

// scrubRaw applies the JSON-structure-safe scrubber to a raw JSON blob,
// tolerating a nil scrubber and empty input.
func (a *Adapter) scrubRaw(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if a.scrubber == nil {
		return string(raw)
	}
	return a.scrubber.RawJSON(raw)
}
