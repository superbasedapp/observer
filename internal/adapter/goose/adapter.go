package goose

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter parses Block's goose agent WAL SQLite store (sessions.db). goose
// keeps a single central store per home, so the watch roots are the
// per-home `sessions` directories. See the package doc for the store shape.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter whose roots are discovered across every
// cross-mount-resolved home.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots()}
}

// NewWithOptions customizes scrubber and/or roots for tests. A nil
// scrubber falls back to the default; empty roots fall back to discovery.
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
func (*Adapter) Name() string { return models.ToolGoose }

// WatchPaths implements adapter.Adapter. The roots are a snapshot taken at
// construction: the goose `sessions` directory per cross-mount-resolved
// home. goose's store is a single central sessions.db, so one root per
// home covers every session.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Matches goose's central store
// sessions.db (and its -wal/-shm siblings) whose immediate parent
// directory is "sessions" and which lives under one of the watch roots.
// The parent-dir guard keeps a stray sessions.db elsewhere from being
// claimed.
func (a *Adapter) IsSessionFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base != "sessions.db" && base != "sessions.db-wal" && base != "sessions.db-shm" {
		return false
	}
	if !strings.EqualFold(filepath.Base(filepath.Dir(path)), "sessions") {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.roots)
}

// ParseSessionFile implements adapter.Adapter. It performs a watermark
// incremental read of the sessions.db at path: fromOffset is the largest
// messages.id already processed. When the current MAX(id) hasn't advanced,
// nothing is re-read. Otherwise every session that gained a message since
// fromOffset is re-emitted in full (its whole message list plus a
// session-level TokenEvent); downstream (source_file, source_event_id)
// dedup makes re-emitting already-seen rows a no-op, and the store's
// MAX-upgrade ON CONFLICT keeps the monotonic accumulated token counts
// correct.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	dbPath := resolveDBPath(path)

	db, err := openReadOnlyDB(dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("goose.ParseSessionFile: open: %w", err)
	}
	defer db.Close()

	latest, err := maxMessageID(ctx, db)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("goose.ParseSessionFile: watermark: %w", err)
	}
	res := adapter.ParseResult{NewOffset: latest}
	if latest <= fromOffset {
		return res, nil
	}

	sessions, err := loadTouchedSessions(ctx, db, fromOffset)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("goose.ParseSessionFile: sessions: %w", err)
	}
	for _, s := range sessions {
		tools, tokens, warns := a.parseSession(ctx, db, dbPath, s)
		res.ToolEvents = append(res.ToolEvents, tools...)
		res.TokenEvents = append(res.TokenEvents, tokens...)
		res.Warnings = append(res.Warnings, warns...)
	}
	return res, nil
}

// resolveProjectRoot turns a session's raw working_dir into a stable
// project root. Foreign-mount Windows paths (a raw C:\… string on a
// Windows-side session) are translated to their /mnt/c equivalent and
// STAT-GATED before git.Resolve: a path that isn't locally reachable is
// returned as-is, because git.Resolve's filepath.Abs would otherwise
// CWD-prefix the observer's own repo onto the foreign string. Empty cwds
// fall back to "[goose]". Returns (root, gitRemote); gitRemote is "" when
// the working dir isn't inside a git repo (or isn't reachable at all).
func (a *Adapter) resolveProjectRoot(workingDir string) (root, gitRemote string, id git.Identity) {
	wd := strings.TrimSpace(workingDir)
	if wd == "" {
		return "[goose]", "", git.Identity{}
	}
	wd = crossmount.TranslateForeignPath(wd)
	if _, err := os.Stat(wd); err != nil {
		return wd, "", git.Identity{}
	}
	identity, err := git.ResolveIdentity(wd, git.IdentityOptions{})
	if err != nil {
		return wd, "", git.Identity{}
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
