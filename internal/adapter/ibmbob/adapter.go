package ibmbob

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

// fallbackProjectRoot is the project root used when a task carries no
// workspace at all.
const fallbackProjectRoot = "[ibm-bob]"

// Adapter parses IBM Bob Shell's WAL SQLite task store (~/.bob/db/bob.db).
// Bob keeps a single central store per home, so the watch roots are the
// per-home `.bob/db` directories. See the package doc for the store shape.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
	// logs caches the parsed sign-in lines of Bob's shell logs (the
	// account timeline, account.go).
	logs *logCache
}

// New returns an adapter whose roots are discovered across every
// cross-mount-resolved home.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots(), logs: newLogCache()}
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
	return &Adapter{scrubber: s, roots: roots, logs: newLogCache()}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolIBMBob }

// WatchPaths implements adapter.Adapter. The roots are a snapshot taken at
// construction: the `.bob/db` directory per cross-mount-resolved home.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Matches Bob's central store
// bob.db (and its -wal/-shm siblings) whose immediate parent directory is
// "db" and which lives under one of the watch roots. The parent-dir guard
// keeps a stray bob.db elsewhere (and the development build's
// .bob/dev-db/bob.db) from being claimed.
func (a *Adapter) IsSessionFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base != dbFile && base != dbFile+"-wal" && base != dbFile+"-shm" {
		return false
	}
	if !strings.EqualFold(filepath.Base(filepath.Dir(path)), storeDirName) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.roots)
}

// ParseSessionFile implements adapter.Adapter. It performs a watermark
// incremental read of bob.db at path: fromOffset is the largest
// tasks.updated_at (epoch ms) already processed. When the current maximum
// hasn't advanced, nothing is re-read. Otherwise every task touched at or
// after fromOffset is re-emitted in full; downstream (source_file,
// source_event_id) dedup makes re-emitting already-seen rows a no-op.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	dbPath := resolveDBPath(path)

	db, err := openReadOnlyDB(dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("ibmbob.ParseSessionFile: open: %w", err)
	}
	defer db.Close()

	latest, err := maxTaskUpdatedAt(ctx, db)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("ibmbob.ParseSessionFile: watermark: %w", err)
	}
	res := adapter.ParseResult{NewOffset: latest}
	if latest <= fromOffset {
		return res, nil
	}

	tasks, err := loadTouchedTasks(ctx, db, fromOffset)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("ibmbob.ParseSessionFile: tasks: %w", err)
	}
	installVersion := readInstallVersion(dbPath)
	var (
		timeline     accountTimeline
		timelineRead bool
	)
	for _, t := range tasks {
		if err := ctx.Err(); err != nil {
			return adapter.ParseResult{}, fmt.Errorf("ibmbob.ParseSessionFile: %w", err)
		}
		out := a.parseTask(ctx, db, dbPath, t, installVersion)
		res.ToolEvents = append(res.ToolEvents, out.Events...)
		res.Warnings = append(res.Warnings, out.Warnings...)
		if len(out.Events) == 0 {
			continue
		}
		if !timelineRead {
			timeline, timelineRead = a.logs.readAccountTimeline(dbPath), true
		}
		res.ToolAccounts = append(res.ToolAccounts, accountObservations(timeline, t.ID, out.Events)...)
		if lin, ok := lineageFor(t); ok {
			res.SessionLineages = append(res.SessionLineages, lin)
		}
		if out.Version != "" {
			res.SessionToolVersions = append(res.SessionToolVersions, models.SessionToolVersion{
				SessionID: t.ID,
				Version:   out.Version,
			})
		}
	}
	return res, nil
}

// resolveProjectRoot turns a task's raw workspace into a stable project
// root. Foreign-mount paths (a raw C:\… workspace on a Windows-side task
// read from WSL) are translated and STAT-GATED before git.Resolve: a path
// that isn't locally reachable is returned as-is, because git.Resolve's
// filepath.Abs would otherwise CWD-prefix the observer's own repo onto the
// foreign string. An empty workspace falls back to "[ibm-bob]".
func (a *Adapter) resolveProjectRoot(workspace string) (root, gitRemote string, id git.Identity) {
	wd := strings.TrimSpace(workspace)
	if wd == "" {
		return fallbackProjectRoot, "", git.Identity{}
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
