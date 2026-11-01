package stakpak

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

// Adapter parses the Stakpak agent CLI's local SQLite store
// (~/.stakpak/data/local.db). Stakpak keeps a single central store per
// home, so the watch roots are the per-home `.stakpak/data` directories. See
// the package doc for the store shape.
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
func (*Adapter) Name() string { return models.ToolStakpak }

// WatchPaths implements adapter.Adapter. The roots are a snapshot taken at
// construction: the `.stakpak/data` directory per cross-mount-resolved
// home. The store is a single central local.db, so one root per home covers
// every session.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Matches Stakpak's local.db (and
// its -wal/-shm siblings) whose parent directory is `data` inside a
// `.stakpak` directory and which lives under one of the watch roots. The
// two-level parent guard keeps an unrelated local.db elsewhere from being
// claimed.
func (a *Adapter) IsSessionFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base != "local.db" && base != "local.db-wal" && base != "local.db-shm" {
		return false
	}
	dir := filepath.Dir(path)
	if !strings.EqualFold(filepath.Base(dir), "data") {
		return false
	}
	if !strings.EqualFold(filepath.Base(filepath.Dir(dir)), ".stakpak") {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.roots)
}

// CursorSemanticsFor implements adapter.CursorSemantics. `local.db` and its
// `-wal` / `-shm` sidecars are scanned by a `checkpoints.rowid` watermark,
// so the persisted cursor is a row id rather than a byte offset.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !a.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	return adapter.FileCursorSemantics{
		Kind:   adapter.CursorWatermark,
		Detail: "stakpak local.db is scanned by a checkpoints.rowid watermark; the cursor is not a byte offset",
	}
}

// parseState accumulates one ParseSessionFile call. calls maps a tool-call
// SourceEventID to its index in tools so a tool message in the same window
// can complete it in place.
type parseState struct {
	sourceFile string
	meta       map[string]sessionMeta
	contexts   map[string]sessionCtx
	tools      []models.ToolEvent
	tokens     []models.TokenEvent
	outcomes   []models.ActionOutcomeUpdate
	calls      map[string]int
	identities map[string]git.Identity
	// started records the sessions whose session_start row this parse
	// already emitted.
	started  map[string]bool
	warnings []string
}

func (st *parseState) warn(format string, args ...any) {
	st.warnings = append(st.warnings, fmt.Sprintf(format, args...))
}

// sessionContext resolves (and caches) the project root of a session from
// its raw cwd.
func (st *parseState) sessionContext(a *Adapter, sessionID string) sessionCtx {
	if c, ok := st.contexts[sessionID]; ok {
		return c
	}
	root, remote, id := a.resolveProjectRoot(st.meta[sessionID].CWD)
	c := sessionCtx{root: root, remote: remote, identity: id}
	st.contexts[sessionID] = c
	if id.Root != "" {
		st.identities[root] = id
	}
	return c
}

// ParseSessionFile implements adapter.Adapter. It performs a watermark
// incremental read of the local.db at path: fromOffset is the largest
// checkpoints.rowid already processed. When the current MAX(rowid) has not
// advanced, nothing is re-read. Otherwise each checkpoint past the watermark
// contributes the messages it added to its parent; downstream
// (source_file, source_event_id) dedup makes a re-parse a no-op.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	if err := ctx.Err(); err != nil {
		return adapter.ParseResult{}, fmt.Errorf("stakpak.ParseSessionFile: %w", err)
	}
	dbPath := resolveDBPath(path)

	db, err := openReadOnlyDB(dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("stakpak.ParseSessionFile: open: %w", err)
	}
	defer db.Close()

	latest, err := maxCheckpointRowID(ctx, db)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("stakpak.ParseSessionFile: watermark: %w", err)
	}
	res := adapter.ParseResult{NewOffset: latest}
	if latest <= fromOffset {
		return res, nil
	}

	meta, err := loadSessionMeta(ctx, db)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("stakpak.ParseSessionFile: sessions: %w", err)
	}
	st := &parseState{
		sourceFile: dbPath,
		meta:       meta,
		contexts:   map[string]sessionCtx{},
		calls:      map[string]int{},
		identities: map[string]git.Identity{},
		started:    map[string]bool{},
	}
	scanErr := scanCheckpointsAfter(ctx, db, fromOffset, func(r checkpointRow) bool {
		if ctx.Err() != nil {
			return false
		}
		a.processCheckpoint(st, r)
		return true
	})
	if scanErr != nil {
		return adapter.ParseResult{}, fmt.Errorf("stakpak.ParseSessionFile: checkpoints: %w", scanErr)
	}
	if err := ctx.Err(); err != nil {
		return adapter.ParseResult{}, fmt.Errorf("stakpak.ParseSessionFile: %w", err)
	}

	res.ToolEvents = st.tools
	res.TokenEvents = st.tokens
	res.OutcomeUpdates = st.outcomes
	res.Warnings = st.warnings
	res.SessionToolVersions = a.sessionToolVersions(dbPath, st.contexts)
	adapter.ApplyProjectIdentityByRoot(&res, st.identities)
	return res, nil
}

// resolveProjectRoot turns a session's raw cwd into a stable project root.
// Foreign-mount Windows paths (a raw C:\... string on a Windows-side
// session) are translated to their /mnt/c equivalent and STAT-GATED before
// git.ResolveIdentity: a path that is not locally reachable is returned
// as-is, because git's filepath.Abs would otherwise CWD-prefix the
// observer's own repo onto the foreign string. An empty cwd falls back to
// "[stakpak]". Returns (root, gitRemote); gitRemote is "" when the
// directory is not inside a git repo (or is not reachable at all).
func (a *Adapter) resolveProjectRoot(cwd string) (root, gitRemote string, id git.Identity) {
	wd := strings.TrimSpace(cwd)
	if wd == "" {
		return "[stakpak]", "", git.Identity{}
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
