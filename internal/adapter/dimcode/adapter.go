package dimcode

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

// Adapter parses DimCode's central WAL SQLite store (dimcode.sqlite). Every
// DimCode surface persists into the one store per home, so the watch roots are
// the per-home `.dimcode/v2` directories. See the package doc for the shape.
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
func (*Adapter) Name() string { return models.ToolDimCode }

// WatchPaths implements adapter.Adapter. The roots are a snapshot taken at
// construction: the `~/.dimcode/v2` directory per cross-mount-resolved home.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile implements adapter.Adapter. Matches DimCode's store
// dimcode.sqlite and its -wal/-shm siblings when they live under one of the
// watch roots. The under-WatchPaths constraint keeps a stray copy elsewhere
// on disk (an archived or backed-up store) from being claimed, and
// schedule-tui.sqlite (the scheduler's separate store) is not a match.
func (a *Adapter) IsSessionFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base != storeFile && base != storeFile+"-wal" && base != storeFile+"-shm" {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.roots)
}

// ParseSessionFile implements adapter.Adapter. It performs a watermark
// incremental read of the store at path: fromOffset is the newest timestamp
// (epoch ms) already processed. When the store's newest timestamp has not
// advanced nothing is re-read. Otherwise every session that gained a message,
// run row or ledger row since fromOffset is re-emitted in full; downstream
// (source_file, source_event_id) dedup makes re-emitting already-seen rows a
// no-op, the store's MAX-upgrade ON CONFLICT keeps token counts monotonic, and
// a tool result that arrived after its tool_use was first stored reaches the
// action through an OutcomeUpdate.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	dbPath := resolveDBPath(path)

	db, err := openReadOnlyDB(dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("dimcode.ParseSessionFile: open: %w", err)
	}
	defer db.Close()

	latest, err := latestWatermark(ctx, db)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("dimcode.ParseSessionFile: watermark: %w", err)
	}
	res := adapter.ParseResult{NewOffset: latest}
	if latest <= fromOffset {
		return res, nil
	}

	// Relations first: a sub-agent's own session is recognised from them
	// (childOf) while it is parsed, so its rows land flagged as sidechain.
	relations, err := loadRelations(ctx, db)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("dimcode.ParseSessionFile: relations: %w", err)
	}
	childOf := subagentParents(relations)

	sessions, err := loadTouchedSessions(ctx, db, fromOffset)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("dimcode.ParseSessionFile: sessions: %w", err)
	}
	version := installVersion(filepath.Dir(dbPath))
	for _, s := range sessions {
		out, warns := a.parseSession(ctx, db, dbPath, s, fromOffset, childOf)
		res.ToolEvents = append(res.ToolEvents, out.ToolEvents...)
		res.TokenEvents = append(res.TokenEvents, out.TokenEvents...)
		res.OutcomeUpdates = append(res.OutcomeUpdates, out.OutcomeUpdates...)
		res.SessionLineages = append(res.SessionLineages, out.SessionLineages...)
		res.Warnings = append(res.Warnings, warns...)
		if version != "" {
			// The store records no per-session version, so every session is
			// stamped with the installed build (operator ruling 2026-10-21);
			// the store write is first-wins-unless-empty.
			res.SessionToolVersions = append(res.SessionToolVersions,
				models.SessionToolVersion{SessionID: s.ID, Version: version})
		}
	}

	res.SessionLineages = append(res.SessionLineages, lineagesFromRelations(relations)...)
	return res, nil
}

// subagentParents indexes child session id -> parent session id over the
// relation rows of type "subagent" (source = parent, target = child).
func subagentParents(rels []relationRow) map[string]string {
	out := map[string]string{}
	for _, r := range rels {
		if r.Type == "subagent" && r.Source != "" && r.Target != "" {
			out[r.Target] = r.Source
		}
	}
	return out
}

// lineagesFromRelations turns session_relations rows into SessionLineage
// markers. relationType "subagent" (source = parent, target = child, per the
// vendor's linkSession call in its sub-agent runner) lands as
// ParentThreadID + ThreadSource "subagent"; "branch" (source = original,
// target = the fork copy) lands as ForkedFromID + ThreadSource "user". Any
// other relation type, or a row missing an end, is skipped.
func lineagesFromRelations(rels []relationRow) []models.SessionLineage {
	var out []models.SessionLineage
	for _, r := range rels {
		if r.Source == "" || r.Target == "" {
			continue
		}
		switch r.Type {
		case "subagent":
			out = append(out, models.SessionLineage{
				SessionID:      r.Target,
				ParentThreadID: r.Source,
				ThreadSource:   "subagent",
			})
		case "branch":
			out = append(out, models.SessionLineage{
				SessionID:    r.Target,
				ForkedFromID: r.Source,
				ThreadSource: "user",
			})
		}
	}
	return out
}

// resolveProjectRoot turns a session's raw cwd into a stable project root.
// Foreign-mount Windows paths (a raw C:\… string on a Windows-side session)
// are translated to their /mnt/c equivalent and STAT-GATED before
// git.ResolveIdentity: a path that is not locally reachable is returned
// as-is, because git's filepath.Abs would otherwise CWD-prefix the observer's
// own repo onto the foreign string. Empty cwds fall back to "[dimcode]".
func (a *Adapter) resolveProjectRoot(cwd string) (root, gitRemote string, id git.Identity) {
	wd := strings.TrimSpace(cwd)
	if wd == "" {
		return "[dimcode]", "", git.Identity{}
	}
	wd = crossmount.TranslateForeignPath(wd)
	if _, err := os.Stat(wd); err != nil {
		return wd, "", git.Identity{}
	}
	identity, err := git.ResolveIdentity(wd, git.IdentityOptions{})
	if err != nil {
		return wd, "", git.Identity{}
	}
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
