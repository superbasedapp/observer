package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// This file is the ONE owner of the project_guidance_files table
// (CLAUDE.md rule #4). The table is NODE-LOCAL — it names private
// project paths and the operator's home-scope files — and its name is in
// tests/invariant/privacy_test.go's forbidden-name sentinel, so it can
// never appear in internal/store/orgpush.go.

// GuidanceUserScopeRoot is the sentinel project_root the HOME-directory
// (ScopeUser) inventory is stored under.
//
// User-scope guidance is the same set of files for every project on the
// machine, so it is scanned ONCE per pass and stored once, rather than
// N times under N project roots (which produced N duplicate rows and N
// redundant walks of ~/.claude). [ListGuidance] folds these rows into
// every project's inventory, so the panel's "From your home directory"
// group renders exactly as before; [GuidanceProjects] excludes them, so
// the sentinel is never offered as a project and its files are never
// counted twice.
//
// "~" is chosen because a real project root is always absolute, so the
// sentinel can never collide with one — not even with the home
// directory itself being a project.
const GuidanceUserScopeRoot = "~"

// GuidanceRow is one stored guidance file. The json tags are the wire
// shape the dashboard API (GUID-B) and the panel (GUID-C) consume.
type GuidanceRow struct {
	ProjectRoot string `json:"project_root"`
	Tool        string `json:"tool"`
	Kind        string `json:"kind"`
	Scope       string `json:"scope"`
	RelPath     string `json:"rel_path"`
	// AbsPath is NODE-LOCAL and deliberately never serialized: the
	// inventory wire (and the dashboard panel that reads it) works in
	// rel_path, and an absolute path is exactly the kind of host detail a
	// remote-exposed GET should not hand out. Go callers that need to
	// open the file re-anchor rel_path themselves (project root, or the
	// home directory for a "~/"-prefixed row).
	AbsPath     string            `json:"-"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	SizeBytes   int64             `json:"size_bytes"`
	ContentHash string            `json:"content_hash"`
	ModifiedAt  time.Time         `json:"modified_at"`
	Frontmatter map[string]string `json:"frontmatter"`
	Present     bool              `json:"present"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastScanned time.Time         `json:"last_scanned"`
	ParseError  string            `json:"parse_error"`
}

// GuidanceScanSummary reports what one scan changed. It is the honest
// answer to "did anything move?" without re-reading the table: Added and
// Tombstoned are the two an operator cares about, Updated means the
// bytes changed, Unchanged means the file is still exactly as last seen.
type GuidanceScanSummary struct {
	Added      int `json:"added"`
	Updated    int `json:"updated"`
	Tombstoned int `json:"tombstoned"`
	Unchanged  int `json:"unchanged"`
}

// GuidanceProjectSummary is one row of the cross-project index.
type GuidanceProjectSummary struct {
	ProjectRoot string    `json:"project_root"`
	Files       int       `json:"files"`
	LastScanned time.Time `json:"last_scanned"`
}

// guidanceKey is the table's unique identity, minus the project root
// (which is fixed for a whole scan).
type guidanceKey struct {
	tool    string
	scope   string
	relPath string
}

// guidanceExisting is the pre-scan snapshot a scan is diffed against.
type guidanceExisting struct {
	contentHash string
	sizeBytes   int64
	modifiedAt  string
	name        string
	description string
	parseError  string
	frontmatter string
	absPath     string
	present     bool
}

// UpsertGuidanceScan records one complete scan of one project root in a
// single transaction: every file in files is inserted or updated, and
// every row previously recorded for that project root which the scan did
// NOT produce is tombstoned (present = 0).
//
// Tombstoning rather than deleting is deliberate. A guidance file that
// vanished is itself a fact — "this project used to have a CLAUDE.md" —
// and deleting would also throw away first_seen, so a file that comes
// back would look brand new.
//
// files must be the COMPLETE result of one scan of projectRoot; a
// partial slice would tombstone everything it omits. Passing an empty
// slice is legal and means "this project has no guidance files", which
// tombstones the lot.
func (s *Store) UpsertGuidanceScan(
	ctx context.Context,
	projectRoot string,
	files []guidance.File,
	scannedAt time.Time,
) (GuidanceScanSummary, error) {
	var sum GuidanceScanSummary
	projectRoot = strings.TrimSpace(projectRoot)
	if projectRoot == "" {
		return sum, errors.New("store.UpsertGuidanceScan: empty project root")
	}
	if scannedAt.IsZero() {
		scannedAt = time.Now()
	}
	stamp := formatGuidanceTime(scannedAt)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return sum, fmt.Errorf("store.UpsertGuidanceScan: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	existing, err := loadGuidanceExisting(ctx, tx, projectRoot)
	if err != nil {
		return sum, err
	}

	upsert, err := tx.PrepareContext(ctx, `
INSERT INTO project_guidance_files (
    project_root, tool, kind, scope, rel_path, abs_path,
    name, description, size_bytes, content_hash, modified_at,
    frontmatter_json, present, first_seen, last_scanned, parse_error
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
ON CONFLICT (project_root, tool, scope, rel_path) DO UPDATE SET
    kind             = excluded.kind,
    abs_path         = excluded.abs_path,
    name             = excluded.name,
    description      = excluded.description,
    size_bytes       = excluded.size_bytes,
    content_hash     = excluded.content_hash,
    modified_at      = excluded.modified_at,
    frontmatter_json = excluded.frontmatter_json,
    present          = 1,
    last_scanned     = excluded.last_scanned,
    parse_error      = excluded.parse_error`)
	if err != nil {
		return sum, fmt.Errorf("store.UpsertGuidanceScan: prepare upsert: %w", err)
	}
	defer upsert.Close()

	seen := make(map[guidanceKey]bool, len(files))
	for _, f := range files {
		key := guidanceKey{tool: f.Tool, scope: string(f.Scope), relPath: f.RelPath}
		if seen[key] {
			// The scanner already dedupes per (tool, path); a duplicate
			// here would otherwise make Added/Updated lie.
			continue
		}
		seen[key] = true

		fm := encodeGuidanceFrontmatter(f.Frontmatter)
		modified := formatGuidanceTime(f.ModTime)
		prev, had := existing[key]
		switch {
		case !had:
			sum.Added++
		case guidanceUnchanged(prev, f, fm, modified):
			sum.Unchanged++
		default:
			sum.Updated++
		}

		if _, err := upsert.ExecContext(ctx,
			projectRoot, f.Tool, string(f.Kind), string(f.Scope), f.RelPath, f.AbsPath,
			f.Name, f.Description, f.SizeBytes, f.ContentHash, modified,
			fm, stamp, stamp, f.ParseErr,
		); err != nil {
			return GuidanceScanSummary{}, fmt.Errorf("store.UpsertGuidanceScan: upsert %s/%s: %w", f.Tool, f.RelPath, err)
		}
	}

	tombstone, err := tx.PrepareContext(ctx, `
UPDATE project_guidance_files
   SET present = 0, last_scanned = ?
 WHERE project_root = ? AND tool = ? AND scope = ? AND rel_path = ? AND present = 1`)
	if err != nil {
		return GuidanceScanSummary{}, fmt.Errorf("store.UpsertGuidanceScan: prepare tombstone: %w", err)
	}
	defer tombstone.Close()

	for key, prev := range existing {
		if seen[key] || !prev.present {
			continue
		}
		if _, err := tombstone.ExecContext(ctx, stamp, projectRoot, key.tool, key.scope, key.relPath); err != nil {
			return GuidanceScanSummary{}, fmt.Errorf("store.UpsertGuidanceScan: tombstone %s/%s: %w", key.tool, key.relPath, err)
		}
		sum.Tombstoned++
	}

	if err := tx.Commit(); err != nil {
		return GuidanceScanSummary{}, fmt.Errorf("store.UpsertGuidanceScan: commit: %w", err)
	}
	return sum, nil
}

// guidanceUnchanged decides Unchanged vs Updated. It compares everything
// the panel renders, not just the hash: a file whose bytes are identical
// but whose mtime moved is still "unchanged" to a reader, while a row
// that was tombstoned and came back is an update even at the same hash.
func guidanceUnchanged(prev guidanceExisting, f guidance.File, frontmatterJSON, modified string) bool {
	return prev.present &&
		prev.contentHash == f.ContentHash &&
		prev.sizeBytes == f.SizeBytes &&
		prev.modifiedAt == modified &&
		prev.name == f.Name &&
		prev.description == f.Description &&
		prev.parseError == f.ParseErr &&
		prev.frontmatter == frontmatterJSON &&
		prev.absPath == f.AbsPath
}

func loadGuidanceExisting(ctx context.Context, tx *sql.Tx, projectRoot string) (map[guidanceKey]guidanceExisting, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT tool, scope, rel_path, abs_path, name, description,
       size_bytes, content_hash, modified_at, frontmatter_json, present, parse_error
  FROM project_guidance_files
 WHERE project_root = ?`, projectRoot)
	if err != nil {
		return nil, fmt.Errorf("store.UpsertGuidanceScan: load existing: %w", err)
	}
	defer rows.Close()

	out := map[guidanceKey]guidanceExisting{}
	for rows.Next() {
		var (
			k       guidanceKey
			e       guidanceExisting
			present int
		)
		if err := rows.Scan(
			&k.tool, &k.scope, &k.relPath, &e.absPath, &e.name, &e.description,
			&e.sizeBytes, &e.contentHash, &e.modifiedAt, &e.frontmatter, &present, &e.parseError,
		); err != nil {
			return nil, fmt.Errorf("store.UpsertGuidanceScan: scan existing: %w", err)
		}
		e.present = present != 0
		out[k] = e
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.UpsertGuidanceScan: iterate existing: %w", err)
	}
	return out, nil
}

// ListGuidance returns one project's guidance rows ordered by tool, kind
// then relative path — the order the panel renders and the order two
// scans can be diffed in. includeAbsent adds the tombstoned rows
// (present = 0); the default is the live set.
//
// The operator's HOME-scope rows are folded in: they live once, under
// [GuidanceUserScopeRoot], and apply to every project, so every
// project's inventory carries them. Asking for the sentinel itself
// returns just those rows (no fold, no duplication).
func (s *Store) ListGuidance(ctx context.Context, projectRoot string, includeAbsent bool) ([]GuidanceRow, error) {
	projectRoot = strings.TrimSpace(projectRoot)
	if projectRoot == "" {
		return nil, errors.New("store.ListGuidance: empty project root")
	}
	args := []any{projectRoot}
	where := `project_root = ?`
	if projectRoot != GuidanceUserScopeRoot {
		where = `project_root IN (?, ?)`
		args = append(args, GuidanceUserScopeRoot)
	}
	// `where` is one of exactly two package literals chosen a few lines
	// above (`project_root = ?` / `project_root IN (?, ?)`); projectRoot
	// itself is bound through args, never interpolated. The concatenation
	// only picks between two fixed shapes because SQL cannot bind a
	// variable-arity IN list.
	//nolint:gosec // G202: concatenated fragment is one of two in-package literals, never caller input; projectRoot is bound.
	query := `
SELECT project_root, tool, kind, scope, rel_path, abs_path, name, description,
       size_bytes, content_hash, modified_at, frontmatter_json, present,
       first_seen, last_scanned, parse_error
  FROM project_guidance_files
 WHERE ` + where
	if !includeAbsent {
		query += ` AND present = 1`
	}
	query += ` ORDER BY tool, kind, rel_path`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListGuidance: %w", err)
	}
	defer rows.Close()

	var out []GuidanceRow
	for rows.Next() {
		var (
			r                                GuidanceRow
			present                          int
			modified, firstSeen, lastScanned string
			frontmatterJSON                  string
		)
		if err := rows.Scan(
			&r.ProjectRoot, &r.Tool, &r.Kind, &r.Scope, &r.RelPath, &r.AbsPath, &r.Name, &r.Description,
			&r.SizeBytes, &r.ContentHash, &modified, &frontmatterJSON, &present,
			&firstSeen, &lastScanned, &r.ParseError,
		); err != nil {
			return nil, fmt.Errorf("store.ListGuidance: scan: %w", err)
		}
		r.Present = present != 0
		r.ModifiedAt = parseGuidanceTime(modified)
		r.FirstSeen = parseGuidanceTime(firstSeen)
		r.LastScanned = parseGuidanceTime(lastScanned)
		r.Frontmatter = decodeGuidanceFrontmatter(frontmatterJSON)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListGuidance: iterate: %w", err)
	}
	return out, nil
}

// GuidanceProjects indexes every project that has ever been scanned,
// most recently scanned first. Files counts only the LIVE rows, so a
// project whose guidance was all deleted reports zero rather than
// disappearing — the row is still evidence a scan happened.
//
// The [GuidanceUserScopeRoot] sentinel is NOT a project and is excluded:
// its rows are folded into every project by [ListGuidance], so counting
// them here would double-count them and would offer "~" as a root the
// dashboard and MCP could be asked to open.
func (s *Store) GuidanceProjects(ctx context.Context) ([]GuidanceProjectSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT project_root,
       SUM(CASE WHEN present = 1 THEN 1 ELSE 0 END) AS live_files,
       MAX(last_scanned) AS last_scanned
  FROM project_guidance_files
 WHERE project_root <> ?
 GROUP BY project_root
 ORDER BY last_scanned DESC, project_root`, GuidanceUserScopeRoot)
	if err != nil {
		return nil, fmt.Errorf("store.GuidanceProjects: %w", err)
	}
	defer rows.Close()

	var out []GuidanceProjectSummary
	for rows.Next() {
		var (
			p           GuidanceProjectSummary
			files       sql.NullInt64
			lastScanned sql.NullString
		)
		if err := rows.Scan(&p.ProjectRoot, &files, &lastScanned); err != nil {
			return nil, fmt.Errorf("store.GuidanceProjects: scan: %w", err)
		}
		p.Files = int(files.Int64)
		if lastScanned.Valid {
			p.LastScanned = parseGuidanceTime(lastScanned.String)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.GuidanceProjects: iterate: %w", err)
	}
	return out, nil
}

// GuidanceScanRoots lists the project roots a guidance pass should walk:
// the most recently ACTIVE projects first, capped at limit.
//
// Plain ProjectRoots() is every project the observer has ever seen, in
// insertion order, and a scan pass over it walks the filesystem once per
// root. On a machine with years of history that is mostly work for
// projects nobody has touched since. Ordering by last session (falling
// back to the row's creation time, so a project with no session yet is
// not stranded at the end forever) and capping the pass keeps a rescan
// proportional to what the operator is actually working on; a dormant
// project is inventoried again the moment a session touches it.
//
// limit <= 0 means no cap.
func (s *Store) GuidanceScanRoots(ctx context.Context, limit int) ([]string, error) {
	query := `
SELECT root_path
  FROM projects
 WHERE root_path <> ''
 ORDER BY COALESCE(NULLIF(last_session_at, ''), created_at) DESC, id DESC`
	args := []any{}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store.GuidanceScanRoots: query: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var root string
		if err := rows.Scan(&root); err != nil {
			return nil, fmt.Errorf("store.GuidanceScanRoots: scan: %w", err)
		}
		if root != "" {
			out = append(out, root)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.GuidanceScanRoots: iterate: %w", err)
	}
	return out, nil
}

// GuidanceUsageWindowDays is the default lookback for [Store.GuidanceUsage].
// A guidance file is a slow-moving thing; 90 days is long enough that a
// skill used once a quarter still reads as "used", and short enough that
// the answer describes how the project works NOW.
const GuidanceUsageWindowDays = 90

// GuidanceUsageStat is one joined usage fact: how many times a guidance
// unit was named by a capture signal inside the window, and when it was
// last named. A zero value means "never inside the window" — which is a
// real answer only for a (tool, kind) pair that CAN emit the signal; see
// the dashboard's usage enum.
type GuidanceUsageStat struct {
	Count int       `json:"count"`
	Last  time.Time `json:"last"`
}

// GuidanceUsage is one project's joined guidance-usage facts.
//
// Skills is keyed by [guidance.SkillKey] — the case-folded,
// extension-stripped "<tool>/<kind>/<name>" identity — so a scanned
// `.claude/skills/deploy/SKILL.md` row joins a `skill_invoke` action
// whose target is "deploy" without either side agreeing on a path.
//
// Files is keyed by the CLEANED absolute path an `instructions_loaded`
// action recorded, which is the same spelling the scanner stored as a
// row's AbsPath.
type GuidanceUsage struct {
	// Since is the start of the window the counts cover. It is carried
	// back so a surface can say "in 90d" honestly rather than assuming.
	Since  time.Time
	Skills map[string]GuidanceUsageStat
	Files  map[string]GuidanceUsageStat
}

// guidanceUsageQuery is the joined usage aggregate, kept as a package
// constant so a test can EXPLAIN the EXACT string production runs.
//
// The plan matters more than the rows here. `actions` is the biggest table
// in the store (734k rows on one live host) and this query runs on a
// dashboard GET, so the only acceptable plan is a seek on
// idx_actions_type: `skill_invoke` + `instructions_loaded` are two rare
// action types, while idx_actions_project would hand back every action of
// the operator's main project and filter 99% of them away in Go's stead.
//
// The unary `+` on project_id is what forces that choice. It disqualifies
// the column from index use (a documented SQLite operator, not a hint), so
// the planner is left with the selective index. Unlike INDEXED BY it
// degrades to a scan rather than a hard error if the index ever goes away.
const guidanceUsageQuery = `
SELECT action_type, tool, target, COUNT(*) AS n, MAX(timestamp) AS last_at
  FROM actions
 WHERE action_type IN (?, ?)
   AND +project_id = ?
   AND timestamp >= ?
   AND target IS NOT NULL
   AND target <> ''
 GROUP BY action_type, tool, target`

// GuidanceUsage joins the guidance inventory to capture: per normalized
// skill key, how many `skill_invoke` actions named it inside the window;
// per absolute file path, how many `instructions_loaded` actions loaded
// it.
//
// It answers only for tools that actually emit those signals. A tool with
// no invocation signal produces no rows here, which is NOT the same as
// zero invocations — the caller must render that difference (the dashboard
// does, via its `not_measurable` usage enum). Returning an empty map for
// an unmeasurable tool and letting a surface print "0" would be the one
// dishonest outcome this whole feature exists to avoid.
//
// since bounds the window; a zero value means [GuidanceUsageWindowDays]
// back from now. An unknown project root is not an error: it returns empty
// maps, because "this root has no captured activity" is a legitimate
// answer, not a failure.
func (s *Store) GuidanceUsage(ctx context.Context, projectRoot string, since time.Time) (GuidanceUsage, error) {
	out := GuidanceUsage{
		Skills: map[string]GuidanceUsageStat{},
		Files:  map[string]GuidanceUsageStat{},
	}
	projectRoot = strings.TrimSpace(projectRoot)
	if projectRoot == "" {
		return out, errors.New("store.GuidanceUsage: empty project root")
	}
	if since.IsZero() {
		since = time.Now().UTC().AddDate(0, 0, -GuidanceUsageWindowDays)
	}
	out.Since = since.UTC()

	// The sentinel root is not a project and has no actions of its own:
	// home-scope guidance is USED inside whatever project the session ran
	// in, so asking for "~" has no answer to give.
	if projectRoot == GuidanceUserScopeRoot {
		return out, nil
	}

	var projectID int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM projects WHERE root_path = ?`, projectRoot).Scan(&projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("store.GuidanceUsage: resolve project: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, guidanceUsageQuery,
		models.ActionSkillInvoke, models.ActionInstructionsLoaded,
		projectID, formatGuidanceTime(out.Since))
	if err != nil {
		return out, fmt.Errorf("store.GuidanceUsage: query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			actionType, tool, target string
			n                        int
			lastAt                   sql.NullString
		)
		if err := rows.Scan(&actionType, &tool, &target, &n, &lastAt); err != nil {
			return out, fmt.Errorf("store.GuidanceUsage: scan: %w", err)
		}
		stat := GuidanceUsageStat{Count: n}
		if lastAt.Valid {
			stat.Last = parseGuidanceTime(lastAt.String)
		}
		switch actionType {
		case models.ActionSkillInvoke:
			// The SAME normalization the scanner's SkillKey applies, so a
			// transcript's "deploy" and a scan's "deploy.md" are one key.
			key := guidance.SkillKey(tool, guidance.KindSkill, target)
			mergeGuidanceUsage(out.Skills, key, stat)
		case models.ActionInstructionsLoaded:
			mergeGuidanceUsage(out.Files, filepath.Clean(target), stat)
		}
	}
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("store.GuidanceUsage: iterate: %w", err)
	}
	return out, nil
}

// mergeGuidanceUsage folds a grouped row into its normalized key. Two
// different raw spellings ("deploy" and "deploy.md", or the same skill
// invoked under two tool casings) collapse onto one key, so the counts
// must add rather than overwrite.
func mergeGuidanceUsage(into map[string]GuidanceUsageStat, key string, stat GuidanceUsageStat) {
	if key == "" {
		return
	}
	prev := into[key]
	prev.Count += stat.Count
	if stat.Last.After(prev.Last) {
		prev.Last = stat.Last
	}
	into[key] = prev
}

// GuidanceNeverScannedExcludeCap bounds how many already-attempted roots
// GuidanceNeverScannedRoots will push into its SQL exclusion.
//
// It is far above any plausible project count (the worst live machine on
// record carried 404 recorded roots) and far below SQLite's own bound-
// parameter ceiling, so in practice the exclusion is always complete. Past
// the cap the query degrades to offering some already-attempted roots, which
// the caller filters out in Go — a wasted slot, never a wrong scan.
const GuidanceNeverScannedExcludeCap = 5000

// GuidanceNeverScannedRoots lists project roots that have NO guidance row
// at all AND are not in exclude — the roots a first-scan trigger has still to
// offer, most recently active first and capped at limit.
//
// "No row" is the only never-scanned marker the schema carries: last_scanned
// lives per FILE, so a root that was scanned and genuinely has no guidance
// file is indistinguishable here from one that was never walked. That is why
// the caller (cmd/observer's first-scan poll) remembers what it has already
// attempted for the daemon's lifetime — otherwise a guidance-free project
// would be re-walked on every poll forever.
//
// exclude is that memory, and it MUST be applied here rather than by the
// caller after the fact. Filtering in Go AFTER the SQL LIMIT is a starvation
// bug: once `limit` guidance-free roots occupy the head of the recency
// ordering, every page is entirely attempted, the caller filters all of it
// away, and root number limit+1 is never offered again for the daemon's
// lifetime. Pushing the exclusion into the WHERE clause makes the LIMIT a
// page of REMAINING work instead of a page of the same dead head.
//
// limit <= 0 means no cap.
func (s *Store) GuidanceNeverScannedRoots(ctx context.Context, limit int, exclude []string) ([]string, error) {
	query := `
SELECT p.root_path
  FROM projects p
 WHERE p.root_path <> ''
   AND NOT EXISTS (
       SELECT 1 FROM project_guidance_files g WHERE g.project_root = p.root_path
   )`
	args := []any{}
	if n := len(exclude); n > 0 {
		if n > GuidanceNeverScannedExcludeCap {
			n = GuidanceNeverScannedExcludeCap
		}
		placeholders := make([]string, 0, n)
		for _, root := range exclude[:n] {
			placeholders = append(placeholders, "?")
			args = append(args, root)
		}
		query += "\n   AND p.root_path NOT IN (" + strings.Join(placeholders, ", ") + ")"
	}
	query += `
 ORDER BY COALESCE(NULLIF(p.last_session_at, ''), p.created_at) DESC, p.id DESC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store.GuidanceNeverScannedRoots: query: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var root string
		if err := rows.Scan(&root); err != nil {
			return nil, fmt.Errorf("store.GuidanceNeverScannedRoots: scan: %w", err)
		}
		if root != "" {
			out = append(out, root)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.GuidanceNeverScannedRoots: iterate: %w", err)
	}
	return out, nil
}

// GuidanceKnownFiles is the [guidance.Options.Known] cache seam, filled
// from what the last scan of this root recorded: absolute path → the
// derived record. A scanner that finds the same size and mtime reuses
// the row instead of re-reading and re-hashing the file.
func (s *Store) GuidanceKnownFiles(ctx context.Context, projectRoot string) (map[string]guidance.KnownFile, error) {
	rows, err := s.ListGuidance(ctx, projectRoot, false)
	if err != nil {
		return nil, err
	}
	out := make(map[string]guidance.KnownFile, len(rows))
	for _, r := range rows {
		if r.AbsPath == "" || r.ContentHash == "" {
			continue
		}
		out[r.AbsPath] = guidance.KnownFile{
			SizeBytes:   r.SizeBytes,
			ModTime:     r.ModifiedAt,
			ContentHash: r.ContentHash,
			Name:        r.Name,
			Description: r.Description,
			Frontmatter: r.Frontmatter,
			ParseErr:    r.ParseError,
		}
	}
	return out, nil
}

// encodeGuidanceFrontmatter renders the flat front-matter map as the
// stored JSON object. An empty map stores "{}" so the column is always
// valid JSON a reader can decode without a nil check.
func encodeGuidanceFrontmatter(fm map[string]string) string {
	if len(fm) == 0 {
		return "{}"
	}
	b, err := json.Marshal(fm)
	if err != nil {
		// A map[string]string cannot fail to marshal; degrade to the
		// empty object rather than failing a whole scan over it.
		return "{}"
	}
	return string(b)
}

func decodeGuidanceFrontmatter(s string) map[string]string {
	if s == "" || s == "{}" {
		return nil
	}
	var fm map[string]string
	if err := json.Unmarshal([]byte(s), &fm); err != nil {
		return nil
	}
	if len(fm) == 0 {
		return nil
	}
	return fm
}

// formatGuidanceTime stores a timestamp in the store's usual UTC
// RFC3339Nano form. A zero time stores as the empty string so "never
// modified" is distinguishable from "modified at the epoch".
func formatGuidanceTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseGuidanceTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}
