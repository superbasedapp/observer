package dimcode

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// storeFile is the basename of DimCode's single central WAL SQLite store.
const storeFile = "dimcode.sqlite"

// homeEnv is DimCode's own home-override variable (read out of the vendor
// binary: when set, the store lives at $DIMCODE_HOME/v2 unless the value
// already ends in `v2`).
const homeEnv = "DIMCODE_HOME"

// allHomesFunc is the test seam over crossmount.AllHomes. Same shape as
// goose.allHomesFunc / crush.allHomesFunc.
var allHomesFunc = crossmount.AllHomes

// storeSubdir is the path-segment list of DimCode's store directory under a
// home. DimCode uses ~/.dimcode/v2 on EVERY OS (it does not follow XDG or
// %APPDATA%), so unlike goose there is no per-OS table.
var storeSubdir = []string{".dimcode", "v2"}

// defaultRoots returns one watch root per cross-mount-resolved home: the
// `~/.dimcode/v2` directory, plus the $DIMCODE_HOME override when the
// observer's own environment carries one. Non-existent dirs are inert (the
// watcher skips them at registry time).
func defaultRoots() []string {
	var roots []string
	seen := map[string]struct{}{}
	add := func(p string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		roots = append(roots, p)
	}
	for _, h := range allHomesFunc() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(append([]string{h.Path}, storeSubdir...)...))
	}
	add(rootFromEnv(os.Getenv(homeEnv)))
	return roots
}

// rootFromEnv mirrors DimCode's resolveCliHomeDirFromEnv: a blank value is
// ignored, a value whose basename is already `v2` is used as-is, anything
// else gets `v2` appended.
func rootFromEnv(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	norm := filepath.Clean(value)
	if filepath.Base(norm) == storeSubdir[1] {
		return norm
	}
	return filepath.Join(norm, storeSubdir[1])
}

// resolveDBPath maps a -wal/-shm sibling event back to the main store file.
func resolveDBPath(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == storeFile+"-wal" || base == storeFile+"-shm" {
		return filepath.Join(filepath.Dir(path), storeFile)
	}
	return path
}

// openReadOnlyDB opens the store read-only, staging a local mirror first when
// the source is a foreign mount.
func openReadOnlyDB(path string) (*sql.DB, error) {
	actual, err := stageMirrorIfForeign(path)
	if err != nil {
		return nil, fmt.Errorf("dimcode.stageMirror: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)", sqlitedsn.Escape(actual))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// stageMirrorIfForeign returns srcDB unchanged when it is native. A
// foreign-mount store (a Windows-side store read by a WSL observer over
// /mnt/c, or the reverse), which modernc.org/sqlite cannot open in place
// while the vendor process writes its WAL, is read through a filtered local
// mirror built by mirrorbase.Stage: only the tables in mirrorSpec are kept,
// so the store's other tables never leave the vendor's file (T-927,
// MIRROR-CRED-1; this adapter's private byte copy was RB1 sweep finding A2).
func stageMirrorIfForeign(srcDB string) (string, error) {
	if !isForeignMountPath(srcDB) {
		return srcDB, nil
	}
	return mirrorbase.Stage(context.Background(), srcDB, mirrorSpec)
}

// mirrorSpec is the allow-list mirror of the store: every table this
// package queries and nothing else. A query on a new table must add it
// here, or the foreign-mount mirror silently lacks it;
// mirrortest.AssertSpecCoversQueries pins that.
var mirrorSpec = mirrorbase.Spec{
	Dir:    "dimcode-mirror",
	File:   "dimcode.sqlite",
	Tables: []string{"sessions", "messages", "session_relations", "session_states", "usage_ledger", "usage_run_stats"},
}

// isForeignMountPath reports whether path lives under a crossmount-detected
// non-native home. Covers both bridge directions.
func isForeignMountPath(path string) bool {
	for _, h := range allHomesFunc() {
		if h.Origin == "native" {
			continue
		}
		sep := string(filepath.Separator)
		if strings.HasPrefix(path, h.Path+sep) || strings.HasPrefix(path, h.Path+"/") {
			return true
		}
	}
	return false
}

// sessionRow is the sessions + session_states metadata one parse needs.
type sessionRow struct {
	ID       string
	CWD      string
	Provider string
	Model    string
	Settings string
	// PermissionSettings is session_states.permissionSettings (JSON): the
	// approval posture (humanApprovalMode, toolPermissions, ...).
	PermissionSettings string
	// CurrentMode is session_states.currentMode ("agent" live).
	CurrentMode string
}

// messageRow is one row of the DimCode `messages` table.
type messageRow struct {
	ID           string
	Role         string
	Parts        string
	ToolMetadata string
	Metadata     string
	CreatedAt    string
	UpdatedAt    string
}

// runRow is one row of `usage_run_stats`.
type runRow struct {
	RunID      string
	Provider   string
	Model      string
	Status     string
	EndedAt    string
	DurationMs sql.NullInt64
	Input      int64
	Output     int64
	CacheRead  sql.NullInt64
	CacheWrite sql.NullInt64
	Cost       string
}

// ledgerRow is one row of `usage_ledger`.
type ledgerRow struct {
	LedgerID  string
	RunID     string
	Provider  string
	Model     string
	Usage     string
	CreatedAt string
}

// relationRow is one row of `session_relations`.
type relationRow struct {
	Source string
	Target string
	Type   string
}

// tableExists reports whether a table is present in the store, so an older or
// partial schema degrades gracefully instead of erroring.
func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var got string
	err := db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&got)
	return err == nil && got == name
}

// columnExists reports whether table has the named column, so a store from a
// build that predates a column degrades to an empty value instead of failing
// the whole parse.
func columnExists(ctx context.Context, db *sql.DB, table, column string) bool {
	rows, err := db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err == nil && n == column {
			return true
		}
	}
	return false
}

// watermarkSources lists every (table, timestamp column) whose newest value
// advances the incremental cursor. sessions.updatedAt alone is NOT enough: it
// stays at session start while a run keeps appending messages.
var watermarkSources = []struct{ table, column string }{
	{"sessions", "updatedAt"},
	{"messages", "updatedAt"},
	{"usage_run_stats", "updatedAt"},
	{"usage_ledger", "createdAt"},
	{"session_relations", "createdAt"},
}

// latestWatermark returns the newest timestamp across watermarkSources in
// epoch milliseconds (0 for an empty or unrecognised store).
func latestWatermark(ctx context.Context, db *sql.DB) (int64, error) {
	var best int64
	for _, src := range watermarkSources {
		if !tableExists(ctx, db, src.table) {
			continue
		}
		var v sql.NullString
		q := fmt.Sprintf(`SELECT MAX(%s) FROM %s`, src.column, src.table) //nolint:gosec // G201: table and column come from the fixed watermarkSources table, never input
		if err := db.QueryRowContext(ctx, q).Scan(&v); err != nil {
			return 0, fmt.Errorf("%s.%s: %w", src.table, src.column, err)
		}
		t := parseTime(v.String)
		if t.IsZero() {
			continue
		}
		if ms := t.UnixMilli(); ms > best {
			best = ms
		}
	}
	return best, nil
}

// thresholdString renders a watermark as the RFC3339 millisecond form
// DimCode writes, so lexical comparison against its timestamp columns is a
// chronological comparison. 0 renders as "" (every non-empty value is newer).
func thresholdString(fromOffset int64) string {
	if fromOffset <= 0 {
		return ""
	}
	return time.UnixMilli(fromOffset).UTC().Format("2006-01-02T15:04:05.000Z")
}

// loadTouchedSessions returns the sessions that gained any message, run row,
// ledger row or session-row update strictly newer than fromOffset, with the
// currently-selected provider/model/settings joined from session_states.
func loadTouchedSessions(ctx context.Context, db *sql.DB, fromOffset int64) ([]sessionRow, error) {
	if !tableExists(ctx, db, "sessions") {
		return nil, nil
	}
	conds := []string{"s.updatedAt > ?1"}
	if tableExists(ctx, db, "messages") {
		conds = append(conds, `EXISTS (SELECT 1 FROM messages m WHERE m.sessionId = s.sessionId AND m.updatedAt > ?1)`)
	}
	if tableExists(ctx, db, "usage_run_stats") {
		conds = append(conds, `EXISTS (SELECT 1 FROM usage_run_stats u WHERE u.sessionId = s.sessionId AND u.updatedAt > ?1)`)
	}
	if tableExists(ctx, db, "usage_ledger") {
		conds = append(conds, `EXISTS (SELECT 1 FROM usage_ledger l WHERE l.sessionId = s.sessionId AND l.createdAt > ?1)`)
	}
	sel := `COALESCE(s.sessionId,''), COALESCE(s.cwd,''), '', '', '', '', ''`
	join := ""
	if tableExists(ctx, db, "session_states") {
		perm, mode := `''`, `''`
		if columnExists(ctx, db, "session_states", "permissionSettings") {
			perm = `COALESCE(t.permissionSettings,'')`
		}
		if columnExists(ctx, db, "session_states", "currentMode") {
			mode = `COALESCE(t.currentMode,'')`
		}
		sel = `COALESCE(s.sessionId,''), COALESCE(s.cwd,''), COALESCE(t.selectedProviderId,''), COALESCE(t.selectedModelId,''), COALESCE(t.settings,''), ` + perm + `, ` + mode
		join = `LEFT JOIN session_states t ON t.sessionId = s.sessionId`
	}
	//nolint:gosec // G201: every fragment is a constant chosen above; the only value is the ?1 bind
	q := fmt.Sprintf(`SELECT %s FROM sessions s %s WHERE %s ORDER BY s.createdAt ASC, s.sessionId ASC`,
		sel, join, strings.Join(conds, " OR "))
	rows, err := db.QueryContext(ctx, q, thresholdString(fromOffset))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sessionRow
	for rows.Next() {
		var s sessionRow
		if err := rows.Scan(&s.ID, &s.CWD, &s.Provider, &s.Model, &s.Settings, &s.PermissionSettings, &s.CurrentMode); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// loadMessages returns every message of a session in chronological order.
func loadMessages(ctx context.Context, db *sql.DB, sessionID string) ([]messageRow, error) {
	if !tableExists(ctx, db, "messages") {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT messageId, role, COALESCE(parts,''), COALESCE(toolMetadata,''),
		       COALESCE(metadata,''), COALESCE(createdAt,''), COALESCE(updatedAt,'')
		  FROM messages
		 WHERE sessionId = ?
		 ORDER BY orderKey ASC, messageId ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []messageRow
	for rows.Next() {
		var m messageRow
		if err := rows.Scan(&m.ID, &m.Role, &m.Parts, &m.ToolMetadata, &m.Metadata, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// loadRuns returns a session's usage_run_stats rows, oldest first.
func loadRuns(ctx context.Context, db *sql.DB, sessionID string) ([]runRow, error) {
	if !tableExists(ctx, db, "usage_run_stats") {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT runId, COALESCE(providerId,''), COALESCE(modelId,''), COALESCE(status,''),
		       COALESCE(endedAt,''), durationMs, inputTokens, outputTokens,
		       cacheReadTokens, cacheWriteTokens, COALESCE(cost,'')
		  FROM usage_run_stats
		 WHERE sessionId = ?
		 ORDER BY endedAt ASC, runId ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runRow
	for rows.Next() {
		var r runRow
		if err := rows.Scan(&r.RunID, &r.Provider, &r.Model, &r.Status, &r.EndedAt,
			&r.DurationMs, &r.Input, &r.Output, &r.CacheRead, &r.CacheWrite, &r.Cost); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// loadLedger returns a session's usage_ledger rows, oldest first.
func loadLedger(ctx context.Context, db *sql.DB, sessionID string) ([]ledgerRow, error) {
	if !tableExists(ctx, db, "usage_ledger") {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT ledgerId, COALESCE(runId,''), COALESCE(providerId,''), COALESCE(modelId,''),
		       COALESCE(usage,''), COALESCE(createdAt,'')
		  FROM usage_ledger
		 WHERE sessionId = ?
		 ORDER BY createdAt ASC, ledgerId ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ledgerRow
	for rows.Next() {
		var l ledgerRow
		if err := rows.Scan(&l.LedgerID, &l.RunID, &l.Provider, &l.Model, &l.Usage, &l.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// loadRelations returns every session_relations row. The set is small (one
// row per spawned sub-agent or fork), so it is read whole on every parse and
// the idempotent lineage upsert converges without dedicated watermark state.
func loadRelations(ctx context.Context, db *sql.DB) ([]relationRow, error) {
	if !tableExists(ctx, db, "session_relations") {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT COALESCE(sourceSessionId,''), COALESCE(targetSessionId,''), COALESCE(relationType,'')
		  FROM session_relations
		 ORDER BY createdAt ASC, relationId ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []relationRow
	for rows.Next() {
		var r relationRow
		if err := rows.Scan(&r.Source, &r.Target, &r.Type); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// parseTime parses DimCode's RFC3339-with-milliseconds UTC timestamps
// ("2026-10-21T06:08:53.471Z"). An empty or unparseable value yields the zero
// time.
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}
