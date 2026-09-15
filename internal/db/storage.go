package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Storage manager primitives (usability arc P6.8). This file is the
// one owner of SQLite maintenance operations — the `observer db` CLI
// and the dashboard's Storage section both consume these instead of
// re-writing the SQL.

// StorageTable is one table's on-disk footprint. Bytes aggregates the
// table's own b-tree plus its indexes and (for FTS5 virtual tables)
// shadow tables, so the list reads like the schema the operator
// knows, not SQLite internals. Rows is -1 when counting failed.
type StorageTable struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
	Rows  int64  `json:"rows"`
}

// StorageReport is the per-table breakdown plus the whole-file
// numbers the vacuum decision needs.
type StorageReport struct {
	PageSize      int64 `json:"page_size"`
	PageCount     int64 `json:"page_count"`
	FreelistPages int64 `json:"freelist_pages"`
	TotalBytes    int64 `json:"total_bytes"`
	// ReclaimableBytes estimates what VACUUM would free right now
	// (freelist pages × page size). Fragmentation inside live pages
	// isn't counted, so a vacuum can reclaim somewhat more.
	ReclaimableBytes int64          `json:"reclaimable_bytes"`
	Tables           []StorageTable `json:"tables"`
}

// Footprint is the CHEAP half of a StorageReport: the whole-file page
// accounting, with no per-table breakdown.
//
// It exists because the two halves have wildly different costs and the
// expensive one is rarely what the caller wants. Everything here comes from
// three O(1) pragma header reads, so it is safe to take on a 36 GB database —
// where the dbstat walk StorageStats performs is a full file scan.
type Footprint struct {
	PageSize      int64 `json:"page_size"`
	PageCount     int64 `json:"page_count"`
	FreelistPages int64 `json:"freelist_pages"`
	TotalBytes    int64 `json:"total_bytes"`
	// ReclaimableBytes estimates what a full rewrite would free right now
	// (freelist pages × page size). Fragmentation inside live pages is not
	// counted, so a reclaim usually returns somewhat more.
	ReclaimableBytes int64 `json:"reclaimable_bytes"`
}

// ReadFootprint reports the whole-file page accounting without touching
// dbstat. See [Footprint] for why the split exists.
func ReadFootprint(ctx context.Context, database *sql.DB) (Footprint, error) {
	var fp Footprint
	for pragma, dst := range map[string]*int64{
		"page_size":      &fp.PageSize,
		"page_count":     &fp.PageCount,
		"freelist_count": &fp.FreelistPages,
	} {
		if err := database.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(dst); err != nil {
			return fp, fmt.Errorf("db.ReadFootprint: pragma %s: %w", pragma, err)
		}
	}
	fp.TotalBytes = fp.PageSize * fp.PageCount
	fp.ReclaimableBytes = fp.PageSize * fp.FreelistPages
	return fp, nil
}

// StorageStats walks dbstat for per-b-tree sizes and aggregates them
// per user-visible table (indexes and FTS5 shadow tables fold into
// their owner). NOTE: dbstat reads every page of every b-tree — on a
// multi-hundred-MB database this is a full file scan. Call on demand,
// never on a poll loop. Callers that only need the whole-file numbers
// should use [ReadFootprint], which skips the walk.
func StorageStats(ctx context.Context, database *sql.DB) (StorageReport, error) {
	var rep StorageReport
	fp, err := ReadFootprint(ctx, database)
	if err != nil {
		return rep, err
	}
	rep.PageSize = fp.PageSize
	rep.PageCount = fp.PageCount
	rep.FreelistPages = fp.FreelistPages
	rep.TotalBytes = fp.TotalBytes
	rep.ReclaimableBytes = fp.ReclaimableBytes

	owners, ftsTables, err := schemaOwners(ctx, database)
	if err != nil {
		return rep, err
	}

	// Per-b-tree page sizes. Every b-tree (table, index, shadow table)
	// appears under its own name; fold into the owning table.
	bytesByOwner := map[string]int64{}
	rows, err := database.QueryContext(ctx, `SELECT name, SUM(pgsize) FROM dbstat GROUP BY name`)
	if err != nil {
		return rep, fmt.Errorf("db.StorageStats: dbstat: %w", err)
	}
	for rows.Next() {
		var name string
		var size int64
		if err := rows.Scan(&name, &size); err != nil {
			rows.Close()
			return rep, fmt.Errorf("db.StorageStats: dbstat scan: %w", err)
		}
		bytesByOwner[resolveOwner(name, owners, ftsTables)] += size
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return rep, fmt.Errorf("db.StorageStats: dbstat rows: %w", err)
	}
	rows.Close()

	for owner, size := range bytesByOwner {
		t := StorageTable{Name: owner, Bytes: size, Rows: -1}
		if owner != sqliteInternalGroup {
			// COUNT works for both regular and FTS5 virtual tables.
			// Identifiers come from sqlite_schema, not user input; quote
			// defensively anyway.
			var n int64
			if err := database.QueryRowContext(ctx,
				fmt.Sprintf("SELECT COUNT(*) FROM %q", owner)).Scan(&n); err == nil {
				t.Rows = n
			}
		}
		rep.Tables = append(rep.Tables, t)
	}
	sort.Slice(rep.Tables, func(i, j int) bool {
		if rep.Tables[i].Bytes != rep.Tables[j].Bytes {
			return rep.Tables[i].Bytes > rep.Tables[j].Bytes
		}
		return rep.Tables[i].Name < rep.Tables[j].Name
	})
	return rep, nil
}

// sqliteInternalGroup is the display bucket for sqlite_* b-trees
// (schema table, sequence table, auto-indexes without a resolvable
// owner).
const sqliteInternalGroup = "(sqlite internals)"

// schemaOwners maps every named schema object to the table it belongs
// to, and reports which tables are FTS5 virtual tables (their shadow
// tables fold into them by name prefix).
func schemaOwners(ctx context.Context, database *sql.DB) (owners map[string]string, ftsTables []string, err error) {
	owners = map[string]string{}
	rows, err := database.QueryContext(ctx,
		`SELECT name, tbl_name, type, COALESCE(sql, '') FROM sqlite_schema`)
	if err != nil {
		return nil, nil, fmt.Errorf("db.StorageStats: schema: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, tbl, typ, sqlText string
		if err := rows.Scan(&name, &tbl, &typ, &sqlText); err != nil {
			return nil, nil, fmt.Errorf("db.StorageStats: schema scan: %w", err)
		}
		owners[name] = tbl
		if typ == "table" && strings.Contains(strings.ToLower(sqlText), "using fts5") {
			ftsTables = append(ftsTables, name)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("db.StorageStats: schema rows: %w", err)
	}
	// Longest prefix first so e.g. "a_b" wins over "a" for "a_b_data".
	sort.Slice(ftsTables, func(i, j int) bool { return len(ftsTables[i]) > len(ftsTables[j]) })
	return owners, ftsTables, nil
}

// resolveOwner folds a dbstat b-tree name into its user-visible
// table: indexes via sqlite_schema's tbl_name, FTS5 shadow tables via
// the virtual table's name prefix, sqlite_* internals into one
// bucket.
func resolveOwner(name string, owners map[string]string, ftsTables []string) string {
	if tbl, ok := owners[name]; ok && tbl != "" && tbl != name {
		name = tbl
	}
	for _, fts := range ftsTables {
		if strings.HasPrefix(name, fts+"_") {
			return fts
		}
	}
	if strings.HasPrefix(name, "sqlite_") {
		return sqliteInternalGroup
	}
	return name
}

// Fingerprint is the cheap identity of a database file, used to prove a
// compacted copy is the same database before anything is swapped.
//
// It deliberately does NOT include row counts or a content digest. A reclaim
// copy is produced by SQLite's own VACUUM INTO, which is a page-level rewrite —
// the failure modes it can actually have are a truncated/corrupt output file
// and a wrong-file mixup, and those are exactly what quick_check plus the
// schema identity catch. Re-counting every table would turn a bounded
// verification into a second full scan of a 36 GB database to re-verify a
// property SQLite already guarantees transactionally.
type Fingerprint struct {
	// QuickCheck is the PRAGMA quick_check result; "ok" is the only pass.
	QuickCheck string `json:"quick_check"`
	// UserVersion is PRAGMA user_version — the migration lineage marker.
	UserVersion int64 `json:"user_version"`
	// SchemaObjects counts rows in sqlite_schema (tables, indexes, triggers,
	// views). A copy that lost objects is not the same database.
	SchemaObjects int64 `json:"schema_objects"`
}

// ReadFingerprint reads the identity of an open database. See [Fingerprint].
//
// quick_check is used rather than integrity_check deliberately: it skips the
// (expensive) index-consistency cross-checks and still detects the structural
// damage a bad copy would have — the same trade the size-gated startup check
// makes.
func ReadFingerprint(ctx context.Context, database *sql.DB) (Fingerprint, error) {
	var fp Fingerprint
	if err := database.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&fp.QuickCheck); err != nil {
		return fp, fmt.Errorf("db.ReadFingerprint: quick_check: %w", err)
	}
	if err := database.QueryRowContext(ctx, "PRAGMA user_version").Scan(&fp.UserVersion); err != nil {
		return fp, fmt.Errorf("db.ReadFingerprint: user_version: %w", err)
	}
	if err := database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sqlite_schema").Scan(&fp.SchemaObjects); err != nil {
		return fp, fmt.Errorf("db.ReadFingerprint: schema count: %w", err)
	}
	return fp, nil
}

// OpenPlain opens an existing SQLite file with no migrations, no integrity
// gate, and a single connection — the handle you want for INSPECTING a file
// (a freshly written reclaim copy, say) rather than running the agent against
// it. [Open] would apply the agent's migration lineage, which is precisely
// what an inspection must not do.
//
// The caller closes the returned handle.
func OpenPlain(ctx context.Context, path string) (*sql.DB, error) {
	if path == "" {
		return nil, errors.New("db.OpenPlain: path is required")
	}
	database, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("db.OpenPlain: %w", err)
	}
	database.SetMaxOpenConns(1)
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("db.OpenPlain: ping %s: %w", path, err)
	}
	return database, nil
}

// Vacuum rebuilds the database file, returning the freed bytes
// (before − after, from page accounting). VACUUM needs the write lock
// and temporarily doubles disk usage; run it at a quiet moment.
func Vacuum(ctx context.Context, database *sql.DB) (freedBytes int64, err error) {
	before, err := fileBytes(ctx, database)
	if err != nil {
		return 0, err
	}
	if _, err := database.ExecContext(ctx, "VACUUM"); err != nil {
		return 0, fmt.Errorf("db.Vacuum: %w", err)
	}
	after, err := fileBytes(ctx, database)
	if err != nil {
		return 0, err
	}
	return before - after, nil
}

// BackupInto writes a consistent snapshot of the live database to
// dest via VACUUM INTO — online-safe under WAL (readers and writers
// keep going; the snapshot is transactionally consistent). The
// destination must not exist; parent directories are created.
func BackupInto(ctx context.Context, database *sql.DB, dest string) error {
	if dest == "" {
		return fmt.Errorf("db.BackupInto: destination path required")
	}
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("db.BackupInto: destination %s already exists", dest)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("db.BackupInto: create backup dir: %w", err)
	}
	if _, err := database.ExecContext(ctx, "VACUUM INTO ?", dest); err != nil {
		return fmt.Errorf("db.BackupInto: %w", err)
	}
	return nil
}

func fileBytes(ctx context.Context, database *sql.DB) (int64, error) {
	var pageSize, pageCount int64
	if err := database.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return 0, fmt.Errorf("db: page_size: %w", err)
	}
	if err := database.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
		return 0, fmt.Errorf("db: page_count: %w", err)
	}
	return pageSize * pageCount, nil
}
