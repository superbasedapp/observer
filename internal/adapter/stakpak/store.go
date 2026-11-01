package stakpak

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// allHomesFunc is the test seam over crossmount.AllHomes — tests override it
// to assert foreign-mount detection without depending on the host's
// filesystem layout. Same shape as goose.allHomesFunc.
var allHomesFunc = crossmount.AllHomes

// storeSubdir returns the path segments of Stakpak's local data directory
// below a home. Stakpak keeps `~/.stakpak/data/local.db` on every OS
// (live-verified on WSL and Windows, 2026-10-21), so the logical OS of the
// home does not change the segments.
func storeSubdir(_ string) []string {
	return []string{".stakpak", "data"}
}

// defaultRoots returns one watch root per cross-mount-resolved home: the
// `.stakpak/data` directory. The OS is the LOGICAL OS of the home
// (crossmount.HomeRoot.OS), not runtime.GOOS — so a WSL2 observer reaches a
// Windows-side store through /mnt/c/Users/<u>/.stakpak/data and a Windows
// observer reaches a WSL store through
// \\wsl.localhost\<distro>\home\<u>\.stakpak\data. Non-existent dirs are
// inert (the watcher skips them at registry time).
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
		add(filepath.Join(append([]string{h.Path}, storeSubdir(h.OS)...)...))
	}
	return roots
}

// resolveDBPath maps a -wal/-shm sibling event back to the main local.db.
func resolveDBPath(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == "local.db-wal" || base == "local.db-shm" {
		return filepath.Join(filepath.Dir(path), "local.db")
	}
	return path
}

// openReadOnlyDB opens the local.db read-only, staging a local mirror first
// when the source is a foreign mount.
func openReadOnlyDB(path string) (*sql.DB, error) {
	actual, err := stageMirrorIfForeign(path)
	if err != nil {
		return nil, fmt.Errorf("stakpak.stageMirror: %w", err)
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
	Dir:    "stakpak-mirror",
	File:   "local.db",
	Tables: []string{"sessions", "checkpoints"},
}

// isForeignMountPath reports whether path lives under a crossmount-detected
// non-native home. Covers both bridge directions (/mnt/c on WSL2, and
// \\wsl.localhost\ on Windows).
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

// maxCheckpointRowID returns the largest checkpoints.rowid in the store —
// the incremental watermark. checkpoints is an ordinary rowid table (TEXT
// primary key), rows are only appended, and the vendor never rewrites a
// checkpoint, so the rowid is monotonic. A missing table (foreign/partial
// schema) yields 0.
func maxCheckpointRowID(ctx context.Context, db *sql.DB) (int64, error) {
	if ok, err := tableExists(ctx, db, "checkpoints"); err != nil || !ok {
		return 0, err
	}
	var v sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(rowid) FROM checkpoints`).Scan(&v); err != nil {
		return 0, err
	}
	return v.Int64, nil
}

// sessionMeta is the sessions-table metadata the parser needs.
type sessionMeta struct {
	CWD string
	// CreatedAt is sessions.created_at (RFC 3339), the session-start clock.
	CreatedAt string
}

// loadSessionMeta returns session id -> metadata for every session. The
// table is tiny (one row per session) and is loaded BEFORE the checkpoint
// scan opens its cursor, because the read-only handle is single-connection.
func loadSessionMeta(ctx context.Context, db *sql.DB) (map[string]sessionMeta, error) {
	out := map[string]sessionMeta{}
	if ok, err := tableExists(ctx, db, "sessions"); err != nil || !ok {
		return out, err
	}
	rows, err := db.QueryContext(ctx, `SELECT id, COALESCE(cwd, ''), COALESCE(created_at, '') FROM sessions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var m sessionMeta
		if err := rows.Scan(&id, &m.CWD, &m.CreatedAt); err != nil {
			return nil, err
		}
		out[id] = m
	}
	return out, rows.Err()
}

// checkpointRow is one checkpoints row past the watermark, with the length
// of its parent's message list learned in SQL.
type checkpointRow struct {
	RowID     int64
	ID        string
	SessionID string
	CreatedAt string
	State     string
	// ParentLen is len(parent.state.messages); HasParent is false for a
	// root checkpoint, a dangling parent_id, or a parent whose state is not
	// valid JSON — in which case every message of this checkpoint counts as
	// new.
	ParentLen int
	HasParent bool
}

// scanCheckpointsAfter streams the checkpoints with rowid > fromOffset in
// rowid order, handing each to fn. The parent's message count is computed by
// SQLite's JSON1 (json_array_length over '$.messages') so the parent's state
// is never decoded in Go. fn returning false stops the scan.
func scanCheckpointsAfter(ctx context.Context, db *sql.DB, fromOffset int64, fn func(checkpointRow) bool) error {
	if ok, err := tableExists(ctx, db, "checkpoints"); err != nil || !ok {
		return err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT c.rowid, c.id, c.session_id, COALESCE(c.created_at, ''), COALESCE(c.state, ''),
		       CASE WHEN p.id IS NOT NULL AND json_valid(p.state)
		            THEN json_array_length(p.state, '$.messages') END
		  FROM checkpoints c
		  LEFT JOIN checkpoints p ON p.id = c.parent_id
		 WHERE c.rowid > ?
		 ORDER BY c.rowid ASC`, fromOffset)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r checkpointRow
		var parentLen sql.NullInt64
		if err := rows.Scan(&r.RowID, &r.ID, &r.SessionID, &r.CreatedAt, &r.State, &parentLen); err != nil {
			return err
		}
		if parentLen.Valid {
			r.HasParent = true
			r.ParentLen = int(parentLen.Int64)
		}
		if !fn(r) {
			break
		}
	}
	return rows.Err()
}

// tableExists reports whether a table is present in the store, so a foreign
// or older schema degrades gracefully instead of erroring. Only "no such
// table" means absent: any other error (a locked or unreadable file, a
// cancelled context) is returned, so an unreadable store never masquerades
// as an empty one.
func tableExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var got string
	err := db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return got == name, nil
}
