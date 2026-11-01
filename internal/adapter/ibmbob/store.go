package ibmbob

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// allHomesFunc is the test seam over crossmount.AllHomes — tests override
// it to assert foreign-mount detection without depending on the host's
// filesystem layout. Same shape as goose.allHomesFunc.
var allHomesFunc = crossmount.AllHomes

// dbFile is the store's file name; storeDirName its parent directory.
const (
	dbFile       = "bob.db"
	storeDirName = "db"
)

// defaultRoots returns one watch root per cross-mount-resolved home: the
// `.bob/db` directory. Bob Shell uses the same home-relative path on every
// OS (path.join(os.homedir(), ".bob", "db")), so no per-OS branch is
// needed. Non-existent dirs are inert (the watcher skips them at registry
// time).
func defaultRoots() []string {
	var roots []string
	seen := map[string]struct{}{}
	for _, h := range allHomesFunc() {
		if h.Path == "" {
			continue
		}
		p := filepath.Clean(filepath.Join(h.Path, ".bob", storeDirName))
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		roots = append(roots, p)
	}
	return roots
}

// resolveDBPath maps a -wal/-shm sibling event back to the main bob.db.
func resolveDBPath(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == dbFile+"-wal" || base == dbFile+"-shm" {
		return filepath.Join(filepath.Dir(path), dbFile)
	}
	return path
}

// openReadOnlyDB opens bob.db read-only, staging a local mirror first when
// the source is a foreign mount.
func openReadOnlyDB(path string) (*sql.DB, error) {
	actual, err := stageMirrorIfForeign(path)
	if err != nil {
		return nil, fmt.Errorf("ibmbob.stageMirror: %w", err)
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
	Dir:    "ibmbob-mirror",
	File:   "bob.db",
	Tables: []string{"tasks", "messages"},
}

// isForeignMountPath reports whether path lives under a crossmount-detected
// non-native home. Covers both bridge directions (/mnt/c on WSL2, and
// \\wsl.localhost\ on Windows).
func isForeignMountPath(path string) bool {
	for _, h := range allHomesFunc() {
		if h.Origin == "native" || h.Path == "" {
			continue
		}
		sep := string(filepath.Separator)
		if strings.HasPrefix(path, h.Path+sep) || strings.HasPrefix(path, h.Path+"/") {
			return true
		}
	}
	return false
}

// taskRow is the tasks-table metadata this adapter needs.
type taskRow struct {
	ID        string
	ProjectID string
	ParentID  string
	TaskType  string
	EnvJSON   string
	CreatedAt int64
	UpdatedAt int64
	// Version is tasks.version (NULL on every grounded 2.0.6 row; the
	// per-session tool version when a build records it).
	Version string
	// GitBranch is tasks.git_branch (NULL on every grounded row).
	GitBranch string
	// ApprovalConfig is the tasks.approval_config JSON (auto-approval
	// switch + allowed permission groups + per-task command approvals).
	ApprovalConfig string
	// LastError is the tasks.last_error JSON ("null" text when clear).
	LastError string
}

// messageRow is one row of the Bob `messages` table.
type messageRow struct {
	ID        string
	Role      string
	Data      string
	CreatedAt int64
}

// maxTaskUpdatedAt returns the store's high-water mark: the newest
// tasks.updated_at (epoch ms). Every Bob message write (addMessage,
// upsertMessage, the whole-task save) bumps its task's updated_at in the
// same statement batch, and an assistant row is REWRITTEN in place when its
// spend lands, so a row-id watermark would freeze mid-turn while this one
// moves. A missing table (foreign/partial schema) yields 0.
func maxTaskUpdatedAt(ctx context.Context, db *sql.DB) (int64, error) {
	if !tableExists(ctx, db, "tasks") {
		return 0, nil
	}
	var v sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(updated_at) FROM tasks`).Scan(&v); err != nil {
		return 0, err
	}
	return v.Int64, nil
}

// loadTouchedTasks returns the tasks whose updated_at is at or past
// fromOffset (every task when fromOffset is 0). The comparison is `>=`, not
// `>`: the task whose write produced the previous watermark may have been
// written again within the same millisecond after the previous read.
// Re-emitting an already-seen task is a no-op downstream under
// (source_file, source_event_id) dedup.
func loadTouchedTasks(ctx context.Context, db *sql.DB, fromOffset int64) ([]taskRow, error) {
	if !tableExists(ctx, db, "tasks") {
		return nil, nil
	}
	cols := taskColumns(ctx, db)
	/* #nosec G202 -- optionalText yields a compile-time column name the caller passes as a literal, or '' */
	rows, err := db.QueryContext(ctx, `
		SELECT id, COALESCE(project_id, ''), COALESCE(parent_id, ''),
		       COALESCE(task_type, ''), COALESCE(env, ''),
		       COALESCE(created_at, 0), COALESCE(updated_at, 0),
		       `+optionalText(cols, "version")+`,
		       `+optionalText(cols, "git_branch")+`,
		       `+optionalText(cols, "approval_config")+`,
		       `+optionalText(cols, "last_error")+`
		  FROM tasks
		 WHERE COALESCE(updated_at, 0) >= ?
		 ORDER BY created_at ASC, id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []taskRow
	for rows.Next() {
		var t taskRow
		if err := rows.Scan(&t.ID, &t.ProjectID, &t.ParentID, &t.TaskType, &t.EnvJSON,
			&t.CreatedAt, &t.UpdatedAt,
			&t.Version, &t.GitBranch, &t.ApprovalConfig, &t.LastError); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// loadMessages returns every message of a task in Bob's own replay order:
// created_at ASC (the save time, shared by a whole turn) then rowid ASC
// (insertion order).
func loadMessages(ctx context.Context, db *sql.DB, taskID string) ([]messageRow, error) {
	if !tableExists(ctx, db, "messages") {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, role, data, created_at
		  FROM messages
		 WHERE task_id = ?
		 ORDER BY created_at ASC, rowid ASC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []messageRow
	for rows.Next() {
		var m messageRow
		if err := rows.Scan(&m.ID, &m.Role, &m.Data, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// tableExists reports whether a table is present in the store, so a foreign
// or older schema degrades gracefully instead of erroring.
func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var got string
	err := db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&got)
	return err == nil && got == name
}

// taskColumns returns the set of column names present on the tasks table.
// Bob added version / approval_config / last_error by later ALTER TABLE
// migrations, so an older or foreign store may lack them; selecting a
// missing column would fail the whole read.
func taskColumns(ctx context.Context, db *sql.DB) map[string]struct{} {
	out := map[string]struct{}{}
	rows, err := db.QueryContext(ctx, `SELECT name FROM pragma_table_info('tasks')`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err == nil {
			out[n] = struct{}{}
		}
	}
	return out
}

// optionalText is a SELECT expression yielding the column as text, or the
// empty string when the column does not exist in this store's schema.
func optionalText(cols map[string]struct{}, name string) string {
	if _, ok := cols[name]; ok {
		return "COALESCE(" + name + ", '')"
	}
	return "''"
}
