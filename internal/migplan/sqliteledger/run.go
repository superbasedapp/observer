package sqliteledger

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/migplan"
)

// Entry is one embedded migration file: its version (the file name's
// leading integer) and its file name.
type Entry struct {
	Version int
	File    string
}

// ReadEntries lists source's NNN_name.sql files in ascending version order.
// errPrefix names the caller in errors (for example
// "archivestore.readMigrationEntries"); a .sql file whose leading segment is
// not an integer is an error.
func ReadEntries(source fs.FS, errPrefix string) ([]Entry, error) {
	dirEntries, err := fs.ReadDir(source, ".")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errPrefix, err)
	}
	var entries []Entry
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if filepath.Ext(name) != ".sql" {
			continue
		}
		prefix := strings.SplitN(name, "_", 2)[0]
		v, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("%s: unparseable migration %q: %w", errPrefix, name, err)
		}
		entries = append(entries, Entry{Version: v, File: name})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Version < entries[j].Version })
	return entries, nil
}

// Run is one complete migration pass of a SQLite runner over entries (read
// from source with ReadEntries): it creates schema_meta if absent, pins one
// connection, takes the migration lock with BEGIN IMMEDIATE, plans with Plan
// on that connection, executes each step's SQL from source through Apply,
// and commits. The whole pass, steps and bookkeeping, is one transaction: a
// failing step rolls everything back. The deferred ROLLBACK runs on a
// context that ignores ctx's cancellation, so a cancelled pass never returns
// its pinned connection to the pool still inside BEGIN IMMEDIATE.
//
// errPrefix names the runner in its errors (for example
// "archivestore.runMigrations"); a failing step's error reads
// "<errPrefix>: exec <file>: <cause>".
//
// Runners with extra needs (the node database's lock wait and lock-free
// no-op fast path) keep their own sequence and call Plan and Apply directly.
func Run(ctx context.Context, db *sql.DB, source fs.FS, entries []Entry, late []migplan.LateStep, errPrefix string) error {
	embedded := make([]int, 0, len(entries))
	byVersion := make(map[int]Entry, len(entries))
	for _, e := range entries {
		embedded = append(embedded, e.Version)
		byVersion[e.Version] = e
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_meta (
		key TEXT PRIMARY KEY, value TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("%s: bootstrap schema_meta: %w", errPrefix, err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("%s: acquire connection: %w", errPrefix, err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("%s: acquire migration lock: %w", errPrefix, err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		}
	}()

	plan, err := Plan(ctx, conn, embedded, late)
	if err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}
	if err := Apply(ctx, conn, plan, func(version int) error {
		e := byVersion[version]
		body, readErr := fs.ReadFile(source, e.File)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", e.File, readErr)
		}
		if _, err := conn.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("exec %s: %w", e.File, err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("%s: commit: %w", errPrefix, err)
	}
	committed = true
	return nil
}
