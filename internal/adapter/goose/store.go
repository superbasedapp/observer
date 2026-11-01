package goose

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
// filesystem layout. Same shape as devin.allHomesFunc / crush.allHomesFunc.
var allHomesFunc = crossmount.AllHomes

// storeSubdir returns the path segments of goose's session store directory
// for a home following the given logical OS. goose uses XDG on Linux/macOS
// (~/.local/share/goose/sessions) and %APPDATA%\Block\goose\data\sessions
// on Windows.
func storeSubdir(homeOS string) []string {
	if homeOS == crossmount.OSWindows {
		return []string{"AppData", "Roaming", "Block", "goose", "data", "sessions"}
	}
	return []string{".local", "share", "goose", "sessions"}
}

// defaultRoots returns one watch root per cross-mount-resolved home: the
// goose `sessions` directory. The OS is the LOGICAL OS of the home
// (crossmount.HomeRoot.OS), not runtime.GOOS — so a WSL2 observer reaches
// a Windows-side store at
// /mnt/c/Users/<u>/AppData/Roaming/Block/goose/data/sessions and a Windows
// observer reaches a WSL store at
// \\wsl.localhost\<distro>\home\<u>\.local\share\goose\sessions.
// Non-existent dirs are inert (the watcher skips them at registry time).
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

// resolveDBPath maps a -wal/-shm sibling event back to the main
// sessions.db.
func resolveDBPath(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == "sessions.db-wal" || base == "sessions.db-shm" {
		return filepath.Join(filepath.Dir(path), "sessions.db")
	}
	return path
}

// openReadOnlyDB opens the sessions.db read-only, staging a local mirror
// first when the source is a foreign mount.
func openReadOnlyDB(path string) (*sql.DB, error) {
	actual, err := stageMirrorIfForeign(path)
	if err != nil {
		return nil, fmt.Errorf("goose.stageMirror: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)", sqlitedsn.Escape(actual))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// stageMirrorIfForeign returns srcDB unchanged when it is native. A foreign-mount
// store (a Windows-side store read by a WSL observer over /mnt/c, or
// the reverse), which modernc.org/sqlite cannot open in place while the
// vendor process writes its WAL, is read through a filtered local
// mirror built by mirrorbase.Stage: only the tables in mirrorSpec are
// kept, so the store's other tables (credentials included) never leave
// the vendor's file.
func stageMirrorIfForeign(srcDB string) (string, error) {
	if !isForeignMountPath(srcDB) {
		return srcDB, nil
	}
	return mirrorbase.Stage(context.Background(), srcDB, mirrorSpec)
}

// mirrorSpec is the allow-list mirror of the Goose store (sessions.db): every table this
// package queries and nothing else. A query on a new table must add it
// here, or the foreign-mount mirror silently lacks it;
// mirrortest.AssertSpecCoversQueries pins that.
var mirrorSpec = mirrorbase.Spec{
	Dir:    "goose-mirror",
	File:   "sessions.db",
	Tables: []string{"sessions", "messages"},
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

// maxMessageID returns the largest messages.id in the store — the
// incremental watermark. A missing table (foreign/partial schema) yields 0.
func maxMessageID(ctx context.Context, db *sql.DB) (int64, error) {
	if !tableExists(ctx, db, "messages") {
		return 0, nil
	}
	var v sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(id) FROM messages`).Scan(&v); err != nil {
		return 0, err
	}
	return v.Int64, nil
}

// loadTouchedSessions returns the sessions that gained at least one message
// with id > fromOffset, each with the metadata + accumulated token bundle
// needed to emit its events and a session-level TokenEvent.
func loadTouchedSessions(ctx context.Context, db *sql.DB, fromOffset int64) ([]sessionRow, error) {
	if !tableExists(ctx, db, "sessions") || !tableExists(ctx, db, "messages") {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT s.id, COALESCE(s.working_dir, ''), COALESCE(s.model_config_json, ''),
		       COALESCE(s.provider_name, ''), COALESCE(s.updated_at, ''),
		       s.accumulated_input_tokens, s.accumulated_output_tokens,
		       s.accumulated_cache_read_tokens, s.accumulated_cache_write_tokens,
		       s.accumulated_total_tokens, s.accumulated_cost
		  FROM sessions s
		 WHERE EXISTS (
		       SELECT 1 FROM messages m
		        WHERE m.session_id = s.id AND m.id > ?)
		 ORDER BY s.updated_at ASC, s.id ASC`, fromOffset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []sessionRow
	for rows.Next() {
		var s sessionRow
		if err := rows.Scan(&s.ID, &s.WorkingDir, &s.ModelConfigJSON, &s.Provider, &s.UpdatedAt,
			&s.AccInput, &s.AccOutput, &s.AccCacheRead, &s.AccCacheWrite,
			&s.AccTotal, &s.AccCost); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// loadMessages returns every message of a session in chronological (id
// ASC) order.
func loadMessages(ctx context.Context, db *sql.DB, sessionID string) ([]messageRow, error) {
	if !tableExists(ctx, db, "messages") {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, COALESCE(message_id, ''), role, content_json, created_timestamp
		  FROM messages
		 WHERE session_id = ?
		 ORDER BY id ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []messageRow
	for rows.Next() {
		var m messageRow
		if err := rows.Scan(&m.ID, &m.MessageID, &m.Role, &m.ContentJSON, &m.Created); err != nil {
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
