package zed

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver (no CGO), per CLAUDE.md

	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// dbName is the fixed basename of the Zed threads store.
const dbName = "threads.db"

// threadRow is one `threads` row's non-blob columns, plus the decoded
// watermark used to decide whether it needs a full re-parse.
type threadRow struct {
	ID          string
	UpdatedAt   time.Time
	UpdatedAtNS int64
	CreatedAt   time.Time // zero if the column is NULL/unparsable
	DataType    string
	ParentID    string
}

// mainDBPath maps a `-wal` / `-shm` sidecar path onto its main store;
// any other path is returned unchanged. Mirrors the freebuff-desktop /
// cline-cli / kirocli / antigravity precedent: the live conversation
// usually lives almost entirely in the WAL, so the sidecars must be
// claimed by IsSessionFile even though every emitted row keys on the
// main db path.
func mainDBPath(path string) string {
	switch {
	case strings.HasSuffix(path, "-wal"):
		return strings.TrimSuffix(path, "-wal")
	case strings.HasSuffix(path, "-shm"):
		return strings.TrimSuffix(path, "-shm")
	}
	return path
}

// openDB opens threads.db read-only, staging a local mirror first when
// the source lives on a foreign mount (the same reason freebuff/goose/
// crush/devin/kirocli all do this: modernc.org/sqlite hits SQLITE_IOERR
// against /mnt/c paths while the live Zed process holds the WAL open).
func openDB(path string) (*sql.DB, error) {
	actual, err := stageMirrorIfForeign(path)
	if err != nil {
		return nil, fmt.Errorf("zed.stageMirror: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)",
		sqlitedsn.Escape(actual))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// allHomesFunc is the test seam over crossmount.AllHomes.
var allHomesFunc = crossmount.AllHomes

// isForeignMountPath reports whether path lives under a
// crossmount-detected non-native home (both bridge directions: /mnt/c
// on WSL2, \\wsl.localhost on Windows).
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

// mirrorSpec is the allow-list mirror of the Zed threads store (threads.db): every table this
// package queries and nothing else. A query on a new table must add it
// here, or the foreign-mount mirror silently lacks it;
// mirrortest.AssertSpecCoversQueries pins that.
var mirrorSpec = mirrorbase.Spec{
	Dir:    "zed-mirror",
	File:   dbName,
	Tables: []string{"threads"},
}

// tableExists lets a foreign or older schema degrade gracefully instead
// of erroring the whole parse.
func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var got string
	err := db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&got)
	return err == nil && got == name
}

// scanWatermarks reads every thread row's (id, updated_at, data_type,
// parent_id, created_at) — cheap TEXT columns only, no BLOB — and
// returns them alongside the overall latest UnixNano watermark. Full
// rows (including the zstd `data` blob) are fetched separately, only
// for the threads that actually changed, so an untouched thread's
// multi-KB payload is never decompressed on a no-op poll tick.
func scanWatermarks(ctx context.Context, db *sql.DB) ([]threadRow, int64, error) {
	if !tableExists(ctx, db, "threads") {
		return nil, 0, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, updated_at, COALESCE(data_type,''), COALESCE(parent_id,''), COALESCE(created_at,'')
		   FROM threads`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []threadRow
	var latest int64
	for rows.Next() {
		var id, updatedAtRaw, dataType, parentID, createdAtRaw string
		if err := rows.Scan(&id, &updatedAtRaw, &dataType, &parentID, &createdAtRaw); err != nil {
			return nil, 0, err
		}
		ts, ok := parseRFC3339(updatedAtRaw)
		if !ok {
			// A row whose watermark can't be parsed is skipped rather
			// than guessed; it will never advance the cursor, so it
			// stays visible for a future adapter version that can.
			continue
		}
		tr := threadRow{
			ID: id, UpdatedAt: ts, UpdatedAtNS: ts.UnixNano(),
			DataType: dataType, ParentID: parentID,
		}
		if createdTS, ok := parseRFC3339(createdAtRaw); ok {
			tr.CreatedAt = createdTS
		}
		out = append(out, tr)
		if tr.UpdatedAtNS > latest {
			latest = tr.UpdatedAtNS
		}
	}
	return out, latest, rows.Err()
}

// loadThreadData fetches the zstd `data` blob for one thread id.
func loadThreadData(ctx context.Context, db *sql.DB, id string) ([]byte, error) {
	var data []byte
	err := db.QueryRowContext(ctx, `SELECT data FROM threads WHERE id = ?`, id).Scan(&data)
	return data, err
}

// parseRFC3339 tries RFC3339Nano first (the observed shape,
// "2026-09-06T08:23:26.777724900Z") then plain RFC3339, so a future
// build that drops the fractional component still parses.
func parseRFC3339(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}
