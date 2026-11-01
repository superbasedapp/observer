package mirrorbase

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	_ "modernc.org/sqlite" // registers the "sqlite" driver used for the in-memory filter
)

// stampVersion versions the mirror format. Bump it whenever the filter
// changes in a way that must invalidate every existing mirror: a mirror
// whose stamp carries another version (or no stamp at all, the pre-filter
// whole-file copies) is deleted and rebuilt.
const stampVersion = "sbo-mirror-v2"

// stampSuffix names the sidecar that records which source state a mirror
// was built from.
const stampSuffix = ".stamp"

// Spec describes one adapter's mirror of one vendor SQLite store.
type Spec struct {
	// Dir is the per-tool subdirectory under Base(), e.g. "opencode-mirror".
	Dir string
	// File is the mirrored database's file name inside the per-source
	// directory, e.g. "opencode.db".
	File string
	// Tables is the allow-list: the only tables the adapter queries and
	// therefore the only tables (with their indexes) the mirror keeps.
	// Matching is case-insensitive, as SQLite's own name resolution is.
	Tables []string
}

var (
	stageMu sync.Mutex
	swept   = map[string]bool{}
)

// Stage builds, or reuses when the source is unchanged, a filtered
// read-only mirror of the vendor SQLite store srcDB and returns the
// mirror's path. It exists for foreign-mount stores (a Windows store read
// by a WSL observer over /mnt/c, or the reverse) that modernc.org/sqlite
// cannot open in place while the vendor process writes its WAL.
//
// Vendor stores mix conversation tables with credential tables (OpenCode's
// `credential`, Kiro CLI's `auth_kv`, Qoder Work's BYOK / OAuth tables),
// so the mirror is never a byte copy. The source and its -wal are read
// into memory, the committed WAL frames are applied in memory (applyWAL),
// the image is opened as an in-memory SQLite database, every table,
// view and trigger outside spec.Tables is dropped together with the
// planner statistics, and only then is the result written to disk with
// VACUUM INTO, which writes the surviving b-trees into a fresh file: no
// freed page of a dropped table reaches the mirror. The -shm index is
// never read. A table outside the allow-list that cannot be dropped
// fails the stage, and any failure removes the mirror, so a pre-filter
// whole-file copy never outlives the first run of this code.
//
// The first Stage call for a Spec.Dir in a process also deletes every
// per-source mirror directory under it that lacks a current stamp
// (whole-file copies left by earlier releases, including mirrors of
// sources that no longer exist).
func Stage(ctx context.Context, srcDB string, spec Spec) (string, error) {
	if spec.Dir == "" || spec.File == "" || len(spec.Tables) == 0 {
		return "", errors.New("mirrorbase.Stage: incomplete spec")
	}
	base, err := Base()
	if err != nil || base == "" {
		base = filepath.Join(os.TempDir(), "superbased-observer")
	}
	toolDir := filepath.Join(base, spec.Dir)

	stageMu.Lock()
	defer stageMu.Unlock()

	if !swept[toolDir] {
		sweepStale(toolDir)
		swept[toolDir] = true
	}

	sum := sha256.Sum256([]byte(srcDB))
	mirrorDir := filepath.Join(toolDir, hex.EncodeToString(sum[:8]))
	if err := os.MkdirAll(mirrorDir, 0o700); err != nil {
		return "", fmt.Errorf("mirrorbase.Stage: mkdir %s: %w", mirrorDir, err)
	}
	dstDB := filepath.Join(mirrorDir, spec.File)

	want, err := sourceStamp(srcDB, spec.Tables)
	if err != nil {
		return "", fmt.Errorf("mirrorbase.Stage: %w", err)
	}
	if stampMatches(dstDB, want) {
		return dstDB, nil
	}
	stamp, err := build(ctx, srcDB, dstDB, spec.Tables)
	if err != nil {
		removeMirror(dstDB)
		return "", fmt.Errorf("mirrorbase.Stage: %w", err)
	}
	if err := writeFileAtomic(dstDB+stampSuffix, []byte(stamp)); err != nil {
		removeMirror(dstDB)
		return "", fmt.Errorf("mirrorbase.Stage: stamp: %w", err)
	}
	return dstDB, nil
}

// build writes the filtered mirror of srcDB to dstDB and returns the
// stamp of the source state it was built from.
func build(ctx context.Context, srcDB, dstDB string, tables []string) (string, error) {
	image, stamp, err := readSource(srcDB, tables)
	if err != nil {
		return "", err
	}
	if len(image) == 0 {
		return "", fmt.Errorf("source %s is empty", srcDB)
	}

	mem, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return "", fmt.Errorf("open memory db: %w", err)
	}
	defer mem.Close()
	mem.SetMaxOpenConns(1)
	conn, err := mem.Conn(ctx)
	if err != nil {
		return "", fmt.Errorf("memory conn: %w", err)
	}
	defer conn.Close()

	if err := conn.Raw(func(dc any) error {
		d, ok := dc.(interface{ Deserialize([]byte) error })
		if !ok {
			return errors.New("sqlite driver cannot deserialize")
		}
		return d.Deserialize(image)
	}); err != nil {
		return "", fmt.Errorf("deserialize: %w", err)
	}

	if err := dropOutsideAllowList(ctx, conn, tables); err != nil {
		return "", err
	}

	tmp := dstDB + ".tmp"
	_ = os.Remove(tmp)
	if _, err := conn.ExecContext(ctx, `VACUUM INTO ?`, tmp); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("vacuum into: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("chmod: %w", err)
	}
	_ = os.Remove(dstDB + "-wal")
	_ = os.Remove(dstDB + "-shm")
	_ = os.Remove(dstDB + stampSuffix)
	if err := os.Rename(tmp, dstDB); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("rename: %w", err)
	}
	return stamp, nil
}

// readSource reads srcDB and its -wal into memory and returns the
// checkpointed image plus the stamp of the state read. The vendor may be
// writing while we read, so the read is retried until the files' size
// and mtime are identical before and after (a few attempts); a torn read
// that slips through is caught by the WAL checksums or by SQLite when
// the image is used, and fails this stage rather than yielding a mirror.
func readSource(srcDB string, tables []string) ([]byte, string, error) {
	const attempts = 3
	for attempt := 1; ; attempt++ {
		before, err := sourceStamp(srcDB, tables)
		if err != nil {
			return nil, "", err
		}
		db, err := os.ReadFile(srcDB) //nolint:gosec // srcDB is the adapter's validated watch-root store
		if err != nil {
			return nil, "", fmt.Errorf("read %s: %w", srcDB, err)
		}
		wal, err := os.ReadFile(srcDB + "-wal") //nolint:gosec // the store's own WAL sibling
		if err != nil && !os.IsNotExist(err) {
			return nil, "", fmt.Errorf("read %s-wal: %w", srcDB, err)
		}
		after, err := sourceStamp(srcDB, tables)
		if err != nil {
			return nil, "", err
		}
		if before != after && attempt < attempts {
			continue
		}
		image, err := applyWAL(db, wal)
		if err != nil {
			return nil, "", err
		}
		return image, after, nil
	}
}

// dropOutsideAllowList removes every schema object the adapter does not
// read: views and triggers first (they may reference dropped tables),
// then virtual tables (which take their shadow tables with them), then
// ordinary tables and their indexes, then the planner statistics
// (sqlite_stat4 samples hold literal index key values). sqlite_sequence
// keeps only the allowed tables' rows. Finally the schema is re-read and
// any surviving table outside the list fails the stage.
func dropOutsideAllowList(ctx context.Context, conn *sql.Conn, tables []string) error {
	allowed := make(map[string]bool, len(tables))
	for _, t := range tables {
		allowed[strings.ToLower(t)] = true
	}

	objs, err := schemaObjects(ctx, conn)
	if err != nil {
		return err
	}
	for _, o := range objs {
		switch o.kind {
		case "view":
			if err := execDrop(ctx, conn, "VIEW", o.name); err != nil {
				return err
			}
		case "trigger":
			if err := execDrop(ctx, conn, "TRIGGER", o.name); err != nil {
				return err
			}
		}
	}
	for _, virtualPass := range []bool{true, false} {
		objs, err = schemaObjects(ctx, conn)
		if err != nil {
			return err
		}
		for _, o := range objs {
			if o.kind != "table" || allowed[strings.ToLower(o.name)] || isInternal(o.name) {
				continue
			}
			if o.virtual != virtualPass {
				continue
			}
			if err := execDrop(ctx, conn, "TABLE", o.name); err != nil {
				return err
			}
		}
	}
	for _, stat := range []string{"sqlite_stat1", "sqlite_stat2", "sqlite_stat3", "sqlite_stat4"} {
		if err := execDrop(ctx, conn, "TABLE", stat); err != nil {
			return err
		}
	}

	objs, err = schemaObjects(ctx, conn)
	if err != nil {
		return err
	}
	var keep []string
	for _, o := range objs {
		if o.kind != "table" {
			continue
		}
		lower := strings.ToLower(o.name)
		if o.name == "sqlite_sequence" || allowed[lower] {
			keep = append(keep, lower)
			continue
		}
		return fmt.Errorf("table %q survived the allow-list filter", o.name)
	}
	if hasTable(objs, "sqlite_sequence") {
		ph := make([]string, 0, len(keep))
		args := make([]any, 0, len(keep))
		for _, k := range keep {
			ph = append(ph, "?")
			args = append(args, k)
		}
		q := `DELETE FROM sqlite_sequence WHERE lower(name) NOT IN (` + strings.Join(ph, ",") + `)` //nolint:gosec // placeholders only
		if _, err := conn.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("trim sqlite_sequence: %w", err)
		}
	}
	return nil
}

type schemaObject struct {
	kind, name string
	virtual    bool
}

func schemaObjects(ctx context.Context, conn *sql.Conn) ([]schemaObject, error) {
	rows, err := conn.QueryContext(ctx,
		`SELECT type, name, COALESCE(sql, '') FROM sqlite_master ORDER BY rowid`)
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	defer rows.Close()
	var out []schemaObject
	for rows.Next() {
		var o schemaObject
		var ddl string
		if err := rows.Scan(&o.kind, &o.name, &ddl); err != nil {
			return nil, fmt.Errorf("scan schema: %w", err)
		}
		o.virtual = strings.HasPrefix(strings.ToUpper(strings.TrimSpace(ddl)), "CREATE VIRTUAL TABLE")
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	return out, nil
}

func hasTable(objs []schemaObject, name string) bool {
	for _, o := range objs {
		if o.kind == "table" && o.name == name {
			return true
		}
	}
	return false
}

// isInternal reports SQLite's own bookkeeping tables. sqlite_sequence
// cannot be dropped (it is trimmed instead) and the sqlite_stat tables
// are dropped explicitly.
func isInternal(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), "sqlite_")
}

func execDrop(ctx context.Context, conn *sql.Conn, kind, name string) error {
	q := "DROP " + kind + " IF EXISTS " + quoteIdent(name) //nolint:gosec // kind is a literal keyword; name is quoted as an identifier
	if _, err := conn.ExecContext(ctx, q); err != nil {
		return fmt.Errorf("drop %s %q: %w", strings.ToLower(kind), name, err)
	}
	return nil
}

func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// sourceStamp fingerprints the source state (size and mtime of the store
// and its -wal) together with the mirror format version and the
// allow-list, so a change to either the vendor file or the adapter's
// list rebuilds the mirror.
func sourceStamp(srcDB string, tables []string) (string, error) {
	st, err := os.Stat(srcDB)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", srcDB, err)
	}
	walPart := "wal=none"
	if w, err := os.Stat(srcDB + "-wal"); err == nil {
		walPart = fmt.Sprintf("wal=%d:%d", w.Size(), w.ModTime().UnixNano())
	}
	list := make([]string, len(tables))
	for i, t := range tables {
		list[i] = strings.ToLower(t)
	}
	sort.Strings(list)
	return fmt.Sprintf("%s\ntables=%s\ndb=%d:%d\n%s\n",
		stampVersion, strings.Join(list, ","), st.Size(), st.ModTime().UnixNano(), walPart), nil
}

func stampMatches(dstDB, want string) bool {
	if _, err := os.Stat(dstDB); err != nil {
		return false
	}
	got, err := os.ReadFile(dstDB + stampSuffix) //nolint:gosec // our own sidecar
	if err != nil {
		return false
	}
	return string(got) == want
}

// sweepStale deletes every per-source directory under toolDir that does
// not hold a current-version stamp. Directories written by releases
// before the filter carry no stamp and are whole-file copies of the
// vendor store, credential tables included.
func sweepStale(toolDir string) {
	entries, err := os.ReadDir(toolDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		p := filepath.Join(toolDir, e.Name())
		if !e.IsDir() {
			_ = os.Remove(p)
			continue
		}
		if !hasCurrentStamp(p) {
			_ = os.RemoveAll(p)
		}
	}
}

func hasCurrentStamp(dir string) bool {
	matches, _ := filepath.Glob(filepath.Join(dir, "*"+stampSuffix))
	for _, m := range matches {
		b, err := os.ReadFile(m) //nolint:gosec // our own sidecar
		if err == nil && strings.HasPrefix(string(b), stampVersion+"\n") {
			return true
		}
	}
	return false
}

func removeMirror(dstDB string) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal", ".tmp", stampSuffix} {
		_ = os.Remove(dstDB + suffix)
	}
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
