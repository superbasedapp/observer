package mirrorbase

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

const (
	canaryCheckpointed = "SBO-CANARY-CHECKPOINTED-7f3a"
	canaryInWAL        = "SBO-CANARY-IN-WAL-91c2"
)

// openWriter opens a WAL-mode writer that never auto-checkpoints, so
// rows written after an explicit checkpoint stay in the -wal file for as
// long as the connection is open (the shape of a live vendor process).
func openWriter(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+sqlitedsn.Escape(path)+
		"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatalf("open writer: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mustExec(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
}

// seedVendorStore builds a store shaped like OpenCode's: two tables the
// adapter reads, plus a credential table, an AUTOINCREMENT table, an FTS5
// virtual table, a view and a trigger over the credential table, and
// planner statistics. One credential canary is checkpointed into the
// main file; the other (and one allowed row) lives only in the WAL.
func seedVendorStore(t *testing.T, path string) *sql.DB {
	t.Helper()
	w := openWriter(t, path)
	mustExec(t, w,
		`CREATE TABLE session (id TEXT PRIMARY KEY, time_updated INTEGER)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, session_id TEXT, data TEXT)`,
		`CREATE INDEX part_session_idx ON part(session_id)`,
		`CREATE TABLE credential (id TEXT PRIMARY KEY, provider TEXT, secret TEXT)`,
		`CREATE INDEX credential_secret_idx ON credential(secret)`,
		`CREATE TABLE account_log (n INTEGER PRIMARY KEY AUTOINCREMENT, secret TEXT)`,
		`CREATE VIRTUAL TABLE cred_fts USING fts5(secret)`,
		`CREATE VIEW cred_view AS SELECT secret FROM credential`,
		`CREATE TRIGGER cred_audit AFTER INSERT ON credential BEGIN INSERT INTO account_log(secret) VALUES (new.secret); END`,
		`INSERT INTO session VALUES ('s1', 1)`,
		`INSERT INTO part VALUES ('p1', 's1', 'hello')`,
		`INSERT INTO credential VALUES ('c1', 'anthropic', '`+canaryCheckpointed+`')`,
		`INSERT INTO cred_fts(secret) VALUES ('`+canaryCheckpointed+`')`,
		`ANALYZE`,
		`PRAGMA wal_checkpoint(TRUNCATE)`,
		`INSERT INTO session VALUES ('s2', 2)`,
		`INSERT INTO part VALUES ('p2', 's2', 'world')`,
		`INSERT INTO credential VALUES ('c2', 'openai', '`+canaryInWAL+`')`,
	)
	if st, err := os.Stat(path + "-wal"); err != nil || st.Size() == 0 {
		t.Fatalf("expected a non-empty WAL holding uncheckpointed rows (err=%v)", err)
	}
	return w
}

func mirrorTables(t *testing.T, path string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+sqlitedsn.Escape(path)+"?mode=ro")
	if err != nil {
		t.Fatalf("open mirror: %v", err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		t.Fatalf("list mirror tables: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, n)
	}
	return out
}

func countRows(t *testing.T, path, table string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+sqlitedsn.Escape(path)+"?mode=ro")
	if err != nil {
		t.Fatalf("open mirror: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + quoteIdent(table)).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

var testSpec = Spec{Dir: "test-mirror", File: "store.db", Tables: []string{"session", "PART"}}

// assertAllowListOnly fails t when the mirror at path holds any table
// outside allow (SQLite's own sqlite_sequence aside) or any of the
// forbidden byte strings anywhere in the file.
func assertAllowListOnly(t *testing.T, path string, allow []string, forbidden ...string) {
	t.Helper()
	ok := map[string]bool{"sqlite_sequence": true}
	for _, a := range allow {
		ok[strings.ToLower(a)] = true
	}
	for _, name := range mirrorTables(t, path) {
		if !ok[strings.ToLower(name)] {
			t.Errorf("mirror holds table %q outside the allow-list %v", name, allow)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read mirror: %v", err)
	}
	for _, f := range forbidden {
		if bytes.Contains(raw, []byte(f)) {
			t.Errorf("mirror file contains forbidden bytes %q", f)
		}
	}
	for _, sib := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + sib); err == nil {
			t.Errorf("mirror has a %s sibling", sib)
		}
	}
}

func TestStageMirrorNeverHoldsTablesOutsideAllowList(t *testing.T) {
	dir := t.TempDir()
	SetBaseForProcess(filepath.Join(dir, "cache"))
	t.Cleanup(func() { SetBaseForProcess("") })
	src := filepath.Join(dir, "vendor", "store.db")
	if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
		t.Fatal(err)
	}
	seedVendorStore(t, src)

	got, err := Stage(context.Background(), src, testSpec)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	assertAllowListOnly(t, got, testSpec.Tables, canaryCheckpointed, canaryInWAL, "cred_view", "cred_audit")

	tables := mirrorTables(t, got)
	sort.Strings(tables)
	if strings.Join(tables, ",") != "part,session" {
		t.Errorf("mirror tables = %v, want [part session]", tables)
	}
	// Rows committed only to the WAL are present: the WAL was applied.
	if n := countRows(t, got, "session"); n != 2 {
		t.Errorf("session rows = %d, want 2 (one checkpointed, one in the WAL)", n)
	}
	if n := countRows(t, got, "part"); n != 2 {
		t.Errorf("part rows = %d, want 2", n)
	}
	// The allowed table's index survives, so adapter queries stay indexed.
	db, err := sql.Open("sqlite", "file:"+sqlitedsn.Escape(got)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var idx int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='part_session_idx'`).Scan(&idx); err != nil || idx != 1 {
		t.Errorf("part_session_idx missing from mirror (n=%d err=%v)", idx, err)
	}
	if st, err := os.Stat(got); err == nil && st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("mirror mode = %v, want owner-only", st.Mode().Perm())
	}
}

func TestStageReusesUnchangedSourceAndRebuildsOnChange(t *testing.T) {
	dir := t.TempDir()
	SetBaseForProcess(filepath.Join(dir, "cache"))
	t.Cleanup(func() { SetBaseForProcess("") })
	src := filepath.Join(dir, "store.db")
	w := seedVendorStore(t, src)

	first, err := Stage(context.Background(), src, testSpec)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	st1, _ := os.Stat(first)
	second, err := Stage(context.Background(), src, testSpec)
	if err != nil || second != first {
		t.Fatalf("second Stage = %q, %v; want %q", second, err, first)
	}
	st2, _ := os.Stat(second)
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Errorf("unchanged source rebuilt the mirror")
	}

	mustExec(t, w, `INSERT INTO session VALUES ('s3', 3)`)
	third, err := Stage(context.Background(), src, testSpec)
	if err != nil {
		t.Fatalf("Stage after write: %v", err)
	}
	if n := countRows(t, third, "session"); n != 3 {
		t.Errorf("session rows after write = %d, want 3", n)
	}
}

// TestStageReplacesLegacyWholeFileMirrors pins the migration: a mirror
// left by an earlier release is a byte copy of the vendor store, with
// the credential table. The next run rebuilds the current source's
// mirror and deletes every other unstamped mirror directory.
func TestStageReplacesLegacyWholeFileMirrors(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache")
	SetBaseForProcess(cache)
	t.Cleanup(func() { SetBaseForProcess("") })
	resetSweepForTest(t)
	src := filepath.Join(dir, "store.db")
	w := seedVendorStore(t, src)
	mustExec(t, w, `PRAGMA wal_checkpoint(TRUNCATE)`)
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}

	want, err := Stage(context.Background(), src, testSpec)
	if err != nil {
		t.Fatal(err)
	}
	// A legacy mirror of a source that no longer exists ...
	orphan := filepath.Join(cache, testSpec.Dir, "0123456789abcdef")
	if err := os.MkdirAll(orphan, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphan, testSpec.File), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// ... and a legacy copy at the current source's own mirror path.
	removeMirror(want)
	if err := os.WriteFile(want, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want+"-wal", []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	resetSweepForTest(t)

	got, err := Stage(context.Background(), src, testSpec)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if got != want {
		t.Fatalf("mirror path moved: %q != %q", got, want)
	}
	assertAllowListOnly(t, got, testSpec.Tables, canaryCheckpointed, canaryInWAL)
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("unstamped legacy mirror dir %s survived the sweep (err=%v)", orphan, err)
	}
}

// TestStageFailureRemovesMirror: a source that cannot be filtered must
// not leave the previous (possibly unfiltered) mirror behind.
func TestStageFailureRemovesMirror(t *testing.T) {
	dir := t.TempDir()
	SetBaseForProcess(filepath.Join(dir, "cache"))
	t.Cleanup(func() { SetBaseForProcess("") })
	src := filepath.Join(dir, "store.db")
	w := seedVendorStore(t, src)
	got, err := Stage(context.Background(), src, testSpec)
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if err := os.WriteFile(src, bytes.Repeat([]byte("not a database "), 512), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(src + "-wal")
	if _, err := Stage(context.Background(), src, testSpec); err == nil {
		t.Fatal("Stage of a non-database source succeeded")
	}
	for _, p := range []string{got, got + stampSuffix} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived a failed stage (err=%v)", p, err)
		}
	}
}

func TestStageRejectsIncompleteSpec(t *testing.T) {
	if _, err := Stage(context.Background(), "x.db", Spec{Dir: "d", File: "f"}); err == nil {
		t.Fatal("empty allow-list accepted")
	}
}

func resetSweepForTest(t *testing.T) {
	t.Helper()
	stageMu.Lock()
	swept = map[string]bool{}
	stageMu.Unlock()
}
