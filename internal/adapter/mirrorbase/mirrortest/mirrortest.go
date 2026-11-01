// Package mirrortest holds the shared test assertions for adapters that
// stage a filtered foreign-mount mirror through mirrorbase.Stage. It is
// imported only from _test.go files.
package mirrortest

import (
	"bytes"
	"database/sql"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"

	_ "modernc.org/sqlite" // sqlite driver for reading the mirror
)

// sqlTableRef matches a table named after FROM or JOIN in an SQL string.
// A name followed by "(" is a table-valued function (json_each,
// pragma_table_info) and is excluded by the caller.
var sqlTableRef = regexp.MustCompile(`\b(?:FROM|JOIN)\s+["\x60]?([A-Za-z_][A-Za-z0-9_]*)["\x60]?(\s*\()?`)

// builtin names that are never vendor tables.
var builtin = map[string]bool{"sqlite_master": true, "sqlite_schema": true, "sqlite_sequence": true}

// QueriedTables returns every table named after FROM/JOIN in the string
// literals of the non-test Go files in dir, minus SQLite's own tables and
// table-valued functions.
func QueriedTables(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	seen := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for _, m := range sqlTableRef.FindAllStringSubmatch(s, -1) {
				name := strings.ToLower(m[1])
				if m[2] != "" || builtin[name] {
					continue
				}
				seen[name] = true
			}
			return true
		})
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// AssertSpecCoversQueries fails t when a table the package in dir queries
// is missing from spec.Tables, which would make the foreign-mount mirror
// silently lack it. otherStores lists tables the package reads from a
// different, unmirrored database.
func AssertSpecCoversQueries(t *testing.T, spec mirrorbase.Spec, dir string, otherStores ...string) {
	t.Helper()
	allowed := map[string]bool{}
	for _, n := range spec.Tables {
		allowed[strings.ToLower(n)] = true
	}
	for _, n := range otherStores {
		allowed[strings.ToLower(n)] = true
	}
	for _, n := range QueriedTables(t, dir) {
		if !allowed[n] {
			t.Errorf("package queries table %q, which %s's mirror allow-list %v does not keep", n, spec.Dir, spec.Tables)
		}
	}
}

// Canaries are the secret values AssertForeignStageFiltered plants in a
// synthetic store's credential tables; none may appear in a mirror.
var Canaries = []string{"SBO-MIRROR-CANARY-MAIN-4b1d", "SBO-MIRROR-CANARY-WAL-8e27"}

// AssertForeignStageFiltered builds a synthetic vendor store named
// spec.File under a fresh directory, registers that directory as a
// foreign-mount home through setForeignHome (the adapter's own
// allHomesFunc seam), and stages it through stage (the adapter's
// stageMirrorIfForeign). The store holds every allow-listed table plus
// credential-shaped tables (`credential`, `auth_kv`) whose canary rows
// sit both in the main file and only in the -wal. The mirror must keep
// every allow-listed table and nothing else.
func AssertForeignStageFiltered(t *testing.T, spec mirrorbase.Spec, setForeignHome func(root string), stage func(string) (string, error)) {
	t.Helper()
	base := t.TempDir()
	mirrorbase.SetBaseForProcess(filepath.Join(base, "cache"))
	t.Cleanup(func() { mirrorbase.SetBaseForProcess("") })
	root := t.TempDir()
	setForeignHome(root)
	src := filepath.Join(root, spec.File)

	w, err := sql.Open("sqlite", "file:"+sqlitedsn.Escape(src)+
		"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatalf("open synthetic store: %v", err)
	}
	w.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = w.Close() })
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := w.Exec(q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	for _, tbl := range spec.Tables {
		exec(`CREATE TABLE "` + tbl + `" (id INTEGER PRIMARY KEY, v TEXT)`)
		exec(`INSERT INTO "`+tbl+`" (v) VALUES (?)`, "kept")
	}
	exec(`CREATE TABLE credential (id TEXT PRIMARY KEY, data TEXT)`)
	exec(`CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT)`)
	exec(`INSERT INTO credential VALUES ('c1', ?)`, Canaries[0])
	exec(`INSERT INTO auth_kv VALUES ('k1', ?)`, Canaries[0])
	exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	exec(`INSERT INTO credential VALUES ('c2', ?)`, Canaries[1])
	exec(`INSERT INTO auth_kv VALUES ('k2', ?)`, Canaries[1])

	got, err := stage(src)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if got == src {
		t.Fatal("foreign-mount store was opened in place, not mirrored")
	}
	if !strings.HasPrefix(got, filepath.Join(base, "cache")) {
		t.Errorf("mirror %s is outside mirrorbase.Base() (%s)", got, filepath.Join(base, "cache"))
	}
	AssertFiltered(t, got, spec, Canaries...)

	db, err := sql.Open("sqlite", "file:"+sqlitedsn.Escape(got)+"?mode=ro")
	if err != nil {
		t.Fatalf("open mirror: %v", err)
	}
	defer db.Close()
	for _, tbl := range spec.Tables {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM "` + tbl + `"`).Scan(&n); err != nil || n != 1 {
			t.Errorf("allow-listed table %q missing from the mirror (rows=%d err=%v)", tbl, n, err)
		}
	}
}

// AssertFiltered fails t when the mirror at path holds a table outside
// spec.Tables (sqlite_sequence aside), any of the forbidden byte strings,
// or a -wal / -shm sibling.
func AssertFiltered(t *testing.T, path string, spec mirrorbase.Spec, forbidden ...string) {
	t.Helper()
	ok := map[string]bool{"sqlite_sequence": true}
	for _, a := range spec.Tables {
		ok[strings.ToLower(a)] = true
	}
	db, err := sql.Open("sqlite", "file:"+sqlitedsn.Escape(path)+"?mode=ro")
	if err != nil {
		t.Fatalf("open mirror: %v", err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		t.Fatalf("list mirror tables: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !ok[strings.ToLower(n)] {
			t.Errorf("mirror %s holds table %q outside the allow-list %v", path, n, spec.Tables)
		}
	}
	raw, err := os.ReadFile(path) //nolint:gosec // test-owned mirror path
	if err != nil {
		t.Fatalf("read mirror: %v", err)
	}
	for _, f := range forbidden {
		if bytes.Contains(raw, []byte(f)) {
			t.Errorf("mirror %s contains forbidden bytes %q", path, f)
		}
	}
	for _, sib := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + sib); err == nil {
			t.Errorf("mirror %s has a %s sibling", path, sib)
		}
	}
}
