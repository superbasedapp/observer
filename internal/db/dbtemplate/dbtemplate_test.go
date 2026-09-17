package dbtemplate

import (
	"context"
	"database/sql"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/migrations"
)

// TestTemplateMatchesMigrationSet is the staleness guard.
//
// The whole speedup rests on the template being schema-current, because that
// is what lets runMigrations take its fast path. A lagging template would
// still WORK — db.Open would migrate it the rest of the way — so the failure
// mode is silent slowness, exactly the condition this package exists to
// remove. Assert the equality instead.
func TestTemplateMatchesMigrationSet(t *testing.T) {
	image, err := Bytes()
	if err != nil {
		t.Fatalf("template unavailable (every caller fell back to full migration): %v", err)
	}
	path := filepath.Join(t.TempDir(), "guard.db")
	if err := writeFile(path, image); err != nil {
		t.Fatalf("materialise template: %v", err)
	}
	// Read the copy directly. Going through db.Open would migrate it first
	// and mask the very drift being tested for.
	database, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open copy: %v", err)
	}
	defer database.Close()

	var raw string
	if err := database.QueryRowContext(context.Background(),
		`SELECT value FROM schema_meta WHERE key = 'version'`).Scan(&raw); err != nil {
		t.Fatalf("read schema_meta version: %v", err)
	}
	got, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("schema_meta version %q is not an integer: %v", raw, err)
	}
	want := maxMigrationVersion(t)
	if want == 0 {
		t.Fatal("no migrations found")
	}
	if got != want {
		t.Fatalf("template schema version = %d, migration set is at %d — the template is stale", got, want)
	}
}

// TestOpenSeedsFreshPathsOnly pins the two properties that make the
// substitution safe at ~670 call sites: a brand-new path IS seeded (or the
// speedup is gone with nothing red), and anything already on disk is NOT
// overwritten.
func TestOpenSeedsFreshPathsOnly(t *testing.T) {
	if !Enabled() {
		t.Skip(DisableEnv + "=0: the template is disabled for this run")
	}
	dir := t.TempDir()

	fresh := filepath.Join(dir, "fresh.db")
	database, seeded, err := OpenSeeded(context.Background(), db.Options{Path: fresh})
	if err != nil {
		t.Fatalf("open fresh path: %v", err)
	}
	if !seeded {
		t.Fatal("a brand-new path was NOT seeded from the template — callers are paying full migration cost again")
	}
	if _, err := database.ExecContext(context.Background(),
		`CREATE TABLE marker_only_in_first_open (x INTEGER)`); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, seeded, err := OpenSeeded(context.Background(), db.Options{Path: fresh})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if seeded {
		t.Fatal("an existing database was overwritten by the template")
	}
	var n int
	if err := reopened.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sqlite_master WHERE name = 'marker_only_in_first_open'`).Scan(&n); err != nil {
		t.Fatalf("query marker: %v", err)
	}
	if n != 1 {
		t.Fatal("reopening an existing path clobbered it with the template")
	}

	// A stale sidecar with no main file is a journal SQLite intends to
	// replay, so the template must not be dropped on top of it.
	orphan := filepath.Join(dir, "orphan.db")
	if err := os.WriteFile(orphan+"-wal", []byte("not a real wal"), 0o600); err != nil {
		t.Fatalf("write orphan wal: %v", err)
	}
	if isFreshPath(orphan) {
		t.Fatal("a path with a stale -wal was treated as fresh")
	}
}

// TestSeededDatabaseMatchesFromScratch is the equivalence proof: the schema a
// caller gets from the template is the schema db.Open would have produced.
func TestSeededDatabaseMatchesFromScratch(t *testing.T) {
	ctx := context.Background()
	seededDB, seeded, err := OpenSeeded(ctx, db.Options{Path: filepath.Join(t.TempDir(), "seeded.db")})
	if err != nil {
		t.Fatalf("templated open: %v", err)
	}
	defer seededDB.Close()
	if Enabled() && !seeded {
		t.Fatal("expected the templated open to seed")
	}
	freshDB, err := OpenFresh(ctx, db.Options{Path: filepath.Join(t.TempDir(), "fresh.db")})
	if err != nil {
		t.Fatalf("from-scratch open: %v", err)
	}
	defer freshDB.Close()

	if got, want := schemaFingerprint(t, seededDB), schemaFingerprint(t, freshDB); got != want {
		t.Fatalf("templated schema differs from a from-scratch migration:\n--- templated ---\n%s\n--- fresh ---\n%s", got, want)
	}
}

// TestOpenRefusesTheLiveDatabaseBeforeCopying pins the ordering: the live-DB
// guard runs before any file is written, so a refused path still gets no
// file. Copying first would defeat db.GuardLiveDB entirely.
func TestOpenRefusesTheLiveDatabaseBeforeCopying(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory to guard against")
	}
	live := filepath.Join(home, ".observer", "dbtemplate-guard-probe.db")
	if err := db.GuardLiveDB(live); err == nil {
		t.Skip("the live-DB gate is disabled in this environment")
	}
	if _, err := Open(context.Background(), db.Options{Path: live}); err == nil {
		t.Fatal("Open accepted a path inside the real ~/.observer")
	}
	if _, err := os.Stat(live); err == nil {
		os.Remove(live)
		t.Fatal("Open created a file at a guarded path")
	}
}

// TestPackageIsTestOnly enforces what the package doc promises: dbtemplate is
// reachable only from _test.go files. It has no business in a shipped binary
// — it writes temp files and holds a whole database image in memory — and
// nothing in the type system stops an import, because the API deliberately
// avoids testing.TB.
func TestPackageIsTestOnly(t *testing.T) {
	root := moduleRoot(t)
	const self = "internal/db/dbtemplate"
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata", "dist", "bin":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if perr != nil {
			return nil // not our business to police unparseable files
		}
		for _, imp := range file.Imports {
			if strings.HasSuffix(strings.Trim(imp.Path.Value, `"`), self) {
				rel, _ := filepath.Rel(root, path)
				offenders = append(offenders, rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("dbtemplate is TEST-ONLY but is imported from non-test files: %v", offenders)
	}
}

func schemaFingerprint(t *testing.T, database *sql.DB) string {
	t.Helper()
	rows, err := database.QueryContext(context.Background(),
		`SELECT type, name, COALESCE(sql, '') FROM sqlite_master
		  WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		t.Fatalf("read sqlite_master: %v", err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var kind, name, ddl string
		if err := rows.Scan(&kind, &name, &ddl); err != nil {
			t.Fatalf("scan sqlite_master: %v", err)
		}
		b.WriteString(kind + " " + name + "\n" + strings.Join(strings.Fields(ddl), " ") + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate sqlite_master: %v", err)
	}
	return b.String()
}

func maxMigrationVersion(t *testing.T) int {
	t.Helper()
	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	highest := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		v, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			continue
		}
		if v > highest {
			highest = v
		}
	}
	return highest
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}
