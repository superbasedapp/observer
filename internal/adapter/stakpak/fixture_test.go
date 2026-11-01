package stakpak

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testhome"

	_ "modernc.org/sqlite"
)

// fixtureDB is built ONCE per test binary by TestMain from
// testdata/stakpak/fixture.sql — an anonymized dump of two live stakpak
// 0.3.88 sessions (one Windows, one WSL/Linux; 2026-10-21). Repo
// convention: SQLite fixtures are synthesized in-test (no .db binary is
// tracked — the tree-wide *.db gitignore is deliberate). The path is
// <tmp>/.stakpak/data/local.db so IsSessionFile's parent-dir guard holds.
//
// Ids are synthetic (00000000-0000-4000-8000-<n>): session A (Windows) is
// ...0001 with checkpoints 0002-0009; session B (Linux) is ...0010 with
// checkpoints 0011-0018.
var fixtureDB string

// fixtureRoot is the watch root (the `data` dir) of fixtureDB.
var fixtureRoot string

const (
	winSession = "00000000-0000-4000-8000-000000000001"
	linSession = "00000000-0000-4000-8000-000000000010"
)

func TestMain(m *testing.M) {
	// Pin the profile roots to a process temp home (surface-gap FU-102):
	// the foreign-mount mirror tests stage a copy under os.UserCacheDir(),
	// which was the developer's real ~/.cache/superbased-observer.
	_, cleanupHome, err := testhome.PinProcess()
	if err != nil {
		panic(err)
	}
	dir, err := os.MkdirTemp("", "stakpak-fixture")
	if err != nil {
		panic(err)
	}
	fixtureRoot = filepath.Join(dir, ".stakpak", "data")
	fixtureDB = filepath.Join(fixtureRoot, "local.db")
	ddl, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "stakpak", "fixture.sql"))
	if err != nil {
		panic(err)
	}
	if err := buildDB(fixtureDB, string(ddl)); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	cleanupHome()
	os.Exit(code)
}

func buildDB(path, ddl string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	if _, err := db.Exec(ddl); err != nil {
		db.Close()
		return err
	}
	return db.Close()
}

// emptyStore returns a fresh store (schema only, no rows) at
// <tmp>/.stakpak/data/local.db and its watch root.
func emptyStore(t *testing.T) (dbPath, root string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), ".stakpak", "data")
	dbPath = filepath.Join(root, "local.db")
	if err := buildDB(dbPath, schemaOnly); err != nil {
		t.Fatalf("buildDB: %v", err)
	}
	return dbPath, root
}

const schemaOnly = `
CREATE TABLE _migrations ( version INTEGER PRIMARY KEY, description TEXT NOT NULL, applied_at TEXT NOT NULL );
CREATE TABLE sessions ( id TEXT PRIMARY KEY, title TEXT NOT NULL, agent_id TEXT, visibility TEXT NOT NULL DEFAULT 'PRIVATE', status TEXT DEFAULT 'ACTIVE', cwd TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL );
CREATE TABLE checkpoints ( id TEXT PRIMARY KEY, session_id TEXT NOT NULL, status TEXT, execution_depth INTEGER, parent_id TEXT, state TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, FOREIGN KEY(session_id) REFERENCES sessions(id), FOREIGN KEY(parent_id) REFERENCES checkpoints(id) );
`

// addSession inserts a session row.
func addSession(t *testing.T, dbPath, id, cwd string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO sessions (id, title, cwd, created_at, updated_at) VALUES (?, 't', ?, '2026-10-21T07:00:00+00:00', '2026-10-21T07:00:00+00:00')`, id, cwd); err != nil {
		t.Fatal(err)
	}
}

// addCheckpoint inserts a checkpoint whose state is the given JSON.
func addCheckpoint(t *testing.T, dbPath, id, session, parent, createdAt, stateJSON string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var p any
	if parent != "" {
		p = parent
	}
	if _, err := db.Exec(`INSERT INTO checkpoints (id, session_id, parent_id, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, session, p, stateJSON, createdAt, createdAt); err != nil {
		t.Fatal(err)
	}
}

// stateJSON renders {"messages":[...]} from already-encoded message objects.
func stateJSON(msgs ...string) string {
	return fmt.Sprintf(`{"messages":[%s]}`, strings.Join(msgs, ","))
}

// rebuildFixture (re)creates the store at dbPath from the fixture SQL and,
// when keep > 0, drops every checkpoint with rowid > keep — a store as it
// looked after the first keep checkpoints were written.
func rebuildFixture(t *testing.T, dbPath string, keep int) {
	t.Helper()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(dbPath + suffix)
	}
	ddl, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "stakpak", "fixture.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if err := buildDB(dbPath, string(ddl)); err != nil {
		t.Fatal(err)
	}
	if keep <= 0 {
		return
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DELETE FROM checkpoints WHERE rowid > ?`, keep); err != nil {
		t.Fatal(err)
	}
}
