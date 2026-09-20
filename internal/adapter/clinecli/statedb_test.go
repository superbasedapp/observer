package clinecli

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// sqliteSequenceRe matches the `CREATE TABLE sqlite_sequence(name,seq);`
// line a sqlite3 .schema dump emits for tables with AUTOINCREMENT
// columns. SQLite reserves that name for internal use and rejects
// explicit CREATE statements against it (the engine creates it
// lazily the first time an AUTOINCREMENT row is inserted).
var sqliteSequenceRe = regexp.MustCompile(`(?m)^CREATE TABLE sqlite_sequence\([^)]*\);\s*$`)

func stripSQLiteSequenceCreate(s string) string {
	return sqliteSequenceRe.ReplaceAllString(s, "")
}

// fixtureSessionID is the session ID in the live capture
// (testdata/clinecli/sample-session-meta.json + the paired
// messages.json). Used as the PK of the inserted fixture row.
const fixtureSessionID = "1780701711502_0v8d2"

// buildFixtureCLineDataDir constructs a clinecli data-dir layout
// under a t.TempDir():
//
//	<root>/data/
//	  ├── db/sessions.db   (schema from testdata/clinecli/sessions.sql
//	  │                     + one INSERT mirroring sample-session-meta.json)
//	  └── sessions/<id>/<id>.messages.json
//	    (copied from testdata/clinecli/sample-session-messages.json)
//
// Returns the absolute path to the sessions.db file. The data dir
// itself is the dbPath's grandparent.
func buildFixtureCLineDataDir(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	dbDir := filepath.Join(dataDir, "db")
	sessionsDir := filepath.Join(dataDir, "sessions", fixtureSessionID)
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatalf("mkdir db: %v", err)
	}
	if err := os.MkdirAll(sessionsDir, 0o755); err != nil {
		t.Fatalf("mkdir sessions/<id>: %v", err)
	}

	dbPath := filepath.Join(dbDir, "sessions.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	schemaPath := filepath.Join("..", "..", "..", "testdata", "clinecli", "sessions.sql")
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	// SQLite reserves sqlite_sequence for internal use — strip any
	// explicit CREATE for it from the dump (SQLite creates it lazily
	// when an AUTOINCREMENT column is exercised).
	cleaned := stripSQLiteSequenceCreate(string(schema))
	if _, err := db.Exec(cleaned); err != nil {
		t.Fatalf("exec schema: %v", err)
	}

	// Load sample-session-meta.json so the INSERT mirrors the live
	// capture verbatim. Re-serialize the `metadata` field as the
	// metadata_json column value.
	metaPath := filepath.Join("..", "..", "..", "testdata", "clinecli", "sample-session-meta.json")
	metaBody, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var meta struct {
		SessionID     string          `json:"session_id"`
		Source        string          `json:"source"`
		PID           int64           `json:"pid"`
		StartedAt     string          `json:"started_at"`
		EndedAt       *string         `json:"ended_at"`
		ExitCode      *int64          `json:"exit_code"`
		Status        string          `json:"status"`
		Interactive   bool            `json:"interactive"`
		Provider      string          `json:"provider"`
		Model         string          `json:"model"`
		CWD           string          `json:"cwd"`
		WorkspaceRoot string          `json:"workspace_root"`
		TeamName      *string         `json:"team_name"`
		EnableTools   bool            `json:"enable_tools"`
		EnableSpawn   bool            `json:"enable_spawn"`
		EnableTeams   bool            `json:"enable_teams"`
		Prompt        string          `json:"prompt"`
		Metadata      json.RawMessage `json:"metadata"`
		MessagesPath  string          `json:"messages_path"`
	}
	if err := json.Unmarshal(metaBody, &meta); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	if meta.SessionID != fixtureSessionID {
		t.Fatalf("fixture session id drift: got %q want %q", meta.SessionID, fixtureSessionID)
	}

	// Override messages_path to point at the temp dir's own copy so
	// the cross-mount fallback resolves cleanly. (The committed
	// fixture's path is a redacted Windows-shape string that won't
	// exist on the test runner.)
	relativeMessagesPath := filepath.Join(sessionsDir, fixtureSessionID+".messages.json")

	insert := `
		INSERT INTO sessions (
			session_id, source, pid, started_at, ended_at, exit_code, status,
			status_lock, interactive, provider, model, cwd, workspace_root,
			team_name, enable_tools, enable_spawn, enable_teams,
			parent_session_id, parent_agent_id, agent_id, conversation_id,
			is_subagent, prompt, metadata_json, transcript_path, hook_path,
			messages_path, updated_at
		) VALUES (
			?, ?, ?, ?, ?, ?, ?,
			0, ?, ?, ?, ?, ?,
			?, ?, ?, ?,
			NULL, NULL, NULL, NULL,
			0, ?, ?, '', '',
			?, ?
		)`
	if _, err := db.Exec(
		insert,
		meta.SessionID, meta.Source, meta.PID, meta.StartedAt, meta.EndedAt, meta.ExitCode, meta.Status,
		boolInt(meta.Interactive), meta.Provider, meta.Model, meta.CWD, meta.WorkspaceRoot,
		nullableString(meta.TeamName), boolInt(meta.EnableTools), boolInt(meta.EnableSpawn), boolInt(meta.EnableTeams),
		meta.Prompt, string(meta.Metadata),
		relativeMessagesPath, "2026-06-05T23:28:30.654Z",
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	// Copy messages.json fixture to the temp sessions dir so the
	// loadMessagesJSON path resolves.
	msgPath := filepath.Join("..", "..", "..", "testdata", "clinecli", "sample-session-messages.json")
	msgBody, err := os.ReadFile(msgPath)
	if err != nil {
		t.Fatalf("read messages.json fixture: %v", err)
	}
	if err := os.WriteFile(relativeMessagesPath, msgBody, 0o600); err != nil {
		t.Fatalf("write messages.json: %v", err)
	}
	return dbPath
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func nullableString(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// TestScanStateDB_LoadsSessionsAndMessages exercises the SQLite read
// + messages.json load path end-to-end against the captured
// fixtures.
func TestScanStateDB_LoadsSessionsAndMessages(t *testing.T) {
	t.Parallel()
	dbPath := buildFixtureCLineDataDir(t)

	sessions, maxOffset, err := scanStateDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("scanStateDB: %v", err)
	}
	if got, want := len(sessions), 1; got != want {
		t.Fatalf("len(sessions) = %d, want %d", got, want)
	}
	if maxOffset == 0 {
		t.Error("maxOffset = 0; want > 0 (UnixMilli of updated_at)")
	}

	s := sessions[0]
	if s.ID != fixtureSessionID {
		t.Errorf("session_id = %q; want %q", s.ID, fixtureSessionID)
	}
	if s.Source != "cli" {
		t.Errorf("source = %q; want cli", s.Source)
	}
	if s.Model != "deepseek/deepseek-v4-flash" {
		t.Errorf("model = %q; want deepseek/deepseek-v4-flash", s.Model)
	}
	if s.CWD == "" {
		t.Error("cwd empty; expected populated for CLI sessions")
	}

	// metadata_json decoded
	if s.Metadata.Title != "Hi" {
		t.Errorf("metadata.title = %q; want Hi", s.Metadata.Title)
	}
	if s.Metadata.Usage.InputTokens != 286579 {
		t.Errorf("metadata.usage.inputTokens = %d; want 286579", s.Metadata.Usage.InputTokens)
	}
	if s.Metadata.Usage.CacheReadTokens != 146304 {
		t.Errorf("metadata.usage.cacheReadTokens = %d; want 146304", s.Metadata.Usage.CacheReadTokens)
	}

	// messages.json loaded
	if s.Messages.SessionID != fixtureSessionID {
		t.Errorf("messages.sessionId = %q; want %q", s.Messages.SessionID, fixtureSessionID)
	}
	if got, want := len(s.Messages.Messages), 6; got != want {
		t.Errorf("len(messages) = %d; want %d (Hi greeting + model-question follow-up)", got, want)
	}
}

// TestScanStateDB_Watermark confirms that re-running with a
// non-zero fromOffset (UnixMilli watermark) filters out previously-
// seen sessions.
func TestScanStateDB_Watermark(t *testing.T) {
	t.Parallel()
	dbPath := buildFixtureCLineDataDir(t)

	_, maxOffset, err := scanStateDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if maxOffset == 0 {
		t.Fatal("first scan maxOffset == 0; expected > 0")
	}

	// Second scan with offset = maxOffset should return 0 sessions
	// (the WHERE clause is strict-greater-than).
	sessions, _, err := scanStateDB(context.Background(), dbPath, maxOffset)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("len(sessions) = %d; want 0 (watermark should exclude already-seen rows)", len(sessions))
	}
}

// TestDeriveRootDir confirms the helper recovers `<root>/data` from
// the sessions.db path so the messages.json fallback resolution
// works.
func TestDeriveRootDir(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"/home/dev/.cline/data/db/sessions.db", filepath.FromSlash("/home/dev/.cline/data")},
		{"/mnt/c/Users/marmu/.cline/data/db/sessions.db", filepath.FromSlash("/mnt/c/Users/marmu/.cline/data")},
		{"/some/random/path.txt", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got := deriveRootDir(tc.in)
			if got != tc.want {
				t.Errorf("deriveRootDir(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestScanStateDB_MultiSession exercises the loop over multiple
// session rows + the watermark advance across the whole set. Live
// fixture only carries one session; this synthesises a parent-
// teammate pair so the subagent linkage + ordering invariants get
// real coverage.
func TestScanStateDB_MultiSession(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	dbDir := filepath.Join(dataDir, "db")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dbDir, "sessions.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	schemaPath := filepath.Join("..", "..", "..", "testdata", "clinecli", "sessions.sql")
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if _, err := db.Exec(stripSQLiteSequenceCreate(string(schema))); err != nil {
		t.Fatalf("exec schema: %v", err)
	}

	rows := []struct {
		id            string
		source        string
		status        string
		parentSession any
		isSubagent    int64
		updatedAt     string
		teamName      any
	}{
		{"lead-001", "cli", "completed", nil, 0, "2026-06-05T23:00:00.000Z", nil},
		{"team-001-mate-A", "subagent", "completed", "lead-001", 1, "2026-06-05T23:10:00.000Z", "team-X"},
		{"team-001-mate-B", "subagent", "completed", "lead-001", 1, "2026-06-05T23:20:00.000Z", "team-X"},
	}
	for _, r := range rows {
		_, err := db.Exec(
			`
			INSERT INTO sessions (
				session_id, source, pid, started_at, ended_at, exit_code, status,
				status_lock, interactive, provider, model, cwd, workspace_root,
				team_name, enable_tools, enable_spawn, enable_teams,
				parent_session_id, parent_agent_id, agent_id, conversation_id,
				is_subagent, prompt, metadata_json, transcript_path, hook_path,
				messages_path, updated_at
			) VALUES (
				?, ?, 1234, ?, NULL, NULL, ?,
				0, 1, 'cline', 'deepseek/deepseek-v4-flash', '/home/dev/proj', '/home/dev/proj',
				?, 1, 1, 1,
				?, NULL, NULL, NULL,
				?, NULL, NULL, '', '',
				NULL, ?
			)`,
			r.id, r.source, r.updatedAt, r.status,
			r.teamName,
			r.parentSession, r.isSubagent, r.updatedAt,
		)
		if err != nil {
			t.Fatalf("insert %s: %v", r.id, err)
		}
	}

	sessions, _, err := scanStateDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("scanStateDB: %v", err)
	}
	if len(sessions) != 3 {
		t.Fatalf("len(sessions) = %d; want 3", len(sessions))
	}

	// Watermark advances to the LATEST updated_at: 2026-06-05T23:20:00Z
	watermarkWant, _ := parseISO8601ms("2026-06-05T23:20:00.000Z")
	_, maxOffset, err := scanStateDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("re-scan: %v", err)
	}
	if maxOffset != watermarkWant {
		t.Errorf("maxOffset = %d; want %d (latest updated_at as UnixMilli)", maxOffset, watermarkWant)
	}

	// Spot-check the parent + teammate rows have correct
	// parent_session_id linkage.
	parentSeen, mateASeen := false, false
	for _, s := range sessions {
		switch s.ID {
		case "lead-001":
			parentSeen = true
			if s.ParentSessionID.Valid {
				t.Errorf("lead-001 parent_session_id should be NULL; got %v", s.ParentSessionID.String)
			}
			if s.IsSubagent != 0 {
				t.Errorf("lead-001 is_subagent = %d; want 0", s.IsSubagent)
			}
		case "team-001-mate-A":
			mateASeen = true
			if !s.ParentSessionID.Valid || s.ParentSessionID.String != "lead-001" {
				t.Errorf("mate-A parent_session_id = %v; want lead-001", s.ParentSessionID)
			}
			if s.IsSubagent != 1 {
				t.Errorf("mate-A is_subagent = %d; want 1", s.IsSubagent)
			}
			if !s.TeamName.Valid || s.TeamName.String != "team-X" {
				t.Errorf("mate-A team_name = %v; want team-X", s.TeamName)
			}
		}
	}
	if !parentSeen {
		t.Error("lead-001 not found in scan result")
	}
	if !mateASeen {
		t.Error("team-001-mate-A not found in scan result")
	}

	// buildEvents over the three-session set: each gets a
	// session_start + session_end row (status="completed" terminal).
	tools, _, _ := buildEvents(context.Background(), sessions, dbPath, nil, nil)
	starts, ends := 0, 0
	for _, ev := range tools {
		switch ev.ActionType {
		case "session_start":
			starts++
		case "session_end":
			ends++
		}
	}
	if starts != 3 || ends != 3 {
		t.Errorf("starts/ends = %d/%d; want 3/3", starts, ends)
	}
}

// TestScanStateDB_MissingMessagesJSON confirms graceful handling
// when a session row references a messages.json file that doesn't
// exist on disk. The session-level rows should still emit; the
// per-message walk just skips.
func TestScanStateDB_MissingMessagesJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	dbDir := filepath.Join(dataDir, "db")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dbDir, "sessions.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	schemaPath := filepath.Join("..", "..", "..", "testdata", "clinecli", "sessions.sql")
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(stripSQLiteSequenceCreate(string(schema))); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO sessions (
			session_id, source, pid, started_at, status, interactive,
			provider, model, cwd, workspace_root, enable_tools, enable_spawn,
			enable_teams, hook_path, updated_at
		) VALUES (
			'sess-no-msg', 'cli', 1234, '2026-06-05T23:00:00.000Z', 'completed', 1,
			'cline', 'deepseek/deepseek-v4-flash', '/home/dev/proj', '/home/dev/proj',
			1, 1, 1, '', '2026-06-05T23:00:01.000Z'
		)`); err != nil {
		t.Fatalf("insert: %v", err)
	}

	sessions, _, err := scanStateDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("scanStateDB: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d; want 1", len(sessions))
	}
	// Messages.Messages should be empty — file doesn't exist.
	if len(sessions[0].Messages.Messages) != 0 {
		t.Errorf("messages loaded despite missing file: %d", len(sessions[0].Messages.Messages))
	}
	// buildEvents still emits the session-level rows.
	tools, _, _ := buildEvents(context.Background(), sessions, dbPath, nil, nil)
	if len(tools) < 2 {
		t.Errorf("len(tools) = %d; want >=2 (session_start + session_end)", len(tools))
	}
}

// fixtureDesktopSessionID is the session ID in the synthetic desktop
// fixture (testdata/clinecli/sample-session-meta-desktop.json +
// sample-session-messages-desktop.json). The live Phase 0 capture only
// ever grounded `source='cli'` rows (buildFixtureCLineDataDir above),
// so this fixture is hand-authored — anonymised, no env/secrets — to
// exercise the `source='desktop'` path end to end (surface stamping +
// token capture), which prior tests never touched.
const fixtureDesktopSessionID = "1780900000000_dsk01"

// buildFixtureCLineDesktopDataDir is buildFixtureCLineDataDir's sibling
// for the desktop fixture pair. Same data-dir layout, same schema,
// different session row (source='desktop') and messages file.
func buildFixtureCLineDesktopDataDir(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	dbDir := filepath.Join(dataDir, "db")
	sessionsDir := filepath.Join(dataDir, "sessions", fixtureDesktopSessionID)
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatalf("mkdir db: %v", err)
	}
	if err := os.MkdirAll(sessionsDir, 0o755); err != nil {
		t.Fatalf("mkdir sessions/<id>: %v", err)
	}

	dbPath := filepath.Join(dbDir, "sessions.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	schemaPath := filepath.Join("..", "..", "..", "testdata", "clinecli", "sessions.sql")
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	cleaned := stripSQLiteSequenceCreate(string(schema))
	if _, err := db.Exec(cleaned); err != nil {
		t.Fatalf("exec schema: %v", err)
	}

	metaPath := filepath.Join("..", "..", "..", "testdata", "clinecli", "sample-session-meta-desktop.json")
	metaBody, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read desktop meta: %v", err)
	}
	var meta struct {
		SessionID     string          `json:"session_id"`
		Source        string          `json:"source"`
		PID           int64           `json:"pid"`
		StartedAt     string          `json:"started_at"`
		EndedAt       *string         `json:"ended_at"`
		ExitCode      *int64          `json:"exit_code"`
		Status        string          `json:"status"`
		Interactive   bool            `json:"interactive"`
		Provider      string          `json:"provider"`
		Model         string          `json:"model"`
		CWD           string          `json:"cwd"`
		WorkspaceRoot string          `json:"workspace_root"`
		TeamName      *string         `json:"team_name"`
		EnableTools   bool            `json:"enable_tools"`
		EnableSpawn   bool            `json:"enable_spawn"`
		EnableTeams   bool            `json:"enable_teams"`
		Prompt        string          `json:"prompt"`
		Metadata      json.RawMessage `json:"metadata"`
		MessagesPath  string          `json:"messages_path"`
	}
	if err := json.Unmarshal(metaBody, &meta); err != nil {
		t.Fatalf("unmarshal desktop meta: %v", err)
	}
	if meta.SessionID != fixtureDesktopSessionID {
		t.Fatalf("desktop fixture session id drift: got %q want %q", meta.SessionID, fixtureDesktopSessionID)
	}
	if meta.Source != "desktop" {
		t.Fatalf("desktop fixture source drift: got %q want %q", meta.Source, "desktop")
	}

	// Same rationale as buildFixtureCLineDataDir: point messages_path at
	// this test's own temp-dir copy rather than the fixture's recorded
	// (non-existent-on-runner) path.
	relativeMessagesPath := filepath.Join(sessionsDir, fixtureDesktopSessionID+".messages.json")

	insert := `
		INSERT INTO sessions (
			session_id, source, pid, started_at, ended_at, exit_code, status,
			status_lock, interactive, provider, model, cwd, workspace_root,
			team_name, enable_tools, enable_spawn, enable_teams,
			parent_session_id, parent_agent_id, agent_id, conversation_id,
			is_subagent, prompt, metadata_json, transcript_path, hook_path,
			messages_path, updated_at
		) VALUES (
			?, ?, ?, ?, ?, ?, ?,
			0, ?, ?, ?, ?, ?,
			?, ?, ?, ?,
			NULL, NULL, NULL, NULL,
			0, ?, ?, '', '',
			?, ?
		)`
	if _, err := db.Exec(
		insert,
		meta.SessionID, meta.Source, meta.PID, meta.StartedAt, meta.EndedAt, meta.ExitCode, meta.Status,
		boolInt(meta.Interactive), meta.Provider, meta.Model, meta.CWD, meta.WorkspaceRoot,
		nullableString(meta.TeamName), boolInt(meta.EnableTools), boolInt(meta.EnableSpawn), boolInt(meta.EnableTeams),
		meta.Prompt, string(meta.Metadata),
		relativeMessagesPath, "2026-06-10T10:02:00.000Z",
	); err != nil {
		t.Fatalf("insert desktop session: %v", err)
	}

	msgPath := filepath.Join("..", "..", "..", "testdata", "clinecli", "sample-session-messages-desktop.json")
	msgBody, err := os.ReadFile(msgPath)
	if err != nil {
		t.Fatalf("read desktop messages.json fixture: %v", err)
	}
	if err := os.WriteFile(relativeMessagesPath, msgBody, 0o600); err != nil {
		t.Fatalf("write desktop messages.json: %v", err)
	}
	return dbPath
}

// TestScanStateDB_DesktopSurfaceEndToEnd exercises the clinecli desktop
// path (`sessions.source='desktop'`) through the REAL scan pipeline —
// scanStateDB -> buildSessionSurfaces / buildEvents — which prior
// coverage never touched (existing statedb tests only insert
// `source='cli'` rows; the desktop surface mapping itself was only
// unit-tested in isolation at surfaceForSource, surface_test.go).
//
// Asserts the full chain: the session row scans with
// surface=desktop/surface_host=cline-desktop, model/provider/cwd are
// captured from the sessions row, and token events are parsed from the
// paired messages.json's per-message usage blocks.
func TestScanStateDB_DesktopSurfaceEndToEnd(t *testing.T) {
	t.Parallel()
	dbPath := buildFixtureCLineDesktopDataDir(t)

	sessions, maxOffset, err := scanStateDB(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("scanStateDB: %v", err)
	}
	if got, want := len(sessions), 1; got != want {
		t.Fatalf("len(sessions) = %d, want %d", got, want)
	}
	if maxOffset == 0 {
		t.Error("maxOffset = 0; want > 0 (UnixMilli of updated_at)")
	}

	s := sessions[0]
	if s.ID != fixtureDesktopSessionID {
		t.Errorf("session_id = %q; want %q", s.ID, fixtureDesktopSessionID)
	}
	if s.Source != "desktop" {
		t.Fatalf("source = %q; want desktop", s.Source)
	}
	if s.Provider != "cline" {
		t.Errorf("provider = %q; want cline", s.Provider)
	}
	if s.Model != "deepseek/deepseek-v4-flash" {
		t.Errorf("model = %q; want deepseek/deepseek-v4-flash", s.Model)
	}
	wantCWD := filepath.ToSlash("/home/dev/desktop-proj")
	if filepath.ToSlash(s.CWD) != wantCWD {
		t.Errorf("cwd = %q; want %q", s.CWD, wantCWD)
	}
	if got, want := len(s.Messages.Messages), 4; got != want {
		t.Fatalf("len(messages) = %d; want %d", got, want)
	}

	// --- surface stamping: scanStateDB's output feeds buildSessionSurfaces
	// exactly as ParseSessionFile wires it (adapter.go::ParseSessionFile).
	surfaces := buildSessionSurfaces(sessions)
	if len(surfaces) != 1 {
		t.Fatalf("len(surfaces) = %d; want 1", len(surfaces))
	}
	if surfaces[0].SessionID != fixtureDesktopSessionID {
		t.Errorf("surface session_id = %q; want %q", surfaces[0].SessionID, fixtureDesktopSessionID)
	}
	if surfaces[0].Surface != models.SurfaceDesktop {
		t.Errorf("surface = %q; want %q", surfaces[0].Surface, models.SurfaceDesktop)
	}
	if surfaces[0].SurfaceHost != "cline-desktop" {
		t.Errorf("surface_host = %q; want cline-desktop", surfaces[0].SurfaceHost)
	}

	// --- token events: buildEvents walks the loaded messages.json and
	// emits one TokenEvent per assistant message carrying a metrics
	// block (perMessageTokenEvent) — two assistant messages in the
	// desktop fixture, matching sample-session-messages-desktop.json.
	_, tokenEvents, warnings := buildEvents(context.Background(), sessions, dbPath, scrub.New(), nil)
	if len(warnings) != 0 {
		t.Errorf("buildEvents warnings = %v; want none", warnings)
	}
	if got, want := len(tokenEvents), 2; got != want {
		t.Fatalf("len(tokenEvents) = %d; want %d", got, want)
	}
	for _, te := range tokenEvents {
		if te.SessionID != fixtureDesktopSessionID {
			t.Errorf("token event session_id = %q; want %q", te.SessionID, fixtureDesktopSessionID)
		}
		if te.InputTokens != 600 || te.OutputTokens != 40 && te.OutputTokens != 44 {
			t.Errorf("token event input/output = %d/%d; want input=600, output in {40,44}", te.InputTokens, te.OutputTokens)
		}
		if te.CacheReadTokens != 200 {
			t.Errorf("token event cache_read = %d; want 200", te.CacheReadTokens)
		}
	}
}

// TestParseISO8601ms covers the watermark conversion. Cline CLI
// writes millisecond-precision ISO 8601 UTC (`2006-01-02T15:04:05.000Z`)
// in sessions.updated_at; we convert to UnixMilli for parse-cursor
// storage.
func TestParseISO8601ms(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in     string
		want   int64
		wantOK bool
	}{
		{"2026-06-05T23:28:30.654Z", 1780702110654, true},
		{"2026-06-05T23:28:30.123456789Z", 1780702110123, true}, // RFC3339Nano fallback
		{"", 0, false},
		{"not-a-timestamp", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			ms, ok := parseISO8601ms(tc.in)
			if ok != tc.wantOK {
				t.Errorf("ok = %v; want %v", ok, tc.wantOK)
			}
			if ok && ms != tc.want {
				t.Errorf("ms = %d; want %d", ms, tc.want)
			}
		})
	}
}
