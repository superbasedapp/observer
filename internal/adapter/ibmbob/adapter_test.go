package ibmbob

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// fixtureRoot / fixtureDB are built ONCE per test binary by TestMain from
// testdata/ibmbob/schema.sql + fixture.sql. Repo convention: SQLite
// fixtures are synthesized in-test (no .db binary is tracked).
var (
	fixtureRoot string
	fixtureDB   string
	// realRoot / realDB hold the REAL anonymized tasks (testdata/ibmbob/
	// real.sql); realSettings is the install-level settings.json sibling.
	realRoot string
	realDB   string
)

const (
	rootTask     = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
	childTask    = "c0ffee00c0ffee00c0ffee00c0ffee01"
	windowsTask  = "b7e1d2c3a4f5061728394a5b6c7d8e9f"
	placeholder  = "f0000000000000000000000000000001"
	newestUpdate = int64(1792554602000)
	rootUpdate   = int64(1792554514226)
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ibmbob-fixture")
	if err != nil {
		panic(err)
	}
	fixtureRoot = filepath.Join(dir, "home", ".bob", "db")
	fixtureDB = filepath.Join(fixtureRoot, dbFile)
	if err := buildFixture(fixtureDB, "schema.sql", "fixture.sql"); err != nil {
		_ = os.RemoveAll(dir)
		panic(err)
	}
	realRoot = filepath.Join(dir, "real", ".bob", "db")
	realDB = filepath.Join(realRoot, dbFile)
	if err := buildFixture(realDB, "schema.sql", "real.sql"); err != nil {
		_ = os.RemoveAll(dir)
		panic(err)
	}
	for _, home := range []string{filepath.Join(dir, "home"), filepath.Join(dir, "real")} {
		if err := writeSettings(home, "2.0.6"); err != nil {
			_ = os.RemoveAll(dir)
			panic(err)
		}
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// writeSettings writes the install-level settings.json sibling of the
// store under home (`<home>/.bob/settings/settings.json`), the file the
// adapter reads bobShell.lastRunVersion from.
func writeSettings(home, version string) error {
	dir := filepath.Join(home, ".bob", "settings")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	body := `{"licenseConsent":true,"bobShell":{"lastRunVersion":"` + version + `"}}`
	return os.WriteFile(filepath.Join(dir, "settings.json"), []byte(body), 0o600)
}

func buildFixture(path string, files ...string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	for _, f := range files {
		body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "ibmbob", f))
		if err != nil {
			return err
		}
		if _, err := db.Exec(string(body)); err != nil {
			return err
		}
	}
	return nil
}

func parseFixture(t *testing.T, from int64) adapter.ParseResult {
	t.Helper()
	a := NewWithOptions(nil, []string{fixtureRoot})
	res, err := a.ParseSessionFile(context.Background(), fixtureDB, from)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res
}

func eventsByID(res adapter.ParseResult) map[string]models.ToolEvent {
	out := map[string]models.ToolEvent{}
	for _, e := range res.ToolEvents {
		out[e.SourceEventID] = e
	}
	return out
}

func TestParseFixtureEvents(t *testing.T) {
	res := parseFixture(t, 0)
	if res.NewOffset != newestUpdate {
		t.Errorf("NewOffset = %d, want %d", res.NewOffset, newestUpdate)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("TokenEvents = %d, want 0 (Bob persists no token split)", len(res.TokenEvents))
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.Warnings)
	}
	got := eventsByID(res)

	cases := []struct {
		id         string
		session    string
		action     string
		raw        string
		success    bool
		target     string
		durationMs int64
		bytes      int64
		model      string
	}{
		{"prompt:" + rootTask + ":10000000000000000000000000000002", rootTask, models.ActionUserPrompt, "ibm-bob.user_prompt", true, "Create hello.py, run it, then delete it.", 0, 0, ""},
		{"tool:" + rootTask + ":tooluse_todo1", rootTask, models.ActionTodoUpdate, "update_todo_list", true, "update_todo_list", 3755, 0, "premium-ide"},
		{"tool:" + rootTask + ":tooluse_write1", rootTask, models.ActionWriteFile, "write_file", true, "/home/user/proj/hello.py", 1175, int64(len("print(\"hi\")\n")), "premium-ide"},
		{"tool:" + rootTask + ":tooluse_cmd1", rootTask, models.ActionRunCommand, "execute_command", false, "python3 hello.py", 3312, 0, "premium-ide"},
		{"tool:" + rootTask + ":tooluse_edit1", rootTask, models.ActionEditFile, "search_and_replace", false, "/home/user/proj/hello.py", 26, int64(len("print(\"hello\")")), "premium-ide"},
		{"text:" + rootTask + ":10000000000000000000000000000011", rootTask, models.ActionAssistantMessage, "ibm-bob.assistant_message", true, "Spawning a helper.", 0, 0, "premium-ide"},
		{"tool:" + rootTask + ":tooluse_sub1", rootTask, models.ActionSpawnSubagent, "spawn_subagent", true, "Inspect the project", 4000, 0, "premium-ide"},
		{"tool:" + rootTask + ":tooluse_mcp1", rootTask, models.ActionMCPCall, "mcp__docs__lookup", true, "mcp__docs__lookup", 12, 0, "premium-ide"},
		{"text:" + rootTask + ":10000000000000000000000000000014", rootTask, models.ActionAssistantMessage, "ibm-bob.assistant_message", true, "All done.", 0, 0, "premium-ide"},
		{"text:" + rootTask + ":10000000000000000000000000000015", rootTask, models.ActionNotification, "ibm-bob.notice", true, "Stopped: the task was cancelled.", 0, 0, ""},
		{"prompt:" + childTask + ":20000000000000000000000000000001", childTask, models.ActionUserPrompt, "ibm-bob.user_prompt", true, "Inspect the project", 0, 0, ""},
		{"tool:" + childTask + ":tooluse_read1", childTask, models.ActionReadFile, "read_file", true, "/home/user/proj/README.md", 5, 0, "premium-ide"},
		{"text:" + childTask + ":20000000000000000000000000000004", childTask, models.ActionAssistantMessage, "ibm-bob.assistant_message", true, "The project has a README.", 0, 0, "premium-ide"},
		{"prompt:" + windowsTask + ":30000000000000000000000000000002", windowsTask, models.ActionUserPrompt, "ibm-bob.user_prompt", true, "List the files", 0, 0, ""},
		{"text:" + windowsTask + ":30000000000000000000000000000003", windowsTask, models.ActionAssistantMessage, "ibm-bob.assistant_message", true, "Listing.", 0, 0, "premium-ide"},
		{"tool:" + windowsTask + ":tooluse_ls1", windowsTask, models.ActionSearchFiles, "list_files", true, `C:\Users\user\proj`, 3, 0, "premium-ide"},
	}
	if len(got) != len(cases) {
		ids := make([]string, 0, len(got))
		for id := range got {
			ids = append(ids, id)
		}
		t.Errorf("got %d events, want %d: %v", len(got), len(cases), ids)
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			e, ok := got[c.id]
			if !ok {
				t.Fatalf("missing event %s", c.id)
			}
			if e.SessionID != c.session {
				t.Errorf("SessionID = %q, want %q", e.SessionID, c.session)
			}
			if e.Tool != models.ToolIBMBob {
				t.Errorf("Tool = %q", e.Tool)
			}
			if e.ActionType != c.action {
				t.Errorf("ActionType = %q, want %q", e.ActionType, c.action)
			}
			if e.RawToolName != c.raw {
				t.Errorf("RawToolName = %q, want %q", e.RawToolName, c.raw)
			}
			if e.Success != c.success {
				t.Errorf("Success = %v, want %v", e.Success, c.success)
			}
			if e.Target != c.target {
				t.Errorf("Target = %q, want %q", e.Target, c.target)
			}
			if e.DurationMs != c.durationMs {
				t.Errorf("DurationMs = %d, want %d", e.DurationMs, c.durationMs)
			}
			if e.ContentBytes != c.bytes {
				t.Errorf("ContentBytes = %d, want %d", e.ContentBytes, c.bytes)
			}
			if e.Model != c.model {
				t.Errorf("Model = %q, want %q", e.Model, c.model)
			}
			if e.Timestamp.IsZero() {
				t.Error("zero Timestamp")
			}
			if e.SourceFile != fixtureDB {
				t.Errorf("SourceFile = %q, want %q", e.SourceFile, fixtureDB)
			}
		})
	}

	// Failure details ride on the failed rows.
	if e := got["tool:"+rootTask+":tooluse_cmd1"]; !strings.Contains(e.ErrorMessage, "NameError") {
		t.Errorf("exit-code failure ErrorMessage = %q", e.ErrorMessage)
	}
	if e := got["tool:"+rootTask+":tooluse_edit1"]; !strings.Contains(e.ErrorMessage, "No match") {
		t.Errorf("isError failure ErrorMessage = %q", e.ErrorMessage)
	}
	// The per-message _meta.timestamp wins over the shared save time.
	if e := got["tool:"+rootTask+":tooluse_write1"]; e.Timestamp.UnixMilli() != 1792554495197 {
		t.Errorf("write_file Timestamp = %d, want the assistant _meta.timestamp", e.Timestamp.UnixMilli())
	}
	for _, e := range res.ToolEvents {
		if e.SessionID == placeholder {
			t.Errorf("placeholder task emitted %s", e.SourceEventID)
		}
		if strings.Contains(e.Target, "replayed") {
			t.Errorf("hidden user message emitted: %s", e.SourceEventID)
		}
	}
}

func TestParseFixtureProjectRoots(t *testing.T) {
	res := parseFixture(t, 0)
	want := map[string]string{
		rootTask:    "/home/user/proj",
		childTask:   "/home/user/proj",
		windowsTask: `C:\Users\user\proj`,
	}
	for _, e := range res.ToolEvents {
		w, ok := want[e.SessionID]
		if !ok {
			continue
		}
		// The fixture paths do not exist on the test host, so the
		// stat-gate returns the (translated) raw workspace.
		got := e.ProjectRoot
		if got != w && filepath.ToSlash(got) != filepath.ToSlash(w) && !strings.HasSuffix(filepath.ToSlash(got), "/Users/user/proj") {
			t.Errorf("%s ProjectRoot = %q, want %q", e.SourceEventID, got, w)
		}
	}
}

func TestParseFixtureLineage(t *testing.T) {
	res := parseFixture(t, 0)
	if len(res.SessionLineages) != 1 {
		t.Fatalf("SessionLineages = %+v, want exactly the child", res.SessionLineages)
	}
	l := res.SessionLineages[0]
	if l.SessionID != childTask || l.ParentThreadID != rootTask || l.ThreadSource != threadSourceSubagent {
		t.Errorf("lineage = %+v", l)
	}
}

func TestParseWatermark(t *testing.T) {
	cases := []struct {
		name     string
		from     int64
		wantSess map[string]bool
	}{
		{"from zero reads every task", 0, map[string]bool{rootTask: true, childTask: true, windowsTask: true}},
		{"at the newest watermark reads nothing", newestUpdate, map[string]bool{}},
		{"past the watermark reads nothing", newestUpdate + 5, map[string]bool{}},
		{"inclusive bound re-reads the boundary task", rootUpdate, map[string]bool{rootTask: true, windowsTask: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := parseFixture(t, c.from)
			if res.NewOffset != newestUpdate {
				t.Errorf("NewOffset = %d, want %d", res.NewOffset, newestUpdate)
			}
			got := map[string]bool{}
			for _, e := range res.ToolEvents {
				got[e.SessionID] = true
			}
			if len(got) != len(c.wantSess) {
				t.Errorf("sessions = %v, want %v", got, c.wantSess)
			}
			for s := range c.wantSess {
				if !got[s] {
					t.Errorf("missing session %s", s)
				}
			}
		})
	}
}

func TestParseIsDeterministic(t *testing.T) {
	a := parseFixture(t, 0)
	b := parseFixture(t, 0)
	if len(a.ToolEvents) != len(b.ToolEvents) {
		t.Fatalf("event count drifted: %d vs %d", len(a.ToolEvents), len(b.ToolEvents))
	}
	for i := range a.ToolEvents {
		if a.ToolEvents[i].SourceEventID != b.ToolEvents[i].SourceEventID {
			t.Errorf("event %d id drifted: %q vs %q", i, a.ToolEvents[i].SourceEventID, b.ToolEvents[i].SourceEventID)
		}
	}
}

func TestParseViaWALSibling(t *testing.T) {
	a := NewWithOptions(nil, []string{fixtureRoot})
	viaWAL, err := a.ParseSessionFile(context.Background(), fixtureDB+"-wal", 0)
	if err != nil {
		t.Fatalf("ParseSessionFile(-wal): %v", err)
	}
	viaMain := parseFixture(t, 0)
	if viaWAL.NewOffset != viaMain.NewOffset || len(viaWAL.ToolEvents) != len(viaMain.ToolEvents) {
		t.Errorf("-wal parse (%d, %d events) != main parse (%d, %d events)",
			viaWAL.NewOffset, len(viaWAL.ToolEvents), viaMain.NewOffset, len(viaMain.ToolEvents))
	}
}

func TestParseEmptyStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".bob", "db")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, dbFile)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE unrelated (x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	a := NewWithOptions(nil, []string{dir})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile on a store with no tasks table: %v", err)
	}
	if res.NewOffset != 0 || len(res.ToolEvents) != 0 {
		t.Errorf("got %+v, want an empty result", res)
	}
}

func TestIsSessionFile(t *testing.T) {
	a := NewWithOptions(nil, []string{fixtureRoot})
	foreign := filepath.Join(t.TempDir(), "foreign", ".bob", "db")
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"main db", filepath.Join(fixtureRoot, "bob.db"), true},
		{"wal sibling", filepath.Join(fixtureRoot, "bob.db-wal"), true},
		{"shm sibling", filepath.Join(fixtureRoot, "bob.db-shm"), true},
		{"other file in root", filepath.Join(fixtureRoot, "other.db"), false},
		{"dev-db build store", filepath.Join(filepath.Dir(fixtureRoot), "dev-db", "bob.db"), false},
		{"same shape outside the watch roots", filepath.Join(foreign, "bob.db"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := a.IsSessionFile(c.path); got != c.want {
				t.Errorf("IsSessionFile(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

func TestCursorSemantics(t *testing.T) {
	a := NewWithOptions(nil, []string{fixtureRoot})
	if got := a.CursorSemanticsFor(fixtureDB).Kind; got != adapter.CursorWatermark {
		t.Errorf("Kind = %v, want CursorWatermark", got)
	}
	if got := a.CursorSemanticsFor(filepath.Join(t.TempDir(), "bob.db")); got != (adapter.FileCursorSemantics{}) {
		t.Errorf("foreign path semantics = %+v, want zero", got)
	}
}

func TestNameAndConstructors(t *testing.T) {
	a := New()
	if a.Name() != models.ToolIBMBob {
		t.Errorf("Name = %q", a.Name())
	}
	if a.scrubber == nil {
		t.Error("New() left a nil scrubber")
	}
	_ = a.WatchPaths()
	if b := NewWithOptions(nil, nil); b.scrubber == nil {
		t.Error("NewWithOptions(nil,nil) left a nil scrubber")
	}
}
