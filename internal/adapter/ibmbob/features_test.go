package ibmbob

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// newHome builds a temp `<home>/.bob/db/bob.db` from schema.sql plus
// extra SQL (or a caller-supplied schema when schema != ""), returning the
// db path. settings, when non-empty, is written as the settings.json body.
func newHome(t *testing.T, schema, extra, settings string) string {
	t.Helper()
	home := t.TempDir()
	dbPath := filepath.Join(home, ".bob", "db", dbFile)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if schema == "" {
		body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "ibmbob", "schema.sql"))
		if err != nil {
			t.Fatal(err)
		}
		schema = string(body)
	}
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(extra); err != nil {
		t.Fatal(err)
	}
	if settings != "" {
		dir := filepath.Join(home, ".bob", "settings")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(settings), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dbPath
}

func parseHome(t *testing.T, dbPath string) adapter.ParseResult {
	t.Helper()
	a := NewWithOptions(nil, []string{filepath.Dir(dbPath)})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res
}

func msgRow(id, task, role, data string, ts int) string {
	return "INSERT INTO messages (id, task_id, role, data, created_at) VALUES ('" + id + "','" + task + "','" + role + "','" +
		strings.ReplaceAll(data, "'", "''") + "'," + itoa(ts) + ");\n"
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestFeatureTaskColumns drives every column-derived dimension through one
// synthetic task: tasks.version beating the install version, tasks.git_branch,
// approval_config "ask", an image attachment on the `images` array and on an
// array-form content part, reasoning text, a mode switch mid-task, and a
// non-hook last_error classified as api_error.
func TestFeatureTaskColumns(t *testing.T) {
	const tid = "aa000000000000000000000000000001"
	extra := `INSERT INTO tasks (id, project_id, parent_id, title, status, directory, version, git_branch, env, costs, created_at, updated_at, approval_config, task_type, last_error)
VALUES ('` + tid + `','file:/nonexistent/proj',NULL,'t','active','','9.9.9','feature/x',
'{"workspace":"/nonexistent/proj","model":{"id":"premium-ide"},"modeId":"agent"}','{}',1792554000000,1792554100000,
'{"autoApprovalEnabled":false,"allowed_permissions":["read"]}','normal',
'{"name":"GatewayError","category":"api","message":"upstream 502","data":{}}');
` +
		msgRow("aa0000000000000000000000000000a1", tid, "user",
			`{"role":"user","content":"look at this","images":[{"mediaType":"image/png","data":"AAAA"},"data:image/jpeg;base64,QQ=="],"_meta":{"timestamp":1792554001000,"mode":{"id":"agent"}}}`, 1792554001000) +
		msgRow("aa0000000000000000000000000000a2", tid, "assistant",
			`{"role":"assistant","content":"thinking out loud","reasoning":"first I should look","_meta":{"timestamp":1792554002000},"toolCalls":[{"id":"t1","name":"read_file","arguments":{"path":"/nonexistent/proj/a.go"}}]}`, 1792554002000) +
		msgRow("aa0000000000000000000000000000a3", tid, "user",
			`{"role":"user","content":[{"type":"image","mediaType":"image/webp"}],"_meta":{"timestamp":1792554003000,"mode":{"id":"ask"}}}`, 1792554003000) +
		msgRow("aa0000000000000000000000000000a4", tid, "assistant",
			`{"role":"assistant","content":"done","stop":true,"_meta":{"timestamp":1792554004000}}`, 1792554004000)
	db := newHome(t, "", extra, `{"bobShell":{"lastRunVersion":"2.0.6"}}`)
	res := parseHome(t, db)

	byID := eventsByID(res)
	p1 := byID["prompt:"+tid+":aa0000000000000000000000000000a1"]
	if len(p1.UserAttachments) != 2 || p1.UserAttachments[0] != (models.UserAttachment{Kind: "image", MediaType: "image/png"}) ||
		p1.UserAttachments[1] != (models.UserAttachment{Kind: "image", MediaType: "image/jpeg"}) {
		t.Errorf("images array attachments = %+v", p1.UserAttachments)
	}
	p2 := byID["prompt:"+tid+":aa0000000000000000000000000000a3"]
	if len(p2.UserAttachments) != 1 || p2.UserAttachments[0].MediaType != "image/webp" || p2.Target != "(attachment only)" {
		t.Errorf("image-only prompt = %+v", p2)
	}
	if p1.TurnIndex != 1 || p2.TurnIndex != 2 {
		t.Errorf("TurnIndex = %d, %d want 1, 2", p1.TurnIndex, p2.TurnIndex)
	}
	// Reasoning rides the first event of the assistant message (the text).
	text := byID["text:"+tid+":aa0000000000000000000000000000a2"]
	read := byID["tool:"+tid+":t1"]
	if text.PrecedingReasoning != "first I should look" || read.PrecedingReasoning != "" {
		t.Errorf("reasoning text/tool = %q / %q", text.PrecedingReasoning, read.PrecedingReasoning)
	}
	// Mode: the switch to "ask" shows on the events after it, "agent" before.
	if read.Metadata.CollaborationMode != "agent" || p2.Metadata.CollaborationMode != "ask" {
		t.Errorf("modes = %q / %q", read.Metadata.CollaborationMode, p2.Metadata.CollaborationMode)
	}
	if p1.Metadata.PermissionMode != "ask" {
		t.Errorf("PermissionMode = %q, want ask", p1.Metadata.PermissionMode)
	}
	final := byID["text:"+tid+":aa0000000000000000000000000000a4"]
	if final.Metadata.StopReason != "end_turn" {
		t.Errorf("final StopReason = %q", final.Metadata.StopReason)
	}
	// Git branch from tasks.git_branch on every row.
	for _, e := range res.ToolEvents {
		if e.GitBranch != "feature/x" {
			t.Errorf("%s GitBranch = %q", e.SourceEventID, e.GitBranch)
		}
	}
	// last_error with a non-hook name is an api_error.
	var errRows []models.ToolEvent
	for _, e := range res.ToolEvents {
		if strings.HasPrefix(e.SourceEventID, "err:") {
			errRows = append(errRows, e)
		}
	}
	if len(errRows) != 1 || errRows[0].ActionType != models.ActionAPIError || errRows[0].Success ||
		errRows[0].Target != "GatewayError" || errRows[0].ErrorMessage != "upstream 502" {
		t.Errorf("error rows = %+v", errRows)
	}
	// tasks.version beats the install-level lastRunVersion.
	if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0].Version != "9.9.9" {
		t.Errorf("SessionToolVersions = %+v, want 9.9.9 from tasks.version", res.SessionToolVersions)
	}
}

func TestFeatureSubagentMetadata(t *testing.T) {
	const parent, child = "bb000000000000000000000000000001", "bb000000000000000000000000000002"
	extra := `INSERT INTO tasks (id, project_id, parent_id, title, status, directory, env, costs, created_at, updated_at, task_type)
VALUES ('` + parent + `','file:/nonexistent/p',NULL,'','active','','{"workspace":"/nonexistent/p"}','{}',1,1000,'normal'),
('` + child + `','file:/nonexistent/p','` + parent + `','','active','','{"workspace":"/nonexistent/p"}','{}',2,2000,'subagent');
` + msgRow("bb0000000000000000000000000000c1", child, "user",
		`{"role":"user","content":"sub task","_meta":{"timestamp":2001}}`, 2001)
	res := parseHome(t, newHome(t, "", extra, ""))
	if len(res.ToolEvents) != 1 {
		t.Fatalf("events = %d, want 1", len(res.ToolEvents))
	}
	m := res.ToolEvents[0].Metadata
	if m == nil || !m.IsSubagent || m.ParentSessionID != parent {
		t.Errorf("child Metadata = %+v", m)
	}
	// No settings.json: no tool version, no error.
	if len(res.SessionToolVersions) != 0 {
		t.Errorf("SessionToolVersions = %+v, want none without a version source", res.SessionToolVersions)
	}
}

// TestOlderSchemaWithoutNewColumns: a store whose tasks table predates the
// version / approval_config / last_error columns must still parse.
func TestOlderSchemaWithoutNewColumns(t *testing.T) {
	schema := `CREATE TABLE tasks (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, parent_id TEXT, title TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active', first_message TEXT, directory TEXT NOT NULL, env TEXT, costs TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, task_type TEXT NOT NULL DEFAULT 'normal');
CREATE TABLE messages (id TEXT PRIMARY KEY, task_id TEXT NOT NULL, role TEXT NOT NULL, data TEXT NOT NULL, created_at INTEGER NOT NULL);`
	extra := `INSERT INTO tasks (id, project_id, directory, env, created_at, updated_at) VALUES ('cc000000000000000000000000000001','file:/nonexistent/p','','{"workspace":"/nonexistent/p"}',1,1000);
` + msgRow("cc0000000000000000000000000000d1", "cc000000000000000000000000000001", "user",
		`{"role":"user","content":"hello","_meta":{"timestamp":1001}}`, 1001)
	res := parseHome(t, newHome(t, schema, extra, `{"bobShell":{"lastRunVersion":"2.0.6"}}`))
	if len(res.ToolEvents) != 1 {
		t.Fatalf("events = %d, want 1", len(res.ToolEvents))
	}
	if m := res.ToolEvents[0].Metadata; m != nil && m.PermissionMode != "" {
		t.Errorf("PermissionMode = %q without an approval_config column", m.PermissionMode)
	}
	if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0].Version != "2.0.6" {
		t.Errorf("SessionToolVersions = %+v", res.SessionToolVersions)
	}
}

func TestPermissionMode(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"null text", "null", ""},
		{"malformed", "{", ""},
		{"read only", `{"autoApprovalEnabled":true,"allowed_permissions":["read"]}`, "auto:read"},
		{"all four", `{"autoApprovalEnabled":true,"allowed_permissions":["read","todo","edit","execute"]}`, "auto:read+todo+edit+execute"},
		{"auto off", `{"autoApprovalEnabled":false,"allowed_permissions":["read"]}`, "ask"},
		{"auto on, nothing allowed", `{"autoApprovalEnabled":true,"allowed_permissions":[]}`, "ask"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := permissionMode(c.in); got != c.want {
				t.Errorf("permissionMode(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestStopReason(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""}, {"true", "end_turn"}, {"false", ""}, {`"max_tokens"`, "max_tokens"}, {"7", ""},
	}
	for _, c := range cases {
		if got := stopReason(json.RawMessage(c.in)); got != c.want {
			t.Errorf("stopReason(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLastErrorOf(t *testing.T) {
	for _, in := range []string{"", "null", "  null  "} {
		if _, ok := lastErrorOf(in); ok {
			t.Errorf("lastErrorOf(%q) reported an error", in)
		}
	}
	if raw, ok := lastErrorOf(`{"name":"X"}`); !ok || raw != `{"name":"X"}` {
		t.Errorf("lastErrorOf(real) = %q, %v", raw, ok)
	}
}

func TestDataURIMediaType(t *testing.T) {
	cases := map[string]string{
		"data:image/png;base64,AAA": "image/png",
		"data:image/gif,xx":         "image/gif",
		"https://x/y.png":           "",
		"data:":                     "",
	}
	for in, want := range cases {
		if got := dataURIMediaType(in); got != want {
			t.Errorf("dataURIMediaType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadInstallVersion(t *testing.T) {
	write := func(body string) string {
		home := t.TempDir()
		dir := filepath.Join(home, ".bob", "settings")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if body != "" {
			if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return filepath.Join(home, ".bob", "db", dbFile)
	}
	cases := []struct{ name, body, want string }{
		{"missing file", "", ""},
		{"malformed", "{", ""},
		{"no key", `{"licenseConsent":true}`, ""},
		{"present", `{"licenseConsent":true,"bobShell":{"lastRunVersion":" 2.0.6 "}}`, "2.0.6"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := readInstallVersion(write(c.body)); got != c.want {
				t.Errorf("readInstallVersion = %q, want %q", got, c.want)
			}
		})
	}
}

// TestSyntheticFixtureStillCovered pins the synthetic subagent + array-image
// shapes against the new fields: the Windows-shaped task's array-form image
// part becomes an attachment, and the child task is flagged a subagent.
func TestSyntheticFixtureStillCovered(t *testing.T) {
	res := parseFixture(t, 0)
	var sawImage, sawChild bool
	for _, e := range res.ToolEvents {
		if e.SessionID == windowsTask && len(e.UserAttachments) > 0 {
			sawImage = true
			if e.UserAttachments[0].Kind != "image" {
				t.Errorf("attachment = %+v", e.UserAttachments)
			}
		}
		if e.SessionID == childTask {
			sawChild = true
			if e.Metadata == nil || !e.Metadata.IsSubagent || e.Metadata.ParentSessionID != rootTask {
				t.Errorf("child event %s Metadata = %+v", e.SourceEventID, e.Metadata)
			}
		}
	}
	if !sawImage || !sawChild {
		t.Errorf("sawImage=%v sawChild=%v", sawImage, sawChild)
	}
	if len(res.SessionToolVersions) < 3 {
		t.Errorf("SessionToolVersions = %+v, want one per emitting task", res.SessionToolVersions)
	}
}
