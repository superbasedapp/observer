package crush

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// crushSchema is the subset of the live Crush schema the adapter reads.
const crushSchema = `
CREATE TABLE sessions (
	id TEXT PRIMARY KEY,
	parent_session_id TEXT,
	title TEXT NOT NULL,
	message_count INTEGER NOT NULL DEFAULT 0,
	prompt_tokens INTEGER NOT NULL DEFAULT 0,
	completion_tokens INTEGER NOT NULL DEFAULT 0,
	cost REAL NOT NULL DEFAULT 0.0,
	updated_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE TABLE messages (
	id TEXT PRIMARY KEY,
	session_id TEXT NOT NULL,
	role TEXT NOT NULL,
	parts TEXT NOT NULL DEFAULT '[]',
	model TEXT,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	finished_at INTEGER,
	provider TEXT,
	is_summary_message INTEGER DEFAULT 0 NOT NULL
);`

func newCrushDB(t *testing.T, path string, stmts ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(crushSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
}

// dbPathUnder returns <root>/.crush/crush.db for a fresh temp project root.
func dbPathUnder(t *testing.T) (root, dbPath string) {
	t.Helper()
	root = t.TempDir()
	// Give the project its own .git marker so git.Resolve pins the root
	// deterministically (some CI temp roots sit under a stray parent .git).
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath = filepath.Join(root, ".crush", "crush.db")
	return root, dbPath
}

// --- fixture statements -----------------------------------------------

// simpleSession: one user text + one assistant text, tokens + cost.
func simpleSession() []string {
	return []string{
		`INSERT INTO sessions(id,title,prompt_tokens,completion_tokens,cost,updated_at,created_at)
		 VALUES ('ses_simple','Greeting',21749,5,0.05448195,1783550924,1783550922)`,
		`INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at) VALUES
		 ('m_u','ses_simple','user','[{"type":"text","data":{"text":"Hi"}},{"type":"finish","data":{"reason":"stop","time":0}}]','','',1783550922,1783550922),
		 ('m_a','ses_simple','assistant','[{"type":"text","data":{"text":"Hi there"}},{"type":"finish","data":{"reason":"end_turn","time":1783550924}}]','gpt-5.4','openai',1783550923,1783550924)`,
	}
}

// toolSession: assistant tool_call (write, ok) + role=tool tool_result,
// plus a failing bash tool_call with an error result and a reasoning block.
func toolSession() []string {
	return []string{
		`INSERT INTO sessions(id,title,prompt_tokens,completion_tokens,cost,updated_at,created_at)
		 VALUES ('ses_tool','Do work',8975,5,0.08627345,1783572212,1783572197)`,
		`INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at) VALUES
		 ('mt_u','ses_tool','user','[{"type":"text","data":{"text":"make hello then dir"}}]','','',1783572197,1783572197),
		 ('mt_a1','ses_tool','assistant','[{"type":"reasoning","data":{"thinking":"I should create the file first.","started_at":1783572201,"finished_at":1783572203}},{"type":"tool_call","data":{"id":"call_write","name":"write","input":"{\"file_path\":\"/proj/hello.txt\",\"content\":\"hello\"}","finished":true}},{"type":"finish","data":{"reason":"tool_use","time":1783572205}}]','gpt-5.4-mini','openai',1783572200,1783572205),
		 ('mt_t1','ses_tool','tool','[{"type":"tool_result","data":{"tool_call_id":"call_write","name":"write","content":"Wrote 5 bytes","is_error":false}}]','','',1783572205,1783572205),
		 ('mt_a2','ses_tool','assistant','[{"type":"tool_call","data":{"id":"call_bash","name":"bash","input":"{\"command\":\"dir\",\"working_dir\":\"/proj\"}","finished":true}},{"type":"finish","data":{"reason":"tool_use","time":1783572207}}]','gpt-5.4-mini','openai',1783572206,1783572207),
		 ('mt_t2','ses_tool','tool','[{"type":"tool_result","data":{"tool_call_id":"call_bash","name":"bash","content":"dir: command not found","is_error":true}}]','','',1783572207,1783572207),
		 ('mt_a3','ses_tool','assistant','[{"type":"text","data":{"text":"Done"}},{"type":"finish","data":{"reason":"end_turn","time":1783572212}}]','gpt-5.4-mini','openai',1783572210,1783572212)`,
	}
}

// failoverSession: two assistant messages, first bedrock/anthropic, second
// openai — the newest wins for token-event model resolution.
func failoverSession() []string {
	return []string{
		`INSERT INTO sessions(id,title,prompt_tokens,completion_tokens,cost,updated_at,created_at)
		 VALUES ('ses_fail','Untitled',12059,49,0.01786425,1783551012,1783550940)`,
		`INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at) VALUES
		 ('mf_u','ses_fail','user','[{"type":"text","data":{"text":"hi"}}]','','',1783550940,1783550940),
		 ('mf_a1','ses_fail','assistant','[{"type":"text","data":{"text":"(bedrock reply)"}}]','us.anthropic.claude-sonnet-4-6','bedrock',1783550948,1783550948),
		 ('mf_u2','ses_fail','user','[{"type":"text","data":{"text":"again"}}]','','',1783551000,1783551000),
		 ('mf_a2','ses_fail','assistant','[{"type":"text","data":{"text":"(openai reply)"}}]','gpt-5.4-mini','openai',1783551012,1783551012)`,
	}
}

// emptySession: a session with no tokens and no cost.
func emptySession() []string {
	return []string{
		`INSERT INTO sessions(id,title,prompt_tokens,completion_tokens,cost,updated_at,created_at)
		 VALUES ('ses_empty','New Session',0,0,0.0,1783550100,1783550100)`,
	}
}

// --- tests ------------------------------------------------------------

func TestIsSessionFile(t *testing.T) {
	root := "/home/u/proj"
	a := NewWithOptions(nil, []string{filepath.Join(root, ".crush")})
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"db under root", filepath.Join(root, ".crush", "crush.db"), true},
		{"wal under root", filepath.Join(root, ".crush", "crush.db-wal"), true},
		{"shm not matched", filepath.Join(root, ".crush", "crush.db-shm"), false},
		{"parent not .crush", filepath.Join(root, "crush.db"), false},
		{"wrong basename", filepath.Join(root, ".crush", "other.db"), false},
		{"outside root", "/somewhere/else/.crush/crush.db", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := a.IsSessionFile(c.path); got != c.want {
				t.Errorf("IsSessionFile(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

func TestParseSessionFile_FullEmission(t *testing.T) {
	root, dbPath := dbPathUnder(t)
	newCrushDB(t, dbPath, toolSession()...)
	a := NewWithOptions(nil, []string{filepath.Join(root, ".crush")})

	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	byRaw := map[string]models.ToolEvent{}
	for _, ev := range res.ToolEvents {
		byRaw[ev.RawToolName] = ev
		if ev.Tool != models.ToolCrush {
			t.Errorf("ev.Tool = %q, want %q", ev.Tool, models.ToolCrush)
		}
		if ev.ProjectRoot != root {
			t.Errorf("ProjectRoot = %q, want %q", ev.ProjectRoot, root)
		}
	}

	want := map[string]string{
		"crush.user_prompt":    models.ActionUserPrompt,
		"crush.assistant_text": models.ActionAssistantMessage,
		"write":                models.ActionWriteFile,
		"bash":                 models.ActionRunCommand,
	}
	for raw, wantAction := range want {
		ev, ok := byRaw[raw]
		if !ok {
			t.Errorf("missing event RawToolName=%q; got=%v", raw, keys(byRaw))
			continue
		}
		if ev.ActionType != wantAction {
			t.Errorf("RawToolName=%q action = %q, want %q", raw, ev.ActionType, wantAction)
		}
	}

	// write succeeded, bash failed (is_error result).
	if w := byRaw["write"]; !w.Success || w.ToolOutput != "Wrote 5 bytes" {
		t.Errorf("write event = %+v, want success + output", w)
	}
	if b := byRaw["bash"]; b.Success || b.ErrorMessage == "" {
		t.Errorf("bash event = %+v, want failure + error", b)
	}
	// B3: reasoning mints no row of its own — the thinking that
	// introduced the `write` call rides that call's PrecedingReasoning.
	if _, ok := byRaw["crush.reasoning"]; ok {
		t.Errorf("crush.reasoning row emitted; reasoning must never be its own action (B3)")
	}
	if w := byRaw["write"]; w.PrecedingReasoning != "I should create the file first." {
		t.Errorf("write PrecedingReasoning = %q, want the reasoning part's text", w.PrecedingReasoning)
	}
	// write target derived from input.file_path.
	if w := byRaw["write"]; w.Target != "/proj/hello.txt" {
		t.Errorf("write target = %q, want /proj/hello.txt", w.Target)
	}
}

func TestParseSessionFile_TokenAndCost(t *testing.T) {
	root, dbPath := dbPathUnder(t)
	newCrushDB(t, dbPath, simpleSession()...)
	a := NewWithOptions(nil, []string{filepath.Join(root, ".crush")})

	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("want 1 token event, got %d", len(res.TokenEvents))
	}
	te := res.TokenEvents[0]
	if te.Tool != models.ToolCrush {
		t.Errorf("Tool = %q, want crush", te.Tool)
	}
	if te.InputTokens != 21749 || te.OutputTokens != 5 {
		t.Errorf("tokens = %d/%d, want 21749/5", te.InputTokens, te.OutputTokens)
	}
	if te.EstimatedCostUSD != 0.05448195 {
		t.Errorf("EstimatedCostUSD = %v, want 0.05448195 (crush pre-computed cost)", te.EstimatedCostUSD)
	}
	if te.Model != "gpt-5.4" {
		t.Errorf("Model = %q, want gpt-5.4 (newest assistant)", te.Model)
	}
	if te.SourceEventID != "tokens:ses_simple" {
		t.Errorf("SourceEventID = %q, want tokens:ses_simple", te.SourceEventID)
	}
	if te.Reliability != models.ReliabilityApproximate || te.Source != models.TokenSourceJSONL {
		t.Errorf("source/reliability = %q/%q", te.Source, te.Reliability)
	}
	if te.ProjectRoot != root {
		t.Errorf("ProjectRoot = %q, want %q", te.ProjectRoot, root)
	}
}

func TestParseSessionFile_ProviderFailover(t *testing.T) {
	root, dbPath := dbPathUnder(t)
	newCrushDB(t, dbPath, failoverSession()...)
	a := NewWithOptions(nil, []string{filepath.Join(root, ".crush")})

	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("want 1 token event, got %d", len(res.TokenEvents))
	}
	if m := res.TokenEvents[0].Model; m != "gpt-5.4-mini" {
		t.Errorf("failover token model = %q, want gpt-5.4-mini (newest assistant wins)", m)
	}
}

func TestParseSessionFile_EmptySessionNoTokens(t *testing.T) {
	root, dbPath := dbPathUnder(t)
	newCrushDB(t, dbPath, emptySession()...)
	a := NewWithOptions(nil, []string{filepath.Join(root, ".crush")})

	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("want 0 token events for empty session, got %d", len(res.TokenEvents))
	}
}

func TestWatermarkResumption(t *testing.T) {
	root, dbPath := dbPathUnder(t)
	newCrushDB(t, dbPath, simpleSession()...)
	a := NewWithOptions(nil, []string{filepath.Join(root, ".crush")})

	res1, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("parse1: %v", err)
	}
	if len(res1.ToolEvents) == 0 {
		t.Fatalf("parse1 emitted nothing")
	}
	// Second parse at the returned watermark: no new rows.
	res2, err := a.ParseSessionFile(context.Background(), dbPath, res1.NewOffset)
	if err != nil {
		t.Fatalf("parse2: %v", err)
	}
	if len(res2.ToolEvents) != 0 || len(res2.TokenEvents) != 0 {
		t.Errorf("parse2 should be empty, got %d tool / %d token", len(res2.ToolEvents), len(res2.TokenEvents))
	}
	if res2.NewOffset != res1.NewOffset {
		t.Errorf("watermark drifted: %d -> %d", res1.NewOffset, res2.NewOffset)
	}

	// Add a newer message; only it should come back.
	appendMessage(t, dbPath, `INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at)
		VALUES ('m_new','ses_simple','user','[{"type":"text","data":{"text":"more"}}]','','',1783551100,1783551100)`)
	res3, err := a.ParseSessionFile(context.Background(), dbPath, res1.NewOffset)
	if err != nil {
		t.Fatalf("parse3: %v", err)
	}
	if len(res3.ToolEvents) != 1 {
		t.Fatalf("parse3 want 1 new event, got %d", len(res3.ToolEvents))
	}
	if res3.ToolEvents[0].SourceEventID != "prompt:m_new:0" {
		t.Errorf("parse3 event = %q, want prompt:m_new:0", res3.ToolEvents[0].SourceEventID)
	}
}

func TestSchemaMissingTables(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, ".crush", "crush.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	// A DB with neither sessions nor messages.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE goose_db_version(id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	a := NewWithOptions(nil, []string{filepath.Join(root, ".crush")})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile on tableless db: %v", err)
	}
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 {
		t.Errorf("want empty result, got %d/%d", len(res.ToolEvents), len(res.TokenEvents))
	}
}

func TestForeignMountStaging(t *testing.T) {
	// Simulate a foreign mount: mark the temp dir's parent as a non-native
	// home so stageMirrorIfForeign copies rather than opening in place.
	src := t.TempDir()
	dbPath := filepath.Join(src, ".crush", "crush.db")
	newCrushDB(t, dbPath, simpleSession()...)

	orig := allHomesFunc
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{{Path: src, OS: crossmount.OSWindows, Origin: "wsl-mnt:test"}}
	}
	defer func() { allHomesFunc = orig }()

	if !isForeignMountPath(dbPath) {
		t.Fatalf("path %q not detected as foreign", dbPath)
	}
	staged, err := stageMirrorIfForeign(dbPath)
	if err != nil {
		t.Fatalf("stageMirror: %v", err)
	}
	if staged == dbPath {
		t.Fatalf("foreign path was not staged to a mirror")
	}
	if _, err := os.Stat(staged); err != nil {
		t.Fatalf("mirror db missing: %v", err)
	}

	// The adapter should parse the staged copy transparently.
	a := NewWithOptions(nil, []string{filepath.Join(src, ".crush")})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile via mirror: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Errorf("want 1 token event via mirror, got %d", len(res.TokenEvents))
	}
}

func TestMapTool(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantAction string
		wantTarget string
	}{
		{"bash", `{"command":"ls -la"}`, models.ActionRunCommand, "ls -la"},
		{"view", `{"file_path":"/a/b.go"}`, models.ActionReadFile, "/a/b.go"},
		{"write", `{"file_path":"/a/c.txt"}`, models.ActionWriteFile, "/a/c.txt"},
		{"edit", `{"file_path":"/a/d.go"}`, models.ActionEditFile, "/a/d.go"},
		{"multiedit", `{"file_path":"/a/e.go"}`, models.ActionEditFile, "/a/e.go"},
		{"ls", `{"path":"/a"}`, models.ActionSearchFiles, "/a"},
		{"glob", `{"pattern":"**/*.go"}`, models.ActionSearchFiles, "**/*.go"},
		{"grep", `{"pattern":"TODO"}`, models.ActionSearchText, "TODO"},
		{"fetch", `{"url":"https://x"}`, models.ActionWebFetch, "https://x"},
		{"sourcegraph", `{"query":"repo:x"}`, models.ActionWebSearch, "repo:x"},
		{"agent", `{"query":"subtask"}`, models.ActionSpawnSubagent, "subtask"},
		{"mcp_serverA_do", `{}`, models.ActionMCPCall, "mcp_serverA_do"},
		{"weirdtool", `{}`, models.ActionUnknown, "weirdtool"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotAction, gotTarget := mapTool(c.name, []byte(c.input))
			if gotAction != c.wantAction {
				t.Errorf("action = %q, want %q", gotAction, c.wantAction)
			}
			if gotTarget != c.wantTarget {
				t.Errorf("target = %q, want %q", gotTarget, c.wantTarget)
			}
		})
	}
}

// b3Session exercises every reasoning-threading rule in one session.
// The message ids sort in creation order, which is the order the parser
// sees them (ORDER BY created_at, id).
//
//	b1 user      "first task"                 → clears pending
//	b2 assistant reasoning THINK_ONE, bash A, bash B
//	                                          → A carries THINK_ONE, B empty (consumed-once)
//	b3 assistant reasoning STALE_ACROSS_TURN  → never consumed
//	b4 user      "second task"                → discards STALE_ACROSS_TURN
//	b5 assistant bash C                       → empty (turn-boundary discard)
//	b6 assistant reasoning FIRST, reasoning SECOND, bash D
//	                                          → D carries SECOND (last-wins)
//	b7 assistant reasoning CROSS_SESSION (ses_b3)
//	b8 assistant bash E in a DIFFERENT session → empty (session-scoped)
func b3Session() []string {
	return []string{
		`INSERT INTO sessions(id,title,prompt_tokens,completion_tokens,cost,updated_at,created_at)
		 VALUES ('ses_b3','B3',10,2,0.01,1783600100,1783600000)`,
		`INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at) VALUES
		 ('b1','ses_b3','user','[{"type":"text","data":{"text":"first task"}}]','','',1783600001,1783600001),
		 ('b2','ses_b3','assistant','[{"type":"reasoning","data":{"thinking":"THINK_ONE","started_at":1783600002,"finished_at":1783600003}},{"type":"tool_call","data":{"id":"call_a","name":"bash","input":"{\"command\":\"cmd_a\"}","finished":true}},{"type":"tool_call","data":{"id":"call_b","name":"bash","input":"{\"command\":\"cmd_b\"}","finished":true}}]','m','openai',1783600004,1783600004),
		 ('b3','ses_b3','assistant','[{"type":"reasoning","data":{"thinking":"STALE_ACROSS_TURN","started_at":1783600005,"finished_at":1783600006}}]','m','openai',1783600007,1783600007),
		 ('b4','ses_b3','user','[{"type":"text","data":{"text":"second task"}}]','','',1783600008,1783600008),
		 ('b5','ses_b3','assistant','[{"type":"tool_call","data":{"id":"call_c","name":"bash","input":"{\"command\":\"cmd_c\"}","finished":true}}]','m','openai',1783600009,1783600009),
		 ('b6','ses_b3','assistant','[{"type":"reasoning","data":{"thinking":"FIRST"}},{"type":"reasoning","data":{"thinking":"SECOND"}},{"type":"tool_call","data":{"id":"call_d","name":"bash","input":"{\"command\":\"cmd_d\"}","finished":true}}]','m','openai',1783600010,1783600010),
		 ('b7','ses_b3','assistant','[{"type":"reasoning","data":{"thinking":"CROSS_SESSION"}}]','m','openai',1783600011,1783600011),
		 ('b8','ses_other','assistant','[{"type":"tool_call","data":{"id":"call_e","name":"bash","input":"{\"command\":\"cmd_e\"}","finished":true}}]','m','openai',1783600012,1783600012)`,
	}
}

// TestReasoningNeverMintsAnAction is the B3 regression pin: a Crush
// `reasoning` part must produce NO action row (neither the retired
// `crush.reasoning` raw name nor any other reasoning-shaped row) and its
// text must instead ride the successor event's PrecedingReasoning under
// the consumed-once / last-wins / turn-boundary-discard contract.
func TestReasoningNeverMintsAnAction(t *testing.T) {
	root, dbPath := dbPathUnder(t)
	newCrushDB(t, dbPath, b3Session()...)
	a := NewWithOptions(nil, []string{filepath.Join(root, ".crush")})

	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	byCmd := map[string]models.ToolEvent{}
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "crush.reasoning" {
			t.Fatalf("crush.reasoning row emitted: %+v", ev)
		}
		if strings.Contains(strings.ToLower(ev.RawToolName), "reasoning") ||
			strings.Contains(strings.ToLower(ev.RawToolName), "thinking") {
			t.Fatalf("reasoning-named action row emitted: raw=%q %+v", ev.RawToolName, ev)
		}
		// No row may carry the reasoning bodies as its own content.
		for _, body := range []string{"THINK_ONE", "STALE_ACROSS_TURN", "FIRST", "SECOND", "CROSS_SESSION"} {
			if ev.Target == body || ev.ToolOutput == body {
				t.Fatalf("reasoning body %q surfaced as action content: %+v", body, ev)
			}
		}
		if ev.RawToolName == "bash" {
			byCmd[ev.Target] = ev
		}
	}
	if len(byCmd) != 5 {
		t.Fatalf("want 5 bash rows, got %d (%v)", len(byCmd), res.ToolEvents)
	}

	cases := []struct{ cmd, wantReasoning, why string }{
		{"cmd_a", "THINK_ONE", "the reasoning that introduced it"},
		{"cmd_b", "", "consumed-once: the sibling call already took it"},
		{"cmd_c", "", "turn-boundary discard: a user prompt intervened"},
		{"cmd_d", "SECOND", "last-wins: the newer reasoning part replaces the older"},
		{"cmd_e", "", "session-scoped: pending reasoning never crosses into another session"},
	}
	for _, c := range cases {
		if got := byCmd[c.cmd].PrecedingReasoning; got != c.wantReasoning {
			t.Errorf("%s PrecedingReasoning = %q, want %q (%s)", c.cmd, got, c.wantReasoning, c.why)
		}
	}
}

// --- helpers ----------------------------------------------------------

func appendMessage(t *testing.T, dbPath, stmt string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(stmt); err != nil {
		t.Fatalf("append: %v", err)
	}
}

func keys(m map[string]models.ToolEvent) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestSessionTokenCounts pins the reportability table: Crush's session
// counters hold the LAST step's usage, so they are the session total
// only for a session with at most one step (one assistant message), and
// counters Crush never wrote are "not recorded", not "zero tokens".
func TestSessionTokenCounts(t *testing.T) {
	cases := []struct {
		name            string
		prompt, compl   int64
		steps           int
		wantIn, wantOut int64
		wantRel         string
	}{
		{"no assistant message yet", 100, 5, 0, 100, 5, models.ReliabilityApproximate},
		{"single step: counters are the total", 21749, 5, 1, 21749, 5, models.ReliabilityApproximate},
		{"two steps: counters are a last-step snapshot", 12059, 49, 2, 0, 0, models.ReliabilityUnknown},
		{"many steps", 40000, 900, 30, 0, 0, models.ReliabilityUnknown},
		{"single step, counters never written", 0, 0, 1, 0, 0, models.ReliabilityUnknown},
		{"no step, counters never written", 0, 0, 0, 0, 0, models.ReliabilityUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := sessionTokenCounts(tc.prompt, tc.compl, tc.steps)
			if u.In != tc.wantIn || u.Out != tc.wantOut || u.Reliability != tc.wantRel {
				t.Errorf("sessionTokenCounts(%d,%d,%d) = %d/%d %q, want %d/%d %q",
					tc.prompt, tc.compl, tc.steps, u.In, u.Out, u.Reliability, tc.wantIn, tc.wantOut, tc.wantRel)
			}
		})
	}
}

// zeroCostMultiStepSession is a flat-rate / local-model session with two
// successful steps and Crush's own cost 0: its counters (9500/30) are the
// second step's context snapshot.
func zeroCostMultiStepSession() []string {
	return []string{
		`INSERT INTO sessions(id,title,prompt_tokens,completion_tokens,cost,updated_at,created_at)
		 VALUES ('ses_flatmulti','Flat multi',9500,30,0.0,1790000310,1790000300)`,
		`INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at) VALUES
		 ('mm_u','ses_flatmulti','user','[{"type":"text","data":{"text":"work"}}]','','',1790000300,1790000300),
		 ('mm_a1','ses_flatmulti','assistant','[{"type":"finish","data":{"reason":"tool_use","time":1790000305}}]','qwen3-coder','ollama',1790000301,1790000305),
		 ('mm_a2','ses_flatmulti','assistant','[{"type":"text","data":{"text":"done"}},{"type":"finish","data":{"reason":"end_turn","time":1790000310}}]','qwen3-coder','ollama',1790000306,1790000310)`,
	}
}

// TestParseSessionFile_StepCountDecidesTokens covers the capture rule
// end to end: Crush's prompt/completion counters are the last usage-
// bearing step's, so they are reported (approximate) only for a one-step
// session; every other non-vacant session still emits its row with the
// model and Crush's own cost, zero counts and Reliability = unknown
// (full coverage, "unknown means unknown"). Steps finished with reason
// error/canceled never updated the counters and do not count.
func TestParseSessionFile_StepCountDecidesTokens(t *testing.T) {
	cases := []struct {
		name            string
		stmts           []string
		session         string
		wantIn, wantOut int64
		wantCost        float64
		wantModel       string
		wantRel         string
	}{
		{
			// (a) one step, positive cost: counts reported unchanged.
			name:    "one-step session reports its counts",
			stmts:   simpleSession(),
			session: "ses_simple",
			wantIn:  21749, wantOut: 5, wantCost: 0.05448195,
			wantModel: "gpt-5.4", wantRel: models.ReliabilityApproximate,
		},
		{
			// (a) one step, Crush's own cost 0: the real counts are kept
			// (full-coverage ruling 2026-09-28; the gross prompt may
			// over-bill on a read-side re-price - documented).
			name: "zero-cost one-step session keeps its counts",
			stmts: []string{
				`INSERT INTO sessions(id,title,prompt_tokens,completion_tokens,cost,updated_at,created_at)
				 VALUES ('ses_flat','Flat rate',9120,40,0.0,1790000110,1790000100)`,
				`INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at) VALUES
				 ('mz_u','ses_flat','user','[{"type":"text","data":{"text":"hi"}}]','','',1790000100,1790000100),
				 ('mz_a','ses_flat','assistant','[{"type":"text","data":{"text":"hello"}},{"type":"finish","data":{"reason":"end_turn","time":1790000110}}]','qwen3-coder','ollama',1790000105,1790000110)`,
			},
			session: "ses_flat",
			wantIn:  9120, wantOut: 40, wantCost: 0,
			wantModel: "qwen3-coder", wantRel: models.ReliabilityApproximate,
		},
		{
			// (b) three successful assistant steps: the counters are the
			// third step's context snapshot, not the session total; the
			// cumulative cost is carried as-is.
			name:    "multi-step session reports cost, tokens unknown",
			stmts:   toolSession(),
			session: "ses_tool",
			wantIn:  0, wantOut: 0, wantCost: 0.08627345,
			wantModel: "gpt-5.4-mini", wantRel: models.ReliabilityUnknown,
		},
		{
			// (c) the R2 follow-up: a zero-cost multi-step session used to
			// emit NO row, losing its model attribution.
			name:    "zero-cost multi-step session keeps its model, tokens unknown",
			stmts:   zeroCostMultiStepSession(),
			session: "ses_flatmulti",
			wantIn:  0, wantOut: 0, wantCost: 0,
			wantModel: "qwen3-coder", wantRel: models.ReliabilityUnknown,
		},
		{
			// Crush recorded a cost but never the counters: unknown, not
			// "zero tokens".
			name: "cost without counters reports tokens unknown",
			stmts: []string{
				`INSERT INTO sessions(id,title,prompt_tokens,completion_tokens,cost,updated_at,created_at)
				 VALUES ('ses_costonly','Cost only',0,0,0.002,1790000510,1790000500)`,
				`INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at) VALUES
				 ('mo_a','ses_costonly','assistant','[{"type":"text","data":{"text":"ok"}},{"type":"finish","data":{"reason":"end_turn","time":1790000510}}]','gpt-5.4-mini','openai',1790000505,1790000510)`,
			},
			session: "ses_costonly",
			wantIn:  0, wantOut: 0, wantCost: 0.002,
			wantModel: "gpt-5.4-mini", wantRel: models.ReliabilityUnknown,
		},
		{
			// Mirrors the live windows_failover capture: a bedrock step
			// that failed (finish reason "error") then one successful
			// openai step, whose usage IS the counters.
			name: "errored step does not count, one real step reports tokens",
			stmts: []string{
				`INSERT INTO sessions(id,title,prompt_tokens,completion_tokens,cost,updated_at,created_at)
				 VALUES ('ses_err','Untitled',12059,49,0.01786425,1783551012,1783550940)`,
				`INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at) VALUES
				 ('me_u','ses_err','user','[{"type":"text","data":{"text":"hi"}}]','','',1783550940,1783550940),
				 ('me_a1','ses_err','assistant','[{"type":"finish","data":{"reason":"error","time":1783550949,"message":"Forbidden"}}]','us.anthropic.claude-sonnet-4-6','bedrock',1783550948,1783550949),
				 ('me_u2','ses_err','user','[{"type":"text","data":{"text":"hi"}}]','','',1783551000,1783551000),
				 ('me_a2','ses_err','assistant','[{"type":"text","data":{"text":"hello"}},{"type":"finish","data":{"reason":"end_turn","time":1783551012}}]','gpt-5.4-mini','openai',1783551010,1783551012)`,
			},
			session: "ses_err",
			wantIn:  12059, wantOut: 49, wantCost: 0.01786425,
			wantModel: "gpt-5.4-mini", wantRel: models.ReliabilityApproximate,
		},
		{
			name: "canceled step does not count",
			stmts: []string{
				`INSERT INTO sessions(id,title,prompt_tokens,completion_tokens,cost,updated_at,created_at)
				 VALUES ('ses_cxl','Untitled',800,7,0.001,1790000020,1790000000)`,
				`INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at) VALUES
				 ('mc_a1','ses_cxl','assistant','[{"type":"finish","data":{"reason":"canceled","time":1790000005}}]','gpt-5.4-mini','openai',1790000001,1790000005),
				 ('mc_a2','ses_cxl','assistant','[{"type":"text","data":{"text":"ok"}},{"type":"finish","data":{"reason":"end_turn","time":1790000020}}]','gpt-5.4-mini','openai',1790000010,1790000020)`,
			},
			session: "ses_cxl",
			wantIn:  800, wantOut: 7, wantCost: 0.001,
			wantModel: "gpt-5.4-mini", wantRel: models.ReliabilityApproximate,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, dbPath := dbPathUnder(t)
			newCrushDB(t, dbPath, tc.stmts...)
			a := NewWithOptions(nil, []string{filepath.Join(root, ".crush")})
			res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			var te *models.TokenEvent
			for i := range res.TokenEvents {
				if res.TokenEvents[i].SessionID == tc.session {
					te = &res.TokenEvents[i]
				}
			}
			if te == nil {
				t.Fatalf("no token event for %s (full coverage: every non-vacant session has a row)", tc.session)
			}
			if te.InputTokens != tc.wantIn || te.OutputTokens != tc.wantOut {
				t.Errorf("tokens = %d/%d, want %d/%d", te.InputTokens, te.OutputTokens, tc.wantIn, tc.wantOut)
			}
			if te.CacheReadTokens != 0 || te.CacheCreationTokens != 0 || te.ReasoningTokens != 0 {
				t.Errorf("cache/reasoning = %d/%d/%d, want 0 (crush.db stores no split)", te.CacheReadTokens, te.CacheCreationTokens, te.ReasoningTokens)
			}
			if te.EstimatedCostUSD != tc.wantCost {
				t.Errorf("EstimatedCostUSD = %v, want %v (Crush's own cumulative cost)", te.EstimatedCostUSD, tc.wantCost)
			}
			if te.Model != tc.wantModel {
				t.Errorf("Model = %q, want %q", te.Model, tc.wantModel)
			}
			if te.Source != models.TokenSourceJSONL || te.Reliability != tc.wantRel {
				t.Errorf("source/reliability = %q/%q, want %q/%q", te.Source, te.Reliability, models.TokenSourceJSONL, tc.wantRel)
			}
			if te.SourceEventID != "tokens:"+tc.session {
				t.Errorf("SourceEventID = %q, want tokens:%s", te.SourceEventID, tc.session)
			}
		})
	}
}

// TestParseSessionFile_TokenRowsIdempotent pins (d): re-parsing the same
// store yields byte-identical token rows under the same deterministic
// SourceEventIDs (one per session, so the store's ON CONFLICT upsert and
// --crush-rescan's correction see the same key), and a session that
// grows from one step to several keeps its ONE row id: the parse emits
// the unknown-count row under the key the one-step row used, never a
// second row beside it.
func TestParseSessionFile_TokenRowsIdempotent(t *testing.T) {
	root, dbPath := dbPathUnder(t)
	stmts := append(simpleSession(), zeroCostMultiStepSession()...)
	stmts = append(stmts, toolSession()...)
	newCrushDB(t, dbPath, stmts...)
	a := NewWithOptions(nil, []string{filepath.Join(root, ".crush")})
	ctx := context.Background()

	first, err := a.ParseSessionFile(ctx, dbPath, 0)
	if err != nil {
		t.Fatalf("parse1: %v", err)
	}
	second, err := a.ParseSessionFile(ctx, dbPath, 0)
	if err != nil {
		t.Fatalf("parse2: %v", err)
	}
	if len(first.TokenEvents) != 3 {
		t.Fatalf("want 3 token rows (one per non-vacant session), got %d", len(first.TokenEvents))
	}
	if !reflect.DeepEqual(first.TokenEvents, second.TokenEvents) {
		t.Errorf("re-parse changed the token rows:\n%+v\n%+v", first.TokenEvents, second.TokenEvents)
	}
	ids := map[string]int{}
	for _, te := range first.TokenEvents {
		ids[te.SourceEventID]++
	}
	for id, n := range ids {
		if n != 1 {
			t.Errorf("SourceEventID %q emitted %d times, want 1", id, n)
		}
	}

	// ses_simple grows a second successful step: its counters become a
	// snapshot, so the row turns unknown - under the SAME key.
	appendMessage(t, dbPath, `INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at)
		VALUES ('m_a2','ses_simple','assistant','[{"type":"text","data":{"text":"more"}},{"type":"finish","data":{"reason":"end_turn","time":1790001200}}]','gpt-5.4','openai',1790001150,1790001200)`)
	appendMessage(t, dbPath, `UPDATE sessions SET prompt_tokens = 22000, completion_tokens = 9, cost = 0.1, updated_at = 1790001200 WHERE id = 'ses_simple'`)
	grown, err := a.ParseSessionFile(ctx, dbPath, first.NewOffset)
	if err != nil {
		t.Fatalf("parse3: %v", err)
	}
	var rows []models.TokenEvent
	for _, te := range grown.TokenEvents {
		if te.SessionID == "ses_simple" {
			rows = append(rows, te)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("grown session emitted %d token rows, want 1", len(rows))
	}
	if g := rows[0]; g.SourceEventID != "tokens:ses_simple" || g.InputTokens != 0 || g.OutputTokens != 0 ||
		g.EstimatedCostUSD != 0.1 || g.Reliability != models.ReliabilityUnknown || g.Model != "gpt-5.4" {
		t.Errorf("grown row = %+v, want tokens:ses_simple 0/0 $0.1 unknown gpt-5.4", g)
	}
}

// TestParseSessionFile_PrismServedModelWins covers Crush v0.96's
// messages.prism_model_id (migration 20260902000000): a Hyper turn
// routed through a Prism model records the ROUTER model in
// messages.model and the model that served the turn in prism_model_id.
// Synthetic fixture; model ids are placeholders.
func TestParseSessionFile_PrismServedModelWins(t *testing.T) {
	root, dbPath := dbPathUnder(t)
	newCrushDB(t, dbPath,
		`ALTER TABLE messages ADD COLUMN prism_model_id TEXT`,
		`ALTER TABLE messages ADD COLUMN prism_model_name TEXT`,
		`ALTER TABLE messages ADD COLUMN prism_hypercredit_savings REAL`,
		`ALTER TABLE messages ADD COLUMN prism_dollar_savings REAL`,
		`INSERT INTO sessions(id,title,prompt_tokens,completion_tokens,cost,updated_at,created_at)
		 VALUES ('ses_prism','Prism',1000,20,0.01,1790000010,1790000000)`,
		`INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at,prism_model_id,prism_model_name) VALUES
		 ('mp_u','ses_prism','user','[{"type":"text","data":{"text":"hi"}}]','','',1790000000,1790000000,NULL,NULL),
		 ('mp_a','ses_prism','assistant','[{"type":"text","data":{"text":"hello"}}]','prism-router','hyper',1790000005,1790000010,'served-model-x','Served Model X')`,
		`INSERT INTO sessions(id,title,prompt_tokens,completion_tokens,cost,updated_at,created_at)
		 VALUES ('ses_direct','Direct',500,10,0.005,1790000110,1790000100)`,
		`INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at,prism_model_id) VALUES
		 ('md_a','ses_direct','assistant','[{"type":"text","data":{"text":"ok"}}]','gpt-5.4-mini','openai',1790000105,1790000110,'')`,
	)
	a := NewWithOptions(nil, []string{filepath.Join(root, ".crush")})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	tokByID := map[string]models.TokenEvent{}
	for _, te := range res.TokenEvents {
		tokByID[te.SessionID] = te
	}
	if m := tokByID["ses_prism"].Model; m != "served-model-x" {
		t.Errorf("prism token model = %q, want served-model-x (prism_model_id wins)", m)
	}
	if m := tokByID["ses_direct"].Model; m != "gpt-5.4-mini" {
		t.Errorf("direct token model = %q, want gpt-5.4-mini (empty prism_model_id falls back)", m)
	}
	for _, ev := range res.ToolEvents {
		if ev.SessionID == "ses_prism" && ev.ActionType == models.ActionAssistantMessage && ev.Model != "served-model-x" {
			t.Errorf("prism assistant action model = %q, want served-model-x", ev.Model)
		}
	}
}
