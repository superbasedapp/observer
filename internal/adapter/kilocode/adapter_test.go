package kilocode

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestParseSessionFile_CLIRichActions pins the happy-path emission shape
// of the CLI adapter against a synthetic kilo.db with the four tool
// types confirmed live in the 2026-06-06 capture (read / write / bash /
// websearch) plus a user prompt and an assistant text reply.
func TestParseSessionFile_CLIRichActions(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupKiloDB(t, path)

	a := NewCLIWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	wantRawNames := map[string]string{
		"chat.message":                 models.ActionUserPrompt,
		"bash":                         models.ActionRunCommand,
		"read":                         models.ActionReadFile,
		"write":                        models.ActionWriteFile,
		"websearch":                    models.ActionWebSearch,
		"kilo-code-cli.assistant_text": models.ActionAssistantMessage,
		"assistant.stop":               models.ActionTaskComplete,
	}
	gotRawNames := map[string]string{}
	for _, ev := range res.ToolEvents {
		gotRawNames[ev.RawToolName] = ev.ActionType
		if ev.Tool != models.ToolKiloCodeCLI {
			t.Errorf("ev.Tool = %q, want %q (every CLI event tagged kilo-code-cli)", ev.Tool, models.ToolKiloCodeCLI)
		}
		// The terminus row stamps the source finish reason into the
		// canonical Metadata.StopReason column.
		if ev.RawToolName == "assistant.stop" {
			if ev.Metadata == nil || ev.Metadata.StopReason != "stop" {
				t.Errorf("assistant.stop StopReason = %+v, want stop", ev.Metadata)
			}
		}
	}
	for raw, wantAction := range wantRawNames {
		got, ok := gotRawNames[raw]
		if !ok {
			t.Errorf("missing emitted event with RawToolName=%q; got rows=%+v", raw, gotRawNames)
			continue
		}
		if got != wantAction {
			t.Errorf("RawToolName=%q action_type = %q, want %q", raw, got, wantAction)
		}
	}
}

// TestParseSessionFile_CLIEmitsTokenEvents pins the per-assistant-
// message token bundle extraction. Numbers chosen deliberately so each
// field's drop-through can be asserted independently — mirrors the
// opencode adapter's token-event regression test pattern.
func TestParseSessionFile_CLIEmitsTokenEvents(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupKiloDBWithTokens(t, path)

	a := NewCLIWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.TokenEvents); got != 1 {
		t.Fatalf("expected 1 token event, got %d", got)
	}
	te := res.TokenEvents[0]
	if te.Tool != models.ToolKiloCodeCLI {
		t.Errorf("Tool = %q, want %q", te.Tool, models.ToolKiloCodeCLI)
	}
	if te.Model != "kilo-auto/free" {
		t.Errorf("Model = %q, want kilo-auto/free", te.Model)
	}
	if te.InputTokens != 368 {
		t.Errorf("InputTokens = %d, want 368", te.InputTokens)
	}
	if te.OutputTokens != 49 {
		t.Errorf("OutputTokens = %d, want 49", te.OutputTokens)
	}
	if te.CacheReadTokens != 45696 {
		t.Errorf("CacheReadTokens = %d, want 45696", te.CacheReadTokens)
	}
	if te.CacheCreationTokens != 0 {
		t.Errorf("CacheCreationTokens = %d, want 0", te.CacheCreationTokens)
	}
	if te.ReasoningTokens != 0 {
		t.Errorf("ReasoningTokens = %d, want 0", te.ReasoningTokens)
	}
	if te.Reliability != models.ReliabilityApproximate {
		t.Errorf("Reliability = %q, want %q", te.Reliability, models.ReliabilityApproximate)
	}
	if te.Source != models.TokenSourceJSONL {
		t.Errorf("Source = %q, want %q", te.Source, models.TokenSourceJSONL)
	}
	if te.MessageID != "msg_asst" {
		t.Errorf("MessageID = %q, want msg_asst", te.MessageID)
	}
}

// TestParseSessionFile_CLISkipsZeroTokenAssistantRows confirms that
// in-progress assistant rows (all-zero token bundle) don't emit
// TokenEvents.
func TestParseSessionFile_CLISkipsZeroTokenAssistantRows(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupKiloDB(t, path) // assistant rows in setupKiloDB carry no tokens

	a := NewCLIWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.TokenEvents); got != 0 {
		t.Errorf("expected 0 token events from token-less rows, got %d: %+v", got, res.TokenEvents)
	}
}

// TestParseSessionFile_CLIStepFinishEmitsToolEventNoTokenEvent pins the
// double-count guard. Step-finish parts carry per-step token slices;
// summed across all step-finishes within a message, they equal the
// message-level token bundle that loadTokenEvents already extracts.
// Emitting TokenEvents from step-finish would double-count — this test
// asserts the ToolEvent lands but no TokenEvent does.
func TestParseSessionFile_CLIStepFinishEmitsToolEventNoTokenEvent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupKiloDBWithStepFinish(t, path)
	a := NewCLIWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var steps []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "kilo-code-cli.step_finish" {
			steps = append(steps, ev)
		}
	}
	if len(steps) != 1 {
		t.Fatalf("kilo-code-cli.step_finish rows: got %d want 1 (all events: %+v)", len(steps), res.ToolEvents)
	}
	if steps[0].Target != "tool-calls" {
		t.Errorf("Target = %q, want tool-calls (finish reason)", steps[0].Target)
	}
	if !strings.Contains(steps[0].RawToolInput, `"tokens"`) {
		t.Errorf("RawToolInput must contain the step-finish JSON tokens block; got %q", steps[0].RawToolInput)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("step-finish must not emit TokenEvents; got %+v", res.TokenEvents)
	}
}

// TestParseSessionFile_CLIReasoningThreadsAndMintsNoRow is the B3
// successor of TestParseSessionFile_CLIReasoningPartEmitsRow
// (2026-07-31). The chain-of-thought used to land as its own
// `kilo-code-cli.reasoning` task_complete row; it now mints NO row and
// is threaded onto the successor part's PrecedingReasoning, beating the
// part's `title` (Kilo's one-line UI label, never reasoning). Kept
// symmetric with the OpenCode adapter's test of the same shape.
func TestParseSessionFile_CLIReasoningThreadsAndMintsNoRow(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupKiloDBWithReasoning(t, path)
	a := NewCLIWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	byRaw := map[string]models.ToolEvent{}
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "kilo-code-cli.reasoning" {
			t.Fatalf("kilo-code-cli.reasoning row minted: %+v", ev)
		}
		byRaw[ev.RawToolName] = ev
	}
	tool, ok := byRaw["bash"]
	if !ok {
		t.Fatalf("no tool row; events=%+v", res.ToolEvents)
	}
	if tool.PrecedingReasoning != "The user wants me to delete hello.py." {
		t.Errorf("tool PrecedingReasoning = %q, want the reasoning body (beating the title %q)",
			tool.PrecedingReasoning, "Run rm")
	}
	asst, ok := byRaw["kilo-code-cli.assistant_text"]
	if !ok {
		t.Fatalf("no assistant_text row; events=%+v", res.ToolEvents)
	}
	if asst.PrecedingReasoning != "Second thought, the newer one." {
		t.Errorf("assistant_text PrecedingReasoning = %q, want the LAST reasoning before it", asst.PrecedingReasoning)
	}
}

// TestParseSessionFile_CLIWatermarkSkipsOldRows pins the incremental-
// parse contract — call ParseSessionFile with a fromOffset past every
// row's time_updated and zero new events come back.
func TestParseSessionFile_CLIWatermarkSkipsOldRows(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupKiloDB(t, path)
	a := NewCLIWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 9999999)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 0 {
		t.Fatalf("expected no events past watermark, got %d", len(res.ToolEvents))
	}
}

// TestParseSessionFile_CLIIdempotentReparse pins that calling
// ParseSessionFile twice with fromOffset=0 produces identical output —
// the (source_file, source_event_id) dedup key downstream relies on it.
func TestParseSessionFile_CLIIdempotentReparse(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupKiloDB(t, path)
	a := NewCLIWithOptions(nil, []string{root})
	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(first.ToolEvents) != len(second.ToolEvents) {
		t.Fatalf("event count differs across re-parse: %d vs %d", len(first.ToolEvents), len(second.ToolEvents))
	}
	for i := range first.ToolEvents {
		if first.ToolEvents[i].SourceEventID != second.ToolEvents[i].SourceEventID {
			t.Errorf("SourceEventID drift at %d: %q vs %q",
				i, first.ToolEvents[i].SourceEventID, second.ToolEvents[i].SourceEventID)
		}
	}
}

// TestParseSessionFile_CLIScrubsSecretsInToolInput pins that the
// scrubber runs over every emitted RawToolInput / ToolOutput /
// ErrorMessage / PrecedingReasoning string.
func TestParseSessionFile_CLIScrubsSecretsInToolInput(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupKiloDBWithSecrets(t, path)
	a := NewCLIWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var bash *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].RawToolName == "bash" {
			bash = &res.ToolEvents[i]
			break
		}
	}
	if bash == nil {
		t.Fatalf("no bash event emitted")
	}
	if strings.Contains(bash.RawToolInput, "sk-AAAA") {
		t.Errorf("RawToolInput leaks API key: %q", bash.RawToolInput)
	}
	if strings.Contains(bash.ToolOutput, "sk-AAAA") {
		t.Errorf("ToolOutput leaks API key: %q", bash.ToolOutput)
	}
}

// TestParseSessionFile_CLIProjectTableJoinForCwd pins the Kilo-specific
// JOIN on the `project` table. When a row's message.path.cwd is empty
// (which happens on the user message in every capture) and
// session.directory is also empty (rare but observed when sessions are
// created via /resume), the parser must fall through to
// project.worktree to recover a non-empty project root.
func TestParseSessionFile_CLIProjectTableJoinForCwd(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupKiloDBWithProjectFallback(t, path)
	a := NewCLIWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt {
			// The user prompt has neither message.path.cwd nor a
			// session.directory; the only place worktree info lives
			// is in the project table.
			if ev.ProjectRoot == "[kilo-code-cli]" {
				t.Errorf("user prompt ProjectRoot fell through to placeholder; want project.worktree fallback. ev=%+v", ev)
			}
			// We can't assert the exact value because
			// resolveProjectRoot runs git.Resolve on whatever we feed
			// it, which may chase off-host parents — but it must NOT
			// be the synthetic placeholder.
			return
		}
	}
	t.Fatalf("no user_prompt event emitted; events=%+v", res.ToolEvents)
}

// TestResolveProjectRoot_TranslatesForeignCwd pins the cross-mount
// foreign-path translation — Windows-style cwds read by a Linux
// observer translate via crossmount.TranslateForeignPath BEFORE
// git.Resolve, so the result lands on /mnt/<drive>/... instead of
// CWD-prefixing observer's own .git.
func TestResolveProjectRoot_TranslatesForeignCwd(t *testing.T) {
	a := NewCLIWithOptions(nil, []string{t.TempDir()})
	cache := map[string]kiloResolvedRoot{}
	got, _ := a.resolveProjectRoot(`C:\programsx\kilo-test`, cache)
	if !strings.HasPrefix(got, "/mnt/") && !strings.Contains(got, "kilo-test") {
		// On hosts where the foreign translation doesn't kick in (no
		// crossmount homes detected) the input is returned verbatim,
		// which still satisfies the no-observer-prefix invariant.
		if strings.Contains(got, ".git") {
			t.Errorf("resolveProjectRoot leaked observer's own .git: %q", got)
		}
	}
}

// TestResolveProjectRoot_EmptyReturnsPlaceholder pins the [kilo-code-cli]
// placeholder convention. Mirrors the opencode adapter's [opencode]
// pattern — empty cwd produces a synthetic project key so downstream
// rollups coalesce until a real cwd is observed.
func TestResolveProjectRoot_EmptyReturnsPlaceholder(t *testing.T) {
	a := NewCLIWithOptions(nil, []string{t.TempDir()})
	cache := map[string]kiloResolvedRoot{}
	if got, _ := a.resolveProjectRoot("", cache); got != "[kilo-code-cli]" {
		t.Errorf("empty cwd -> %q, want [kilo-code-cli]", got)
	}
}

// TestIsForeignMountPath_OnlyForeignHomes pins the foreign-mount
// detection — only paths under a crossmount-detected non-native home
// match. Mirrors the opencode adapter's identical test.
func TestIsForeignMountPath_OnlyForeignHomes(t *testing.T) {
	orig := allHomesFunc
	t.Cleanup(func() { allHomesFunc = orig })
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: "/home/me", OS: crossmount.OSLinux, Origin: "native"},
			{Path: "/mnt/c/Users/auzy_", OS: crossmount.OSWindows, Origin: "wsl-mnt:auzy_"},
		}
	}
	cases := []struct {
		path string
		want bool
	}{
		{"/home/me/.local/share/kilo/kilo.db", false},
		{"/mnt/c/Users/auzy_/.local/share/kilo/kilo.db", true},
		{"/tmp/something", false},
	}
	for _, tc := range cases {
		if got := isForeignMountPath(tc.path); got != tc.want {
			t.Errorf("isForeignMountPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestStageMirrorIfForeign_NativePassThrough pins the fast path — a
// native source returns unchanged with no copy.
func TestStageMirrorIfForeign_NativePassThrough(t *testing.T) {
	orig := allHomesFunc
	t.Cleanup(func() { allHomesFunc = orig })
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: "/home/me", OS: crossmount.OSLinux, Origin: "native"},
		}
	}
	got, err := stageMirrorIfForeign("/home/me/.local/share/kilo/kilo.db")
	if err != nil {
		t.Fatalf("stageMirrorIfForeign: %v", err)
	}
	if got != "/home/me/.local/share/kilo/kilo.db" {
		t.Errorf("native path got remapped to %q", got)
	}
}

// TestMapTool_KiloConfirmedTools pins the four live-confirmed tool
// names map onto the correct normalized actions. Mirrors the opencode
// adapter's equivalent test (broader OpenCode taxonomy is covered
// inline by setupKiloDB; this test exists so a future tweak to mapTool
// can't silently regress the live-confirmed surface).
func TestMapTool_KiloConfirmedTools(t *testing.T) {
	cases := []struct {
		tool, want string
	}{
		{"read", models.ActionReadFile},
		{"write", models.ActionWriteFile},
		{"bash", models.ActionRunCommand},
		{"websearch", models.ActionWebSearch},
		{"edit", models.ActionEditFile},
		{"multiedit", models.ActionEditFile},
		{"apply_patch", models.ActionEditFile},
		{"grep", models.ActionSearchText},
		{"glob", models.ActionSearchFiles},
		{"webfetch", models.ActionWebFetch},
		{"task", models.ActionSpawnSubagent},
		{"todowrite", models.ActionTodoUpdate},
		{"unknown_tool", models.ActionUnknown},
		{"custom_mcp_server_call", models.ActionMCPCall},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			part := toolPartData{Tool: tc.tool}
			got, _, _, _ := mapTool(part)
			if got != tc.want {
				t.Errorf("mapTool(%q) = %q, want %q", tc.tool, got, tc.want)
			}
		})
	}
}

// TestParseSessionFile_CLIMalformedJSONDoesNotCrash pins the malformed-
// row tolerance — a bad `message.data` JSON gets skipped (the json.
// Unmarshal returns ok=false in the per-row helpers) without aborting
// the whole parse pass.
func TestParseSessionFile_CLIMalformedJSONDoesNotCrash(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupKiloDBWithMalformed(t, path)
	a := NewCLIWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// We seeded ONE valid user prompt and ONE bad assistant row; the
	// adapter should emit the prompt and silently skip the bad row.
	found := false
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt {
			found = true
		}
	}
	if !found {
		t.Errorf("malformed assistant row killed the parse; want at least the user_prompt event. got=%+v", res.ToolEvents)
	}
}

// TestIsSessionFile_MatchesKiloDBAndWAL pins the basename predicate.
func TestIsSessionFile_MatchesKiloDBAndWAL(t *testing.T) {
	root := t.TempDir()
	a := NewCLIWithOptions(nil, []string{root})
	cases := []struct {
		name string
		ok   bool
	}{
		{filepath.Join(root, "kilo.db"), true},
		{filepath.Join(root, "kilo.db-wal"), true},
		{filepath.Join(root, "kilo.db-shm"), false}, // we don't fsnotify on -shm
		{filepath.Join(root, "opencode.db"), false},
		{filepath.Join("/tmp/foreign", "kilo.db"), false},
	}
	for _, tc := range cases {
		if got := a.IsSessionFile(tc.name); got != tc.ok {
			t.Errorf("IsSessionFile(%q) = %v, want %v", tc.name, got, tc.ok)
		}
	}
}

// ---- setup helpers ----

func setupKiloDB(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := []string{
		`CREATE TABLE project (id TEXT PRIMARY KEY, worktree TEXT NOT NULL, time_updated INTEGER NOT NULL, sandboxes TEXT NOT NULL DEFAULT '[]')`,
		`CREATE TABLE session (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			directory TEXT NOT NULL,
			time_updated INTEGER NOT NULL
		)`,
		`CREATE TABLE message (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			time_created INTEGER NOT NULL,
			time_updated INTEGER NOT NULL,
			data TEXT NOT NULL
		)`,
		`CREATE TABLE part (
			id TEXT PRIMARY KEY,
			message_id TEXT NOT NULL,
			session_id TEXT NOT NULL,
			time_created INTEGER NOT NULL,
			time_updated INTEGER NOT NULL,
			data TEXT NOT NULL
		)`,
		`INSERT INTO project(id, worktree, time_updated) VALUES ('proj_a', '/tmp/kilo-test', 1000)`,
		`INSERT INTO session(id, project_id, directory, time_updated) VALUES ('ses_1', 'proj_a', '/tmp/kilo-test', 9000)`,
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_user',  'ses_1', 1000, 1001, '{"role":"user","agent":"code","model":{"providerID":"kilo","modelID":"kilo-auto/free"},"time":{"created":1000}}'),
			('msg_asst',  'ses_1', 2000, 9000, '{"parentID":"msg_user","role":"assistant","mode":"code","agent":"code","path":{"cwd":"/tmp/kilo-test","root":"/tmp/kilo-test"},"modelID":"kilo-auto/free","providerID":"kilo","time":{"created":2000,"completed":9000},"finish":"stop"}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_user_text',  'msg_user', 'ses_1', 1000, 1001, '{"type":"text","text":"Help me out"}'),
			('prt_asst_text',  'msg_asst', 'ses_1', 2100, 2200, '{"type":"text","text":"On it."}'),
			('prt_bash',       'msg_asst', 'ses_1', 2300, 2400, '{"type":"tool","tool":"bash","callID":"c_bash","state":{"status":"completed","input":{"command":"ls","workdir":"/tmp/kilo-test"},"output":"a\nb\n","metadata":{"output":"a\nb\n","exit":0,"description":"ls","truncated":false},"title":"ls","time":{"start":2300,"end":2400}}}'),
			('prt_read',       'msg_asst', 'ses_1', 2500, 2600, '{"type":"tool","tool":"read","callID":"c_read","state":{"status":"completed","input":{"filePath":"/tmp/kilo-test/README"},"output":"<path>/tmp/kilo-test/README</path>\n<type>file</type>\n<content>1: hi\n</content>","time":{"start":2500,"end":2600}}}'),
			('prt_write',      'msg_asst', 'ses_1', 2700, 2800, '{"type":"tool","tool":"write","callID":"c_write","state":{"status":"completed","input":{"content":"hi","filePath":"/tmp/kilo-test/out.txt"},"output":"Wrote file successfully.","metadata":{"diagnostics":{},"filepath":"/tmp/kilo-test/out.txt","exists":false}}}'),
			('prt_websearch',  'msg_asst', 'ses_1', 2900, 3000, '{"type":"tool","tool":"websearch","callID":"c_ws","state":{"status":"completed","input":{"query":"latest python","numResults":3},"output":"{\"search_id\":\"s_x\",\"results\":[]}"}}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

func setupKiloDBWithTokens(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := []string{
		`CREATE TABLE project (id TEXT PRIMARY KEY, worktree TEXT NOT NULL, time_updated INTEGER NOT NULL, sandboxes TEXT NOT NULL DEFAULT '[]')`,
		`CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO project(id, worktree, time_updated) VALUES ('proj_a', '/tmp/kilo-test', 1000)`,
		`INSERT INTO session(id, project_id, directory, time_updated) VALUES ('ses_1', 'proj_a', '/tmp/kilo-test', 3000)`,
		// Numbers match the 2026-06-06 live capture's first assistant
		// message exactly: input=368, output=49, cache.read=45696
		// (others zero on this Gateway-free-tier capture).
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_asst', 'ses_1', 2900, 3000,
			 '{"role":"assistant","agent":"code","modelID":"kilo-auto/free","providerID":"kilo","path":{"cwd":"/tmp/kilo-test","root":"/tmp/kilo-test"},"time":{"created":2900,"completed":3000},"finish":"stop","tokens":{"total":46113,"input":368,"output":49,"reasoning":0,"cache":{"read":45696,"write":0}},"cost":0}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

func setupKiloDBWithStepFinish(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := []string{
		`CREATE TABLE project (id TEXT PRIMARY KEY, worktree TEXT NOT NULL, time_updated INTEGER NOT NULL, sandboxes TEXT NOT NULL DEFAULT '[]')`,
		`CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO project(id, worktree, time_updated) VALUES ('proj_a', '/tmp/kilo-test', 1000)`,
		`INSERT INTO session(id, project_id, directory, time_updated) VALUES ('ses_1', 'proj_a', '/tmp/kilo-test', 3000)`,
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_asst', 'ses_1', 2000, 3000,
			 '{"role":"assistant","agent":"code","modelID":"kilo-auto/free","providerID":"kilo","path":{"cwd":"/tmp/kilo-test"},"time":{"created":2000,"completed":3000},"finish":"tool-calls"}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_step', 'msg_asst', 'ses_1', 2500, 3000, '{"type":"step-finish","reason":"tool-calls","tokens":{"input":15321,"output":266,"reasoning":0,"total":15587,"cache":{"read":2304,"write":0}},"cost":0}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

func setupKiloDBWithReasoning(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := []string{
		`CREATE TABLE project (id TEXT PRIMARY KEY, worktree TEXT NOT NULL, time_updated INTEGER NOT NULL, sandboxes TEXT NOT NULL DEFAULT '[]')`,
		`CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO project(id, worktree, time_updated) VALUES ('proj_a', '/tmp/kilo-test', 1000)`,
		`INSERT INTO session(id, project_id, directory, time_updated) VALUES ('ses_1', 'proj_a', '/tmp/kilo-test', 5000)`,
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_asst', 'ses_1', 2000, 5000, '{"role":"assistant","agent":"code","modelID":"kilo-auto/free","providerID":"kilo","path":{"cwd":"/tmp/kilo-test"},"time":{"created":2000,"completed":5000},"finish":"stop"}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_reasoning', 'msg_asst', 'ses_1', 3000, 4200, '{"type":"reasoning","text":"The user wants me to delete hello.py.","time":{"start":3000,"end":4200}}'),
			('prt_tool', 'msg_asst', 'ses_1', 4300, 4400, '{"type":"tool","tool":"bash","callID":"c1","state":{"status":"completed","input":{"command":"rm hello.py"},"output":"ok","title":"Run rm","time":{"start":4300,"end":4400}}}'),
			('prt_reasoning_2', 'msg_asst', 'ses_1', 4500, 4600, '{"type":"reasoning","text":"First thought, superseded.","time":{"start":4500,"end":4600}}'),
			('prt_reasoning_3', 'msg_asst', 'ses_1', 4700, 4800, '{"type":"reasoning","text":"Second thought, the newer one.","time":{"start":4700,"end":4800}}'),
			('prt_text', 'msg_asst', 'ses_1', 4900, 4950, '{"type":"text","text":"Deleted."}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

func setupKiloDBWithSecrets(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := []string{
		`CREATE TABLE project (id TEXT PRIMARY KEY, worktree TEXT NOT NULL, time_updated INTEGER NOT NULL, sandboxes TEXT NOT NULL DEFAULT '[]')`,
		`CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO project(id, worktree, time_updated) VALUES ('proj_a', '/tmp/kilo-test', 1000)`,
		`INSERT INTO session(id, project_id, directory, time_updated) VALUES ('ses_1', 'proj_a', '/tmp/kilo-test', 3000)`,
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_asst', 'ses_1', 2000, 3000,
			 '{"role":"assistant","agent":"code","modelID":"kilo-auto/free","providerID":"kilo","path":{"cwd":"/tmp/kilo-test"},"time":{"created":2000,"completed":3000},"finish":"tool-calls"}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_bash', 'msg_asst', 'ses_1', 2200, 2500,
			 '{"type":"tool","tool":"bash","callID":"c_bash","state":{"status":"completed","input":{"command":"echo sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","workdir":"/tmp"},"output":"sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n","metadata":{"output":"sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n","exit":0,"description":"echo a secret"}}}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

func setupKiloDBWithProjectFallback(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := []string{
		`CREATE TABLE project (id TEXT PRIMARY KEY, worktree TEXT NOT NULL, time_updated INTEGER NOT NULL, sandboxes TEXT NOT NULL DEFAULT '[]')`,
		`CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO project(id, worktree, time_updated) VALUES ('proj_a', '/tmp/kilo-fallback-test', 1000)`,
		// session.directory empty, message.path.cwd empty → must fall
		// through to project.worktree.
		`INSERT INTO session(id, project_id, directory, time_updated) VALUES ('ses_1', 'proj_a', '', 3000)`,
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_user', 'ses_1', 1000, 1001, '{"role":"user","agent":"code","time":{"created":1000}}')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_user_text', 'msg_user', 'ses_1', 1000, 1001, '{"type":"text","text":"Hello"}')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

func setupKiloDBWithMalformed(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := []string{
		`CREATE TABLE project (id TEXT PRIMARY KEY, worktree TEXT NOT NULL, time_updated INTEGER NOT NULL, sandboxes TEXT NOT NULL DEFAULT '[]')`,
		`CREATE TABLE session (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, directory TEXT NOT NULL, time_updated INTEGER NOT NULL)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER NOT NULL, time_updated INTEGER NOT NULL, data TEXT NOT NULL)`,
		`INSERT INTO project(id, worktree, time_updated) VALUES ('proj_a', '/tmp/kilo-test', 1000)`,
		`INSERT INTO session(id, project_id, directory, time_updated) VALUES ('ses_1', 'proj_a', '/tmp/kilo-test', 3000)`,
		// One valid user message. One malformed assistant message
		// (the `data` blob is unparseable JSON). The user_prompt path
		// must still emit; the assistant row must skip silently.
		// Note: SQL-level integrity (FK on session_id, NOT NULL on
		// data) is satisfied; the JSON itself is bad.
		`INSERT INTO message(id, session_id, time_created, time_updated, data) VALUES
			('msg_user',       'ses_1', 1000, 1001, '{"role":"user","agent":"code","time":{"created":1000}}'),
			('msg_bad',        'ses_1', 2000, 2500, 'this is not JSON {{{')`,
		`INSERT INTO part(id, message_id, session_id, time_created, time_updated, data) VALUES
			('prt_user_text',  'msg_user', 'ses_1', 1000, 1001, '{"type":"text","text":"Hi"}'),
			('prt_bad_part',   'msg_bad',  'ses_1', 2100, 2200, 'not JSON')`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}
