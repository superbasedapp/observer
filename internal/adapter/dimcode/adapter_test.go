package dimcode

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// fixtureDir is the repo-level fixture directory (testdata/dimcode).
var fixtureDir = filepath.Join("..", "..", "..", "testdata", "dimcode")

// buildStore creates <home>/.dimcode/v2/dimcode.sqlite from schema.sql plus
// the given fixture files and returns (dbPath, rootDir).
func buildStore(t *testing.T, fixtures ...string) (string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), ".dimcode", "v2")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(root, storeFile)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, name := range append([]string{"schema.sql"}, fixtures...) {
		b, err := os.ReadFile(filepath.Join(fixtureDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(b)); err != nil {
			t.Fatalf("exec %s: %v", name, err)
		}
	}
	return dbPath, root
}

func parseAll(t *testing.T, fixtures ...string) (adapter.ParseResult, string) {
	t.Helper()
	dbPath, root := buildStore(t, fixtures...)
	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res, dbPath
}

func eventsOfType(res adapter.ParseResult, action string) []models.ToolEvent {
	var out []models.ToolEvent
	for _, e := range res.ToolEvents {
		if e.ActionType == action {
			out = append(out, e)
		}
	}
	return out
}

func eventByRawName(t *testing.T, res adapter.ParseResult, raw string) models.ToolEvent {
	t.Helper()
	for _, e := range res.ToolEvents {
		if e.RawToolName == raw {
			return e
		}
	}
	t.Fatalf("no event with RawToolName %q", raw)
	return models.ToolEvent{}
}

func tokenByID(t *testing.T, res adapter.ParseResult, id string) models.TokenEvent {
	t.Helper()
	for _, e := range res.TokenEvents {
		if e.SourceEventID == id {
			return e
		}
	}
	t.Fatalf("no token event %q", id)
	return models.TokenEvent{}
}

func TestIdentityAndSessionFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".dimcode", "v2")
	a := NewWithOptions(nil, []string{root})
	if a.Name() != models.ToolDimCode {
		t.Fatalf("Name = %q", a.Name())
	}
	if got := a.WatchPaths(); len(got) != 1 || got[0] != root {
		t.Fatalf("WatchPaths = %v", got)
	}
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"main store", filepath.Join(root, "dimcode.sqlite"), true},
		{"wal sibling", filepath.Join(root, "dimcode.sqlite-wal"), true},
		{"shm sibling", filepath.Join(root, "dimcode.sqlite-shm"), true},
		{"scheduler store is not a session file", filepath.Join(root, "schedule-tui.sqlite"), false},
		{"config", filepath.Join(root, "config.json"), false},
		{"copy outside the watch root", filepath.Join(t.TempDir(), "dimcode.sqlite"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Errorf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
	if got := resolveDBPath(filepath.Join(root, "dimcode.sqlite-wal")); got != filepath.Join(root, "dimcode.sqlite") {
		t.Errorf("resolveDBPath(-wal) = %q", got)
	}
	sem := a.CursorSemanticsFor(filepath.Join(root, "dimcode.sqlite"))
	if sem.Kind != adapter.CursorWatermark {
		t.Errorf("cursor kind = %v, want watermark", sem.Kind)
	}
	if k := a.CursorSemanticsFor(filepath.Join(root, "other.txt")).Kind; k != adapter.CursorByteOffset {
		t.Errorf("non-session file cursor kind = %v, want zero value", k)
	}
}

func TestDefaultRootsAcrossHomes(t *testing.T) {
	orig := allHomesFunc
	t.Cleanup(func() { allHomesFunc = orig })
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: filepath.Join("home", "u"), OS: crossmount.OSLinux, Origin: "native"},
			{Path: filepath.Join("mnt", "c", "Users", "u"), OS: crossmount.OSWindows, Origin: "wsl-mnt:u"},
			{Path: "", OS: crossmount.OSLinux, Origin: "bogus"},
		}
	}
	t.Setenv(homeEnv, "")
	got := defaultRoots()
	want := []string{
		filepath.Join("home", "u", ".dimcode", "v2"),
		filepath.Join("mnt", "c", "Users", "u", ".dimcode", "v2"),
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("defaultRoots = %v, want %v", got, want)
	}
}

func TestRootFromEnv(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"   ", ""},
		{filepath.Join("data", "dim"), filepath.Join("data", "dim", "v2")},
		{filepath.Join("data", "dim", "v2"), filepath.Join("data", "dim", "v2")},
	}
	for _, tc := range cases {
		if got := rootFromEnv(tc.in); got != tc.want {
			t.Errorf("rootFromEnv(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNetInput(t *testing.T) {
	cases := []struct {
		name                   string
		prompt, read, write, w int64
	}{
		{"live wsl run", 147551, 41504, 0, 106047},
		{"live windows run", 55911, 35840, 0, 20071},
		{"cache read and write are both subsets", 20000, 12000, 3000, 5000},
		{"no cache", 138, 0, 0, 138},
		{"clamped at zero", 10, 50, 0, 0},
	}
	for _, tc := range cases {
		if got := netInput(tc.prompt, tc.read, tc.write); got != tc.w {
			t.Errorf("%s: netInput = %d, want %d", tc.name, got, tc.w)
		}
	}
}

// TestLiveWSLCapture pins the parse of the real WSL session
// (sess_1792562933471_0gxgbenesl7a, poolside/laguna-s-2.1:free via
// openrouter).
func TestLiveWSLCapture(t *testing.T) {
	res, dbPath := parseAll(t, "fixture-wsl.sql")
	const sid = "sess_1792562933471_0gxgbenesl7a"

	if res.NewOffset <= 0 {
		t.Fatalf("NewOffset = %d", res.NewOffset)
	}
	counts := map[string]int{}
	for _, e := range res.ToolEvents {
		if e.SessionID != sid {
			t.Errorf("event %s has session %q, want the vendor id verbatim", e.SourceEventID, e.SessionID)
		}
		if e.Tool != models.ToolDimCode {
			t.Errorf("event %s tool %q", e.SourceEventID, e.Tool)
		}
		if e.SourceFile != dbPath {
			t.Errorf("event %s source file %q", e.SourceEventID, e.SourceFile)
		}
		counts[e.ActionType]++
	}
	want := map[string]int{
		models.ActionUserPrompt:       1,
		models.ActionAssistantMessage: 2, // "I'll work through this" + the final summary
		models.ActionTodoUpdate:       7,
		models.ActionWriteFile:        1,
		models.ActionEditFile:         1,
		models.ActionRunCommand:       4,
	}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("%s count = %d, want %d (all: %v)", k, counts[k], v, counts)
		}
	}

	w := eventsOfType(res, models.ActionWriteFile)[0]
	if w.Target != "/home/user/project/hello.py" || !w.Success || w.ContentBytes != int64(len(`print("Hello, World!")`)) {
		t.Errorf("write event = %+v", w)
	}
	if w.Model != "poolside/laguna-s-2.1:free" {
		t.Errorf("write model = %q", w.Model)
	}
	if w.OutcomePending {
		t.Error("a paired call must not be pending")
	}
	e := eventsOfType(res, models.ActionEditFile)[0]
	if e.ContentBytes != int64(len(`print("Hello, autohand!")`)) {
		t.Errorf("edit ContentBytes = %d", e.ContentBytes)
	}
	var execDur int
	for _, x := range eventsOfType(res, models.ActionRunCommand) {
		if x.DurationMs > 0 {
			execDur++
		}
		if !x.Success {
			t.Errorf("exec %q should be a success", x.Target)
		}
	}
	if execDur != 4 {
		t.Errorf("execs with wallTimeMs duration = %d, want 4", execDur)
	}

	// Reasoning was threaded onto the first tool call of the first message.
	todo := eventsOfType(res, models.ActionTodoUpdate)[0]
	if !strings.Contains(todo.PrecedingReasoning, "hello world python file") {
		t.Errorf("PrecedingReasoning = %q", todo.PrecedingReasoning)
	}

	// Tokens: the run (gross 147551 / cacheRead 41504 -> net 106047) plus the
	// standalone session-title ledger call.
	if len(res.TokenEvents) != 2 {
		t.Fatalf("token events = %d, want 2: %+v", len(res.TokenEvents), res.TokenEvents)
	}
	run := tokenByID(t, res, "run:run_1792562933965_85j6zf")
	if run.InputTokens != 106047 || run.OutputTokens != 1906 || run.CacheReadTokens != 41504 || run.CacheCreationTokens != 0 {
		t.Errorf("run tokens = %+v", run)
	}
	if run.Model != "poolside/laguna-s-2.1:free" || run.TurnID != "run_1792562933965_85j6zf" {
		t.Errorf("run model/turn = %q / %q", run.Model, run.TurnID)
	}
	if run.EstimatedCostUSD != 0 {
		t.Errorf("missing_price quality must not carry a cost, got %v", run.EstimatedCostUSD)
	}
	if run.Source != models.TokenSourceJSONL || run.Reliability != models.ReliabilityApproximate {
		t.Errorf("run source/reliability = %q/%q", run.Source, run.Reliability)
	}
	if !strings.HasPrefix(run.MessageID, "msg_") {
		t.Errorf("run MessageID = %q, want the final assistant message", run.MessageID)
	}
	if run.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z") != "2026-10-21T06:10:47.461Z" {
		t.Errorf("run timestamp = %v", run.Timestamp)
	}
	title := tokenByID(t, res, "ledger:plugin_ledger_fd4f964c-451e-4fcd-a7bb-f7859b2847db")
	if title.InputTokens != 138 || title.OutputTokens != 100 || title.CacheReadTokens != 0 {
		t.Errorf("title-call tokens = %+v", title)
	}
	if len(res.SessionLineages) != 0 || len(res.OutcomeUpdates) != 0 {
		t.Errorf("no lineage/outcome updates expected: %v %v", res.SessionLineages, res.OutcomeUpdates)
	}
}

// TestLiveWindowsCapture pins the parse of the real Windows session
// (sess_1792562920436_15k4s9hq3ynj, C:\ cwd, dots-studio/…:free).
func TestLiveWindowsCapture(t *testing.T) {
	res, _ := parseAll(t, "fixture-win.sql")
	const sid = "sess_1792562920436_15k4s9hq3ynj"
	counts := map[string]int{}
	for _, e := range res.ToolEvents {
		if e.SessionID != sid {
			t.Errorf("event %s has session %q", e.SourceEventID, e.SessionID)
		}
		if !strings.HasSuffix(e.ProjectRoot, "project") {
			t.Errorf("event %s project root %q", e.SourceEventID, e.ProjectRoot)
		}
		counts[e.ActionType]++
	}
	if counts[models.ActionUserPrompt] != 1 || counts[models.ActionWriteFile] != 2 || counts[models.ActionRunCommand] != 3 {
		t.Errorf("counts = %v", counts)
	}
	run := tokenByID(t, res, "run:run_1792562921221_8v5w3a")
	if run.InputTokens != 20071 || run.OutputTokens != 577 || run.CacheReadTokens != 35840 {
		t.Errorf("windows run tokens = %+v", run)
	}
	if run.Model != "dots-studio/dots-3-note-preview:free" {
		t.Errorf("model = %q", run.Model)
	}
	title := tokenByID(t, res, "ledger:plugin_ledger_28e4802a-3ff6-42e6-accd-4d3be035763c")
	if title.InputTokens != 129 || title.OutputTokens != 100 {
		t.Errorf("windows title tokens = %+v", title)
	}
}

func TestSyntheticTools(t *testing.T) {
	res, _ := parseAll(t, "fixture-synthetic.sql")

	read := eventByRawName(t, res, "read")
	if read.ActionType != models.ActionReadFile || read.Target != "/home/user/synthetic/a.go" || !read.Success {
		t.Errorf("read = %+v", read)
	}
	if !strings.Contains(read.PrecedingReasoning, "Plan: read a.go") {
		t.Errorf("reasoning not threaded onto the first tool: %q", read.PrecedingReasoning)
	}
	grep := eventByRawName(t, res, "grep")
	if grep.ActionType != models.ActionSearchText || grep.Success || grep.ErrorMessage != "grep: bad pattern" {
		t.Errorf("failed grep = %+v", grep)
	}
	if grep.PrecedingReasoning != "" {
		t.Errorf("reasoning must be consumed once, got %q on the second tool", grep.PrecedingReasoning)
	}

	// exec: status "success" but exitCode 1 -> failure, with wallTimeMs.
	ex := eventByRawName(t, res, "exec")
	if ex.Success || ex.DurationMs != 2500 || ex.ErrorMessage == "" || ex.Target != "go test ./..." {
		t.Errorf("failing exec = %+v", ex)
	}

	// agent create with no result: spawn_subagent, pending.
	ag := eventByRawName(t, res, "agent")
	if ag.ActionType != models.ActionSpawnSubagent || ag.Target != "Find TODOs" || !ag.OutcomePending || !ag.Success {
		t.Errorf("agent = %+v", ag)
	}
	if ag.IsSidechain {
		t.Error("the spawning call must not be a sidechain row")
	}
	glob := eventByRawName(t, res, "glob")
	if glob.ActionType != models.ActionSearchFiles || !glob.OutcomePending {
		t.Errorf("glob = %+v", glob)
	}
	mcp := eventByRawName(t, res, "some_mcp_tool")
	if mcp.ActionType != models.ActionUnknown || mcp.RawToolName != "some_mcp_tool" {
		t.Errorf("unmapped tool = %+v", mcp)
	}

	// Effort is stamped from session_states.settings on the parent only.
	for _, e := range res.ToolEvents {
		if e.SessionID == "sess_1000000000000_synthparent01" && e.ActionType != models.ActionUserPrompt {
			if e.Metadata == nil || e.Metadata.EffortLevel != "high" {
				t.Errorf("event %s metadata = %+v, want effort high", e.SourceEventID, e.Metadata)
			}
		}
		if e.SessionID == "sess_1000000000001_synthchild001" && e.Metadata != nil && e.Metadata.EffortLevel != "" {
			t.Errorf("child has no effort setting but metadata = %+v", e.Metadata)
		}
	}
	// Per-run model beats the session's current selection.
	if m := eventByRawName(t, res, "read").Model; m != "anthropic/claude-sonnet-4.5" {
		t.Errorf("read model = %q", m)
	}
}

func TestSyntheticTokens(t *testing.T) {
	res, _ := parseAll(t, "fixture-synthetic.sql")

	// Parent run: gross 20000, cacheRead 12000, cacheWrite 3000 -> net 5000;
	// cost quality "exact" carries the vendor total.
	run := tokenByID(t, res, "run:run_s1")
	if run.InputTokens != 5000 || run.OutputTokens != 500 || run.CacheReadTokens != 12000 || run.CacheCreationTokens != 3000 {
		t.Errorf("run_s1 = %+v", run)
	}
	if run.EstimatedCostUSD != 0.0123 {
		t.Errorf("exact cost = %v, want 0.0123", run.EstimatedCostUSD)
	}
	if run.MessageID != "msg_a4" {
		t.Errorf("MessageID = %q, want the final assistant message of the run", run.MessageID)
	}
	// Child: nullable cache columns.
	child := tokenByID(t, res, "run:run_c1")
	if child.InputTokens != 1000 || child.CacheReadTokens != 0 || child.EstimatedCostUSD != 0 {
		t.Errorf("run_c1 = %+v", child)
	}
	// Standalone ledger call, and the mirror that stands in for a run whose
	// run_stats row is absent.
	solo := tokenByID(t, res, "ledger:plugin_ledger_synth0001")
	if solo.InputTokens != 100 || solo.OutputTokens != 20 || solo.TurnID != "" {
		t.Errorf("standalone ledger = %+v", solo)
	}
	orph := tokenByID(t, res, "run:run_orph")
	if orph.InputTokens != 400 || orph.CacheReadTokens != 100 || orph.TurnID != "run_orph" {
		t.Errorf("orphan mirror = %+v", orph)
	}
	// The mirrors of runs that DO have a run_stats row must not duplicate.
	ids := map[string]int{}
	for _, e := range res.TokenEvents {
		ids[e.SourceEventID]++
	}
	for id, n := range ids {
		if n != 1 {
			t.Errorf("token event %q emitted %d times", id, n)
		}
	}
	if len(res.TokenEvents) != 4 {
		t.Errorf("token events = %d, want 4 (run_s1, run_c1, solo, run_orph; the mirrors of runs with a run_stats row are skipped): %v", len(res.TokenEvents), ids)
	}
}

func TestSyntheticLineage(t *testing.T) {
	res, _ := parseAll(t, "fixture-synthetic.sql")
	got := map[string]models.SessionLineage{}
	for _, l := range res.SessionLineages {
		got[l.SessionID] = l
	}
	if len(got) != 2 {
		t.Fatalf("lineages = %+v (the unknown relation type must be skipped)", res.SessionLineages)
	}
	child := got["sess_1000000000001_synthchild001"]
	if child.ParentThreadID != "sess_1000000000000_synthparent01" || child.ThreadSource != "subagent" || child.ForkedFromID != "" {
		t.Errorf("subagent lineage = %+v", child)
	}
	fork := got["sess_1000000000002_synthfork0001"]
	if fork.ForkedFromID != "sess_1000000000000_synthparent01" || fork.ThreadSource != "user" || fork.ParentThreadID != "" {
		t.Errorf("branch lineage = %+v", fork)
	}
}

func TestIncrementalWatermark(t *testing.T) {
	dbPath, root := buildStore(t, "fixture-synthetic.sql")
	a := NewWithOptions(nil, []string{root})
	ctx := context.Background()

	first, err := a.ParseSessionFile(ctx, dbPath, 0)
	if err != nil || len(first.ToolEvents) == 0 {
		t.Fatalf("first parse: %v events=%d", err, len(first.ToolEvents))
	}
	again, err := a.ParseSessionFile(ctx, dbPath, first.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.ToolEvents)+len(again.TokenEvents)+len(again.SessionLineages)+len(again.OutcomeUpdates) != 0 || again.NewOffset != first.NewOffset {
		t.Errorf("a parse at the watermark must be a no-op, got %+v", again)
	}

	// A -wal event resolves to the same store.
	viaWAL, err := a.ParseSessionFile(ctx, dbPath+"-wal", 0)
	if err != nil || len(viaWAL.ToolEvents) != len(first.ToolEvents) {
		t.Errorf("-wal path parse: %v events=%d want %d", err, len(viaWAL.ToolEvents), len(first.ToolEvents))
	}

	// Only the session touched after the cursor is re-read; a result that
	// arrived after the tool_use was first stored resolves via OutcomeUpdate.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO messages VALUES('msg_tr_glob','sess_1000000000000_synthparent01','tool_result',
		'[{"type":"tool_result","tool_use_id":"call_glob1","content":"a.go\nb.go","is_error":false}]',NULL,
		'{"runId":"run_s1","toolCallId":"call_glob1","toolName":"glob","status":"success"}',NULL,'0001-0008',
		'2026-10-22T11:00:00.000Z','2026-10-22T11:00:00.000Z')`); err != nil {
		t.Fatal(err)
	}
	next, err := a.ParseSessionFile(ctx, dbPath, first.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if next.NewOffset <= first.NewOffset {
		t.Fatalf("watermark did not advance: %d -> %d", first.NewOffset, next.NewOffset)
	}
	for _, e := range next.ToolEvents {
		if e.SessionID != "sess_1000000000000_synthparent01" {
			t.Errorf("untouched session %s re-emitted", e.SessionID)
		}
	}
	if len(next.OutcomeUpdates) != 1 {
		t.Fatalf("outcome updates = %+v", next.OutcomeUpdates)
	}
	u := next.OutcomeUpdates[0]
	if !u.SuccessKnown || !u.Success || !strings.HasSuffix(u.SourceEventID, ":call_glob1") || !strings.Contains(u.ToolOutput, "a.go") {
		t.Errorf("outcome update = %+v", u)
	}
	// The re-emitted action now carries the result and is no longer pending.
	if g := eventByRawName(t, next, "glob"); g.OutcomePending || !g.Success {
		t.Errorf("glob after result = %+v", g)
	}
}

func TestDeterministicUniqueIDs(t *testing.T) {
	dbPath, root := buildStore(t, "fixture-wsl.sql", "fixture-synthetic.sql")
	a := NewWithOptions(nil, []string{root})
	r1, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	ids := func(r adapter.ParseResult) []string {
		var out []string
		for _, e := range r.ToolEvents {
			out = append(out, e.SourceEventID)
		}
		for _, e := range r.TokenEvents {
			out = append(out, "tok:"+e.SourceEventID)
		}
		sort.Strings(out)
		return out
	}
	a1, a2 := ids(r1), ids(r2)
	if strings.Join(a1, "\n") != strings.Join(a2, "\n") {
		t.Error("two parses of the same store produced different SourceEventIDs")
	}
	seen := map[string]bool{}
	for _, id := range a1 {
		if seen[id] {
			t.Errorf("duplicate SourceEventID %q", id)
		}
		seen[id] = true
	}
}

func TestEmptyAndForeignSchemas(t *testing.T) {
	// An empty, schema-less SQLite file degrades to a no-op.
	root := filepath.Join(t.TempDir(), ".dimcode", "v2")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(root, storeFile)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE unrelated (x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	res, err := NewWithOptions(nil, []string{root}).ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("foreign schema: %v", err)
	}
	if len(res.ToolEvents)+len(res.TokenEvents) != 0 || res.NewOffset != 0 {
		t.Errorf("expected an empty result, got %+v", res)
	}
}

func TestMalformedPartsAreWarnedNotFatal(t *testing.T) {
	dbPath, root := buildStore(t)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range []string{
		`INSERT INTO sessions VALUES('sess_1_x','/home/user/p','t','active',NULL,NULL,NULL,'2026-10-22T10:00:00.000Z','2026-10-22T10:00:00.000Z',1)`,
		`INSERT INTO messages VALUES('m1','sess_1_x','user','not json',NULL,NULL,NULL,'1-0','2026-10-22T10:00:00.000Z','2026-10-22T10:00:00.000Z')`,
		`INSERT INTO messages VALUES('m2','sess_1_x','user','[{"type":"text","text":"hi"}]',NULL,NULL,NULL,'1-1','2026-10-22T10:00:01.000Z','2026-10-22T10:00:01.000Z')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	res, err := NewWithOptions(nil, []string{root}).ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 1 || len(res.ToolEvents) != 1 {
		t.Errorf("warnings=%v events=%d", res.Warnings, len(res.ToolEvents))
	}
}

func TestMapTool(t *testing.T) {
	cases := []struct {
		name, args, wantAction, wantTarget string
	}{
		{"exec", `{"command":"ls -la","cwd":"/x"}`, models.ActionRunCommand, "ls -la"},
		{"read", `{"path":"/a/b.go"}`, models.ActionReadFile, "/a/b.go"},
		{"write", `{"path":"/a/b.go","content":"x"}`, models.ActionWriteFile, "/a/b.go"},
		{"edit", `{"path":"/a/b.go","oldText":"a","newText":"b"}`, models.ActionEditFile, "/a/b.go"},
		{"glob", `{"pattern":"*.go"}`, models.ActionSearchFiles, "*.go"},
		{"find", `{"pattern":"x"}`, models.ActionSearchFiles, "x"},
		{"grep", `{"pattern":"TODO"}`, models.ActionSearchText, "TODO"},
		{"rg", `{"pattern":"TODO"}`, models.ActionSearchText, "TODO"},
		{"search", `{"query":"q"}`, models.ActionSearchText, "q"},
		{"WebFetch", `{"url":"https://example.com"}`, models.ActionWebFetch, "https://example.com"},
		{"WebSearch", `{"query":"go"}`, models.ActionWebSearch, "go"},
		{"todowrite", `{"todos":[{"status":"completed"},{"status":"pending"}]}`, models.ActionTodoUpdate, "2 todos (1 completed)"},
		{"todowrite", `{}`, models.ActionTodoUpdate, "todowrite"},
		{"AskUserQuestion", `{}`, models.ActionAskUser, "AskUserQuestion"},
		{"agent", `{"action":"create","taskTitle":"T","agentName":"A"}`, models.ActionSpawnSubagent, "T"},
		{"agent", `{"action":"create_external","agentName":"A"}`, models.ActionSpawnSubagent, "A"},
		{"agent", `{"action":"list"}`, models.ActionAgentControl, "list"},
		{"agent", `{"action":"cancel"}`, models.ActionAgentControl, "cancel"},
		{"wait", `{}`, models.ActionSubagentWait, "wait"},
		{"skill", `{"skill":"pdf"}`, models.ActionSkillInvoke, "pdf"},
		{"chrome", `{"action":"open"}`, models.ActionBrowserAction, "open"},
		{"goal", `{"action":"get"}`, models.ActionHarnessCall, "get"},
		{"workflow", `{"name":"w"}`, models.ActionHarnessCall, "w"},
		{"workflow_result", `{}`, models.ActionHarnessCall, "workflow_result"},
		{"EXEC", `{"command":"x"}`, models.ActionRunCommand, "x"},
		{"mystery_tool", `{"query":"q"}`, models.ActionUnknown, "q"},
		{"mystery_tool", `not json`, models.ActionUnknown, "mystery_tool"},
	}
	for _, tc := range cases {
		gotA, gotT := mapTool(tc.name, []byte(tc.args))
		if gotA != tc.wantAction || gotT != tc.wantTarget {
			t.Errorf("mapTool(%q, %s) = (%q, %q), want (%q, %q)", tc.name, tc.args, gotA, gotT, tc.wantAction, tc.wantTarget)
		}
	}
}

func TestExactCost(t *testing.T) {
	cases := []struct {
		raw  string
		want float64
	}{
		{`{"totalCostUsd":0.5,"quality":"exact"}`, 0.5},
		{`{"totalCostUsd":0.5,"quality":"base_tokens"}`, 0},
		{`{"totalCostUsd":0,"quality":"missing_price"}`, 0},
		{`{"totalCostUsd":-1,"quality":"exact"}`, 0},
		{``, 0},
		{`garbage`, 0},
	}
	for _, tc := range cases {
		if got := exactCost(tc.raw); got != tc.want {
			t.Errorf("exactCost(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestTruncateKeepsRunes(t *testing.T) {
	s := strings.Repeat("é", 10) // 20 bytes
	got := truncate(s, 5)
	if !strings.HasPrefix(s, got) || len(got) > 5 || len(got)%2 != 0 {
		t.Errorf("truncate split a rune: %q", got)
	}
}
