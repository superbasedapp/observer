package deepagents

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// Fixture thread ids (testdata/deepagents/fixture.sql; see its README).
const (
	threadA = "01a00000-0000-7000-8000-00000000a001" // the real WSL session, anonymized
	threadB = "01a00000-0000-7000-8000-00000000b002" // synthetic: Anthropic blocks, errors, attachments
	threadC = "01a00000-0000-7000-8000-00000000c003" // synthetic: Windows cwd, OpenAI usage
	threadD = "01a00000-0000-7000-8000-00000000d004" // real Windows headless session, anonymized
	threadE = "01a00000-0000-7000-8000-00000000e005" // real WSL headless session with a sub-agent, anonymized
)

// buildStore materialises the fixture into <tmp>/.deepagents/.state/sessions.db
// and returns that path plus its watch root.
func buildStore(t *testing.T) (dbPath, root string) {
	t.Helper()
	ddl, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "deepagents", "fixture.sql"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	root = filepath.Join(t.TempDir(), ".deepagents", ".state")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath = filepath.Join(root, "sessions.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// One transaction: hundreds of autocommit INSERTs would each fsync.
	if _, err := db.Exec("BEGIN;\n" + string(ddl) + "\nCOMMIT;"); err != nil {
		db.Close()
		t.Fatalf("load fixture: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return dbPath, root
}

func parseAll(t *testing.T, from int64) (adapter.ParseResult, string) {
	t.Helper()
	dbPath, root := buildStore(t)
	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, from)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res, dbPath
}

func toolsOf(res adapter.ParseResult, session string) []models.ToolEvent {
	var out []models.ToolEvent
	for _, e := range res.ToolEvents {
		if e.SessionID == session {
			out = append(out, e)
		}
	}
	return out
}

func tokensOf(res adapter.ParseResult, session string) []models.TokenEvent {
	var out []models.TokenEvent
	for _, e := range res.TokenEvents {
		if e.SessionID == session {
			out = append(out, e)
		}
	}
	return out
}

func toolByID(t *testing.T, evs []models.ToolEvent, id string) models.ToolEvent {
	t.Helper()
	for _, e := range evs {
		if e.SourceEventID == id {
			return e
		}
	}
	t.Fatalf("no tool event %q in %d events", id, len(evs))
	return models.ToolEvent{}
}

func tokenByID(t *testing.T, evs []models.TokenEvent, id string) models.TokenEvent {
	t.Helper()
	for _, e := range evs {
		if e.SourceEventID == id {
			return e
		}
	}
	t.Fatalf("no token event %q in %d events", id, len(evs))
	return models.TokenEvent{}
}

func TestNewAndName(t *testing.T) {
	a := New()
	if a.scrubber == nil {
		t.Fatal("New() left a nil scrubber")
	}
	if a.Name() != models.ToolDeepAgentsCode {
		t.Errorf("Name()=%q want %q", a.Name(), models.ToolDeepAgentsCode)
	}
	_ = a.WatchPaths()
	if b := NewWithOptions(nil, nil); b.scrubber == nil {
		t.Fatal("NewWithOptions(nil,nil) left a nil scrubber")
	}
}

func TestDefaultRoots(t *testing.T) {
	orig := allHomesFunc
	defer func() { allHomesFunc = orig }()
	nativeHome, foreignHome := t.TempDir(), t.TempDir()
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: nativeHome, OS: crossmount.OSLinux, Origin: "native"},
			{Path: foreignHome, OS: crossmount.OSWindows, Origin: "wsl-mnt:c"},
			{Path: nativeHome, OS: crossmount.OSLinux, Origin: "duplicate"},
		}
	}
	t.Setenv(homeEnv, "")
	got := defaultRoots()
	want := []string{
		filepath.Join(nativeHome, ".deepagents", ".state"),
		filepath.Join(foreignHome, ".deepagents", ".state"),
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("roots=%v want %v", got, want)
	}

	override := t.TempDir()
	t.Setenv(homeEnv, override)
	got = defaultRoots()
	if wantExtra := filepath.Join(override, ".state"); got[len(got)-1] != wantExtra {
		t.Errorf("DEEPAGENTS_HOME root missing: %v", got)
	}
	t.Setenv(homeEnv, "relative/dir") // dcode rejects it; so do we
	if got = defaultRoots(); len(got) != 2 {
		t.Errorf("relative DEEPAGENTS_HOME must not add a root: %v", got)
	}
}

func TestIsSessionFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".deepagents", ".state")
	a := NewWithOptions(nil, []string{root})
	other := filepath.Join(t.TempDir(), "goose", "sessions")
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"db", filepath.Join(root, "sessions.db"), true},
		{"wal", filepath.Join(root, "sessions.db-wal"), true},
		{"shm", filepath.Join(root, "sessions.db-shm"), true},
		{"upper-case", filepath.Join(root, "Sessions.DB"), true},
		{"other basename", filepath.Join(root, "history.jsonl"), false},
		{"owner lock file", filepath.Join(root, "sessions.db.owners", "abc.owner"), false},
		{"credential store", filepath.Join(root, "auth.json"), false},
		{"wrong parent dir", filepath.Join(filepath.Dir(root), "sessions.db"), false},
		{"goose store (same basename)", filepath.Join(other, "sessions.db"), false},
	}
	for _, c := range cases {
		if got := a.IsSessionFile(c.path); got != c.want {
			t.Errorf("%s: IsSessionFile(%q)=%v want %v", c.name, c.path, got, c.want)
		}
	}
}

func TestResolveDBPath(t *testing.T) {
	d := filepath.Join("x", ".state")
	for _, suf := range []string{"", "-wal", "-shm"} {
		if got, want := resolveDBPath(filepath.Join(d, "sessions.db"+suf)), filepath.Join(d, "sessions.db"); got != want {
			t.Errorf("resolveDBPath(%q)=%q want %q", suf, got, want)
		}
	}
}

func TestCursorSemantics(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".state")
	a := NewWithOptions(nil, []string{root})
	var _ adapter.CursorSemantics = a
	cs := a.CursorSemanticsFor(filepath.Join(root, "sessions.db-wal"))
	if cs.Kind != adapter.CursorWatermark {
		t.Errorf("kind=%v want watermark", cs.Kind)
	}
	if got := a.CursorSemanticsFor(filepath.Join(root, "auth.json")); got.Kind != adapter.CursorByteOffset {
		t.Errorf("foreign file got kind %v", got.Kind)
	}
}

func TestUUIDTime(t *testing.T) {
	// 1f1cd130-6b58-652c-bfff-3cff8309fa1f is the first checkpoint of the
	// grounded session; its blob `ts` is 2026-10-21T05:48:22.582802Z.
	got, ok := uuidTime("1f1cd130-6b58-652c-bfff-3cff8309fa1f")
	if !ok {
		t.Fatal("uuidTime rejected a UUIDv6")
	}
	want := time.Date(2026, 10, 21, 5, 48, 22, 582802000, time.UTC)
	if d := got.Sub(want); d < -time.Millisecond || d > time.Millisecond {
		t.Errorf("uuidTime=%s want ~%s", got, want)
	}
	if c := cursorOf("1f1cd130-6b58-652c-bfff-3cff8309fa1f"); c != got.UnixNano()/100 {
		t.Errorf("cursorOf=%d", c)
	}
	for _, bad := range []string{"", "not-a-uuid", "1f1cd130-6b58-452c-bfff-3cff8309fa1f", "zzzzzzzz-6b58-652c-bfff-3cff8309fa1f"} {
		if _, ok := uuidTime(bad); ok {
			t.Errorf("uuidTime accepted %q", bad)
		}
	}
	// A UUIDv7 carries Unix milliseconds in its first 48 bits.
	v7, ok := uuidTime("019c1234-5678-7abc-8def-0123456789ab")
	if !ok || v7.UnixMilli() != 0x019c12345678 {
		t.Errorf("uuidv7 time=%v ok=%v", v7, ok)
	}
}

func TestLoadMessageWritesSelectsOnlyMessages(t *testing.T) {
	dbPath, _ := buildStore(t)
	db, err := openReadOnlyDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	var total, messages int
	if err := db.QueryRow(`SELECT COUNT(*) FROM writes`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{threadA, threadB, threadC, threadD, threadE} {
		w, err := loadMessageWrites(ctx, db, id)
		if err != nil {
			t.Fatal(err)
		}
		messages += len(w)
	}
	// D: 10 root writes; E: 7 root + 9 sub-agent writes.
	if messages != 24+8+2+10+16 {
		t.Errorf("message writes=%d want 60", messages)
	}
	// Non-message writes: the `_quickjs_snapshot_payload` decoy, D's 16 and
	// E's 22 HITL / hook-protocol / request-start writes (read by their own
	// loaders), and E's sub-agent `_session_cost_transfers` (never read: it
	// restates the child's usage, which is counted from its messages).
	if total != messages+1+16+22+1 {
		t.Errorf("unexpected non-message writes; total=%d messages=%d", total, messages)
	}
}

func TestParseFixture_Counts(t *testing.T) {
	res, _ := parseAll(t, 0)
	if len(res.Warnings) != 0 {
		t.Errorf("warnings: %v", res.Warnings)
	}
	// Thread A: 19 distinct messages (24 writes: five AI messages are
	// re-written by the after-model middleware) -> 9 model calls, plus the
	// out-of-graph naming spend row.
	if got := len(tokensOf(res, threadA)); got != 9+1 {
		t.Errorf("thread A token rows=%d want 10 (9 model calls, duplicates folded, + naming spend)", got)
	}
	if got := len(tokensOf(res, threadB)); got != 3+1 {
		t.Errorf("thread B token rows=%d want 4 (3 calls + naming spend)", got)
	}
	// Thread C: its dcode_btw_costs row is the `null` deletion tombstone.
	if got := len(tokensOf(res, threadC)); got != 1 {
		t.Errorf("thread C token rows=%d want 1", got)
	}
	count := func(session, action string) int {
		n := 0
		for _, e := range toolsOf(res, session) {
			if e.ActionType == action {
				n++
			}
		}
		return n
	}
	// Thread A: three prompts (the first "hi" was interrupted before any
	// reply), five distinct tool calls and the two stop replies.
	if n := count(threadA, models.ActionUserPrompt); n != 3 {
		t.Errorf("A user prompts=%d want 3", n)
	}
	if n := count(threadA, models.ActionSearchFiles); n != 2 {
		t.Errorf("A ls calls=%d want 2", n)
	}
	if n := count(threadA, models.ActionWriteFile); n != 1 {
		t.Errorf("A write_file=%d want 1 (duplicate write folded)", n)
	}
	if n := count(threadA, models.ActionEditFile); n != 2 { // edit_file + delete
		t.Errorf("A edit_file=%d want 2 (edit_file + delete)", n)
	}
	if n := count(threadA, models.ActionRunCommand); n != 2 {
		t.Errorf("A execute=%d want 2", n)
	}
	if n := count(threadA, models.ActionTaskComplete); n != 2 {
		t.Errorf("A task_complete=%d want 2 (the two finish_reason=stop replies)", n)
	}
}

func TestParseFixture_GrossInputNetted(t *testing.T) {
	res, dbPath := parseAll(t, 0)

	// Live grounding: input 14510 includes cache_read 14359 -> net 151.
	a := tokensOf(res, threadA)
	var seen bool
	for _, tk := range a {
		if tk.CacheReadTokens == 14359 {
			seen = true
			if tk.InputTokens != 151 || tk.OutputTokens != 41 {
				t.Errorf("A input/output=%d/%d want 151/41", tk.InputTokens, tk.OutputTokens)
			}
			if tk.Model != "minimax/minimax-m3.1-flash:free" {
				t.Errorf("A model=%q", tk.Model)
			}
			if tk.Source != models.TokenSourceJSONL || tk.Reliability != models.ReliabilityApproximate {
				t.Errorf("A source/reliability=%q/%q", tk.Source, tk.Reliability)
			}
			if tk.SourceFile != dbPath {
				t.Errorf("A source file=%q want %q", tk.SourceFile, dbPath)
			}
			if tk.TurnID == "" {
				t.Errorf("A token row lost its dcode turn id")
			}
		}
	}
	if !seen {
		t.Fatal("did not find the 14510/14359 sample")
	}

	// Anthropic shape: input 1000 = 300 net + 600 read + 100 write; output
	// 200 = 150 net + 50 reasoning; 40 of the write is the 1h tier.
	b := tokenByID(t, tokensOf(res, threadB), "tokens:lc_run--b2")
	if b.InputTokens != 300 || b.CacheReadTokens != 600 || b.CacheCreationTokens != 100 || b.CacheCreation1hTokens != 40 {
		t.Errorf("B input split=%d/%d/%d/%d", b.InputTokens, b.CacheReadTokens, b.CacheCreationTokens, b.CacheCreation1hTokens)
	}
	if b.OutputTokens != 150 || b.ReasoningTokens != 50 {
		t.Errorf("B output/reasoning=%d/%d want 150/50", b.OutputTokens, b.ReasoningTokens)
	}
	if b.MessageID != "msg_fixture_b2" || b.Model != "claude-sonnet-4-5" || b.TurnID != "turn-b1" {
		t.Errorf("B ids/model: %q %q %q", b.MessageID, b.Model, b.TurnID)
	}

	// Provider-reported dollar cost rides along.
	if b5 := tokenByID(t, tokensOf(res, threadB), "tokens:lc_run--b5"); b5.EstimatedCostUSD != 0.0123 || b5.InputTokens != 500 {
		t.Errorf("B5 cost/input=%v/%d want 0.0123/500", b5.EstimatedCostUSD, b5.InputTokens)
	}
	// OpenAI shape with reasoning: 500-128 = 372 net; 20-10 = 10 net output.
	c := tokensOf(res, threadC)[0]
	if c.InputTokens != 372 || c.OutputTokens != 10 || c.ReasoningTokens != 10 || c.Model != "gpt-5.5" {
		t.Errorf("C = %+v", c)
	}
}

func TestParseFixture_ToolActions(t *testing.T) {
	res, _ := parseAll(t, 0)
	a := toolsOf(res, threadA)

	w := toolByID(t, a, "tool:call_function_1i8z467cux1j_1")
	if w.ActionType != models.ActionWriteFile || w.Target != "/home/user/demo-project/hello_world.py" {
		t.Errorf("write_file = %q %q", w.ActionType, w.Target)
	}
	if w.ContentBytes != int64(len("print(\"Hello, World!\")\n")) || !w.Success {
		t.Errorf("write_file bytes/success = %d/%v", w.ContentBytes, w.Success)
	}
	if !strings.Contains(w.RawToolInput, "hello_world.py") || w.RawToolName != "write_file" {
		t.Errorf("write_file raw = %q %q", w.RawToolName, w.RawToolInput)
	}
	if w.Metadata == nil || w.Metadata.PermissionMode != "manual" {
		t.Errorf("write_file permission mode = %+v", w.Metadata)
	}
	if w.Model != "minimax/minimax-m3.1-flash:free" {
		t.Errorf("write_file model=%q", w.Model)
	}
	ex := toolByID(t, a, "tool:call_function_ct9gia4nbnvt_1")
	if ex.ActionType != models.ActionRunCommand || !strings.Contains(ex.Target, "python3 hello_world.py") {
		t.Errorf("execute = %q %q", ex.ActionType, ex.Target)
	}
	if !strings.Contains(ex.ToolOutput, "Hello, World!") {
		t.Errorf("execute output = %q", ex.ToolOutput)
	}
	if d := toolByID(t, a, "tool:call_function_gwgzlymo6xhr_1"); d.ActionType != models.ActionEditFile || d.RawToolName != "delete" {
		t.Errorf("delete = %q %q", d.ActionType, d.RawToolName)
	}

	// Prompt + assistant text + terminal marker.
	var prompts []models.ToolEvent
	for _, e := range a {
		if e.ActionType == models.ActionUserPrompt {
			prompts = append(prompts, e)
		}
	}
	sort.Slice(prompts, func(i, j int) bool { return prompts[i].Timestamp.Before(prompts[j].Timestamp) })
	if len(prompts) != 3 || prompts[0].Target != "hi" || prompts[1].Target != "hi" || !strings.HasPrefix(prompts[2].Target, "Create a hello world python file") {
		t.Errorf("prompts = %+v", prompts)
	}
	for _, e := range a {
		if e.Tool != models.ToolDeepAgentsCode || e.SessionID != threadA || e.Timestamp.IsZero() {
			t.Errorf("bad envelope on %s: tool=%q session=%q ts=%v", e.SourceEventID, e.Tool, e.SessionID, e.Timestamp)
		}
	}
	if !strings.HasSuffix(filepath.ToSlash(a[0].ProjectRoot), "demo-project") {
		t.Errorf("project root=%q", a[0].ProjectRoot)
	}
	if a[0].GitBranch != "master" {
		t.Errorf("git branch=%q", a[0].GitBranch)
	}
}

func TestParseFixture_SyntheticShapes(t *testing.T) {
	res, _ := parseAll(t, 0)
	b := toolsOf(res, threadB)

	// Failed shell call: the exit code lives in the message artifact, the
	// status stays "success".
	fail := toolByID(t, b, "tool:toolu_b1")
	if fail.Success || !strings.Contains(fail.ErrorMessage, "exit code 1") || fail.OutcomePending {
		t.Errorf("failed execute: success=%v err=%q pending=%v", fail.Success, fail.ErrorMessage, fail.OutcomePending)
	}
	// Reasoning attaches once, to the first row the model call produced
	// (its assistant text), never repeated onto the tool calls.
	if fail.PrecedingReasoning != "" {
		t.Errorf("tool call repeated the reasoning: %q", fail.PrecedingReasoning)
	}
	if sub := toolByID(t, b, "tool:toolu_b2"); sub.ActionType != models.ActionSpawnSubagent || sub.Target != "general-purpose" || !sub.Success {
		t.Errorf("task = %q %q success=%v", sub.ActionType, sub.Target, sub.Success)
	}
	// Assistant text: reasoning blocks are excluded from the visible text.
	txt := toolByID(t, b, "text:lc_run--b2")
	if txt.ToolOutput != "Running the tests now." || txt.Metadata == nil || txt.Metadata.StopReason != "tool_use" {
		t.Errorf("text = %q meta=%+v", txt.ToolOutput, txt.Metadata)
	}
	if txt.PrecedingReasoning != "Plan: run the test suite first." {
		t.Errorf("reasoning = %q", txt.PrecedingReasoning)
	}
	// A call with no ToolMessage yet is persisted optimistically + flagged.
	pend := toolByID(t, b, "tool:toolu_b7")
	if !pend.OutcomePending || !pend.Success || pend.ActionType != models.ActionWriteFile {
		t.Errorf("pending call = %+v", pend)
	}
	// Harness-injected [SYSTEM] human message is context, not a user prompt.
	if sys := toolByID(t, b, "prompt:hb6"); sys.ActionType != models.ActionPromptContext {
		t.Errorf("[SYSTEM] message = %q", sys.ActionType)
	}
	// Attachments: presence + kind + media type, no bytes or names.
	up := toolByID(t, b, "prompt:hb1")
	if up.ActionType != models.ActionUserPrompt || up.Target != "Run the tests and fix failures" {
		t.Errorf("prompt = %q %q", up.ActionType, up.Target)
	}
	if len(up.UserAttachments) != 1 || up.UserAttachments[0] != (models.UserAttachment{Kind: "image", MediaType: "image/png"}) {
		t.Errorf("attachments = %+v", up.UserAttachments)
	}
	if up.Metadata == nil || up.Metadata.PermissionMode != "auto" {
		t.Errorf("approval mode not carried: %+v", up.Metadata)
	}
	// Remove messages never delete anything that was already spent.
	if toolByID(t, b, "prompt:hb6").SourceEventID == "" {
		t.Error("RemoveMessage dropped a message")
	}
	if done := toolByID(t, b, "complete:lc_run--b5"); done.ActionType != models.ActionTaskComplete {
		t.Errorf("complete = %q", done.ActionType)
	}

	// Windows cwd: kept (translated when reachable) and never CWD-prefixed.
	c := toolsOf(res, threadC)
	if len(c) == 0 {
		t.Fatal("no thread C events")
	}
	if root := filepath.ToSlash(c[0].ProjectRoot); !strings.Contains(root, "win-project") || strings.Contains(root, "superbased") {
		t.Errorf("windows project root = %q", c[0].ProjectRoot)
	}
}

func TestParseFixture_CacheObservations(t *testing.T) {
	res, _ := parseAll(t, 0)
	byMsg := map[string]models.CacheTurnObservation{}
	for _, o := range res.CacheObservations {
		byMsg[o.MessageID] = o
		if o.SourceEventID != "cachetrack:"+o.MessageID {
			t.Errorf("cache source id %q", o.SourceEventID)
		}
	}
	// One per usage-bearing ROOT-namespace model call: A 9, B 3, C 1, D 4,
	// E 2 (E's three sub-agent calls feed no Tier-2 observation).
	if len(res.CacheObservations) != 9+3+1+4+2 {
		t.Errorf("cache observations=%d want 19 (one per usage-bearing root model call)", len(res.CacheObservations))
	}
	anth := byMsg["msg_fixture_b2"]
	if anth.ImplicitCache {
		t.Error("Anthropic call must stay explicit-cache shape")
	}
	if anth.Usage.CacheCreationTokens != 100 || anth.Usage.CacheCreation1hTokens != 40 || anth.Usage.NetInputTokens != 300 {
		t.Errorf("anthropic usage = %+v", anth.Usage)
	}
	if len(anth.BlockHashes) == 0 {
		t.Error("anthropic call carried no block delta")
	}
	or := byMsg["gen-fixture-b5"]
	if !or.ImplicitCache || or.BlockHashes != nil {
		t.Errorf("openrouter call must overlay implicit cache: implicit=%v blocks=%v", or.ImplicitCache, or.BlockHashes)
	}
	if byMsg["resp_fixture_c2"].Model != "gpt-5.5" || !byMsg["resp_fixture_c2"].ImplicitCache {
		t.Errorf("openai observation = %+v", byMsg["resp_fixture_c2"])
	}
}

func TestParseFixture_ToolVersion(t *testing.T) {
	res, _ := parseAll(t, 0)
	got := map[string]string{}
	for _, v := range res.SessionToolVersions {
		got[v.SessionID] = v.Version
	}
	for _, id := range []string{threadA, threadB, threadC, threadD, threadE} {
		if got[id] != "0.1.87" {
			t.Errorf("tool version for %s = %q", id, got[id])
		}
	}
}

func TestParse_Idempotent(t *testing.T) {
	dbPath, root := buildStore(t)
	a := NewWithOptions(nil, []string{root})
	ids := func() []string {
		res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range res.ToolEvents {
			out = append(out, "T|"+e.SourceEventID)
		}
		for _, e := range res.TokenEvents {
			out = append(out, "K|"+e.SourceEventID)
		}
		sort.Strings(out)
		return out
	}
	first, second := ids(), ids()
	if strings.Join(first, "\n") != strings.Join(second, "\n") {
		t.Error("re-parse produced different source event ids")
	}
	seen := map[string]bool{}
	for _, id := range first {
		if seen[id] {
			t.Errorf("duplicate source event id %q within one parse", id)
		}
		seen[id] = true
	}
}

func TestParse_WatermarkAndOutcomes(t *testing.T) {
	dbPath, root := buildStore(t)
	a := NewWithOptions(nil, []string{root})
	first, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.NewOffset <= 0 {
		t.Fatalf("NewOffset=%d", first.NewOffset)
	}
	if len(first.OutcomeUpdates) != 0 {
		t.Errorf("a from-scratch parse needs no late outcome updates, got %d", len(first.OutcomeUpdates))
	}
	// Nothing new since the watermark: nothing read.
	again, err := a.ParseSessionFile(context.Background(), dbPath, first.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.ToolEvents)+len(again.TokenEvents) != 0 || again.NewOffset != first.NewOffset {
		t.Errorf("unchanged store re-emitted %d/%d events (offset %d)", len(again.ToolEvents), len(again.TokenEvents), again.NewOffset)
	}
	// A cursor just before the newest checkpoint (thread D's last one)
	// re-emits only the thread that moved.
	partial, err := a.ParseSessionFile(context.Background(), dbPath, first.NewOffset-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(partial.ToolEvents) == 0 {
		t.Fatal("the newest thread was not re-emitted")
	}
	for _, e := range partial.ToolEvents {
		if e.SessionID != threadD {
			t.Errorf("thread %s should not be re-emitted", e.SessionID)
		}
	}
	partial2, err := a.ParseSessionFile(context.Background(), dbPath, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(partial2.OutcomeUpdates) == 0 {
		t.Fatal("incremental parse emitted no late outcome updates")
	}
	var sawFail bool
	for _, u := range partial2.OutcomeUpdates {
		if !u.SuccessKnown || u.SourceFile != dbPath {
			t.Errorf("bad outcome update %+v", u)
		}
		if u.SourceEventID == "tool:toolu_b1" && !u.Success && strings.Contains(u.ErrorMessage, "exit code 1") {
			sawFail = true
		}
	}
	if !sawFail {
		t.Error("the failed execute was not re-emitted as a late outcome")
	}
}

func TestParse_EmptyAndMissingStores(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".deepagents", ".state")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, []string{dir})

	// The Windows install's sessions.db was a 0-byte file (the TUI never
	// got a server up): no tables, no error.
	empty := filepath.Join(dir, "sessions.db")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), empty, 0)
	if err != nil {
		t.Fatalf("empty store: %v", err)
	}
	if res.NewOffset != 0 || len(res.ToolEvents) != 0 {
		t.Errorf("empty store produced %+v", res)
	}
	// A -wal event whose database has vanished.
	if _, err := a.ParseSessionFile(context.Background(), filepath.Join(dir, "gone.db-wal"), 7); err != nil {
		t.Fatalf("missing store: %v", err)
	}
}

func TestIsForeignMountPathAndMirror(t *testing.T) {
	orig := allHomesFunc
	defer func() { allHomesFunc = orig }()
	foreignHome := t.TempDir()
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: "/home/native", OS: crossmount.OSLinux, Origin: "native"},
			{Path: foreignHome, OS: crossmount.OSWindows, Origin: "wsl-mnt:c"},
		}
	}
	if isForeignMountPath(filepath.Join("/home/native", ".deepagents", ".state", "sessions.db")) {
		t.Error("native path classified foreign")
	}
	src := filepath.Join(foreignHome, ".deepagents", ".state", "sessions.db")
	if !isForeignMountPath(src) {
		t.Fatal("foreign path not classified foreign")
	}
	// Staging itself (a filtered mirror, never a byte copy) is pinned by
	// TestForeignMirrorKeepsOnlyAllowListedTables (RB1 sweep finding A2).
}

func TestMapTool(t *testing.T) {
	cases := []struct {
		name   string
		args   map[string]any
		action string
		target string
	}{
		{"execute", map[string]any{"command": "ls -la"}, models.ActionRunCommand, "ls -la"},
		{"js_eval", map[string]any{"code": "\n  const x = 1;\n  x"}, models.ActionRunCommand, "const x = 1;"},
		{"read_file", map[string]any{"file_path": "/a/b"}, models.ActionReadFile, "/a/b"},
		{"write_file", map[string]any{"file_path": "/a/b", "content": "x"}, models.ActionWriteFile, "/a/b"},
		{"edit_file", map[string]any{"file_path": "/a/b"}, models.ActionEditFile, "/a/b"},
		{"delete", map[string]any{"file_path": "/a/b"}, models.ActionEditFile, "/a/b"},
		{"ls", map[string]any{"path": "/a"}, models.ActionSearchFiles, "/a"},
		{"glob", map[string]any{"pattern": "**/*.go", "path": "/a"}, models.ActionSearchFiles, "**/*.go"},
		{"grep", map[string]any{"pattern": "TODO"}, models.ActionSearchText, "TODO"},
		{"web_search", map[string]any{"query": "q"}, models.ActionWebSearch, "q"},
		{"fetch_url", map[string]any{"url": "https://example.com"}, models.ActionWebFetch, "https://example.com"},
		{"task", map[string]any{"description": "d", "subagent_type": "researcher"}, models.ActionSpawnSubagent, "researcher"},
		{"write_todos", map[string]any{"todos": []any{}}, models.ActionTodoUpdate, "write_todos"},
		{"ask_user", nil, models.ActionAskUser, "ask_user"},
		{"compact_conversation", nil, models.ActionContextCompacted, "compact_conversation"},
		{"EXECUTE", map[string]any{"command": "x"}, models.ActionRunCommand, "x"},
		{"github_create_issue", map[string]any{"title": "t"}, models.ActionUnknown, "github_create_issue"},
	}
	for _, c := range cases {
		action, target := mapTool(c.name, c.args)
		if action != c.action || target != c.target {
			t.Errorf("mapTool(%q) = %q,%q want %q,%q", c.name, action, target, c.action, c.target)
		}
	}
}

func TestTruncateIsRuneSafe(t *testing.T) {
	if got := truncate("héllo", 2); got != "h" {
		t.Errorf("truncate split a rune: %q", got)
	}
	if got := truncate("abc", 5); got != "abc" {
		t.Errorf("truncate=%q", got)
	}
}

func TestParseFixture_SideCost(t *testing.T) {
	res, _ := parseAll(t, 0)
	// Live grounding (thread A): 297 gross input incl. 184 cached, 91 output
	// incl. 87 reasoning -> net 113 / 4, reasoning 87, on the thread's model.
	a := tokenByID(t, tokensOf(res, threadA), "btw:"+threadA)
	if a.InputTokens != 113 || a.CacheReadTokens != 184 || a.OutputTokens != 4 || a.ReasoningTokens != 87 {
		t.Errorf("A side cost = in %d cr %d out %d rs %d", a.InputTokens, a.CacheReadTokens, a.OutputTokens, a.ReasoningTokens)
	}
	if a.Model != "minimax/minimax-m3.1-flash:free" || a.MessageID != "btw:"+threadA {
		t.Errorf("A side cost model/id = %q %q", a.Model, a.MessageID)
	}
	if a.Timestamp.IsZero() {
		t.Error("side cost row has no timestamp")
	}
	b := tokenByID(t, tokensOf(res, threadB), "btw:"+threadB)
	// 100 gross - 40 read - 10 write = 50 net; 30 - 10 reasoning = 20 net.
	if b.InputTokens != 50 || b.CacheCreationTokens != 10 || b.OutputTokens != 20 || b.EstimatedCostUSD != 0.002 {
		t.Errorf("B side cost = %+v", b)
	}
	for _, tk := range tokensOf(res, threadC) {
		if strings.HasPrefix(tk.SourceEventID, "btw:") {
			t.Errorf("tombstoned side cost produced a row: %+v", tk)
		}
	}
}
