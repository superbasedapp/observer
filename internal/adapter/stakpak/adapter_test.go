package stakpak

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

func parseFixture(t *testing.T, from int64) adapter.ParseResult {
	t.Helper()
	a := NewWithOptions(nil, []string{fixtureRoot})
	res, err := a.ParseSessionFile(context.Background(), fixtureDB, from)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res
}

func TestNewAndWatchPaths(t *testing.T) {
	a := New()
	if a.scrubber == nil {
		t.Fatal("New() left a nil scrubber")
	}
	_ = a.WatchPaths() // may be empty on a host with no resolvable homes; must not panic
	if a.Name() != models.ToolStakpak {
		t.Errorf("Name() = %q, want %q", a.Name(), models.ToolStakpak)
	}
	b := NewWithOptions(nil, nil)
	if b.scrubber == nil {
		t.Fatal("NewWithOptions(nil,nil) left a nil scrubber")
	}
	c := NewWithOptions(nil, []string{"/x"})
	if got := c.WatchPaths(); len(got) != 1 || got[0] != "/x" {
		t.Errorf("WatchPaths = %v, want [/x]", got)
	}
}

func TestDefaultRootsOnePerHome(t *testing.T) {
	orig := allHomesFunc
	defer func() { allHomesFunc = orig }()
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: filepath.Join("h", "linux"), OS: crossmount.OSLinux, Origin: "native"},
			{Path: filepath.Join("h", "win"), OS: crossmount.OSWindows, Origin: "wsl-mnt:c"},
			{Path: "", OS: crossmount.OSLinux, Origin: "native"},
			{Path: filepath.Join("h", "linux"), OS: crossmount.OSLinux, Origin: "native"}, // dup
		}
	}
	got := defaultRoots()
	want := []string{
		filepath.Join("h", "linux", ".stakpak", "data"),
		filepath.Join("h", "win", ".stakpak", "data"),
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("defaultRoots = %v, want %v", got, want)
	}
}

func TestResolveDBPath(t *testing.T) {
	d := filepath.Join("x", ".stakpak", "data")
	cases := map[string]string{
		filepath.Join(d, "local.db"):     filepath.Join(d, "local.db"),
		filepath.Join(d, "local.db-wal"): filepath.Join(d, "local.db"),
		filepath.Join(d, "local.db-shm"): filepath.Join(d, "local.db"),
	}
	for in, want := range cases {
		if got := resolveDBPath(in); got != want {
			t.Errorf("resolveDBPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIsSessionFile(t *testing.T) {
	root := filepath.Join(string(filepath.Separator)+"home", "u", ".stakpak", "data")
	a := NewWithOptions(nil, []string{root})
	other := filepath.Join(string(filepath.Separator)+"home", "u", "proj", "data")
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"main db", filepath.Join(root, "local.db"), true},
		{"wal", filepath.Join(root, "local.db-wal"), true},
		{"shm", filepath.Join(root, "local.db-shm"), true},
		{"upper-case name", filepath.Join(root, "LOCAL.DB"), true},
		{"other db name", filepath.Join(root, "other.db"), false},
		{"wrong parent dir", filepath.Join(filepath.Dir(root), "local.db"), false},
		{"data dir not under .stakpak", filepath.Join(other, "local.db"), false},
		{"outside watch root", filepath.Join(string(filepath.Separator)+"srv", ".stakpak", "data", "local.db"), false},
		{"autopilot db", filepath.Join(filepath.Dir(root), "autopilot", "autopilot.db"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Errorf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestCursorSemantics(t *testing.T) {
	a := NewWithOptions(nil, []string{fixtureRoot})
	cs := a.CursorSemanticsFor(fixtureDB)
	if cs.Kind != adapter.CursorWatermark {
		t.Fatalf("Kind = %v, want CursorWatermark", cs.Kind)
	}
	if cs.Kind.LagMeaningful() || cs.ActionsExpected() {
		t.Errorf("watermark semantics must suppress byte-lag and zero-action signals: %+v", cs)
	}
	if got := a.CursorSemanticsFor(filepath.Join(fixtureRoot, "other.db")); got != (adapter.FileCursorSemantics{}) {
		t.Errorf("non-session path got %+v, want zero value", got)
	}
	var _ adapter.CursorSemantics = a
}

// counts tallies a parse result's events per session.
type counts struct {
	prompts, texts, calls, tokens, starts int
	byAction                              map[string]int
}

func tally(res adapter.ParseResult, session string) counts {
	c := counts{byAction: map[string]int{}}
	for _, ev := range res.ToolEvents {
		if ev.SessionID != session {
			continue
		}
		switch ev.ActionType {
		case models.ActionUserPrompt:
			c.prompts++
		case models.ActionAssistantMessage:
			c.texts++
		case models.ActionSessionStart:
			c.starts++
		default:
			c.calls++
		}
		c.byAction[ev.ActionType]++
	}
	for _, tk := range res.TokenEvents {
		if tk.SessionID == session {
			c.tokens++
		}
	}
	return c
}

func TestParseFixtureCounts(t *testing.T) {
	res := parseFixture(t, 0)
	if res.NewOffset != 16 {
		t.Errorf("NewOffset = %d, want 16 (8 Windows + 8 Linux checkpoints, rowid watermark)", res.NewOffset)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v", res.Warnings)
	}

	win := tally(res, winSession)
	if win.prompts != 2 || win.texts != 5 || win.calls != 8 || win.tokens != 7 || win.starts != 1 {
		t.Errorf("windows session counts = %+v, want prompts 2, texts 5, calls 8, tokens 7, one session_start", win)
	}
	wantWin := map[string]int{
		models.ActionRunCommand: 3, models.ActionWriteFile: 2, models.ActionReadFile: 2, models.ActionEditFile: 1,
	}
	for k, v := range wantWin {
		if win.byAction[k] != v {
			t.Errorf("windows action %s = %d, want %d", k, win.byAction[k], v)
		}
	}

	lin := tally(res, linSession)
	if lin.prompts != 1 || lin.texts != 2 || lin.calls != 7 || lin.tokens != 7 || lin.starts != 1 {
		t.Errorf("linux session counts = %+v, want prompts 1, texts 2, calls 7, tokens 7, one session_start", lin)
	}
	if lin.byAction[models.ActionEditFile] != 2 { // str_replace + remove
		t.Errorf("linux edit_file = %d, want 2", lin.byAction[models.ActionEditFile])
	}
}

func TestParseFixtureEventShape(t *testing.T) {
	res := parseFixture(t, 0)
	seen := map[string]bool{}
	for _, ev := range res.ToolEvents {
		if ev.Tool != models.ToolStakpak {
			t.Errorf("Tool = %q", ev.Tool)
		}
		if ev.SourceFile != fixtureDB {
			t.Errorf("SourceFile = %q, want %q", ev.SourceFile, fixtureDB)
		}
		if seen[ev.SourceEventID] {
			t.Errorf("duplicate SourceEventID %q", ev.SourceEventID)
		}
		seen[ev.SourceEventID] = true
		if ev.Timestamp.IsZero() {
			t.Errorf("zero timestamp on %q", ev.SourceEventID)
		}
		if ev.Model != "" {
			t.Errorf("Model = %q on %q: the store records no model", ev.Model, ev.SourceEventID)
		}
		if strings.HasPrefix(ev.RawToolName, toolNamespace) {
			t.Errorf("RawToolName %q kept the stakpak__ namespace", ev.RawToolName)
		}
		if strings.Contains(ev.Target, localContextTag) {
			t.Errorf("target of %q leaked the <local_context> block", ev.SourceEventID)
		}
	}
	for _, tk := range res.TokenEvents {
		if seen[tk.SourceEventID] {
			t.Errorf("token SourceEventID %q collides with a tool event", tk.SourceEventID)
		}
		seen[tk.SourceEventID] = true
		if tk.Tool != models.ToolStakpak || tk.Source != models.TokenSourceJSONL {
			t.Errorf("token tool/source = %q/%q", tk.Tool, tk.Source)
		}
		if tk.MessageID == "" || tk.InputTokens <= 0 || tk.OutputTokens <= 0 {
			t.Errorf("token row incomplete: %+v", tk)
		}
		if tk.CacheReadTokens != 0 || tk.CacheCreationTokens != 0 {
			t.Errorf("no cache split in live data, got %+v", tk)
		}
	}
}

// TestParseFixtureProjectRoot pins that the raw cwd of each session is the
// project root, passed through the same translate+stat gate the adapter uses
// (so the expectation holds on Windows, Linux and macOS test hosts).
func TestParseFixtureProjectRoot(t *testing.T) {
	res := parseFixture(t, 0)
	want := map[string]string{
		winSession: crossmount.TranslateForeignPath(`C:\Users\user\project`),
		linSession: crossmount.TranslateForeignPath("/home/user/project"),
	}
	for _, ev := range res.ToolEvents {
		if ev.ProjectRoot != want[ev.SessionID] {
			t.Errorf("%s ProjectRoot = %q, want %q", ev.SourceEventID, ev.ProjectRoot, want[ev.SessionID])
		}
	}
}

func eventByRaw(t *testing.T, res adapter.ParseResult, session, raw string) []models.ToolEvent {
	t.Helper()
	var out []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.SessionID == session && ev.RawToolName == raw {
			out = append(out, ev)
		}
	}
	return out
}

func TestParseFixtureOutcomes(t *testing.T) {
	res := parseFixture(t, 0)

	// Windows: the first create was cancelled (TOOL_CALL_CANCELLED), the
	// second succeeded.
	creates := eventByRaw(t, res, winSession, "create")
	if len(creates) != 2 {
		t.Fatalf("windows create events = %d, want 2", len(creates))
	}
	if creates[0].Success || !strings.Contains(creates[0].ErrorMessage, "cancelled") {
		t.Errorf("first create should be a cancelled failure: %+v", creates[0])
	}
	if !creates[1].Success || creates[1].ToolOutput == "" || creates[1].OutcomePending {
		t.Errorf("second create should be a paired success: %+v", creates[1])
	}
	if creates[1].ContentBytes != int64(len(`print("Hello, Stackpack!")`+"\n")) {
		t.Errorf("create ContentBytes = %d", creates[1].ContentBytes)
	}
	if creates[1].ActionType != models.ActionWriteFile || !strings.HasSuffix(creates[1].Target, "hello_world.py") {
		t.Errorf("create mapped as %s -> %q", creates[1].ActionType, creates[1].Target)
	}

	// Linux: the `ls` after the delete returned COMMAND_FAILED.
	var failed []models.ToolEvent
	for _, ev := range eventByRaw(t, res, linSession, "run_command") {
		if !ev.Success {
			failed = append(failed, ev)
		}
	}
	if len(failed) != 1 || !strings.Contains(failed[0].Target, "ls -la") || failed[0].ErrorMessage == "" {
		t.Errorf("linux COMMAND_FAILED not captured as one failure: %+v", failed)
	}

	// The last Linux call has no result in the fixture: optimistic + pending.
	runs := eventByRaw(t, res, linSession, "run_command")
	last := runs[len(runs)-1]
	if !last.OutcomePending || !last.Success {
		t.Errorf("unresolved last call should be pending/optimistic: %+v", last)
	}

	// All Windows calls except possibly the trailing ones resolve.
	for _, ev := range res.ToolEvents {
		if ev.SessionID == winSession && ev.ActionType != models.ActionUserPrompt &&
			ev.ActionType != models.ActionAssistantMessage && ev.OutcomePending {
			t.Errorf("windows call %s unexpectedly pending", ev.SourceEventID)
		}
	}
}

func TestUserPromptStripsLocalContext(t *testing.T) {
	res := parseFixture(t, 0)
	var first *models.ToolEvent
	for i, ev := range res.ToolEvents {
		if ev.SessionID == winSession && ev.ActionType == models.ActionUserPrompt {
			first = &res.ToolEvents[i]
			break
		}
	}
	if first == nil {
		t.Fatal("no windows user prompt")
	}
	if first.Target != "1. Create a new Python hello world file and execute it." {
		t.Errorf("prompt target = %q", first.Target)
	}
}

// TestParseFixtureTokens pins the per-call usage rows against the live
// usage numbers of the Windows session (prompt_tokens as plain input).
func TestParseFixtureTokens(t *testing.T) {
	res := parseFixture(t, 0)
	var win []models.TokenEvent
	for _, tk := range res.TokenEvents {
		if tk.SessionID == winSession {
			win = append(win, tk)
		}
	}
	wantIn := []int64{16344, 16478, 16848, 16962, 17043, 17218, 17470}
	wantOut := []int64{64, 200, 376, 61, 47, 140, 181}
	if len(win) != len(wantIn) {
		t.Fatalf("windows token rows = %d, want %d", len(win), len(wantIn))
	}
	for i, tk := range win {
		if tk.InputTokens != wantIn[i] || tk.OutputTokens != wantOut[i] {
			t.Errorf("row %d = %d/%d, want %d/%d", i, tk.InputTokens, tk.OutputTokens, wantIn[i], wantOut[i])
		}
		if !strings.HasPrefix(tk.SourceEventID, "tokens:00000000-0000-4000-8000-") {
			t.Errorf("row %d SourceEventID = %q", i, tk.SourceEventID)
		}
	}
	// Token rows pair with the action MessageID of the same checkpoint.
	for _, ev := range res.ToolEvents {
		if ev.SessionID != winSession || ev.RawToolName != "view" {
			continue
		}
		found := false
		for _, tk := range win {
			if tk.MessageID == ev.MessageID {
				found = true
			}
		}
		if !found {
			t.Errorf("view call %s MessageID %q matches no token row", ev.SourceEventID, ev.MessageID)
		}
	}
}

func TestParseWatermarkNoAdvance(t *testing.T) {
	res := parseFixture(t, 16)
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 || res.NewOffset != 16 {
		t.Errorf("at-watermark parse should be empty: %+v", res)
	}
	res = parseFixture(t, 9999)
	if len(res.ToolEvents) != 0 || res.NewOffset != 16 {
		t.Errorf("past-watermark parse should be empty with NewOffset=MAX: %+v", res)
	}
}

// TestParseWindowsCompose proves the incremental contract: parsing a store
// in two windows yields exactly the one-shot parse's events, and a tool
// result that lands in the second window for a call persisted by the first
// comes back as an ActionOutcomeUpdate keyed like the call.
func TestParseWindowsCompose(t *testing.T) {
	full := parseFixture(t, 0)

	// Window 1: only the first 4 Windows checkpoints exist.
	dbPath := filepath.Join(t.TempDir(), ".stakpak", "data", "local.db")
	root := filepath.Dir(dbPath)
	rebuildFixture(t, dbPath, 4)
	a := NewWithOptions(nil, []string{root})
	w1, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if w1.NewOffset != 4 {
		t.Fatalf("window 1 NewOffset = %d, want 4", w1.NewOffset)
	}
	// Window 2: the whole store, from the first window's watermark.
	rebuildFixture(t, dbPath, 0)
	w2, err := a.ParseSessionFile(context.Background(), dbPath, w1.NewOffset)
	if err != nil {
		t.Fatal(err)
	}

	ids := func(r adapter.ParseResult) map[string]bool {
		m := map[string]bool{}
		for _, ev := range r.ToolEvents {
			m[ev.SourceEventID] = true
		}
		for _, tk := range r.TokenEvents {
			m[tk.SourceEventID] = true
		}
		return m
	}
	w1ids, w2ids, fullIDs := ids(w1), ids(w2), ids(full)
	for id := range w1ids {
		if w2ids[id] {
			t.Errorf("event %q emitted by BOTH windows", id)
		}
	}
	union := map[string]bool{}
	for id := range w1ids {
		union[id] = true
	}
	for id := range w2ids {
		union[id] = true
	}
	for id := range fullIDs {
		if !union[id] {
			t.Errorf("event %q missing from the two-window union", id)
		}
	}
	if len(union) != len(fullIDs) {
		t.Errorf("two-window union has %d ids, one-shot parse %d", len(union), len(fullIDs))
	}

	// Window 1 ends with a call whose result is in window 2.
	pending := map[string]bool{}
	for _, ev := range w1.ToolEvents {
		if ev.OutcomePending {
			pending[ev.SourceEventID] = true
		}
	}
	if len(pending) == 0 {
		t.Fatal("window 1 should end with at least one pending call")
	}
	updated := map[string]bool{}
	for _, u := range w2.OutcomeUpdates {
		if !u.SuccessKnown {
			t.Errorf("outcome update without a verdict: %+v", u)
		}
		updated[u.SourceEventID] = true
		if u.SourceFile != dbPath {
			t.Errorf("outcome update SourceFile = %q", u.SourceFile)
		}
	}
	for id := range pending {
		if !updated[id] {
			t.Errorf("pending call %q got no OutcomeUpdate in window 2", id)
		}
	}
}

func TestScrubbedToolInput(t *testing.T) {
	dbPath, root := emptyStore(t)
	addSession(t, dbPath, "s1", "")
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	addCheckpoint(t, dbPath, "c1", "s1", "", "2026-10-21T07:00:00.000000000+00:00", stateJSON(
		`{"role":"user","content":"deploy"}`,
		`{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"stakpak__run_command","arguments":"{\"command\":\"echo `+secret+`\"}"}}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`,
	))
	a := NewWithOptions(scrub.New(), []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range res.ToolEvents {
		if strings.Contains(ev.RawToolInput, secret) || strings.Contains(ev.ToolOutput, secret) {
			t.Errorf("secret survived scrubbing in %s: %q", ev.SourceEventID, ev.RawToolInput)
		}
	}
	// An empty cwd falls back to the synthetic placeholder.
	for _, ev := range res.ToolEvents {
		if ev.ProjectRoot != "[stakpak]" {
			t.Errorf("ProjectRoot = %q, want [stakpak]", ev.ProjectRoot)
		}
	}
}

func TestParseMissingTablesAndMalformedState(t *testing.T) {
	dbPath, root := emptyStore(t)
	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil || res.NewOffset != 0 || len(res.ToolEvents) != 0 {
		t.Fatalf("empty store: res=%+v err=%v", res, err)
	}

	addSession(t, dbPath, "s1", "")
	addCheckpoint(t, dbPath, "bad", "s1", "", "2026-10-21T07:00:00+00:00", `{not json`)
	addCheckpoint(t, dbPath, "ok", "s1", "bad", "2026-10-21T07:00:01+00:00", stateJSON(`{"role":"user","content":"hi"}`))
	res, err = a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "malformed state") {
		t.Errorf("warnings = %v, want one malformed-state warning", res.Warnings)
	}
	// The malformed parent is not valid JSON, so its length is unknown and
	// the child's messages all count as new.
	var prompts int
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt {
			prompts++
		}
	}
	if prompts != 1 {
		t.Errorf("events = %+v, want the child's one user prompt", res.ToolEvents)
	}
}

func TestParseContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := NewWithOptions(nil, []string{fixtureRoot})
	if _, err := a.ParseSessionFile(ctx, fixtureDB, 0); err == nil {
		t.Error("cancelled context should surface an error")
	}
}

func TestParseTimeAndHelpers(t *testing.T) {
	got := parseTime("2026-10-21T07:10:33.847876800+00:00")
	want := time.Date(2026, 10, 21, 7, 10, 33, 847876800, time.UTC)
	if !got.Equal(want) {
		t.Errorf("parseTime = %v, want %v", got, want)
	}
	if !parseTime("").IsZero() || !parseTime("garbage").IsZero() {
		t.Error("empty/garbage must be the zero time")
	}
	if got := truncate("abcdef", 3); got != "abc" {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate("abc", 0); got != "abc" {
		t.Errorf("truncate n=0 = %q", got)
	}
	if got := firstNonEmpty("", "  ", "x", "y"); got != "x" {
		t.Errorf("firstNonEmpty = %q", got)
	}
}

// TestParseUnreadableStoreErrors: a file that is not a SQLite database must
// surface an error rather than read as an empty store (which would advance
// the cursor over data that was never seen).
func TestParseUnreadableStoreErrors(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".stakpak", "data")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(root, "local.db")
	if err := os.WriteFile(bad, []byte(strings.Repeat("not a database ", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, []string{root})
	if res, err := a.ParseSessionFile(context.Background(), bad, 0); err == nil {
		t.Errorf("garbage store parsed without error: %+v", res)
	}
}

// TestReparseIsDeterministic: two parses of the same store emit the same
// events in the same order with the same SourceEventIDs (audit Check 3).
func TestReparseIsDeterministic(t *testing.T) {
	a, b := parseFixture(t, 0), parseFixture(t, 0)
	if len(a.ToolEvents) != len(b.ToolEvents) || len(a.TokenEvents) != len(b.TokenEvents) {
		t.Fatalf("event counts differ between parses: %d/%d vs %d/%d",
			len(a.ToolEvents), len(a.TokenEvents), len(b.ToolEvents), len(b.TokenEvents))
	}
	for i := range a.ToolEvents {
		if a.ToolEvents[i].SourceEventID != b.ToolEvents[i].SourceEventID || a.ToolEvents[i].Success != b.ToolEvents[i].Success {
			t.Errorf("tool event %d differs: %+v vs %+v", i, a.ToolEvents[i], b.ToolEvents[i])
		}
	}
	for i := range a.TokenEvents {
		if a.TokenEvents[i].SourceEventID != b.TokenEvents[i].SourceEventID {
			t.Errorf("token event %d differs", i)
		}
	}
}
