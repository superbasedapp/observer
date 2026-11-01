package autohand

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

const (
	winSession   = "aaaaaaaa-1111-4222-8333-444444444444-1792553743146"
	winPartial   = "cccccccc-1111-4222-8333-444444444444-1792552793812"
	linuxSession = "bbbbbbbb-1111-4222-8333-444444444444-1792552680220"
	// linuxHookBlocked: a shell call blocked by Observer's pre-tool hook
	// (live E2E 2026-10-22, WSL).
	linuxHookBlocked = "dddddddd-1111-4222-8333-444444444444-1792669417085"
	// linuxAbandoned: a session that never saved a message (2026-10-22 WSL).
	linuxAbandoned = "99999999-1111-4222-8333-444444444444-1792667111552"
)

func fixtureRoot(t *testing.T, osName string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "testdata", "autohand", osName, "sessions"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("fixture root missing: %v", err)
	}
	return root
}

func parseFixture(t *testing.T, osName, session, file string) adapter.ParseResult {
	t.Helper()
	root := fixtureRoot(t, osName)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), filepath.Join(root, session, file), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res
}

func countAction(evs []models.ToolEvent, action string) int {
	n := 0
	for _, e := range evs {
		if e.ActionType == action {
			n++
		}
	}
	return n
}

func TestNameAndRoots(t *testing.T) {
	a := NewWithOptions(nil, "/x/sessions")
	if a.Name() != models.ToolAutohand {
		t.Fatalf("Name = %q", a.Name())
	}
	if got := a.WatchPaths(); len(got) != 1 || got[0] != "/x/sessions" {
		t.Fatalf("WatchPaths = %v", got)
	}
	for _, r := range New().WatchPaths() {
		if !strings.HasSuffix(filepath.ToSlash(r), ".autohand/sessions") {
			t.Errorf("default root %q does not end in .autohand/sessions", r)
		}
	}
}

func TestIsSessionFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sessions")
	a := NewWithOptions(nil, root)
	id := "u-1"
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"conversation", filepath.Join(root, id, "conversation.jsonl"), true},
		{"metadata", filepath.Join(root, id, "metadata.json"), true},
		{"index", filepath.Join(root, "index.json"), false},
		{"state sidecar", filepath.Join(root, id, "state.json"), false},
		{"index lock", filepath.Join(root, "index.json.lock"), false},
		{"too deep", filepath.Join(root, id, "sub", "conversation.jsonl"), false},
		{"outside root", filepath.Join(t.TempDir(), "sessions", id, "conversation.jsonl"), false},
		{"wrong parent dir", filepath.Join(root, "..", "other", id, "conversation.jsonl"), false},
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
	a := NewWithOptions(nil, "/x/sessions")
	conv := a.CursorSemanticsFor("/x/sessions/s/conversation.jsonl")
	if conv.Kind != adapter.CursorByteOffset || !conv.StreamsFromCursor || !conv.ActionsExpected() {
		t.Errorf("conversation semantics = %+v", conv)
	}
	meta := a.CursorSemanticsFor("/x/sessions/s/metadata.json")
	if meta.Kind != adapter.CursorNoActions || meta.ActionsExpected() {
		t.Errorf("metadata semantics = %+v", meta)
	}
}

func TestParseWindowsSession(t *testing.T) {
	res := parseFixture(t, "windows", winSession, "conversation.jsonl")
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	if got := countAction(res.ToolEvents, models.ActionUserPrompt); got != 1 {
		t.Errorf("user prompts = %d, want 1", got)
	}
	// 10 of the 11 assistant lines carry prose; one is tool calls only.
	if got := countAction(res.ToolEvents, models.ActionAssistantMessage); got != 10 {
		t.Errorf("assistant messages = %d, want 10", got)
	}
	byRaw := map[string]int{}
	for _, e := range res.ToolEvents {
		if e.RawToolName != "" && !strings.HasPrefix(e.RawToolName, "autohand.") {
			byRaw[e.RawToolName]++
		}
	}
	wantRaw := map[string]int{
		"git_status": 1, "list_tree": 2, "todo_write": 4, "run_command": 3,
		"write_file": 1, "shell": 2, "search_replace": 1, "delete_path": 1,
	}
	for k, v := range wantRaw {
		if byRaw[k] != v {
			t.Errorf("raw tool %s = %d, want %d (all: %v)", k, byRaw[k], v, byRaw)
		}
	}
	for _, e := range res.ToolEvents {
		if e.SessionID != winSession {
			t.Fatalf("SessionID = %q", e.SessionID)
		}
		if e.Tool != models.ToolAutohand {
			t.Fatalf("Tool = %q", e.Tool)
		}
		if e.Model != "minimax/minimax-m3.1-flash:free" {
			t.Fatalf("Model = %q", e.Model)
		}
		if e.ProjectRoot != `C:\Users\user\proj` && e.ProjectRoot != "/mnt/c/Users/user/proj" {
			t.Fatalf("ProjectRoot = %q", e.ProjectRoot)
		}
		if e.Timestamp.IsZero() {
			t.Fatalf("zero timestamp on %s", e.SourceEventID)
		}
		if strings.ContainsRune(e.ToolOutput, 0x1b) {
			t.Errorf("ANSI escape survived in output of %s", e.SourceEventID)
		}
	}

	var writeEv, editEv, delEv *models.ToolEvent
	for i := range res.ToolEvents {
		switch res.ToolEvents[i].RawToolName {
		case "write_file":
			writeEv = &res.ToolEvents[i]
		case "search_replace":
			editEv = &res.ToolEvents[i]
		case "delete_path":
			delEv = &res.ToolEvents[i]
		}
	}
	if writeEv == nil || writeEv.ActionType != models.ActionWriteFile || writeEv.Target != "hello_world.py" {
		t.Errorf("write_file event = %+v", writeEv)
	} else if writeEv.ContentBytes != int64(len("print(\"hello world\")\n")) {
		t.Errorf("write_file ContentBytes = %d", writeEv.ContentBytes)
	}
	if editEv == nil || editEv.ActionType != models.ActionEditFile {
		t.Errorf("search_replace event = %+v", editEv)
	} else if editEv.ContentBytes != int64(len("print(\"hello autohand\")\n")) {
		t.Errorf("search_replace ContentBytes = %d", editEv.ContentBytes)
	}
	if delEv == nil || delEv.ActionType != models.ActionEditFile || !delEv.Success {
		t.Errorf("delete_path event = %+v", delEv)
	}
	if len(res.OutcomeUpdates) != 0 {
		t.Errorf("whole-file parse emitted %d outcome updates", len(res.OutcomeUpdates))
	}

	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events = %d, want 1", len(res.TokenEvents))
	}
	tk := res.TokenEvents[0]
	if tk.SourceEventID != "tokens:session:"+winSession || tk.SessionID != winSession {
		t.Errorf("token ids = %q / %q", tk.SourceEventID, tk.SessionID)
	}
	// promptTokens 198106 is GROSS of cacheRead 108832.
	if tk.InputTokens != 198106-108832 || tk.OutputTokens != 2420 || tk.CacheReadTokens != 108832 || tk.CacheCreationTokens != 0 {
		t.Errorf("tokens = in %d out %d cr %d cw %d", tk.InputTokens, tk.OutputTokens, tk.CacheReadTokens, tk.CacheCreationTokens)
	}
	if tk.Reliability != models.ReliabilityApproximate || tk.Source != models.TokenSourceJSONL {
		t.Errorf("source/reliability = %s/%s", tk.Source, tk.Reliability)
	}
	if tk.Model != "minimax/minimax-m3.1-flash:free" {
		t.Errorf("token model = %q", tk.Model)
	}
	wantTS := time.Date(2026, 10, 21, 3, 37, 31, 491_000_000, time.UTC)
	if !tk.Timestamp.Equal(wantTS) {
		t.Errorf("token timestamp = %v, want %v", tk.Timestamp, wantTS)
	}

	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].Surface != models.SurfaceCLI ||
		res.SessionSurfaces[0].SurfaceHost != "autohand" || res.SessionSurfaces[0].SessionID != winSession {
		t.Errorf("surfaces = %+v", res.SessionSurfaces)
	}
	if len(res.SessionLineages) != 0 {
		t.Errorf("lineages = %+v", res.SessionLineages)
	}
	info, _ := os.Stat(filepath.Join(fixtureRoot(t, "windows"), winSession, "conversation.jsonl"))
	if res.NewOffset != info.Size() {
		t.Errorf("NewOffset = %d, want %d", res.NewOffset, info.Size())
	}
}

func TestParseLinuxSession(t *testing.T) {
	res := parseFixture(t, "linux", linuxSession, "conversation.jsonl")
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	// The operator typed the same prompt three times at distinct instants
	// (1 + 3 = 4 user lines): each is its own row.
	if got := countAction(res.ToolEvents, models.ActionUserPrompt); got != 4 {
		t.Errorf("user prompts = %d, want 4", got)
	}
	seen := map[string]bool{}
	for _, e := range res.ToolEvents {
		if seen[e.SourceEventID] {
			t.Errorf("duplicate SourceEventID %q", e.SourceEventID)
		}
		seen[e.SourceEventID] = true
		if e.ProjectRoot != "/home/user/proj" {
			t.Fatalf("ProjectRoot = %q", e.ProjectRoot)
		}
	}
	// A shell command that exited non-zero is a failed action.
	var failed *models.ToolEvent
	for i := range res.ToolEvents {
		if !res.ToolEvents[i].Success {
			failed = &res.ToolEvents[i]
		}
	}
	if failed == nil || failed.RawToolName != "run_command" || !strings.HasPrefix(failed.ErrorMessage, "Command exited with code 2") {
		t.Errorf("failed event = %+v", failed)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events = %d", len(res.TokenEvents))
	}
	tk := res.TokenEvents[0]
	if tk.InputTokens != 300986-165425 || tk.OutputTokens != 2490 || tk.CacheReadTokens != 165425 {
		t.Errorf("tokens = in %d out %d cr %d", tk.InputTokens, tk.OutputTokens, tk.CacheReadTokens)
	}
	// tokenUsageStatus "unavailable" => the counts are a lower bound.
	if tk.Reliability != models.ReliabilityUnreliable {
		t.Errorf("reliability = %s, want unreliable", tk.Reliability)
	}
	if tk.Model != "fantail" {
		t.Errorf("model = %q", tk.Model)
	}
}

// TestHookBlockedShellCallIsFailed: a shell call a pre-tool hook blocked
// (Observer's own guard, live 2026-10-22 on WSL) is saved with the hook's
// bare reason as its content and no success flag; it must read as a failed
// action carrying that reason.
func TestHookBlockedShellCallIsFailed(t *testing.T) {
	res := parseFixture(t, "linux", linuxHookBlocked, "conversation.jsonl")
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	var shell *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].RawToolName == "shell" {
			shell = &res.ToolEvents[i]
		}
	}
	if shell == nil {
		t.Fatalf("no shell event in %+v", res.ToolEvents)
	}
	if shell.Success || shell.ActionType != models.ActionRunCommand || shell.Target != "echo observer-e2e-forbidden" ||
		!strings.HasPrefix(shell.ErrorMessage, "user rule U-901:") {
		t.Errorf("shell event = success %v action %q target %q error %q", shell.Success, shell.ActionType, shell.Target, shell.ErrorMessage)
	}
	if got := countAction(res.ToolEvents, models.ActionAssistantMessage); got != 1 {
		t.Errorf("assistant messages = %d, want 1", got)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events = %d", len(res.TokenEvents))
	}
	if tk := res.TokenEvents[0]; tk.InputTokens != 28825-314 || tk.OutputTokens != 203 || tk.CacheReadTokens != 314 ||
		tk.Reliability != models.ReliabilityApproximate {
		t.Errorf("tokens = %+v", tk)
	}
}

// TestHookBlockedResultInLaterWindow: the same block resolved through an
// OutcomeUpdate (the call parsed in an earlier window) is a failure too.
func TestHookBlockedResultInLaterWindow(t *testing.T) {
	root := fixtureRoot(t, "linux")
	path := filepath.Join(root, linuxHookBlocked, "conversation.jsonl")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(body), "\n")
	cut := int64(len(lines[0]) + len(lines[1])) // user + the shell call
	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), path, cut)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.OutcomeUpdates) != 1 {
		t.Fatalf("outcome updates = %+v", res.OutcomeUpdates)
	}
	if u := res.OutcomeUpdates[0]; !u.SuccessKnown || u.Success || !strings.HasPrefix(u.ErrorMessage, "user rule U-901:") {
		t.Errorf("outcome = %+v", u)
	}
}

// TestAbandonedSessionMetadataOnly: the WSL sessions of 2026-10-22 that never
// saved a message (metadata.json only: status "active", messageCount 0, an
// auto title, no usage, no conversation.jsonl) parse cleanly to nothing.
func TestAbandonedSessionMetadataOnly(t *testing.T) {
	res := parseFixture(t, "linux", linuxAbandoned, "metadata.json")
	if len(res.Warnings) != 0 || len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 || len(res.OutcomeUpdates) != 0 || res.RetrySuggested {
		t.Errorf("abandoned session parse = %+v", res)
	}
	if res.NewOffset == 0 {
		t.Errorf("metadata cursor did not advance")
	}
}

func TestMetadataFileYieldsTokensOnly(t *testing.T) {
	res := parseFixture(t, "windows", winSession, "metadata.json")
	if len(res.ToolEvents) != 0 || len(res.OutcomeUpdates) != 0 {
		t.Fatalf("metadata parse emitted actions: %d/%d", len(res.ToolEvents), len(res.OutcomeUpdates))
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events = %d", len(res.TokenEvents))
	}
	conv := parseFixture(t, "windows", winSession, "conversation.jsonl")
	a, b := res.TokenEvents[0], conv.TokenEvents[0]
	// Both file roles must land the same logical row so the store dedups.
	if a.SourceFile != b.SourceFile || a.SourceEventID != b.SourceEventID ||
		a.InputTokens != b.InputTokens || a.OutputTokens != b.OutputTokens {
		t.Errorf("token rows differ:\n%+v\n%+v", a, b)
	}
	if filepath.Base(a.SourceFile) != "conversation.jsonl" {
		t.Errorf("token SourceFile = %q", a.SourceFile)
	}
	if len(res.SessionSurfaces) != 1 {
		t.Errorf("surfaces = %+v", res.SessionSurfaces)
	}
}

func TestParseIsIdempotent(t *testing.T) {
	a := parseFixture(t, "windows", winSession, "conversation.jsonl")
	b := parseFixture(t, "windows", winSession, "conversation.jsonl")
	if len(a.ToolEvents) != len(b.ToolEvents) {
		t.Fatalf("event counts differ: %d vs %d", len(a.ToolEvents), len(b.ToolEvents))
	}
	for i := range a.ToolEvents {
		if a.ToolEvents[i].SourceEventID != b.ToolEvents[i].SourceEventID {
			t.Errorf("event %d id %q != %q", i, a.ToolEvents[i].SourceEventID, b.ToolEvents[i].SourceEventID)
		}
	}
}

// sessionCopy copies a fixture session into a temp sessions root and returns
// (adapter, conversation path, sessions root).
func sessionCopy(t *testing.T, osName, session string) (*Adapter, string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "sessions")
	dir := filepath.Join(root, session)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(fixtureRoot(t, osName), session)
	for _, f := range []string{"conversation.jsonl", "metadata.json"} {
		data, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return NewWithOptions(nil, root), filepath.Join(dir, "conversation.jsonl"), root
}

// lineOffsets returns the byte offset just past each line of data.
func lineOffsets(data []byte) []int64 {
	var out []int64
	for i, b := range data {
		if b == '\n' {
			out = append(out, int64(i+1))
		}
	}
	return out
}

func TestIncrementalParseAndCrossWindowOutcomes(t *testing.T) {
	a, conv, _ := sessionCopy(t, "windows", winSession)
	data, err := os.ReadFile(conv)
	if err != nil {
		t.Fatal(err)
	}
	full, err := a.ParseSessionFile(context.Background(), conv, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Split right after the 5th line: line 5 is an assistant line whose
	// tool calls' results land in the second window.
	offs := lineOffsets(data)
	split := offs[7] // after the todo_write assistant line and its run_command call
	if err := os.WriteFile(conv, data[:split], 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := a.ParseSessionFile(context.Background(), conv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.NewOffset != split {
		t.Fatalf("first NewOffset = %d, want %d", first.NewOffset, split)
	}
	if err := os.WriteFile(conv, data, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(context.Background(), conv, first.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if second.NewOffset != int64(len(data)) {
		t.Fatalf("second NewOffset = %d, want %d", second.NewOffset, len(data))
	}

	ids := map[string]int{}
	for _, e := range append(append([]models.ToolEvent{}, first.ToolEvents...), second.ToolEvents...) {
		ids[e.SourceEventID]++
	}
	if len(ids) != len(full.ToolEvents) {
		t.Errorf("windows produced %d distinct events, whole parse %d", len(ids), len(full.ToolEvents))
	}
	for id, n := range ids {
		if n != 1 {
			t.Errorf("event %q emitted %d times across windows", id, n)
		}
	}
	// The first window ended with unanswered calls; their results reach the
	// store as outcome updates keyed by the call-id event id.
	if len(second.OutcomeUpdates) == 0 {
		t.Fatal("expected cross-window outcome updates in the second window")
	}
	for _, u := range second.OutcomeUpdates {
		if !u.SuccessKnown || !strings.HasPrefix(u.SourceEventID, "tool:"+winSession+":") || u.SourceFile != conv {
			t.Errorf("bad outcome update %+v", u)
		}
		if ids[u.SourceEventID] != 1 {
			t.Errorf("outcome update %q targets an event no window emitted", u.SourceEventID)
		}
	}
}

func TestPartialTrailingLineIsDeferred(t *testing.T) {
	a, conv, _ := sessionCopy(t, "windows", winSession)
	data, _ := os.ReadFile(conv)
	offs := lineOffsets(data)
	cut := offs[2] + 25 // mid-way into line 4
	if err := os.WriteFile(conv, data[:cut], 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), conv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != offs[2] {
		t.Errorf("NewOffset = %d, want %d (before the partial line)", res.NewOffset, offs[2])
	}
}

func TestMalformedLineSkippedAndAdvanced(t *testing.T) {
	a, conv, _ := sessionCopy(t, "windows", winSession)
	body := "not json\n" + `{"role":"user","content":"hi","timestamp":"2026-10-21T03:36:55.352Z"}` + "\n"
	if err := os.WriteFile(conv, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), conv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != int64(len(body)) {
		t.Errorf("NewOffset = %d, want %d", res.NewOffset, len(body))
	}
	if len(res.Warnings) != 1 || countAction(res.ToolEvents, models.ActionUserPrompt) != 1 {
		t.Errorf("warnings=%v events=%d", res.Warnings, len(res.ToolEvents))
	}
}

func TestTruncatedRewriteRestartsFromZero(t *testing.T) {
	a, conv, _ := sessionCopy(t, "windows", winSession)
	body := `{"role":"user","content":"hi","timestamp":"2026-10-21T03:36:55.352Z"}` + "\n"
	if err := os.WriteFile(conv, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), conv, 999999)
	if err != nil {
		t.Fatal(err)
	}
	if countAction(res.ToolEvents, models.ActionUserPrompt) != 1 || res.NewOffset != int64(len(body)) {
		t.Errorf("events=%d offset=%d", len(res.ToolEvents), res.NewOffset)
	}
}

func TestStreamChunksAndInjectedContextSkipped(t *testing.T) {
	a, conv, _ := sessionCopy(t, "windows", winSession)
	lines := []string{
		`{"role":"user","content":"real prompt","timestamp":"2026-10-21T03:36:55.352Z"}`,
		`{"role":"user","content":"peer context","timestamp":"2026-10-21T03:36:56.000Z","_meta":{"peerContext":{"version":1}}}`,
		`{"role":"assistant","content":"","timestamp":"2026-10-21T03:36:57.000Z","toolCalls":[{"id":"c1","tool":"shell","args":{"command":"echo hi"}}]}`,
		`{"role":"tool","content":"partial","name":"shell","timestamp":"2026-10-21T03:36:57.100Z","tool_call_id":"c1","_meta":{"stream":"stdout"}}`,
		`{"role":"tool","content":"$ x\n> echo hi\nhi\n","name":"shell","timestamp":"2026-10-21T03:36:58.000Z","tool_call_id":"c1"}`,
	}
	if err := os.WriteFile(conv, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), conv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := countAction(res.ToolEvents, models.ActionUserPrompt); got != 1 {
		t.Errorf("user prompts = %d, want 1 (peer context must be skipped)", got)
	}
	var shell *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].RawToolName == "shell" {
			shell = &res.ToolEvents[i]
		}
	}
	if shell == nil || !strings.Contains(shell.ToolOutput, "hi") || strings.Contains(shell.ToolOutput, "partial") {
		t.Errorf("shell event = %+v", shell)
	}
	if shell != nil && shell.Target != "echo hi" {
		t.Errorf("shell target = %q", shell.Target)
	}
}

func TestToolWithoutCallID(t *testing.T) {
	a, conv, _ := sessionCopy(t, "windows", winSession)
	lines := []string{
		`{"role":"assistant","content":"","timestamp":"2026-10-21T03:36:57.000Z","toolCalls":[{"tool":"read_file","args":{"path":"a.go"}},{"tool":"read_file","args":{"path":"b.go"}}]}`,
	}
	if err := os.WriteFile(conv, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), conv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) != 2 || res.ToolEvents[0].SourceEventID == res.ToolEvents[1].SourceEventID {
		t.Errorf("events = %+v", res.ToolEvents)
	}
}

// writeSession lays out a synthetic session directory.
func writeSession(t *testing.T, root, id string, meta map[string]any, lines []string) string {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mb, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), mb, 0o600); err != nil {
		t.Fatal(err)
	}
	conv := filepath.Join(dir, "conversation.jsonl")
	if err := os.WriteFile(conv, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return conv
}

func TestBranchedSessionSkipsInheritedAndSubtractsUsage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sessions")
	proj := t.TempDir()
	srcID := "src-1700000000000"
	brID := "br-1700000009999"
	srcUsage := map[string]any{
		"promptTokens": 1000, "completionTokens": 100, "totalTokens": 1100,
		"cacheReadTokens": 400, "turnCount": 1, "tokenUsageStatus": "actual",
		"updatedAt": "2026-10-21T01:00:05.000Z",
	}
	writeSession(t, root, srcID, map[string]any{
		"sessionId": srcID, "createdAt": "2026-10-21T01:00:00.000Z", "projectPath": proj,
		"model": "m", "client": "terminal", "usage": srcUsage,
	}, []string{
		`{"role":"user","content":"old prompt","timestamp":"2026-10-21T01:00:01.000Z"}`,
		`{"role":"assistant","content":"old answer","timestamp":"2026-10-21T01:00:04.000Z"}`,
	})
	brUsage := map[string]any{
		"promptTokens": 1800, "completionTokens": 150, "totalTokens": 1950,
		"cacheReadTokens": 900, "turnCount": 2, "tokenUsageStatus": "actual",
		"updatedAt": "2026-10-21T02:00:30.000Z",
	}
	conv := writeSession(t, root, brID, map[string]any{
		"sessionId": brID, "createdAt": "2026-10-21T02:00:00.000Z", "projectPath": proj,
		"model": "m", "client": "terminal", "usage": brUsage,
		"branch": map[string]any{"type": "fork", "sourceSessionId": srcID, "createdAt": "2026-10-21T02:00:00.000Z"},
	}, []string{
		`{"role":"user","content":"old prompt","timestamp":"2026-10-21T01:00:01.000Z"}`,
		`{"role":"assistant","content":"old answer","timestamp":"2026-10-21T01:00:04.000Z"}`,
		`{"role":"user","content":"new prompt","timestamp":"2026-10-21T02:00:10.000Z"}`,
		`{"role":"assistant","content":"new answer","timestamp":"2026-10-21T02:00:20.000Z"}`,
	})
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), conv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	if len(res.ToolEvents) != 2 {
		t.Fatalf("events = %d, want 2 (only the post-fork turn): %+v", len(res.ToolEvents), res.ToolEvents)
	}
	for _, e := range res.ToolEvents {
		if !strings.Contains(e.Target, "new") {
			t.Errorf("inherited event leaked: %+v", e)
		}
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("token events = %d", len(res.TokenEvents))
	}
	tk := res.TokenEvents[0]
	// own usage = branch - source: prompt 800, completion 50, cacheRead 500.
	if tk.InputTokens != 800-500 || tk.OutputTokens != 50 || tk.CacheReadTokens != 500 {
		t.Errorf("tokens = in %d out %d cr %d", tk.InputTokens, tk.OutputTokens, tk.CacheReadTokens)
	}
	if len(res.SessionLineages) != 1 || res.SessionLineages[0].ForkedFromID != srcID ||
		res.SessionLineages[0].SessionID != brID || res.SessionLineages[0].ThreadSource != "user" {
		t.Errorf("lineages = %+v", res.SessionLineages)
	}

	// Metadata-file parse agrees.
	mres, err := a.ParseSessionFile(context.Background(), filepath.Join(root, brID, "metadata.json"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(mres.TokenEvents) != 1 || mres.TokenEvents[0].InputTokens != tk.InputTokens {
		t.Errorf("metadata parse token = %+v", mres.TokenEvents)
	}
}

func TestBranchUsageNotSeparable(t *testing.T) {
	proj := t.TempDir()
	cases := []struct {
		name      string
		srcUpdate string // empty => no source session on disk
		brUpdate  string
		wantEvent bool
		wantWarn  bool
	}{
		{"no own turn yet", "2026-10-21T01:00:05.000Z", "2026-10-21T01:00:05.000Z", false, false},
		{"source missing", "", "2026-10-21T02:00:30.000Z", false, true},
		{"source advanced", "2026-10-21T03:00:00.000Z", "2026-10-21T02:00:30.000Z", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "sessions")
			srcID, brID := "src-1", "br-2"
			if tc.srcUpdate != "" {
				writeSession(t, root, srcID, map[string]any{
					"sessionId": srcID, "createdAt": "2026-10-21T01:00:00.000Z", "projectPath": proj,
					"usage": map[string]any{"promptTokens": 10, "completionTokens": 1, "tokenUsageStatus": "actual", "updatedAt": tc.srcUpdate},
				}, []string{`{"role":"user","content":"x","timestamp":"2026-10-21T01:00:01.000Z"}`})
			}
			conv := writeSession(t, root, brID, map[string]any{
				"sessionId": brID, "createdAt": "2026-10-21T02:00:00.000Z", "projectPath": proj,
				"usage":  map[string]any{"promptTokens": 20, "completionTokens": 2, "tokenUsageStatus": "actual", "updatedAt": tc.brUpdate},
				"branch": map[string]any{"type": "clone", "sourceSessionId": srcID, "createdAt": "2026-10-21T02:00:00.000Z"},
			}, []string{`{"role":"user","content":"y","timestamp":"2026-10-21T02:00:10.000Z"}`})
			res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), conv, 0)
			if err != nil {
				t.Fatal(err)
			}
			if (len(res.TokenEvents) == 1) != tc.wantEvent {
				t.Errorf("token events = %d, want event=%v", len(res.TokenEvents), tc.wantEvent)
			}
			if (len(res.Warnings) > 0) != tc.wantWarn {
				t.Errorf("warnings = %v, want warn=%v", res.Warnings, tc.wantWarn)
			}
		})
	}
}

func TestImportedSessionSkipsPreImportMessages(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sessions")
	conv := writeSession(t, root, "imp-1", map[string]any{
		"sessionId": "imp-1", "createdAt": "2026-10-21T05:00:00.000Z", "projectPath": t.TempDir(),
		"importedFrom": map[string]any{"source": "claude", "originalId": "orig", "importedAt": "2026-10-21T05:00:00.000Z"},
	}, []string{
		`{"role":"user","content":"from claude","timestamp":"2026-10-20T10:00:00.000Z"}`,
		`{"role":"user","content":"typed in autohand","timestamp":"2026-10-21T05:10:00.000Z"}`,
	})
	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), conv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) != 1 || !strings.Contains(res.ToolEvents[0].Target, "typed in autohand") {
		t.Errorf("events = %+v", res.ToolEvents)
	}
}

func TestSyncedCopyUnderForeignHomeIsSkipped(t *testing.T) {
	cases := []struct {
		name     string
		fixture  string
		session  string
		homeOS   string
		wantSkip bool
	}{
		{"windows session in windows home", "windows", winSession, crossmount.OSWindows, false},
		{"windows session in linux home", "windows", winSession, crossmount.OSLinux, true},
		{"windows session in darwin home", "windows", winSession, crossmount.OSDarwin, true},
		{"linux session in linux home", "linux", linuxSession, crossmount.OSLinux, false},
		{"linux session in darwin home", "linux", linuxSession, crossmount.OSDarwin, false},
		{"linux session in windows home", "linux", linuxSession, crossmount.OSWindows, true},
		{"unknown home os never filters", "linux", linuxSession, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, conv, root := sessionCopy(t, tc.fixture, tc.session)
			a := newWithSpecs(nil, []rootSpec{{path: root, os: tc.homeOS}})
			for _, file := range []string{"conversation.jsonl", "metadata.json"} {
				p := filepath.Join(filepath.Dir(conv), file)
				res, err := a.ParseSessionFile(context.Background(), p, 0)
				if err != nil {
					t.Fatal(err)
				}
				skipped := len(res.ToolEvents) == 0 && len(res.TokenEvents) == 0
				if skipped != tc.wantSkip {
					t.Errorf("%s: skipped=%v, want %v", file, skipped, tc.wantSkip)
				}
				if tc.wantSkip && file == "conversation.jsonl" {
					if info, _ := os.Stat(p); res.NewOffset != info.Size() {
						t.Errorf("skipped copy NewOffset = %d, want file size %d", res.NewOffset, info.Size())
					}
				}
			}
		})
	}
}

func TestFlexInt(t *testing.T) {
	var u usage
	if err := json.Unmarshal([]byte(`{"promptTokens":12.0,"completionTokens":3,"cacheReadTokens":null,"updatedAt":"x"}`), &u); err != nil {
		t.Fatal(err)
	}
	if u.PromptTokens != 12 || u.CompletionTokens != 3 || u.CacheReadTokens != 0 {
		t.Errorf("usage = %+v", u)
	}
}

func TestTokenNettingClamps(t *testing.T) {
	m := metadata{Model: "m"}
	tk := tokenEvent("f", "s", "r", "", "", m, usage{PromptTokens: 100, CacheReadTokens: 80, CacheWriteTokens: 50, Status: "actual", UpdatedAt: "2026-10-21T00:00:00Z"})
	if tk.InputTokens != 0 {
		t.Errorf("InputTokens = %d, want clamp to 0", tk.InputTokens)
	}
	tk = tokenEvent("f", "s", "r", "", "", m, usage{PromptTokens: 100, CacheReadTokens: 30, CacheWriteTokens: 20, Status: "actual"})
	if tk.InputTokens != 50 || tk.CacheCreationTokens != 20 {
		t.Errorf("in %d cw %d", tk.InputTokens, tk.CacheCreationTokens)
	}
}

func TestNoUsageNoTokenEvent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sessions")
	conv := writeSession(t, root, "s-1", map[string]any{
		"sessionId": "s-1", "createdAt": "2026-10-21T01:00:00.000Z", "projectPath": t.TempDir(),
	}, []string{`{"role":"user","content":"x","timestamp":"2026-10-21T01:00:01.000Z"}`})
	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), conv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.TokenEvents) != 0 || len(res.ToolEvents) != 1 {
		t.Errorf("tokens=%d events=%d", len(res.TokenEvents), len(res.ToolEvents))
	}
}

func TestMissingFilesAreTolerated(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sessions")
	a := NewWithOptions(nil, root)
	for _, f := range []string{"conversation.jsonl", "metadata.json"} {
		res, err := a.ParseSessionFile(context.Background(), filepath.Join(root, "ghost", f), 0)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if len(res.ToolEvents)+len(res.TokenEvents) != 0 {
			t.Errorf("%s: events from a missing file", f)
		}
	}
}

func TestSessionIDPrefersMetadataThenDirName(t *testing.T) {
	if got := sessionIDFor("/r/dirid/conversation.jsonl", metadata{SessionID: "meta"}); got != "meta" {
		t.Errorf("got %q", got)
	}
	if got := sessionIDFor(filepath.Join("r", "dirid", "conversation.jsonl"), metadata{}); got != "dirid" {
		t.Errorf("got %q", got)
	}
}

func TestResolveProjectFallbacks(t *testing.T) {
	if root, _, _ := resolveProject(""); root != noProjectRoot {
		t.Errorf("empty => %q", root)
	}
	// A path that does not exist locally is carried verbatim, never handed to
	// git (which would CWD-prefix a foreign-OS path).
	for _, raw := range []string{`C:\Users\nobody\gone`, "/home/nobody/gone"} {
		root, branch, _ := resolveProject(raw)
		if root != raw && root != "/mnt/c/Users/nobody/gone" {
			t.Errorf("resolveProject(%q) root = %q", raw, root)
		}
		if branch != "" {
			t.Errorf("branch = %q", branch)
		}
	}
	dir := t.TempDir()
	if root, _, _ := resolveProject(dir); filepath.Clean(root) == "" {
		t.Errorf("existing dir resolved to empty root")
	}
}
