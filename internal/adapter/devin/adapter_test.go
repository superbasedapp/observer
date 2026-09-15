package devin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

func mkdirAll(p string) error { return os.MkdirAll(p, 0o755) }

func mustReadFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustWriteFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newTestAdapter() *Adapter {
	// Roots are irrelevant for direct ParseSessionFile calls (the path is
	// passed in), but IsSessionFile needs the fixture's dir as a root.
	return NewWithOptions(nil, []string{filepath.Dir(fixtureDB)})
}

func parseFixture(t *testing.T, from int64) map[string]models.ToolEvent {
	t.Helper()
	a := newTestAdapter()
	res, err := a.ParseSessionFile(context.Background(), fixtureDB, from)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	byID := map[string]models.ToolEvent{}
	for _, e := range res.ToolEvents {
		byID[e.SourceEventID] = e
	}
	return byID
}

func TestName(t *testing.T) {
	if got := (&Adapter{}).Name(); got != models.ToolDevin {
		t.Fatalf("Name() = %q, want %q", got, models.ToolDevin)
	}
}

func TestIsSessionFile(t *testing.T) {
	root := "/home/u/.local/share/devin/cli"
	a := NewWithOptions(nil, []string{root})
	cases := []struct {
		path string
		want bool
	}{
		{filepath.Join(root, "sessions.db"), true},
		{filepath.Join(root, "sessions.db-wal"), true},
		{filepath.Join(root, "sessions.db-shm"), true},
		{filepath.Join(root, "other.db"), false},
		{"/home/u/.local/share/devin/sessions.db", false},   // parent dir not "cli"
		{"/tmp/elsewhere/cli/sessions.db", false},           // not under root
		{filepath.Join(root, "logs", "sessions.db"), false}, // parent dir "logs"
	}
	for _, c := range cases {
		if got := a.IsSessionFile(c.path); got != c.want {
			t.Errorf("IsSessionFile(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestWatchPaths_Windows(t *testing.T) {
	old := allHomesFunc
	defer func() { allHomesFunc = old }()
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: "/home/u", OS: "linux", Origin: "native"},
			{Path: "/mnt/c/Users/dev", OS: crossmount.OSWindows, Origin: "wsl-mnt:c"},
		}
	}
	roots := defaultRoots()
	wantLinux := filepath.Join("/home/u", ".local", "share", "devin", "cli")
	wantWin := filepath.Join("/mnt/c/Users/dev", "AppData", "Roaming", "devin", "cli")
	found := map[string]bool{}
	for _, r := range roots {
		found[r] = true
	}
	if !found[wantLinux] {
		t.Errorf("missing linux root %q in %v", wantLinux, roots)
	}
	if !found[wantWin] {
		t.Errorf("missing windows root %q in %v", wantWin, roots)
	}
}

func TestParse_ActiveChainDedupsRegeneration(t *testing.T) {
	byID := parseFixture(t, 0)

	// The DEAD regeneration branch (node 2, call_dead / a-dead) must NOT
	// appear — only the live chain from main_chain_id=6.
	if _, ok := byID["tool:call_dead"]; ok {
		t.Error("dead-branch tool call was emitted; active-chain walk failed to dedup")
	}
	if _, ok := byID["text:a-dead"]; ok {
		t.Error("dead-branch assistant text was emitted")
	}

	// The live user prompt.
	up, ok := byID["prompt:u-1"]
	if !ok {
		t.Fatal("missing live user prompt")
	}
	if up.ActionType != models.ActionUserPrompt {
		t.Errorf("user prompt action = %q", up.ActionType)
	}
	if up.SessionID != "cobalt-fruit" {
		t.Errorf("session id = %q", up.SessionID)
	}

	// The write tool call: action, target, success, content bytes.
	w, ok := byID["tool:call_write1"]
	if !ok {
		t.Fatal("missing write tool call")
	}
	if w.ActionType != models.ActionWriteFile {
		t.Errorf("write action = %q, want write_file", w.ActionType)
	}
	if w.Target != "/home/user/project/hello.txt" {
		t.Errorf("write target = %q", w.Target)
	}
	if !w.Success {
		t.Error("write should be success=true")
	}
	if w.ContentBytes != int64(len("hi")) {
		t.Errorf("write ContentBytes = %d, want 2", w.ContentBytes)
	}
	if w.PrecedingReasoning == "" {
		t.Error("write should carry thinking as PrecedingReasoning")
	}
	if w.Model != "swe-1-6-slow" {
		t.Errorf("write model = %q", w.Model)
	}

	// The exec tool call → run_command.
	ex, ok := byID["tool:call_exec1"]
	if !ok {
		t.Fatal("missing exec tool call")
	}
	if ex.ActionType != models.ActionRunCommand {
		t.Errorf("exec action = %q, want run_command", ex.ActionType)
	}
	if ex.Target != "ls" {
		t.Errorf("exec target = %q", ex.Target)
	}
	if ex.ToolOutput == "" {
		t.Error("exec should carry the paired tool result output")
	}

	// The final assistant message (finish=stop, no tool calls) → task_complete.
	fin, ok := byID["text:a-final"]
	if !ok {
		t.Fatal("missing final assistant text")
	}
	if fin.ActionType != models.ActionTaskComplete {
		t.Errorf("final action = %q, want task_complete", fin.ActionType)
	}
}

func TestParse_Tokens(t *testing.T) {
	a := newTestAdapter()
	res, err := a.ParseSessionFile(context.Background(), fixtureDB, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	byID := map[string]models.TokenEvent{}
	for _, tk := range res.TokenEvents {
		byID[tk.SourceEventID] = tk
	}

	// Dead-branch metrics (input 999) must be excluded.
	if _, ok := byID["tokens:a-dead"]; ok {
		t.Error("dead-branch token metrics were emitted")
	}

	live, ok := byID["tokens:a-live1"]
	if !ok {
		t.Fatal("missing live assistant token event")
	}
	if live.InputTokens != 120 || live.OutputTokens != 20 {
		t.Errorf("live tokens in=%d out=%d, want 120/20", live.InputTokens, live.OutputTokens)
	}
	if live.ReasoningTokens != 0 {
		t.Errorf("reasoning tokens = %d, want 0 (folded into output)", live.ReasoningTokens)
	}
	if live.Source != models.TokenSourceJSONL || live.Reliability != models.ReliabilityApproximate {
		t.Errorf("token source/reliability = %q/%q", live.Source, live.Reliability)
	}
	if live.Model != "swe-1-6-slow" {
		t.Errorf("token model = %q", live.Model)
	}

	fin, ok := byID["tokens:a-final"]
	if !ok {
		t.Fatal("missing final token event")
	}
	if fin.InputTokens != 200 || fin.OutputTokens != 15 {
		t.Errorf("final tokens in=%d out=%d, want 200/15", fin.InputTokens, fin.OutputTokens)
	}
}

func TestParse_MalformedNodeSkipped(t *testing.T) {
	a := newTestAdapter()
	res, err := a.ParseSessionFile(context.Background(), fixtureDB, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile returned error on malformed node: %v", err)
	}
	// The malformed-test session's user prompt is emitted; the invalid
	// leaf node is skipped with a warning.
	var sawMalformedPrompt bool
	for _, e := range res.ToolEvents {
		if e.SessionID == "malformed-test" && e.ActionType == models.ActionUserPrompt {
			sawMalformedPrompt = true
		}
	}
	if !sawMalformedPrompt {
		t.Error("expected the malformed session's valid user prompt to survive")
	}
	var sawWarn bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "malformed") && strings.Contains(w, "malformed-test") {
			sawWarn = true
		}
	}
	if !sawWarn {
		t.Errorf("expected a malformed-node warning, got %v", res.Warnings)
	}
}

func TestParse_Watermark(t *testing.T) {
	a := newTestAdapter()
	// A fromOffset at/above the max row_id yields no events but reports
	// the watermark.
	first, err := a.ParseSessionFile(context.Background(), fixtureDB, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if first.NewOffset <= 0 {
		t.Fatalf("expected positive watermark, got %d", first.NewOffset)
	}
	second, err := a.ParseSessionFile(context.Background(), fixtureDB, first.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if len(second.ToolEvents) != 0 || len(second.TokenEvents) != 0 {
		t.Errorf("re-parse above watermark emitted %d tool / %d token events, want 0",
			len(second.ToolEvents), len(second.TokenEvents))
	}
	if second.NewOffset != first.NewOffset {
		t.Errorf("watermark drifted: %d -> %d", first.NewOffset, second.NewOffset)
	}
}

func TestParse_IdempotentEventIDs(t *testing.T) {
	one := parseFixture(t, 0)
	two := parseFixture(t, 0)
	if len(one) != len(two) {
		t.Fatalf("re-parse produced different event count: %d vs %d", len(one), len(two))
	}
	for id := range one {
		if _, ok := two[id]; !ok {
			t.Errorf("event id %q not stable across re-parse", id)
		}
	}
}

func TestResolveProjectRoot_ForeignWindows(t *testing.T) {
	a := newTestAdapter()
	// A raw C:\ path should be translated (crossmount) rather than
	// resolved against the observer's own repo. On a host with no
	// Windows mount it degrades to the translated/native string, never
	// to the observer's git root — assert it still reflects the input.
	got, _, _ := a.resolveProjectRoot(`C:\Users\dev\project`)
	if strings.Contains(got, "superbased-observer") {
		t.Errorf("foreign windows cwd misfiled under observer repo: %q", got)
	}
	if root, _, _ := a.resolveProjectRoot(""); root != "[devin]" {
		t.Errorf("empty cwd should fall back to [devin]")
	}
}

func TestMapTool(t *testing.T) {
	cases := []struct {
		name   string
		args   string
		action string
		target string
	}{
		{"write", `{"file_path":"/a/b.txt","content":"x"}`, models.ActionWriteFile, "/a/b.txt"},
		{"exec", `{"command":"go test"}`, models.ActionRunCommand, "go test"},
		{"read", `{"path":"/a/b.txt"}`, models.ActionReadFile, "/a/b.txt"},
		{"str_replace", `{"file_path":"/a/b.go","new_string":"y"}`, models.ActionEditFile, "/a/b.go"},
		{"grep", `{"pattern":"foo"}`, models.ActionSearchText, "foo"},
		{"glob", `{"glob_pattern":"*.go"}`, models.ActionSearchFiles, "*.go"},
		{"web_search", `{"query":"golang"}`, models.ActionWebSearch, "golang"},
		{"fetch", `{"url":"https://x.dev"}`, models.ActionWebFetch, "https://x.dev"},
		{"run_subagent", `{"query":"explore"}`, models.ActionSpawnSubagent, "explore"},
		{"request_scope", `{}`, models.ActionPermissionRequest, "request_scope"},
		{"some_mcp_tool", `{}`, models.ActionMCPCall, "some_mcp_tool"},
		{"totally_unknown", `{}`, models.ActionUnknown, "totally_unknown"},
	}
	for _, c := range cases {
		gotA, gotT := mapTool(c.name, []byte(c.args))
		if gotA != c.action {
			t.Errorf("mapTool(%q) action = %q, want %q", c.name, gotA, c.action)
		}
		if gotT != c.target {
			t.Errorf("mapTool(%q) target = %q, want %q", c.name, gotT, c.target)
		}
	}
}

func TestNewAndWatchPaths(t *testing.T) {
	a := New()
	if a.Name() != models.ToolDevin {
		t.Fatalf("Name = %q", a.Name())
	}
	// WatchPaths returns the discovery snapshot (may be empty on a host
	// with no home; just assert it doesn't panic and mirrors the field).
	_ = a.WatchPaths()
}

func TestResolveDBPath(t *testing.T) {
	dir := "/x/cli"
	cases := map[string]string{
		filepath.Join(dir, "sessions.db"):     filepath.Join(dir, "sessions.db"),
		filepath.Join(dir, "sessions.db-wal"): filepath.Join(dir, "sessions.db"),
		filepath.Join(dir, "sessions.db-shm"): filepath.Join(dir, "sessions.db"),
	}
	for in, want := range cases {
		if got := resolveDBPath(in); got != want {
			t.Errorf("resolveDBPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParse_ForeignMountStaging(t *testing.T) {
	// Copy the fixture trio into a fake foreign-mount home and mark it
	// foreign so ParseSessionFile stages a local mirror before opening.
	foreignHome := t.TempDir()
	cliDir := filepath.Join(foreignHome, "AppData", "Roaming", "devin", "cli")
	if err := mkdirAll(cliDir); err != nil {
		t.Fatal(err)
	}
	src := mustReadFile(t, fixtureDB)
	foreignDB := filepath.Join(cliDir, "sessions.db")
	mustWriteFile(t, foreignDB, src)

	old := allHomesFunc
	defer func() { allHomesFunc = old }()
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: foreignHome, OS: crossmount.OSWindows, Origin: "wsl-mnt:c"},
		}
	}

	a := NewWithOptions(nil, []string{cliDir})
	if !isForeignMountPath(foreignDB) {
		t.Fatal("test setup: foreignDB not detected as foreign")
	}
	res, err := a.ParseSessionFile(context.Background(), foreignDB, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile (foreign): %v", err)
	}
	if len(res.ToolEvents) == 0 {
		t.Error("foreign-mount parse produced no events")
	}
	// Second parse should hit the up-to-date mirror path.
	if _, err := a.ParseSessionFile(context.Background(), foreignDB, 0); err != nil {
		t.Fatalf("second foreign parse: %v", err)
	}
}

func TestHelpers_Edges(t *testing.T) {
	if contentString(nil) != "" {
		t.Error("contentString(nil) should be empty")
	}
	if got := contentString([]byte(`{"a":1}`)); got != `{"a":1}` {
		t.Errorf("contentString non-string fallback = %q", got)
	}
	if thinkingText([]byte(`"bare"`)) != "bare" {
		t.Error("thinkingText bare-string")
	}
	if thinkingText(nil) != "" {
		t.Error("thinkingText(nil)")
	}
	if !resultSuccess(nil) {
		t.Error("resultSuccess(nil) should default true")
	}
	md := &nodeMetadata{Extensions: []byte(`{"chisel/tool_result_meta":{"success":false}}`)}
	if resultSuccess(md) {
		t.Error("resultSuccess should read success=false")
	}
	if metaModel(nil) != "" || metaFinish(nil) != "" {
		t.Error("nil metadata accessors")
	}
	if eventKey("", 7) != "n7" {
		t.Errorf("eventKey fallback = %q", eventKey("", 7))
	}
	if !secondsToTime(0).IsZero() {
		t.Error("secondsToTime(0) should be zero")
	}
}
