package aider

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	p := filepath.Join("..", "..", "..", "testdata", "aider", name)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// newTestAdapter builds an adapter WITHOUT running root discovery (which
// would walk the real $HOME). Tests that need parsing only care about the
// scrubber; tests that need watch roots inject them explicitly.
func newTestAdapter() *Adapter {
	return NewWithOptions(nil, []string{string(filepath.Separator) + "no-such-root"})
}

// parseFixture parses a fixture with a fixed project root, bypassing
// git.Resolve so the assertions are deterministic regardless of where the
// test runs.
func parseFixture(t *testing.T, name string) ([]models.ToolEvent, []models.TokenEvent) {
	t.Helper()
	a := newTestAdapter()
	return a.parseTranscript(context.Background(), fixture(t, name), "/proj", "/proj", "")
}

func countActions(evs []models.ToolEvent, action string) int {
	n := 0
	for _, e := range evs {
		if e.ActionType == action {
			n++
		}
	}
	return n
}

func firstAction(evs []models.ToolEvent, action string) (models.ToolEvent, bool) {
	for _, e := range evs {
		if e.ActionType == action {
			return e, true
		}
	}
	return models.ToolEvent{}, false
}

func TestName(t *testing.T) {
	if got := newTestAdapter().Name(); got != models.ToolAider {
		t.Fatalf("Name() = %q, want %q", got, models.ToolAider)
	}
}

func TestIsSessionFile(t *testing.T) {
	root := t.TempDir()
	a := NewWithOptions(nil, []string{root})
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"transcript under root", filepath.Join(root, "repo", ".aider.chat.history.md"), true},
		{"transcript at root", filepath.Join(root, ".aider.chat.history.md"), true},
		{"input history sibling", filepath.Join(root, "repo", ".aider.input.history"), false},
		{"tags cache", filepath.Join(root, "repo", ".aider.tags.cache.v4", "cache.db"), false},
		{"unrelated md", filepath.Join(root, "repo", "README.md"), false},
		{"foreign path", filepath.Join("/tmp", "foreign", ".aider.chat.history.md"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Fatalf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestParseReadonlyFixture(t *testing.T) {
	tools, tokens := parseFixture(t, "readonly.md")

	if got := countActions(tools, models.ActionUserPrompt); got != 3 {
		t.Errorf("user prompts = %d, want 3", got)
	}
	if got := countActions(tools, models.ActionAssistantMessage); got != 2 {
		t.Errorf("assistant texts = %d, want 2", got)
	}
	if len(tokens) != 2 {
		t.Fatalf("token events = %d, want 2", len(tokens))
	}

	// Model banner captured.
	if tools[0].Model != "gpt-4o" {
		t.Errorf("model = %q, want gpt-4o", tools[0].Model)
	}

	// First token line: `11k sent, 21 received. Cost: $0.03 message`.
	tk := tokens[0]
	if tk.InputTokens != 11000 || tk.OutputTokens != 21 {
		t.Errorf("token[0] in/out = %d/%d, want 11000/21", tk.InputTokens, tk.OutputTokens)
	}
	if tk.CacheReadTokens != 0 {
		t.Errorf("token[0] cacheRead = %d, want 0", tk.CacheReadTokens)
	}
	if tk.EstimatedCostUSD != 0.03 {
		t.Errorf("token[0] cost = %v, want 0.03", tk.EstimatedCostUSD)
	}
	if tk.Reliability != models.ReliabilityUnreliable {
		t.Errorf("token[0] reliability = %q, want unreliable", tk.Reliability)
	}
	if tk.Source != models.TokenSourceJSONL {
		t.Errorf("token[0] source = %q, want jsonl", tk.Source)
	}

	// The `#### /exit` trailing prompt (no closing token line) is still captured.
	var sawExit bool
	for _, e := range tools {
		if e.ActionType == models.ActionUserPrompt && strings.Contains(e.Target, "/exit") {
			sawExit = true
		}
	}
	if !sawExit {
		t.Error("trailing /exit user prompt not captured")
	}

	// All events share the session start timestamp (2026-07-09 04:37:13).
	for _, e := range tools {
		if e.Timestamp.IsZero() {
			t.Errorf("event %q has zero timestamp", e.SourceEventID)
		}
	}
}

func TestParseEditFixture(t *testing.T) {
	tools, tokens := parseFixture(t, "edit-linux.md")

	edit, ok := firstAction(tools, models.ActionEditFile)
	if !ok {
		t.Fatal("no edit_file event")
	}
	if edit.Target != "src/app.py" {
		t.Errorf("edit target = %q, want src/app.py", edit.Target)
	}
	if edit.RawToolName != "aider.apply_edit" {
		t.Errorf("edit raw name = %q", edit.RawToolName)
	}

	run, ok := firstAction(tools, models.ActionRunCommand)
	if !ok {
		t.Fatal("no run_command event")
	}
	if run.Target != "pytest -q" {
		t.Errorf("run target = %q, want 'pytest -q'", run.Target)
	}

	// Model from `Main model: claude-3-5-sonnet`.
	if edit.Model != "claude-3-5-sonnet" {
		t.Errorf("model = %q, want claude-3-5-sonnet", edit.Model)
	}

	// First token line: gross-vs-net + cache split.
	// `5.0k sent, 1.2k cache write, 512 cache hit, 240 received`.
	tk := tokens[0]
	if tk.InputTokens != 4488 { // 5000 - 512 cache hit
		t.Errorf("netInput = %d, want 4488 (5000-512)", tk.InputTokens)
	}
	if tk.CacheReadTokens != 512 {
		t.Errorf("cacheRead = %d, want 512", tk.CacheReadTokens)
	}
	if tk.CacheCreationTokens != 1200 {
		t.Errorf("cacheCreation = %d, want 1200", tk.CacheCreationTokens)
	}
	if tk.OutputTokens != 240 {
		t.Errorf("output = %d, want 240", tk.OutputTokens)
	}
	if tk.EstimatedCostUSD != 0.02 {
		t.Errorf("cost = %v, want 0.02", tk.EstimatedCostUSD)
	}
}

func TestScrubbing(t *testing.T) {
	tools, _ := parseFixture(t, "edit-linux.md")
	for _, e := range tools {
		if strings.Contains(e.Target, "sk-testKEY") || strings.Contains(e.RawToolInput, "sk-testKEY") ||
			strings.Contains(e.ToolOutput, "sk-testKEY") {
			t.Fatalf("secret leaked in event %q: target=%q", e.SourceEventID, e.Target)
		}
	}
	// Sanity: the secret-bearing prompt WAS captured (just scrubbed).
	var sawRedactPrompt bool
	for _, e := range tools {
		if e.ActionType == models.ActionUserPrompt && strings.Contains(e.Target, "redact my key") {
			sawRedactPrompt = true
		}
	}
	if !sawRedactPrompt {
		t.Error("secret-bearing user prompt not captured at all")
	}
}

func TestParseMultiSession(t *testing.T) {
	tools, tokens := parseFixture(t, "windows-multi.md")

	sessions := map[string]bool{}
	for _, e := range tools {
		sessions[e.SessionID] = true
	}
	if len(sessions) != 2 {
		t.Fatalf("distinct sessions = %d, want 2", len(sessions))
	}

	if len(tokens) != 2 {
		t.Fatalf("token events = %d, want 2", len(tokens))
	}
	// Session 1: `3.2k sent, 18 received`; session 2: `1.5k sent, 12 received`.
	if tokens[0].InputTokens != 3200 || tokens[0].OutputTokens != 18 {
		t.Errorf("token[0] = %d/%d, want 3200/18", tokens[0].InputTokens, tokens[0].OutputTokens)
	}
	if tokens[1].InputTokens != 1500 || tokens[1].OutputTokens != 12 {
		t.Errorf("token[1] = %d/%d, want 1500/12", tokens[1].InputTokens, tokens[1].OutputTokens)
	}

	// Windows edit + shell markers.
	if _, ok := firstAction(tools, models.ActionEditFile); !ok {
		t.Error("no edit_file event in windows fixture")
	}
	if run, ok := firstAction(tools, models.ActionRunCommand); !ok {
		t.Error("no run_command event")
	} else if run.Target != "cmd /c dir" {
		t.Errorf("run target = %q, want 'cmd /c dir'", run.Target)
	}
}

func TestParseTokenCount(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"500", 500},
		{"21", 21},
		{"11k", 11000},
		{"9.4k", 9400},
		{"32k", 32000},
		{"1.2k", 1200},
		{"", 0},
		{"garbage", 0},
		{"3.0", 3},
	}
	for _, tc := range cases {
		if got := parseTokenCount(tc.in); got != tc.want {
			t.Errorf("parseTokenCount(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestDeterministicIDs(t *testing.T) {
	a := newTestAdapter()
	data := fixture(t, "readonly.md")
	t1, k1 := a.parseTranscript(context.Background(), data, "/proj", "/proj", "")
	t2, k2 := a.parseTranscript(context.Background(), data, "/proj", "/proj", "")

	if len(t1) != len(t2) || len(k1) != len(k2) {
		t.Fatal("event counts differ between parses")
	}
	for i := range t1 {
		if t1[i].SourceEventID != t2[i].SourceEventID {
			t.Errorf("tool id[%d] not stable: %q vs %q", i, t1[i].SourceEventID, t2[i].SourceEventID)
		}
	}
	for i := range k1 {
		if k1[i].SourceEventID != k2[i].SourceEventID {
			t.Errorf("token id[%d] not stable: %q vs %q", i, k1[i].SourceEventID, k2[i].SourceEventID)
		}
	}
	// IDs are unique within the batch.
	seen := map[string]bool{}
	for _, e := range t1 {
		if seen[e.SourceEventID] {
			t.Errorf("duplicate tool id %q", e.SourceEventID)
		}
		seen[e.SourceEventID] = true
	}
}

func TestParseSessionFileWatermark(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".aider.chat.history.md")
	if err := os.WriteFile(path, fixture(t, "readonly.md"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, []string{dir})

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) == 0 {
		t.Fatal("expected events on first parse")
	}
	info, _ := os.Stat(path)
	if res.NewOffset != info.Size() {
		t.Errorf("NewOffset = %d, want file size %d", res.NewOffset, info.Size())
	}

	// Re-parse from the returned offset: no growth ⇒ no events.
	res2, err := a.ParseSessionFile(context.Background(), path, res.NewOffset)
	if err != nil {
		t.Fatalf("ParseSessionFile (2): %v", err)
	}
	if len(res2.ToolEvents) != 0 || len(res2.TokenEvents) != 0 {
		t.Errorf("expected no events on unchanged file, got %d/%d", len(res2.ToolEvents), len(res2.TokenEvents))
	}
	if res2.NewOffset != res.NewOffset {
		t.Errorf("NewOffset moved on unchanged file: %d != %d", res2.NewOffset, res.NewOffset)
	}

	// Missing file: graceful, cursor preserved.
	res3, err := a.ParseSessionFile(context.Background(), filepath.Join(dir, "nope", ".aider.chat.history.md"), 42)
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if res3.NewOffset != 42 {
		t.Errorf("missing-file NewOffset = %d, want 42", res3.NewOffset)
	}
}

func TestResolveProjectRoot(t *testing.T) {
	dir := t.TempDir()
	a := newTestAdapter()
	got, _, _ := a.resolveProjectRoot(filepath.Join(dir, ".aider.chat.history.md"))
	// The project root is the transcript's directory, resolved through
	// git.Resolve. We avoid asserting an exact path (the temp dir could
	// sit inside a git working tree on some CI hosts), only that a real,
	// non-placeholder absolute path came back.
	if got == "" || got == "[aider]" || !filepath.IsAbs(got) {
		t.Errorf("resolveProjectRoot = %q, want a real absolute path", got)
	}

	// The empty/degenerate case yields the placeholder.
	if p, _, _ := a.resolveProjectRoot(".aider.chat.history.md"); p == "" {
		t.Error("resolveProjectRoot of bare filename returned empty")
	}
}

func TestDiscoverRoots(t *testing.T) {
	home := t.TempDir()
	// Plant an aider transcript a couple levels deep, plus a decoy under a
	// pruned heavy dir and a decoy dot-dir.
	repo := filepath.Join(home, "code", "acme")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, historyFileName), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	heavy := filepath.Join(home, "node_modules", "pkg")
	_ = os.MkdirAll(heavy, 0o755)
	_ = os.WriteFile(filepath.Join(heavy, historyFileName), []byte("x"), 0o600)
	hidden := filepath.Join(home, ".cache", "x")
	_ = os.MkdirAll(hidden, 0o755)
	_ = os.WriteFile(filepath.Join(hidden, historyFileName), []byte("x"), 0o600)

	orig := allHomesFunc
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{{Path: home, OS: crossmount.OSLinux, Origin: "native"}}
	}
	defer func() { allHomesFunc = orig }()

	roots := discoverRoots()
	found := false
	for _, r := range roots {
		if r == filepath.Join(repo, historyFileName) {
			found = true
		}
		if strings.Contains(r, "node_modules") || strings.Contains(r, ".cache") {
			t.Errorf("discovery descended into pruned dir: %q", r)
		}
	}
	if !found {
		t.Errorf("discovery did not find planted repo %q; roots=%v", repo, roots)
	}
}

func TestDiscoverRootsEnvOverride(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom.history.md")
	t.Setenv("AIDER_CHAT_HISTORY_FILE", custom)
	orig := allHomesFunc
	allHomesFunc = func() []crossmount.HomeRoot { return nil }
	defer func() { allHomesFunc = orig }()

	roots := discoverRoots()
	if len(roots) == 0 || roots[0] != custom {
		t.Errorf("env override not honored; roots=%v want [%q]", roots, custom)
	}
}

// TestWalkForAiderRootsBreadthFirst pins the BFS property: a shallow repo
// must be found even when a deep tree that sorts lexically EARLIER would
// exhaust the visit budget under a depth-first walk (the ~/go/pkg/mod
// failure mode observed live 2026-07-09).
func TestWalkForAiderRootsBreadthFirst(t *testing.T) {
	home := t.TempDir()
	// "aaa" sorts before "repo" and is a 10-deep chain.
	deep := filepath.Join(home, "aaa")
	for i := 0; i < 9; i++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(home, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, historyFileName), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Budget 4: home + aaa + repo fit breadth-first; a DFS lexical walk
	// would burn all 4 inside the aaa chain and miss the repo.
	found, _ := walkForAiderRootsBudget(t, home, 4)
	want := filepath.Join(repo, historyFileName)
	ok := false
	for _, f := range found {
		if f == want {
			ok = true
		}
	}
	if !ok {
		t.Errorf("breadth-first walk missed shallow repo under tight budget; found=%v want contains %q", found, want)
	}
}

func walkForAiderRootsBudget(t *testing.T, root string, budget int) ([]string, int) {
	t.Helper()
	return walkForAiderRoots(root, budget)
}
