package goose

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
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

func newTestAdapter() *Adapter {
	return NewWithOptions(scrub.New(), []string{filepath.Dir(fixtureDB)})
}

// sid maps a raw goose session id to the store-scoped id the adapter
// emits for the shared fixture store (see scopedSessionID).
func sid(id string) string { return scopedSessionID(id, fixtureDB) }

// parseFixture parses the shared fixture DB from offset 0.
func parseFixture(t *testing.T) ([]models.ToolEvent, []models.TokenEvent, []string) {
	t.Helper()
	a := newTestAdapter()
	res, err := a.ParseSessionFile(context.Background(), fixtureDB, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res.ToolEvents, res.TokenEvents, res.Warnings
}

func TestName(t *testing.T) {
	if got := (&Adapter{}).Name(); got != models.ToolGoose {
		t.Fatalf("Name()=%q want %q", got, models.ToolGoose)
	}
}

func TestWatchPaths_Linux(t *testing.T) {
	orig := allHomesFunc
	defer func() { allHomesFunc = orig }()
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{{Path: "/home/u", OS: crossmount.OSLinux, Origin: "native"}}
	}
	want := filepath.Join("/home/u", ".local", "share", "goose", "sessions")
	got := defaultRoots()
	if len(got) != 1 || got[0] != want {
		t.Fatalf("defaultRoots()=%v want [%s]", got, want)
	}
}

func TestWatchPaths_Windows(t *testing.T) {
	orig := allHomesFunc
	defer func() { allHomesFunc = orig }()
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{{Path: "/mnt/c/Users/dev", OS: crossmount.OSWindows, Origin: "wsl-mnt:c"}}
	}
	want := filepath.Join("/mnt/c/Users/dev", "AppData", "Roaming", "Block", "goose", "data", "sessions")
	got := defaultRoots()
	found := false
	for _, r := range got {
		if r == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing windows root %q in %v", want, got)
	}
}

func TestIsSessionFile(t *testing.T) {
	root := "/home/u/.local/share/goose/sessions"
	a := NewWithOptions(nil, []string{root})
	cases := []struct {
		path string
		want bool
	}{
		{filepath.Join(root, "sessions.db"), true},
		{filepath.Join(root, "sessions.db-wal"), true},
		{filepath.Join(root, "sessions.db-shm"), true},
		{filepath.Join(root, "other.db"), false},                // wrong basename
		{"/home/u/.local/share/goose/other/sessions.db", false}, // wrong parent dir
		{"/tmp/foreign/sessions/sessions.db", false},            // right shape, not under root
	}
	for _, c := range cases {
		if got := a.IsSessionFile(c.path); got != c.want {
			t.Errorf("IsSessionFile(%q)=%v want %v", c.path, got, c.want)
		}
	}
}

func TestParseFixture_Counts(t *testing.T) {
	tools, tokens, warns := parseFixture(t)
	if len(tools) != 14 {
		t.Errorf("tool events = %d, want 14", len(tools))
	}
	if len(tokens) != 4 {
		t.Errorf("token events = %d, want 4 (token-bearing sessions)", len(tokens))
	}
	if len(warns) == 0 {
		t.Errorf("expected a malformed-content warning, got none")
	}
}

func tokenBySession(tokens []models.TokenEvent, id string) (models.TokenEvent, bool) {
	for _, tk := range tokens {
		if tk.SessionID == id {
			return tk, true
		}
	}
	return models.TokenEvent{}, false
}

func TestParseFixture_GrossInputNetted(t *testing.T) {
	_, tokens, _ := parseFixture(t)

	// Single-turn GROSS proof: input 3062, cache_read 2944 -> net 118.
	tk5, ok := tokenBySession(tokens, sid("20260709_5"))
	if !ok {
		t.Fatal("no token event for 20260709_5")
	}
	if tk5.InputTokens != 118 {
		t.Errorf("20260709_5 InputTokens=%d want 118 (3062-2944)", tk5.InputTokens)
	}
	if tk5.CacheReadTokens != 2944 || tk5.OutputTokens != 2 {
		t.Errorf("20260709_5 cacheRead=%d output=%d want 2944/2", tk5.CacheReadTokens, tk5.OutputTokens)
	}
	if tk5.CacheCreationTokens != 0 {
		t.Errorf("20260709_5 CacheCreationTokens=%d want 0 (NULL cache_write)", tk5.CacheCreationTokens)
	}
	if tk5.Model != "gpt-4o-mini" {
		t.Errorf("20260709_5 Model=%q want gpt-4o-mini", tk5.Model)
	}
	if tk5.Source != models.TokenSourceJSONL || tk5.Reliability != models.ReliabilityApproximate {
		t.Errorf("20260709_5 source/reliability=%q/%q", tk5.Source, tk5.Reliability)
	}

	// Multi-turn accumulated GROSS: 6193-2944 = 3249.
	tk4, _ := tokenBySession(tokens, sid("20260709_4"))
	if tk4.InputTokens != 3249 {
		t.Errorf("20260709_4 InputTokens=%d want 3249 (6193-2944)", tk4.InputTokens)
	}
	if tk4.EstimatedCostUSD != 0.00075735 {
		t.Errorf("20260709_4 cost=%v want 0.00075735", tk4.EstimatedCostUSD)
	}

	// cache_read=0 session nets to full input.
	tk3, _ := tokenBySession(tokens, sid("20260709_3"))
	if tk3.InputTokens != 4053 || tk3.CacheReadTokens != 0 {
		t.Errorf("20260709_3 input=%d cacheRead=%d want 4053/0", tk3.InputTokens, tk3.CacheReadTokens)
	}
	if tk3.Model != "gpt-4o" {
		t.Errorf("20260709_3 Model=%q want gpt-4o", tk3.Model)
	}
}

func TestParseFixture_TokenEmptySkipped(t *testing.T) {
	tools, tokens, _ := parseFixture(t)
	for _, id := range []string{"20260709_1", "20260709_2", "20260709_6"} {
		if _, ok := tokenBySession(tokens, sid(id)); ok {
			t.Errorf("token-empty session %s should emit no TokenEvent", id)
		}
	}
	// The provider-error sessions still record their user prompt.
	var sawScratchPrompt bool
	for _, e := range tools {
		if e.SessionID == sid("20260709_1") && e.ActionType == models.ActionUserPrompt {
			sawScratchPrompt = true
		}
	}
	if !sawScratchPrompt {
		t.Error("token-empty session's user prompt was dropped")
	}
}

func TestParseFixture_ToolCallPairing(t *testing.T) {
	tools, _, _ := parseFixture(t)
	byID := map[string]models.ToolEvent{}
	for _, e := range tools {
		byID[e.SourceEventID] = e
	}

	write, ok := byID["tool:call_write1"]
	if !ok {
		t.Fatal("write tool event missing")
	}
	if write.ActionType != models.ActionWriteFile {
		t.Errorf("write ActionType=%q want write_file", write.ActionType)
	}
	if write.Target != "hello.txt" {
		t.Errorf("write Target=%q want hello.txt", write.Target)
	}
	if write.RawToolName != "write" {
		t.Errorf("write RawToolName=%q want write", write.RawToolName)
	}
	if write.ContentBytes != int64(len("hello from goose.")) {
		t.Errorf("write ContentBytes=%d want %d", write.ContentBytes, len("hello from goose."))
	}
	if !write.Success {
		t.Error("write should be success")
	}
	if !strings.Contains(write.ToolOutput, "Created hello.txt") {
		t.Errorf("write ToolOutput=%q missing result text", write.ToolOutput)
	}
	if write.Model != "gpt-4o-mini" {
		t.Errorf("write Model=%q want gpt-4o-mini", write.Model)
	}

	shell, ok := byID["tool:call_shell1"]
	if !ok {
		t.Fatal("shell tool event missing")
	}
	if shell.ActionType != models.ActionRunCommand {
		t.Errorf("shell ActionType=%q want run_command", shell.ActionType)
	}
	if shell.Target != "ls" {
		t.Errorf("shell Target=%q want ls", shell.Target)
	}
	// structuredContent stdout falls back into the flattened result text.
	if !strings.Contains(shell.ToolOutput, "hello.txt") {
		t.Errorf("shell ToolOutput=%q missing stdout", shell.ToolOutput)
	}
	if shell.ContentBytes != 0 {
		t.Errorf("shell ContentBytes=%d want 0 (not authored code)", shell.ContentBytes)
	}
}

func TestParseFixture_WindowsProjectRoot(t *testing.T) {
	tools, tokens, _ := parseFixture(t)
	// Windows-side session's raw C:\ working_dir must be translated, never
	// resolved against the observer's own repo.
	want := crossmount.TranslateForeignPath(`C:\Users\dev\project`)
	var checked bool
	for _, e := range tools {
		if e.SessionID != sid("20260708_1") {
			continue
		}
		checked = true
		if strings.Contains(e.ProjectRoot, "superbased-observer") {
			t.Fatalf("windows cwd misfiled under observer repo: %q", e.ProjectRoot)
		}
		if e.ProjectRoot != want {
			t.Errorf("windows ProjectRoot=%q want %q", e.ProjectRoot, want)
		}
	}
	if !checked {
		t.Fatal("no events for the windows session 20260708_1")
	}
	tk, _ := tokenBySession(tokens, sid("20260708_1"))
	if tk.ProjectRoot != want {
		t.Errorf("windows token ProjectRoot=%q want %q", tk.ProjectRoot, want)
	}
	if tk.InputTokens != 4166 { // 8134 - 3968
		t.Errorf("windows token InputTokens=%d want 4166", tk.InputTokens)
	}
}

func TestParseFixture_Watermark(t *testing.T) {
	a := newTestAdapter()
	ctx := context.Background()

	full, err := a.ParseSessionFile(ctx, fixtureDB, 0)
	if err != nil {
		t.Fatal(err)
	}
	if full.NewOffset != 17 {
		t.Fatalf("NewOffset=%d want 17 (MAX message id)", full.NewOffset)
	}

	// At the watermark: nothing re-read.
	none, err := a.ParseSessionFile(ctx, fixtureDB, 17)
	if err != nil {
		t.Fatal(err)
	}
	if len(none.ToolEvents) != 0 || len(none.TokenEvents) != 0 {
		t.Errorf("re-parse at watermark emitted %d/%d events, want 0/0", len(none.ToolEvents), len(none.TokenEvents))
	}

	// Partial: only sessions touched after message id 8 (_4, _5, _6).
	partial, err := a.ParseSessionFile(ctx, fixtureDB, 8)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range partial.ToolEvents {
		seen[e.SessionID] = true
	}
	for _, id := range []string{"20260709_4", "20260709_5"} {
		if !seen[sid(id)] {
			t.Errorf("partial parse missing touched session %s", id)
		}
	}
	if seen[sid("20260708_1")] || seen[sid("20260709_3")] {
		t.Errorf("partial parse re-emitted an untouched session: %v", seen)
	}
}

func TestIdempotentSourceEventIDs(t *testing.T) {
	a := newTestAdapter()
	ctx := context.Background()
	first, _ := a.ParseSessionFile(ctx, fixtureDB, 0)
	second, _ := a.ParseSessionFile(ctx, fixtureDB, 0)

	ids := func(res []models.ToolEvent) map[string]int {
		m := map[string]int{}
		for _, e := range res {
			m[e.SourceEventID]++
		}
		return m
	}
	a1, a2 := ids(first.ToolEvents), ids(second.ToolEvents)
	if len(a1) != len(first.ToolEvents) {
		t.Errorf("duplicate SourceEventIDs within one parse: %d ids for %d events", len(a1), len(first.ToolEvents))
	}
	if len(a1) != len(a2) {
		t.Errorf("non-deterministic id set: %d vs %d", len(a1), len(a2))
	}
	for id := range a1 {
		if a2[id] == 0 {
			t.Errorf("id %q missing on second parse", id)
		}
	}
}

func TestResolveProjectRoot(t *testing.T) {
	a := newTestAdapter()
	if got, remote, _ := a.resolveProjectRoot(""); got != "[goose]" || remote != "" {
		t.Errorf("empty cwd => (%q, %q) want ([goose], \"\")", got, remote)
	}
	if got, _, _ := a.resolveProjectRoot(`C:\Users\dev\project`); strings.Contains(got, "superbased-observer") {
		t.Errorf("foreign windows cwd misfiled under observer repo: %q", got)
	}
}

func TestMapTool(t *testing.T) {
	cases := []struct {
		name   string
		args   string
		action string
		target string
	}{
		{"write", `{"path":"a.txt","content":"x"}`, models.ActionWriteFile, "a.txt"},
		{"shell", `{"command":"ls -la"}`, models.ActionRunCommand, "ls -la"},
		{"text_editor", `{"path":"b.go","new_str":"y"}`, models.ActionEditFile, "b.go"},
		{"read", `{"path":"c.md"}`, models.ActionReadFile, "c.md"},
		{"grep", `{"pattern":"foo"}`, models.ActionSearchText, "foo"},
		{"glob", `{"pattern":"*.go"}`, models.ActionSearchFiles, "*.go"},
		{"web_search", `{"query":"golang"}`, models.ActionWebSearch, "golang"},
		{"fetch", `{"url":"http://x"}`, models.ActionWebFetch, "http://x"},
		{"some_mcp_tool", `{}`, models.ActionMCPCall, "some_mcp_tool"},
		{"totally_unknown", `{}`, models.ActionUnknown, "totally_unknown"},
	}
	for _, c := range cases {
		gotAction, gotTarget := mapTool(c.name, []byte(c.args))
		if gotAction != c.action || gotTarget != c.target {
			t.Errorf("mapTool(%q) = (%q,%q) want (%q,%q)", c.name, gotAction, gotTarget, c.action, c.target)
		}
	}
}

func TestScrubsSecrets(t *testing.T) {
	// Build a tiny DB whose user prompt and write-tool content carry a
	// secret the default scrubber redacts (AWS access-key shape). The
	// literal is assembled at runtime so the test file itself carries no
	// recognizable secret.
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sessions.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
CREATE TABLE sessions (id TEXT PRIMARY KEY, working_dir TEXT NOT NULL,
  updated_at TIMESTAMP, provider_name TEXT, model_config_json TEXT,
  accumulated_input_tokens INTEGER, accumulated_output_tokens INTEGER,
  accumulated_cache_read_tokens INTEGER, accumulated_cache_write_tokens INTEGER,
  accumulated_total_tokens INTEGER, accumulated_cost REAL);
INSERT INTO sessions (id, working_dir, updated_at, model_config_json)
  VALUES ('s1','/home/user/proj','2026-07-09 10:00:00','{"model_name":"gpt-4o"}');
CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT,
  session_id TEXT NOT NULL, role TEXT NOT NULL, content_json TEXT NOT NULL,
  created_timestamp INTEGER NOT NULL);
INSERT INTO messages (message_id, session_id, role, content_json, created_timestamp) VALUES
 ('m1','s1','user','[{"type":"text","text":"my key is ` + secret + `"}]',1783590600),
 ('m2','s1','assistant','[{"type":"toolRequest","id":"c1","toolCall":{"status":"success","value":{"name":"write","arguments":{"path":"k.txt","content":"` + secret + `"}}}}]',1783590601);
`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	a := NewWithOptions(scrub.New(), []string{dir})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) == 0 {
		t.Fatal("no events produced")
	}
	for _, e := range res.ToolEvents {
		if strings.Contains(e.Target, secret) || strings.Contains(e.RawToolInput, secret) ||
			strings.Contains(e.ToolOutput, secret) {
			t.Fatalf("secret leaked in event %q: target=%q rawInput=%q", e.SourceEventID, e.Target, e.RawToolInput)
		}
	}
	// Sanity: the secret-bearing prompt WAS captured (just scrubbed).
	var sawPrompt bool
	for _, e := range res.ToolEvents {
		if e.ActionType == models.ActionUserPrompt && strings.Contains(e.Target, "my key is") {
			sawPrompt = true
		}
	}
	if !sawPrompt {
		t.Error("secret-bearing user prompt not captured at all")
	}
}

// TestCrossStoreIDCollision pins the store-scoped SessionID lane. goose
// ids are YYYYMMDD_seq generated INDEPENDENTLY per store, so a WSL store
// and a Windows store on one machine both contain a `20260708_1`. Parsing
// both stores must yield two DISTINCT sessions (and distinct token-row
// SourceEventIDs), never one merged row.
func TestCrossStoreIDCollision(t *testing.T) {
	a := NewWithOptions(scrub.New(), []string{filepath.Dir(fixtureDB), filepath.Dir(fixtureDB2)})
	ctx := context.Background()

	res1, err := a.ParseSessionFile(ctx, fixtureDB, 0)
	if err != nil {
		t.Fatal(err)
	}
	res2, err := a.ParseSessionFile(ctx, fixtureDB2, 0)
	if err != nil {
		t.Fatal(err)
	}

	sessionsFor := func(events []models.ToolEvent, rawID string) map[string]bool {
		out := map[string]bool{}
		for _, e := range events {
			if strings.HasPrefix(e.SessionID, rawID+"@") {
				out[e.SessionID] = true
			}
		}
		return out
	}
	s1 := sessionsFor(res1.ToolEvents, "20260708_1")
	s2 := sessionsFor(res2.ToolEvents, "20260708_1")
	if len(s1) != 1 || len(s2) != 1 {
		t.Fatalf("expected exactly one scoped 20260708_1 per store, got %v / %v", s1, s2)
	}
	for id := range s1 {
		if s2[id] {
			t.Fatalf("colliding raw id produced the SAME scoped SessionID %q across two stores", id)
		}
	}

	// Every emitted SessionID carries a store scope (uniform namespacing —
	// no bare raw id may leak from either store).
	for _, res := range []struct {
		name   string
		events []models.ToolEvent
	}{{"store1", res1.ToolEvents}, {"store2", res2.ToolEvents}} {
		for _, e := range res.events {
			if !strings.Contains(e.SessionID, "@") {
				t.Errorf("%s event %q has un-scoped SessionID %q", res.name, e.SourceEventID, e.SessionID)
			}
		}
	}

	// Determinism: re-parsing yields the identical scoped id.
	again, err := a.ParseSessionFile(ctx, fixtureDB2, 0)
	if err != nil {
		t.Fatal(err)
	}
	s2b := sessionsFor(again.ToolEvents, "20260708_1")
	for id := range s2 {
		if !s2b[id] {
			t.Errorf("scoped id %q not stable across re-parses", id)
		}
	}

	// The second store's non-colliding session comes through as its own
	// scoped session too.
	if got := sessionsFor(res2.ToolEvents, "20260708_2"); len(got) != 1 {
		t.Errorf("second store's 20260708_2 missing/fragmented: %v", got)
	}
}

func TestMirrorHelpersNativePath(t *testing.T) {
	// A native path is returned unchanged (no mirror staging).
	got, err := stageMirrorIfForeign("/home/u/.local/share/goose/sessions/sessions.db")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/home/u/.local/share/goose/sessions/sessions.db" {
		t.Errorf("native path mutated to %q", got)
	}
	_ = os.Stat // keep os import used across build tags
}
