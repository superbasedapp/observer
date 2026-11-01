package codebuddy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// interface conformance — the watcher only accepts adapter.Adapter.
var _ adapter.Adapter = (*Adapter)(nil)

// fixturePath resolves a file in testdata/codebuddy/.
func fixturePath(name string) string {
	return filepath.Join("..", "..", "..", "testdata", "codebuddy", name)
}

// stage writes body as `<root>/.codebuddy/projects/<slug>/<session>.jsonl`
// and returns the path plus an adapter rooted at that projects dir.
func stage(t *testing.T, session, body string) (string, *Adapter) {
	t.Helper()
	projects := filepath.Join(t.TempDir(), ".codebuddy", "projects")
	dir := filepath.Join(projects, "home-user-project")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, session+".jsonl")
	if err := os.WriteFile(dst, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dst, NewWithOptions(nil, projects)
}

// stageFixture stages a testdata fixture under the given session id and
// parses it from offset 0.
func stageFixture(t *testing.T, fixture, session string) (adapter.ParseResult, string) {
	t.Helper()
	body, err := os.ReadFile(fixturePath(fixture))
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixture, err)
	}
	p, a := stage(t, session, string(body))
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res, p
}

func countActions(evs []models.ToolEvent) map[string]int {
	out := map[string]int{}
	for _, ev := range evs {
		out[ev.ActionType]++
	}
	return out
}

func findByRaw(t *testing.T, evs []models.ToolEvent, raw string) models.ToolEvent {
	t.Helper()
	for _, ev := range evs {
		if ev.RawToolName == raw {
			return ev
		}
	}
	t.Fatalf("no event with RawToolName %q", raw)
	return models.ToolEvent{}
}

func TestIsSessionFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".codebuddy", "projects")
	a := NewWithOptions(nil, root)
	j := func(parts ...string) string { return filepath.Join(append([]string{root}, parts...)...) }
	home := filepath.Dir(filepath.Dir(root))
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"main transcript", j("home-u-proj", "01a15cae-7d33-7739-8d55-8b6a3940d798.jsonl"), true},
		{"windows slug", j("c-Users-u-proj", "01a15cad-f2df-7ac8-a141-61794a419f5b.jsonl"), true},
		{"subagent transcript not claimed", j("home-u-proj", "01a15cae", "subagents", "agent-1.jsonl"), false},
		{"tool-results not claimed", j("home-u-proj", "01a15cae", "tool-results", "x.jsonl"), false},
		{"file directly under projects", j("x.jsonl"), false},
		{"meta json rejected", j("home-u-proj", "agent-1.meta.json"), false},
		{"top-level history rejected", filepath.Join(home, ".codebuddy", "history.jsonl"), false},
		{"trace rejected", filepath.Join(home, ".codebuddy", "traces", "123", "trace_ab.jsonl"), false},
		{"claude-code transcript outside root", filepath.Join(home, ".claude", "projects", "p", "x.jsonl"), false},
		{"commandcode transcript outside root", filepath.Join(home, ".commandcode", "projects", "p", "x.jsonl"), false},
		{"foreign codebuddy root", filepath.Join(string(filepath.Separator)+"tmp", "foreign", ".codebuddy", "projects", "p", "x.jsonl"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Fatalf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestWatchPathsDefaultShape(t *testing.T) {
	t.Setenv(configDirEnv, "")
	roots := New().WatchPaths()
	if len(roots) == 0 {
		t.Fatal("no default watch roots")
	}
	for _, r := range roots {
		if !strings.HasSuffix(filepath.ToSlash(r), "/.codebuddy/projects") {
			t.Errorf("watch root %q does not end in .codebuddy/projects", r)
		}
	}
}

func TestConfigDirEnvOverride(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cb-home")
	t.Setenv(configDirEnv, dir)
	roots := New().WatchPaths()
	want := filepath.Join(dir, "projects")
	if len(roots) == 0 || roots[0] != want {
		t.Fatalf("first root = %v, want %q", roots, want)
	}
	// A transcript under the override root is claimed even though its
	// path carries no `.codebuddy` segment.
	p := filepath.Join(want, "slug", "abc.jsonl")
	if !New().IsSessionFile(p) {
		t.Errorf("IsSessionFile(%q) = false under the CODEBUDDY_CONFIG_DIR root", p)
	}
}

// TestParseWSLAuthErrorSession parses the REAL (anonymized) WSL session:
// the operator ran /model, /config, "hi", /status, /model, "hi" without
// being logged in.
func TestParseWSLAuthErrorSession(t *testing.T) {
	const sid = "01a15cae-7d33-7739-8d55-8b6a3940d798"
	res, p := stageFixture(t, "wsl-auth-error-session.jsonl", sid)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != fi.Size() {
		t.Errorf("NewOffset = %d, want EOF %d", res.NewOffset, fi.Size())
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", res.Warnings)
	}
	got := countActions(res.ToolEvents)
	want := map[string]int{
		models.ActionSessionStart: 1,
		models.ActionUserPrompt:   2, // the two "hi"; slash-command records are skipRun bookkeeping
		models.ActionAPIError:     2,
	}
	if len(got) != len(want) {
		t.Errorf("action kinds = %v, want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s = %d, want %d (all %v)", k, got[k], n, got)
		}
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("token events = %d, want 0 (no turn reached a model)", len(res.TokenEvents))
	}
	for _, ev := range res.ToolEvents {
		if ev.SessionID != sid || ev.Tool != models.ToolCodeBuddy {
			t.Fatalf("session/tool = %q/%q", ev.SessionID, ev.Tool)
		}
		if !strings.HasSuffix(filepath.ToSlash(ev.ProjectRoot), "/project") {
			t.Errorf("%s project root = %q, want the inline cwd", ev.ActionType, ev.ProjectRoot)
		}
		if ev.Timestamp.IsZero() || ev.Timestamp.Year() != 2026 {
			t.Errorf("%s timestamp = %v, want 2026 (epoch-ms decode)", ev.ActionType, ev.Timestamp)
		}
		switch ev.ActionType {
		case models.ActionUserPrompt:
			if ev.Target != "hi" {
				t.Errorf("prompt target = %q, want hi", ev.Target)
			}
		case models.ActionAPIError:
			if ev.Success || !strings.Contains(ev.ErrorMessage, "Authentication required") {
				t.Errorf("api_error success=%v msg=%q", ev.Success, ev.ErrorMessage)
			}
			if ev.Target == "" || ev.RawToolName != "error" {
				t.Errorf("api_error target=%q raw=%q, want the turn id and class error", ev.Target, ev.RawToolName)
			}
		}
	}
}

// TestParseWindowsAuthErrorSession parses the REAL (anonymized) Windows
// session, whose cwd is a lower-case drive-letter path.
func TestParseWindowsAuthErrorSession(t *testing.T) {
	const sid = "01a15cad-f2df-7ac8-a141-61794a419f5b"
	res, _ := stageFixture(t, "windows-auth-error-session.jsonl", sid)
	got := countActions(res.ToolEvents)
	if got[models.ActionSessionStart] != 1 || got[models.ActionUserPrompt] != 1 || got[models.ActionAPIError] != 1 {
		t.Errorf("actions = %v, want 1 session_start / 1 user_prompt / 1 api_error", got)
	}
	for _, ev := range res.ToolEvents {
		if !strings.HasSuffix(strings.ToLower(filepath.ToSlash(ev.ProjectRoot)), "/project") {
			t.Errorf("%s project root = %q", ev.ActionType, ev.ProjectRoot)
		}
	}
}

// TestParseSyntheticToolSession exercises the shapes NO live capture has
// produced (reasoning, attachments, MCP, an unmapped tool, a sub-agent
// forwarded line, cache read/write usage, a non-zero Bash exit, compaction
// summaries) on a SYNTHETIC fixture built from the agents-core schema and
// the vendor bundle. The shapes a live capture DID produce are covered by
// the TestParseLive* tests on real anonymized sessions.
func TestParseSyntheticToolSession(t *testing.T) {
	const sid = "01a20000-0000-7000-8000-0000000000aa"
	res, _ := stageFixture(t, "synthetic-unobserved-shapes.jsonl", sid)

	got := countActions(res.ToolEvents)
	want := map[string]int{
		models.ActionSessionStart:     1,
		models.ActionUserPrompt:       1,
		models.ActionReadFile:         1,
		models.ActionRunCommand:       2,
		models.ActionMCPCall:          1,
		models.ActionContextCompacted: 2,
		models.ActionUnknown:          1, // ImageGen is deliberately unmapped
		models.ActionAssistantMessage: 2,
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s = %d, want %d (all %v)", k, got[k], n, got)
		}
	}

	prompt := findByRaw(t, res.ToolEvents, models.ToolCodeBuddy+".user_prompt")
	if len(prompt.UserAttachments) != 1 || prompt.UserAttachments[0].Kind != "image" ||
		prompt.UserAttachments[0].MediaType != "image/png" {
		t.Errorf("attachments = %+v, want one image/png", prompt.UserAttachments)
	}

	read := findByRaw(t, res.ToolEvents, "Read")
	if read.SourceEventID != "tool:call_read_1" || !read.Success || read.OutcomePending {
		t.Errorf("read id=%q success=%v pending=%v", read.SourceEventID, read.Success, read.OutcomePending)
	}
	if read.Target != "/home/user/project/README.md" || !strings.Contains(read.ToolOutput, "Example Project") {
		t.Errorf("read target=%q output=%q", read.Target, read.ToolOutput)
	}
	if read.PrecedingReasoning != "I should read the README first." || read.Model != "hy3" || read.MessageID != "gen-0001" {
		t.Errorf("read reasoning=%q model=%q msg=%q", read.PrecedingReasoning, read.Model, read.MessageID)
	}
	if read.DurationMs != 1100 {
		t.Errorf("read duration = %d, want 1100", read.DurationMs)
	}

	bash := findByRaw(t, res.ToolEvents, "Bash")
	if bash.Success || bash.ErrorMessage != "exit status 1" || bash.Target != "go test ./..." {
		t.Errorf("bash success=%v err=%q target=%q", bash.Success, bash.ErrorMessage, bash.Target)
	}
	if bash.ContentBytes != int64(len("go test ./...")) {
		t.Errorf("bash content bytes = %d", bash.ContentBytes)
	}

	var bash2 models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "Bash" && ev.Target == "make build" {
			bash2 = ev
		}
	}
	if bash2.Success || bash2.ErrorMessage != "exit code 2" {
		t.Errorf("non-zero rawResponse.exitCode must fail the call: success=%v err=%q", bash2.Success, bash2.ErrorMessage)
	}
	var compactions []string
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionContextCompacted {
			compactions = append(compactions, ev.Target)
			if ev.ToolOutput != "" || ev.RawToolInput != "" {
				t.Errorf("compaction row must carry no content: %+v", ev)
			}
		}
	}
	if len(compactions) != 2 || compactions[0] != "pre-compact" || compactions[1] != "provider" {
		t.Errorf("compactions = %v, want [pre-compact provider]", compactions)
	}

	unknown := findByRaw(t, res.ToolEvents, "ImageGen")
	if unknown.ActionType != models.ActionUnknown {
		t.Errorf("ImageGen action = %q", unknown.ActionType)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "ImageGen") {
		t.Errorf("warnings = %v, want one ImageGen warning", res.Warnings)
	}

	// Sidechain: the forwarded sub-agent assistant line.
	var side int
	for _, ev := range res.ToolEvents {
		if ev.IsSidechain {
			side++
		}
	}
	if side != 1 {
		t.Errorf("sidechain tool events = %d, want 1", side)
	}

	type tok struct {
		id                                     string
		in, out, cacheRead, cacheWrite, reason int64
		side                                   bool
	}
	wantTok := []tok{
		{"tok:gen-0001", 4000, 200, 8000, 0, 100, false},
		{"tok:gen-0002", 1100, 50, 11900, 600, 0, false},
		{"tok:gen-sub-0001", 2000, 40, 0, 0, 0, true},
		{"tok:gen-0003", 1000, 80, 13000, 0, 0, false},
	}
	if len(res.TokenEvents) != len(wantTok) {
		t.Fatalf("token events = %d, want %d", len(res.TokenEvents), len(wantTok))
	}
	for i, w := range wantTok {
		g := res.TokenEvents[i]
		if g.SourceEventID != w.id || g.InputTokens != w.in || g.OutputTokens != w.out ||
			g.CacheReadTokens != w.cacheRead || g.CacheCreationTokens != w.cacheWrite ||
			g.ReasoningTokens != w.reason || g.IsSidechain != w.side {
			t.Errorf("token %d = %+v, want %+v", i, g, w)
		}
		if g.Model != "hy3" || g.TurnID != "01a20000turn0001" || g.SessionID != sid {
			t.Errorf("token %d model=%q turn=%q session=%q", i, g.Model, g.TurnID, g.SessionID)
		}
		if g.Source != models.TokenSourceJSONL || g.Reliability != models.ReliabilityApproximate {
			t.Errorf("token %d source/reliability = %q/%q", i, g.Source, g.Reliability)
		}
	}
	if len(res.CacheObservations) != len(wantTok) {
		t.Errorf("cache observations = %d, want %d", len(res.CacheObservations), len(wantTok))
	}
}

// TestResumedParseOutcomeUpdates splits the synthetic session between the
// tool calls and their results: the first window flags the calls
// OutcomePending, the second delivers the outcomes as OutcomeUpdates and
// still resolves the project root through the prescan.
func TestResumedParseOutcomeUpdates(t *testing.T) {
	body, err := os.ReadFile(fixturePath("synthetic-unobserved-shapes.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	p, a := stage(t, "s1", string(body))
	lines := strings.SplitAfter(string(body), "\n")
	var cut int64
	for _, l := range lines[:6] {
		cut += int64(len(l))
	}
	if err := os.WriteFile(p, body[:cut], 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	pending := 0
	for _, ev := range first.ToolEvents {
		if ev.OutcomePending {
			pending++
		}
	}
	if pending != 2 || first.NewOffset != cut {
		t.Fatalf("pending = %d (want 2), offset = %d (want %d)", pending, first.NewOffset, cut)
	}

	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(context.Background(), p, first.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	upd := map[string]models.ActionOutcomeUpdate{}
	for _, u := range second.OutcomeUpdates {
		upd[u.SourceEventID] = u
	}
	if u := upd["tool:call_read_1"]; !u.SuccessKnown || !u.Success {
		t.Errorf("read update = %+v", u)
	}
	if u := upd["tool:call_bash_1"]; !u.SuccessKnown || u.Success || u.ErrorMessage != "exit status 1" {
		t.Errorf("bash update = %+v", u)
	}
	for _, ev := range second.ToolEvents {
		if ev.ActionType == models.ActionSessionStart {
			t.Error("session_start re-emitted on a resumed parse")
		}
		if !strings.HasSuffix(filepath.ToSlash(ev.ProjectRoot), "/project") {
			t.Errorf("resumed %s project root = %q", ev.ActionType, ev.ProjectRoot)
		}
	}
}

func TestDeterministicIDs(t *testing.T) {
	body, err := os.ReadFile(fixturePath("synthetic-unobserved-shapes.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	p, a := stage(t, "s1", string(body))
	r1, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(r1.ToolEvents) != len(r2.ToolEvents) || len(r1.TokenEvents) != len(r2.TokenEvents) {
		t.Fatal("event counts differ across re-parses")
	}
	seen := map[string]bool{}
	for i := range r1.ToolEvents {
		id := r1.ToolEvents[i].SourceEventID
		if id != r2.ToolEvents[i].SourceEventID {
			t.Errorf("tool id %d differs: %q vs %q", i, id, r2.ToolEvents[i].SourceEventID)
		}
		if seen[id] {
			t.Errorf("duplicate SourceEventID %q", id)
		}
		seen[id] = true
	}
	for i := range r1.TokenEvents {
		if r1.TokenEvents[i].SourceEventID != r2.TokenEvents[i].SourceEventID {
			t.Errorf("token id %d differs", i)
		}
	}
}

func TestCRLFAndPartialTrailingLine(t *testing.T) {
	body, err := os.ReadFile(fixturePath("wsl-auth-error-session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	crlf := strings.ReplaceAll(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n", "\r\n")
	partial := `{"id":"x","timestamp":1792600000000,"type":"message","role":"user","content":[{"type":"input_text","text":"half`
	p, a := stage(t, "01a15cae-7d33-7739-8d55-8b6a3940d798", crlf+partial)
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != int64(len(crlf)) {
		t.Errorf("NewOffset = %d, want %d (stop before the partial line)", res.NewOffset, len(crlf))
	}
	if got := countActions(res.ToolEvents)[models.ActionUserPrompt]; got != 2 {
		t.Errorf("CRLF user prompts = %d, want 2", got)
	}
	for _, ev := range res.ToolEvents {
		if strings.ContainsAny(ev.Target, "\r") {
			t.Errorf("CR leaked into target %q", ev.Target)
		}
	}
}

func TestMalformedLineAdvances(t *testing.T) {
	body := "{not json\n" +
		`{"id":"a1","timestamp":1792600000000,"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}],"cwd":"/home/user/project"}` + "\n"
	p, a := stage(t, "s1", body)
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != int64(len(body)) || len(res.Warnings) != 1 {
		t.Errorf("offset=%d warnings=%v", res.NewOffset, res.Warnings)
	}
	if countActions(res.ToolEvents)[models.ActionUserPrompt] != 1 {
		t.Error("prompt after a malformed line was lost")
	}
}

func TestScrubsSecrets(t *testing.T) {
	secret := "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD"
	body := `{"id":"u1","timestamp":1792600000000,"type":"message","role":"user","content":[{"type":"input_text","text":"use OPENAI_API_KEY=` + secret + `"}],"cwd":"/home/user/project"}` + "\n" +
		`{"id":"c1","timestamp":1792600001000,"type":"function_call","callId":"call_1","name":"Bash","arguments":"{\"command\":\"OPENAI_API_KEY=` + secret + ` make\"}","providerData":{"messageId":"g1"},"cwd":"/home/user/project"}` + "\n" +
		`{"id":"r1","timestamp":1792600002000,"type":"function_call_result","callId":"call_1","name":"Bash","status":"incomplete","output":"auth failed for ` + secret + `","providerData":{}}` + "\n"
	p, a := stage(t, "s1", body)
	res, err := a.ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) != 3 { // session_start + the prompt + the call
		t.Fatalf("events = %d, want 3", len(res.ToolEvents))
	}
	for _, ev := range res.ToolEvents {
		for field, v := range map[string]string{
			"target": ev.Target, "input": ev.RawToolInput, "output": ev.ToolOutput, "error": ev.ErrorMessage,
		} {
			if strings.Contains(v, secret) {
				t.Errorf("%s %s leaks the secret: %q", ev.ActionType, field, v)
			}
		}
	}
}
