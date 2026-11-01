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
	"github.com/marmutapp/superbased-observer/internal/toolaccount"
)

const (
	probeSession = "ffffffff-1111-4222-8333-444444444444-1792584719058"
	quotaSession = "eeeeeeee-1111-4222-8333-444444444444-1792552897123"
)

// hermeticHome points the running process's home at an empty temp dir so no
// real npm install on the test host can leak a version into a test.
func hermeticHome(t *testing.T) string {
	t.Helper()
	h := t.TempDir()
	t.Setenv("HOME", h)
	t.Setenv("USERPROFILE", h)
	return h
}

// dataHomeRoot creates <tmp>/.autohand and returns (dataHome, sessionsRoot).
func dataHomeRoot(t *testing.T) (string, string) {
	t.Helper()
	home := hermeticHome(t)
	dh := filepath.Join(home, ".autohand")
	root := filepath.Join(dh, "sessions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return dh, root
}

func baseMeta(id string) map[string]any {
	return map[string]any{
		"sessionId": id, "createdAt": "2026-10-21T10:00:00.000Z", "lastActiveAt": "2026-10-21T10:05:00.000Z",
		"projectPath": filepath.Join(os.TempDir(), "no-such-project-dir"), "model": "m", "client": "terminal",
	}
}

func userLine(ts, text string) string {
	b, _ := json.Marshal(map[string]any{"role": "user", "content": text, "timestamp": ts})
	return string(b)
}

func TestGitRemoteStampedOnEventsAndTokens(t *testing.T) {
	hermeticHome(t)
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/acme/widgets.git\n"
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "sessions")
	meta := baseMeta("s-remote")
	meta["projectPath"] = repo
	meta["usage"] = map[string]any{"promptTokens": 100, "completionTokens": 10, "tokenUsageStatus": "actual", "updatedAt": "2026-10-21T10:04:00.000Z"}
	conv := writeSession(t, root, "s-remote", meta, []string{userLine("2026-10-21T10:00:01.000Z", "hello")})
	a := NewWithOptions(nil, root)
	for _, p := range []string{conv, filepath.Join(filepath.Dir(conv), metadataName)} {
		res, err := a.ParseSessionFile(context.Background(), p, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.TokenEvents) != 1 || res.TokenEvents[0].GitRemote == "" {
			t.Fatalf("%s: token GitRemote = %+v", filepath.Base(p), res.TokenEvents)
		}
		if filepath.Base(p) == conversationName {
			if len(res.ToolEvents) == 0 || res.ToolEvents[0].GitRemote == "" {
				t.Fatalf("tool GitRemote empty: %+v", res.ToolEvents)
			}
		}
	}
}

func TestTurnIndexIsSessionWideAcrossWindows(t *testing.T) {
	_, root := dataHomeRoot(t)
	lines := []string{
		userLine("2026-10-21T10:00:01.000Z", "one"),
		`{"role":"assistant","content":"a1","timestamp":"2026-10-21T10:00:02.000Z"}`,
		userLine("2026-10-21T10:00:03.000Z", "two"),
		`{"role":"assistant","content":"a2","timestamp":"2026-10-21T10:00:04.000Z"}`,
		userLine("2026-10-21T10:00:05.000Z", "three"),
		`{"role":"assistant","content":"a3","timestamp":"2026-10-21T10:00:06.000Z"}`,
	}
	conv := writeSession(t, root, "s-turn", baseMeta("s-turn"), lines)
	a := NewWithOptions(nil, root)
	whole, err := a.ParseSessionFile(context.Background(), conv, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"a1": 0, "a2": 1, "a3": 2}
	for _, ev := range whole.ToolEvents {
		if ev.ActionType == models.ActionAssistantMessage && ev.TurnIndex != want[ev.Target] {
			t.Errorf("whole parse: %q TurnIndex = %d, want %d", ev.Target, ev.TurnIndex, want[ev.Target])
		}
	}
	data, _ := os.ReadFile(conv)
	offs := lineOffsets(data)
	tail, err := a.ParseSessionFile(context.Background(), conv, offs[3]) // after assistant a2
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, ev := range tail.ToolEvents {
		seen++
		if ev.TurnIndex != 2 {
			t.Errorf("windowed %s %q TurnIndex = %d, want 2", ev.ActionType, ev.Target, ev.TurnIndex)
		}
	}
	if seen != 2 {
		t.Errorf("windowed events = %d, want 2", seen)
	}
}

func TestToolVersionAndAPIErrorFromErrorLog(t *testing.T) {
	hermeticHome(t)
	root := fixtureRoot(t, "windows")
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), filepath.Join(root, quotaSession, "conversation.jsonl"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0].Version != "0.9.8" || res.SessionToolVersions[0].SessionID != quotaSession {
		t.Fatalf("versions = %+v", res.SessionToolVersions)
	}
	var errs []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionAPIError {
			errs = append(errs, ev)
		}
	}
	if len(errs) != 1 {
		t.Fatalf("api_error rows = %d, want 1", len(errs))
	}
	e := errs[0]
	if e.Success || !strings.Contains(e.ErrorMessage, "quota") || e.RawToolName != "autohand.ApiError" ||
		!strings.HasSuffix(e.SourceFile, conversationName) || e.SourceEventID == "" {
		t.Errorf("api_error row = %+v", e)
	}
	// The same record is emitted (same key) from the metadata file.
	res2, err := a.ParseSessionFile(context.Background(), filepath.Join(root, quotaSession, "metadata.json"), 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range res2.ToolEvents {
		if ev.ActionType == models.ActionAPIError && ev.SourceEventID == e.SourceEventID && ev.SourceFile == e.SourceFile {
			found = true
		}
	}
	if !found {
		t.Errorf("metadata parse did not emit the same api_error key")
	}
	// A session outside the record's span gets no api_error row.
	res3, err := a.ParseSessionFile(context.Background(), filepath.Join(root, probeSession, "conversation.jsonl"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if countAction(res3.ToolEvents, models.ActionAPIError) != 0 {
		t.Errorf("unrelated session got an api_error row")
	}
	// ... but still gets the install-level history (newest record before it).
	if len(res3.SessionToolVersions) != 1 || res3.SessionToolVersions[0].Version != "0.9.8" {
		t.Errorf("history version = %+v", res3.SessionToolVersions)
	}
}

func TestToolVersionInstallLevelAndAbsent(t *testing.T) {
	dh, root := dataHomeRoot(t)
	home := filepath.Dir(dh)
	conv := writeSession(t, root, "s-ver", baseMeta("s-ver"), []string{userLine("2026-10-21T10:00:01.000Z", "hi")})
	a := NewWithOptions(nil, root)

	res, err := a.ParseSessionFile(context.Background(), conv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionToolVersions) != 0 {
		t.Fatalf("no source must stamp nothing, got %+v", res.SessionToolVersions)
	}

	pkgDir := filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "autohand-cli")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"name":"autohand-cli","version":"1.2.3"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = a.ParseSessionFile(context.Background(), conv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0].Version != "1.2.3" {
		t.Fatalf("install-level version = %+v", res.SessionToolVersions)
	}

	// A different package at the same path is not trusted.
	pj := filepath.Join(pkgDir, "package.json")
	if err := os.WriteFile(pj, []byte(`{"name":"other","version":"9.9.9"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	_ = os.Chtimes(pj, future, future)
	res, _ = a.ParseSessionFile(context.Background(), conv, 0)
	if len(res.SessionToolVersions) != 0 {
		t.Fatalf("foreign package stamped: %+v", res.SessionToolVersions)
	}
}

func TestErrorLogMalformedRecords(t *testing.T) {
	body := []byte("not json\n---\n" +
		`{"timestamp":"2026-10-21T01:00:00.000Z","cli":{"version":"0.9.7"},"context":{"workspace":"/w"}}` + "\n---\n" +
		`{"timestamp":"2026-10-21T02:00:00.000Z","cli":{"version":"not a version"}}` + "\n---\n" +
		`{"timestamp":"bad"}` + "\n")
	got := parseErrorLog(body)
	if len(got) != 2 || got[0].Version != "0.9.7" || got[1].Version != "" {
		t.Fatalf("entries = %+v", got)
	}
}

func TestAccountObservationsAreAccountLevel(t *testing.T) {
	hermeticHome(t)
	root := fixtureRoot(t, "windows")
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), filepath.Join(root, probeSession, "conversation.jsonl"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolAccounts) != len(res.ToolEvents) || len(res.ToolAccounts) == 0 {
		t.Fatalf("accounts = %d, events = %d", len(res.ToolAccounts), len(res.ToolEvents))
	}
	ids := map[string]bool{}
	for _, ev := range res.ToolEvents {
		ids[ev.SourceEventID] = true
	}
	for _, o := range res.ToolAccounts {
		if _, _, ok := toolaccount.Normalize(o); !ok {
			t.Fatalf("Normalize rejected %+v", o)
		}
		if !models.ToolAccountScopeIsAccountLevel(o.Scope) || o.Email != "" || o.Name != "" ||
			o.AccountID != "personal_00000000-0000-4000-8000-000000000000" || o.Tool != models.ToolAutohand ||
			o.Stage != "activity" || o.BindingKind != "message" || !ids[o.BindingID] {
			t.Errorf("observation = %+v", o)
		}
	}
	// No snapshot, no observation.
	root2 := filepath.Join(t.TempDir(), "sessions")
	conv := writeSession(t, root2, "s", baseMeta("s"), []string{userLine("2026-10-21T10:00:01.000Z", "hi")})
	res, _ = NewWithOptions(nil, root2).ParseSessionFile(context.Background(), conv, 0)
	if len(res.ToolAccounts) != 0 {
		t.Errorf("accounts without a snapshot: %+v", res.ToolAccounts)
	}
}

func writeActiveAgent(t *testing.T, dh, file string, rec map[string]any) string {
	t.Helper()
	dir := filepath.Join(dh, "active-agents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(rec)
	p := filepath.Join(dir, file)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// agentRec is the vendor record shape (ActiveAgentRegistry, autohand-cli
// 0.9.8). No live file exists on disk while no CLI runs, so it is built from
// the vendor source.
func agentRec(id string, pid int, updated time.Time) map[string]any {
	return map[string]any{
		"version": 1, "pid": pid, "sessionId": id, "workspaceRoot": "/w", "projectName": "w",
		"provider": "openrouter", "model": "m", "mode": "interactive", "status": "idle",
		"startedAt": "2026-10-21T10:00:00.000Z", "updatedAt": updated.UTC().Format(time.RFC3339Nano),
		"messageCount": 1, "contextPercent": 0, "tokensUsed": 0,
	}
}

func TestProcessSeedFromActiveAgents(t *testing.T) {
	dh, root := dataHomeRoot(t)
	conv := writeSession(t, root, "s-seed", baseMeta("s-seed"), []string{userLine("2026-10-21T10:00:01.000Z", "hi")})
	writeActiveAgent(t, dh, "s-seed.json", agentRec("s-seed", 4242, time.Now()))
	writeActiveAgent(t, dh, "other.json", agentRec("other", 99, time.Now()))
	bad := agentRec("s-seed", 7, time.Now())
	bad["version"] = 2
	writeActiveAgent(t, dh, "s-seed.inst.json", bad)
	a := NewWithOptions(nil, root)
	for _, p := range []string{conv, filepath.Join(filepath.Dir(conv), metadataName)} {
		res, err := a.ParseSessionFile(context.Background(), p, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.SessionProcessSeeds) != 1 {
			t.Fatalf("%s: seeds = %+v", filepath.Base(p), res.SessionProcessSeeds)
		}
		s := res.SessionProcessSeeds[0]
		if s.PID != 4242 || s.SessionID != "s-seed" || s.Tool != models.ToolAutohand || s.ExecHint != "autohand" || s.CWD != "/w" {
			t.Errorf("seed = %+v", s)
		}
	}
}

func TestResolveTerminalSession(t *testing.T) {
	dh, root := dataHomeRoot(t)
	for _, id := range []string{"s-a", "s-b"} {
		writeSession(t, root, id, baseMeta(id), []string{userLine("2026-10-21T10:00:01.000Z", "hi")})
	}
	a := NewWithOptions(nil, root)
	ctx := context.Background()
	resolve := func(pid int) adapter.TerminalSessionIdentity {
		t.Helper()
		id, err := a.ResolveTerminalSession(ctx, adapter.TerminalProcess{PID: pid})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	writeActiveAgent(t, dh, "s-a.json", agentRec("s-a", 4242, time.Now()))
	if id := resolve(4242); id.SessionID != "s-a" || id.Evidence == "" {
		t.Fatalf("resolve = %+v", id)
	}
	if id := resolve(4243); id.SessionID != "" {
		t.Errorf("unknown pid resolved: %+v", id)
	}
	if id := resolve(1); id.SessionID != "" {
		t.Errorf("pid 1 resolved: %+v", id)
	}
	// A record for a session whose directory does not exist is not trusted.
	writeActiveAgent(t, dh, "ghost.json", agentRec("ghost", 5000, time.Now()))
	if id := resolve(5000); id.SessionID != "" {
		t.Errorf("ghost session resolved: %+v", id)
	}
	// A stale heartbeat is not trusted.
	writeActiveAgent(t, dh, "s-b.json", agentRec("s-b", 6000, time.Now().Add(-time.Hour)))
	if id := resolve(6000); id.SessionID != "" {
		t.Errorf("stale record resolved: %+v", id)
	}
	// Two sessions claiming one pid is ambiguous.
	writeActiveAgent(t, dh, "s-b.json", agentRec("s-b", 4242, time.Now()))
	if id := resolve(4242); id.SessionID != "" {
		t.Errorf("ambiguous pid resolved: %+v", id)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := a.ResolveTerminalSession(cctx, adapter.TerminalProcess{PID: 4242}); err == nil {
		t.Error("cancelled context must error")
	}
}

func TestReadTranscript(t *testing.T) {
	root := fixtureRoot(t, "windows")
	a := NewWithOptions(nil, root)
	hint := filepath.Join(root, probeSession, "metadata.json")
	sess := models.Session{ID: probeSession}
	msgs, err := a.ReadTranscript(context.Background(), sess, []string{hint})
	if err != nil {
		t.Fatal(err)
	}
	// One user prompt, then ONE merged assistant exchange (all calls resolved).
	if len(msgs) != 2 || msgs[0].Role != models.TranscriptUser || msgs[1].Role != models.TranscriptAssistant {
		t.Fatalf("messages = %+v", msgs)
	}
	asst := msgs[1]
	if len(asst.ToolCalls) != 5 || asst.Model != "minimax/minimax-m3.1-flash:free" {
		t.Fatalf("assistant = %+v", asst)
	}
	for _, c := range asst.ToolCalls {
		if !c.Resolved || c.Name == "" {
			t.Errorf("unresolved call %+v", c)
		}
	}
	if !strings.Contains(asst.Text, "7319") {
		t.Errorf("assistant text = %q", asst.Text)
	}
	for _, c := range asst.ToolCalls {
		if strings.Contains(c.ResultExcerpt, "\x1b") {
			t.Errorf("ANSI left in result %q", c.ResultExcerpt)
		}
	}

	// Without a hint the session is found under the watch root.
	if _, err := a.ReadTranscriptFull(context.Background(), sess, nil); err != nil {
		t.Fatalf("root walk: %v", err)
	}
	if _, err := a.ReadTranscript(context.Background(), models.Session{ID: "nope"}, nil); err == nil {
		t.Error("unknown session must error")
	}
	if _, err := a.ReadTranscript(context.Background(), models.Session{ID: "../" + probeSession}, nil); err == nil {
		t.Error("path-traversing id must error")
	}
}

func TestReadTranscriptSkipsInjectedAndStreamChunks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sessions")
	lines := []string{
		userLine("2026-10-21T10:00:01.000Z", "real prompt"),
		`{"role":"user","content":"peer context","timestamp":"2026-10-21T10:00:02.000Z","_meta":{"peerContext":{"x":1}}}`,
		`{"role":"assistant","content":"","timestamp":"2026-10-21T10:00:03.000Z","toolCalls":[{"id":"c1","tool":"shell","args":{"command":"ls"}}]}`,
		`{"role":"tool","content":"chunk","name":"shell","timestamp":"2026-10-21T10:00:04.000Z","tool_call_id":"c1","_meta":{"stream":{"i":0}}}`,
		`{"role":"tool","content":"\u001b[31mfinal\u001b[0m","name":"shell","timestamp":"2026-10-21T10:00:05.000Z","tool_call_id":"c1"}`,
	}
	writeSession(t, root, "s-t", baseMeta("s-t"), lines)
	a := NewWithOptions(nil, root)
	msgs, err := a.ReadTranscript(context.Background(), models.Session{ID: "s-t"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("messages = %+v", msgs)
	}
	if got := msgs[1].ToolCalls[0].ResultExcerpt; got != "final" {
		t.Errorf("result = %q, want final", got)
	}
}
