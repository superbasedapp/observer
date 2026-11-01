package kimchi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// Session ids of the two operator sessions the fixtures were cut from.
const (
	wslSessionID = "01a15d30-a3bd-7702-b5d5-f25eb07c1348"
	winSessionID = "01a15d31-25ed-77b5-9469-15f2cb7b9241"
	// The live sub-agent pair (WSL probe, 2026-10-21): the parent spawned one
	// General-Purpose agent whose own transcript is the child.
	agentParentID = "01a15e7c-4b0a-7717-9be6-b76b788e2652"
	agentChildID  = "01a15e7c-6310-76ac-8c7d-fd37a8f77b89"
)

// fixture copies testdata/kimchi/<name> into a session-shaped path under a
// temp watch root (`sessions/--slug--/<ts>_<id>.jsonl`) and returns the
// adapter and the copy's path. The copy's mtime is `now`, which keeps the
// tail-deferral grace deterministic.
func fixture(t *testing.T, name, sessionID string) (*Adapter, string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "kimchi", name)) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return writeSession(t, body, sessionID)
}

// writeSession writes body as a session file under a fresh temp root.
func writeSession(t *testing.T, body []byte, sessionID string) (*Adapter, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), ".config", "kimchi", "harness", "sessions")
	dir := filepath.Join(root, "--home-user-proj--")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "2026-10-21T06-40-31-166Z_"+sessionID+".jsonl")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return NewWithOptions(nil, root), path
}

func parse(t *testing.T, a *Adapter, path string, from int64) adapter.ParseResult {
	t.Helper()
	res, err := a.ParseSessionFile(context.Background(), path, from)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res
}

func countActions(evs []models.ToolEvent) map[string]int {
	out := map[string]int{}
	for _, e := range evs {
		out[e.ActionType]++
	}
	return out
}

func TestWatchPathsEndInKimchiSessions(t *testing.T) {
	t.Setenv(agentDirEnv, "")
	roots := New().WatchPaths()
	if len(roots) == 0 {
		t.Fatal("no default watch roots")
	}
	for _, p := range roots {
		if !strings.HasSuffix(filepath.ToSlash(p), "/.config/kimchi/harness/sessions") {
			t.Errorf("watch root %q does not end in .config/kimchi/harness/sessions", p)
		}
	}
}

func TestDefaultRootsHonourAgentDirEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(agentDirEnv, dir)
	roots := defaultRoots()
	want := filepath.Join(dir, "sessions")
	if len(roots) == 0 || roots[0] != want {
		t.Fatalf("roots[0] = %v, want %q first", roots, want)
	}
	seen := map[string]bool{}
	for _, r := range roots {
		if seen[r] {
			t.Errorf("duplicate root %q", r)
		}
		seen[r] = true
	}
}

// TestIsSessionFile pins both halves of the predicate: the bare `.jsonl`
// shape is shared with claude-code, codex, pi and prime-agent, so the
// under-root half does the real work.
func TestIsSessionFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".config", "kimchi", "harness", "sessions")
	a := NewWithOptions(nil, root)
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"session under slug dir", filepath.Join(root, "--home-u-p--", "2026-10-21T06-40-31-166Z_"+wslSessionID+".jsonl"), true},
		{"uppercase extension", filepath.Join(root, "--home-u-p--", "X.JSONL"), true},
		{"image cache file", filepath.Join(root, "--home-u-p--", "image-cache", "a.png"), false},
		{"sibling settings", filepath.Join(root, "..", "settings.json"), false},
		{"work-attribution jsonl outside root", filepath.Join(root, "..", "work-attribution", wslSessionID+".jsonl"), false},
		{"pi session, foreign root", filepath.Join(t.TempDir(), ".pi", "agent", "sessions", "--x--", "a.jsonl"), false},
		{"right shape, foreign root", "/tmp/foreign/.config/kimchi/harness/sessions/--x--/a.jsonl", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Errorf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestSessionIDFromPath(t *testing.T) {
	cases := []struct {
		name, path, want string
	}{
		{"linux", "/home/u/.config/kimchi/harness/sessions/--x--/2026-10-21T06-40-31-166Z_" + wslSessionID + ".jsonl", wslSessionID},
		{"windows separators", `C:\Users\u\.config\kimchi\harness\sessions\--C--x--\2026-10-21T06-41-04-493Z_` + winSessionID + ".jsonl", winSessionID},
		{"non-uuid suffix keeps stem", "/x/2026_notauuid.jsonl", "2026_notauuid"},
		{"bare name", "abc.jsonl", "abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sessionIDFromPath(tc.path); got != tc.want {
				t.Errorf("sessionIDFromPath = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestParseLiveFixtures parses both trimmed operator sessions. The token
// sums are the vendor's OWN final `cache_summary` cumulative for each
// session (input; output + reasoning; cacheRead; dollars), which the rows
// must reproduce exactly — while the per-call `llm_response_debug`
// entries that repeat every usage envelope must add nothing.
func TestParseLiveFixtures(t *testing.T) {
	cases := []struct {
		name      string
		file      string
		sessionID string
		cwd       string
		actions   map[string]int
		tokens    int
		input     int64
		output    int64
		reasoning int64
		cacheRead int64
		usd       float64
		failed    int
	}{
		{
			name: "wsl", file: "session-wsl.jsonl", sessionID: wslSessionID,
			cwd: "/home/user/teams-observer-test",
			actions: map[string]int{
				models.ActionSessionStart: 1, models.ActionUserPrompt: 4, models.ActionAPIError: 3,
				models.ActionAssistantMessage: 8, models.ActionRunCommand: 5, models.ActionTodoUpdate: 6,
				models.ActionReadFile: 1, models.ActionWriteFile: 1, models.ActionEditFile: 1,
			},
			tokens: 8, input: 12896, output: 1005, reasoning: 263, cacheRead: 75008, usd: 0.00560096,
			failed: 3,
		},
		{
			name: "windows", file: "session-windows.jsonl", sessionID: winSessionID,
			cwd: `C:\Users\user\sbo-stepin`,
			actions: map[string]int{
				models.ActionSessionStart: 1, models.ActionUserPrompt: 2, models.ActionAPIError: 1,
				models.ActionAssistantMessage: 6, models.ActionRunCommand: 10, models.ActionTodoUpdate: 7,
				models.ActionReadFile: 1, models.ActionWriteFile: 1, models.ActionEditFile: 1,
			},
			tokens: 12, input: 14016, output: 1550, reasoning: 772, cacheRead: 117888, usd: 0.00794736,
			// the kimchi-dev error + bash exit 49 twice + bash exit 127.
			failed: 4,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, path := fixture(t, tc.file, tc.sessionID)
			res := parse(t, a, path, 0)
			if len(res.Warnings) != 0 {
				t.Errorf("warnings: %v", res.Warnings)
			}
			if info, _ := os.Stat(path); res.NewOffset != info.Size() {
				t.Errorf("NewOffset = %d, want file size %d", res.NewOffset, info.Size())
			}
			got := countActions(res.ToolEvents)
			for k, v := range tc.actions {
				if got[k] != v {
					t.Errorf("%s = %d, want %d (all: %v)", k, got[k], v, got)
				}
			}
			failed := 0
			for _, e := range res.ToolEvents {
				if e.SessionID != tc.sessionID {
					t.Errorf("event %s has session %q", e.SourceEventID, e.SessionID)
				}
				if e.Tool != models.ToolKimchi {
					t.Errorf("event %s tool = %q", e.SourceEventID, e.Tool)
				}
				if e.ProjectRoot != tc.cwd {
					t.Errorf("event %s root = %q, want %q", e.SourceEventID, e.ProjectRoot, tc.cwd)
				}
				if e.OutcomePending {
					t.Errorf("event %s left OutcomePending in a complete transcript", e.SourceEventID)
				}
				if !e.Success {
					failed++
				}
			}
			if failed != tc.failed {
				t.Errorf("failed rows = %d, want %d", failed, tc.failed)
			}
			if len(res.TokenEvents) != tc.tokens {
				t.Fatalf("token rows = %d, want %d", len(res.TokenEvents), tc.tokens)
			}
			var in, out, rs, cr int64
			var usd float64
			for _, e := range res.TokenEvents {
				in += e.InputTokens
				out += e.OutputTokens
				rs += e.ReasoningTokens
				cr += e.CacheReadTokens
				usd += e.EstimatedCostUSD
				if e.Model != "openai-codex/gpt-5.6-luna" {
					t.Errorf("token model = %q", e.Model)
				}
				if e.GenMs <= 0 || e.GenBasis != models.GenBasisNative || e.GenTimingV != genTimingV {
					t.Errorf("gen timing = %d/%q/%d", e.GenMs, e.GenBasis, e.GenTimingV)
				}
			}
			if in != tc.input || out != tc.output || rs != tc.reasoning || cr != tc.cacheRead {
				t.Errorf("sums in/out/reasoning/cacheRead = %d/%d/%d/%d, want %d/%d/%d/%d",
					in, out, rs, cr, tc.input, tc.output, tc.reasoning, tc.cacheRead)
			}
			if d := usd - tc.usd; d > 1e-9 || d < -1e-9 {
				t.Errorf("usd = %v, want %v", usd, tc.usd)
			}
			if len(res.CacheObservations) != tc.tokens {
				t.Errorf("cache observations = %d, want %d", len(res.CacheObservations), tc.tokens)
			}
			for _, o := range res.CacheObservations {
				if !o.ImplicitCache {
					t.Errorf("observation %s not marked implicit (openai-codex-responses lane)", o.SourceEventID)
				}
			}
			if len(res.SessionLineages) != 0 {
				t.Errorf("unexpected lineage %v", res.SessionLineages)
			}
		})
	}
}

// TestToolResultStamping checks the Windows session's failing shell calls
// (exit 49, exit 127) land as failures with their output, and a passing
// one as success.
func TestToolResultStamping(t *testing.T) {
	a, path := fixture(t, "session-windows.jsonl", winSessionID)
	res := parse(t, a, path, 0)
	var fail, ok int
	for _, e := range res.ToolEvents {
		if e.RawToolName != "bash" {
			continue
		}
		if e.Success {
			ok++
			continue
		}
		fail++
		if !strings.Contains(e.ErrorMessage, "exited with code") {
			t.Errorf("failed bash %s has error %q", e.SourceEventID, e.ErrorMessage)
		}
	}
	if fail != 3 || ok != 6 {
		t.Errorf("bash fail/ok = %d/%d, want 3/6", fail, ok)
	}
}

func TestEffortAndStopReasonMetadata(t *testing.T) {
	cases := []struct {
		file, sessionID, effort string
	}{
		{"session-windows.jsonl", winSessionID, "medium"},
		{"session-wsl.jsonl", wslSessionID, "off"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			a, path := fixture(t, tc.file, tc.sessionID)
			res := parse(t, a, path, 0)
			for _, e := range res.ToolEvents {
				switch e.ActionType {
				case models.ActionUserPrompt, models.ActionSessionStart:
					continue
				}
				if e.Metadata == nil || e.Metadata.EffortLevel != tc.effort {
					t.Fatalf("%s metadata = %+v, want effort %q", e.SourceEventID, e.Metadata, tc.effort)
				}
				if e.ActionType == models.ActionAPIError && e.Metadata.StopReason != "error" {
					t.Errorf("api_error stop reason = %q", e.Metadata.StopReason)
				}
			}
		})
	}
}

// TestIncrementalParseRecoversState resumes from the middle of the file:
// the cwd, the selected model and the thinking level all sit behind the
// cursor and must be recovered, the ids must match a full parse, and the
// session_start marker must not be re-emitted.
func TestIncrementalParseRecoversState(t *testing.T) {
	a, path := fixture(t, "session-windows.jsonl", winSessionID)
	full := parse(t, a, path, 0)
	body, _ := os.ReadFile(path) //nolint:gosec // test temp file
	// Cut at the start of the second gpt-5.6-luna assistant record.
	idx := strings.Index(string(body), `"id":"29eefa61"`)
	if idx < 0 {
		t.Fatal("anchor record not found")
	}
	cut := int64(strings.LastIndex(string(body[:idx]), "\n") + 1)
	part := parse(t, a, path, cut)

	fullIDs := map[string]models.ToolEvent{}
	for _, e := range full.ToolEvents {
		fullIDs[e.SourceEventID] = e
	}
	if len(part.ToolEvents) == 0 {
		t.Fatal("no events after the cut")
	}
	for _, e := range part.ToolEvents {
		if e.ActionType == models.ActionSessionStart {
			t.Error("session_start re-emitted on a resumed parse")
		}
		want, ok := fullIDs[e.SourceEventID]
		if !ok {
			t.Errorf("resumed id %s not in the full parse", e.SourceEventID)
			continue
		}
		if e.ProjectRoot != want.ProjectRoot || e.Model != want.Model {
			t.Errorf("%s root/model = %q/%q, want %q/%q", e.SourceEventID, e.ProjectRoot, e.Model, want.ProjectRoot, want.Model)
		}
		if (e.Metadata == nil) != (want.Metadata == nil) || (e.Metadata != nil && e.Metadata.EffortLevel != want.Metadata.EffortLevel) {
			t.Errorf("%s effort metadata drifted: %+v vs %+v", e.SourceEventID, e.Metadata, want.Metadata)
		}
	}
	if part.NewOffset != full.NewOffset {
		t.Errorf("resumed NewOffset = %d, full = %d", part.NewOffset, full.NewOffset)
	}
}

// TestDeferUnpairedToolCall truncates the transcript right after an
// assistant record whose tool calls have no result yet: the record must be
// deferred whole (cursor rewound to its start, nothing emitted for it) so
// the next poll sees call and result together.
func TestDeferUnpairedToolCall(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "kimchi", "session-windows.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	idx := strings.Index(string(src), `"id":"29eefa61"`)
	start := strings.LastIndex(string(src[:idx]), "\n") + 1
	end := start + strings.Index(string(src[start:]), "\n") + 1
	a, path := writeSession(t, src[:end], winSessionID)

	res := parse(t, a, path, 0)
	if res.NewOffset != int64(start) {
		t.Errorf("NewOffset = %d, want the deferred record's start %d", res.NewOffset, start)
	}
	if !res.RetrySuggested {
		t.Error("RetrySuggested not set on a deferred tail")
	}
	for _, e := range res.ToolEvents {
		if e.MessageID == "29eefa61" {
			t.Errorf("deferred record emitted %s", e.SourceEventID)
		}
	}
	for _, e := range res.TokenEvents {
		if e.MessageID == "29eefa61" {
			t.Error("deferred record emitted its token row")
		}
	}
	for _, o := range res.CacheObservations {
		if o.MessageID == "29eefa61" {
			t.Error("deferred record emitted its cache observation")
		}
	}
}

func TestSubagentLineage(t *testing.T) {
	a, path := fixture(t, "session-agent-child-wsl.jsonl", agentChildID)
	res := parse(t, a, path, 0)
	if len(res.SessionLineages) != 1 {
		t.Fatalf("lineages = %v", res.SessionLineages)
	}
	got := res.SessionLineages[0]
	want := models.SessionLineage{
		SessionID: agentChildID, ForkedFromID: agentParentID,
		ParentThreadID: agentParentID, ThreadSource: threadSourceSubagent,
	}
	if got != want {
		t.Errorf("lineage = %+v, want %+v", got, want)
	}
	// A resumed poll past the header must not re-stamp it.
	body, _ := os.ReadFile(path) //nolint:gosec // test temp file
	first := int64(strings.Index(string(body), "\n") + 1)
	if again := parse(t, a, path, first); len(again.SessionLineages) != 0 {
		t.Errorf("lineage re-stamped on a resumed parse: %v", again.SessionLineages)
	}
}

// TestForkLineage: a parentSession with no sub-agent marker is an
// operator fork (pi-mono's branch / fork flows), parent named by a Windows
// path read on any host.
func TestForkLineage(t *testing.T) {
	body := `{"type":"session","version":3,"id":"01a15d50-0000-7000-8000-000000000001","timestamp":"2026-10-21T07:00:00.000Z","cwd":"C:\\Users\\user\\p","parentSession":"C:\\Users\\user\\.config\\kimchi\\harness\\sessions\\--C--Users-user-p--\\2026-10-21T06-41-04-493Z_` + winSessionID + `.jsonl"}` + "\n"
	a, path := writeSession(t, []byte(body), "01a15d50-0000-7000-8000-000000000001")
	res := parse(t, a, path, 0)
	want := []models.SessionLineage{{SessionID: "01a15d50-0000-7000-8000-000000000001", ForkedFromID: winSessionID, ThreadSource: threadSourceUser}}
	if len(res.SessionLineages) != 1 || res.SessionLineages[0] != want[0] {
		t.Errorf("lineage = %+v, want %+v", res.SessionLineages, want)
	}
}

func TestMalformedAndPartialLines(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "kimchi", "session-agent-child-wsl.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src) + "{not json\n" + "\n" + `{"type":"message","id":"partial"`
	a, path := writeSession(t, []byte(body), agentChildID)
	res := parse(t, a, path, 0)
	if len(res.Warnings) != 1 {
		t.Errorf("warnings = %v, want exactly the malformed line", res.Warnings)
	}
	wantOffset := int64(len(body) - len(`{"type":"message","id":"partial"`))
	if res.NewOffset != wantOffset {
		t.Errorf("NewOffset = %d, want %d (partial tail deferred)", res.NewOffset, wantOffset)
	}
}

func TestUserAttachmentsAndStringContent(t *testing.T) {
	body := `{"type":"session","version":3,"id":"x","timestamp":"2026-10-21T07:00:00.000Z","cwd":"/nonexistent/p"}` + "\n" +
		`{"type":"message","id":"u1","timestamp":"2026-10-21T07:00:01.000Z","message":{"role":"user","content":[{"type":"image","data":"AAAA","mimeType":"image/png"}],"timestamp":1792566001000}}` + "\n" +
		`{"type":"message","id":"u2","timestamp":"2026-10-21T07:00:02.000Z","message":{"role":"user","content":"plain string prompt","timestamp":1792566002000}}` + "\n"
	a, path := writeSession(t, []byte(body), "01a15d60-0000-7000-8000-000000000001")
	res := parse(t, a, path, 0)
	var prompts []models.ToolEvent
	for _, e := range res.ToolEvents {
		if e.ActionType == models.ActionUserPrompt {
			prompts = append(prompts, e)
		}
	}
	if len(prompts) != 2 {
		t.Fatalf("prompts = %d, want 2", len(prompts))
	}
	if got := prompts[0].UserAttachments; len(got) != 1 || got[0] != (models.UserAttachment{Kind: "image", MediaType: "image/png"}) {
		t.Errorf("attachments = %+v", got)
	}
	if strings.Contains(prompts[0].RawToolInput, "AAAA") {
		t.Error("image payload leaked into the row")
	}
	if prompts[1].Target != "plain string prompt" {
		t.Errorf("string-content prompt target = %q", prompts[1].Target)
	}
	if prompts[0].ProjectRoot != "/nonexistent/p" {
		t.Errorf("unreachable cwd root = %q, want it kept raw", prompts[0].ProjectRoot)
	}
}

func TestScrubsSecrets(t *testing.T) {
	secret := "sk-ant-api03-" + strings.Repeat("A", 90)
	body := `{"type":"session","version":3,"id":"x","timestamp":"2026-10-21T07:00:00.000Z","cwd":"/nonexistent/p"}` + "\n" +
		`{"type":"message","id":"u1","timestamp":"2026-10-21T07:00:01.000Z","message":{"role":"user","content":[{"type":"text","text":"use ANTHROPIC_API_KEY=` + secret + `"}],"timestamp":1792566001000}}` + "\n" +
		`{"type":"message","id":"a1","timestamp":"2026-10-21T07:00:03.000Z","message":{"role":"assistant","content":[{"type":"toolCall","id":"c1","name":"bash","arguments":{"command":"export KEY=` + secret + `"}}],"api":"openai-codex-responses","provider":"openai-codex","model":"gpt-5.6-luna","usage":{"input":1,"output":1,"cacheRead":0,"cacheWrite":0,"totalTokens":2,"cost":{"total":0}},"stopReason":"toolUse","timestamp":1792566002000}}` + "\n" +
		`{"type":"message","id":"r1","timestamp":"2026-10-21T07:00:04.000Z","message":{"role":"toolResult","toolCallId":"c1","toolName":"bash","content":[{"type":"text","text":"` + secret + `"}],"isError":false,"timestamp":1792566004000}}` + "\n"
	a, path := writeSession(t, []byte(body), "01a15d70-0000-7000-8000-000000000001")
	res := parse(t, a, path, 0)
	for _, e := range res.ToolEvents {
		for _, f := range []string{e.Target, e.RawToolInput, e.ToolOutput, e.ErrorMessage} {
			if strings.Contains(f, secret) {
				t.Errorf("%s leaked the secret: %q", e.SourceEventID, f)
			}
		}
	}
}

func TestUsageSplit(t *testing.T) {
	cases := []struct {
		name             string
		u                usage
		wantOut, wantRsn int64
	}{
		{"responses lane", usage{Output: 301, Reasoning: 92}, 209, 92},
		{"no reasoning key", usage{Output: 50}, 50, 0},
		{"reasoning exceeds output clamps", usage{Output: 5, Reasoning: 9}, 0, 9},
		{"negative reasoning ignored", usage{Output: 5, Reasoning: -1}, 5, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, rsn := tc.u.split()
			if out != tc.wantOut || rsn != tc.wantRsn {
				t.Errorf("split = %d/%d, want %d/%d", out, rsn, tc.wantOut, tc.wantRsn)
			}
		})
	}
}

func TestGenMs(t *testing.T) {
	base := time.Date(2026, 10, 21, 6, 47, 4, 875e6, time.UTC)
	cases := []struct {
		name       string
		end, start time.Time
		want       int64
	}{
		{"live span", base.Add(4016 * time.Millisecond), base, 4016},
		{"missing start", base, time.Time{}, 0},
		{"missing end", time.Time{}, base, 0},
		{"inverted", base, base.Add(time.Second), 0},
		{"implausibly long", base.Add(2 * time.Hour), base, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := genMs(tc.end, tc.start); got != tc.want {
				t.Errorf("genMs = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCacheFamilyForAPI(t *testing.T) {
	cases := map[string]string{
		"openai-codex-responses": "openai",
		"openai-completions":     "openai",
		"anthropic-messages":     "anthropic",
		"google-generative-ai":   "",
		"":                       "",
	}
	for api, want := range cases {
		if got := cacheFamilyForAPI(api); got != want {
			t.Errorf("cacheFamilyForAPI(%q) = %q, want %q", api, got, want)
		}
	}
}

func TestMapToolName(t *testing.T) {
	cases := map[string]string{
		"read": models.ActionReadFile, "write": models.ActionWriteFile, "edit": models.ActionEditFile,
		"bash": models.ActionRunCommand, "powershell": models.ActionRunCommand,
		"bash_control": models.ActionAgentControl, "grep": models.ActionSearchText,
		"find": models.ActionSearchFiles, "ls": models.ActionSearchFiles,
		"web_search": models.ActionWebSearch, "web_fetch": models.ActionWebFetch,
		"Agent": models.ActionSpawnSubagent, "dispatch_to_cloud_agent": models.ActionSpawnSubagent,
		"create_todos": models.ActionTodoUpdate, "mark_todo": models.ActionTodoUpdate, "clear_todos": models.ActionTodoUpdate,
		"questionnaire": models.ActionAskUser, "skill_view": models.ActionSkillInvoke,
		"submit_plan": models.ActionPermissionMode, "set_model": models.ActionHarnessCall,
		"mcp": models.ActionMCPCall, "mcp__github__list_issues": models.ActionMCPCall,
		"debug_launch": models.ActionUnknown,
	}
	for name, want := range cases {
		if got := mapToolName(name); got != want {
			t.Errorf("mapToolName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestAuthoredBytes(t *testing.T) {
	cases := []struct {
		name string
		call contentPart
		want int64
	}{
		{"write content", contentPart{Name: "write", Arguments: map[string]any{"content": "print(1)\n"}}, 9},
		{"edit edits[]", contentPart{Name: "edit", Arguments: map[string]any{"edits": []any{
			map[string]any{"oldText": "a", "newText": "bcd"}, map[string]any{"newText": "ef"},
		}}}, 5},
		{"bash command", contentPart{Name: "bash", Arguments: map[string]any{"command": "ls -la"}}, 6},
		{"read authors nothing", contentPart{Name: "read", Arguments: map[string]any{"path": "x"}}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authoredBytes(tc.call); got != tc.want {
				t.Errorf("authoredBytes = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestDeterministicIDs re-parses the same bytes and requires identical ids
// (the (source_file, source_event_id) dedup key, §4.5).
func TestDeterministicIDs(t *testing.T) {
	a, path := fixture(t, "session-wsl.jsonl", wslSessionID)
	first, second := parse(t, a, path, 0), parse(t, a, path, 0)
	if len(first.ToolEvents) != len(second.ToolEvents) || len(first.TokenEvents) != len(second.TokenEvents) {
		t.Fatal("re-parse changed the row counts")
	}
	seen := map[string]bool{}
	for i := range first.ToolEvents {
		id := first.ToolEvents[i].SourceEventID
		if id != second.ToolEvents[i].SourceEventID {
			t.Errorf("id drift at %d: %s vs %s", i, id, second.ToolEvents[i].SourceEventID)
		}
		if seen[id] {
			t.Errorf("duplicate source event id %s", id)
		}
		seen[id] = true
	}
}
