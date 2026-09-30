package copilotcli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// jsonStr returns s as a JSON string literal (including surrounding
// quotes), with any special characters escaped. Fixtures embed OS
// paths into events.jsonl bodies; on Windows a raw path like
// `C:\Users\...` contains backslashes that are invalid JSON escapes
// (`\U`), so the line fails to decode and session.start/model/cwd
// state is never built. Marshalling escapes them while preserving the
// exact byte value the parser reads back (on POSIX this is a no-op).
func jsonStr(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("jsonStr(%q): %v", s, err)
	}
	return string(b)
}

func TestName(t *testing.T) {
	if got := New().Name(); got != models.ToolCopilotCLI {
		t.Fatalf("Name() = %q, want %q", got, models.ToolCopilotCLI)
	}
}

func TestIsSessionFile(t *testing.T) {
	root := t.TempDir()
	ssRoot := filepath.Join(root, ".copilot", "session-state")
	logsRoot := filepath.Join(root, ".copilot", "logs")
	a := NewWithOptions(nil, ssRoot, logsRoot)

	uuid := "9da4aa10-1da9-49a5-931f-f89c2528c6db"
	cases := []struct {
		name string
		path string
		want bool
	}{
		{"events.jsonl under session-state", filepath.Join(ssRoot, uuid, "events.jsonl"), true},
		{"process log under logs", filepath.Join(logsRoot, "process-1779010107630-20477.log"), true},
		{"workspace.yaml ignored", filepath.Join(ssRoot, uuid, "workspace.yaml"), false},
		{"session.db ignored", filepath.Join(ssRoot, uuid, "session.db"), false},
		{"events.jsonl outside watch root", "/tmp/foreign/" + uuid + "/events.jsonl", false},
		{"non-uuid parent rejected", filepath.Join(ssRoot, "notauuid", "events.jsonl"), false},
		{"log without process- prefix", filepath.Join(logsRoot, "other.log"), false},
		{"log outside logs dir", filepath.Join(ssRoot, "process-123.log"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := a.IsSessionFile(c.path); got != c.want {
				t.Errorf("IsSessionFile(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

// TestParseEventsJSONL_Minimal feeds a small synthetic events.jsonl
// covering session.start / user.message / assistant.message (with
// outputTokens) / tool.execution_start + complete / session.shutdown
// and asserts the resulting ToolEvents + TokenEvents.
func TestParseEventsJSONL_Minimal(t *testing.T) {
	dir := t.TempDir()
	uuid := "9da4aa10-1da9-49a5-931f-f89c2528c6db"
	ssRoot := filepath.Join(dir, ".copilot", "session-state")
	sessDir := filepath.Join(ssRoot, uuid)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatal(err)
	}
	evt := filepath.Join(sessDir, "events.jsonl")
	body := strings.Join([]string{
		`{"type":"session.start","data":{"sessionId":"` + uuid + `","copilotVersion":"1.0.48","selectedModel":"gpt-5-mini","context":{"cwd":` + jsonStr(t, dir) + `,"gitRoot":` + jsonStr(t, dir) + `,"branch":"main","repository":"test/repo"}},"id":"e1","timestamp":"2026-05-17T09:28:27.909Z","parentId":null}`,
		`{"type":"system.message","data":{"role":"system","content":"You are the GitHub Copilot CLI."},"id":"e2","timestamp":"2026-05-17T09:28:38.158Z","parentId":"e1"}`,
		`{"type":"user.message","data":{"content":"hello","transformedContent":"hello expanded"},"id":"e3","timestamp":"2026-05-17T09:28:38.300Z","parentId":"e1"}`,
		`{"type":"tool.execution_start","data":{"toolCallId":"call_A","toolName":"view","arguments":{"path":"README.md"},"turnId":"0"},"id":"e4","timestamp":"2026-05-17T09:28:45.201Z","parentId":"e3"}`,
		`{"type":"tool.execution_complete","data":{"toolCallId":"call_A","model":"gpt-5-mini","interactionId":"i1","turnId":"0","success":true,"result":{"content":"file read","detailedContent":"file body"}},"id":"e5","timestamp":"2026-05-17T09:28:45.500Z","parentId":"e4"}`,
		`{"type":"assistant.message","data":{"messageId":"m1","model":"gpt-5-mini","content":"Here is your answer.","interactionId":"i1","turnId":"0","outputTokens":42,"requestId":"00000-abc"},"id":"e6","timestamp":"2026-05-17T09:28:46.000Z","parentId":"e5"}`,
		`{"type":"session.shutdown","data":{},"id":"e7","timestamp":"2026-05-17T09:30:00.000Z","parentId":"e6"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(evt, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if res.NewOffset != int64(len(body)) {
		t.Errorf("NewOffset = %d, want %d", res.NewOffset, len(body))
	}

	// Expect: 1 system_prompt + 1 user_prompt + 1 tool_complete + 0 assistant_text (because content present but assistant.message had 0 tool requests AND content was set — re-check: my code emits assistant_text only when content non-empty AND no tool requests; here there's content and no tool requests, so we WOULD emit assistant_text)
	// Actually look at the body: assistant.message has content "Here is your answer." and no toolRequests → emit assistant_text. Plus session.shutdown.
	// Plus the TokenEvent (outputTokens=42, requestId 00000-abc).
	wantTypes := map[string]int{
		models.ActionSystemPrompt:     1,
		models.ActionUserPrompt:       1,
		models.ActionReadFile:         1,
		models.ActionAssistantMessage: 1, // assistant_text (was ActionUnknown)
		models.ActionSessionEnd:       1,
	}
	got := map[string]int{}
	for _, e := range res.ToolEvents {
		got[e.ActionType]++
	}
	for k, want := range wantTypes {
		if got[k] != want {
			t.Errorf("action %q: got %d, want %d (full got=%v)", k, got[k], want, got)
		}
	}

	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1", len(res.TokenEvents))
	}
	tok := res.TokenEvents[0]
	if tok.OutputTokens != 42 {
		t.Errorf("OutputTokens = %d, want 42", tok.OutputTokens)
	}
	if tok.MessageID != "00000-abc" {
		t.Errorf("MessageID = %q, want %q (requestId)", tok.MessageID, "00000-abc")
	}
	if tok.Reliability != models.ReliabilityUnreliable {
		t.Errorf("Reliability = %q, want unreliable (Tier 3 fallback)", tok.Reliability)
	}
}

// TestParseProcessLog_DebugUsage feeds a synthetic log with the
// Tier-1 debug pattern and asserts the extracted usage row.
func TestParseProcessLog_DebugUsage(t *testing.T) {
	dir := t.TempDir()
	logsRoot := filepath.Join(dir, ".copilot", "logs")
	if err := os.MkdirAll(logsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(logsRoot, "process-1779010107630-20477.log")
	body := `2026-05-17T09:28:27.900Z [INFO] Workspace initialized: 9da4aa10-1da9-49a5-931f-f89c2528c6db (checkpoints: 0)
2026-05-17T09:28:29.893Z [INFO] Using default model: gpt-5-mini
2026-05-17T09:28:38.632Z [INFO] CompactionProcessor: Utilization 14.9% (19052/128000 tokens) below threshold 80%
2026-05-17T10:08:24.316Z [DEBUG] response (Request-ID 00000-9b802492-c2eb-431d-a99a-f417284f7140):
2026-05-17T10:08:24.316Z [DEBUG] data:
2026-05-17T10:08:24.316Z [DEBUG] {
  "id": "abc",
  "choices": [
    { "message": { "content": null, "role": "assistant" }, "index": 0, "finish_reason": "stop" }
  ],
  "usage": {
    "completion_tokens": 565,
    "prompt_tokens": 15474,
    "total_tokens": 16039,
    "prompt_tokens_details": {
      "cached_tokens": 2560
    },
    "completion_tokens_details": {
      "reasoning_tokens": 448
    }
  }
}
2026-05-17T10:08:30.000Z [INFO] CompactionProcessor: Utilization 16.5% (21100/128000 tokens) below threshold 80%
`
	if err := os.WriteFile(log, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, logsRoot)
	res, err := a.ParseSessionFile(context.Background(), log, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1 (got %+v)", len(res.TokenEvents), res.TokenEvents)
	}
	tok := res.TokenEvents[0]
	if tok.MessageID != "00000-9b802492-c2eb-431d-a99a-f417284f7140" {
		t.Errorf("MessageID = %q, want the Request-ID", tok.MessageID)
	}
	// InputTokens is NET non-cached. Upstream reported prompt_tokens=15474
	// with cached_tokens=2560, so net = 12914. See log.go emitTokenEvent
	// and the cost-engine TokenBundle.Input contract.
	if tok.InputTokens != 12914 {
		t.Errorf("InputTokens = %d, want 12914 (15474 gross - 2560 cached)", tok.InputTokens)
	}
	// Wire completion_tokens (565) is GROSS and contains the reasoning
	// subset (448); the adapter nets it → OutputTokens=117 so the cost
	// engine (which bills Reasoning additively at the output rate) doesn't
	// double-bill reasoning. Invariant: net output + reasoning == 565.
	if tok.OutputTokens != 117 {
		t.Errorf("OutputTokens = %d, want 117 (565 gross - 448 reasoning)", tok.OutputTokens)
	}
	if tok.CacheReadTokens != 2560 {
		t.Errorf("CacheReadTokens = %d, want 2560", tok.CacheReadTokens)
	}
	if tok.ReasoningTokens != 448 {
		t.Errorf("ReasoningTokens = %d, want 448", tok.ReasoningTokens)
	}
	if got := tok.OutputTokens + tok.ReasoningTokens; got != 565 {
		t.Errorf("net output + reasoning = %d, want 565 (gross completion_tokens)", got)
	}
	if tok.SessionID != "9da4aa10-1da9-49a5-931f-f89c2528c6db" {
		t.Errorf("SessionID = %q, want extracted from Workspace initialized line", tok.SessionID)
	}
	if tok.Model != "gpt-5-mini" {
		t.Errorf("Model = %q, want gpt-5-mini", tok.Model)
	}
	if tok.Reliability != models.ReliabilityApproximate {
		t.Errorf("Reliability = %q, want approximate (Tier 1)", tok.Reliability)
	}
}

// TestParseProcessLog_CacheCreationDecomposed pins the modern Copilot CLI
// (1.0.60+ Anthropic-via-Bedrock) cache-write capture. The usage block reports
// `cache_creation_tokens` inside `prompt_tokens_details`, and `prompt_tokens`
// is the GROSS prompt = input + cached_tokens + cache_creation_tokens. The
// parser must net BOTH cached subsets out of input and surface cache_creation
// in its own column — otherwise the cache-write portion bills at the full
// input rate AND again as cache_creation. Live shape (session 946bfb36):
// prompt 16267 = 10 input + 0 read + 16257 write.
func TestParseProcessLog_CacheCreationDecomposed(t *testing.T) {
	dir := t.TempDir()
	logsRoot := filepath.Join(dir, ".copilot", "logs")
	if err := os.MkdirAll(logsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(logsRoot, "process-1780921459687-23436.log")
	body := `2026-06-08T12:24:00.000Z [INFO] Workspace initialized: 946bfb36-ad80-4323-8a19-9c5d7620c331 (checkpoints: 0)
2026-06-08T12:24:00.100Z [INFO] Using default model: claude-haiku-4.5
2026-06-08T12:24:28.075Z [DEBUG] response (Request-ID DD86:3DBC98:11337CF:121E92C:6A26B477):
2026-06-08T12:24:28.075Z [DEBUG] data:
2026-06-08T12:24:28.075Z [DEBUG] {
  "id": "msg_bdrk_014uM7R7eDswYHRTFdNihDUK",
  "model": "claude-haiku-4-5-20251001",
  "usage": {
    "prompt_tokens": 16267,
    "completion_tokens": 152,
    "total_tokens": 16419,
    "prompt_tokens_details": {
      "cached_tokens": 0,
      "cache_creation_tokens": 16257
    },
    "completion_tokens_details": {
      "reasoning_tokens": 93
    }
  }
}
2026-06-08T12:24:28.200Z [INFO] some non-DEBUG line that closes the block
`
	if err := os.WriteFile(log, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, logsRoot)
	res, err := a.ParseSessionFile(context.Background(), log, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1 (got %+v)", len(res.TokenEvents), res.TokenEvents)
	}
	tok := res.TokenEvents[0]
	if tok.InputTokens != 10 {
		t.Errorf("InputTokens = %d, want 10 (16267 gross - 0 read - 16257 write)", tok.InputTokens)
	}
	if tok.CacheReadTokens != 0 {
		t.Errorf("CacheReadTokens = %d, want 0", tok.CacheReadTokens)
	}
	if tok.CacheCreationTokens != 16257 {
		t.Errorf("CacheCreationTokens = %d, want 16257 (the cache-write portion)", tok.CacheCreationTokens)
	}
	// Wire completion_tokens (152) is GROSS and contains the reasoning
	// subset (93 — verified 16267 prompt + 152 completion == 16419 total,
	// so reasoning is inside completion, not a separate summand). The
	// adapter nets it → OutputTokens=59. Invariant: 59 + 93 == 152.
	if tok.OutputTokens != 59 {
		t.Errorf("OutputTokens = %d, want 59 (152 gross - 93 reasoning)", tok.OutputTokens)
	}
	if tok.ReasoningTokens != 93 {
		t.Errorf("ReasoningTokens = %d, want 93", tok.ReasoningTokens)
	}
	if got := tok.OutputTokens + tok.ReasoningTokens; got != 152 {
		t.Errorf("net output + reasoning = %d, want 152 (gross completion_tokens)", got)
	}
}

// TestParseProcessLog_ModelFromResponseBlockWithoutDefaultModel pins audit
// Finding A: a process log that lacks the `[INFO] Using default model: …` line
// recovers the model from the response body's top-level "model" field, so the
// Tier-1 row is no longer stamped with an empty model (which would price as
// $0 / unknown). The capi: router prefix is stripped; the dashed
// claude-opus-4-7 form is preserved — NOT remapped to a dot — because our
// pricing table keys on the dashed form (the §3 dash/dot caveat).
func TestParseProcessLog_ModelFromResponseBlockWithoutDefaultModel(t *testing.T) {
	dir := t.TempDir()
	logsRoot := filepath.Join(dir, ".copilot", "logs")
	if err := os.MkdirAll(logsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(logsRoot, "process-1779010107630-20477.log")
	// No `[INFO] Using default model:` line — the model lives only in the
	// response body, carrying a capi: routing prefix.
	body := `2026-05-17T09:28:27.900Z [INFO] Workspace initialized: 9da4aa10-1da9-49a5-931f-f89c2528c6db (checkpoints: 0)
2026-05-17T10:08:24.316Z [DEBUG] response (Request-ID 00000-9b802492-c2eb-431d-a99a-f417284f7140):
2026-05-17T10:08:24.316Z [DEBUG] data:
2026-05-17T10:08:24.316Z [DEBUG] {
  "id": "abc",
  "model": "capi:claude-opus-4-7",
  "usage": {
    "completion_tokens": 565,
    "prompt_tokens": 15474,
    "total_tokens": 16039,
    "prompt_tokens_details": {
      "cached_tokens": 2560
    }
  }
}
2026-05-17T10:08:30.000Z [INFO] some non-DEBUG line that closes the block
`
	if err := os.WriteFile(log, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, logsRoot)
	res, err := a.ParseSessionFile(context.Background(), log, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1 (got %+v)", len(res.TokenEvents), res.TokenEvents)
	}
	if got := res.TokenEvents[0].Model; got != "claude-opus-4-7" {
		t.Errorf("Model = %q, want claude-opus-4-7 (capi: stripped, dashed form preserved, not remapped to a dot)", got)
	}
}

// TestParseProcessLog_ModelFallbackFromSiblingEvents pins audit Finding A's
// last-resort recovery: a process log with neither an `[INFO] Using default
// model: …` line nor a response-body "model" field falls back to the sibling
// session-state/<id>/events.jsonl selectedModel, so the Tier-1 row is
// attributed instead of landing unpriced as unknown-model. The sibling
// selectedModel is kept verbatim (dots preserved — dispatchState does not
// normalize).
func TestParseProcessLog_ModelFallbackFromSiblingEvents(t *testing.T) {
	dir := t.TempDir()
	uuid := "9da4aa10-1da9-49a5-931f-f89c2528c6db"
	logsRoot := filepath.Join(dir, ".copilot", "logs")
	if err := os.MkdirAll(logsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	// Sibling events.jsonl carrying the selectedModel (dotted, 1m-internal).
	sessDir := filepath.Join(dir, ".copilot", "session-state", uuid)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatal(err)
	}
	events := `{"type":"session.start","data":{"sessionId":"` + uuid + `","selectedModel":"claude-opus-4.7-1m-internal"},"id":"e1","timestamp":"2026-05-17T09:28:27.909Z","parentId":null}` + "\n"
	if err := os.WriteFile(filepath.Join(sessDir, "events.jsonl"), []byte(events), 0o644); err != nil {
		t.Fatal(err)
	}
	// Process log: a usage block but NO model anywhere (no default-model line,
	// no response-body "model").
	log := filepath.Join(logsRoot, "process-1779010107630-20477.log")
	body := `2026-05-17T09:28:27.900Z [INFO] Workspace initialized: ` + uuid + ` (checkpoints: 0)
2026-05-17T10:08:24.316Z [DEBUG] response (Request-ID 00000-9b802492-c2eb-431d-a99a-f417284f7140):
2026-05-17T10:08:24.316Z [DEBUG] data:
2026-05-17T10:08:24.316Z [DEBUG] {
  "usage": {
    "completion_tokens": 565,
    "prompt_tokens": 15474,
    "total_tokens": 16039,
    "prompt_tokens_details": {
      "cached_tokens": 2560
    }
  }
}
2026-05-17T10:08:30.000Z [INFO] some non-DEBUG line that closes the block
`
	if err := os.WriteFile(log, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, logsRoot)
	res, err := a.ParseSessionFile(context.Background(), log, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1 (got %+v)", len(res.TokenEvents), res.TokenEvents)
	}
	if got := res.TokenEvents[0].Model; got != "claude-opus-4.7-1m-internal" {
		t.Errorf("Model = %q, want claude-opus-4.7-1m-internal (recovered from sibling events.jsonl, verbatim)", got)
	}
}

// TestParseProcessLog_RecoverNullRequestIDFromSiblingEvents pins the modern
// Copilot CLI (1.0.60+) Request-ID recovery: the process log emits
// `[DEBUG] response (Request-ID null)`, so reResponseHdr captures the literal
// "null". The sibling events.jsonl assistant.message still records the real
// hex:colon requestId; the parser recovers it onto the Tier-1 MessageID by
// matching output-token count. SourceEventID stays log:null:1 (deterministic
// + migration-safe — a rescan UPSERTs onto the existing row instead of
// inserting a duplicate).
func TestParseProcessLog_RecoverNullRequestIDFromSiblingEvents(t *testing.T) {
	dir := t.TempDir()
	uuid := "946bfb36-ad80-4323-8a19-9c5d7620c331"
	logsRoot := filepath.Join(dir, ".copilot", "logs")
	if err := os.MkdirAll(logsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	sessDir := filepath.Join(dir, ".copilot", "session-state", uuid)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Sibling events.jsonl: the assistant.message carries the real
	// hex:colon requestId + the matching outputTokens.
	events := `{"type":"session.start","data":{"sessionId":"` + uuid + `","selectedModel":"claude-haiku-4.5"},"id":"e1","timestamp":"2026-06-08T12:24:00.000Z","parentId":null}` + "\n" +
		`{"type":"assistant.message","data":{"requestId":"DD86:3DBC98:11337CF:121E92C:6A26B477","messageId":"e0182ce3-f80e-48dc-bd3d-b8f4591126c0","outputTokens":152,"model":"claude-haiku-4.5"},"id":"a1","timestamp":"2026-06-08T12:24:28.076Z","parentId":null}` + "\n"
	if err := os.WriteFile(filepath.Join(sessDir, "events.jsonl"), []byte(events), 0o644); err != nil {
		t.Fatal(err)
	}
	// Process log: a Tier-1 usage block whose header is `Request-ID null`.
	log := filepath.Join(logsRoot, "process-1780921459687-23436.log")
	body := `2026-06-08T12:24:00.000Z [INFO] Workspace initialized: ` + uuid + ` (checkpoints: 0)
2026-06-08T12:24:00.100Z [INFO] Using default model: claude-haiku-4.5
2026-06-08T12:24:28.075Z [DEBUG] response (Request-ID null):
2026-06-08T12:24:28.075Z [DEBUG] data:
2026-06-08T12:24:28.075Z [DEBUG] {
  "id": "msg_bdrk_014uM7R7eDswYHRTFdNihDUK",
  "model": "claude-haiku-4-5-20251001",
  "usage": {
    "completion_tokens": 152,
    "prompt_tokens": 16267,
    "total_tokens": 16419,
    "prompt_tokens_details": { "cached_tokens": 0 },
    "completion_tokens_details": { "reasoning_tokens": 93 }
  }
}
2026-06-08T12:24:28.200Z [INFO] some non-DEBUG line that closes the block
`
	if err := os.WriteFile(log, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, logsRoot)
	res, err := a.ParseSessionFile(context.Background(), log, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1 (got %+v)", len(res.TokenEvents), res.TokenEvents)
	}
	tok := res.TokenEvents[0]
	if tok.MessageID != "DD86:3DBC98:11337CF:121E92C:6A26B477" {
		t.Errorf("MessageID = %q, want the recovered hex:colon requestId (not the literal \"null\")", tok.MessageID)
	}
	if tok.SourceEventID != "log:null:1" {
		t.Errorf("SourceEventID = %q, want log:null:1 (kept stable so a rescan UPSERTs onto the existing row)", tok.SourceEventID)
	}
	if tok.OutputTokens != 152 {
		t.Errorf("OutputTokens = %d, want 152", tok.OutputTokens)
	}
}

// TestParseProcessLog_RecoverNullRequestIDsMultiTurnNearestTimestamp pins the
// consume-once + nearest-timestamp disambiguation: two `Request-ID null`
// blocks with the SAME output-token count must each map to a distinct
// events.jsonl ref, chosen by closest timestamp.
func TestParseProcessLog_RecoverNullRequestIDsMultiTurnNearestTimestamp(t *testing.T) {
	dir := t.TempDir()
	uuid := "11111111-2222-3333-4444-555555555555"
	logsRoot := filepath.Join(dir, ".copilot", "logs")
	if err := os.MkdirAll(logsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	sessDir := filepath.Join(dir, ".copilot", "session-state", uuid)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Two assistant.message refs, identical outputTokens=100, distinct
	// requestIds + timestamps near each block.
	events := `{"type":"session.start","data":{"sessionId":"` + uuid + `","selectedModel":"gpt-5-mini"},"id":"e1","timestamp":"2026-06-08T12:24:00.000Z","parentId":null}` + "\n" +
		`{"type":"assistant.message","data":{"requestId":"REQ-A:1","outputTokens":100},"id":"a1","timestamp":"2026-06-08T12:24:10.050Z","parentId":null}` + "\n" +
		`{"type":"assistant.message","data":{"requestId":"REQ-B:2","outputTokens":100},"id":"a2","timestamp":"2026-06-08T12:24:20.050Z","parentId":null}` + "\n"
	if err := os.WriteFile(filepath.Join(sessDir, "events.jsonl"), []byte(events), 0o644); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(logsRoot, "process-1780921459687-99999.log")
	body := `2026-06-08T12:24:00.000Z [INFO] Workspace initialized: ` + uuid + ` (checkpoints: 0)
2026-06-08T12:24:00.100Z [INFO] Using default model: gpt-5-mini
2026-06-08T12:24:10.000Z [DEBUG] response (Request-ID null):
2026-06-08T12:24:10.000Z [DEBUG] data:
2026-06-08T12:24:10.000Z [DEBUG] {
  "usage": {
    "completion_tokens": 100,
    "prompt_tokens": 5000,
    "total_tokens": 5100,
    "prompt_tokens_details": { "cached_tokens": 0 }
  }
}
2026-06-08T12:24:20.000Z [DEBUG] response (Request-ID null):
2026-06-08T12:24:20.000Z [DEBUG] data:
2026-06-08T12:24:20.000Z [DEBUG] {
  "usage": {
    "completion_tokens": 100,
    "prompt_tokens": 6000,
    "total_tokens": 6100,
    "prompt_tokens_details": { "cached_tokens": 0 }
  }
}
2026-06-08T12:24:30.000Z [INFO] some non-DEBUG line that closes the block
`
	if err := os.WriteFile(log, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, logsRoot)
	res, err := a.ParseSessionFile(context.Background(), log, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 2 {
		t.Fatalf("TokenEvents = %d, want 2 (got %+v)", len(res.TokenEvents), res.TokenEvents)
	}
	byEID := map[string]string{}
	for _, te := range res.TokenEvents {
		byEID[te.SourceEventID] = te.MessageID
	}
	if byEID["log:null:1"] != "REQ-A:1" {
		t.Errorf("first block (ts 12:24:10) MessageID = %q, want REQ-A:1 (nearest timestamp)", byEID["log:null:1"])
	}
	if byEID["log:null:2"] != "REQ-B:2" {
		t.Errorf("second block (ts 12:24:20) MessageID = %q, want REQ-B:2 (the remaining ref)", byEID["log:null:2"])
	}
}

// TestParseProcessLog_HexOpaqueRequestID pins the v1.6.8 B3 fix:
// Copilot CLI's debug log emits `[DEBUG] response (Request-ID …)`
// headers using TWO distinct Request-ID shapes. The dominant shape
// in production (91.9% on the operator sample) is hex:colon style —
// uppercase hex octets separated by colons, e.g.
// `6BB4:37EE0:992BB:A7CA1:69E65431`. The original v1.6.6 regex
// `[0-9a-f-]+` rejected uppercase + colons and silently dropped
// Tier-1 coverage for those requests. The fix uses `[^\s)]+` —
// permissive up to the closing paren. See audit doc §B3.
func TestParseProcessLog_HexOpaqueRequestID(t *testing.T) {
	dir := t.TempDir()
	logsRoot := filepath.Join(dir, ".copilot", "logs")
	if err := os.MkdirAll(logsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(logsRoot, "process-1779010107630-20477.log")
	// Two consecutive response blocks: one hex:colon (the dominant
	// production format), one 00000-uuid (the format the v1.6.6 regex
	// matched). Both must extract usage correctly.
	body := `2026-05-17T09:28:27.900Z [INFO] Workspace initialized: 9da4aa10-1da9-49a5-931f-f89c2528c6db (checkpoints: 0)
2026-05-17T09:28:29.893Z [INFO] Using default model: claude-opus-4.7
2026-05-17T10:08:24.316Z [DEBUG] response (Request-ID 6BB4:37EE0:992BB:A7CA1:69E65431):
2026-05-17T10:08:24.316Z [DEBUG] data:
2026-05-17T10:08:24.316Z [DEBUG] {
  "usage": {
    "completion_tokens": 100,
    "prompt_tokens": 5000,
    "total_tokens": 5100,
    "prompt_tokens_details": {
      "cached_tokens": 1000
    }
  }
}
2026-05-17T10:09:00.000Z [DEBUG] response (Request-ID 00000-abcd1234-ef56-7890-abcd-1234567890ab):
2026-05-17T10:09:00.000Z [DEBUG] data:
2026-05-17T10:09:00.000Z [DEBUG] {
  "usage": {
    "completion_tokens": 200,
    "prompt_tokens": 6000,
    "total_tokens": 6200,
    "prompt_tokens_details": {
      "cached_tokens": 2000
    }
  }
}
2026-05-17T10:10:00.000Z [INFO] some non-DEBUG line that closes the prior response block
`
	if err := os.WriteFile(log, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, logsRoot)
	res, err := a.ParseSessionFile(context.Background(), log, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if got := len(res.TokenEvents); got != 2 {
		t.Fatalf("TokenEvents = %d, want 2 (one per Request-ID shape)", got)
	}
	byMID := map[string]models.TokenEvent{}
	for _, te := range res.TokenEvents {
		byMID[te.MessageID] = te
	}
	// InputTokens are NET non-cached: fixture's gross 5000 with 1000
	// cached → 4000; gross 6000 with 2000 cached → 4000.
	if te, ok := byMID["6BB4:37EE0:992BB:A7CA1:69E65431"]; !ok {
		t.Errorf("missing TokenEvent for hex:colon Request-ID (got %v)", byMID)
	} else if te.InputTokens != 4000 || te.OutputTokens != 100 || te.CacheReadTokens != 1000 {
		t.Errorf("hex:colon usage: got in=%d out=%d cr=%d want 4000/100/1000 (gross 5000 net of 1000 cached)", te.InputTokens, te.OutputTokens, te.CacheReadTokens)
	}
	if te, ok := byMID["00000-abcd1234-ef56-7890-abcd-1234567890ab"]; !ok {
		t.Errorf("missing TokenEvent for 00000-uuid Request-ID")
	} else if te.InputTokens != 4000 || te.OutputTokens != 200 || te.CacheReadTokens != 2000 {
		t.Errorf("uuid usage: got in=%d out=%d cr=%d want 4000/200/2000 (gross 6000 net of 2000 cached)", te.InputTokens, te.OutputTokens, te.CacheReadTokens)
	}
}

// TestParseProcessLog_MultipleResponseBlocks confirms the state machine
// emits N TokenEvents for N response blocks within one log file.
func TestParseProcessLog_MultipleResponseBlocks(t *testing.T) {
	dir := t.TempDir()
	logsRoot := filepath.Join(dir, ".copilot", "logs")
	if err := os.MkdirAll(logsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(logsRoot, "process-1779013421413-36764.log")
	body := `2026-05-17T10:23:42.745Z [INFO] Workspace initialized: 72bbb346-0158-4da7-bbd7-cb65b8f37109 (checkpoints: 0)
2026-05-17T10:23:45.427Z [INFO] Using default model: gpt-5-mini
2026-05-17T10:23:46.918Z [INFO] CompactionProcessor: Utilization 13.6% (17352/128000 tokens) below threshold 80%
2026-05-17T10:23:47.000Z [DEBUG] response (Request-ID 00000-9b802492-c2eb-431d-a99a-f417284f7140):
2026-05-17T10:23:47.000Z [DEBUG] data:
2026-05-17T10:23:47.000Z [DEBUG] {
  "usage": {
    "completion_tokens": 565,
    "prompt_tokens": 15474,
    "total_tokens": 16039,
    "prompt_tokens_details": { "cached_tokens": 2560 },
    "completion_tokens_details": { "reasoning_tokens": 448 }
  }
}
2026-05-17T10:23:54.000Z [INFO] CompactionProcessor: Utilization 13.7% (17544/128000 tokens) below threshold 80%
2026-05-17T10:23:55.000Z [DEBUG] response (Request-ID 00000-9b802492-c2eb-431d-a99a-f417284f7140):
2026-05-17T10:23:55.000Z [DEBUG] data:
2026-05-17T10:23:55.000Z [DEBUG] {
  "usage": {
    "completion_tokens": 603,
    "prompt_tokens": 16065,
    "total_tokens": 16668,
    "prompt_tokens_details": { "cached_tokens": 15872 },
    "completion_tokens_details": { "reasoning_tokens": 448 }
  }
}
`
	if err := os.WriteFile(log, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, logsRoot)
	res, err := a.ParseSessionFile(context.Background(), log, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 2 {
		t.Fatalf("TokenEvents = %d, want 2 (got %+v)", len(res.TokenEvents), res.TokenEvents)
	}
	totalIn := res.TokenEvents[0].InputTokens + res.TokenEvents[1].InputTokens
	totalOut := res.TokenEvents[0].OutputTokens + res.TokenEvents[1].OutputTokens
	if totalIn != 15474+16065 {
		t.Errorf("sum InputTokens = %d, want %d", totalIn, 15474+16065)
	}
	if totalOut != 565+603 {
		t.Errorf("sum OutputTokens = %d, want %d", totalOut, 565+603)
	}
}

// TestParseEventsJSONL_PartialTrailingLine verifies the cursor defers
// past a partial (no-newline) trailing line per Invariants #52/#53.
func TestParseEventsJSONL_PartialTrailingLine(t *testing.T) {
	dir := t.TempDir()
	uuid := "9da4aa10-1da9-49a5-931f-f89c2528c6db"
	ssRoot := filepath.Join(dir, ".copilot", "session-state")
	sessDir := filepath.Join(ssRoot, uuid)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatal(err)
	}
	evt := filepath.Join(sessDir, "events.jsonl")
	full := `{"type":"session.start","data":{"sessionId":"` + uuid + `"},"id":"e1","timestamp":"2026-05-17T09:28:27.909Z","parentId":null}` + "\n"
	partial := `{"type":"user.message","data":{"content":"`
	if err := os.WriteFile(evt, []byte(full+partial), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if res.NewOffset != int64(len(full)) {
		t.Errorf("NewOffset = %d, want %d (cursor must NOT advance past partial trailing line)", res.NewOffset, len(full))
	}
}

// TestParseProcessLog_Tier2_InfoOnlyLogging confirms that when a
// log file has NO [DEBUG] response (Request-ID …) lines (i.e. the
// agent ran without --log-level debug), the parser emits one
// Tier 2 TokenEvent per CompactionProcessor: Utilization snapshot.
// Pins the v1.6.3 fallback path that closes the
// "no debug log = no input tokens" gap.
func TestParseProcessLog_Tier2_InfoOnlyLogging(t *testing.T) {
	dir := t.TempDir()
	logsRoot := filepath.Join(dir, ".copilot", "logs")
	if err := os.MkdirAll(logsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(logsRoot, "process-1779030000000-12345.log")
	body := `2026-05-17T09:28:27.900Z [INFO] Workspace initialized: 9da4aa10-1da9-49a5-931f-f89c2528c6db (checkpoints: 0)
2026-05-17T09:28:29.893Z [INFO] Using default model: gpt-5-mini
2026-05-17T09:28:38.632Z [INFO] CompactionProcessor: Utilization 14.9% (19052/128000 tokens) below threshold 80%
2026-05-17T09:28:38.634Z [INFO] --- Start of group: Sending request to the AI model ---
2026-05-17T09:28:45.198Z [INFO] --- End of group ---
2026-05-17T09:28:45.233Z [INFO] CompactionProcessor: Utilization 14.9% (19113/128000 tokens) below threshold 80%
2026-05-17T09:28:45.233Z [INFO] --- Start of group: Sending request to the AI model ---
2026-05-17T09:28:48.096Z [INFO] --- End of group ---
2026-05-17T09:28:48.202Z [INFO] CompactionProcessor: Utilization 21.5% (27526/128000 tokens) below threshold 80%
`
	if err := os.WriteFile(log, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, logsRoot)
	res, err := a.ParseSessionFile(context.Background(), log, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 3 {
		t.Fatalf("TokenEvents = %d, want 3 (one per Utilization sample); got %+v",
			len(res.TokenEvents), res.TokenEvents)
	}
	wantInputs := []int64{19052, 19113, 27526}
	for i, tok := range res.TokenEvents {
		if tok.InputTokens != wantInputs[i] {
			t.Errorf("event %d: InputTokens = %d, want %d", i, tok.InputTokens, wantInputs[i])
		}
		if tok.OutputTokens != 0 {
			t.Errorf("event %d: OutputTokens = %d, want 0 (Tier 2 is input-only)", i, tok.OutputTokens)
		}
		if tok.Source != models.TokenSourceLogDelta {
			t.Errorf("event %d: Source = %q, want %q", i, tok.Source, models.TokenSourceLogDelta)
		}
		if tok.Reliability != models.ReliabilityApproximate {
			t.Errorf("event %d: Reliability = %q, want approximate", i, tok.Reliability)
		}
		if tok.MessageID != "" {
			t.Errorf("event %d: MessageID = %q, want empty (no Request-ID at INFO level)", i, tok.MessageID)
		}
		if tok.SessionID != "9da4aa10-1da9-49a5-931f-f89c2528c6db" {
			t.Errorf("event %d: SessionID = %q", i, tok.SessionID)
		}
		if tok.Model != "gpt-5-mini" {
			t.Errorf("event %d: Model = %q, want gpt-5-mini", i, tok.Model)
		}
	}
}

// TestParseProcessLog_Tier2_SuppressedByDebugLogging confirms that
// when the same log file ALSO carries [DEBUG] response (Request-ID …)
// lines (i.e. --log-level debug is on), the Tier 2 candidates are
// dropped — Tier 1 emissions cover every request with the full
// usage breakdown, so emitting Tier 2 would double-count
// InputTokens. Pins the v1.6.3 mutual-exclusion contract between
// Tier 1 and Tier 2.
func TestParseProcessLog_Tier2_SuppressedByDebugLogging(t *testing.T) {
	dir := t.TempDir()
	logsRoot := filepath.Join(dir, ".copilot", "logs")
	if err := os.MkdirAll(logsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(logsRoot, "process-1779030001234-67890.log")
	body := `2026-05-17T09:28:27.900Z [INFO] Workspace initialized: 9da4aa10-1da9-49a5-931f-f89c2528c6db (checkpoints: 0)
2026-05-17T09:28:29.893Z [INFO] Using default model: gpt-5-mini
2026-05-17T09:28:38.632Z [INFO] CompactionProcessor: Utilization 14.9% (19052/128000 tokens) below threshold 80%
2026-05-17T09:28:39.000Z [DEBUG] response (Request-ID 00000-aaa):
2026-05-17T09:28:39.000Z [DEBUG] data:
2026-05-17T09:28:39.000Z [DEBUG] {
  "usage": {
    "completion_tokens": 100,
    "prompt_tokens": 19052,
    "total_tokens": 19152,
    "prompt_tokens_details": { "cached_tokens": 0 },
    "completion_tokens_details": { "reasoning_tokens": 0 }
  }
}
2026-05-17T09:28:45.233Z [INFO] CompactionProcessor: Utilization 14.9% (19113/128000 tokens) below threshold 80%
`
	if err := os.WriteFile(log, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, logsRoot)
	res, err := a.ParseSessionFile(context.Background(), log, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1 (Tier 1 only; Tier 2 must be suppressed)",
			len(res.TokenEvents))
	}
	tok := res.TokenEvents[0]
	if tok.Source != models.TokenSourceOTel {
		t.Errorf("Source = %q, want otel (Tier 1)", tok.Source)
	}
	if tok.MessageID != "00000-aaa" {
		t.Errorf("MessageID = %q, want the Request-ID", tok.MessageID)
	}
	if tok.InputTokens != 19052 || tok.OutputTokens != 100 {
		t.Errorf("Tier 1 counts: in=%d out=%d want 19052/100", tok.InputTokens, tok.OutputTokens)
	}
}

// writeMinimalEventsFile writes a session-state events.jsonl with one
// session.start envelope plus whatever extra lines the caller supplies,
// returning the file path. Used by the Tier-0 (session.shutdown
// modelMetrics) adapter tests to keep boilerplate out of the test
// bodies.
func writeMinimalEventsFile(t *testing.T, sessUUID string, extraLines ...string) string {
	t.Helper()
	dir := t.TempDir()
	ssRoot := filepath.Join(dir, ".copilot", "session-state")
	sessDir := filepath.Join(ssRoot, sessUUID)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatal(err)
	}
	evt := filepath.Join(sessDir, "events.jsonl")
	lines := []string{
		`{"type":"session.start","data":{"sessionId":"` + sessUUID + `","copilotVersion":"1.0.48","selectedModel":"gpt-5-mini","context":{"cwd":` + jsonStr(t, dir) + `,"gitRoot":` + jsonStr(t, dir) + `,"branch":"main","repository":"test/repo"}},"id":"e1","timestamp":"2026-05-17T09:28:27.909Z","parentId":null}`,
	}
	lines = append(lines, extraLines...)
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(evt, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return evt
}

// TestParseEventsJSONL_SessionShutdownModelMetrics pins the v1.6.6
// Tier-0 capture: session.shutdown.data.modelMetrics is the only
// place inputTokens / cacheReadTokens / cacheWriteTokens /
// reasoningTokens are reported for users not running
// `copilot --log-level debug`. The adapter must emit one TokenEvent
// per model with non-zero usage, mapping cacheWriteTokens onto
// CacheCreationTokens and leaving OutputTokens at zero (Tier 3 already
// covers output per-message).
func TestParseEventsJSONL_SessionShutdownModelMetrics(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	shutdown := `{"type":"session.shutdown","data":{"shutdownType":"routine","modelMetrics":{` +
		`"claude-opus-4.7":{"requests":{"count":18,"cost":15},"usage":{"inputTokens":578788,"outputTokens":17822,"cacheReadTokens":507943,"cacheWriteTokens":12345,"reasoningTokens":111}},` +
		`"gpt-5.4":{"requests":{"count":3,"cost":0},"usage":{"inputTokens":4096,"outputTokens":256,"cacheReadTokens":2048,"cacheWriteTokens":0,"reasoningTokens":64}},` +
		`"claude-haiku-4.5":{"requests":{"count":2,"cost":0},"usage":{"inputTokens":512,"outputTokens":32,"cacheReadTokens":256,"cacheWriteTokens":0,"reasoningTokens":0}}` +
		`}},"id":"shut-1","timestamp":"2026-05-17T09:30:00.000Z","parentId":"e1"}`
	evt := writeMinimalEventsFile(t, uuid, shutdown)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	// One TokenEvent per model with non-zero usage = 3 rows.
	if len(res.TokenEvents) != 3 {
		t.Fatalf("TokenEvents = %d, want 3 (one per model in modelMetrics)", len(res.TokenEvents))
	}
	byModel := map[string]models.TokenEvent{}
	for _, te := range res.TokenEvents {
		byModel[te.Model] = te
	}

	// Spot-check the headline opus row.
	opus, ok := byModel["claude-opus-4.7"]
	if !ok {
		t.Fatalf("missing claude-opus-4.7 row")
	}
	// InputTokens is NET non-cached: gross 578788 - cached 507943 = 70845.
	if opus.InputTokens != 70845 {
		t.Errorf("opus InputTokens = %d, want 70845 (578788 gross - 507943 cached)", opus.InputTokens)
	}
	if opus.OutputTokens != 0 {
		t.Errorf("opus OutputTokens = %d, want 0 (Tier 3 covers output)", opus.OutputTokens)
	}
	if opus.CacheReadTokens != 507943 {
		t.Errorf("opus CacheReadTokens = %d, want 507943", opus.CacheReadTokens)
	}
	if opus.CacheCreationTokens != 12345 {
		t.Errorf("opus CacheCreationTokens = %d, want 12345 (mapped from cacheWriteTokens)", opus.CacheCreationTokens)
	}
	if opus.ReasoningTokens != 111 {
		t.Errorf("opus ReasoningTokens = %d, want 111", opus.ReasoningTokens)
	}
	if opus.Source != models.TokenSourceSessionSummary {
		t.Errorf("opus Source = %q, want session_summary", opus.Source)
	}
	if opus.Reliability != models.ReliabilityApproximate {
		t.Errorf("opus Reliability = %q, want approximate", opus.Reliability)
	}
	if opus.SourceEventID != "shut-1:claude-opus-4.7" {
		t.Errorf("opus SourceEventID = %q, want shut-1:claude-opus-4.7", opus.SourceEventID)
	}
	if opus.MessageID != "session-shutdown:shut-1" {
		t.Errorf("opus MessageID = %q, want session-shutdown:shut-1", opus.MessageID)
	}
	if opus.SessionID != uuid {
		t.Errorf("opus SessionID = %q, want %q", opus.SessionID, uuid)
	}
	if opus.Tool != models.ToolCopilotCLI {
		t.Errorf("opus Tool = %q, want copilot-cli", opus.Tool)
	}

	// All three models present.
	for _, want := range []string{"claude-opus-4.7", "gpt-5.4", "claude-haiku-4.5"} {
		if _, ok := byModel[want]; !ok {
			t.Errorf("missing TokenEvent for model %q", want)
		}
	}

	// Session-end marker ToolEvent must still be emitted.
	var sawSessionEnd bool
	for _, te := range res.ToolEvents {
		if te.ActionType == models.ActionSessionEnd {
			sawSessionEnd = true
			break
		}
	}
	if !sawSessionEnd {
		t.Errorf("missing ActionSessionEnd ToolEvent — marker must still emit alongside Tier 0 rows")
	}
}

// TestParseEventsJSONL_SessionShutdownEmptyModelMetrics pins that a
// shutdown with no usage data emits zero TokenEvents but still
// produces the session-end marker. This is the common case for
// shutdowns that fire on idle pauses (resume → no API call → shutdown).
func TestParseEventsJSONL_SessionShutdownEmptyModelMetrics(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	cases := []struct {
		name string
		body string
	}{
		{"absent modelMetrics field", `{"type":"session.shutdown","data":{"shutdownType":"routine"},"id":"shut-2","timestamp":"2026-05-17T09:30:00.000Z","parentId":"e1"}`},
		{"explicit empty map", `{"type":"session.shutdown","data":{"shutdownType":"routine","modelMetrics":{}},"id":"shut-3","timestamp":"2026-05-17T09:30:00.000Z","parentId":"e1"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evt := writeMinimalEventsFile(t, uuid, tc.body)
			ssRoot := filepath.Dir(filepath.Dir(evt))
			a := NewWithOptions(nil, ssRoot)
			res, err := a.ParseSessionFile(context.Background(), evt, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			if len(res.TokenEvents) != 0 {
				t.Errorf("TokenEvents = %d, want 0 (empty modelMetrics)", len(res.TokenEvents))
			}
			var sawSessionEnd bool
			for _, te := range res.ToolEvents {
				if te.ActionType == models.ActionSessionEnd {
					sawSessionEnd = true
				}
			}
			if !sawSessionEnd {
				t.Errorf("missing ActionSessionEnd ToolEvent")
			}
		})
	}
}

// TestParseEventsJSONL_SessionShutdownSkipsZeroUsage pins the
// noise-suppression rule: a model whose modelMetrics entry has every
// token column at zero — typical of a shutdown firing right after a
// resume with no API activity — should not emit a TokenEvent. Mirrors
// the same noise filter the cost engine applies via isNoiseRow.
func TestParseEventsJSONL_SessionShutdownSkipsZeroUsage(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	shutdown := `{"type":"session.shutdown","data":{"modelMetrics":{` +
		`"claude-opus-4.7":{"usage":{"inputTokens":0,"outputTokens":0,"cacheReadTokens":0,"cacheWriteTokens":0,"reasoningTokens":0}},` +
		`"gpt-5.4":{"usage":{"inputTokens":4096,"outputTokens":256,"cacheReadTokens":2048,"cacheWriteTokens":0,"reasoningTokens":64}}` +
		`}},"id":"shut-zeros","timestamp":"2026-05-17T09:30:00.000Z","parentId":"e1"}`
	evt := writeMinimalEventsFile(t, uuid, shutdown)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1 (zero-usage opus row must be skipped)", len(res.TokenEvents))
	}
	if res.TokenEvents[0].Model != "gpt-5.4" {
		t.Errorf("Model = %q, want gpt-5.4 (the only non-zero entry)", res.TokenEvents[0].Model)
	}
}

// TestParseEventsJSONL_CompactionTokensOldSchema pins that the older
// session.compaction_complete payload shape ({input, output,
// cachedInput} — no "Tokens" suffix, no model field) yields a
// TokenEvent with values resolved from the legacy field names. Model
// falls back to the session's current model since the payload doesn't
// tag it.
func TestParseEventsJSONL_CompactionTokensOldSchema(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	compaction := `{"type":"session.compaction_complete","data":{"success":true,"preCompactionTokens":134537,"preCompactionMessagesLength":201,"summaryContent":"...","checkpointNumber":1,"checkpointPath":"chk.md","compactionTokensUsed":{"input":131922,"output":3967,"cachedInput":126959,"duration":4521},"requestId":"00000-b74c904b-163b-4693-9e4d-ae41b64982a8"},"id":"comp-old","timestamp":"2026-04-20T18:41:27.952Z","parentId":"e1"}`
	evt := writeMinimalEventsFile(t, uuid, compaction)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1 (old-schema compactionTokensUsed)", len(res.TokenEvents))
	}
	te := res.TokenEvents[0]
	// InputTokens is NET non-cached: gross 131922 - cached 126959 = 4963.
	if te.InputTokens != 4963 {
		t.Errorf("InputTokens = %d, want 4963 (131922 gross net of 126959 cached, from .input + .cachedInput fallbacks)", te.InputTokens)
	}
	if te.OutputTokens != 3967 {
		t.Errorf("OutputTokens = %d, want 3967 (from .output fallback)", te.OutputTokens)
	}
	if te.CacheReadTokens != 126959 {
		t.Errorf("CacheReadTokens = %d, want 126959 (from .cachedInput fallback)", te.CacheReadTokens)
	}
	if te.CacheCreationTokens != 0 {
		t.Errorf("CacheCreationTokens = %d, want 0 (no cacheWriteTokens in old schema)", te.CacheCreationTokens)
	}
	if te.MessageID != "00000-b74c904b-163b-4693-9e4d-ae41b64982a8" {
		t.Errorf("MessageID = %q, want compaction requestId", te.MessageID)
	}
	if te.SourceEventID != "comp-old:compaction" {
		t.Errorf("SourceEventID = %q, want comp-old:compaction", te.SourceEventID)
	}
	if te.Source != models.TokenSourceJSONL {
		t.Errorf("Source = %q, want jsonl", te.Source)
	}
	if te.Model != "gpt-5-mini" {
		t.Errorf("Model = %q, want gpt-5-mini (st.model fallback when payload lacks model)", te.Model)
	}
}

// TestParseEventsJSONL_CompactionTokensNewSchema pins the newer
// session.compaction_complete payload shape ({inputTokens,
// outputTokens, cacheReadTokens, cacheWriteTokens, model}) — the
// explicit Model field overrides the st.model fallback, and the
// "Tokens"-suffixed fields populate without going through the legacy
// fallback.
func TestParseEventsJSONL_CompactionTokensNewSchema(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	compaction := `{"type":"session.compaction_complete","data":{"success":true,"compactionTokensUsed":{"inputTokens":150346,"outputTokens":7690,"cacheReadTokens":142230,"cacheWriteTokens":2048,"model":"claude-opus-4.7"},"requestId":"00000-newcomp-abc"},"id":"comp-new","timestamp":"2026-04-22T11:00:00.000Z","parentId":"e1"}`
	evt := writeMinimalEventsFile(t, uuid, compaction)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1", len(res.TokenEvents))
	}
	te := res.TokenEvents[0]
	// InputTokens is NET non-cached: gross 150346 - cached 142230 = 8116.
	if te.InputTokens != 8116 || te.OutputTokens != 7690 ||
		te.CacheReadTokens != 142230 || te.CacheCreationTokens != 2048 {
		t.Errorf("token columns wrong: in=%d out=%d cr=%d cc=%d want 8116/7690/142230/2048 (gross input 150346 net of 142230 cached)",
			te.InputTokens, te.OutputTokens, te.CacheReadTokens, te.CacheCreationTokens)
	}
	if te.Model != "claude-opus-4.7" {
		t.Errorf("Model = %q, want claude-opus-4.7 (from payload, NOT st.model)", te.Model)
	}
	if te.MessageID != "00000-newcomp-abc" {
		t.Errorf("MessageID = %q, want the compaction requestId", te.MessageID)
	}
}

// TestParseEventsJSONL_CompactionTokensEmptyOrZero pins that a
// compaction event with no compactionTokensUsed field OR an all-zero
// payload emits zero TokenEvents (don't accumulate noise rows).
func TestParseEventsJSONL_CompactionTokensEmptyOrZero(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	cases := []struct {
		name string
		body string
	}{
		{"no compactionTokensUsed field", `{"type":"session.compaction_complete","data":{"success":true},"id":"c1","timestamp":"2026-04-22T11:00:00.000Z","parentId":"e1"}`},
		{"all-zero values", `{"type":"session.compaction_complete","data":{"success":true,"compactionTokensUsed":{"input":0,"output":0,"cachedInput":0}},"id":"c2","timestamp":"2026-04-22T11:00:00.000Z","parentId":"e1"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evt := writeMinimalEventsFile(t, uuid, tc.body)
			ssRoot := filepath.Dir(filepath.Dir(evt))
			a := NewWithOptions(nil, ssRoot)
			res, err := a.ParseSessionFile(context.Background(), evt, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			if len(res.TokenEvents) != 0 {
				t.Errorf("TokenEvents = %d, want 0 (empty/zero compactionTokensUsed)", len(res.TokenEvents))
			}
		})
	}
}

// TestParseEventsJSONL_CompactionTokensMissingRequestID pins that
// when compactionTokensUsed has tokens but the data.requestId field
// is absent (or empty), the MessageID falls back to
// "compaction:<env.ID>" so the row remains uniquely keyable.
func TestParseEventsJSONL_CompactionTokensMissingRequestID(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	compaction := `{"type":"session.compaction_complete","data":{"success":true,"compactionTokensUsed":{"input":100,"output":50}},"id":"c-no-req","timestamp":"2026-04-22T11:00:00.000Z","parentId":"e1"}`
	evt := writeMinimalEventsFile(t, uuid, compaction)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1", len(res.TokenEvents))
	}
	if res.TokenEvents[0].MessageID != "compaction:c-no-req" {
		t.Errorf("MessageID = %q, want fallback compaction:c-no-req", res.TokenEvents[0].MessageID)
	}
}

// TestParseEventsJSONL_SubagentModelAttribution pins the v1.6.8 B4
// fix: when an assistant.message is emitted under a subagent's
// context (envelope.agentId set), the resulting Tier-3 TokenEvent
// MUST be attributed to the subagent's model — NOT to the parent
// session's st.model. The subagent's model is only known once
// subagent.completed has been parsed; the adapter defers model
// resolution and patches Model at end-of-scan.
//
// Fixture mimics the operator sample shape: parent runs opus-4.7;
// a `task` tool spawns a rubber-duck subagent on gpt-5.4; the
// subagent emits assistant.messages tagged with the subagent's
// agentId; subagent.completed reports model=gpt-5.4.
//
// Tier-3 row for the subagent's asst.message must show model=gpt-5.4,
// not the parent's gpt-5-mini (st.model from session.start in this
// fixture).
func TestParseEventsJSONL_SubagentModelAttribution(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	// Two distinct subagents: one resolves to gpt-5.4 (gpt-5.2
	// would also work), the other to claude-haiku-4.5 — both
	// shapes seen in the operator sample. A control asst.message
	// without env.agentId asserts the parent-context fallback to
	// st.model still works.
	subStartedA := `{"type":"subagent.started","data":{"toolCallId":"agent-A","agentName":"rubber-duck","agentDescription":"second-opinion"},"id":"sa1","timestamp":"2026-04-20T18:38:21.175Z","parentId":"e1","agentId":"agent-A"}`
	asstUnderA := `{"type":"assistant.message","data":{"messageId":"mA1","content":"subagent A says hi","outputTokens":1234,"requestId":"00000-rid-A"},"id":"asA1","timestamp":"2026-04-20T18:38:22.000Z","parentId":"sa1","agentId":"agent-A"}`
	subCompletedA := `{"type":"subagent.completed","data":{"toolCallId":"agent-A","agentName":"rubber-duck","model":"gpt-5.4","totalTokens":18791,"totalToolCalls":2,"durationMs":73305},"id":"sc1","timestamp":"2026-04-20T18:39:33.943Z","parentId":"asA1","agentId":"agent-A"}`
	subStartedB := `{"type":"subagent.started","data":{"toolCallId":"agent-B","agentName":"rubber-duck"},"id":"sa2","timestamp":"2026-04-20T18:40:00.000Z","parentId":"sc1","agentId":"agent-B"}`
	asstUnderB := `{"type":"assistant.message","data":{"messageId":"mB1","content":"subagent B answers","outputTokens":2222,"requestId":"00000-rid-B"},"id":"asB1","timestamp":"2026-04-20T18:40:05.000Z","parentId":"sa2","agentId":"agent-B"}`
	subCompletedB := `{"type":"subagent.completed","data":{"toolCallId":"agent-B","agentName":"rubber-duck","model":"claude-haiku-4.5","totalTokens":99999,"totalToolCalls":0,"durationMs":12345},"id":"sc2","timestamp":"2026-04-20T18:41:00.000Z","parentId":"asB1","agentId":"agent-B"}`
	// Control: parent-context asst.message with no agentId.
	parentAsst := `{"type":"assistant.message","data":{"messageId":"m-parent","content":"parent reply","outputTokens":7777,"requestId":"00000-rid-parent"},"id":"asP","timestamp":"2026-04-20T18:42:00.000Z","parentId":"e1"}`

	evt := writeMinimalEventsFile(
		t, uuid,
		subStartedA, asstUnderA, subCompletedA,
		subStartedB, asstUnderB, subCompletedB,
		parentAsst,
	)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	// Index TokenEvents by RequestID (MessageID for Tier-3).
	byMsg := map[string]models.TokenEvent{}
	for _, te := range res.TokenEvents {
		byMsg[te.MessageID] = te
	}
	if got := len(byMsg); got != 3 {
		t.Fatalf("TokenEvents indexed: got %d want 3", got)
	}
	if m := byMsg["00000-rid-A"].Model; m != "gpt-5.4" {
		t.Errorf("subagent A model: got %q want gpt-5.4 (subagent attribution)", m)
	}
	if m := byMsg["00000-rid-B"].Model; m != "claude-haiku-4.5" {
		t.Errorf("subagent B model: got %q want claude-haiku-4.5 (subagent attribution)", m)
	}
	// Parent-context message uses st.model (gpt-5-mini from session.start).
	if m := byMsg["00000-rid-parent"].Model; m != "gpt-5-mini" {
		t.Errorf("parent-context model: got %q want gpt-5-mini (st.model fallback)", m)
	}
}

// TestParseEventsJSONL_SubagentNeverCompleted pins the fallback
// behaviour when a subagent.started fires but subagent.completed
// never lands in the parsed file (orphan / crash / cancelled run).
// The asst.message emitted under that agentId stays attributed to
// st.model — the parent's selected model is the best-effort fallback.
func TestParseEventsJSONL_SubagentNeverCompleted(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	subStarted := `{"type":"subagent.started","data":{"toolCallId":"agent-X","agentName":"rubber-duck"},"id":"sa-x","timestamp":"2026-04-20T18:38:21.175Z","parentId":"e1","agentId":"agent-X"}`
	asst := `{"type":"assistant.message","data":{"messageId":"mX","content":"orphan","outputTokens":500,"requestId":"00000-rid-X"},"id":"asX","timestamp":"2026-04-20T18:38:22.000Z","parentId":"sa-x","agentId":"agent-X"}`
	// No subagent.completed → no model resolution for agent-X.
	evt := writeMinimalEventsFile(t, uuid, subStarted, asst)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d want 1", len(res.TokenEvents))
	}
	if m := res.TokenEvents[0].Model; m != "gpt-5-mini" {
		t.Errorf("orphan subagent model fallback: got %q want gpt-5-mini (st.model)", m)
	}
}

// TestParseEventsJSONL_SubagentCompletedWithoutModelField pins the
// behaviour when subagent.completed fires but data.model is empty
// (20/37 of the operator sample's subagent.completed events look
// this way — cancelled / aborted subagents that never resolved a
// model). The patch step must NOT clobber a previously-attributed
// Model with empty string. Asst.message stays on st.model.
func TestParseEventsJSONL_SubagentCompletedWithoutModelField(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	subStarted := `{"type":"subagent.started","data":{"toolCallId":"agent-Y","agentName":"rubber-duck"},"id":"sa-y","timestamp":"2026-04-20T18:38:21.175Z","parentId":"e1","agentId":"agent-Y"}`
	asst := `{"type":"assistant.message","data":{"messageId":"mY","content":"cancelled","outputTokens":300,"requestId":"00000-rid-Y"},"id":"asY","timestamp":"2026-04-20T18:38:22.000Z","parentId":"sa-y","agentId":"agent-Y"}`
	subCompleted := `{"type":"subagent.completed","data":{"toolCallId":"agent-Y","agentName":"rubber-duck"},"id":"sc-y","timestamp":"2026-04-20T18:38:30.000Z","parentId":"asY","agentId":"agent-Y"}`
	evt := writeMinimalEventsFile(t, uuid, subStarted, asst, subCompleted)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d want 1", len(res.TokenEvents))
	}
	if m := res.TokenEvents[0].Model; m != "gpt-5-mini" {
		t.Errorf("no-model-completed fallback: got %q want gpt-5-mini (must not clobber to empty)", m)
	}
}

// TestParseEventsJSONL_SubagentResolvedFromToolExecution pins the
// v1.6.8 V6k fallback: when subagent.completed.data.model is empty
// (cancelled / short-lived subagent), the adapter must source the
// subagent's model from in-context tool.execution_complete.data.model
// events sharing the same agentId. This recovers 15 of the 20
// unresolved subagents on the operator sample.
//
// Fixture: subagent.started, then a tool.execution_complete under
// the subagent's agentId carrying data.model="gpt-5.4", then the
// subagent's asst.message, then subagent.completed WITHOUT a model.
// Expected: Tier-3 token row attributes to gpt-5.4 (recovered from
// the tool execution), not st.model.
func TestParseEventsJSONL_SubagentResolvedFromToolExecution(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	subStarted := `{"type":"subagent.started","data":{"toolCallId":"agent-T","agentName":"investigator"},"id":"sa-t","timestamp":"2026-04-20T18:38:21.175Z","parentId":"e1","agentId":"agent-T"}`
	// A tool the subagent ran — its execution_complete carries the
	// subagent's actual running model in data.model.
	toolStart := `{"type":"tool.execution_start","data":{"toolCallId":"call-1","toolName":"grep","arguments":{"pattern":"foo"},"turnId":"0"},"id":"ts1","timestamp":"2026-04-20T18:38:21.500Z","parentId":"sa-t","agentId":"agent-T"}`
	toolCompl := `{"type":"tool.execution_complete","data":{"toolCallId":"call-1","model":"gpt-5.4","interactionId":"i1","turnId":"0","success":true,"result":{"content":"found"}},"id":"tc1","timestamp":"2026-04-20T18:38:22.000Z","parentId":"ts1","agentId":"agent-T"}`
	// Asst.message under the subagent — no data.model.
	asst := `{"type":"assistant.message","data":{"messageId":"mT","content":"investigation result","outputTokens":500,"requestId":"00000-rid-T"},"id":"asT","timestamp":"2026-04-20T18:38:23.000Z","parentId":"tc1","agentId":"agent-T"}`
	// Subagent.completed without a model (the cancelled / lost-model case).
	subCompleted := `{"type":"subagent.completed","data":{"toolCallId":"agent-T","agentName":"investigator","totalToolCalls":1,"totalTokens":500},"id":"sc-t","timestamp":"2026-04-20T18:38:30.000Z","parentId":"asT","agentId":"agent-T"}`

	evt := writeMinimalEventsFile(t, uuid, subStarted, toolStart, toolCompl, asst, subCompleted)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// Find the Tier-3 token row for the subagent's asst.message.
	var foundTier3 *models.TokenEvent
	for i := range res.TokenEvents {
		if res.TokenEvents[i].MessageID == "00000-rid-T" {
			foundTier3 = &res.TokenEvents[i]
			break
		}
	}
	if foundTier3 == nil {
		t.Fatalf("Tier-3 row for subagent asst.message not emitted (TokenEvents=%+v)", res.TokenEvents)
	}
	if foundTier3.Model != "gpt-5.4" {
		t.Errorf("V6k fallback: got model=%q want gpt-5.4 (from tool.execution_complete.data.model)", foundTier3.Model)
	}
}

// TestParseEventsJSONL_SubagentCompletedModelWinsOverToolExecution
// pins precedence: subagent.completed.data.model is authoritative —
// when both sources are available, the explicit subagent.completed
// model wins over any tool.execution_complete fallback that fired
// earlier in the same scan.
func TestParseEventsJSONL_SubagentCompletedModelWinsOverToolExecution(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	subStarted := `{"type":"subagent.started","data":{"toolCallId":"agent-W","agentName":"router"},"id":"sa-w","timestamp":"2026-04-20T18:38:21.175Z","parentId":"e1","agentId":"agent-W"}`
	// A tool.execution_complete fires FIRST with one model.
	toolStart := `{"type":"tool.execution_start","data":{"toolCallId":"call-w","toolName":"grep","arguments":{"pattern":"x"},"turnId":"0"},"id":"tsw","timestamp":"2026-04-20T18:38:21.500Z","parentId":"sa-w","agentId":"agent-W"}`
	toolCompl := `{"type":"tool.execution_complete","data":{"toolCallId":"call-w","model":"gpt-5-mini","interactionId":"i1","turnId":"0","success":true,"result":{"content":"hit"}},"id":"tcw","timestamp":"2026-04-20T18:38:22.000Z","parentId":"tsw","agentId":"agent-W"}`
	asst := `{"type":"assistant.message","data":{"messageId":"mW","content":"done","outputTokens":400,"requestId":"00000-rid-W"},"id":"asW","timestamp":"2026-04-20T18:38:23.000Z","parentId":"tcw","agentId":"agent-W"}`
	// Subagent.completed with a DIFFERENT, authoritative model.
	subCompleted := `{"type":"subagent.completed","data":{"toolCallId":"agent-W","agentName":"router","model":"claude-haiku-4.5","totalToolCalls":1,"totalTokens":400},"id":"sc-w","timestamp":"2026-04-20T18:38:30.000Z","parentId":"asW","agentId":"agent-W"}`
	evt := writeMinimalEventsFile(t, uuid, subStarted, toolStart, toolCompl, asst, subCompleted)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var foundTier3 *models.TokenEvent
	for i := range res.TokenEvents {
		if res.TokenEvents[i].MessageID == "00000-rid-W" {
			foundTier3 = &res.TokenEvents[i]
			break
		}
	}
	if foundTier3 == nil {
		t.Fatalf("Tier-3 row not emitted")
	}
	if foundTier3.Model != "claude-haiku-4.5" {
		t.Errorf("precedence: got model=%q want claude-haiku-4.5 (subagent.completed authoritative)", foundTier3.Model)
	}
}

// TestParseEventsJSONL_SubagentExplicitModelWins pins that an
// asst.message carrying data.model wins over both subagent-model
// lookup AND st.model fallback. The 14 of 3303 asst.message events
// in the operator sample that explicitly tag data.model are the
// load-bearing case here — they must NOT be rewritten by the patch.
func TestParseEventsJSONL_SubagentExplicitModelWins(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	subStarted := `{"type":"subagent.started","data":{"toolCallId":"agent-Z","agentName":"rubber-duck"},"id":"sa-z","timestamp":"2026-04-20T18:38:21.175Z","parentId":"e1","agentId":"agent-Z"}`
	// data.model = explicit claude-opus-4.7 — should override
	// everything.
	asst := `{"type":"assistant.message","data":{"messageId":"mZ","model":"claude-opus-4.7","content":"explicit tag","outputTokens":600,"requestId":"00000-rid-Z"},"id":"asZ","timestamp":"2026-04-20T18:38:22.000Z","parentId":"sa-z","agentId":"agent-Z"}`
	subCompleted := `{"type":"subagent.completed","data":{"toolCallId":"agent-Z","agentName":"rubber-duck","model":"gpt-5.4"},"id":"sc-z","timestamp":"2026-04-20T18:38:30.000Z","parentId":"asZ","agentId":"agent-Z"}`
	evt := writeMinimalEventsFile(t, uuid, subStarted, asst, subCompleted)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d want 1", len(res.TokenEvents))
	}
	if m := res.TokenEvents[0].Model; m != "claude-opus-4.7" {
		t.Errorf("explicit data.model: got %q want claude-opus-4.7 (must beat subagent lookup AND st.model)", m)
	}
}

// TestParseEventsJSONL_SessionShutdownPartialFields pins that a
// shutdown event with some token columns missing from the JSON (e.g.
// older Copilot CLI versions that didn't emit reasoningTokens) parses
// cleanly with zero-fill. No crash, no spurious values.
func TestParseEventsJSONL_SessionShutdownPartialFields(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	// `reasoningTokens` and `cacheWriteTokens` deliberately absent.
	shutdown := `{"type":"session.shutdown","data":{"modelMetrics":{` +
		`"gpt-5.4":{"usage":{"inputTokens":4096,"outputTokens":256,"cacheReadTokens":2048}}` +
		`}},"id":"shut-partial","timestamp":"2026-05-17T09:30:00.000Z","parentId":"e1"}`
	evt := writeMinimalEventsFile(t, uuid, shutdown)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1", len(res.TokenEvents))
	}
	te := res.TokenEvents[0]
	// InputTokens is NET non-cached: gross 4096 - cached 2048 = 2048.
	if te.InputTokens != 2048 || te.CacheReadTokens != 2048 {
		t.Errorf("captured fields wrong: in=%d cr=%d want 2048/2048 (gross 4096 net of 2048 cached)", te.InputTokens, te.CacheReadTokens)
	}
	if te.ReasoningTokens != 0 || te.CacheCreationTokens != 0 {
		t.Errorf("missing fields must zero-fill: reasoning=%d cache_creation=%d", te.ReasoningTokens, te.CacheCreationTokens)
	}
}

// TestParseEventsJSONL_ToolFailureErrorMessage pins the v1.6.13 B1
// fix: failed tool.execution_complete events carry the real failure
// text at top-level `data.error.message`, NOT at `result.content`.
// The pre-fix parser read result.content on failure and emitted an
// empty error_message column for 158/158 failures in the operator
// specimen (2026-05-19 audit).
func TestParseEventsJSONL_ToolFailureErrorMessage(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	start := `{"type":"tool.execution_start","data":{"toolCallId":"call_F1","toolName":"bash","arguments":{"command":"pwsh.exe --version"},"turnId":"0"},"id":"es-f1","timestamp":"2026-05-19T01:00:00.000Z","parentId":"e1"}`
	// Failure shape from the operator specimen: success=false, top-
	// level error.{message,code}, result absent.
	complete := `{"type":"tool.execution_complete","data":{"toolCallId":"call_F1","model":"claude-opus-4.6","interactionId":"i-f1","turnId":"0","success":false,"error":{"message":"<exited with error: PowerShell 6+ (pwsh) is not available.>","code":"failure"}},"id":"ec-f1","timestamp":"2026-05-19T01:00:01.000Z","parentId":"es-f1"}`
	evt := writeMinimalEventsFile(t, uuid, start, complete)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var failure *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SourceEventID == "ec-f1" {
			failure = &res.ToolEvents[i]
			break
		}
	}
	if failure == nil {
		t.Fatalf("failure row missing; got %d ToolEvents", len(res.ToolEvents))
	}
	if failure.Success {
		t.Errorf("Success = true, want false")
	}
	wantMsg := "<exited with error: PowerShell 6+ (pwsh) is not available.>"
	if failure.ErrorMessage != wantMsg {
		t.Errorf("ErrorMessage = %q, want %q (must come from data.error.message)", failure.ErrorMessage, wantMsg)
	}
}

// TestParseEventsJSONL_ToolFailureFallsBackToResultContent pins the
// B1 fallback: when data.error.message is empty, the parser still
// reads result.content (defensive against shape drift in future
// Copilot CLI versions).
func TestParseEventsJSONL_ToolFailureFallsBackToResultContent(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	start := `{"type":"tool.execution_start","data":{"toolCallId":"call_F2","toolName":"bash","arguments":{"command":"false"},"turnId":"0"},"id":"es-f2","timestamp":"2026-05-19T01:00:00.000Z","parentId":"e1"}`
	complete := `{"type":"tool.execution_complete","data":{"toolCallId":"call_F2","success":false,"result":{"content":"legacy error in result.content"}},"id":"ec-f2","timestamp":"2026-05-19T01:00:01.000Z","parentId":"es-f2"}`
	evt := writeMinimalEventsFile(t, uuid, start, complete)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var failure *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SourceEventID == "ec-f2" {
			failure = &res.ToolEvents[i]
			break
		}
	}
	if failure == nil {
		t.Fatalf("failure row missing")
	}
	if failure.ErrorMessage != "legacy error in result.content" {
		t.Errorf("ErrorMessage = %q, want fallback %q", failure.ErrorMessage, "legacy error in result.content")
	}
}

// TestParseEventsJSONL_PermissionShellShape pins the v1.6.13 B2 fix:
// permission events are shell-command shaped in current Copilot CLI
// (kind="shell", fullCommandText, commands[], possiblePaths[]). The
// pre-fix parser read FileName only, so RawToolInput was empty for
// every shell approval. All 3 permission requests in the operator
// specimen 2026-05-19 are shell-shaped.
func TestParseEventsJSONL_PermissionShellShape(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	req := `{"type":"permission.requested","data":{"requestId":"r1","permissionRequest":{"kind":"shell","toolCallId":"tc1","fullCommandText":"python -c \"print(1)\"","intention":"Run a script","commands":[{"identifier":"python","readOnly":false}],"possiblePaths":["python"],"hasWriteFileRedirection":false,"canOfferSessionApproval":true}},"id":"pr1","timestamp":"2026-05-19T01:00:00.000Z","parentId":"e1"}`
	done := `{"type":"permission.completed","data":{"requestId":"r1","toolCallId":"tc1","result":{"kind":"approved"}},"id":"pc1","timestamp":"2026-05-19T01:00:05.000Z","parentId":"pr1"}`
	evt := writeMinimalEventsFile(t, uuid, req, done)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var permRow *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SourceEventID == "pc1" {
			permRow = &res.ToolEvents[i]
			break
		}
	}
	if permRow == nil {
		t.Fatalf("permission.completed row missing; got %d ToolEvents", len(res.ToolEvents))
	}
	if permRow.ActionType != models.ActionPermissionRequest {
		t.Errorf("ActionType = %q, want %q", permRow.ActionType, models.ActionPermissionRequest)
	}
	if !permRow.Success {
		t.Errorf("Success = false, want true (kind=approved)")
	}
	if permRow.RawToolName != "shell" {
		t.Errorf("RawToolName = %q, want %q", permRow.RawToolName, "shell")
	}
	if permRow.Target != "Run a script" {
		t.Errorf("Target = %q, want intention %q", permRow.Target, "Run a script")
	}
	if !strings.Contains(permRow.RawToolInput, "python -c") {
		t.Errorf("RawToolInput = %q, want it to carry fullCommandText (must NOT be empty)", permRow.RawToolInput)
	}
	if permRow.Metadata != nil {
		t.Errorf("Metadata = %+v, want nil for plain approved (no granularity to record)", permRow.Metadata)
	}
}

// TestParseEventsJSONL_PermissionApprovedForLocation pins the second
// half of B2: "approved-for-location" is a real approval (Success=true)
// with a LocationKey scope that we capture into ActionMetadata so
// downstream tooling can distinguish a single-call grant from a
// directory-scoped one. Pre-fix code marked this as Success=false
// because Kind != "approved" literally.
func TestParseEventsJSONL_PermissionApprovedForLocation(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	req := `{"type":"permission.requested","data":{"requestId":"r2","permissionRequest":{"kind":"shell","toolCallId":"tc2","fullCommandText":"python script.py","intention":"Dump shutdowns","commands":[{"identifier":"python","readOnly":false}]}},"id":"pr2","timestamp":"2026-05-19T01:00:00.000Z","parentId":"e1"}`
	done := `{"type":"permission.completed","data":{"requestId":"r2","toolCallId":"tc2","result":{"kind":"approved-for-location","approval":{"kind":"commands","commandIdentifiers":["python"]},"locationKey":"D:\\OneDrive - Microsoft"}},"id":"pc2","timestamp":"2026-05-19T01:00:05.000Z","parentId":"pr2"}`
	evt := writeMinimalEventsFile(t, uuid, req, done)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var permRow *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SourceEventID == "pc2" {
			permRow = &res.ToolEvents[i]
			break
		}
	}
	if permRow == nil {
		t.Fatalf("permission.completed row missing")
	}
	if !permRow.Success {
		t.Errorf("Success = false, want true (approved-for-location is still an approval)")
	}
	if permRow.ActionType != models.ActionPermissionRequest {
		t.Errorf("ActionType = %q, want %q (not denied)", permRow.ActionType, models.ActionPermissionRequest)
	}
	if permRow.Metadata == nil {
		t.Fatalf("Metadata = nil, want non-nil with approval granularity")
	}
	if permRow.Metadata.PermissionApprovalKind != "approved-for-location" {
		t.Errorf("PermissionApprovalKind = %q, want %q", permRow.Metadata.PermissionApprovalKind, "approved-for-location")
	}
	if permRow.Metadata.PermissionLocationKey != "D:\\OneDrive - Microsoft" {
		t.Errorf("PermissionLocationKey = %q, want %q", permRow.Metadata.PermissionLocationKey, "D:\\OneDrive - Microsoft")
	}
}

// TestParseEventsJSONL_PermissionDenied pins the denied branch:
// ActionPermissionDenied + Success=false.
func TestParseEventsJSONL_PermissionDenied(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	req := `{"type":"permission.requested","data":{"requestId":"r3","permissionRequest":{"kind":"shell","toolCallId":"tc3","fullCommandText":"rm -rf /","intention":"Wipe filesystem"}},"id":"pr3","timestamp":"2026-05-19T01:00:00.000Z","parentId":"e1"}`
	done := `{"type":"permission.completed","data":{"requestId":"r3","toolCallId":"tc3","result":{"kind":"denied"}},"id":"pc3","timestamp":"2026-05-19T01:00:05.000Z","parentId":"pr3"}`
	evt := writeMinimalEventsFile(t, uuid, req, done)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var permRow *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SourceEventID == "pc3" {
			permRow = &res.ToolEvents[i]
			break
		}
	}
	if permRow == nil {
		t.Fatalf("permission.completed row missing")
	}
	if permRow.Success {
		t.Errorf("Success = true, want false (denied)")
	}
	if permRow.ActionType != models.ActionPermissionDenied {
		t.Errorf("ActionType = %q, want %q", permRow.ActionType, models.ActionPermissionDenied)
	}
	if !strings.Contains(permRow.RawToolInput, "rm -rf") {
		t.Errorf("RawToolInput = %q, want fullCommandText preserved even on denial (audit signal)", permRow.RawToolInput)
	}
}

// TestParseEventsJSONL_PermissionFileShape pins backward-compat:
// older Copilot CLI shapes used FileName/Diff (file-oriented write
// approvals). RawToolInput must fall back to FileName when
// FullCommandText is absent.
func TestParseEventsJSONL_PermissionFileShape(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	req := `{"type":"permission.requested","data":{"requestId":"r4","permissionRequest":{"kind":"write","toolCallId":"tc4","intention":"Edit a file","fileName":"src/main.go","diff":"--- a/src/main.go\n+++ b/src/main.go\n@@ -1,1 +1,1 @@\n-foo\n+bar"}},"id":"pr4","timestamp":"2026-05-19T01:00:00.000Z","parentId":"e1"}`
	done := `{"type":"permission.completed","data":{"requestId":"r4","toolCallId":"tc4","result":{"kind":"approved"}},"id":"pc4","timestamp":"2026-05-19T01:00:05.000Z","parentId":"pr4"}`
	evt := writeMinimalEventsFile(t, uuid, req, done)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var permRow *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SourceEventID == "pc4" {
			permRow = &res.ToolEvents[i]
			break
		}
	}
	if permRow == nil {
		t.Fatalf("permission.completed row missing")
	}
	if permRow.RawToolInput != "src/main.go" {
		t.Errorf("RawToolInput = %q, want FileName fallback %q", permRow.RawToolInput, "src/main.go")
	}
	if permRow.RawToolName != "write" {
		t.Errorf("RawToolName = %q, want %q", permRow.RawToolName, "write")
	}
}

// TestParseEventsJSONL_SessionResumeUpdatesModel pins the v1.6.13 G1
// fix: session.resume.data carries selectedModel + context (cwd /
// gitRoot / branch / repository). The pre-fix parser ignored these,
// so long-lived sessions where the model changed across a resume
// (without a later session.model_change) mis-attributed every
// subsequent assistant.message to the original session.start model.
func TestParseEventsJSONL_SessionResumeUpdatesModel(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	// Resume mid-session with a different model; an assistant.message
	// after the resume that omits data.model must inherit the resumed
	// model (claude-opus-4.7), not the session.start model (gpt-5-mini).
	resume := `{"type":"session.resume","data":{"resumeTime":"2026-04-26T18:30:14.211Z","eventCount":24041,"selectedModel":"claude-opus-4.7","reasoningEffort":"medium","context":{"cwd":"E:\\"}},"id":"sr1","timestamp":"2026-04-26T18:30:14.211Z","parentId":"e1"}`
	// data.model intentionally omitted — forces fallback to st.model.
	asst := `{"type":"assistant.message","data":{"messageId":"m-post-resume","content":"hello after resume","outputTokens":99,"requestId":"00000-post"},"id":"am-pr","timestamp":"2026-04-26T18:30:15.000Z","parentId":"sr1"}`
	evt := writeMinimalEventsFile(t, uuid, resume, asst)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1", len(res.TokenEvents))
	}
	if res.TokenEvents[0].Model != "claude-opus-4.7" {
		t.Errorf("Model = %q, want %q (must inherit resumed model, not session.start model)", res.TokenEvents[0].Model, "claude-opus-4.7")
	}
}

// TestParseEventsJSONL_SessionResumeEmptyModelKeepsCurrent pins that
// a resume event with an empty selectedModel does NOT clobber the
// existing st.model (defensive — older or partial resume payloads
// should leave context intact).
func TestParseEventsJSONL_SessionResumeEmptyModelKeepsCurrent(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	// Empty selectedModel — must not blank st.model out.
	resume := `{"type":"session.resume","data":{"resumeTime":"2026-04-26T18:30:14.211Z","eventCount":24041,"reasoningEffort":"medium"},"id":"sr2","timestamp":"2026-04-26T18:30:14.211Z","parentId":"e1"}`
	asst := `{"type":"assistant.message","data":{"messageId":"m-post-resume","content":"hello","outputTokens":99,"requestId":"00000-post2"},"id":"am-pr2","timestamp":"2026-04-26T18:30:15.000Z","parentId":"sr2"}`
	evt := writeMinimalEventsFile(t, uuid, resume, asst)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1", len(res.TokenEvents))
	}
	// session.start used selectedModel=gpt-5-mini in the helper.
	if res.TokenEvents[0].Model != "gpt-5-mini" {
		t.Errorf("Model = %q, want %q (empty resume must NOT clobber the original)", res.TokenEvents[0].Model, "gpt-5-mini")
	}
}

// TestParseEventsJSONL_WorkspaceYAMLWinsForProjectRoot pins the
// v1.6.13 G2 fix: when a sibling workspace.yaml is present, its
// git_root takes precedence over the event-stream cwd/gitRoot. The
// operator specimen has session.start.context.cwd="E:\\" (drive root)
// but real edits target "E:\\opencell\\..." — the pre-fix parser
// normalized action rows to the drive root.
func TestParseEventsJSONL_WorkspaceYAMLWinsForProjectRoot(t *testing.T) {
	dir := t.TempDir()
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	ssRoot := filepath.Join(dir, ".copilot", "session-state")
	sessDir := filepath.Join(ssRoot, uuid)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Real project root we want action rows to normalize to.
	projectDir := filepath.Join(dir, "real-project")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Stage workspace.yaml pointing at the real project.
	yaml := "cwd: " + projectDir + "\n" +
		"git_root: " + projectDir + "\n" +
		"branch: main\n"
	if err := os.WriteFile(filepath.Join(sessDir, "workspace.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	// events.jsonl uses a misleading drive-root cwd (mirrors the
	// operator specimen's "E:\\" pattern).
	evt := filepath.Join(sessDir, "events.jsonl")
	body := `{"type":"session.start","data":{"sessionId":"` + uuid + `","copilotVersion":"1.0.48","selectedModel":"gpt-5-mini","context":{"cwd":"E:\\"}},"id":"e1","timestamp":"2026-05-19T01:00:00.000Z","parentId":null}` + "\n" +
		`{"type":"user.message","data":{"content":"hello"},"id":"e2","timestamp":"2026-05-19T01:00:01.000Z","parentId":"e1"}` + "\n"
	if err := os.WriteFile(evt, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) == 0 {
		t.Fatalf("ToolEvents empty")
	}
	// Every emitted row must adopt the project root from workspace.yaml,
	// NOT the misleading drive-root cwd from the event stream.
	for i, e := range res.ToolEvents {
		if e.ProjectRoot != projectDir {
			t.Errorf("ToolEvents[%d].ProjectRoot = %q, want %q (workspace.yaml must win over event-stream cwd)", i, e.ProjectRoot, projectDir)
		}
	}
}

// TestParseEventsJSONL_WorkspaceYAMLAbsentFallsBackToStream pins
// the fallback: when no sibling workspace.yaml is present, the parser
// falls back to the event-stream cwd/gitRoot (existing behavior). No
// regression for sessions captured without a workspace.yaml.
func TestParseEventsJSONL_WorkspaceYAMLAbsentFallsBackToStream(t *testing.T) {
	dir := t.TempDir()
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	ssRoot := filepath.Join(dir, ".copilot", "session-state")
	sessDir := filepath.Join(ssRoot, uuid)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// No workspace.yaml.
	evt := filepath.Join(sessDir, "events.jsonl")
	body := `{"type":"session.start","data":{"sessionId":"` + uuid + `","copilotVersion":"1.0.48","selectedModel":"gpt-5-mini","context":{"cwd":` + jsonStr(t, dir) + `,"gitRoot":` + jsonStr(t, dir) + `}},"id":"e1","timestamp":"2026-05-19T01:00:00.000Z","parentId":null}` + "\n" +
		`{"type":"user.message","data":{"content":"hello"},"id":"e2","timestamp":"2026-05-19T01:00:01.000Z","parentId":"e1"}` + "\n"
	if err := os.WriteFile(evt, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) == 0 {
		t.Fatalf("ToolEvents empty")
	}
	// Should fall back to the event-stream cwd (the tempdir).
	for i, e := range res.ToolEvents {
		if e.ProjectRoot != dir {
			t.Errorf("ToolEvents[%d].ProjectRoot = %q, want %q (event-stream fallback)", i, e.ProjectRoot, dir)
		}
	}
}

// TestParseEventsJSONL_MCPEnrichment_PromotesUnknownToMCPCall pins
// the v1.6.13 MCP enrichment: a tool whose toolName doesn't match
// any built-in classifier (e.g. `ide-get_selection`) but carries
// mcpServerName must classify as ActionMCPCall, not ActionUnknown.
// The pre-fix classifier relied solely on toolName and missed MCP
// servers without the `github-mcp-server-` prefix convention.
func TestParseEventsJSONL_MCPEnrichment_PromotesUnknownToMCPCall(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	start := `{"type":"tool.execution_start","data":{"toolCallId":"call_M1","toolName":"ide-get_selection","mcpServerName":"ide","mcpToolName":"get_selection","arguments":{},"turnId":"0"},"id":"es-m1","timestamp":"2026-05-19T01:00:00.000Z","parentId":"e1"}`
	complete := `{"type":"tool.execution_complete","data":{"toolCallId":"call_M1","model":"gpt-5-mini","interactionId":"i-m1","success":true,"result":{"content":"text"}},"id":"ec-m1","timestamp":"2026-05-19T01:00:01.000Z","parentId":"es-m1"}`
	evt := writeMinimalEventsFile(t, uuid, start, complete)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var row *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SourceEventID == "ec-m1" {
			row = &res.ToolEvents[i]
			break
		}
	}
	if row == nil {
		t.Fatalf("tool.execution_complete row missing")
	}
	if row.ActionType != models.ActionMCPCall {
		t.Errorf("ActionType = %q, want %q (mcpServerName must promote Unknown → MCPCall)", row.ActionType, models.ActionMCPCall)
	}
	if row.RawToolName != "ide:get_selection" {
		t.Errorf("RawToolName = %q, want %q (server-prefixed for MCP attribution)", row.RawToolName, "ide:get_selection")
	}
}

// TestParseEventsJSONL_MCPEnrichment_PreservesKnownClassification pins
// that an MCP-routed call to a name that DOES match the built-in
// classifier (e.g. `web_search` via `github-mcp-server`) keeps its
// semantic action type. We only promote Unknown — never demote a
// matched type. The operator specimen has 49 such web_search calls.
func TestParseEventsJSONL_MCPEnrichment_PreservesKnownClassification(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	start := `{"type":"tool.execution_start","data":{"toolCallId":"call_M2","toolName":"web_search","mcpServerName":"github-mcp-server","mcpToolName":"web_search","arguments":{"query":"copilot cli docs"},"turnId":"0"},"id":"es-m2","timestamp":"2026-05-19T01:00:00.000Z","parentId":"e1"}`
	complete := `{"type":"tool.execution_complete","data":{"toolCallId":"call_M2","model":"gpt-5-mini","interactionId":"i-m2","success":true,"result":{"content":"results"}},"id":"ec-m2","timestamp":"2026-05-19T01:00:01.000Z","parentId":"es-m2"}`
	evt := writeMinimalEventsFile(t, uuid, start, complete)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var row *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SourceEventID == "ec-m2" {
			row = &res.ToolEvents[i]
			break
		}
	}
	if row == nil {
		t.Fatalf("tool.execution_complete row missing")
	}
	if row.ActionType != models.ActionWebSearch {
		t.Errorf("ActionType = %q, want %q (web_search must stay web_search even when MCP-routed)", row.ActionType, models.ActionWebSearch)
	}
	if row.RawToolName != "github-mcp-server:web_search" {
		t.Errorf("RawToolName = %q, want %q (server attribution preserved)", row.RawToolName, "github-mcp-server:web_search")
	}
}

// TestParseEventsJSONL_MCPEnrichment_StripsServerPrefix pins the
// composeRawToolName behavior for the github-mcp-server-* convention:
// toolName="github-mcp-server-get_file_contents" with the same
// mcpServerName must NOT produce a doubled prefix in raw_tool_name.
func TestParseEventsJSONL_MCPEnrichment_StripsServerPrefix(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	start := `{"type":"tool.execution_start","data":{"toolCallId":"call_M3","toolName":"github-mcp-server-get_file_contents","mcpServerName":"github-mcp-server","mcpToolName":"get_file_contents","arguments":{"path":"README.md"},"turnId":"0"},"id":"es-m3","timestamp":"2026-05-19T01:00:00.000Z","parentId":"e1"}`
	complete := `{"type":"tool.execution_complete","data":{"toolCallId":"call_M3","model":"gpt-5-mini","interactionId":"i-m3","success":true,"result":{"content":"body"}},"id":"ec-m3","timestamp":"2026-05-19T01:00:01.000Z","parentId":"es-m3"}`
	evt := writeMinimalEventsFile(t, uuid, start, complete)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var row *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SourceEventID == "ec-m3" {
			row = &res.ToolEvents[i]
			break
		}
	}
	if row == nil {
		t.Fatalf("tool.execution_complete row missing")
	}
	if row.ActionType != models.ActionMCPCall {
		t.Errorf("ActionType = %q, want %q", row.ActionType, models.ActionMCPCall)
	}
	want := "github-mcp-server:get_file_contents"
	if row.RawToolName != want {
		t.Errorf("RawToolName = %q, want %q (must not double-prefix)", row.RawToolName, want)
	}
}

// TestParseEventsJSONL_ReasoningNeverMintsAnAction is the B3 regression
// pin: an assistant.message's reasoningText / reasoningOpaque produce NO
// action row (they briefly minted a `cline-cli`-shaped
// `<tool>.reasoning` task_complete). Readable reasoningText rides the
// sibling assistant_text row's PrecedingReasoning; an OPAQUE-ONLY
// message threads NOTHING (the uniform placeholder rule — an encrypted
// blob is not content, matching codex).
func TestParseEventsJSONL_ReasoningNeverMintsAnAction(t *testing.T) {
	cases := []struct {
		name          string
		reasoningAttr string
		wantThreaded  string
	}{
		{
			name:          "readable text threads",
			reasoningAttr: `"reasoningText":"THREADED_REASONING",`,
			wantThreaded:  "THREADED_REASONING",
		},
		{
			// The dominant live shape on models that return encrypted
			// reasoning: only `reasoningOpaque` is present. Pre-fix this
			// threaded "[encrypted reasoning, 40 bytes]".
			name:          "opaque-only threads nothing",
			reasoningAttr: `"reasoningOpaque":"0123456789abcdef0123456789abcdef01234567",`,
			wantThreaded:  "",
		},
		{
			// Both present: the readable text wins, the blob is ignored.
			name:          "readable text wins over opaque",
			reasoningAttr: `"reasoningText":"THREADED_REASONING","reasoningOpaque":"0123456789abcdef0123456789abcdef01234567",`,
			wantThreaded:  "THREADED_REASONING",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			uuid := "11111111-2222-3333-4444-555555555555"
			ssRoot := filepath.Join(dir, ".copilot", "session-state")
			sessDir := filepath.Join(ssRoot, uuid)
			if err := os.MkdirAll(sessDir, 0o755); err != nil {
				t.Fatal(err)
			}
			evt := filepath.Join(sessDir, "events.jsonl")
			body := strings.Join([]string{
				`{"type":"session.start","data":{"sessionId":"` + uuid + `","copilotVersion":"1.0.48","selectedModel":"gpt-5-mini","context":{"cwd":` + jsonStr(t, dir) + `,"gitRoot":` + jsonStr(t, dir) + `,"branch":"main"}},"id":"e1","timestamp":"2026-05-17T09:28:27.909Z","parentId":null}`,
				`{"type":"user.message","data":{"content":"do the thing"},"id":"e2","timestamp":"2026-05-17T09:28:38.300Z","parentId":"e1"}`,
				`{"type":"assistant.message","data":{"messageId":"m1","model":"gpt-5-mini","content":"Here is your answer.",` + c.reasoningAttr + `"interactionId":"i1","turnId":"0"},"id":"e3","timestamp":"2026-05-17T09:28:46.000Z","parentId":"e2"}`,
			}, "\n") + "\n"
			if err := os.WriteFile(evt, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}

			a := NewWithOptions(nil, ssRoot)
			res, err := a.ParseSessionFile(context.Background(), evt, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			var assistantRows int
			for _, ev := range res.ToolEvents {
				if strings.Contains(strings.ToLower(ev.RawToolName), "reasoning") {
					t.Fatalf("reasoning-named action row emitted: raw=%q %+v", ev.RawToolName, ev)
				}
				if ev.Target == "THREADED_REASONING" || ev.ToolOutput == "THREADED_REASONING" {
					t.Fatalf("reasoning body surfaced as action content: %+v", ev)
				}
				// No surface may carry the opaque blob, its byte count,
				// or a placeholder standing in for it.
				for _, field := range []string{ev.Target, ev.ToolOutput, ev.RawToolInput, ev.PrecedingReasoning} {
					if strings.Contains(strings.ToLower(field), "encrypted reasoning") ||
						strings.Contains(field, "0123456789abcdef") {
						t.Fatalf("opaque reasoning placeholder/blob surfaced in %q: %+v", field, ev)
					}
				}
				if ev.RawToolName != models.ToolCopilotCLI+".assistant_text" {
					continue
				}
				assistantRows++
				if ev.PrecedingReasoning != c.wantThreaded {
					t.Errorf("assistant_text PrecedingReasoning = %q, want %q",
						ev.PrecedingReasoning, c.wantThreaded)
				}
			}
			if assistantRows != 1 {
				t.Fatalf("assistant_text rows = %d, want 1: %+v", assistantRows, res.ToolEvents)
			}
		})
	}
}

// TestThreadableReasoning covers the helper's contract directly: only
// readable reasoningText is threadable; an opaque blob yields "" no
// matter its size (B3 uniform placeholder rule).
func TestThreadableReasoning(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"plain text", "I should look at the file.", "I should look at the file."},
		{"whitespace-only is empty", "   \n\t ", ""},
		{"absent is empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := threadableReasoning(c.text); got != c.want {
				t.Errorf("threadableReasoning(%q) = %q, want %q", c.text, got, c.want)
			}
		})
	}
}

// TestParseEventsJSONL_SubagentEventsStampedSidechain pins that every
// row emitted inside a subagent's execution context (env.agentId != "")
// gets IsSidechain=true, on BOTH ToolEvents and TokenEvents — while the
// spawning context (parent-level rows with no agentId, including the
// asst.message that precedes subagent.started) stays IsSidechain=false.
// This covers the copilot-cli half of the WS-SUBAGENT/EFFORT work-stream
// (adapter-parity-audit-2026-08-25.md §2.4): the deferred subagent
// model-attribution mechanism existed, but nothing derived from it ever
// flagged the child rows as sidechain.
func TestParseEventsJSONL_SubagentEventsStampedSidechain(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	// Parent-context control: no agentId anywhere on this row.
	parentAsst := `{"type":"assistant.message","data":{"messageId":"m-parent","content":"parent reply","outputTokens":11,"requestId":"00000-rid-parent"},"id":"asP","timestamp":"2026-04-20T18:37:00.000Z","parentId":"e1"}`
	subStarted := `{"type":"subagent.started","data":{"toolCallId":"agent-T","agentName":"rubber-duck"},"id":"sa-t","timestamp":"2026-04-20T18:38:21.175Z","parentId":"e1","agentId":"agent-T"}`
	// Child asst.message + tool call, both carrying agentId="agent-T".
	toolStart := `{"type":"tool.execution_start","data":{"toolCallId":"call-1","toolName":"grep","arguments":{"pattern":"foo"},"turnId":"0"},"id":"ts1","timestamp":"2026-04-20T18:38:21.500Z","parentId":"sa-t","agentId":"agent-T"}`
	toolCompl := `{"type":"tool.execution_complete","data":{"toolCallId":"call-1","model":"gpt-5.4","interactionId":"i1","turnId":"0","success":true,"result":{"content":"found"}},"id":"tc1","timestamp":"2026-04-20T18:38:22.000Z","parentId":"ts1","agentId":"agent-T"}`
	asstUnderAgent := `{"type":"assistant.message","data":{"messageId":"mA1","content":"subagent says hi","outputTokens":1234,"requestId":"00000-rid-A"},"id":"asA1","timestamp":"2026-04-20T18:38:23.000Z","parentId":"tc1","agentId":"agent-T"}`
	subCompleted := `{"type":"subagent.completed","data":{"toolCallId":"agent-T","agentName":"rubber-duck","model":"gpt-5.4","totalTokens":18791,"totalToolCalls":1,"durationMs":73305},"id":"sc1","timestamp":"2026-04-20T18:39:33.943Z","parentId":"asA1","agentId":"agent-T"}`

	evt := writeMinimalEventsFile(t, uuid, parentAsst, subStarted, toolStart, toolCompl, asstUnderAgent, subCompleted)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	toolEventsByMsg := map[string]models.ToolEvent{}
	for _, te := range res.ToolEvents {
		toolEventsByMsg[te.SourceEventID] = te
	}
	tokenEventsByMsg := map[string]models.TokenEvent{}
	for _, te := range res.TokenEvents {
		tokenEventsByMsg[te.MessageID] = te
	}

	// Parent-context rows: IsSidechain must be false.
	if got := tokenEventsByMsg["00000-rid-parent"].IsSidechain; got {
		t.Errorf("parent asst.message TokenEvent IsSidechain = %v, want false", got)
	}
	// Child rows under agent-T: IsSidechain must be true.
	toolCompleteRow, ok := toolEventsByMsg["tc1"]
	if !ok {
		t.Fatalf("tool.execution_complete ToolEvent (id=tc1) not found among %d ToolEvents", len(res.ToolEvents))
	}
	if !toolCompleteRow.IsSidechain {
		t.Errorf("subagent tool.execution_complete IsSidechain = %v, want true", toolCompleteRow.IsSidechain)
	}
	if got := tokenEventsByMsg["00000-rid-A"].IsSidechain; !got {
		t.Errorf("subagent asst.message TokenEvent IsSidechain = %v, want true", got)
	}
	assistantTextRow, ok := toolEventsByMsg["asA1"]
	if !ok {
		t.Fatalf("subagent assistant_text ToolEvent (id=asA1) not found among %d ToolEvents", len(res.ToolEvents))
	}
	if !assistantTextRow.IsSidechain {
		t.Errorf("subagent assistant_text IsSidechain = %v, want true", assistantTextRow.IsSidechain)
	}
	// The spawning subagent.started/completed markers themselves don't
	// mint rows (no ToolEvent case for those types) — nothing further
	// to assert there; the point is the CHILD work rows above are the
	// ones flagged, per the convention documented on emitEvent.
}

// TestParseEventsJSONL_ReasoningEffortWiredIntoMetadata pins the
// copilot-cli half of adapter-parity-audit-2026-08-25.md §2.5:
// session.model_change.data.reasoningEffort and
// session.resume.data.reasoningEffort were parsed into structs but
// never referenced — this asserts they now land in
// ActionMetadata.EffortLevel on subsequently emitted rows, persist as
// session state across further rows until changed, and compose safely
// with metadata already set for another reason (permission grants).
func TestParseEventsJSONL_ReasoningEffortWiredIntoMetadata(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	// Before any reasoningEffort is seen: no EffortLevel.
	preAsst := `{"type":"assistant.message","data":{"messageId":"m-pre","content":"before effort is set","outputTokens":5,"requestId":"00000-rid-pre"},"id":"as-pre","timestamp":"2026-04-20T18:00:00.000Z","parentId":"e1"}`
	modelChange := `{"type":"session.model_change","data":{"previousModel":"gpt-5-mini","newModel":"claude-opus-4.7","previousReasoningEffort":"low","reasoningEffort":"high"},"id":"mc1","timestamp":"2026-04-20T18:01:00.000Z","parentId":"e1"}`
	postAsst := `{"type":"assistant.message","data":{"messageId":"m-post","content":"after effort is set","outputTokens":9,"requestId":"00000-rid-post"},"id":"as-post","timestamp":"2026-04-20T18:02:00.000Z","parentId":"mc1"}`
	// A second unrelated row after: EffortLevel must persist (session state).
	laterAsst := `{"type":"assistant.message","data":{"messageId":"m-later","content":"still after effort is set","outputTokens":3,"requestId":"00000-rid-later"},"id":"as-later","timestamp":"2026-04-20T18:03:00.000Z","parentId":"as-post"}`

	evt := writeMinimalEventsFile(t, uuid, preAsst, modelChange, postAsst, laterAsst)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	byMsg := map[string]models.ToolEvent{}
	for _, te := range res.ToolEvents {
		byMsg[te.SourceEventID] = te
	}
	preRow, ok := byMsg["as-pre"]
	if !ok {
		t.Fatalf("pre-effort assistant_text row not found")
	}
	if preRow.Metadata != nil && preRow.Metadata.EffortLevel != "" {
		t.Errorf("pre-effort row EffortLevel = %q, want empty (reasoningEffort not yet seen)", preRow.Metadata.EffortLevel)
	}
	postRow, ok := byMsg["as-post"]
	if !ok {
		t.Fatalf("post-effort assistant_text row not found")
	}
	if postRow.Metadata == nil || postRow.Metadata.EffortLevel != "high" {
		t.Fatalf("post-effort row Metadata = %+v, want EffortLevel=high", postRow.Metadata)
	}
	laterRow, ok := byMsg["as-later"]
	if !ok {
		t.Fatalf("later assistant_text row not found")
	}
	if laterRow.Metadata == nil || laterRow.Metadata.EffortLevel != "high" {
		t.Fatalf("later row Metadata = %+v, want EffortLevel=high (must persist as session state)", laterRow.Metadata)
	}
}

// TestParseEventsJSONL_ReasoningEffortMergesWithPermissionMetadata pins
// that effortMetadata composes with (never clobbers) metadata already
// populated for another reason — here permission.completed's
// PermissionApprovalKind/PermissionLocationKey.
func TestParseEventsJSONL_ReasoningEffortMergesWithPermissionMetadata(t *testing.T) {
	uuid := "5c51d44b-5a9f-4b23-85ff-0fddaadf2212"
	modelChange := `{"type":"session.model_change","data":{"previousModel":"gpt-5-mini","newModel":"gpt-5-mini","reasoningEffort":"medium"},"id":"mc1","timestamp":"2026-04-20T18:01:00.000Z","parentId":"e1"}`
	permReq := `{"type":"permission.requested","data":{"requestId":"pr1","permissionRequest":{"kind":"shell","toolCallId":"tc1","fullCommandText":"go test ./...","intention":"run tests"}},"id":"pq1","timestamp":"2026-04-20T18:02:00.000Z","parentId":"mc1"}`
	permCompleted := `{"type":"permission.completed","data":{"requestId":"pr1","toolCallId":"tc1","result":{"kind":"approved-for-session","locationKey":"/repo"}},"id":"pc1","timestamp":"2026-04-20T18:02:05.000Z","parentId":"pq1"}`

	evt := writeMinimalEventsFile(t, uuid, modelChange, permReq, permCompleted)
	ssRoot := filepath.Dir(filepath.Dir(evt))
	a := NewWithOptions(nil, ssRoot)
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	var permRow *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].SourceEventID == "pc1" {
			permRow = &res.ToolEvents[i]
		}
	}
	if permRow == nil {
		t.Fatalf("permission.completed row (id=pc1) not found among %d ToolEvents", len(res.ToolEvents))
	}
	if permRow.Metadata == nil {
		t.Fatalf("Metadata is nil, want PermissionApprovalKind + EffortLevel both set")
	}
	if permRow.Metadata.PermissionApprovalKind != "approved-for-session" {
		t.Errorf("PermissionApprovalKind = %q, want %q", permRow.Metadata.PermissionApprovalKind, "approved-for-session")
	}
	if permRow.Metadata.PermissionLocationKey != "/repo" {
		t.Errorf("PermissionLocationKey = %q, want %q", permRow.Metadata.PermissionLocationKey, "/repo")
	}
	if permRow.Metadata.EffortLevel != "medium" {
		t.Errorf("EffortLevel = %q, want %q (must merge with permission metadata, not clobber it)", permRow.Metadata.EffortLevel, "medium")
	}
}

// TestParseEventsJSONL_AutoModeResolvedReplacesSentinel pins Auto-routing
// attribution. When the user picks Auto, Copilot CLI writes
// session.model_change{newModel:"auto"} (the router sentinel, which prices as a
// MISS) and then session.auto_mode_resolved{chosenModel:<routed id>}. A token
// row whose assistant.message omits data.model must bill at the ROUTED id, and
// a row that does carry data.model keeps its own (per-message wins). Shape from
// a live ~/.copilot/session-state events.jsonl (2026-08).
func TestParseEventsJSONL_AutoModeResolvedReplacesSentinel(t *testing.T) {
	uuid := "533a8529-1d64-41ec-a43c-c312c0222ee2"
	toAuto := `{"type":"session.model_change","data":{"previousModel":"gpt-5-mini","newModel":"auto"},"id":"mc1","timestamp":"2026-08-01T11:40:00.000Z","parentId":"e1"}`
	// Before the router resolves, the only session-level identity is the
	// sentinel; an id-less message here stays "auto" (an honest MISS).
	preResolve := `{"type":"assistant.message","data":{"messageId":"m0","content":"x","outputTokens":5,"requestId":"req-0"},"id":"am0","timestamp":"2026-08-01T11:40:01.000Z","parentId":"mc1"}`
	resolved := `{"type":"session.auto_mode_resolved","data":{"chosenModel":"claude-haiku-4.5","candidateModels":["gpt-5-mini","claude-haiku-4.5"]},"id":"ar1","timestamp":"2026-08-01T11:40:02.000Z","parentId":"mc1"}`
	noModel := `{"type":"assistant.message","data":{"messageId":"m1","content":"x","outputTokens":7,"requestId":"req-1"},"id":"am1","timestamp":"2026-08-01T11:40:03.000Z","parentId":"ar1"}`
	ownModel := `{"type":"assistant.message","data":{"messageId":"m2","content":"x","outputTokens":9,"requestId":"req-2","model":"gpt-5-mini"},"id":"am2","timestamp":"2026-08-01T11:40:04.000Z","parentId":"ar1"}`
	emptyResolve := `{"type":"session.auto_mode_resolved","data":{"candidateModels":["gpt-5-mini"]},"id":"ar2","timestamp":"2026-08-01T11:40:05.000Z","parentId":"ar1"}`
	afterEmpty := `{"type":"assistant.message","data":{"messageId":"m3","content":"x","outputTokens":11,"requestId":"req-3"},"id":"am3","timestamp":"2026-08-01T11:40:06.000Z","parentId":"ar2"}`

	evt := writeMinimalEventsFile(t, uuid, toAuto, preResolve, resolved, noModel, ownModel, emptyResolve, afterEmpty)
	a := NewWithOptions(nil, filepath.Dir(filepath.Dir(evt)))
	res, err := a.ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	want := map[string]string{
		"req-0": "auto",             // pre-resolution: the sentinel, never a guess
		"req-1": "claude-haiku-4.5", // routed id replaces the sentinel
		"req-2": "gpt-5-mini",       // per-message data.model wins
		"req-3": "claude-haiku-4.5", // an empty chosenModel does not clobber
	}
	got := map[string]string{}
	for _, te := range res.TokenEvents {
		got[te.MessageID] = te.Model
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("token row %s model = %q, want %q (all rows: %v)", id, got[id], w, got)
		}
	}
}

// TestParseProcessLog_SiblingFallbackUsesAutoResolvedModel pins the same fix
// on the process-log lane: a Tier-1 usage block with no model of its own
// recovers the session model from the sibling events.jsonl, and under Auto
// that must be the router's chosenModel rather than the "auto" sentinel.
func TestParseProcessLog_SiblingFallbackUsesAutoResolvedModel(t *testing.T) {
	dir := t.TempDir()
	uuid := "26df8a84-8f2d-4b5b-babe-04146c5e7b0b"
	logsRoot := filepath.Join(dir, ".copilot", "logs")
	sessDir := filepath.Join(dir, ".copilot", "session-state", uuid)
	for _, d := range []string{logsRoot, sessDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	events := `{"type":"session.start","data":{"sessionId":"` + uuid + `","selectedModel":"gpt-5-mini"},"id":"e1","timestamp":"2026-08-01T11:39:00.000Z","parentId":null}` + "\n" +
		`{"type":"session.model_change","data":{"previousModel":"gpt-5-mini","newModel":"auto"},"id":"mc1","timestamp":"2026-08-01T11:40:00.000Z","parentId":"e1"}` + "\n" +
		`{"type":"session.auto_mode_resolved","data":{"chosenModel":"claude-haiku-4.5","candidateModels":["gpt-5-mini","claude-haiku-4.5"]},"id":"ar1","timestamp":"2026-08-01T11:40:02.000Z","parentId":"mc1"}` + "\n"
	if err := os.WriteFile(filepath.Join(sessDir, "events.jsonl"), []byte(events), 0o644); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(logsRoot, "process-1785584340000-4242.log")
	body := `2026-08-01T11:39:00.000Z [INFO] Workspace initialized: ` + uuid + ` (checkpoints: 0)
2026-08-01T11:40:03.000Z [DEBUG] response (Request-ID 00000-auto-1):
2026-08-01T11:40:03.000Z [DEBUG] data:
2026-08-01T11:40:03.000Z [DEBUG] {
  "usage": {
    "completion_tokens": 120,
    "prompt_tokens": 9000,
    "total_tokens": 9120,
    "prompt_tokens_details": {
      "cached_tokens": 4000
    }
  }
}
2026-08-01T11:40:04.000Z [INFO] some non-DEBUG line that closes the block
`
	if err := os.WriteFile(log, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, logsRoot)
	res, err := a.ParseSessionFile(context.Background(), log, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("TokenEvents = %d, want 1 (got %+v)", len(res.TokenEvents), res.TokenEvents)
	}
	if got := res.TokenEvents[0].Model; got != "claude-haiku-4.5" {
		t.Errorf("Model = %q, want claude-haiku-4.5 (the Auto router's chosenModel, not the sentinel)", got)
	}
}
