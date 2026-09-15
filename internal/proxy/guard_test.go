package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// stubGuard scripts GuardScanner responses and records calls.
type stubGuard struct {
	mu            sync.Mutex
	result        GuardRequestResult
	scanned       [][]byte
	inspected     [][]GuardToolUse
	inspectedTurn []int64 // apiTurnID handed to each InspectResponse call
}

func (s *stubGuard) ScanRequest(_ context.Context, _ string, body []byte, _ string) GuardRequestResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(body))
	copy(cp, body)
	s.scanned = append(s.scanned, cp)
	return s.result
}

func (s *stubGuard) InspectResponse(_ context.Context, _ string, apiTurnID int64, tools []GuardToolUse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inspected = append(s.inspected, tools)
	s.inspectedTurn = append(s.inspectedTurn, apiTurnID)
}

func (s *stubGuard) inspectedTurnIDs() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int64, len(s.inspectedTurn))
	copy(out, s.inspectedTurn)
	return out
}

func (s *stubGuard) inspectedCalls() [][]GuardToolUse {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]GuardToolUse, len(s.inspected))
	copy(out, s.inspected)
	return out
}

// newGuardedTestProxy wires a proxy with the stub guard against one
// Anthropic-shaped upstream that records the body it received.
func newGuardedTestProxy(t *testing.T, g GuardScanner, upstreamBody string) (*Proxy, *fakeSink, *[]byte, func()) {
	t.Helper()
	var gotBody []byte
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = b
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(upstreamBody))
	}))
	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: up.URL,
		OpenAIUpstream:    up.URL,
		Sink:              sink,
		Guard:             g,
	})
	if err != nil {
		up.Close()
		t.Fatalf("proxy.New: %v", err)
	}
	return p, sink, &gotBody, up.Close
}

const anthropicOKBody = `{"id":"msg_1","model":"claude-opus-4-8","stop_reason":"end_turn",` +
	`"content":[{"type":"text","text":"hi"}],` +
	`"usage":{"input_tokens":10,"output_tokens":5}}`

// TestGuardDeny pins the §8.5 deny semantics end-to-end: synthetic
// 403, provider-shaped error body carrying the rule ID, no upstream
// call, and an error api_turn recorded for visibility.
func TestGuardDeny(t *testing.T) {
	t.Parallel()
	g := &stubGuard{result: GuardRequestResult{
		Action: "deny", RuleID: "R-172",
		Reason: "secret-shaped content in an outbound LLM API request: detected github_pat×2",
	}}
	p, sink, gotBody, closeUp := newGuardedTestProxy(t, g, anthropicOKBody)
	defer closeUp()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"x"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var envelope struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("deny body is not JSON: %v (%s)", err, body)
	}
	if envelope.Type != "error" || envelope.Error.Type != "invalid_request_error" {
		t.Errorf("deny body envelope = %+v, want Anthropic error shape", envelope)
	}
	if !strings.Contains(envelope.Error.Message, "[observer-guard R-172]") {
		t.Errorf("deny message %q missing the rule ID marker", envelope.Error.Message)
	}
	if *gotBody != nil {
		t.Error("upstream received a denied request")
	}
	turns := sink.all()
	if len(turns) != 1 || turns[0].HTTPStatus != http.StatusForbidden {
		t.Fatalf("turns = %+v, want one 403 error turn", turns)
	}
	if !strings.Contains(turns[0].ErrorMessage, "observer-guard R-172") {
		t.Errorf("error turn message %q missing the guard marker", turns[0].ErrorMessage)
	}
}

// TestGuardMask pins §8.2 masking: the upstream receives the
// REWRITTEN body; the client request flows normally.
func TestGuardMask(t *testing.T) {
	t.Parallel()
	masked := `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"[REDACTED:github_pat]"}]}`
	g := &stubGuard{result: GuardRequestResult{Action: "mask", Body: []byte(masked)}}
	p, sink, gotBody, closeUp := newGuardedTestProxy(t, g, anthropicOKBody)
	defer closeUp()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"ghp_secret"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(*gotBody) != masked {
		t.Fatalf("upstream body = %s, want the masked form", *gotBody)
	}
	if turns := sink.all(); len(turns) != 1 || turns[0].InputTokens != 10 {
		t.Fatalf("turns = %+v, want the normal success turn", turns)
	}
}

// TestGuardScanSeesFinalBody pins the §8.1 position: the scanner
// receives the POST-COMPRESSION body (the bytes the provider sees),
// not the client's original.
func TestGuardScanSeesFinalBody(t *testing.T) {
	t.Parallel()
	compressed := `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"compressed"}]}`
	g := &stubGuard{}
	var gotBody []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(anthropicOKBody))
	}))
	defer up.Close()
	sink := &fakeSink{}
	p, err := New(Options{
		AnthropicUpstream: up.URL,
		OpenAIUpstream:    up.URL,
		Sink:              sink,
		Guard:             g,
		Compressor: stubCompressor{result: CompressionResult{
			Body:            []byte(compressed),
			OriginalBytes:   100,
			CompressedBytes: len(compressed),
			CompressedCount: 1,
		}},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"original original original"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.scanned) != 1 {
		t.Fatalf("ScanRequest calls = %d, want exactly 1 (§8.1: ONE guard call per request)", len(g.scanned))
	}
	if string(g.scanned[0]) != compressed {
		t.Fatalf("scanner saw %s, want the post-compression body", g.scanned[0])
	}
	if string(gotBody) != compressed {
		t.Fatalf("upstream saw %s, want the post-compression body", gotBody)
	}
}

// stubCompressor returns a fixed CompressionResult.
type stubCompressor struct{ result CompressionResult }

func (s stubCompressor) Compress(_ context.Context, _ string, _ []byte) CompressionResult {
	return s.result
}

// TestGuardResponseInspection pins §8.3 wiring on both response
// paths: the scanner receives the tool_use blocks from a JSON body
// and from an SSE capture.
func TestGuardResponseInspection(t *testing.T) {
	t.Parallel()

	t.Run("non-streaming JSON", func(t *testing.T) {
		t.Parallel()
		respBody := `{"id":"msg_1","model":"claude-opus-4-8","stop_reason":"tool_use",` +
			`"content":[{"type":"tool_use","id":"tu_1","name":"Bash","input":{"command":"rm -rf ~"}}],` +
			`"usage":{"input_tokens":10,"output_tokens":5}}`
		g := &stubGuard{}
		p, _, _, closeUp := newGuardedTestProxy(t, g, respBody)
		defer closeUp()
		ts := httptest.NewServer(p.Handler())
		defer ts.Close()
		resp, err := http.Post(ts.URL+"/v1/messages", "application/json",
			strings.NewReader(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"x"}]}`))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
		calls := g.inspectedCalls()
		if len(calls) != 1 || len(calls[0]) != 1 {
			t.Fatalf("InspectResponse calls = %+v, want one call with one tool", calls)
		}
		if calls[0][0].Name != "Bash" || !strings.Contains(string(calls[0][0].Input), "rm -rf ~") {
			t.Errorf("tool = %+v, want the Bash rm command", calls[0][0])
		}
		// The response carried usage + model → a turn was inserted; the
		// verdict must be anchored to it (api_turn_id non-zero) so the
		// obs trajectory enrichment can join the guard verdict by api_turn.
		if ids := g.inspectedTurnIDs(); len(ids) != 1 || ids[0] == 0 {
			t.Errorf("inspected apiTurnID = %v, want one non-zero id anchored to the inserted turn", ids)
		}
	})

	t.Run("anthropic SSE stream", func(t *testing.T) {
		t.Parallel()
		sse := strings.Join([]string{
			`event: message_start`,
			`data: {"type":"message_start","message":{"id":"msg_1","model":"claude-opus-4-8","usage":{"input_tokens":10}}}`,
			``,
			`event: content_block_start`,
			`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tu_1","name":"Bash","input":{}}}`,
			``,
			`event: content_block_delta`,
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"rm "}}`,
			``,
			`event: content_block_delta`,
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"-rf ~\"}"}}`,
			``,
			`event: message_delta`,
			`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":7}}`,
			``,
		}, "\n")
		g := &stubGuard{}
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(sse))
		}))
		defer up.Close()
		sink := &fakeSink{}
		p, err := New(Options{AnthropicUpstream: up.URL, OpenAIUpstream: up.URL, Sink: sink, Guard: g})
		if err != nil {
			t.Fatalf("proxy.New: %v", err)
		}
		ts := httptest.NewServer(p.Handler())
		defer ts.Close()
		resp, err := http.Post(ts.URL+"/v1/messages", "application/json",
			strings.NewReader(`{"model":"claude-opus-4-8","stream":true,"messages":[{"role":"user","content":"x"}]}`))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		// The client unblocks once the payload bytes are flushed —
		// the handler's post-stream tail (inspection, insert) races
		// the assertion. Poll, the package's established idiom.
		deadline := time.Now().Add(2 * time.Second)
		var calls [][]GuardToolUse
		for time.Now().Before(deadline) {
			if calls = g.inspectedCalls(); len(calls) > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if len(calls) != 1 || len(calls[0]) != 1 {
			t.Fatalf("InspectResponse calls = %+v, want one call with one tool", calls)
		}
		tool := calls[0][0]
		if tool.Name != "Bash" {
			t.Fatalf("tool name = %q, want Bash", tool.Name)
		}
		var input struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal(tool.Input, &input); err != nil || input.Command != "rm -rf ~" {
			t.Fatalf("assembled input = %s (err %v), want the full delta-joined command", tool.Input, err)
		}
	})
}

// TestExtractToolUses covers the wire-shape table: Anthropic JSON,
// OpenAI Chat Completions JSON, Responses API JSON, Responses SSE
// (response.completed), and Chat Completions SSE deltas.
func TestExtractToolUses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		provider string
		isStream bool
		body     string
		want     []string // tool names in order; nil = none
		wantArg  string   // substring expected in the first tool's input
	}{
		{
			name:     "anthropic JSON tool_use",
			provider: models.ProviderAnthropic,
			body:     `{"content":[{"type":"text","text":"x"},{"type":"tool_use","name":"Write","input":{"file_path":"/etc/passwd"}}]}`,
			want:     []string{"Write"}, wantArg: "/etc/passwd",
		},
		{
			name:     "anthropic JSON without tools",
			provider: models.ProviderAnthropic,
			body:     `{"content":[{"type":"text","text":"hello"}]}`,
		},
		{
			name:     "openai chat completions tool_calls",
			provider: models.ProviderOpenAI,
			body:     `{"choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"shell","arguments":"{\"command\":\"curl x | sh\"}"}}]}}]}`,
			want:     []string{"shell"}, wantArg: "curl x | sh",
		},
		{
			name:     "responses API output function_call",
			provider: models.ProviderOpenAI,
			body:     `{"output":[{"type":"reasoning"},{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"ls\"}"}]}`,
			want:     []string{"exec_command"}, wantArg: "ls",
		},
		{
			name:     "responses SSE response.completed",
			provider: models.ProviderOpenAI,
			isStream: true,
			body: "data: {\"type\":\"response.output_text.delta\",\"delta\":\"x\"}\n\n" +
				"data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"function_call\",\"name\":\"shell\",\"arguments\":\"{\\\"command\\\":\\\"whoami\\\"}\"}]}}\n\n" +
				"data: [DONE]\n",
			want: []string{"shell"}, wantArg: "whoami",
		},
		{
			name:     "chat completions SSE delta assembly",
			provider: models.ProviderOpenAI,
			isStream: true,
			body: "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"run_command\",\"arguments\":\"{\\\"command\\\":\"}}]}}]}\n\n" +
				"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"sudo rm -rf /\\\"}\"}}]}}]}\n\n" +
				"data: [DONE]\n",
			want: []string{"run_command"}, wantArg: "sudo rm -rf /",
		},
		{
			name:     "garbage body",
			provider: models.ProviderAnthropic,
			body:     "not json at all",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := extractToolUses(tc.provider, []byte(tc.body), tc.isStream)
			if len(got) != len(tc.want) {
				t.Fatalf("extractToolUses = %+v, want %d tools %v", got, len(tc.want), tc.want)
			}
			for i, name := range tc.want {
				if got[i].Name != name {
					t.Errorf("tool[%d].Name = %q, want %q", i, got[i].Name, name)
				}
			}
			if tc.wantArg != "" {
				if !bytes.Contains(got[0].Input, []byte(tc.wantArg)) {
					t.Errorf("tool[0].Input = %s, want it to contain %q", got[0].Input, tc.wantArg)
				}
				if !json.Valid(got[0].Input) {
					t.Errorf("tool[0].Input = %s is not valid JSON (arguments must be normalized to object form)", got[0].Input)
				}
			}
		})
	}
}

// TestGuardDenyBody pins both provider error shapes.
func TestGuardDenyBody(t *testing.T) {
	t.Parallel()
	anth := guardDenyBody(models.ProviderAnthropic, "R-172", "reason text", 403)
	var a struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(anth, &a); err != nil || a.Type != "error" || a.Error.Type != "invalid_request_error" {
		t.Fatalf("anthropic deny body = %s (err %v)", anth, err)
	}
	oai := guardDenyBody(models.ProviderOpenAI, "R-172", "reason text", 403)
	var o struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(oai, &o); err != nil || o.Error.Type != "invalid_request_error" || o.Error.Code != "observer_guard_denied" {
		t.Fatalf("openai deny body = %s (err %v)", oai, err)
	}
	for _, b := range [][]byte{anth, oai} {
		if !bytes.Contains(b, []byte("[observer-guard R-172]")) {
			t.Errorf("deny body %s missing the rule marker", b)
		}
	}
}

// TestGuardDenyBody_GeminiShape closes the gap the prompt-submit
// intervention contract documented (§3.1): a Gemini-routed R-172 deny
// previously fell through to the OpenAI error shape, which a Gemini
// client does not parse as an error. Google's own error envelope
// (google.aip.dev/193) is {"error":{"code","message","status"}}. The
// plain "deny" action always renders at 403 (serveGuardDeny's own
// default; guard.ProxyRequestResult carries no Status for this path),
// so 403 is what this test exercises.
func TestGuardDenyBody_GeminiShape(t *testing.T) {
	t.Parallel()
	body := guardDenyBody(models.ProviderGoogle, "R-172", "reason text", 403)
	var g struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &g); err != nil {
		t.Fatalf("gemini deny body is not JSON: %v (%s)", err, body)
	}
	if g.Error.Code != 403 || g.Error.Status != "PERMISSION_DENIED" {
		t.Errorf("gemini deny body = %+v, want code=403 status=PERMISSION_DENIED", g.Error)
	}
	if !bytes.Contains(body, []byte("[observer-guard R-172]")) {
		t.Errorf("gemini deny body %s missing the rule marker", body)
	}
}

// TestGeminiErrorBody_StatusPassesThrough pins the NIT fix (phase-3b
// review): the Gemini error envelope's own {"code",...} field must
// track the REAL HTTP status passed in — not a hardcoded 400 — across
// every status this package ever calls it with, plus a defensive
// unmapped value.
func TestGeminiErrorBody_StatusPassesThrough(t *testing.T) {
	t.Parallel()
	tests := []struct {
		status     int
		wantStatus string
	}{
		{400, "INVALID_ARGUMENT"},
		{403, "PERMISSION_DENIED"},
		{500, "UNKNOWN"}, // defensive: should be unreachable in practice
	}
	for _, tc := range tests {
		body := geminiErrorBody("reason text", tc.status)
		var g struct {
			Error struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
				Status  string `json:"status"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &g); err != nil {
			t.Fatalf("status %d: gemini error body is not JSON: %v (%s)", tc.status, err, body)
		}
		if g.Error.Code != tc.status || g.Error.Status != tc.wantStatus {
			t.Errorf("status %d: gemini error body = %+v, want code=%d status=%s", tc.status, g.Error, tc.status, tc.wantStatus)
		}
	}
}

// TestGuardPromptDenyBody pins the prompt-submit intervention PROXY
// LANE's error shapes (contract §3.2's error-body table): all three
// provider envelopes, and — unlike guardDenyBody — NO
// "[observer-guard ...] request blocked by Observer policy:"
// wrapping, since reason already is the complete, house-styled
// developer-facing message.
func TestGuardPromptDenyBody(t *testing.T) {
	t.Parallel()
	const reason = "observer: detected credit_card×1 (16 chars). Send it again unchanged to confirm, or edit it out."

	anth := guardPromptDenyBody(models.ProviderAnthropic, reason, 400)
	var a struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(anth, &a); err != nil || a.Type != "error" || a.Error.Type != "invalid_request_error" || a.Error.Message != reason {
		t.Fatalf("anthropic prompt-deny body = %s (err %v)", anth, err)
	}

	oai := guardPromptDenyBody(models.ProviderOpenAI, reason, 400)
	var o struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(oai, &o); err != nil || o.Error.Type != "invalid_request_error" || o.Error.Code != "observer_prompt_guard" || o.Error.Message != reason {
		t.Fatalf("openai prompt-deny body = %s (err %v)", oai, err)
	}

	gem := guardPromptDenyBody(models.ProviderGoogle, reason, 400)
	var g struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	if err := json.Unmarshal(gem, &g); err != nil || g.Error.Code != 400 || g.Error.Status != "INVALID_ARGUMENT" || g.Error.Message != reason {
		t.Fatalf("gemini prompt-deny body = %s (err %v)", gem, err)
	}

	for _, b := range [][]byte{anth, oai, gem} {
		if bytes.Contains(b, []byte("[observer-guard")) || bytes.Contains(b, []byte("egress policy")) {
			t.Errorf("prompt-deny body %s wrongly carries the agent-facing egress framing", b)
		}
	}
}

// TestGuardPromptDeny pins the prompt-submit intervention PROXY LANE's
// end-to-end deny (contract §3): the "prompt_deny" action renders at
// the SCANNER-CHOSEN status (400 here, a fresh ask-once interrupt),
// with the developer-facing body — never a connection drop, never the
// egress-policy framing.
func TestGuardPromptDeny(t *testing.T) {
	t.Parallel()
	g := &stubGuard{result: GuardRequestResult{
		Action: "prompt_deny", RuleID: "R-190", Status: 400,
		Reason: "observer: detected credit_card×1 (16 chars). Send it again unchanged to confirm, or edit it out.",
	}}
	p, sink, gotBody, closeUp := newGuardedTestProxy(t, g, anthropicOKBody)
	defer closeUp()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"x"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var envelope struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("prompt-deny body is not JSON: %v (%s)", err, body)
	}
	if envelope.Type != "error" || envelope.Error.Type != "invalid_request_error" {
		t.Errorf("prompt-deny body envelope = %+v, want Anthropic error shape", envelope)
	}
	if !strings.HasPrefix(envelope.Error.Message, "observer: ") {
		t.Errorf("prompt-deny message %q, want the developer-facing house message", envelope.Error.Message)
	}
	if *gotBody != nil {
		t.Error("upstream received a prompt-denied request")
	}
	turns := sink.all()
	if len(turns) != 1 || turns[0].HTTPStatus != http.StatusBadRequest {
		t.Fatalf("turns = %+v, want one 400 error turn", turns)
	}
}

// TestGuardPromptDeny_UnsetStatusDefaultsTo403 pins the safe fallback
// for a GuardRequestResult that never sets Status (never 429, never a
// 5xx even by omission).
func TestGuardPromptDeny_UnsetStatusDefaultsTo403(t *testing.T) {
	t.Parallel()
	g := &stubGuard{result: GuardRequestResult{
		Action: "prompt_deny", RuleID: "R-190",
		Reason: "observer: edit it out before sending.",
	}}
	p, _, _, closeUp := newGuardedTestProxy(t, g, anthropicOKBody)
	defer closeUp()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"x"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (the safe unset-Status default)", resp.StatusCode)
	}
}

// TestGuardPromptDeny_ClampsUnsafeStatus pins F8 (phase-3b review):
// serveGuardPromptDeny does not trust an arbitrary Status value from
// the guard scanner — contract §3.3 allows exactly {400, 403}, so
// anything else (a scanner-side bug that produced, say, 429 — the
// exact value the contract singles out as unsafe because every major
// SDK retries it by default) is clamped to the conservative 403
// default rather than reaching the client verbatim.
func TestGuardPromptDeny_ClampsUnsafeStatus(t *testing.T) {
	t.Parallel()
	g := &stubGuard{result: GuardRequestResult{
		Action: "prompt_deny", RuleID: "R-190", Status: http.StatusTooManyRequests,
		Reason: "observer: edit it out before sending.",
	}}
	p, _, _, closeUp := newGuardedTestProxy(t, g, anthropicOKBody)
	defer closeUp()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-opus-4-8","messages":[{"role":"user","content":"x"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 429 clamped to 403", resp.StatusCode)
	}
}

// stubPhaseGuard implements PromptPhaseScanner on top of stubGuard: the
// prompt phase denies when the ORIGINAL body still carries a key-shaped
// marker, and both phases record the bodies they were handed.
type stubPhaseGuard struct {
	stubGuard
	promptBodies [][]byte
	afterBodies  [][]byte
}

func (s *stubPhaseGuard) ScanPrompt(_ context.Context, _ string, body []byte, _ string) GuardRequestResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.promptBodies = append(s.promptBodies, append([]byte(nil), body...))
	if strings.Contains(string(body), "sk-ant-") {
		return GuardRequestResult{Action: "prompt_deny", RuleID: "R-172", Reason: "observer: secret-shaped content in the prompt", Status: 400}
	}
	if strings.Contains(string(body), "MASKME") {
		return GuardRequestResult{Action: "mask", Body: []byte(strings.ReplaceAll(string(body), "MASKME", "[REDACTED:test]"))}
	}
	return GuardRequestResult{}
}

// captureCompressor forwards its input unchanged and records it, so a
// test can prove which body the compressor was handed.
type captureCompressor struct {
	mu     sync.Mutex
	inputs [][]byte
}

func (c *captureCompressor) Compress(_ context.Context, _ string, body []byte) CompressionResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inputs = append(c.inputs, append([]byte(nil), body...))
	return CompressionResult{Body: body, OriginalBytes: len(body), CompressedBytes: len(body)}
}

// TestGuardPromptPhaseMaskFeedsCompressor pins the phase-1 redact branch
// (proxy.go `case "mask"`): the masked body is what the compressor, phase
// 2 and upstream all see — the original secret text never leaves phase 1.
func TestGuardPromptPhaseMaskFeedsCompressor(t *testing.T) {
	t.Parallel()
	const original = `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"token MASKME here"}]}`
	const masked = `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"token [REDACTED:test] here"}]}`
	var gotUpstream []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUpstream, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(anthropicOKBody))
	}))
	defer up.Close()
	g := &stubPhaseGuard{}
	comp := &captureCompressor{}
	p, err := New(Options{AnthropicUpstream: up.URL, OpenAIUpstream: up.URL, Sink: &fakeSink{}, Guard: g, Compressor: comp})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(original))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200 (redact forwards)", resp.StatusCode)
	}
	comp.mu.Lock()
	if len(comp.inputs) != 1 || string(comp.inputs[0]) != masked {
		t.Fatalf("compressor input = %q, want the phase-1 masked body", comp.inputs)
	}
	comp.mu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.afterBodies) != 1 || string(g.afterBodies[0]) != masked {
		t.Fatalf("phase 2 saw %q, want the masked body", g.afterBodies)
	}
	if string(gotUpstream) != masked {
		t.Fatalf("upstream saw %q, want the masked body", gotUpstream)
	}
	if strings.Contains(string(gotUpstream), "MASKME") {
		t.Fatalf("original secret text reached upstream")
	}
}

func (s *stubPhaseGuard) ScanRequestAfterPrompt(_ context.Context, _ string, body []byte, _ string) GuardRequestResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.afterBodies = append(s.afterBodies, append([]byte(nil), body...))
	return s.result
}

// TestGuardPromptPhaseScansPreCompressionBody pins the LIVE CORRECTION of
// 2026-09-07: conversation compression forward-scrubs the outbound body,
// so the prompt lane must see the ORIGINAL body (phase 1, before the
// compressor) — a single post-compression scan saw [REDACTED] where the
// pasted secret was and two live Codex Desktop turns went upstream
// silently redacted with no ask, no event and no message. Phase 2 then
// runs on the final body and the legacy ScanRequest is never called.
func TestGuardPromptPhaseScansPreCompressionBody(t *testing.T) {
	t.Parallel()
	const original = `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"my key is sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"}]}`
	const scrubbed = `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"my key is [REDACTED]"}]}`
	const benign = `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"refactor the parser"}]}`
	const benignCompressed = `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"refactor"}]}`

	newProxy := func(t *testing.T, g GuardScanner, compressed string, hits *int) *httptest.Server {
		t.Helper()
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*hits++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(anthropicOKBody))
		}))
		t.Cleanup(up.Close)
		p, err := New(Options{
			AnthropicUpstream: up.URL,
			OpenAIUpstream:    up.URL,
			Sink:              &fakeSink{},
			Guard:             g,
			Compressor: stubCompressor{result: CompressionResult{
				Body: []byte(compressed), OriginalBytes: len(original), CompressedBytes: len(compressed), CompressedCount: 1,
			}},
		})
		if err != nil {
			t.Fatalf("proxy.New: %v", err)
		}
		ts := httptest.NewServer(p.Handler())
		t.Cleanup(ts.Close)
		return ts
	}

	t.Run("secret in the original body is denied before compression can scrub it", func(t *testing.T) {
		g := &stubPhaseGuard{}
		hits := 0
		ts := newProxy(t, g, scrubbed, &hits)
		resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(original))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("status = %d, want 400 (prompt-lane ask-once interrupt); body=%s", resp.StatusCode, body)
		}
		if hits != 0 {
			t.Fatalf("upstream was reached %d times; a prompt deny must never forward", hits)
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		if len(g.promptBodies) != 1 || !strings.Contains(string(g.promptBodies[0]), "sk-ant-") {
			t.Fatalf("prompt phase saw %q, want the ORIGINAL body carrying the secret", g.promptBodies)
		}
		if len(g.afterBodies) != 0 || len(g.scanned) != 0 {
			t.Fatalf("after-phase=%d legacy=%d calls after a prompt deny, want 0/0", len(g.afterBodies), len(g.scanned))
		}
	})

	t.Run("benign prompt: phase 1 sees the original, phase 2 the compressed body, legacy ScanRequest never called", func(t *testing.T) {
		g := &stubPhaseGuard{}
		hits := 0
		ts := newProxy(t, g, benignCompressed, &hits)
		resp, err := http.Post(ts.URL+"/v1/messages", "application/json", strings.NewReader(benign))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if hits != 1 {
			t.Fatalf("upstream hits = %d, want 1", hits)
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		if len(g.promptBodies) != 1 || string(g.promptBodies[0]) != benign {
			t.Fatalf("prompt phase saw %q, want the original body", g.promptBodies)
		}
		if len(g.afterBodies) != 1 || string(g.afterBodies[0]) != benignCompressed {
			t.Fatalf("after phase saw %q, want the post-compression body", g.afterBodies)
		}
		if len(g.scanned) != 0 {
			t.Fatalf("legacy ScanRequest called %d times for a two-phase scanner, want 0", len(g.scanned))
		}
	})
}
