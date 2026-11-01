package otlpvendor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

// fixtureDir is the repo-root testdata/otlp tree (see its README for how each
// fixture was captured and anonymized).
func fixtureDir(t *testing.T, tool string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "otlp", tool)
}

// loadFixture decodes one fixture into msg. Fixtures captured from a JSON
// exporter are kept in the OTLP/HTTP JSON wire form (hex ids) and decoded the
// way the receiver decodes them; the Codex fixture was captured as protobuf
// and is kept as canonical protojson.
func loadFixture(t *testing.T, tool, file string, wire bool, msg proto.Message) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir(t, tool), file))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if wire {
		err = otlpingest.UnmarshalJSON(raw, msg)
	} else {
		err = protojson.Unmarshal(raw, msg)
	}
	if err != nil {
		t.Fatalf("decode fixture %s/%s: %v", tool, file, err)
	}
}

// wantTurn is the normalized shape a live fixture's turns must take. Every
// live capture ran against the same mock upstream, which reports 1234 input
// (1000 of it cached), 56 output and 16 reasoning tokens per call, so every
// vendor must normalize to NET input 234, cache read 1000, and a GROSS
// output of 56 (reasoning inside output) or 72 (reasoning reported beside
// output and added back, the transcript adapters' convention).
type wantTurn struct {
	n         int
	session   string
	model     string
	input     int64
	output    int64
	cacheRead int64
	reasoning int64
	requestID string // prefix; "otel:" means synthesized
}

func checkTurns(t *testing.T, res Result, tool string, w wantTurn) {
	t.Helper()
	var got []Turn
	for _, tr := range res.Turns {
		if tr.Tool == tool {
			got = append(got, tr)
		}
	}
	if len(got) != w.n {
		t.Fatalf("%s: %d turns, want %d: %+v", tool, len(got), w.n, res.Turns)
	}
	seen := map[string]bool{}
	for _, tr := range got {
		if tr.SessionID != w.session || tr.Model != w.model {
			t.Errorf("%s: identity session=%q model=%q, want %q %q", tool, tr.SessionID, tr.Model, w.session, w.model)
		}
		if tr.InputTokens != w.input || tr.OutputTokens != w.output || tr.CacheReadTokens != w.cacheRead || tr.ReasoningTokens != w.reasoning {
			t.Errorf("%s: tokens in=%d out=%d cr=%d reason=%d, want %d %d %d %d", tool,
				tr.InputTokens, tr.OutputTokens, tr.CacheReadTokens, tr.ReasoningTokens, w.input, w.output, w.cacheRead, w.reasoning)
		}
		if !strings.HasPrefix(tr.RequestID, w.requestID) {
			t.Errorf("%s: request id %q, want prefix %q", tool, tr.RequestID, w.requestID)
		}
		if tr.RequestSynthetic != (w.requestID == "otel:") {
			t.Errorf("%s: synthetic=%v for %q", tool, tr.RequestSynthetic, tr.RequestID)
		}
		if seen[tr.RequestID] {
			t.Errorf("%s: duplicate request id %q (two calls would merge into one row)", tool, tr.RequestID)
		}
		seen[tr.RequestID] = true
		if tr.Timestamp.IsZero() {
			t.Errorf("%s: zero timestamp", tool)
		}
		if tr.SourceTag != SourceNativeOTel {
			t.Errorf("%s: source %q", tool, tr.SourceTag)
		}
	}
}

// TestLiveFixtures maps every export captured live from an installed tool
// (testdata/otlp/README.md) and pins the normalized result. These are the
// rows whose attribute names were seen on the wire, not read from docs.
func TestLiveFixtures(t *testing.T) {
	t.Run("codex", func(t *testing.T) {
		var req collogspb.ExportLogsServiceRequest
		loadFixture(t, "codex", "logs.json", false, &req)
		res := ParseLogs(&req)
		checkTurns(t, res, "codex", wantTurn{
			n: 2, session: "01a10e5e-dbc2-7fe3-b64f-4d7d1918389a", model: "gpt-5.5",
			input: 234, output: 56, cacheRead: 1000, reasoning: 16, requestID: "otel:",
		})
		if len(res.Tools) != 1 || res.Tools[0].Name != "shell" || res.Tools[0].CallID != "call_mock1" ||
			!res.Tools[0].SuccessKnown || res.Tools[0].Success {
			t.Errorf("codex tool calls: %+v (want shell call_mock1 failed)", res.Tools)
		}
		kinds := contentKinds(res)
		if kinds[ContentPrompt] != 1 || kinds[ContentToolInput] != 1 || kinds[ContentToolOutput] != 1 {
			t.Errorf("codex content kinds = %v", kinds)
		}
	})
	t.Run("gemini-cli", func(t *testing.T) {
		var req collogspb.ExportLogsServiceRequest
		loadFixture(t, "gemini-cli", "logs.json", true, &req)
		res := ParseLogs(&req)
		// The export ALSO carries gen_ai.client.inference.operation.details
		// events with token counts; the resource is claimed by gemini-cli,
		// so they are never read as a second turn.
		checkTurns(t, res, "gemini-cli", wantTurn{
			n: 2, session: "655fdd60-68db-4734-b0fa-041f5c562a33", model: "gemini-3.5-flash",
			input: 234, output: 72, cacheRead: 1000, reasoning: 16, requestID: "otel:",
		})
		if len(res.Tools) != 1 || res.Tools[0].Name != "list_directory" || !res.Tools[0].Success || !strings.HasPrefix(res.Tools[0].CallID, "otel:gemini-cli:") {
			t.Errorf("gemini tool calls: %+v", res.Tools)
		}
		if contentKinds(res)[ContentPrompt] != 1 {
			t.Errorf("gemini prompt not captured: %+v", res.Contents)
		}
	})
	t.Run("qwen-code", func(t *testing.T) {
		var req collogspb.ExportLogsServiceRequest
		loadFixture(t, "qwen-code", "logs.json", true, &req)
		res := ParseLogs(&req)
		checkTurns(t, res, "qwen-code", wantTurn{
			n: 2, session: "00f3ac91-e678-4ff1-8dfe-b3b89499a366", model: "mock-model",
			// output_token_count 56 already holds the 16 thoughts (total
			// 1290 == 1234 + 56): gross output stays 56 (T-542).
			input: 234, output: 56, cacheRead: 1000, reasoning: 16, requestID: "chatcmpl-mock",
		})
		if len(res.Tools) != 1 || res.Tools[0].Name != "list_directory" || res.Tools[0].Success {
			t.Errorf("qwen tool calls: %+v", res.Tools)
		}
	})
	t.Run("copilot-cli", func(t *testing.T) {
		var req coltracepb.ExportTraceServiceRequest
		loadFixture(t, "copilot-cli", "traces.json", true, &req)
		res := ParseSpans(&req)
		// Two chat spans; the invoke_agent span carries their SUM and must
		// not be read as a third turn.
		checkTurns(t, res, "copilot-cli", wantTurn{
			n: 2, session: "7bb16a66-a714-4265-b119-e9208f02cbff", model: "gpt-5.5",
			input: 234, output: 56, cacheRead: 1000, reasoning: 16, requestID: "chatcmpl-mock",
		})
		if len(res.Tools) != 1 || res.Tools[0].Name != "list_directory" || res.Tools[0].CallID != "call_mock1" || res.Tools[0].Success {
			t.Errorf("copilot-cli tool calls: %+v", res.Tools)
		}
	})

	// AP-131 (2026-10-22). IBM Bob was a real signed-in run; CodeBuddy and
	// Kimchi ran against the loopback mock, so their usage is the mock's
	// 1234 / 1000 / 56 / 16.
	t.Run("ibm-bob", func(t *testing.T) {
		var req coltracepb.ExportTraceServiceRequest
		loadFixture(t, "ibm-bob", "traces.json", true, &req)
		res := ParseSpans(&req)
		// The external exporter's allow-list carries no token counts: the
		// two LLM Generation spans must not become (zero-token, Bobcoin-
		// priced) turns.
		if len(res.Turns) != 0 || len(res.Contents) != 0 || len(res.Unclaimed) != 0 {
			t.Fatalf("ibm-bob: turns=%d contents=%d unclaimed=%v, want only tool calls", len(res.Turns), len(res.Contents), res.Unclaimed)
		}
		checkGenTimings(t, res, nil, "") // no token row to carry it (AP-125)
		want := []struct {
			name string
			ms   int64
		}{{"read_file", 70}, {"write_file", 79}, {"execute_command", 121}}
		if len(res.Tools) != len(want) {
			t.Fatalf("ibm-bob tool calls: %+v", res.Tools)
		}
		for n, w := range want {
			tc := res.Tools[n]
			if tc.Name != w.name || tc.DurationMS != w.ms || !tc.SuccessKnown || !tc.Success ||
				tc.SessionID != "0a1b2c3d4e5f60718293a4b5c6d7e8f9" || !strings.HasPrefix(tc.CallID, "otel:ibm-bob:") {
				t.Errorf("ibm-bob tool %d = %+v, want %s %dms ok in the task's session", n, tc, w.name, w.ms)
			}
		}
	})
	t.Run("codebuddy/agentlens", func(t *testing.T) {
		var req coltracepb.ExportTraceServiceRequest
		loadFixture(t, "codebuddy", "traces.json", true, &req)
		res := ParseSpans(&req)
		// GROSS prompt, no cache or reasoning split on the wire: the turn
		// keeps the gross input (nothing to net it against).
		checkTurns(t, res, "codebuddy", wantTurn{
			n: 2, session: "01a165ad-1a86-7973-8bb9-a42e9af357ad", model: "mock-model",
			input: 1234, output: 56, cacheRead: 0, reasoning: 0, requestID: "01a165ad",
		})
		ttft := map[int64]bool{}
		for _, tr := range res.Turns {
			ttft[tr.TimeToFirstTokenMS] = true
			if tr.DurationMS <= 0 {
				t.Errorf("codebuddy turn %s has no duration", tr.RequestID)
			}
		}
		if !ttft[39] || !ttft[16] {
			t.Errorf("codebuddy time to first token = %v, want 39 and 16", ttft)
		}
		names := map[string]string{}
		for _, tc := range res.Tools {
			if !tc.SuccessKnown || !tc.Success || tc.SessionID != "01a165ad-1a86-7973-8bb9-a42e9af357ad" {
				t.Errorf("codebuddy tool %+v", tc)
			}
			names[tc.CallID] = tc.Name
		}
		if len(res.Tools) != 3 || names["call_mock1"] != "Read" || names["call_mock2"] != "Bash" || names["call_mock3"] != "Write" {
			t.Errorf("codebuddy tool calls: %+v", res.Tools)
		}
		// AP-131 follow-up: each model_stream span also yields the call's
		// end-to-end generation duration keyed by request.id (the
		// transcript's messageId): span end minus the first_token_received
		// event, plus that event's ttft_ms (14.234 + 39 and 4.263 + 16).
		checkGenTimings(t, res, map[string]int64{
			"01a165ad1cf775ed99158878cfa4ee77": 53,
			"01a165ad1ed87934a1734acbac73157b": 20,
		}, "01a165ad-1a86-7973-8bb9-a42e9af357ad")
	})
	t.Run("codebuddy/default-semconv", func(t *testing.T) {
		var req coltracepb.ExportTraceServiceRequest
		loadFixture(t, "codebuddy", "traces-default-semconv.json", true, &req)
		res := ParseSpans(&req)
		// The default semconv puts usage only in events of the interaction
		// span: no turns. Its codebuddy_code.tool spans still map, the
		// session read from their agent.tool.* events.
		if len(res.Turns) != 0 || len(res.Unclaimed) != 0 {
			t.Errorf("default semconv: turns=%d unclaimed=%v", len(res.Turns), res.Unclaimed)
		}
		names := map[string]string{}
		for _, tc := range res.Tools {
			if !tc.SuccessKnown || !tc.Success || tc.SessionID != "01a165ac-f1b6-776f-b094-7e94318ef62a" || tc.DurationMS <= 0 {
				t.Errorf("default-semconv codebuddy tool %+v", tc)
			}
			names[tc.CallID] = tc.Name
		}
		if len(res.Tools) != 3 || names["call_mock1"] != "Read" || names["call_mock2"] != "Bash" || names["call_mock3"] != "Write" {
			t.Errorf("default-semconv codebuddy tool calls: %+v", res.Tools)
		}
		// No session on the default-semconv model_stream span: no timing
		// (the join is proven only for the agentlens capture).
		checkGenTimings(t, res, nil, "")
	})
	t.Run("kimchi", func(t *testing.T) {
		var req collogspb.ExportLogsServiceRequest
		loadFixture(t, "kimchi", "logs.json", true, &req)
		res := ParseLogs(&req)
		// input_tokens is already NET of cache reads; output holds the
		// reasoning (no reasoning count on the wire).
		checkTurns(t, res, "kimchi", wantTurn{
			n: 2, session: "01a165b1-cd10-71bf-97ff-2e5a1ebfdeac", model: "mock-model",
			input: 234, output: 56, cacheRead: 1000, reasoning: 0, requestID: "otel:",
		})
		for _, tr := range res.Turns {
			if tr.CostUSD != 0.000446 || tr.Provider != "mock" {
				t.Errorf("kimchi turn cost=%v provider=%q", tr.CostUSD, tr.Provider)
			}
		}
		if len(res.Tools) != 3 {
			t.Fatalf("kimchi tool calls: %+v", res.Tools)
		}
		for _, tc := range res.Tools {
			if !tc.SuccessKnown || !tc.Success || tc.DurationMS <= 0 || !strings.HasPrefix(tc.CallID, "otel:kimchi:") {
				t.Errorf("kimchi tool %+v", tc)
			}
		}
		// Regression: kimchi reuses Claude Code's bare event names. Before
		// the kimchi row claimed its resource, the Claude Code row read it
		// and stored each tool_result / tool_decision event NAME as content.
		checkGenTimings(t, res, nil, "") // no per-call id; native timing already on the transcript
		if len(res.Contents) != 0 || res.Skipped != 0 {
			t.Errorf("kimchi export misread: %d contents, %d skipped api_request", len(res.Contents), res.Skipped)
		}
	})
}

func contentKinds(res Result) map[string]int {
	m := map[string]int{}
	for _, c := range res.Contents {
		m[c.Kind]++
	}
	return m
}
