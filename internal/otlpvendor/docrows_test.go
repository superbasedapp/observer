package otlpvendor

import (
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// The rows below are grounded on vendor documentation or source, not on a
// live capture (no local install, or the install needs an account). Each
// fixture is built from the vendor's documented attribute names and is
// labelled with its source; a live capture that disagrees must change the
// row AND this fixture.

func s(v string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}
}

func i(v int64) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: v}}
}

func b(v bool) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: v}}
}

func kvs(pairs ...any) []*commonpb.KeyValue {
	var out []*commonpb.KeyValue
	for n := 0; n+1 < len(pairs); n += 2 {
		out = append(out, &commonpb.KeyValue{Key: pairs[n].(string), Value: pairs[n+1].(*commonpb.AnyValue)})
	}
	return out
}

func logsExport(service string, recs ...*logspb.LogRecord) *collogspb.ExportLogsServiceRequest {
	var res []*commonpb.KeyValue
	if service != "" {
		res = kvs("service.name", s(service))
	}
	return &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource:  &resourcepb.Resource{Attributes: res},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: recs}},
	}}}
}

func spansExport(service string, spans ...*tracepb.Span) *coltracepb.ExportTraceServiceRequest {
	return &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource:   &resourcepb.Resource{Attributes: kvs("service.name", s(service))},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: spans}},
	}}}
}

func span(name string, id byte, attrs []*commonpb.KeyValue) *tracepb.Span {
	return &tracepb.Span{
		Name: name, SpanId: []byte{id, 1, 2, 3, 4, 5, 6, 7}, TraceId: make([]byte, 16),
		StartTimeUnixNano: 1_790_000_000_000_000_000, EndTimeUnixNano: 1_790_000_001_500_000_000,
		Attributes: attrs,
	}
}

// TestDocRows pins every documentation-grounded row's mapping.
func TestDocRows(t *testing.T) {
	genaiChat := func(conv string) []*commonpb.KeyValue {
		return kvs("gen_ai.operation.name", s("chat"), "gen_ai.conversation.id", s(conv),
			"gen_ai.request.model", s("gpt-5.5"), "gen_ai.response.model", s("gpt-5.5"), "gen_ai.response.id", s("resp-1"),
			"gen_ai.usage.input_tokens", i(1500), "gen_ai.usage.output_tokens", i(80),
			"gen_ai.usage.cache_read.input_tokens", i(1000), "gen_ai.usage.cache_creation.input_tokens", i(200),
			"gen_ai.usage.reasoning.output_tokens", i(20))
	}
	genaiTool := func(conv string) []*commonpb.KeyValue {
		return kvs("gen_ai.operation.name", s("execute_tool"), "gen_ai.conversation.id", s(conv),
			"gen_ai.tool.name", s("readFile"), "gen_ai.tool.call.id", s("call-1"), "error.type", s("failure"))
	}
	for _, tc := range []struct {
		name   string
		tool   string
		res    Result
		turn   Turn
		nTools int
	}{
		{
			// code.visualstudio.com monitoring-agents: GenAI chat span; input
			// GROSS of cache read and write (semconv), output gross.
			name: "copilot (VS Code)", tool: "copilot",
			res:    ParseSpans(spansExport("copilot-chat", span("chat gpt-5.5", 1, genaiChat("conv-vs")), span("execute_tool readFile", 2, genaiTool("conv-vs")))),
			turn:   Turn{SessionID: "conv-vs", Model: "gpt-5.5", RequestID: "resp-1", InputTokens: 300, OutputTokens: 80, CacheReadTokens: 1000, CacheWriteTokens: 200, ReasoningTokens: 20, DurationMS: 1500},
			nTools: 1,
		},
		{
			// goose reply_parts.rs: stream_response_from_provider, gen_ai.*.
			name: "goose", tool: "goose",
			res: ParseSpans(spansExport("goose", span("stream_response_from_provider", 1, kvs(
				"gen_ai.operation.name", s("chat"), "gen_ai.conversation.id", s("20261006_1"), "session.id", s("20261006_1"),
				"gen_ai.request.model", s("claude-sonnet-5"), "gen_ai.response.id", s("msg_1"),
				"gen_ai.usage.input_tokens", i(1300), "gen_ai.usage.output_tokens", i(40),
				"gen_ai.usage.cache_read.input_tokens", i(1000), "gen_ai.usage.cache_creation.input_tokens", i(100))),
				span("execute_tool developer__shell", 2, kvs("gen_ai.operation.name", s("execute_tool"), "session.id", s("20261006_1"),
					"gen_ai.tool.name", s("developer__shell"), "gen_ai.tool.call.id", s("toolu_1"))))),
			turn:   Turn{SessionID: "20261006_1", Model: "claude-sonnet-5", RequestID: "msg_1", InputTokens: 200, OutputTokens: 40, CacheReadTokens: 1000, CacheWriteTokens: 100, DurationMS: 1500},
			nTools: 1,
		},
		{
			// vercel/ai 6.0.168 stream-text.ts doStream span, opencode llm.ts.
			name: "opencode", tool: "opencode",
			res: ParseSpans(spansExport("opencode", span("ai.streamText.doStream", 1, kvs(
				"session.id", s("ses_abc"), "ai.model.id", s("claude-sonnet-5"), "ai.response.model", s("claude-sonnet-5"), "ai.response.id", s("msg_2"),
				"ai.usage.inputTokens", i(1100), "ai.usage.outputTokens", i(30),
				"ai.usage.inputTokenDetails.cacheReadTokens", i(1000), "ai.usage.inputTokenDetails.cacheWriteTokens", i(50))),
				span("ai.toolCall", 2, kvs("session.id", s("ses_abc"), "ai.toolCall.name", s("bash"), "ai.toolCall.id", s("toolu_2"))))),
			turn:   Turn{SessionID: "ses_abc", Model: "claude-sonnet-5", RequestID: "msg_2", InputTokens: 50, OutputTokens: 30, CacheReadTokens: 1000, CacheWriteTokens: 50, DurationMS: 1500},
			nTools: 1,
		},
		{
			// xai-org/grok-build 24-monitoring-usage.md grok_code.api_request.
			name: "grok", tool: "grok",
			res: ParseLogs(logsExport("grok-cli",
				&logspb.LogRecord{TimeUnixNano: 1_790_000_000_000_000_000, Attributes: kvs("event.name", s("grok_code.api_request"), "session.id", s("g-1"),
					"model", s("grok-5"), "input_tokens", i(900), "output_tokens", i(60), "reasoning_tokens", i(10), "cache_read_tokens", i(800), "duration_ms", i(700))},
				&logspb.LogRecord{TimeUnixNano: 1_790_000_000_100_000_000, Attributes: kvs("event.name", s("grok_code.tool_result"), "session.id", s("g-1"),
					"tool_name", s("bash"), "tool_use_id", s("tu-1"), "success", b(true), "duration_ms", i(20))})),
			turn:   Turn{SessionID: "g-1", Model: "grok-5", InputTokens: 100, OutputTokens: 60, CacheReadTokens: 800, ReasoningTokens: 10, DurationMS: 700},
			nTools: 1,
		},
		{
			// zai-org/ZCode agent-trace-runtime.ts model_attempt span.
			name: "zcode", tool: "zcode",
			res: ParseSpans(spansExport("zcode-cli-agent", span("model_attempt", 1, kvs(
				"zcode.execution.session_id", s("zs-1"), "zcode.model_attempt.response_model", s("glm-5"),
				"zcode.model_attempt.input_tokens", i(700), "zcode.model_attempt.output_tokens", i(25),
				"zcode.model_attempt.cache_read_tokens", i(500), "zcode.model_attempt.reasoning_tokens", i(5))))),
			turn: Turn{SessionID: "zs-1", Model: "glm-5", InputTokens: 200, OutputTokens: 25, CacheReadTokens: 500, ReasoningTokens: 5, DurationMS: 1500},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.res.Turns) != 1 {
				t.Fatalf("turns = %+v", tc.res.Turns)
			}
			got := tc.res.Turns[0]
			want := tc.turn
			if got.Tool != tc.tool || got.SessionID != want.SessionID || got.Model != want.Model ||
				got.InputTokens != want.InputTokens || got.OutputTokens != want.OutputTokens ||
				got.CacheReadTokens != want.CacheReadTokens || got.CacheWriteTokens != want.CacheWriteTokens ||
				got.ReasoningTokens != want.ReasoningTokens || got.DurationMS != want.DurationMS {
				t.Errorf("turn = %+v\nwant  %+v", got, want)
			}
			if want.RequestID != "" && got.RequestID != want.RequestID {
				t.Errorf("request id %q, want %q", got.RequestID, want.RequestID)
			}
			if len(tc.res.Tools) != tc.nTools {
				t.Errorf("tools = %+v, want %d", tc.res.Tools, tc.nTools)
			}
		})
	}
}

// TestTeamGrainRowsParseButAreRefused pins the Cursor and Cowork rows: they
// map (so the org side can reuse them and the resource is never read by
// another row) and Admit refuses them on a node whatever the transcript
// state.
func TestTeamGrainRowsParseButAreRefused(t *testing.T) {
	// cursor.com/docs/enterprise/opentelemetry-export: cursor.api.request.
	cursor := ParseLogs(logsExport("cursor", &logspb.LogRecord{
		TimeUnixNano: 1_790_000_000_000_000_000,
		Attributes: kvs("event.name", s("cursor.api.request"), "cursor.conversation.id", s("bc-123"), "cursor.event.id", s("ev-1"),
			"cursor.model.name", s("Auto"), "cursor.api.request.input_tokens", i(500), "cursor.api.request.output_tokens", i(70),
			"cursor.api.request.cache_read_tokens", i(400), "cursor.api.request.cache_creation_tokens", i(10)),
	}))
	if len(cursor.Turns) != 1 || cursor.Turns[0].Tool != "cursor" || cursor.Turns[0].SessionID != "bc-123" || cursor.Turns[0].InputTokens != 500 {
		t.Fatalf("cursor turn = %+v", cursor.Turns)
	}
	// claude.com/docs/cowork/monitoring.md: unprefixed api_request under
	// service.name cowork must land as cowork, never as Claude Code.
	cowork := ParseLogs(logsExport("cowork", &logspb.LogRecord{
		Attributes: kvs("event.name", s("api_request"), "request_id", s("req_cw"), "session.id", s("cw-1"), "input_tokens", i(5)),
	}))
	if len(cowork.Turns) != 1 || cowork.Turns[0].Tool != "cowork" {
		t.Fatalf("cowork turn = %+v", cowork.Turns)
	}
	for _, tool := range []string{"cursor", "cowork"} {
		v, ok := ForTool(tool)
		if !ok {
			t.Fatalf("no row for %s", tool)
		}
		for _, transcript := range []bool{true, false} {
			if a := Admit(v, transcript); a.Refused == "" || a.Tokens || a.Tools || a.Content || a.Timing {
				t.Errorf("%s transcript=%v admitted: %+v", tool, transcript, a)
			}
		}
	}
}

// TestAdmitTable is one case per admission-table row.
func TestAdmitTable(t *testing.T) {
	codex, _ := ForTool("codex")
	copilot, _ := ForTool("copilot")
	cc, _ := ForTool("claude-code")
	cursor, _ := ForTool("cursor")
	codebuddy, _ := ForTool("codebuddy")
	for _, tc := range []struct {
		name       string
		v          Vendor
		transcript bool
		proxied    bool
		want       Admission
	}{
		{"team grain refused, even proxied", cursor, false, true, Admission{Refused: RefusedTeamGrain}},
		{"transcript off: export owns every kind", copilot, false, false, Admission{Tokens: true, Tools: true, Content: true}},
		{"transcript on, twin-safe tokens", codex, true, false, Admission{Tokens: true}},
		{"transcript on, not twin-safe", copilot, true, false, Admission{}},
		{"claude code keeps its pre-T-475 posture", cc, true, false, Admission{Tokens: true, Content: true}},
		// T-536: the proxy owns tokens; the export keeps what the proxy
		// cannot see.
		{"proxied, transcript off: tools and content only", codex, false, true, Admission{Tools: true, Content: true, TokensOwner: TokensOwnedByProxy}},
		{"proxied, transcript on: tokens dropped", codex, true, true, Admission{TokensOwner: TokensOwnedByProxy}},
		{"proxied claude code merges by request id", cc, true, true, Admission{Tokens: true, Content: true}},
		// AP-131 follow-up: a row declaring a transcript timing join stamps
		// the transcript's rows while that transcript captures; the proxy
		// route does not change it (a stamp adds no row).
		{"transcript on, timing join declared", codebuddy, true, false, Admission{Timing: true}},
		{"transcript off: the export turn carries its own duration", codebuddy, false, false, Admission{Tokens: true, Tools: true, Content: true}},
		{"proxied, transcript on: timing still stamps", codebuddy, true, true, Admission{Timing: true, TokensOwner: TokensOwnedByProxy}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := AdmitWith(tc.v, AdmitInput{TranscriptCapture: tc.transcript, ProxyRouted: tc.proxied}); got != tc.want {
				t.Errorf("AdmitWith = %+v, want %+v", got, tc.want)
			}
			if !tc.proxied {
				if got := Admit(tc.v, tc.transcript); got != tc.want {
					t.Errorf("Admit = %+v, want %+v", got, tc.want)
				}
			}
		})
	}
}

// TestRouteMarkerOnResource pins the launcher marker: a turn from a resource
// carrying sbo.route=proxy is flagged ViaProxyRoute, one without it is not.
func TestRouteMarkerOnResource(t *testing.T) {
	rec := func() *logspb.LogRecord {
		return &logspb.LogRecord{Attributes: kvs("event.name", s("codex.sse_event"), "event.kind", s("response.completed"),
			"input_token_count", s("5"), "output_token_count", s("2"), "conversation.id", s("c1"))}
	}
	plain := ParseLogs(logsExport("codex_exec", rec()))
	marked := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource:  &resourcepb.Resource{Attributes: kvs("service.name", s("codex_exec"), RouteResourceAttr, s(RouteProxy), RouteToolResourceAttr, s("codex"))},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{rec()}}},
	}}}
	got := ParseLogs(marked)
	// P3-36: the marker a parent launch scoped to another tool (inherited
	// through the environment by a nested tool) does not make this tool's
	// turns proxied, and neither does an unscoped marker.
	for _, attrs := range [][]*commonpb.KeyValue{
		kvs("service.name", s("codex_exec"), RouteResourceAttr, s(RouteProxy), RouteToolResourceAttr, s("gemini-cli")),
		kvs("service.name", s("codex_exec"), RouteResourceAttr, s(RouteProxy)),
	} {
		inherited := ParseLogs(&collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
			Resource:  &resourcepb.Resource{Attributes: attrs},
			ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{rec()}}},
		}}})
		if len(inherited.Turns) != 1 || inherited.Turns[0].ViaProxyRoute {
			t.Fatalf("a marker not scoped to codex made its turn proxied: %+v", inherited.Turns)
		}
	}
	if len(plain.Turns) != 1 || plain.Turns[0].ViaProxyRoute {
		t.Fatalf("unmarked turn = %+v, want one turn not via the proxy", plain.Turns)
	}
	if len(got.Turns) != 1 || !got.Turns[0].ViaProxyRoute {
		t.Fatalf("marked turn = %+v, want one turn via the proxy", got.Turns)
	}
}

// TestClaimAndEcho covers resource claiming: an unmapped service.name is
// reported, an Observer-emitted resource is never read, and a resource no
// row claims is still read by the Claude Code row (its original parser read
// every resource).
func TestClaimAndEcho(t *testing.T) {
	unmapped := ParseLogs(logsExport("some-other-agent", &logspb.LogRecord{Attributes: kvs("event.name", s("x"))}))
	if len(unmapped.Unclaimed) != 1 || unmapped.Unclaimed[0] != "some-other-agent" {
		t.Errorf("unclaimed = %v", unmapped.Unclaimed)
	}
	echo := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resourcepb.Resource{Attributes: kvs("service.name", s("codex_exec"), "sbo.emitted_by", s("observer"))},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{Attributes: kvs("event.name", s("codex.sse_event"),
			"event.kind", s("response.completed"), "input_token_count", s("5"), "conversation.id", s("c"))}}}},
	}}}
	if r := ParseLogs(echo); len(r.Turns) != 0 {
		t.Errorf("echo guard failed: %+v", r.Turns)
	}
	ccNoService := ParseLogs(logsExport("my-renamed-service", &logspb.LogRecord{
		EventName: "claude_code.api_request", Attributes: kvs("request_id", s("req_x"), "input_tokens", i(3)),
	}))
	if len(ccNoService.Turns) != 1 || ccNoService.Turns[0].Tool != "claude-code" || len(ccNoService.Unclaimed) != 0 {
		t.Errorf("claude code on an unclaimed resource: %+v unclaimed=%v", ccNoService.Turns, ccNoService.Unclaimed)
	}
	for svc, want := range map[string]bool{"github-copilot": true, "my-llm-app": false, "": false} {
		if _, got := claim(svc); got != want {
			t.Errorf("claim(%q) = %v, want %v", svc, got, want)
		}
	}
}
