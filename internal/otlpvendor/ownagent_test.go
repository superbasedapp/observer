package otlpvendor

import (
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/ownagent"
)

// resSpans builds a one-resource trace export with the given resource
// attributes.
func resSpans(res []*commonpb.KeyValue, spans ...*tracepb.Span) *coltracepb.ExportTraceServiceRequest {
	return &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource:   &resourcepb.Resource{Attributes: res},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: spans}},
	}}}
}

// agentChat is a GenAI chat span as the stock instrumentors emit it.
func agentChat(id byte, extra ...any) *tracepb.Span {
	pairs := append([]any{
		"gen_ai.operation.name", s("chat"), "gen_ai.system", s("openai"),
		"gen_ai.request.model", s("gpt-5.5-mini"), "gen_ai.response.model", s("gpt-5.5-mini"),
		"gen_ai.response.id", s("chatcmpl-x"),
		"gen_ai.usage.input_tokens", i(1234), "gen_ai.usage.output_tokens", i(56),
	}, extra...)
	return span("chat gpt-5.5-mini", id, kvs(pairs...))
}

// TestOwnAgentLiveFixture maps the export captured from the stock
// OpenTelemetry Python SDK with opentelemetry-instrumentation-openai-v2
// 2.3b0 against the local mock (testdata/otlp/README.md). The instrumentor
// reports input GROSS of the 1000 cached tokens and sends no cache
// attribute, so the self-reported turn honestly carries input 1234 with no
// cache split; the session is the proxy path's id for (fixture-bot, run-1).
func TestOwnAgentLiveFixture(t *testing.T) {
	var req coltracepb.ExportTraceServiceRequest
	loadFixture(t, "custom-agent", "traces.json", false, &req)
	if c := ClaimTraceResource(req.GetResourceSpans()[0]); c.Plane != ownagent.OTLPOwnAgent || c.Agent != "fixture-bot" {
		t.Fatalf("claim = %+v, want own-agent fixture-bot", c)
	}
	res := ParseSpans(&req)
	session := ownagent.SessionID("fixture-bot", "run-1")
	if len(res.Turns) != 2 {
		t.Fatalf("turns = %+v, want 2", res.Turns)
	}
	for n, tr := range res.Turns {
		want := []string{"chatcmpl-mock-1", "chatcmpl-mock-2"}[n]
		if tr.Tool != models.ToolCustomAgent || tr.Agent != "fixture-bot" || tr.SessionID != session ||
			tr.RequestID != want || tr.RequestSynthetic || tr.Model != "gpt-5.5-mini-2026-10-01" ||
			tr.Provider != "openai" || tr.SourceTag != SourceAgentOTel {
			t.Errorf("turn %d identity = %+v", n, tr)
		}
		if tr.InputTokens != 1234 || tr.OutputTokens != 56 || tr.CacheReadTokens != 0 || tr.ReasoningTokens != 0 {
			t.Errorf("turn %d tokens in=%d out=%d cr=%d reason=%d, want the instrumentor's own 1234 / 56 / 0 / 0",
				n, tr.InputTokens, tr.OutputTokens, tr.CacheReadTokens, tr.ReasoningTokens)
		}
		if tr.DurationMS < 0 || tr.Timestamp.IsZero() {
			t.Errorf("turn %d timing = %+v", n, tr)
		}
	}
	if len(res.Tools) != 1 || res.Tools[0].Name != "list_files" || res.Tools[0].CallID != "call_fixture_1" ||
		res.Tools[0].SessionID != session || res.Tools[0].Agent != "fixture-bot" {
		t.Errorf("tool calls = %+v", res.Tools)
	}
	if len(res.Contents) != 0 {
		t.Errorf("content without the instrumentor's content capture: %+v", res.Contents)
	}
	if len(res.Unclaimed) != 0 {
		t.Errorf("an own-agent resource reported as unclaimed: %v", res.Unclaimed)
	}
}

// TestOwnAgentResourceClaim runs the claim table's rows on real export
// shapes: the decision each makes, and that ParseSpans reads exactly the
// claimed resources with the claimed row.
func TestOwnAgentResourceClaim(t *testing.T) {
	for _, tc := range []struct {
		name      string
		res       []*commonpb.KeyValue
		spans     []*tracepb.Span
		wantPlane ownagent.OTLPPlane
		wantTool  string // tool of the mapped turn, "" for no turn
	}{
		{
			name:      "echo",
			res:       kvs("sbo.emitted_by", s("observer"), "sbo.agent", s("bot")),
			spans:     []*tracepb.Span{agentChat(1)},
			wantPlane: ownagent.OTLPUnclaimed,
		},
		{
			name:      "coding tool service.name wins over sbo.agent",
			res:       kvs("service.name", s("github-copilot"), "sbo.agent", s("bot"), "gen_ai.conversation.id", s("c1")),
			spans:     []*tracepb.Span{agentChat(1)},
			wantPlane: ownagent.OTLPCodingTool, wantTool: "copilot-cli",
		},
		{
			name:      "hosted app on the resource stays Plane A",
			res:       kvs("service.name", s("support-app"), "sbo.agent", s("bot"), "sbo.tenant", s("acme")),
			spans:     []*tracepb.Span{agentChat(1)},
			wantPlane: ownagent.OTLPUnclaimed,
		},
		{
			name:      "hosted end user on one span keeps the whole resource Plane A",
			res:       kvs("service.name", s("support-app"), "sbo.agent", s("bot")),
			spans:     []*tracepb.Span{agentChat(1), agentChat(2, "enduser.id", s("u-42"))},
			wantPlane: ownagent.OTLPUnclaimed,
		},
		{
			name:      "Plane A's generic user.id on one span keeps the resource Plane A",
			res:       kvs("service.name", s("support-app"), "sbo.agent", s("bot")),
			spans:     []*tracepb.Span{agentChat(1, "user.id", s("u-7"))},
			wantPlane: ownagent.OTLPUnclaimed,
		},
		{
			name:      "Plane A's generic tenant on the resource keeps it Plane A",
			res:       kvs("service.name", s("support-app"), "sbo.agent", s("bot"), "tenant", s("acme")),
			spans:     []*tracepb.Span{agentChat(1)},
			wantPlane: ownagent.OTLPUnclaimed,
		},
		{
			name:      "own agent",
			res:       kvs("service.name", s("my-agent"), "sbo.agent", s("Bot"), "session.id", s("run-1")),
			spans:     []*tracepb.Span{agentChat(1)},
			wantPlane: ownagent.OTLPOwnAgent, wantTool: models.ToolCustomAgent,
		},
		{
			name:      "malformed agent name",
			res:       kvs("service.name", s("my-agent"), "sbo.agent", s("***")),
			spans:     []*tracepb.Span{agentChat(1)},
			wantPlane: ownagent.OTLPDropped,
		},
		{
			name:      "plain app",
			res:       kvs("service.name", s("my-llm-app")),
			spans:     []*tracepb.Span{agentChat(1)},
			wantPlane: ownagent.OTLPUnclaimed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := resSpans(tc.res, tc.spans...)
			if got := ClaimTraceResource(req.GetResourceSpans()[0]); got.Plane != tc.wantPlane {
				t.Fatalf("plane = %s (rule %s), want %s", got.Plane, got.Rule, tc.wantPlane)
			}
			res := ParseSpans(req)
			if tc.wantTool == "" {
				if len(res.Turns) != 0 || len(res.Tools) != 0 {
					t.Fatalf("a resource no Plane B row claims was mapped: %+v", res)
				}
				return
			}
			if len(res.Turns) != 1 || res.Turns[0].Tool != tc.wantTool {
				t.Fatalf("turns = %+v, want one %s turn", res.Turns, tc.wantTool)
			}
			if tc.wantTool == models.ToolCustomAgent {
				if res.Turns[0].Agent != "bot" || res.Turns[0].SessionID != ownagent.SessionID("bot", "run-1") {
					t.Fatalf("own-agent turn identity = %+v", res.Turns[0])
				}
			} else if res.Turns[0].Agent != "" {
				t.Fatalf("a coding tool's turn carries an agent name: %+v", res.Turns[0])
			}
		})
	}
}

// TestOwnAgentTokenHonesty: a span without any usage attribute yields no
// turn (never a zero-token guess), every inference operation with usage
// yields one, an invoke_agent span (per-run sums) yields none, the GenAI
// semconv cache split is netted, and a span with no session takes its trace
// as the session.
func TestOwnAgentTokenHonesty(t *testing.T) {
	agentRes := kvs("service.name", s("my-agent"), "sbo.agent", s("bot"))
	noUsage := span("chat gpt-5.5", 1, kvs("gen_ai.operation.name", s("chat"), "gen_ai.request.model", s("gpt-5.5"), "gen_ai.response.id", s("r1")))
	if r := ParseSpans(resSpans(agentRes, noUsage)); len(r.Turns) != 0 {
		t.Fatalf("a span without usage became a turn: %+v", r.Turns)
	}
	invoke := span("invoke_agent bot", 2, kvs("gen_ai.operation.name", s("invoke_agent"), "gen_ai.usage.input_tokens", i(9000)))
	if r := ParseSpans(resSpans(agentRes, invoke)); len(r.Turns) != 0 {
		t.Fatalf("an invoke_agent sum became a turn: %+v", r.Turns)
	}
	for n, op := range agentInferenceOps {
		sp := span(op+" m", byte(10+n), kvs("gen_ai.operation.name", s(op), "gen_ai.request.model", s("m"), "gen_ai.usage.output_tokens", i(7)))
		r := ParseSpans(resSpans(agentRes, sp))
		if len(r.Turns) != 1 || r.Turns[0].OutputTokens != 7 || r.Turns[0].InputTokens != 0 {
			t.Errorf("%s: turns = %+v, want one with output 7", op, r.Turns)
		}
	}
	// Semconv input includes cache read and write: netted to the proxy-row
	// convention.
	split := agentChat(3, "gen_ai.usage.cache_read.input_tokens", i(1000), "gen_ai.usage.cache_creation.input_tokens", i(34))
	r := ParseSpans(resSpans(agentRes, split))
	if len(r.Turns) != 1 || r.Turns[0].InputTokens != 200 || r.Turns[0].CacheReadTokens != 1000 || r.Turns[0].CacheWriteTokens != 34 {
		t.Fatalf("semconv split = %+v, want net input 200, cache 1000 / 34", r.Turns)
	}
	// No session on the resource or span: the trace is the session.
	sp := agentChat(4)
	sp.TraceId = []byte{0xab, 0xcd, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}
	r = ParseSpans(resSpans(agentRes, sp))
	want := ownagent.SessionID("bot", "trace:abcd0102030405060708090a0b0c0d0e")
	if len(r.Turns) != 1 || r.Turns[0].SessionID != want {
		t.Fatalf("trace session = %+v, want %s", r.Turns, want)
	}
	// Neither a session nor a trace id: nothing lands.
	bare := agentChat(5)
	bare.TraceId = nil
	if r := ParseSpans(resSpans(agentRes, bare)); len(r.Turns) != 0 {
		t.Fatalf("a session-less own-agent span landed: %+v", r.Turns)
	}
	// A skipped span never stamps its duration on the record before it.
	first := agentChat(6, "gen_ai.response.id", s("r-first"))
	bare.EndTimeUnixNano = bare.StartTimeUnixNano + 9_000_000_000
	r = ParseSpans(resSpans(agentRes, first, bare))
	if len(r.Turns) != 1 || r.Turns[0].DurationMS != 1500 {
		t.Fatalf("skipped span changed the previous turn: %+v", r.Turns)
	}
}

// TestOwnAgentLogsResource (fix round 1, L5): a resource that carries
// sbo.agent (well formed or not) under a service.name no row claims keeps
// the pre-phase-2 log reading: the Claude Code event-name row still maps a
// claude_code.* event in it (a renamed OTEL_SERVICE_NAME that inherited an
// sbo.agent from the process that started Claude Code must not lose its
// turns), as Claude Code's turn, never as the agent's. The own-agent row maps
// no logs.
func TestOwnAgentLogsResource(t *testing.T) {
	rec := &logspb.LogRecord{EventName: "claude_code.api_request", Attributes: kvs("request_id", s("req_x"), "input_tokens", i(3))}
	other := &logspb.LogRecord{EventName: "my_agent.step", Attributes: kvs("gen_ai.usage.input_tokens", i(3))}
	for _, name := range []string{"bot", "***"} {
		req := &collogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
			Resource:  &resourcepb.Resource{Attributes: kvs("service.name", s("my-agent"), "sbo.agent", s(name))},
			ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{rec, other}}},
		}}}
		r := ParseLogs(req)
		if len(r.Turns) != 1 || r.Turns[0].Tool != "claude-code" || r.Turns[0].Agent != "" || r.Turns[0].RequestID != "req_x" {
			t.Errorf("sbo.agent=%q logs: turns %+v, want only Claude Code's own turn", name, r.Turns)
		}
		if len(r.Unclaimed) != 0 || len(r.Tools) != 0 || len(r.Contents) != 0 {
			t.Errorf("sbo.agent=%q logs: %+v", name, r)
		}
	}
}

// TestEventNameRowsMapLogsOnly: the rows that read every resource no
// service.name row claims (ClaimByEventName) map logs only, so they can
// never read an own agent's (or a hosted app's) spans.
func TestEventNameRowsMapLogsOnly(t *testing.T) {
	for _, v := range Vendors() {
		if !v.ClaimByEventName {
			continue
		}
		for _, r := range v.Rules {
			if r.Signal != SignalLogs {
				t.Errorf("%s: an event-name row maps a non-log signal", v.Tool)
			}
		}
	}
}

// TestOneAgentClaimRow: exactly one row claims by agent, it is the
// custom-agent row, it is adapter-gated, user grain, and merges with the
// proxy by request id.
func TestOneAgentClaimRow(t *testing.T) {
	var rows []Vendor
	for _, v := range Vendors() {
		if v.ClaimByAgent {
			rows = append(rows, v)
		}
		if v.AdapterGated && !v.ClaimByAgent {
			t.Errorf("%s: adapter-gated without the agent claim", v.Tool)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("%d agent-claim rows, want 1", len(rows))
	}
	v := rows[0]
	if v.Tool != models.ToolCustomAgent || !v.AdapterGated || v.Grain != GrainUser || !v.Owner.TokensMergeWithProxy ||
		v.NoSessionRows || len(v.ServiceNames)+len(v.ServiceNamePrefixes) != 0 || v.ClaimByEventName {
		t.Fatalf("agent row = %+v", v)
	}
}

// TestAdmitAdapterGated is one case per admission row an adapter-gated
// vendor can reach.
func TestAdmitAdapterGated(t *testing.T) {
	v, _ := ForTool(models.ToolCustomAgent)
	for _, tc := range []struct {
		name             string
		enabled, proxied bool
		want             Admission
	}{
		{"adapter off: nothing lands", false, false, Admission{Refused: RefusedCaptureOff}},
		{"adapter off, proxied: nothing lands", false, true, Admission{Refused: RefusedCaptureOff}},
		{"adapter on: the export owns every kind", true, false, Admission{Tokens: true, Tools: true, Content: true}},
		{"adapter on, proxied: tokens merge with the proxy row", true, true, Admission{Tokens: true, Tools: true, Content: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := AdmitWith(v, AdmitInput{TranscriptCapture: tc.enabled, ProxyRouted: tc.proxied}); got != tc.want {
				t.Fatalf("AdmitWith = %+v, want %+v", got, tc.want)
			}
		})
	}
}
