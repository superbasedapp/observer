package otlpvendor

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/otelident"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

// The claude-code row tests. They were the internal/adapter/ccotel tests,
// which pinned the original Claude Code parser's behaviour when it moved
// onto this table (T-475); ccotel was a test-only wrapper filtering
// ParseLogs to claude-code and is gone, so the cases read the row directly.
// Every export here carries no service.name: the row claims Claude Code's
// records by event name.

func ccDbl(f float64) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: f}}
}

func ccKV(k string, v *commonpb.AnyValue) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: v}
}

// ccExport wraps one resource (with attrs) holding the given records.
func ccExport(resAttrs []*commonpb.KeyValue, recs ...*logspb.LogRecord) *collogspb.ExportLogsServiceRequest {
	return &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource:  &resourcepb.Resource{Attributes: resAttrs},
			ScopeLogs: []*logspb.ScopeLogs{{LogRecords: recs}},
		}},
	}
}

// ccTurns is the claude-code view of ParseLogs: its turns, plus the export's
// skipped count.
func ccTurns(req *collogspb.ExportLogsServiceRequest) ([]Turn, int) {
	res := ParseLogs(req)
	var out []Turn
	for _, t := range res.Turns {
		if t.Tool == models.ToolClaudeCode {
			out = append(out, t)
		}
	}
	return out, res.Skipped
}

// ccContents is the claude-code view of ParseLogs' content records.
func ccContents(req *collogspb.ExportLogsServiceRequest) []Content {
	var out []Content
	for _, c := range ParseLogs(req).Contents {
		if c.Tool == models.ToolClaudeCode {
			out = append(out, c)
		}
	}
	return out
}

func TestClaudeCodeRowSourceTag(t *testing.T) {
	v, ok := ForTool(models.ToolClaudeCode)
	if !ok {
		t.Fatal("no claude-code row")
	}
	// The store maps "cc_otel" to the native-exact fidelity; the equality
	// with store.SourceCCOTel is pinned in cmd/observer (this package may
	// not import the store).
	if v.SourceTag != sourceCCOTel || sourceCCOTel != "cc_otel" {
		t.Fatalf("claude-code row source tag = %q (sourceCCOTel %q), want cc_otel", v.SourceTag, sourceCCOTel)
	}
}

func TestClaudeCodeAPIRequestEvent(t *testing.T) {
	rec := &logspb.LogRecord{
		EventName:    "claude_code.api_request",
		TimeUnixNano: 1_700_000_000_000_000_000,
		Attributes: []*commonpb.KeyValue{
			ccKV("request_id", s("req_abc")),
			ccKV("model", s("claude-opus-4-8")),
			ccKV("input_tokens", i(1000)),
			ccKV("output_tokens", i(200)),
			ccKV("cache_read_tokens", i(50)),
			ccKV("cache_creation_tokens", i(10)),
			ccKV("cost_usd", ccDbl(0.42)),
			ccKV("duration_ms", i(1500)),
		},
	}
	res := []*commonpb.KeyValue{ccKV("session.id", s("sess-1"))}

	turns, skipped := ccTurns(ccExport(res, rec))
	if skipped != 0 || len(turns) != 1 {
		t.Fatalf("got %d turns, %d skipped; want 1,0", len(turns), skipped)
	}
	got := turns[0]
	if got.RequestID != "req_abc" || got.Model != "claude-opus-4-8" || got.Provider != "anthropic" {
		t.Fatalf("identity wrong: %+v", got)
	}
	if got.InputTokens != 1000 || got.OutputTokens != 200 || got.CacheReadTokens != 50 ||
		got.CacheWriteTokens != 10 || got.CostUSD != 0.42 || got.DurationMS != 1500 {
		t.Fatalf("metrics wrong: %+v", got)
	}
	if got.SessionID != "sess-1" {
		t.Fatalf("session from resource attr not picked up: %q", got.SessionID)
	}
	if got.SourceTag != sourceCCOTel {
		t.Fatalf("source = %q, want %q", got.SourceTag, sourceCCOTel)
	}
	if got.Timestamp.IsZero() {
		t.Fatalf("timestamp not resolved from TimeUnixNano")
	}
}

func TestClaudeCodeLegacyEventNameAttributeAndDoubleTokens(t *testing.T) {
	// Older Claude Code: event name in an attribute, counts as doubles,
	// request id under "request.id".
	rec := &logspb.LogRecord{
		Attributes: []*commonpb.KeyValue{
			ccKV("event.name", s("api_request")),
			ccKV("request.id", s("req_legacy")),
			ccKV("input_tokens", ccDbl(7)),
		},
	}
	turns, skipped := ccTurns(ccExport(nil, rec))
	if len(turns) != 1 || skipped != 0 {
		t.Fatalf("got %d turns %d skipped; want 1,0", len(turns), skipped)
	}
	if turns[0].RequestID != "req_legacy" || turns[0].InputTokens != 7 {
		t.Fatalf("legacy/double parse wrong: %+v", turns[0])
	}
}

func TestClaudeCodeSkipsNonAPIRequestAndMissingRequestID(t *testing.T) {
	other := &logspb.LogRecord{
		EventName:  "claude_code.tool_result",
		Attributes: []*commonpb.KeyValue{ccKV("tool_use_id", s("tu-1"))},
	}
	noReqID := &logspb.LogRecord{
		EventName:  "claude_code.api_request",
		Attributes: []*commonpb.KeyValue{ccKV("input_tokens", i(5))},
	}

	turns, skipped := ccTurns(ccExport(nil, other, noReqID))
	if len(turns) != 0 {
		t.Fatalf("unexpected turns: %+v", turns)
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1 (the api_request lacking request_id)", skipped)
	}
}

func TestClaudeCodeEchoGuardDropsObserverEmitted(t *testing.T) {
	rec := &logspb.LogRecord{
		EventName:  "claude_code.api_request",
		Attributes: []*commonpb.KeyValue{ccKV("request_id", s("req_echo"))},
	}
	res := []*commonpb.KeyValue{ccKV(otelident.EchoAttr, s(otelident.EchoValue))}

	turns, skipped := ccTurns(ccExport(res, rec))
	if len(turns) != 0 || skipped != 0 {
		t.Fatalf("echo guard failed: %d turns %d skipped", len(turns), skipped)
	}
}

func TestClaudeCodeContentPromptAndTool(t *testing.T) {
	prompt := &logspb.LogRecord{
		EventName: "claude_code.user_prompt",
		Attributes: []*commonpb.KeyValue{
			ccKV("request_id", s("req_1")),
			ccKV("session.id", s("sess_1")),
			ccKV("prompt", s("refactor the parser")),
		},
	}
	tool := &logspb.LogRecord{
		EventName: "tool_result", // legacy short name
		Attributes: []*commonpb.KeyValue{
			ccKV("request_id", s("req_1")),
			ccKV("tool_use_id", s("toolu_9")),
			ccKV("output", s("3 files changed")),
		},
	}

	recs := ccContents(ccExport(nil, prompt, tool))
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d: %+v", len(recs), recs)
	}
	if recs[0].Kind != ContentPrompt || recs[0].Content != "refactor the parser" || recs[0].RequestID != "req_1" {
		t.Fatalf("prompt record wrong: %+v", recs[0])
	}
	if recs[1].Kind != ContentToolOutput || recs[1].ToolUseID != "toolu_9" || recs[1].Content != "3 files changed" {
		t.Fatalf("tool record wrong: %+v", recs[1])
	}
}

func TestClaudeCodeContentBodyFallbackAndEmptySkipped(t *testing.T) {
	viaBody := &logspb.LogRecord{
		EventName: "user_prompt",
		Body:      s("hello from body"),
		Attributes: []*commonpb.KeyValue{
			ccKV("request_id", s("req_b")),
		},
	}
	empty := &logspb.LogRecord{EventName: "user_prompt"} // no content anywhere
	notContent := &logspb.LogRecord{
		EventName:  "claude_code.api_request",
		Attributes: []*commonpb.KeyValue{ccKV("request_id", s("x"))},
	}

	recs := ccContents(ccExport(nil, viaBody, empty, notContent))
	if len(recs) != 1 || recs[0].Content != "hello from body" {
		t.Fatalf("body fallback / empty-skip wrong: %+v", recs)
	}
}

// TestClaudeCodeContentBodyEqualToEventNameIsNotContent pins the OTel-direct
// spike's finding (docs/security.md OTELDIRECT-5): Claude Code sets every
// event's body to the event name, so a record with no content attribute must
// not become a content row holding that name. One case per name shape.
func TestClaudeCodeContentBodyEqualToEventNameIsNotContent(t *testing.T) {
	for _, c := range []struct {
		name      string
		eventName string
		attrName  string
		body      string
		want      int
	}{
		{"prefixed typed name", "claude_code.tool_result", "", "claude_code.tool_result", 0},
		{"bare typed name, prefixed body", "tool_result", "", "claude_code.tool_result", 0},
		{"event.name attribute only", "", "tool_decision", "tool_decision", 0},
		{"flag-less user prompt", "claude_code.user_prompt", "user_prompt", "claude_code.user_prompt", 0},
		{"body padded with spaces", "claude_code.tool_result", "", "  claude_code.tool_result ", 0},
		{"real body kept", "claude_code.user_prompt", "", "fix the retry handler", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			attrs := []*commonpb.KeyValue{ccKV("session.id", s("s1")), ccKV("request_id", s("r1"))}
			if c.attrName != "" {
				attrs = append(attrs, ccKV("event.name", s(c.attrName)))
			}
			rec := &logspb.LogRecord{EventName: c.eventName, Body: s(c.body), Attributes: attrs}
			if got := len(ccContents(ccExport(nil, rec))); got != c.want {
				t.Fatalf("content rows = %d, want %d", got, c.want)
			}
		})
	}
}

func TestClaudeCodeContentEchoGuard(t *testing.T) {
	rec := &logspb.LogRecord{
		EventName:  "user_prompt",
		Attributes: []*commonpb.KeyValue{ccKV("prompt", s("x"))},
	}
	res := []*commonpb.KeyValue{ccKV(otelident.EchoAttr, s(otelident.EchoValue))}
	if recs := ccContents(ccExport(res, rec)); len(recs) != 0 {
		t.Fatalf("echo guard failed: %+v", recs)
	}
}

func TestClaudeCodeNilExport(t *testing.T) {
	if turns, skipped := ccTurns(nil); turns != nil || skipped != 0 {
		t.Fatalf("nil request not handled: %v %d", turns, skipped)
	}
	if recs := ccContents(nil); recs != nil {
		t.Fatalf("nil request yielded content: %v", recs)
	}
}
