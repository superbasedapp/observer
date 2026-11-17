package ccotel

import (
	"testing"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
)

func TestParseContent_PromptAndTool(t *testing.T) {
	prompt := &logspb.LogRecord{
		EventName: "claude_code.user_prompt",
		Attributes: []*commonpb.KeyValue{
			kv("request_id", sv("req_1")),
			kv("session.id", sv("sess_1")),
			kv("prompt", sv("refactor the parser")),
		},
	}
	tool := &logspb.LogRecord{
		EventName: "tool_result", // legacy short name
		Attributes: []*commonpb.KeyValue{
			kv("request_id", sv("req_1")),
			kv("tool_use_id", sv("toolu_9")),
			kv("output", sv("3 files changed")),
		},
	}

	recs := ParseContent(export(nil, prompt, tool))
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d: %+v", len(recs), recs)
	}
	if recs[0].Kind != KindPrompt || recs[0].Content != "refactor the parser" || recs[0].RequestID != "req_1" {
		t.Fatalf("prompt record wrong: %+v", recs[0])
	}
	if recs[1].Kind != KindToolOutput || recs[1].ToolUseID != "toolu_9" || recs[1].Content != "3 files changed" {
		t.Fatalf("tool record wrong: %+v", recs[1])
	}
}

func TestParseContent_BodyFallbackAndEmptySkipped(t *testing.T) {
	viaBody := &logspb.LogRecord{
		EventName: "user_prompt",
		Body:      &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "hello from body"}},
		Attributes: []*commonpb.KeyValue{
			kv("request_id", sv("req_b")),
		},
	}
	empty := &logspb.LogRecord{EventName: "user_prompt"} // no content anywhere
	notContent := &logspb.LogRecord{
		EventName:  "claude_code.api_request",
		Attributes: []*commonpb.KeyValue{kv("request_id", sv("x"))},
	}

	recs := ParseContent(export(nil, viaBody, empty, notContent))
	if len(recs) != 1 || recs[0].Content != "hello from body" {
		t.Fatalf("body fallback / empty-skip wrong: %+v", recs)
	}
}

// TestParseContent_BodyEqualToEventNameIsNotContent pins the OTel-direct
// spike's finding (docs/security.md OTELDIRECT-5): Claude Code sets every
// event's body to the event name, so a record with no content attribute must
// not become a content row holding that name. One case per name shape.
func TestParseContent_BodyEqualToEventNameIsNotContent(t *testing.T) {
	body := func(s string) *commonpb.AnyValue {
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: s}}
	}
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
			attrs := []*commonpb.KeyValue{kv("session.id", sv("s1")), kv("request_id", sv("r1"))}
			if c.attrName != "" {
				attrs = append(attrs, kv("event.name", sv(c.attrName)))
			}
			rec := &logspb.LogRecord{EventName: c.eventName, Body: body(c.body), Attributes: attrs}
			if got := len(ParseContent(export(nil, rec))); got != c.want {
				t.Fatalf("content rows = %d, want %d", got, c.want)
			}
		})
	}
}

func TestParseContent_EchoGuard(t *testing.T) {
	rec := &logspb.LogRecord{
		EventName:  "user_prompt",
		Attributes: []*commonpb.KeyValue{kv("prompt", sv("x"))},
	}
	res := []*commonpb.KeyValue{kv(attrEmittedBy, sv(emittedBySelf))}
	if recs := ParseContent(export(res, rec)); len(recs) != 0 {
		t.Fatalf("echo guard failed: %+v", recs)
	}
}
