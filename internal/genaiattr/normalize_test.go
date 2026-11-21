package genaiattr

import (
	"encoding/json"
	"testing"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// TestNormalizeModel: a router's provider segment is stripped (A-08), a
// segment that is part of the id is kept.
func TestNormalizeModel(t *testing.T) {
	cases := []struct{ in, want string }{
		{"anthropic/claude-haiku-5-5", "claude-haiku-5-5"},
		{"openrouter/anthropic/claude-sonnet-4-5", "claude-sonnet-4-5"},
		{"openai/gpt-5-nano", "gpt-5-nano"},
		{"meta-llama/Llama-3.1-8B", "meta-llama/Llama-3.1-8B"},
		{"huggingface/meta-llama/Llama-3.1-8B", "meta-llama/Llama-3.1-8B"},
		{"claude-haiku-5-5", "claude-haiku-5-5"},
		{"anthropic.claude-3-5-sonnet", "anthropic.claude-3-5-sonnet"},
		{"openai/", "openai/"},
		{"", ""},
	}
	for _, c := range cases {
		if got := NormalizeModel(c.in); got != c.want {
			t.Errorf("NormalizeModel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestReadRouterModelKeepsRaw: Read normalises the model and keeps the
// emitted name as the request model when none is set (A-08).
func TestReadRouterModelKeepsRaw(t *testing.T) {
	f := Read(Attrs{"llm.model_name": sv("anthropic/claude-haiku-5-5")})
	if f.Model != "claude-haiku-5-5" || f.RequestModel != "anthropic/claude-haiku-5-5" || f.ResponseModel != "claude-haiku-5-5" {
		t.Fatalf("model %q request %q response %q", f.Model, f.RequestModel, f.ResponseModel)
	}
}

// TestRequestParamsEffort: a reasoning effort nested in an invocation
// parameter blob reaches reasoning_level (A-10).
func TestRequestParamsEffort(t *testing.T) {
	cases := []struct{ name, blob, want string }{
		{"anthropic output_config", `{"max_tokens": 1000, "output_config": {"effort": "low"}}`, "low"},
		{"langchain.js outputConfig", `{"outputConfig": {"effort": "medium"}}`, "medium"},
		{"openai responses", `{"reasoning": {"effort": "minimal", "summary": "auto"}}`, "minimal"},
		{"openai chat", `{"reasoning_effort": "high"}`, "high"},
		{"langchain alias", `{"effort": "low"}`, "low"},
		{"none", `{"max_tokens": 64}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := RequestParams(Attrs{InvocationParamsKey: sv(c.blob)})
			var m map[string]any
			_ = json.Unmarshal([]byte(raw), &m)
			got, _ := m[ReasoningLevelParam].(string)
			if got != c.want {
				t.Fatalf("reasoning_level = %q, want %q (params %s)", got, c.want, raw)
			}
		})
	}
	// An explicit gen_ai.request.reasoning.level wins over a blob member.
	raw := RequestParams(Attrs{"gen_ai.request.reasoning.level": sv("high"), InvocationParamsKey: sv(`{"output_config":{"effort":"low"}}`)})
	if raw != `{"reasoning_level":"high"}` {
		t.Fatalf("explicit level lost: %s", raw)
	}
}

// lcOutputValue is LangChain.js's serialized generation for an Anthropic
// call whose cache write sits in the TTL bucket (live run A-04).
const lcOutputValue = `{"generations":[[{"text":"ok","message":{"lc":1,"type":"constructor","id":["langchain_core","messages","AIMessage"],` +
	`"kwargs":{"content":"ok","usage_metadata":{"input_tokens":5804,"output_tokens":12,"total_tokens":5816,` +
	`"input_token_details":{"cache_creation":0,"cache_read":0,"ephemeral_5m_input_tokens":5720,"ephemeral_1h_input_tokens":0}}}}}]]}`

// TestReadUsageLangChainCacheWrite: the cache write LangChain.js's
// instrumentation never maps is read from usage_metadata (A-04).
func TestReadUsageLangChainCacheWrite(t *testing.T) {
	a := Attrs{
		"llm.token_count.prompt":     iv(5804),
		"llm.token_count.completion": iv(12),
		"llm.token_count.total":      iv(5816),
		"output.value":               sv(lcOutputValue),
	}
	u := ReadUsage(a)
	if u.CacheWrite == nil || *u.CacheWrite != 5720 {
		t.Fatalf("cache write = %v, want 5720", u.CacheWrite)
	}
	if u.CacheRead != nil {
		t.Fatalf("cache read = %d, want none", *u.CacheRead)
	}
	if u.InputShape != ShapeGross {
		t.Fatalf("input shape = %q, want gross", u.InputShape)
	}
	// cache_creation set (non-streamed path): it is taken as is.
	a["output.value"] = sv(`{"generations":[[{"message":{"usage_metadata":{"input_tokens":200,"input_token_details":{"cache_creation":150,"cache_read":40}}}}]]}`)
	u = ReadUsage(a)
	if u.CacheWrite == nil || *u.CacheWrite != 150 || u.CacheRead == nil || *u.CacheRead != 40 {
		t.Fatalf("write %v read %v, want 150 / 40", u.CacheWrite, u.CacheRead)
	}
	// A flat key wins over the blob.
	a["llm.token_count.prompt_details.cache_write"] = iv(99)
	if u = ReadUsage(a); *u.CacheWrite != 99 {
		t.Fatalf("flat key lost: %d", *u.CacheWrite)
	}
	// No usage at all: the blob is not read.
	if u = ReadUsage(Attrs{"output.value": sv(lcOutputValue)}); u.CacheWrite != nil {
		t.Fatal("cache write without an input count")
	}
}

// TestReadRequestModelFromParams: OpenInference's openai instrumentation
// names the requested model only in its invocation parameters (LC-06).
func TestReadRequestModelFromParams(t *testing.T) {
	f := Read(Attrs{
		"openinference.span.kind":    sv("LLM"),
		"llm.model_name":             sv("gpt-5-nano-2025-08-07"),
		InvocationParamsKey:          sv(`{"model": "gpt-5-nano", "reasoning_effort": "low"}`),
		"llm.token_count.prompt":     iv(213),
		"llm.token_count.completion": iv(151),
	})
	if f.RequestModel != "gpt-5-nano" || f.Model != "gpt-5-nano-2025-08-07" {
		t.Fatalf("request %q model %q", f.RequestModel, f.Model)
	}
	// An explicit request-model key wins.
	f = Read(Attrs{"gen_ai.request.model": sv("a"), InvocationParamsKey: sv(`{"model":"b"}`)})
	if f.RequestModel != "a" {
		t.Fatalf("request model %q, want a", f.RequestModel)
	}
}

// TestReadAgentNameFromGraphNode: CrewAI's agent span carries the role only
// in graph.node.id (LC-03); a non-agent span's node id is not a name.
func TestReadAgentNameFromGraphNode(t *testing.T) {
	f := Read(Attrs{"openinference.span.kind": sv("AGENT"), "graph.node.id": sv("Geography helper")})
	if f.AgentName != "Geography helper" {
		t.Fatalf("agent name %q", f.AgentName)
	}
	if f = Read(Attrs{"openinference.span.kind": sv("CHAIN"), "graph.node.id": sv("answer")}); f.AgentName != "" {
		t.Fatalf("chain span got agent name %q", f.AgentName)
	}
	if f = Read(Attrs{"openinference.span.kind": sv("AGENT"), "agent.name": sv("x"), "graph.node.id": sv("y")}); f.AgentName != "x" {
		t.Fatalf("explicit agent name lost: %q", f.AgentName)
	}
}

// TestSpanErrorType: an exception event's type is the error type when
// error.type is absent (LC-04).
func TestSpanErrorType(t *testing.T) {
	evs := []*tracepb.Span_Event{
		{Name: "log"},
		{Name: ExceptionEventName, Attributes: []*commonpb.KeyValue{
			{Key: "exception.message", Value: sv("Connection error.")},
			{Key: ExceptionTypeKey, Value: sv("APIConnectionError")},
		}},
	}
	if got := SpanErrorType("", evs); got != "APIConnectionError" {
		t.Fatalf("error type %q", got)
	}
	if got := SpanErrorType("timeout", evs); got != "timeout" {
		t.Fatalf("error.type lost: %q", got)
	}
	if got := SpanErrorType("", nil); got != "" {
		t.Fatalf("no events: %q", got)
	}
}

// TestUtilityCall: CrewAI's token-count preflight is not a model call
// (LC-02); a real model call with the same name shape is.
func TestUtilityCall(t *testing.T) {
	tokenCount := Attrs{
		"openinference.span.kind": sv("LLM"),
		"llm.provider":            sv("openai"),
		"output.value":            sv(`{"input_tokens":161,"object":"response.input_tokens"}`),
	}
	if !UtilityCall("InputTokenCountResponse", tokenCount) {
		t.Fatal("token count by name: not a utility call")
	}
	if !UtilityCall("something", tokenCount) {
		t.Fatal("token count by object: not a utility call")
	}
	// Content not captured: the name alone says so.
	if !UtilityCall("InputTokenCountResponse", Attrs{"openinference.span.kind": sv("LLM")}) {
		t.Fatal("token count without content: not a utility call")
	}
	call := Attrs{
		"openinference.span.kind":    sv("LLM"),
		"llm.token_count.prompt":     iv(213),
		"llm.token_count.completion": iv(151),
		"output.value":               sv(`{"object":"chat.completion"}`),
	}
	if UtilityCall("ChatCompletion", call) {
		t.Fatal("model call classified as utility")
	}
	// Usage present: never a utility call, whatever the name.
	if UtilityCall("InputTokenCountResponse", call) {
		t.Fatal("span with usage classified as utility")
	}
	// A failed model call (no usage, no output) stays a model call.
	if UtilityCall("ChatCompletion", Attrs{"openinference.span.kind": sv("LLM")}) {
		t.Fatal("failed model call classified as utility")
	}
}
