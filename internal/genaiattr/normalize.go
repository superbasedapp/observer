package genaiattr

import (
	"encoding/json"
	"strings"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// This file holds the read-side normalisations the live chatbot runs of
// 2026-11-20 showed were missing (lane LF-4): a router's provider prefix on a
// model name, the reasoning effort nested in a request-parameter blob, a cache
// write that only reaches a span inside LangChain's serialized output, the
// request model OpenInference keeps only in its invocation parameters, the
// error type an exception event carries, an agent's name OpenInference keeps
// in graph.node.id, and a provider call that is not a model call. Each is a
// table walked by a small function, never a branch on a provider name.

// RouterModelPrefixes are the provider route segments a model router (LiteLLM,
// OpenRouter) puts in front of a model id: "anthropic/claude-haiku-5-5" names
// the model "claude-haiku-5-5". A segment not in the table is part of the id
// ("meta-llama/Llama-3.1-8B" stays as is).
var RouterModelPrefixes = map[string]bool{
	"anthropic": true, "openai": true, "azure": true, "azure_ai": true,
	"gemini": true, "vertex_ai": true, "vertex_ai_beta": true,
	"bedrock": true, "bedrock_converse": true, "sagemaker": true,
	"mistral": true, "groq": true, "cohere": true, "cohere_chat": true,
	"deepseek": true, "xai": true, "together_ai": true, "fireworks_ai": true,
	"ollama": true, "ollama_chat": true, "openrouter": true, "perplexity": true,
	"cerebras": true, "huggingface": true, "databricks": true, "watsonx": true,
	"nvidia_nim": true, "deepinfra": true, "replicate": true, "ai21": true,
	"cloudflare": true, "hosted_vllm": true, "lm_studio": true, "litellm_proxy": true,
	"dashscope": true, "moonshot": true, "github": true,
}

// NormalizeModel strips every leading router provider segment
// (RouterModelPrefixes) from a model name, so a model reached through a router
// groups, filters and prices under the provider's own id. A name with no such
// segment is returned unchanged; a name that is only a prefix ("openai/") is
// returned unchanged too.
func NormalizeModel(raw string) string {
	m := strings.TrimSpace(raw)
	for {
		head, rest, ok := strings.Cut(m, "/")
		if !ok || rest == "" || !RouterModelPrefixes[strings.ToLower(head)] {
			return m
		}
		m = rest
	}
}

// SpanModel resolves a span's model over keys (first present wins) and
// normalises it (NormalizeModel). raw is the value as emitted, so a caller can
// keep it where the request model is unset.
func SpanModel(a Attrs, keys []string) (model, raw string) {
	raw = a.First(keys)
	return NormalizeModel(raw), raw
}

// effortPaths are the places a request-parameter blob carries a reasoning
// effort, each lifted into the canonical reasoning_level parameter (the name
// gen_ai.request.reasoning.level fills): Anthropic's output_config.effort
// (raw SDK and LangChain Python), LangChain.js's outputConfig.effort, OpenAI
// Responses' reasoning.effort, OpenAI Chat Completions' reasoning_effort and
// LangChain's effort alias. The first present wins.
var effortPaths = [][]string{
	{"output_config", "effort"},
	{"outputConfig", "effort"},
	{"reasoning", "effort"},
	{"reasoning_effort"},
	{"reasoningEffort"},
	{"effort"},
}

// ReasoningLevelParam is the canonical request-parameter name of a reasoning
// effort.
const ReasoningLevelParam = "reasoning_level"

// liftEffort sets ReasoningLevelParam from the first effortPaths member of a
// decoded blob that is a short string, unless out already holds one.
func liftEffort(out, blob map[string]any) {
	if _, set := out[ReasoningLevelParam]; set {
		return
	}
	for _, p := range effortPaths {
		if s, ok := lookupPath(blob, p).(string); ok && s != "" && len(s) <= maxParamString {
			out[ReasoningLevelParam] = s
			return
		}
	}
}

// lookupPath walks a decoded JSON object by member names; nil when absent.
func lookupPath(v any, path []string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// requestModelFromParams is the model an OpenInference span names only in its
// llm.invocation_parameters blob ("" when none): openinference-instrumentation-
// openai writes no request-model attribute.
func requestModelFromParams(a Attrs) string {
	raw := strings.TrimSpace(a.Str(InvocationParamsKey))
	if !strings.HasPrefix(raw, "{") {
		return ""
	}
	var blob map[string]any
	if json.Unmarshal([]byte(raw), &blob) != nil {
		return ""
	}
	if s, ok := blob["model"].(string); ok && len(s) <= maxParamString {
		return strings.TrimSpace(s)
	}
	return ""
}

// OpenInference keeps a graph node's id (CrewAI: the agent's role) here; on an
// AGENT span with no agent name it names the agent.
const graphNodeIDKey = "graph.node.id"

// agentNameFallback is graph.node.id on an OpenInference AGENT span.
func agentNameFallback(a Attrs) string {
	if !strings.EqualFold(strings.TrimSpace(a.First(Keys(FieldSpanKindOI))), "AGENT") {
		return ""
	}
	return strings.TrimSpace(a.Str(graphNodeIDKey))
}

// The OpenTelemetry exception event (core semconv): an instrumentation that
// records an exception as a span event, not as error.type, names its type here.
const (
	ExceptionEventName = "exception"
	ExceptionTypeKey   = "exception.type"
)

// ExceptionType is the exception.type of one span event, "" unless the event
// is an exception event that carries one. A mapper uses the first non-empty
// one as the span's error type when error.type is absent.
func ExceptionType(eventName string, attrs []*commonpb.KeyValue) string {
	if eventName != ExceptionEventName {
		return ""
	}
	for _, kv := range attrs {
		if kv.GetKey() == ExceptionTypeKey {
			return strings.TrimSpace(Text(kv.GetValue()))
		}
	}
	return ""
}

// SpanErrorType is a span's error type: errType (its error.type attribute)
// when set, else the type of its first exception event that names one.
func SpanErrorType(errType string, events []*tracepb.Span_Event) string {
	if errType = strings.TrimSpace(errType); errType != "" {
		return errType
	}
	for _, ev := range events {
		if t := ExceptionType(ev.GetName(), ev.GetAttributes()); t != "" {
			return t
		}
	}
	return ""
}

// Provider calls an instrumentation wraps as an LLM span that make no model
// call: OpenAI's token-count endpoint (responses.input_tokens.count, which
// CrewAI calls before each model call), seen by the response object type in
// the serialized output or by the span name openinference-instrumentation-
// openai gives it (the response class).
var (
	utilityObjects   = map[string]bool{"response.input_tokens": true}
	utilitySpanNames = map[string]bool{"InputTokenCountResponse": true}
)

// UtilityCall reports whether an LLM-classified span is a provider utility
// call, not a model call: it carries no token usage and either its name
// (utilitySpanNames) or its serialized output's object type (utilityObjects)
// says so. A mapper classifies such a span as a chain step, so it is never
// counted, timed or priced as a model call.
func UtilityCall(name string, a Attrs) bool {
	u := ReadUsage(a)
	if u.Input != nil || u.Output != nil || u.CacheRead != nil || u.CacheWrite != nil {
		return false
	}
	if utilitySpanNames[strings.TrimSpace(name)] {
		return true
	}
	out := strings.TrimSpace(a.First(Keys(FieldResponseValue)))
	if !strings.HasPrefix(out, "{") || len(out) > 4096 {
		return false
	}
	var obj struct {
		Object string `json:"object"`
	}
	if json.Unmarshal([]byte(out), &obj) != nil {
		return false
	}
	return utilityObjects[obj.Object]
}

// LangChain reports a model call's usage on the generated message
// (usage_metadata), which OpenInference serializes into output.value. The
// LangChain.js instrumentation maps cache reads from it but never the cache
// write, and LangChain splits Anthropic's write by TTL
// (ephemeral_5m_input_tokens, ephemeral_1h_input_tokens) with cache_creation
// sometimes 0. lcUsageMarker gates the decode so other outputs are not parsed.
const lcUsageMarker = `"usage_metadata"`

// maxLCOutput bounds the output blob decoded for usage_metadata.
const maxLCOutput = 1 << 20

type lcTokenDetails struct {
	CacheCreation *int64 `json:"cache_creation"`
	CacheRead     *int64 `json:"cache_read"`
	Ephemeral5m   *int64 `json:"ephemeral_5m_input_tokens"`
	Ephemeral1h   *int64 `json:"ephemeral_1h_input_tokens"`
}

type lcUsage struct {
	InputTokenDetails *lcTokenDetails `json:"input_token_details"`
}

type lcMessage struct {
	UsageMetadata *lcUsage `json:"usage_metadata"`
	Kwargs        *struct {
		UsageMetadata *lcUsage `json:"usage_metadata"`
	} `json:"kwargs"`
}

type lcOutput struct {
	Generations [][]struct {
		Message *lcMessage `json:"message"`
	} `json:"generations"`
}

// lcCacheDetails decodes the first generation's input_token_details from a
// LangChain output blob, nil when the blob is not one or carries none.
func lcCacheDetails(a Attrs) *lcTokenDetails {
	out := a.Str("output.value")
	if len(out) > maxLCOutput || !strings.Contains(out, lcUsageMarker) {
		return nil
	}
	var o lcOutput
	if json.Unmarshal([]byte(out), &o) != nil || len(o.Generations) == 0 || len(o.Generations[0]) == 0 {
		return nil
	}
	m := o.Generations[0][0].Message
	if m == nil {
		return nil
	}
	u := m.UsageMetadata
	if u == nil && m.Kwargs != nil {
		u = m.Kwargs.UsageMetadata
	}
	if u == nil {
		return nil
	}
	return u.InputTokenDetails
}

// fillCacheFromLangChain fills the cache buckets the flat keys left empty, or
// reported as 0, from LangChain's usage_metadata: the write is cache_creation,
// or the sum of the TTL buckets when that is larger (both are subsets of the
// gross input LangChain reports).
func fillCacheFromLangChain(a Attrs, u *Usage) {
	if u.Input == nil || (nonZeroCount(u.CacheWrite) && nonZeroCount(u.CacheRead)) {
		return
	}
	d := lcCacheDetails(a)
	if d == nil {
		return
	}
	if !nonZeroCount(u.CacheWrite) {
		w := deref64(d.CacheCreation)
		if ttl := deref64(d.Ephemeral5m) + deref64(d.Ephemeral1h); ttl > w {
			w = ttl
		}
		if w > 0 {
			u.CacheWrite = &w
		}
	}
	if !nonZeroCount(u.CacheRead) && deref64(d.CacheRead) > 0 {
		r := *d.CacheRead
		u.CacheRead = &r
	}
}

func nonZeroCount(p *int64) bool { return p != nil && *p != 0 }

func deref64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
