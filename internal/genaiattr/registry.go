package genaiattr

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/otelident"
)

// The pinned GenAI semantic-convention state (see the package doc).
const (
	// SemconvRepo is the repository the GenAI dialect is pinned to.
	SemconvRepo = "open-telemetry/semantic-conventions-genai"
	// SemconvCommit is the pinned commit of SemconvRepo.
	SemconvCommit = "76e0c19e7fe11dc693fe258642363a438af4d3aa"
	// SemconvSchemaURL is the registry schema URL at SemconvCommit.
	SemconvSchemaURL = "https://opentelemetry.io/schemas/gen-ai-dev/1.42.0-dev"
	// SemconvOptIn is the OTEL_SEMCONV_STABILITY_OPT_IN value under which an
	// instrumentation emits the newest GenAI names this table leads with.
	SemconvOptIn = "gen_ai_latest_experimental"
)

// Version names this vocabulary generation. Bump it (never re-use) when a key
// list or its order changes in a way that could alter a mapping outcome.
// genaiattr-2: the langfuse dialect (W5-2), OpenInference's
// llm.request/response.model_name and embedding.model_name, the AI SDK's
// reasoning count, the embedding input texts.
// genaiattr-3 (lane LF-4): router-prefixed model names normalised, the
// reasoning effort lifted into reasoning_level, LangChain's cache write read
// from usage_metadata, the request model from OpenInference's invocation
// parameters, graph.node.id as an AGENT span's name, exception.type as the
// error type, provider utility calls (token counting) not model calls.
const Version = "genaiattr-3"

// Dialect names the vocabulary a key belongs to.
type Dialect string

// The dialects.
const (
	// DialectGenAI is the pinned OpenTelemetry GenAI semconv (SemconvCommit).
	DialectGenAI Dialect = "genai"
	// DialectGenAILegacy is a GenAI name renamed away or removed before the
	// pin, still emitted by many live instrumentors.
	DialectGenAILegacy Dialect = "genai_legacy"
	// DialectOpenInference is Arize OpenInference (llm.*, input.value, tool.*).
	DialectOpenInference Dialect = "openinference"
	// DialectTraceloop is Traceloop / OpenLLMetry (llm.usage.*, traceloop.*,
	// gen_ai.usage.cache_*_input_tokens).
	DialectTraceloop Dialect = "traceloop"
	// DialectGeneric is a vendor-neutral fallback (model, provider,
	// request.id, ...) no single convention owns.
	DialectGeneric Dialect = "generic"
	// DialectIdentity is an identity key (tenant, user, session, service).
	// Tenant and user come from internal/otelident.
	DialectIdentity Dialect = "identity"
)

// Field is one canonical meaning a key maps to.
type Field string

// The canonical fields. The order of a field's keys in the table is its
// precedence: the first key present on a span wins.
const (
	FieldModel         Field = "model"          // response model, else request model, else generic
	FieldRequestModel  Field = "request_model"  // the model asked for
	FieldResponseModel Field = "response_model" // the model that answered
	FieldProvider      Field = "provider"
	FieldOperation     Field = "operation"    // gen_ai.operation.name
	FieldRequestType   Field = "request_type" // Traceloop's operation companion
	FieldSpanKindOI    Field = "span_kind_openinference"
	FieldSpanKindTL    Field = "span_kind_traceloop"

	FieldInputTokens      Field = "input_tokens"
	FieldOutputTokens     Field = "output_tokens"
	FieldTotalTokens      Field = "total_tokens"
	FieldCacheReadTokens  Field = "cache_read_tokens"
	FieldCacheWriteTokens Field = "cache_write_tokens" //nolint:gosec // G101: a token-count field name, never a credential
	FieldReasoningTokens  Field = "reasoning_tokens"

	FieldCostTotal      Field = "cost_total"
	FieldCostInput      Field = "cost_input"
	FieldCostOutput     Field = "cost_output"
	FieldCostCacheRead  Field = "cost_cache_read"
	FieldCostCacheWrite Field = "cost_cache_write"
	FieldCostReasoning  Field = "cost_reasoning"
	FieldCostTool       Field = "cost_tool"

	FieldRequestID  Field = "request_id"
	FieldResponseID Field = "response_id"

	FieldToolName      Field = "tool_name"
	FieldToolCallID    Field = "tool_call_id"
	FieldToolArguments Field = "tool_arguments"
	FieldToolResult    Field = "tool_result"

	FieldAgentName  Field = "agent_name"
	FieldAgentID    Field = "agent_id"
	FieldEntityName Field = "entity_name" // Traceloop's name fallback

	FieldInputMessages      Field = "input_messages"      // structured message list
	FieldOutputMessages     Field = "output_messages"     // structured message list
	FieldSystemInstructions Field = "system_instructions" // structured instructions
	FieldPromptValue        Field = "prompt_value"        // LLM-span request blob fallback
	FieldResponseValue      Field = "response_value"      // LLM-span response blob fallback
	FieldInputValue         Field = "input_value"         // any span's serialized input
	FieldOutputValue        Field = "output_value"        // any span's serialized output

	FieldErrorType     Field = "error_type"
	FieldFinishReasons Field = "finish_reasons"

	FieldSession     Field = "session"
	FieldThread      Field = "thread"
	FieldTenant      Field = "tenant"
	FieldUser        Field = "user"
	FieldProjectRoot Field = "project_root"
	FieldService     Field = "service"
	FieldApplication Field = "application"
	FieldRepository  Field = "repository" // the service's source repository (W4-3, lane C3)

	// The prompt a span was produced from (Plane A W3-3, lane B8; contract
	// docs/plans/plane-a-sdk-buildout/contracts/prompts.md section 5): the
	// SDK's get_prompt stamps sbo.prompt.*; the Langfuse spellings are
	// lower-precedence aliases.
	FieldPromptName    Field = "prompt_name"
	FieldPromptVersion Field = "prompt_version"
	FieldPromptLabel   Field = "prompt_label"
	// FieldPromptCohort is the rollout side a v2 SDK was served
	// (candidate, base or unkeyed; W5-3, lane C8, contract section 9.4).
	FieldPromptCohort Field = "prompt_cohort"
)

// Key is one row of the vocabulary: an attribute name, the field it fills and
// the dialect it comes from.
type Key struct {
	Name    string
	Field   Field
	Dialect Dialect
}

// rows builds the rows of one field, in precedence order.
func rows(f Field, kv ...any) []Key {
	out := make([]Key, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, Key{Name: kv[i].(string), Field: f, Dialect: kv[i+1].(Dialect)})
	}
	return out
}

// identityRows renders an otelident key list as identity rows.
func identityRows(f Field, keys []string) []Key {
	out := make([]Key, 0, len(keys))
	for _, k := range keys {
		out = append(out, Key{Name: k, Field: f, Dialect: DialectIdentity})
	}
	return out
}

const (
	g     = DialectGenAI
	gl    = DialectGenAILegacy
	oi    = DialectOpenInference
	tl    = DialectTraceloop
	gn    = DialectGeneric
	ident = DialectIdentity
)

// table is the vocabulary, field by field, each field's keys in precedence
// order. The orders of the fields the mappers shipped before this package
// existed are kept byte for byte; the pinned semconv names are added ahead of
// the spellings they replaced.
var table = concat(
	// openinference-instrumentation-anthropic writes llm.request.model_name /
	// llm.response.model_name beside llm.model_name; OpenInference embedding
	// spans name the model embedding.model_name (lanes B2/B3 fixtures).
	rows(FieldModel,
		"gen_ai.response.model", g, "gen_ai.request.model", g,
		"llm.model_name", oi, "llm.response.model_name", oi, "llm.request.model_name", oi,
		"embedding.model_name", oi, LangfuseObservationModel, lf,
		"llm.model", gn, "model", gn),
	rows(FieldRequestModel, "gen_ai.request.model", g, "llm.request.model_name", oi),
	rows(FieldResponseModel, "gen_ai.response.model", g, "llm.model_name", oi, "llm.response.model_name", oi),
	// gen_ai.system is the pre-rename spelling most live instrumentors still
	// emit. llm.vendor is no known emitter's key (openllmetry semconv 0.62.3,
	// source-checked 2026-08-15); it stays as a defensive alias.
	rows(FieldProvider,
		"gen_ai.provider.name", g, "gen_ai.system", gl,
		"llm.provider", oi, "llm.system", oi, "llm.vendor", tl, "provider", gn),
	rows(FieldOperation, "gen_ai.operation.name", g),
	rows(FieldRequestType, "llm.request.type", tl),
	rows(FieldSpanKindOI, "openinference.span.kind", oi),
	rows(FieldSpanKindTL, "traceloop.span.kind", tl),

	rows(FieldInputTokens,
		"gen_ai.usage.input_tokens", g, "gen_ai.usage.prompt_tokens", gl,
		"llm.token_count.prompt", oi, "llm.usage.prompt_tokens", tl),
	rows(FieldOutputTokens,
		"gen_ai.usage.output_tokens", g, "gen_ai.usage.completion_tokens", gl,
		"llm.token_count.completion", oi, "llm.usage.completion_tokens", tl),
	// The GenAI semconv defines no total; gen_ai.usage.total_tokens is a
	// widespread instrumentor key.
	rows(FieldTotalTokens,
		"gen_ai.usage.total_tokens", gn, "llm.token_count.total", oi, "llm.usage.total_tokens", tl),
	rows(FieldCacheReadTokens,
		"gen_ai.usage.cache_read.input_tokens", g,
		"gen_ai.usage.cache_read_input_tokens", tl, "gen_ai.usage.cached_tokens", gn,
		"llm.token_count.prompt_details.cache_read", oi, "llm.token_count.cache_read", oi),
	// gen_ai.usage.cache_creation.input_tokens was renamed to
	// cache_write.input_tokens (semconv-genai changelog 440).
	rows(FieldCacheWriteTokens,
		"gen_ai.usage.cache_write.input_tokens", g,
		"gen_ai.usage.cache_creation.input_tokens", gl,
		"gen_ai.usage.cache_creation_input_tokens", tl,
		"llm.token_count.prompt_details.cache_write", oi, "llm.token_count.cache_write", oi),
	rows(FieldReasoningTokens,
		"gen_ai.usage.reasoning.output_tokens", g,
		"gen_ai.usage.reasoning_tokens", gn, "gen_ai.usage.completion_tokens_details.reasoning_tokens", gn,
		"llm.token_count.completion_details.reasoning", oi, "llm.token_count.reasoning", oi,
		// @ai-sdk/otel 1.0.177 (ai 7.0.177) reports reasoning only here (B3).
		"ai.usage.outputTokenDetails.reasoningTokens", ais),

	// Reported cost, USD. OpenInference emits a breakdown; GenAI-style
	// emitters a total. The input component prefers prompt_details.input over
	// the top-level prompt total so the components never overlap the cache
	// components.
	rows(FieldCostTotal, "gen_ai.usage.cost", gn, "llm.cost.total", oi, "cost.total", gn),
	rows(FieldCostInput, "llm.cost.prompt_details.input", oi, "llm.cost.prompt", oi, "gen_ai.usage.input_cost", gn),
	rows(FieldCostOutput, "llm.cost.completion_details.output", oi, "llm.cost.completion", oi, "gen_ai.usage.output_cost", gn),
	rows(FieldCostCacheRead, "llm.cost.prompt_details.cache_read", oi),
	rows(FieldCostCacheWrite, "llm.cost.prompt_details.cache_write", oi),
	rows(FieldCostReasoning, "llm.cost.completion_details.reasoning", oi),
	rows(FieldCostTool, "llm.cost.tool", oi, "gen_ai.usage.tool_cost", gn),

	rows(FieldRequestID,
		"gen_ai.request.id", gn, "request.id", gn, "request_id", gn, "http.request.header.x-request-id", gn),
	rows(FieldResponseID, "gen_ai.response.id", g, "llm.response.id", tl, "response.id", gn),

	rows(FieldToolName, "tool.name", oi, "gen_ai.tool.name", g),
	rows(FieldToolCallID, "gen_ai.tool.call.id", g, "tool_call.id", oi, "tool.call_id", gn),
	// input.value is OpenInference's TOOL-span argument blob; tool.parameters
	// is its tool's parameter schema, kept as the shipped fallback.
	rows(FieldToolArguments,
		"gen_ai.tool.call.arguments", g, "input.value", oi, "traceloop.entity.input", tl,
		LangfuseObservationInput, lf,
		"tool.parameters", oi, "gen_ai.tool.input", gn, "tool_call.function.arguments", oi),
	rows(FieldToolResult,
		"gen_ai.tool.call.result", g, "output.value", oi, "traceloop.entity.output", tl,
		LangfuseObservationOutput, lf,
		"gen_ai.tool.output", gn, "tool.result", gn, "tool_call.result", gn),

	rows(FieldAgentName, "gen_ai.agent.name", g, "agent.name", oi),
	rows(FieldAgentID, "gen_ai.agent.id", g),
	rows(FieldEntityName, "traceloop.entity.name", tl, "traceloop.workflow.name", tl),

	rows(FieldInputMessages, "gen_ai.input.messages", g),
	rows(FieldOutputMessages, "gen_ai.output.messages", g),
	rows(FieldSystemInstructions, "gen_ai.system_instructions", g),
	// A Langfuse observation's input / output is JSON (or a plain string)
	// whatever its type; the trace-level pair is the last fallback of a
	// non-LLM span (Python langfuse < 5, @langfuse/* 6.x).
	rows(FieldPromptValue,
		"input.value", oi, "gen_ai.prompt", gl, LangfuseObservationInput, lf, "llm.prompt", gn, "prompt", gn),
	rows(FieldResponseValue,
		"output.value", oi, "gen_ai.output.value", gn, "gen_ai.completion", gl,
		LangfuseObservationOutput, lf, "llm.completion", gn, "completion", gn),
	rows(FieldInputValue,
		"input.value", oi, "traceloop.entity.input", tl, "gen_ai.retrieval.query.text", g,
		LangfuseObservationInput, lf, LangfuseTraceInput, lf),
	rows(FieldOutputValue,
		"output.value", oi, "gen_ai.output.value", gn, "traceloop.entity.output", tl, "gen_ai.retrieval.documents", g,
		LangfuseObservationOutput, lf, LangfuseTraceOutput, lf),

	rows(FieldErrorType, "error.type", g),
	rows(FieldFinishReasons,
		"gen_ai.response.finish_reasons", g, "llm.finish_reason", oi,
		"llm.response.finish_reason", tl, "llm.response.stop_reason", tl),

	// The session keys have ONE owner, internal/otelident (review E-22): the
	// mappers' session column and every reader of this field use the same
	// list, in the same order.
	identityRows(FieldSession, otelident.SessionKeys),
	rows(FieldThread, "thread.id", gn, "gen_ai.thread.id", gn),
	identityRows(FieldTenant, otelident.TenantKeys),
	identityRows(FieldUser, otelident.UserKeys),
	rows(FieldProjectRoot, "sbo.project_root", ident, "project.root", ident),
	rows(FieldService, "service.name", ident),
	rows(FieldApplication, "application", ident),
	identityRows(FieldRepository, otelident.RepositoryKeys),
	evaluationRows(),
	rows(FieldPromptName, "sbo.prompt.name", gn, LangfusePromptName, lf),
	rows(FieldPromptVersion, "sbo.prompt.version", gn, LangfusePromptVersion, lf),
	rows(FieldPromptLabel, "sbo.prompt.label", gn),
	rows(FieldPromptCohort, "sbo.prompt.cohort", gn),
	langfuseRows(),
)

func concat(lists ...[]Key) []Key {
	var out []Key
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// byField is the precomputed, ordered key list per field. Built once.
var byField = func() map[Field][]string {
	m := map[Field][]string{}
	for _, k := range table {
		m[k.Field] = append(m[k.Field], k.Name)
	}
	return m
}()

// Keys returns the ordered candidate keys of f (first present wins). The
// slice is shared: callers must not modify it. An unknown field has no keys.
func Keys(f Field) []string { return byField[f] }

// KeysWhere returns the keys of f whose row satisfies pred, in precedence
// order, as a fresh slice.
func KeysWhere(f Field, pred func(Key) bool) []string {
	var out []string
	for _, k := range table {
		if k.Field == f && pred(k) {
			out = append(out, k.Name)
		}
	}
	return out
}

// Table returns a copy of the whole vocabulary, field by field in precedence
// order.
func Table() []Key {
	out := make([]Key, len(table))
	copy(out, table)
	return out
}

// AllFields returns every field that has at least one key, in table order.
func AllFields() []Field {
	var out []Field
	seen := map[Field]bool{}
	for _, k := range table {
		if !seen[k.Field] {
			seen[k.Field] = true
			out = append(out, k.Field)
		}
	}
	return out
}

// KeySet returns the set of every key of the given fields.
func KeySet(fields ...Field) map[string]struct{} {
	out := map[string]struct{}{}
	for _, f := range fields {
		for _, k := range byField[f] {
			out[k] = struct{}{}
		}
	}
	return out
}

// Indexed message-list shapes: a flattened list is "<Prefix>.<i><Role>" /
// "<Prefix>.<i><Content>" (OpenInference llm.*_messages, legacy GenAI and
// Traceloop gen_ai.prompt / gen_ai.completion).
type IndexedList struct {
	Prefix, Role, Content string
	Dialect               Dialect
}

// The indexed message lists, request side then response side, each in
// precedence order.
var (
	IndexedInput = []IndexedList{
		{Prefix: "llm.input_messages", Role: ".message.role", Content: ".message.content", Dialect: oi},
		{Prefix: "gen_ai.prompt", Role: ".role", Content: ".content", Dialect: tl},
	}
	IndexedOutput = []IndexedList{
		{Prefix: "llm.output_messages", Role: ".message.role", Content: ".message.content", Dialect: oi},
		{Prefix: "gen_ai.completion", Role: ".role", Content: ".content", Dialect: tl},
	}
)

// IndexedFinishReason is Traceloop's per-choice finish reason suffix on a
// gen_ai.completion.<i> entry.
const IndexedFinishReason = ".finish_reason"

// Param is one request-parameter key and the canonical parameter name it
// fills in Fields.RequestParams.
type Param struct {
	Key     string
	Name    string
	Dialect Dialect
}

// Params is the request-parameter vocabulary, in precedence order per name
// (the first present key of a name wins).
var Params = []Param{
	{"gen_ai.request.max_tokens", "max_tokens", g},
	{"gen_ai.request.temperature", "temperature", g},
	{"gen_ai.request.top_p", "top_p", g},
	{"gen_ai.request.top_k", "top_k", g},
	{"llm.top_k", "top_k", tl},
	{"gen_ai.request.stop_sequences", "stop_sequences", g},
	{"llm.chat.stop_sequences", "stop_sequences", tl},
	{"gen_ai.request.frequency_penalty", "frequency_penalty", g},
	{"llm.frequency_penalty", "frequency_penalty", tl},
	{"gen_ai.request.presence_penalty", "presence_penalty", g},
	{"llm.presence_penalty", "presence_penalty", tl},
	{"gen_ai.request.seed", "seed", g},
	{"gen_ai.openai.request.seed", "seed", gl},
	{"gen_ai.request.choice.count", "choice_count", g},
	{"gen_ai.request.stream", "stream", g},
	{"llm.is_streaming", "stream", tl},
	{"gen_ai.request.reasoning.level", "reasoning_level", g},
	{"gen_ai.request.encoding_formats", "encoding_formats", g},
	{"gen_ai.output.type", "output_type", g},
	{"llm.request.repetition_penalty", "repetition_penalty", tl},
}

// InvocationParamsKey is OpenInference's request-parameter blob: a JSON
// object whose members are merged under Params (Params win on a clash).
const InvocationParamsKey = "llm.invocation_parameters"

// ParamBlobKeys are the request-parameter blobs, in merge precedence order
// (an earlier blob's member wins): OpenInference's LLM and embedding
// invocation parameters, then Langfuse's model parameters.
var ParamBlobKeys = []string{InvocationParamsKey, "embedding.invocation_parameters", LangfuseModelParameters}

// ParamKeys returns every request-parameter key (Params plus
// ParamBlobKeys).
func ParamKeys() map[string]struct{} {
	out := map[string]struct{}{}
	for _, k := range ParamBlobKeys {
		out[k] = struct{}{}
	}
	for _, p := range Params {
		out[p.Key] = struct{}{}
	}
	return out
}

// HasPrefix is a small helper for dialect views built by key prefix (the
// convention profiles filter llm.* / gen_ai.* this way).
func HasPrefix(prefix string) func(Key) bool {
	return func(k Key) bool { return strings.HasPrefix(k.Name, prefix) }
}
