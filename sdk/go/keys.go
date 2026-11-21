package superbased

import "strings"

// Span kinds (OpenInference, uppercase). Pass one as SpanOptions.Kind.
const (
	KindLLM       = "LLM"
	KindTool      = "TOOL"
	KindRetriever = "RETRIEVER"
	KindEmbedding = "EMBEDDING"
	KindChain     = "CHAIN"
	KindAgent     = "AGENT"
	KindGuardrail = "GUARDRAIL"
	KindEvaluator = "EVALUATOR"
)

// Attribute keys the SDK writes. They come from the shared vocabulary
// (internal/genaiattr and internal/otelident in the superbased repository);
// sdk/contract/sdk-attribute-keys.json is the machine-readable list and the
// tests pin this file to it.
const (
	keySpanKind  = "openinference.span.kind"
	keyOperation = "gen_ai.operation.name"

	keyRequestModel  = "gen_ai.request.model"
	keyResponseModel = "gen_ai.response.model"
	keyOIModel       = "llm.model_name"
	keyProvider      = "gen_ai.provider.name"
	keyLegacySystem  = "gen_ai.system"
	keyOIProvider    = "llm.provider"

	keyInputTokens      = "gen_ai.usage.input_tokens"
	keyOutputTokens     = "gen_ai.usage.output_tokens"
	keyTotalTokens      = "gen_ai.usage.total_tokens"
	keyCacheReadTokens  = "gen_ai.usage.cache_read.input_tokens"
	keyCacheWriteTokens = "gen_ai.usage.cache_write.input_tokens"
	keyReasoningTokens  = "gen_ai.usage.reasoning.output_tokens"
	keyCost             = "gen_ai.usage.cost"

	keyResponseID    = "gen_ai.response.id"
	keyRequestID     = "request_id"
	keyFinishReasons = "gen_ai.response.finish_reasons"

	keyToolName           = "gen_ai.tool.name"
	keyOIToolName         = "tool.name"
	keyToolCallID         = "gen_ai.tool.call.id"
	keyToolArguments      = "gen_ai.tool.call.arguments"
	keyToolResult         = "gen_ai.tool.call.result"
	keyAgentName          = "gen_ai.agent.name"
	keyOIAgentName        = "agent.name"
	keyAgentID            = "gen_ai.agent.id"
	keyRetrievalQuery     = "gen_ai.retrieval.query.text"
	keyRetrievalDocuments = "gen_ai.retrieval.documents"

	keyInputValue         = "input.value"
	keyOutputValue        = "output.value"
	keyInputMessages      = "gen_ai.input.messages"
	keyOutputMessages     = "gen_ai.output.messages"
	keySystemInstructions = "gen_ai.system_instructions"

	keyServiceName = "service.name"
	keyUser        = "sbo.user"
	keySession     = "session.id"
	keyTenant      = "sbo.tenant"
	keyTags        = "sbo.tags"
	keyMetaPrefix  = "sbo.metadata."
	keyRelease     = "sbo.release"
	keyEnvironment = "sbo.environment"
	// The resource-level spellings Init writes for release and environment.
	keyResourceRelease     = "service.version"
	keyResourceEnvironment = "deployment.environment.name"

	// SDK-owned keys (not mapping vocabulary).
	keySDK                = "sbo.sdk"
	keyAdmissionAllowed   = "sbo.admission.allowed"
	keyAdmissionDecision  = "sbo.admission.decision"
	keyAdmissionVerdictID = "sbo.admission.verdict_id"
	keyAdmissionDegraded  = "sbo.admission.degraded"
	keyPromptName         = "sbo.prompt.name"
	keyPromptVersion      = "sbo.prompt.version"
	keyPromptLabel        = "sbo.prompt.label"
	keyPromptCohort       = "sbo.prompt.cohort"
	keyExperimentRunID    = "sbo.experiment.run_id"
	keyExperimentItemID   = "sbo.experiment.item_id"
)

// requestParamKeys maps a RequestParams field (by its wire name) to its key.
var requestParamKeys = map[string]string{
	"max_tokens":        "gen_ai.request.max_tokens",
	"temperature":       "gen_ai.request.temperature",
	"top_p":             "gen_ai.request.top_p",
	"top_k":             "gen_ai.request.top_k",
	"stop_sequences":    "gen_ai.request.stop_sequences",
	"frequency_penalty": "gen_ai.request.frequency_penalty",
	"presence_penalty":  "gen_ai.request.presence_penalty",
	"seed":              "gen_ai.request.seed",
	"stream":            "gen_ai.request.stream",
	"reasoning_level":   "gen_ai.request.reasoning.level",
}

// otelident bounds.
const (
	maxValueLen         = 256
	maxTags             = 32
	maxTagLen           = 128
	maxMetadataKeys     = 32
	maxMetadataKeyLen   = 128
	maxMetadataValueLen = 512
)

// contentKeys are the keys of genaiattr's content fields.
var contentKeys = map[string]bool{
	keyInputMessages: true, keyOutputMessages: true, keySystemInstructions: true,
	keyInputValue: true, "gen_ai.prompt": true, "llm.prompt": true, "prompt": true,
	keyOutputValue: true, "gen_ai.output.value": true, "gen_ai.completion": true, "llm.completion": true, "completion": true,
	"traceloop.entity.input": true, "traceloop.entity.output": true, keyRetrievalQuery: true,
	"langfuse.observation.input": true, "langfuse.observation.output": true,
	"langfuse.trace.input": true, "langfuse.trace.output": true,
	keyRetrievalDocuments: true,
	keyToolArguments:      true, "tool.parameters": true, "gen_ai.tool.input": true, "tool_call.function.arguments": true,
	keyToolResult: true, "gen_ai.tool.output": true, "tool.result": true, "tool_call.result": true,
}

// contentPrefixes are the indexed message lists; every key under them is
// content except the exempt suffixes.
var contentPrefixes = []string{"llm.input_messages.", "llm.output_messages.", "gen_ai.prompt.", "gen_ai.completion."}

var contentPrefixExemptSuffixes = []string{".role", ".finish_reason"}

// extraContentPrefixes is content an instrumentor emits under keys the
// vocabulary does not map yet; masked and dropped like any other content.
var extraContentPrefixes = []string{
	"embedding.embeddings.",
	"retrieval.documents.", "llm.prompt_template.", "llm.prompts",
	"final_result", "pydantic_ai.all_messages",
	"crew_inputs", "crew_tasks", "crew_agents",
}

// IsContentKey reports whether key carries prompt, response or tool I/O
// content: CaptureContent, Mask and MaxContentChars apply to it.
func IsContentKey(key string) bool {
	if contentKeys[key] {
		return true
	}
	for _, p := range contentPrefixes {
		if strings.HasPrefix(key, p) {
			for _, s := range contentPrefixExemptSuffixes {
				if strings.HasSuffix(key, s) {
					return false
				}
			}
			return true
		}
	}
	for _, p := range extraContentPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}
