/**
 * Every span-attribute key the SDK writes, in one place.
 *
 * The keys come from the Observer vocabulary: `internal/genaiattr` (GenAI
 * semconv pinned to open-telemetry/semantic-conventions-genai at
 * `SEMCONV_COMMIT`, plus the OpenInference names Observer reads) and
 * `internal/otelident` (identity), plus the SDK-owned `sbo.*` keys of
 * contract sdk-api-surface.md section 9. The SDK never invents a key:
 * `vocabulary.test.mjs` checks each one against those Go files and against
 * `sdk/contract/sdk-attribute-keys.json`.
 */

/** The pinned GenAI semconv state (`internal/genaiattr.SemconvCommit`). */
export const SEMCONV_COMMIT = "76e0c19e7fe11dc693fe258642363a438af4d3aa";
export const SEMCONV_SCHEMA_URL = "https://opentelemetry.io/schemas/gen-ai-dev/1.42.0-dev";

export const K = {
  // OpenInference span kind (Observer normalizes either case).
  spanKind: "openinference.span.kind",
  // GenAI semconv.
  operation: "gen_ai.operation.name",
  provider: "gen_ai.provider.name",
  systemLegacy: "gen_ai.system",
  requestModel: "gen_ai.request.model",
  responseModel: "gen_ai.response.model",
  responseId: "gen_ai.response.id",
  finishReasons: "gen_ai.response.finish_reasons",
  inputTokens: "gen_ai.usage.input_tokens",
  totalTokens: "gen_ai.usage.total_tokens",
  outputTokens: "gen_ai.usage.output_tokens",
  cacheReadTokens: "gen_ai.usage.cache_read.input_tokens",
  cacheWriteTokens: "gen_ai.usage.cache_write.input_tokens",
  reasoningTokens: "gen_ai.usage.reasoning.output_tokens",
  cost: "gen_ai.usage.cost",
  toolName: "gen_ai.tool.name",
  toolCallId: "gen_ai.tool.call.id",
  toolArguments: "gen_ai.tool.call.arguments",
  toolResult: "gen_ai.tool.call.result",
  agentName: "gen_ai.agent.name",
  agentId: "gen_ai.agent.id",
  retrievalQuery: "gen_ai.retrieval.query.text",
  retrievalDocuments: "gen_ai.retrieval.documents",
  inputMessages: "gen_ai.input.messages",
  outputMessages: "gen_ai.output.messages",
  systemInstructions: "gen_ai.system_instructions",
  errorType: "error.type",
  // OpenInference.
  oiModel: "llm.model_name",
  oiProvider: "llm.provider",
  oiToolName: "tool.name",
  oiAgentName: "agent.name",
  inputValue: "input.value",
  outputValue: "output.value",
  // Generic.
  requestId: "request_id",
  // Identity (internal/otelident).
  tenant: "sbo.tenant",
  user: "sbo.user",
  session: "session.id",
  environment: "sbo.environment",
  release: "sbo.release",
  tags: "sbo.tags",
  metadataPrefix: "sbo.metadata.",
  serviceVersion: "service.version",
  deploymentEnvironment: "deployment.environment.name",
  sdk: "sbo.sdk",
  // Experiment item (W3-2, SDK-owned).
  experimentRunId: "sbo.experiment.run_id",
  experimentItemId: "sbo.experiment.item_id",
  // Prompt registry stamp (W3-3).
  promptName: "sbo.prompt.name",
  promptVersion: "sbo.prompt.version",
  promptLabel: "sbo.prompt.label",
  /** Which side of a staged rollout served the prompt (prompts.md v2 section 9.4; genaiattr field prompt_cohort, lane C8). */
  promptCohort: "sbo.prompt.cohort",
  // Admission verdict stamp (W2-1).
  admissionAllowed: "sbo.admission.allowed",
  admissionDecision: "sbo.admission.decision",
  admissionVerdictId: "sbo.admission.verdict_id",
  admissionDegraded: "sbo.admission.degraded",
} as const;

/**
 * Content-bearing keys and prefixes: the ones `captureContent`, the
 * `maxContentChars` clip and the `mask` hook apply to at export, whichever
 * instrumentation wrote them (genaiattr content fields, every dialect).
 */
export const CONTENT_KEYS: ReadonlySet<string> = new Set([
  "input.value",
  "output.value",
  "gen_ai.input.messages",
  "gen_ai.output.messages",
  "gen_ai.system_instructions",
  "gen_ai.tool.call.arguments",
  "gen_ai.tool.call.result",
  "gen_ai.retrieval.query.text",
  "gen_ai.retrieval.documents",
  "gen_ai.prompt",
  "gen_ai.completion",
  "gen_ai.output.value",
  "gen_ai.tool.input",
  "gen_ai.tool.output",
  "tool.parameters",
  "tool.result",
  "tool_call.function.arguments",
  "tool_call.result",
  "traceloop.entity.input",
  "traceloop.entity.output",
  // The langfuse dialect (W5-2): a Langfuse SDK's observation and trace
  // input/output.
  "langfuse.observation.input",
  "langfuse.observation.output",
  "langfuse.trace.input",
  "langfuse.trace.output",
  "llm.prompt",
  "llm.completion",
  "prompt",
  "completion",
]);
export const CONTENT_PREFIXES: readonly string[] = [
  "gen_ai.prompt.",
  "gen_ai.completion.",
  "llm.input_messages.",
  "llm.output_messages.",
];
/**
 * Content an instrumentation emits under keys the Go vocabulary does not map
 * (yet): the contract's `extra_content_prefixes`, exactly as Python's
 * EXTRA_CONTENT_PREFIXES. The SDK never writes them, but an instrumentation
 * does, so they are masked, clipped and dropped like the rest: content never
 * leaves unmasked because Observer does not read it. Each is a prefix (an
 * exact key is its own prefix: OpenInference's `llm.prompts` is one key).
 */
export const EXTRA_CONTENT_PREFIXES: readonly string[] = [
  // OpenInference embedding inputs (text and vectors).
  "embedding.embeddings.",
  // OpenInference retriever documents, prompt templates and their variables,
  // and the rendered prompt list of a completion call.
  "retrieval.documents.",
  "llm.prompt_template.",
  "llm.prompts",
  // Pydantic AI's own agent-span content.
  "final_result",
  "pydantic_ai.all_messages",
  // OpenInference CrewAI: the crew's inputs, task descriptions and agents.
  "crew_inputs",
  "crew_tasks",
  "crew_agents",
];

/** Indexed-list members that are structure, not content (`gen_ai.prompt.0.role`). */
export const CONTENT_PREFIX_EXEMPT_SUFFIXES: readonly string[] = [".role", ".finish_reason"];

/** True when `key` carries prompt, response or tool I/O content (Python's is_content_key). */
export function isContentKey(key: string): boolean {
  if (CONTENT_KEYS.has(key)) return true;
  if (CONTENT_PREFIXES.some((p) => key.startsWith(p))) return !CONTENT_PREFIX_EXEMPT_SUFFIXES.some((s) => key.endsWith(s));
  return EXTRA_CONTENT_PREFIXES.some((p) => key.startsWith(p));
}

/** `setRequestParams` option -> `gen_ai.request.*` key (the genaiattr Params names). */
export const REQUEST_PARAMS = {
  maxTokens: "gen_ai.request.max_tokens",
  temperature: "gen_ai.request.temperature",
  topP: "gen_ai.request.top_p",
  topK: "gen_ai.request.top_k",
  stopSequences: "gen_ai.request.stop_sequences",
  frequencyPenalty: "gen_ai.request.frequency_penalty",
  presencePenalty: "gen_ai.request.presence_penalty",
  seed: "gen_ai.request.seed",
  stream: "gen_ai.request.stream",
  reasoningLevel: "gen_ai.request.reasoning.level",
} as const;

/** Bounds of the identity contract (`internal/otelident`): ingest clamps with the same numbers. */
export const LIMITS = {
  valueLen: 256,
  tags: 32,
  tagLen: 128,
  metadataKeys: 32,
  metadataKeyLen: 128,
  metadataValueLen: 512,
} as const;
