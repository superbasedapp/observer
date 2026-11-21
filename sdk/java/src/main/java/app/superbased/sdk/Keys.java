package app.superbased.sdk;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Every span-attribute key the SDK writes, in one place.
 *
 * <p>The keys come from the shared vocabulary (Go {@code internal/genaiattr}
 * and {@code internal/otelident}); the SDK never invents a mapping key. The
 * SDK-owned keys ({@code sbo.sdk}, {@code sbo.admission.*},
 * {@code sbo.experiment.*}) are listed as such.
 * {@code sdk/contract/sdk-attribute-keys.json} is the machine-readable copy;
 * the SDK's tests check this class against it.
 */
public final class Keys {
  private Keys() {}

  // span kind and operation
  public static final String SPAN_KIND = "openinference.span.kind";
  public static final String OPERATION = "gen_ai.operation.name";

  // model and provider
  public static final String REQUEST_MODEL = "gen_ai.request.model";
  public static final String RESPONSE_MODEL = "gen_ai.response.model";
  public static final String OI_MODEL = "llm.model_name";
  public static final String PROVIDER = "gen_ai.provider.name";
  public static final String LEGACY_SYSTEM = "gen_ai.system";
  public static final String OI_PROVIDER = "llm.provider";

  // usage (the genaiattr token buckets: input is GROSS, cache is a subset)
  public static final String INPUT_TOKENS = "gen_ai.usage.input_tokens";
  public static final String OUTPUT_TOKENS = "gen_ai.usage.output_tokens";
  public static final String TOTAL_TOKENS = "gen_ai.usage.total_tokens";
  public static final String CACHE_READ_TOKENS = "gen_ai.usage.cache_read.input_tokens";
  public static final String CACHE_WRITE_TOKENS = "gen_ai.usage.cache_write.input_tokens";
  public static final String REASONING_TOKENS = "gen_ai.usage.reasoning.output_tokens";
  public static final String COST = "gen_ai.usage.cost";

  // ids and outcome
  public static final String RESPONSE_ID = "gen_ai.response.id";
  public static final String REQUEST_ID = "request_id";
  public static final String FINISH_REASONS = "gen_ai.response.finish_reasons";
  public static final String ERROR_TYPE = "error.type";

  // tools, agents, retrieval
  public static final String TOOL_NAME = "gen_ai.tool.name";
  public static final String OI_TOOL_NAME = "tool.name";
  public static final String TOOL_CALL_ID = "gen_ai.tool.call.id";
  public static final String TOOL_ARGUMENTS = "gen_ai.tool.call.arguments";
  public static final String TOOL_RESULT = "gen_ai.tool.call.result";
  public static final String AGENT_NAME = "gen_ai.agent.name";
  public static final String OI_AGENT_NAME = "agent.name";
  public static final String AGENT_ID = "gen_ai.agent.id";
  public static final String RETRIEVAL_QUERY = "gen_ai.retrieval.query.text";
  public static final String RETRIEVAL_DOCUMENTS = "gen_ai.retrieval.documents";

  // content
  public static final String INPUT_VALUE = "input.value";
  public static final String OUTPUT_VALUE = "output.value";
  public static final String INPUT_MESSAGES = "gen_ai.input.messages";
  public static final String OUTPUT_MESSAGES = "gen_ai.output.messages";
  public static final String SYSTEM_INSTRUCTIONS = "gen_ai.system_instructions";

  /** Request parameters (genaiattr.Params, canonical names), by option name. */
  public static final Map<String, String> REQUEST_PARAMS;

  static {
    Map<String, String> p = new LinkedHashMap<>();
    p.put("max_tokens", "gen_ai.request.max_tokens");
    p.put("temperature", "gen_ai.request.temperature");
    p.put("top_p", "gen_ai.request.top_p");
    p.put("top_k", "gen_ai.request.top_k");
    p.put("stop_sequences", "gen_ai.request.stop_sequences");
    p.put("frequency_penalty", "gen_ai.request.frequency_penalty");
    p.put("presence_penalty", "gen_ai.request.presence_penalty");
    p.put("seed", "gen_ai.request.seed");
    p.put("stream", "gen_ai.request.stream");
    p.put("reasoning_level", "gen_ai.request.reasoning.level");
    REQUEST_PARAMS = java.util.Collections.unmodifiableMap(p);
  }

  // identity (otelident)
  public static final String SERVICE_NAME = "service.name";
  public static final String USER = "sbo.user";
  public static final String SESSION = "session.id";
  public static final String TENANT = "sbo.tenant";
  public static final String TAGS = "sbo.tags";
  public static final String METADATA_PREFIX = "sbo.metadata.";
  public static final String RELEASE = "sbo.release";
  public static final String ENVIRONMENT = "sbo.environment";
  /** The resource-level spelling init() writes for release. */
  public static final String RESOURCE_RELEASE = "service.version";
  /** The resource-level spelling init() writes for environment. */
  public static final String RESOURCE_ENVIRONMENT = "deployment.environment.name";

  // otelident bounds
  public static final int MAX_VALUE_LEN = 256;
  public static final int MAX_TAGS = 32;
  public static final int MAX_TAG_LEN = 128;
  public static final int MAX_METADATA_KEYS = 32;
  public static final int MAX_METADATA_KEY_LEN = 128;
  public static final int MAX_METADATA_VALUE_LEN = 512;

  // SDK-owned keys (not mapping vocabulary)
  public static final String SDK = "sbo.sdk";
  public static final String ADMISSION_ALLOWED = "sbo.admission.allowed";
  public static final String ADMISSION_DECISION = "sbo.admission.decision";
  public static final String ADMISSION_VERDICT_ID = "sbo.admission.verdict_id";
  public static final String ADMISSION_DEGRADED = "sbo.admission.degraded";
  public static final String PROMPT_NAME = "sbo.prompt.name";
  public static final String PROMPT_VERSION = "sbo.prompt.version";
  public static final String PROMPT_LABEL = "sbo.prompt.label";
  /** prompts.md v2: the staged-rollout side that served the prompt. */
  public static final String PROMPT_COHORT = "sbo.prompt.cohort";
  public static final String EXPERIMENT_RUN_ID = "sbo.experiment.run_id";
  public static final String EXPERIMENT_ITEM_ID = "sbo.experiment.item_id";

  /**
   * The keys of the genaiattr content fields: capture_content, mask and
   * max_content_chars apply to them.
   */
  public static final Set<String> CONTENT_KEYS =
      Set.of(
          INPUT_MESSAGES,
          OUTPUT_MESSAGES,
          SYSTEM_INSTRUCTIONS,
          INPUT_VALUE,
          "gen_ai.prompt",
          "llm.prompt",
          "prompt",
          OUTPUT_VALUE,
          "gen_ai.output.value",
          "gen_ai.completion",
          "llm.completion",
          "completion",
          "traceloop.entity.input",
          "traceloop.entity.output",
          RETRIEVAL_QUERY,
          "langfuse.observation.input",
          "langfuse.observation.output",
          "langfuse.trace.input",
          "langfuse.trace.output",
          RETRIEVAL_DOCUMENTS,
          TOOL_ARGUMENTS,
          "tool.parameters",
          "gen_ai.tool.input",
          "tool_call.function.arguments",
          TOOL_RESULT,
          "gen_ai.tool.output",
          "tool.result",
          "tool_call.result");

  /** The indexed message lists; every key under them is content but the exempt suffixes. */
  public static final List<String> CONTENT_PREFIXES =
      List.of("llm.input_messages.", "llm.output_messages.", "gen_ai.prompt.", "gen_ai.completion.");

  /** Members of an indexed message list that are not content. */
  public static final List<String> CONTENT_PREFIX_EXEMPT_SUFFIXES = List.of(".role", ".finish_reason");

  /** Content an instrumentor emits under keys the Go vocabulary does not map (yet). */
  public static final List<String> EXTRA_CONTENT_PREFIXES =
      List.of(
          "embedding.embeddings.",
          "retrieval.documents.",
          "llm.prompt_template.",
          "llm.prompts",
          "final_result",
          "pydantic_ai.all_messages",
          "crew_inputs",
          "crew_tasks",
          "crew_agents");

  /** True when {@code key} carries prompt, response or tool I/O content. */
  public static boolean isContentKey(String key) {
    if (CONTENT_KEYS.contains(key)) {
      return true;
    }
    for (String p : CONTENT_PREFIXES) {
      if (key.startsWith(p)) {
        for (String s : CONTENT_PREFIX_EXEMPT_SUFFIXES) {
          if (key.endsWith(s)) {
            return false;
          }
        }
        return true;
      }
    }
    for (String p : EXTRA_CONTENT_PREFIXES) {
      if (key.startsWith(p)) {
        return true;
      }
    }
    return false;
  }
}
