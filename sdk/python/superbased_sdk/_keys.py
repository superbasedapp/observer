"""Every span-attribute key the SDK writes, in one place.

The keys come from the shared vocabulary (Go ``internal/genaiattr`` and
``internal/otelident``); the SDK never invents a mapping key. The few keys the
SDK owns (``sbo.sdk``, ``sbo.admission.*``, ``sbo.prompt.*``,
``sbo.experiment.*``) are listed as such. ``sdk/contract/sdk-attribute-keys.json``
is the machine-readable copy: the SDK tests check this module against it, and
``go test ./tests/sdkcontract`` checks it against the Go vocabulary.
"""

from __future__ import annotations

from typing import FrozenSet, Tuple

# --- span kind and operation ----------------------------------------------------
SPAN_KIND = "openinference.span.kind"
OPERATION = "gen_ai.operation.name"

# --- model and provider ---------------------------------------------------------
REQUEST_MODEL = "gen_ai.request.model"
RESPONSE_MODEL = "gen_ai.response.model"
OI_MODEL = "llm.model_name"
PROVIDER = "gen_ai.provider.name"
LEGACY_SYSTEM = "gen_ai.system"
OI_PROVIDER = "llm.provider"

# --- usage (the genaiattr token buckets: input is GROSS, cache is a subset) ------
INPUT_TOKENS = "gen_ai.usage.input_tokens"
OUTPUT_TOKENS = "gen_ai.usage.output_tokens"
TOTAL_TOKENS = "gen_ai.usage.total_tokens"
CACHE_READ_TOKENS = "gen_ai.usage.cache_read.input_tokens"
CACHE_WRITE_TOKENS = "gen_ai.usage.cache_write.input_tokens"
REASONING_TOKENS = "gen_ai.usage.reasoning.output_tokens"
COST = "gen_ai.usage.cost"

# --- ids and outcome ------------------------------------------------------------
RESPONSE_ID = "gen_ai.response.id"
REQUEST_ID = "request_id"
FINISH_REASONS = "gen_ai.response.finish_reasons"
ERROR_TYPE = "error.type"

# --- tools, agents, retrieval ---------------------------------------------------
TOOL_NAME = "gen_ai.tool.name"
OI_TOOL_NAME = "tool.name"
TOOL_CALL_ID = "gen_ai.tool.call.id"
TOOL_ARGUMENTS = "gen_ai.tool.call.arguments"
TOOL_RESULT = "gen_ai.tool.call.result"
AGENT_NAME = "gen_ai.agent.name"
OI_AGENT_NAME = "agent.name"
AGENT_ID = "gen_ai.agent.id"
RETRIEVAL_QUERY = "gen_ai.retrieval.query.text"
RETRIEVAL_DOCUMENTS = "gen_ai.retrieval.documents"

# --- content --------------------------------------------------------------------
INPUT_VALUE = "input.value"
OUTPUT_VALUE = "output.value"
INPUT_MESSAGES = "gen_ai.input.messages"
OUTPUT_MESSAGES = "gen_ai.output.messages"
SYSTEM_INSTRUCTIONS = "gen_ai.system_instructions"

# --- request parameters (genaiattr.Params, canonical names) ----------------------
REQUEST_PARAMS = {
    "max_tokens": "gen_ai.request.max_tokens",
    "temperature": "gen_ai.request.temperature",
    "top_p": "gen_ai.request.top_p",
    "top_k": "gen_ai.request.top_k",
    "stop_sequences": "gen_ai.request.stop_sequences",
    "frequency_penalty": "gen_ai.request.frequency_penalty",
    "presence_penalty": "gen_ai.request.presence_penalty",
    "seed": "gen_ai.request.seed",
    "stream": "gen_ai.request.stream",
    "reasoning_level": "gen_ai.request.reasoning.level",
}

# --- identity (otelident) --------------------------------------------------------
SERVICE_NAME = "service.name"
USER = "sbo.user"
SESSION = "session.id"
TENANT = "sbo.tenant"
TAGS = "sbo.tags"
METADATA_PREFIX = "sbo.metadata."
RELEASE = "sbo.release"
ENVIRONMENT = "sbo.environment"
# The resource-level spellings init() writes for release and environment.
RESOURCE_RELEASE = "service.version"
RESOURCE_ENVIRONMENT = "deployment.environment.name"

# otelident bounds (MaxTags, MaxTagLen, MaxMetadataKeys, ...).
MAX_VALUE_LEN = 256
MAX_TAGS = 32
MAX_TAG_LEN = 128
MAX_METADATA_KEYS = 32
MAX_METADATA_KEY_LEN = 128
MAX_METADATA_VALUE_LEN = 512

# --- SDK-owned keys (not mapping vocabulary) ---------------------------------------
SDK = "sbo.sdk"
ADMISSION_ALLOWED = "sbo.admission.allowed"
ADMISSION_DECISION = "sbo.admission.decision"
ADMISSION_VERDICT_ID = "sbo.admission.verdict_id"
ADMISSION_DEGRADED = "sbo.admission.degraded"
PROMPT_NAME = "sbo.prompt.name"
PROMPT_VERSION = "sbo.prompt.version"
PROMPT_LABEL = "sbo.prompt.label"
# prompts.md v2 (W5-3): the staged-rollout side that served the prompt
# (candidate, base or unkeyed). genaiattr field prompt_cohort (lane C8).
PROMPT_COHORT = "sbo.prompt.cohort"
EXPERIMENT_RUN_ID = "sbo.experiment.run_id"
EXPERIMENT_ITEM_ID = "sbo.experiment.item_id"

# --- content keys: capture_content, mask and max_content_chars apply ---------------
# The keys of the genaiattr content fields (input/output messages, system
# instructions, prompt/response value, input/output value, tool arguments and
# result). Pinned to genaiattr by tests/sdkcontract.
CONTENT_KEYS: FrozenSet[str] = frozenset(
    {
        # FieldInputMessages, FieldOutputMessages, FieldSystemInstructions
        INPUT_MESSAGES,
        OUTPUT_MESSAGES,
        SYSTEM_INSTRUCTIONS,
        # FieldPromptValue
        INPUT_VALUE,
        "gen_ai.prompt",
        "llm.prompt",
        "prompt",
        # FieldResponseValue
        OUTPUT_VALUE,
        "gen_ai.output.value",
        "gen_ai.completion",
        "llm.completion",
        "completion",
        # FieldInputValue / FieldOutputValue
        "traceloop.entity.input",
        "traceloop.entity.output",
        RETRIEVAL_QUERY,
        # The langfuse dialect (W5-2): a Langfuse SDK's observation and
        # trace input/output, masked like every other content key.
        "langfuse.observation.input",
        "langfuse.observation.output",
        "langfuse.trace.input",
        "langfuse.trace.output",
        RETRIEVAL_DOCUMENTS,
        # FieldToolArguments
        TOOL_ARGUMENTS,
        "tool.parameters",
        "gen_ai.tool.input",
        "tool_call.function.arguments",
        # FieldToolResult
        TOOL_RESULT,
        "gen_ai.tool.output",
        "tool.result",
        "tool_call.result",
    }
)

# The indexed message lists (genaiattr.IndexedInput / IndexedOutput prefixes).
# Every key under them is content except the role and finish-reason members.
CONTENT_PREFIXES: Tuple[str, ...] = (
    "llm.input_messages.",
    "llm.output_messages.",
    "gen_ai.prompt.",
    "gen_ai.completion.",
)
CONTENT_PREFIX_EXEMPT_SUFFIXES: Tuple[str, ...] = (".role", ".finish_reason")

# Content an instrumentor emits under keys the Go vocabulary does not map
# (yet). The SDK still masks, clips and drops them so no content leaves
# unmasked. tests/sdkcontract fails when genaiattr starts mapping one of these,
# so it moves to the lists above. Each is a prefix (an exact key is its own
# prefix).
EXTRA_CONTENT_PREFIXES: Tuple[str, ...] = (
    # OpenInference embedding inputs (text and vectors).
    "embedding.embeddings.",
    # OpenInference retriever documents (LlamaIndex), prompt templates and
    # their variables, and the rendered prompt list of a completion call.
    "retrieval.documents.",
    "llm.prompt_template.",
    "llm.prompts",
    # Pydantic AI's own agent-span content.
    "final_result",
    "pydantic_ai.all_messages",
    # OpenInference CrewAI: the crew's inputs, its task descriptions and its
    # agents' role, goal and backstory.
    "crew_inputs",
    "crew_tasks",
    "crew_agents",
)


def is_content_key(key: str) -> bool:
    """True when ``key`` carries prompt, response or tool I/O content."""
    if key in CONTENT_KEYS:
        return True
    if key.startswith(CONTENT_PREFIXES):
        return not key.endswith(CONTENT_PREFIX_EXEMPT_SUFFIXES)
    return key.startswith(EXTRA_CONTENT_PREFIXES)
