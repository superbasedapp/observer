/**
 * Span helpers: `withSpan` / `observe` and the typed helpers for LLM, tool,
 * retriever, agent and embedding spans. Every key they write is in attrs.ts.
 */

import { SpanStatusCode, trace, type Attributes, type Span } from "@opentelemetry/api";

import { K, REQUEST_PARAMS } from "./attrs.js";
import { policyStats } from "./policy.js";
import { contentText, runtime, tracer, truncateContent } from "./runtime.js";

/** Canonical OpenInference span kinds (Observer normalizes either case). */
export const Kind = {
  LLM: "LLM",
  TOOL: "TOOL",
  RETRIEVER: "RETRIEVER",
  EMBEDDING: "EMBEDDING",
  CHAIN: "CHAIN",
  AGENT: "AGENT",
  GUARDRAIL: "GUARDRAIL",
  EVALUATOR: "EVALUATOR",
} as const;
export type SpanKind = (typeof Kind)[keyof typeof Kind];

function statusUnset(span: Span): boolean {
  const st = (span as unknown as { status?: { code?: number } }).status;
  return !st || st.code === undefined || st.code === SpanStatusCode.UNSET;
}

function markOk(span: Span): void {
  try {
    if (statusUnset(span)) span.setStatus({ code: SpanStatusCode.OK });
  } catch {
    // ignore
  }
}

function markError(span: Span, err: unknown): void {
  try {
    const e = err instanceof Error ? err : new Error(String(err));
    span.recordException(e);
    span.setStatus({ code: SpanStatusCode.ERROR, message: `${e.name}: ${e.message}` });
    const attrs = (span as unknown as { attributes?: Record<string, unknown> }).attributes ?? {};
    if (!(K.errorType in attrs)) span.setAttribute(K.errorType, e.name || "Error");
  } catch {
    // ignore
  }
}

function isThenable(v: unknown): v is PromiseLike<unknown> {
  return v != null && (typeof v === "object" || typeof v === "function") && typeof (v as { then?: unknown }).then === "function";
}

function clean(attrs: Record<string, unknown>): Attributes {
  const out: Attributes = {};
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === "") continue;
    out[k] = v as Attributes[string];
  }
  return out;
}

export interface SpanOptions {
  kind?: SpanKind;
  attributes?: Record<string, unknown>;
}

function runSpan<T>(name: string, kind: SpanKind, fn: (span: Span) => T, attributes: Record<string, unknown> = {}): T {
  return tracer().startActiveSpan(name, { attributes: clean({ [K.spanKind]: kind, ...attributes }) }, (span): T => {
    let out: T;
    try {
      out = fn(span);
    } catch (err) {
      markError(span, err);
      span.end();
      throw err;
    }
    if (isThenable(out)) {
      return Promise.resolve(out).then(
        (v) => {
          markOk(span);
          span.end();
          return v;
        },
        (err: unknown) => {
          markError(span, err);
          span.end();
          throw err;
        },
      ) as T;
    }
    markOk(span);
    span.end();
    return out;
  });
}

/**
 * Run `fn` inside a span. A sync callback's value is returned synchronously;
 * a promise is returned for an async one. Records an exception once, sets
 * ERROR and `error.type` on failure; sets OK on success unless `fn` already
 * set a status (an ERROR you set is kept).
 *
 * ```ts
 * withSpan("plan", (span) => plan());
 * withSpan("search", { kind: Kind.TOOL, attributes: { "tool.name": "search" } }, () => search(q));
 * ```
 *
 * The A7 form `withSpan(name, kind, fn, attributes)` still works.
 */
export function withSpan<T>(name: string, fn: (span: Span) => T): T;
export function withSpan<T>(name: string, opts: SpanOptions, fn: (span: Span) => T): T;
export function withSpan<T>(name: string, kind: SpanKind, fn: (span: Span) => T, attributes?: Record<string, unknown>): T;
export function withSpan<T>(
  name: string,
  a: ((span: Span) => T) | SpanOptions | SpanKind,
  b?: (span: Span) => T,
  attributes?: Record<string, unknown>,
): T {
  if (typeof a === "function") return runSpan(name, Kind.CHAIN, a);
  if (typeof a === "string") return runSpan(name, a, b!, attributes);
  return runSpan(name, a?.kind ?? Kind.CHAIN, b!, a?.attributes);
}

export interface ObserveOptions {
  /** Span name (default: the function's name, else "observe"). */
  name?: string;
  kind?: SpanKind;
  attributes?: Record<string, unknown>;
  /** Record the call's arguments as `input.value` and its result as `output.value` (subject to captureContent). Default false. */
  captureIo?: boolean;
}

/**
 * Wrap a function so each call runs in a span. Works for sync and async
 * functions (the span covers the awaited result); `this` and arguments pass
 * through unchanged.
 *
 * ```ts
 * const answer = observe(async (q: string) => llm(q), { name: "answer", kind: Kind.AGENT });
 * ```
 */
export function observe<A extends unknown[], R>(fn: (...args: A) => R, opts: ObserveOptions = {}): (...args: A) => R {
  const name = opts.name || fn.name || "observe";
  const kind = opts.kind ?? Kind.CHAIN;
  const wrapped = function (this: unknown, ...args: A): R {
    return runSpan(
      name,
      kind,
      (span) => {
        if (opts.captureIo) setInput(span, args.length === 1 ? args[0] : args);
        const out = fn.apply(this, args);
        if (!opts.captureIo) return out;
        if (isThenable(out)) {
          return Promise.resolve(out).then((v) => {
            setOutput(span, v);
            return v;
          }) as R;
        }
        setOutput(span, out);
        return out;
      },
      opts.attributes,
    );
  };
  Object.defineProperty(wrapped, "name", { value: fn.name, configurable: true });
  return wrapped;
}

function recording(span: Span | undefined): span is Span {
  try {
    if (!span) return false;
    return typeof span.isRecording === "function" ? span.isRecording() : true;
  } catch {
    return false;
  }
}

function spanKindOf(span: Span): string {
  const a = (span as unknown as { attributes?: Record<string, unknown> }).attributes ?? {};
  return String(a[K.spanKind] ?? "").toUpperCase();
}

function contentAttr(span: Span, key: string, v: unknown): void {
  if (!runtime.captureContent || v === undefined || v === null || !recording(span)) return;
  try {
    span.setAttribute(key, truncateContent(contentText(v)));
  } catch {
    // never raise
  }
}

/** Set a span's serialized input (`input.value`), subject to captureContent. */
export function setInput(span: Span, input: unknown): void {
  contentAttr(span, K.inputValue, input);
}

/** Set a span's serialized output (`output.value`; on a RETRIEVER span, `gen_ai.retrieval.documents`). */
export function setOutput(span: Span, output: unknown): void {
  contentAttr(span, recording(span) && spanKindOf(span) === Kind.RETRIEVER ? K.retrievalDocuments : K.outputValue, output);
}

// --- LLM ---------------------------------------------------------------------

/** Anything that can stamp a prompt's identity on a span (a fetched {@link Prompt}). */
export interface PromptRef {
  stamp(span?: Span): void;
}

/** A registry prompt (anything with `stamp(span)`), not request content. */
function isPromptRef(v: unknown): v is PromptRef {
  return v !== null && typeof v === "object" && !Array.isArray(v) && typeof (v as { stamp?: unknown }).stamp === "function";
}

export interface LlmInfo {
  model?: string;
  provider?: string;
  /** `gen_ai.operation.name` (default "chat"). */
  operation?: string;
  /**
   * The request: a string (`input.value`) or a message list
   * (`gen_ai.input.messages`); content. A `Prompt` from `getPrompt()` stamps
   * `sbo.prompt.*` on the span and records no content (the contract's
   * `llm_span(prompt=<Prompt>)`; review E-49).
   */
  prompt?: string | unknown[] | PromptRef;
  /** System instructions (`gen_ai.system_instructions`); content. */
  system?: unknown;
  /** @deprecated Pass the fetched prompt as `prompt`; still read (review E-49). */
  promptRef?: PromptRef;
  attributes?: Record<string, unknown>;
}

/** withSpan for an LLM call: pre-tags `gen_ai.operation.name`, model and
 * `gen_ai.provider.name` (plus the legacy `gen_ai.system`) and the
 * OpenInference `llm.*` keys. Pass the response via setUsage({ response }). */
export function withLlmSpan<T>(name: string, info: LlmInfo, fn: (span: Span) => T): T {
  const attrs: Record<string, unknown> = { [K.operation]: info.operation ?? "chat" };
  if (info.model) {
    attrs[K.requestModel] = info.model;
    attrs[K.oiModel] = info.model;
  }
  if (info.provider) {
    attrs[K.provider] = info.provider;
    attrs[K.systemLegacy] = info.provider;
    attrs[K.oiProvider] = info.provider;
  }
  const registry = isPromptRef(info.prompt) ? info.prompt : info.promptRef;
  const content = isPromptRef(info.prompt) ? undefined : info.prompt;
  if (runtime.captureContent) {
    if (Array.isArray(content)) attrs[K.inputMessages] = truncateContent(contentText(content));
    else if (content != null) attrs[K.inputValue] = truncateContent(String(content));
    if (info.system != null) attrs[K.systemInstructions] = truncateContent(contentText(info.system));
  }
  Object.assign(attrs, info.attributes ?? {});
  return runSpan(name, Kind.LLM, (span) => {
    if (registry) registry.stamp(span);
    return fn(span);
  }, attrs);
}

export interface Usage {
  /**
   * Input tokens, GROSS: including cache-read and cache-write tokens (the
   * GenAI semconv bucket). For a provider that reports net input (Anthropic),
   * pass input + cache read + cache write.
   */
  inputTokens?: number;
  /** Output tokens, including reasoning tokens. */
  outputTokens?: number;
  /** Optional; Observer derives input + output when it is absent. */
  totalTokens?: number;
  /** Input tokens served from the prompt cache (a subset of inputTokens). */
  cacheReadTokens?: number;
  /** Input tokens written to the prompt cache (a subset of inputTokens). */
  cacheWriteTokens?: number;
  /** Reasoning / thinking tokens (a subset of outputTokens). */
  reasoningTokens?: number;
  responseId?: string;
  requestId?: string;
  responseModel?: string;
  /** Why the model stopped (`gen_ai.response.finish_reasons`). */
  finishReasons?: string[];
  /** A reported cost. Observer prefers its own computed cost when it prices the model. */
  costUsd?: number;
  /** Request body; content. */
  prompt?: string | unknown[];
  /** Response body; content. */
  response?: string | unknown[];
}

const TOKEN_FIELDS = [
  ["inputTokens", K.inputTokens],
  ["outputTokens", K.outputTokens],
  ["totalTokens", K.totalTokens],
  ["cacheReadTokens", K.cacheReadTokens],
  ["cacheWriteTokens", K.cacheWriteTokens],
  ["reasoningTokens", K.reasoningTokens],
] as const;

let netInputWarned = false;

/** Reset the once-per-process net-input warning (tests only). */
export function _resetNetInputWarningForTests(): void {
  netInputWarned = false;
}

const count = (v: number | null | undefined): number | undefined =>
  v != null && Number.isFinite(v) ? Math.trunc(v) : undefined;

/** The usage with a GROSS input count: `inputTokens` as given, unless it is
 * below its own cache parts. Then it cannot be gross (it is a NET count, as
 * Anthropic's `usage.input_tokens` is), so the cache parts are added (and to a
 * `totalTokens` equal to that net input + output), the correction is counted
 * (`diagnostics().usageNetInputCorrected`) and a warning is logged once. */
function grossUsage(u: Usage): Usage {
  const input = count(u.inputTokens);
  const cache = (count(u.cacheReadTokens) ?? 0) + (count(u.cacheWriteTokens) ?? 0);
  if (input === undefined || input >= cache) return u;
  policyStats.usageNetInputCorrected += 1;
  if (!netInputWarned) {
    netInputWarned = true;
    console.warn(
      `@superbased/sdk: setUsage inputTokens ${input} is below cacheReadTokens + cacheWriteTokens (${cache}); ` +
        `recorded as a net count (input + cache = ${input + cache}). Pass the gross input: for Anthropic, ` +
        "usage.input_tokens + cache_creation_input_tokens + cache_read_input_tokens.",
    );
  }
  const out: Usage = { ...u, inputTokens: input + cache };
  const total = count(u.totalTokens);
  if (total !== undefined && total === input + (count(u.outputTokens) ?? 0)) out.totalTokens = total + cache;
  return out;
}

/** Record token usage / ids on an LLM span with the keys Observer reconciles
 * against proxy turns. `responseId` (the provider message id) doubles as the
 * dedup key when no `requestId` is set. A negative count is a RangeError; a
 * fraction is truncated. `inputTokens` is the GROSS input (cache reads and
 * writes included); one below `cacheReadTokens + cacheWriteTokens` is read as
 * a net count (Anthropic's `usage.input_tokens`), recorded as input + cache,
 * counted in `diagnostics().usageNetInputCorrected` and warned about once. */
export function setUsage(span: Span, u: Usage): void {
  for (const [field, key] of TOKEN_FIELDS) {
    const v = u[field];
    if (v != null && Number.isFinite(v) && v < 0) throw new RangeError(`@superbased/sdk: ${field} must not be negative`);
  }
  if (!recording(span)) return;
  u = grossUsage(u);
  try {
    for (const [field, key] of TOKEN_FIELDS) {
      const v = u[field];
      if (v != null && Number.isFinite(v)) span.setAttribute(key, Math.trunc(v));
    }
    if (u.responseId) span.setAttribute(K.responseId, u.responseId);
    if (u.requestId) span.setAttribute(K.requestId, u.requestId);
    if (u.responseModel) span.setAttribute(K.responseModel, u.responseModel);
    if (u.finishReasons?.length) span.setAttribute(K.finishReasons, u.finishReasons.map(String));
    if (u.costUsd != null && Number.isFinite(u.costUsd)) span.setAttribute(K.cost, u.costUsd);
  } catch {
    // never raise
  }
  if (u.prompt != null || u.response != null) setContent(span, { prompt: u.prompt, response: u.response });
}

export interface Content {
  /** LLM request: a string or a message list (or, on a TOOL span, the tool args). */
  prompt?: unknown;
  /** LLM response: a string or a message list (or, on a TOOL span, the tool result). */
  response?: unknown;
  /** Tool call arguments. */
  toolArgs?: unknown;
  /** Tool call result. */
  toolResult?: unknown;
}

/** Attach request/response bodies (LLM span: `input.value` / `output.value`,
 * or `gen_ai.input.messages` / `gen_ai.output.messages` for a message list;
 * TOOL span: `gen_ai.tool.call.arguments` / `.result`). No-op when capture is
 * off; each body is clipped to maxContentChars. */
export function setContent(span: Span, c: Content): void {
  if (!runtime.captureContent || !recording(span)) return;
  const tool = spanKindOf(span) === Kind.TOOL;
  const req = c.prompt ?? c.toolArgs;
  const res = c.response ?? c.toolResult;
  // Only a list whose every element is an object is a message list.
  const isMessages = (v: unknown): boolean => Array.isArray(v) && v.every((m) => m !== null && typeof m === "object" && !Array.isArray(m));
  if (req != null) contentAttr(span, tool ? K.toolArguments : isMessages(req) ? K.inputMessages : K.inputValue, req);
  if (res != null) contentAttr(span, tool ? K.toolResult : isMessages(res) ? K.outputMessages : K.outputValue, res);
}

export type RequestParams = { [P in keyof typeof REQUEST_PARAMS]?: P extends "stopSequences" ? string[] : P extends "stream" ? boolean : P extends "reasoningLevel" ? string : number };

/** Record the request's sampling parameters (`gen_ai.request.*`). */
export function setRequestParams(span: Span, p: RequestParams): void {
  if (!recording(span)) return;
  try {
    for (const [name, key] of Object.entries(REQUEST_PARAMS)) {
      const v = (p as Record<string, unknown>)[name];
      if (v === undefined || v === null) continue;
      if (Array.isArray(v)) span.setAttribute(key, v.map(String));
      else if (typeof v === "number" || typeof v === "boolean" || typeof v === "string") span.setAttribute(key, v);
    }
  } catch {
    // never raise
  }
}

// --- tool ----------------------------------------------------------------------

export interface ToolInfo {
  /** The tool's name (default: the span name). */
  toolName?: string;
  /** The model's tool-call id, when the call came from a model. */
  callId?: string;
  /** The call's arguments (any JSON value); content. */
  arguments?: unknown;
  attributes?: Record<string, unknown>;
}

/** withSpan for a tool call (`execute_tool`). Record the result with setToolResult. */
export function withToolSpan<T>(name: string, info: ToolInfo, fn: (span: Span) => T): T {
  const tool = info.toolName || name;
  const attrs: Record<string, unknown> = {
    [K.operation]: "execute_tool",
    [K.toolName]: tool,
    [K.oiToolName]: tool,
    [K.toolCallId]: info.callId,
  };
  if (info.arguments !== undefined && runtime.captureContent) attrs[K.toolArguments] = truncateContent(contentText(info.arguments));
  Object.assign(attrs, info.attributes ?? {});
  return runSpan(name, Kind.TOOL, fn, attrs);
}

/** Record a tool call's result (`gen_ai.tool.call.result`); content. */
export function setToolResult(span: Span, result: unknown): void {
  contentAttr(span, K.toolResult, result);
}

// --- retriever -----------------------------------------------------------------

export interface RetrieverInfo {
  /** The query text; content. */
  query?: string;
  attributes?: Record<string, unknown>;
}

/** One retrieved document. */
export interface Document {
  id?: string;
  content?: string;
  score?: number;
  metadata?: Record<string, unknown>;
}

/** withSpan for a retrieval (`retrieval`). Record what came back with setDocuments. */
export function withRetrieverSpan<T>(name: string, info: RetrieverInfo, fn: (span: Span) => T): T {
  const attrs: Record<string, unknown> = { [K.operation]: "retrieval" };
  if (info.query != null && runtime.captureContent) attrs[K.retrievalQuery] = truncateContent(String(info.query));
  Object.assign(attrs, info.attributes ?? {});
  return runSpan(name, Kind.RETRIEVER, fn, attrs);
}

/** Record retrieved documents (`gen_ai.retrieval.documents`, a JSON array); content. */
export function setDocuments(span: Span, docs: Array<string | Document>): void {
  contentAttr(span, K.retrievalDocuments, docs.map((d) => (typeof d === "string" ? { content: d } : d)));
}

// --- agent ---------------------------------------------------------------------

export interface AgentInfo {
  /** The agent's name (default: the span name). */
  agentName?: string;
  agentId?: string;
  attributes?: Record<string, unknown>;
}

/** withSpan for an agent run (`invoke_agent`). Record input and answer with setInput / setOutput. */
export function withAgentSpan<T>(name: string, info: AgentInfo, fn: (span: Span) => T): T {
  const agent = info.agentName || name;
  const attrs: Record<string, unknown> = {
    [K.operation]: "invoke_agent",
    [K.agentName]: agent,
    [K.oiAgentName]: agent,
    [K.agentId]: info.agentId,
    ...(info.attributes ?? {}),
  };
  return runSpan(name, Kind.AGENT, fn, attrs);
}

// --- embedding -----------------------------------------------------------------

export interface EmbeddingInfo {
  model?: string;
  provider?: string;
  attributes?: Record<string, unknown>;
}

/** withSpan for an embedding call (`embeddings`). Record tokens with setUsage({ inputTokens }). */
export function withEmbeddingSpan<T>(name: string, info: EmbeddingInfo, fn: (span: Span) => T): T {
  const attrs: Record<string, unknown> = {
    [K.operation]: "embeddings",
    [K.requestModel]: info.model,
    [K.provider]: info.provider,
    [K.systemLegacy]: info.provider,
    ...(info.attributes ?? {}),
  };
  return runSpan(name, Kind.EMBEDDING, fn, attrs);
}

// --- ids ---------------------------------------------------------------------------

function validId(id: string | undefined, len: number): string {
  return id && id.length === len && /^[0-9a-f]+$/.test(id) && !/^0+$/.test(id) ? id : "";
}

/** The active trace id (32 hex), or "" outside a span. Use it to attach a score later. */
export function getCurrentTraceId(): string {
  try {
    return validId(trace.getActiveSpan()?.spanContext().traceId, 32);
  } catch {
    return "";
  }
}

/** The active span id (16 hex), or "" outside a span. */
export function getCurrentSpanId(): string {
  try {
    return validId(trace.getActiveSpan()?.spanContext().spanId, 16);
  } catch {
    return "";
  }
}
