// Package genaiattr is the one owner of every GenAI span-attribute key and
// dialect Observer reads (plan of record
// docs/plans/plane-a-sdk-buildout/02-plan-of-record-2026-11-19.md, principle
// 2 "one attribute vocabulary"). The node mapper (internal/obs/ingest), the
// gateway mapper and its convention profiles (internal/orgserver/gateway,
// internal/orgserver/gateway/convention) and the OTel-direct vendor rows
// (internal/otlpvendor, read by internal/oteldirect) all take their key lists
// from here: one key list, every caller.
//
// # Pinned semantic conventions
//
// The GenAI dialect is pinned to open-telemetry/semantic-conventions-genai at
// commit 76e0c19e7fe11dc693fe258642363a438af4d3aa (2026-11-19), registry
// schema https://opentelemetry.io/schemas/gen-ai-dev/1.42.0-dev (stability
// development), which depends on the core semantic conventions v1.45.0 for
// error.type. These are the names an instrumentation emits under
// OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental: gen_ai.provider.name,
// gen_ai.input.messages / gen_ai.output.messages / gen_ai.system_instructions
// as structured (array / kvlist) values, gen_ai.tool.call.arguments /
// gen_ai.tool.call.result, the dotted usage keys
// gen_ai.usage.cache_read.input_tokens, gen_ai.usage.cache_write.input_tokens
// and gen_ai.usage.reasoning.output_tokens. SemconvCommit, SemconvSchemaURL
// and SemconvRepo state the pin in code; the SDKs emit exactly this version.
//
// The mappers ACCEPT older spellings too (principle 8): the renamed-away GenAI
// names (gen_ai.system, gen_ai.usage.prompt_tokens / completion_tokens,
// gen_ai.usage.cache_creation.input_tokens, the flat and indexed
// gen_ai.prompt / gen_ai.completion), OpenInference (llm.*, input.value /
// output.value, tool.*, openinference.span.kind) and Traceloop / OpenLLMetry
// (llm.usage.*, gen_ai.usage.cache_*_input_tokens, traceloop.*). Each key in
// the table carries its Dialect so a caller can view one vocabulary
// (KeysWhere). The langfuse.* dialect (task W5-2, langfuse.go) is pinned to
// the Langfuse SDK sources it was read from: Python langfuse 5.2.0 / 4.18.0 /
// 3.15.0 and JS @langfuse/* 6.1.1. Its usage_details and cost_details are
// JSON objects decoded by a shape table (Langfuse's buckets are disjoint, so
// the gross input is the sum of its input buckets).
//
// # Token buckets
//
// The usage buckets follow the GenAI semconv definition, which OpenInference
// shares (llm.token_count.prompt_details.* are subsets of
// llm.token_count.prompt):
//
//   - Input is the GROSS input count: it includes cache-read and cache-write
//     tokens. CacheRead and CacheWrite are SUBSETS of Input, never addends.
//   - Output includes Reasoning; Reasoning is a SUBSET of Output.
//   - Total, when no total attribute is present, is DERIVED as Input +
//     Output (TotalDerived = true). Cache and reasoning tokens are never added
//     on top, so a cached call is never double-counted.
//   - Every bucket is first-present-wins over its ordered key list: an
//     emitter that sets both the dotted and the underscore cache key yields
//     ONE value, never a sum.
//
// ReadUsage keeps every count as reported and resolves the counts' SHAPE
// (shape.go, Usage.InputShape / OutputShape): a reported total that equals the
// counts only when the input excludes the cache tokens, or the output excludes
// the reasoning tokens, marks that count net. A consumer nets or adds by that
// fact, never by a provider name (review finding E-18). The node span mapper
// (internal/obs/ingest) stores the GROSS counts (spanprice.GrossOf), so a stored
// span needs no shape column; the org gateway carries the shape to its pricer.
//
// Identity keys (tenant, end user) come from internal/otelident; the session,
// thread, service, application and project-root lists here move there with
// task W1a-2.
//
// # Purity
//
// The package is pure data and value rendering: no database/sql, net/http,
// fsnotify, and never internal/obs (tests/invariant/obs_boundary_test.go),
// pinned by imports_test.go. Its only non-stdlib imports are the OTLP common
// proto types and internal/otelident.
package genaiattr
