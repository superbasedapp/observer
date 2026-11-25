# superbased SDK for TypeScript / Node

Send your LLM app's and agents' traces to superbased over OpenTelemetry: to
the Observer on your machine while you build, to your organization's (or
superbased's hosted) gateway in production, or to both.

- Package `@superbased/sdk`, ESM and CommonJS, typed. Apache-2.0.
- Node `>=20.6.0` (the `vercel-ai` instrumentation needs Node 22).
- A thin layer over OpenTelemetry JS 2.x: anything it sends, a plain OTel
  exporter pointed at superbased could send too, and it attaches to an
  OpenTelemetry setup you already have.

Full reference: [superbased.app/docs/sdk/typescript](https://superbased.app/docs/sdk/typescript).

## Install

The quickest way: in your app's folder run

```bash
npx @superbased/sdk setup
```

It finds your model libraries, installs the SDK and their instrumentation
with your package manager, sets up where traces go (your online dashboard
after one approval in the browser, or this computer's Observer), sends one
hello trace, prints its link, and prints the one line to add. Online, the
SDK key is kept in a file only your user account can read; it is never
printed. `--json` gives one JSON object per step for coding agents;
`--status`, `--forget` and `--online --replace` manage the key; Go and Java
apps use `--key-only`. `npx @superbased/sdk setup --help` lists the rest.

Or by hand:

```bash
npm install @superbased/sdk
```

To use this machine's Observer, turn on Settings > Your apps in its
dashboard (or `[observability] enabled = true`). The SDK sends spans to
`http://127.0.0.1:4318/v1/traces` unless you point it elsewhere.

## Quick start

The one line, CommonJS:

```js
require("@superbased/sdk").init(); // first line of the entry file
```

ESM (an ESM namespace cannot be patched after it loads, so the SDK loads first):

```bash
node --import @superbased/sdk/register server.js
```

Next.js, `instrumentation.ts` (and list the SDK and your model libraries in
`next.config`'s `serverExternalPackages`, so Node loads them itself):

```ts
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") await import("@superbased/sdk/register");
}
```

With that, every installed model library is instrumented and the service is
named after your package.json. Richer traces:

```ts
import { init, propagateAttributes, setUsage, shutdown, withAgentSpan, withLlmSpan } from "@superbased/sdk";

init({ serviceName: "support-bot", release: "1.4.0" }); // once at startup; idempotent

app.post("/chat", (req, res) =>
  propagateAttributes({ user: req.user.id, sessionId: req.body.thread }, () =>
    withAgentSpan("answer", {}, async () => {
      await withLlmSpan("chat", { model: "gpt-4o", provider: "openai", prompt: req.body.messages }, async (span) => {
        const r = await openai.chat.completions.create(/* ... */);
        setUsage(span, {
          inputTokens: r.usage?.prompt_tokens,
          outputTokens: r.usage?.completion_tokens,
          cacheReadTokens: r.usage?.prompt_tokens_details?.cached_tokens,
          responseId: r.id,
          response: r.choices[0].message.content ?? "",
        });
      });
    }),
  ),
);

await shutdown(); // in a short-lived process: flush before exit (bounded, never rejects)
```

Or let `instrument()` create the LLM spans for you (see below).

## Per-request attributes

```ts
propagateAttributes({ user, sessionId, tenant, tags: ["beta"], metadata: { plan: "pro" }, release, environment }, () => handle(req));
const scope = identify({ user: req.user.id }); // the rest of this request; scope.reset() undoes it
getCurrentAttributes();                          // what is in effect here
```

- Every span started inside gets the values (the SDK's, an instrumentation's,
  or your own OTel spans), carried through async work by AsyncLocalStorage.
  The span already active gets the values you just set too.
- Inner values win; tags are unioned; metadata merges per key (`null` removes
  a key). `undefined` leaves an outer value and `""` clears it.
- Keys: `sbo.user` (your app's end user; personal data), `session.id`,
  `sbo.tenant` (your own customer), `sbo.tags`, `sbo.metadata.<key>`,
  `sbo.release`, `sbo.environment`. Bounds: 256 chars a value, 32 tags of
  128, 32 metadata keys (key 128, value 512).
- `init()` takes the same seven as process-wide defaults, on the resource
  (release as `service.version`, environment as
  `deployment.environment.name`).

## Spans

| Helper | Kind | Writes |
|---|---|---|
| `withSpan(name, fn)`, `withSpan(name, { kind, attributes }, fn)` | any (default CHAIN) | `openinference.span.kind` |
| `observe(fn, { name, kind, attributes, captureIo })` | any | wraps a function; `captureIo` records arguments and result |
| `withLlmSpan(name, { model, provider, operation, prompt, system, attributes }, fn)` | LLM | `gen_ai.operation.name`, `gen_ai.request.model`, `gen_ai.provider.name` (+ legacy `gen_ai.system`, `llm.*`); `prompt` string to `input.value`, message list to `gen_ai.input.messages`, a `Prompt` from `getPrompt()` to the `sbo.prompt.*` stamp; `system` to `gen_ai.system_instructions` |
| `withToolSpan(name, { toolName, callId, arguments }, fn)` | TOOL | `execute_tool`, `gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.tool.call.arguments` |
| `withRetrieverSpan(name, { query }, fn)` | RETRIEVER | `retrieval`, `gen_ai.retrieval.query.text` |
| `withAgentSpan(name, { agentName, agentId }, fn)` | AGENT | `invoke_agent`, `gen_ai.agent.name`, `gen_ai.agent.id` |
| `withEmbeddingSpan(name, { model, provider }, fn)` | EMBEDDING | `embeddings`, model and provider |

A sync callback's value is returned synchronously; an async one returns a
promise. A failure records the exception once, sets ERROR and `error.type`;
success sets OK unless you set a status yourself.

Setters (no-ops on a span that is not recording):

- `setUsage(span, { inputTokens, outputTokens, totalTokens, cacheReadTokens, cacheWriteTokens, reasoningTokens, responseId, requestId, responseModel, finishReasons, costUsd, prompt, response })`.
  `inputTokens` is GROSS (it includes cache reads and writes, which are
  subsets of it); `outputTokens` includes `reasoningTokens`. `totalTokens` is
  optional (Observer derives input + output). A negative count is a
  RangeError. A reported `costUsd` is kept, but Observer's own price wins when
  it knows the model.
- `setContent(span, { prompt, response, toolArgs, toolResult })`,
  `setInput(span, v)`, `setOutput(span, v)` (on a RETRIEVER span: the
  documents), `setToolResult(span, r)`, `setDocuments(span, docs)`,
  `setRequestParams(span, { temperature, maxTokens, topP, ... })`.
- `getCurrentTraceId()`, `getCurrentSpanId()`.

The SDK writes only keys from Observer's vocabulary (the GenAI semantic
conventions pinned at `SEMCONV_COMMIT`, plus OpenInference names Observer
reads); `Attr` lists them.

## Auto-instrumentation: `init()` and `instrument()`

`init()` instruments by itself (`instrument` option, env
`SUPERBASED_INSTRUMENT`; the option wins):

| Setting | Provider | Result |
|---|---|---|
| `"off"` (also `false`, `0`, `none`, an empty list) | any | nothing |
| a list (`["openai", "langgraph"]` or `"openai,anthropic"`) | any | exactly those |
| `"auto"` (default) | your app registered its own OpenTelemetry provider | nothing (one note), so model spans never reach your other exporters; call `instrument([...])` |
| `"auto"` | the SDK's own | every installed target, except `openai-agents` (only when named) |

Nothing is imported to check: a library already loaded is instrumented at
`init()`, another on its first `require`; ESM apps start with
`--import @superbased/sdk/register`. `diagnostics().instrumented` gives each
target's status (`instrumented`, `pending` until its first load,
`skipped: auto_excluded | host_provider | not_installed`, ...). An unknown
name in the env list is skipped with a warning.

```ts
init({ instrument: "off" });
instrument(["openai", "anthropic", "langchain", "mcp", "vercel-ai", "gemini", "bedrock", "llama-index", "openai-agents"]); // or instrument() for every installed one
```

| Target | Install next to the framework | Notes |
|---|---|---|
| `openai` | `@arizeai/openinference-instrumentation-openai` | chat, completions, embeddings, responses |
| `anthropic` | `@arizeai/openinference-instrumentation-anthropic` | messages, with cache usage |
| `langchain` (also `langgraph`) | `@arizeai/openinference-instrumentation-langchain` | LangGraph runs are LangChain runs |
| `mcp` | `@arizeai/openinference-instrumentation-mcp` | carries the trace across MCP stdio / SSE / streamable HTTP, so a server's spans join the caller's trace |
| `vercel-ai` | `@ai-sdk/otel` | AI SDK v7 (Node 22+): registers its telemetry integration, which already emits the GenAI semconv |
| `gemini` (also `google-genai`) | `@traceloop/instrumentation-google-generativeai` | `@google/genai` (Node 22+), clients built after `instrument()`; ESM: hand over `{ ...(await import("@google/genai")) }` and build the client from that copy |
| `bedrock` | `@arizeai/openinference-instrumentation-bedrock` | `@aws-sdk/client-bedrock-runtime`: InvokeModel, Converse and their streams |
| `llama-index` (also `llamaindex`) | `@traceloop/instrumentation-llamaindex` | LlamaIndex.TS engines, retrievers, synthesizers and LLM `chat` |
| `openai-agents` (also `agents`) | `@arizeai/openinference-instrumentation-openai-agents` | `@openai/agents`: a tracing processor added beside yours |

CrewAI and Pydantic AI are Python-only frameworks; asking for them here is a
TypeError that says so (use the Python SDK).

- Returns `{ target: status }`: `instrumented`, `already`, `not-installed`
  (install the package above and the framework) or `error: ...`. It never
  throws, except a TypeError for an unknown target name.
- CommonJS apps: call it before or after `require("openai")`.
- ESM apps import their own copy of the framework, so hand it over:
  `instrument(["openai"], { modules: { openai: await import("openai") } })`
  (`anthropic`: `await import("@anthropic-ai/sdk")`; `langchain`:
  `@langchain/core/callbacks/manager`; `vercel-ai`: `{ ai, otel }`).
- The spans go through the SDK, so per-request attributes, sampling, masking
  and the destination apply to them. `uninstrument()` undoes it.

## Where your data goes: `destination`

| Value | The SDK exports to |
|---|---|
| `local` | this machine's Observer only |
| `online` | your organization's (or superbased's hosted) gateway only |
| `both` | each of them, through its own exporter: one being down never delays or drops the other |

The choice: `init({ destination })`, then `SUPERBASED_DESTINATION`, then the
SDK-held file `setup` wrote (below), then the default this machine's
Observer advertises (`both` when you have signed in, `local` otherwise, or
what you chose in its Settings), then `local`. While the SDK asks the
machine (at most 500 ms, loopback only), finished spans wait;
`await ready()` resolves once it knows.

- The gateway URL: `orgUrl`, `SUPERBASED_ORG_URL`, then the one the machine
  learned when you signed in. Spans go to `<orgUrl>/v1/traces`.
- The credential: `apiKey`, `SUPERBASED_API_KEY`, then the file the machine
  wrote at sign-in (read only when it is yours alone: not a symlink, mode
  0600), then the SDK-held file. It is sent only to the gateway its record
  names, never to the machine.
- The SDK-held file (`setup` writes it): `SUPERBASED_CREDENTIAL_FILE`, else
  `$XDG_CONFIG_HOME/superbased/sdk-credential` or
  `~/.config/superbased/sdk-credential`, on Windows
  `%LOCALAPPDATA%\superbased\sdk-credential`. Read only when it is yours
  alone (unix: no symlink, mode 0600, your uid; Windows: no link, inside
  your own `%LOCALAPPDATA%`). The machine's key wins over it; an expired key
  sends nothing and says to run `setup` again; from 14 days before expiry the
  SDK says so once. `diagnostics().sdkFile` gives its path and state, never
  the key.
- `online` without a gateway URL or a credential exports nothing; `both`
  exports to the machine only. Either way the SDK says so once and in
  `diagnostics().destinationProblems`. Fix: `observer sdk sign-in`, or
  set `SUPERBASED_ORG_URL` and `SUPERBASED_API_KEY`.
- An explicit `destination` of `online` or `both` still takes the gateway URL
  and the credential file from the machine when you did not give them.
- No destination chosen, no machine answering, and a gateway URL plus a
  credential given: `online` (`destinationSource: "inferred"`).
- An explicit `endpoint` only sets where the local destination sends.
- Your app's `OTEL_EXPORTER_OTLP_*` variables configure the local exporter,
  and only when the destination is `local`; they never redirect or add
  headers to the online one, and the key never rides to their endpoint.
- Control calls and `admit()` follow no redirect.

## Scores and feedback

```ts
const traceId = getCurrentTraceId();                    // keep it with your answer
await score("faithfulness", 0.92, { traceId, scorer: "judge", scorerVersion: "3" });
await feedback(false, { traceId, comment: "wrong city" }); // an end user's thumbs-down
```

- `score(name, value, { traceId, spanId, comment, kind, scorer, scorerVersion, runId, scoreId, timestamp })`:
  the value is a number, a boolean or a label; `traceId` defaults to the
  active trace and the score is trace-level unless you pass `spanId` (the
  same as Python).
- Written to every destination (`both`: to each, with the same id, so a
  retry or the second copy never doubles it). Resolves
  `{ ok, id, clientId, destinations, errors }`: `ok` only when every
  destination accepted it, `id` the stored `sc_...` id. It never throws: a
  score the rules refuse (a bad name, a `kind` that disagrees with the value,
  no trace) resolves `ok: false` with an error naming the rule's code
  (`invalid_name`, `kind_mismatch`, `invalid_trace_id`, ...) before any call.
- `flush()` waits for pending score writes.

## Where a trace's cost came from: `getTraceCost`

```ts
const cost = await getTraceCost(traceId);   // null when no destination has the trace
for (const s of cost?.spans ?? []) console.log(s.model, s.costUsd, s.costSource, s.costDeltaUsd);

// Calls through your organization's AI gateway: let the SDK carry the join key
const openai = new OpenAI({ baseURL: "https://gw.example/v1", fetch: gatewayFetch() });
```

- `costSource`: `gateway_exact` (the org AI
  gateway observed the provider's tokens), `proxy_exact` (this machine's
  proxy did), `computed` (priced from the span's tokens), `reported` (the
  instrumentation's own number, used only for an unpriced model) or `""`:
  unpriced, `costUsd: null`, never $0. `costDeltaUsd` is exact minus
  reported. `costProvenance` labels the trace (`mixed`, and `complete:
  false` when a span is unpriced).
- Reads the org (`GET /v1/sdk/traces/{id}/cost`, scope `sdk:read`) under
  `online`, the machine's trace detail under `local`, the org then the
  machine under `both`.
- `gatewayFetch()` sends an `X-SBO-Request-Id` when the call carries none and
  stamps the id the gateway answers with on the active span as `request_id`,
  the exact join key. `stampGatewayRequestId(response)` does the stamp for a
  response you got another way. It also names the end user and the service
  for the gateway's app budgets (`X-Superbased-User`: the per-request user,
  else `init`'s; `X-Superbased-Service`: the spans' `service.name`), keeping
  any such header the call already sets, and sends the active span's
  `traceparent`. Pass `gatewayFetch()` only to a client pointed at the
  gateway: the end user is PII.

## Model calls through the AI gateway

The AI gateway is the proxy your app's model calls go through: it prices each
call exactly, holds your app's budgets and applies your organization's model
and admission rules. `openAIOptions()` and `anthropicOptions()` are the options
for a client pointed at it:

```ts
import OpenAI from "openai";
import { init, openAIOptions } from "@superbased/sdk";

init({ serviceName: "support-bot" });
const openai = new OpenAI(await openAIOptions()); // the key: SUPERBASED_AI_GATEWAY_KEY
```

The address is resolved first set wins: `url`, then `SUPERBASED_AI_GATEWAY_URL`
(the gateway's address, without `/v1`), then your organization's address
`<org url>/ai/<upstream>` when the destination is `online`, then this
machine's app lane (`observer apps lane add`) when it is `local` or `both`.
The upstream defaults to `openai` or `anthropic` (`{ upstream }` names
another). With nothing to use they reject with `GatewayNotConfiguredError`:
they never fall back to the provider itself. On the machine's app lane the
client keeps the provider's own key (`OPENAI_API_KEY`); a remote gateway never
receives it. `gatewayBaseUrl("openai")` resolves just the base URL.

The options' `fetch` is `gatewayFetch()` that follows no redirect. A refusal
reads as a `GatewayRefusalError`: `gatewayRefusal(err)` on the model SDK's
error, `gatewayRefusalFromResponse(response)`, or `parseGatewayRefusal(status,
body, headers)`. `kind` is `budget_exceeded` (402, with `budget`),
`model_not_allowed`, `admission_denied`, `plan_required` (403),
`quota_exceeded` (429, with `retryAfterMs`) or `other`, and `planRefusal`
carries the plan detail when the plan is why.

## Experiments

```ts
const res = await runExperiment({
  name: "prompt-v7",
  dataset: "golden-qa",            // a dataset name or id, or inline items with datasetName
  task: async (input) => answer(input),
  evaluators: [function exact_match({ output, expectedOutput }) { return output === expectedOutput; }],
  failUnder: 0.9,                  // CI gate
});
console.log(res.passRate, res.summary);
```

- Creates a run on each destination (freezing a dataset snapshot unless
  `snapshotVersion` pins one), runs `task` on each item in its own trace, runs
  the evaluators in-process and posts each result as it finishes, then
  finishes the run. Under `both` the task runs once and each result goes to
  both sides.
- Evaluators return a number, a boolean, a label, `{ name, value, comment }`
  or a list of those; `{ name, version, evaluate }` names and versions the
  scorer.
- Inline items: pass `datasetName` to record them as a snapshot of that
  dataset; without it they run in-process only.
- A dataset found nowhere, or a run that cannot be created, rejects with
  `ExperimentError`; below `failUnder` it rejects with `ExperimentGateFailed`
  and sets `process.exitCode = 1`. The gate is strict by default: a run that
  scored nothing, a skipped destination or a result that was not accepted
  also fails it (`strict: false` gates on the pass rate alone). A CI key
  needs the `sdk:eval` scope.
- The key `observer sdk sign-in` stores has no `sdk:eval`, so the org answers
  403 `insufficient_scope`: that destination is skipped with an entry in
  `errors` and the run goes on with this machine under `both` (never a
  rejection; under `online` alone the result is empty).
- `getDataset(nameOrId, { version })` reads a snapshot's items; a dataset
  found nowhere rejects with `ExperimentError`.

## Prompts

```ts
const p = await getPrompt("support-reply", { label: "production", fallback: "Answer: {{question}}" });
const text = p.compile({ question });  // also stamps sbo.prompt.name / version / label on the active span
withLlmSpan("chat", { model: "gpt-4o", prompt: p }, () => /* ... */);
```

- By `label` (`production`, the default, or `staging`) or `version`, not both.
- Cached for `promptCacheTtlMs` (60 s); after that the cached copy is returned
  at once and revalidated in the background (stale-while-revalidate, ETag). A
  failed refresh keeps serving the cached copy; a 404 drops it.
- Staged rollout: when a label serves a candidate to a
  percentage of users, the SDK sends the SHA-256 of the current trace's user
  (else its session; or pass `user` / `sessionId`), never the id itself, and
  gets that key's side. It caches at most one copy per side (`candidate`,
  `base`, `unkeyed`) and buckets other keys itself with the rollout's salt,
  so a million users cost three fetches. `p.version` is the version served,
  `p.cohort` the side; both are stamped (`sbo.prompt.version`,
  `sbo.prompt.cohort`).
- Each destination keeps its own cached copy and revalidates against itself,
  so under `both` one side failing never drops a copy the other served.
- With nothing cached, a failed fetch throws `PromptNotFound` (no destination
  has it) or `PromptFetchError` (a transport or server failure), both
  `PromptError`s, unless you pass
  a `fallback` (returned with `isFallback: true`, never cached, stamps
  nothing).
- `compile()` fills `{{name}}` in one pass and throws `PromptCompileError`
  naming every missing variable. `p.text`, `p.messages`, `p.variables`,
  `p.config`, `p.version`, `p.label`.

## Trace context across services

```ts
await queue.send({ body, headers: inject() });                     // traceparent (+ baggage)
continueTrace(message.headers, () => withSpan("consume", work));   // join the caller's trace
```

`extract(headers)` returns the context; `getTraceparent()` the header value.
They always use W3C trace context, whatever propagator your app set. Values
set with `propagateAttributes({ ..., asBaggage: true })` travel as W3C
baggage and are restored by `continueTrace` (only use it for values the next
service may see).

## Sampling, filtering, masking

- `sampleRate` (0..1, `SUPERBASED_SAMPLE_RATE`, or `OTEL_TRACES_SAMPLER` +
  `_ARG`): keeps or drops whole traces by trace id, parent-based. The same
  trace id gets the same answer in every service and in both superbased SDKs.
- `shouldExport(span) => boolean`: return false to drop a finished span. A
  hook that throws keeps the span and is counted.
- `mask(value, key) => value`: rewrites every content value (prompts,
  responses, messages, tool arguments and results, documents; on spans and
  span events, from any instrumentation) before export. Return `null` to drop
  it. A hook that throws drops that value, never the span, and is counted:
  content is never sent unmasked by accident.
- Content is captured by default. `captureContent: false` removes it from
  every exported span, an instrumentation's included; `maxContentChars`
  clips each value.

These apply to what the SDK exports; a provider's other processors see the
original span.

## Pre-flight check: `admit()`

```ts
const v = await admit(userMessage, { user: "alice", session: "s1" });
if (!v.allowed) return v.reason;
```

- Goes where your destination points: this machine for `local`, your
  organization's gateway (`<orgUrl>/v1/sdk/admit`, with the key) for `online`
  or `both`, the machine when the gateway is not configured. An explicit
  `endpoint` or `orgUrl` wins.
- Never rejects. With no decision it admits, unless `failClosed: true`
  (`SUPERBASED_ADMISSION_FAIL_CLOSED=1`). `v.degraded` says why:
  `admission-unavailable` (403/404), `client-timeout`, `client-transport`,
  `client-http-error`, `client-bad-response`.
- Timeout 12 s, or what the server advertises. Inside a span the verdict is
  recorded on it (`sbo.admission.*`).

## An app that already uses OpenTelemetry

- No provider registered: `init()` registers its own (`diagnostics().mode` is `owned`).
- OTel JS 2.x providers take processors only at construction. Add the SDK's
  and `init()` exports through yours (`attached`):

  ```ts
  const provider = new NodeTracerProvider({ spanProcessors: [spanProcessor(), ...yourProcessors] });
  provider.register();
  init({ serviceName: "my-app" });
  ```
- An OTel JS 1.x provider (has `addSpanProcessor`): the SDK adds its processor (`attached`).
- Any other provider: the SDK keeps a private one for its own spans
  (`standalone`); they still join the active trace.

`shutdown()` stops only the SDK's exporters; your provider keeps running.
Calling `init()` again with the same settings does nothing; with different
settings it replaces the exporters in place.

## Flush, shutdown, diagnostics

- `await flush(timeoutMs?)`: export now and wait for pending score writes
  (await it at the end of a serverless handler). `await shutdown(timeoutMs?)`:
  flush and stop. Both are bounded by `shutdownTimeoutMs` and never reject.
- On `beforeExit` the SDK flushes by itself (`exitHook`). Call `shutdown()`
  before `process.exit()`. With an endpoint down, its in-flight request can
  keep the process alive up to `exportTimeoutMs` after the flush gives up.
- Failures are summarised in at most one `console.warn` line a minute
  (`debug: true` logs each).
- `diagnostics()`: `mode`, `destination`, `destinationSource`,
  `destinations`, `destinationProblems`, `pendingSpans`, `exportedSpans`,
  `failedExports`, `droppedSpans`, `sampledOutSpans`, `filteredSpans`,
  `shouldExportErrors`, `maskErrors`, `lastError`, `controlCalls`,
  `controlFailures`, `planRefusal`.

## When the plan does not include AI Apps

The organization's AI Apps gateway refuses ingest when its plan does not
include AI Apps (HTTP 403 `plan_required`) or this month's allowance is used
up (HTTP 429). The SDK reads that answer as a `PlanRefusalError`: a
`PlanRequiredError` for the first, an `AllowanceExceededError` for the
second. `message` says why, and `upgradeUrl` is where the organization's
billing owner changes the plan. It also has `kind`, `code`, `status`,
`capability`, `plan` (the plan in force), `allowance`, `plans` (the plans that
include more), and on a 429 `quota` and `retryAfterMs`.

- `getPrompt()`, `getDataset()` and `runExperiment()` reject with the error
  they always reject with (`PromptFetchError`, `ExperimentError`), now with
  `planRefusal` set (it is also the error's `cause`), so an existing `catch`
  still works.
- The calls that never reject carry it: `ScoreResult.planRefusal`,
  `Verdict.planRefusal` (from `admit()`) and `ExperimentResult.planRefusal`.
  `getTraceCost()` resolves to null, as for any failed read.
- Export never throws. A refused export (a 403) shows in
  `diagnostics().planRefusal` (`planRefusalAt` says when), and the SDK writes
  one `console.warn` line a minute with the message and the upgrade URL. The
  last refusal of any call is kept there. The OpenTelemetry exporter retries a
  429 and drops its body, so an allowance refusal on export is counted as a
  failed export but not read as a plan refusal.

```ts
try {
  await getPrompt("support-reply");
} catch (err) {
  if (err instanceof PromptFetchError && err.planRefusal) console.error(err.planRefusal.message, err.planRefusal.upgradeUrl);
}
```

`parsePlanRefusal(status, body, headers?)` reads a refusal from any HTTP
answer, and returns null for anything else.

## Settings

Every option has an environment variable. An explicit option wins, then the
`SUPERBASED_*` variable, then the standard OpenTelemetry one, then (for the
destination, gateway URL and credential) what this machine advertises, then
the default. `settings()` returns what was resolved. Durations are
milliseconds.

| `init()` option | Environment | Default |
|---|---|---|
| `destination` | `SUPERBASED_DESTINATION` | the machine's default, else `local` |
| `orgUrl` | `SUPERBASED_ORG_URL` | the machine's, else none |
| `apiKey` | `SUPERBASED_API_KEY` | the machine's credential file, else none |
| `endpoint` (the local destination's URL) | `SUPERBASED_OTLP_ENDPOINT`; for destination `local` only also `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT` (+ `/v1/traces`) | the machine's advertised receiver, else `http://127.0.0.1:4318/v1/traces` |
| `headers` | `SUPERBASED_OTLP_HEADERS`; for destination `local` only also `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TRACES_HEADERS` (merged; option on top) | none |
| `nodeUrl` | `SUPERBASED_NODE_URL` | `http://127.0.0.1:8081` |
| `discover` | `SUPERBASED_DISCOVER` | on |
| `discoverTimeoutMs` | `SUPERBASED_DISCOVER_TIMEOUT_MS` | 500 |
| `serviceName` | `SUPERBASED_SERVICE_NAME`, `OTEL_SERVICE_NAME`, `service.name` in `OTEL_RESOURCE_ATTRIBUTES` | the nearest package.json's `name` (scope dropped), else the entry script's folder, else `custom-app` (`diagnostics().serviceNameSource`) |
| `instrument` | `SUPERBASED_INSTRUMENT` | `auto` |
| none | `SUPERBASED_CREDENTIAL_FILE` | the SDK-held file's path (above) |
| none | `SUPERBASED_FIRST_TRACE_LINK` | on: once per process, after the first trace is exported, one stderr line with its link, only on a terminal and not under `CI` |
| `resourceAttributes` | `OTEL_RESOURCE_ATTRIBUTES` | none |
| `user` | `SUPERBASED_USER` | none |
| `sessionId` | `SUPERBASED_SESSION_ID` | none |
| `tenant` | `SUPERBASED_TENANT` | none |
| `tags` | `SUPERBASED_TAGS` (comma list) | none |
| `metadata` | `SUPERBASED_METADATA` (`k=v,k2=v2`) | none |
| `release` | `SUPERBASED_RELEASE` | none |
| `environment` | `SUPERBASED_ENVIRONMENT` | none |
| `captureContent` | `SUPERBASED_CAPTURE_CONTENT` (legacy `OBSERVER_CAPTURE_CONTENT`) | on |
| `maxContentChars` | `SUPERBASED_MAX_CONTENT_CHARS` | 8000 (0 = no clip) |
| `sampleRate` | `SUPERBASED_SAMPLE_RATE`, `OTEL_TRACES_SAMPLER` + `OTEL_TRACES_SAMPLER_ARG` | 1 |
| `mask`, `shouldExport` | code only | none |
| `exportTimeoutMs` | `SUPERBASED_EXPORT_TIMEOUT_MS`, `OTEL_EXPORTER_OTLP_TRACES_TIMEOUT`, `OTEL_EXPORTER_OTLP_TIMEOUT` | 5000 |
| `shutdownTimeoutMs` | `SUPERBASED_SHUTDOWN_TIMEOUT_MS` | 2000 |
| `apiTimeoutMs` (scores, prompts, datasets, experiments) | `SUPERBASED_API_TIMEOUT_MS` | 5000 |
| `promptCacheTtlMs` | `SUPERBASED_PROMPT_CACHE_TTL_MS` | 60000 |
| `exitHook` | `SUPERBASED_EXIT_HOOK` | on |
| `debug` | `SUPERBASED_DEBUG` | off |
| `console` (also print spans) | `SUPERBASED_CONSOLE` | off |
| `exporter`, `tracerProvider` | code only | OTLP/HTTP; the global provider |

`admit()` options: `endpoint` (`SUPERBASED_ADMISSION_ENDPOINT`), `orgUrl`
(`SUPERBASED_ORG_URL`), `apiKey` (`SUPERBASED_API_KEY`), `timeoutMs` (the
server's advertised timeout, else 12000), `failClosed`
(`SUPERBASED_ADMISSION_FAIL_CLOSED`, off).

## Changes in 0.2.0

The SDK quickstart:

- `npx @superbased/sdk setup` (the `superbased-sdk` bin; Node built-ins
  only, never loaded by the runtime).
- `init()` instruments every installed model library when the SDK owns the
  tracer provider. **Effect on existing apps:** one that called
  `instrument([...])` keeps its spans but also gets spans for installed
  libraries it left out (set `init({ instrument: [...] })` to keep the old
  set); one that wrapped model calls with `withLlmSpan` by hand now sees
  them twice (set `init({ instrument: "off" })`); one with its own
  OpenTelemetry provider is unchanged.
- `@superbased/sdk/register` for ESM apps and Next.js.
- The service name defaults from package.json (then the entry folder),
  not `custom-app`: an app that relied on `custom-app` starts a new service
  in the dashboard; set `serviceName` to keep the old one.
- The SDK-held credential file (rung 3 of the destination and of the
  credential), read on Windows too.
- The first-trace line on stderr (a terminal only; `SUPERBASED_FIRST_TRACE_LINK=0` turns it off).

## Echo-guard caveat

Never set the resource attribute `sbo.emitted_by=observer`: it marks
Observer's own telemetry, and a resource carrying it is dropped at ingestion.
The SDK sets `sbo.sdk="superbased-typescript"`.

## Development

```bash
npm ci              # from the committed lockfile
npm test            # build (ESM + CJS) and run every node --test suite, offline
npm run typecheck
npm run example     # compile and run examples/quickstart.ts
```

`SUPERBASED_RECORD_FIXTURES=1 npm test` re-records the instrumentation
fixtures (`sdk/contract/fixtures/instrument/*-ts.json`) after an upgrade;
review the diff.
