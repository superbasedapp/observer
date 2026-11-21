# superbased SDK for Python

Traces, scores, prompts and experiments for LLM apps and agents, on standard
OpenTelemetry. Send to the superbased app on your own machine while you
develop, to your organization's gateway in production, or to both.

Distribution `superbased-sdk`, import `superbased_sdk`. Apache-2.0. Python 3.9
to 3.13.

- Guides: [superbased.app/docs/sdk/python](https://superbased.app/docs/sdk/python)
  (tracing, destinations, auto-instrumentation, scores and experiments,
  prompts, cost, versioning).
- The same API in TypeScript:
  [superbased.app/docs/sdk/typescript](https://superbased.app/docs/sdk/typescript).

## Install

The package is not on PyPI yet. Install from a checkout:

```bash
pip install -e sdk/python
```

Auto-instrumentation for a framework is an extra:

```bash
pip install -e "sdk/python[openai]"   # also [anthropic], [langchain] (LangGraph too), [mcp], [gemini],
                                      # [bedrock], [llama-index], [crewai], [pydantic-ai], [openai-agents], [all]
```

## Quick start

```python
import superbased_sdk as sb

sb.init(service_name="support-bot")      # once at startup; idempotent
sb.instrument(["openai"])                # optional: trace every OpenAI call

def handle(request):
    with sb.propagate_attributes(user=request.user_id, session_id=request.chat_id):
        with sb.agent_span("support"):
            with sb.llm_span("answer", model="gpt-4o", provider="openai",
                             prompt=[{"role": "user", "content": request.text}]) as s:
                resp = client.chat.completions.create(...)
                sb.set_usage(s, input_tokens=resp.usage.prompt_tokens,
                             output_tokens=resp.usage.completion_tokens,
                             cache_read_tokens=resp.usage.prompt_tokens_details.cached_tokens,
                             response_id=resp.id, response=resp.choices[0].message.content)
            return resp, sb.get_current_trace_id()   # hand the trace id to the browser

# later, when the user clicks thumbs-up:
sb.feedback(True, trace_id=trace_id_from_browser)

sb.shutdown()    # flush before a short-lived process exits
```

On your own machine, turn on "Your apps" in the superbased dashboard Settings
(or set `[observability] enabled = true` in `~/.observer/config.toml`): it
receives spans on `127.0.0.1:4318`, the SDK's default.

## What is in the box

| Area | Functions |
|---|---|
| Setup | `init`, `flush`, `shutdown`, `settings`, `diagnostics` |
| Spans | `span`, `observe` (functions, async, generators), `llm_span`, `tool_span`, `retriever_span`, `agent_span`, `embedding_span` |
| Span data | `set_usage` (incl. cache and reasoning tokens), `set_content`, `set_input`, `set_output`, `set_tool_result`, `set_documents`, `set_request_params` |
| Per request | `propagate_attributes`, `identify`, `get_current_attributes` |
| Trace context | `inject`, `extract`, `continue_trace`, `get_current_trace_id`, `get_current_span_id`, `get_traceparent` |
| Auto-instrumentation | `instrument`, `uninstrument` (OpenAI, Anthropic, LangChain / LangGraph, MCP, Gemini / Vertex AI, Bedrock, LlamaIndex, CrewAI, Pydantic AI, OpenAI Agents) |
| Scores | `score`, `feedback`, `async_score`, `async_feedback` |
| Experiments | `run_experiment`, `async_run_experiment`, `get_dataset`, `Evaluation` |
| Prompts | `get_prompt`, `async_get_prompt`, `Prompt.compile` |
| Admission | `admit` |
| Cost | `get_trace_cost`, `async_get_trace_cost` (each span's `cost_source`: gateway exact, proxy exact, computed, reported or unpriced) |
| AI gateway | `gateway_event_hooks`, `async_gateway_event_hooks`, `GatewayAuth`, `gateway_headers`, `stamp_gateway_request_id` (send the app's end user and service to the AI gateway, and record its request id) |

Nothing on the tracing path raises into your app: export failures are counted
(`sb.diagnostics()`) and summarized in at most one `superbased_sdk` log line a
minute. Content (prompts, responses, tool arguments) is captured by default;
`mask=` rewrites it before it leaves the process and `capture_content=False`
drops it.

## Settings

Every option is an `init()` argument and an environment variable. An explicit
argument wins, then the `SUPERBASED_*` variable, then the standard
OpenTelemetry variable, then (for the destination) this machine's default,
then the built-in default. Durations are seconds in Python and milliseconds
in the environment. `sb.settings()` returns what was resolved;
`sb.diagnostics()` shows where data goes and why.

| `init()` argument | Environment | Default |
|---|---|---|
| `destination` | `SUPERBASED_DESTINATION` (`local`, `online`, `both`) | this machine's default, else `local` |
| `org_url` (the gateway) | `SUPERBASED_ORG_URL` | the address in this machine's SDK key file, after sign-in |
| `api_key` (the SDK credential) | `SUPERBASED_API_KEY` | this machine's credential file, after sign-in |
| `node_url` (this machine's dashboard API) | `SUPERBASED_NODE_URL` | `http://127.0.0.1:8081` |
| `discover` (ask this machine for its default) | `SUPERBASED_DISCOVER` | on |
| `endpoint` (the local OTLP receiver) | `SUPERBASED_OTLP_ENDPOINT`, then (destination `local` only) `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT` + `/v1/traces` | `http://127.0.0.1:4318/v1/traces` |
| `headers` | `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TRACES_HEADERS` (destination `local` only), `SUPERBASED_OTLP_HEADERS` | none |
| `service_name` | `SUPERBASED_SERVICE_NAME`, `OTEL_SERVICE_NAME`, `service.name` in `OTEL_RESOURCE_ATTRIBUTES` | `custom-app` |
| (resource attributes) | `OTEL_RESOURCE_ATTRIBUTES` | none |
| `user`, `session_id`, `tenant` | `SUPERBASED_USER`, `SUPERBASED_SESSION_ID`, `SUPERBASED_TENANT` | none |
| `release`, `environment` | `SUPERBASED_RELEASE`, `SUPERBASED_ENVIRONMENT` | none |
| `tags`, `metadata` | `SUPERBASED_TAGS` (`a,b`), `SUPERBASED_METADATA` (`k=v,k2=v2`) | none |
| `sample_rate` (0..1, head sampling) | `SUPERBASED_SAMPLE_RATE`, `OTEL_TRACES_SAMPLER` + `OTEL_TRACES_SAMPLER_ARG` | 1.0 |
| `capture_content` | `SUPERBASED_CAPTURE_CONTENT` (legacy `OBSERVER_CAPTURE_CONTENT`) | on |
| `max_content_chars` (0 = no clip) | `SUPERBASED_MAX_CONTENT_CHARS` | 8000 |
| `export_timeout` | `SUPERBASED_EXPORT_TIMEOUT_MS`, `OTEL_EXPORTER_OTLP_TRACES_TIMEOUT`, `OTEL_EXPORTER_OTLP_TIMEOUT` | 5 s |
| `shutdown_timeout` (bounds flush and shutdown) | `SUPERBASED_SHUTDOWN_TIMEOUT_MS` | 2 s |
| `api_timeout` (scores, prompts, experiments) | `SUPERBASED_API_TIMEOUT_MS` | 5 s |
| `prompt_cache_ttl` | `SUPERBASED_PROMPT_CACHE_TTL_MS` | 60 s |
| `gateway_request_id` (stamp the AI gateway's `X-SBO-Request-Id` on the span that made the call) | `SUPERBASED_GATEWAY_REQUEST_ID` | on |
| `quiet` (keep exporter warnings out of your logs) | `SUPERBASED_QUIET` | on |
| `console` (also print spans) | `SUPERBASED_CONSOLE` | off |
| `should_export(span) -> bool`, `mask(value, key) -> value` | code only | none |
| `exporter`, `tracer_provider` | code only | OTLP/HTTP; the global provider |

`admit()` takes `endpoint` (`SUPERBASED_ADMISSION_ENDPOINT`), `org_url`,
`api_key`, `timeout` (the server-advertised one, else 12 s) and `fail_closed`
(`SUPERBASED_ADMISSION_FAIL_CLOSED`, off). Without them it follows the
destination: the gateway for `online` / `both`, else this machine. Re-recording
the instrumentation fixtures uses `SUPERBASED_RECORD_FIXTURES=1` (tests only).

## Pre-flight check: `admit()`

```python
v = sb.admit(user_message)          # user / session come from propagate_attributes
if not v.allowed:
    return v.reason
```

It never raises. When no decision can be obtained it admits by default; pass
`fail_closed=True` to deny. `v.degraded` says why a verdict is not a clean
decision (`admission-unavailable`, `client-timeout`, `client-transport`,
`client-http-error`, `client-bad-response`). Inside a span the verdict is
recorded on it (`sbo.admission.*`).

## An app that already uses OpenTelemetry

If the app registered an OpenTelemetry SDK `TracerProvider` before
`sb.init()`, the SDK adds its span processor to that provider instead of
replacing it, so the app's spans and the SDK's land in one trace. Sampling,
`should_export` and `mask` then apply only to what the SDK exports; your own
exporters see the original spans. Anything this SDK sends, a stock OTel
exporter pointed at superbased can send too; see
[`examples/raw_otlp.py`](examples/raw_otlp.py).

Never set the resource attribute `sbo.emitted_by=observer`: it marks
telemetry superbased emitted itself, and a resource carrying it is dropped at
ingestion.

## Development

```bash
cd sdk/python
pip install -e ".[test,dev]"                 # unit tests and mypy
pip install -e ".[test-instrument]"          # + the offline instrumentation scenarios (Python 3.10+)
pip install -e ".[test-instrument-crewai]"   # the CrewAI scenario, in its own environment (Python 3.10-3.13)
pytest
mypy
```

From the repository root, `go test ./tests/sdkcontract` checks the shared
fixtures in `sdk/contract/` (attribute keys, instrumentation spans) against
the Go vocabulary.
