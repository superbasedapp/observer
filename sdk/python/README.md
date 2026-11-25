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

## One command: `setup`

In the project folder:

```bash
uvx superbased-sdk setup          # or: pipx run superbased-sdk setup
                                  # or: pip install superbased-sdk && python -m superbased_sdk setup
```

`setup` finds the model libraries the project uses, installs the SDK with
their extras (with the project's own tool: uv, poetry, pdm, pipenv or pip),
and sets up where traces go:

- **Online** (no Observer on this computer, or `--online`): it prints a link
  and a code; sign in (or sign up) in the browser, check the code and click
  Approve. Your own SDK key goes straight into a file only your user can
  read (below); it is never printed. Traces need this SDK key, and nothing
  else.
- **This computer** (Observer running, or `--local`): with AI Apps off it asks
  y/N on a terminal, or opens the dashboard's Turn on page when an agent runs
  it.

It then sends one hello span, waits for it to arrive, prints a link to it,
and prints the one line to add to the app: `import superbased_sdk;
superbased_sdk.init()`. It never edits your source files and never installs
Observer. `--json` writes one JSON object per phase for agents; `--status`
says what is configured; `--forget` revokes the stored key and removes its
file; `--online --replace` gets a new key; `--key-only` only gets the key
and sends the hello (for a Go or Java project, whose SDKs read the same file).
Exit codes: 0 the trace arrived, 1 an unexpected error, 2 waiting for you
(declined, expired, not clicked: run it again), 3 refused (the plan, the
membership), 4 the environment (no supported project, the install failed,
a self-hosted organization), 5 sent but not seen within 60 s.

## Install

```bash
pip install superbased-sdk
```

`init()` instruments every model library whose extra is installed (below),
when the SDK owns the tracer provider; a framework the app has not imported
yet is instrumented on its first import. The instrumentation is an extra:

```bash
pip install "superbased-sdk[openai]"  # also [anthropic], [langchain] (LangGraph too), [mcp], [gemini],
                                      # [bedrock], [llama-index], [crewai], [pydantic-ai], [openai-agents], [all]
```

## Quick start

```python
import superbased_sdk as sb

sb.init()                                # once at startup; idempotent: traces every installed model library

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
| AI gateway | `openai_client`, `anthropic_client`, `gateway_base_url`, `gateway_endpoint`, `gateway_key` (point a model client at the AI gateway; see below); `parse_gateway_refusal`, `gateway_refusal`, `GatewayRefusalError`; `gateway_event_hooks`, `async_gateway_event_hooks`, `GatewayAuth`, `gateway_headers`, `stamp_gateway_request_id` (send the app's end user, service and trace context to the AI gateway, and record its request id) |

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
| `destination` | `SUPERBASED_DESTINATION` (`local`, `online`, `both`) | the SDK-held key file's choice, else this machine's default, else `local` |
| `org_url` (the gateway) | `SUPERBASED_ORG_URL` | the address in this machine's SDK key file after sign-in, else the SDK-held key file's |
| `api_key` (the SDK credential) | `SUPERBASED_API_KEY` | this machine's credential file after sign-in, else the SDK-held key file `setup` wrote |
| `node_url` (this machine's dashboard API) | `SUPERBASED_NODE_URL` | `http://127.0.0.1:8081` |
| `discover` (ask this machine for its default) | `SUPERBASED_DISCOVER` | on |
| `endpoint` (the local OTLP receiver) | `SUPERBASED_OTLP_ENDPOINT`, then (destination `local` only) `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT` + `/v1/traces` | `http://127.0.0.1:4318/v1/traces` |
| `headers` | `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TRACES_HEADERS` (destination `local` only), `SUPERBASED_OTLP_HEADERS` | none |
| `service_name` | `SUPERBASED_SERVICE_NAME`, `OTEL_SERVICE_NAME`, `service.name` in `OTEL_RESOURCE_ATTRIBUTES` | the project's own name (`[project] name` or `[tool.poetry] name` of the nearest `pyproject.toml` above the entry script), else the entry script's folder, else `custom-app` (`diagnostics()["service_name_source"]`) |
| `instrument` (`"auto"`, `"off"` or a list of targets) | `SUPERBASED_INSTRUMENT` | `auto`: every installed target when the SDK owns the provider; never `openai-agents` unless named; nothing when the app registered its own provider (`diagnostics()["instrumented"]`) |
| (the SDK-held key file `setup` writes) | `SUPERBASED_CREDENTIAL_FILE` | `$XDG_CONFIG_HOME` or `~/.config` `/superbased/sdk-credential`; Windows `%LOCALAPPDATA%\superbased\sdk-credential` |
| (the first-trace line) | `SUPERBASED_FIRST_TRACE_LINK` (`0`, `false` or `off` turns it off) | on, only on a terminal and not under `CI` |
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

### The SDK-held key file

`setup` stores the member's SDK key in one file per user, outside any
project: the key line, then `gateway_url`, `destination`, `dashboard_url` and
`expires_at`. The SDK reads it itself (no environment variable), only when it
is a regular file owned by this user and readable by nobody else (on Windows:
under the user's own `%LOCALAPPDATA%`, owned by the user, no link or
junction). The key expires after 90 days; the SDK warns from 14 days before,
and `uvx superbased-sdk setup` gets a new one. A computer whose Observer is
signed in keeps using Observer's key, and the file is reported as unused.

### The first-trace line

On a terminal, once per process, the SDK writes one line to stderr after the
app's first trace is exported: `superbased: first trace from this process:
<link>` (the dashboard on this computer, or the online one when the key file
names it). Never under `CI`; `SUPERBASED_FIRST_TRACE_LINK=0` turns it off.

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

## Model calls through the AI gateway

The AI gateway is the proxy your app's model calls go through: it prices each
call exactly, holds your app's budgets and applies your organization's model
and admission rules. `openai_client()` and `anthropic_client()` build a client
pointed at it:

```python
import superbased_sdk as sb

sb.init(service_name="support-bot")
client = sb.openai_client()  # the key: SUPERBASED_AI_GATEWAY_KEY
reply = client.chat.completions.create(model="gpt-5-nano", messages=messages)
```

The address is resolved first set wins: `url=`, then
`SUPERBASED_AI_GATEWAY_URL` (the gateway's address, without `/v1`), then your
organization's address `<org url>/ai/<upstream>` when the destination is
`online`, then this machine's app lane (`observer apps lane add`) when it is
`local` or `both`. The upstream defaults to `openai` or `anthropic`; name
another with the first argument. With nothing to use the helpers raise
`GatewayNotConfigured`: they never fall back to the provider itself. On the
machine's app lane the client keeps the provider's own key
(`OPENAI_API_KEY`); a remote gateway never receives it.
`gateway_base_url("openai")` returns just the base URL for any other client.

The client sends your app's end user and service, a request id and the
current span's `traceparent`, and follows no redirect. A refusal reads as a
`GatewayRefusalError` (`sb.gateway_refusal(err)` on the model SDK's error, or
`parse_gateway_refusal(status, body, headers)`): `kind` is `budget_exceeded`
(402, with `budget`), `model_not_allowed`, `admission_denied`,
`plan_required` (403), `quota_exceeded` (429, with `retry_after`) or `other`,
and `plan_refusal` carries the plan detail when the plan is why.

## When the plan does not include AI Apps

The organization's AI Apps gateway refuses ingest when its plan does not
include AI Apps (HTTP 403 `plan_required`) or this month's allowance is used
up (HTTP 429). The SDK reads that answer as a typed error,
`sb.PlanRefusalError`: a `PlanRequiredError` for the first, an
`AllowanceExceededError` for the second. `message` says why, and
`upgrade_url` is where the organization's billing owner changes the plan. It
also has `code`, `status`, `capability`, `plan` (the plan in force),
`allowance`, `plans` (the plans that include more), and on a 429 `quota` and
`retry_after` (seconds).

- `get_prompt()`, `get_dataset()` and `run_experiment()` raise it. It is also
  the `PromptFetchError` or `ExperimentError` they raise, so an existing
  `except` still catches it.
- The calls that never raise carry it: `ScoreResult.plan_refusal`,
  `Verdict.plan_refusal` (from `admit()`) and `ExperimentResult.plan_refusal`.
  `get_trace_cost()` returns None, as for any failed read.
- Export never raises. A refused export shows in
  `sb.diagnostics()["plan_refusal"]` (a dict of the same fields;
  `plan_refusal_at` says when), and the SDK logs one warning line a minute
  with the message and the upgrade URL. The last refusal of any call is kept
  there.

```python
try:
    prompt = sb.get_prompt("support-reply")
except sb.PlanRefusalError as e:
    print(e.message, e.upgrade_url)
```

`sb.parse_plan_refusal(status, body, headers)` reads a refusal from any HTTP
answer, and returns None for anything else.

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

## Changelog

### 0.2.0

- **`setup`**: one command from a project to its first trace
  (`uvx superbased-sdk setup`, `python -m superbased_sdk setup`): detection,
  the install, the online device sign-in or this computer's AI Apps enable,
  a hello span with its link, and the one init line.
- **`init()` instruments by itself** (`instrument=`, `SUPERBASED_INSTRUMENT`,
  default `auto`) when the SDK owns the tracer provider. If your app called
  `instrument([...])` and deliberately left an installed library out, it now
  gets spans for that library too: pass `instrument=[...]` to `init()` to
  keep the old set. If it wraps model calls with `llm_span` by hand, those
  calls now appear twice: pass `instrument="off"`. An app with its own
  OpenTelemetry provider is unchanged, and `openai-agents` is instrumented
  only when named.
- **The service name comes from the project** (`pyproject.toml`, else the
  folder). An app that relied on `custom-app` starts a new service in the
  dashboard: set `service_name=` or `SUPERBASED_SERVICE_NAME` to keep it.
- **The SDK-held key file** is read as the destination's third rung
  (`sdk_file`) and the third credential record.
- **The first-trace line** on a terminal.
- `diagnostics()` gains `instrument`, `instrumented`, `service_name`,
  `service_name_source`, `sdk_file` and `first_trace_link`; `mode` can read
  `standalone` (the SDK's own provider beside a non-SDK one the app
  registered).

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
