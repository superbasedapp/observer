# superbased SDK for Go

The Go SDK for superbased AI Apps: it sends your LLM app's and agents' traces
to superbased over OpenTelemetry (OTLP/HTTP), screens requests with `Admit`,
records scores and feedback, runs experiments, fetches managed prompts and
reads a trace's cost. It is the Go twin of the Python (`superbased-sdk`) and
TypeScript (`@superbased/sdk`) SDKs: the same features, the same wire and the
same behaviour, checked by the shared cases in
[`sdk/contract/sdk-behaviour-cases.json`](../contract/sdk-behaviour-cases.json).

It is a thin layer over the official
[OpenTelemetry Go SDK](https://opentelemetry.io/docs/languages/go/) and its
OTLP/HTTP exporter: anything it sends, a stock OpenTelemetry exporter can send
too.

## Install

The module is `github.com/superbasedapp/observer/sdk/go` (package
`superbased`), Go 1.25 or newer:

```bash
go get github.com/superbasedapp/observer/sdk/go
```

```go
import superbased "github.com/superbasedapp/observer/sdk/go"
```

## Quick start

```go
ctx := context.Background()
if _, err := superbased.Init(ctx, superbased.Options{ServiceName: "support-bot", Release: "1.4.0"}); err != nil {
	log.Fatal(err) // only a sample rate outside 0..1 is an error
}
defer superbased.Shutdown(ctx) // flush before the process exits

ctx = superbased.PropagateAttributes(ctx, superbased.Attributes{User: "alice", SessionID: "s1", Tenant: "acme"})

v := superbased.Admit(ctx, userMessage, superbased.AdmitOptions{})
if !v.Allowed {
	return v.Reason
}

err := superbased.WithLLMSpan(ctx, "chat", superbased.LLMOptions{Model: "gpt-5-nano", Provider: "openai"},
	func(ctx context.Context, span trace.Span) error {
		resp, err := callModel(ctx, messages)
		if err != nil {
			return err // recorded once, status ERROR
		}
		superbased.SetContent(span, superbased.Content{Prompt: messages, Response: resp.Text})
		return superbased.SetUsage(span, superbased.Usage{
			InputTokens:     superbased.Int(resp.Usage.PromptTokens), // GROSS: cache reads included
			OutputTokens:    superbased.Int(resp.Usage.CompletionTokens),
			CacheReadTokens: superbased.Int(resp.Usage.CachedTokens),
			ResponseID:      resp.ID,
		})
	})
```

With no settings, spans go to the superbased app on this machine
(`http://127.0.0.1:4318/v1/traces`), or wherever the machine's
[destination](../../docs/sdk/destination.md) setting says once you signed in.

The service name defaults to your main module's name (its last path element,
a `/vN` suffix dropped, from the binary's build info), so most apps need no
`ServiceName`.

### A key without installing Observer

Go has no `setup` command of its own. Run the Node or Python one once in the
project with `--key-only`:

```bash
npx @superbased/sdk setup --key-only
```

(or `uvx superbased-sdk setup --key-only`). You approve once in the browser;
setup writes your own SDK key to a file only your user account can read, and
the Go SDK reads it from there: no environment variable to set and nothing in
the project folder. The key is never printed.

| OS | The SDK-held key file |
|---|---|
| Linux, macOS | `$XDG_CONFIG_HOME/superbased/sdk-credential`, else `~/.config/superbased/sdk-credential` |
| Windows | `%LOCALAPPDATA%\superbased\sdk-credential` |
| Any | `SUPERBASED_CREDENTIAL_FILE` names another path |

The SDK refuses the file (with a warning, then the next setting applies) when
it is a symlink, is not a regular file, is readable by other users or is
owned by another user; on Windows when it is a reparse point, is not inside
your own `%LOCALAPPDATA%` or is owned by another user. Its key goes only to
the gateway address stored beside it. When Observer on this machine is
signed in, its own key wins and the file is reported as unused. From 14 days
before the key expires the SDK says so; an expired key is not used (run
setup again). `GetDiagnostics()` shows `credential_source` and `sdk_file`
(`path`, `state`: `absent`, `used`, `unused`, `refused`, `expired` or
`not_read`, and the refused rule in `reason`; never the key).

On a terminal (not under `CI`), the first trace a process exports writes one
line to stderr with its link on the dashboard: `superbased: first trace from
this process: https://.../trajectories?trace=...` (the local dashboard's
`/apps/traces?trace=...` when it went to this machine).
`SUPERBASED_FIRST_TRACE_LINK=0` (or `false`, `off`) turns it off.

## Tour

| What | Go |
|---|---|
| Set up, flush, stop | `Init(ctx, Options)`, `Flush(ctx)`, `Shutdown(ctx)`; `CurrentSettings()`, `GetDiagnostics()` |
| Spans | `WithSpan` / `StartSpan` + `EndSpan`, `Observe[T]`; typed `WithLLMSpan`, `WithToolSpan`, `WithRetrieverSpan`, `WithAgentSpan`, `WithEmbeddingSpan` (and `Start…` forms); kinds `KindLLM` … `KindEvaluator` |
| Setters | `SetUsage` (returns an error for a negative count), `SetContent`, `SetInput`, `SetOutput`, `SetToolResult`, `SetDocuments`, `SetRequestParams` |
| Per-request identity | `PropagateAttributes(ctx, Attributes)` / `Identify`, `CurrentAttributes(ctx)` |
| Trace context | `Inject`, `InjectHeader`, `Extract`, `ExtractHeader`, `ContinueTrace`, `CurrentTraceID`, `CurrentSpanID`, `Traceparent` |
| Screening | `Admit(ctx, message, AdmitOptions) Verdict` (never fails; degraded causes `Degraded…`) |
| Scores | `Score(ctx, name, value, ScoreOptions)`, `Feedback(ctx, value, FeedbackOptions)` return a `ScoreResult` |
| Experiments | `RunExperiment(ctx, ExperimentOptions)`, `GetDataset`, `ExperimentGate`; `*ExperimentError`, `*ExperimentGateFailed` |
| Prompts | `GetPrompt(ctx, name, PromptOptions) (*Prompt, error)`, `Prompt.Compile` / `CompileText` / `CompileMessages`, `Prompt.Stamp`; `ErrPromptNotFound`, `ErrPromptFetch`, `*PromptCompileError` |
| Cost | `GetTraceCost(ctx, traceID) (*TraceCost, error)`; `CostSourceLabels`, `IsExactCost` |
| AI gateway | `GatewayBaseURL(provider, upstream)`, `ResolveGateway(provider, GatewayOptions) (GatewayEndpoint, error)`, `GatewayEndpoint.HTTPClient(base)`, `GatewayEndpoint.APIKey()`, `GatewayKey()`; `GatewayTransport(base)` (an `http.RoundTripper` that sends `X-Superbased-User`, `X-Superbased-Service`, `X-SBO-Request-Id` and `traceparent`, and stamps the answer's request id), `GatewayHeaders(ctx)`, `StampGatewayRequestID`; refusals `*GatewayRefusalError`, `ParseGatewayRefusal`, `GatewayRefusalFromResponse`; see below |
| Plan refusals | `*PlanRefusalError` (`ErrPlanRequired`, `ErrAllowanceExceeded`), `ParsePlanRefusal`; see below |
| Logging | `SetLogger(*slog.Logger)` (default `slog.Default()`) |

Go has no ambient context, so every call that reads the current span, trace
or per-request identity takes a `context.Context`.

## Model calls through the AI gateway

The AI gateway is the proxy your app's model calls go through: it prices each
call exactly, holds your app's budgets and applies your organization's model
and admission rules. `ResolveGateway` finds its address, first set wins:

1. `GatewayOptions.URL`;
2. `SUPERBASED_AI_GATEWAY_URL` (the gateway's address, without `/v1`);
3. your organization's address, `<org url>/ai/<upstream>`, when the
   destination is `online`;
4. this machine's app lane (`observer apps lane add`), when the destination
   is `local` or `both`.

It never falls back to the provider itself: with nothing to use it returns an
error matching `ErrGatewayNotConfigured`. The provider is the client family:
`GatewayProviderOpenAI` (the base URL ends in `/v1`),
`GatewayProviderAnthropic` or `GatewayProviderAzureOpenAI`. The upstream
defaults to `openai` or `anthropic`.

```go
ep, err := superbased.ResolveGateway(superbased.GatewayProviderOpenAI, superbased.GatewayOptions{})
if err != nil {
	return err
}
key, err := ep.APIKey()
if err != nil {
	return err // a remote gateway and no SUPERBASED_AI_GATEWAY_KEY
}
opts := []option.RequestOption{option.WithBaseURL(ep.BaseURL), option.WithHTTPClient(ep.HTTPClient(nil))}
if key != "" {
	opts = append(opts, option.WithAPIKey(key)) // SUPERBASED_AI_GATEWAY_KEY
}
client := openai.NewClient(opts...)
```

`ep.APIKey()` is the key rule every SDK shares: the AI gateway key
(`SUPERBASED_AI_GATEWAY_KEY`) for a gateway; `""` on this machine's app lane
or a loopback gateway with no gateway key, so the client keeps sending its
own provider key; and an error with problem `no_key` (matching
`ErrGatewayNotConfigured`) for a remote gateway with no gateway key, so the
provider's key is never sent there.

`ep.HTTPClient` sends the app identity headers, a request id and the
`traceparent` of the span in the request's context, adds `X-SBO-Upstream`
when the address needs it, and follows no redirect. A refusal reads as a
`*GatewayRefusalError` (`ParseGatewayRefusal`, or `GatewayRefusalFromResponse`
on an `*http.Response`): `errors.Is` matches `ErrBudgetExceeded` (402),
`ErrModelNotAllowed`, `ErrAdmissionDenied` (403), `ErrGatewayQuotaExceeded`
(429) and, through its `PlanRefusal`, `ErrPlanRequired` or
`ErrAllowanceExceeded`. `Budget` names the cap a 402 hit, `RequestID` the
gateway's request id and `RetryAfter` the Retry-After header.

## When the plan does not include AI Apps

The organization's AI Apps gateway refuses ingest when its plan does not
include AI Apps (HTTP 403 `plan_required`) or this month's allowance is used
up (HTTP 429). The SDK reads that answer as a `*PlanRefusalError`.
`errors.Is(err, ErrPlanRequired)` matches the first and
`errors.Is(err, ErrAllowanceExceeded)` the second. `Message` says why, and
`UpgradeURL` is where the organization's billing owner changes the plan. It
also has `Kind`, `Code`, `Status`, `Capability`, `Plan` (the plan in force),
`Allowance`, `Plans` (the plans that include more), and on a 429 `Quota` and
`RetryAfter`.

- `GetPrompt`, `GetDataset` and `RunExperiment` return the error they always
  return (one wrapping `ErrPromptFetch`, an `*ExperimentError`), and it now
  also wraps the `*PlanRefusalError`, so `errors.As` finds it and existing
  checks still match.
- The calls that never fail carry it: `ScoreResult.PlanRefusal`,
  `Verdict.PlanRefusal` (from `Admit`) and `ExperimentResult.PlanRefusal`.
  `GetTraceCost` returns nil, as for any failed read.
- Export never fails a caller. A refused export shows in
  `GetDiagnostics().PlanRefusal` (`PlanRefusalAt` says when), and the SDK logs
  one warning line a minute with the message and the upgrade URL. The last
  refusal of any call is kept there. On export, `RetryAfter` is not known (the
  OTLP exporter keeps the body but not the headers).

```go
_, err := superbased.GetPrompt(ctx, "support-reply", superbased.PromptOptions{})
var refusal *superbased.PlanRefusalError
if errors.As(err, &refusal) {
	log.Printf("%s (%s)", refusal.Message, refusal.UpgradeURL)
}
```

`ParsePlanRefusal(status, body, header)` reads a refusal from any HTTP
answer, and returns nil for anything else.

## Settings

Every option resolves as: the `Options` field, then the `SUPERBASED_*`
variable, then the standard `OTEL_*` variable where one exists, then (only
`Destination`) the machine's default, then the built-in default. A pointer
field (`*bool`, `*int`, `*float64`) is one whose zero value is a real choice:
set it with `superbased.Bool`, `Int` or `Float`.

| Option | Environment | Default |
|---|---|---|
| `Destination` | `SUPERBASED_DESTINATION` | the SDK-held key file's choice, else the machine's default, else `local` |
| `OrgURL` | `SUPERBASED_ORG_URL` | the `gateway_url` line of the machine's credential file, else of the SDK-held key file |
| `APIKey` | `SUPERBASED_API_KEY` | the machine's credential file (unix file rules), else the SDK-held key file (`SUPERBASED_CREDENTIAL_FILE` moves it) |
| `NodeURL` | `SUPERBASED_NODE_URL` | `http://127.0.0.1:8081` (only a loopback address is asked) |
| `Discover` | `SUPERBASED_DISCOVER` | on (500 ms, one attempt) |
| `Endpoint` | `SUPERBASED_OTLP_ENDPOINT`; for `local` also `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT` + `/v1/traces` | the machine's receiver, else `http://127.0.0.1:4318/v1/traces` |
| `Headers` | `SUPERBASED_OTLP_HEADERS` (for `local` also `OTEL_EXPORTER_OTLP_[TRACES_]HEADERS`) | none |
| `ServiceName` | `SUPERBASED_SERVICE_NAME`, `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES` | the main module's name, else `custom-app` (`service_name_source` in diagnostics: `argument`, `env`, `manifest` or `default`) |
| `Tenant`, `User`, `SessionID` | `SUPERBASED_TENANT`, `SUPERBASED_USER`, `SUPERBASED_SESSION_ID` | none |
| `Release`, `Environment` | `SUPERBASED_RELEASE`, `SUPERBASED_ENVIRONMENT` | none |
| `Tags`, `Metadata` | `SUPERBASED_TAGS` (comma list), `SUPERBASED_METADATA` (`k=v,k2=v2`) | none |
| `CaptureContent` | `SUPERBASED_CAPTURE_CONTENT` | on |
| `MaxContentChars` | `SUPERBASED_MAX_CONTENT_CHARS` | 8000 |
| `SampleRate` | `SUPERBASED_SAMPLE_RATE`, `OTEL_TRACES_SAMPLER` + `_ARG` | 1 (a bad env value is ignored and named in a warning) |
| `ShouldExport`, `Mask` | code only | none |
| `ExportTimeout` | `SUPERBASED_EXPORT_TIMEOUT_MS`, `OTEL_EXPORTER_OTLP_[TRACES_]TIMEOUT` | 5 s |
| `ShutdownTimeout` | `SUPERBASED_SHUTDOWN_TIMEOUT_MS` | 2 s |
| `APITimeout` | `SUPERBASED_API_TIMEOUT_MS` | 5 s |
| `PromptCacheTTL` | `SUPERBASED_PROMPT_CACHE_TTL_MS` | 60 s |
| `Quiet` | `SUPERBASED_QUIET` | on |
| `Console` | `SUPERBASED_CONSOLE` | off |
| `Exporter`, `Exporters`, `TracerProvider` | code only | the OTLP/HTTP exporter; the global provider |

`Admit` also reads `SUPERBASED_ADMISSION_ENDPOINT` and
`SUPERBASED_ADMISSION_FAIL_CLOSED`. `SUPERBASED_FIRST_TRACE_LINK=0` turns the
first-trace line off.

## Development

```bash
cd sdk/go
go vet ./...
go test -race ./...   # runs every section of sdk/contract/sdk-behaviour-cases.json
```

The tests read the shared contract files from `../contract`
(`SUPERBASED_CONTRACT_DIR` overrides it); `TestEverySectionHasARunner` fails
when the case file gains a section with no Go runner.

## Changelog

### 0.2.0 (not yet published)

- The SDK reads the SDK-held key file `setup --key-only` writes (paths and
  rules above): its destination is used after `SUPERBASED_DESTINATION` and
  before the machine's default (`destination_source` `sdk_file`), and its key
  after the machine's own (`credential_source` `sdk_file`). Windows reads this
  file under its own rule; the machine's sign-in file is still not read on
  Windows.
- The service name defaults to the main module's name instead of
  `custom-app`. An app that relied on `custom-app` appears as a new service:
  set `ServiceName` (or `SUPERBASED_SERVICE_NAME`) to keep the old one.
- One first-trace line on stderr with the dashboard link, on a terminal
  only.
- Also in 0.2.0: the AI gateway helpers and the plan refusals (above).

Licence: Apache-2.0 (`LICENSE`, `NOTICE`).
