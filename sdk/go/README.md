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
| AI gateway | `GatewayTransport(base)` (an `http.RoundTripper` that sends `X-Superbased-User`, `X-Superbased-Service`, `X-SBO-Request-Id` and stamps the answer's request id), `GatewayHeaders(ctx)`, `StampGatewayRequestID` |
| Logging | `SetLogger(*slog.Logger)` (default `slog.Default()`) |

Go has no ambient context, so every call that reads the current span, trace
or per-request identity takes a `context.Context`.

## Settings

Every option resolves as: the `Options` field, then the `SUPERBASED_*`
variable, then the standard `OTEL_*` variable where one exists, then (only
`Destination`) the machine's default, then the built-in default. A pointer
field (`*bool`, `*int`, `*float64`) is one whose zero value is a real choice:
set it with `superbased.Bool`, `Int` or `Float`.

| Option | Environment | Default |
|---|---|---|
| `Destination` | `SUPERBASED_DESTINATION` | the machine's default, else `local` |
| `OrgURL` | `SUPERBASED_ORG_URL` | the `gateway_url` line of the machine's credential file |
| `APIKey` | `SUPERBASED_API_KEY` | the machine's credential file (unix file rules) |
| `NodeURL` | `SUPERBASED_NODE_URL` | `http://127.0.0.1:8081` (only a loopback address is asked) |
| `Discover` | `SUPERBASED_DISCOVER` | on (500 ms, one attempt) |
| `Endpoint` | `SUPERBASED_OTLP_ENDPOINT`; for `local` also `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_ENDPOINT` + `/v1/traces` | the machine's receiver, else `http://127.0.0.1:4318/v1/traces` |
| `Headers` | `SUPERBASED_OTLP_HEADERS` (for `local` also `OTEL_EXPORTER_OTLP_[TRACES_]HEADERS`) | none |
| `ServiceName` | `SUPERBASED_SERVICE_NAME`, `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES` | `custom-app` |
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
`SUPERBASED_ADMISSION_FAIL_CLOSED`.

## Development

```bash
cd sdk/go
go vet ./...
go test -race ./...   # runs every section of sdk/contract/sdk-behaviour-cases.json
```

The tests read the shared contract files from `../contract`
(`SUPERBASED_CONTRACT_DIR` overrides it); `TestEverySectionHasARunner` fails
when the case file gains a section with no Go runner.

Licence: Apache-2.0 (`LICENSE`, `NOTICE`).
