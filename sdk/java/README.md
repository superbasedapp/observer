# superbased SDK for Java

Send your LLM app's and agents' traces to superbased over OpenTelemetry: to
the Observer on your machine while you build, to your organization's (or
superbased's hosted) gateway in production, or to both. Screen requests with
`admit()`, record scores and feedback, fetch managed prompts, run dataset
experiments with a CI gate, and read a trace's cost.

- Maven `app.superbased:superbased-sdk`, Java 17 or later, Apache-2.0.
- A thin layer over the official OpenTelemetry Java SDK (1.56) and its
  OTLP/HTTP exporter, sent with the JDK `HttpClient`. The one other runtime
  dependency is Gson (to read JSON).
- The same behaviour as the Python and TypeScript SDKs: its tests run every
  section of `sdk/contract/sdk-behaviour-cases.json`.

Full reference: [superbased.app/docs/sdk/java](https://superbased.app/docs/sdk/java)
(source `docs/sdk/java.md`: every option, its environment variable and
default, and the Python-to-Java name table).

## Install

Not on Maven Central yet. Install from a checkout into your local Maven
repository:

```bash
mvn -q -f /path/to/sdk/java install -DskipTests
```

```xml
<dependency>
  <groupId>app.superbased</groupId>
  <artifactId>superbased-sdk</artifactId>
  <version>0.2.0</version>
</dependency>
```

To use this machine's Observer, turn on Settings > Your apps in its
dashboard (or `[observability] enabled = true`). The SDK sends spans to
`http://127.0.0.1:4318/v1/traces` unless you point it elsewhere.

### A key without installing Observer

Java has no `setup` command of its own. Run the Node or Python one once in
the project with `--key-only`:

```bash
npx @superbased/sdk setup --key-only
```

(or `uvx superbased-sdk setup --key-only`). You approve once in the browser;
setup writes your own SDK key to a file only your user account can read, and
the Java SDK reads it from there: no environment variable to set and nothing
in the project folder. The key is never printed.

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
setup again). `Superbased.diagnostics()` shows `credential_source` and
`sdk_file` (`path`, `state`: `absent`, `used`, `unused`, `refused`,
`expired` or `not_read`, and the refused rule in `reason`; never the key).

The service name defaults to the `Implementation-Title` in your jar's
manifest (normalised), else `custom-app`; `service_name_source` in
diagnostics says which (`argument`, `env`, `manifest` or `default`).

On a terminal (not under `CI`), the first trace a process exports writes one
line to stderr with its link on the dashboard: `superbased: first trace from
this process: https://.../trajectories?trace=...` (the local dashboard's
`/apps/traces?trace=...` when it went to this machine).
`SUPERBASED_FIRST_TRACE_LINK=0` (or `false`, `off`) turns it off.

## Quick start

```java
import app.superbased.sdk.*;

public class Bot {
  public static void main(String[] args) {
    Superbased.init(InitOptions.builder().serviceName("support-bot").release("1.4.0").build());

    try (AttributeScope who = Superbased.propagateAttributes(
            TraceAttributes.builder().user("alice").sessionId("s-42").tenant("acme").build());
         SbSpan turn = Superbased.agentSpan("support-agent").start()) {
      Verdict v = Superbased.admit("What is your return window?");
      if (!v.allowed()) {
        return;
      }
      try (SbSpan s = Superbased.llmSpan("chat").model("gpt-5-nano").provider("openai")
              .prompt("What is your return window?").start()) {
        // ... call the model ...
        s.setUsage(Usage.builder()
            .inputTokens(1200)       // GROSS: cache reads and writes included
            .outputTokens(80)        // reasoning included
            .cacheReadTokens(1024)
            .responseId("chatcmpl-123")
            .response("30 days.")
            .build());
      }
      Superbased.score("helpful", true);
    } finally {
      Superbased.shutdown(); // flush before a short-lived process exits
    }
  }
}
```

## A tour

**Spans.** `span(name)` (any kind: `.kind(Kind.AGENT)`), `llmSpan`,
`toolSpan`, `retrieverSpan`, `agentSpan`, `embeddingSpan`. Each returns a
`SpanStarter`: set its options, then `.start()` in a try-with-resources
block, or `.call(s -> ...)` / `.run(s -> ...)`, which also record an
exception (ERROR) and set OK on success. The setters (`setUsage`,
`setContent`, `setInput`, `setOutput`, `setToolResult`, `setDocuments`,
`setRequestParams`) exist on `SbSpan` and as static methods taking any
OpenTelemetry `Span`, so they work on an instrumentation's spans too.

**Identity.** `propagateAttributes(TraceAttributes)` (a block) and
`identify(TraceAttributes)` (until `reset()`): end user, session, tenant,
tags, metadata, release, environment, on every span started inside.
`asBaggage(true)` also carries them in W3C baggage; `inject()`,
`extract(headers)` and `continueTrace(headers)` move a trace between
services.

**Where data goes.** `destination` `local`, `online` or `both`
(`SUPERBASED_DESTINATION`; with none set, this machine's choice, else
`local`). `online` needs `orgUrl` and an SDK key (`apiKey`,
`SUPERBASED_API_KEY`, or the credential file `observer sdk sign-in` writes,
which the SDK finds by asking this machine). `diagnostics()` says what was
chosen and why, and what is missing.

**admit().** `Superbased.admit(text)` asks the admission policy before the
agent runs and returns a `Verdict`. It never throws: no decision admits (or
denies with `failClosed(true)`), is counted (`admission_degraded`) and is
warned about once a minute per cause, naming the fix.

**Scores and feedback.** `score(name, value)` and `feedback(value)`: a
number, a boolean or a short label, on the current trace (pass
`spanId(...)` to score a span). Never throws; `ScoreResult.ok()` is true only
when every destination accepted it.

**Prompts.** `getPrompt(name)` fetches a managed prompt (label `production`,
or `.label("staging")`, or `.version(n)`), caches it, revalidates in the
background, and with `.fallback(...)` survives a registry that is down.
`prompt.compileText(values)` / `compileMessages(values)` fill
`{{placeholders}}`; `llmSpan(...).prompt(prompt)` stamps the span with the
prompt's name and version.

**Experiments.** `runExperiment(dataset, ExperimentOptions)` runs a task over
a dataset (a name, a `Dataset`, or a list of items), each item in its own
trace, scores each output with your `Evaluator`s, posts the results and reads
back the pass rate. `failUnder(0.9)` throws `ExperimentGateFailedException`
below it (uncaught on `main`, the JVM exits 1: a CI gate).

**Cost.** `getTraceCost(traceId)` returns the trace's cost with where each
number came from (`gateway_exact`, `proxy_exact`, `computed`, `reported`).
`gatewayHeaders()` and `stampGatewayRequestId(headers, span)` join a call
routed through the organization's AI gateway to its exact cost.

**The AI gateway.** The AI gateway is the proxy your app's model calls go
through: it prices each call exactly, holds your app's budgets and applies
your organization's model and admission rules. `Gateway.endpoint(provider,
upstream)` finds its address, first set wins: an address you pass
(`Gateway.endpoint(provider, upstream, url)`), then `SUPERBASED_AI_GATEWAY_URL`
(the gateway's address, without `/v1`), then your organization's address
`<org url>/ai/<upstream>` when the destination is `online`, then this
machine's app lane (`observer apps lane add`) when it is `local` or `both`. It
throws `Gateway.NotConfiguredException` when nothing applies, never falling
back to the provider itself. The provider is the client family
(`Gateway.PROVIDER_OPENAI`, whose base URL ends in `/v1`,
`PROVIDER_ANTHROPIC` or `PROVIDER_AZURE_OPENAI`); the upstream defaults to
`openai` or `anthropic`.

```java
GatewayEndpoint ep = Gateway.endpoint(Gateway.PROVIDER_OPENAI, null);
HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(ep.url("chat/completions")));
ep.headers().forEach(req::header); // identity, request id, traceparent, X-SBO-Upstream
String key = ep.apiKey();          // SUPERBASED_AI_GATEWAY_KEY; null on the machine lane
```

`Gateway.baseUrl(provider)` gives just the base URL for a client library.
On the machine's app lane `apiKey()` is null: send the provider's own key,
which the lane forwards; a remote gateway never needs it. A refusal reads with
`GatewayRefusalException.parse(status, body, headers)`: `kind()` is
`budget_exceeded` (402, with `budget()`), `model_not_allowed`,
`admission_denied`, `plan_required` (403), `quota_exceeded` (429, with
`retryAfter()`) or `other`, and `planRefusal()` (also its cause) carries the
plan detail when the plan is why.

**Content and sampling.** `captureContent` (default on),
`maxContentChars` (8000), a `mask((value, key) -> ...)` hook and a
`shouldExport(span -> ...)` hook apply to the exported copy of every span;
`sampleRate` (or `SUPERBASED_SAMPLE_RATE`, `OTEL_TRACES_SAMPLER[_ARG]`)
samples by trace id with the same rule as the other SDKs.

## When the plan does not include AI Apps

The organization's AI Apps gateway refuses ingest when its plan does not
include AI Apps (HTTP 403 `plan_required`) or this month's allowance is used
up (HTTP 429). The SDK reads that answer as a `PlanRefusalException`: a
`PlanRefusalException.PlanRequired` for the first, a
`PlanRefusalException.AllowanceExceeded` for the second. `getMessage()` says
why, and `upgradeUrl()` is where the organization's billing owner changes the
plan. It also has `kind()`, `code()`, `status()`, `capability()`, `plan()`
(the plan in force), `allowance()`, `plans()` (the plans that include more),
and on a 429 `quota()` and `retryAfter()`.

- `getPrompt`, `getDataset` and `runExperiment` throw the exception they always
  throw (`PromptException.FetchFailed`, `ExperimentException`), now with the
  refusal as its cause and its `planRefusal()`, so an existing `catch` still
  works.
- The calls that never throw carry it: `ScoreResult.planRefusal()`,
  `Verdict.planRefusal()` (from `admit()`) and `ExperimentResult.planRefusal()`.
  `getTraceCost` returns null, as for any failed read.
- Export never throws. A refused export shows in
  `Superbased.diagnostics().get("plan_refusal")` (a map of the same fields;
  `plan_refusal_at` says when), and the SDK logs one warning line a minute with
  the message and the upgrade URL. The last refusal of any call is kept there.
  On export, `retryAfter()` is not known (the OTLP exporter keeps the body but
  not the headers).

```java
try {
  Prompt p = Superbased.getPrompt("support-reply");
} catch (PromptException.FetchFailed e) {
  if (e.planRefusal() != null) {
    System.err.println(e.planRefusal().getMessage() + " " + e.planRefusal().upgradeUrl());
  }
}
```

`PlanRefusalException.parse(status, body, headers)` reads a refusal from any
HTTP answer, and returns null for anything else.

## Build and test

```bash
mvn -B test
```

`BehaviourCasesTest` runs every section of
`../contract/sdk-behaviour-cases.json` (one parameterized test per section,
named after it) and fails when a section has no Java runner.
`ContractFilesTest` runs the shared prompt compile and rollout cases and the
attribute-key list; `ApiTest` covers the rest. The contract directory is
`../contract` by default; elsewhere pass
`-Dsuperbased.contract.dir=<repo>/sdk/contract`.

## Changelog

### 0.2.0 (not yet published)

- The SDK reads the SDK-held key file `setup --key-only` writes (paths and
  rules above): its destination is used after `SUPERBASED_DESTINATION` and
  before the machine's default (`destination_source` `sdk_file`), and its key
  after the machine's own (`credential_source` `sdk_file`). Windows reads this
  file under its own rule; the machine's sign-in file is still not read on
  Windows.
- The service name defaults to the main jar's `Implementation-Title` instead
  of `custom-app`. An app that relied on `custom-app` appears as a new
  service: set `serviceName` (or `SUPERBASED_SERVICE_NAME`) to keep the old
  one.
- One first-trace line on stderr with the dashboard link, on a terminal
  only.
- Also in 0.2.0: the AI gateway helpers and the plan refusals (above).

## Publishing (not done yet)

Coordinates `app.superbased:superbased-sdk` (the group is the reverse of the
`superbased.app` domain, which Maven Central verifies with a DNS TXT record).
Publishing to Maven Central needs: the `app.superbased` namespace verified on
central.sonatype.com, a GPG key to sign every artifact, the `-sources` and
`-javadoc` jars (the build attaches the sources jar; a javadoc jar step is to
add), the POM metadata this `pom.xml` already carries (name, description,
url, licence, developers, scm), and the `central-publishing-maven-plugin`
with a Central portal token held as a CI secret.
