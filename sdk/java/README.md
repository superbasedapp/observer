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
  <version>0.1.0</version>
</dependency>
```

To use this machine's Observer, turn on Settings > Your apps in its
dashboard (or `[observability] enabled = true`). The SDK sends spans to
`http://127.0.0.1:4318/v1/traces` unless you point it elsewhere.

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

**Content and sampling.** `captureContent` (default on),
`maxContentChars` (8000), a `mask((value, key) -> ...)` hook and a
`shouldExport(span -> ...)` hook apply to the exported copy of every span;
`sampleRate` (or `SUPERBASED_SAMPLE_RATE`, `OTEL_TRACES_SAMPLER[_ARG]`)
samples by trace id with the same rule as the other SDKs.

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

## Publishing (not done yet)

Coordinates `app.superbased:superbased-sdk` (the group is the reverse of the
`superbased.app` domain, which Maven Central verifies with a DNS TXT record).
Publishing to Maven Central needs: the `app.superbased` namespace verified on
central.sonatype.com, a GPG key to sign every artifact, the `-sources` and
`-javadoc` jars (the build attaches the sources jar; a javadoc jar step is to
add), the POM metadata this `pom.xml` already carries (name, description,
url, licence, developers, scm), and the `central-publishing-maven-plugin`
with a Central portal token held as a CI secret.
