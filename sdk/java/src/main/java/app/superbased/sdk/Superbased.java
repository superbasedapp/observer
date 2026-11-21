package app.superbased.sdk;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.trace.TracerProvider;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporterBuilder;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.ReadWriteSpan;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.SpanProcessor;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.BatchSpanProcessor;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import io.opentelemetry.sdk.trace.export.SpanExporter;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

/**
 * The superbased SDK for Java: send LLM-app and agent traces, scores,
 * prompts and experiments to superbased over OpenTelemetry.
 *
 * <pre>{@code
 * Superbased.init(InitOptions.builder().serviceName("support-bot").build());
 *
 * try (SbSpan s = Superbased.llmSpan("chat").model("gpt-5-nano").provider("openai").start()) {
 *   ... // call the model
 *   s.setUsage(Usage.builder().inputTokens(1200).outputTokens(80).build());
 * }
 *
 * Superbased.shutdown(); // flush before a short-lived process exits
 * }</pre>
 *
 * <p>Every method is static and thread-safe. The tracing path never throws
 * into the host; the documented exceptions are programmer errors
 * (IllegalArgumentException), the prompt errors ({@link PromptException})
 * and the experiment errors ({@link ExperimentException},
 * {@link ExperimentGateFailedException}).
 *
 * <p>IMPORTANT: never set {@code sbo.emitted_by=observer}. That is
 * Observer's own echo-guard marker; a resource carrying it is DROPPED at
 * ingestion.
 */
public final class Superbased {
  /** The SDK version. */
  public static final String VERSION = "0.1.0";

  static final String TRACER_NAME = "superbased_sdk";
  static final String SDK_MARKER = "superbased-java";

  private static final Object LOCK = new Object();
  private static volatile Tracer tracer;
  private static volatile TracerProvider provider;
  private static volatile SdkTracerProvider ownedProvider;
  private static Map<String, Object> ownedResourceAttrs = Map.of();
  private static volatile Export.SwitchableProcessor processor;
  private static Export.SwitchableProcessor hostProcessor;
  private static String configKey;
  private static volatile String mode = "";
  private static volatile String modeWarning = "";
  /** The service.name the provider holding the SDK's spans carries (first span seen). */
  private static volatile String serviceSeen;
  private static volatile Map<String, String> vendorTracing = Map.of();
  private static volatile boolean captureContent = true;
  private static volatile int maxContentChars = Settings.DEFAULT_MAX_CONTENT_CHARS;
  private static volatile Duration shutdownTimeout = Settings.DEFAULT_SHUTDOWN_TIMEOUT;
  private static volatile Settings settings;
  private static volatile Destination.Plan plan;
  private static final Pipeline.SwitchableSampler SAMPLER = new Pipeline.SwitchableSampler();
  private static final ExecutorService ASYNC =
      Executors.newCachedThreadPool(
          r -> {
            Thread t = new Thread(r, "superbased-sdk-async");
            t.setDaemon(true);
            return t;
          });

  private Superbased() {}

  // --- setup and lifecycle --------------------------------------------------------------------

  /** {@link #init(InitOptions)} with every option from the environment. */
  public static Settings init() {
    return init(InitOptions.defaults());
  }

  /**
   * Configure tracing to export to superbased over OTLP/HTTP. Idempotent: a
   * second call with the same export targets only updates the content,
   * sampling and hook options; different targets swap the exporters (never
   * a second processor). Returns the resolved settings.
   *
   * @throws IllegalArgumentException when {@code sampleRate} is outside 0..1
   */
  public static Settings init(InitOptions opts) {
    InitOptions o = opts == null ? InitOptions.defaults() : opts;
    Map<String, String> env = Env.snapshot();
    Settings s = Settings.resolve(env, o);
    Destination.Plan p = Destination.resolve(s, env, o.destination, o.endpoint, o.headers, o.apiKey != null);
    if (o.sampleRate == null) {
      String bad = Settings.samplingEnvProblem(env);
      if (!bad.isEmpty()) {
        p.withWarning(bad);
      }
    }
    Destination.logOnce(p);
    synchronized (LOCK) {
      vendorTracing = Map.copyOf(Vendor.apply());
      settings = s;
      plan = p;
      captureContent = s.captureContent;
      maxContentChars = s.maxContentChars;
      shutdownTimeout = s.shutdownTimeout;
      Map<String, Object> identity = s.identity(SDK_MARKER);
      SAMPLER.set(s.sampleRate, s.sampleParentBased);
      String key = configKey(s, p, o, identity);

      if (processor != null && processor.delegate() != null && key.equals(configKey)) {
        processor.pipeline = makePipeline(s, o, ownedProvider != null);
        return s;
      }

      if (provider == null || (o.tracerProvider != null && o.tracerProvider != provider)) {
        if (o.tracerProvider != null) {
          provider = o.tracerProvider;
          ownedProvider = null;
          ownedResourceAttrs = Map.of();
          processor = spanProcessorInternal();
          mode = "attached";
          modeWarning = "";
          serviceSeen = null;
        } else {
          Export.SwitchableProcessor proc = new Export.SwitchableProcessor();
          Map<String, Object> attrs = new LinkedHashMap<>(s.resourceAttributes);
          attrs.putAll(identity);
          attrs.put(Keys.SERVICE_NAME, s.serviceName);
          Resource resource = Resource.getDefault().merge(Resource.create(Attr.of(attrs)));
          SdkTracerProvider sdk =
              SdkTracerProvider.builder().setResource(resource).setSampler(SAMPLER).addSpanProcessor(proc).build();
          String newMode = "owned";
          modeWarning = "";
          try {
            GlobalOpenTelemetry.set(
                OpenTelemetrySdk.builder()
                    .setTracerProvider(sdk)
                    .setPropagators(ContextPropagators.create(AttributeContext.PROPAGATOR))
                    .build());
          } catch (IllegalStateException e) {
            // A host (or an OTel agent) registered its own: ours stays private
            // and not global, so it is "standalone", not "owned" (spans still
            // export and join the active trace).
            newMode = "standalone";
            modeWarning =
                "a global OpenTelemetry was already registered, so the SDK's provider is not the global one (mode standalone): spans from the app's own tracer reach the SDK only through spanProcessor() and tracerProvider()";
            Util.warn(modeWarning);
          }
          provider = sdk;
          ownedProvider = sdk;
          ownedResourceAttrs = attrs;
          processor = proc;
          mode = newMode;
          serviceSeen = null;
        }
      }

      SpanProcessor delegate = buildDelegate(s, p, o, processor);
      Map<String, Object> stamp = new LinkedHashMap<>();
      for (Map.Entry<String, Object> e : identity.entrySet()) {
        if (!Objects.equals(ownedResourceAttrs.get(e.getKey()), e.getValue())) {
          stamp.put(e.getKey(), e.getValue());
        }
      }
      processor.shutdownTimeout = shutdownTimeout;
      processor.pipeline = makePipeline(s, o, ownedProvider != null);
      SpanProcessor old = processor.swap(delegate, stamp);
      if (old != null) {
        Export.shutdownBounded(old, shutdownTimeout);
      }
      configKey = key;
      tracer = provider.get(TRACER_NAME, VERSION);
      return s;
    }
  }

  private static String configKey(Settings s, Destination.Plan p, InitOptions o, Map<String, Object> identity) {
    StringBuilder sb = new StringBuilder();
    for (Destination.Target t : p.exporters) {
      sb.append(t.key()).append(';');
    }
    sb.append(identity).append(';').append(s.serviceName).append(';').append(s.quiet).append(';').append(s.console);
    sb.append(';').append(o.exporter == null ? 0 : System.identityHashCode(o.exporter));
    sb.append(';').append(o.exporters == null ? "" : identityOf(o.exporters));
    sb.append(';').append(o.tracerProvider == null ? 0 : System.identityHashCode(o.tracerProvider));
    return sb.toString();
  }

  private static String identityOf(Map<String, SpanExporter> m) {
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<String, SpanExporter> e : new java.util.TreeMap<>(m).entrySet()) {
      sb.append(e.getKey()).append('=').append(System.identityHashCode(e.getValue())).append(',');
    }
    return sb.toString();
  }

  private static Pipeline makePipeline(Settings s, InitOptions o, boolean owns) {
    return new Pipeline(
        s.captureContent,
        s.maxContentChars,
        o.mask,
        o.shouldExport,
        owns ? null : s.sampleRate,
        Vendor.dropPrefixes(vendorTracing));
  }

  private static SpanProcessor buildDelegate(Settings s, Destination.Plan p, InitOptions o, Export.SwitchableProcessor owner) {
    List<SpanProcessor> procs = new ArrayList<>();
    boolean ownExporter = false;
    for (Destination.Target t : p.exporters) {
      SpanExporter inner = null;
      if (o.exporters != null) {
        inner = o.exporters.get(t.name);
      } else if (o.exporter != null) {
        inner = o.exporter;
      }
      if (inner == null) {
        OtlpHttpSpanExporterBuilder b =
            OtlpHttpSpanExporter.builder().setEndpoint(t.endpoint).setTimeout(t.timeout).setExecutorService(Export.EXPORT_EXECUTOR);
        for (Map.Entry<String, String> h : t.headers.entrySet()) {
          b.addHeader(h.getKey(), h.getValue());
        }
        inner = b.build();
        ownExporter = true;
      }
      procs.add(BatchSpanProcessor.builder(new Export.CountingExporter(inner, owner)).build());
    }
    if (ownExporter) {
      Export.installLogCapture(s.quiet);
    } else {
      Export.removeLogCapture();
    }
    int legs = procs.size();
    if (s.console) {
      // The console is another destination: it gets the same content rules as export.
      procs.add(SimpleSpanProcessor.create(new Export.CountingContentExporter(new ConsoleExporter(), owner)));
    }
    if (procs.isEmpty()) {
      return new Export.Discard();
    }
    if (procs.size() == 1 && legs == 1) {
      return procs.get(0);
    }
    return new Export.Fanout(procs, legs);
  }

  /** Prints each finished span to stderr (the {@code console} option). */
  static final class ConsoleExporter implements SpanExporter {
    @Override
    public CompletableResultCode export(Collection<SpanData> spans) {
      for (SpanData s : spans) {
        System.err.println(
            "superbased span "
                + s.getName()
                + " trace="
                + s.getTraceId()
                + " span="
                + s.getSpanId()
                + " "
                + s.getAttributes());
      }
      return CompletableResultCode.ofSuccess();
    }

    @Override
    public CompletableResultCode flush() {
      return CompletableResultCode.ofSuccess();
    }

    @Override
    public CompletableResultCode shutdown() {
      return CompletableResultCode.ofSuccess();
    }
  }

  private static Export.SwitchableProcessor spanProcessorInternal() {
    synchronized (LOCK) {
      if (hostProcessor == null) {
        hostProcessor = new Export.SwitchableProcessor();
      }
      return hostProcessor;
    }
  }

  /**
   * The SDK's span processor, for an app that builds its own
   * {@link SdkTracerProvider}: add it with {@code .addSpanProcessor(...)} and
   * pass the built provider to {@link InitOptions.Builder#tracerProvider}.
   * Inert until init().
   */
  public static SpanProcessor spanProcessor() {
    return spanProcessorInternal();
  }

  /** {@link #flush(Duration)} bounded by the init shutdown timeout. */
  public static boolean flush() {
    return flush(null);
  }

  /**
   * Export every finished span now, bounded by {@code timeout} (null: the
   * init shutdown timeout). True when everything was exported in time; never
   * throws. Call at the end of a serverless handler.
   */
  public static boolean flush(Duration timeout) {
    Export.SwitchableProcessor proc = processor;
    if (proc == null || proc.delegate() == null) {
      return true;
    }
    try {
      return Export.flushBounded(proc, timeout == null ? shutdownTimeout : timeout);
    } catch (RuntimeException e) {
      return false;
    }
  }

  /** {@link #shutdown(Duration)} bounded by the init shutdown timeout. */
  public static boolean shutdown() {
    return shutdown(null);
  }

  /**
   * Flush and stop the SDK's exporters, bounded by {@code timeout} even when
   * an endpoint is down; never throws. A host's own provider keeps running. A
   * later init() starts exporting again.
   */
  public static boolean shutdown(Duration timeout) {
    SpanProcessor old;
    synchronized (LOCK) {
      Export.SwitchableProcessor proc = processor;
      if (proc == null) {
        return true;
      }
      old = proc.detach();
      configKey = null;
    }
    // Undo the exporter log filters init() installed (a later init() reinstalls them).
    Export.removeLogCapture();
    if (old == null) {
      return true;
    }
    try {
      return Export.shutdownBounded(old, timeout == null ? shutdownTimeout : timeout);
    } catch (RuntimeException e) {
      return false;
    } finally {
      Export.maybeLogFailures();
    }
  }

  /** The settings the last init() resolved (null before init). */
  public static Settings settings() {
    return settings;
  }

  static Destination.Plan plan() {
    return plan;
  }

  static boolean captureContent() {
    return captureContent;
  }

  static int maxContentChars() {
    return maxContentChars;
  }

  /**
   * A snapshot of the SDK's health, by the contract's wire names
   * (sdk-api-surface.md section 1): {@code mode}, {@code initialized},
   * {@code pending_spans}, {@code exported_spans}, {@code failed_exports},
   * {@code dropped_spans}, {@code last_error}, {@code sampled_out_spans},
   * {@code filtered_spans}, {@code mask_errors}, {@code destination},
   * {@code destinations}, {@code admission_degraded}, {@code vendor_tracing},
   * {@code usage_net_input_corrected} and the rest. Never the credential.
   */
  public static Map<String, Object> diagnostics() {
    Map<String, Object> out = new LinkedHashMap<>(Export.STATS.snapshot());
    out.putAll(Pipeline.COUNTERS.snapshot());
    out.putAll(Admit.snapshot());
    Export.SwitchableProcessor proc = processor;
    out.put("mode", mode);
    out.put("initialized", proc != null && proc.delegate() != null);
    out.put("vendor_tracing", new LinkedHashMap<>(vendorTracing));
    Destination.Plan p = plan;
    if (p != null) {
      out.putAll(p.summary());
    } else {
      out.put("destinations", new ArrayList<>());
    }
    String mw = modeWarning;
    if (!mw.isEmpty()) {
      List<String> ws = new ArrayList<>();
      Object have = out.get("warnings");
      if (have instanceof List) {
        for (Object w : (List<?>) have) {
          ws.add(String.valueOf(w));
        }
      }
      ws.add(mw);
      out.put("warnings", ws);
    }
    return out;
  }

  /** The provider that holds the SDK's spans (the SDK's own, or the app's), or the global one before init(). */
  public static TracerProvider tracerProvider() {
    TracerProvider p = provider;
    return p != null ? p : GlobalOpenTelemetry.getTracerProvider();
  }

  static Tracer tracer() {
    Tracer t = tracer;
    return t != null ? t : GlobalOpenTelemetry.getTracer(TRACER_NAME);
  }

  /** The service.name the SDK's spans carry ("" when unknown). */
  static String resourceServiceName() {
    String seen = serviceSeen;
    if (seen != null) {
      return seen;
    }
    if (ownedProvider != null) {
      Object v = ownedResourceAttrs.get(Keys.SERVICE_NAME);
      return v == null ? "" : String.valueOf(v);
    }
    return "";
  }

  /**
   * Remember the service.name of the resource of the provider holding the
   * SDK's spans (an attached app's own provider), the first one seen.
   */
  static void noteServiceName(ReadWriteSpan span) {
    if (serviceSeen != null) {
      return;
    }
    try {
      String v = span.toSpanData().getResource().getAttribute(io.opentelemetry.api.common.AttributeKey.stringKey(Keys.SERVICE_NAME));
      if (v != null) {
        String name = String.valueOf(v).strip();
        if (!name.isEmpty() && !name.startsWith("unknown_service")) {
          serviceSeen = name;
        }
      }
    } catch (RuntimeException e) {
      // never breaks the span
    }
  }

  // --- spans -----------------------------------------------------------------------------------

  /** A span of any OpenInference kind (default CHAIN): {@code .kind(Kind.AGENT).start()}. */
  public static SpanStarter span(String name) {
    return new SpanStarter(name, "span", Kind.CHAIN);
  }

  /** An LLM span ({@code gen_ai.operation.name} default chat; model, provider, prompt, system). */
  public static SpanStarter llmSpan(String name) {
    return new SpanStarter(name, "llm", Kind.LLM);
  }

  /** A TOOL span ({@code execute_tool}; toolName, callId, arguments). */
  public static SpanStarter toolSpan(String name) {
    return new SpanStarter(name, "tool", Kind.TOOL);
  }

  /** A RETRIEVER span ({@code retrieval}; query). */
  public static SpanStarter retrieverSpan(String name) {
    return new SpanStarter(name, "retriever", Kind.RETRIEVER);
  }

  /** An AGENT span ({@code invoke_agent}; agentName, agentId). */
  public static SpanStarter agentSpan(String name) {
    return new SpanStarter(name, "agent", Kind.AGENT);
  }

  /** An EMBEDDING span ({@code embeddings}; model, provider). */
  public static SpanStarter embeddingSpan(String name) {
    return new SpanStarter(name, "embedding", Kind.EMBEDDING);
  }

  /**
   * Record token usage, ids and the outcome on an LLM (or embedding) span.
   * An input below cache read + cache write is read as NET, recorded as
   * input + cache, counted ({@code usage_net_input_corrected}) and warned
   * about once.
   *
   * @throws IllegalArgumentException for a negative count (nothing is written)
   */
  public static void setUsage(Span span, Usage usage) {
    Spans.setUsage(span, usage);
  }

  /**
   * Attach request and response bodies (content rules apply): on a TOOL span
   * to {@code gen_ai.tool.call.arguments} / {@code .result}; otherwise a
   * string to {@code input.value} / {@code output.value} and a message list
   * to {@code gen_ai.input.messages} / {@code gen_ai.output.messages}.
   */
  public static void setContent(Span span, Object prompt, Object response) {
    Spans.setContent(span, prompt, response, null, null);
  }

  /** {@code input.value} (a non-string is JSON-encoded; content rules apply). */
  public static void setInput(Span span, Object value) {
    Spans.setInput(span, value);
  }

  /** {@code output.value}; on a RETRIEVER span, the documents. */
  public static void setOutput(Span span, Object value) {
    Spans.setOutput(span, value);
  }

  /** {@code gen_ai.tool.call.result}. */
  public static void setToolResult(Span span, Object result) {
    Spans.setToolResult(span, result);
  }

  /** {@code gen_ai.retrieval.documents} (a JSON array; a string element becomes {@code {"content": s}}). */
  public static void setDocuments(Span span, Object documents) {
    Spans.setDocuments(span, documents);
  }

  /** {@code gen_ai.request.<name>}. */
  public static void setRequestParams(Span span, RequestParams params) {
    Spans.setRequestParams(span, params);
  }

  // --- identity and trace context ------------------------------------------------------------

  /**
   * Apply per-request values to the current span and to every span started
   * while the returned scope is open (inner wins, tags union). Close it in
   * a try-with-resources block.
   */
  public static AttributeScope propagateAttributes(TraceAttributes attrs) {
    return AttributeContext.enter(attrs);
  }

  /** {@link #propagateAttributes} around {@code fn}. */
  public static <T> T propagateAttributes(TraceAttributes attrs, Supplier<T> fn) {
    try (AttributeScope ignored = AttributeContext.enter(attrs)) {
      return fn.get();
    }
  }

  /** The same values from now on in this context; {@link AttributeScope#reset()} undoes them. */
  public static AttributeScope identify(TraceAttributes attrs) {
    return AttributeContext.enter(attrs);
  }

  /** The per-request values in effect here, by option name ({@code user}, {@code session_id}, ...). */
  public static Map<String, Object> getCurrentAttributes() {
    return AttributeContext.current(null).publicView();
  }

  /** The current trace id (32 lowercase hex), or "" outside a span. */
  public static String getCurrentTraceId() {
    return AttributeContext.currentTraceId();
  }

  /** The current span id (16 lowercase hex), or "". */
  public static String getCurrentSpanId() {
    return AttributeContext.currentSpanId();
  }

  /** The W3C {@code traceparent} of the current span, or "". */
  public static String getTraceparent() {
    return AttributeContext.inject(new LinkedHashMap<>()).getOrDefault("traceparent", "");
  }

  /** {@code traceparent} (+ {@code tracestate}, {@code baggage}) of the current context, in a new map. */
  public static Map<String, String> inject() {
    return AttributeContext.inject(null);
  }

  /** Write the W3C headers of the current context into {@code carrier} and return it. */
  public static Map<String, String> inject(Map<String, String> carrier) {
    return AttributeContext.inject(carrier);
  }

  /** The context carried by W3C headers in {@code carrier} (names matched case-insensitively). */
  public static Context extract(Map<String, ?> carrier) {
    return AttributeContext.extract(carrier);
  }

  /**
   * Make the context carried by {@code carrier} current (spans join the
   * caller's trace) and restore the {@code sbo.*} values sent as baggage.
   * Close the returned scope.
   */
  public static Scope continueTrace(Map<String, ?> carrier) {
    return AttributeContext.continueTrace(carrier);
  }

  /** {@link #continueTrace(Map)} around {@code fn}. */
  public static <T> T continueTrace(Map<String, ?> carrier, Supplier<T> fn) {
    try (Scope ignored = AttributeContext.continueTrace(carrier)) {
      return fn.get();
    }
  }

  // --- admit -----------------------------------------------------------------------------------

  /** {@link #admit(String, AdmitOptions)} with the defaults. */
  public static Verdict admit(String message) {
    return Admit.admit(message, null);
  }

  /**
   * Check an incoming user message against the app's admission policy BEFORE
   * running the agent. Never throws: no decision admits (or denies under
   * failClosed), counted in diagnostics and warned with the fix.
   */
  public static Verdict admit(String message, AdmitOptions options) {
    return Admit.admit(message, options);
  }

  // --- scores ----------------------------------------------------------------------------------

  /** {@link #score(String, Object, ScoreOptions)} with the defaults. */
  public static ScoreResult score(String name, Object value) {
    return Scores.score(name, value, null);
  }

  /**
   * Record a score ({@code source=sdk}) on a trace or span: a number, a
   * boolean or a short label. Never throws: check {@link ScoreResult#ok()}.
   */
  public static ScoreResult score(String name, Object value, ScoreOptions options) {
    return Scores.score(name, value, options);
  }

  /** {@link #feedback(Object, ScoreOptions)} with the defaults. */
  public static ScoreResult feedback(Object value) {
    return Scores.feedback(value, null);
  }

  /** Record an end user's feedback ({@code source=feedback}); every call is its own row. */
  public static ScoreResult feedback(Object value, ScoreOptions options) {
    return Scores.feedback(value, options);
  }

  /** {@link #score} on a worker thread (the current trace is carried). */
  public static CompletableFuture<ScoreResult> scoreAsync(String name, Object value, ScoreOptions options) {
    return CompletableFuture.supplyAsync(Context.current().wrapSupplier(() -> score(name, value, options)), ASYNC);
  }

  /** {@link #feedback} on a worker thread. */
  public static CompletableFuture<ScoreResult> feedbackAsync(Object value, ScoreOptions options) {
    return CompletableFuture.supplyAsync(Context.current().wrapSupplier(() -> feedback(value, options)), ASYNC);
  }

  // --- prompts ---------------------------------------------------------------------------------

  /** {@link #getPrompt(String, PromptOptions)} by label {@code production}. */
  public static Prompt getPrompt(String name) {
    return Prompts.getPrompt(name, null);
  }

  /**
   * Fetch prompt {@code name} from the registry of the destination, cached
   * for the cache TTL then revalidated in the background.
   *
   * @throws PromptException.NotFound when no registry has it (and no fallback was given)
   * @throws PromptException.FetchFailed when it could not be fetched (and no fallback)
   * @throws IllegalArgumentException for a bad name, label, version, or label + version
   */
  public static Prompt getPrompt(String name, PromptOptions options) {
    return Prompts.getPrompt(name, options);
  }

  /** {@link #getPrompt} on a worker thread; stamps the span current HERE. */
  public static CompletableFuture<Prompt> getPromptAsync(String name, PromptOptions options) {
    Span here = Span.current();
    return CompletableFuture.supplyAsync(Context.current().wrapSupplier(() -> getPrompt(name, options)), ASYNC)
        .thenApply(
            p -> {
              p.stamp(here);
              return p;
            });
  }

  // --- datasets and experiments ------------------------------------------------------------

  /**
   * A dataset by name or id on the first destination that has it.
   *
   * @throws ExperimentException when no destination has it or none is usable
   */
  public static Dataset getDataset(String nameOrId) {
    return Experiments.getDataset(nameOrId);
  }

  /**
   * Run the task over every item of {@code dataset} (a name or id, a
   * {@link Dataset}, or an Iterable of items: maps with {@code input},
   * {@code expected}, {@code metadata}, {@code id}, or bare inputs) and score
   * each output.
   *
   * @throws ExperimentException when the dataset is not found or the run cannot be created
   * @throws ExperimentGateFailedException when the failUnder gate fails
   */
  public static ExperimentResult runExperiment(Object dataset, ExperimentOptions options) {
    return Experiments.run(dataset, options);
  }

  /** {@link #runExperiment} on a worker thread. */
  public static CompletableFuture<ExperimentResult> runExperimentAsync(Object dataset, ExperimentOptions options) {
    return CompletableFuture.supplyAsync(Context.current().wrapSupplier(() -> runExperiment(dataset, options)), ASYNC);
  }

  // --- cost --------------------------------------------------------------------------------

  /** {@link #getTraceCost(String)} of the current trace. */
  public static Map<String, Object> getTraceCost() {
    return TraceCost.get(null);
  }

  /**
   * The TraceCost object of {@code traceId} with the wire names
   * ({@code cost_usd}, {@code cost_provenance}, {@code spans[].cost_source},
   * ...) plus {@code destination}, or null when no destination has it yet.
   *
   * @throws IllegalArgumentException for a malformed trace id
   */
  public static Map<String, Object> getTraceCost(String traceId) {
    return TraceCost.get(traceId);
  }

  /** {@link #getTraceCost(String)} on a worker thread (null: the trace current HERE). */
  public static CompletableFuture<Map<String, Object>> getTraceCostAsync(String traceId) {
    String tid = TraceCost.traceId(traceId);
    if (tid.isEmpty()) {
      return CompletableFuture.completedFuture(null);
    }
    return CompletableFuture.supplyAsync(() -> TraceCost.get(tid), ASYNC);
  }

  /**
   * Set {@code request_id} on {@code span} (null: the current one) from the
   * AI gateway's {@code X-SBO-Request-Id} response header. See {@link Gateway}.
   */
  public static boolean stampGatewayRequestId(Map<String, ?> responseHeaders, Span span) {
    return Gateway.stampRequestId(responseHeaders, span);
  }

  /** The app identity headers for a request to the AI gateway. See {@link Gateway#headers()}. */
  public static Map<String, String> gatewayHeaders() {
    return Gateway.headers();
  }

  // --- tests -----------------------------------------------------------------------------------

  /** Forget all SDK state (tests only). */
  static void resetForTests() {
    synchronized (LOCK) {
      if (processor != null) {
        SpanProcessor old = processor.detach();
        if (old != null) {
          Export.shutdownBounded(old, Duration.ofSeconds(1));
        }
      }
      if (ownedProvider != null) {
        ownedProvider.shutdown().join(1, java.util.concurrent.TimeUnit.SECONDS);
      }
      tracer = null;
      provider = null;
      ownedProvider = null;
      ownedResourceAttrs = Map.of();
      processor = null;
      hostProcessor = null;
      configKey = null;
      settings = null;
      plan = null;
      mode = "";
      modeWarning = "";
      serviceSeen = null;
      vendorTracing = Map.of();
      captureContent = true;
      maxContentChars = Settings.DEFAULT_MAX_CONTENT_CHARS;
      shutdownTimeout = Settings.DEFAULT_SHUTDOWN_TIMEOUT;
      SAMPLER.set(1.0, true);
      GlobalOpenTelemetry.resetForTest();
    }
    Export.removeLogCapture();
    Destination.resetForTests();
    Control.resetForTests();
    Prompts.CACHE.clear();
    Export.STATS.reset();
    Admit.resetForTests();
    Pipeline.COUNTERS.reset();
    Vendor.resetForTests();
    Spans.resetForTests();
    Scores.resetForTests();
    TraceCost.resetForTests();
    Http.transport = Http.JDK;
  }

  /** Attributes builder helper kept for typed callers. */
  static Attributes attributes(Map<String, Object> m) {
    AttributesBuilder b = Attributes.builder();
    for (Map.Entry<String, Object> e : m.entrySet()) {
      Attr.put(b, e.getKey(), e.getValue());
    }
    return b.build();
  }
}
