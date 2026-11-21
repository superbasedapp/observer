package app.superbased.sdk;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SpanExporter;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Predicate;

/**
 * The options of {@link Superbased#init(InitOptions)}. Every option has an
 * environment variable (a {@code SUPERBASED_*} one, then the standard
 * {@code OTEL_*} one where it exists); an option set here wins. An option left
 * unset falls through to the environment, then to the default.
 *
 * <pre>{@code
 * Superbased.init(InitOptions.builder()
 *     .serviceName("support-bot")
 *     .release("2026.11.20")
 *     .build());
 * }</pre>
 */
public final class InitOptions {
  final String endpoint;
  final String tenant;
  final String user;
  final String sessionId;
  final String serviceName;
  final Map<String, String> headers;
  final String apiKey;
  final Boolean console;
  final Boolean captureContent;
  final Integer maxContentChars;
  final Duration exportTimeout;
  final Duration shutdownTimeout;
  final Boolean quiet;
  final String release;
  final String environment;
  final List<String> tags;
  final Map<String, Object> metadata;
  final Double sampleRate;
  final Predicate<SpanData> shouldExport;
  final BiFunction<Object, String, Object> mask;
  final String destination;
  final String orgUrl;
  final String nodeUrl;
  final Boolean discover;
  final Duration apiTimeout;
  final Duration promptCacheTtl;
  final SpanExporter exporter;
  final Map<String, SpanExporter> exporters;
  final SdkTracerProvider tracerProvider;

  private InitOptions(Builder b) {
    endpoint = b.endpoint;
    tenant = b.tenant;
    user = b.user;
    sessionId = b.sessionId;
    serviceName = b.serviceName;
    headers = b.headers == null ? null : Map.copyOf(b.headers);
    apiKey = b.apiKey;
    console = b.console;
    captureContent = b.captureContent;
    maxContentChars = b.maxContentChars;
    exportTimeout = b.exportTimeout;
    shutdownTimeout = b.shutdownTimeout;
    quiet = b.quiet;
    release = b.release;
    environment = b.environment;
    tags = b.tags == null ? null : List.copyOf(b.tags);
    metadata = b.metadata == null ? null : java.util.Collections.unmodifiableMap(new LinkedHashMap<>(b.metadata));
    sampleRate = b.sampleRate;
    shouldExport = b.shouldExport;
    mask = b.mask;
    destination = b.destination;
    orgUrl = b.orgUrl;
    nodeUrl = b.nodeUrl;
    discover = b.discover;
    apiTimeout = b.apiTimeout;
    promptCacheTtl = b.promptCacheTtl;
    exporter = b.exporter;
    exporters = b.exporters == null ? null : Map.copyOf(b.exporters);
    tracerProvider = b.tracerProvider;
  }

  /** Every option unset: the environment and the defaults decide. */
  public static InitOptions defaults() {
    return builder().build();
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Builder of {@link InitOptions}. Every setter is optional. */
  public static final class Builder {
    private String endpoint;
    private String tenant;
    private String user;
    private String sessionId;
    private String serviceName;
    private Map<String, String> headers;
    private String apiKey;
    private Boolean console;
    private Boolean captureContent;
    private Integer maxContentChars;
    private Duration exportTimeout;
    private Duration shutdownTimeout;
    private Boolean quiet;
    private String release;
    private String environment;
    private List<String> tags;
    private Map<String, Object> metadata;
    private Double sampleRate;
    private Predicate<SpanData> shouldExport;
    private BiFunction<Object, String, Object> mask;
    private String destination;
    private String orgUrl;
    private String nodeUrl;
    private Boolean discover;
    private Duration apiTimeout;
    private Duration promptCacheTtl;
    private SpanExporter exporter;
    private Map<String, SpanExporter> exporters;
    private SdkTracerProvider tracerProvider;

    private Builder() {}

    /** The local destination's OTLP/HTTP traces URL ({@code SUPERBASED_OTLP_ENDPOINT}). */
    public Builder endpoint(String v) {
      endpoint = v;
      return this;
    }

    /** Process-wide tenant ({@code SUPERBASED_TENANT}). */
    public Builder tenant(String v) {
      tenant = v;
      return this;
    }

    /** Process-wide end user ({@code SUPERBASED_USER}). */
    public Builder user(String v) {
      user = v;
      return this;
    }

    /** Process-wide session id ({@code SUPERBASED_SESSION_ID}). */
    public Builder sessionId(String v) {
      sessionId = v;
      return this;
    }

    /** {@code service.name} ({@code SUPERBASED_SERVICE_NAME}, {@code OTEL_SERVICE_NAME}). */
    public Builder serviceName(String v) {
      serviceName = v;
      return this;
    }

    /** Extra export headers, over {@code SUPERBASED_OTLP_HEADERS}. */
    public Builder headers(Map<String, String> v) {
      headers = v;
      return this;
    }

    /** The SDK credential {@code <key_id>.<secret>} ({@code SUPERBASED_API_KEY}). */
    public Builder apiKey(String v) {
      apiKey = v;
      return this;
    }

    /** Also print spans to stderr ({@code SUPERBASED_CONSOLE}). */
    public Builder console(boolean v) {
      console = v;
      return this;
    }

    /** Record prompt and response bodies (default on; {@code SUPERBASED_CAPTURE_CONTENT}). */
    public Builder captureContent(boolean v) {
      captureContent = v;
      return this;
    }

    /** Clip each content body to this many characters (default 8000). */
    public Builder maxContentChars(int v) {
      maxContentChars = v;
      return this;
    }

    /** Per export request ({@code SUPERBASED_EXPORT_TIMEOUT_MS}; default 5 s). */
    public Builder exportTimeout(Duration v) {
      exportTimeout = v;
      return this;
    }

    /** The bound on flush() and shutdown() ({@code SUPERBASED_SHUTDOWN_TIMEOUT_MS}; default 2 s). */
    public Builder shutdownTimeout(Duration v) {
      shutdownTimeout = v;
      return this;
    }

    /** Keep exporter warnings out of the host's logs (default on). */
    public Builder quiet(boolean v) {
      quiet = v;
      return this;
    }

    /** The app's release ({@code SUPERBASED_RELEASE}; resource {@code service.version}). */
    public Builder release(String v) {
      release = v;
      return this;
    }

    /** The deployment environment ({@code SUPERBASED_ENVIRONMENT}). */
    public Builder environment(String v) {
      environment = v;
      return this;
    }

    /** Process-wide tags ({@code SUPERBASED_TAGS}, a comma list). */
    public Builder tags(Collection<String> v) {
      tags = v == null ? null : new ArrayList<>(v);
      return this;
    }

    /** Process-wide metadata ({@code SUPERBASED_METADATA}, {@code k=v,k2=v2}). */
    public Builder metadata(Map<String, ?> v) {
      metadata = v == null ? null : new LinkedHashMap<>(v);
      return this;
    }

    /** Head sampling rate 0..1 (outside it: IllegalArgumentException at init). */
    public Builder sampleRate(double v) {
      sampleRate = v;
      return this;
    }

    /** Drop finished spans before export (a hook that throws keeps the span). */
    public Builder shouldExport(Predicate<SpanData> v) {
      shouldExport = v;
      return this;
    }

    /**
     * Rewrite each content attribute {@code (value, key) -> value} before
     * export; return null to drop it. A hook that throws drops that content,
     * never the span.
     */
    public Builder mask(BiFunction<Object, String, Object> v) {
      mask = v;
      return this;
    }

    /** {@code local}, {@code online} or {@code both} ({@code SUPERBASED_DESTINATION}). */
    public Builder destination(String v) {
      destination = v;
      return this;
    }

    /** The organization's gateway base URL ({@code SUPERBASED_ORG_URL}). */
    public Builder orgUrl(String v) {
      orgUrl = v;
      return this;
    }

    /** This machine's dashboard API ({@code SUPERBASED_NODE_URL}; default http://127.0.0.1:8081). */
    public Builder nodeUrl(String v) {
      nodeUrl = v;
      return this;
    }

    /** Ask the machine for its destination ({@code SUPERBASED_DISCOVER}; default on). */
    public Builder discover(boolean v) {
      discover = v;
      return this;
    }

    /** Scores, prompts, datasets, experiments ({@code SUPERBASED_API_TIMEOUT_MS}; default 5 s). */
    public Builder apiTimeout(Duration v) {
      apiTimeout = v;
      return this;
    }

    /** How long a fetched prompt is fresh ({@code SUPERBASED_PROMPT_CACHE_TTL_MS}; default 60 s). */
    public Builder promptCacheTtl(Duration v) {
      promptCacheTtl = v;
      return this;
    }

    /** Export with this exporter instead of OTLP/HTTP (tests, a custom transport). */
    public Builder exporter(SpanExporter v) {
      exporter = v;
      return this;
    }

    /** One exporter per destination name ({@code local}, {@code online}). */
    public Builder exporters(Map<String, SpanExporter> v) {
      exporters = v;
      return this;
    }

    /**
     * Attach to the app's own provider instead of building one. A built
     * {@link SdkTracerProvider} cannot take a processor later, so the app
     * builds it with {@code .addSpanProcessor(Superbased.spanProcessor())}
     * and passes it here.
     */
    public Builder tracerProvider(SdkTracerProvider v) {
      tracerProvider = v;
      return this;
    }

    public InitOptions build() {
      return new InitOptions(this);
    }
  }

  /** Attribute keys are plain strings; this helper exists for typed callers. */
  static AttributeKey<String> key(String name) {
    return AttributeKey.stringKey(name);
  }
}
