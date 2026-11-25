package app.superbased.sdk;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Every SDK option, resolved: the {@link InitOptions} value, else the
 * {@code SUPERBASED_*} variable, else the standard {@code OTEL_*} one (where
 * one exists), else the default. {@link #toString()} never shows the
 * credential or the headers.
 */
public final class Settings {
  public static final String DEFAULT_ENDPOINT = "http://127.0.0.1:4318/v1/traces";
  public static final String DEFAULT_SERVICE_NAME = "custom-app";
  public static final int DEFAULT_MAX_CONTENT_CHARS = 8000;
  public static final Duration DEFAULT_EXPORT_TIMEOUT = Duration.ofSeconds(5);
  public static final Duration DEFAULT_SHUTDOWN_TIMEOUT = Duration.ofSeconds(2);
  public static final String TRACES_PATH = "/v1/traces";
  public static final String DEFAULT_NODE_URL = "http://127.0.0.1:8081";
  public static final Duration DEFAULT_API_TIMEOUT = Duration.ofSeconds(5);
  public static final Duration DEFAULT_PROMPT_CACHE_TTL = Duration.ofSeconds(60);

  final String endpoint;
  final Map<String, String> headers;
  final String apiKey;
  final String serviceName;
  /** Which rung named the service: argument, env, manifest (the main jar's Implementation-Title) or default. */
  final String serviceNameSource;
  final Map<String, String> resourceAttributes;
  final String tenant;
  final String user;
  final String sessionId;
  final boolean captureContent;
  final int maxContentChars;
  final Duration exportTimeout;
  final Duration shutdownTimeout;
  final boolean quiet;
  final boolean console;
  final String release;
  final String environment;
  final List<String> tags;
  final Map<String, String> metadata;
  final double sampleRate;
  final boolean sampleParentBased;
  final String destination;
  final String orgUrl;
  final String nodeUrl;
  final boolean discover;
  final Duration apiTimeout;
  final Duration promptCacheTtl;

  private Settings(
      String endpoint,
      Map<String, String> headers,
      String apiKey,
      String serviceName,
      String serviceNameSource,
      Map<String, String> resourceAttributes,
      String tenant,
      String user,
      String sessionId,
      boolean captureContent,
      int maxContentChars,
      Duration exportTimeout,
      Duration shutdownTimeout,
      boolean quiet,
      boolean console,
      String release,
      String environment,
      List<String> tags,
      Map<String, String> metadata,
      double sampleRate,
      boolean sampleParentBased,
      String destination,
      String orgUrl,
      String nodeUrl,
      boolean discover,
      Duration apiTimeout,
      Duration promptCacheTtl) {
    this.endpoint = endpoint;
    this.headers = headers;
    this.apiKey = apiKey;
    this.serviceName = serviceName;
    this.serviceNameSource = serviceNameSource;
    this.resourceAttributes = resourceAttributes;
    this.tenant = tenant;
    this.user = user;
    this.sessionId = sessionId;
    this.captureContent = captureContent;
    this.maxContentChars = maxContentChars;
    this.exportTimeout = exportTimeout;
    this.shutdownTimeout = shutdownTimeout;
    this.quiet = quiet;
    this.console = console;
    this.release = release;
    this.environment = environment;
    this.tags = tags;
    this.metadata = metadata;
    this.sampleRate = sampleRate;
    this.sampleParentBased = sampleParentBased;
    this.destination = destination;
    this.orgUrl = orgUrl;
    this.nodeUrl = nodeUrl;
    this.discover = discover;
    this.apiTimeout = apiTimeout;
    this.promptCacheTtl = promptCacheTtl;
  }

  // --- public read access (never the credential or headers) -------------------------

  public String endpoint() {
    return endpoint;
  }

  public String serviceName() {
    return serviceName;
  }

  /** Which rung named the service: argument, env, manifest (the main jar's Implementation-Title) or default. */
  public String serviceNameSource() {
    return serviceNameSource;
  }

  public String tenant() {
    return tenant;
  }

  public String user() {
    return user;
  }

  public String sessionId() {
    return sessionId;
  }

  public boolean captureContent() {
    return captureContent;
  }

  public int maxContentChars() {
    return maxContentChars;
  }

  public Duration exportTimeout() {
    return exportTimeout;
  }

  public Duration shutdownTimeout() {
    return shutdownTimeout;
  }

  public boolean quiet() {
    return quiet;
  }

  public boolean console() {
    return console;
  }

  public String release() {
    return release;
  }

  public String environment() {
    return environment;
  }

  public List<String> tags() {
    return tags;
  }

  public Map<String, String> metadata() {
    return metadata;
  }

  public double sampleRate() {
    return sampleRate;
  }

  public boolean sampleParentBased() {
    return sampleParentBased;
  }

  /** The destination asked for ("" when none was: the machine's default, else local). */
  public String destination() {
    return destination;
  }

  public String orgUrl() {
    return orgUrl;
  }

  public String nodeUrl() {
    return nodeUrl;
  }

  public boolean discover() {
    return discover;
  }

  public Duration apiTimeout() {
    return apiTimeout;
  }

  public Duration promptCacheTtl() {
    return promptCacheTtl;
  }

  /** Whether a credential was configured (never the credential itself). */
  public boolean hasApiKey() {
    return !apiKey.isEmpty();
  }

  @Override
  public String toString() {
    return "Settings{endpoint="
        + endpoint
        + ", serviceName="
        + serviceName
        + ", destination="
        + destination
        + ", orgUrl="
        + orgUrl
        + ", nodeUrl="
        + nodeUrl
        + ", discover="
        + discover
        + ", captureContent="
        + captureContent
        + ", maxContentChars="
        + maxContentChars
        + ", sampleRate="
        + sampleRate
        + ", release="
        + release
        + ", environment="
        + environment
        + ", tags="
        + tags
        + "}";
  }

  /** Process-wide identity, on the resource (or stamped per span when attached). */
  Map<String, Object> identity(String sdkMarker) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put(Keys.SDK, sdkMarker);
    if (!tenant.isEmpty()) {
      out.put(Keys.TENANT, tenant);
    }
    if (!user.isEmpty()) {
      out.put(Keys.USER, user);
    }
    if (!sessionId.isEmpty()) {
      out.put(Keys.SESSION, sessionId);
    }
    if (!release.isEmpty()) {
      out.put(Keys.RESOURCE_RELEASE, release);
    }
    if (!environment.isEmpty()) {
      out.put(Keys.RESOURCE_ENVIRONMENT, environment);
    }
    if (!tags.isEmpty()) {
      out.put(Keys.TAGS, tags);
    }
    for (Map.Entry<String, String> e : metadata.entrySet()) {
      out.put(Keys.METADATA_PREFIX + e.getKey(), e.getValue());
    }
    return out;
  }

  // --- resolution ----------------------------------------------------------------------

  private static final List<String> FALSE_WORDS = List.of("0", "false", "no", "off", "");

  static boolean envFlag(Map<String, String> env, boolean dflt, String... names) {
    for (String n : names) {
      String raw = env.get(n);
      if (raw != null) {
        return !FALSE_WORDS.contains(raw.strip().toLowerCase(Locale.ROOT));
      }
    }
    return dflt;
  }

  static String envStr(Map<String, String> env, String... names) {
    for (String n : names) {
      String v = env.get(n);
      if (v != null && !v.strip().isEmpty()) {
        return v.strip();
      }
    }
    return "";
  }

  private static final Pattern FLOAT =
      Pattern.compile("[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?");

  /** A decimal number (Python {@code float()} of a plain numeral), or null. */
  static Double parseNumber(String raw) {
    if (raw == null) {
      return null;
    }
    String s = raw.strip();
    if (!FLOAT.matcher(s).matches()) {
      return null;
    }
    try {
      return Double.parseDouble(s);
    } catch (NumberFormatException e) {
      return null;
    }
  }

  static Duration envMs(Map<String, String> env, String... names) {
    for (String n : names) {
      Double v = parseNumber(env.get(n));
      if (v != null) {
        return Duration.ofNanos((long) (Math.max(1.0, v) * 1_000_000L));
      }
    }
    return null;
  }

  private static int envInt(Map<String, String> env, String name, int dflt) {
    String raw = env.get(name);
    if (raw == null || raw.strip().isEmpty()) {
      return dflt;
    }
    try {
      return Integer.parseInt(raw.strip());
    } catch (NumberFormatException e) {
      return dflt;
    }
  }

  /** The service name the ladder gives for this process ({@link ServiceName}). */
  static String resolveServiceName(String explicit, Map<String, String> env) {
    return ServiceName.resolve(explicit, env).name;
  }

  static String resolveEndpoint(String explicit, Map<String, String> env) {
    if (explicit != null && !explicit.isEmpty()) {
      return explicit;
    }
    String v = envStr(env, "SUPERBASED_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT");
    if (!v.isEmpty()) {
      return v;
    }
    String base = envStr(env, "OTEL_EXPORTER_OTLP_ENDPOINT");
    if (!base.isEmpty()) {
      return Http.stripRight(base, '/') + TRACES_PATH;
    }
    return DEFAULT_ENDPOINT;
  }

  /** One sampler row: rate (null: from the ARG), parent based, takes an ARG. */
  private static final class SamplerRow {
    final Double rate;
    final boolean parent;
    final boolean takesArg;

    SamplerRow(Double rate, boolean parent, boolean takesArg) {
      this.rate = rate;
      this.parent = parent;
      this.takesArg = takesArg;
    }
  }

  private static final Map<String, SamplerRow> SAMPLERS = new TreeMap<>();

  static {
    SAMPLERS.put("always_on", new SamplerRow(1.0, false, false));
    SAMPLERS.put("always_off", new SamplerRow(0.0, false, false));
    SAMPLERS.put("traceidratio", new SamplerRow(null, false, true));
    SAMPLERS.put("parentbased_always_on", new SamplerRow(1.0, true, false));
    SAMPLERS.put("parentbased_always_off", new SamplerRow(0.0, true, false));
    SAMPLERS.put("parentbased_traceidratio", new SamplerRow(null, true, true));
  }

  private static Double ratio(String raw) {
    Double v = parseNumber(raw);
    return v != null && v >= 0.0 && v <= 1.0 ? v : null;
  }

  /** (rate, parent based), as a two-element holder. */
  static final class Sampling {
    final double rate;
    final boolean parentBased;

    Sampling(double rate, boolean parentBased) {
      this.rate = rate;
      this.parentBased = parentBased;
    }
  }

  /**
   * The explicit rate, then {@code SUPERBASED_SAMPLE_RATE} (parent based),
   * then {@code OTEL_TRACES_SAMPLER} / {@code OTEL_TRACES_SAMPLER_ARG}, else
   * (1.0, parent based). An explicit rate outside 0..1 throws
   * IllegalArgumentException; a bad env value is ignored.
   */
  static Sampling resolveSampling(Double explicit, Map<String, String> env) {
    if (explicit != null) {
      if (explicit.isNaN() || explicit < 0.0 || explicit > 1.0) {
        throw new IllegalArgumentException("sampleRate must be a number in 0..1, got " + explicit);
      }
      return new Sampling(explicit, true);
    }
    Double v = ratio(envStr(env, "SUPERBASED_SAMPLE_RATE"));
    if (v != null) {
      return new Sampling(v, true);
    }
    SamplerRow row = SAMPLERS.get(envStr(env, "OTEL_TRACES_SAMPLER").toLowerCase(Locale.ROOT));
    if (row != null) {
      double rate = row.rate == null ? 1.0 : row.rate;
      if (row.takesArg) {
        Double arg = ratio(envStr(env, "OTEL_TRACES_SAMPLER_ARG"));
        rate = arg == null ? 1.0 : arg;
      }
      return new Sampling(rate, row.parent);
    }
    return new Sampling(1.0, true);
  }

  /**
   * Why an environment sampling value was ignored ("" when none was), naming
   * each variable (review E-38). Only consulted with no explicit rate.
   */
  static String samplingEnvProblem(Map<String, String> env) {
    List<String> bad = new ArrayList<>();
    String raw = envStr(env, "SUPERBASED_SAMPLE_RATE");
    if (!raw.isEmpty() && ratio(raw) == null) {
      bad.add("SUPERBASED_SAMPLE_RATE='" + raw + "'");
    }
    if (raw.isEmpty() || ratio(raw) == null) {
      SamplerRow row = SAMPLERS.get(envStr(env, "OTEL_TRACES_SAMPLER").toLowerCase(Locale.ROOT));
      String arg = envStr(env, "OTEL_TRACES_SAMPLER_ARG");
      if (row != null && row.takesArg && !arg.isEmpty() && ratio(arg) == null) {
        bad.add("OTEL_TRACES_SAMPLER_ARG='" + arg + "'");
      }
    }
    if (bad.isEmpty()) {
      return "";
    }
    return String.join(" and ", bad) + " is not a number in 0..1; ignored";
  }

  private static <T> T pick(T explicit, T fromEnv) {
    return explicit == null ? fromEnv : explicit;
  }

  private static Duration durationOr(Duration explicit, Map<String, String> env, String name, Duration dflt, boolean floorZero) {
    Duration min = floorZero ? Duration.ZERO : Duration.ofMillis(1);
    if (explicit != null) {
      return explicit.compareTo(min) < 0 ? min : explicit;
    }
    Duration v = envMs(env, name);
    if (v == null) {
      return dflt;
    }
    return v.compareTo(min) < 0 ? min : v;
  }

  /** Settings from {@code opts} over {@code env}. */
  static Settings resolve(Map<String, String> env, InitOptions opts) {
    InitOptions o = opts == null ? InitOptions.defaults() : opts;
    Map<String, String> hdrs = new TreeMap<>();
    for (String n : List.of("OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS", "SUPERBASED_OTLP_HEADERS")) {
      hdrs.putAll(Util.parseKvList(env.get(n)));
    }
    if (o.headers != null) {
      hdrs.putAll(o.headers);
    }
    Sampling sampling = resolveSampling(o.sampleRate, env);
    Object tagsIn = o.tags != null ? o.tags : envStr(env, "SUPERBASED_TAGS");
    Map<String, ?> metaIn = o.metadata != null ? o.metadata : Util.parseKvList(env.get("SUPERBASED_METADATA"));
    List<String> tags = List.copyOf(Util.normalizeTags(tagsIn));
    Map<String, String> meta = new TreeMap<>(Json::compareCodePoints);
    meta.putAll(Util.normalizeMetadata(List.of(metaIn)));
    Duration exportTimeout;
    if (o.exportTimeout != null) {
      exportTimeout = o.exportTimeout.compareTo(Duration.ofMillis(1)) < 0 ? Duration.ofMillis(1) : o.exportTimeout;
    } else {
      Duration v = envMs(env, "SUPERBASED_EXPORT_TIMEOUT_MS", "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", "OTEL_EXPORTER_OTLP_TIMEOUT");
      exportTimeout = v == null ? DEFAULT_EXPORT_TIMEOUT : v;
    }
    Duration shutdown = o.shutdownTimeout != null ? o.shutdownTimeout : envMs(env, "SUPERBASED_SHUTDOWN_TIMEOUT_MS");
    if (shutdown == null) {
      shutdown = DEFAULT_SHUTDOWN_TIMEOUT;
    }
    if (shutdown.isNegative()) {
      shutdown = Duration.ZERO;
    }
    String nodeUrl = pick(o.nodeUrl, Util.first(envStr(env, "SUPERBASED_NODE_URL"), DEFAULT_NODE_URL));
    ServiceName.Resolved service = ServiceName.resolve(o.serviceName, env);
    return new Settings(
        resolveEndpoint(o.endpoint, env),
        java.util.Collections.unmodifiableMap(hdrs),
        pick(o.apiKey, envStr(env, "SUPERBASED_API_KEY")),
        service.name,
        service.source,
        java.util.Collections.unmodifiableMap(new TreeMap<>(Util.parseKvList(env.get("OTEL_RESOURCE_ATTRIBUTES")))),
        pick(o.tenant, envStr(env, "SUPERBASED_TENANT")),
        pick(o.user, envStr(env, "SUPERBASED_USER")),
        pick(o.sessionId, envStr(env, "SUPERBASED_SESSION_ID")),
        pick(o.captureContent, envFlag(env, true, "SUPERBASED_CAPTURE_CONTENT", "OBSERVER_CAPTURE_CONTENT")),
        pick(o.maxContentChars, envInt(env, "SUPERBASED_MAX_CONTENT_CHARS", DEFAULT_MAX_CONTENT_CHARS)),
        exportTimeout,
        shutdown,
        pick(o.quiet, envFlag(env, true, "SUPERBASED_QUIET")),
        pick(o.console, envFlag(env, false, "SUPERBASED_CONSOLE")),
        Util.head(pick(o.release, envStr(env, "SUPERBASED_RELEASE")).strip(), 256),
        Util.head(pick(o.environment, envStr(env, "SUPERBASED_ENVIRONMENT")).strip(), 256),
        tags,
        java.util.Collections.unmodifiableMap(meta),
        sampling.rate,
        sampling.parentBased,
        pick(o.destination, envStr(env, "SUPERBASED_DESTINATION")).strip().toLowerCase(Locale.ROOT),
        Http.stripRight(pick(o.orgUrl, envStr(env, "SUPERBASED_ORG_URL")).strip(), '/'),
        Http.stripRight(nodeUrl.strip(), '/'),
        pick(o.discover, envFlag(env, true, "SUPERBASED_DISCOVER")),
        durationOr(o.apiTimeout, env, "SUPERBASED_API_TIMEOUT_MS", DEFAULT_API_TIMEOUT, false),
        durationOr(o.promptCacheTtl, env, "SUPERBASED_PROMPT_CACHE_TTL_MS", DEFAULT_PROMPT_CACHE_TTL, true));
  }
}
