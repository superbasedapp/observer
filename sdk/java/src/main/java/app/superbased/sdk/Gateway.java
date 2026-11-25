package app.superbased.sdk;

import io.opentelemetry.api.trace.Span;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpHeaders;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * The organization's AI gateway helpers (contract cost-source.md section 4):
 * the request id the gateway answers with ({@code X-SBO-Request-Id}) stamped
 * on the span that made the call, so the organization joins its exact cost to
 * that span; and the app identity headers its app budget caps reserve against
 * ({@code X-Superbased-User}, {@code X-Superbased-Service}).
 *
 * <p>The Java SDK wraps no HTTP client (as the TypeScript SDK): pass
 * {@link #headers()} on each request to the gateway, and hand the response's
 * headers to {@link #stampRequestId}.
 *
 * <p>{@link #endpoint} and {@link #baseUrl} resolve where the gateway is
 * (hosted AI gateway arc L-172, lane L8; shared cases
 * {@code sdk/contract/ai-gateway-cases.json}): the organization's address
 * {@code https://<org host>/ai/<upstream>}, any address you name, or this
 * machine's app lane {@code http://127.0.0.1:8820/up/<lane>}.
 * {@link GatewayRefusalException#parse} reads a refusal.
 */
public final class Gateway {
  public static final String REQUEST_ID_HEADER = "X-SBO-Request-Id";
  public static final String USER_HEADER = "X-Superbased-User";
  public static final String SERVICE_HEADER = "X-Superbased-Service";
  /** Selects the upstream on a gateway without a path lane. */
  public static final String UPSTREAM_HEADER = "X-SBO-Upstream";
  /** The W3C trace context header {@link #headers()} sends. */
  public static final String TRACEPARENT_HEADER = "traceparent";
  /** The gateway's address for the client, without the provider's API path. */
  public static final String URL_ENV = "SUPERBASED_AI_GATEWAY_URL";
  /** The AI gateway key ({@code sbo-vk-...}) {@link #key()} reads. */
  public static final String KEY_ENV = "SUPERBASED_AI_GATEWAY_KEY";

  /** The OpenAI client and every OpenAI-compatible one: the base URL ends in {@code /v1}. */
  public static final String PROVIDER_OPENAI = "openai";
  /** The Anthropic client: the gateway address as it is (the client adds {@code /v1/messages}). */
  public static final String PROVIDER_ANTHROPIC = "anthropic";
  /** The Azure OpenAI client: its {@code azure_endpoint}; no default upstream. */
  public static final String PROVIDER_AZURE_OPENAI = "azure_openai";

  public static final String SOURCE_ARGUMENT = "argument";
  public static final String SOURCE_ENV = "env";
  public static final String SOURCE_ORG = "org";
  public static final String SOURCE_MACHINE = "machine";

  public static final String PROBLEM_UNKNOWN_PROVIDER = "unknown_provider";
  public static final String PROBLEM_BAD_UPSTREAM = "bad_upstream";
  public static final String PROBLEM_UPSTREAM_REQUIRED = "upstream_required";
  public static final String PROBLEM_BAD_URL = "bad_url";
  public static final String PROBLEM_NOT_CONFIGURED = "not_configured";
  public static final String PROBLEM_NO_KEY = "no_key";
  /** The gateway ignores a longer value. */
  public static final int MAX_APP_ID_LEN = 512;
  static final int MAX_REQUEST_ID_LEN = 256;

  private Gateway() {}

  private static String appValue(String v) {
    String s = v == null ? "" : v.strip();
    if (s.isEmpty() || s.length() > MAX_APP_ID_LEN) {
      return "";
    }
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c < ' ' || c > '~') {
        return "";
      }
    }
    return s;
  }

  /**
   * The headers the gateway reads a call's app identity from, for the request
   * being made now: {@code X-Superbased-User} (the per-request user, else
   * init()'s), {@code X-Superbased-Service} (the spans' {@code service.name}),
   * a fresh {@code X-SBO-Request-Id} and the current span's
   * {@code traceparent}. A value that is empty, too long or
   * not printable ASCII is left out. Never throws.
   */
  public static Map<String, String> headers() {
    Map<String, String> out = new LinkedHashMap<>();
    try {
      Object scoped = AttributeContext.current(null).publicView().get("user");
      Settings s = Superbased.settings();
      String user = appValue(scoped != null ? String.valueOf(scoped) : (s == null ? "" : s.user));
      if (!user.isEmpty()) {
        out.put(USER_HEADER, user);
      }
      String service = appValue(Admit.serviceName(Env.snapshot()));
      if (!service.isEmpty()) {
        out.put(SERVICE_HEADER, service);
      }
      out.put(REQUEST_ID_HEADER, "sdk-" + Util.randomHex32());
      // The current span, so the organization joins the call to it even without the request id.
      String tp = Superbased.getTraceparent();
      if (!tp.isEmpty()) {
        out.put(TRACEPARENT_HEADER, tp);
      }
    } catch (RuntimeException e) {
      // never breaks the host's HTTP call
    }
    return out;
  }

  /** {@link #headers()} for those of them {@code existing} does not carry (case-insensitive). */
  public static Map<String, String> missingHeaders(Map<String, ?> existing) {
    Map<String, String> out = new LinkedHashMap<>();
    java.util.Set<String> have = new java.util.HashSet<>();
    if (existing != null) {
      for (String k : existing.keySet()) {
        have.add(k.toLowerCase(Locale.ROOT));
      }
    }
    for (Map.Entry<String, String> e : headers().entrySet()) {
      if (!have.contains(e.getKey().toLowerCase(Locale.ROOT))) {
        out.put(e.getKey(), e.getValue());
      }
    }
    return out;
  }

  /**
   * Set {@code request_id} on {@code span} (null: the current span) from the
   * gateway's {@code X-SBO-Request-Id} in {@code headers} (any map, matched
   * case-insensitively; a list value uses its first element). Returns true
   * when it stamped; a missing header, a span that already has
   * {@code request_id} or a non-recording span stamps nothing. Never throws.
   */
  public static boolean stampRequestId(Map<String, ?> headers, Span span) {
    try {
      String rid = "";
      if (headers != null) {
        for (Map.Entry<String, ?> e : headers.entrySet()) {
          if (e.getKey() != null && e.getKey().equalsIgnoreCase(REQUEST_ID_HEADER)) {
            Object v = e.getValue();
            if (v instanceof List) {
              v = ((List<?>) v).isEmpty() ? null : ((List<?>) v).get(0);
            }
            rid = v == null ? "" : String.valueOf(v);
            break;
          }
        }
      }
      if (rid.isBlank()) {
        return false;
      }
      Span sp = span != null ? span : Span.current();
      if (!sp.isRecording() || Attr.has(sp, Keys.REQUEST_ID)) {
        return false;
      }
      sp.setAttribute(Keys.REQUEST_ID, Util.head(rid.strip(), MAX_REQUEST_ID_LEN));
      return true;
    } catch (RuntimeException e) {
      return false;
    }
  }

  /** {@link #stampRequestId(Map, Span)} from a JDK {@link HttpHeaders}. */
  public static boolean stampRequestId(HttpHeaders headers, Span span) {
    return headers != null && stampRequestId(headers.map(), span);
  }

  // --- where the AI gateway is ----------------------------------------------------------

  /** No usable AI gateway address (or key); {@link #problem()} is one of the {@code PROBLEM_*} values. */
  public static final class NotConfiguredException extends IllegalStateException {
    private static final long serialVersionUID = 1L;
    private final String problem;

    NotConfiguredException(String problem, String message) {
      super(message);
      this.problem = problem;
    }

    public String problem() {
      return problem;
    }
  }

  /** client family -> {the path its base URL ends in, the upstream used when none is named}. One row per family. */
  private static final Map<String, String[]> PROVIDERS =
      Map.of(PROVIDER_OPENAI, new String[] {"/v1", "openai"}, PROVIDER_ANTHROPIC, new String[] {"", "anthropic"}, PROVIDER_AZURE_OPENAI, new String[] {"", ""});

  /** A pooled upstream id (plan section 3.4); v1 and v1beta read as provider paths. */
  private static final Pattern UPSTREAM_ID = Pattern.compile("[a-z0-9][a-z0-9-]{0,31}");

  private static final Set<String> RESERVED = Set.of("v1", "v1beta");
  private static final String AI_PATH_LANE = "/ai";

  /**
   * "" when {@code raw} is a usable gateway address: http(s), a host, no user
   * info, query or fragment, plain http only to a loopback host (the AI
   * gateway key travels with every call).
   */
  static String urlProblem(String raw) {
    URI u;
    try {
      u = new URI(raw);
    } catch (URISyntaxException e) {
      return "\"" + raw + "\" is not a URL";
    }
    String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
    if ((!scheme.equals("http") && !scheme.equals("https")) || u.getHost() == null || u.getHost().isEmpty()) {
      return "\"" + raw + "\" is not an http(s) address with a host";
    }
    if (u.getRawUserInfo() != null) {
      return "\"" + raw + "\" carries a user name or password";
    }
    if (u.getRawQuery() != null || u.getRawFragment() != null) {
      return "\"" + raw + "\" carries a query or fragment";
    }
    if (scheme.equals("http") && !Http.isLoopbackUrl(raw)) {
      return "\"" + raw + "\" is plain http to a remote host";
    }
    return "";
  }

  private static String trimSlash(String s) {
    int end = s.length();
    while (end > 0 && s.charAt(end - 1) == '/') {
      end--;
    }
    return s.substring(0, end);
  }

  private static String withSuffix(String base, String suffix) {
    String b = trimSlash(base);
    return suffix.isEmpty() || b.endsWith(suffix) ? b : b + suffix;
  }

  /** The base URL of the lane named {@code upstream} in the discovery answer's {@code local.app_lanes} ("" when none is usable). */
  private static String machineLane(Object local, String upstream) {
    if (!(local instanceof Map) || !(((Map<?, ?>) local).get("app_lanes") instanceof List)) {
      return "";
    }
    for (Object lane : (List<?>) ((Map<?, ?>) local).get("app_lanes")) {
      if (!(lane instanceof Map)) {
        continue;
      }
      Object id = ((Map<?, ?>) lane).get("id");
      Object base = ((Map<?, ?>) lane).get("base_url");
      if (!(id instanceof String) || !(base instanceof String) || !id.equals(upstream) || ((String) base).isEmpty()) {
        continue;
      }
      if (!urlProblem((String) base).isEmpty() || !Http.isLoopbackUrl((String) base)) {
        continue;
      }
      return trimSlash((String) base);
    }
    return "";
  }

  /** The pure resolver's answer: the endpoint, or the problem and a message. */
  static final class Resolution {
    final GatewayEndpoint endpoint;
    final String problem;
    final String message;

    Resolution(GatewayEndpoint endpoint, String problem, String message) {
      this.endpoint = endpoint;
      this.problem = problem;
      this.message = message;
    }
  }

  /**
   * The pure resolver (contract base_url cases). {@code local} loads the
   * machine's discovery answer's {@code local} object, and is called only
   * when it is needed.
   */
  static Resolution resolve(String provider, String upstream, String url, String env, String destination, String orgUrl, Supplier<Object> local) {
    String fam = provider == null ? "" : provider.strip().toLowerCase(Locale.ROOT);
    String[] row = PROVIDERS.get(fam);
    if (row == null) {
      return new Resolution(null, PROBLEM_UNKNOWN_PROVIDER, "the AI gateway helpers know the clients openai, anthropic and azure_openai, not \"" + provider + "\"");
    }
    String named = upstream == null ? "" : upstream.strip();
    if (!named.isEmpty() && (!UPSTREAM_ID.matcher(named).matches() || RESERVED.contains(named))) {
      return new Resolution(
          null, PROBLEM_BAD_UPSTREAM, "upstream \"" + named + "\" is not an upstream id (lower-case letters, digits and -, at most 32, not v1 or v1beta)");
    }
    String up = named.isEmpty() ? row[1] : named;
    String[][] given = {{url, SOURCE_ARGUMENT, "the AI gateway URL"}, {env, SOURCE_ENV, URL_ENV}};
    for (String[] g : given) {
      String v = g[0] == null ? "" : g[0].strip();
      if (v.isEmpty()) {
        continue;
      }
      String problem = urlProblem(v);
      if (!problem.isEmpty()) {
        return new Resolution(null, PROBLEM_BAD_URL, g[2] + " is not usable: " + problem);
      }
      return new Resolution(new GatewayEndpoint(withSuffix(v, row[0]), g[1], named, named), "", "");
    }
    String notConfigured =
        "no AI gateway address for "
            + fam
            + ": pass the URL, set "
            + URL_ENV
            + ", use destination online with the organization's address (SUPERBASED_ORG_URL or `observer sdk sign-in`), or add an app lane on this machine (`observer apps lane add`)";
    if ("online".equals(destination)) {
      String org = trimSlash(orgUrl == null ? "" : orgUrl.strip());
      if (org.isEmpty() || !urlProblem(org).isEmpty()) {
        return new Resolution(null, PROBLEM_NOT_CONFIGURED, notConfigured);
      }
      if (up.isEmpty()) {
        return new Resolution(null, PROBLEM_UPSTREAM_REQUIRED, "the " + fam + " client has no default upstream: name one");
      }
      return new Resolution(new GatewayEndpoint(org + AI_PATH_LANE + "/" + up + row[0], SOURCE_ORG, up, ""), "", "");
    }
    if ("local".equals(destination) || "both".equals(destination)) {
      if (up.isEmpty()) {
        return new Resolution(null, PROBLEM_UPSTREAM_REQUIRED, "the " + fam + " client has no default upstream: name one");
      }
      String base = machineLane(local == null ? null : local.get(), up);
      if (!base.isEmpty()) {
        return new Resolution(new GatewayEndpoint(base + row[0], SOURCE_MACHINE, up, ""), "", "");
      }
    }
    return new Resolution(null, PROBLEM_NOT_CONFIGURED, notConfigured);
  }

  /**
   * Where a model client of the given family ({@link #PROVIDER_OPENAI},
   * {@link #PROVIDER_ANTHROPIC}, {@link #PROVIDER_AZURE_OPENAI}) sends its
   * calls, first set wins: {@code url} (null: none);
   * {@code SUPERBASED_AI_GATEWAY_URL}; the organization's address,
   * {@code <org url>/ai/<upstream>}, when the destination is {@code online};
   * this machine's app lane for the upstream (from its loopback discovery
   * answer) when the destination is {@code local} or {@code both}. The
   * destination is init()'s, or the one the environment resolves before
   * init(). {@code upstream} null or "" is the provider's default
   * ({@code openai}, {@code anthropic}).
   *
   * @throws NotConfiguredException when nothing applies; it never falls back
   *     to the provider itself, which would skip every rule the gateway applies
   */
  public static GatewayEndpoint endpoint(String provider, String upstream, String url) {
    Destination.Plan plan = Control.currentPlan();
    Resolution r =
        resolve(
            provider,
            upstream,
            url,
            Env.get(URL_ENV),
            plan.destination,
            plan.gatewayUrl,
            () -> {
              Settings s = Superbased.settings();
              if (s == null) {
                s = Settings.resolve(Env.snapshot(), null);
              }
              if (!s.discover) {
                return null;
              }
              Destination.Discovered d = Destination.discover(plan.nodeUrl);
              return d.body == null ? null : d.body.get("local");
            });
    if (r.endpoint == null) {
      throw new NotConfiguredException(r.problem, r.message);
    }
    return r.endpoint;
  }

  /** {@link #endpoint(String, String, String)} with no explicit address. */
  public static GatewayEndpoint endpoint(String provider, String upstream) {
    return endpoint(provider, upstream, null);
  }

  /** The base URL to give a model client of the given family, for its default upstream. */
  public static String baseUrl(String provider) {
    return endpoint(provider, null, null).baseUrl();
  }

  /** The base URL to give a model client of the given family, for {@code upstream}. */
  public static String baseUrl(String provider, String upstream) {
    return endpoint(provider, upstream, null).baseUrl();
  }

  /** The AI gateway key from {@code SUPERBASED_AI_GATEWAY_KEY} ("" when unset). */
  public static String key() {
    String k = Env.get(KEY_ENV);
    return k == null ? "" : k.strip();
  }
}
