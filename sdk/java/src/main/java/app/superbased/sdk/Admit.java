package app.superbased.sdk;

import io.opentelemetry.api.trace.Span;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * {@code admit()}: the input-admission pre-flight check. Never throws into
 * the host: any failure (transport, timeout, HTTP error, a body that is not a
 * JSON object, a field of the wrong type) yields a degraded {@link Verdict}
 * that admits (fail open, the default) or denies ({@code failClosed}), is
 * counted in diagnostics and warned about once per cause per minute with the
 * fix (review E-39).
 */
public final class Admit {
  public static final String DEFAULT_ADMISSION_ENDPOINT = "http://127.0.0.1:8081/api/obs/admission/check";
  public static final String SDK_ADMIT_PATH = "/v1/sdk/admit";
  /** Longer than the server's judge budget (10 s), so the client does not fail open early. */
  public static final Duration DEFAULT_ADMIT_TIMEOUT = Duration.ofSeconds(12);

  /** HTTP 403 / 404: admission off or not permitted. */
  public static final String UNAVAILABLE = "admission-unavailable";
  public static final String TIMEOUT = "client-timeout";
  public static final String TRANSPORT = "client-transport";
  public static final String HTTP_ERROR = "client-http-error";
  public static final String BAD_RESPONSE = "client-bad-response";
  /** The organization answered mode off: it has no admission policy (L-05, ruling D29). */
  public static final String ADMISSION_OFF = "admission-off";

  static final List<String> TIMEOUT_HEADERS = List.of("x-sbo-recommended-timeout-ms", "x-superbased-admit-timeout-ms");
  static final List<String> TIMEOUT_FIELDS = List.of("recommended_client_timeout_ms", "recommended_timeout_ms");
  static final Duration DEGRADED_LOG_INTERVAL = Duration.ofSeconds(60);

  private Admit() {}

  private static final Map<String, Duration> ADVERTISED = new HashMap<>();

  // --- the fix table (TypeScript and Python have the same rows) ----------------------------

  /** cause, lowest status, highest status, fix, where ("machine" or "" for any address). */
  private static final Object[][] FIXES = {
    {
      UNAVAILABLE,
      404,
      404,
      "this machine has no admission check: update Observer (a current machine answers allow while no admission policy is set), or turn admission on",
      "machine"
    },
    {
      HTTP_ERROR,
      300,
      399,
      "the address redirects, and admit() never follows a redirect (the key must not move hosts): use the final URL",
      ""
    },
    {HTTP_ERROR, 401, 401, "the SDK key was refused: check apiKey / SUPERBASED_API_KEY, or sign in again", ""},
    {UNAVAILABLE, 403, 403, "the key may not run admission checks, or admission is off for this app", ""},
    {
      UNAVAILABLE,
      404,
      404,
      "no admission check at this address: point orgUrl / SUPERBASED_ORG_URL at the AI Apps gateway (not the dashboard), or turn admission on",
      ""
    },
    {HTTP_ERROR, 429, 429, "the server is rate limiting admission checks", ""},
    {HTTP_ERROR, 0, 999, "the admission server answered with an error", ""},
    {TIMEOUT, 0, 999, "no answer within the timeout: raise the timeout, or check the server", ""},
    {TRANSPORT, 0, 999, "nothing answered at this address: check the URL and that Observer is running", ""},
    {BAD_RESPONSE, 0, 999, "the address did not answer like an admission check: check the URL", ""},
    {
      ADMISSION_OFF,
      0,
      999,
      "your organization has no admission policy for AI Apps (mode off): ask an admin to turn admission on, or use destination both so this machine's policy applies",
      ""
    },
  };

  /** What to fix for a degraded verdict ("" for a server-side reason). */
  static String degradedFix(String cause, int status, String url) {
    boolean machine = isMachineAdmission(url);
    for (Object[] row : FIXES) {
      String where = (String) row[4];
      if (row[0].equals(cause)
          && (Integer) row[1] <= status
          && status <= (Integer) row[2]
          && (where.isEmpty() || ("machine".equals(where)) == machine)) {
        return (String) row[3];
      }
    }
    return "";
  }

  private static boolean isMachineAdmission(String url) {
    try {
      String path = URI.create(url).getPath();
      return path != null && Http.stripRight(path, '/').endsWith(Destination.ADMISSION_PATH);
    } catch (RuntimeException e) {
      return false;
    }
  }

  private static String where(String url) {
    try {
      URI u = URI.create(url);
      String host = u.getHost() == null ? "" : u.getHost();
      if (u.getPort() > 0) {
        host += ":" + u.getPort();
      }
      return u.getScheme() + "://" + host + (u.getPath() == null ? "" : u.getPath());
    } catch (RuntimeException e) {
      return "the admission address";
    }
  }

  /** The admit-side counters (review E-39). */
  static final class Stats {
    long degraded;
    String lastError = "";
    double lastErrorAt;
    final Map<String, Long> loggedAt = new HashMap<>();

    synchronized void reset() {
      degraded = 0;
      lastError = "";
      lastErrorAt = 0;
      loggedAt.clear();
    }
  }

  static final Stats STATS = new Stats();

  /** Count a degraded verdict and warn once a minute per cause. */
  static void noteDegraded(Verdict v, String url) {
    try {
      int status = v.httpStatus;
      String detail = status != 0 ? "HTTP " + status : (v.error.isEmpty() ? v.degraded : v.error);
      String fix = degradedFix(v.degraded, status, url);
      if (v.planRefusal != null) {
        // The org's plan refused it: its own words and where to fix it.
        fix = String.join(" ", v.planRefusal.getMessage().trim().split("\\s+")) + " (upgrade: " + v.planRefusal.upgradeUrl() + ")";
        PlanRefusalException.note(v.planRefusal, "");
      }
      String verdict = v.allowed ? "admitted (fail open)" : "denied (failClosed)";
      String whereText = url.isEmpty() ? "" : " from " + where(url);
      String msg =
          "admit() got no decision"
              + whereText
              + " ("
              + v.degraded
              + ": "
              + detail
              + "); the message was "
              + verdict
              + (fix.isEmpty() ? "" : ". Fix: " + fix);
      String key = v.degraded + ":" + status;
      long now = System.currentTimeMillis();
      boolean due;
      synchronized (STATS) {
        STATS.degraded++;
        STATS.lastError = Util.head(msg, 500);
        STATS.lastErrorAt = now / 1000.0;
        Long last = STATS.loggedAt.get(key);
        due = last == null || now - last >= DEGRADED_LOG_INTERVAL.toMillis();
        if (due) {
          STATS.loggedAt.put(key, now);
        }
      }
      if (due) {
        Util.warn(msg);
      }
    } catch (RuntimeException e) {
      // reporting never breaks admit()
    }
  }

  static Map<String, Object> snapshot() {
    synchronized (STATS) {
      Map<String, Object> out = new LinkedHashMap<>();
      out.put("admission_degraded", STATS.degraded);
      out.put("admission_last_error", STATS.lastError);
      out.put("admission_last_error_at", STATS.lastErrorAt);
      return out;
    }
  }

  static Verdict degraded(String cause, boolean failClosed, int status, String error, long startedNanos) {
    Verdict v = new Verdict();
    v.allowed = !failClosed;
    v.decision = failClosed ? "deny" : "allow";
    v.reason = failClosed ? "admission check unavailable" : "";
    v.degraded = cause;
    v.httpStatus = status;
    v.error = Util.head(error == null ? "" : error, 300);
    v.latencyMs = (System.nanoTime() - startedNanos) / 1_000_000L;
    return v;
  }

  // --- where the check goes ---------------------------------------------------------------

  // Where the URL came from decides whether a credential may ride along.
  static final String ORG = "org";
  static final String PLAN_ORG = "plan-org";
  static final String EXPLICIT = "explicit";
  static final String MACHINE = "machine";

  /** {url, origin, init key}. */
  static String[] resolveUrl(String endpoint, String orgUrl, Map<String, String> env) {
    Destination.Plan plan = Superbased.plan();
    String initKey = plan != null ? plan.key : "";
    if (endpoint != null && !endpoint.isEmpty()) {
      return new String[] {endpoint, EXPLICIT, initKey};
    }
    if (orgUrl != null && !orgUrl.isEmpty()) {
      return new String[] {Http.stripRight(orgUrl, '/') + SDK_ADMIT_PATH, ORG, initKey};
    }
    String val = Util.first(env.get("SUPERBASED_ADMISSION_ENDPOINT"));
    if (!val.isEmpty()) {
      return new String[] {val, EXPLICIT, initKey};
    }
    if (plan != null && !plan.admitUrl.isEmpty()) {
      if (plan.onlineEnabled() && !plan.gatewayUrl.isEmpty() && plan.admitUrl.startsWith(plan.gatewayUrl)) {
        return new String[] {plan.admitUrl, PLAN_ORG, initKey};
      }
      return new String[] {plan.admitUrl, MACHINE, ""};
    }
    String org = Util.first(env.get("SUPERBASED_ORG_URL"));
    if (!org.isEmpty()) {
      return new String[] {Http.stripRight(org, '/') + SDK_ADMIT_PATH, ORG, initKey};
    }
    return new String[] {DEFAULT_ADMISSION_ENDPOINT, MACHINE, ""};
  }

  private static String machineAdmissionUrl() {
    Destination.Plan plan = Superbased.plan();
    if (plan == null) {
      return DEFAULT_ADMISSION_ENDPOINT;
    }
    return !plan.machineAdmitUrl.isEmpty()
        ? plan.machineAdmitUrl
        : Http.stripRight(plan.nodeUrl, '/') + Destination.ADMISSION_PATH;
  }

  /**
   * The {@code service.name} the app's spans carry (service-scoped budget
   * caps bind on it): the SDK's provider's resource, else the configured name.
   */
  static String serviceName(Map<String, String> env) {
    String fromProvider = Superbased.resourceServiceName();
    if (fromProvider != null && !fromProvider.isBlank() && !fromProvider.startsWith("unknown_service")) {
      return fromProvider.strip();
    }
    // Then init()'s serviceName (an attached app's provider may not have
    // produced a span yet), then the env, then the default (Go admit.go).
    Settings s = Superbased.settings();
    if (s != null && !s.serviceName.isEmpty()) {
      return s.serviceName;
    }
    return Settings.resolveServiceName(null, env);
  }

  private static void remember(String url, Object raw) {
    if (raw == null || raw instanceof Boolean) {
      return;
    }
    Double ms = raw instanceof Number ? ((Number) raw).doubleValue() : Settings.parseNumber(String.valueOf(raw));
    if (ms == null || ms < 100 || ms > 120_000) {
      return;
    }
    synchronized (ADVERTISED) {
      ADVERTISED.put(url, Duration.ofNanos((long) (ms * 1_000_000L)));
    }
  }

  private static void stampSpan(Verdict v) {
    try {
      Span sp = Span.current();
      if (!sp.isRecording()) {
        return;
      }
      sp.setAttribute(Keys.ADMISSION_ALLOWED, v.allowed);
      sp.setAttribute(Keys.ADMISSION_DECISION, v.decision);
      if (!v.verdictId.isEmpty()) {
        sp.setAttribute(Keys.ADMISSION_VERDICT_ID, v.verdictId);
      }
      if (!v.degraded.isEmpty()) {
        sp.setAttribute(Keys.ADMISSION_DEGRADED, v.degraded);
      }
    } catch (RuntimeException e) {
      // never raises
    }
  }

  static Verdict admit(String message, AdmitOptions o) {
    long started = System.nanoTime();
    AdmitOptions opts = o == null ? AdmitOptions.defaults() : o;
    // Resolved before any other work, so the last-resort handler honours it too.
    boolean failClosed = resolveFailClosed(opts);
    try {
      return run(message, opts, failClosed, started);
    } catch (RuntimeException e) {
      Verdict v = degraded(BAD_RESPONSE, failClosed, 0, e.toString(), started);
      noteDegraded(v, "");
      return v;
    }
  }

  private static String firstNonEmpty(String... vals) {
    for (String v : vals) {
      if (v != null && !v.isEmpty()) {
        return v;
      }
    }
    return "";
  }

  /** The per-call option, else SUPERBASED_ADMISSION_FAIL_CLOSED. Never throws. */
  static boolean resolveFailClosed(AdmitOptions o) {
    try {
      if (o.failClosed != null) {
        return o.failClosed;
      }
      String raw = Util.first(Env.snapshot().get("SUPERBASED_ADMISSION_FAIL_CLOSED")).toLowerCase(Locale.ROOT);
      return !(raw.isEmpty() || raw.equals("0") || raw.equals("false") || raw.equals("no") || raw.equals("off"));
    } catch (RuntimeException e) {
      return false;
    }
  }

  private static Verdict run(String message, AdmitOptions o, boolean failClosed, long started) {
    Map<String, String> env = Env.snapshot();
    String[] r = resolveUrl(o.endpoint, o.orgUrl, env);
    String url = r[0];
    String origin = r[1];
    String initKey = r[2];

    // Identity: the argument, else the request scope, else init()'s (contract section 2).
    Map<String, Object> scope = AttributeContext.current(null).publicView();
    Settings s = Superbased.settings();
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("text", message == null ? "" : message);
    payload.put("tenant", firstNonEmpty(o.tenant, (String) scope.get("tenant"), s == null ? "" : s.tenant));
    payload.put("user", firstNonEmpty(o.user, (String) scope.get("user"), s == null ? "" : s.user));
    payload.put("session", firstNonEmpty(o.session, (String) scope.get("session_id"), s == null ? "" : s.sessionId));
    payload.put("service", serviceName(env));
    payload.put("trace_id", firstNonEmpty(o.traceId, AttributeContext.currentTraceId()));
    payload.put("request_id", firstNonEmpty(o.requestId));
    byte[] body = Json.write(payload).getBytes(StandardCharsets.UTF_8);

    Verdict v = post(url, origin, initKey, body, o.apiKey, o.headers, o.timeout, env, failClosed, started);
    if ((ORG.equals(origin) || PLAN_ORG.equals(origin)) && v.degraded.isEmpty() && "off".equals(v.mode)) {
      // The org has no admission policy, so it made no decision (L-05).
      Destination.Plan plan = Superbased.plan();
      if (PLAN_ORG.equals(origin) && plan != null && Destination.BOTH.equals(plan.destination)) {
        // The key never goes to the machine, not even an explicit one.
        Map<String, String> hdrs = new LinkedHashMap<>();
        if (o.headers != null) {
          for (Map.Entry<String, String> e : o.headers.entrySet()) {
            if (!e.getKey().equalsIgnoreCase("authorization")) {
              hdrs.put(e.getKey(), e.getValue());
            }
          }
        }
        v = post(machineAdmissionUrl(), MACHINE, "", body, null, hdrs, o.timeout, env, failClosed, started);
      } else {
        v = degraded(ADMISSION_OFF, failClosed, v.httpStatus, "the organization answered mode off", started);
        noteDegraded(v, url);
      }
    }
    stampSpan(v);
    return v;
  }

  @SuppressWarnings("unchecked")
  private static Verdict post(
      String url,
      String origin,
      String initKey,
      byte[] body,
      String apiKey,
      Map<String, String> extraHeaders,
      Duration timeoutOpt,
      Map<String, String> env,
      boolean failClosed,
      long started) {
    Duration timeout = timeoutOpt;
    if (timeout == null) {
      synchronized (ADVERTISED) {
        timeout = ADVERTISED.get(url);
      }
      if (timeout == null) {
        timeout = DEFAULT_ADMIT_TIMEOUT;
      }
    }
    Map<String, String> hdrs = new LinkedHashMap<>();
    hdrs.put("Content-Type", "application/json");
    hdrs.put("Accept", "application/json");
    hdrs.put("User-Agent", Http.USER_AGENT);
    // The credential goes to the org or to an explicit remote endpoint, never
    // to this machine's own routes. An explicit apiKey is the caller's call.
    String key = apiKey == null ? "" : apiKey;
    if (key.isEmpty()
        && (ORG.equals(origin) || PLAN_ORG.equals(origin) || (EXPLICIT.equals(origin) && !Http.isLoopbackUrl(url)))) {
      key = !initKey.isEmpty() ? initKey : Util.first(env.get("SUPERBASED_API_KEY"));
    }
    if (!key.isEmpty()) {
      hdrs.put("Authorization", "Bearer " + key);
    }
    if (extraHeaders != null) {
      hdrs.putAll(extraHeaders);
    }
    Http.Raw raw;
    try {
      raw = Http.send(new Http.Call("POST", url, hdrs, body, timeout, Http.isLoopbackUrl(url)));
    } catch (HttpTimeoutException e) {
      return fail(TIMEOUT, 0, e.getMessage() == null ? "timed out" : e.getMessage(), failClosed, started, url);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return fail(TRANSPORT, 0, "interrupted", failClosed, started, url);
    } catch (IOException | IllegalArgumentException e) {
      return fail(TRANSPORT, 0, e.toString(), failClosed, started, url);
    }
    int status = raw.status;
    if (status < 200 || status >= 300) {
      PlanRefusalException refusal = PlanRefusalException.parse(status, raw.body, raw.headers);
      if (refusal != null) {
        Verdict v =
            degraded(status == 403 ? UNAVAILABLE : HTTP_ERROR, failClosed, status, "HTTP " + status + " " + refusal.code() + ": " + refusal.getMessage(), started);
        v.planRefusal = refusal;
        noteDegraded(v, url);
        return v;
      }
      if (status == 403 || status == 404) {
        return fail(UNAVAILABLE, status, "HTTP " + status, failClosed, started, url);
      }
      return fail(HTTP_ERROR, status, "HTTP " + status, failClosed, started, url);
    }
    for (String h : TIMEOUT_HEADERS) {
      String hv = raw.headers.get(h);
      if (hv != null) {
        remember(url, hv);
        break;
      }
    }
    Object data;
    try {
      data = Json.parse(new String(raw.body == null ? new byte[0] : raw.body, StandardCharsets.UTF_8));
    } catch (IllegalArgumentException e) {
      return fail(BAD_RESPONSE, status, e.getMessage(), failClosed, started, url);
    }
    if (!(data instanceof Map)) {
      String what = data == null ? "null" : data.getClass().getSimpleName();
      return fail(BAD_RESPONSE, status, "response body is " + what + ", not an object", failClosed, started, url);
    }
    Map<String, Object> d = (Map<String, Object>) data;
    if (!(d.get("allowed") instanceof Boolean)) {
      return fail(BAD_RESPONSE, status, "response field 'allowed' is missing or not a boolean", failClosed, started, url);
    }
    for (String f : TIMEOUT_FIELDS) {
      if (d.get(f) != null) {
        remember(url, d.get(f));
        break;
      }
    }
    Verdict v = Verdict.fromBody(d);
    v.httpStatus = status;
    return v;
  }

  private static Verdict fail(String cause, int status, String error, boolean failClosed, long started, String url) {
    Verdict v = degraded(cause, failClosed, status, error, started);
    noteDegraded(v, url);
    return v;
  }

  static void resetForTests() {
    STATS.reset();
    synchronized (ADVERTISED) {
      ADVERTISED.clear();
    }
  }
}
