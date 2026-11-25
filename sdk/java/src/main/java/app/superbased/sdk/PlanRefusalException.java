package app.superbased.sdk;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The organization's plan refused AI Apps ingest (sdk/contract/plan-refusal-cases.json).
 *
 * <p>The org's AI Apps gateway (OTLP {@code /v1/traces} and the SDK control
 * API {@code /v1/sdk/*}) refuses ingest when the organization's plan does not
 * include AI Apps (HTTP 403 {@code plan_required}: {@link PlanRequired}) or
 * this month's allowance is used up (HTTP 429
 * {@code planea_events_quota_exceeded} / {@code planea_bytes_quota_exceeded}:
 * {@link AllowanceExceeded}). {@link #code()} is the gateway's error code,
 * {@link #status()} the HTTP status, {@link #getMessage()} its explanation and
 * {@link #upgradeUrl()} where the organization's billing owner changes the
 * plan. {@link #capability()} names what was refused; {@link #plan()} is the
 * plan in force, {@link #allowance()} the org's monthly allowance and
 * {@link #plans()} the plans that include more (each may be absent). A 429
 * also carries {@link #quota()} and {@link #retryAfter()}.
 *
 * <p>The calls that throw keep throwing their own exception
 * ({@link PromptException.FetchFailed}, {@link ExperimentException}) with this
 * one as its cause and its {@code planRefusal()}, so an existing
 * {@code catch} keeps working. The calls that never throw carry it
 * ({@link ScoreResult#planRefusal()}, {@link Verdict#planRefusal()},
 * {@link ExperimentResult#planRefusal()}), and {@code
 * Superbased.diagnostics().get("plan_refusal")} keeps the last one, export
 * included.
 */
public class PlanRefusalException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  /** The gateway's plan refusal codes. */
  public static final String PLAN_REQUIRED = "plan_required";

  public static final String EVENTS_QUOTA_EXCEEDED = "planea_events_quota_exceeded";
  public static final String BYTES_QUOTA_EXCEEDED = "planea_bytes_quota_exceeded";
  /** The AI gateway's monthly request allowance (the same refusal shape). */
  public static final String AIGW_QUOTA_EXCEEDED = "aigw_requests_quota_exceeded";

  private final String kind;
  private final String code;
  private final int status;
  private final String upgradeUrl;
  private final String capability;
  private final Plan plan;
  private final Allowance allowance;
  private final List<Plan> plans;
  private final Quota quota;
  private final Duration retryAfter;

  PlanRefusalException(String kind, Fields f) {
    super(f.message);
    this.kind = kind;
    this.code = f.code;
    this.status = f.status;
    this.upgradeUrl = f.upgradeUrl;
    this.capability = f.capability;
    this.plan = f.plan;
    this.allowance = f.allowance;
    this.plans = List.copyOf(f.plans);
    this.quota = f.quota;
    this.retryAfter = f.retryAfter;
  }

  /** {@code plan_required} (HTTP 403) or {@code allowance_exceeded} (HTTP 429). */
  public String kind() {
    return kind;
  }

  /** The gateway's error code. */
  public String code() {
    return code;
  }

  /** The HTTP status: 403 or 429. */
  public int status() {
    return status;
  }

  /** Where the organization's billing owner changes the plan. */
  public String upgradeUrl() {
    return upgradeUrl;
  }

  /** What was refused ({@code org.planea.gateway}). */
  public String capability() {
    return capability;
  }

  /** The plan in force, or null when the refusal does not name it. */
  public Plan plan() {
    return plan;
  }

  /** The org's monthly allowance, or null when the refusal does not carry it. */
  public Allowance allowance() {
    return allowance;
  }

  /** The plans that include more (catalog order; empty when none does). */
  public List<Plan> plans() {
    return plans;
  }

  /** The quota a 429 is about, or null. */
  public Quota quota() {
    return quota;
  }

  /** The Retry-After header of a 429, or null when it had none. */
  public Duration retryAfter() {
    return retryAfter;
  }

  /** The fields as plain values (snake_case, as {@code diagnostics()} shows them). */
  public Map<String, Object> toMap() {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("kind", kind);
    out.put("code", code);
    out.put("status", status);
    out.put("message", getMessage());
    out.put("upgrade_url", upgradeUrl);
    out.put("capability", capability);
    out.put("plan", plan == null ? null : plan.toMap());
    out.put("allowance", allowance == null ? null : allowance.toMap());
    List<Object> ps = new ArrayList<>();
    for (Plan p : plans) {
      ps.add(p.toMap());
    }
    out.put("plans", ps);
    out.put("quota", quota == null ? null : quota.toMap());
    out.put("retry_after_seconds", retryAfter == null ? null : retryAfter.getSeconds());
    return out;
  }

  /** HTTP 403 {@code plan_required}: the plan does not include AI Apps ingest, or includes no allowance. */
  public static final class PlanRequired extends PlanRefusalException {
    private static final long serialVersionUID = 1L;

    PlanRequired(Fields f) {
      super("plan_required", f);
    }
  }

  /** HTTP 429 over the plan's monthly AI Apps allowance (events or bytes); {@link #quota()} says which. */
  public static final class AllowanceExceeded extends PlanRefusalException {
    private static final long serialVersionUID = 1L;

    AllowanceExceeded(Fields f) {
      super("allowance_exceeded", f);
    }
  }

  /**
   * A plan's allowance: AI Apps events and GB a month, and the AI gateway's
   * requests a month and concurrent calls. A null axis has no cap (or the
   * refusal did not name it).
   */
  public static final class Allowance implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    private final Long eventsMonthly;
    private final Long gbMonthly;
    private final Long requestsMonthly;
    private final Long concurrency;

    Allowance(Long eventsMonthly, Long gbMonthly) {
      this(eventsMonthly, gbMonthly, null, null);
    }

    Allowance(Long eventsMonthly, Long gbMonthly, Long requestsMonthly, Long concurrency) {
      this.eventsMonthly = eventsMonthly;
      this.gbMonthly = gbMonthly;
      this.requestsMonthly = requestsMonthly;
      this.concurrency = concurrency;
    }

    /** AI gateway requests a month, or null (no cap). */
    public Long requestsMonthly() {
      return requestsMonthly;
    }

    /** AI gateway concurrent calls, or null (no cap). */
    public Long concurrency() {
      return concurrency;
    }

    /** Events a month, or null (no cap). */
    public Long eventsMonthly() {
      return eventsMonthly;
    }

    /** GB a month, or null (no cap). */
    public Long gbMonthly() {
      return gbMonthly;
    }

    Map<String, Object> toMap() {
      Map<String, Object> m = new LinkedHashMap<>();
      m.put("events_monthly", eventsMonthly);
      m.put("gb_monthly", gbMonthly);
      // The AI gateway's axes only when named, so an AI Apps refusal reads as before.
      if (requestsMonthly != null) {
        m.put("requests_monthly", requestsMonthly);
      }
      if (concurrency != null) {
        m.put("concurrency", concurrency);
      }
      return m;
    }

    @Override
    public String toString() {
      String gw = requestsMonthly == null && concurrency == null ? "" : ", requestsMonthly=" + requestsMonthly + ", concurrency=" + concurrency;
      return "Allowance{eventsMonthly=" + eventsMonthly + ", gbMonthly=" + gbMonthly + gw + "}";
    }
  }

  /** A catalog plan: the plan in force, or one on offer (with its allowance). */
  public static final class Plan implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    private final String name;
    private final int version;
    private final String label;
    private final Allowance allowance;

    Plan(String name, int version, String label, Allowance allowance) {
      this.name = name;
      this.version = version;
      this.label = label;
      this.allowance = allowance;
    }

    public String name() {
      return name;
    }

    public int version() {
      return version;
    }

    public String label() {
      return label;
    }

    /** An offered plan's allowance; null for the plan in force. */
    public Allowance allowance() {
      return allowance;
    }

    Map<String, Object> toMap() {
      Map<String, Object> m = new LinkedHashMap<>();
      m.put("name", name);
      m.put("version", version);
      m.put("label", label);
      if (allowance != null) {
        m.put("allowance", allowance.toMap());
      }
      return m;
    }

    @Override
    public String toString() {
      return "Plan{" + name + " v" + version + " " + label + "}";
    }
  }

  /** The monthly quota a 429 is about; {@link #resetsAt()} is RFC 3339. */
  public static final class Quota implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    private final String quota;
    private final String unit;
    private final long used;
    private final long limit;
    private final String resetsAt;

    Quota(String quota, String unit, long used, long limit, String resetsAt) {
      this.quota = quota;
      this.unit = unit;
      this.used = used;
      this.limit = limit;
      this.resetsAt = resetsAt;
    }

    /** {@code events_monthly} or {@code bytes_monthly}. */
    public String quota() {
      return quota;
    }

    /** {@code events} or {@code bytes}. */
    public String unit() {
      return unit;
    }

    public long used() {
      return used;
    }

    public long limit() {
      return limit;
    }

    public String resetsAt() {
      return resetsAt;
    }

    Map<String, Object> toMap() {
      Map<String, Object> m = new LinkedHashMap<>();
      m.put("quota", quota);
      m.put("unit", unit);
      m.put("used", used);
      m.put("limit", limit);
      m.put("resets_at", resetsAt);
      return m;
    }

    @Override
    public String toString() {
      return "Quota{" + quota + " " + used + "/" + limit + " " + unit + ", resets " + resetsAt + "}";
    }
  }

  /** What one refusal is built from (the parser fills it). */
  static final class Fields {
    String code = "";
    int status;
    String message = "";
    String upgradeUrl = "";
    String capability = "";
    Plan plan;
    Allowance allowance;
    List<Plan> plans = new ArrayList<>();
    Quota quota;
    Duration retryAfter;
  }

  // --- the one parser ------------------------------------------------------------------

  /** code -> the status it rides on. One row per code. */
  private static final Map<String, Integer> STATUS_OF =
      Map.of(PLAN_REQUIRED, 403, EVENTS_QUOTA_EXCEEDED, 429, BYTES_QUOTA_EXCEEDED, 429, AIGW_QUOTA_EXCEEDED, 429);

  /**
   * The plan refusal in one HTTP answer, or null. {@code body} is the decoded
   * JSON object (a {@code Map}), or the raw body (a {@code String} or
   * {@code byte[]}); {@code headers} any map (the name {@code Retry-After} is
   * matched without regard to case), or null. A plan refusal is a 403
   * {@code plan_required} or a 429 {@code planea_events_quota_exceeded} /
   * {@code planea_bytes_quota_exceeded} / {@code aigw_requests_quota_exceeded}
   * (the AI gateway's allowance) whose body carries a non-empty
   * {@code upgrade_url}; anything else, malformed input included, is null.
   * Never throws.
   */
  public static PlanRefusalException parse(int status, Object body, Map<String, ?> headers) {
    try {
      return parseOrNull(status, body, headers);
    } catch (RuntimeException e) {
      return null;
    }
  }

  @SuppressWarnings("unchecked")
  private static PlanRefusalException parseOrNull(int status, Object body, Map<String, ?> headers) {
    if (status != 403 && status != 429) {
      return null;
    }
    Object o = decode(body);
    if (!(o instanceof Map)) {
      return null;
    }
    Map<String, Object> m = (Map<String, Object>) o;
    String code = str(m.get("error"));
    Integer want = STATUS_OF.get(code);
    String upgrade = str(m.get("upgrade_url")).trim();
    if (want == null || want != status || upgrade.isEmpty()) {
      return null;
    }
    Fields f = new Fields();
    f.code = code;
    f.status = status;
    f.upgradeUrl = upgrade;
    f.message = str(m.get("message")).trim();
    if (f.message.isEmpty()) {
      f.message = defaultMessage(code, upgrade);
    }
    f.capability = str(m.get("capability"));
    f.plan = plan(m.get("plan"), false);
    f.allowance = allowance(m.get("allowance"));
    if (m.get("plans") instanceof List) {
      for (Object x : (List<Object>) m.get("plans")) {
        Plan p = plan(x, true);
        if (p != null) {
          f.plans.add(p);
        }
      }
    }
    f.quota = quota(m.get("quota"));
    f.retryAfter = retryAfter(headers);
    return status == 403 ? new PlanRequired(f) : new AllowanceExceeded(f);
  }

  /** The line a refusal shows when the gateway sent no message. */
  static String defaultMessage(String code, String upgradeUrl) {
    if (AIGW_QUOTA_EXCEEDED.equals(code)) {
      return "AI gateway calls were refused by the organization's plan (" + code + "); its billing owner can change the plan at " + upgradeUrl;
    }
    return "AI Apps ingest was refused by the organization's plan (" + code + "); its billing owner can change the plan at " + upgradeUrl;
  }

  private static Object decode(Object body) {
    if (body instanceof Map) {
      return body;
    }
    String text;
    if (body instanceof byte[]) {
      try {
        text =
            StandardCharsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap((byte[]) body))
                .toString();
      } catch (CharacterCodingException e) {
        return null;
      }
    } else if (body instanceof String) {
      text = (String) body;
    } else {
      return null;
    }
    if (text.isBlank()) {
      return null;
    }
    try {
      return Json.parse(text);
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  private static String str(Object v) {
    return v instanceof String ? (String) v : "";
  }

  /** An integer (Gson's Long, or a whole Double); null otherwise. */
  private static Long integer(Object v) {
    if (v instanceof Long || v instanceof Integer) {
      return ((Number) v).longValue();
    }
    if (v instanceof Double) {
      double d = (Double) v;
      if (d == Math.rint(d) && !Double.isInfinite(d) && Math.abs(d) < 9.007199254740992E15) {
        return (long) d;
      }
    }
    return null;
  }

  private static Allowance allowance(Object v) {
    if (!(v instanceof Map)) {
      return null;
    }
    Map<?, ?> m = (Map<?, ?>) v;
    return new Allowance(
        integer(m.get("events_monthly")), integer(m.get("gb_monthly")), integer(m.get("requests_monthly")), integer(m.get("concurrency")));
  }

  private static Plan plan(Object v, boolean withAllowance) {
    if (!(v instanceof Map)) {
      return null;
    }
    Map<?, ?> m = (Map<?, ?>) v;
    String name = str(m.get("name"));
    if (name.isEmpty()) {
      return null;
    }
    Long version = integer(m.get("version"));
    return new Plan(name, version == null ? 0 : version.intValue(), str(m.get("label")), withAllowance ? allowance(m.get("allowance")) : null);
  }

  private static Quota quota(Object v) {
    if (!(v instanceof Map)) {
      return null;
    }
    Map<?, ?> m = (Map<?, ?>) v;
    Long used = integer(m.get("used"));
    Long limit = integer(m.get("limit"));
    return new Quota(str(m.get("quota")), str(m.get("unit")), used == null ? 0 : used, limit == null ? 0 : limit, str(m.get("resets_at")));
  }

  private static Duration retryAfter(Map<String, ?> headers) {
    if (headers == null) {
      return null;
    }
    for (Map.Entry<String, ?> e : headers.entrySet()) {
      if (e.getKey() != null && e.getKey().toLowerCase(Locale.ROOT).equals("retry-after")) {
        Object v = e.getValue() instanceof List && !((List<?>) e.getValue()).isEmpty() ? ((List<?>) e.getValue()).get(0) : e.getValue();
        String s = v == null ? "" : String.valueOf(v).trim();
        if (s.isEmpty() || !s.chars().allMatch(c -> c >= '0' && c <= '9') || s.length() > 12) {
          return null;
        }
        return Duration.ofSeconds(Long.parseLong(s));
      }
    }
    return null;
  }

  // --- the last refusal, for diagnostics() ---------------------------------------------

  /** How often the SDK may write its one-line plan-refusal warning. */
  static final Duration LOG_INTERVAL = Duration.ofSeconds(60);

  private static final Object LAST_LOCK = new Object();
  private static PlanRefusalException last;
  private static double lastAt;
  private static long loggedAtMs;

  /**
   * Keep {@code r} as the last refusal (diagnostics' {@code plan_refusal}).
   * With {@code logAs} (what was refused, e.g. "trace export"), write ONE
   * warning line, at most once a minute: the message and the upgrade URL.
   * True when it logged.
   */
  static boolean note(PlanRefusalException r, String logAs) {
    long now = System.currentTimeMillis();
    boolean due;
    synchronized (LAST_LOCK) {
      last = r;
      lastAt = now / 1000.0;
      due = logAs != null && !logAs.isEmpty() && now - loggedAtMs >= LOG_INTERVAL.toMillis();
      if (due) {
        loggedAtMs = now;
      }
    }
    if (due) {
      Util.warn(logAs + " refused by the organization's plan: " + String.join(" ", r.getMessage().trim().split("\\s+")) + " (upgrade: " + r.upgradeUrl + ")");
    }
    return due;
  }

  /** {@code plan_refusal} (the last refusal as a map, or null) and {@code plan_refusal_at} (epoch seconds, 0 when never). */
  static Map<String, Object> snapshot() {
    PlanRefusalException r;
    double at;
    synchronized (LAST_LOCK) {
      r = last;
      at = lastAt;
    }
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("plan_refusal", r == null ? null : Collections.unmodifiableMap(r.toMap()));
    out.put("plan_refusal_at", at);
    return out;
  }

  static void resetForTests() {
    synchronized (LAST_LOCK) {
      last = null;
      lastAt = 0;
      loggedAtMs = 0;
    }
  }
}
