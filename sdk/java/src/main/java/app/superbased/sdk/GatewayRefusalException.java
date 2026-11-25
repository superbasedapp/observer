package app.superbased.sdk;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The organization's AI gateway refused a model call (shared cases:
 * {@code sdk/contract/ai-gateway-cases.json}). {@link #kind()} is
 * {@code budget_exceeded} (402), {@code model_not_allowed},
 * {@code admission_denied}, {@code plan_required} (403), {@code quota_exceeded}
 * (429, the organization's monthly allowance) or {@code other};
 * {@link #code()} the gateway's reason; {@link #requestId()} its
 * {@code X-SBO-Request-Id}. {@link #budget()} is set for a budget refusal,
 * {@link #planRefusal()} for a plan refusal that names where to change the
 * plan. {@link #parse} reads one from an HTTP answer.
 */
public class GatewayRefusalException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  public static final String BUDGET_EXCEEDED = "budget_exceeded";
  public static final String MODEL_NOT_ALLOWED = "model_not_allowed";
  public static final String ADMISSION_DENIED = "admission_denied";
  public static final String PLAN_REQUIRED = "plan_required";
  public static final String QUOTA_EXCEEDED = "quota_exceeded";
  public static final String OTHER = "other";

  /** code -> {status, kind}. One row per code; any other code, or a code on another status, is "other". */
  private static final Map<String, Object[]> KINDS =
      Map.of(
          "budget_exceeded", new Object[] {402, BUDGET_EXCEEDED},
          "model_not_allowed", new Object[] {403, MODEL_NOT_ALLOWED},
          "admission_denied", new Object[] {403, ADMISSION_DENIED},
          PlanRefusalException.PLAN_REQUIRED, new Object[] {403, PLAN_REQUIRED},
          PlanRefusalException.AIGW_QUOTA_EXCEEDED, new Object[] {429, QUOTA_EXCEEDED});

  private final String kind;
  private final String code;
  private final int status;
  private final String requestId;
  private final Duration retryAfter;
  private final Budget budget;
  private final PlanRefusalException planRefusal;

  GatewayRefusalException(
      String message, String kind, String code, int status, String requestId, Duration retryAfter, Budget budget, PlanRefusalException planRefusal) {
    super(message, planRefusal);
    this.kind = kind;
    this.code = code;
    this.status = status;
    this.requestId = requestId;
    this.retryAfter = retryAfter;
    this.budget = budget;
    this.planRefusal = planRefusal;
  }

  public String kind() {
    return kind;
  }

  public String code() {
    return code;
  }

  public int status() {
    return status;
  }

  /** The gateway's request id ({@code X-SBO-Request-Id}, else {@code request-id} or {@code x-request-id}); "" when none. */
  public String requestId() {
    return requestId;
  }

  /** The Retry-After header, or null. */
  public Duration retryAfter() {
    return retryAfter;
  }

  /** The cap a budget refusal names, or null. */
  public Budget budget() {
    return budget;
  }

  /** The plan detail (also this exception's cause), or null. */
  public PlanRefusalException planRefusal() {
    return planRefusal;
  }

  /**
   * The cap a 402 refusal names, in the cap's own unit ({@code usd} or
   * {@code tokens}). A null field was absent; a remaining below zero is how
   * far calls already let through went past the cap.
   */
  public static final class Budget implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    private final String level;
    private final String scopeId;
    private final String unit;
    private final Double remaining;
    private final Double cap;
    private final boolean estimated;

    Budget(String level, String scopeId, String unit, Double remaining, Double cap, boolean estimated) {
      this.level = level;
      this.scopeId = scopeId;
      this.unit = unit;
      this.remaining = remaining;
      this.cap = cap;
      this.estimated = estimated;
    }

    public String level() {
      return level;
    }

    public String scopeId() {
      return scopeId;
    }

    public String unit() {
      return unit;
    }

    public Double remaining() {
      return remaining;
    }

    public Double cap() {
      return cap;
    }

    public boolean estimated() {
      return estimated;
    }

    @Override
    public String toString() {
      return "Budget{level=" + level + ", scopeId=" + scopeId + ", unit=" + unit + ", remaining=" + remaining + ", cap=" + cap + ", estimated=" + estimated + "}";
    }
  }

  /**
   * The AI gateway refusal in one HTTP answer, or null. {@code body} is the
   * decoded JSON object (a {@code Map}), or the raw body (a {@code String} or
   * {@code byte[]}); {@code headers} any map (names matched without regard to
   * case; a list value uses its first element), or null. A gateway refusal is
   * a non-2xx answer whose JSON object body carries the gateway's top-level
   * {@code reason} (or a plan refusal's code as a top-level string
   * {@code error}); a provider's own error the gateway relays as is,
   * malformed input included, is null. Never throws.
   */
  public static GatewayRefusalException parse(int status, Object body, Map<String, ?> headers) {
    try {
      return parseOrNull(status, body, headers);
    } catch (RuntimeException e) {
      return null;
    }
  }

  @SuppressWarnings("unchecked")
  private static GatewayRefusalException parseOrNull(int status, Object body, Map<String, ?> headers) {
    if (status < 400) {
      return null;
    }
    Object o = decode(body);
    if (!(o instanceof Map)) {
      return null;
    }
    Map<String, Object> m = (Map<String, Object>) o;
    String errStr = str(m.get("error")).strip();
    String code = str(m.get("reason")).strip();
    if (code.isEmpty() && KINDS.containsKey(errStr)) {
      code = errStr;
    }
    if (code.isEmpty()) {
      return null;
    }
    Object[] row = KINDS.get(code);
    String kind = row != null && ((Integer) row[0]) == status ? (String) row[1] : OTHER;
    String message = "";
    if (m.get("error") instanceof Map) {
      message = str(((Map<String, Object>) m.get("error")).get("message")).strip();
    }
    if (message.isEmpty()) {
      message = str(m.get("message")).strip();
    }
    if (message.isEmpty() && !errStr.isEmpty() && !errStr.equals(code)) {
      message = errStr;
    }
    if (message.isEmpty()) {
      message = "the AI gateway refused the call (" + code + ")";
    }
    String requestId = Util.first(header(headers, "x-sbo-request-id"), header(headers, "request-id"), header(headers, "x-request-id"));
    Budget budget = "budget_exceeded".equals(code) ? budget(m) : null;
    PlanRefusalException plan = null;
    if (PlanRefusalException.PLAN_REQUIRED.equals(code) || PlanRefusalException.AIGW_QUOTA_EXCEEDED.equals(code)) {
      // The plan detail is the planrefusal body's top-level fields; its parser reads the code from a string error.
      Map<String, Object> norm = new LinkedHashMap<>(m);
      norm.put("error", code);
      if (str(norm.get("message")).isBlank()) {
        norm.put("message", message);
      }
      plan = PlanRefusalException.parse(status, norm, headers);
    }
    return new GatewayRefusalException(message, kind, code, status, requestId, retryAfter(headers), budget, plan);
  }

  private static Budget budget(Map<String, Object> m) {
    String unit = m.get("unit") instanceof String ? (String) m.get("unit") : null;
    String[] fields = "usd".equals(unit) ? new String[] {"remaining_usd", "cap_usd"} : "tokens".equals(unit) ? new String[] {"remaining_tokens", "cap_tokens"} : null;
    return new Budget(
        m.get("level") instanceof String ? (String) m.get("level") : null,
        m.get("scope_id") instanceof String ? (String) m.get("scope_id") : null,
        unit,
        fields == null ? null : number(m.get(fields[0])),
        fields == null ? null : number(m.get(fields[1])),
        Boolean.TRUE.equals(m.get("estimated")));
  }

  private static Double number(Object v) {
    if (v instanceof Number && !(v instanceof Boolean)) {
      double d = ((Number) v).doubleValue();
      return Double.isFinite(d) ? d : null;
    }
    return null;
  }

  private static String str(Object v) {
    return v instanceof String ? (String) v : "";
  }

  private static String header(Map<String, ?> headers, String name) {
    if (headers == null) {
      return "";
    }
    for (Map.Entry<String, ?> e : headers.entrySet()) {
      if (e.getKey() != null && e.getKey().toLowerCase(Locale.ROOT).equals(name)) {
        Object v = e.getValue() instanceof List ? (((List<?>) e.getValue()).isEmpty() ? null : ((List<?>) e.getValue()).get(0)) : e.getValue();
        return v == null ? "" : String.valueOf(v).strip();
      }
    }
    return "";
  }

  private static Duration retryAfter(Map<String, ?> headers) {
    String s = header(headers, "retry-after");
    if (s.isEmpty() || s.length() > 12 || !s.chars().allMatch(c -> c >= '0' && c <= '9')) {
      return null;
    }
    return Duration.ofSeconds(Long.parseLong(s));
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

  @Override
  public String toString() {
    return "GatewayRefusalException{kind=" + kind + ", code=" + code + ", status=" + status + ", message=" + getMessage() + "}";
  }
}
