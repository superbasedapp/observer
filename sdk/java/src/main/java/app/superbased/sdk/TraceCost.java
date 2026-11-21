package app.superbased.sdk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * {@code getTraceCost()}: a trace's cost and where each number came from
 * (contract cost-source.md section 6). The organization answers
 * {@code GET /v1/sdk/traces/{trace_id}/cost}; the machine carries the same
 * object under {@code cost} in {@code GET /api/obs/trace/{id}}.
 * {@code online} reads the organization, {@code local} the machine,
 * {@code both} the organization first, then the machine.
 */
public final class TraceCost {
  public static final String GATEWAY_EXACT = "gateway_exact";
  public static final String PROXY_EXACT = "proxy_exact";
  public static final String COMPUTED = "computed";
  public static final String REPORTED = "reported";
  public static final String UNPRICED = "";
  /** Every cost_source value, in precedence order, then unpriced. */
  public static final List<String> COST_SOURCES = List.of(GATEWAY_EXACT, PROXY_EXACT, COMPUTED, REPORTED, UNPRICED);

  /** The display label of each value. */
  public static final Map<String, String> LABELS;

  static {
    Map<String, String> m = new LinkedHashMap<>();
    m.put(GATEWAY_EXACT, "Gateway exact");
    m.put(PROXY_EXACT, "Proxy exact");
    m.put(COMPUTED, "Computed");
    m.put(REPORTED, "Reported");
    m.put(UNPRICED, "Unpriced");
    LABELS = java.util.Collections.unmodifiableMap(m);
  }

  private static final Pattern TRACE_ID = Pattern.compile("^[0-9a-f]{32}$");
  private static long lastLog;

  private TraceCost() {}

  /** True for the exact family ({@code gateway_exact}, {@code proxy_exact}). */
  public static boolean isExact(String costSource) {
    return GATEWAY_EXACT.equals(costSource) || PROXY_EXACT.equals(costSource);
  }

  static String traceId(String traceId) {
    if (traceId == null) {
      return AttributeContext.currentTraceId();
    }
    String tid = traceId.strip().toLowerCase(Locale.ROOT);
    if (!TRACE_ID.matcher(tid).matches() || tid.equals("0".repeat(32))) {
      throw new IllegalArgumentException("traceId '" + traceId + "' must be 32 hex digits, not all zero");
    }
    return tid;
  }

  private static void log(String msg) {
    long now = System.currentTimeMillis();
    synchronized (TraceCost.class) {
      if (now - lastLog < 60_000) {
        return;
      }
      lastLog = now;
    }
    Util.warn("trace cost not read: " + msg);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> costObject(String side, Object body) {
    if (!(body instanceof Map)) {
      return null;
    }
    Object obj = Destination.LOCAL.equals(side) ? ((Map<String, Object>) body).get("cost") : body;
    if (!(obj instanceof Map) || !((Map<String, Object>) obj).containsKey("spans")) {
      return null;
    }
    Map<String, Object> out = (Map<String, Object>) Json.copy(obj);
    out.put("destination", side);
    return out;
  }

  /**
   * The TraceCost object (wire names, plus {@code destination}) of
   * {@code traceId} (null: the current trace), or null when no destination
   * has it yet, there is no trace, or the read failed.
   */
  static Map<String, Object> get(String traceId) {
    String tid = traceId(traceId);
    if (tid.isEmpty()) {
      return null;
    }
    List<Control.Side> targets = Control.sides();
    if (targets.isEmpty()) {
      log(Control.unavailableReason());
      return null;
    }
    List<String> errors = new ArrayList<>();
    for (Control.Side side : targets) {
      Http.Response resp = side.call("GET", "trace_cost", null, null, null, Map.of("id", tid));
      if (resp.status == 200) {
        Map<String, Object> obj = costObject(side.name, resp.body);
        if (obj != null) {
          return obj;
        }
        errors.add(side.name + ": the answer carries no trace cost (an older server)");
        continue;
      }
      if (resp.status == 404) {
        continue;
      }
      errors.add(side.name + ": " + resp.describe());
    }
    if (!errors.isEmpty()) {
      log(String.join("; ", errors));
    }
    return null;
  }

  static synchronized void resetForTests() {
    lastLog = 0;
  }
}
