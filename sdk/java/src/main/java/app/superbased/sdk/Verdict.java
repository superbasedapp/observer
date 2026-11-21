package app.superbased.sdk;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The result of an {@link Superbased#admit} check.
 *
 * <p>{@link #allowed()} is what the app should honour. In {@code observe}
 * mode the server always allows and records the shadow verdict; in
 * {@code enforce} mode it returns the real decision ({@code ask} and
 * {@code deny} are not allowed; {@code flag} still admits).
 *
 * <p>{@link #degraded()} is empty for a clean decision. A client-side failure
 * sets it to one of {@link Admit#UNAVAILABLE}, {@link Admit#TIMEOUT},
 * {@link Admit#TRANSPORT}, {@link Admit#HTTP_ERROR},
 * {@link Admit#BAD_RESPONSE} or {@link Admit#ADMISSION_OFF};
 * {@link #httpStatus()} and {@link #error()} carry the detail.
 */
public final class Verdict {
  boolean allowed;
  String decision;
  String severity = "";
  String criterion = "";
  String reason = "";
  String mode = "";
  boolean judgeUsed;
  String degraded = "";
  String enforceDecision = "";
  long latencyMs;
  String verdictId = "";
  int httpStatus;
  String error = "";

  Verdict() {}

  static Verdict fromBody(Map<String, Object> d) {
    Verdict v = new Verdict();
    Object allowed = d.getOrDefault("allowed", Boolean.TRUE);
    v.allowed = allowed instanceof Boolean && (Boolean) allowed;
    v.decision = str(d, "decision");
    if (v.decision.isEmpty()) {
      v.decision = v.allowed ? "allow" : "deny";
    }
    v.severity = str(d, "severity");
    v.criterion = str(d, "criterion");
    v.reason = str(d, "reason");
    v.mode = str(d, "mode");
    v.judgeUsed = Boolean.TRUE.equals(d.get("judge_used"));
    v.degraded = str(d, "degraded");
    v.enforceDecision = str(d, "enforce_decision");
    Object lat = d.get("latency_ms");
    v.latencyMs = lat instanceof Number ? ((Number) lat).longValue() : 0;
    Object vid = d.containsKey("verdict_id") ? d.get("verdict_id") : d.get("id");
    if (vid instanceof String) {
      v.verdictId = (String) vid;
    } else if (vid instanceof Long) {
      v.verdictId = vid.toString();
    } else if (vid instanceof Double && ((Double) vid) == Math.rint((Double) vid)) {
      v.verdictId = Long.toString(((Double) vid).longValue());
    }
    return v;
  }

  private static String str(Map<String, Object> d, String k) {
    Object v = d.get(k);
    return v instanceof String ? (String) v : "";
  }

  public boolean allowed() {
    return allowed;
  }

  /** {@code allow}, {@code flag}, {@code ask} or {@code deny}. */
  public String decision() {
    return decision;
  }

  public String severity() {
    return severity;
  }

  public String criterion() {
    return criterion;
  }

  public String reason() {
    return reason;
  }

  /** {@code observe}, {@code enforce}, {@code off} or "". */
  public String mode() {
    return mode;
  }

  public boolean judgeUsed() {
    return judgeUsed;
  }

  /** Why no decision was made, "" for a clean decision. */
  public String degraded() {
    return degraded;
  }

  /** What enforce mode would decide (an observe-mode preview). */
  public String enforceDecision() {
    return enforceDecision;
  }

  public long latencyMs() {
    return latencyMs;
  }

  /** The server's id of the recorded verdict, "" when none. */
  public String verdictId() {
    return verdictId;
  }

  /** The HTTP status of the answer (0 when there was none). */
  public int httpStatus() {
    return httpStatus;
  }

  public String error() {
    return error;
  }

  /** Every field by its wire name. */
  public Map<String, Object> toMap() {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("allowed", allowed);
    m.put("decision", decision);
    m.put("severity", severity);
    m.put("criterion", criterion);
    m.put("reason", reason);
    m.put("mode", mode);
    m.put("judge_used", judgeUsed);
    m.put("degraded", degraded);
    m.put("enforce_decision", enforceDecision);
    m.put("latency_ms", latencyMs);
    m.put("verdict_id", verdictId);
    m.put("http_status", httpStatus);
    m.put("error", error);
    return m;
  }

  @Override
  public String toString() {
    return "Verdict{allowed="
        + allowed
        + ", decision="
        + decision
        + ", enforceDecision="
        + enforceDecision
        + ", degraded="
        + degraded
        + ", reason="
        + reason
        + "}";
  }
}
