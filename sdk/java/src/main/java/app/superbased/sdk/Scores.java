package app.superbased.sdk;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * {@code score()} and {@code feedback()} (contract scores.md). A score is
 * validated by the {@code internal/scorecore} rules before any call, gets an
 * idempotency id, and is written to each destination of the plan (the
 * gateway first under {@code both}, with the same id). Never throws.
 */
final class Scores {
  static final String SOURCE_SDK = "sdk";
  static final String SOURCE_FEEDBACK = "feedback";
  static final List<String> KINDS = List.of("numeric", "boolean", "categorical");
  static final String DEFAULT_FEEDBACK_NAME = "user_feedback";

  private static final Pattern NAME = Pattern.compile("^[a-z0-9_.-]{1,64}$");
  private static final Pattern ID = Pattern.compile("^[A-Za-z0-9_.:-]{1,128}$");
  private static final Pattern TRACE = Pattern.compile("^[0-9a-f]{32}$");
  private static final Pattern SPAN = Pattern.compile("^[0-9a-f]{16}$");
  static final int MAX_VALUE_BYTES = 120;
  static final int MAX_COMMENT_BYTES = 2000;

  private Scores() {}

  /** A score the rules refuse; the message starts with the contract's error code. */
  static final class ScoreError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    final String code;

    ScoreError(String code, String message) {
      super(code + ": " + message);
      this.code = code;
    }
  }

  static String kindOf(Object value) {
    if (value instanceof Boolean) {
      return "boolean";
    }
    if (value instanceof Number) {
      return "numeric";
    }
    if (value instanceof String) {
      return "categorical";
    }
    throw new ScoreError(
        "invalid_value",
        "value must be a number, a boolean or a string, got " + (value == null ? "null" : value.getClass().getSimpleName()));
  }

  /** The wire score object (scores.md section 1), validated. */
  static Map<String, Object> build(
      String name,
      Object value,
      String traceId,
      String spanId,
      String comment,
      String kind,
      String source,
      String scorer,
      String scorerVersion,
      String runId,
      String scoreId,
      String timestamp,
      boolean useCurrentTrace) {
    String n = (name == null ? "" : name).strip().toLowerCase(Locale.ROOT);
    if (!NAME.matcher(n).matches()) {
      throw new ScoreError("invalid_name", "name '" + name + "' must be 1-64 chars of a-z 0-9 _ . -");
    }
    String inferred = kindOf(value);
    if (kind != null && !kind.equals(inferred)) {
      if (!KINDS.contains(kind)) {
        throw new ScoreError("kind_mismatch", "kind '" + kind + "' is not numeric, boolean or categorical");
      }
      throw new ScoreError("kind_mismatch", "kind " + kind + " does not match a " + inferred + " value");
    }
    Object v = value;
    if ("numeric".equals(inferred)) {
      double d = ((Number) value).doubleValue();
      if (Double.isNaN(d) || Double.isInfinite(d)) {
        throw new ScoreError("invalid_value", "value " + value + " is not a finite number");
      }
    }
    if ("categorical".equals(inferred)) {
      String c = ((String) value).strip();
      if (c.isEmpty() || c.getBytes(StandardCharsets.UTF_8).length > MAX_VALUE_BYTES || c.contains("\n") || c.contains("\r")) {
        throw new ScoreError("invalid_value", "a categorical value must be 1-" + MAX_VALUE_BYTES + " bytes on one line");
      }
      v = c;
    }
    String tid = (traceId != null && !traceId.isEmpty() ? traceId : (useCurrentTrace ? AttributeContext.currentTraceId() : ""))
        .strip()
        .toLowerCase(Locale.ROOT);
    if (tid.isEmpty()) {
      throw new ScoreError("invalid_trace_id", "no traceId given and no current span");
    }
    if (!TRACE.matcher(tid).matches() || tid.equals("0".repeat(32))) {
      throw new ScoreError("invalid_trace_id", "traceId '" + traceId + "' must be 32 hex characters, not all zero");
    }
    String sid = (spanId == null ? "" : spanId).strip().toLowerCase(Locale.ROOT);
    if (!sid.isEmpty() && (!SPAN.matcher(sid).matches() || sid.equals("0".repeat(16)))) {
      throw new ScoreError("invalid_span_id", "spanId '" + spanId + "' must be 16 hex characters");
    }
    if (comment != null && comment.getBytes(StandardCharsets.UTF_8).length > MAX_COMMENT_BYTES) {
      throw new ScoreError("comment_too_long", "comment is over " + MAX_COMMENT_BYTES + " bytes");
    }
    String cid = scoreId != null && !scoreId.isEmpty() ? scoreId : "sdk_" + Util.randomHex32();
    if (!ID.matcher(cid).matches()) {
      throw new ScoreError("invalid_id", "scoreId '" + scoreId + "' must be 1-128 chars of A-Z a-z 0-9 _ . : -");
    }
    if (!SOURCE_SDK.equals(source) && !SOURCE_FEEDBACK.equals(source)) {
      throw new ScoreError("invalid_source", "source '" + source + "' must be sdk or feedback");
    }
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("id", cid);
    out.put("trace_id", tid);
    out.put("name", n);
    out.put("value", v);
    out.put("kind", inferred);
    out.put("source", source);
    if (!sid.isEmpty()) {
      out.put("span_id", sid);
    }
    if (comment != null && !comment.isEmpty()) {
      out.put("comment", comment);
    }
    if (scorer != null && !scorer.isEmpty()) {
      if (scorer.length() > 64 || (scorerVersion != null && scorerVersion.length() > 32)) {
        throw new ScoreError("bad_request", "scorer name is 1-64 chars and version 1-32");
      }
      Map<String, Object> sc = new LinkedHashMap<>();
      sc.put("name", scorer);
      sc.put("version", scorerVersion != null && !scorerVersion.isEmpty() ? scorerVersion : "1");
      out.put("scorer", sc);
    }
    if (runId != null && !runId.isEmpty()) {
      out.put("run_id", runId);
    }
    if (timestamp != null && !timestamp.isEmpty()) {
      out.put("timestamp", timestamp);
    }
    return out;
  }

  /**
   * No answer, 429 or a 5xx: worth one more try. A 429 over the plan's
   * allowance is not: it holds until the plan changes or the month turns.
   */
  static boolean retryable(Http.Response r) {
    if (r.status == 429 && r.planRefusal() != null) {
      return false;
    }
    return r.status == 0 || r.status == 429 || r.status >= 500;
  }

  /** Write already-built score objects to every destination. Never throws. */
  @SuppressWarnings("unchecked")
  static List<ScoreResult> post(List<Map<String, Object>> objs) {
    List<ScoreResult> results = new ArrayList<>();
    for (Map<String, Object> o : objs) {
      results.add(new ScoreResult((String) o.get("id")));
    }
    Object body = objs.size() == 1 ? objs.get(0) : Map.of("scores", objs);
    List<Control.Side> targets = Control.sides();
    if (targets.isEmpty()) {
      String reason = Control.unavailableReason();
      for (ScoreResult r : results) {
        r.put(Destination.ONLINE, false, 0, "", reason);
        r.errors.add("online: " + reason);
      }
    }
    for (Control.Side side : targets) {
      Http.Response resp = side.call("POST", "scores", body, null, null, null);
      if (retryable(resp)) {
        // Once, with the same ids: the id makes a repeat a no-op.
        resp = side.call("POST", "scores", body, null, null, null);
      }
      PlanRefusalException refusal = resp.planRefusal();
      Map<Integer, String> accepted = new LinkedHashMap<>();
      Map<Integer, String> rejected = new LinkedHashMap<>();
      Map<String, Object> rb = resp.object();
      if (rb != null) {
        if (rb.get("accepted") instanceof List) {
          for (Object a : (List<Object>) rb.get("accepted")) {
            if (a instanceof Map && ((Map<String, Object>) a).get("index") instanceof Long) {
              Map<String, Object> am = (Map<String, Object>) a;
              Object id = am.get("id");
              accepted.put(((Long) am.get("index")).intValue(), id == null ? "" : String.valueOf(id));
            }
          }
        }
        if (rb.get("rejected") instanceof List) {
          for (Object a : (List<Object>) rb.get("rejected")) {
            if (a instanceof Map && ((Map<String, Object>) a).get("index") instanceof Long) {
              Map<String, Object> am = (Map<String, Object>) a;
              String err = am.get("error") == null ? "rejected" : String.valueOf(am.get("error"));
              String msg = am.get("message") == null ? "" : String.valueOf(am.get("message"));
              rejected.put(((Long) am.get("index")).intValue(), msg.isEmpty() ? err : err + ": " + msg);
            }
          }
        }
      }
      for (int i = 0; i < results.size(); i++) {
        ScoreResult r = results.get(i);
        if (accepted.containsKey(i) && (resp.status == 200 || resp.status == 201)) {
          r.put(side.name, true, resp.status, accepted.get(i), "");
          if (r.id.isEmpty()) {
            r.id = accepted.get(i);
          }
        } else {
          String err = rejected.containsKey(i) ? rejected.get(i) : resp.describe();
          r.put(side.name, false, resp.status, "", err);
          r.errors.add(side.name + ": " + err);
          if (r.planRefusal == null) {
            r.planRefusal = refusal;
          }
        }
      }
    }
    for (ScoreResult r : results) {
      r.ok = ScoreResult.resultOk(r);
      if (!r.ok) {
        logFailure(r);
      }
    }
    return results;
  }

  private static long lastLog;

  private static void logFailure(ScoreResult r) {
    long now = System.currentTimeMillis();
    synchronized (Scores.class) {
      if (now - lastLog < 60_000) {
        return;
      }
      lastLog = now;
    }
    Util.warn("a score was not stored: " + (r.errors.isEmpty() ? "unknown" : String.join("; ", r.errors)));
  }

  static ScoreResult write(String name, Object value, ScoreOptions o, String source) {
    Map<String, Object> obj;
    try {
      obj =
          build(
              name,
              value,
              o.traceId,
              o.spanId,
              o.comment,
              o.kind,
              source,
              o.scorer,
              o.scorerVersion,
              o.runId,
              o.scoreId,
              o.timestamp,
              true);
    } catch (ScoreError e) {
      ScoreResult r = new ScoreResult();
      r.errors.add(e.getMessage());
      logFailure(r);
      return r;
    }
    try {
      return post(List.of(obj)).get(0);
    } catch (RuntimeException e) {
      ScoreResult r = new ScoreResult((String) obj.get("id"));
      r.errors.add(e.toString());
      return r;
    }
  }

  static ScoreResult score(String name, Object value, ScoreOptions o) {
    ScoreOptions opts = o == null ? ScoreOptions.defaults() : o;
    return write(name, value, opts, SOURCE_SDK);
  }

  static ScoreResult feedback(Object value, ScoreOptions o) {
    ScoreOptions opts = o == null ? ScoreOptions.defaults() : o;
    String name = opts.name != null && !opts.name.isEmpty() ? opts.name : DEFAULT_FEEDBACK_NAME;
    // feedback has no kind, scorer or run (scores.md: source feedback).
    ScoreOptions fb =
        ScoreOptions.builder()
            .traceId(opts.traceId)
            .spanId(opts.spanId)
            .comment(opts.comment)
            .scoreId(opts.scoreId)
            .timestamp(opts.timestamp)
            .build();
    return write(name, value, fb, SOURCE_FEEDBACK);
  }

  static synchronized void resetForTests() {
    lastLog = 0;
  }
}
