package app.superbased.sdk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The outcome of {@link Superbased#runExperiment}. */
public final class ExperimentResult {
  final String name;
  String runId = "";
  final Map<String, String> runs = new LinkedHashMap<>();
  final List<ItemResult> items = new ArrayList<>();
  int skippedNoContent;
  /** destination -> its GET experiment body (first side first). */
  final Map<String, Object> server = new LinkedHashMap<>();
  final List<String> errors = Collections.synchronizedList(new ArrayList<>());
  /** Destinations skipped for want of a scope (403 insufficient_scope). */
  final List<String> skippedSides = new ArrayList<>();
  /** Results a destination did not accept. */
  int failedPosts;
  /** The org's plan refusing a post or the finish (posting runs on several threads). */
  volatile PlanRefusalException planRefusal;

  ExperimentResult(String name) {
    this.name = name;
  }

  public String name() {
    return name;
  }

  /** The first destination's run id ("" for an in-process run). */
  public String runId() {
    return runId;
  }

  /** destination -> run id. */
  public Map<String, String> runs() {
    return Collections.unmodifiableMap(runs);
  }

  public List<ItemResult> items() {
    return Collections.unmodifiableList(items);
  }

  /** Items skipped because the destination has no content for them. */
  public int skippedNoContent() {
    return skippedNoContent;
  }

  /** destination -> the run as the destination reports it after finish. */
  public Map<String, Object> server() {
    return Collections.unmodifiableMap(server);
  }

  /** Posting problems (results kept locally), skipped sides, gate notes. */
  public List<String> errors() {
    synchronized (errors) {
      return List.copyOf(errors);
    }
  }

  public List<String> skippedSides() {
    return Collections.unmodifiableList(skippedSides);
  }

  public int failedPosts() {
    return failedPosts;
  }

  /**
   * Set when the org's plan refused a post or the finish (the reason is in
   * {@link #errors()} too): its message and {@code upgradeUrl()} say why and
   * where to fix it. Null otherwise.
   */
  public PlanRefusalException planRefusal() {
    return planRefusal;
  }

  synchronized void notePlanRefusal(PlanRefusalException r) {
    if (planRefusal == null && r != null) {
      planRefusal = r;
    }
  }

  private static boolean isCount(Object v) {
    return v instanceof Long && (Long) v >= 0 || v instanceof Integer && (Integer) v >= 0;
  }

  private List<ItemResult> localScored() {
    List<ItemResult> out = new ArrayList<>();
    for (ItemResult i : items) {
      if (!i.error.isEmpty() || !i.scores.isEmpty()) {
        out.add(i);
      }
    }
    return out;
  }

  /**
   * How many items were scored: the first side's {@code total}, else the local
   * count of items with a score or a task error. An item with neither is
   * neither passed nor failed.
   */
  @SuppressWarnings("unchecked")
  public int scored() {
    boolean noneLocal = localScored().isEmpty();
    for (Object b : server.values()) {
      if (b instanceof Map) {
        Object total = ((Map<String, Object>) b).get("total");
        if (isCount(total) && (((Number) total).longValue() > 0 || noneLocal)) {
          return ((Number) total).intValue();
        }
      }
    }
    return localScored().size();
  }

  /** The first side's pass rate, else the local rate over scored items; NaN when nothing was scored. */
  @SuppressWarnings("unchecked")
  public double passRate() {
    for (Object b : server.values()) {
      if (!(b instanceof Map)) {
        continue;
      }
      Map<String, Object> m = (Map<String, Object>) b;
      Object pr = m.get("pass_rate");
      if (!(pr instanceof Number)) {
        continue;
      }
      Object total = m.get("total");
      if (isCount(total) && ((Number) total).longValue() == 0) {
        continue; // an older server's 0 for "nothing scored"
      }
      return ((Number) pr).doubleValue();
    }
    List<ItemResult> scored = localScored();
    if (scored.isEmpty()) {
      return Double.NaN;
    }
    long passed = scored.stream().filter(ItemResult::passed).count();
    return (double) passed / scored.size();
  }

  /** Per evaluator: {@code count}, {@code passed} and the {@code mean} of numeric and boolean values. */
  public Map<String, Map<String, Double>> summary() {
    Map<String, double[]> rows = new LinkedHashMap<>();
    for (ItemResult it : items) {
      for (Evaluation s : it.scores) {
        double[] r = rows.computeIfAbsent(s.name, k -> new double[4]);
        r[0] += 1;
        r[1] += s.passed() ? 1 : 0;
        if (s.value instanceof Boolean) {
          r[2] += ((Boolean) s.value) ? 1 : 0;
          r[3] += 1;
        } else if (s.value instanceof Number) {
          r[2] += ((Number) s.value).doubleValue();
          r[3] += 1;
        }
      }
    }
    Map<String, Map<String, Double>> out = new LinkedHashMap<>();
    for (Map.Entry<String, double[]> e : rows.entrySet()) {
      double[] r = e.getValue();
      Map<String, Double> m = new LinkedHashMap<>();
      m.put("count", r[0]);
      m.put("passed", r[1]);
      m.put("mean", r[3] > 0 ? r[2] / r[3] : 0.0);
      out.put(e.getKey(), m);
    }
    return out;
  }

  @Override
  public String toString() {
    return "ExperimentResult{name=" + name + ", runs=" + runs + ", scored=" + scored() + ", passRate=" + passRate() + "}";
  }
}
