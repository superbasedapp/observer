package app.superbased.sdk;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The SDK control API by destination: which base URL, path and headers a
 * score, prompt, dataset, experiment or trace-cost call uses on this machine
 * ({@code local}) and on the organization's gateway ({@code online}). One
 * table, so the resources never disagree about where a destination is.
 */
final class Control {
  static final String API_VERSION_HEADER = "X-SBO-SDK-API-Version";
  static final String API_VERSION = "1";

  /** resource -> {machine path, gateway path}; {name}, {id}, {version} are filled (escaped). */
  static final Map<String, String[]> PATHS = new LinkedHashMap<>();

  static {
    PATHS.put("scores", new String[] {"/api/obs/scores", "/v1/sdk/scores"});
    PATHS.put("prompt", new String[] {"/api/obs/sdk/prompts/{name}", "/v1/sdk/prompts/{name}"});
    PATHS.put("prompts", new String[] {"/api/obs/sdk/prompts", "/v1/sdk/prompts"});
    PATHS.put("datasets", new String[] {"/api/obs/eval/datasets", "/v1/sdk/datasets"});
    PATHS.put("dataset", new String[] {"/api/obs/eval/datasets/{id}", "/v1/sdk/datasets/{id}"});
    PATHS.put(
        "dataset_items",
        new String[] {"/api/obs/eval/datasets/{id}/items", "/v1/sdk/datasets/{id}/snapshots/{version}/items"});
    PATHS.put("dataset_snapshot", new String[] {"/api/obs/eval/datasets/{id}/items", "/v1/sdk/datasets/{id}/snapshots"});
    PATHS.put("experiments", new String[] {"/api/obs/eval/experiments", "/v1/sdk/experiments"});
    PATHS.put("experiment", new String[] {"/api/obs/eval/experiments/{id}", "/v1/sdk/experiments/{id}"});
    PATHS.put(
        "experiment_results",
        new String[] {"/api/obs/eval/experiments/{id}/results", "/v1/sdk/experiments/{id}/results"});
    PATHS.put(
        "experiment_finish", new String[] {"/api/obs/eval/experiments/{id}/finish", "/v1/sdk/experiments/{id}/finish"});
    PATHS.put("trace_cost", new String[] {"/api/obs/trace/{id}", "/v1/sdk/traces/{id}/cost"});
  }

  private Control() {}

  /** One destination's control API. */
  static final class Side {
    final String name; // "local" or "online"
    final String base;
    final Map<String, String> headers; // the online one carries the credential
    final Duration timeout;

    Side(String name, String base, Map<String, String> headers, Duration timeout) {
      this.name = name;
      this.base = base;
      this.headers = headers;
      this.timeout = timeout;
    }

    String url(String resource, Map<String, ?> query, Map<String, ?> parts) {
      String path = PATHS.get(resource)[name.equals(Destination.ONLINE) ? 1 : 0];
      if (parts != null) {
        for (Map.Entry<String, ?> e : parts.entrySet()) {
          path = path.replace("{" + e.getKey() + "}", Http.escapeSegment(String.valueOf(e.getValue())));
        }
      }
      return Http.join(base, path, query);
    }

    Http.Response call(String method, String resource, Object body, Map<String, ?> query, Map<String, String> headers, Map<String, ?> parts) {
      Map<String, String> h = new LinkedHashMap<>(this.headers);
      if (headers != null) {
        h.putAll(headers);
      }
      return Http.request(method, url(resource, query, parts), body, h, timeout);
    }
  }

  private static final Object LOCK = new Object();
  private static Destination.Plan fallbackPlan;

  /** The plan of the last init(), or one resolved from the environment (cached) before init(). */
  static Destination.Plan currentPlan() {
    Destination.Plan p = Superbased.plan();
    if (p != null) {
      return p;
    }
    synchronized (LOCK) {
      if (fallbackPlan == null) {
        Map<String, String> env = Env.snapshot();
        fallbackPlan = Destination.resolve(Settings.resolve(env, null), env, null, null, null, false);
      }
      return fallbackPlan;
    }
  }

  static Duration apiTimeout() {
    Settings s = Superbased.settings();
    return s != null ? s.apiTimeout : Settings.DEFAULT_API_TIMEOUT;
  }

  /**
   * The control API of each active destination, online first. A degraded
   * {@code online} (no gateway or no credential) has NO target (review
   * R-B18); only admit() may fall back to the machine, and it does not use
   * this.
   */
  static List<Side> sides(Destination.Plan plan) {
    Destination.Plan p = plan != null ? plan : currentPlan();
    Duration t = apiTimeout();
    List<Side> out = new ArrayList<>();
    if (p.onlineEnabled()) {
      Map<String, String> h = new LinkedHashMap<>(p.onlineHeaders());
      h.put(API_VERSION_HEADER, API_VERSION);
      out.add(new Side(Destination.ONLINE, p.gatewayUrl, h, t));
    }
    if (Destination.LOCAL.equals(p.destination) || Destination.BOTH.equals(p.destination)) {
      out.add(new Side(Destination.LOCAL, p.nodeUrl, Map.of(), t));
    }
    return out;
  }

  static List<Side> sides() {
    return sides(null);
  }

  /** Why {@link #sides()} is empty. */
  static String unavailableReason() {
    Destination.Plan p = currentPlan();
    return !p.degraded.isEmpty() ? p.degraded : "destination " + p.destination + " has no usable target";
  }

  static void resetForTests() {
    synchronized (LOCK) {
      fallbackPlan = null;
    }
  }
}
