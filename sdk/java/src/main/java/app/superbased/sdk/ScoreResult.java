package app.superbased.sdk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The outcome of one score write. {@link #ok()} is true only when EVERY
 * destination the call went to accepted it; no destination at all is not ok
 * (sdk-behaviour-cases.json {@code score_ok}). {@link #id()} is the stored
 * score id ({@code sc_…}) the first accepting destination returned;
 * {@link #clientId()} the idempotency id that was sent.
 */
public final class ScoreResult {
  boolean ok;
  String id = "";
  String clientId = "";
  /** name -> {ok, status, id, error}. */
  final Map<String, Map<String, Object>> destinations = new LinkedHashMap<>();
  final List<String> errors = new ArrayList<>();
  PlanRefusalException planRefusal;

  ScoreResult() {}

  ScoreResult(String clientId) {
    this.clientId = clientId;
  }

  public boolean ok() {
    return ok;
  }

  public String id() {
    return id;
  }

  public String clientId() {
    return clientId;
  }

  /** Per destination ({@code online}, {@code local}): {@code {ok, status, id, error}}. */
  public Map<String, Map<String, Object>> destinations() {
    return Collections.unmodifiableMap(destinations);
  }

  /** Every problem (validation or transport). */
  public List<String> errors() {
    return Collections.unmodifiableList(errors);
  }

  /**
   * Set when the org's plan refused the score: its message and
   * {@code upgradeUrl()} say why and where to fix it. Null otherwise.
   */
  public PlanRefusalException planRefusal() {
    return planRefusal;
  }

  void put(String side, boolean ok, int status, String id, String error) {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("ok", ok);
    m.put("status", status);
    m.put("id", id);
    m.put("error", error);
    destinations.put(side, m);
  }

  /** Every destination accepted, and there was at least one. */
  static boolean resultOk(ScoreResult r) {
    if (r.destinations.isEmpty()) {
      return false;
    }
    for (Map<String, Object> d : r.destinations.values()) {
      if (!Boolean.TRUE.equals(d.get("ok"))) {
        return false;
      }
    }
    return true;
  }

  @Override
  public String toString() {
    return "ScoreResult{ok=" + ok + ", id=" + id + ", clientId=" + clientId + ", errors=" + errors + "}";
  }
}
