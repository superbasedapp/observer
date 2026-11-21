package app.superbased.sdk;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The environment the SDK reads its {@code SUPERBASED_*} and {@code OTEL_*}
 * variables from: the process environment with an SDK-owned overlay on top.
 *
 * <p>Java cannot change its own process environment, so a value the SDK sets
 * (the model client libraries' self-tracing switch, see {@link Vendor}) lives
 * in the overlay, and every SDK read goes through here. Tests use the overlay
 * to set and unset variables. A {@code null} overlay value means "unset", even
 * when the process environment has the variable.
 */
final class Env {
  private static final Object LOCK = new Object();
  private static final Map<String, String> OVERLAY = new HashMap<>();
  private static final String UNSET = new String("\u0000unset");

  private Env() {}

  /** The value of {@code name}, or {@code null} when it is not set. */
  static String get(String name) {
    synchronized (LOCK) {
      if (OVERLAY.containsKey(name)) {
        String v = OVERLAY.get(name);
        return v == UNSET ? null : v;
      }
    }
    return System.getenv(name);
  }

  /** The whole environment as one immutable map (the overlay applied). */
  static Map<String, String> snapshot() {
    Map<String, String> out = new HashMap<>(System.getenv());
    synchronized (LOCK) {
      for (Map.Entry<String, String> e : OVERLAY.entrySet()) {
        if (e.getValue() == UNSET) {
          out.remove(e.getKey());
        } else {
          out.put(e.getKey(), e.getValue());
        }
      }
    }
    return Collections.unmodifiableMap(out);
  }

  /** Set {@code name} for the SDK (null unsets it). */
  static void set(String name, String value) {
    Objects.requireNonNull(name, "name");
    synchronized (LOCK) {
      OVERLAY.put(name, value == null ? UNSET : value);
    }
  }

  /** Forget the overlay entry for {@code name} (the process value shows again). */
  static void clear(String name) {
    synchronized (LOCK) {
      OVERLAY.remove(name);
    }
  }

  /** Forget the whole overlay (tests). */
  static void resetForTests() {
    synchronized (LOCK) {
      OVERLAY.clear();
    }
  }
}
