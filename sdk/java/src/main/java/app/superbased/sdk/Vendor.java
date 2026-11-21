package app.superbased.sdk;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Model client libraries that trace themselves.
 *
 * <p>Some provider SDKs start an OpenTelemetry span for every API call (the
 * Anthropic SDKs, switch {@code ANTHROPIC_OPEN_TELEMETRY}). Under a framework
 * instrumentation or a manual LLM span every call would then be recorded and
 * counted twice. So init() turns such a library's own tracing off when the
 * app has not set its switch, and the export pipeline drops spans from its
 * tracer scope. An app that set the switch to anything other than its off
 * value keeps the library's spans.
 *
 * <p>Java cannot change its own process environment: the switch the SDK sets
 * lives in the SDK's environment view ({@link Env}), which is what
 * diagnostics report. The scope filter is what keeps the second copy out.
 */
final class Vendor {
  static final String OFF = "off";
  static final String KEPT = "kept";

  /** One client library that traces itself. */
  static final class SelfTracing {
    final String name;
    final String env;
    final String off;
    final String scopePrefix;

    SelfTracing(String name, String env, String off, String scopePrefix) {
      this.name = name;
      this.env = env;
      this.off = off;
      this.scopePrefix = scopePrefix;
    }
  }

  static final List<SelfTracing> LIBRARIES =
      List.of(new SelfTracing("anthropic", "ANTHROPIC_OPEN_TELEMETRY", "false", "com.anthropic.sdk"));

  // name -> the app's own value of the switch at the first init() (null: unset).
  private static final Map<String, String[]> APP_VALUE = new HashMap<>();

  private Vendor() {}

  /** Turn each library's own tracing off unless the app set its switch: {name: off|kept}. */
  static synchronized Map<String, String> apply() {
    Map<String, String> out = new LinkedHashMap<>();
    for (SelfTracing lib : LIBRARIES) {
      if (!APP_VALUE.containsKey(lib.name)) {
        APP_VALUE.put(lib.name, new String[] {Env.get(lib.env)});
      }
      String app = APP_VALUE.get(lib.name)[0];
      if (app == null) {
        Env.set(lib.env, lib.off);
        out.put(lib.name, OFF);
      } else if (app.strip().toLowerCase(Locale.ROOT).equals(lib.off)) {
        out.put(lib.name, OFF);
      } else {
        out.put(lib.name, KEPT);
      }
    }
    return out;
  }

  /** The tracer scopes whose spans the export pipeline drops. */
  static List<String> dropPrefixes(Map<String, String> state) {
    List<String> out = new ArrayList<>();
    for (SelfTracing lib : LIBRARIES) {
      if (OFF.equals(state.get(lib.name))) {
        out.add(lib.scopePrefix);
      }
    }
    return out;
  }

  static synchronized void resetForTests() {
    for (SelfTracing lib : LIBRARIES) {
      if (APP_VALUE.containsKey(lib.name)) {
        APP_VALUE.remove(lib.name);
        Env.clear(lib.env);
      }
    }
  }
}
