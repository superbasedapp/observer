package app.superbased.sdk;

import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.sdk.trace.data.SpanData;
import java.io.PrintStream;
import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import java.util.function.BooleanSupplier;

/**
 * The app's first-trace line (SDK quickstart plan section 3.8, ruling R12;
 * contract sdk-api-surface.md section 16; cases
 * {@code sdk-behaviour-cases.json} {@code first_trace_link}):
 * after the first root span of the process is exported, the SDK writes one
 * line to stderr, directly (not through java.util.logging, which apps
 * usually keep at warnings):
 *
 * <pre>superbased: first trace from this process: &lt;link&gt;</pre>
 *
 * <p>Only with a console, {@code CI} unset (or empty, 0, false) and
 * {@code SUPERBASED_FIRST_TRACE_LINK} not 0, false or off, so production logs
 * stay quiet. Once per process; a plan refusal is said in its place.
 */
final class FirstTrace {
  static final String ENV = "SUPERBASED_FIRST_TRACE_LINK";
  static final String PREFIX = "superbased: first trace from this process: ";
  static final String REFUSED_PREFIX = "superbased: traces from this process were refused: ";
  static final String LOCAL_PATH = "/apps/traces?trace=";
  static final String ONLINE_PATH = "/trajectories?trace=";

  /** Whether stderr is a terminal (tests replace it). */
  static volatile BooleanSupplier terminal = FirstTrace::detectTerminal;

  /** Where the line goes (tests replace it). */
  static volatile PrintStream out = System.err;

  static final Tracker TRACKER = new Tracker();

  private FirstTrace() {}

  /**
   * {@code System.console() != null}; on Java 22 and later, where a console
   * object exists even when the streams are redirected, its
   * {@code isTerminal()}.
   */
  private static boolean detectTerminal() {
    Object c = System.console();
    if (c == null) {
      return false;
    }
    try {
      Object t = c.getClass().getMethod("isTerminal").invoke(c);
      return Boolean.TRUE.equals(t);
    } catch (ReflectiveOperationException | RuntimeException e) {
      return true;
    }
  }

  /** Ruling R12's gate: a terminal, CI unset (or empty, 0, false), not opted out. Pure. */
  static boolean allowed(boolean isTerminal, Map<String, String> env) {
    if (!isTerminal) {
      return false;
    }
    String ci = env.get("CI") == null ? "" : env.get("CI").strip().toLowerCase(Locale.ROOT);
    if (!(ci.isEmpty() || ci.equals("0") || ci.equals("false"))) {
      return false;
    }
    String opt = env.get(ENV) == null ? "" : env.get(ENV).strip().toLowerCase(Locale.ROOT);
    return !(opt.equals("0") || opt.equals("false") || opt.equals("off"));
  }

  /** The dashboard link to {@code traceId} for a destination ("" when none). Pure. */
  static String link(String dest, String base, String traceId) {
    String b = Http.stripRight(base == null ? "" : base, '/');
    if (b.isEmpty() || traceId == null || traceId.isEmpty()) {
      return "";
    }
    if (Destination.ONLINE.equals(dest)) {
      return b + ONLINE_PATH + traceId;
    }
    if (Destination.LOCAL.equals(dest)) {
      return b + LOCAL_PATH + traceId;
    }
    return "";
  }

  /** The line that says a plan refusal: the server's message as sent, then its upgrade link. Pure. */
  static String refusalLine(PlanRefusalException r) {
    String msg = r.getMessage() == null ? "" : r.getMessage().strip();
    String upgrade = r.upgradeUrl() == null ? "" : r.upgradeUrl();
    return REFUSED_PREFIX + msg + (upgrade.isEmpty() ? "" : " " + upgrade);
  }

  /**
   * The link bases a plan knows: local is the machine's dashboard when the
   * plan exports locally and the machine answered discovery; online is the
   * organization's dashboard when the plan exports online under record 2 or
   * 3 (none under record 1). Under both with an online base, a local success
   * waits for the online verdict.
   */
  static final class Bases {
    final String local;
    final String online;
    final boolean waitOnline;

    Bases(String local, String online, boolean waitOnline) {
      this.local = local == null ? "" : local;
      this.online = online == null ? "" : online;
      this.waitOnline = waitOnline;
    }

    static Bases of(Destination.Plan p) {
      if (p == null) {
        return new Bases("", "", false);
      }
      String local =
          Destination.LOCAL.equals(p.destination) || Destination.BOTH.equals(p.destination) ? p.localDashboard : "";
      String online = p.onlineEnabled() ? p.onlineDashboard : "";
      return new Bases(local, online, Destination.BOTH.equals(p.destination) && !online.isEmpty());
    }
  }

  /** Decides the line from the exports of root spans, in the order they finish (one owner of this state). */
  static final class Tracker {
    private boolean done;
    private String pendingLocal = "";
    private boolean onlineFailed;
    private String link = "";

    /** One export to {@code dest} of a batch whose first root span has {@code traceId}: {line, link}. */
    private String[] step(Bases b, String dest, String traceId, boolean ok, PlanRefusalException refusal) {
      String[] none = {"", ""};
      if (done || traceId == null || traceId.isEmpty()) {
        return none;
      }
      if (Destination.ONLINE.equals(dest)) {
        if (refusal != null) {
          return new String[] {refusalLine(refusal), ""};
        }
        if (ok && !b.online.isEmpty()) {
          String l = link(Destination.ONLINE, b.online, traceId);
          return new String[] {PREFIX + l, l};
        }
        if (ok) {
          onlineFailed = false;
          return none;
        }
        if (!pendingLocal.isEmpty()) {
          return new String[] {PREFIX + pendingLocal, pendingLocal};
        }
        onlineFailed = true;
        return none;
      }
      if (Destination.LOCAL.equals(dest)) {
        if (!ok || b.local.isEmpty()) {
          return none;
        }
        String l = link(Destination.LOCAL, b.local, traceId);
        if (b.waitOnline && !onlineFailed) {
          if (pendingLocal.isEmpty()) {
            pendingLocal = l;
          }
          return none;
        }
        return new String[] {PREFIX + l, l};
      }
      return none;
    }

    /** Run one export through the tracker and, when a line is due and the gate allows it, write it once. */
    synchronized void note(
        Bases b, String dest, String traceId, boolean ok, PlanRefusalException refusal, BooleanSupplier allowed, PrintStream to) {
      String[] r = step(b, dest, traceId, ok, refusal);
      if (r[0].isEmpty()) {
        return;
      }
      done = true;
      if (!allowed.getAsBoolean()) {
        return; // not a terminal, CI or opted out: for good
      }
      link = r[1];
      to.println(r[0]);
      to.flush();
    }

    synchronized boolean done() {
      return done;
    }

    synchronized String printed() {
      return link;
    }

    synchronized void reset() {
      done = false;
      pendingLocal = "";
      onlineFailed = false;
      link = "";
    }
  }

  /** The trace id of the first local root span (no parent, or a remote one); "" when none. */
  static String rootTraceId(Collection<SpanData> spans) {
    for (SpanData s : spans) {
      SpanContext parent = s.getParentSpanContext();
      if (parent == null || !parent.isValid() || parent.isRemote()) {
        return s.getTraceId();
      }
    }
    return "";
  }

  /** The exporter's one call: an export to {@code dest} of {@code spans} finished. */
  static void note(String dest, Collection<SpanData> spans, boolean ok, PlanRefusalException refusal) {
    if (TRACKER.done()) {
      return;
    }
    String id = rootTraceId(spans);
    if (id.isEmpty()) {
      return;
    }
    TRACKER.note(Bases.of(Superbased.plan), dest, id, ok, refusal, () -> allowed(terminal.getAsBoolean(), Env.snapshot()), out);
  }

  static void resetForTests() {
    TRACKER.reset();
    terminal = FirstTrace::detectTerminal;
    out = System.err;
  }
}
