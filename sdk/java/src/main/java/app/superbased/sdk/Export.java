package app.superbased.sdk;

import io.opentelemetry.context.Context;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.trace.ReadWriteSpan;
import io.opentelemetry.sdk.trace.ReadableSpan;
import io.opentelemetry.sdk.trace.SpanProcessor;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SpanExporter;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Filter;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Export plumbing: a failure-counting exporter wrapper, the one switchable
 * span processor, quiet logging and the diagnostics counters.
 *
 * <p>The SDK has exactly ONE span processor ({@link SwitchableProcessor}) on
 * the provider that holds the app's spans. Re-running init() swaps the
 * processor's delegate (a BatchSpanProcessor over a {@link CountingExporter}
 * per destination) instead of adding another, so spans are never exported
 * twice or lost to an orphaned provider.
 */
final class Export {
  static final Duration FAILURE_LOG_INTERVAL = Duration.ofSeconds(60);

  private Export() {}

  /** Process-wide export counters. */
  static final class Stats {
    long handedSpans;
    long exportedSpans;
    long abandonedSpans;
    long failedExports;
    long droppedSpans;
    String lastError = "";
    double lastErrorAt;
    long lastLoggedAtMs;
    long unloggedFailures;

    synchronized void reset() {
      handedSpans = 0;
      exportedSpans = 0;
      abandonedSpans = 0;
      failedExports = 0;
      droppedSpans = 0;
      lastError = "";
      lastErrorAt = 0;
      lastLoggedAtMs = 0;
      unloggedFailures = 0;
    }

    long pendingLocked() {
      return Math.max(0, handedSpans - exportedSpans - droppedSpans - abandonedSpans);
    }

    synchronized void noteError(String message) {
      lastError = Util.head(message, 500);
      lastErrorAt = System.currentTimeMillis() / 1000.0;
    }

    synchronized Map<String, Object> snapshot() {
      Map<String, Object> out = new LinkedHashMap<>();
      out.put("pending_spans", pendingLocked());
      out.put("exported_spans", exportedSpans);
      out.put("failed_exports", failedExports);
      out.put("dropped_spans", droppedSpans);
      out.put("last_error", lastError);
      out.put("last_error_at", lastErrorAt);
      return out;
    }
  }

  static final Stats STATS = new Stats();

  /** At most one summary line per FAILURE_LOG_INTERVAL; true when one was written. */
  static boolean maybeLogFailures() {
    long n;
    long total;
    String err;
    long now = System.currentTimeMillis();
    synchronized (STATS) {
      if (STATS.unloggedFailures == 0 || now - STATS.lastLoggedAtMs < FAILURE_LOG_INTERVAL.toMillis()) {
        return false;
      }
      n = STATS.unloggedFailures;
      err = STATS.lastError;
      total = STATS.droppedSpans;
      STATS.unloggedFailures = 0;
      STATS.lastLoggedAtMs = now;
    }
    Util.warn(
        n
            + " trace export(s) failed since the last report ("
            + total
            + " spans dropped in total); last error: "
            + (err.isEmpty() ? "unknown" : err));
    return true;
  }

  // --- quiet logging --------------------------------------------------------------------

  /**
   * The loggers the OTLP/HTTP exporter writes its failures to. A java.util.logging
   * filter belongs to one logger and is NOT inherited by child loggers, so the
   * filter goes on each concrete logger (a filter on the "io.opentelemetry.exporter"
   * parent never sees a child's record).
   */
  static final List<String> EXPORTER_LOGGERS =
      List.of("io.opentelemetry.exporter.internal.http.HttpExporter", "io.opentelemetry.exporter.sender.jdk.internal.JdkHttpSender");

  /** Name prefix of the threads the SDK's own exporter sends on. */
  static final String EXPORT_THREAD_PREFIX = "superbased-otlp-export-";

  private static final java.util.concurrent.atomic.AtomicInteger EXPORT_THREADS = new java.util.concurrent.atomic.AtomicInteger();

  /**
   * The executor the SDK's own OTLP exporters send on: its threads are how a
   * log record is told apart from a host exporter's (the filter only touches
   * records written on these threads, or inside the SDK's export call).
   */
  static final java.util.concurrent.ExecutorService EXPORT_EXECUTOR =
      java.util.concurrent.Executors.newCachedThreadPool(
          r -> {
            Thread t = new Thread(r, EXPORT_THREAD_PREFIX + EXPORT_THREADS.incrementAndGet());
            t.setDaemon(true);
            return t;
          });

  /** Set while the SDK's own export call runs on this thread. */
  private static final ThreadLocal<Boolean> IN_SDK_EXPORT = ThreadLocal.withInitial(() -> Boolean.FALSE);

  private static boolean fromSdkExporter() {
    return IN_SDK_EXPORT.get() || Thread.currentThread().getName().startsWith(EXPORT_THREAD_PREFIX);
  }

  private static final Object LOG_LOCK = new Object();
  private static final Map<Logger, Filter[]> INSTALLED = new LinkedHashMap<>(); // logger -> {prior, ours}
  private static volatile boolean quietSuppress;

  /**
   * Route the SDK's own exporter's warnings into {@code last_error} (diagnostics
   * keeps the real cause) and, when {@code suppress} is true (the {@code quiet}
   * option), keep them out of the host's logs. Only records written by the
   * SDK's own exporter are touched: a host's other OTLP exporters in the JVM
   * log as before. {@link #removeLogCapture()} undoes it (shutdown()).
   */
  static void installLogCapture(boolean suppress) {
    synchronized (LOG_LOCK) {
      quietSuppress = suppress;
      for (String name : EXPORTER_LOGGERS) {
        Logger lg = Logger.getLogger(name);
        if (INSTALLED.containsKey(lg)) {
          continue;
        }
        Filter prior = lg.getFilter();
        Filter ours =
            rec -> {
              if (rec.getLevel().intValue() >= Level.WARNING.intValue() && fromSdkExporter()) {
                STATS.noteError(causeOf(rec));
                if (quietSuppress) {
                  return false;
                }
              }
              return prior == null || prior.isLoggable(rec);
            };
        lg.setFilter(ours);
        INSTALLED.put(lg, new Filter[] {prior, ours});
      }
    }
  }

  /** Put every logger's filter back as it was (only where ours is still the one installed). */
  static void removeLogCapture() {
    synchronized (LOG_LOCK) {
      for (Map.Entry<Logger, Filter[]> e : INSTALLED.entrySet()) {
        if (e.getKey().getFilter() == e.getValue()[1]) {
          e.getKey().setFilter(e.getValue()[0]);
        }
      }
      INSTALLED.clear();
    }
  }

  private static String causeOf(java.util.logging.LogRecord rec) {
    String msg = String.valueOf(rec.getMessage());
    Throwable t = rec.getThrown();
    if (t != null) {
      msg += " (" + t + ")";
    }
    return msg;
  }

  /**
   * Wraps a SpanExporter that is not an export destination (the console):
   * applies the same content rules (captureContent, mask, maxContentChars)
   * before the delegate sees a span, and counts nothing.
   */
  static final class CountingContentExporter implements SpanExporter {
    private final SpanExporter inner;
    private final SwitchableProcessor owner;

    CountingContentExporter(SpanExporter inner, SwitchableProcessor owner) {
      this.inner = inner;
      this.owner = owner;
    }

    @Override
    public CompletableResultCode export(Collection<SpanData> spans) {
      Pipeline p = owner.pipeline;
      List<SpanData> out = new ArrayList<>(spans.size());
      for (SpanData s : spans) {
        out.add(p == null ? s : p.applyContentRules(s));
      }
      return inner.export(out);
    }

    @Override
    public CompletableResultCode flush() {
      return inner.flush();
    }

    @Override
    public CompletableResultCode shutdown() {
      return inner.shutdown();
    }
  }

  /** Wraps a SpanExporter: applies the content rules, never throws, counts failures and drops. */
  static final class CountingExporter implements SpanExporter {
    private final SpanExporter inner;
    private final SwitchableProcessor owner;

    CountingExporter(SpanExporter inner, SwitchableProcessor owner) {
      this.inner = inner;
      this.owner = owner;
    }

    @Override
    public CompletableResultCode export(Collection<SpanData> spans) {
      Pipeline p = owner.pipeline;
      List<SpanData> out = new ArrayList<>(spans.size());
      for (SpanData s : spans) {
        out.add(p == null ? s : p.applyContentRules(s));
      }
      int n = out.size();
      CompletableResultCode result;
      IN_SDK_EXPORT.set(Boolean.TRUE);
      try {
        result = inner.export(out);
      } catch (RuntimeException e) {
        STATS.noteError(e.toString());
        result = CompletableResultCode.ofFailure();
      } finally {
        IN_SDK_EXPORT.set(Boolean.FALSE);
      }
      CompletableResultCode done = result;
      done.whenComplete(() -> counted(done.isSuccess(), n));
      return done;
    }

    private static void counted(boolean success, int n) {
      synchronized (STATS) {
        long late = Math.min(STATS.abandonedSpans, n);
        STATS.abandonedSpans -= late;
        if (success) {
          STATS.droppedSpans -= late;
          STATS.exportedSpans += n;
          return;
        }
        if (late == 0) {
          STATS.failedExports++;
          STATS.unloggedFailures++;
        }
        STATS.droppedSpans += n - late;
        if (STATS.lastError.isEmpty()) {
          STATS.lastError = "export failed";
          STATS.lastErrorAt = System.currentTimeMillis() / 1000.0;
        }
      }
      maybeLogFailures();
    }

    @Override
    public CompletableResultCode flush() {
      try {
        return inner.flush();
      } catch (RuntimeException e) {
        return CompletableResultCode.ofFailure();
      }
    }

    @Override
    public CompletableResultCode shutdown() {
      try {
        return inner.shutdown();
      } catch (RuntimeException e) {
        return CompletableResultCode.ofSuccess();
      }
    }
  }

  /** The delegate of a plan with nowhere to export: every span counted as dropped. */
  static final class Discard implements SpanProcessor {
    @Override
    public void onStart(Context parentContext, ReadWriteSpan span) {}

    @Override
    public boolean isStartRequired() {
      return false;
    }

    @Override
    public void onEnd(ReadableSpan span) {
      synchronized (STATS) {
        STATS.droppedSpans++;
      }
    }

    @Override
    public boolean isEndRequired() {
      return true;
    }
  }

  /**
   * Several processors as one delegate: one per destination of {@code both},
   * plus the console option. Flush and shutdown run every processor at once,
   * so a destination that is down never spends the other's share.
   */
  static final class Fanout implements SpanProcessor {
    final List<SpanProcessor> procs;
    /** The number of counted destinations (diagnostics' pending figure). */
    final int legs;

    Fanout(List<SpanProcessor> procs, int legs) {
      this.procs = procs;
      this.legs = legs;
    }

    @Override
    public void onStart(Context parentContext, ReadWriteSpan span) {
      for (SpanProcessor p : procs) {
        try {
          p.onStart(parentContext, span);
        } catch (RuntimeException e) {
          // never raises
        }
      }
    }

    @Override
    public boolean isStartRequired() {
      return true;
    }

    @Override
    public void onEnd(ReadableSpan span) {
      for (SpanProcessor p : procs) {
        try {
          p.onEnd(span);
        } catch (RuntimeException e) {
          // never raises
        }
      }
    }

    @Override
    public boolean isEndRequired() {
      return true;
    }

    @Override
    public CompletableResultCode forceFlush() {
      List<CompletableResultCode> all = new ArrayList<>();
      for (SpanProcessor p : procs) {
        all.add(p.forceFlush());
      }
      return CompletableResultCode.ofAll(all);
    }

    @Override
    public CompletableResultCode shutdown() {
      List<CompletableResultCode> all = new ArrayList<>();
      for (SpanProcessor p : procs) {
        all.add(p.shutdown());
      }
      return CompletableResultCode.ofAll(all);
    }
  }

  static int legsOf(SpanProcessor d) {
    if (d instanceof Fanout) {
      return ((Fanout) d).legs;
    }
    return 1;
  }

  /**
   * The one span processor the SDK adds. Forwards to a replaceable delegate,
   * stamps identity and per-request attributes the span does not carry, and
   * applies the pipeline before the delegate sees a finished span.
   */
  static final class SwitchableProcessor implements SpanProcessor {
    private volatile SpanProcessor delegate;
    private volatile Map<String, Object> stamp = Map.of();
    volatile Pipeline pipeline;
    volatile Duration shutdownTimeout = Settings.DEFAULT_SHUTDOWN_TIMEOUT;
    /** False until init() runs: a processor the app added before init() stays inert. */
    volatile boolean active;

    synchronized SpanProcessor swap(SpanProcessor d, Map<String, Object> newStamp) {
      SpanProcessor old = delegate;
      delegate = d;
      stamp = Map.copyOf(newStamp);
      return old;
    }

    SpanProcessor detach() {
      return swap(null, Map.of());
    }

    SpanProcessor delegate() {
      return delegate;
    }

    @Override
    public void onStart(Context parentContext, ReadWriteSpan span) {
      SpanProcessor d = delegate;
      Map<String, Object> st = stamp;
      if (d == null) {
        return;
      }
      Superbased.noteServiceName(span);
      try {
        Map<String, Object> scope = AttributeContext.scopeAttributes(parentContext);
        for (Map.Entry<String, Object> e : scope.entrySet()) {
          if (!Attr.has(span, e.getKey())) {
            Attr.set(span, e.getKey(), e.getValue());
          }
        }
        for (Map.Entry<String, Object> e : st.entrySet()) {
          Object have = Attr.get(span, e.getKey());
          if (have == null) {
            Attr.set(span, e.getKey(), e.getValue());
          } else if (e.getKey().equals(Keys.TAGS) && scope.containsKey(Keys.TAGS)) {
            Attr.set(span, Keys.TAGS, Util.normalizeTags(have, e.getValue()));
          }
        }
      } catch (RuntimeException e) {
        // tagging never breaks the span
      }
      try {
        d.onStart(parentContext, span);
      } catch (RuntimeException e) {
        // never raises
      }
    }

    @Override
    public boolean isStartRequired() {
      return true;
    }

    @Override
    public void onEnd(ReadableSpan span) {
      SpanProcessor d = delegate;
      if (d == null) {
        return;
      }
      if (!Pipeline.keep(span, pipeline)) {
        return;
      }
      synchronized (STATS) {
        STATS.handedSpans += legsOf(d);
      }
      try {
        d.onEnd(span);
      } catch (RuntimeException e) {
        // never raises
      }
    }

    @Override
    public boolean isEndRequired() {
      return true;
    }

    @Override
    public CompletableResultCode shutdown() {
      // Called when the HOLDING provider shuts down: close our delegate, bounded.
      SpanProcessor old = detach();
      if (old != null) {
        shutdownBounded(old, shutdownTimeout);
      }
      return CompletableResultCode.ofSuccess();
    }

    @Override
    public CompletableResultCode forceFlush() {
      SpanProcessor d = delegate;
      if (d == null) {
        return CompletableResultCode.ofSuccess();
      }
      try {
        return d.forceFlush();
      } catch (RuntimeException e) {
        return CompletableResultCode.ofFailure();
      }
    }
  }

  /** A flush or shutdown ran out of time: the unresolved spans are written off as dropped. */
  static void noteTimeout(String op, Duration timeout) {
    synchronized (STATS) {
      long pending = STATS.pendingLocked();
      STATS.failedExports++;
      STATS.abandonedSpans += pending;
      STATS.droppedSpans += pending;
      STATS.unloggedFailures++;
      String msg =
          op
              + " timed out after "
              + (timeout.toMillis() / 1000.0)
              + "s with "
              + pending
              + " span(s) not exported"
              + (STATS.lastError.isEmpty() ? "" : "; exporter: " + STATS.lastError);
      STATS.lastError = Util.head(msg, 500);
      STATS.lastErrorAt = System.currentTimeMillis() / 1000.0;
    }
  }

  /**
   * Flush, bounded. True only when every span was exported in time: the
   * OpenTelemetry Java batch processor reports a flush as done even when its
   * export failed, so a failure or a drop during the flush, or a span still
   * pending after it, makes it false.
   */
  static boolean flushBounded(SpanProcessor p, Duration timeout) {
    long failedBefore;
    long droppedBefore;
    synchronized (STATS) {
      failedBefore = STATS.failedExports;
      droppedBefore = STATS.droppedSpans;
    }
    CompletableResultCode r;
    try {
      r = p.forceFlush();
    } catch (RuntimeException e) {
      return false;
    }
    r.join(Math.max(0, timeout.toMillis()), TimeUnit.MILLISECONDS);
    if (!r.isDone()) {
      noteTimeout("flush", timeout);
      return false;
    }
    synchronized (STATS) {
      return r.isSuccess()
          && STATS.failedExports == failedBefore
          && STATS.droppedSpans == droppedBefore
          && STATS.pendingLocked() == 0;
    }
  }

  static boolean shutdownBounded(SpanProcessor p, Duration timeout) {
    CompletableResultCode r;
    try {
      r = p.shutdown();
    } catch (RuntimeException e) {
      return false;
    }
    r.join(Math.max(0, timeout.toMillis()), TimeUnit.MILLISECONDS);
    if (!r.isDone()) {
      noteTimeout("shutdown", timeout);
      return false;
    }
    return true;
  }
}
