package app.superbased.sdk;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.context.Context;
import io.opentelemetry.sdk.trace.ReadableSpan;
import io.opentelemetry.sdk.trace.data.DelegatingSpanData;
import io.opentelemetry.sdk.trace.data.EventData;
import io.opentelemetry.sdk.trace.data.LinkData;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.samplers.Sampler;
import io.opentelemetry.sdk.trace.samplers.SamplingResult;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Predicate;

/**
 * What happens to a finished span before the SDK exports it: the vendor
 * scope filter, the attached-mode sample filter, the {@code shouldExport}
 * hook, and the content rules ({@code captureContent}, the {@code mask} hook,
 * {@code maxContentChars}). The original span is never changed: the content
 * rules export a copy.
 */
final class Pipeline {
  static final String TRUNCATED_MARK = "…[truncated]";
  private static final BigInteger TWO_64 = BigInteger.ONE.shiftLeft(64);

  final boolean captureContent;
  final int maxContentChars;
  final BiFunction<Object, String, Object> mask;
  final Predicate<SpanData> shouldExport;
  /** Applied only when the host's sampler decided (attached mode); null: export every recorded span. */
  final Double exportRatio;
  final List<String> dropScopePrefixes;

  Pipeline(
      boolean captureContent,
      int maxContentChars,
      BiFunction<Object, String, Object> mask,
      Predicate<SpanData> shouldExport,
      Double exportRatio,
      List<String> dropScopePrefixes) {
    this.captureContent = captureContent;
    this.maxContentChars = maxContentChars;
    this.mask = mask;
    this.shouldExport = shouldExport;
    this.exportRatio = exportRatio;
    this.dropScopePrefixes = dropScopePrefixes;
  }

  /** The pipeline-side counters, read by diagnostics(). */
  static final class Counters {
    long sampledOutSpans;
    long filteredSpans;
    long maskErrors;
    long shouldExportErrors;
    long vendorSpansDropped;
    long usageNetInputCorrected;
    String lastHookError = "";

    synchronized void reset() {
      sampledOutSpans = 0;
      filteredSpans = 0;
      maskErrors = 0;
      shouldExportErrors = 0;
      vendorSpansDropped = 0;
      usageNetInputCorrected = 0;
      lastHookError = "";
    }

    synchronized void error(String err) {
      if (err != null && !err.isEmpty()) {
        lastHookError = Util.head(err, 500);
      }
    }

    synchronized Map<String, Object> snapshot() {
      Map<String, Object> out = new LinkedHashMap<>();
      out.put("sampled_out_spans", sampledOutSpans);
      out.put("filtered_spans", filteredSpans);
      out.put("mask_errors", maskErrors);
      out.put("should_export_errors", shouldExportErrors);
      out.put("vendor_spans_dropped", vendorSpansDropped);
      out.put("usage_net_input_corrected", usageNetInputCorrected);
      out.put("last_hook_error", lastHookError);
      return out;
    }
  }

  static final Counters COUNTERS = new Counters();

  /** TraceIdRatioBased's bound: a trace is kept when the low 64 bits of its id are below it. */
  static BigInteger ratioBound(double rate) {
    double r = Math.max(0.0, Math.min(1.0, rate));
    return new BigDecimal(r).multiply(new BigDecimal(TWO_64)).setScale(0, java.math.RoundingMode.HALF_EVEN).toBigInteger();
  }

  /**
   * The ratio rule both other SDKs use (the low 64 bits of the trace id,
   * unsigned, below round(rate * 2^64)), so every service and every SDK keeps
   * the same traces.
   */
  static boolean keepByRatio(String traceIdHex, double rate) {
    if (traceIdHex == null || traceIdHex.length() != 32) {
      return true;
    }
    BigInteger low = new BigInteger(traceIdHex.substring(16), 16);
    return low.compareTo(ratioBound(rate)) < 0;
  }

  private static String scopeName(ReadableSpan span) {
    try {
      return span.getInstrumentationScopeInfo().getName();
    } catch (RuntimeException e) {
      return "";
    }
  }

  /** Whether a finished span goes on to export (every drop is counted). */
  static boolean keep(ReadableSpan span, Pipeline p) {
    if (p == null) {
      return true;
    }
    if (!p.dropScopePrefixes.isEmpty()) {
      String scope = scopeName(span);
      for (String prefix : p.dropScopePrefixes) {
        if (!scope.isEmpty() && scope.startsWith(prefix)) {
          synchronized (COUNTERS) {
            COUNTERS.vendorSpansDropped++;
          }
          return false;
        }
      }
    }
    if (p.exportRatio != null && p.exportRatio < 1.0) {
      try {
        if (!keepByRatio(span.getSpanContext().getTraceId(), p.exportRatio)) {
          synchronized (COUNTERS) {
            COUNTERS.sampledOutSpans++;
          }
          return false;
        }
      } catch (RuntimeException e) {
        // keep
      }
    }
    if (p.shouldExport != null) {
      boolean ok;
      try {
        ok = p.shouldExport.test(span.toSpanData());
      } catch (RuntimeException e) {
        synchronized (COUNTERS) {
          COUNTERS.shouldExportErrors++;
          COUNTERS.error("shouldExport: " + e);
        }
        ok = true; // fail open: keep the span
      }
      if (!ok) {
        synchronized (COUNTERS) {
          COUNTERS.filteredSpans++;
        }
        return false;
      }
    }
    return true;
  }

  private boolean needsContentRules() {
    return !captureContent || mask != null || maxContentChars > 0;
  }

  /** {keep, value} for one content attribute. */
  private Object[] contentValue(String key, Object value) {
    if (!captureContent) {
      return new Object[] {false, null};
    }
    Object v = value;
    if (mask != null) {
      try {
        v = mask.apply(value, key);
      } catch (RuntimeException e) {
        synchronized (COUNTERS) {
          COUNTERS.maskErrors++;
          COUNTERS.error("mask(" + key + "): " + e);
        }
        return new Object[] {false, null};
      }
      if (v == null) {
        return new Object[] {false, null};
      }
      if (!(v instanceof String || v instanceof Boolean || v instanceof Number || v instanceof Collection)) {
        v = String.valueOf(v);
      }
    }
    if (maxContentChars > 0 && v instanceof String && ((String) v).codePointCount(0, ((String) v).length()) > maxContentChars) {
      v = Util.head((String) v, maxContentChars) + TRUNCATED_MARK;
    }
    return new Object[] {true, v};
  }

  /** New attributes when a content rule changes {@code attrs}; null when none. */
  private Attributes rewrite(Attributes attrs) {
    if (attrs == null || attrs.isEmpty()) {
      return null;
    }
    boolean changed = false;
    AttributesBuilder b = Attributes.builder();
    for (Map.Entry<AttributeKey<?>, Object> e : attrs.asMap().entrySet()) {
      String key = e.getKey().getKey();
      if (!Keys.isContentKey(key)) {
        putRaw(b, e.getKey(), e.getValue());
        continue;
      }
      Object[] kv = contentValue(key, e.getValue());
      if (!(Boolean) kv[0]) {
        changed = true;
        continue;
      }
      if (kv[1] != e.getValue() && !kv[1].equals(e.getValue())) {
        changed = true;
        Attr.put(b, key, kv[1]);
      } else {
        putRaw(b, e.getKey(), e.getValue());
      }
    }
    return changed ? b.build() : null;
  }

  @SuppressWarnings("unchecked")
  private static void putRaw(AttributesBuilder b, AttributeKey<?> key, Object value) {
    b.put((AttributeKey<Object>) key, value);
  }

  /** The span data to export: {@code data} itself, or a copy with rewritten content. */
  SpanData applyContentRules(SpanData data) {
    if (!needsContentRules()) {
      return data;
    }
    try {
      Attributes newAttrs = rewrite(data.getAttributes());
      List<EventData> events = data.getEvents();
      List<EventData> newEvents = null;
      for (int i = 0; i < events.size(); i++) {
        EventData ev = events.get(i);
        Attributes ea = rewrite(ev.getAttributes());
        if (ea != null) {
          if (newEvents == null) {
            newEvents = new ArrayList<>(events);
          }
          newEvents.set(i, EventData.create(ev.getEpochNanos(), ev.getName(), ea, ev.getTotalAttributeCount()));
        }
      }
      if (newAttrs == null && newEvents == null) {
        return data;
      }
      return new View(data, newAttrs, newEvents);
    } catch (RuntimeException e) {
      synchronized (COUNTERS) {
        COUNTERS.maskErrors++;
        COUNTERS.error("content rules: " + e);
      }
      return stripAll(data);
    }
  }

  private static SpanData stripAll(SpanData data) {
    AttributesBuilder b = Attributes.builder();
    for (Map.Entry<AttributeKey<?>, Object> e : data.getAttributes().asMap().entrySet()) {
      if (!Keys.isContentKey(e.getKey().getKey())) {
        putRaw(b, e.getKey(), e.getValue());
      }
    }
    return new View(data, b.build(), List.of());
  }

  /** A span data copy with other attributes and events. */
  static final class View extends DelegatingSpanData {
    private final Attributes attrs;
    private final List<EventData> events;

    View(SpanData delegate, Attributes attrs, List<EventData> events) {
      super(delegate);
      this.attrs = attrs;
      this.events = events;
    }

    @Override
    public Attributes getAttributes() {
      return attrs != null ? attrs : super.getAttributes();
    }

    @Override
    public List<EventData> getEvents() {
      return events != null ? events : super.getEvents();
    }

    @Override
    public int getTotalAttributeCount() {
      return Math.max(super.getTotalAttributeCount(), getAttributes().size());
    }
  }

  /**
   * The sampler of a provider the SDK owns: parent based (or not) trace-id
   * ratio by the rule of {@link #keepByRatio}, with the rate swappable by a
   * later init().
   */
  static final class SwitchableSampler implements Sampler {
    private volatile Sampler inner = Sampler.parentBased(Sampler.alwaysOn());
    private volatile double rate = 1.0;

    void set(double rate, boolean parentBased) {
      Sampler root;
      if (rate >= 1.0) {
        root = Sampler.alwaysOn();
      } else if (rate <= 0.0) {
        root = Sampler.alwaysOff();
      } else {
        root = new RatioSampler(rate);
      }
      this.rate = rate;
      this.inner = parentBased ? Sampler.parentBased(root) : root;
    }

    double rate() {
      return rate;
    }

    @Override
    public SamplingResult shouldSample(
        Context parentContext,
        String traceId,
        String name,
        SpanKind spanKind,
        Attributes attributes,
        List<LinkData> parentLinks) {
      return inner.shouldSample(parentContext, traceId, name, spanKind, attributes, parentLinks);
    }

    @Override
    public String getDescription() {
      return "SuperbasedSampler{" + inner.getDescription() + "}";
    }
  }

  /** Trace-id ratio by the shared rule (not Java's TraceIdRatioBased, which differs). */
  static final class RatioSampler implements Sampler {
    private final double rate;

    RatioSampler(double rate) {
      this.rate = rate;
    }

    @Override
    public SamplingResult shouldSample(
        Context parentContext,
        String traceId,
        String name,
        SpanKind spanKind,
        Attributes attributes,
        List<LinkData> parentLinks) {
      return keepByRatio(traceId, rate) ? SamplingResult.recordAndSample() : SamplingResult.drop();
    }

    @Override
    public String getDescription() {
      return "TraceIdRatioBased{" + rate + "}";
    }
  }
}
