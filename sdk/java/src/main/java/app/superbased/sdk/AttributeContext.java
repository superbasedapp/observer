package app.superbased.sdk;

import io.opentelemetry.api.baggage.Baggage;
import io.opentelemetry.api.baggage.BaggageBuilder;
import io.opentelemetry.api.baggage.BaggageEntry;
import io.opentelemetry.api.baggage.propagation.W3CBaggagePropagator;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.ContextKey;
import io.opentelemetry.context.propagation.TextMapGetter;
import io.opentelemetry.context.propagation.TextMapPropagator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Per-request attributes ({@code propagateAttributes} / {@code identify}) and
 * W3C trace-context helpers ({@code inject} / {@code extract} /
 * {@code continueTrace}).
 *
 * <p>The attribute scope lives in the OpenTelemetry {@link Context} (a
 * thread-local in Java): it follows the current thread and an executor wrapped
 * with {@code Context.current().wrap(...)}. The SDK's span processor reads it
 * when a span starts and stamps the values the span does not already carry.
 */
final class AttributeContext {
  private static final ContextKey<RequestScope> KEY = ContextKey.named("superbased-sdk-attributes");
  static final TextMapPropagator PROPAGATOR =
      TextMapPropagator.composite(W3CTraceContextPropagator.getInstance(), W3CBaggagePropagator.getInstance());

  /** Option name -> span attribute (the scalar options). */
  static final Map<String, String> SCALAR_KEYS;

  static {
    Map<String, String> m = new LinkedHashMap<>();
    m.put("user", Keys.USER);
    m.put("session_id", Keys.SESSION);
    m.put("tenant", Keys.TENANT);
    m.put("release", Keys.RELEASE);
    m.put("environment", Keys.ENVIRONMENT);
    SCALAR_KEYS = Collections.unmodifiableMap(m);
  }

  private AttributeContext() {}

  /** An immutable set of per-request values (one level of nesting). */
  static final class RequestScope {
    static final RequestScope EMPTY = new RequestScope(Map.of(), List.of(), Map.of(), false);

    final Map<String, String> scalars; // attribute key -> value
    final List<String> tags;
    final Map<String, String> metadata;
    final boolean baggage;

    RequestScope(Map<String, String> scalars, List<String> tags, Map<String, String> metadata, boolean baggage) {
      this.scalars = scalars;
      this.tags = tags;
      this.metadata = metadata;
      this.baggage = baggage;
    }

    /** This scope with {@code a} on top. */
    RequestScope merged(TraceAttributes a) {
      Map<String, String> s = new LinkedHashMap<>(scalars);
      for (Object[] row : a.scalars()) {
        String v = (String) row[1];
        if (v == null) {
          continue;
        }
        String key = SCALAR_KEYS.get((String) row[0]);
        String c = Util.clamp(v, Keys.MAX_VALUE_LEN);
        if (c.isEmpty()) {
          s.remove(key); // "" clears it for the inner scope
        } else {
          s.put(key, c);
        }
      }
      List<String> t = Util.normalizeTags(tags, a.tags);
      List<Map<String, ?>> maps = new ArrayList<>();
      maps.add(metadata);
      maps.add(a.metadata);
      Map<String, String> m = Util.normalizeMetadata(maps);
      return new RequestScope(
          Collections.unmodifiableMap(s), List.copyOf(t), Collections.unmodifiableMap(m), baggage || a.asBaggage);
    }

    /** The span attributes this scope writes. */
    Map<String, Object> attributes() {
      Map<String, Object> out = new LinkedHashMap<>(scalars);
      if (!tags.isEmpty()) {
        out.put(Keys.TAGS, tags);
      }
      for (Map.Entry<String, String> e : metadata.entrySet()) {
        out.put(Keys.METADATA_PREFIX + e.getKey(), e.getValue());
      }
      return out;
    }

    /** The option-named view (getCurrentAttributes). */
    Map<String, Object> publicView() {
      Map<String, Object> out = new LinkedHashMap<>();
      for (Map.Entry<String, String> e : SCALAR_KEYS.entrySet()) {
        String v = scalars.get(e.getValue());
        if (v != null) {
          out.put(e.getKey(), v);
        }
      }
      if (!tags.isEmpty()) {
        out.put("tags", tags);
      }
      if (!metadata.isEmpty()) {
        out.put("metadata", metadata);
      }
      return out;
    }
  }

  static RequestScope current(Context ctx) {
    RequestScope s = (ctx == null ? Context.current() : ctx).get(KEY);
    return s == null ? RequestScope.EMPTY : s;
  }

  static Map<String, Object> scopeAttributes(Context ctx) {
    return current(ctx).attributes();
  }

  private static Context withBaggage(Context ctx, RequestScope scope) {
    BaggageBuilder b = Baggage.fromContext(ctx).toBuilder();
    for (Map.Entry<String, String> e : scope.scalars.entrySet()) {
      b.put(e.getKey(), e.getValue());
    }
    if (!scope.tags.isEmpty()) {
      b.put(Keys.TAGS, String.join(",", scope.tags));
    }
    for (Map.Entry<String, String> e : scope.metadata.entrySet()) {
      b.put(Keys.METADATA_PREFIX + e.getKey(), e.getValue());
    }
    return ctx.with(b.build());
  }

  /** Write the values just set onto the current span too (a root entered before the block). */
  private static void applyToCurrentSpan(RequestScope scope, TraceAttributes a) {
    Span sp = Span.current();
    if (!sp.isRecording()) {
      return;
    }
    try {
      Map<String, Object> attrs = scope.attributes();
      for (Object[] row : a.scalars()) {
        String v = (String) row[1];
        String key = SCALAR_KEYS.get((String) row[0]);
        if (v != null && !v.isEmpty() && attrs.containsKey(key)) {
          Attr.set(sp, key, attrs.get(key));
        }
      }
      if (a.tags != null && attrs.containsKey(Keys.TAGS)) {
        Attr.set(sp, Keys.TAGS, Util.normalizeTags(Attr.get(sp, Keys.TAGS), attrs.get(Keys.TAGS)));
      }
      if (a.metadata != null) {
        for (String k : a.metadata.keySet()) {
          String key = Keys.METADATA_PREFIX + Util.clamp(k, Keys.MAX_METADATA_KEY_LEN);
          if (attrs.containsKey(key)) {
            Attr.set(sp, key, attrs.get(key));
          }
        }
      }
    } catch (RuntimeException e) {
      // tagging never breaks the caller
    }
  }

  static AttributeScope enter(TraceAttributes a) {
    RequestScope scope = current(null).merged(a);
    Context ctx = Context.current().with(KEY, scope);
    if (scope.baggage) {
      ctx = withBaggage(ctx, scope);
    }
    AttributeScope handle = new AttributeScope(ctx.makeCurrent());
    applyToCurrentSpan(scope, a);
    return handle;
  }

  // --- trace context ---------------------------------------------------------------------

  static SpanContext validContext() {
    SpanContext sc = Span.current().getSpanContext();
    return sc.isValid() ? sc : null;
  }

  static String currentTraceId() {
    SpanContext sc = validContext();
    return sc == null ? "" : sc.getTraceId();
  }

  static String currentSpanId() {
    SpanContext sc = validContext();
    return sc == null ? "" : sc.getSpanId();
  }

  static Map<String, String> inject(Map<String, String> carrier) {
    Map<String, String> out = carrier == null ? new LinkedHashMap<>() : carrier;
    try {
      PROPAGATOR.inject(Context.current(), out, Map::put);
    } catch (RuntimeException e) {
      // never raises
    }
    return out;
  }

  private static final TextMapGetter<Map<String, ?>> GETTER =
      new TextMapGetter<>() {
        @Override
        public Iterable<String> keys(Map<String, ?> carrier) {
          List<String> out = new ArrayList<>();
          for (String k : carrier.keySet()) {
            out.add(k);
          }
          return out;
        }

        @Override
        public String get(Map<String, ?> carrier, String key) {
          if (carrier == null) {
            return null;
          }
          String want = key.toLowerCase(Locale.ROOT);
          for (Map.Entry<String, ?> e : carrier.entrySet()) {
            if (e.getKey() != null && e.getKey().toLowerCase(Locale.ROOT).equals(want)) {
              Object v = e.getValue();
              if (v instanceof List) {
                List<?> l = (List<?>) v;
                return l.isEmpty() ? null : String.valueOf(l.get(0));
              }
              return v == null ? null : String.valueOf(v);
            }
          }
          return null;
        }
      };

  static Context extract(Map<String, ?> carrier) {
    try {
      return PROPAGATOR.extract(Context.current(), carrier == null ? Map.of() : carrier, GETTER);
    } catch (RuntimeException e) {
      return Context.current();
    }
  }

  private static RequestScope scopeFromBaggage(Context ctx) {
    Map<String, BaggageEntry> entries = Baggage.fromContext(ctx).asMap();
    if (entries.isEmpty()) {
      return null;
    }
    Map<String, String> reverse = new LinkedHashMap<>();
    for (Map.Entry<String, String> e : SCALAR_KEYS.entrySet()) {
      reverse.put(e.getValue(), e.getKey());
    }
    TraceAttributes.Builder b = TraceAttributes.builder().asBaggage(true);
    Map<String, Object> meta = new LinkedHashMap<>();
    boolean any = false;
    for (Map.Entry<String, BaggageEntry> e : entries.entrySet()) {
      String k = e.getKey();
      String v = e.getValue().getValue();
      String opt = reverse.get(k);
      if (opt != null) {
        any = true;
        switch (opt) {
          case "user":
            b.user(v);
            break;
          case "session_id":
            b.sessionId(v);
            break;
          case "tenant":
            b.tenant(v);
            break;
          case "release":
            b.release(v);
            break;
          default:
            b.environment(v);
        }
      } else if (k.equals(Keys.TAGS)) {
        any = true;
        b.tags(List.of(v.split(",", -1)));
      } else if (k.startsWith(Keys.METADATA_PREFIX)) {
        meta.put(k.substring(Keys.METADATA_PREFIX.length()), v);
      }
    }
    if (!meta.isEmpty()) {
      any = true;
      b.metadata(meta);
    }
    return any ? current(ctx).merged(b.build()) : null;
  }

  /** The extracted context made current, with sbo.* baggage restored into the attribute scope. */
  static io.opentelemetry.context.Scope continueTrace(Map<String, ?> carrier) {
    Context ctx = extract(carrier);
    RequestScope scope = scopeFromBaggage(ctx);
    if (scope != null) {
      ctx = ctx.with(KEY, scope);
    }
    return ctx.makeCurrent();
  }

  static Context continuedContext(Map<String, ?> carrier) {
    Context ctx = extract(carrier);
    RequestScope scope = scopeFromBaggage(ctx);
    return scope != null ? ctx.with(KEY, scope) : ctx;
  }
}
