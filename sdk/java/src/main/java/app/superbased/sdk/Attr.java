package app.superbased.sdk;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.sdk.trace.ReadableSpan;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/** Untyped span-attribute helpers over the typed OpenTelemetry Java API. Never throw. */
final class Attr {
  private Attr() {}

  /** Set {@code key} to {@code value} (string, whole number, number, bool, or a list of strings). */
  static void set(Span sp, String key, Object value) {
    if (sp == null || value == null) {
      return;
    }
    try {
      if (value instanceof String) {
        sp.setAttribute(key, (String) value);
      } else if (value instanceof Boolean) {
        sp.setAttribute(key, (Boolean) value);
      } else if (value instanceof Double || value instanceof Float) {
        sp.setAttribute(key, ((Number) value).doubleValue());
      } else if (value instanceof Number) {
        sp.setAttribute(key, ((Number) value).longValue());
      } else if (value instanceof Collection) {
        List<String> out = new ArrayList<>();
        for (Object o : (Collection<?>) value) {
          out.add(String.valueOf(o));
        }
        sp.setAttribute(AttributeKey.stringArrayKey(key), out);
      } else {
        sp.setAttribute(key, String.valueOf(value));
      }
    } catch (RuntimeException e) {
      // a non-recording span or a bad value: never raises into the host
    }
  }

  /** Put {@code value} into {@code b} under {@code key} (the same types as {@link #set}). */
  static void put(AttributesBuilder b, String key, Object value) {
    if (value == null) {
      return;
    }
    if (value instanceof String) {
      b.put(key, (String) value);
    } else if (value instanceof Boolean) {
      b.put(key, (Boolean) value);
    } else if (value instanceof Double || value instanceof Float) {
      b.put(key, ((Number) value).doubleValue());
    } else if (value instanceof Number) {
      b.put(key, ((Number) value).longValue());
    } else if (value instanceof Collection) {
      List<String> out = new ArrayList<>();
      for (Object o : (Collection<?>) value) {
        out.add(String.valueOf(o));
      }
      b.put(AttributeKey.stringArrayKey(key), out);
    } else {
      b.put(key, String.valueOf(value));
    }
  }

  static Attributes of(Map<String, Object> m) {
    AttributesBuilder b = Attributes.builder();
    for (Map.Entry<String, Object> e : m.entrySet()) {
      put(b, e.getKey(), e.getValue());
    }
    return b.build();
  }

  /** The value of attribute {@code name} on a span the SDK can read, else null. */
  static Object get(Object sp, String name) {
    if (!(sp instanceof ReadableSpan)) {
      return null;
    }
    try {
      return get(((ReadableSpan) sp).getAttributes(), name);
    } catch (RuntimeException e) {
      return null;
    }
  }

  static Object get(Attributes attrs, String name) {
    for (Map.Entry<AttributeKey<?>, Object> e : attrs.asMap().entrySet()) {
      if (e.getKey().getKey().equals(name)) {
        return e.getValue();
      }
    }
    return null;
  }

  static boolean has(Object sp, String name) {
    return get(sp, name) != null;
  }
}
