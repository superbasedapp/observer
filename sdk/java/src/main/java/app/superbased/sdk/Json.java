package app.superbased.sdk;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.google.gson.ToNumberPolicy;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * JSON for the SDK. Parsing uses Gson (objects keep their key order; a whole
 * number is a {@link Long}, anything else a {@link Double}). Writing is the
 * SDK's own: compact, the way JavaScript's {@code JSON.stringify} writes it
 * (ECMAScript number form: {@code 1.0} is {@code 1}, {@code 1e-7},
 * {@code 1e+21}; NaN and infinities {@code null}; non-ASCII kept; keys in
 * insertion order), so the Java, Python and TypeScript SDKs render a value
 * the same way (sdk/contract/sdk-behaviour-cases.json {@code compile_values}).
 */
public final class Json {
  private static final Gson GSON =
      new GsonBuilder()
          .setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE)
          .serializeNulls()
          .disableHtmlEscaping()
          .create();

  private Json() {}

  /**
   * Parse JSON text into plain Java values: {@code Map<String,Object>} (key
   * order kept), {@code List<Object>}, {@code String}, {@code Long},
   * {@code Double}, {@code Boolean} or {@code null}.
   *
   * @throws IllegalArgumentException when the text is not JSON
   */
  public static Object parse(String text) {
    try {
      return GSON.fromJson(text, Object.class);
    } catch (JsonParseException | IllegalStateException e) {
      throw new IllegalArgumentException("not JSON: " + e.getMessage(), e);
    }
  }

  /** Compact JSON in the {@code JSON.stringify} form (keys in insertion order). */
  public static String write(Object v) {
    StringBuilder sb = new StringBuilder();
    write(sb, v, false);
    return sb.toString();
  }

  /**
   * Canonical JSON: compact, object keys sorted (by code point) at every
   * level, numbers in the ECMAScript form. The literal experiment item id is
   * derived from it (review E-75).
   */
  public static String canonical(Object v) {
    StringBuilder sb = new StringBuilder();
    write(sb, v, true);
    return sb.toString();
  }

  private static void write(StringBuilder sb, Object v, boolean sorted) {
    if (v == null) {
      sb.append("null");
    } else if (v instanceof Boolean) {
      sb.append(((Boolean) v) ? "true" : "false");
    } else if (v instanceof Double || v instanceof Float) {
      sb.append(jsNumber(((Number) v).doubleValue()));
    } else if (v instanceof BigDecimal) {
      sb.append(jsNumber(((BigDecimal) v).doubleValue()));
    } else if (v instanceof Number) {
      sb.append(v.toString());
    } else if (v instanceof CharSequence || v instanceof Character) {
      quote(sb, v.toString());
    } else if (v instanceof Map) {
      Map<?, ?> m = (Map<?, ?>) v;
      Iterable<? extends Map.Entry<?, ?>> entries = m.entrySet();
      if (sorted) {
        TreeMap<String, Object> t = new TreeMap<>(Json::compareCodePoints);
        for (Map.Entry<?, ?> e : m.entrySet()) {
          t.put(String.valueOf(e.getKey()), e.getValue());
        }
        entries = t.entrySet();
      }
      sb.append('{');
      boolean first = true;
      for (Map.Entry<?, ?> e : entries) {
        if (!first) {
          sb.append(',');
        }
        first = false;
        quote(sb, String.valueOf(e.getKey()));
        sb.append(':');
        write(sb, e.getValue(), sorted);
      }
      sb.append('}');
    } else if (v instanceof Collection || v instanceof Object[]) {
      Iterable<?> it = v instanceof Object[] ? List.of((Object[]) v) : (Collection<?>) v;
      sb.append('[');
      boolean first = true;
      for (Object x : it) {
        if (!first) {
          sb.append(',');
        }
        first = false;
        write(sb, x, sorted);
      }
      sb.append(']');
    } else {
      quote(sb, v.toString());
    }
  }

  static int compareCodePoints(String a, String b) {
    int i = 0;
    int j = 0;
    while (i < a.length() && j < b.length()) {
      int ca = a.codePointAt(i);
      int cb = b.codePointAt(j);
      if (ca != cb) {
        return Integer.compare(ca, cb);
      }
      i += Character.charCount(ca);
      j += Character.charCount(cb);
    }
    return Integer.compare(a.length() - i, b.length() - j);
  }

  /** A JSON string literal (the JSON.stringify escapes; non-ASCII kept). */
  static void quote(StringBuilder sb, String s) {
    sb.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"':
          sb.append("\\\"");
          break;
        case '\\':
          sb.append("\\\\");
          break;
        case '\n':
          sb.append("\\n");
          break;
        case '\r':
          sb.append("\\r");
          break;
        case '\t':
          sb.append("\\t");
          break;
        case '\b':
          sb.append("\\b");
          break;
        case '\f':
          sb.append("\\f");
          break;
        default:
          if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int) c));
          } else {
            sb.append(c);
          }
      }
    }
    sb.append('"');
  }

  /**
   * ECMAScript {@code Number::toString} of a double: the shortest digits that
   * read back as the same double, then plain or exponent form by the spec's
   * rule (exponent form below 1e-6 and from 1e21). NaN and infinities give
   * {@code null} (as JSON.stringify writes them).
   */
  public static String jsNumber(double x) {
    if (Double.isNaN(x) || Double.isInfinite(x)) {
      return "null";
    }
    if (x == 0) {
      return "0";
    }
    String sign = x < 0 ? "-" : "";
    double a = Math.abs(x);
    BigDecimal exact = new BigDecimal(a);
    BigDecimal shortest = exact;
    for (int p = 1; p <= 17; p++) {
      BigDecimal r = exact.round(new MathContext(p, RoundingMode.HALF_EVEN));
      if (Double.parseDouble(r.toString()) == a) {
        shortest = r;
        break;
      }
    }
    shortest = shortest.stripTrailingZeros();
    BigInteger unscaled = shortest.unscaledValue();
    String digits = unscaled.toString();
    int k = digits.length();
    int n = k - shortest.scale(); // value = 0.digits * 10^n
    String out;
    if (k <= n && n <= 21) {
      out = digits + "0".repeat(n - k);
    } else if (0 < n && n <= 21) {
      out = digits.substring(0, n) + "." + digits.substring(n);
    } else if (-6 < n && n <= 0) {
      out = "0." + "0".repeat(-n) + digits;
    } else {
      int e = n - 1;
      out =
          digits.charAt(0)
              + (k > 1 ? "." + digits.substring(1) : "")
              + "e"
              + (e >= 0 ? "+" : "-")
              + Math.abs(e);
    }
    return sign + out;
  }

  /** Deep copy of parsed JSON values into fresh mutable maps and lists. */
  @SuppressWarnings("unchecked")
  static Object copy(Object v) {
    if (v instanceof Map) {
      Map<String, Object> out = new java.util.LinkedHashMap<>();
      for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
        out.put(String.valueOf(e.getKey()), copy(e.getValue()));
      }
      return out;
    }
    if (v instanceof List) {
      List<Object> out = new ArrayList<>();
      for (Object x : (List<Object>) v) {
        out.add(copy(x));
      }
      return out;
    }
    return v;
  }
}
