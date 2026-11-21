package app.superbased.sdk;

import io.opentelemetry.api.trace.Span;
import java.net.http.HttpHeaders;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The organization's AI gateway helpers (contract cost-source.md section 4):
 * the request id the gateway answers with ({@code X-SBO-Request-Id}) stamped
 * on the span that made the call, so the organization joins its exact cost to
 * that span; and the app identity headers its app budget caps reserve against
 * ({@code X-Superbased-User}, {@code X-Superbased-Service}).
 *
 * <p>The Java SDK wraps no HTTP client (as the TypeScript SDK): pass
 * {@link #headers()} on each request to the gateway, and hand the response's
 * headers to {@link #stampRequestId}.
 */
public final class Gateway {
  public static final String REQUEST_ID_HEADER = "X-SBO-Request-Id";
  public static final String USER_HEADER = "X-Superbased-User";
  public static final String SERVICE_HEADER = "X-Superbased-Service";
  /** The gateway ignores a longer value. */
  public static final int MAX_APP_ID_LEN = 512;
  static final int MAX_REQUEST_ID_LEN = 256;

  private Gateway() {}

  private static String appValue(String v) {
    String s = v == null ? "" : v.strip();
    if (s.isEmpty() || s.length() > MAX_APP_ID_LEN) {
      return "";
    }
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c < ' ' || c > '~') {
        return "";
      }
    }
    return s;
  }

  /**
   * The headers the gateway reads a call's app identity from, for the request
   * being made now: {@code X-Superbased-User} (the per-request user, else
   * init()'s), {@code X-Superbased-Service} (the spans' {@code service.name})
   * and a fresh {@code X-SBO-Request-Id}. A value that is empty, too long or
   * not printable ASCII is left out. Never throws.
   */
  public static Map<String, String> headers() {
    Map<String, String> out = new LinkedHashMap<>();
    try {
      Object scoped = AttributeContext.current(null).publicView().get("user");
      Settings s = Superbased.settings();
      String user = appValue(scoped != null ? String.valueOf(scoped) : (s == null ? "" : s.user));
      if (!user.isEmpty()) {
        out.put(USER_HEADER, user);
      }
      String service = appValue(Admit.serviceName(Env.snapshot()));
      if (!service.isEmpty()) {
        out.put(SERVICE_HEADER, service);
      }
      out.put(REQUEST_ID_HEADER, "sdk-" + Util.randomHex32());
    } catch (RuntimeException e) {
      // never breaks the host's HTTP call
    }
    return out;
  }

  /** {@link #headers()} for those of them {@code existing} does not carry (case-insensitive). */
  public static Map<String, String> missingHeaders(Map<String, ?> existing) {
    Map<String, String> out = new LinkedHashMap<>();
    java.util.Set<String> have = new java.util.HashSet<>();
    if (existing != null) {
      for (String k : existing.keySet()) {
        have.add(k.toLowerCase(Locale.ROOT));
      }
    }
    for (Map.Entry<String, String> e : headers().entrySet()) {
      if (!have.contains(e.getKey().toLowerCase(Locale.ROOT))) {
        out.put(e.getKey(), e.getValue());
      }
    }
    return out;
  }

  /**
   * Set {@code request_id} on {@code span} (null: the current span) from the
   * gateway's {@code X-SBO-Request-Id} in {@code headers} (any map, matched
   * case-insensitively; a list value uses its first element). Returns true
   * when it stamped; a missing header, a span that already has
   * {@code request_id} or a non-recording span stamps nothing. Never throws.
   */
  public static boolean stampRequestId(Map<String, ?> headers, Span span) {
    try {
      String rid = "";
      if (headers != null) {
        for (Map.Entry<String, ?> e : headers.entrySet()) {
          if (e.getKey() != null && e.getKey().equalsIgnoreCase(REQUEST_ID_HEADER)) {
            Object v = e.getValue();
            if (v instanceof List) {
              v = ((List<?>) v).isEmpty() ? null : ((List<?>) v).get(0);
            }
            rid = v == null ? "" : String.valueOf(v);
            break;
          }
        }
      }
      if (rid.isBlank()) {
        return false;
      }
      Span sp = span != null ? span : Span.current();
      if (!sp.isRecording() || Attr.has(sp, Keys.REQUEST_ID)) {
        return false;
      }
      sp.setAttribute(Keys.REQUEST_ID, Util.head(rid.strip(), MAX_REQUEST_ID_LEN));
      return true;
    } catch (RuntimeException e) {
      return false;
    }
  }

  /** {@link #stampRequestId(Map, Span)} from a JDK {@link HttpHeaders}. */
  public static boolean stampRequestId(HttpHeaders headers, Span span) {
    return headers != null && stampRequestId(headers.map(), span);
  }
}
