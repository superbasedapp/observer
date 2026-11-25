package app.superbased.sdk;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.net.InetAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A small JSON-over-HTTP client (the JDK {@link HttpClient}) for the SDK's
 * control calls: destination discovery, admit, scores, prompts, datasets,
 * experiments and trace cost.
 *
 * <p>Never follows a redirect (a credential must not ride to a host the caller
 * did not name), and a loopback call never goes through a proxy. Never throws
 * for a transport or HTTP failure: the caller gets a {@link Response} with
 * {@code status} 0 and the reason.
 */
final class Http {
  static final String USER_AGENT = "superbased-sdk-java/" + Superbased.VERSION;

  private Http() {}

  /** One request as the transport sees it. */
  static final class Call {
    final String method;
    final String url;
    final Map<String, String> headers;
    final byte[] body;
    final Duration timeout;
    final boolean loopback;

    Call(String method, String url, Map<String, String> headers, byte[] body, Duration timeout, boolean loopback) {
      this.method = method;
      this.url = url;
      this.headers = headers;
      this.body = body;
      this.timeout = timeout;
      this.loopback = loopback;
    }
  }

  /** What came back on the wire (header names lower-cased). */
  static final class Raw {
    final int status;
    final Map<String, String> headers;
    final byte[] body;

    Raw(int status, Map<String, String> headers, byte[] body) {
      this.status = status;
      this.headers = headers;
      this.body = body;
    }
  }

  /** The seam tests replace to capture requests without dialling. */
  interface Transport {
    /**
     * Send one request.
     *
     * @throws HttpTimeoutException when no answer came in time
     * @throws IOException on any other transport failure
     */
    Raw send(Call call) throws IOException, InterruptedException;
  }

  static final Transport JDK = new JdkTransport();
  static volatile Transport transport = JDK;

  /** The outcome of one control call. {@code status} 0: no HTTP answer (see {@code error}). */
  static final class Response {
    final int status;
    final Object body;
    final Map<String, String> headers;
    final String error;
    final boolean timedOut;

    Response(int status, Object body, Map<String, String> headers, String error, boolean timedOut) {
      this.status = status;
      this.body = body;
      this.headers = headers == null ? Map.of() : headers;
      this.error = error == null ? "" : error;
      this.timedOut = timedOut;
    }

    static Response failed(String error, boolean timedOut) {
      return new Response(0, null, Map.of(), error, timedOut);
    }

    boolean ok() {
      return status >= 200 && status < 300;
    }

    String header(String name) {
      String v = headers.get(name.toLowerCase(Locale.ROOT));
      return v == null ? "" : v;
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> object() {
      return body instanceof Map ? (Map<String, Object>) body : null;
    }

    /** The SDK control API error envelope's {@code error} field, or "". */
    String errorCode() {
      Map<String, Object> o = object();
      return o != null && o.get("error") instanceof String ? (String) o.get("error") : "";
    }

    /** The org's plan refusal in this answer (a 403 {@code plan_required}, or a 429 over the plan's allowance), or null. */
    PlanRefusalException planRefusal() {
      return status == 403 || status == 429 ? PlanRefusalException.parse(status, body, headers) : null;
    }

    String describe() {
      if (status == 0) {
        return error.isEmpty() ? "no response" : error;
      }
      String code = errorCode();
      Map<String, Object> o = object();
      Object msg = o == null ? null : o.get("message");
      return "HTTP "
          + status
          + (code.isEmpty() ? "" : " " + code)
          + (msg instanceof String && !((String) msg).isEmpty() ? ": " + msg : "");
    }
  }

  /** True when {@code url}'s host is 127.0.0.0/8, ::1 or localhost. */
  static boolean isLoopbackUrl(String url) {
    String host;
    try {
      host = URI.create(url.trim()).getHost();
    } catch (RuntimeException e) {
      return false;
    }
    if (host == null || host.isEmpty()) {
      return false;
    }
    if (host.equalsIgnoreCase("localhost")) {
      return true;
    }
    if (host.startsWith("[") && host.endsWith("]")) {
      host = host.substring(1, host.length() - 1);
    }
    if (!looksLikeIp(host)) {
      return false; // never resolve a name here
    }
    try {
      return InetAddress.getByName(host).isLoopbackAddress();
    } catch (IOException e) {
      return false;
    }
  }

  private static boolean looksLikeIp(String host) {
    if (host.contains(":")) {
      return host.matches("[0-9A-Fa-f:.]+");
    }
    return host.matches("\\d{1,3}(\\.\\d{1,3}){3}");
  }

  /** {@code base} + {@code path} + a query of the non-empty values. */
  static String join(String base, String path, Map<String, ?> query) {
    String url = stripRight(base, '/') + path;
    if (query != null) {
      StringBuilder q = new StringBuilder();
      for (Map.Entry<String, ?> e : query.entrySet()) {
        Object v = e.getValue();
        if (v == null || "".equals(v)) {
          continue;
        }
        q.append(q.length() == 0 ? "" : "&")
            .append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
            .append('=')
            .append(URLEncoder.encode(String.valueOf(v), StandardCharsets.UTF_8));
      }
      if (q.length() > 0) {
        url += "?" + q;
      }
    }
    return url;
  }

  static String stripRight(String s, char c) {
    int end = s.length();
    while (end > 0 && s.charAt(end - 1) == c) {
      end--;
    }
    return s.substring(0, end);
  }

  /** Path-segment escaping (the Python {@code quote(v, safe="")} set). */
  static String escapeSegment(String v) {
    return URLEncoder.encode(v, StandardCharsets.UTF_8).replace("+", "%20").replace("%7E", "~");
  }

  /** One JSON call; a body is sent when {@code body} is not null. Never throws. */
  static Response request(String method, String url, Object body, Map<String, String> headers, Duration timeout) {
    Map<String, String> hdrs = new LinkedHashMap<>();
    hdrs.put("Accept", "application/json");
    hdrs.put("User-Agent", USER_AGENT);
    byte[] data = null;
    if (body != null) {
      data = Json.write(body).getBytes(StandardCharsets.UTF_8);
      hdrs.put("Content-Type", "application/json");
    }
    if (headers != null) {
      hdrs.putAll(headers);
    }
    try {
      Raw raw = send(new Call(method, url, hdrs, data, timeout, isLoopbackUrl(url)));
      Object parsed = null;
      if (raw.body != null && raw.body.length > 0) {
        try {
          parsed = Json.parse(new String(raw.body, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
          parsed = null;
        }
      }
      return new Response(raw.status, parsed, raw.headers, "", false);
    } catch (HttpTimeoutException e) {
      return Response.failed("timeout after " + timeout.toMillis() + "ms", true);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return Response.failed("interrupted", false);
    } catch (IOException | RuntimeException e) {
      return Response.failed(e.getClass().getSimpleName() + ": " + e.getMessage(), false);
    }
  }

  /** Send through the current transport (tests may capture it). */
  static Raw send(Call call) throws IOException, InterruptedException {
    return transport.send(call);
  }

  private static final class JdkTransport implements Transport {
    private volatile HttpClient loopback;
    private volatile HttpClient remote;

    private HttpClient client(boolean isLoopback) {
      if (isLoopback) {
        HttpClient c = loopback;
        if (c == null) {
          c =
              HttpClient.newBuilder()
                  .followRedirects(HttpClient.Redirect.NEVER)
                  .proxy(HttpClient.Builder.NO_PROXY)
                  .connectTimeout(Duration.ofSeconds(10))
                  .version(HttpClient.Version.HTTP_1_1)
                  .build();
          loopback = c;
        }
        return c;
      }
      HttpClient c = remote;
      if (c == null) {
        c =
            HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .proxy(ProxySelector.getDefault())
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        remote = c;
      }
      return c;
    }

    @Override
    public Raw send(Call call) throws IOException, InterruptedException {
      HttpRequest.BodyPublisher pub =
          call.body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(call.body);
      HttpRequest.Builder b =
          HttpRequest.newBuilder(URI.create(call.url))
              .timeout(call.timeout.isZero() || call.timeout.isNegative() ? Duration.ofMillis(1) : call.timeout)
              .method(call.method, pub);
      for (Map.Entry<String, String> h : call.headers.entrySet()) {
        b.header(h.getKey(), h.getValue());
      }
      // The deadline bounds the whole exchange, headers and body: the JDK's
      // request timeout covers the headers only, so a server that answers and
      // then drips the body would hold the caller past its budget.
      Duration budget = call.timeout.isZero() || call.timeout.isNegative() ? Duration.ofMillis(1) : call.timeout;
      long deadline = System.nanoTime() + budget.toNanos();
      CompletableFuture<HttpResponse<InputStream>> fut =
          client(call.loopback).sendAsync(b.build(), HttpResponse.BodyHandlers.ofInputStream());
      HttpResponse<InputStream> resp;
      try {
        resp = fut.get(Math.max(1L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
      } catch (TimeoutException e) {
        fut.cancel(true);
        throw new HttpTimeoutException("request timed out");
      } catch (ExecutionException e) {
        Throwable c = e.getCause();
        if (c instanceof IOException) {
          throw (IOException) c;
        }
        throw new IOException(String.valueOf(c), c);
      } catch (InterruptedException e) {
        fut.cancel(true);
        throw e;
      }
      byte[] bodyBytes;
      try (InputStream in = resp.body()) {
        bodyBytes = readBounded(in, deadline);
      }
      Map<String, String> headers = new LinkedHashMap<>();
      for (Map.Entry<String, List<String>> e : resp.headers().map().entrySet()) {
        if (!e.getValue().isEmpty()) {
          headers.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue().get(0));
        }
      }
      return new Raw(resp.statusCode(), headers, bodyBytes);
    }
  }

  /** The most of a response body any control call reads (1 MiB, as the Go SDK). */
  static final int MAX_BODY_BYTES = 1 << 20;

  private static final ScheduledExecutorService WATCHDOG =
      Executors.newSingleThreadScheduledExecutor(
          r -> {
            Thread t = new Thread(r, "superbased-http-deadline");
            t.setDaemon(true);
            return t;
          });

  /**
   * Read {@code in} up to {@link #MAX_BODY_BYTES}, giving up at {@code deadline}
   * (nanoTime): a watchdog closes the stream, which unblocks a stalled read.
   * A body longer than the cap is an error, not a silent truncation.
   */
  static byte[] readBounded(InputStream in, long deadline) throws IOException {
    AtomicBoolean fired = new AtomicBoolean();
    ScheduledFuture<?> guard =
        WATCHDOG.schedule(
            () -> {
              fired.set(true);
              try {
                in.close();
              } catch (IOException | RuntimeException e) {
                // the read below fails
              }
            },
            Math.max(1L, deadline - System.nanoTime()),
            TimeUnit.NANOSECONDS);
    try {
      byte[] raw = in.readNBytes(MAX_BODY_BYTES + 1);
      if (fired.get()) {
        throw new HttpTimeoutException("response body timed out");
      }
      if (raw.length > MAX_BODY_BYTES) {
        throw new IOException("response body larger than " + MAX_BODY_BYTES + " bytes");
      }
      return raw;
    } catch (IOException e) {
      if (fired.get() && !(e instanceof HttpTimeoutException)) {
        throw new HttpTimeoutException("response body timed out");
      }
      throw e;
    } finally {
      guard.cancel(false);
    }
  }
}
