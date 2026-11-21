package app.superbased.sdk;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.function.Function;

/**
 * A tiny HTTP server whose answers are scripted per test (the Python suite's
 * conftest Stub): {@link #reply} sets the default answer; {@link #route}
 * answers one method and path (query ignored) with a fixed reply or a
 * function of the request. Every request is recorded.
 */
final class Stub implements AutoCloseable {
  /** One recorded request. */
  static final class Req {
    final String method;
    final String path; // with the query
    final Map<String, String> headers; // lower-cased names
    final Object body; // parsed JSON, or null
    final byte[] raw;

    Req(String method, String path, Map<String, String> headers, Object body, byte[] raw) {
      this.method = method;
      this.path = path;
      this.headers = headers;
      this.body = body;
      this.raw = raw;
    }

    String bare() {
      int q = path.indexOf('?');
      return q < 0 ? path : path.substring(0, q);
    }

    String query() {
      int q = path.indexOf('?');
      return q < 0 ? "" : path.substring(q + 1);
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> json() {
      return (Map<String, Object>) body;
    }
  }

  /** An answer: status, body (bytes or a JSON value), headers. */
  static final class Answer {
    final int status;
    final Object body;
    final Map<String, String> headers;

    Answer(int status, Object body, Map<String, String> headers) {
      this.status = status;
      this.body = body;
      this.headers = headers == null ? Map.of() : headers;
    }
  }

  final List<Req> requests = Collections.synchronizedList(new ArrayList<>());
  private final Map<String, Function<Req, Answer>> routes = new ConcurrentHashMap<>();
  private volatile Answer dflt = new Answer(200, Map.of(), Map.of());
  volatile long delayMs;
  private final HttpServer server;
  final String url;

  Stub() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/", this::handle);
    server.setExecutor(Executors.newCachedThreadPool(r -> {
      Thread t = new Thread(r, "stub");
      t.setDaemon(true);
      return t;
    }));
    server.start();
    url = "http://127.0.0.1:" + server.getAddress().getPort();
  }

  void reply(Object body, int status, Map<String, String> headers) {
    dflt = new Answer(status, body, headers);
  }

  void reply(Object body) {
    reply(body, 200, null);
  }

  void route(String method, String path, Function<Req, Answer> fn) {
    routes.put(method + " " + path, fn);
  }

  void route(String method, String path, Object body) {
    Answer a = new Answer(200, body, null);
    routes.put(method + " " + path, r -> a);
  }

  List<Req> paths(String path) {
    List<Req> out = new ArrayList<>();
    synchronized (requests) {
      for (Req r : requests) {
        if (r.bare().equals(path)) {
          out.add(r);
        }
      }
    }
    return out;
  }

  private void handle(HttpExchange ex) throws IOException {
    byte[] raw = ex.getRequestBody().readAllBytes();
    Object body = null;
    if (raw.length > 0) {
      try {
        body = Json.parse(new String(raw, StandardCharsets.UTF_8));
      } catch (IllegalArgumentException e) {
        body = null;
      }
    }
    Map<String, String> headers = new LinkedHashMap<>();
    for (Map.Entry<String, List<String>> e : ex.getRequestHeaders().entrySet()) {
      headers.put(e.getKey().toLowerCase(java.util.Locale.ROOT), e.getValue().isEmpty() ? "" : e.getValue().get(0));
    }
    Req req = new Req(ex.getRequestMethod(), ex.getRequestURI().toString(), headers, body, raw);
    requests.add(req);
    Function<Req, Answer> fn = routes.get(req.method + " " + req.bare());
    Answer a = fn != null ? fn.apply(req) : dflt;
    if (delayMs > 0) {
      try {
        Thread.sleep(delayMs);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
    byte[] out = a.body instanceof byte[] ? (byte[]) a.body : Json.write(a.body).getBytes(StandardCharsets.UTF_8);
    for (Map.Entry<String, String> h : a.headers.entrySet()) {
      ex.getResponseHeaders().add(h.getKey(), h.getValue());
    }
    if (a.status == 304 || a.status == 204) {
      ex.sendResponseHeaders(a.status, -1);
    } else {
      ex.sendResponseHeaders(a.status, out.length == 0 ? -1 : out.length);
      if (out.length > 0) {
        try (OutputStream os = ex.getResponseBody()) {
          os.write(out);
        }
      }
    }
    ex.close();
  }

  @Override
  public void close() {
    server.stop(0);
  }

  /** A loopback URL nothing listens on. */
  static String deadUrl() throws IOException {
    int port;
    try (ServerSocket s = new ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))) {
      port = s.getLocalPort();
    }
    return "http://127.0.0.1:" + port;
  }
}
