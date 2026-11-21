package app.superbased.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The Java fixes of the final pre-release review (FR-S02..S14, 2026-11-21). */
@SuppressWarnings("unchecked")
class FinalReviewFixesTest extends SdkTestBase {

  // --- FR-S02 -----------------------------------------------------------------------------

  @Test
  void s02_fail_closed_env_is_honoured_by_the_last_resort_handler() {
    Env.set("SUPERBASED_ADMISSION_FAIL_CLOSED", "1");
    // A transport that throws a RuntimeException is not one of the failures
    // post() maps; it reaches admit()'s last-resort catch.
    Http.transport =
        call -> {
          throw new IllegalStateException("boom");
        };
    Verdict v = Superbased.admit("hi", AdmitOptions.builder().endpoint("http://127.0.0.1:9/check").build());
    assertFalse(v.allowed());
    assertEquals("deny", v.decision());
    assertFalse(v.degraded().isEmpty());

    Env.set("SUPERBASED_ADMISSION_FAIL_CLOSED", null);
    Verdict open = Superbased.admit("hi", AdmitOptions.builder().endpoint("http://127.0.0.1:9/check").build());
    assertTrue(open.allowed());
    // The per-call option beats the env.
    Env.set("SUPERBASED_ADMISSION_FAIL_CLOSED", "1");
    Verdict forced = Superbased.admit("hi", AdmitOptions.builder().endpoint("http://127.0.0.1:9/check").failClosed(false).build());
    assertTrue(forced.allowed());
  }

  // --- FR-S03 -----------------------------------------------------------------------------

  @Test
  void s03_attached_mode_sends_the_providers_service_name() throws Exception {
    InMemorySpanExporter mem = InMemorySpanExporter.create();
    SdkTracerProvider app =
        SdkTracerProvider.builder()
            .setResource(Resource.getDefault().toBuilder().put("service.name", "checkout").build())
            .addSpanProcessor(Superbased.spanProcessor())
            .build();
    try (Stub stub = new Stub()) {
      stub.reply(Map.of("allowed", true, "decision", "allow"));
      Superbased.init(InitOptions.builder().tracerProvider(app).serviceName("init-name").exporter(mem).destination("local").build());
      AdmitOptions ao = AdmitOptions.builder().endpoint(stub.url + "/check").build();
      // Before any span, init()'s serviceName stands (not the default).
      Superbased.admit("hi", ao);
      assertEquals("init-name", stub.requests.get(0).json().get("service"));
      // Once the provider's own resource is seen, it wins.
      Superbased.span("work").run(s -> {});
      Superbased.admit("hi", ao);
      assertEquals("checkout", stub.requests.get(1).json().get("service"));
      assertEquals("checkout", Superbased.gatewayHeaders().get(Gateway.SERVICE_HEADER));
    } finally {
      app.shutdown();
    }
  }

  // --- FR-S04 -----------------------------------------------------------------------------

  @Test
  void s04_the_sdk_credential_replaces_any_authorization_on_the_online_exporter() throws Exception {
    for (String name : List.of("authorization", "Authorization", "AUTHORIZATION")) {
      Superbased.resetForTests();
      Env.set("SUPERBASED_DISCOVER", "0");
      try (Stub stub = new Stub()) {
        Superbased.init(
            InitOptions.builder()
                .exporter(InMemorySpanExporter.create())
                .destination("online")
                .orgUrl(stub.url)
                .apiKey("ik_1.sdkkey")
                .headers(Map.of(name, "Bearer collector-token", "x-keep", "1"))
                .discover(false)
                .build());
        Destination.Target t = Superbased.plan().exporters.get(0);
        int auth = 0;
        for (Map.Entry<String, String> e : t.headers.entrySet()) {
          if (e.getKey().equalsIgnoreCase("authorization")) {
            auth++;
            assertEquals("Bearer ik_1.sdkkey", e.getValue());
          }
        }
        assertEquals(1, auth, "one Authorization header for " + name);
        assertEquals("1", t.headers.get("x-keep"));
      }
    }
  }

  // --- FR-S05 -----------------------------------------------------------------------------

  @Test
  void s05_console_output_follows_capture_content() {
    PrintStream prior = System.err;
    for (boolean capture : new boolean[] {false, true}) {
      Superbased.resetForTests();
      Env.set("SUPERBASED_DISCOVER", "0");
      ByteArrayOutputStream buf = new ByteArrayOutputStream();
      System.setErr(new PrintStream(buf, true, StandardCharsets.UTF_8));
      try {
        Superbased.init(InitOptions.builder().console(true).captureContent(capture).exporter(InMemorySpanExporter.create()).destination("local").build());
        try (SbSpan s = Superbased.llmSpan("chat").prompt("TOPSECRET-PROMPT").start()) {
          // ends on close
        }
        Superbased.flush(Duration.ofSeconds(5));
      } finally {
        System.setErr(prior);
      }
      String out = buf.toString(StandardCharsets.UTF_8);
      assertTrue(out.contains("superbased span chat"), out);
      assertEquals(capture, out.contains("TOPSECRET-PROMPT"), "captureContent=" + capture + ": " + out);
    }
  }

  // --- FR-S06 -----------------------------------------------------------------------------

  private static final class Collect extends Handler {
    final List<LogRecord> records = Collections.synchronizedList(new ArrayList<>());

    @Override
    public void publish(LogRecord r) {
      if (r.getLevel().intValue() >= Level.WARNING.intValue()) {
        records.add(r);
      }
    }

    @Override
    public void flush() {}

    @Override
    public void close() {}
  }

  private static void waitFor(java.util.function.BooleanSupplier c) throws InterruptedException {
    long end = System.nanoTime() + Duration.ofSeconds(15).toNanos();
    while (!c.getAsBoolean() && System.nanoTime() < end) {
      Thread.sleep(25);
    }
  }

  private static SpanData oneSpan() {
    InMemorySpanExporter m = InMemorySpanExporter.create();
    SdkTracerProvider p = SdkTracerProvider.builder().addSpanProcessor(SimpleSpanProcessor.create(m)).build();
    p.get("t").spanBuilder("host-span").startSpan().end();
    return m.getFinishedSpanItems().get(0);
  }

  @Test
  void s06_quiet_silences_the_sdks_own_exporter_only_and_shutdown_undoes_it() throws Exception {
    Logger parent = Logger.getLogger("io.opentelemetry.exporter"); // held: JUL keeps loggers weakly
    Collect seen = new Collect();
    parent.addHandler(seen);
    List<Logger> leaf = new ArrayList<>();
    for (String n : Export.EXPORTER_LOGGERS) {
      leaf.add(Logger.getLogger(n));
    }
    try {
      String dead = Stub.deadUrl() + "/v1/traces";
      Superbased.init(InitOptions.builder().endpoint(dead).destination("local").exportTimeout(Duration.ofSeconds(2)).quiet(true).build());
      for (Logger l : leaf) {
        assertNotEquals(null, l.getFilter(), "the leaf logger carries the SDK's filter");
      }
      Superbased.span("lost").run(s -> {});
      Superbased.flush(Duration.ofSeconds(10));
      waitFor(() -> ((Number) Superbased.diagnostics().get("failed_exports")).longValue() >= 1);
      assertTrue(((Number) Superbased.diagnostics().get("failed_exports")).longValue() >= 1);
      Thread.sleep(200);
      assertEquals(0, seen.records.size(), "the SDK exporter's warnings stay out of the host's logs");
      String cause = (String) Superbased.diagnostics().get("last_error");
      assertNotEquals("export failed", cause, "last_error carries the real cause");
      assertTrue(cause.contains("Failed to export"), cause);

      // A host exporter elsewhere in the JVM still logs as before.
      OtlpHttpSpanExporter host = OtlpHttpSpanExporter.builder().setEndpoint(dead).setTimeout(Duration.ofSeconds(2)).build();
      host.export(List.of(oneSpan())).join(10, java.util.concurrent.TimeUnit.SECONDS);
      host.shutdown();
      waitFor(() -> !seen.records.isEmpty());
      assertFalse(seen.records.isEmpty(), "other OTLP exporters are not silenced");

      Superbased.shutdown();
      for (Logger l : leaf) {
        assertNull(l.getFilter(), "shutdown() removes the SDK's filter");
      }
    } finally {
      parent.removeHandler(seen);
    }
  }

  @Test
  void s06_quiet_off_leaves_the_warnings_visible_but_still_records_the_cause() throws Exception {
    Logger parent = Logger.getLogger("io.opentelemetry.exporter");
    Collect seen = new Collect();
    parent.addHandler(seen);
    try {
      Superbased.init(
          InitOptions.builder().endpoint(Stub.deadUrl() + "/v1/traces").destination("local").exportTimeout(Duration.ofSeconds(2)).quiet(false).build());
      Superbased.span("lost").run(s -> {});
      Superbased.flush(Duration.ofSeconds(10));
      waitFor(() -> !seen.records.isEmpty());
      assertFalse(seen.records.isEmpty());
      assertTrue(((String) Superbased.diagnostics().get("last_error")).contains("Failed to export"));
    } finally {
      parent.removeHandler(seen);
    }
  }

  // --- FR-S09 -----------------------------------------------------------------------------

  /** A server that sends headers, then drips (or floods) the body. */
  private static final class Drip implements AutoCloseable {
    final ServerSocket server;
    final String url;
    volatile boolean stop;

    Drip(boolean flood) throws IOException {
      server = new ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"));
      url = "http://127.0.0.1:" + server.getLocalPort() + "/x";
      Thread t =
          new Thread(
              () -> {
                try (Socket s = server.accept()) {
                  InputStream in = s.getInputStream();
                  byte[] b = new byte[8192];
                  in.read(b);
                  OutputStream out = s.getOutputStream();
                  if (flood) {
                    out.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                    byte[] chunk = new byte[65536];
                    java.util.Arrays.fill(chunk, (byte) ' ');
                    for (int i = 0; i < 64 && !stop; i++) {
                      out.write(chunk);
                    }
                    return;
                  }
                  out.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{".getBytes(StandardCharsets.US_ASCII));
                  out.flush();
                  while (!stop) {
                    Thread.sleep(50);
                    out.write(' ');
                    out.flush();
                  }
                } catch (IOException | InterruptedException e) {
                  // the client gave up
                }
              },
              "drip");
      t.setDaemon(true);
      t.start();
    }

    @Override
    public void close() throws IOException {
      stop = true;
      server.close();
    }
  }

  @Test
  void s09_a_dripping_body_is_cut_off_at_the_call_deadline() throws Exception {
    try (Drip d = new Drip(false)) {
      long t0 = System.nanoTime();
      Http.Response r = Http.request("GET", d.url, null, null, Duration.ofMillis(700));
      long ms = (System.nanoTime() - t0) / 1_000_000;
      assertTrue(ms < 3000, "returned in " + ms + " ms");
      assertEquals(0, r.status);
      assertTrue(r.timedOut);
    }
  }

  @Test
  void s09_an_oversized_body_is_refused_and_admit_stays_within_its_budget() throws Exception {
    try (Drip d = new Drip(true)) {
      Http.Response r = Http.request("GET", d.url, null, null, Duration.ofSeconds(5));
      assertEquals(0, r.status);
      assertTrue(r.error.contains("larger than"), r.error);
    }
    try (Drip d = new Drip(false)) {
      long t0 = System.nanoTime();
      Verdict v = Superbased.admit("hi", AdmitOptions.builder().endpoint(d.url).timeout(Duration.ofMillis(700)).build());
      long ms = (System.nanoTime() - t0) / 1_000_000;
      assertTrue(ms < 3000, "admit returned in " + ms + " ms");
      assertEquals(Admit.TIMEOUT, v.degraded());
    }
  }

  // --- FR-S13 -----------------------------------------------------------------------------

  @Test
  void s13_the_credential_owner_is_compared_by_uid_not_name(@TempDir Path dir) throws Exception {
    Path f = dir.resolve("key");
    Files.writeString(f, "kid.secret\n", StandardCharsets.US_ASCII);
    Files.setPosixFilePermissions(f, PosixFilePermissions.fromString("rw-------"));
    long uid = ((Number) Files.getAttribute(f, "unix:uid")).longValue();
    String prior = System.getProperty("user.name");
    java.util.function.LongSupplier priorUid = Destination.processUid;
    try {
      // A container uid with no passwd entry: the name never matches the file's owner.
      System.setProperty("user.name", "no-such-user");
      Destination.processUid = () -> uid;
      Destination.Credential ok = Destination.readCredentialRecord(f.toString());
      assertEquals("", ok.error);
      assertEquals("kid.secret", ok.key);
      // Another uid is refused whatever the name says.
      System.setProperty("user.name", prior);
      Destination.processUid = () -> uid + 1;
      assertTrue(Destination.readCredentialRecord(f.toString()).error.contains("owned by another user"));
    } finally {
      System.setProperty("user.name", prior);
      Destination.processUid = priorUid;
    }
  }

  // --- FR-S14 -----------------------------------------------------------------------------

  @Test
  void s14_a_global_opentelemetry_already_set_reports_standalone() {
    GlobalOpenTelemetry.set(OpenTelemetry.noop());
    InMemorySpanExporter mem = InMemorySpanExporter.create();
    Superbased.init(InitOptions.builder().exporter(mem).destination("local").build());
    Map<String, Object> d = Superbased.diagnostics();
    assertEquals("standalone", d.get("mode"));
    assertTrue(d.get("warnings").toString().contains("already registered"), d.toString());
    // The SDK's spans still export.
    Superbased.span("x").run(s -> {});
    Superbased.flush(Duration.ofSeconds(5));
    assertEquals(1, mem.getFinishedSpanItems().size());
  }

  @Test
  void s14_without_a_prior_global_the_mode_stays_owned() {
    Superbased.init(InitOptions.builder().exporter(InMemorySpanExporter.create()).destination("local").build());
    assertEquals("owned", Superbased.diagnostics().get("mode"));
    assertFalse(Superbased.diagnostics().toString().contains("already registered"));
  }
}
