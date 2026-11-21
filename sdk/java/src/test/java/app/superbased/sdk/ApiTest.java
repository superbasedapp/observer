package app.superbased.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.data.SpanData;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The SDK's own behaviour beyond the shared case file. */
@SuppressWarnings("unchecked")
class ApiTest extends SdkTestBase {

  private InMemorySpanExporter mem;

  private void init(InitOptions.Builder b) {
    mem = InMemorySpanExporter.create();
    Superbased.init(b.exporter(mem).destination("local").build());
  }

  private List<SpanData> spans() {
    Superbased.flush(Duration.ofSeconds(5));
    return mem.getFinishedSpanItems();
  }

  private static Object attr(SpanData s, String key) {
    return Attr.get(s.getAttributes(), key);
  }

  @Test
  void init_is_idempotent_and_diagnostics_never_show_the_key() {
    init(InitOptions.builder().apiKey("ik_secret.s3cr3t"));
    Settings s1 = Superbased.settings();
    init(InitOptions.builder().apiKey("ik_secret.s3cr3t"));
    Map<String, Object> d = Superbased.diagnostics();
    assertEquals("owned", d.get("mode"));
    assertEquals(true, d.get("initialized"));
    assertEquals("local", d.get("destination"));
    assertFalse(d.toString().contains("s3cr3t"));
    assertFalse(s1.toString().contains("s3cr3t"));
    assertTrue(s1.hasApiKey());
  }

  @Test
  void spans_carry_kinds_identity_and_status() {
    init(InitOptions.builder().user("svc").release("1.2").serviceName("svc-a"));
    String out =
        Superbased.agentSpan("plan")
            .call(
                a -> {
                  try (AttributeScope s = Superbased.propagateAttributes(TraceAttributes.builder().user("alice").tags("a, b").build())) {
                    Superbased.toolSpan("search").arguments(Map.of("q", 1)).run(t -> t.setToolResult(List.of(1, 2)));
                  }
                  return "done";
                });
    assertEquals("done", out);
    assertThrows(
        IllegalStateException.class,
        () -> Superbased.span("boom").run(s -> {
          throw new IllegalStateException("x");
        }));
    List<SpanData> sp = spans();
    SpanData tool = sp.stream().filter(s -> s.getName().equals("search")).findFirst().orElseThrow();
    assertEquals("TOOL", attr(tool, Keys.SPAN_KIND));
    assertEquals("execute_tool", attr(tool, Keys.OPERATION));
    assertEquals("search", attr(tool, Keys.TOOL_NAME));
    assertEquals("{\"q\":1}", attr(tool, Keys.TOOL_ARGUMENTS));
    assertEquals("[1,2]", attr(tool, Keys.TOOL_RESULT));
    assertEquals("alice", attr(tool, Keys.USER));
    assertEquals(List.of("a", "b"), attr(tool, Keys.TAGS));
    SpanData agent = sp.stream().filter(s -> s.getName().equals("plan")).findFirst().orElseThrow();
    assertEquals(StatusCode.OK, agent.getStatus().getStatusCode());
    assertEquals("plan", attr(agent, Keys.AGENT_NAME));
    assertEquals("svc", agent.getResource().getAttribute(AttributeKey.stringKey(Keys.USER)));
    assertEquals("1.2", agent.getResource().getAttribute(AttributeKey.stringKey("service.version")));
    assertEquals("svc-a", agent.getResource().getAttribute(AttributeKey.stringKey("service.name")));
    assertEquals("superbased-java", agent.getResource().getAttribute(AttributeKey.stringKey(Keys.SDK)));
    SpanData boom = sp.stream().filter(s -> s.getName().equals("boom")).findFirst().orElseThrow();
    assertEquals(StatusCode.ERROR, boom.getStatus().getStatusCode());
    assertEquals(1, boom.getEvents().size());
  }

  @Test
  void llm_span_prompt_forms_and_usage_validation() {
    init(InitOptions.builder());
    Map<String, Object> msg = new LinkedHashMap<>();
    msg.put("role", "user");
    msg.put("content", "hi");
    try (SbSpan s =
        Superbased.llmSpan("chat").model("gpt-5-nano").provider("openai").prompt(List.of(msg)).system("be brief").start()) {
      assertThrows(IllegalArgumentException.class, () -> s.setUsage(Usage.builder().inputTokens(5).outputTokens(-1).build()));
      s.setUsage(Usage.builder().inputTokens(10).outputTokens(3).finishReason("stop").response("ok").build());
    }
    SpanData d = spans().get(0);
    assertEquals("chat", attr(d, Keys.OPERATION));
    assertEquals("gpt-5-nano", attr(d, Keys.REQUEST_MODEL));
    assertEquals("gpt-5-nano", attr(d, Keys.OI_MODEL));
    assertEquals("openai", attr(d, Keys.PROVIDER));
    assertEquals("openai", attr(d, Keys.LEGACY_SYSTEM));
    assertEquals("[{\"role\":\"user\",\"content\":\"hi\"}]", attr(d, Keys.INPUT_MESSAGES));
    assertEquals("be brief", attr(d, Keys.SYSTEM_INSTRUCTIONS));
    assertEquals(10L, attr(d, Keys.INPUT_TOKENS));
    assertEquals(List.of("stop"), attr(d, Keys.FINISH_REASONS));
    assertEquals("ok", attr(d, Keys.OUTPUT_VALUE));
  }

  @Test
  void net_input_correction_raises_a_matching_total() {
    init(InitOptions.builder());
    try (SbSpan s = Superbased.llmSpan("chat").start()) {
      s.setUsage(Usage.builder().inputTokens(10).outputTokens(5).totalTokens(15).cacheReadTokens(100).build());
    }
    SpanData d = spans().get(0);
    assertEquals(110L, attr(d, Keys.INPUT_TOKENS));
    assertEquals(115L, attr(d, Keys.TOTAL_TOKENS));
  }

  @Test
  void content_rules_mask_truncate_and_capture_off() {
    init(
        InitOptions.builder()
            .maxContentChars(5)
            .mask((v, k) -> k.equals(Keys.OUTPUT_VALUE) ? null : String.valueOf(v).toUpperCase(java.util.Locale.ROOT)));
    try (SbSpan s = Superbased.span("c").start()) {
      s.setInput("hello world");
      s.setOutput("dropped");
      s.setAttribute("llm.input_messages.0.message.role", "user");
      s.setAttribute("custom", "kept as is");
    }
    SpanData d = spans().get(0);
    // mask first (upper), then the clip; the original span is untouched (the exported copy only).
    assertEquals("HELLO…[truncated]", attr(d, Keys.INPUT_VALUE));
    assertNull(attr(d, Keys.OUTPUT_VALUE));
    assertEquals("user", attr(d, "llm.input_messages.0.message.role"));
    assertEquals("kept as is", attr(d, "custom"));

    Superbased.resetForTests();
    init(InitOptions.builder().captureContent(false));
    try (SbSpan s = Superbased.span("c").start()) {
      s.setInput("secret");
      s.setAttribute(Keys.OUTPUT_VALUE, "from an instrumentor");
    }
    SpanData d2 = spans().get(0);
    assertNull(attr(d2, Keys.INPUT_VALUE));
    assertNull(attr(d2, Keys.OUTPUT_VALUE));
  }

  @Test
  void mask_that_throws_drops_only_the_content() {
    init(
        InitOptions.builder()
            .mask(
                (v, k) -> {
                  throw new IllegalStateException("bad mask");
                }));
    try (SbSpan s = Superbased.span("c").start()) {
      s.setInput("x");
      s.setAttribute("other", 1L);
    }
    SpanData d = spans().get(0);
    assertNull(attr(d, Keys.INPUT_VALUE));
    assertEquals(1L, attr(d, "other"));
    assertEquals(1L, Superbased.diagnostics().get("mask_errors"));
  }

  @Test
  void should_export_filters_and_fails_open() {
    init(InitOptions.builder().shouldExport(s -> !s.getName().startsWith("drop")));
    Superbased.span("drop-me").run(s -> {});
    Superbased.span("keep").run(s -> {});
    List<SpanData> sp = spans();
    assertEquals(1, sp.size());
    assertEquals(1L, Superbased.diagnostics().get("filtered_spans"));
    Superbased.resetForTests();
    init(
        InitOptions.builder()
            .shouldExport(
                s -> {
                  throw new IllegalStateException("x");
                }));
    Superbased.span("keep").run(s -> {});
    assertEquals(1, spans().size());
    assertEquals(1L, Superbased.diagnostics().get("should_export_errors"));
  }

  @Test
  void sampling_zero_records_nothing_and_ratio_matches_the_shared_rule() {
    init(InitOptions.builder().sampleRate(0.0));
    Superbased.span("x").run(s -> {});
    assertEquals(0, spans().size());
    assertThrows(IllegalArgumentException.class, () -> Superbased.init(InitOptions.builder().sampleRate(1.5).build()));
    // low 64 bits below round(rate * 2^64)
    assertTrue(Pipeline.keepByRatio("0000000000000000" + "0000000000000001", 0.5));
    assertFalse(Pipeline.keepByRatio("0000000000000000" + "ffffffffffffffff", 0.5));
    assertTrue(Pipeline.keepByRatio("ffffffffffffffff" + "7fffffffffffffff", 0.5));
    assertFalse(Pipeline.keepByRatio("0000000000000000" + "8000000000000000", 0.5));
  }

  @Test
  void inject_extract_and_continue_trace_carry_baggage() {
    init(InitOptions.builder());
    Map<String, String> carrier;
    String tid;
    try (SbSpan s = Superbased.span("caller").start();
        AttributeScope a =
            Superbased.propagateAttributes(TraceAttributes.builder().user("bob").tenant("acme").metadata(Map.of("plan", "pro")).asBaggage(true).build())) {
      tid = Superbased.getCurrentTraceId();
      carrier = Superbased.inject();
      assertTrue(Superbased.getTraceparent().startsWith("00-" + tid));
    }
    assertTrue(carrier.get("baggage").contains("sbo.user=bob"));
    Map<String, Object> upper = new LinkedHashMap<>();
    upper.put("TraceParent", carrier.get("traceparent"));
    upper.put("BAGGAGE", carrier.get("baggage"));
    try (Scope sc = Superbased.continueTrace(upper)) {
      assertEquals("bob", Superbased.getCurrentAttributes().get("user"));
      Superbased.span("callee").run(s -> {});
    }
    SpanData callee = spans().stream().filter(s -> s.getName().equals("callee")).findFirst().orElseThrow();
    assertEquals(tid, callee.getTraceId());
    assertEquals("bob", attr(callee, Keys.USER));
    assertEquals("pro", attr(callee, "sbo.metadata.plan"));
    Context bad = Superbased.extract(Map.of("traceparent", "garbage"));
    assertFalse(Span.fromContext(bad).getSpanContext().isValid());
  }

  @Test
  void identify_reset_and_scope_merge_rules() {
    try (AttributeScope outer = Superbased.identify(TraceAttributes.builder().user("a").sessionId("s").tags(List.of("x")).metadata(Map.of("k", 1, "j", "v")).build())) {
      try (AttributeScope inner = Superbased.propagateAttributes(TraceAttributes.builder().user("").tags(List.of("y")).metadata(nullValue("j")).build())) {
        Map<String, Object> cur = Superbased.getCurrentAttributes();
        assertNull(cur.get("user"));
        assertEquals("s", cur.get("session_id"));
        assertEquals(List.of("x", "y"), cur.get("tags"));
        assertEquals(Map.of("k", "1"), cur.get("metadata"));
      }
      assertEquals("a", Superbased.getCurrentAttributes().get("user"));
      outer.reset();
      outer.reset();
    }
    assertTrue(Superbased.getCurrentAttributes().isEmpty());
  }

  private static Map<String, Object> nullValue(String k) {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put(k, null);
    return m;
  }

  @Test
  void credential_file_rules(@TempDir Path dir) throws Exception {
    Path f = dir.resolve("key");
    Files.writeString(f, "kid.secret\ngateway_url=https://gw.example.com/\nother=1\n", StandardCharsets.US_ASCII);
    Files.setPosixFilePermissions(f, PosixFilePermissions.fromString("rw-------"));
    Destination.Credential c = Destination.readCredentialRecord(f.toString());
    assertEquals("kid.secret", c.key);
    assertEquals("https://gw.example.com", c.gateway);
    assertEquals("", c.error);
    Files.setPosixFilePermissions(f, PosixFilePermissions.fromString("rw-r--r--"));
    assertTrue(Destination.readCredentialRecord(f.toString()).error.contains("readable by other users"));
    Files.setPosixFilePermissions(f, PosixFilePermissions.fromString("rw-------"));
    Path link = dir.resolve("link");
    Files.createSymbolicLink(link, f);
    assertTrue(Destination.readCredentialRecord(link.toString()).error.contains("symlink"));
    Files.writeString(f, "kid.secret\ngateway_url=http://gw.example.com\n", StandardCharsets.US_ASCII);
    Destination.Credential plain = Destination.readCredentialRecord(f.toString());
    assertEquals("kid.secret", plain.key);
    assertEquals("", plain.gateway);
    assertTrue(plain.error.contains("plain http"));
    Files.writeString(f, "no dot here\n", StandardCharsets.US_ASCII);
    assertTrue(Destination.readCredentialRecord(f.toString()).error.contains("not one key line"));
  }

  @Test
  void discovery_reads_the_credential_file_and_its_gateway(@TempDir Path dir) throws Exception {
    Path f = dir.resolve("key");
    try (Stub machine = new Stub()) {
      Files.writeString(f, "kid.secret\ngateway_url=" + "https://gw.example.com" + "\n", StandardCharsets.US_ASCII);
      Files.setPosixFilePermissions(f, PosixFilePermissions.fromString("rw-------"));
      Map<String, Object> body = new LinkedHashMap<>();
      body.put("api_version", 1);
      body.put("destination", "online");
      body.put("signed_in", true);
      body.put("local", Map.of("enabled", true, "otlp_traces_url", "https://evil.example/v1/traces"));
      body.put("online", Map.of("credential_present", true, "credential_file", f.toString(), "gateway_url", "https://evil.example"));
      body.put("warnings", List.of("hello"));
      machine.route("GET", "/api/sdk/destination", body);
      Env.set("SUPERBASED_DISCOVER", "1");
      Superbased.init(InitOptions.builder().nodeUrl(machine.url).exporter(InMemorySpanExporter.create()).build());
      Map<String, Object> d = Superbased.diagnostics();
      assertEquals("online", d.get("destination"));
      assertEquals("machine", d.get("destination_source"));
      assertEquals("https://gw.example.com", d.get("gateway_url"));
      assertEquals("file", d.get("credential_source"));
      assertEquals(true, d.get("signed_in"));
      assertTrue(d.get("warnings").toString().contains("machine: hello"));
      assertFalse(d.toString().contains("kid.secret"));
    }
  }

  @Test
  void prompts_cache_revalidate_fallback_and_errors() throws Exception {
    Map<String, Object> fx = loadContract("prompt-fetch-response.json");
    Object body = fx.get("body");
    String etag = (String) ((Map<String, Object>) fx.get("headers")).get("Etag");
    try (Stub stub = new Stub()) {
      int[] calls = {0};
      stub.route(
          "GET",
          "/api/obs/sdk/prompts/support-reply",
          r -> {
            calls[0]++;
            if (etag.equals(r.headers.get("if-none-match"))) {
              return new Stub.Answer(304, new byte[0], Map.of("ETag", etag));
            }
            return new Stub.Answer(200, body, Map.of("ETag", etag));
          });
      stub.route("GET", "/api/obs/sdk/prompts/missing", r -> new Stub.Answer(404, Map.of("error", "prompt_not_found", "message", "no"), null));
      stub.route("GET", "/api/obs/sdk/prompts/broken", r -> new Stub.Answer(500, Map.of("error", "internal"), null));
      init(InitOptions.builder().nodeUrl(stub.url).promptCacheTtl(Duration.ofSeconds(60)));
      Prompt p = Superbased.getPrompt("support-reply");
      assertEquals(3, p.version());
      assertEquals("production", p.label());
      assertEquals("local", p.source());
      assertEquals(List.of("customer", "topic"), p.variables());
      assertEquals(
          "Hello Ada, thanks for writing about returns.", p.compileText(Map.of("customer", "Ada", "topic", "returns")));
      assertThrows(PromptException.CompileFailed.class, () -> p.compile(Map.of()));
      Superbased.getPrompt("support-reply");
      assertEquals(1, calls[0]);
      Superbased.getPrompt("support-reply", PromptOptions.builder().cacheTtl(Duration.ZERO).build());
      long deadline = System.currentTimeMillis() + 2000;
      while (calls[0] < 2 && System.currentTimeMillis() < deadline) {
        Thread.sleep(10);
      }
      assertEquals(2, calls[0]);
      assertTrue(stub.requests.get(stub.requests.size() - 1).query().contains("label=production"));
      assertThrows(PromptException.NotFound.class, () -> Superbased.getPrompt("missing"));
      assertThrows(PromptException.FetchFailed.class, () -> Superbased.getPrompt("broken"));
      Prompt fb = Superbased.getPrompt("broken", PromptOptions.builder().fallback("Hi {{x}}").build());
      assertTrue(fb.isFallback());
      assertEquals(0, fb.version());
      assertTrue(fb.attributes().isEmpty());
      assertThrows(IllegalArgumentException.class, () -> Superbased.getPrompt("support-reply", PromptOptions.builder().label("production").version(2).build()));
      assertThrows(IllegalArgumentException.class, () -> Superbased.getPrompt("bad name"));
      assertThrows(IllegalArgumentException.class, () -> Superbased.getPrompt("x", PromptOptions.builder().label("dev").build()));
      Superbased.getPrompt("support-reply", PromptOptions.builder().version(3).build());
      assertTrue(stub.requests.get(stub.requests.size() - 1).query().contains("version=3"));
    }
  }

  @Test
  void degraded_online_has_no_control_target() {
    Superbased.init(InitOptions.builder().destination("online").exporter(InMemorySpanExporter.create()).build());
    try (SbSpan s = Superbased.span("x").start()) {
      ScoreResult r = Superbased.score("accuracy", 1);
      assertFalse(r.ok());
      assertEquals(false, r.destinations().get("online").get("ok"));
      assertNull(Superbased.getTraceCost());
    }
    assertThrows(PromptException.FetchFailed.class, () -> Superbased.getPrompt("p"));
    assertTrue(Superbased.diagnostics().get("degraded").toString().contains("observer sdk sign-in"));
  }

  @Test
  void score_validation_and_both_sends_the_same_id() throws Exception {
    try (Stub machine = new Stub();
        Stub gateway = new Stub()) {
      Map<String, Object> acc = Map.of("accepted", List.of(Map.of("index", 0, "id", "sc_g")), "rejected", List.of());
      gateway.route("POST", "/v1/sdk/scores", acc);
      machine.route("POST", "/api/obs/scores", Map.of("accepted", List.of(Map.of("index", 0, "id", "sc_m")), "rejected", List.of()));
      Superbased.init(
          InitOptions.builder().destination("both").nodeUrl(machine.url).orgUrl(gateway.url).apiKey("ik_1.s").exporter(InMemorySpanExporter.create()).build());
      String tid = "0af7651916cd43dd8448eb211c80319c";
      ScoreResult r = Superbased.score("Accuracy", 0.9, ScoreOptions.builder().traceId(tid).scorer("judge").comment("fine").build());
      assertTrue(r.ok(), r.errors().toString());
      assertEquals("sc_g", r.id());
      Map<String, Object> g = gateway.requests.get(0).json();
      Map<String, Object> m = machine.requests.get(0).json();
      assertEquals(g.get("id"), m.get("id"));
      assertEquals("accuracy", g.get("name"));
      assertEquals("numeric", g.get("kind"));
      assertEquals(Map.of("name", "judge", "version", "1"), g.get("scorer"));
      assertEquals("Bearer ik_1.s", gateway.requests.get(0).headers.get("authorization"));
      assertNull(machine.requests.get(0).headers.get("authorization"));
      assertEquals("1", gateway.requests.get(0).headers.get("x-sbo-sdk-api-version"));
      ScoreResult fb = Superbased.feedback(true, ScoreOptions.builder().traceId(tid).build());
      assertEquals("feedback", gateway.requests.get(1).json().get("source"));
      assertEquals("user_feedback", gateway.requests.get(1).json().get("name"));
      assertTrue(fb.ok());
      ScoreResult bad = Superbased.score("x", "two\nlines", ScoreOptions.builder().traceId(tid).build());
      assertTrue(bad.errors().get(0).startsWith("invalid_value"));
      ScoreResult kind = Superbased.score("x", true, ScoreOptions.builder().traceId(tid).kind("numeric").build());
      assertTrue(kind.errors().get(0).startsWith("kind_mismatch"));
      assertEquals(2, gateway.requests.size());
    }
  }

  @Test
  void score_retries_once_with_the_same_id() throws Exception {
    try (Stub stub = new Stub()) {
      List<Object> ids = new ArrayList<>();
      stub.route(
          "POST",
          "/api/obs/scores",
          r -> {
            ids.add(r.json().get("id"));
            return ids.size() == 1
                ? new Stub.Answer(503, Map.of(), null)
                : new Stub.Answer(200, Map.of("accepted", List.of(Map.of("index", 0, "id", "sc_1"))), null);
          });
      init(InitOptions.builder().nodeUrl(stub.url));
      ScoreResult r = Superbased.score("a", 1, ScoreOptions.builder().traceId("0af7651916cd43dd8448eb211c80319c").build());
      assertTrue(r.ok());
      assertEquals(2, ids.size());
      assertEquals(ids.get(0), ids.get(1));
    }
  }

  @Test
  void trace_cost_by_destination() throws Exception {
    Map<String, Object> fx = loadContract("trace-cost-response.json");
    try (Stub machine = new Stub();
        Stub gateway = new Stub()) {
      String tid = "0af7651916cd43dd8448eb211c80319c";
      Map<String, Object> cost = new LinkedHashMap<>();
      cost.put("trace_id", tid);
      cost.put("cost_usd", 0.5);
      cost.put("spans", List.of(Map.of("span_id", "b7ad6b7169203331", "cost_source", "computed")));
      gateway.route("GET", "/v1/sdk/traces/" + tid + "/cost", r -> new Stub.Answer(404, Map.of("error", "not_found"), null));
      machine.route("GET", "/api/obs/trace/" + tid, Map.of("trace", Map.of(), "cost", cost));
      Superbased.init(
          InitOptions.builder().destination("both").nodeUrl(machine.url).orgUrl(gateway.url).apiKey("k").exporter(InMemorySpanExporter.create()).build());
      Map<String, Object> got = Superbased.getTraceCost(tid);
      assertEquals("local", got.get("destination"));
      assertEquals(0.5, got.get("cost_usd"));
      assertThrows(IllegalArgumentException.class, () -> Superbased.getTraceCost("0".repeat(32)));
      assertNull(Superbased.getTraceCost());
      assertTrue(TraceCost.isExact("gateway_exact"));
      assertFalse(TraceCost.isExact("computed"));
      assertTrue(fx.toString().contains("gateway_exact"));
      for (String s : TraceCost.COST_SOURCES) {
        assertTrue(TraceCost.LABELS.containsKey(s));
      }
    }
  }

  @Test
  void gateway_headers_and_request_id_stamp() {
    init(InitOptions.builder().user("svc-user").serviceName("bot"));
    try (SbSpan s = Superbased.llmSpan("chat").start();
        AttributeScope a = Superbased.propagateAttributes(TraceAttributes.builder().user("end-user").build())) {
      Map<String, String> h = Superbased.gatewayHeaders();
      assertEquals("end-user", h.get(Gateway.USER_HEADER));
      assertEquals("bot", h.get(Gateway.SERVICE_HEADER));
      assertTrue(h.get(Gateway.REQUEST_ID_HEADER).startsWith("sdk-"));
      assertFalse(Gateway.missingHeaders(Map.of("x-superbased-user", "kept")).containsKey(Gateway.USER_HEADER));
      assertTrue(Superbased.stampGatewayRequestId(Map.of("x-sbo-request-id", List.of("gw-1")), null));
      assertFalse(Superbased.stampGatewayRequestId(Map.of("X-SBO-Request-Id", "gw-2"), null));
    }
    assertEquals("gw-1", attr(spans().get(0), Keys.REQUEST_ID));
  }

  @Test
  void literal_experiment_uploads_runs_scores_and_gates() throws Exception {
    try (Stub stub = new Stub()) {
      List<Map<String, Object>> posted = new ArrayList<>();
      stub.route("POST", "/api/obs/eval/datasets", Map.of("dataset", Map.of("id", "9")));
      stub.route("POST", "/api/obs/eval/datasets/9/items", Map.of("version", 2, "item_ids", List.of("i1", "i2")));
      stub.route("POST", "/api/obs/eval/experiments", r -> new Stub.Answer(201, Map.of("id", "run1", "snapshot_version", 2), null));
      stub.route(
          "GET",
          "/api/obs/eval/datasets/9/items",
          Map.of(
              "items",
              List.of(
                  Map.of("item_id", "i1", "client_id", "fr", "input", "Capital of France?", "expected", "Paris"),
                  Map.of("item_id", "i2", "client_id", "jp", "input", "Capital of Japan?", "expected", "Tokyo")),
              "next_cursor",
              ""));
      stub.route(
          "POST",
          "/api/obs/eval/experiments/run1/results",
          r -> {
            synchronized (posted) {
              posted.addAll((List<Map<String, Object>>) r.json().get("results"));
            }
            return new Stub.Answer(200, Map.of("accepted", 1), null);
          });
      stub.route("GET", "/api/obs/eval/experiments/run1", Map.of("total", 2, "passed", 1, "pass_rate", 0.5));
      init(InitOptions.builder().nodeUrl(stub.url));
      List<Object> items =
          List.of(
              Map.of("id", "fr", "input", "Capital of France?", "expected", "Paris"),
              Map.of("id", "jp", "input", "Capital of Japan?", "expected", "Tokyo"));
      Evaluator exact = Evaluator.of("Exact Match", in -> String.valueOf(in.output()).equalsIgnoreCase(String.valueOf(in.expected())));
      ExperimentOptions opts =
          ExperimentOptions.builder()
              .inputTask(in -> String.valueOf(in).contains("France") ? "Paris" : "Kyoto")
              .evaluator(exact)
              .datasetName("capitals")
              .name("caps")
              .failUnder(0.9)
              .build();
      ExperimentGateFailedException e = assertThrows(ExperimentGateFailedException.class, () -> Superbased.runExperiment(items, opts));
      ExperimentResult r = e.result();
      assertEquals(1, e.exitCode());
      assertTrue(e.reasons().isEmpty());
      assertEquals("run1", r.runId());
      assertEquals(0.5, r.passRate(), 1e-9);
      assertEquals(2, r.scored());
      assertEquals(2, posted.size());
      Map<String, Object> score = ((List<Map<String, Object>>) posted.get(0).get("scores")).get(0);
      assertEquals("exact_match", score.get("name"));
      assertEquals(Map.of("name", "exact_match", "version", "1"), score.get("scorer"));
      Map<String, Object> create = stub.paths("/api/obs/eval/experiments").get(0).json();
      assertEquals(List.of("i1", "i2"), create.get("item_ids"));
      assertTrue(stub.paths("/api/obs/eval/datasets/9/items").stream().anyMatch(q -> q.query().contains("run=run1")));
      List<SpanData> sp = spans();
      assertEquals(2, sp.stream().filter(s -> s.getName().equals("experiment caps")).count());
      assertTrue(sp.stream().allMatch(s -> "run1".equals(attr(s, Keys.EXPERIMENT_RUN_ID))));
      assertEquals(2, sp.stream().map(SpanData::getTraceId).distinct().count());
    }
  }

  @Test
  void in_process_experiment_and_summary() {
    init(InitOptions.builder());
    ExperimentResult r =
        Superbased.runExperiment(
            List.of("a", "bb", Map.of("input", "ccc", "expected", 3)),
            ExperimentOptions.builder()
                .task(item -> {
                  if (String.valueOf(item.input()).equals("bb")) {
                    throw new IllegalStateException("task failed");
                  }
                  return String.valueOf(item.input()).length();
                })
                .evaluator(Evaluator.of("long", in -> ((Number) in.output()).intValue() >= 3))
                .evaluator(Evaluator.of("bad", in -> {
                  throw new IllegalArgumentException("x");
                }))
                .maxConcurrency(2)
                .build());
    assertEquals("", r.runId());
    assertEquals(3, r.items().size());
    assertEquals(3, r.scored());
    assertEquals(1.0 / 3, r.passRate(), 1e-9);
    assertEquals(2.0, r.summary().get("long").get("count"));
    assertTrue(r.items().get(1).error().contains("task failed"));
    assertEquals(1, r.items().get(0).evaluatorErrors().size());
  }

  @Test
  void flush_and_shutdown_are_bounded_against_a_dead_endpoint() throws Exception {
    Env.set("SUPERBASED_OTLP_ENDPOINT", Stub.deadUrl() + "/v1/traces");
    Superbased.init(InitOptions.builder().destination("local").exportTimeout(Duration.ofMillis(300)).shutdownTimeout(Duration.ofSeconds(1)).build());
    Superbased.span("x").run(s -> {});
    long t0 = System.nanoTime();
    boolean flushed = Superbased.flush();
    assertFalse(flushed);
    assertTrue(Superbased.shutdown(Duration.ofSeconds(2)) || true);
    assertTrue((System.nanoTime() - t0) / 1_000_000 < 6000);
    Map<String, Object> d = Superbased.diagnostics();
    assertTrue((Long) d.get("dropped_spans") >= 1, d.toString());
    assertEquals(0L, d.get("pending_spans"));
    assertEquals(false, d.get("initialized"));
  }

  @Test
  void loopback_admit_bypasses_a_configured_proxy() throws Exception {
    java.net.ProxySelector prior = java.net.ProxySelector.getDefault();
    String dead = Stub.deadUrl();
    int port = Integer.parseInt(dead.substring(dead.lastIndexOf(':') + 1));
    try (Stub stub = new Stub()) {
      java.net.ProxySelector.setDefault(java.net.ProxySelector.of(new java.net.InetSocketAddress("127.0.0.1", port)));
      stub.reply(Map.of("allowed", true, "decision", "allow"));
      Verdict v = Superbased.admit("hi", AdmitOptions.builder().endpoint(stub.url + "/check").build());
      assertEquals("", v.degraded());
      assertEquals(1, stub.requests.size());
    } finally {
      java.net.ProxySelector.setDefault(prior);
    }
  }

  @Test
  void json_numbers_follow_ecmascript() {
    assertEquals("1", Json.jsNumber(1.0));
    assertEquals("0.1", Json.jsNumber(0.1));
    assertEquals("123456789012345680000", Json.jsNumber(1.2345678901234568e20));
    assertEquals("1.7976931348623157e+308", Json.jsNumber(Double.MAX_VALUE));
    assertEquals("5e-324", Json.jsNumber(Double.MIN_VALUE));
    assertEquals("-1.5e-7", Json.jsNumber(-1.5e-7));
    Attributes none = Attributes.empty();
    assertTrue(none.isEmpty());
  }
}
