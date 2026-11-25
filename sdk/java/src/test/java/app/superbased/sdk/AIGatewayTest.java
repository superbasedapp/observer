package app.superbased.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.TraceFlags;
import io.opentelemetry.api.trace.TraceState;
import io.opentelemetry.context.Scope;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * The AI gateway helpers (hosted AI gateway arc, lane L8):
 * sdk/contract/ai-gateway-cases.json through the pure resolver and
 * GatewayRefusalException.parse (Python, TypeScript and Go run the same
 * file), and the endpoint's headers and key against a stub gateway.
 */
@SuppressWarnings("unchecked")
class AIGatewayTest extends SdkTestBase {

  private static String s(Object v) {
    return v == null ? null : (String) v;
  }

  @Test
  void base_url_contract_cases() throws Exception {
    List<Object> cases = (List<Object>) loadContract("ai-gateway-cases.json").get("base_url");
    assertTrue(cases.size() >= 20);
    for (Object o : cases) {
      Map<String, Object> c = (Map<String, Object>) o;
      String name = (String) c.get("name");
      AtomicInteger asked = new AtomicInteger();
      Gateway.Resolution r =
          Gateway.resolve(
              s(c.get("provider")),
              s(c.get("upstream")),
              s(c.get("url")),
              s(c.get("env")),
              s(c.get("destination")),
              s(c.get("org_url")),
              () -> {
                asked.incrementAndGet();
                return c.get("local");
              });
      Map<String, Object> want = (Map<String, Object>) c.get("want");
      if (want.containsKey("problem")) {
        assertNull(r.endpoint, name);
        assertEquals(want.get("problem"), r.problem, name);
        assertFalse(r.message.isEmpty(), name);
        continue;
      }
      assertNotNull(r.endpoint, name + ": " + r.message);
      assertEquals(want.get("url"), r.endpoint.baseUrl(), name);
      assertEquals(want.get("source"), r.endpoint.source(), name);
      assertEquals(want.getOrDefault("upstream_header", ""), r.endpoint.upstreamHeader(), name);
      if ("online".equals(c.get("destination"))) {
        assertEquals(0, asked.get(), name + ": asked the machine under online");
      }
    }
  }

  private static void assertNum(Object want, Double got, String name) {
    if (want == null) {
      assertNull(got, name);
      return;
    }
    assertNotNull(got, name);
    assertEquals(((Number) want).doubleValue(), got, 1e-12, name);
  }

  private static void check(GatewayRefusalException got, Map<String, Object> want, String name) {
    if (want == null) {
      assertNull(got, name);
      return;
    }
    assertNotNull(got, name);
    assertEquals(want.get("kind"), got.kind(), name);
    assertEquals(want.get("code"), got.code(), name);
    assertEquals(((Number) want.get("status")).intValue(), got.status(), name);
    assertFalse(got.getMessage().isEmpty(), name);
    if (want.containsKey("message")) {
      assertEquals(want.get("message"), got.getMessage(), name);
    }
    assertEquals(want.getOrDefault("request_id", ""), got.requestId(), name);
    if (want.containsKey("retry_after_seconds")) {
      assertEquals(Duration.ofSeconds(((Number) want.get("retry_after_seconds")).longValue()), got.retryAfter(), name);
    } else {
      assertNull(got.retryAfter(), name);
    }
    if (want.containsKey("budget")) {
      Map<String, Object> b = (Map<String, Object>) want.get("budget");
      GatewayRefusalException.Budget g = got.budget();
      assertNotNull(g, name);
      assertEquals(b.get("level"), g.level(), name);
      assertEquals(b.get("scope_id"), g.scopeId(), name);
      assertEquals(b.get("unit"), g.unit(), name);
      assertNum(b.get("remaining"), g.remaining(), name);
      assertNum(b.get("cap"), g.cap(), name);
      assertEquals(b.get("estimated"), g.estimated(), name);
    } else {
      assertNull(got.budget(), name);
    }
    if (want.containsKey("plan_refusal")) {
      Map<String, Object> p = (Map<String, Object>) want.get("plan_refusal");
      PlanRefusalException g = got.planRefusal();
      assertNotNull(g, name);
      assertEquals(p.get("kind"), g.kind(), name);
      assertEquals(p.get("code"), g.code(), name);
      assertEquals(p.get("upgrade_url"), g.upgradeUrl(), name);
      assertEquals(p.get("capability"), g.capability(), name);
      assertSame(g, got.getCause(), name);
    } else {
      assertNull(got.planRefusal(), name);
    }
  }

  @Test
  void api_key_contract_cases() throws Exception {
    // The shared key rule (hosted AI gateway review L7): a provider's own key
    // never reaches a remote gateway.
    List<Object> cases = (List<Object>) loadContract("ai-gateway-cases.json").get("api_key");
    assertTrue(cases.size() >= 10);
    for (Object o : cases) {
      Map<String, Object> c = (Map<String, Object>) o;
      String name = (String) c.get("name");
      if (c.get("gateway_key") == null) {
        Env.set(Gateway.KEY_ENV, null);
      } else {
        Env.set(Gateway.KEY_ENV, (String) c.get("gateway_key"));
      }
      GatewayEndpoint ep = new GatewayEndpoint(s(c.get("base_url")), s(c.get("source")), "", "");
      Map<String, Object> want = (Map<String, Object>) c.get("want");
      if (want.containsKey("problem")) {
        Gateway.NotConfiguredException e = assertThrows(Gateway.NotConfiguredException.class, ep::apiKey, name);
        assertEquals(want.get("problem"), e.problem(), name);
        continue;
      }
      assertEquals(want.get("key"), ep.apiKey(), name);
    }
  }

  @Test
  void refusal_contract_cases() throws Exception {
    List<Object> cases = (List<Object>) loadContract("ai-gateway-cases.json").get("refusal");
    assertTrue(cases.size() >= 15);
    for (Object o : cases) {
      Map<String, Object> c = (Map<String, Object>) o;
      String name = (String) c.get("name");
      int status = ((Number) c.get("status")).intValue();
      Map<String, Object> headers = (Map<String, Object>) c.get("headers");
      Map<String, Object> want = (Map<String, Object>) c.get("want");
      Object body = c.get("body");
      check(GatewayRefusalException.parse(status, body, headers), want, name);
      String text = body instanceof String ? (String) body : Json.write(body);
      check(GatewayRefusalException.parse(status, text, headers), want, name + " (text)");
      check(GatewayRefusalException.parse(status, text.getBytes(StandardCharsets.UTF_8), headers), want, name + " (bytes)");
    }
  }

  @Test
  void parse_never_throws() {
    for (Object junk : new Object[] {null, 0, "null", "[]", new byte[] {(byte) 0xff, (byte) 0xfe}, Map.of("reason", 7)}) {
      assertNull(GatewayRefusalException.parse(402, junk, null));
    }
  }

  @Test
  void online_resolves_the_organizations_address() {
    Env.set("SUPERBASED_DESTINATION", "online");
    Env.set("SUPERBASED_ORG_URL", "https://acme.superbased.app");
    Env.set("SUPERBASED_API_KEY", "ik_1.secret");
    assertEquals("https://acme.superbased.app/ai/openai/v1", Gateway.baseUrl(Gateway.PROVIDER_OPENAI));
    GatewayEndpoint ep = Gateway.endpoint(Gateway.PROVIDER_ANTHROPIC, "claude");
    assertEquals("https://acme.superbased.app/ai/claude", ep.baseUrl());
    assertEquals(Gateway.SOURCE_ORG, ep.source());
    assertEquals("https://acme.superbased.app/ai/claude/v1/messages", ep.url("/v1/messages"));
    Env.set(Gateway.URL_ENV, "https://ai.example.com");
    ep = Gateway.endpoint(Gateway.PROVIDER_OPENAI, "openai-eu");
    assertEquals("https://ai.example.com/v1", ep.baseUrl());
    assertEquals("openai-eu", ep.upstreamHeader());
    assertEquals("https://arg.example.com/v1", Gateway.endpoint(Gateway.PROVIDER_OPENAI, null, "https://arg.example.com").baseUrl());
    Gateway.NotConfiguredException e = assertThrows(Gateway.NotConfiguredException.class, () -> Gateway.baseUrl("cohere"));
    assertEquals(Gateway.PROBLEM_UNKNOWN_PROVIDER, e.problem());
  }

  @Test
  void the_machine_lane_from_discovery() {
    Env.set("SUPERBASED_DESTINATION", "local");
    Env.set("SUPERBASED_DISCOVER", "1");
    AtomicInteger asked = new AtomicInteger();
    Destination.Discoverer orig = Destination.discoverer;
    Destination.discoverer =
        nodeUrl -> {
          asked.incrementAndGet();
          Map<String, Object> lane = new LinkedHashMap<>();
          lane.put("id", "openai");
          lane.put("base_url", "http://127.0.0.1:8820/up/openai");
          List<Object> lanes = new ArrayList<>();
          lanes.add(lane);
          Map<String, Object> body = new LinkedHashMap<>();
          body.put("api_version", 1L);
          body.put("local", Map.of("app_lanes", lanes));
          return new Destination.Discovered(body, "");
        };
    try {
      assertEquals("http://127.0.0.1:8820/up/openai/v1", Gateway.baseUrl(Gateway.PROVIDER_OPENAI));
      Gateway.NotConfiguredException e = assertThrows(Gateway.NotConfiguredException.class, () -> Gateway.baseUrl(Gateway.PROVIDER_ANTHROPIC));
      assertEquals(Gateway.PROBLEM_NOT_CONFIGURED, e.problem());
      assertTrue(e.getMessage().contains("observer apps lane add"));
      GatewayEndpoint ep = Gateway.endpoint(Gateway.PROVIDER_OPENAI, null);
      Env.set(Gateway.KEY_ENV, "sbo-vk-not-for-the-lane");
      assertNull(ep.apiKey(), "the machine lane keeps the provider's own key");
      assertEquals(1, asked.get(), "discovery is asked once per process");
      Env.set("SUPERBASED_DISCOVER", "0");
      Superbased.resetForTests();
      assertThrows(Gateway.NotConfiguredException.class, () -> Gateway.baseUrl(Gateway.PROVIDER_OPENAI));
      assertEquals(1, asked.get(), "discovery off still asked the machine");
    } finally {
      Destination.discoverer = orig;
    }
  }

  @Test
  void a_remote_gateway_without_a_gateway_key_never_gets_one() {
    GatewayEndpoint ep = Gateway.endpoint(Gateway.PROVIDER_OPENAI, null, "https://ai.example.com");
    Gateway.NotConfiguredException e = assertThrows(Gateway.NotConfiguredException.class, ep::apiKey);
    assertEquals(Gateway.PROBLEM_NO_KEY, e.problem());
    Env.set(Gateway.KEY_ENV, "sbo-vk-test");
    assertEquals("sbo-vk-test", ep.apiKey());
    GatewayEndpoint loop = Gateway.endpoint(Gateway.PROVIDER_OPENAI, null, "http://127.0.0.1:8840");
    assertEquals("sbo-vk-test", loop.apiKey(), "a loopback address with a key set uses it");
    Env.set(Gateway.KEY_ENV, null);
    assertNull(loop.apiKey(), "a loopback address without a key leaves the provider's own");
  }

  @Test
  void headers_carry_the_upstream_and_the_current_traceparent() throws Exception {
    try (Stub stub = new Stub()) {
      Map<String, String> answerHeaders = new LinkedHashMap<>();
      answerHeaders.put("Content-Type", "application/json");
      answerHeaders.put("X-SBO-Request-Id", "gw-1");
      stub.reply(Map.of("error", "denied", "reason", "budget_exceeded", "unit", "usd", "cap_usd", 1, "remaining_usd", -0.5, "estimated", true), 402, answerHeaders);
      Env.set(Gateway.KEY_ENV, "sbo-vk-test");
      GatewayEndpoint ep = Gateway.endpoint(Gateway.PROVIDER_OPENAI, "openai-eu", stub.url);
      SpanContext sc = SpanContext.create("0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331", TraceFlags.getSampled(), TraceState.getDefault());
      HttpResponse<byte[]> resp;
      try (Scope ignored = Span.wrap(sc).makeCurrent()) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(ep.url("chat/completions"))).POST(HttpRequest.BodyPublishers.ofString("{}"));
        ep.headers().forEach(b::header);
        b.header("Authorization", "Bearer " + ep.apiKey());
        resp = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build().send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
      }
      Stub.Req req = stub.requests.get(stub.requests.size() - 1);
      assertEquals("/v1/chat/completions", req.bare());
      assertEquals("openai-eu", req.headers.get("x-sbo-upstream"));
      assertEquals("Bearer sbo-vk-test", req.headers.get("authorization"));
      assertEquals("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", req.headers.get("traceparent"));
      assertTrue(req.headers.get("x-sbo-request-id").startsWith("sdk-"));
      GatewayRefusalException r = GatewayRefusalException.parse(resp.statusCode(), resp.body(), resp.headers().map());
      assertNotNull(r);
      assertEquals(GatewayRefusalException.BUDGET_EXCEEDED, r.kind());
      assertEquals("gw-1", r.requestId());
      assertEquals(-0.5, r.budget().remaining(), 1e-12);
    }
  }
}
