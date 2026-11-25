package app.superbased.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The AI Apps gateway's plan refusal: sdk/contract/plan-refusal-cases.json
 * through {@link PlanRefusalException#parse} (the other SDKs run the same
 * file), and how each call surfaces it: a throwing call throws its own
 * exception with the refusal as its cause, a never-throw call carries it,
 * export keeps it in diagnostics().
 */
@SuppressWarnings("unchecked")
class PlanRefusalTest extends SdkTestBase {

  private static Map<String, Object> allowance(PlanRefusalException.Allowance a) {
    Map<String, Object> m = new LinkedHashMap<>();
    if (a.eventsMonthly() != null) {
      m.put("events_monthly", a.eventsMonthly());
    }
    if (a.gbMonthly() != null) {
      m.put("gb_monthly", a.gbMonthly());
    }
    if (a.requestsMonthly() != null) {
      m.put("requests_monthly", a.requestsMonthly());
    }
    if (a.concurrency() != null) {
      m.put("concurrency", a.concurrency());
    }
    return m;
  }

  private static void check(PlanRefusalException got, Map<String, Object> want, String name) {
    if (want == null) {
      assertNull(got, name);
      return;
    }
    assertNotNull(got, name);
    Class<? extends PlanRefusalException> kind =
        "plan_required".equals(want.get("kind")) ? PlanRefusalException.PlanRequired.class : PlanRefusalException.AllowanceExceeded.class;
    assertTrue(kind.isInstance(got), name);
    assertEquals(want.get("kind"), got.kind(), name);
    assertEquals(want.get("code"), got.code(), name);
    assertEquals(((Long) want.get("status")).intValue(), got.status(), name);
    assertEquals(want.get("upgrade_url"), got.upgradeUrl(), name);
    assertEquals(want.get("capability"), got.capability(), name);
    assertFalse(got.getMessage().isEmpty(), name);
    if (want.containsKey("message")) {
      assertEquals(want.get("message"), got.getMessage(), name);
    }
    if (want.containsKey("plan_name")) {
      assertEquals(want.get("plan_name"), got.plan().name(), name);
      if (want.containsKey("plan_version")) {
        assertEquals(((Long) want.get("plan_version")).intValue(), got.plan().version(), name);
        assertEquals(want.get("plan_label"), got.plan().label(), name);
      }
    } else {
      assertNull(got.plan(), name);
    }
    if (want.containsKey("allowance")) {
      assertEquals(want.get("allowance"), allowance(got.allowance()), name);
    } else {
      assertNull(got.allowance(), name);
    }
    List<String> names = new ArrayList<>();
    for (PlanRefusalException.Plan p : got.plans()) {
      names.add(p.name());
    }
    assertEquals(want.get("plans"), names, name);
    if (want.containsKey("offered_allowance")) {
      assertEquals(want.get("offered_allowance"), allowance(got.plans().get(0).allowance()), name);
    }
    if (want.containsKey("quota")) {
      Map<String, Object> q = (Map<String, Object>) want.get("quota");
      PlanRefusalException.Quota g = got.quota();
      assertEquals(q.get("quota"), g.quota(), name);
      assertEquals(q.get("unit"), g.unit(), name);
      assertEquals(q.get("used"), g.used(), name);
      assertEquals(q.get("limit"), g.limit(), name);
      assertEquals(q.get("resets_at"), g.resetsAt(), name);
    } else {
      assertNull(got.quota(), name);
    }
    if (want.containsKey("retry_after_seconds")) {
      assertEquals(Duration.ofSeconds((Long) want.get("retry_after_seconds")), got.retryAfter(), name);
    } else {
      assertNull(got.retryAfter(), name);
    }
  }

  @Test
  void every_shared_case() throws Exception {
    List<Object> cases = (List<Object>) loadContract("plan-refusal-cases.json").get("cases");
    assertTrue(cases.size() >= 10);
    for (Object o : cases) {
      Map<String, Object> c = (Map<String, Object>) o;
      String name = String.valueOf(c.get("name"));
      int status = ((Long) c.get("status")).intValue();
      Map<String, Object> headers = (Map<String, Object>) c.get("headers");
      Object body = c.get("body");
      Map<String, Object> want = (Map<String, Object>) c.get("want");
      check(PlanRefusalException.parse(status, body, headers), want, name);
      // The same answer as the raw bytes a transport holds.
      String raw = body instanceof String ? (String) body : Json.write(body);
      check(PlanRefusalException.parse(status, raw.getBytes(StandardCharsets.UTF_8), headers), want, name + " (bytes)");
    }
  }

  @Test
  void parse_never_throws() {
    for (Object junk : new Object[] {null, 0, List.of(), "null", new byte[] {(byte) 0xff, (byte) 0xfe}, Map.of("error", 7)}) {
      assertNull(PlanRefusalException.parse(403, junk, null));
      assertNull(PlanRefusalException.parse(429, junk, Map.of("Retry-After", List.of("x"))));
    }
  }

  static final Map<String, Object> PLAN_REQUIRED =
      Map.of(
          "error", "plan_required",
          "message", "AI Apps ingest is not part of this organization's plan (Team).",
          "capability", "org.planea.gateway",
          "plan", Map.of("name", "team", "version", 1, "label", "Team"),
          "upgrade_url", "https://cloud.superbased.app/portal/orgs/org_1");

  static final Map<String, Object> EVENTS_OVER =
      Map.of(
          "error", "planea_events_quota_exceeded",
          "message", "This organization has used this month's AI Apps allowance of its plan (Team).",
          "quota", Map.of("quota", "events_monthly", "unit", "events", "used", 10, "limit", 10, "resets_at", "2026-12-01T00:00:00Z"),
          "capability", "org.planea.gateway",
          "upgrade_url", "https://cloud.superbased.app/portal/orgs/org_1");

  private static void online(Stub gw) {
    Superbased.init(
        InitOptions.builder().destination("online").orgUrl(gw.url).apiKey("ik_1.s").exporter(InMemorySpanExporter.create()).build());
  }

  @Test
  void getPrompt_throws_FetchFailed_with_the_plan_refusal() throws Exception {
    try (Stub gw = new Stub()) {
      gw.reply(PLAN_REQUIRED, 403, null);
      online(gw);
      PromptException.FetchFailed e = assertThrows(PromptException.FetchFailed.class, () -> Superbased.getPrompt("greet"));
      assertInstanceOf(PlanRefusalException.PlanRequired.class, e.planRefusal());
      assertSame(e.planRefusal(), e.getCause());
      assertEquals("https://cloud.superbased.app/portal/orgs/org_1", e.planRefusal().upgradeUrl());
      Map<String, Object> d = (Map<String, Object>) Superbased.diagnostics().get("plan_refusal");
      assertEquals("plan_required", d.get("code"));
      assertTrue((Double) Superbased.diagnostics().get("plan_refusal_at") > 0);
    }
  }

  @Test
  void getDataset_throws_ExperimentException_with_the_plan_refusal() throws Exception {
    try (Stub gw = new Stub()) {
      gw.reply(EVENTS_OVER, 429, Map.of("Retry-After", "120"));
      online(gw);
      ExperimentException e = assertThrows(ExperimentException.class, () -> Superbased.getDataset("golden"));
      PlanRefusalException r = e.planRefusal();
      assertInstanceOf(PlanRefusalException.AllowanceExceeded.class, r);
      assertEquals(Duration.ofSeconds(120), r.retryAfter());
      assertEquals("events_monthly", r.quota().quota());
    }
  }

  @Test
  void score_never_throws_and_carries_the_plan_refusal_without_a_retry() throws Exception {
    try (Stub gw = new Stub()) {
      gw.reply(EVENTS_OVER, 429, Map.of("Retry-After", "120"));
      online(gw);
      ScoreResult r;
      try (SbSpan s = Superbased.span("req").start()) {
        r = Superbased.score("accuracy", 1);
      }
      assertFalse(r.ok());
      assertInstanceOf(PlanRefusalException.AllowanceExceeded.class, r.planRefusal());
      assertEquals(1, gw.paths("/v1/sdk/scores").size());
    }
  }

  @Test
  void admit_never_throws_and_carries_the_plan_refusal() throws Exception {
    try (Stub gw = new Stub()) {
      gw.reply(PLAN_REQUIRED, 403, null);
      Verdict v = Superbased.admit("hi", AdmitOptions.builder().orgUrl(gw.url).apiKey("ik_1.s").build());
      assertTrue(v.allowed());
      assertEquals(Admit.UNAVAILABLE, v.degraded());
      assertEquals(403, v.httpStatus());
      assertInstanceOf(PlanRefusalException.PlanRequired.class, v.planRefusal());
      assertEquals("plan_required", ((Map<String, Object>) v.toMap().get("plan_refusal")).get("code"));
      assertTrue(logs.stream().anyMatch(l -> l.contains("upgrade: https://cloud.superbased.app/portal/orgs/org_1")), String.valueOf(logs));
      gw.reply(Map.of("error", "insufficient_scope", "message", "no"), 403, null);
      assertNull(Superbased.admit("hi", AdmitOptions.builder().orgUrl(gw.url).apiKey("ik_1.s").build()).planRefusal());
    }
  }

  @Test
  void a_refused_export_shows_in_diagnostics_and_is_logged_once() throws Exception {
    try (Stub gw = new Stub()) {
      gw.route("POST", "/v1/traces", r -> new Stub.Answer(403, PLAN_REQUIRED, null));
      assertNull(Superbased.diagnostics().get("plan_refusal"));
      Superbased.init(InitOptions.builder().destination("online").orgUrl(gw.url).apiKey("ik_1.s").build());
      for (int i = 0; i < 2; i++) {
        Superbased.span("refused").run(s -> {});
        assertFalse(Superbased.flush(Duration.ofSeconds(5)));
      }
      Map<String, Object> d = Superbased.diagnostics();
      assertTrue(((Long) d.get("failed_exports")) >= 2, String.valueOf(d));
      Map<String, Object> pr = (Map<String, Object>) d.get("plan_refusal");
      assertNotNull(pr, String.valueOf(d));
      assertEquals("plan_required", pr.get("kind"));
      assertEquals("team", ((Map<String, Object>) pr.get("plan")).get("name"));
      List<String> lines = new ArrayList<>();
      for (String l : new ArrayList<>(logs)) {
        if (l.contains("refused by the organization's plan")) {
          lines.add(l);
        }
      }
      assertEquals(1, lines.size(), String.valueOf(lines));
      assertTrue(lines.get(0).contains("upgrade: https://cloud.superbased.app/portal/orgs/org_1"));
      assertFalse(lines.get(0).contains("\n"));
    }
  }

  @Test
  void an_exporter_failure_that_is_no_plan_refusal_is_ignored() {
    assertFalse(Export.noteExportRefusal(null));
    assertFalse(Export.noteExportRefusal(new RuntimeException("connection refused")));
    assertNull(Superbased.diagnostics().get("plan_refusal"));
  }

  @Test
  void the_warning_is_written_at_most_once_a_minute() {
    PlanRefusalException e = PlanRefusalException.parse(403, PLAN_REQUIRED, null);
    assertTrue(PlanRefusalException.note(e, "trace export"));
    assertFalse(PlanRefusalException.note(e, "trace export"));
    assertFalse(PlanRefusalException.note(e, "")); // a control call keeps it, never logs here
  }
}
