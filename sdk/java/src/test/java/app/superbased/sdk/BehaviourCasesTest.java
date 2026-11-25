package app.superbased.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.data.SpanData;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

/**
 * sdk/contract/sdk-behaviour-cases.json: the behaviours every superbased SDK
 * shares (review R-B19). Each section is one parameterized test NAMED AFTER
 * the section; {@link #every_section_has_a_runner} fails when a section has
 * no test here (the Python and TypeScript suites have the same guard).
 */
@SuppressWarnings("unchecked")
class BehaviourCasesTest extends SdkTestBase {

  static Map<String, Object> section(String name) {
    try {
      return (Map<String, Object>) behaviourSections().get(name);
    } catch (java.io.IOException e) {
      throw new IllegalStateException(e);
    }
  }

  static Map<String, Object> caseOf(String sec, int i) {
    return (Map<String, Object>) ((List<Object>) section(sec).get("cases")).get(i);
  }

  static Map<String, Object> map(Object o) {
    return o == null ? new LinkedHashMap<>() : (Map<String, Object>) o;
  }

  static String str(Object o) {
    return o == null ? null : String.valueOf(o);
  }

  static Map<String, String> strMap(Object o) {
    Map<String, String> out = new LinkedHashMap<>();
    for (Map.Entry<String, Object> e : map(o).entrySet()) {
      out.put(e.getKey(), str(e.getValue()));
    }
    return out;
  }

  static Object attr(SpanData s, String key) {
    return Attr.get(s.getAttributes(), key);
  }

  static Http.Raw ok(String body) {
    return new Http.Raw(200, Map.of(), body.getBytes(StandardCharsets.UTF_8));
  }

  /** A transport that records each call and answers a clean verdict: nothing is dialled. */
  static final class Captured implements Http.Transport {
    final List<Http.Call> calls = Collections.synchronizedList(new ArrayList<>());

    @Override
    public Http.Raw send(Http.Call call) {
      calls.add(call);
      return ok("{\"allowed\": true, \"decision\": \"allow\"}");
    }

    Map<String, Object> lastBody() {
      Http.Call c = calls.get(calls.size() - 1);
      return (Map<String, Object>) Json.parse(new String(c.body, StandardCharsets.UTF_8));
    }

    boolean lastHasAuthorization() {
      for (String k : calls.get(calls.size() - 1).headers.keySet()) {
        if (k.equalsIgnoreCase("authorization")) {
          return true;
        }
      }
      return false;
    }
  }

  // --- the guard ----------------------------------------------------------------------------

  @Test
  void every_section_has_a_runner() throws Exception {
    // A section whose sdks does not name java needs no Java runner.
    Set<String> sections = new TreeSet<>();
    for (Map.Entry<String, Object> e : behaviourSections().entrySet()) {
      if (namesJava(map(e.getValue()).get("sdks"))) {
        sections.add(e.getKey());
      }
    }
    Set<String> runners = new TreeSet<>();
    for (Method m : BehaviourCasesTest.class.getDeclaredMethods()) {
      if (m.isAnnotationPresent(ParameterizedTest.class) && m.isAnnotationPresent(ArgumentsSource.class)) {
        runners.add(m.getName());
      }
    }
    assertEquals(sections, runners, "every section of sdk-behaviour-cases.json needs a Java runner (and no runner without a section)");
  }

  // --- sections -----------------------------------------------------------------------------

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void compile_values(int i) {
    Map<String, Object> sec = section("compile_values");
    Map<String, Object> c = caseOf("compile_values", i);
    Map<String, Object> vals = new HashMap<>();
    vals.put("v", c.get("value"));
    assertEquals(c.get("want"), Prompt.compileText((String) sec.get("prompt"), vals));
  }

  @Test
  void compile_non_finite_is_null() {
    Map<String, Object> vals = new HashMap<>();
    vals.put("v", Double.NaN);
    assertEquals("null", Prompt.compileText("{{v}}", vals));
    vals.put("v", Double.NEGATIVE_INFINITY);
    assertEquals("null", Prompt.compileText("{{v}}", vals));
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void score_target(int i) throws Exception {
    Map<String, Object> c = caseOf("score_target", i);
    try (Stub stub = new Stub()) {
      stub.route("POST", "/api/obs/scores", Map.of("accepted", List.of(Map.of("index", 0, "id", "sc_1")), "rejected", List.of()));
      Superbased.init(InitOptions.builder().exporter(InMemorySpanExporter.create()).nodeUrl(stub.url).destination("local").build());
      Map<String, Object> args = map(c.get("args"));
      String[] ids = new String[2];
      ScoreResult[] res = new ScoreResult[1];
      Runnable call =
          () -> {
            ScoreOptions.Builder b = ScoreOptions.builder();
            if ("current".equals(args.get("span_id"))) {
              b.spanId(Superbased.getCurrentSpanId());
            }
            res[0] = Superbased.score("accuracy", 1.0, b.build());
            ids[0] = Superbased.getCurrentTraceId();
            ids[1] = Superbased.getCurrentSpanId();
          };
      if (Boolean.TRUE.equals(c.get("in_span"))) {
        try (SbSpan s = Superbased.span("req").start()) {
          call.run();
        }
      } else {
        call.run();
      }
      Map<String, Object> want = map(c.get("want"));
      if (want.containsKey("error")) {
        assertFalse(res[0].ok());
        assertTrue(res[0].errors().stream().anyMatch(e -> e.contains((String) want.get("error"))), res[0].errors().toString());
        return;
      }
      Map<String, Object> body = stub.requests.get(stub.requests.size() - 1).json();
      assertEquals(ids[0], body.get("trace_id"));
      assertEquals("current".equals(want.get("span_id")) ? ids[1] : "", body.getOrDefault("span_id", ""));
    }
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void score_ok(int i) {
    Map<String, Object> c = caseOf("score_ok", i);
    ScoreResult r = new ScoreResult("sdk_x");
    for (Map.Entry<String, Object> e : map(c.get("destinations")).entrySet()) {
      boolean ok = (Boolean) e.getValue();
      r.put(e.getKey(), ok, ok ? 200 : 500, "", "");
    }
    assertEquals(c.get("want"), ScoreResult.resultOk(r));
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void destination(int i) throws Exception {
    Map<String, Object> c = caseOf("destination", i);
    try (Stub stub = new Stub()) {
      Map<String, String> env = new HashMap<>();
      env.put("SUPERBASED_DISCOVER", "1");
      env.putAll(strMap(c.get("env")));
      List<String> asked = Collections.synchronizedList(new ArrayList<>());
      Object machine = c.get("machine");
      Destination.discoverer =
          nodeUrl -> {
            asked.add(nodeUrl);
            if (machine != null && nodeUrl.equals(stub.url)) {
              return Destination.discoverOnce(nodeUrl);
            }
            return new Destination.Discovered(null, "no machine (test)");
          };
      if (machine != null) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("api_version", 1);
        body.put("destination", map(machine).get("destination"));
        body.put("source", "config");
        body.put("configured", "");
        body.put("signed_in", false);
        body.put("local", Map.of("enabled", true));
        body.put("online", Map.of());
        body.put("warnings", List.of());
        stub.route("GET", "/api/sdk/destination", body);
        env.put("SUPERBASED_NODE_URL", stub.url);
      } else if (!env.containsKey("SUPERBASED_MACHINE_URL")) {
        env.put("SUPERBASED_NODE_URL", "http://127.0.0.1:1");
      }
      Map<String, Object> args = map(c.get("args"));
      InitOptions.Builder ob = InitOptions.builder();
      if (args.containsKey("org_url")) {
        ob.orgUrl(str(args.get("org_url")));
      }
      if (args.containsKey("api_key")) {
        ob.apiKey(str(args.get("api_key")));
      }
      if (args.containsKey("destination")) {
        ob.destination(str(args.get("destination")));
      }
      Settings s = Settings.resolve(env, ob.build());
      Destination.Plan p = Destination.resolve(s, env, str(args.get("destination")), null, null, args.containsKey("api_key"));
      Map<String, Object> want = map(c.get("want"));
      assertEquals(want.get("destination"), p.destination);
      assertEquals(want.get("source"), p.source);
      if (want.containsKey("node_url")) {
        assertEquals(want.get("node_url"), p.nodeUrl);
        assertFalse(asked.contains(env.get("SUPERBASED_MACHINE_URL")));
      }
    }
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void control_targets(int i) {
    Map<String, Object> c = caseOf("control_targets", i);
    boolean ready = Boolean.TRUE.equals(c.get("online_ready"));
    Map<String, String> env = new HashMap<>();
    env.put("SUPERBASED_DISCOVER", "0");
    env.put("SUPERBASED_DESTINATION", str(c.get("destination")));
    env.put("SUPERBASED_ORG_URL", ready ? "https://gw.example.com" : "");
    env.put("SUPERBASED_API_KEY", ready ? "ik_1.s" : "");
    Destination.Plan p = Destination.resolve(Settings.resolve(env, null), env, null, null, null, false);
    List<String> names = new ArrayList<>();
    for (Control.Side s : Control.sides(p)) {
      names.add(s.name);
    }
    assertEquals(c.get("want"), names);
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void admit_identity(int i) {
    Map<String, Object> c = caseOf("admit_identity", i);
    Captured cap = new Captured();
    Http.transport = cap;
    Map<String, Object> init = map(c.get("init"));
    if (!init.isEmpty()) {
      Superbased.init(
          InitOptions.builder()
              .exporter(InMemorySpanExporter.create())
              .destination("local")
              .tenant(str(init.get("tenant")))
              .user(str(init.get("user")))
              .sessionId(str(init.get("session_id")))
              .build());
    }
    Map<String, Object> args = map(c.get("args"));
    AdmitOptions ao =
        AdmitOptions.builder()
            .endpoint("http://127.0.0.1:9/check")
            .user(str(args.get("user")))
            .tenant(str(args.get("tenant")))
            .session(str(args.get("session")))
            .build();
    Map<String, Object> scope = map(c.get("scope"));
    if (!scope.isEmpty()) {
      TraceAttributes ta =
          TraceAttributes.builder()
              .user(str(scope.get("user")))
              .tenant(str(scope.get("tenant")))
              .sessionId(str(scope.get("session_id")))
              .build();
      try (AttributeScope ignored = Superbased.propagateAttributes(ta)) {
        Superbased.admit("hi", ao);
      }
    } else {
      Superbased.admit("hi", ao);
    }
    Map<String, Object> body = cap.lastBody();
    Map<String, Object> got = new LinkedHashMap<>();
    for (String k : List.of("tenant", "user", "session")) {
      got.put(k, body.get(k));
    }
    assertEquals(map(c.get("want")), got);
  }

  private static final Map<String, String> HOSTS = Map.of("loopback", "http://127.0.0.1:9", "remote", "https://admit.example.com");

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void admit_credential(int i) {
    Map<String, Object> c = caseOf("admit_credential", i);
    Captured cap = new Captured();
    Http.transport = cap;
    String host = HOSTS.get(str(c.get("host")));
    AdmitOptions.Builder ao = AdmitOptions.builder();
    switch (str(c.get("key"))) {
      case "argument":
        ao.apiKey("ik_arg");
        break;
      case "init":
        Superbased.init(InitOptions.builder().exporter(InMemorySpanExporter.create()).destination("local").apiKey("ik_init").build());
        break;
      default:
        Env.set("SUPERBASED_API_KEY", "ik_env");
    }
    switch (str(c.get("via"))) {
      case "endpoint":
        ao.endpoint(host + "/check");
        break;
      case "env_endpoint":
        Env.set("SUPERBASED_ADMISSION_ENDPOINT", host + "/check");
        break;
      case "org_url":
        ao.orgUrl(host);
        break;
      case "env_org_url":
        Env.set("SUPERBASED_ORG_URL", host);
        break;
      default:
        break;
    }
    Superbased.admit("hi", ao.build());
    assertEquals(c.get("want_key"), cap.lastHasAuthorization(), cap.calls.get(cap.calls.size() - 1).url);
    assertEquals("loopback".equals(c.get("host")), cap.calls.get(cap.calls.size() - 1).loopback);
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void admit_redirect(int i) throws Exception {
    Map<String, Object> c = caseOf("admit_redirect", i);
    try (Stub stub = new Stub();
        Stub stub2 = new Stub()) {
      stub.reply(Map.of(), ((Long) c.get("status")).intValue(), Map.of("Location", stub2.url + "/stolen"));
      Verdict v = Superbased.admit("hi", AdmitOptions.builder().endpoint(stub.url + "/check").apiKey("ik_1.s").build());
      Map<String, Object> want = map(c.get("want"));
      assertEquals(((Long) want.get("requests")).intValue(), stub.requests.size());
      assertTrue(stub2.requests.isEmpty());
      assertEquals(want.get("degraded"), v.degraded());
      assertEquals(((Long) want.get("http_status")).intValue(), v.httpStatus());
    }
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void local_export_credential(int i) {
    Map<String, Object> c = caseOf("local_export_credential", i);
    Map<String, String> env = new HashMap<>();
    env.put("SUPERBASED_DISCOVER", "0");
    env.put("SUPERBASED_DESTINATION", "local");
    env.put("SUPERBASED_API_KEY", "ik_1.s");
    String explicit = null;
    switch (str(c.get("endpoint_from"))) {
      case "argument":
        explicit = str(c.get("endpoint"));
        break;
      case "superbased_env":
        env.put("SUPERBASED_OTLP_ENDPOINT", str(c.get("endpoint")));
        break;
      case "otel_env":
        env.put("OTEL_EXPORTER_OTLP_ENDPOINT", str(c.get("endpoint")));
        break;
      default:
        break;
    }
    Destination.Plan p =
        Destination.resolve(Settings.resolve(env, InitOptions.builder().endpoint(explicit).build()), env, null, explicit, null, false);
    assertEquals(1, p.exporters.size());
    boolean hasKey = p.exporters.get(0).headers.keySet().stream().anyMatch(k -> k.equalsIgnoreCase("authorization"));
    assertEquals(c.get("want_key"), hasKey);
  }

  private static ExperimentResult resultOf(Map<String, Object> c) {
    ExperimentResult res = new ExperimentResult("r");
    List<Object> items = (List<Object>) c.get("items");
    for (int n = 0; n < items.size(); n++) {
      Map<String, Object> it = map(items.get(n));
      ItemResult ir = new ItemResult("it_" + n, "x", null, null);
      ir.error = it.containsKey("error") ? str(it.get("error")) : "";
      for (Object s : (List<Object>) it.get("scores")) {
        Map<String, Object> sm = map(s);
        ir.scores.add(new Evaluation(str(sm.get("name")), sm.get("value")));
      }
      long errs = it.containsKey("evaluator_errors") ? (Long) it.get("evaluator_errors") : 0;
      for (int k = 0; k < errs; k++) {
        ir.evaluatorErrors.add("boom");
      }
      res.items.add(ir);
    }
    return res;
  }

  private static Double dbl(Object o) {
    return o == null ? null : ((Number) o).doubleValue();
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void experiment_pass_rate(int i) {
    Map<String, Object> c = caseOf("experiment_pass_rate", i);
    ExperimentResult res = resultOf(c);
    List<Object> sides = (List<Object>) c.get("sides");
    for (int n = 0; n < sides.size(); n++) {
      res.server.put(n == 0 ? "online" : "local", sides.get(n));
    }
    Map<String, Object> want = map(c.get("want"));
    assertEquals(((Long) want.get("scored")).intValue(), res.scored());
    if (want.get("pass_rate") == null) {
      assertTrue(Double.isNaN(res.passRate()));
    } else {
      assertEquals(dbl(want.get("pass_rate")), res.passRate(), 1e-9);
    }
    // This section is the rate rule alone; experiment_strict_gate covers strict.
    assertEquals(want.get("gate_failed"), Experiments.gateFails(res, dbl(c.get("fail_under")), false));
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void literal_item_ids(int i) {
    Map<String, Object> c = caseOf("literal_item_ids", i);
    List<String> ids = new ArrayList<>();
    for (Map<String, Object> r : Experiments.literal((List<Object>) c.get("items"))) {
      ids.add(str(r.get("id")));
    }
    assertEquals(c.get("want"), ids);
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void sampling_env(int i) {
    Map<String, Object> c = caseOf("sampling_env", i);
    Map<String, String> env = strMap(c.get("env"));
    Map<String, Object> want = map(c.get("want"));
    if (Boolean.TRUE.equals(want.get("error"))) {
      assertThrows(IllegalArgumentException.class, () -> Settings.resolveSampling(dbl(c.get("explicit")), env));
      return;
    }
    Settings.Sampling s = Settings.resolveSampling(dbl(c.get("explicit")), env);
    assertEquals(dbl(want.get("rate")), s.rate, 0.0);
    assertEquals(want.get("parent_based"), s.parentBased);
    String problem = Settings.samplingEnvProblem(env);
    List<String> named = new ArrayList<>();
    for (String v : List.of("SUPERBASED_SAMPLE_RATE", "OTEL_TRACES_SAMPLER_ARG")) {
      if (problem.contains(v + "=")) {
        named.add(v);
      }
    }
    assertEquals(want.get("ignored"), named, problem);
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void pending_per_destination(int i) throws Exception {
    Map<String, Object> c = caseOf("pending_per_destination", i);
    List<Object> held = (List<Object>) c.get("held");
    try (Stub local = new Stub();
        Stub online = new Stub()) {
      local.reply(Map.of());
      online.reply(Map.of());
      local.delayMs = held.contains("local") ? 1000 : 0;
      online.delayMs = held.contains("online") ? 1000 : 0;
      Env.set("SUPERBASED_OTLP_ENDPOINT", local.url + "/v1/traces");
      String dest = str(c.get("destination"));
      InitOptions.Builder ob =
          InitOptions.builder().destination(dest).shutdownTimeout(Duration.ofSeconds(5)).exportTimeout(Duration.ofSeconds(5));
      if (dest.equals("both")) {
        ob.orgUrl(online.url).apiKey("ik_1.s");
      }
      Superbased.init(ob.build());
      try (SbSpan s = Superbased.span("x").start()) {
        s.setAttribute("k", "v");
      }
      Thread t = new Thread(() -> Superbased.flush(Duration.ofSeconds(5)));
      t.start();
      int legs = dest.equals("both") ? 2 : 1;
      int answered = legs - held.size();
      long deadline = System.currentTimeMillis() + 3000;
      while (((Long) Superbased.diagnostics().get("exported_spans")) < answered && System.currentTimeMillis() < deadline) {
        Thread.sleep(20);
      }
      if (!held.isEmpty()) {
        assertEquals(((Long) c.get("want_pending")), Superbased.diagnostics().get("pending_spans"), Superbased.diagnostics().toString());
      }
      t.join(6000);
      assertEquals(0L, Superbased.diagnostics().get("pending_spans"), Superbased.diagnostics().toString());
      if (held.isEmpty()) {
        assertEquals(0L, c.get("want_pending"));
      }
    }
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void admit_degraded(int i) throws Exception {
    Map<String, Object> c = caseOf("admit_degraded", i);
    Map<String, Object> want = map(c.get("want"));
    try (Stub stub = new Stub()) {
      String url;
      if ("transport".equals(c.get("status"))) {
        url = Stub.deadUrl() + "/check";
      } else {
        int status = ((Long) c.get("status")).intValue();
        stub.reply(status == 200 ? Map.of("allowed", true, "decision", "allow") : Map.of(), status, null);
        url = stub.url + (c.containsKey("path") ? str(c.get("path")) : "/check");
      }
      boolean failClosed = Boolean.TRUE.equals(c.get("fail_closed"));
      List<Verdict> vs = new ArrayList<>();
      for (int k = 0; k < 2; k++) {
        vs.add(Superbased.admit("hi", AdmitOptions.builder().endpoint(url).timeout(Duration.ofSeconds(1)).failClosed(failClosed).build()));
      }
      for (Verdict v : vs) {
        assertEquals(want.get("allowed"), v.allowed());
        assertEquals(want.get("degraded"), v.degraded());
      }
      List<String> lines = new ArrayList<>();
      synchronized (logs) {
        for (String l : logs) {
          if (l.contains("admit()")) {
            lines.add(l);
          }
        }
      }
      assertEquals(((Long) want.get("warnings")).intValue(), lines.size(), lines.toString());
      String fix = want.containsKey("fix") ? str(want.get("fix")) : "";
      for (String l : lines) {
        assertTrue(l.contains("Fix:") && l.contains(fix), l);
      }
      assertEquals(want.get("counted"), Superbased.diagnostics().get("admission_degraded"));
    }
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void control_before_discovery(int i) throws Exception {
    Map<String, Object> c = caseOf("control_before_discovery", i);
    try (Stub machine = new Stub();
        Stub gateway = new Stub()) {
      Map<String, Object> found = new LinkedHashMap<>();
      found.put("api_version", 1);
      found.put("destination", c.get("discovery"));
      found.put("source", "config");
      found.put("configured", "");
      found.put("signed_in", true);
      found.put("local", Map.of("enabled", true));
      found.put("online", Map.of());
      found.put("warnings", List.of());
      long delay = (Long) c.get("delay_ms");
      machine.route(
          "GET",
          "/api/sdk/destination",
          r -> {
            try {
              Thread.sleep(delay);
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            }
            return new Stub.Answer(200, found, null);
          });
      Map<String, Object> accepted = Map.of("accepted", List.of(Map.of("index", 0, "id", "sc_1")), "rejected", List.of());
      machine.route("POST", "/api/obs/scores", accepted);
      gateway.route("POST", "/v1/sdk/scores", accepted);
      Env.set("SUPERBASED_DISCOVER", "1");
      // The gateway is named by the app (review E-04: never by discovery).
      Superbased.init(
          InitOptions.builder().nodeUrl(machine.url).apiKey("ik_1.s").orgUrl(gateway.url).exporter(InMemorySpanExporter.create()).build());
      ScoreResult res;
      try (SbSpan s = Superbased.span("req").start()) {
        res = Superbased.score("accuracy", 1.0);
      }
      assertTrue(res.ok(), res.errors().toString());
      assertEquals(List.of(c.get("want")), new ArrayList<>(res.destinations().keySet()));
    }
  }

  private static void datasetRoutes(Stub stub, java.util.function.Function<Stub.Req, Stub.Answer> create) {
    stub.route("GET", "/api/obs/eval/datasets", Map.of("datasets", List.of(Map.of("id", "7", "name", "golden"))));
    stub.route("POST", "/api/obs/eval/experiments", create);
    stub.route("GET", "/api/obs/eval/datasets/7/items", Map.of("items", List.of(), "next_cursor", ""));
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void experiment_snapshot_version(int i) throws Exception {
    Map<String, Object> c = caseOf("experiment_snapshot_version", i);
    try (Stub stub = new Stub()) {
      List<Map<String, Object>> created = Collections.synchronizedList(new ArrayList<>());
      datasetRoutes(
          stub,
          r -> {
            created.add(r.json());
            return new Stub.Answer(201, Map.of("id", "1", "snapshot_version", r.json().get("snapshot_version")), null);
          });
      Superbased.init(InitOptions.builder().exporter(InMemorySpanExporter.create()).nodeUrl(stub.url).destination("local").build());
      ExperimentOptions.Builder eo = ExperimentOptions.builder().inputTask(input -> input);
      if (c.get("snapshot_version") != null) {
        eo.snapshotVersion((Long) c.get("snapshot_version"));
      }
      Superbased.runExperiment("golden", eo.build());
      assertEquals(c.get("want"), created.get(0).get("snapshot_version"));
    }
  }

  private static final Pattern CREATE_ID = Pattern.compile("[A-Za-z0-9_.:-]{1,128}");

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void experiment_create_id(int i) throws Exception {
    Map<String, Object> c = caseOf("experiment_create_id", i);
    int first = ((Long) c.get("first_status")).intValue();
    try (Stub stub = new Stub()) {
      List<Map<String, Object>> created = Collections.synchronizedList(new ArrayList<>());
      datasetRoutes(
          stub,
          r -> {
            created.add(r.json());
            if (created.size() == 1 && first != 201) {
              return new Stub.Answer(first, Map.of("error", "x", "message", "x"), null);
            }
            return new Stub.Answer(201, Map.of("id", "1", "snapshot_version", 1), null);
          });
      Superbased.init(InitOptions.builder().exporter(InMemorySpanExporter.create()).nodeUrl(stub.url).destination("local").build());
      ExperimentOptions eo = ExperimentOptions.builder().inputTask(input -> input).build();
      if (first == 201 || first == 429 || first >= 500) {
        Superbased.runExperiment("golden", eo);
      } else {
        assertThrows(ExperimentException.class, () -> Superbased.runExperiment("golden", eo));
      }
      assertEquals(((Long) c.get("want_creates")).intValue(), created.size());
      Set<Object> ids = new HashSet<>();
      for (Map<String, Object> b : created) {
        ids.add(b.get("id"));
      }
      assertEquals(1, ids.size());
      Object cid = ids.iterator().next();
      assertTrue(cid instanceof String && CREATE_ID.matcher((String) cid).matches(), String.valueOf(cid));
      if (first == 201) {
        Superbased.runExperiment("golden", eo);
        assertNotEquals(cid, created.get(created.size() - 1).get("id"));
      }
    }
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void llm_span_prompt(int i) throws Exception {
    Map<String, Object> c = caseOf("llm_span_prompt", i);
    Object body = loadContract(str(c.get("fixture"))).get("body");
    Prompt prompt = Prompts.parse(body, "online", "production");
    InMemorySpanExporter mem = InMemorySpanExporter.create();
    Superbased.init(InitOptions.builder().exporter(mem).destination("local").build());
    try (SbSpan s = Superbased.llmSpan("chat").prompt(prompt).start()) {
      s.setAttribute("x", 1L);
    }
    Superbased.flush(Duration.ofSeconds(5));
    List<SpanData> spans = mem.getFinishedSpanItems();
    SpanData last = spans.get(spans.size() - 1);
    Map<String, Object> want = map(c.get("want"));
    assertEquals(want.get("name"), attr(last, "sbo.prompt.name"));
    assertEquals(want.get("version"), attr(last, "sbo.prompt.version"));
    boolean content = attr(last, "input.value") != null || attr(last, "gen_ai.input.messages") != null;
    assertEquals(want.get("content"), content);
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void local_receiver_discovery(int i) throws Exception {
    Map<String, Object> sec = section("local_receiver_discovery");
    Map<String, Object> c = caseOf("local_receiver_discovery", i);
    String receiver = str(sec.get("machine_receiver"));
    try (Stub stub = new Stub()) {
      Map<String, Object> body = new LinkedHashMap<>();
      body.put("api_version", 1);
      body.put("destination", "local");
      body.put("source", "config");
      body.put("configured", "");
      body.put("signed_in", false);
      body.put("local", Map.of("enabled", true, "otlp_traces_url", receiver));
      body.put("online", Map.of());
      body.put("warnings", List.of());
      stub.route("GET", "/api/sdk/destination", body);
      Map<String, String> env = new HashMap<>();
      env.put("SUPERBASED_DISCOVER", Boolean.TRUE.equals(c.get("discover")) ? "1" : "0");
      env.put("SUPERBASED_DESTINATION", str(c.get("destination")));
      env.put("SUPERBASED_NODE_URL", stub.url);
      env.put("SUPERBASED_ORG_URL", "https://gw.example.com");
      env.put("SUPERBASED_API_KEY", "ik_1.s");
      String explicit = null;
      String named = c.containsKey("endpoint") ? str(c.get("endpoint")) : "";
      switch (str(c.get("endpoint_from"))) {
        case "argument":
          explicit = named;
          break;
        case "superbased_env":
          env.put("SUPERBASED_OTLP_ENDPOINT", named);
          break;
        case "otel_env":
          env.put("OTEL_EXPORTER_OTLP_ENDPOINT", named);
          named = Http.stripRight(named, '/') + "/v1/traces";
          break;
        default:
          break;
      }
      Destination.Plan p =
          Destination.resolve(Settings.resolve(env, InitOptions.builder().endpoint(explicit).build()), env, null, explicit, null, false);
      List<String> local = new ArrayList<>();
      for (Destination.Target t : p.exporters) {
        if (t.name.equals("local")) {
          local.add(t.endpoint);
        }
      }
      Map<String, Object> want = map(c.get("want"));
      Object w = want.get("local");
      List<String> expect;
      if (w == null) {
        expect = List.of();
      } else if (w.equals("machine")) {
        expect = List.of(receiver);
      } else if (w.equals("named")) {
        expect = List.of(named);
      } else {
        expect = List.of("http://127.0.0.1:4318/v1/traces");
      }
      assertEquals(expect, local);
      assertEquals(want.get("asked"), !stub.paths("/api/sdk/destination").isEmpty());
    }
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void vendor_self_tracing(int i) {
    Map<String, Object> c = caseOf("vendor_self_tracing", i);
    Map<String, Object> want = map(c.get("want"));
    for (String k : map(want.get("env_after")).keySet()) {
      Env.set(k, null);
    }
    for (Map.Entry<String, String> e : strMap(c.get("env")).entrySet()) {
      Env.set(e.getKey(), e.getValue());
    }
    InMemorySpanExporter mem = InMemorySpanExporter.create();
    Superbased.init(InitOptions.builder().exporter(mem).destination("local").build());
    assertEquals(want.get("status"), Superbased.diagnostics().get("vendor_tracing"));
    for (Map.Entry<String, String> e : strMap(want.get("env_after")).entrySet()) {
      assertEquals(e.getValue(), Env.get(e.getKey()));
    }
    Map<String, Object> exported = map(want.get("exported"));
    for (String scope : exported.keySet()) {
      Superbased.tracerProvider().get(scope).spanBuilder("call " + scope).startSpan().end();
    }
    Superbased.flush(Duration.ofSeconds(5));
    Set<String> got = new HashSet<>();
    for (SpanData s : mem.getFinishedSpanItems()) {
      got.add(s.getInstrumentationScopeInfo().getName());
    }
    Map<String, Object> seen = new LinkedHashMap<>();
    long dropped = 0;
    for (Map.Entry<String, Object> e : exported.entrySet()) {
      seen.put(e.getKey(), got.contains(e.getKey()));
      if (Boolean.FALSE.equals(e.getValue())) {
        dropped++;
      }
    }
    assertEquals(exported, seen);
    assertEquals(dropped, Superbased.diagnostics().get("vendor_spans_dropped"));
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void set_usage_net_input(int i) {
    Map<String, Object> c = caseOf("set_usage_net_input", i);
    InMemorySpanExporter mem = InMemorySpanExporter.create();
    Superbased.init(InitOptions.builder().exporter(mem).destination("local").build());
    long before = (Long) Superbased.diagnostics().get("usage_net_input_corrected");
    Map<String, Object> u = map(c.get("usage"));
    Usage.Builder ub = Usage.builder();
    if (u.containsKey("input_tokens")) {
      ub.inputTokens((Long) u.get("input_tokens"));
    }
    if (u.containsKey("output_tokens")) {
      ub.outputTokens((Long) u.get("output_tokens"));
    }
    if (u.containsKey("cache_read_tokens")) {
      ub.cacheReadTokens((Long) u.get("cache_read_tokens"));
    }
    if (u.containsKey("cache_write_tokens")) {
      ub.cacheWriteTokens((Long) u.get("cache_write_tokens"));
    }
    try (SbSpan s = Superbased.llmSpan("chat").start()) {
      Superbased.setUsage(s.span(), ub.build());
    }
    Superbased.flush(Duration.ofSeconds(5));
    List<SpanData> spans = mem.getFinishedSpanItems();
    Attributes attrs = spans.get(spans.size() - 1).getAttributes();
    Map<String, Object> want = map(c.get("want"));
    assertEquals(want.get("input_tokens"), attrs.get(AttributeKey.longKey("gen_ai.usage.input_tokens")));
    assertEquals(want.get("corrected"), (Long) Superbased.diagnostics().get("usage_net_input_corrected") - before);
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void admit_org_off(int i) throws Exception {
    Map<String, Object> c = caseOf("admit_org_off", i);
    Map<String, Object> want = map(c.get("want"));
    try (Stub machine = new Stub();
        Stub gateway = new Stub()) {
      gateway.route("POST", "/v1/sdk/admit", c.get("org"));
      String nodeUrl = Stub.deadUrl();
      if (!"transport".equals(c.get("machine"))) {
        machine.route("POST", "/api/obs/admission/check", c.get("machine"));
        nodeUrl = machine.url;
      }
      Env.set("SUPERBASED_DISCOVER", "0");
      Superbased.init(
          InitOptions.builder()
              .destination(str(c.get("destination")))
              .nodeUrl(nodeUrl)
              .orgUrl(gateway.url)
              .apiKey("ik_1.s")
              .exporter(InMemorySpanExporter.create())
              .build());
      AdmitOptions.Builder ao =
          AdmitOptions.builder().timeout(Duration.ofSeconds(1)).failClosed(Boolean.TRUE.equals(c.get("fail_closed")));
      if ("org_url".equals(c.get("via"))) {
        ao.orgUrl(gateway.url);
      }
      Verdict v = Superbased.admit("hi", ao.build());
      assertEquals(want.get("allowed"), v.allowed());
      assertEquals(want.get("decision"), v.decision());
      assertEquals(want.get("degraded"), v.degraded());
      List<Stub.Req> asked = machine.paths("/api/obs/admission/check");
      assertEquals(want.get("asked_machine"), !asked.isEmpty());
      for (Stub.Req r : asked) {
        assertFalse(r.headers.containsKey("authorization"));
      }
      assertEquals(want.get("counted"), Superbased.diagnostics().get("admission_degraded"));
    }
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void experiment_strict_gate(int i) {
    Map<String, Object> c = caseOf("experiment_strict_gate", i);
    ExperimentResult res = resultOf(c);
    for (Object s : (List<Object>) c.get("skipped_sides")) {
      res.skippedSides.add(str(s));
    }
    res.failedPosts = ((Long) c.get("failed_posts")).intValue();
    Map<String, Object> want = map(c.get("want"));
    assertEquals(((Long) want.get("reasons")).intValue(), Experiments.gateProblems(res).size());
    boolean strict = !c.containsKey("strict") || Boolean.TRUE.equals(c.get("strict"));
    assertEquals(want.get("gate_failed"), Experiments.gateFails(res, dbl(c.get("fail_under")), strict));
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void get_dataset_missing(int i) throws Exception {
    Map<String, Object> c = caseOf("get_dataset_missing", i);
    try (Stub stub = new Stub()) {
      Env.set("SUPERBASED_DISCOVER", "0");
      if ("no_destination".equals(c.get("datasets"))) {
        Superbased.init(InitOptions.builder().destination("online").exporter(InMemorySpanExporter.create()).build());
      } else {
        List<Object> listed = new ArrayList<>();
        List<Object> names = (List<Object>) c.get("datasets");
        for (int n = 0; n < names.size(); n++) {
          listed.add(Map.of("id", String.valueOf(n + 7), "name", names.get(n), "item_count", 0, "latest_snapshot", 1));
        }
        stub.route("GET", "/api/obs/eval/datasets", Map.of("api_version", "v1", "datasets", listed));
        stub.reply(Map.of("items", List.of(), "next_cursor", ""));
        Superbased.init(InitOptions.builder().destination("local").nodeUrl(stub.url).exporter(InMemorySpanExporter.create()).build());
      }
      String name = str(c.get("name"));
      if (Boolean.TRUE.equals(map(c.get("want")).get("found"))) {
        assertEquals(name, Superbased.getDataset(name).name());
      } else {
        assertThrows(ExperimentException.class, () -> Superbased.getDataset(name));
      }
    }
  }

  // --- the SDK quickstart (sdk-api-surface.md sections 15 and 16, destination.md section 6a) ---

  /** Whether case {@code c} of section {@code sec} names Java (the case's sdks narrows the section's). */
  static boolean caseNamesJava(String sec, Map<String, Object> c) {
    Object sdks = c.containsKey("sdks") ? c.get("sdks") : section(sec).get("sdks");
    return namesJava(sdks);
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void service_name_default(int i) {
    Map<String, Object> c = caseOf("service_name_default", i);
    org.junit.jupiter.api.Assumptions.assumeTrue(caseNamesJava("service_name_default", c), "not a Java case");
    Object title = map(c.get("project")).get("implementation_title");
    ServiceName.project = () -> title == null ? "" : (String) title;
    Map<String, String> env = strMap(c.get("env"));
    String arg = (String) map(c.get("args")).get("service_name");
    Settings s = Settings.resolve(env, InitOptions.builder().serviceName(arg).build());
    Map<String, Object> want = map(c.get("want"));
    assertEquals(want.get("service_name"), s.serviceName(), (String) c.get("name"));
    assertEquals(want.get("source"), s.serviceNameSource(), (String) c.get("name"));
  }

  static final String CASE_SDK_FILE_KEY = "00000000000000000000000000000002.fake-sdk-file-secret";
  static final String CASE_MACHINE_FILE_KEY = "00000000000000000000000000000003.fake-machine-secret";

  static java.nio.file.Path writeOwnerOnly(java.nio.file.Path f, String text, String perms) throws java.io.IOException {
    java.nio.file.Files.writeString(f, text, StandardCharsets.US_ASCII);
    java.nio.file.Files.setPosixFilePermissions(f, java.nio.file.attribute.PosixFilePermissions.fromString(perms));
    return f;
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void destination_sdk_file(int i) throws Exception {
    Map<String, Object> c = caseOf("destination_sdk_file", i);
    String name = (String) c.get("name");
    java.nio.file.Path dir = java.nio.file.Files.createTempDirectory("sbsdkfile");
    java.nio.file.Path file = dir.resolve("sdk-credential");
    Map<String, Object> sf = (Map<String, Object>) c.get("sdk_file");
    if (sf != null) {
      String state = (String) sf.get("state");
      org.junit.jupiter.api.Assumptions.assumeFalse("refused".equals(state) && SdkFile.windows(), "the unix read rules decide refused");
      StringBuilder b = new StringBuilder(CASE_SDK_FILE_KEY).append("\ngateway_url=https://u-k7x2.superbased.app\n");
      if (sf.get("destination") != null) {
        b.append("destination=").append(sf.get("destination")).append('\n');
      }
      java.time.Instant exp = "expired".equals(state) ? java.time.Instant.now().minusSeconds(3600) : java.time.Instant.now().plus(Duration.ofDays(365));
      b.append("expires_at=").append(exp.truncatedTo(java.time.temporal.ChronoUnit.SECONDS)).append('\n');
      writeOwnerOnly(file, b.toString(), "refused".equals(state) ? "rw-r--r--" : "rw-------");
    }
    Map<String, String> env = new HashMap<>();
    env.put("SUPERBASED_DISCOVER", "1");
    env.put("SUPERBASED_NODE_URL", "http://127.0.0.1:9");
    env.put(SdkFile.ENV_CREDENTIAL_FILE, file.toString());
    env.put("LOCALAPPDATA", dir.toString());
    env.putAll(strMap(c.get("env")));
    Map<String, Object> m = (Map<String, Object>) c.get("machine");
    Map<String, Object> answer = null;
    if (m != null) {
      Map<String, Object> online = new LinkedHashMap<>();
      if (Boolean.TRUE.equals(m.get("credential_present"))) {
        java.nio.file.Path mf = writeOwnerOnly(dir.resolve("machine-credential"), CASE_MACHINE_FILE_KEY + "\ngateway_url=https://gw.machine.example\n", "rw-------");
        online.put("credential_present", true);
        online.put("credential_file", mf.toString());
      }
      answer = new LinkedHashMap<>();
      answer.put("api_version", 1L);
      answer.put("destination", m.get("destination"));
      answer.put("signed_in", m.get("signed_in"));
      answer.put("local", Map.of("enabled", m.get("local_enabled")));
      answer.put("online", online);
      answer.put("warnings", List.of());
    }
    Map<String, Object> body = answer;
    Destination.Discoverer orig = Destination.discoverer;
    Destination.discoverer = n -> body == null ? new Destination.Discovered(null, "no machine (test)") : new Destination.Discovered(body, "");
    try {
      Destination.resetCacheForTests();
      Map<String, Object> args = map(c.get("args"));
      String argDest = (String) args.get("destination");
      Settings s = Settings.resolve(env, InitOptions.builder().destination(argDest).build());
      Destination.Plan p = Destination.resolve(s, env, argDest, null, null, false);
      Map<String, Object> want = map(c.get("want"));
      String got = p.destination + "|" + p.source + "|" + p.credentialSource + "|" + p.sdkFile.get("state");
      String exp = want.get("destination") + "|" + want.get("source") + "|" + want.get("credential_source") + "|" + want.get("sdk_file");
      assertEquals(exp, got, name + "; warnings " + p.warnings);
      if (want.get("warning_contains") != null) {
        assertTrue(String.join("\n", p.warnings).contains((String) want.get("warning_contains")), name + ": " + p.warnings);
      }
      assertEquals(Boolean.TRUE.equals(want.get("degraded")), !p.degraded.isEmpty(), name + ": " + p.degraded);
      if (Boolean.TRUE.equals(want.get("degraded")) && sf != null) {
        assertTrue(p.degraded.contains("setup"), name + ": " + p.degraded);
      }
      for (String w : p.warnings) {
        assertFalse(w.contains("fake-sdk-file-secret") || w.contains("fake-machine-secret"), name + ": a warning carries a key");
      }
    } finally {
      Destination.discoverer = orig;
    }
  }

  @ParameterizedTest
  @ArgumentsSource(CaseIndexes.class)
  void first_trace_link(int i) throws Exception {
    Map<String, Object> c = caseOf("first_trace_link", i);
    String name = (String) c.get("name");
    Destination.Plan p = new Destination.Plan();
    p.destination = (String) c.get("destination");
    p.localDashboard = (String) c.get("node_url");
    if ("online".equals(p.destination) || "both".equals(p.destination)) {
      p.onlineReady = true;
      Object record = c.get("record");
      if ("sdk_file".equals(record) || "machine".equals(record)) {
        p.onlineDashboard = c.get("dashboard_url") == null ? "" : (String) c.get("dashboard_url");
      }
    }
    Map<String, String> env = strMap(c.get("env"));
    boolean tty = Boolean.TRUE.equals(c.get("tty"));
    FirstTrace.Tracker tr = new FirstTrace.Tracker();
    java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
    java.io.PrintStream ps = new java.io.PrintStream(buf, true, StandardCharsets.UTF_8);
    FirstTrace.Bases bases = FirstTrace.Bases.of(p);
    for (Object o : (List<Object>) c.get("exports")) {
      Map<String, Object> x = map(o);
      String id = (String) x.get("trace_id");
      if (x.get("local") != null) {
        tr.note(bases, "local", id, "ok".equals(x.get("local")), null, () -> FirstTrace.allowed(tty, env), ps);
      }
      if (x.get("online") != null) {
        String outcome = (String) x.get("online");
        PlanRefusalException refusal = null;
        if (!"ok".equals(outcome) && !"failed".equals(outcome)) {
          refusal = planRefusalCase(outcome);
        }
        tr.note(bases, "online", id, "ok".equals(outcome), refusal, () -> FirstTrace.allowed(tty, env), ps);
      }
    }
    List<String> lines = new ArrayList<>();
    for (String l : buf.toString(StandardCharsets.UTF_8).split("\n")) {
      if (l.startsWith("superbased: ")) {
        lines.add(l);
      }
    }
    assertEquals(map(c.get("want")).get("lines"), lines, name);
  }

  static PlanRefusalException planRefusalCase(String name) throws java.io.IOException {
    for (Object o : (List<Object>) loadContract("plan-refusal-cases.json").get("cases")) {
      Map<String, Object> rc = map(o);
      if (name.equals(rc.get("name"))) {
        PlanRefusalException r = PlanRefusalException.parse(((Number) rc.get("status")).intValue(), rc.get("body"), strMap(rc.get("headers")));
        if (r == null) {
          throw new IllegalStateException("plan-refusal case " + name + " is not a refusal");
        }
        return r;
      }
    }
    throw new IllegalStateException("no plan-refusal case " + name);
  }
}
