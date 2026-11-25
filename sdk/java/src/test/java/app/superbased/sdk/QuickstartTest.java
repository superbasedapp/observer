package app.superbased.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.data.SpanData;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.jar.Attributes;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;

/**
 * The SDK quickstart's Java side (plan sections 3.2, 3.4, 3.8; lane L6):
 * {@code sdk/contract/credential-file-cases.json}, and what the shared cases
 * leave to each SDK (a key never sent to another address, whole records, the
 * expiry texts, diagnostics, the Windows rule's facts, the manifest, the
 * first-trace line through real exports). The behaviour sections run in
 * {@link BehaviourCasesTest}. Fakes only: never a real key.
 */
@SuppressWarnings("unchecked")
class QuickstartTest extends SdkTestBase {
  static final String KEY = "00000000000000000000000000000001.FAKE-sdk-key-secret-for-contract-tests-only";
  static final String SECRET = "FAKE-sdk-key-secret-for-contract-tests-only";
  static final String GW = "https://u-k7x2.superbased.app";
  static final String ONLINE = body("gateway_url=" + GW, "destination=online", "dashboard_url=https://u-k7x2.superbased.app");

  static String body(String... lines) {
    StringBuilder b = new StringBuilder(KEY).append('\n');
    for (String l : lines) {
      b.append(l).append('\n');
    }
    return b.toString();
  }

  static Path held(Path dir, String body, String perms) throws Exception {
    Path d = Files.createDirectories(dir.resolve("superbased-" + System.nanoTime()));
    Path f = d.resolve("sdk-credential");
    Files.writeString(f, body, StandardCharsets.US_ASCII);
    Files.setPosixFilePermissions(f, PosixFilePermissions.fromString(perms));
    return f;
  }

  static Map<String, String> env(String... kv) {
    Map<String, String> m = new HashMap<>();
    for (int i = 0; i < kv.length; i += 2) {
      m.put(kv[i], kv[i + 1]);
    }
    return m;
  }

  static Map<String, Object> map(Object o) {
    return o == null ? new LinkedHashMap<>() : (Map<String, Object>) o;
  }

  // --- credential-file-cases.json -------------------------------------------------------

  @Test
  void the_credential_file_path_cases() throws Exception {
    Map<String, Object> f = loadContract("credential-file-cases.json");
    assertTrue(namesJava(f.get("sdks")));
    List<Object> cases = (List<Object>) f.get("path_cases");
    assertTrue(cases.size() >= 8);
    for (Object o : cases) {
      Map<String, Object> c = map(o);
      Map<String, String> e = new HashMap<>();
      for (Map.Entry<String, Object> x : map(c.get("env")).entrySet()) {
        e.put(x.getKey(), String.valueOf(x.getValue()));
      }
      boolean onWindows = "windows".equals(c.get("os"));
      e.put(onWindows ? "USERPROFILE" : "HOME", (String) c.get("home"));
      Object want = map(c.get("want")).get("path");
      assertEquals(want == null ? "" : want, SdkFile.path(e, onWindows), (String) c.get("name"));
    }
    List<String> reasons = (List<String>) f.get("reasons");
    for (String r :
        List.of(
            SdkFile.R_SYMLINK,
            SdkFile.R_NOT_REGULAR,
            SdkFile.R_MODE,
            SdkFile.R_OWNER,
            SdkFile.R_TOO_LARGE,
            SdkFile.R_EMPTY,
            SdkFile.R_BAD_KEY_LINE,
            SdkFile.R_BAD_NAME_LINE,
            SdkFile.R_REPARSE_POINT,
            SdkFile.R_OUTSIDE_LOCALAPPDATA)) {
      assertTrue(reasons.contains(r), r);
    }
  }

  @TestFactory
  List<DynamicTest> the_credential_file_reader_cases() throws Exception {
    List<DynamicTest> out = new ArrayList<>();
    for (Object o : (List<Object>) loadContract("credential-file-cases.json").get("reader_cases")) {
      Map<String, Object> c = map(o);
      out.add(DynamicTest.dynamicTest((String) c.get("name"), () -> runReaderCase(c)));
    }
    assertTrue(out.size() >= 30);
    return out;
  }

  /**
   * One reader case. Unix cases run on a real file (another owner through
   * the processUid seam); a Windows case runs the Windows rule over its facts,
   * then the format rules over the text, on every OS; "any" runs on a real
   * file here.
   */
  void runReaderCase(Map<String, Object> c) throws Exception {
    Superbased.resetForTests();
    String text = (String) c.get("text");
    SdkFile.Held h;
    if ("windows".equals(c.get("os"))) {
      SdkFile.WindowsFacts f = new SdkFile.WindowsFacts();
      f.reparsePoint = Boolean.TRUE.equals(c.get("reparse_point"));
      f.regularFile = !"directory".equals(c.get("kind"));
      f.insideRoot = !"outside".equals(c.get("location"));
      f.ownerIsUser = !"other".equals(c.get("owner_sid"));
      h = new SdkFile.Held();
      h.present = text != null || "directory".equals(c.get("kind"));
      String[] p = SdkFile.windowsProblem(f);
      if (h.present && !p[0].isEmpty()) {
        h.problem = p[0];
        h.reason = p[1];
      } else if (h.present) {
        SdkFile.Record r = SdkFile.parse(text.getBytes(StandardCharsets.ISO_8859_1));
        h.problem = r.problem;
        h.reason = r.reason;
        h.ok = r.problem.isEmpty();
        h.record = r;
      }
    } else {
      Assumptions.assumeFalse("unix".equals(c.get("os")) && SdkFile.windows(), "a unix rule");
      Path dir = Files.createTempDirectory("sbcred");
      Path p = dir.resolve("sdk-credential");
      if ("directory".equals(c.get("kind"))) {
        Files.createDirectory(p);
      } else if (text != null) {
        Path target = Boolean.TRUE.equals(c.get("symlink")) ? dir.resolve("target") : p;
        Files.write(target, text.getBytes(StandardCharsets.ISO_8859_1));
        String mode = c.get("mode") == null ? "0600" : (String) c.get("mode");
        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString(perms(mode)));
        if (Boolean.TRUE.equals(c.get("symlink"))) {
          Files.createSymbolicLink(p, target);
        }
      }
      java.util.function.LongSupplier orig = Destination.processUid;
      if ("other".equals(c.get("owner"))) {
        long uid = orig.getAsLong();
        Destination.processUid = () -> uid + 4242;
      }
      try {
        h = SdkFile.read(p.toString(), dir.toString(), Instant.parse("2026-11-25T00:00:00Z"));
      } finally {
        Destination.processUid = orig;
      }
    }
    Map<String, Object> want = map(c.get("want"));
    String state = !h.present ? "absent" : h.ok ? "ok" : "refused";
    String name = (String) c.get("name");
    assertEquals(want.get("state"), state, name + ": " + h.problem);
    if ("refused".equals(state)) {
      assertEquals(want.get("reason"), h.reason, name + ": " + h.problem);
      return;
    }
    if (!"ok".equals(state)) {
      return;
    }
    SdkFile.Record r = h.record;
    assertEquals(want.get("key_id"), r.key.substring(0, r.key.indexOf('.')), name);
    assertEquals(want.get("gateway_url"), r.gateway.isEmpty() ? null : r.gateway, name);
    assertEquals(want.get("destination"), r.destination.isEmpty() ? null : r.destination, name);
    assertEquals(want.get("dashboard_url"), r.dashboardUrl.isEmpty() ? null : r.dashboardUrl, name);
    assertEquals(want.get("expires_at"), r.expiresRaw.isEmpty() ? null : r.expiresRaw, name);
    assertEquals(new TreeSet<>((List<String>) want.get("ignored")), new TreeSet<>(r.ignored), name);
    assertEquals(r.ignored.size(), r.warnings.size(), name);
  }

  static String perms(String octal) {
    int m = Integer.parseInt(octal, 8);
    String bits = "rwxrwxrwx";
    StringBuilder b = new StringBuilder();
    for (int i = 0; i < 9; i++) {
      b.append((m & (1 << (8 - i))) != 0 ? bits.charAt(i) : '-');
    }
    return b.toString();
  }

  // --- what the cases leave to each SDK ----------------------------------------------------

  @Test
  void the_record_format_extras() {
    for (String[] c :
        new String[][] {
          {"id.s\nname=caf\u00e9\n", SdkFile.R_BAD_NAME_LINE},
          {"id.caf\u00e9\n", SdkFile.R_BAD_KEY_LINE},
          {"id.s\u0001\n", SdkFile.R_BAD_KEY_LINE},
          {"\n", SdkFile.R_BAD_KEY_LINE},
          {"id.s\ngateway_url=https://gw.example.com\n\n", SdkFile.R_BAD_NAME_LINE},
        }) {
      SdkFile.Record r = SdkFile.parse(c[0].getBytes(StandardCharsets.UTF_8));
      assertFalse(r.problem.isEmpty(), c[0]);
      assertEquals(c[1], r.reason, c[0]);
      assertEquals("", r.key);
      assertFalse(r.problem.contains("id."), "a refusal names the key");
    }
    assertEquals("online", SdkFile.parse(body("destination=ONLINE").getBytes(StandardCharsets.US_ASCII)).destination);
    SdkFile.Record r = SdkFile.parse(body("gateway_url=" + GW + "/", "dashboard_url=https://u-k7x2.superbased.app/").getBytes(StandardCharsets.US_ASCII));
    assertEquals(GW, r.gateway);
    assertEquals(GW, r.dashboardUrl);
  }

  @Test
  void the_expiry_warning(@TempDir Path dir) throws Exception {
    Assumptions.assumeFalse(SdkFile.windows(), "written with unix modes");
    Instant now = Instant.parse("2027-04-01T00:00:00Z");
    Object[][] cases = {
      {"2027-06-01T00:00:00Z", false, ""},
      {"2027-04-10T00:00:00Z", false, "your SDK key expires on 2027-04-10; run setup again"},
      {"2027-03-01T00:00:00Z", true, "expired on 2027-03-01, so it is not used: run setup again"},
    };
    for (Object[] c : cases) {
      SdkFile.Held h = SdkFile.read(held(dir, body("gateway_url=" + GW, "expires_at=" + c[0]), "rw-------").toString(), "", now);
      assertTrue(h.ok);
      assertEquals(c[1], h.expired);
      assertEquals(!(Boolean) c[1], h.usable());
      String w = String.join("|", h.warnings);
      if (((String) c[2]).isEmpty()) {
        assertEquals("", w);
      } else {
        assertTrue(w.contains((String) c[2]), w);
      }
    }
  }

  @Test
  void the_windows_rule_over_facts() {
    SdkFile.WindowsFacts ok = new SdkFile.WindowsFacts();
    ok.regularFile = true;
    ok.insideRoot = true;
    ok.ownerIsUser = true;
    assertEquals("", SdkFile.windowsProblem(ok)[0]);
    SdkFile.WindowsFacts f = new SdkFile.WindowsFacts();
    f.regularFile = true;
    f.insideRoot = true;
    f.ownerIsUser = true;
    f.reparsePoint = true;
    assertEquals(SdkFile.R_REPARSE_POINT, SdkFile.windowsProblem(f)[1]);
    f.reparsePoint = false;
    f.symlink = true;
    assertEquals(SdkFile.R_REPARSE_POINT, SdkFile.windowsProblem(f)[1]);
    f.symlink = false;
    f.insideRoot = false;
    assertEquals(SdkFile.R_OUTSIDE_LOCALAPPDATA, SdkFile.windowsProblem(f)[1]);
    f.insideRoot = true;
    f.ownerIsUser = false;
    assertEquals(SdkFile.R_OWNER, SdkFile.windowsProblem(f)[1]);
    f.ownerIsUser = true;
    f.regularFile = false;
    assertEquals(SdkFile.R_NOT_REGULAR, SdkFile.windowsProblem(f)[1]);

    String base = "C:\\Users\\me\\AppData\\Local";
    assertTrue(SdkFile.insideWindowsRoot("\\\\?\\C:\\Users\\me\\AppData\\Local\\superbased\\sdk-credential", base));
    assertTrue(SdkFile.insideWindowsRoot("c:\\users\\ME\\appdata\\local\\superbased\\sdk-credential", base));
    assertTrue(SdkFile.insideWindowsRoot("C:/Users/me/AppData/Local/superbased/sdk-credential", base));
    assertFalse(SdkFile.insideWindowsRoot("C:\\Users\\me\\AppData\\LocalLow\\sdk-credential", base));
    assertFalse(SdkFile.insideWindowsRoot("C:\\Users\\me\\AppData\\Local", base));
    assertFalse(SdkFile.insideWindowsRoot("C:\\Users\\someone\\AppData\\Local\\superbased\\sdk-credential", base));
    assertFalse(SdkFile.insideWindowsRoot("D:\\keys\\sdk-credential", base));
    assertFalse(SdkFile.insideWindowsRoot("C:\\x", ""));
  }

  static Map<String, Object> machine(String dest, boolean signedIn, String credFile) {
    Map<String, Object> online = new LinkedHashMap<>();
    if (credFile != null) {
      online.put("credential_present", true);
      online.put("credential_file", credFile);
      online.put("dashboard_url", "https://acme.superbased.app");
    }
    Map<String, Object> b = new LinkedHashMap<>();
    b.put("api_version", 1L);
    b.put("destination", dest);
    b.put("signed_in", signedIn);
    b.put("local", Map.of("enabled", true));
    b.put("online", online);
    b.put("warnings", List.of());
    return b;
  }

  static Destination.Plan plan(Path file, Map<String, String> extra, Map<String, Object> machine, String explicitDest) {
    Map<String, String> e = new HashMap<>();
    e.put(SdkFile.ENV_CREDENTIAL_FILE, file.toString());
    e.put("SUPERBASED_DISCOVER", "1");
    e.put("SUPERBASED_NODE_URL", "http://127.0.0.1:9");
    e.putAll(extra);
    Destination.Discoverer orig = Destination.discoverer;
    Destination.discoverer = n -> machine == null ? new Destination.Discovered(null, "no machine (test)") : new Destination.Discovered(machine, "");
    try {
      Destination.resetCacheForTests();
      InitOptions o = explicitDest == null ? InitOptions.defaults() : InitOptions.builder().destination(explicitDest).build();
      return Destination.resolve(Settings.resolve(e, o), e, explicitDest, null, null, false);
    } finally {
      Destination.discoverer = orig;
    }
  }

  @Test
  void whole_records_and_the_files_key_goes_only_to_its_own_gateway(@TempDir Path dir) throws Exception {
    Assumptions.assumeFalse(SdkFile.windows(), "written with unix modes");
    Path online = held(dir, ONLINE, "rw-------");
    Destination.Plan p = plan(online, Map.of(), null, null);
    assertEquals(KEY, p.key);
    assertEquals(GW, p.gatewayUrl);
    assertEquals(GW, p.onlineDashboard);
    assertEquals("", p.localDashboard);
    assertEquals(GW + "/v1/traces", p.exporters.get(0).endpoint);
    assertEquals(GW + "/v1/sdk/admit", p.admitUrl);

    Path loose = held(dir, "ik_9a.s3cr3t\ngateway_url=https://gw.example.com\n", "rw-r--r--");
    p = plan(online, Map.of(), machine("both", true, loose.toString()), null);
    assertEquals(KEY, p.key, "the machine's file refused: the SDK-held record is used");
    assertEquals("sdk_file", p.credentialSource);

    Path noGateway = held(dir, "ik_9a.s3cr3t\n", "rw-------");
    p = plan(online, Map.of(), machine("both", true, noGateway.toString()), null);
    assertFalse(p.onlineReady, "a machine key is never paired with the file's gateway");
    assertEquals("file", p.credentialSource);

    Path mf = held(dir, "ik_9a.s3cr3t\ngateway_url=https://gw.example.com\n", "rw-------");
    p = plan(online, Map.of(), machine("both", true, mf.toString()), null);
    assertEquals("https://acme.superbased.app", p.onlineDashboard, "the machine's key: discovery's dashboard");

    p = plan(online, Map.of("SUPERBASED_API_KEY", "ik_env.secret"), null, null);
    assertEquals("ik_env.secret", p.key);
    assertEquals(GW, p.gatewayUrl);
    assertEquals("env", p.credentialSource);
    assertEquals("unused", p.sdkFile.get("state"));
    assertEquals("", p.onlineDashboard, "record 1 has no link base");

    p = plan(online, Map.of("SUPERBASED_ORG_URL", "https://other.example.com"), null, null);
    assertEquals("", p.key);
    assertFalse(p.onlineReady);
    for (Destination.Target t : p.exporters) {
      assertFalse(t.key().contains(SECRET));
    }
    assertTrue(String.join("|", p.warnings).contains("not sent there"));

    p = plan(online, Map.of("SUPERBASED_ORG_URL", GW + "/"), null, null);
    assertEquals(KEY, p.key);
    assertTrue(p.onlineReady);

    p = plan(held(dir, body("destination=online"), "rw-------"), Map.of(), null, null);
    assertEquals("online", p.destination);
    assertFalse(p.onlineReady);
    assertTrue(p.degraded.contains("setup") && p.degraded.contains("gateway address"), p.degraded);

    p = plan(held(dir, body("gateway_url=" + GW), "rw-------"), Map.of(), null, null);
    assertEquals("local", p.destination, "a file key never makes the inferred rung");
    assertEquals("default", p.source);

    p = plan(held(dir, ONLINE, "rw-r-----"), Map.of(), null, null);
    assertEquals("refused", p.sdkFile.get("state"));
    assertEquals(SdkFile.R_MODE, p.sdkFile.get("reason"));
  }

  @Test
  void diagnostics_and_the_ai_gateway(@TempDir Path dir) throws Exception {
    Assumptions.assumeFalse(SdkFile.windows(), "written with unix modes");
    Path file = held(dir, ONLINE, "rw-------");
    Env.set(SdkFile.ENV_CREDENTIAL_FILE, file.toString());
    Superbased.init(InitOptions.builder().exporter(InMemorySpanExporter.create()).build());
    Map<String, Object> d = Superbased.diagnostics();
    assertEquals("sdk_file", d.get("credential_source"));
    assertEquals("sdk_file", d.get("destination_source"));
    assertEquals(Map.of("path", file.toString(), "state", "used", "reason", ""), d.get("sdk_file"));
    assertFalse(String.valueOf(d).contains(SECRET), "diagnostics carry the key");

    GatewayEndpoint ep = Gateway.endpoint(Gateway.PROVIDER_OPENAI, null);
    assertEquals(GW + "/ai/openai/v1", ep.baseUrl());
    assertEquals(Gateway.SOURCE_ORG, ep.source());
    Gateway.NotConfiguredException e = assertThrows(Gateway.NotConfiguredException.class, ep::apiKey);
    assertEquals(Gateway.PROBLEM_NO_KEY, e.problem());
    assertFalse(e.getMessage().contains(SECRET));

    Superbased.init(InitOptions.builder().exporter(InMemorySpanExporter.create()).destination("local").build());
    assertEquals("not_read", ((Map<String, Object>) Superbased.diagnostics().get("sdk_file")).get("state"));
  }

  // --- service name ---------------------------------------------------------------------------------

  @Test
  void the_service_name_ladder_edges() {
    assertEquals("Checkout API", ServiceName.ladder("  Checkout API ", env(), "").name);
    assertEquals("argument", ServiceName.ladder("Checkout API", env(), "").source);
    ServiceName.Resolved r = ServiceName.ladder("  ", env(), "bot");
    assertEquals("bot", r.name);
    assertEquals("manifest", r.source);
    r = ServiceName.ladder(null, env("SUPERBASED_SERVICE_NAME", "  "), "bot");
    assertEquals("manifest", r.source);
    assertEquals("support_bot-api", ServiceName.normalise("Support_Bot  API!"));
    assertEquals("support_bot", ServiceName.normalise("_support_bot_"));
    assertEquals(64, ServiceName.normalise("ab".repeat(40)).length());
    assertEquals("a".repeat(63), ServiceName.normalise("a".repeat(63) + "_b"));
    r = ServiceName.ladder(null, env(), "___");
    assertEquals("custom-app", r.name);
    assertEquals("default", r.source);
  }

  @Test
  void the_service_name_from_the_jar_manifest(@TempDir Path dir) throws Exception {
    Manifest m = new Manifest();
    m.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    m.getMainAttributes().put(Attributes.Name.IMPLEMENTATION_TITLE, "Support Bot");
    Path jar = dir.resolve("app.jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar), m)) {
      out.flush();
    }
    assertEquals("Support Bot", ServiceName.jarTitle(jar.toString()));
    assertEquals("", ServiceName.jarTitle(dir.resolve("missing.jar").toString()));
    ServiceName.project = () -> ServiceName.jarTitle(jar.toString());
    Settings s = Superbased.init(InitOptions.builder().exporter(InMemorySpanExporter.create()).destination("local").build());
    assertEquals("support-bot", s.serviceName());
    assertEquals("manifest", s.serviceNameSource());
    assertEquals("manifest", Superbased.diagnostics().get("service_name_source"));
    Env.set("OTEL_SERVICE_NAME", "from-env");
    assertEquals("env", Superbased.init(InitOptions.builder().exporter(InMemorySpanExporter.create()).destination("local").build()).serviceNameSource());
  }

  // --- first-trace line -----------------------------------------------------------------------------

  @Test
  void the_first_trace_gate() {
    assertTrue(FirstTrace.allowed(true, env()));
    assertFalse(FirstTrace.allowed(false, env()));
    assertFalse(FirstTrace.allowed(true, env("CI", "true")));
    assertFalse(FirstTrace.allowed(true, env("CI", "1")));
    assertTrue(FirstTrace.allowed(true, env("CI", "")));
    assertTrue(FirstTrace.allowed(true, env("CI", "0")));
    assertTrue(FirstTrace.allowed(true, env("CI", "False")));
    assertFalse(FirstTrace.allowed(true, env(FirstTrace.ENV, "0")));
    assertFalse(FirstTrace.allowed(true, env(FirstTrace.ENV, "off")));
    assertFalse(FirstTrace.allowed(true, env(FirstTrace.ENV, "FALSE")));
    assertTrue(FirstTrace.allowed(true, env(FirstTrace.ENV, "1")));
  }

  @Test
  void the_tracker_under_both() {
    String a = "4bf92f3577b34da6a3ce929d0e0e4736";
    String b = "0af7651916cd43dd8448eb211c80319c";
    FirstTrace.Bases both = new FirstTrace.Bases("http://127.0.0.1:8081", "https://o", true);
    String[][] want = {
      {"online fails first, then local succeeds", "http://127.0.0.1:8081/apps/traces?trace=" + a},
      {"local waits, online succeeds later", "https://o/trajectories?trace=" + a},
      {"the first local success is kept", "http://127.0.0.1:8081/apps/traces?trace=" + a},
      {"a gate that says no ends it for good", ""},
    };
    for (int i = 0; i < want.length; i++) {
      FirstTrace.Tracker tr = new FirstTrace.Tracker();
      ByteArrayOutputStream buf = new ByteArrayOutputStream();
      PrintStream ps = new PrintStream(buf, true, StandardCharsets.UTF_8);
      switch (i) {
        case 0:
          tr.note(both, "online", a, false, null, () -> true, ps);
          tr.note(both, "local", a, true, null, () -> true, ps);
          break;
        case 1:
          tr.note(both, "local", a, true, null, () -> true, ps);
          tr.note(both, "online", a, true, null, () -> true, ps);
          break;
        case 2:
          tr.note(both, "local", a, true, null, () -> true, ps);
          tr.note(both, "local", b, true, null, () -> true, ps);
          tr.note(both, "online", b, false, null, () -> true, ps);
          break;
        default:
          FirstTrace.Bases local = new FirstTrace.Bases("http://l", "", false);
          tr.note(local, "local", a, true, null, () -> false, ps);
          tr.note(local, "local", b, true, null, () -> true, ps);
      }
      String got = buf.toString(StandardCharsets.UTF_8).strip();
      assertEquals(want[i][1].isEmpty() ? "" : FirstTrace.PREFIX + want[i][1], got, want[i][0]);
      assertEquals(want[i][1], tr.printed(), want[i][0]);
    }
  }

  List<String> firstTraceRun(Path dir, boolean terminal, int roots, String[] firstId) throws Exception {
    Env.set(SdkFile.ENV_CREDENTIAL_FILE, held(dir, ONLINE, "rw-------").toString());
    FirstTrace.terminal = () -> terminal;
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    FirstTrace.out = new PrintStream(buf, true, StandardCharsets.UTF_8);
    Superbased.init(InitOptions.builder().exporter(InMemorySpanExporter.create()).build());
    for (int i = 0; i < roots; i++) {
      try (SbSpan root = Superbased.span("root").start()) {
        if (i == 0) {
          firstId[0] = root.traceId();
        }
        try (SbSpan child = Superbased.span("child").start()) {
          child.ok();
        }
      }
      Superbased.flush(Duration.ofSeconds(5));
    }
    List<String> lines = new ArrayList<>();
    for (String l : buf.toString(StandardCharsets.UTF_8).split("\n")) {
      if (l.startsWith("superbased: ")) {
        lines.add(l);
      }
    }
    return lines;
  }

  @Test
  void the_first_trace_line_through_exports(@TempDir Path dir) throws Exception {
    Assumptions.assumeFalse(SdkFile.windows(), "written with unix modes");
    Env.set("CI", null);
    String[] id = new String[1];
    List<String> lines = firstTraceRun(dir, true, 3, id);
    String link = "https://u-k7x2.superbased.app/trajectories?trace=" + id[0];
    assertEquals(List.of(FirstTrace.PREFIX + link), lines);
    assertEquals(link, Superbased.diagnostics().get("first_trace_link"));
    assertFalse(logs.stream().anyMatch(l -> l.contains("first trace")), "the line went to the logger");
  }

  @Test
  void no_first_trace_line_off_a_terminal_or_under_ci(@TempDir Path dir) throws Exception {
    Assumptions.assumeFalse(SdkFile.windows(), "written with unix modes");
    Env.set("CI", null);
    assertTrue(firstTraceRun(dir, false, 1, new String[1]).isEmpty());
    Superbased.resetForTests();
    Env.set("CI", "true");
    assertTrue(firstTraceRun(dir, true, 1, new String[1]).isEmpty());
    Superbased.resetForTests();
    Env.set("CI", null);
    Env.set(FirstTrace.ENV, "0");
    assertTrue(firstTraceRun(dir, true, 1, new String[1]).isEmpty());
    assertEquals("", Superbased.diagnostics().get("first_trace_link"));
  }

  @Test
  void a_child_only_batch_has_no_root() {
    assertEquals("", FirstTrace.rootTraceId(List.<SpanData>of()));
    InMemorySpanExporter mem = InMemorySpanExporter.create();
    Superbased.init(InitOptions.builder().exporter(mem).destination("local").build());
    try (SbSpan root = Superbased.span("root").start()) {
      try (SbSpan child = Superbased.span("child").start()) {
        child.ok();
      }
      Superbased.flush(Duration.ofSeconds(5));
      assertEquals("", FirstTrace.rootTraceId(mem.getFinishedSpanItems()));
    }
    Superbased.flush(Duration.ofSeconds(5));
    assertFalse(FirstTrace.rootTraceId(mem.getFinishedSpanItems()).isEmpty());
  }
}
