// Dry-run canary for one Java example: no provider call, ever.
//
// The runner starts it with the JDK's single-file source launcher
// (`java -cp <the example's classpath> Canary.java <json>`), so it compiles in
// memory against the example's own resolved classpath (the SDK installed from
// this checkout, Gson) and nothing is written into the example's tree.
//
// It checks that init() resolves a destination and exports one synthetic
// trace (a root AGENT span and one manual LLM span with fixed usage) that
// verify.py then checks on the machine and/or the org. The Java SDK has no
// instrument(): the Java examples call the SDK directly. With "admit_probe"
// it also calls admit(<text>) and records the verdict. Provider keys are
// stripped from the environment by the runner.
//
// Argument: one JSON object
//   {"service": "...", "model": "...", "provider": "...", "out": "/path/run.json", "admit_probe": ""}

import app.superbased.sdk.AttributeScope;
import app.superbased.sdk.InitOptions;
import app.superbased.sdk.Kind;
import app.superbased.sdk.SbSpan;
import app.superbased.sdk.Superbased;
import app.superbased.sdk.TraceAttributes;
import app.superbased.sdk.Usage;
import app.superbased.sdk.Verdict;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class Canary {
  static final int INPUT = 1000, OUTPUT = 100, CACHED = 0;

  static String str(JsonObject o, String k) {
    return o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsString() : "";
  }

  public static void main(String[] args) throws Exception {
    JsonObject a = new Gson().fromJson(args[0], JsonObject.class);
    String service = str(a, "service"), model = str(a, "model"), provider = str(a, "provider");
    String out = str(a, "out"), probe = str(a, "admit_probe");
    String runId = System.getenv("RUN_ID");
    if (runId == null || runId.isEmpty()) {
      runId = String.valueOf(System.currentTimeMillis() / 1000);
    }
    Superbased.init(InitOptions.builder().serviceName(service).release("planea-e2e-canary").build());

    String user = "user-ada", session = "canary-" + runId, tenant = "acme";
    List<String> traceIds = new ArrayList<>();
    List<Map<String, Object>> verdicts = new ArrayList<>();
    TraceAttributes who = TraceAttributes.builder().user(user).sessionId(session).tenant(tenant).build();
    try (AttributeScope ignored = Superbased.propagateAttributes(who)) {
      try (SbSpan root = Superbased.span("canary-turn").kind(Kind.AGENT).start()) {
        traceIds.add(Superbased.getCurrentTraceId());
        try (SbSpan s = Superbased.llmSpan("canary-chat").model(model).provider(provider).start()) {
          s.setUsage(Usage.builder().inputTokens(INPUT).outputTokens(OUTPUT).cacheReadTokens(CACHED)
              .responseModel(model).response("canary").build());
        }
        root.ok();
      }
      if (!probe.isEmpty()) {
        Verdict v = Superbased.admit(probe);
        Map<String, Object> vr = new LinkedHashMap<>();
        vr.put("probe", probe);
        vr.put("decision", v.decision());
        vr.put("allowed", v.allowed());
        vr.put("mode", v.mode());
        vr.put("degraded", v.degraded());
        verdicts.add(vr);
      }
    }
    Superbased.flush();
    Map<String, Object> all = Superbased.diagnostics();
    Map<String, Object> diag = new LinkedHashMap<>();
    for (String k : List.of("destination", "destination_source", "destinations", "signed_in", "credential_source",
        "failed_exports", "dropped_spans", "warnings")) {
      if (all.containsKey(k)) {
        diag.put(k, all.get(k));
      }
    }
    Map<String, Object> call = new LinkedHashMap<>();
    call.put("kind", "canary");
    call.put("input", INPUT);
    call.put("output", OUTPUT);
    call.put("cached", CACHED);
    Map<String, Object> record = new LinkedHashMap<>();
    record.put("service", service);
    record.put("run_id", runId);
    record.put("user", user);
    record.put("session", session);
    record.put("tenant", tenant);
    record.put("trace_ids", traceIds);
    record.put("calls", List.of(call));
    record.put("instrument", Map.of());
    record.put("verdicts", verdicts);
    record.put("diagnostics", diag);
    String json = new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create().toJson(record);
    Files.writeString(Path.of(out), json, StandardCharsets.UTF_8);
    Superbased.shutdown();
  }
}
