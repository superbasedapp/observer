package app.superbased.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.data.SpanData;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The other shared contract files both SDKs run: prompt-compile-cases.json,
 * prompt-rollout-cases.json with the recorded rollout fetch, and
 * sdk-attribute-keys.json (the SDK writes only listed keys).
 */
@SuppressWarnings("unchecked")
class ContractFilesTest extends SdkTestBase {

  @Test
  void shared_compile_cases() throws Exception {
    List<Object> cases = (List<Object>) loadContract("prompt-compile-cases.json").get("cases");
    assertTrue(cases.size() >= 10);
    for (Object o : cases) {
      Map<String, Object> c = (Map<String, Object>) o;
      String name = String.valueOf(c.get("name"));
      Prompt p = Prompt.of("p", 1, (String) c.get("type"), c.get("prompt"));
      TreeSet<String> vars = new TreeSet<>(Json::compareCodePoints);
      if ("chat".equals(c.get("type"))) {
        for (Object m : (List<Object>) c.get("prompt")) {
          vars.addAll(Prompt.placeholders((String) ((Map<String, Object>) m).get("content")));
        }
      } else {
        vars.addAll(Prompt.placeholders((String) c.get("prompt")));
      }
      assertEquals(c.get("variables"), new ArrayList<>(vars), name);
      Map<String, Object> values = (Map<String, Object>) c.get("values");
      if (c.containsKey("missing")) {
        PromptException.CompileFailed e = assertThrows(PromptException.CompileFailed.class, () -> p.compile(values), name);
        assertEquals(c.get("missing"), e.missing(), name);
      } else {
        assertEquals(c.get("want"), p.compile(values), name);
      }
    }
  }

  @Test
  void compile_never_mutates_and_renders_numbers() {
    List<Map<String, Object>> msgs = new ArrayList<>();
    msgs.add(new LinkedHashMap<>(Map.of("role", "user", "content", "{{n}} items, ok={{ok}}")));
    Prompt p = Prompt.of("p", 1, "chat", msgs);
    assertEquals(List.of(Map.of("role", "user", "content", "3 items, ok=true")), p.compile(Map.of("n", 3, "ok", true)));
    assertEquals("{{n}} items, ok={{ok}}", p.messages().get(0).get("content"));
  }

  @Test
  void rollout_cases_bucket_like_the_cohort_engine() throws Exception {
    List<Object> cases = (List<Object>) loadContract("prompt-rollout-cases.json").get("cases");
    assertTrue(cases.size() >= 25);
    for (Object o : cases) {
      Map<String, Object> c = (Map<String, Object>) o;
      assertEquals(c.get("hash"), Prompts.cohortHash((String) c.get("id")));
      assertEquals(c.get("subject"), c.get("key") + ":" + c.get("hash"));
      int b = Prompts.rolloutBucket((String) c.get("salt"), (String) c.get("subject"));
      assertEquals(((Long) c.get("bucket")).intValue(), b, c.toString());
      assertEquals(c.get("candidate"), b < ((Long) c.get("percent")).intValue());
    }
  }

  private static Map<String, String> query(Stub.Req r) {
    Map<String, String> out = new HashMap<>();
    for (String kv : r.query().split("&")) {
      int eq = kv.indexOf('=');
      if (eq > 0) {
        out.put(kv.substring(0, eq), URLDecoder.decode(kv.substring(eq + 1), StandardCharsets.UTF_8));
      }
    }
    return out;
  }

  @Test
  void rollout_sends_only_the_hash_and_caches_one_copy_per_side() throws Exception {
    Map<String, Object> fx = loadContract("prompt-fetch-rollout-response.json");
    Map<String, Map<String, Object>> legs = new HashMap<>();
    for (Object l : (List<Object>) fx.get("legs")) {
      legs.put((String) ((Map<String, Object>) l).get("name"), (Map<String, Object>) l);
    }
    String candidateHash = ((String) legs.get("candidate").get("query")).split("user_hash=")[1];
    try (Stub stub = new Stub()) {
      stub.route(
          "GET",
          "/v1/sdk/prompts/support-reply",
          r -> {
            Map<String, String> q = query(r);
            String h = q.containsKey("user_hash") ? q.get("user_hash") : q.get("session_hash");
            Map<String, Object> leg =
                h == null ? legs.get("unkeyed") : (h.equals(candidateHash) ? legs.get("candidate") : legs.get("base"));
            String etag = (String) ((Map<String, Object>) leg.get("headers")).get("Etag");
            return new Stub.Answer(200, leg.get("body"), Map.of("ETag", etag));
          });
      InMemorySpanExporter mem = InMemorySpanExporter.create();
      Superbased.init(InitOptions.builder().exporter(mem).destination("online").orgUrl(stub.url).apiKey("k").discover(false).build());
      Prompt p;
      try (SbSpan s = Superbased.span("handler").start();
          AttributeScope a = Superbased.propagateAttributes(TraceAttributes.builder().user("Ünïcode user").build())) {
        p = Superbased.getPrompt("support-reply");
      }
      assertEquals(4, p.version());
      assertEquals("candidate", p.cohort());
      assertEquals(20, p.rollout().percent());
      Stub.Req last = stub.requests.get(stub.requests.size() - 1);
      assertEquals(Prompts.cohortHash("Ünïcode user"), query(last).get("user_hash"));
      assertFalse(last.path.contains("Ünïcode"));
      try (AttributeScope a = Superbased.propagateAttributes(TraceAttributes.builder().user("alice@example.com").build())) {
        assertEquals(3, Superbased.getPrompt("support-reply").version());
      }
      int n = stub.requests.size();
      try (AttributeScope a = Superbased.propagateAttributes(TraceAttributes.builder().user("alice@example.com").build())) {
        assertEquals("base", Superbased.getPrompt("support-reply").cohort());
      }
      assertEquals(n, stub.requests.size());
      assertEquals("unkeyed", Superbased.getPrompt("support-reply").cohort());
      Map<String, String> q = query(stub.requests.get(stub.requests.size() - 1));
      assertFalse(q.containsKey("user_hash") || q.containsKey("session_hash"));
      assertEquals(List.of("base", "candidate", "unkeyed"), Prompts.CACHE.sidesOf("support-reply"));
      Superbased.flush(Duration.ofSeconds(5));
      SpanData handler = mem.getFinishedSpanItems().get(0);
      assertEquals(4L, handler.getAttributes().get(AttributeKey.longKey("sbo.prompt.version")));
      assertEquals("candidate", handler.getAttributes().get(AttributeKey.stringKey("sbo.prompt.cohort")));
      assertEquals("production", handler.getAttributes().get(AttributeKey.stringKey("sbo.prompt.label")));
    }
  }

  @Test
  void keys_class_matches_the_contract() throws Exception {
    Map<String, Object> c = loadContract("sdk-attribute-keys.json");
    assertEquals(new HashSet<>((List<Object>) c.get("content_keys")), new HashSet<Object>(Keys.CONTENT_KEYS));
    assertEquals(c.get("content_prefixes"), Keys.CONTENT_PREFIXES);
    assertEquals(c.get("content_prefix_exempt_suffixes"), Keys.CONTENT_PREFIX_EXEMPT_SUFFIXES);
    assertEquals(c.get("extra_content_prefixes"), Keys.EXTRA_CONTENT_PREFIXES);
    Map<String, Object> limits = (Map<String, Object>) c.get("limits");
    assertEquals((long) Keys.MAX_VALUE_LEN, limits.get("max_value_len"));
    assertEquals((long) Keys.MAX_TAGS, limits.get("max_tags"));
    assertEquals((long) Keys.MAX_TAG_LEN, limits.get("max_tag_len"));
    assertEquals((long) Keys.MAX_METADATA_KEYS, limits.get("max_metadata_keys"));
    assertEquals((long) Keys.MAX_METADATA_KEY_LEN, limits.get("max_metadata_key_len"));
    assertEquals((long) Keys.MAX_METADATA_VALUE_LEN, limits.get("max_metadata_value_len"));
    Set<Object> keys = allowedKeys(c);
    List<Object> prefixes = allowedPrefixes(c);
    for (Field f : Keys.class.getDeclaredFields()) {
      if (Modifier.isStatic(f.getModifiers()) && f.getType() == String.class) {
        String v = (String) f.get(null);
        assertTrue(keys.contains(v) || prefixes.contains(v), "Keys." + f.getName() + " = " + v + " is not in the contract");
      }
    }
    for (String v : Keys.REQUEST_PARAMS.values()) {
      assertTrue(keys.contains(v), v);
    }
  }

  private static Set<Object> allowedKeys(Map<String, Object> c) {
    Set<Object> keys = new HashSet<>((List<Object>) c.get("vocabulary"));
    keys.addAll((List<Object>) c.get("sdk_owned"));
    keys.addAll((List<Object>) c.getOrDefault("pending_vocabulary", List.of()));
    return keys;
  }

  private static List<Object> allowedPrefixes(Map<String, Object> c) {
    List<Object> p = new ArrayList<>((List<Object>) c.get("vocabulary_prefixes"));
    p.addAll((List<Object>) c.getOrDefault("sdk_owned_prefixes", List.of()));
    return p;
  }

  @Test
  void every_emitted_key_is_in_the_contract() throws Exception {
    Map<String, Object> c = loadContract("sdk-attribute-keys.json");
    try (Stub stub = new Stub()) {
      stub.reply(Map.of("allowed", true, "decision", "allow", "verdict_id", "v1"));
      InMemorySpanExporter mem = InMemorySpanExporter.create();
      Superbased.init(
          InitOptions.builder()
              .exporter(mem)
              .tenant("t")
              .user("u")
              .sessionId("s")
              .release("r")
              .environment("e")
              .tags(List.of("x"))
              .metadata(Map.of("m", "1"))
              .build());
      TraceAttributes ta =
          TraceAttributes.builder()
              .user("u2")
              .sessionId("s2")
              .tenant("t2")
              .tags(List.of("y"))
              .metadata(Map.of("k", "v"))
              .release("r2")
              .environment("e2")
              .build();
      try (AttributeScope a = Superbased.propagateAttributes(ta);
          SbSpan agent = Superbased.agentSpan("agent").agentId("a1").start()) {
        try (SbSpan s =
            Superbased.llmSpan("llm").model("m").provider("p").prompt(List.of(Map.of("role", "user", "content", "hi"))).system("s").start()) {
          Superbased.admit("hi", AdmitOptions.builder().endpoint(stub.url).build());
          s.setUsage(
              Usage.builder()
                  .inputTokens(1)
                  .outputTokens(1)
                  .totalTokens(2)
                  .cacheReadTokens(0)
                  .cacheWriteTokens(0)
                  .reasoningTokens(0)
                  .responseId("r")
                  .requestId("q")
                  .responseModel("m")
                  .finishReasons(List.of("stop"))
                  .costUsd(0.1)
                  .response("yo")
                  .build());
          s.setRequestParams(
              RequestParams.builder()
                  .maxTokens(1)
                  .temperature(0.1)
                  .topP(1.0)
                  .topK(1)
                  .stopSequences(List.of("x"))
                  .frequencyPenalty(0)
                  .presencePenalty(0)
                  .seed(1)
                  .stream(false)
                  .reasoningLevel("low")
                  .build());
        }
        try (SbSpan s2 = Superbased.llmSpan("llm2").prompt("text").start()) {
          s2.setContent(null, "text");
        }
        try (SbSpan t = Superbased.toolSpan("tool").callId("c").arguments(Map.of("a", 1)).start()) {
          t.setToolResult("ok");
        }
        try (SbSpan r = Superbased.retrieverSpan("ret").query("q").start()) {
          r.setDocuments(List.of("d"));
        }
        try (SbSpan e = Superbased.embeddingSpan("emb").model("e").provider("p").start()) {
          e.setAttribute(Keys.INPUT_TOKENS, 3L);
        }
        try (SbSpan ch = Superbased.span("chain").start()) {
          ch.setInput("i");
          ch.setOutput("o");
        }
      }
      assertTrue(Superbased.flush(Duration.ofSeconds(5)));
      Set<Object> keys = allowedKeys(c);
      List<Object> prefixes = allowedPrefixes(c);
      Set<String> seen = new TreeSet<>();
      for (SpanData sp : mem.getFinishedSpanItems()) {
        sp.getAttributes().forEach((k, v) -> seen.add(k.getKey()));
        sp.getResource().getAttributes().forEach((k, v) -> seen.add(k.getKey()));
      }
      List<String> unknown = new ArrayList<>();
      for (String k : seen) {
        if (k.startsWith("telemetry.sdk.") || k.equals("service.instance.id")) {
          continue; // the OTel SDK's own resource keys
        }
        boolean ok = keys.contains(k) || prefixes.stream().anyMatch(p -> k.startsWith((String) p));
        if (!ok) {
          unknown.add(k);
        }
      }
      assertEquals(List.of(), unknown, "keys the contract does not list");
      for (String k :
          List.of(Keys.CACHE_READ_TOKENS, Keys.TOOL_ARGUMENTS, Keys.RETRIEVAL_DOCUMENTS, Keys.AGENT_ID, Keys.TAGS, Keys.ADMISSION_VERDICT_ID)) {
        assertTrue(seen.contains(k), k);
      }
    }
  }
}
