package example;

import app.superbased.sdk.AttributeScope;
import app.superbased.sdk.InitOptions;
import app.superbased.sdk.Kind;
import app.superbased.sdk.Prompt;
import app.superbased.sdk.PromptOptions;
import app.superbased.sdk.RequestParams;
import app.superbased.sdk.SbSpan;
import app.superbased.sdk.ScoreOptions;
import app.superbased.sdk.ScoreResult;
import app.superbased.sdk.Superbased;
import app.superbased.sdk.TraceAttributes;
import app.superbased.sdk.Usage;
import app.superbased.sdk.Verdict;
import com.google.gson.GsonBuilder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A chatbot built on the superbased Java SDK directly, with no framework.
 *
 * <p>Per turn: {@code admit()} screens the user's message before the model
 * runs; the system prompt comes from the prompt registry ({@code getPrompt},
 * label production), compiled with a variable, and stamps the span with its
 * version; a manual LLM span around a raw OpenAI call, with {@code setUsage}
 * (input, output, cached and reasoning tokens) and the response content; a
 * score per turn and end-user feedback; {@code getTraceCost()} for the turn's
 * trace once it is ingested; the end user, session and customer tenant on
 * every span. Writes run.json for ../../verify.py.
 */
public final class Chatbot {
  static final String SERVICE = env("SUPERBASED_SERVICE_NAME", "sdk-direct-chatbot");
  static final String RUN_ID = env("RUN_ID", Long.toString(System.currentTimeMillis() / 1000));
  static final String PROMPT = env("PROMPT_NAME", "support-system");
  static final List<String> TURNS =
      List.of(
          "Hi! What can you do?",
          "What is your return window?",
          "Tell me about competitor pricing."); // the admission policy refuses this one

  private Chatbot() {}

  static String env(String k, String d) {
    String v = System.getenv(k);
    return v == null || v.isEmpty() ? d : v;
  }

  static Map<String, Object> msg(String role, String content) {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("role", role);
    m.put("content", content);
    return m;
  }

  /** One model call inside an LLM span; returns the reply and records its usage in {@code calls}. */
  static String answer(Prompt prompt, String system, List<Map<String, Object>> history, String text, List<Map<String, Object>> calls)
      throws Exception {
    List<Map<String, Object>> messages = new ArrayList<>();
    messages.add(msg("system", system));
    messages.addAll(history);
    messages.add(msg("user", text));
    // prompt(<Prompt>) stamps the span with the registry prompt's name and
    // version (sbo.prompt.*); setContent records the messages actually sent.
    try (SbSpan s = Superbased.llmSpan("chat").model(OpenAi.MODEL).provider("openai").prompt(prompt).start()) {
      s.setContent(messages, null);
      s.setRequestParams(RequestParams.builder().maxTokens(400).build());
      OpenAi.Reply r;
      try {
        r = OpenAi.chat(messages, 400);
      } catch (Exception e) {
        s.recordException(e);
        throw e;
      }
      Map<String, Object> usage = new LinkedHashMap<>();
      usage.put("kind", "chat");
      usage.put("id", r.id);
      usage.put("input", r.input);
      usage.put("output", r.output);
      usage.put("cached", r.cached);
      usage.put("reasoning", r.reasoning);
      calls.add(usage);
      // inputTokens is the gross input (cache reads are part of it);
      // outputTokens includes the reasoning tokens.
      s.setUsage(
          Usage.builder()
              .inputTokens(r.input)
              .outputTokens(r.output)
              .cacheReadTokens(r.cached)
              .reasoningTokens(r.reasoning)
              .finishReason(r.finishReason)
              .responseId(r.id)
              .responseModel(r.model)
              .response(r.content)
              .build());
      return r.content;
    }
  }

  public static void main(String[] args) throws Exception {
    Superbased.init(InitOptions.builder().serviceName(SERVICE).release("examples-1").build());
    String user = "user-ada";
    String session = "sd-" + RUN_ID;
    String tenant = "acme";
    Prompt prompt =
        Superbased.getPrompt(PROMPT, PromptOptions.builder().fallback("You are a terse support bot. Answer in one sentence.").build());
    System.err.println("prompt: " + prompt.name() + " v" + prompt.version() + " label='" + prompt.label() + "'");
    String system = prompt.version() > 0 ? prompt.compileText(Map.of("company", "Acme Widgets")) : prompt.text();

    List<String> traceIds = new ArrayList<>();
    List<Map<String, Object>> calls = new ArrayList<>();
    List<Map<String, Object>> verdicts = new ArrayList<>();
    List<Map<String, Object>> scores = new ArrayList<>();
    List<Map<String, Object>> history = new ArrayList<>();
    TraceAttributes who = TraceAttributes.builder().user(user).sessionId(session).tenant(tenant).build();
    try (AttributeScope ignored = Superbased.propagateAttributes(who)) {
      for (int i = 1; i <= TURNS.size(); i++) {
        String text = TURNS.get(i - 1);
        String tid;
        Verdict v;
        String reply;
        try (SbSpan root = Superbased.span("turn-" + i).kind(Kind.AGENT).start()) {
          tid = Superbased.getCurrentTraceId();
          traceIds.add(tid);
          root.setInput(text);
          v = Superbased.admit(text);
          Map<String, Object> vr = new LinkedHashMap<>();
          vr.put("turn", i);
          vr.put("decision", v.decision());
          vr.put("allowed", v.allowed());
          vr.put("mode", v.mode());
          vr.put("degraded", v.degraded());
          vr.put("judge_used", v.judgeUsed());
          verdicts.add(vr);
          if (!v.allowed()) {
            reply = "Sorry, I can't help with that here.";
          } else {
            reply = answer(prompt, system, history, text, calls);
            history.add(msg("user", text));
            history.add(msg("assistant", reply));
          }
          root.setOutput(reply);
          // A toy evaluator: a support answer should be short.
          ScoreResult r =
              Superbased.score("concise", reply.length() <= 240, ScoreOptions.builder().scorer("length-check").scorerVersion("1").build());
          scores.add(Map.of("turn", i, "ok", r.ok(), "errors", r.errors()));
          root.ok();
        }
        ScoreResult fb = Superbased.feedback(true, ScoreOptions.builder().traceId(tid).comment("helpful").build());
        scores.add(Map.of("turn", i, "feedback_ok", fb.ok(), "errors", fb.errors()));
        System.out.println(
            "turn " + i + ": '" + text + "' -> '" + reply + "' (admit: " + v.decision() + (v.degraded().isEmpty() ? "" : ", " + v.degraded()) + ")");
      }
    }

    Superbased.flush();
    Map<String, Object> costs = new LinkedHashMap<>();
    for (String tid : traceIds) {
      Map<String, Object> cost = null;
      for (int k = 0; k < 20; k++) { // the cost exists once the spans are ingested
        cost = Superbased.getTraceCost(tid);
        if (cost != null && cost.get("spans") instanceof List && !((List<?>) cost.get("spans")).isEmpty()) {
          break;
        }
        Thread.sleep(1000);
      }
      Map<String, Object> c = null;
      if (cost != null) {
        c = new LinkedHashMap<>();
        c.put("cost_usd", cost.get("cost_usd"));
        Object prov = cost.get("cost_provenance");
        c.put("label", prov instanceof Map ? ((Map<?, ?>) prov).get("label") : null);
        c.put("from", cost.get("destination"));
      }
      costs.put(tid, c);
      System.out.println("cost " + tid + ": " + c);
    }

    Map<String, Object> diag = new LinkedHashMap<>();
    Map<String, Object> all = Superbased.diagnostics();
    for (String k : List.of("destination", "destinations", "failed_exports", "dropped_spans", "admission_degraded", "admission_last_error")) {
      diag.put(k, all.get(k));
    }
    Map<String, Object> record = new LinkedHashMap<>();
    record.put("service", SERVICE);
    record.put("run_id", RUN_ID);
    record.put("user", user);
    record.put("session", session);
    record.put("tenant", tenant);
    record.put("prompt", Map.of("name", prompt.name(), "version", prompt.version()));
    record.put("trace_ids", traceIds);
    record.put("calls", calls);
    record.put("verdicts", verdicts);
    record.put("scores", scores);
    record.put("costs", costs);
    record.put("diagnostics", diag);
    String json = new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create().toJson(record);
    Files.writeString(Path.of(env("RUN_OUT", "run.json")), json, StandardCharsets.UTF_8);
    System.err.println(diag);
    Superbased.shutdown();
  }
}
