package app.superbased.sdk;

import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.context.Context;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Options of a span about to start, from {@link Superbased#span},
 * {@link Superbased#llmSpan}, {@link Superbased#toolSpan},
 * {@link Superbased#retrieverSpan}, {@link Superbased#agentSpan} or
 * {@link Superbased#embeddingSpan}. Each option applies to the kinds the
 * contract lists for it (sdk-api-surface.md section 3) and is ignored
 * otherwise. Then {@link #start()} (try-with-resources), {@link #call} or
 * {@link #run}.
 */
public final class SpanStarter {
  private final String name;
  private final String helper; // "span", "llm", "tool", "retriever", "agent", "embedding"
  private String kind;
  private final Map<String, Object> attributes = new LinkedHashMap<>();
  private String model;
  private String provider;
  private String operation = "chat";
  private Object prompt;
  private Object system;
  private String toolName;
  private String callId;
  private Object arguments;
  private Object query;
  private String agentName;
  private String agentId;
  private Context parent;

  SpanStarter(String name, String helper, String kind) {
    this.name = name;
    this.helper = helper;
    this.kind = kind;
  }

  /** The OpenInference kind of a plain {@code span(...)} (default CHAIN). */
  public SpanStarter kind(String v) {
    if (helper.equals("span") && v != null) {
      kind = v;
    }
    return this;
  }

  /** Extra attributes set when the span starts (applied last). */
  public SpanStarter attribute(String key, Object value) {
    attributes.put(key, value);
    return this;
  }

  /** Extra attributes set when the span starts (applied last). */
  public SpanStarter attributes(Map<String, ?> v) {
    if (v != null) {
      attributes.putAll(v);
    }
    return this;
  }

  /** LLM and embedding spans: {@code gen_ai.request.model}. */
  public SpanStarter model(String v) {
    model = v;
    return this;
  }

  /** LLM and embedding spans: {@code gen_ai.provider.name}. */
  public SpanStarter provider(String v) {
    provider = v;
    return this;
  }

  /** LLM spans: {@code gen_ai.operation.name} (default chat). */
  public SpanStarter operation(String v) {
    if (v != null) {
      operation = v;
    }
    return this;
  }

  /**
   * LLM spans: a string goes to {@code input.value}, a list of message maps
   * to {@code gen_ai.input.messages}; a {@link Prompt} from
   * {@link Superbased#getPrompt} stamps {@code sbo.prompt.*} and is not
   * request content.
   */
  public SpanStarter prompt(Object v) {
    prompt = v;
    return this;
  }

  /** LLM spans: {@code gen_ai.system_instructions}. */
  public SpanStarter system(Object v) {
    system = v;
    return this;
  }

  /** Tool spans: {@code gen_ai.tool.name} (default: the span name). */
  public SpanStarter toolName(String v) {
    toolName = v;
    return this;
  }

  /** Tool spans: {@code gen_ai.tool.call.id}. */
  public SpanStarter callId(String v) {
    callId = v;
    return this;
  }

  /** Tool spans: {@code gen_ai.tool.call.arguments} (content; non-string JSON-encoded). */
  public SpanStarter arguments(Object v) {
    arguments = v;
    return this;
  }

  /** Retriever spans: {@code gen_ai.retrieval.query.text} (content). */
  public SpanStarter query(Object v) {
    query = v;
    return this;
  }

  /** Agent spans: {@code gen_ai.agent.name} (default: the span name). */
  public SpanStarter agentName(String v) {
    agentName = v;
    return this;
  }

  /** Agent spans: {@code gen_ai.agent.id}. */
  public SpanStarter agentId(String v) {
    agentId = v;
    return this;
  }

  /** Start under this parent context instead of the current one. */
  public SpanStarter parent(Context v) {
    parent = v;
    return this;
  }

  Map<String, Object> startAttributes() {
    Map<String, Object> a = new LinkedHashMap<>();
    a.put(Keys.SPAN_KIND, kind);
    switch (helper) {
      case "llm":
        a.put(Keys.OPERATION, operation);
        if (model != null && !model.isEmpty()) {
          a.put(Keys.REQUEST_MODEL, model);
          a.put(Keys.OI_MODEL, model);
        }
        if (provider != null && !provider.isEmpty()) {
          a.put(Keys.PROVIDER, provider);
          a.put(Keys.LEGACY_SYSTEM, provider);
          a.put(Keys.OI_PROVIDER, provider);
        }
        Object p = prompt;
        if (p instanceof Prompt) {
          a.putAll(((Prompt) p).attributes());
          p = null;
        }
        String body = Spans.content(p);
        if (body != null) {
          a.put(Spans.isMessageList(p) ? Keys.INPUT_MESSAGES : Keys.INPUT_VALUE, body);
        }
        String instr = Spans.content(system);
        if (instr != null) {
          a.put(Keys.SYSTEM_INSTRUCTIONS, instr);
        }
        break;
      case "tool":
        String tname = toolName != null && !toolName.isEmpty() ? toolName : name;
        a.put(Keys.OPERATION, "execute_tool");
        a.put(Keys.TOOL_NAME, tname);
        a.put(Keys.OI_TOOL_NAME, tname);
        if (callId != null && !callId.isEmpty()) {
          a.put(Keys.TOOL_CALL_ID, callId);
        }
        String args = Spans.content(arguments);
        if (args != null) {
          a.put(Keys.TOOL_ARGUMENTS, args);
        }
        break;
      case "retriever":
        a.put(Keys.OPERATION, "retrieval");
        String q = Spans.content(query);
        if (q != null) {
          a.put(Keys.RETRIEVAL_QUERY, q);
        }
        break;
      case "agent":
        String an = agentName != null && !agentName.isEmpty() ? agentName : name;
        a.put(Keys.OPERATION, "invoke_agent");
        a.put(Keys.AGENT_NAME, an);
        a.put(Keys.OI_AGENT_NAME, an);
        if (agentId != null && !agentId.isEmpty()) {
          a.put(Keys.AGENT_ID, agentId);
        }
        break;
      case "embedding":
        a.put(Keys.OPERATION, "embeddings");
        if (model != null && !model.isEmpty()) {
          a.put(Keys.REQUEST_MODEL, model);
        }
        if (provider != null && !provider.isEmpty()) {
          a.put(Keys.PROVIDER, provider);
          a.put(Keys.LEGACY_SYSTEM, provider);
        }
        break;
      default:
        break;
    }
    a.putAll(attributes);
    return a;
  }

  /** Start the span and make it current until {@link SbSpan#close()}. */
  public SbSpan start() {
    AttributesBuilder ab = Attributes.builder();
    for (Map.Entry<String, Object> e : startAttributes().entrySet()) {
      Attr.put(ab, e.getKey(), e.getValue());
    }
    io.opentelemetry.api.trace.SpanBuilder b = Superbased.tracer().spanBuilder(name).setAllAttributes(ab.build());
    if (parent != null) {
      b.setParent(parent);
    }
    Span sp = b.startSpan();
    Context ctx = (parent != null ? parent : Context.current()).with(sp);
    return new SbSpan(sp, ctx.makeCurrent());
  }

  /**
   * Run {@code fn} inside the span and return its value. An exception is
   * recorded once and sets ERROR (then rethrown); success sets OK unless the
   * body set a status.
   */
  public <T> T call(Function<SbSpan, T> fn) {
    try (SbSpan s = start()) {
      try {
        T out = fn.apply(s);
        s.ok();
        return out;
      } catch (RuntimeException | Error e) {
        s.recordException(e);
        throw e;
      }
    }
  }

  /** {@link #call} for a body with no value. */
  public void run(Consumer<SbSpan> fn) {
    call(
        s -> {
          fn.accept(s);
          return null;
        });
  }
}
