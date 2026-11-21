package app.superbased.sdk;

import io.opentelemetry.api.trace.Span;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One prompt version as the registry served it ({@link Superbased#getPrompt}).
 * {@link #compile} fills the {@code {{variable}}} placeholders by the
 * registry's rules; using it stamps {@code sbo.prompt.name} /
 * {@code .version} / {@code .label} on the span.
 */
public final class Prompt {
  static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{[ \\t]*([A-Za-z_][A-Za-z0-9_]*)[ \\t]*\\}\\}");

  final String name;
  final long version;
  final String type;
  final Object prompt; // a String (text) or a List<Map<String,Object>> (chat)
  final Map<String, Object> config;
  final List<String> labels;
  final String label;
  final String resolvedBy;
  final List<String> variables;
  final String digest;
  final String commitMessage;
  final String createdAt;
  final boolean fallback;
  final String source;
  final PromptRollout rollout;

  Prompt(
      String name,
      long version,
      String type,
      Object prompt,
      Map<String, Object> config,
      List<String> labels,
      String label,
      String resolvedBy,
      List<String> variables,
      String digest,
      String commitMessage,
      String createdAt,
      boolean fallback,
      String source,
      PromptRollout rollout) {
    this.name = name;
    this.version = version;
    this.type = type;
    this.prompt = prompt;
    this.config = config == null ? Map.of() : Collections.unmodifiableMap(config);
    this.labels = labels == null ? List.of() : List.copyOf(labels);
    this.label = label == null ? "" : label;
    this.resolvedBy = resolvedBy == null ? "" : resolvedBy;
    this.variables = variables == null ? List.of() : List.copyOf(variables);
    this.digest = digest == null ? "" : digest;
    this.commitMessage = commitMessage == null ? "" : commitMessage;
    this.createdAt = createdAt == null ? "" : createdAt;
    this.fallback = fallback;
    this.source = source == null ? "" : source;
    this.rollout = rollout;
  }

  /** A prompt built in code (tests, or a prompt kept beside the app). */
  public static Prompt of(String name, long version, String type, Object body) {
    return new Prompt(name, version, type, body, null, null, "", "", null, "", "", "", false, "", null);
  }

  public String name() {
    return name;
  }

  /** The version; 0 for a fallback. */
  public long version() {
    return version;
  }

  /** {@code text} or {@code chat}. */
  public String type() {
    return type;
  }

  /** The body as served: a String (text) or a list of message maps (chat). */
  public Object prompt() {
    return prompt;
  }

  /** The body of a text prompt ("" for chat). */
  public String text() {
    return prompt instanceof String ? (String) prompt : "";
  }

  /** The messages of a chat prompt (copies; empty for text). */
  @SuppressWarnings("unchecked")
  public List<Map<String, Object>> messages() {
    List<Map<String, Object>> out = new ArrayList<>();
    if (prompt instanceof List) {
      for (Object m : (List<Object>) prompt) {
        out.add(new LinkedHashMap<>((Map<String, Object>) m));
      }
    }
    return out;
  }

  public Map<String, Object> config() {
    return config;
  }

  public List<String> labels() {
    return labels;
  }

  /** The label it was resolved by; "" for a version fetch. */
  public String label() {
    return label;
  }

  public String resolvedBy() {
    return resolvedBy;
  }

  public List<String> variables() {
    return variables;
  }

  public String digest() {
    return digest;
  }

  public String commitMessage() {
    return commitMessage;
  }

  public String createdAt() {
    return createdAt;
  }

  /** True for the {@code fallback} an unreachable registry gave (stamps nothing). */
  public boolean isFallback() {
    return fallback;
  }

  /** {@code online}, {@code local} or {@code fallback}. */
  public String source() {
    return source;
  }

  /** The label's staged rollout, or null. */
  public PromptRollout rollout() {
    return rollout;
  }

  /** Which rollout side served this copy ({@code candidate}, {@code base}, {@code unkeyed}); "" without one. */
  public String cohort() {
    return rollout != null ? rollout.cohort() : "";
  }

  /** The distinct placeholder names in {@code text}, sorted. */
  static List<String> placeholders(String text) {
    TreeSet<String> out = new TreeSet<>(Json::compareCodePoints);
    Matcher m = PLACEHOLDER.matcher(text == null ? "" : text);
    while (m.find()) {
      out.add(m.group(1));
    }
    return new ArrayList<>(out);
  }

  /** A placeholder value as text: a string as is, anything else as JSON.stringify writes it. */
  static String asText(Object v) {
    return v instanceof String ? (String) v : Json.write(v);
  }

  /** One left-to-right pass: a substituted value is never re-scanned. */
  static String compileText(String text, Map<String, ?> values) {
    TreeSet<String> missing = new TreeSet<>(Json::compareCodePoints);
    Matcher m = PLACEHOLDER.matcher(text);
    while (m.find()) {
      if (!values.containsKey(m.group(1))) {
        missing.add(m.group(1));
      }
    }
    if (!missing.isEmpty()) {
      throw new PromptException.CompileFailed(new ArrayList<>(missing));
    }
    m = PLACEHOLDER.matcher(text);
    StringBuilder sb = new StringBuilder();
    while (m.find()) {
      m.appendReplacement(sb, Matcher.quoteReplacement(asText(values.get(m.group(1)))));
    }
    m.appendTail(sb);
    return sb.toString();
  }

  /**
   * Fill every {@code {{name}}} placeholder: a String for a text prompt, a new
   * list of message maps for chat (each content compiled, roles untouched).
   * Throws {@link PromptException.CompileFailed} naming every missing name
   * (sorted); extra names are ignored. Stamps the current span.
   */
  @SuppressWarnings("unchecked")
  public Object compile(Map<String, ?> values) {
    Map<String, ?> vals = values == null ? Map.of() : values;
    Object out;
    if (prompt instanceof List) {
      TreeSet<String> missing = new TreeSet<>(Json::compareCodePoints);
      for (Object o : (List<Object>) prompt) {
        Object c = ((Map<String, Object>) o).get("content");
        for (String n : placeholders(c instanceof String ? (String) c : "")) {
          if (!vals.containsKey(n)) {
            missing.add(n);
          }
        }
      }
      if (!missing.isEmpty()) {
        throw new PromptException.CompileFailed(new ArrayList<>(missing));
      }
      List<Map<String, Object>> msgs = new ArrayList<>();
      for (Object o : (List<Object>) prompt) {
        Map<String, Object> mm = new LinkedHashMap<>((Map<String, Object>) o);
        Object c = mm.get("content");
        mm.put("content", compileText(c instanceof String ? (String) c : "", vals));
        msgs.add(mm);
      }
      out = msgs;
    } else {
      out = compileText(String.valueOf(prompt), vals);
    }
    stamp(null);
    return out;
  }

  /** {@link #compile} of a text prompt. */
  public String compileText(Map<String, ?> values) {
    Object out = compile(values);
    return out instanceof String ? (String) out : Json.write(out);
  }

  /** {@link #compile} of a chat prompt. */
  @SuppressWarnings("unchecked")
  public List<Map<String, Object>> compileMessages(Map<String, ?> values) {
    Object out = compile(values);
    return out instanceof List ? (List<Map<String, Object>>) out : List.of(Map.of("role", "user", "content", out));
  }

  /** The span attributes this prompt stamps (empty for a fallback). */
  public Map<String, Object> attributes() {
    Map<String, Object> out = new LinkedHashMap<>();
    if (fallback) {
      return out;
    }
    out.put(Keys.PROMPT_NAME, name);
    out.put(Keys.PROMPT_VERSION, version);
    if (!label.isEmpty()) {
      out.put(Keys.PROMPT_LABEL, label);
    }
    if (rollout != null) {
      out.put(Keys.PROMPT_COHORT, rollout.cohort());
    }
    return out;
  }

  /** Stamp {@code span} (null: the current span) with this prompt. */
  public void stamp(Span span) {
    Span sp = span != null ? span : Span.current();
    try {
      if (sp.isRecording()) {
        for (Map.Entry<String, Object> e : attributes().entrySet()) {
          Attr.set(sp, e.getKey(), e.getValue());
        }
      }
    } catch (RuntimeException e) {
      // never raises
    }
  }

  @Override
  public String toString() {
    return "Prompt{name=" + name + ", version=" + version + ", type=" + type + ", label=" + label + ", source=" + source + "}";
  }
}
