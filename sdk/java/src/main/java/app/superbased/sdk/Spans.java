package app.superbased.sdk;

import io.opentelemetry.api.trace.Span;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The span setters behind {@link Superbased#setUsage} and friends. Each is a
 * no-op on a non-recording span and never throws, except the
 * IllegalArgumentException of a negative token count (nothing is written
 * then).
 */
final class Spans {
  private static final AtomicBoolean NET_INPUT_WARNED = new AtomicBoolean();

  private Spans() {}

  /** A content body as an attribute value (clipped), or null when capture is off. */
  static String content(Object value) {
    if (!Superbased.captureContent() || value == null) {
      return null;
    }
    return truncate(json(value));
  }

  static String truncate(String value) {
    int max = Superbased.maxContentChars();
    if (max > 0 && value.codePointCount(0, value.length()) > max) {
      return Util.head(value, max) + Pipeline.TRUNCATED_MARK;
    }
    return value;
  }

  static String json(Object value) {
    if (value instanceof String) {
      return (String) value;
    }
    try {
      return Json.write(value);
    } catch (RuntimeException e) {
      return String.valueOf(value);
    }
  }

  static boolean isMessageList(Object value) {
    if (!(value instanceof Collection)) {
      return false;
    }
    for (Object m : (Collection<?>) value) {
      if (!(m instanceof Map)) {
        return false;
      }
    }
    return true;
  }

  static String kindOf(Span sp) {
    Object k = Attr.get(sp, Keys.SPAN_KIND);
    return k == null ? "" : String.valueOf(k).toUpperCase(Locale.ROOT);
  }

  private static Long count(String name, Long value) {
    if (value == null) {
      return null;
    }
    if (value < 0) {
      throw new IllegalArgumentException(name + " must not be negative, got " + value);
    }
    return value;
  }

  /**
   * The gross input: {@code input} as given, unless it is below its own
   * cache parts; then it is a NET count (as Anthropic's
   * {@code usage.input_tokens} is), so the cache parts are added, the
   * correction is counted and a warning is logged once per process.
   */
  static Long grossInput(Long input, Long cacheRead, Long cacheWrite) {
    long cache = (cacheRead == null ? 0 : cacheRead) + (cacheWrite == null ? 0 : cacheWrite);
    if (input == null || input >= cache) {
      return input;
    }
    synchronized (Pipeline.COUNTERS) {
      Pipeline.COUNTERS.usageNetInputCorrected++;
    }
    if (NET_INPUT_WARNED.compareAndSet(false, true)) {
      Util.warn(
          "setUsage: inputTokens "
              + input
              + " is below cacheReadTokens + cacheWriteTokens ("
              + cache
              + "); recorded as a net count (input + cache = "
              + (input + cache)
              + "). Pass the gross input: for Anthropic, usage.input_tokens + "
              + "cache_creation_input_tokens + cache_read_input_tokens.");
    }
    return input + cache;
  }

  static void setUsage(Span sp, Usage u) {
    if (u == null) {
      return;
    }
    String[][] rows = {
      {Keys.INPUT_TOKENS, "inputTokens"},
      {Keys.OUTPUT_TOKENS, "outputTokens"},
      {Keys.TOTAL_TOKENS, "totalTokens"},
      {Keys.CACHE_READ_TOKENS, "cacheReadTokens"},
      {Keys.CACHE_WRITE_TOKENS, "cacheWriteTokens"},
      {Keys.REASONING_TOKENS, "reasoningTokens"},
    };
    Long[] vals = {u.inputTokens, u.outputTokens, u.totalTokens, u.cacheReadTokens, u.cacheWriteTokens, u.reasoningTokens};
    Map<String, Long> resolved = new LinkedHashMap<>();
    for (int i = 0; i < rows.length; i++) {
      resolved.put(rows[i][0], count(rows[i][1], vals[i])); // validate before writing any
    }
    Long netIn = resolved.get(Keys.INPUT_TOKENS);
    Long grossIn = grossInput(netIn, resolved.get(Keys.CACHE_READ_TOKENS), resolved.get(Keys.CACHE_WRITE_TOKENS));
    if (netIn != null && !grossIn.equals(netIn)) {
      long added = grossIn - netIn;
      Long total = resolved.get(Keys.TOTAL_TOKENS);
      Long out = resolved.get(Keys.OUTPUT_TOKENS);
      resolved.put(Keys.INPUT_TOKENS, grossIn);
      if (total != null && total == netIn + (out == null ? 0 : out)) {
        resolved.put(Keys.TOTAL_TOKENS, total + added);
      }
    }
    for (Map.Entry<String, Long> e : resolved.entrySet()) {
      if (e.getValue() != null) {
        Attr.set(sp, e.getKey(), e.getValue());
      }
    }
    if (u.responseId != null && !u.responseId.isEmpty()) {
      Attr.set(sp, Keys.RESPONSE_ID, u.responseId);
    }
    if (u.requestId != null && !u.requestId.isEmpty()) {
      Attr.set(sp, Keys.REQUEST_ID, u.requestId);
    }
    if (u.responseModel != null && !u.responseModel.isEmpty()) {
      Attr.set(sp, Keys.RESPONSE_MODEL, u.responseModel);
    }
    if (u.finishReasons != null) {
      Attr.set(sp, Keys.FINISH_REASONS, u.finishReasons);
    }
    if (u.costUsd != null) {
      Attr.set(sp, Keys.COST, u.costUsd);
    }
    if (u.prompt != null || u.response != null) {
      setContent(sp, u.prompt, u.response, null, null);
    }
  }

  static void setContent(Span sp, Object prompt, Object response, Object toolArgs, Object toolResult) {
    if (!Superbased.captureContent()) {
      return;
    }
    Object req = prompt != null ? prompt : toolArgs;
    Object res = response != null ? response : toolResult;
    String inKey;
    String outKey;
    if (Kind.TOOL.equals(kindOf(sp))) {
      inKey = Keys.TOOL_ARGUMENTS;
      outKey = Keys.TOOL_RESULT;
    } else {
      inKey = isMessageList(req) ? Keys.INPUT_MESSAGES : Keys.INPUT_VALUE;
      outKey = isMessageList(res) ? Keys.OUTPUT_MESSAGES : Keys.OUTPUT_VALUE;
    }
    if (req != null) {
      Attr.set(sp, inKey, truncate(json(req)));
    }
    if (res != null) {
      Attr.set(sp, outKey, truncate(json(res)));
    }
  }

  static void setInput(Span sp, Object value) {
    String body = content(value);
    if (body != null) {
      Attr.set(sp, Keys.INPUT_VALUE, body);
    }
  }

  static void setOutput(Span sp, Object value) {
    if (Kind.RETRIEVER.equals(kindOf(sp))) {
      setDocuments(sp, value);
      return;
    }
    String body = content(value);
    if (body != null) {
      Attr.set(sp, Keys.OUTPUT_VALUE, body);
    }
  }

  static void setToolResult(Span sp, Object result) {
    String body = content(result);
    if (body != null) {
      Attr.set(sp, Keys.TOOL_RESULT, body);
    }
  }

  static void setDocuments(Span sp, Object documents) {
    if (documents == null) {
      return;
    }
    Object docs = documents;
    if (documents instanceof Collection) {
      List<Object> out = new ArrayList<>();
      for (Object d : (Collection<?>) documents) {
        out.add(d instanceof Map ? d : Map.of("content", d == null ? "" : d));
      }
      docs = out;
    }
    String body = content(docs);
    if (body != null) {
      Attr.set(sp, Keys.RETRIEVAL_DOCUMENTS, body);
    }
  }

  static void setRequestParams(Span sp, RequestParams params) {
    if (params == null) {
      return;
    }
    for (Map.Entry<String, Object> e : params.values.entrySet()) {
      if (e.getValue() != null) {
        Attr.set(sp, Keys.REQUEST_PARAMS.get(e.getKey()), e.getValue());
      }
    }
  }

  static void resetForTests() {
    NET_INPUT_WARNED.set(false);
  }
}
