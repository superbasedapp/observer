package app.superbased.sdk;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.context.Scope;

/**
 * A started span that is current until {@link #close()}: use it in a
 * try-with-resources block.
 *
 * <pre>{@code
 * try (SbSpan s = Superbased.llmSpan("chat").model("gpt-5-nano").provider("openai").start()) {
 *   ChatCompletion r = client.chat().completions().create(params);
 *   s.setUsage(Usage.builder().inputTokens(...).outputTokens(...).build());
 * } // ends the span
 * }</pre>
 *
 * <p>A try-with-resources block cannot see an exception thrown inside it, so
 * {@code close()} leaves the status as the body set it: call
 * {@link #recordException(Throwable)} in a catch block, or use
 * {@link SpanStarter#call} / {@link SpanStarter#run}, which record an
 * exception once and set ERROR, and set OK on success.
 */
public final class SbSpan implements AutoCloseable {
  private final Span span;
  private Scope scope;
  private volatile boolean failed;

  SbSpan(Span span, Scope scope) {
    this.span = span;
    this.scope = scope;
  }

  /** The underlying OpenTelemetry span. */
  public Span span() {
    return span;
  }

  /** 32 lowercase hex, "" when the span is not valid. */
  public String traceId() {
    return span.getSpanContext().isValid() ? span.getSpanContext().getTraceId() : "";
  }

  /** 16 lowercase hex, "" when the span is not valid. */
  public String spanId() {
    return span.getSpanContext().isValid() ? span.getSpanContext().getSpanId() : "";
  }

  /** Set one attribute (string, number, bool or a list of strings). Never throws. */
  public SbSpan setAttribute(String key, Object value) {
    Attr.set(span, key, value);
    return this;
  }

  /** {@link Superbased#setUsage}. */
  public SbSpan setUsage(Usage usage) {
    Spans.setUsage(span, usage);
    return this;
  }

  /** {@link Superbased#setContent}. */
  public SbSpan setContent(Object prompt, Object response) {
    Spans.setContent(span, prompt, response, null, null);
    return this;
  }

  /** {@link Superbased#setInput}. */
  public SbSpan setInput(Object value) {
    Spans.setInput(span, value);
    return this;
  }

  /** {@link Superbased#setOutput}. */
  public SbSpan setOutput(Object value) {
    Spans.setOutput(span, value);
    return this;
  }

  /** {@link Superbased#setToolResult}. */
  public SbSpan setToolResult(Object result) {
    Spans.setToolResult(span, result);
    return this;
  }

  /** {@link Superbased#setDocuments}. */
  public SbSpan setDocuments(Object documents) {
    Spans.setDocuments(span, documents);
    return this;
  }

  /** {@link Superbased#setRequestParams}. */
  public SbSpan setRequestParams(RequestParams params) {
    Spans.setRequestParams(span, params);
    return this;
  }

  /** Record {@code t} once and set ERROR. Never throws. */
  public SbSpan recordException(Throwable t) {
    markError(span, t);
    failed = true;
    return this;
  }

  /** Set OK (unless an error was recorded). */
  public SbSpan ok() {
    if (!failed) {
      try {
        span.setStatus(StatusCode.OK);
      } catch (RuntimeException e) {
        // never raises
      }
    }
    return this;
  }

  static void markError(Span sp, Throwable t) {
    try {
      sp.recordException(t);
      sp.setStatus(StatusCode.ERROR, t.getClass().getSimpleName() + ": " + t.getMessage());
    } catch (RuntimeException e) {
      // never raises
    }
  }

  /** End the span and restore the previous current span. Idempotent. */
  @Override
  public synchronized void close() {
    Scope s = scope;
    if (s == null) {
      return;
    }
    scope = null;
    try {
      s.close();
    } catch (RuntimeException e) {
      // never raises
    }
    span.end();
  }
}
