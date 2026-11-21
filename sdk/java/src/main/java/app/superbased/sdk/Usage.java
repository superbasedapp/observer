package app.superbased.sdk;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Token usage, ids and the outcome of a model call, for
 * {@link Superbased#setUsage}. Token buckets follow the GenAI semantic
 * conventions: {@code inputTokens} is the GROSS input and includes cache
 * reads and writes (the cache counts are subsets, never addends);
 * {@code outputTokens} includes {@code reasoningTokens}.
 *
 * <pre>{@code
 * Superbased.setUsage(span, Usage.builder()
 *     .inputTokens(1200).outputTokens(80).cacheReadTokens(1024)
 *     .responseId(resp.id()).build());
 * }</pre>
 */
public final class Usage {
  final Long inputTokens;
  final Long outputTokens;
  final Long totalTokens;
  final Long cacheReadTokens;
  final Long cacheWriteTokens;
  final Long reasoningTokens;
  final String responseId;
  final String requestId;
  final String responseModel;
  final List<String> finishReasons;
  final Double costUsd;
  final Object prompt;
  final Object response;

  private Usage(Builder b) {
    inputTokens = b.inputTokens;
    outputTokens = b.outputTokens;
    totalTokens = b.totalTokens;
    cacheReadTokens = b.cacheReadTokens;
    cacheWriteTokens = b.cacheWriteTokens;
    reasoningTokens = b.reasoningTokens;
    responseId = b.responseId;
    requestId = b.requestId;
    responseModel = b.responseModel;
    finishReasons = b.finishReasons == null ? null : List.copyOf(b.finishReasons);
    costUsd = b.costUsd;
    prompt = b.prompt;
    response = b.response;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Builder of {@link Usage}. Every value is optional. */
  public static final class Builder {
    private Long inputTokens;
    private Long outputTokens;
    private Long totalTokens;
    private Long cacheReadTokens;
    private Long cacheWriteTokens;
    private Long reasoningTokens;
    private String responseId;
    private String requestId;
    private String responseModel;
    private List<String> finishReasons;
    private Double costUsd;
    private Object prompt;
    private Object response;

    private Builder() {}

    /** The gross input (cache reads and writes included). */
    public Builder inputTokens(long v) {
      inputTokens = v;
      return this;
    }

    /** The output, reasoning included. */
    public Builder outputTokens(long v) {
      outputTokens = v;
      return this;
    }

    /** Optional: ingest derives input + output. */
    public Builder totalTokens(long v) {
      totalTokens = v;
      return this;
    }

    public Builder cacheReadTokens(long v) {
      cacheReadTokens = v;
      return this;
    }

    public Builder cacheWriteTokens(long v) {
      cacheWriteTokens = v;
      return this;
    }

    public Builder reasoningTokens(long v) {
      reasoningTokens = v;
      return this;
    }

    /** The provider's message id ({@code msg_…}, {@code chatcmpl-…}). */
    public Builder responseId(String v) {
      responseId = v;
      return this;
    }

    public Builder requestId(String v) {
      requestId = v;
      return this;
    }

    public Builder responseModel(String v) {
      responseModel = v;
      return this;
    }

    public Builder finishReasons(Collection<String> v) {
      finishReasons = v == null ? null : new ArrayList<>(v);
      return this;
    }

    /** One finish reason. */
    public Builder finishReason(String v) {
      finishReasons = v == null ? null : List.of(v);
      return this;
    }

    public Builder costUsd(double v) {
      costUsd = v;
      return this;
    }

    /** The request body (content: a string or a list of message maps). */
    public Builder prompt(Object v) {
      prompt = v;
      return this;
    }

    /** The response body (content). */
    public Builder response(Object v) {
      response = v;
      return this;
    }

    public Usage build() {
      return new Usage(this);
    }
  }
}
