package app.superbased.sdk;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Model request parameters for {@link Superbased#setRequestParams} ({@code gen_ai.request.<name>}). */
public final class RequestParams {
  final Map<String, Object> values;

  private RequestParams(Map<String, Object> values) {
    this.values = values;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Builder of {@link RequestParams}. Every value is optional. */
  public static final class Builder {
    private final Map<String, Object> v = new LinkedHashMap<>();

    private Builder() {}

    public Builder maxTokens(long x) {
      v.put("max_tokens", x);
      return this;
    }

    public Builder temperature(double x) {
      v.put("temperature", x);
      return this;
    }

    public Builder topP(double x) {
      v.put("top_p", x);
      return this;
    }

    public Builder topK(double x) {
      v.put("top_k", x);
      return this;
    }

    public Builder stopSequences(Collection<String> x) {
      v.put("stop_sequences", x == null ? null : new ArrayList<>(x));
      return this;
    }

    public Builder stopSequence(String x) {
      v.put("stop_sequences", x == null ? null : List.of(x));
      return this;
    }

    public Builder frequencyPenalty(double x) {
      v.put("frequency_penalty", x);
      return this;
    }

    public Builder presencePenalty(double x) {
      v.put("presence_penalty", x);
      return this;
    }

    public Builder seed(long x) {
      v.put("seed", x);
      return this;
    }

    public Builder stream(boolean x) {
      v.put("stream", x);
      return this;
    }

    /** {@code gen_ai.request.reasoning.level}. */
    public Builder reasoningLevel(String x) {
      v.put("reasoning_level", x);
      return this;
    }

    public RequestParams build() {
      return new RequestParams(new LinkedHashMap<>(v));
    }
  }
}
