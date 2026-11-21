package app.superbased.sdk;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The options of {@link Superbased#getPrompt(String, PromptOptions)}: a
 * {@code label} ({@code production}, the default, or {@code staging}) OR a
 * {@code version}, never both.
 */
public final class PromptOptions {
  final String label;
  final Long version;
  final Duration cacheTtl;
  final Object fallback;
  final String user;
  final String sessionId;

  private PromptOptions(Builder b) {
    label = b.label;
    version = b.version;
    cacheTtl = b.cacheTtl;
    fallback = b.fallback;
    user = b.user;
    sessionId = b.sessionId;
  }

  public static PromptOptions defaults() {
    return builder().build();
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Builder of {@link PromptOptions}. */
  public static final class Builder {
    private String label;
    private Long version;
    private Duration cacheTtl;
    private Object fallback;
    private String user;
    private String sessionId;

    private Builder() {}

    /** {@code production} (default) or {@code staging}. */
    public Builder label(String v) {
      label = v;
      return this;
    }

    /** A positive version number (not with a label). */
    public Builder version(long v) {
      version = v;
      return this;
    }

    /** How long a fetched copy is fresh (default: init()'s promptCacheTtl, 60 s). */
    public Builder cacheTtl(Duration v) {
      cacheTtl = v;
      return this;
    }

    /** A text body returned (version 0, stamps nothing) when nothing is cached and the fetch fails. */
    public Builder fallback(String text) {
      fallback = text;
      return this;
    }

    /** A chat body returned when nothing is cached and the fetch fails. */
    public Builder fallback(List<Map<String, Object>> messages) {
      fallback = messages == null ? null : new ArrayList<>(messages);
      return this;
    }

    /** The end user a staged rollout buckets by (default: the trace's user). Only its SHA-256 is sent. */
    public Builder user(String v) {
      user = v;
      return this;
    }

    /** The session a staged rollout buckets by when there is no user. Only its SHA-256 is sent. */
    public Builder sessionId(String v) {
      sessionId = v;
      return this;
    }

    public PromptOptions build() {
      return new PromptOptions(this);
    }
  }
}
