package app.superbased.sdk;

/**
 * The options of {@link Superbased#score} and {@link Superbased#feedback}.
 * Every value is optional. Inside a span with no trace id and no span id, a
 * score is TRACE level; pass {@code spanId(Superbased.getCurrentSpanId())} to
 * score the span.
 */
public final class ScoreOptions {
  final String traceId;
  final String spanId;
  final String comment;
  final String kind;
  final String scorer;
  final String scorerVersion;
  final String runId;
  final String scoreId;
  final String timestamp;
  final String name;

  private ScoreOptions(Builder b) {
    traceId = b.traceId;
    spanId = b.spanId;
    comment = b.comment;
    kind = b.kind;
    scorer = b.scorer;
    scorerVersion = b.scorerVersion;
    runId = b.runId;
    scoreId = b.scoreId;
    timestamp = b.timestamp;
    name = b.name;
  }

  public static ScoreOptions defaults() {
    return builder().build();
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Builder of {@link ScoreOptions}. */
  public static final class Builder {
    private String traceId;
    private String spanId;
    private String comment;
    private String kind;
    private String scorer;
    private String scorerVersion;
    private String runId;
    private String scoreId;
    private String timestamp;
    private String name;

    private Builder() {}

    /** Default: the current trace. */
    public Builder traceId(String v) {
      traceId = v;
      return this;
    }

    /** Absent: a trace-level score. */
    public Builder spanId(String v) {
      spanId = v;
      return this;
    }

    /** Content (masked by the server's capture policy); at most 2000 bytes. */
    public Builder comment(String v) {
      comment = v;
      return this;
    }

    /** numeric, boolean or categorical (inferred from the value; a disagreeing kind is refused). */
    public Builder kind(String v) {
      kind = v;
      return this;
    }

    /** The evaluator's name (score() only). */
    public Builder scorer(String v) {
      scorer = v;
      return this;
    }

    /** The evaluator's version (default "1" when a scorer is set). */
    public Builder scorerVersion(String v) {
      scorerVersion = v;
      return this;
    }

    public Builder runId(String v) {
      runId = v;
      return this;
    }

    /** The idempotency id (default a random {@code sdk_<32 hex>}). */
    public Builder scoreId(String v) {
      scoreId = v;
      return this;
    }

    /** RFC 3339. */
    public Builder timestamp(String v) {
      timestamp = v;
      return this;
    }

    /** feedback() only: the score name (default {@code user_feedback}). */
    public Builder name(String v) {
      name = v;
      return this;
    }

    public ScoreOptions build() {
      return new ScoreOptions(this);
    }
  }
}
