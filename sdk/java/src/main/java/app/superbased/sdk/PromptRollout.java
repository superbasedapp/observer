package app.superbased.sdk;

/**
 * A label's staged rollout as the server reported it (prompts.md v2 section
 * 9.3): which version this key was served ({@link #cohort()}), the split and
 * the salt the server bucketed with.
 */
public final class PromptRollout {
  private final long baseVersion;
  private final long candidateVersion;
  private final int percent;
  private final String cohort;
  private final String key;
  private final String salt;

  PromptRollout(long baseVersion, long candidateVersion, int percent, String cohort, String key, String salt) {
    this.baseVersion = baseVersion;
    this.candidateVersion = candidateVersion;
    this.percent = percent;
    this.cohort = cohort;
    this.key = key;
    this.salt = salt;
  }

  public long baseVersion() {
    return baseVersion;
  }

  public long candidateVersion() {
    return candidateVersion;
  }

  public int percent() {
    return percent;
  }

  /** {@code candidate}, {@code base} or {@code unkeyed}. */
  public String cohort() {
    return cohort;
  }

  /** {@code user}, {@code session} or "". */
  public String key() {
    return key;
  }

  public String salt() {
    return salt;
  }

  String signature() {
    return candidateVersion + "|" + percent + "|" + salt;
  }
}
