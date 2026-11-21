package app.superbased.sdk;

import java.util.Locale;
import java.util.Set;

/** One evaluator result: {@code value} is a number, a boolean or a short label. */
public final class Evaluation {
  private static final Set<String> FAIL_WORDS = Set.of("fail", "false", "no", "bad");

  final String name;
  final Object value;
  final String comment;
  final String scorerVersion;

  public Evaluation(String name, Object value) {
    this(name, value, null, "1");
  }

  public Evaluation(String name, Object value, String comment, String scorerVersion) {
    this.name = name;
    this.value = value;
    this.comment = comment;
    this.scorerVersion = scorerVersion == null || scorerVersion.isEmpty() ? "1" : scorerVersion;
  }

  public String name() {
    return name;
  }

  public Object value() {
    return value;
  }

  public String comment() {
    return comment;
  }

  public String scorerVersion() {
    return scorerVersion;
  }

  /** The contract's pass rule: boolean true, a number of at least 0.5, or a label not in fail/false/no/bad. */
  public boolean passed() {
    return passes(value);
  }

  static boolean passes(Object value) {
    if (value instanceof Boolean) {
      return (Boolean) value;
    }
    if (value instanceof Number) {
      return ((Number) value).doubleValue() >= 0.5;
    }
    return !FAIL_WORDS.contains(String.valueOf(value).strip().toLowerCase(Locale.ROOT));
  }

  @Override
  public String toString() {
    return "Evaluation{name=" + name + ", value=" + value + "}";
  }
}
