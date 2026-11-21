package app.superbased.sdk;

/** What an {@link Evaluator} sees for one item: its input, the task's output, the expected value and metadata. */
public final class EvalInput {
  final Object input;
  final Object output;
  final Object expected;
  final Object metadata;

  EvalInput(Object input, Object output, Object expected, Object metadata) {
    this.input = input;
    this.output = output;
    this.expected = expected;
    this.metadata = metadata;
  }

  public Object input() {
    return input;
  }

  public Object output() {
    return output;
  }

  /** The item's expected value (Python {@code expected} / {@code expected_output}). */
  public Object expected() {
    return expected;
  }

  public Object metadata() {
    return metadata;
  }
}
