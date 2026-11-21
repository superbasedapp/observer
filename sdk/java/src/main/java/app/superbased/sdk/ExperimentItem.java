package app.superbased.sdk;

/** One dataset item as a task sees it: its id, input, expected value and metadata. */
public final class ExperimentItem {
  final String id;
  final Object input;
  final Object expected;
  final Object metadata;

  ExperimentItem(String id, Object input, Object expected, Object metadata) {
    this.id = id;
    this.input = input;
    this.expected = expected;
    this.metadata = metadata;
  }

  public String id() {
    return id;
  }

  public Object input() {
    return input;
  }

  public Object expected() {
    return expected;
  }

  public Object metadata() {
    return metadata;
  }
}
