package app.superbased.sdk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** One item's outcome in an {@link ExperimentResult}. */
public final class ItemResult {
  final String itemId;
  final Object input;
  final Object expected;
  final Object metadata;
  Object output;
  String traceId = "";
  final List<Evaluation> scores = new ArrayList<>();
  String error = "";
  final List<String> evaluatorErrors = new ArrayList<>();

  ItemResult(String itemId, Object input, Object expected, Object metadata) {
    this.itemId = itemId;
    this.input = input;
    this.expected = expected;
    this.metadata = metadata;
  }

  public String itemId() {
    return itemId;
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

  public Object output() {
    return output;
  }

  public String traceId() {
    return traceId;
  }

  public List<Evaluation> scores() {
    return Collections.unmodifiableList(scores);
  }

  /** The task's error ("" when it returned). */
  public String error() {
    return error;
  }

  /** Evaluators that threw. */
  public List<String> evaluatorErrors() {
    return Collections.unmodifiableList(evaluatorErrors);
  }

  /** No error and every score passing. */
  public boolean passed() {
    if (!error.isEmpty()) {
      return false;
    }
    for (Evaluation s : scores) {
      if (!s.passed()) {
        return false;
      }
    }
    return true;
  }
}
