package app.superbased.sdk;

import java.util.List;

/**
 * The {@code failUnder} gate failed (Python {@code ExperimentGateFailed}, a
 * {@code SystemExit(1)}). Uncaught on the main thread it ends the JVM with
 * exit status 1, so a CI job fails; {@link #exitCode()} is 1 for a caller
 * that exits itself. With the strict gate (the default) {@link #reasons()}
 * says why it failed before the pass rate was compared; empty when the rate
 * itself is below {@link #failUnder()}.
 */
public final class ExperimentGateFailedException extends RuntimeException {
  private static final long serialVersionUID = 1L;
  private final transient ExperimentResult result;
  private final double failUnder;
  private final List<String> reasons;

  ExperimentGateFailedException(ExperimentResult result, double failUnder, List<String> reasons) {
    super(message(result, failUnder, reasons));
    this.result = result;
    this.failUnder = failUnder;
    this.reasons = List.copyOf(reasons);
  }

  private static String message(ExperimentResult result, double failUnder, List<String> reasons) {
    if (!reasons.isEmpty()) {
      return "experiment '" + result.name() + "': the failUnder gate cannot pass: " + String.join("; ", reasons)
          + " (strict; set strict(false) to gate on the pass rate alone)";
    }
    return String.format(
        "experiment '%s': pass rate %.3f is below %.3f", result.name(), result.passRate(), failUnder);
  }

  public ExperimentResult result() {
    return result;
  }

  public double failUnder() {
    return failUnder;
  }

  /** Why the strict gate failed before the rate was compared (empty when the rate decided). */
  public List<String> reasons() {
    return reasons;
  }

  /** The exit status a CI script should end with: 1. */
  public int exitCode() {
    return 1;
  }
}
