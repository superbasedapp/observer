package app.superbased.sdk;

/**
 * The experiment could not be set up: the dataset is not found on any
 * destination (or none is usable), or the run could not be created (Python
 * {@code ExperimentError}). {@link #planRefusal()} (also the cause) is set
 * when the org's plan refused it: its message and {@code upgradeUrl()} say
 * why and where to fix it.
 */
public class ExperimentException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  ExperimentException(String message) {
    super(message);
  }

  ExperimentException(String message, PlanRefusalException planRefusal) {
    super(message, planRefusal);
  }

  /** The org's plan refusal behind this error, or null. */
  public PlanRefusalException planRefusal() {
    return getCause() instanceof PlanRefusalException ? (PlanRefusalException) getCause() : null;
  }
}
