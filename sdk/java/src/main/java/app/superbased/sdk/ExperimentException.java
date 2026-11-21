package app.superbased.sdk;

/**
 * The experiment could not be set up: the dataset is not found on any
 * destination (or none is usable), or the run could not be created (Python
 * {@code ExperimentError}).
 */
public class ExperimentException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  ExperimentException(String message) {
    super(message);
  }
}
