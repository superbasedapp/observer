package app.superbased.sdk;

import java.util.List;

/**
 * Base class of the prompt errors (contract prompts.md; Python {@code PromptError}).
 * {@link #planRefusal()} (also the cause) is set when the org's plan refused
 * the fetch: its message and {@code upgradeUrl()} say why and where to fix it.
 */
public class PromptException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  PromptException(String message) {
    super(message);
  }

  PromptException(String message, PlanRefusalException planRefusal) {
    super(message, planRefusal);
  }

  /** The org's plan refusal behind this error, or null. */
  public PlanRefusalException planRefusal() {
    return getCause() instanceof PlanRefusalException ? (PlanRefusalException) getCause() : null;
  }

  /** No registry had the prompt, or the label points at nothing (Python {@code PromptNotFound}). */
  public static final class NotFound extends PromptException {
    private static final long serialVersionUID = 1L;

    NotFound(String message) {
      super(message);
    }
  }

  /**
   * The registry could not be reached or answered badly, and nothing was
   * cached; {@link #planRefusal()} is set when the org's plan refused it.
   */
  public static final class FetchFailed extends PromptException {
    private static final long serialVersionUID = 1L;

    FetchFailed(String message) {
      super(message);
    }

    FetchFailed(String message, PlanRefusalException planRefusal) {
      super(message, planRefusal);
    }
  }

  /** {@link Prompt#compile} was missing values; {@link #missing()} lists the names, sorted. */
  public static final class CompileFailed extends PromptException {
    private static final long serialVersionUID = 1L;
    private final List<String> missing;

    CompileFailed(List<String> missing) {
      super("missing prompt variables: " + String.join(", ", missing));
      this.missing = List.copyOf(missing);
    }

    public List<String> missing() {
      return missing;
    }
  }
}
