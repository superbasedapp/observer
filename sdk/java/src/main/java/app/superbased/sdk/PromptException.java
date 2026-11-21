package app.superbased.sdk;

import java.util.List;

/** Base class of the prompt errors (contract prompts.md; Python {@code PromptError}). */
public class PromptException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  PromptException(String message) {
    super(message);
  }

  /** No registry had the prompt, or the label points at nothing (Python {@code PromptNotFound}). */
  public static final class NotFound extends PromptException {
    private static final long serialVersionUID = 1L;

    NotFound(String message) {
      super(message);
    }
  }

  /** The registry could not be reached or answered badly, and nothing was cached. */
  public static final class FetchFailed extends PromptException {
    private static final long serialVersionUID = 1L;

    FetchFailed(String message) {
      super(message);
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
