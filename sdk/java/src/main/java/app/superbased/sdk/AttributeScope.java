package app.superbased.sdk;

import io.opentelemetry.context.Scope;

/**
 * The handle {@link Superbased#identify} and
 * {@link Superbased#propagateAttributes} return: {@link #close()} (or
 * {@link #reset()}) restores the previous values. Idempotent. Use it in a
 * try-with-resources block; scopes close in the reverse order they opened
 * (the OpenTelemetry context rule).
 */
public final class AttributeScope implements AutoCloseable {
  private Scope scope;

  AttributeScope(Scope scope) {
    this.scope = scope;
  }

  /** Undo the values this scope set (idempotent). */
  public synchronized void reset() {
    Scope s = scope;
    scope = null;
    if (s != null) {
      try {
        s.close();
      } catch (RuntimeException e) {
        // never breaks the caller
      }
    }
  }

  @Override
  public void close() {
    reset();
  }
}
