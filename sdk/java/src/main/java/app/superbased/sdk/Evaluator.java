package app.superbased.sdk;

import java.util.function.Function;

/**
 * Scores one experiment item. {@link #evaluate} may return a number, a
 * boolean, a label, an {@link Evaluation}, a {@code {name, value, comment,
 * version}} map, a list of those, or null (no score). An exception becomes
 * the item's evaluator error. {@link #name()} and {@link #version()} name the
 * scorer (lowercased; characters outside {@code [a-z0-9_.-]} become
 * {@code _}).
 */
@FunctionalInterface
public interface Evaluator {
  Object evaluate(EvalInput in) throws Exception;

  default String name() {
    return "evaluator";
  }

  default String version() {
    return "1";
  }

  /** A named evaluator from a function. */
  static Evaluator of(String name, Function<EvalInput, Object> fn) {
    return of(name, "1", fn);
  }

  /** A named, versioned evaluator from a function. */
  static Evaluator of(String name, String version, Function<EvalInput, Object> fn) {
    return new Evaluator() {
      @Override
      public Object evaluate(EvalInput in) {
        return fn.apply(in);
      }

      @Override
      public String name() {
        return name;
      }

      @Override
      public String version() {
        return version;
      }
    };
  }
}
