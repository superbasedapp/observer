package app.superbased.sdk;

import java.util.function.Function;

/** The code under test: called once per item, inside the item's own trace. An exception is the item's error. */
@FunctionalInterface
public interface ExperimentTask {
  Object run(ExperimentItem item) throws Exception;

  /** A task that takes the item's input only. */
  static ExperimentTask ofInput(Function<Object, Object> fn) {
    return item -> fn.apply(item.input());
  }
}
