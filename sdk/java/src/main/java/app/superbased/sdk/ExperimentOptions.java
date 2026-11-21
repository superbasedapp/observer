package app.superbased.sdk;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/** The options of {@link Superbased#runExperiment(Object, ExperimentOptions)}. */
public final class ExperimentOptions {
  final ExperimentTask task;
  final List<Evaluator> evaluators;
  final String name;
  final Map<String, Object> metadata;
  final int maxConcurrency;
  final Long snapshotVersion;
  final String datasetName;
  final Double failUnder;
  final boolean strict;

  private ExperimentOptions(Builder b) {
    task = b.task;
    evaluators = List.copyOf(b.evaluators);
    name = b.name;
    metadata = b.metadata == null ? Map.of() : new LinkedHashMap<>(b.metadata);
    maxConcurrency = b.maxConcurrency;
    snapshotVersion = b.snapshotVersion;
    datasetName = b.datasetName;
    failUnder = b.failUnder;
    strict = b.strict;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Builder of {@link ExperimentOptions}; {@code task} is required. */
  public static final class Builder {
    private ExperimentTask task;
    private final List<Evaluator> evaluators = new ArrayList<>();
    private String name;
    private Map<String, Object> metadata;
    private int maxConcurrency = 4;
    private Long snapshotVersion;
    private String datasetName;
    private Double failUnder;
    private boolean strict = true;

    private Builder() {}

    /** The task, given the whole item. */
    public Builder task(ExperimentTask v) {
      task = v;
      return this;
    }

    /** The task, given the item's input. */
    public Builder inputTask(Function<Object, Object> v) {
      task = ExperimentTask.ofInput(v);
      return this;
    }

    public Builder evaluator(Evaluator v) {
      evaluators.add(v);
      return this;
    }

    public Builder evaluators(Collection<Evaluator> v) {
      evaluators.addAll(v);
      return this;
    }

    /** The run's name (default {@code experiment}). */
    public Builder name(String v) {
      name = v;
      return this;
    }

    public Builder metadata(Map<String, ?> v) {
      metadata = v == null ? null : new LinkedHashMap<>(v);
      return this;
    }

    /** Workers (default 4). */
    public Builder maxConcurrency(int v) {
      maxConcurrency = v;
      return this;
    }

    /** Pin the run to this dataset snapshot (default: freeze a new one). */
    public Builder snapshotVersion(long v) {
      snapshotVersion = v;
      return this;
    }

    /** Upload literal items to this dataset (else they run in-process only). */
    public Builder datasetName(String v) {
      datasetName = v;
      return this;
    }

    /** Fail (ExperimentGateFailedException) when the pass rate is below this (0..1). */
    public Builder failUnder(double v) {
      failUnder = v;
      return this;
    }

    /** Strict gate (default true): nothing scored, a skipped side or a rejected result also fails it. */
    public Builder strict(boolean v) {
      strict = v;
      return this;
    }

    public ExperimentOptions build() {
      if (task == null) {
        throw new IllegalArgumentException("runExperiment needs a task");
      }
      return new ExperimentOptions(this);
    }
  }
}
