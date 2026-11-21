package app.superbased.sdk;

import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * {@code runExperiment(dataset, task, evaluators)} (contract experiments.md).
 * The run lives on the destination(s) of the plan; the SDK creates it (which
 * freezes a dataset snapshot), reads the snapshot's items, runs the task on
 * each item in its own trace, runs the evaluators in-process, posts each
 * item's result as soon as it is done, finishes the run and reads back the
 * totals. Under {@code both} the task runs once and each result goes to both
 * sides (items matched by client id, else by input).
 */
final class Experiments {
  static final int RESULTS_PER_POST = 200;
  static final int ITEMS_PAGE = 500;

  private Experiments() {}

  // --- the gate ------------------------------------------------------------------------------

  /** Why a strict failUnder gate fails before the rate is compared (review E-12). */
  static List<String> gateProblems(ExperimentResult r) {
    List<String> out = new ArrayList<>();
    if (r.scored() == 0) {
      out.add("no item was scored (no evaluator returned a score)");
    }
    for (String side : r.skippedSides) {
      out.add("the " + side + " destination was skipped");
    }
    if (r.failedPosts > 0) {
      out.add(r.failedPosts + " result(s) were not accepted, so the recorded pass rate covers only part of the run");
    }
    return out;
  }

  /** Whether {@code failUnder} fails this run (strict: any gate problem fails it). */
  static boolean gateFails(ExperimentResult r, Double failUnder, boolean strict) {
    if (failUnder == null) {
      return false;
    }
    if (strict && !gateProblems(r).isEmpty()) {
      return true;
    }
    if (r.scored() == 0) {
      return false;
    }
    return !(r.passRate() >= failUnder);
  }

  // --- evaluators ----------------------------------------------------------------------------

  static String evaluatorName(Evaluator ev) {
    String raw;
    try {
      raw = ev.name();
    } catch (RuntimeException e) {
      raw = "";
    }
    if (raw == null || raw.isEmpty()) {
      raw = "evaluator";
    }
    String n = raw.strip().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_.-]+", "_");
    n = n.replaceAll("^_+|_+$", "");
    if (n.isEmpty()) {
      n = "evaluator";
    }
    return n.length() > 64 ? n.substring(0, 64) : n;
  }

  static String evaluatorVersion(Evaluator ev) {
    try {
      String v = ev.version();
      return v == null || v.isEmpty() ? "1" : v;
    } catch (RuntimeException e) {
      return "1";
    }
  }

  @SuppressWarnings("unchecked")
  static List<Evaluation> normalize(Evaluator ev, Object out) {
    String name = evaluatorName(ev);
    String version = evaluatorVersion(ev);
    List<Evaluation> res = new ArrayList<>();
    if (out == null) {
      return res;
    }
    if (out instanceof Evaluation) {
      res.add((Evaluation) out);
    } else if (out instanceof Collection) {
      for (Object o : (Collection<Object>) out) {
        res.addAll(normalize(ev, o));
      }
    } else if (out instanceof Map) {
      Map<String, Object> m = (Map<String, Object>) out;
      Object n = m.get("name");
      Object c = m.get("comment");
      Object v = m.get("version");
      res.add(
          new Evaluation(
              n == null || String.valueOf(n).isEmpty() ? name : String.valueOf(n),
              m.get("value"),
              c == null ? null : String.valueOf(c),
              v == null || String.valueOf(v).isEmpty() ? version : String.valueOf(v)));
    } else {
      res.add(new Evaluation(name, out, null, version));
    }
    return res;
  }

  // --- destinations --------------------------------------------------------------------------

  static final class Run {
    final Control.Side side;
    String datasetId;
    String runId = "";
    long snapshotVersion;
    List<Map<String, Object>> items = new ArrayList<>();
    Map<Integer, String> itemMap = new HashMap<>();
    List<String> itemIds = new ArrayList<>();

    Run(Control.Side side, String datasetId, long snapshotVersion, List<String> itemIds) {
      this.side = side;
      this.datasetId = datasetId;
      this.snapshotVersion = snapshotVersion;
      this.itemIds = itemIds;
    }
  }

  /** A destination refused for want of a scope (403 insufficient_scope): skipped, the run goes on. */
  static final class SideSkipped extends ExperimentException {
    private static final long serialVersionUID = 1L;

    SideSkipped(String message) {
      super(message);
    }
  }

  private static Map<String, Object> ok(Http.Response resp, String what, String side) {
    if (!resp.ok()) {
      if (resp.status == 403 && "insufficient_scope".equals(resp.errorCode())) {
        throw new SideSkipped(
            side
                + ": skipped, "
                + what
                + " refused: "
                + resp.describe()
                + " (an SDK key from sign-in has no sdk:eval scope; run experiments on the org with a CI credential that has it)");
      }
      throw new ExperimentException(side + ": " + what + " failed: " + resp.describe());
    }
    Map<String, Object> o = resp.object();
    return o == null ? new LinkedHashMap<>() : o;
  }

  private static long num(Object v) {
    return v instanceof Number ? ((Number) v).longValue() : 0;
  }

  private static String str(Object v) {
    return v == null ? "" : String.valueOf(v);
  }

  @SuppressWarnings("unchecked")
  static Dataset findDataset(Control.Side side, String ref) {
    Map<String, Object> query = Destination.ONLINE.equals(side.name) && !ref.startsWith("ds_") ? Map.of("name", ref) : null;
    Map<String, Object> body = ok(side.call("GET", "datasets", null, query, null, null), "dataset list", side.name);
    Object list = body.get("datasets");
    if (list instanceof List) {
      for (Object d : (List<Object>) list) {
        if (!(d instanceof Map)) {
          continue;
        }
        Map<String, Object> m = (Map<String, Object>) d;
        if (str(m.get("id")).equals(ref) || ref.equals(m.get("name"))) {
          return new Dataset(str(m.get("id")), str(m.get("name")), side.name, num(m.get("item_count")), num(m.get("latest_snapshot")), m);
        }
      }
    }
    return null;
  }

  static Dataset getDataset(String nameOrId) {
    List<String> errors = new ArrayList<>();
    List<Control.Side> targets = Control.sides();
    if (targets.isEmpty()) {
      errors.add(Control.unavailableReason());
    }
    for (Control.Side side : targets) {
      try {
        Dataset d = findDataset(side, nameOrId);
        if (d != null) {
          return d;
        }
      } catch (ExperimentException e) {
        errors.add(e.getMessage());
      }
    }
    throw new ExperimentException(
        "dataset '" + nameOrId + "' not found" + (errors.isEmpty() ? "" : ": " + String.join("; ", errors)));
  }

  /** The default id of a literal item: content-derived (review E-75). */
  static String literalItemId(Object input, Object expected, Object metadata) {
    List<Object> triple = new ArrayList<>();
    triple.add(input);
    triple.add(expected);
    triple.add(metadata);
    return "item-" + Util.hex(Util.sha256(Json.canonical(triple))).substring(0, 16);
  }

  /** Literal items (maps or bare inputs) as {id, input, expected, metadata?} rows. */
  @SuppressWarnings("unchecked")
  static List<Map<String, Object>> literal(Iterable<?> items) {
    List<Map<String, Object>> out = new ArrayList<>();
    Map<String, Integer> seen = new HashMap<>();
    for (Object raw : items) {
      Map<String, Object> it;
      if (raw instanceof Map) {
        it = (Map<String, Object>) raw;
      } else {
        it = new LinkedHashMap<>();
        it.put("input", raw);
      }
      Object expected = it.containsKey("expected") ? it.get("expected") : it.get("expected_output");
      Object idv = it.get("id");
      String id = idv == null ? "" : String.valueOf(idv);
      if (id.isEmpty()) {
        id = literalItemId(it.get("input"), expected, it.get("metadata"));
        int n = seen.merge(id, 1, Integer::sum);
        if (n > 1) {
          id = id + "-" + n;
        }
      }
      Map<String, Object> row = new LinkedHashMap<>();
      row.put("id", id);
      row.put("input", it.get("input"));
      row.put("expected", expected);
      if (it.get("metadata") != null) {
        row.put("metadata", it.get("metadata"));
      }
      out.add(row);
    }
    return out;
  }

  @SuppressWarnings("unchecked")
  private static Run uploadLiteral(Control.Side side, String datasetName, List<Map<String, Object>> items) {
    if (Destination.LOCAL.equals(side.name)) {
      Map<String, Object> body = ok(side.call("POST", "datasets", Map.of("name", datasetName), null, null, null), "dataset create", side.name);
      Map<String, Object> ds = body.get("dataset") instanceof Map ? (Map<String, Object>) body.get("dataset") : body;
      String dsId = str(ds.get("id"));
      if (dsId.isEmpty()) {
        throw new ExperimentException("local: dataset create answered no id");
      }
      body = ok(side.call("POST", "dataset_snapshot", Map.of("items", items), null, null, Map.of("id", dsId)), "dataset items", side.name);
      List<String> ids = new ArrayList<>();
      if (body.get("item_ids") instanceof List) {
        for (Object x : (List<Object>) body.get("item_ids")) {
          if (x instanceof String || x instanceof Long) {
            ids.add(String.valueOf(x));
          }
        }
      }
      long version = num(body.get("version")) != 0 ? num(body.get("version")) : num(body.get("snapshot_version"));
      return new Run(side, dsId, version, ids);
    }
    Dataset d = findDataset(side, datasetName);
    if (d == null) {
      throw new ExperimentException(
          "online: dataset '" + datasetName + "' does not exist on the org (create it on the dashboard first)");
    }
    Map<String, Object> body = ok(side.call("POST", "dataset_snapshot", Map.of("items", items), null, null, Map.of("id", d.id)), "dataset snapshot", side.name);
    return new Run(side, d.id, num(body.get("version")), new ArrayList<>());
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> readItems(Control.Side side, Run run) {
    List<Map<String, Object>> out = new ArrayList<>();
    String cursor = "";
    for (int i = 0; i < 10_000; i++) {
      Map<String, Object> query = new LinkedHashMap<>();
      query.put("limit", ITEMS_PAGE);
      query.put("cursor", cursor);
      if (Destination.LOCAL.equals(side.name)) {
        query.put("version", run.snapshotVersion == 0 ? null : run.snapshotVersion);
        if (!run.runId.isEmpty()) {
          query.put("run", run.runId);
        }
      }
      Map<String, Object> parts = new LinkedHashMap<>();
      parts.put("id", run.datasetId);
      parts.put("version", run.snapshotVersion);
      Map<String, Object> body = ok(side.call("GET", "dataset_items", null, query, null, parts), "dataset items", side.name);
      if (body.get("items") instanceof List) {
        for (Object it : (List<Object>) body.get("items")) {
          if (it instanceof Map) {
            out.add((Map<String, Object>) it);
          }
        }
      }
      cursor = str(body.get("next_cursor"));
      if (cursor.isEmpty()) {
        break;
      }
    }
    return out;
  }

  private static String inputKey(Map<String, Object> item) {
    return Json.canonical(item.get("input"));
  }

  static Map<Integer, String> mapItems(List<Map<String, Object>> primary, List<Map<String, Object>> other) {
    Map<String, String> byClient = new HashMap<>();
    Map<String, LinkedList<String>> byInput = new HashMap<>();
    for (Map<String, Object> i : other) {
      String cid = str(i.get("client_id"));
      if (!cid.isEmpty()) {
        byClient.put(cid, str(i.get("item_id")));
      }
      byInput.computeIfAbsent(inputKey(i), k -> new LinkedList<>()).add(str(i.get("item_id")));
    }
    Map<Integer, String> out = new HashMap<>();
    for (int n = 0; n < primary.size(); n++) {
      Map<String, Object> it = primary.get(n);
      String cid = str(it.get("client_id"));
      if (!cid.isEmpty() && byClient.containsKey(cid)) {
        out.put(n, byClient.get(cid));
      } else {
        LinkedList<String> l = byInput.get(inputKey(it));
        if (l != null && !l.isEmpty()) {
          out.put(n, l.removeFirst());
        }
      }
    }
    return out;
  }

  // --- the run -------------------------------------------------------------------------------

  @SuppressWarnings("unchecked")
  static ExperimentResult run(Object dataset, ExperimentOptions o) {
    String runName = o.name != null && !o.name.isEmpty() ? o.name : "experiment";
    ExperimentResult result = new ExperimentResult(runName);
    List<Run> runs = new ArrayList<>();
    List<Map<String, Object>> items = new ArrayList<>();
    List<Map<String, Object>> scorers = new ArrayList<>();
    for (Evaluator e : o.evaluators) {
      Map<String, Object> s = new LinkedHashMap<>();
      s.put("name", evaluatorName(e));
      s.put("version", evaluatorVersion(e));
      scorers.add(s);
    }
    List<Control.Side> targets = Control.sides();
    if (dataset instanceof String || dataset instanceof Dataset) {
      String ref = dataset instanceof Dataset ? ((Dataset) dataset).id : (String) dataset;
      if (targets.isEmpty()) {
        throw new ExperimentException("dataset '" + ref + "': " + Control.unavailableReason());
      }
      int skipped = 0;
      for (Control.Side side : targets) {
        Dataset d;
        try {
          if (dataset instanceof Dataset && !((Dataset) dataset).side.isEmpty() && !((Dataset) dataset).side.equals(side.name)) {
            Dataset given = (Dataset) dataset;
            d = given.name.isEmpty() ? null : findDataset(side, given.name);
          } else {
            d = findDataset(side, ref);
          }
        } catch (SideSkipped e) {
          result.errors.add(e.getMessage());
          result.skippedSides.add(side.name);
          skipped++;
          continue;
        }
        if (d != null) {
          runs.add(new Run(side, d.id, o.snapshotVersion == null ? 0 : o.snapshotVersion, new ArrayList<>()));
        }
      }
      if (runs.isEmpty() && skipped == 0) {
        throw new ExperimentException("dataset '" + ref + "' not found on any destination");
      }
    } else if (dataset instanceof Iterable) {
      List<Map<String, Object>> lit = literal((Iterable<?>) dataset);
      if (o.datasetName != null && !o.datasetName.isEmpty()) {
        if (targets.isEmpty()) {
          result.errors.add(
              "dataset '" + o.datasetName + "' not uploaded, the run is in-process only: " + Control.unavailableReason());
        }
        for (Control.Side side : targets) {
          try {
            runs.add(uploadLiteral(side, o.datasetName, lit));
          } catch (SideSkipped e) {
            result.errors.add(e.getMessage());
            result.skippedSides.add(side.name);
          }
        }
      }
      for (Map<String, Object> it : lit) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("item_id", it.get("id"));
        row.put("client_id", it.get("id"));
        row.put("input", it.get("input"));
        row.put("expected", it.get("expected"));
        row.put("metadata", it.get("metadata"));
        row.put("has_content", true);
        items.add(row);
      }
    } else {
      throw new IllegalArgumentException("dataset must be a name or id, a Dataset, or an Iterable of items");
    }

    List<Run> started = new ArrayList<>();
    // One idempotency id per runExperiment call (review E-79).
    String createId = Util.randomHex32();
    for (Run r : runs) {
      try {
        Map<String, Object> create = new LinkedHashMap<>();
        create.put("id", createId);
        create.put("name", runName);
        create.put("dataset_id", r.datasetId);
        create.put("snapshot_version", r.snapshotVersion);
        create.put("metadata", o.metadata);
        create.put("scorers", scorers);
        if (!r.itemIds.isEmpty()) {
          create.put("item_ids", r.itemIds);
        }
        Http.Response resp = r.side.call("POST", "experiments", create, null, null, null);
        if (Scores.retryable(resp)) {
          resp = r.side.call("POST", "experiments", create, null, null, null);
        }
        Map<String, Object> body = ok(resp, "experiment create", r.side.name);
        r.runId = str(body.get("id"));
        long sv = num(body.get("snapshot_version"));
        if (sv != 0) {
          r.snapshotVersion = sv;
        }
        if (r.runId.isEmpty()) {
          throw new ExperimentException(r.side.name + ": experiment create answered no id");
        }
        r.items = readItems(r.side, r);
      } catch (SideSkipped e) {
        result.errors.add(e.getMessage());
        result.skippedSides.add(r.side.name);
        continue;
      }
      result.runs.put(r.side.name, r.runId);
      started.add(r);
    }
    runs = started;
    if (!runs.isEmpty()) {
      items = runs.get(0).items;
      for (int n = 0; n < items.size(); n++) {
        runs.get(0).itemMap.put(n, str(items.get(n).get("item_id")));
      }
      for (Run r : runs.subList(1, runs.size())) {
        r.itemMap = mapItems(items, r.items);
        int unmapped = items.size() - r.itemMap.size();
        if (unmapped > 0) {
          result.errors.add(
              r.side.name + ": " + unmapped + " item(s) have no match there; their results go to " + runs.get(0).side.name + " only");
        }
      }
      result.runId = runs.get(0).runId;
    }

    List<Integer> runnable = new ArrayList<>();
    for (int n = 0; n < items.size(); n++) {
      if (!Boolean.FALSE.equals(items.get(n).get("has_content"))) {
        runnable.add(n);
      }
    }
    result.skippedNoContent = items.size() - runnable.size();
    ItemResult[] done = new ItemResult[items.size()];
    Map<String, List<Map<String, Object>>> pending = new LinkedHashMap<>();
    for (Run r : runs) {
      pending.put(r.side.name, new ArrayList<>());
    }
    final List<Run> fruns = runs;
    final List<Map<String, Object>> fitems = items;
    Object lock = new Object();
    AtomicInteger failedPosts = new AtomicInteger();

    Runnable flushPending =
        () -> {
          for (Run r : fruns) {
            List<Map<String, Object>> batch;
            synchronized (lock) {
              batch = pending.get(r.side.name);
              if (batch.isEmpty()) {
                continue;
              }
              pending.put(r.side.name, new ArrayList<>());
            }
            for (int start = 0; start < batch.size(); start += RESULTS_PER_POST) {
              List<Map<String, Object>> chunk = batch.subList(start, Math.min(batch.size(), start + RESULTS_PER_POST));
              Http.Response resp =
                  r.side.call("POST", "experiment_results", Map.of("results", chunk), null, null, Map.of("id", r.runId));
              if (!resp.ok()) {
                failedPosts.addAndGet(chunk.size());
                result.errors.add(r.side.name + ": posting " + chunk.size() + " result(s) failed: " + resp.describe());
              } else if (resp.object() != null && resp.object().get("rejected") instanceof List) {
                for (Object rej : (List<Object>) resp.object().get("rejected")) {
                  if (rej instanceof Map) {
                    Map<String, Object> rm = (Map<String, Object>) rej;
                    failedPosts.incrementAndGet();
                    result.errors.add(r.side.name + ": result rejected: " + rm.get("error") + ": " + str(rm.get("message")));
                  }
                }
              }
            }
          }
        };

    String firstRunId = runs.isEmpty() ? "" : runs.get(0).runId;
    java.util.function.IntConsumer one =
        n -> {
          ItemResult res = runItem(o, fitems.get(n), runName, firstRunId);
          done[n] = res;
          for (Run r : fruns) {
            if (r.itemMap.containsKey(n)) {
              Map<String, Object> row = resultRow(r.itemMap.get(n), res);
              synchronized (lock) {
                pending.get(r.side.name).add(row);
              }
            }
          }
          flushPending.run();
        };

    int workers = Math.max(1, o.maxConcurrency);
    if (workers == 1 || runnable.size() <= 1) {
      for (int n : runnable) {
        one.accept(n);
      }
    } else {
      ExecutorService pool =
          Executors.newFixedThreadPool(
              Math.min(workers, runnable.size()),
              rr -> {
                Thread t = new Thread(rr, "superbased-experiment");
                t.setDaemon(true);
                return t;
              });
      try {
        List<Future<?>> futures = new ArrayList<>();
        for (int n : runnable) {
          futures.add(pool.submit(() -> one.accept(n)));
        }
        for (Future<?> f : futures) {
          try {
            f.get();
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            break;
          } catch (java.util.concurrent.ExecutionException e) {
            result.errors.add("item: " + e.getCause());
          }
        }
      } finally {
        pool.shutdown();
      }
    }
    flushPending.run();
    result.failedPosts += failedPosts.get();
    for (ItemResult r : done) {
      if (r != null) {
        result.items.add(r);
      }
    }

    Superbased.flush(); // the items' traces, before the run is read back
    for (Run r : runs) {
      Http.Response resp = r.side.call("POST", "experiment_finish", Map.of(), null, null, Map.of("id", r.runId));
      if (!resp.ok()) {
        result.errors.add(r.side.name + ": finish failed: " + resp.describe());
      }
      Http.Response got = r.side.call("GET", "experiment", null, null, null, Map.of("id", r.runId));
      if (got.ok() && got.object() != null) {
        result.server.put(r.side.name, got.object());
      }
    }
    for (String e : result.errors()) {
      Util.warn("experiment " + runName + ": " + e);
    }
    if (o.failUnder != null && o.strict) {
      List<String> problems = gateProblems(result);
      if (!problems.isEmpty()) {
        for (String p : problems) {
          result.errors.add("gate: " + p);
        }
        throw new ExperimentGateFailedException(result, o.failUnder, problems);
      }
    }
    if (o.failUnder != null && result.scored() == 0) {
      String msg = "no scores: no item was scored (no evaluator ran), so failUnder was not applied (strict=false)";
      result.errors.add(msg);
      Util.warn("experiment " + runName + ": " + msg);
    }
    if (gateFails(result, o.failUnder, o.strict)) {
      throw new ExperimentGateFailedException(result, o.failUnder, List.of());
    }
    return result;
  }

  private static ItemResult runItem(ExperimentOptions o, Map<String, Object> it, String runName, String runId) {
    ItemResult res = new ItemResult(str(it.get("item_id")), it.get("input"), it.get("expected"), it.get("metadata"));
    AttributesBuilder ab = Attributes.builder().put(Keys.SPAN_KIND, Kind.CHAIN);
    if (!runId.isEmpty()) {
      ab.put(Keys.EXPERIMENT_RUN_ID, runId);
    }
    if (!res.itemId.isEmpty()) {
      ab.put(Keys.EXPERIMENT_ITEM_ID, res.itemId);
    }
    // A fresh root context: every item is its own trace.
    Span sp = Superbased.tracer().spanBuilder("experiment " + runName).setParent(Context.root()).setAllAttributes(ab.build()).startSpan();
    try (Scope ignored = Context.root().with(sp).makeCurrent()) {
      res.traceId = sp.getSpanContext().isValid() ? sp.getSpanContext().getTraceId() : "";
      Spans.setInput(sp, res.input);
      try {
        res.output = o.task.run(new ExperimentItem(res.itemId, res.input, res.expected, res.metadata));
        Spans.setOutput(sp, res.output);
      } catch (Exception e) {
        res.error = Util.head(e.getClass().getSimpleName() + ": " + e.getMessage(), 500);
        try {
          sp.recordException(e);
          sp.setStatus(StatusCode.ERROR, res.error);
        } catch (RuntimeException ignored2) {
          // never raises
        }
      }
    } finally {
      sp.end();
    }
    if (!res.error.isEmpty()) {
      return res;
    }
    EvalInput in = new EvalInput(res.input, res.output, res.expected, res.metadata);
    for (Evaluator ev : o.evaluators) {
      try {
        res.scores.addAll(normalize(ev, ev.evaluate(in)));
      } catch (Exception e) {
        res.evaluatorErrors.add(Util.head(evaluatorName(ev) + ": " + e.getClass().getSimpleName() + ": " + e.getMessage(), 300));
      }
    }
    return res;
  }

  private static Map<String, Object> resultRow(String itemId, ItemResult res) {
    Map<String, Object> row = new LinkedHashMap<>();
    row.put("item_id", itemId);
    if (!res.traceId.isEmpty()) {
      row.put("trace_id", res.traceId);
    }
    if (!res.error.isEmpty()) {
      row.put("error", res.error);
    } else if (Superbased.captureContent() && res.output != null) {
      row.put("output", res.output instanceof String ? res.output : Json.write(res.output));
    }
    List<Map<String, Object>> scores = new ArrayList<>();
    for (Evaluation s : res.scores) {
      Map<String, Object> obj;
      try {
        obj =
            Scores.build(
                s.name,
                s.value,
                res.traceId.isEmpty() ? "1".repeat(32) : res.traceId,
                null,
                s.comment,
                null,
                Scores.SOURCE_SDK,
                s.name,
                s.scorerVersion,
                null,
                null,
                null,
                false);
      } catch (Scores.ScoreError e) {
        synchronized (res.evaluatorErrors) {
          res.evaluatorErrors.add(s.name + ": " + e.getMessage());
        }
        continue;
      }
      obj.remove("id");
      obj.remove("trace_id");
      obj.remove("span_id");
      obj.remove("source");
      scores.add(obj);
    }
    row.put("scores", scores);
    return row;
  }
}
