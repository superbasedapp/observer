/**
 * Datasets and experiments (W3-2; contract `contracts/experiments.md`, lane
 * B7; the same flow as the Python SDK's `run_experiment`).
 *
 * `runExperiment({ dataset, task, evaluators })`:
 * 1. finds the dataset by name or id on each destination side (online
 *    first, then this machine), or uploads inline items as a literal
 *    snapshot of `datasetName` (created on the machine; on the org it must
 *    exist). Inline items without `datasetName` run in-process only and
 *    nothing is posted;
 * 2. creates a run on each side (`POST /v1/sdk/experiments`, machine
 *    `/api/obs/eval/experiments`), which freezes a snapshot unless
 *    `snapshotVersion` pins one, and reads that snapshot's items. Under `both`
 *    the task runs once: the other side's items are matched by client id,
 *    then by input;
 * 3. runs `task` on each item in its own trace (a CHAIN root span stamped
 *    `sbo.experiment.run_id` / `sbo.experiment.item_id`), then the
 *    evaluators in-process;
 * 4. posts each item's result (output under captureContent, scores, error)
 *    to each run as it finishes; the server also stores each score on the
 *    item's trace;
 * 5. finishes the runs and reads their totals.
 *
 * An experiment is an explicit batch job, so unlike the tracing calls a
 * dataset that cannot be found or a run that cannot be created rejects with
 * {@link ExperimentError}, and `failUnder` rejects with
 * {@link ExperimentGateFailed} (and sets `process.exitCode = 1`) when the
 * pass rate is below it. A task or evaluator that throws is recorded on its
 * item; the run goes on. CI credentials need the `sdk:eval` scope.
 */

import { createHash } from "node:crypto";

import { context, trace } from "@opentelemetry/api";

import { K } from "./attrs.js";
import { apiTimeout, call, newId, noTargetReason, retryable, targets, type ControlOptions, type ControlResponse, type Target, type TargetName } from "./control.js";
import type { PlanRefusalError } from "./planrefusal.js";
import { contentText, destinationKnown, runtime, truncateContent } from "./runtime.js";
import { getCurrentTraceId, Kind, setInput, setOutput, withSpan } from "./spans.js";

export interface DatasetItem {
  /** The server's item id (`it_...`), or yours for an inline item. */
  id?: string;
  input: unknown;
  expectedOutput?: unknown;
  metadata?: Record<string, unknown>;
}

export interface Dataset {
  id: string;
  name: string;
  /** The snapshot version the items come from (0 for inline items). */
  version: number;
  items: DatasetItem[];
  /** Items frozen without content (their trace's content was not stored); skipped by an experiment. */
  skippedNoContent: number;
  target?: TargetName;
}

export interface EvaluatorArgs {
  input: unknown;
  output: unknown;
  expectedOutput: unknown;
  /** The same as expectedOutput (the Python SDK's name). */
  expected: unknown;
  metadata: Record<string, unknown>;
  item: DatasetItem;
}

/** One evaluation: a bare value (named after the evaluator) or a named result. */
export type Evaluation = number | boolean | string | { name?: string; value: number | boolean | string; comment?: string };
type EvalOut = Evaluation | Evaluation[] | null | undefined;

/** An evaluator: a function (its name names the score) or a named, versioned function. */
export type Evaluator =
  | ((args: EvaluatorArgs) => EvalOut | Promise<EvalOut>)
  | { name: string; version?: string; evaluate: (args: EvaluatorArgs) => EvalOut | Promise<EvalOut> };

export interface ExperimentOptions extends ControlOptions {
  /** A dataset name or id (fetched), a fetched Dataset, or the items themselves. */
  dataset: string | Dataset | Array<DatasetItem & { expected?: unknown }>;
  /** Runs on one item's input; may be async. */
  task: (input: unknown, item: DatasetItem) => unknown;
  evaluators?: Evaluator[];
  /** The experiment's name (default: the task's name, else `experiment`). */
  name?: string;
  /** Stored with the run. */
  metadata?: Record<string, unknown>;
  /** Items run at once (default 4). */
  maxConcurrency?: number;
  /** A frozen snapshot version to run over (default: freeze a new one). The contract name (Python `snapshot_version`). */
  snapshotVersion?: number;
  /** @deprecated The pre-contract name of `snapshotVersion`; still read when `snapshotVersion` is not set (review E-49). */
  datasetVersion?: number;
  /** For inline items: the dataset they are uploaded to (created on the machine; on the org it must exist). */
  datasetName?: string;
  /** CI gate: below this pass rate runExperiment rejects with ExperimentGateFailed and sets process.exitCode = 1. */
  failUnder?: number;
  /**
   * With `failUnder` set, the gate is strict by default (review E-12): a run
   * that scored nothing, a skipped destination or a result a destination did
   * not accept also fails it, because a CI gate that passes on an outage is
   * worse than none. `false` gates on the pass rate alone.
   */
  strict?: boolean;
}

export interface ItemResult {
  item: DatasetItem;
  traceId: string;
  output: unknown;
  /** The task's error, if it threw. */
  error: string;
  scores: Array<{ name: string; value: number | boolean | string; comment?: string; error?: string }>;
  /** Why a result was not accepted ("" when it was, or nothing was posted). */
  postError: string;
}

export interface ExperimentResult {
  /** The first side's run id ("" when nothing was recorded). */
  runId: string;
  /** Run id per side. */
  runs: Partial<Record<TargetName, string>>;
  name: string;
  datasetId: string;
  snapshotVersion: number;
  items: ItemResult[];
  /** Mean of each numeric / boolean score, with its count. */
  summary: Record<string, { mean: number; count: number }>;
  /**
   * The first side's pass rate, else computed locally over the scored items.
   * NaN when nothing was scored (`scored` 0): no rate, not 0.
   */
  passRate: number;
  /**
   * How many items were scored: the side's `total`, else the local count of
   * items with a score or a task error. An item with neither (no evaluator
   * ran, or every evaluator threw) is neither passed nor failed. `failUnder`
   * is not applied when this is 0; `errors` says "no scores" instead.
   */
  scored: number;
  /** Whether the runs were created and finished. */
  recorded: boolean;
  skippedNoContent: number;
  /** Problems that are not one item's (a result a side refused, an unmatched item). */
  errors: string[];
  /** Destinations skipped for want of a scope (403 insufficient_scope). */
  skippedSides: TargetName[];
  /** Results a destination did not accept (a failed post or a rejected row; one per result per side). */
  failedPosts: number;
  /** Set when the org's plan refused a post or the finish (its `message` and `upgradeUrl` say why and where to fix it). */
  planRefusal?: PlanRefusalError;
  /** The totals each side returned (`GET .../experiments/{id}`). */
  server: Partial<Record<TargetName, Record<string, unknown>>>;
}

/**
 * The experiment could not be set up (dataset, run creation). `planRefusal`
 * (also the `cause`) is set when the org's plan refused it: its `message`
 * and `upgradeUrl` say why and where to fix it.
 */
export class ExperimentError extends Error {
  readonly planRefusal?: PlanRefusalError;

  constructor(message: string, planRefusal?: PlanRefusalError) {
    super(message, planRefusal ? { cause: planRefusal } : undefined);
    this.name = "ExperimentError";
    if (planRefusal) this.planRefusal = planRefusal;
  }
}

/**
 * A destination refused a dataset or experiment call for want of a scope
 * (403 `insufficient_scope`): a member SDK key from `observer sdk sign-in`
 * deliberately lacks `sdk:eval`, which every org dataset and experiment route
 * needs. runExperiment skips that destination with an entry in `errors` and
 * carries on with the other one; it never rejects for this.
 */
class SideSkipped extends ExperimentError {}

function scopeRefused(r: ControlResponse): boolean {
  return r.status === 403 && r.error === "insufficient_scope";
}

function skipReason(side: TargetName, what: string, r: ControlResponse): string {
  return `${side}: skipped, ${what} refused: ${describe(r)} (an SDK key from sign-in has no sdk:eval scope; run experiments on the org with a CI credential that has it)`;
}

/**
 * The `failUnder` gate failed (a CI gate): the pass rate is below it, or,
 * strict (the default), `reasons` says why the gate could not pass at all.
 */
export class ExperimentGateFailed extends Error {
  constructor(
    readonly result: ExperimentResult,
    readonly failUnder: number,
    readonly reasons: string[] = [],
  ) {
    super(
      reasons.length
        ? `experiment ${JSON.stringify(result.name)}: the failUnder gate cannot pass: ${reasons.join("; ")} (strict; pass strict: false to gate on the pass rate alone)`
        : `experiment ${JSON.stringify(result.name)}: pass rate ${result.passRate.toFixed(3)} is below ${failUnder.toFixed(3)}`,
    );
    this.name = "ExperimentGateFailed";
  }
}

/**
 * The `failUnder` gate (contract experiments.md 4.2, review E-12): `reasons`
 * are why a strict gate fails before the rate is compared (nothing scored, a
 * skipped destination, results not accepted); `failed` applies them when
 * `strict`, then the rate. A run that scored nothing is not failed when not
 * strict. Python: gate_problems / gate_fails.
 */
export function experimentGate(
  r: Pick<ExperimentResult, "scored" | "passRate" | "skippedSides" | "failedPosts">,
  failUnder: number | undefined,
  strict = true,
): { failed: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (r.scored === 0) reasons.push("no item was scored (no evaluator returned a score)");
  for (const side of r.skippedSides) reasons.push(`the ${side} destination was skipped`);
  if (r.failedPosts) reasons.push(`${r.failedPosts} result(s) were not accepted, so the recorded pass rate covers only part of the run`);
  if (failUnder === undefined || failUnder === null) return { failed: false, reasons };
  if (strict && reasons.length) return { failed: true, reasons };
  return { failed: r.scored > 0 && !(r.passRate >= failUnder), reasons };
}

function obj(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

const idOf = (v: unknown): string => (typeof v === "string" || typeof v === "number" ? String(v) : "");

function describe(r: ControlResponse): string {
  return `${r.target}: ${r.status ? `HTTP ${r.status} ` : ""}${r.error}${r.message ? `: ${r.message}` : ""}`;
}

const enc = encodeURIComponent;

/** Find a dataset by name or id on one target. */
async function findDataset(
  t: Target,
  nameOrId: string,
  opts: ControlOptions,
): Promise<{ id: string; name: string; error: string; skipped?: boolean; planRefusal?: PlanRefusalError }> {
  const timeoutMs = apiTimeout(opts);
  const list = await call(t, "GET", { online: `/datasets?name=${enc(nameOrId)}`, local: "/api/obs/eval/datasets" }, { timeoutMs, quiet404: true });
  if (scopeRefused(list)) return { id: "", name: "", error: skipReason(t.name, "dataset list", list), skipped: true };
  if (list.ok) {
    const rows = (Array.isArray(obj(list.body).datasets) ? obj(list.body).datasets : Array.isArray(list.body) ? list.body : []) as unknown[];
    const hit = rows.map(obj).find((d) => d.name === nameOrId || idOf(d.id) === nameOrId);
    if (hit) return { id: idOf(hit.id), name: String(hit.name ?? nameOrId), error: "" };
  }
  const one = await call(t, "GET", { online: `/datasets/${enc(nameOrId)}`, local: `/api/obs/eval/datasets/${enc(nameOrId)}` }, { timeoutMs, quiet404: true });
  if (one.ok) {
    const d = obj(obj(one.body).dataset ?? one.body);
    if (idOf(d.id)) return { id: idOf(d.id), name: String(d.name ?? nameOrId), error: "" };
  }
  return { id: "", name: "", error: list.ok ? `${t.name}: no dataset named ${JSON.stringify(nameOrId)}` : describe(list), planRefusal: list.planRefusal ?? one.planRefusal };
}

function parseItem(x: Record<string, unknown>): { item: DatasetItem; hasContent: boolean } {
  return {
    item: {
      id: idOf(x.item_id ?? x.id) || undefined,
      input: x.input,
      expectedOutput: x.expected ?? x.expected_output,
      metadata: Object.keys(obj(x.metadata)).length ? obj(x.metadata) : undefined,
    },
    hasContent: x.has_content !== false,
  };
}

/**
 * Compact JSON with object keys sorted at every level (`undefined` as null):
 * the same text Python's canonical form gives, so both SDKs derive the same
 * item id.
 */
function canonical(v: unknown): string {
  if (v === undefined || v === null) return "null";
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v) ?? "null";
}

/**
 * The default id of a literal item: derived from its content (review E-75),
 * so a re-run with changed inputs makes new items on the machine instead of
 * matching the previous run's `item-00001`. Python gives the same id
 * (sdk-behaviour-cases.json `literal_item_ids`).
 */
export function literalItemId(input: unknown, expected?: unknown, metadata?: unknown): string {
  return "item-" + createHash("sha256").update(canonical([input, expected, metadata]), "utf8").digest("hex").slice(0, 16);
}

/**
 * Inline items as the literal upload rows `{id, input, expected, metadata?}`.
 * A missing id is {@link literalItemId} of the content; the same content
 * twice gets `-2`, `-3`, ... (E-75; Python's `_literal`).
 */
export function literalRows(ds: ReadonlyArray<DatasetItem & { expected?: unknown }>): Array<Record<string, unknown>> {
  const seen = new Map<string, number>();
  return ds.map((it) => {
    const expected = it.expectedOutput ?? it.expected;
    let id = it.id === undefined || it.id === null || it.id === "" ? "" : String(it.id);
    if (!id) {
      id = literalItemId(it.input, expected, it.metadata);
      const n = (seen.get(id) ?? 0) + 1;
      seen.set(id, n);
      if (n > 1) id = `${id}-${n}`;
    }
    const row: Record<string, unknown> = { id, input: it.input, expected };
    if (it.metadata) row.metadata = it.metadata;
    return row;
  });
}

/** Read a snapshot's items on one target (all pages); `runId`: the run's own items on the machine. */
async function readItems(
  t: Target,
  datasetId: string,
  version: number,
  opts: ControlOptions,
  runId = "",
): Promise<{ items: DatasetItem[]; raw: Array<Record<string, unknown>>; skipped: number; error: string; scopeRefused?: ControlResponse; planRefusal?: PlanRefusalError }> {
  const items: DatasetItem[] = [];
  const rawItems: Array<Record<string, unknown>> = [];
  let skipped = 0;
  let cursor = "";
  for (let page = 0; page < 1000; page++) {
    const q = `limit=500${cursor ? `&cursor=${enc(cursor)}` : ""}`;
    const r = await call(
      t,
      "GET",
      {
        online: `/datasets/${enc(datasetId)}/snapshots/${version}/items?${q}`,
        // run=: the run's pinned set (a literal upload), else every item up to its version (R-B22, E-75).
        local: `/api/obs/eval/datasets/${enc(datasetId)}/items?${q}${version ? `&version=${version}` : ""}${runId ? `&run=${enc(runId)}` : ""}`,
      },
      { timeoutMs: apiTimeout(opts) },
    );
    if (!r.ok) return { items, raw: rawItems, skipped, error: describe(r), scopeRefused: scopeRefused(r) ? r : undefined, planRefusal: r.planRefusal };
    const body = obj(r.body);
    for (const raw of (Array.isArray(body.items) ? body.items : []) as unknown[]) {
      const { item, hasContent } = parseItem(obj(raw));
      if (hasContent) {
        items.push(item);
        rawItems.push(obj(raw));
      } else skipped += 1;
    }
    cursor = typeof body.next_cursor === "string" ? body.next_cursor : "";
    if (!cursor) break;
  }
  return { items, raw: rawItems, skipped, error: "" };
}

/**
 * Fetch a dataset's items: by name or id, from a snapshot `version` (default
 * the latest), from the first destination that has it (the org first under
 * `both`). Rejects with {@link ExperimentError} when no destination has it
 * (or none is usable), as Python's `get_dataset` raises (review R-C34);
 * `errors` lists what an earlier destination answered when a later one had
 * it.
 */
export async function getDataset(nameOrId: string, opts: ControlOptions & { version?: number } = {}): Promise<Dataset & { errors: string[] }> {
  const errors: string[] = [];
  let refused: PlanRefusalError | undefined;
  await destinationKnown();
  const ts = targets("read", opts);
  if (!ts.length) errors.push(noTargetReason());
  for (const t of ts) {
    const ds = await findDataset(t, nameOrId, opts);
    if (!ds.id) {
      errors.push(ds.error);
      refused ??= ds.planRefusal;
      continue;
    }
    let version = opts.version ?? 0;
    if (!version && t.name === "online") {
      const d = await call(t, "GET", `/datasets/${enc(ds.id)}`, { timeoutMs: apiTimeout(opts) });
      const snaps = (Array.isArray(obj(d.body).snapshots) ? obj(d.body).snapshots : []) as unknown[];
      version = Math.max(0, ...snaps.map((x) => Number(obj(x).version) || 0));
      if (!version) version = Number(obj(obj(d.body).dataset).latest_snapshot) || 0;
    }
    const r = await readItems(t, ds.id, version, opts);
    if (r.error) {
      errors.push(r.error);
      refused ??= r.planRefusal;
      continue;
    }
    return { id: ds.id, name: ds.name, version, items: r.items, skippedNoContent: r.skipped, target: t.name, errors };
  }
  const why = errors.filter((e) => e);
  throw new ExperimentError(`dataset ${JSON.stringify(nameOrId)} not found${why.length ? `: ${why.join("; ")}` : ""}`, refused);
}

function evaluatorMeta(e: Evaluator, i: number): { name: string; version: string; run: (a: EvaluatorArgs) => EvalOut | Promise<EvalOut> } {
  if (typeof e === "function") return { name: e.name || `evaluator_${i + 1}`, version: "1", run: e };
  return { name: e.name || `evaluator_${i + 1}`, version: e.version || "1", run: (a) => e.evaluate(a) };
}

function normalize(name: string, r: Evaluation): { name: string; value: number | boolean | string; comment?: string } | null {
  if (r === null || r === undefined) return null;
  if (typeof r === "object") {
    if (r.value === undefined || r.value === null) return null;
    return { name: r.name || name, value: r.value, comment: r.comment };
  }
  return { name, value: r };
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (x: T, i: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

interface Run {
  target: Target;
  datasetId: string;
  version: number;
  id: string;
  /** Our item index -> this side's item id. */
  itemIds: Map<number, string>;
  /** The machine's ids of a literal upload's items: the run is pinned to exactly them (R-B22, E-75). */
  pinned: string[];
}

const keyOf = (input: unknown): string => {
  try {
    return JSON.stringify(input, Object.keys(obj(input)).sort()) ?? String(input);
  } catch {
    return String(input);
  }
};

function routes(id = "", version = 0) {
  const i = enc(id);
  return {
    datasets: { online: "/datasets", local: "/api/obs/eval/datasets" },
    snapshot: { online: `/datasets/${i}/snapshots`, local: `/api/obs/eval/datasets/${i}/items` },
    experiments: { online: "/experiments", local: "/api/obs/eval/experiments" },
    results: { online: `/experiments/${i}/results`, local: `/api/obs/eval/experiments/${i}/results` },
    finish: { online: `/experiments/${i}/finish`, local: `/api/obs/eval/experiments/${i}/finish` },
    run: { online: `/experiments/${i}`, local: `/api/obs/eval/experiments/${i}` },
    version,
  };
}

/** Put literal items where a run can see them: [dataset id, snapshot version, the machine's ids of exactly these items (empty on the org)]. */
async function uploadLiteral(t: Target, datasetName: string, items: Array<Record<string, unknown>>, timeoutMs: number): Promise<[string, number, string[]]> {
  let id = "";
  if (t.name === "local") {
    const made = await call(t, "POST", routes().datasets, { body: { name: datasetName }, timeoutMs });
    if (scopeRefused(made)) throw new SideSkipped(skipReason(t.name, "dataset create", made));
    if (!made.ok) throw new ExperimentError(`local: dataset create: ${describe(made)}`, made.planRefusal);
    id = idOf(obj(obj(made.body).dataset ?? made.body).id);
    if (!id) throw new ExperimentError("local: dataset create answered no id");
  } else {
    const found = await findDataset(t, datasetName, { timeoutMs });
    if (found.skipped) throw new SideSkipped(found.error);
    if (!found.id && found.planRefusal) throw new ExperimentError(`online: dataset list: ${found.error}`, found.planRefusal);
    if (!found.id) throw new ExperimentError(`online: dataset ${JSON.stringify(datasetName)} does not exist on the org (create it on the dashboard first)`);
    id = found.id;
  }
  const r = await call(t, "POST", routes(id).snapshot, { body: { items }, timeoutMs });
  if (scopeRefused(r)) throw new SideSkipped(skipReason(t.name, "dataset snapshot", r));
  if (!r.ok) throw new ExperimentError(`${t.name}: dataset snapshot: ${describe(r)}`, r.planRefusal);
  const raw = obj(r.body).item_ids;
  const pinned = t.name === "local" && Array.isArray(raw) ? raw.filter((x) => typeof x === "string" || typeof x === "number").map(String) : [];
  return [id, Number(obj(r.body).version ?? obj(r.body).snapshot_version) || 0, pinned];
}

/**
 * Run `task` over a dataset and score each output.
 *
 * ```ts
 * const res = await runExperiment({
 *   name: "prompt-v7",
 *   dataset: "golden-qa",
 *   task: async (input) => answer(input),
 *   evaluators: [function exact_match({ output, expectedOutput }) { return output === expectedOutput; }],
 *   failUnder: 0.9,
 * });
 * ```
 */
export async function runExperiment(opts: ExperimentOptions): Promise<ExperimentResult> {
  const name = opts.name || opts.task.name || "experiment";
  const result: ExperimentResult = {
    runId: "",
    runs: {},
    name,
    datasetId: "",
    snapshotVersion: 0,
    items: [],
    summary: {},
    passRate: NaN,
    scored: 0,
    recorded: false,
    skippedNoContent: 0,
    errors: [],
    skippedSides: [],
    failedPosts: 0,
    server: {},
  };
  const evaluators = (opts.evaluators ?? []).map(evaluatorMeta);
  const scorers = evaluators.map((e) => ({ name: e.name, version: e.version }));
  const timeoutMs = apiTimeout(opts);
  await destinationKnown();
  const sides = targets("read", opts); // online first, then this machine
  const runs: Run[] = [];
  let items: DatasetItem[] = [];

  // 1. The dataset on each side.
  const ds = opts.dataset;
  if (Array.isArray(ds)) {
    const literal = literalRows(ds);
    items = literal.map((r) => ({ id: String(r.id), input: r.input, expectedOutput: r.expected, metadata: r.metadata as Record<string, unknown> | undefined }));
    if (opts.datasetName) {
      // A degraded online uploads nothing: the run stays in-process and says
      // why (contract section 6; as Python).
      if (!sides.length) result.errors.push(`dataset ${JSON.stringify(opts.datasetName)} not uploaded, the run is in-process only: ${noTargetReason()}`);
      for (const t of sides) {
        try {
          const [id, version, pinned] = await uploadLiteral(t, opts.datasetName, literal, timeoutMs);
          runs.push({ target: t, datasetId: id, version, id: "", itemIds: new Map(), pinned });
        } catch (err) {
          if (!(err instanceof SideSkipped)) throw err;
          result.errors.push(err.message);
          result.skippedSides.push(t.name);
        }
      }
    }
  } else {
    const ref = typeof ds === "string" ? ds : ds.id;
    if (!sides.length) throw new ExperimentError(`dataset ${JSON.stringify(ref)}: ${noTargetReason()}`);
    let skipped = 0;
    let refused: PlanRefusalError | undefined;
    for (const t of sides) {
      const found = typeof ds !== "string" && ds.target && ds.target !== t.name && ds.name ? await findDataset(t, ds.name, opts) : await findDataset(t, ref, opts);
      refused ??= found.planRefusal;
      if (found.skipped) {
        result.errors.push(found.error);
        result.skippedSides.push(t.name);
        skipped += 1;
      } else if (found.id) runs.push({ target: t, datasetId: found.id, version: opts.snapshotVersion ?? opts.datasetVersion ?? 0, id: "", itemIds: new Map(), pinned: [] });
    }
    if (!runs.length && !skipped) {
      const why = refused ? `: ${refused.code}: ${refused.message}` : "";
      throw new ExperimentError(`dataset ${JSON.stringify(ref)} not found on any destination${why}`, refused);
    }
  }

  // 2. A run on each side, and its snapshot's items. A side that refuses
  // for want of a scope is skipped (SideSkipped), the others go on.
  const started: Run[] = [];
  // One idempotency id per runExperiment call (review E-79): every side's
  // create carries it, and a create retried after no answer, a 429 or a 5xx
  // carries it again, so the side answers the run the first attempt opened
  // instead of opening a second one (contract experiments.md 4.1).
  const createId = newId();
  for (const r of runs) {
    const create: Record<string, unknown> = { id: createId, name, dataset_id: r.datasetId, snapshot_version: r.version, metadata: opts.metadata ?? {}, scorers };
    if (r.pinned.length) create.item_ids = r.pinned;
    let created = await call(r.target, "POST", routes().experiments, { body: create, timeoutMs });
    if (retryable(created)) created = await call(r.target, "POST", routes().experiments, { body: create, timeoutMs });
    if (scopeRefused(created)) {
      result.errors.push(skipReason(r.target.name, "experiment create", created));
      result.skippedSides.push(r.target.name);
      continue;
    }
    if (!created.ok) throw new ExperimentError(`${r.target.name}: experiment create: ${describe(created)}`, created.planRefusal);
    const body = obj(created.body);
    r.id = idOf(body.id);
    if (!r.id) throw new ExperimentError(`${r.target.name}: experiment create answered no id`);
    r.version = Number(body.snapshot_version) || r.version;
    const read = await readItems(r.target, r.datasetId, r.version, opts, r.target.name === "local" ? r.id : "");
    if (read.scopeRefused) {
      result.errors.push(skipReason(r.target.name, "dataset items", read.scopeRefused));
      result.skippedSides.push(r.target.name);
      continue;
    }
    if (read.error) throw new ExperimentError(`${r.target.name}: dataset items: ${read.error}`, read.planRefusal);
    result.runs[r.target.name] = r.id;
    const n = started.length;
    started.push(r);
    if (n === 0 && !Array.isArray(ds)) {
      items = read.items;
      result.skippedNoContent = read.skipped;
      items.forEach((it, i) => r.itemIds.set(i, it.id ?? ""));
    } else {
      // Match this side's items to ours: by client id, then by input.
      const byClient = new Map<string, string>();
      const byInput = new Map<string, string[]>();
      for (const it of read.raw) {
        const id = idOf(it.item_id ?? it.id);
        if (it.client_id) byClient.set(idOf(it.client_id), id);
        const k = keyOf(it.input);
        byInput.set(k, [...(byInput.get(k) ?? []), id]);
      }
      let unmatched = 0;
      items.forEach((it, i) => {
        const hit = (it.id && byClient.get(it.id)) || byInput.get(keyOf(it.input))?.shift();
        if (hit) r.itemIds.set(i, hit);
        else unmatched += 1;
      });
      if (unmatched) result.errors.push(`${r.target.name}: ${unmatched} item(s) have no match there; their results go to ${started[0].target.name} only`);
    }
  }
  runs.splice(0, runs.length, ...started);
  if (runs.length) {
    result.runId = runs[0].id;
    result.datasetId = runs[0].datasetId;
    result.snapshotVersion = runs[0].version;
  }

  // 3-4. Run, evaluate, post each result.
  const firstRunId = runs[0]?.id ?? "";
  result.items = await mapLimit(items, opts.maxConcurrency ?? 4, async (item, idx) => {
    const ir: ItemResult = { item, traceId: "", output: undefined, error: "", scores: [], postError: "" };
    const itemId = runs[0]?.itemIds.get(idx) || item.id || "";
    const attrs: Record<string, unknown> = {};
    if (firstRunId) attrs[K.experimentRunId] = firstRunId;
    if (itemId) attrs[K.experimentItemId] = itemId;
    // Each item is its own trace, even when runExperiment runs inside a span.
    await context
      .with(trace.deleteSpan(context.active()), () =>
        withSpan(`experiment ${name}`, { kind: Kind.CHAIN, attributes: attrs }, async (span) => {
          ir.traceId = getCurrentTraceId();
          setInput(span, item.input);
          try {
            ir.output = await opts.task(item.input, item);
            setOutput(span, ir.output);
          } catch (err) {
            ir.error = (err instanceof Error ? `${err.name}: ${err.message}` : String(err)).slice(0, 500);
            throw err; // the span records it; the item keeps the error
          }
        }),
      )
      .catch(() => undefined);
    const wire: Array<Record<string, unknown>> = [];
    if (!ir.error) {
      const args: EvaluatorArgs = {
        input: item.input,
        output: ir.output,
        expectedOutput: item.expectedOutput,
        expected: item.expectedOutput,
        metadata: item.metadata ?? {},
        item,
      };
      for (const ev of evaluators) {
        try {
          const raw = await ev.run(args);
          for (const one of Array.isArray(raw) ? raw : [raw]) {
            const sc = normalize(ev.name, one as Evaluation);
            if (!sc) continue;
            ir.scores.push(sc);
            wire.push({ name: sc.name, value: sc.value, ...(sc.comment ? { comment: sc.comment } : {}), scorer: { name: ev.name, version: ev.version } });
          }
        } catch (err) {
          ir.scores.push({ name: ev.name, value: "", error: (err instanceof Error ? err.message : String(err)).slice(0, 300) });
        }
      }
    }
    for (const r of runs) {
      const sideItem = r.itemIds.get(idx);
      if (!sideItem) continue;
      const row: Record<string, unknown> = { item_id: sideItem, scores: wire };
      if (ir.traceId) row.trace_id = ir.traceId;
      if (ir.error) row.error = ir.error;
      if (runtime.captureContent && ir.output !== undefined) row.output = truncateContent(contentText(ir.output));
      const resp = await call(r.target, "POST", routes(r.id).results, { body: { results: [row] }, timeoutMs });
      const rejected = (Array.isArray(obj(resp.body).rejected) ? obj(resp.body).rejected : []) as unknown[];
      const why = !resp.ok ? describe(resp) : rejected.length ? `${String(obj(rejected[0]).error)}: ${String(obj(rejected[0]).message ?? "")}` : "";
      if (why) {
        ir.postError = ir.postError ? `${ir.postError}; ${r.target.name}: ${why}` : `${r.target.name}: ${why}`;
        result.failedPosts += 1;
        result.planRefusal ??= resp.planRefusal;
      }
    }
    return ir;
  });

  // Local summary.
  const sums: Record<string, { sum: number; count: number }> = {};
  for (const it of result.items) {
    for (const sc of it.scores) {
      if (sc.error) continue;
      const v = typeof sc.value === "boolean" ? (sc.value ? 1 : 0) : typeof sc.value === "number" ? sc.value : NaN;
      if (!Number.isFinite(v)) continue;
      sums[sc.name] ??= { sum: 0, count: 0 };
      sums[sc.name].sum += v;
      sums[sc.name].count += 1;
    }
  }
  for (const [k, v] of Object.entries(sums)) result.summary[k] = { mean: v.sum / v.count, count: v.count };
  const refused = result.items.filter((i) => i.postError);
  if (refused.length) result.errors.push(`${refused.length} result(s) not accepted; first: ${refused[0].postError}`);

  // 5. Finish and read the totals.
  let finished = 0;
  for (const r of runs) {
    const fin = await call(r.target, "POST", routes(r.id).finish, { body: {}, timeoutMs });
    if (!fin.ok && fin.status !== 409) {
      result.errors.push(`${r.target.name}: finish: ${describe(fin)}`);
      result.planRefusal ??= fin.planRefusal;
    } else finished += 1;
    const got = await call(r.target, "GET", routes(r.id).run, { timeoutMs });
    if (got.ok) result.server[r.target.name] = obj(got.body);
  }
  result.recorded = runs.length > 0 && finished === runs.length;
  const totals = experimentTotals(
    result.items,
    runs.map((r) => result.server[r.target.name]).filter((b): b is Record<string, unknown> => !!b),
    opts.failUnder,
  );
  result.passRate = totals.passRate;
  result.scored = totals.scored;
  const strict = opts.strict ?? true;
  const gate = experimentGate(result, opts.failUnder, strict);
  if (opts.failUnder !== undefined && strict && gate.reasons.length) {
    for (const r of gate.reasons) result.errors.push(`gate: ${r}`);
    if (typeof process !== "undefined") process.exitCode = 1;
    throw new ExperimentGateFailed(result, opts.failUnder, gate.reasons);
  }
  if (opts.failUnder !== undefined && result.scored === 0) {
    const msg = "no scores: no item was scored (no evaluator ran), so failUnder was not applied (strict: false)";
    result.errors.push(msg);
    try {
      console.warn(`@superbased/sdk: experiment ${JSON.stringify(name)}: ${msg}`);
    } catch {
      // ignore
    }
  }
  if (opts.failUnder !== undefined && gate.failed) {
    if (typeof process !== "undefined") process.exitCode = 1;
    throw new ExperimentGateFailed(result, opts.failUnder);
  }
  return result;
}

const FAIL_LABELS = new Set(["fail", "false", "no", "bad"]);

/** B7's pass rule (contract 4.2): boolean true, a number >= 0.5, a label not fail/false/no/bad. */
export function scorePasses(v: number | boolean | string): boolean {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v >= 0.5;
  return !FAIL_LABELS.has(v.trim().toLowerCase());
}

/** Items that count toward a pass rate: a task error, or a score an evaluator returned (one that threw is no score). */
function scoredItems(items: ItemResult[]): ItemResult[] {
  return items.filter((i) => i.error || i.scores.some((sc) => !sc.error));
}

const isCount = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0;

/**
 * A run's pass rate and scored count (contract experiments.md 4.2), as
 * Python's ExperimentResult computes them: the first side whose totals say
 * something was scored, else the local tally over scored items (an item
 * passes with no task error and every returned score passing). A side's
 * `pass_rate` with `total` 0 (an older server's 0 for "nothing scored") is
 * not a rate. NaN when nothing was scored. `gateFailed`: the rate is below
 * `failUnder`; never for a run that scored nothing.
 */
export function experimentTotals(
  items: ItemResult[],
  sides: Array<Record<string, unknown>> = [],
  failUnder?: number,
): { scored: number; passRate: number; gateFailed: boolean } {
  const local = scoredItems(items);
  let scored = local.length;
  for (const b of sides) {
    if (isCount(b.total) && (b.total > 0 || !local.length)) {
      scored = b.total;
      break;
    }
  }
  for (const b of sides) {
    if (typeof b.pass_rate !== "number") continue;
    if (isCount(b.total) && b.total === 0) continue;
    return { scored, passRate: b.pass_rate, gateFailed: gate(scored, b.pass_rate, failUnder) };
  }
  const passed = local.filter((i) => !i.error && i.scores.every((sc) => sc.error || scorePasses(sc.value))).length;
  const passRate = local.length ? passed / local.length : NaN;
  return { scored, passRate, gateFailed: gate(scored, passRate, failUnder) };
}

function gate(scored: number, passRate: number, failUnder?: number): boolean {
  return failUnder !== undefined && scored > 0 && !(passRate >= failUnder);
}
