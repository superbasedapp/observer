import assert from "node:assert/strict";
import test from "node:test";

import {
  EMPTY_INPUTS,
  SKIP_REASONS,
  applyBody,
  buildFilterBody,
  canApply,
  canRevert,
  deltaWord,
  filterProblem,
  fmtOldNew,
  fmtRepriceUSD,
  fmtSignedUSD,
  inputsKey,
  planChangedFrom,
  planHeadline,
  runKindLabel,
  runStatus,
  serverErrorText,
  sinceForDays,
  skipLabel,
  skippedRows,
  windowLabel,
  type RepricePlanView,
  type RepriceRunView,
  type RepriceSummary,
} from "./reprice.ts";

const summary: RepriceSummary = {
  scanned: 10,
  changed: 3,
  filled: 1,
  old_usd: 1,
  new_usd: 2.24,
  delta_usd: 1.24,
  skipped: null,
  tables: null,
  models: null,
};

const plan: RepricePlanView = {
  since: "2026-09-01",
  until: "",
  model: "",
  pricing: { source: "feed", version: 7, description: "public price feed v7" },
  digest: "abc",
  rule_version: 1,
  summary,
};

const run: RepriceRunView = {
  id: 4,
  kind: "apply",
  created_at: "2026-09-29T10:00:00Z",
  actor: "local",
  since: "",
  until: "",
  model: "",
  rule_version: 1,
  pricing_source: "feed",
  pricing_version: 7,
  scanned: 10,
  changed: 3,
  filled: 1,
  cas_missed: 0,
  old_usd: 1,
  new_usd: 2.24,
  delta_usd: 1.24,
  reverts_run: 0,
  reverted_by_run: 0,
  status: "applied",
};

test("buildFilterBody trims and omits empty fields", () => {
  const cases: { in: typeof EMPTY_INPUTS; want: object }[] = [
    { in: EMPTY_INPUTS, want: {} },
    { in: { since: "2026-09-01", until: "", model: "" }, want: { since: "2026-09-01" } },
    { in: { since: "", until: "2026-09-02", model: "  " }, want: { until: "2026-09-02" } },
    {
      in: { since: " 2026-09-01 ", until: "2026-09-02", model: " claude-sonnet-4 " },
      want: { since: "2026-09-01", until: "2026-09-02", model: "claude-sonnet-4" },
    },
  ];
  for (const c of cases) assert.deepEqual(buildFilterBody(c.in), c.want);
});

test("applyBody sends the dry run's RESOLVED window and digest, not the form", () => {
  const mkPlan = (since: string, until: string, model: string, digest: string): RepricePlanView => ({
    since,
    until,
    model,
    digest,
    pricing: { source: "seed", version: 0, description: "" },
    rule_version: 1,
    summary: {
      scanned: 1, changed: 1, filled: 0, old_usd: 1, new_usd: 2, delta_usd: 1,
      skipped: null, tables: null, models: null,
    },
  });
  // A relative window the server resolved to an exact instant is applied at
  // that instant, so the apply's re-plan names the same rows.
  assert.deepEqual(applyBody(mkPlan("2026-09-22T10:00:00.123456789Z", "", "", "d1g")), {
    since: "2026-09-22T10:00:00.123456789Z",
    digest: "d1g",
  });
  assert.deepEqual(applyBody(mkPlan("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z", "m", "x")), {
    since: "2026-09-01T00:00:00Z",
    until: "2026-09-02T00:00:00Z",
    model: "m",
    digest: "x",
  });
  assert.deepEqual(applyBody(mkPlan("", "", "", "")), { digest: "" });
});

test("inputsKey normalizes whitespace but distinguishes fields", () => {
  assert.equal(inputsKey({ since: "", until: "", model: " m " }), inputsKey({ since: "", until: "", model: "m" }));
  assert.notEqual(inputsKey({ since: "2026-09-01", until: "", model: "" }), inputsKey({ since: "", until: "2026-09-01", model: "" }));
});

test("filterProblem table", () => {
  const cases: [typeof EMPTY_INPUTS, string | null][] = [
    [EMPTY_INPUTS, null],
    [{ since: "2026-09-01", until: "2026-09-30", model: "" }, null],
    [{ since: "2026-09-01", until: "2026-09-01", model: "" }, null],
    [{ since: "2026-09-30", until: "2026-09-01", model: "" }, "Since is after until."],
    [{ since: "yesterday", until: "", model: "" }, "Since must be a date (YYYY-MM-DD)."],
    [{ since: "", until: "9/1/2026", model: "" }, "Until must be a date (YYYY-MM-DD)."],
  ];
  for (const [inp, want] of cases) assert.equal(filterProblem(inp), want);
});

test("sinceForDays counts back local calendar days", () => {
  const now = new Date(2026, 8, 29, 15, 30); // Sep 29 2026 local
  assert.equal(sinceForDays(7, now), "2026-09-22");
  assert.equal(sinceForDays(30, now), "2026-08-30");
  assert.equal(sinceForDays(0, now), "");
  assert.equal(sinceForDays(-5, now), "");
  assert.equal(sinceForDays(Number.NaN, now), "");
  assert.equal(sinceForDays(1, new Date(2026, 0, 1, 0, 5)), "2025-12-31");
});

test("money: signed deltas, sub-cent escalation, old -> new", () => {
  assert.equal(fmtSignedUSD(1.24), "+$1.24");
  assert.equal(fmtSignedUSD(-0.3), "-$0.30");
  assert.equal(fmtSignedUSD(0), "$0.00");
  assert.equal(fmtSignedUSD(0.0012), "+$0.0012");
  assert.equal(fmtSignedUSD(-0.0012), "-$0.0012");
  assert.equal(fmtRepriceUSD(12.5), "$12.50");
  assert.equal(fmtRepriceUSD(0.004), "$0.0040");
  assert.equal(fmtOldNew(1, 2.24), "$1.00 -> $2.24");
  assert.equal(fmtSignedUSD(null), fmtRepriceUSD(undefined));
});

test("deltaWord", () => {
  assert.equal(deltaWord(1), "higher");
  assert.equal(deltaWord(-1), "lower");
  assert.equal(deltaWord(0), "no change");
});

test("skip labels: every planner reason is labelled, required copy is exact", () => {
  assert.deepEqual(
    SKIP_REASONS.map((r) => r.reason),
    ["source_reported", "no_model", "no_timestamp", "no_price", "invalid_price", "fast_tier_unknown", "unchanged"],
  );
  assert.equal(skipLabel("source_reported"), "Reported by the tool or vendor, kept");
  assert.equal(skipLabel("no_price"), "No price known, left unknown");
  assert.equal(skipLabel("unchanged"), "Already at the right price");
  assert.equal(skipLabel("brand_new_reason"), "brand new reason");
  for (const r of SKIP_REASONS) assert.ok(!r.label.includes("\u2014"), `no em-dash in ${r.reason}`);
});

test("skippedRows: known reasons in table order, zeros dropped, unknown appended", () => {
  const rows = skippedRows({ unchanged: 5, zzz_new: 2, source_reported: 3, no_price: 0 });
  assert.deepEqual(
    rows.map((r) => [r.reason, r.count]),
    [["source_reported", 3], ["unchanged", 5], ["zzz_new", 2]],
  );
  assert.deepEqual(skippedRows(null), []);
});

test("planHeadline table", () => {
  const cases: [Partial<RepriceSummary>, string][] = [
    [{ scanned: 0, changed: 0, filled: 0 }, "No stored rows in this window."],
    [{ scanned: 1, changed: 0, filled: 0 }, "1 row scanned - nothing would change."],
    [{ scanned: 1200, changed: 3, filled: 0 }, "1,200 rows scanned - 3 would change."],
    [{ scanned: 10, changed: 3, filled: 1 }, "10 rows scanned - 3 would change (1 without a cost before)."],
  ];
  for (const [patch, want] of cases) assert.equal(planHeadline({ ...summary, ...patch }), want);
});

test("canApply needs a current, non-empty dry run", () => {
  const key = inputsKey({ since: "2026-09-01", until: "", model: "" });
  assert.equal(canApply(plan, key, key), true);
  assert.equal(canApply(null, key, key), false);
  assert.equal(canApply(plan, key, inputsKey(EMPTY_INPUTS)), false, "inputs changed since the dry run");
  assert.equal(canApply({ ...plan, summary: { ...summary, changed: 0 } }, key, key), false);
  assert.equal(canApply({ ...plan, digest: "" }, key, key), false);
});

test("planChangedFrom reads only a plan_changed 409", () => {
  const body = JSON.stringify({ error: "plan_changed", plan });
  assert.deepEqual(planChangedFrom(409, body), plan);
  assert.equal(planChangedFrom(400, body), null);
  assert.equal(planChangedFrom(409, JSON.stringify({ error: "already reverted" })), null);
  assert.equal(planChangedFrom(409, "not json"), null);
  assert.equal(planChangedFrom(409, ""), null);
});

test("serverErrorText", () => {
  assert.equal(serverErrorText(JSON.stringify({ error: "run already reverted" })), "run already reverted");
  assert.equal(serverErrorText(" plain text \n"), "plain text");
});

test("windowLabel", () => {
  assert.equal(windowLabel("", ""), "all time");
  assert.equal(windowLabel("2026-09-01", ""), "from 2026-09-01");
  assert.equal(windowLabel("", "2026-09-30T00:00:00Z"), "until 2026-09-30");
  assert.equal(windowLabel("2026-09-01", "2026-09-30"), "2026-09-01 to 2026-09-30");
  assert.equal(windowLabel("2026-09-01", "2026-09-01"), "2026-09-01");
});

test("canRevert table", () => {
  const cases: [Partial<RepriceRunView>, boolean][] = [
    [{}, true],
    [{ kind: "revert", reverts_run: 2 }, false],
    [{ reverted_by_run: 9 }, false],
    [{ status: "reverted" }, false],
    [{ status: "failed" }, false],
    [{ changed: 0 }, false],
  ];
  for (const [patch, want] of cases) assert.equal(canRevert({ ...run, ...patch }), want, JSON.stringify(patch));
});

test("runStatus and runKindLabel", () => {
  assert.deepEqual(runStatus(run), { text: "applied", tone: "success" });
  assert.deepEqual(runStatus({ ...run, reverted_by_run: 9 }), { text: "reverted by #9", tone: "neutral" });
  assert.deepEqual(runStatus({ ...run, status: "odd" }), { text: "odd", tone: "neutral" });
  assert.deepEqual(runStatus({ ...run, status: "" }), { text: "unknown", tone: "neutral" });
  assert.equal(runKindLabel(run), "re-price");
  assert.equal(runKindLabel({ ...run, kind: "revert", reverts_run: 4 }), "revert of #4");
});
