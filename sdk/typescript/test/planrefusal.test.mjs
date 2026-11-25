// The AI Apps gateway's plan refusal: sdk/contract/plan-refusal-cases.json
// through parsePlanRefusal (Python, Go and Java run the same file), and how
// each call surfaces it: a rejecting call rejects with its own error carrying
// `planRefusal`, a never-throw call carries it, export keeps it in
// diagnostics().
import { test, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";

import * as sb from "../dist/esm/index.js";
import { noteExportRefusal } from "../dist/esm/export.js";
import { notePlanRefusal, planRefusalStats } from "../dist/esm/planrefusal.js";
import { reset, startStub } from "./helpers.mjs";

const contractDir = process.env.SUPERBASED_CONTRACT_DIR || join(dirname(fileURLToPath(import.meta.url)), "..", "..", "contract");
const FILE = join(contractDir, "plan-refusal-cases.json");
const CASES = existsSync(FILE) ? JSON.parse(readFileSync(FILE, "utf8")).cases : null;
const skip = !CASES && "sdk/contract is not present";

beforeEach(reset);
after(reset);

function quiet() {
  const warn = console.warn;
  const lines = [];
  console.warn = (...a) => lines.push(a.join(" "));
  return { lines, restore: () => (console.warn = warn) };
}

function allowance(a) {
  const out = {};
  if (a.events_monthly !== undefined) out.eventsMonthly = a.events_monthly;
  if (a.gb_monthly !== undefined) out.gbMonthly = a.gb_monthly;
  if (a.requests_monthly !== undefined) out.requestsMonthly = a.requests_monthly;
  if (a.concurrency !== undefined) out.concurrency = a.concurrency;
  return out;
}

function check(got, want, name) {
  if (want === null) {
    assert.equal(got, null, name);
    return;
  }
  assert.ok(got instanceof sb.PlanRefusalError, name);
  assert.ok(got instanceof (want.kind === "plan_required" ? sb.PlanRequiredError : sb.AllowanceExceededError), name);
  assert.equal(got.kind, want.kind, name);
  assert.equal(got.code, want.code, name);
  assert.equal(got.status, want.status, name);
  assert.equal(got.upgradeUrl, want.upgrade_url, name);
  assert.equal(got.capability, want.capability, name);
  assert.ok(got.message, name);
  if ("message" in want) assert.equal(got.message, want.message, name);
  if ("plan_name" in want) {
    assert.equal(got.plan?.name, want.plan_name, name);
    if ("plan_version" in want) assert.deepEqual([got.plan.version, got.plan.label], [want.plan_version, want.plan_label], name);
  } else assert.equal(got.plan, undefined, name);
  if ("allowance" in want) assert.deepEqual(got.allowance, allowance(want.allowance), name);
  else assert.equal(got.allowance, undefined, name);
  assert.deepEqual(got.plans.map((p) => p.name), want.plans, name);
  if ("offered_allowance" in want) assert.deepEqual(got.plans[0].allowance, allowance(want.offered_allowance), name);
  if ("quota" in want) {
    const q = want.quota;
    assert.deepEqual(got.quota, { quota: q.quota, unit: q.unit, used: q.used, limit: q.limit, resetsAt: q.resets_at }, name);
  } else assert.equal(got.quota, undefined, name);
  if ("retry_after_seconds" in want) assert.equal(got.retryAfterMs, want.retry_after_seconds * 1000, name);
  else assert.equal(got.retryAfterMs, undefined, name);
}

test("every shared plan refusal case", { skip }, () => {
  assert.ok(CASES.length >= 10);
  for (const c of CASES) {
    check(sb.parsePlanRefusal(c.status, c.body, c.headers), c.want, c.name);
    // The same answer as raw text and as bytes, with fetch Headers.
    const raw = typeof c.body === "string" ? c.body : JSON.stringify(c.body);
    check(sb.parsePlanRefusal(c.status, raw, new Headers(c.headers)), c.want, `${c.name} (text)`);
    check(sb.parsePlanRefusal(c.status, new TextEncoder().encode(raw), c.headers), c.want, `${c.name} (bytes)`);
  }
});

test("parsePlanRefusal never throws", () => {
  for (const junk of [undefined, null, 0, {}, [], "null", new Uint8Array([0xff, 0xfe]), { error: null }]) {
    assert.equal(sb.parsePlanRefusal(403, junk), null);
    assert.equal(sb.parsePlanRefusal(429, junk, { "Retry-After": ["x"] }), null);
  }
});

const PLAN_REQUIRED = {
  error: "plan_required",
  message: "AI Apps ingest is not part of this organization's plan (Team).",
  capability: "org.planea.gateway",
  plan: { name: "team", version: 1, label: "Team" },
  upgrade_url: "https://cloud.superbased.app/portal/orgs/org_1",
};
const EVENTS_OVER = {
  error: "planea_events_quota_exceeded",
  message: "This organization has used this month's AI Apps allowance of its plan (Team).",
  quota: { quota: "events_monthly", unit: "events", used: 10, limit: 10, resets_at: "2026-12-01T00:00:00Z" },
  capability: "org.planea.gateway",
  upgrade_url: "https://cloud.superbased.app/portal/orgs/org_1",
};

test("the error serializes its fields", () => {
  const e = sb.parsePlanRefusal(403, PLAN_REQUIRED);
  const j = JSON.parse(JSON.stringify(e));
  assert.equal(j.kind, "plan_required");
  assert.equal(j.upgradeUrl, PLAN_REQUIRED.upgrade_url);
  assert.equal(j.message, PLAN_REQUIRED.message);
});

test("getPrompt rejects with PromptFetchError carrying the plan refusal", async () => {
  const gw = await startStub();
  const q = quiet();
  try {
    gw.reply({ ...PLAN_REQUIRED, api_version: "1", request_id: "r1" }, 403);
    sb.init({ exporter: new InMemorySpanExporter(), orgUrl: gw.url, apiKey: "sk", destination: "online" });
    const err = await sb.getPrompt("greet").then(
      () => null,
      (e) => e,
    );
    assert.ok(err instanceof sb.PromptFetchError);
    assert.ok(err.planRefusal instanceof sb.PlanRequiredError);
    assert.equal(err.cause, err.planRefusal);
    assert.equal(err.planRefusal.upgradeUrl, PLAN_REQUIRED.upgrade_url);
    assert.equal(sb.diagnostics().planRefusal?.code, "plan_required");
    assert.ok(sb.diagnostics().planRefusalAt > 0);
    // A fallback still wins.
    assert.equal((await sb.getPrompt("greet", { fallback: "hi" })).isFallback, true);
  } finally {
    q.restore();
    await gw.close();
  }
});

test("getDataset rejects with ExperimentError carrying the plan refusal", async () => {
  const gw = await startStub();
  const q = quiet();
  try {
    gw.reply(EVENTS_OVER, 429, { "Retry-After": "120" });
    sb.init({ exporter: new InMemorySpanExporter(), orgUrl: gw.url, apiKey: "sk", destination: "online" });
    const err = await sb.getDataset("golden").then(
      () => null,
      (e) => e,
    );
    assert.ok(err instanceof sb.ExperimentError);
    assert.ok(err.planRefusal instanceof sb.AllowanceExceededError);
    assert.equal(err.planRefusal.retryAfterMs, 120_000);
    assert.equal(err.planRefusal.quota.quota, "events_monthly");
  } finally {
    q.restore();
    await gw.close();
  }
});

test("score() never throws, carries the plan refusal and does not retry an allowance refusal", async () => {
  const gw = await startStub();
  const q = quiet();
  try {
    gw.reply(EVENTS_OVER, 429, { "Retry-After": "120" });
    sb.init({ exporter: new InMemorySpanExporter(), orgUrl: gw.url, apiKey: "sk", destination: "online" });
    const res = await sb.score("accuracy", 1, { traceId: "0af7651916cd43dd8448eb211c80319c" });
    assert.equal(res.ok, false);
    assert.ok(res.planRefusal instanceof sb.AllowanceExceededError);
    assert.equal(res.planRefusal.upgradeUrl, EVENTS_OVER.upgrade_url);
    assert.equal(gw.requests.filter((r) => r.path.endsWith("/scores")).length, 1);
  } finally {
    q.restore();
    await gw.close();
  }
});

test("admit() never throws and carries the plan refusal", async () => {
  const gw = await startStub();
  const q = quiet();
  try {
    gw.reply(PLAN_REQUIRED, 403);
    const v = await sb.admit("hi", { orgUrl: gw.url, apiKey: "sk" });
    assert.equal(v.allowed, true);
    assert.equal(v.degraded, sb.Degraded.UNAVAILABLE);
    assert.equal(v.httpStatus, 403);
    assert.ok(v.planRefusal instanceof sb.PlanRequiredError);
    assert.ok(q.lines.some((l) => l.includes(`upgrade: ${PLAN_REQUIRED.upgrade_url}`)));
    gw.reply({ error: "insufficient_scope", message: "no" }, 403);
    assert.equal((await sb.admit("hi", { orgUrl: gw.url, apiKey: "sk" })).planRefusal, undefined);
  } finally {
    q.restore();
    await gw.close();
  }
});

test("a refused export shows in diagnostics() and is logged once", async () => {
  const gw = await startStub();
  const q = quiet();
  try {
    gw.reply(PLAN_REQUIRED, 403);
    assert.equal(sb.diagnostics().planRefusal, null);
    sb.init({ orgUrl: gw.url, apiKey: "sk", destination: "online", discover: false });
    for (let i = 0; i < 2; i++) {
      sb.withSpan("refused", () => undefined);
      assert.equal(await sb.flush(), false); // never throws
    }
    const d = sb.diagnostics();
    assert.ok(d.failedExports >= 2);
    assert.ok(d.planRefusal instanceof sb.PlanRequiredError);
    assert.equal(d.planRefusal.plan?.name, "team");
    const lines = q.lines.filter((l) => l.includes("refused by the organization's plan"));
    assert.equal(lines.length, 1, lines.join("\n"));
    assert.ok(lines[0].includes(PLAN_REQUIRED.message) && lines[0].includes(PLAN_REQUIRED.upgrade_url) && !lines[0].includes("\n"));
  } finally {
    q.restore();
    await gw.close();
  }
});

test("an exporter error that is no plan refusal is ignored", () => {
  assert.equal(noteExportRefusal(undefined), false);
  assert.equal(noteExportRefusal(new Error("ECONNREFUSED")), false);
  assert.equal(noteExportRefusal(Object.assign(new Error("Forbidden"), { code: 403, data: '{"error":"insufficient_scope"}' })), false);
  assert.equal(planRefusalStats.last, null);
});

test("the plan refusal warning is written at most once a minute", () => {
  const q = quiet();
  try {
    const e = sb.parsePlanRefusal(403, PLAN_REQUIRED);
    assert.equal(notePlanRefusal(e, "trace export", 1_000_000), true);
    assert.equal(notePlanRefusal(e, "trace export", 1_010_000), false);
    assert.equal(notePlanRefusal(e, "", 1_100_000), false); // a control call keeps it, never logs here
    assert.equal(notePlanRefusal(e, "trace export", 1_061_000), true);
    assert.equal(q.lines.length, 2);
  } finally {
    q.restore();
  }
});
