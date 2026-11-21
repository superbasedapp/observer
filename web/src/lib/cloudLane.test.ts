import { test } from "node:test";
import assert from "node:assert/strict";
import {
  accountCoverage,
  costCoverageLabel,
  groupCloudTwins,
  laneShown,
  laneSplit,
  ledgerProvenance,
  ledgerValue,
  offMachineSessions,
  spendSplit,
  tokenCoverageLabel,
  tokenProvenance,
} from "./cloudLane.ts";
import type { CloudLaneBucket, CloudLaneResponse, ProjectSpendLocations } from "./types.ts";

const base: CloudLaneResponse = {
  buckets: [],
  off_machine_sessions: 0,
  unknown_sessions: 0,
  projects: [{ id: 1, root_path: "/src/app" }],
  since: "2026-10-01T00:00:00Z",
  until: "2026-10-31T00:00:00Z",
  window_days: 30,
};

const bucket = (b: Partial<CloudLaneBucket>): CloudLaneBucket => ({
  location: "vendor_cloud",
  sessions: 2,
  sessions_with_tokens: 0,
  sessions_with_turns: 0,
  token_coverage: "unknown",
  turns: 0,
  cost_coverage: "unknown",
  ...b,
});

test("the lane stays hidden for a project that never ran anywhere else", () => {
  assert.equal(laneShown(null), false);
  assert.equal(laneShown(base), false);
  assert.equal(laneShown({ ...base, off_machine_sessions: 1 }), true);
  assert.equal(laneShown({ ...base, projects: [...base.projects, { id: 2, root_path: "cloud:github.com/a/b", synthetic: true }] }), true);
  assert.equal(laneShown({ ...base, folded_into: { id: 9, root_path: "/src/app" } }), true);
  assert.equal(laneShown({ ...base, accounts: [{ connector: "codex-cloud", provider: "openai" }] }), true);
});

test("a missing token or cost figure reads as not reported, never zero", () => {
  const silent = bucket({});
  assert.deepEqual(tokenCoverageLabel(silent).label, "Not reported");
  assert.match(tokenCoverageLabel(silent).detail, /unknown, not zero/);
  assert.equal(costCoverageLabel(silent).label, "Not reported");
  const unpriced = bucket({ turns: 3, cost_coverage: "unknown" });
  assert.equal(costCoverageLabel(unpriced).label, "Not priced");
});

test("partial coverage names how much is covered", () => {
  const b = bucket({ sessions: 3, sessions_with_tokens: 1, token_coverage: "partial", turns: 4, unpriced_turns: 1, cost_coverage: "partial" });
  assert.equal(tokenCoverageLabel(b).label, "1 of 3 sessions");
  assert.equal(tokenCoverageLabel(b).status, "partial");
  assert.equal(costCoverageLabel(b).label, "1 unpriced");
  assert.match(costCoverageLabel(b).detail, /floor/);
  const silent = bucket({ sessions: 2, sessions_with_turns: 1, turns: 1, cost_coverage: "partial" });
  assert.equal(costCoverageLabel(silent).label, "1 of 2 sessions");
  assert.match(costCoverageLabel(silent).detail, /unknown, not zero/);
});

test("ledger figures keep their own unit and say where they came from", () => {
  const f = {
    connector: "devin",
    unit: "acu",
    value_type: "delta",
    measurement_source: "provider_run_total",
    monetary_status: "not_monetary",
    rollup: "sum" as const,
    value: 12.5,
    entries: 3,
    sessions: 1,
    coverage: "partial" as const,
  };
  assert.equal(ledgerValue(f), "12.5 acu");
  assert.equal(ledgerProvenance(f), "devin · provider run total · summed");
  assert.equal(ledgerProvenance({ ...f, monetary_status: "reported_charge", measurement_source: "new_kind" }), "devin · new_kind · summed · charged");
});

test("token provenance lists capture paths", () => {
  assert.equal(tokenProvenance(bucket({})), "");
  assert.equal(tokenProvenance(bucket({ provenance: [{ source: "proxy", turns: 3 }, { source: "jsonl", turns: 2 }] })), "via proxy 3, transcript 2");
});

test("account coverage maps the plan's states and keeps an unknown token readable", () => {
  assert.deepEqual(accountCoverage("partial_history"), { label: "Partial history", status: "partial" });
  assert.deepEqual(accountCoverage("verified"), { label: "Verified", status: "full" });
  assert.deepEqual(accountCoverage(undefined), { label: "Not assessed", status: "unknown" });
  assert.deepEqual(accountCoverage("network_level_blocks_host"), { label: "Network level blocks host", status: "unknown" });
});

test("a synthetic cloud project lists right after its local twin", () => {
  const rows = [
    { id: 3, cloud_twin_of: 1 },
    { id: 1 },
    { id: 2 },
    { id: 4, cloud_twin_of: 99 }, // twin filtered out: keeps its place
    { id: 5, cloud_twin_of: 1 },
  ];
  assert.deepEqual(
    groupCloudTwins(rows).map((r) => r.id),
    [1, 3, 5, 2, 4],
  );
  assert.deepEqual(groupCloudTwins([]), []);
});

test("off-machine sessions count cloud and worker only", () => {
  assert.equal(offMachineSessions(undefined), 0);
  assert.equal(offMachineSessions({ local: 4, unknown: 2 }), 0);
  assert.equal(offMachineSessions({ vendor_cloud: 2, customer_worker: 1, local: 9 }), 3);
});

// ---------- Spend split (lane CA-C1): the B5 screenshot case ----------
// The tile read $4.57 (local project only) while the lane added up to $8.04.
// The folded split carries all four parts; they add up to the one total.

const b5: ProjectSpendLocations = {
  buckets: [
    { location: "local", sessions: 2, sessions_with_tokens: 2, token_coverage: "full", cost_usd: 3.96, sessions_with_turns: 2, turns: 2, cost_coverage: "full", tokens: { input: 60000, output: 8500, cache_read: 0, cache_write: 0, total: 68500 } },
    {
      location: "vendor_cloud", sessions: 2, sessions_with_tokens: 1, token_coverage: "partial", cost_usd: 3.47, sessions_with_turns: 1, turns: 1, cost_coverage: "partial",
      ledger: [{ connector: "codex-cloud", unit: "credit", value_type: "delta", measurement_source: "provider_run_total", monetary_status: "not_monetary", rollup: "sum", value: 14, entries: 1, sessions: 1, coverage: "partial" }],
    },
    { location: "customer_worker", sessions: 1, sessions_with_tokens: 1, token_coverage: "full", cost_usd: 0.61, sessions_with_turns: 1, turns: 1, cost_coverage: "full" },
    { location: "unknown", sessions: 1, sessions_with_tokens: 0, token_coverage: "unknown", sessions_with_turns: 0, turns: 0, cost_coverage: "unknown" },
  ],
  folded: [{ id: 2, root_path: "cloud:github.com/acme/app", synthetic: true }],
  superseded_turns: 1,
};

test("the spend split carries every location and adds up to the folded total", () => {
  const s = spendSplit(b5);
  assert.ok(s);
  assert.deepEqual(s.parts.map((p) => p.location), ["local", "vendor_cloud", "customer_worker", "unknown"]);
  const sum = s.parts.reduce((a, p) => a + (p.cost_usd ?? 0), 0);
  assert.equal(Math.round(sum * 100) / 100, 8.04);
  assert.equal(s.parts[3].cost_usd, undefined, "a location nothing priced has no cost, never 0");
  assert.equal(s.parts[3].cost.label, "Not reported");
  assert.equal(s.parts[1].cost.label, "1 of 2 sessions");
  assert.equal(s.partial, true, "a partial or missing part marks the total partial");
  assert.deepEqual(s.usage.map((u) => [u.location, u.figure.value, u.figure.unit]), [["vendor_cloud", 14, "credit"]]);
  assert.deepEqual(s.folded, ["cloud:github.com/acme/app"]);
  assert.equal(s.superseded_turns, 1);
});

test("a fully priced split is not partial, and no split is null", () => {
  const s = spendSplit({ buckets: [b5.buckets[0], b5.buckets[2]] });
  assert.equal(s?.partial, false);
  assert.equal(spendSplit(undefined), null);
  assert.equal(spendSplit({ buckets: [] }), null);
});

test("the lane payload yields the same split for the Spend tab", () => {
  const lane: CloudLaneResponse = {
    ...base,
    buckets: b5.buckets,
    off_machine_sessions: 3,
    unknown_sessions: 1,
    projects: [{ id: 1, root_path: "/src/app" }, { id: 2, root_path: "cloud:github.com/acme/app", synthetic: true }],
    superseded_turns: 1,
  };
  const s = laneSplit(lane);
  assert.deepEqual(s?.folded, ["cloud:github.com/acme/app"]);
  assert.equal(s?.parts.length, 4);
  assert.equal(laneSplit(base), null, "an all-local lane renders no split");
});
