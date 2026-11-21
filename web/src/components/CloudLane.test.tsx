// Component tests of the "where it ran" surfaces (cloud-agents lane CA-B5):
// the shared ExecutionLocationBadge and the Projects detail CloudLane, rendered
// with react-dom/server under node's test runner (scripts/test-components.mjs).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import {
  EXECUTION_FILTER_OPTIONS,
  ExecutionLocationBadge,
  executionLocationLabel,
  isExecutionFilterValue,
} from "@shared/primitives/ExecutionLocationBadge";
import { CloudLaneView } from "@/components/projectdetail/CloudLane";
import type { CloudLaneResponse } from "@/lib/types";

test("the badge renders nothing for an unstamped or unknown location", () => {
  assert.equal(renderToStaticMarkup(<ExecutionLocationBadge />), "");
  assert.equal(renderToStaticMarkup(<ExecutionLocationBadge location="" />), "");
  assert.equal(renderToStaticMarkup(<ExecutionLocationBadge location="mars" />), "");
  assert.equal(renderToStaticMarkup(<ExecutionLocationBadge location="local" hideLocal />), "");
});

test("the badge names each location in short words", () => {
  assert.match(renderToStaticMarkup(<ExecutionLocationBadge location="vendor_cloud" vendorRef="cse_01ABC" />), />cloud</);
  assert.match(renderToStaticMarkup(<ExecutionLocationBadge location="customer_worker" />), />worker</);
  assert.match(renderToStaticMarkup(<ExecutionLocationBadge location="local" />), />local</);
  assert.equal(executionLocationLabel("vendor_cloud"), "cloud");
  assert.equal(executionLocationLabel(undefined), "unknown");
});

test("the filter offers every location plus unknown, and no em dashes", () => {
  assert.deepEqual(
    EXECUTION_FILTER_OPTIONS.map((o) => o.value),
    ["", "local", "vendor_cloud", "customer_worker", "unknown"],
  );
  for (const o of EXECUTION_FILTER_OPTIONS) {
    assert.ok(!o.label.includes("—"), `em dash in ${o.label}`);
    assert.ok(isExecutionFilterValue(o.value));
  }
  assert.equal(isExecutionFilterValue("cloud"), false);
});

const lane: CloudLaneResponse = {
  buckets: [
    {
      location: "local",
      sessions: 3,
      sessions_with_tokens: 3,
      tokens: { input: 1000, output: 200, cache_read: 0, cache_write: 0, total: 1200 },
      token_coverage: "full",
      cost_usd: 1.25,
      sessions_with_turns: 3,
      turns: 4,
      cost_coverage: "full",
      provenance: [{ source: "proxy", turns: 4 }],
    },
    {
      location: "vendor_cloud",
      sessions: 2,
      sessions_with_tokens: 0,
      sessions_with_turns: 0,
      token_coverage: "unknown",
      turns: 0,
      cost_coverage: "unknown",
      ledger: [
        {
          connector: "devin",
          unit: "acu",
          value_type: "delta",
          measurement_source: "provider_run_total",
          monetary_status: "not_monetary",
          rollup: "sum",
          value: 7,
          entries: 2,
          sessions: 1,
          coverage: "partial",
        },
      ],
    },
    { location: "unknown", sessions: 1, sessions_with_tokens: 0, sessions_with_turns: 0, token_coverage: "unknown", turns: 0, cost_coverage: "unknown" },
  ],
  off_machine_sessions: 2,
  unknown_sessions: 1,
  accounts: [{ connector: "devin", provider: "cognition", coverage_state: "partial_history" }],
  projects: [
    { id: 1, root_path: "/src/app" },
    { id: 2, root_path: "cloud:github.com/acme/app", synthetic: true },
  ],
  since: "2026-10-01T00:00:00Z",
  until: "2026-10-31T00:00:00Z",
  window_days: 30,
};

test("the overview lane shows tokens with coverage and never a fabricated zero", () => {
  const html = renderToStaticMarkup(<CloudLaneView data={lane} view="overview" />);
  assert.match(html, /Where it ran/);
  assert.match(html, /cloud:github\.com\/acme\/app/);
  assert.match(html, /1\.2K/);
  assert.match(html, /Reported/);
  assert.match(html, /via proxy 4/);
  assert.match(html, /not reported/);
  assert.match(html, />unknown</);
  assert.match(html, /Partial history/);
  assert.ok(!/Provider usage/.test(html), "provider usage is a Spend-view column");
});

test("the spend lane keeps provider units native and missing dollars unreported", () => {
  const html = renderToStaticMarkup(<CloudLaneView data={lane} view="spend" />);
  assert.match(html, /Provider usage/);
  assert.match(html, /7 acu/);
  assert.match(html, /devin · provider run total · summed/);
  assert.match(html, /1 of 2 sessions/);
  assert.match(html, /\$1\.25/);
  assert.ok(!html.includes("$0.00"), "a cloud lane with no priced turn must not read $0.00");
  assert.match(html, /none reported|-/);
});

test("a folded synthetic project points at its local twin", () => {
  const folded: CloudLaneResponse = { ...lane, projects: [lane.projects[1]], folded_into: { id: 1, root_path: "/src/app" } };
  const html = renderToStaticMarkup(<CloudLaneView data={folded} view="overview" />);
  assert.match(html, /now groups under the local project/);
  assert.match(html, /\/src\/app/);
});

test("the lane says the Spend total includes a folded twin and names set-aside turns", () => {
  const html = renderToStaticMarkup(<CloudLaneView data={{ ...lane, superseded_turns: 2 }} view="spend" />);
  assert.match(html, /Spend total counts them too/);
  assert.match(html, /2 turns set aside/);
  assert.ok(!html.includes("—"), "no em dashes in UI copy");
});
