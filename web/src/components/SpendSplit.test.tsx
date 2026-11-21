// Component tests of the folded project Spend total (cloud-agents lane
// CA-C1, decision CA-D21): one total with a local / cloud / worker / unknown
// split, native provider units beside the dollars, never a fabricated zero.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { SpendSplitLine } from "@/components/projectdetail/SpendSplit";
import { OverviewTab } from "@/components/projectdetail/OverviewTab";
import { spendSplit } from "@/lib/cloudLane";
import type { ProjectDetail, ProjectSpendLocations } from "@/lib/types";

// The B5 screenshot case: the tile read $4.57 while the lane added to $8.04.
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
};

test("the split names every location, keeps credits native and never reads $0.00", () => {
  const html = renderToStaticMarkup(<SpendSplitLine split={spendSplit(b5)!} showDollars />);
  for (const want of [/local/, /\$3\.96/, /cloud/, /\$3\.47/, /worker/, /\$0\.61/, /unknown/, /not reported/, /partial total/, /14 credit/, /not in the dollar total/, /cloud:github\.com\/acme\/app/]) {
    assert.match(html, want);
  }
  assert.ok(!html.includes("$0.00"), "a missing figure must not read as zero");
  assert.ok(!html.includes("—"), "no em dashes in UI copy");
});

test("the token view shows tokens per location, not dollars", () => {
  const html = renderToStaticMarkup(<SpendSplitLine split={spendSplit(b5)!} showDollars={false} />);
  assert.match(html, /68\.5K tokens/);
  assert.ok(!html.includes("$3.96"));
  assert.ok(!html.includes("partial total"));
});

const detail = (locations?: ProjectSpendLocations): ProjectDetail =>
  ({
    project: { id: 1, root_path: "/src/app", tools: ["claude-code"] },
    spend: { total_usd: 8.04, by_tool: [], by_model: [], by_day: [], by_session: [], locations },
    loc: { ai_added: 0, ai_modified: 0, ai_comment: 0, ai_split: { code: 0, comment: 0 }, human_capture: "vscode" },
    commits: { count: 0, ai_touched: 0, with_spend_usd: 0 },
    tasks: { total: 0, done: 0, cost_usd: 0, available: true },
    roi: [],
    capture: { commits: "ok", human_loc: "vscode" },
    window_days: 30,
  }) as unknown as ProjectDetail;

// The tile's value is a count-up figure (it renders from 0 before the
// browser animates it), so these tests read the split under it.
test("the Overview Spend tile shows one folded total with its split", () => {
  const html = renderToStaticMarkup(<OverviewTab d={detail(b5)} />);
  assert.match(html, /Spend by where it ran/);
  assert.match(html, /\$3\.47/);
  assert.match(html, /14 credit/);
});

test("an all-local project's tile has no split", () => {
  const html = renderToStaticMarkup(<OverviewTab d={detail(undefined)} />);
  assert.match(html, />Spend</);
  assert.ok(!html.includes("Spend by where it ran"));
});
