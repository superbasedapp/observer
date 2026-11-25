// gatewayRows: the hosted AI gateway's allowances on the Plans comparison
// (hosted AI gateway arc, lane L9; decision 4 of L-174). A forwarded request
// is the unit: refused calls do not count, and tokens are never capped. The
// numbers are the plan versions lane L4 ships (personal_free v3 and
// personal_pro v3: aigw.requests_monthly and aigw.concurrency); keep them
// equal to the plan versions in force.
//
// It ships dark (decision 6) and no hosted team is offered it yet
// (claims register C-118, L-188), so the section says exactly that: the
// allowances are what the plans carry for when it opens. Pure: no React, no
// imports, so node:test runs it.

/** One comparison row, the same shape as util.ts PLAN_COMPARISON_ROWS. */
export interface GatewayComparisonRow {
  label: string;
  free: string;
  plus: string;
}

/** GATEWAY_COMPARISON_TITLE heads the rows. */
export const GATEWAY_COMPARISON_TITLE = "AI gateway";

/** GATEWAY_STATUS_PILL labels the heading while no hosted team is offered it. */
export const GATEWAY_STATUS_PILL = "Not offered yet";

/** GATEWAY_BETA_NOTE is the one line under the rows while it is not offered. */
export const GATEWAY_BETA_NOTE =
  "The AI gateway is built for hosted teams but not offered yet; these allowances apply once it opens.";

/** The allowances, per plan (decision 4). */
export const GATEWAY_ALLOWANCES = {
  free: { requestsMonthly: 10_000, concurrency: 4 },
  plus: { requestsMonthly: 250_000, concurrency: 16 },
} as const;

function count(n: number): string {
  return n.toLocaleString("en-US");
}

/** GATEWAY_COMPARISON_ROWS: the rows under the AI gateway heading. */
export const GATEWAY_COMPARISON_ROWS: readonly GatewayComparisonRow[] = [
  {
    label: "Model calls forwarded a month",
    free: count(GATEWAY_ALLOWANCES.free.requestsMonthly),
    plus: count(GATEWAY_ALLOWANCES.plus.requestsMonthly),
  },
  {
    label: "Model calls at once",
    free: count(GATEWAY_ALLOWANCES.free.concurrency),
    plus: count(GATEWAY_ALLOWANCES.plus.concurrency),
  },
];
