// gatewayUsage: the hosted AI gateway's requests on the staff OrgDetail usage
// card (hosted AI gateway arc, lane L9; plan section 3.14). The org's host
// adds an additive `aigw_requests` count to each daily usage report (lane L4:
// the usage pull and cloud org_usage_days). A host that predates it omits the
// field, so the card shows the column only when some row carries it, and an
// absent day is "-", never a zero. Pure: no React, no imports.

/** One daily usage row with the optional gateway count. */
export interface GatewayUsageDay {
  day: string;
  aigw_requests?: number | null;
}

/** hasGatewayUsage reports whether any row carries the gateway count. */
export function hasGatewayUsage(rows: readonly GatewayUsageDay[]): boolean {
  return rows.some((r) => typeof r.aigw_requests === "number");
}

/** monthOf is the UTC calendar month (YYYY-MM) of an instant. */
export function monthOf(now: Date): string {
  return now.toISOString().slice(0, 7);
}

/** gatewayMonthToDate sums this UTC month's gateway requests over the rows
 *  that carry the count; null when none of this month's rows carries it. */
export function gatewayMonthToDate(rows: readonly GatewayUsageDay[], now: Date): number | null {
  const month = monthOf(now);
  let total: number | null = null;
  for (const r of rows) {
    if (!r.day.startsWith(month) || typeof r.aigw_requests !== "number") continue;
    total = (total ?? 0) + Math.max(0, r.aigw_requests);
  }
  return total;
}

/** gatewayCell renders one day's count: the number, or "-" when the host
 *  did not report it that day. */
export function gatewayCell(r: GatewayUsageDay): string {
  return typeof r.aigw_requests === "number" ? r.aigw_requests.toLocaleString("en-US") : "-";
}
