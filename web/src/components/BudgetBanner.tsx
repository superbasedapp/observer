import { useState } from "react";
import { Link } from "react-router-dom";
import { useApi } from "@/lib/useApi";
import { fmtUSD } from "@/lib/format";
import type { BudgetResponse, BudgetScope } from "@/lib/types";

// BudgetBanner — slim strip under the TopBar when a monthly budget
// crosses its 80% or 100% threshold (usability arc P6.3). ADVISORY
// ONLY and says so: budgets never gate traffic. Each (month, scope,
// level) crossing fires once — dismissing acknowledges that level for
// that scope this month; crossing the next level fires again.
const ACK_KEY = "sb_budget_ack";

function acks(): Record<string, true> {
  try {
    return JSON.parse(localStorage.getItem(ACK_KEY) ?? "{}") as Record<
      string,
      true
    >;
  } catch {
    return {};
  }
}

function ackKey(month: string, scope: BudgetScope, level: string): string {
  return `${month}|${scope.root || "global"}|${level}`;
}

export function BudgetBanner() {
  // 60s cadence: budget state moves at spend speed, not request speed.
  // The endpoint short-circuits to one config read when no budget is
  // configured, so the idle cost of this poll is negligible.
  const budget = useApi<BudgetResponse>("/api/budget", undefined, [], {
    refreshMs: 60000,
  });
  const [, bump] = useState(0);

  const data = budget.data;
  if (!data?.configured) return null;

  const scopes: BudgetScope[] = [
    ...(data.global ? [data.global] : []),
    ...(data.projects ?? []),
  ];
  const acked = acks();
  // Highest severity first; within a severity, global before projects
  // (scopes array order already does that).
  const firing =
    scopes.find(
      (sc) =>
        sc.threshold === "over100" && !acked[ackKey(data.month, sc, "over100")],
    ) ??
    scopes.find(
      (sc) =>
        sc.threshold === "warn80" && !acked[ackKey(data.month, sc, "warn80")],
    );
  if (!firing) return null;

  const over = firing.threshold === "over100";
  const label = firing.root ? shortRoot(firing.root) : "Monthly spend";
  const dismiss = () => {
    const next = acks();
    next[ackKey(data.month, firing, firing.threshold ?? "")] = true;
    try {
      localStorage.setItem(ACK_KEY, JSON.stringify(next));
    } catch {
      // Storage unavailable — the banner stays; nothing breaks.
    }
    bump((n) => n + 1);
  };

  return (
    <div
      className={
        over
          ? "flex items-center gap-2 border-b border-danger/30 bg-danger-soft px-4 py-1.5 text-[11.5px] text-fg-2"
          : "flex items-center gap-2 border-b border-warn/30 bg-warn-soft px-4 py-1.5 text-[11.5px] text-fg-2"
      }
    >
      <span className={over ? "font-semibold text-danger" : "font-semibold text-warn"}>
        Budget {over ? "exceeded" : "at " + Math.round(firing.pct) + "%"}
      </span>
      <span className="min-w-0 truncate">
        {label} is at {fmtUSD(firing.mtd_usd)} of its{" "}
        {fmtUSD(firing.budget_usd)} monthly budget
        {firing.forecast_usd > firing.budget_usd
          ? ` - on pace for ${fmtUSD(firing.forecast_usd)} by month end`
          : ""}
        . Advisory only - nothing is blocked.
      </span>
      <div className="flex-1" />
      <Link
        to="/cost"
        className="shrink-0 text-[11px] font-medium text-accent hover:text-accent-strong"
      >
        View costs →
      </Link>
      <button
        type="button"
        onClick={dismiss}
        className="shrink-0 rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-fg-2 hover:bg-bg-3"
      >
        dismiss
      </button>
    </div>
  );
}

function shortRoot(p: string): string {
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts.length === 0 ? p : parts[parts.length - 1];
}
