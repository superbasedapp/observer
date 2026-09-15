import { useEffect, useId, useMemo, useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { getUsage } from "../api";
import type { MixEntry, UsageView, UsageWarning } from "../api";
import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { StatCard } from "@shared/primitives/StatCard";
import { ChartShell } from "@shared/primitives/ChartShell";
import { Pill } from "@shared/primitives/Pill";
import { fmtCompact, fmtDateTime, fmtInt, fmtPct } from "@shared/lib/format";
import { FEATURE_LABELS, JOB_STATE_LABELS, PLAN_LABELS, labelFor } from "../lib/labels";

// Usage (D20), rebuilt onto the shared design-system primitives so the cloud
// portal renders the same visual grammar as the local dashboard. Data loading
// is unchanged from the original page: which PLAN and budget pool the caps
// come from, the per-window warnings the server already computes, the job
// states the allowance was actually spent on, and when each window restarts.

// MIX_COLORS mirrors Overview's categorical palette (webcloud/src/styles.css
// --mix-1..6) so the jobs-by-state donut here reads consistently with the
// rest of the portal.
const MIX_COLORS = [
  "var(--mix-1)",
  "var(--mix-2)",
  "var(--mix-3)",
  "var(--mix-4)",
  "var(--mix-5)",
  "var(--mix-6)",
];

// MixDonut is the same small donut + legend idiom Overview uses for its
// jobs-by-state and tool/model mix cards, copied locally (generic over the
// portal's {key,count} MixEntry shape) rather than reached for across pages.
function MixDonut({
  entries,
  totalLabel,
}: {
  entries: MixEntry[];
  totalLabel: string;
}) {
  const id = useId();
  const top = useMemo(
    () => entries.slice().sort((a, b) => b.count - a.count).slice(0, 6),
    [entries],
  );
  const total = useMemo(() => top.reduce((a, e) => a + e.count, 0), [top]);

  if (total === 0) {
    return (
      <div className="grid h-[160px] place-items-center text-[12px] text-fg-3">
        No data yet
      </div>
    );
  }

  const data = top.map((e, i) => ({
    key: e.key,
    value: e.count,
    color: MIX_COLORS[i % MIX_COLORS.length],
  }));

  return (
    <div className="grid grid-cols-[140px_1fr] items-center gap-4">
      <div className="relative h-[140px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="key"
              innerRadius="65%"
              outerRadius="92%"
              paddingAngle={1.5}
              stroke="var(--bg-2)"
              strokeWidth={2}
              isAnimationActive={false}
            >
              {data.map((d, i) => (
                <Cell key={`${id}-${i}`} fill={d.color} />
              ))}
            </Pie>
            <Tooltip
              content={({ active, payload }) => {
                if (!active || !payload?.length) return null;
                const p = payload[0].payload as (typeof data)[number];
                return (
                  <div className="rounded-2 border border-line-3 bg-bg-3/95 px-3 py-2 text-[11px] shadow-2 backdrop-blur">
                    <div className="font-mono text-fg-1">{p.key}</div>
                    <div className="mt-0.5 text-fg-3">
                      {fmtCompact(p.value)} · {fmtPct(p.value / total)} of shown
                    </div>
                  </div>
                );
              }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 grid place-items-center">
          <div className="text-center">
            <div className="text-[16px] font-semibold leading-none tracking-tight text-fg-0">
              {fmtCompact(total)}
            </div>
            <div className="mt-1 text-[9px] uppercase tracking-[0.06em] text-fg-3">
              {totalLabel}
            </div>
          </div>
        </div>
      </div>
      <ul className="space-y-1">
        {data.map((d) => {
          const share = d.value / total;
          return (
            <li
              key={d.key}
              className="grid grid-cols-[8px_1fr_auto] items-baseline gap-2 text-[11.5px]"
            >
              <span
                className="block h-2 w-2 self-center rounded-pill"
                style={{ background: d.color }}
              />
              <span className="truncate text-fg-1">{d.key}</span>
              <span className="shrink-0 tabular-nums text-fg-3">
                {fmtCompact(d.value)} · {fmtPct(share)}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

// meterFillClass mirrors the thresholds the server's warning levels already
// imply: danger at "critical"/"exhausted" (or a full/overfull bar even
// without an attached warning row), warn at "warn" (or 70%+), accent below
// that.
function meterFillClass(pct: number, level?: string): string {
  if (level === "critical" || level === "exhausted" || pct >= 90) {
    return "bg-danger";
  }
  if (level === "warn" || pct >= 70) {
    return "bg-warn";
  }
  return "bg-accent";
}

function levelPillVariant(
  level?: string,
): "warn" | "danger" | undefined {
  if (level === "critical" || level === "exhausted") return "danger";
  if (level === "warn") return "warn";
  return undefined;
}

function warningFor(
  warnings: UsageWarning[],
  window: string,
): UsageWarning["level"] | undefined {
  return warnings.find((w) => w.window === window)?.level;
}

// UsageMeterCard is a StatCard whose body carries a slim used/cap progress
// bar (StatCard's `children` slot), used for the three allowance windows.
function UsageMeterCard({
  label,
  used,
  cap,
  level,
  sub,
}: {
  label: string;
  used: number;
  cap: number;
  level?: string;
  sub: string;
}) {
  const pct = cap > 0 ? Math.min(100, (used / cap) * 100) : 0;
  const variant = levelPillVariant(level);
  return (
    <StatCard
      label={label}
      value={`${fmtInt(used)} / ${fmtInt(cap)}`}
      sub={sub}
      cornerPill={variant && <Pill variant={variant}>{level}</Pill>}
      warn={pct >= 70}
    >
      <div className="mt-2 h-1.5 w-full overflow-hidden rounded-pill bg-bg-4">
        <div
          className={`h-full rounded-pill ${meterFillClass(pct, level)}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </StatCard>
  );
}

export function Usage() {
  const [data, setData] = useState<UsageView | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    getUsage()
      .then((d) => {
        if (live) setData(d);
      })
      .catch((err: unknown) => {
        if (live)
          setError(err instanceof Error ? err.message : "failed to load");
      });
    return () => {
      live = false;
    };
  }, []);

  if (error) {
    return (
      <div className="rounded-3 border border-danger/30 bg-bg-2 px-4 py-3 text-[13px] text-danger">
        Could not load usage: {error}
      </div>
    );
  }
  if (!data) {
    return <div className="text-[13px] text-fg-3">Loading usage...</div>;
  }

  const jobEntries: MixEntry[] = Object.entries(data.jobs_by_state).map(
    ([key, count]) => ({ key: labelFor(JOB_STATE_LABELS, key), count }),
  );

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-[20px] font-semibold text-fg-0">Usage</h1>
        <p className="mt-1 text-[11px] text-fg-3" title={data.feature}>
          Feature: {labelFor(FEATURE_LABELS, data.feature)}
        </p>
      </div>

      {data.warnings.length > 0 && (
        <div className="flex flex-col gap-2 rounded-3 border border-warn/30 bg-bg-2 p-4">
          <h3 className="text-[13px] font-semibold text-fg-0">Warnings</h3>
          <ul className="flex flex-wrap gap-2">
            {data.warnings.map((w) => (
              <li key={w.window}>
                <Pill
                  variant={levelPillVariant(w.level) ?? "neutral"}
                  title={`${fmtInt(w.used)} of ${fmtInt(w.cap)} used (${fmtPct(w.used_fraction)})`}
                >
                  {w.window}: {w.level}
                </Pill>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Allowance meters */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <UsageMeterCard
          label="Daily"
          used={data.daily_used}
          cap={data.daily_cap}
          level={warningFor(data.warnings, "daily")}
          sub={`resets ${fmtDateTime(data.daily_resets_at)}`}
        />
        <UsageMeterCard
          label="Monthly"
          used={data.monthly_used}
          cap={data.monthly_cap}
          level={warningFor(data.warnings, "monthly")}
          sub={`resets ${fmtDateTime(data.monthly_resets_at)}`}
        />
        <UsageMeterCard
          label="Concurrency"
          used={data.concurrency_used}
          cap={data.concurrency_cap}
          level={warningFor(data.warnings, "concurrency")}
          sub={data.concurrency_note}
        />
      </div>

      {/* Plan + jobs breakdown */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <StatCard
          label="Plan"
          value={data.plan_label}
          sub={`v${data.plan_version} · ${labelFor(PLAN_LABELS, data.budget_pool)} pool`}
        >
          {data.plan_overridden && (
            <p className="mt-2 text-[11px] text-fg-3">
              These caps come from an explicit per-account entitlement
              override, not from the plan.
            </p>
          )}
          <DefinitionList className="mt-2">
            <DefinitionRow label="Weekly project digest" value={data.digest_weekly ? (
              <>Included{typeof data.digests_this_week === "number" ? ` (${fmtInt(data.digests_this_week)} this week)` : ""}</>
            ) : (
              <>Not in your plan — <a href="/portal/billing" className="text-accent">Plus</a></>
            )} />
            <DefinitionRow label="Results kept" value={data.results_retention_days ? `${fmtInt(data.results_retention_days)} days` : "Unknown"} />
          </DefinitionList>
        </StatCard>

        <ChartShell
          title="Jobs by state"
          sub={
            data.jobs_total > 0
              ? `${fmtInt(data.jobs_total)} jobs drew on this allowance`
              : "No enrichment jobs yet"
          }
        >
          {data.jobs_total === 0 ? (
            <p className="text-[12px] text-fg-3">
              No enrichment jobs yet, so nothing has drawn on this allowance.
            </p>
          ) : (
            <MixDonut entries={jobEntries} totalLabel="jobs" />
          )}
        </ChartShell>
      </div>
    </div>
  );
}
