import { Link } from "react-router-dom";
import { Stagger } from "@shared/primitives/Motion";
import { usePortalQuery } from "../lib/query";
import { DashboardSkeleton, ErrorPanel } from "../components/LoadState";
import { getUsage } from "../api";
import type { UsageView, UsageWarning } from "../api";
import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { StatCard } from "@shared/primitives/StatCard";
import { ChartShell } from "@shared/primitives/ChartShell";
import { Pill } from "@shared/primitives/Pill";
import { EmptyState } from "@shared/primitives/EmptyState";
import { fmtDateTime, fmtInt, fmtPct } from "@shared/lib/format";
import { FEATURE_LABELS, PLAN_LABELS, labelFor } from "../lib/labels";
import { TriangleAlert, Workflow, type LucideIcon } from "lucide-react";
import { PageHeader } from "@shared/primitives/PageHeader";
import { CardHeader } from "@shared/primitives/CardHeader";
import { PortalMetricIcon, type PortalMetricKey } from "../lib/metricIcons";
import { routeIcon } from "../lib/nav";
import { RawIdHint } from "../components/RawIdHint";
import { Meter } from "@shared/primitives/Meter";
import type { Tone } from "@shared/lib/tone";
import { MixDonut, jobMixSlices } from "../components/MixDonut";

// SECTION_ICONS: one glyph per Usage section title.
const SECTION_ICONS = {
  warnings: TriangleAlert,
  jobs: Workflow,
} as const satisfies Record<string, LucideIcon>;

// Usage (D20), rebuilt onto the shared design-system primitives so the cloud
// portal renders the same visual grammar as the local dashboard. Data loading
// is unchanged from the original page: which PLAN and budget pool the caps
// come from, the per-window warnings the server already computes, the job
// states the allowance was actually spent on, and when each window restarts.

// METER_TONE_RULES mirrors the thresholds the server's warning levels
// already imply, walked top-down: danger at "critical"/"exhausted" (or a
// full/overfull bar even without an attached warning row), warn at "warn"
// (or 70%+), accent below that.
const METER_TONE_RULES: readonly { tone: Tone; levels: readonly string[]; minPct: number }[] = [
  { tone: "danger", levels: ["critical", "exhausted"], minPct: 90 },
  { tone: "warn", levels: ["warn"], minPct: 70 },
];
function meterTone(pct: number, level?: string): Tone {
  return (
    METER_TONE_RULES.find((r) => (level !== undefined && r.levels.includes(level)) || pct >= r.minPct)
      ?.tone ?? "accent"
  );
}

// LEVEL_PILL: the pill tone for each server warning level (no row, no pill).
const LEVEL_PILL: Readonly<Record<string, "warn" | "danger">> = {
  warn: "warn",
  critical: "danger",
  exhausted: "danger",
};
function levelPillVariant(level?: string): "warn" | "danger" | undefined {
  return level === undefined ? undefined : LEVEL_PILL[level];
}

// Human wording for the server's warning enums (the pill used to print the
// raw "daily: critical").
const WINDOW_WORDS: Record<string, string> = {
  daily: "Daily",
  monthly: "Monthly",
  concurrency: "Concurrency",
};
const LEVEL_WORDS: Record<UsageWarning["level"], string> = {
  warn: "nearing the cap",
  critical: "almost used up",
  exhausted: "used up",
};
function warningText(w: UsageWarning): string {
  return `${WINDOW_WORDS[w.window] ?? w.window}: ${LEVEL_WORDS[w.level] ?? w.level}`;
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
  metric,
  used,
  cap,
  level,
  sub,
}: {
  label: string;
  metric: PortalMetricKey;
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
      icon={<PortalMetricIcon metric={metric} />}
      value={`${fmtInt(used)} / ${fmtInt(cap)}`}
      sub={sub}
      cornerPill={
        variant && (
          <Pill variant={variant}>
            {LEVEL_WORDS[level as UsageWarning["level"]] ?? level}
          </Pill>
        )
      }
      warn={pct >= 70}
    >
      <Meter
        className="mt-2 w-full"
        ratio={pct / 100}
        tone={meterTone(pct, level)}
        label={`${label} allowance used`}
      />
    </StatCard>
  );
}

export function Usage() {
  // Same "usage" key the Overview reads: one shared, cached request.
  const q = usePortalQuery<UsageView>("usage", getUsage);
  const data = q.data;
  if (q.error && !data) {
    return <ErrorPanel variant="page" what="usage" error={q.error} onRetry={q.reload} />;
  }
  if (!data) {
    return <DashboardSkeleton stats={3} />;
  }

  const jobSlices = jobMixSlices(data.jobs_by_state);

  return (
    <Stagger className="flex flex-col gap-6">
      <PageHeader
        title="Usage"
        icon={routeIcon("/usage")}
        sub={
          <RawIdHint id={data.feature}>
            Feature: {labelFor(FEATURE_LABELS, data.feature)}
          </RawIdHint>
        }
      />

      {data.warnings.length > 0 && (
        <div className="flex flex-col gap-2 rounded-3 border border-warn/30 bg-bg-2 p-4">
          <CardHeader icon={SECTION_ICONS.warnings} title="Warnings" className="mb-0" />
          <ul className="flex flex-wrap gap-2">
            {data.warnings.map((w) => (
              <li key={w.window}>
                <Pill
                  variant={levelPillVariant(w.level) ?? "neutral"}
                  title={`${fmtInt(w.used)} of ${fmtInt(w.cap)} used (${fmtPct(w.used_fraction)})`}
                >
                  {warningText(w)}
                </Pill>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Allowance meters */}
      <Stagger className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <UsageMeterCard
          label="Daily"
          metric="dailyAllowance"
          used={data.daily_used}
          cap={data.daily_cap}
          level={warningFor(data.warnings, "daily")}
          sub={`resets ${fmtDateTime(data.daily_resets_at)}`}
        />
        <UsageMeterCard
          label="Monthly"
          metric="monthlyAllowance"
          used={data.monthly_used}
          cap={data.monthly_cap}
          level={warningFor(data.warnings, "monthly")}
          sub={`resets ${fmtDateTime(data.monthly_resets_at)}`}
        />
        <UsageMeterCard
          label="Concurrency"
          metric="concurrency"
          used={data.concurrency_used}
          cap={data.concurrency_cap}
          level={warningFor(data.warnings, "concurrency")}
          sub={data.concurrency_note}
        />
      </Stagger>

      {/* Plan + jobs breakdown */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <StatCard
          label="Plan"
          icon={<PortalMetricIcon metric="plan" />}
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
              <>Not in your plan - <Link to="/billing" className="text-accent">Plus</Link></>
            )} />
            <DefinitionRow label="Results kept" value={data.results_retention_days ? `${fmtInt(data.results_retention_days)} days` : "Unknown"} />
          </DefinitionList>
        </StatCard>

        <ChartShell
          title="Jobs by state"
          icon={SECTION_ICONS.jobs}
          sub={
            data.jobs_total > 0
              ? `${fmtInt(data.jobs_total)} jobs drew on this allowance`
              : "No enrichment jobs yet"
          }
        >
          {data.jobs_total === 0 ? (
            <EmptyState
              variant="inline"
              illustration="enrich"
              illustrationSize={96}
              title="No enrichment jobs yet"
              body="Nothing has drawn on this allowance."
            />
          ) : (
            <MixDonut slices={jobSlices} totalLabel="jobs" />
          )}
        </ChartShell>
      </div>
    </Stagger>
  );
}
