import { useSearchParams } from "react-router-dom";
import { FadeIn, UpdatingBadge } from "@shared/primitives/Motion";
import { ChartSkeleton } from "@shared/primitives/Skeleton";
import { EmptyState } from "@shared/primitives/EmptyState";
import { chartMotion } from "@shared/lib/motion";
import { usePortalQuery } from "../lib/query";
import { ErrorPanel, HeaderSkeleton } from "../components/LoadState";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { getCommunity, getCommunityMetrics } from "../api";
import type {
  CommunityMetric,
  CommunityMetricsView,
  CommunityView,
} from "../api";
import { ChartShell } from "@shared/primitives/ChartShell";
import { Pill } from "@shared/primitives/Pill";
import { SegmentedControl } from "@shared/primitives/SegmentedControl";
import { CHART_AXIS, CHART_GRID } from "@shared/charts/common";
import { ChartTooltip } from "@shared/charts/ChartTooltip";
import { fmtInt, fmtYearMonth } from "@shared/lib/format";
import { PageHeader } from "@shared/primitives/PageHeader";
import { CardHeader } from "@shared/primitives/CardHeader";
import { BookText, ChartColumn, type LucideIcon } from "lucide-react";
import { routeIcon } from "../lib/nav";

// SECTION_ICONS: one glyph per Community section title.
const SECTION_ICONS = {
  bands: ChartColumn,
  definitions: BookText,
} as const satisfies Record<string, LucideIcon>;

// Community percentiles (divergence plan §3 W5 / R3), rebuilt onto the shared
// design-system primitives so the cloud portal renders the same visual
// grammar as the local dashboard. A developer sees the PRIVATE, floored,
// k-suppressed cohort band distribution for a chosen metric and WHERE THEY
// SIT in it — never a public leaderboard, never another person's number. The
// page stays honest about every degraded shape the backend can hand back: a
// cohort below the >=30 opt-in floor (no bands), a developer who is not
// contributing this metric yet (no own placement), and suppressed cells
// (bands omitted from an otherwise-present distribution). Metric and cohort
// definitions are shown so a band is never an unexplained number (R3).

// fmtEdge renders a band-edge threshold compactly: integers plain, fractional
// values trimmed. Edges are the width_bucket thresholds from the backend.
function fmtEdge(n: number): string {
  if (Number.isInteger(n)) {
    return String(n);
  }
  return String(Math.round(n * 100) / 100);
}

// bandLabel turns a band index into a human range using the edges array. With
// edges [1,2,3,5,8,13]: band 0 = "<1", band i = "edges[i-1]-edges[i]", and the
// last band (>= edges[last]) = "13+". Not every index is guaranteed present in
// the returned bands (suppressed cells are omitted), so this labels whatever
// index the backend actually returned.
function bandLabel(band: number, edges: number[]): string {
  const n = edges.length;
  if (n === 0) {
    return "Band " + String(band);
  }
  if (band <= 0) {
    return "<" + fmtEdge(edges[0]);
  }
  if (band >= n) {
    return fmtEdge(edges[n - 1]) + "+";
  }
  return fmtEdge(edges[band - 1]) + "-" + fmtEdge(edges[band]);
}

// fmtValue renders the developer's own value with its unit, when present.
function fmtValue(value: number, unit: string): string {
  const v = Number.isInteger(value)
    ? String(value)
    : String(Math.round(value * 100) / 100);
  return unit ? v + " " + unit : v;
}

function Definitions({
  metrics,
  cohortLabel,
  cohortDescription,
}: {
  metrics: CommunityMetric[];
  cohortLabel?: string;
  cohortDescription?: string;
}) {
  return (
    <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
      <CardHeader
        icon={SECTION_ICONS.definitions}
        title="Metric definitions"
        sub="Every band is a range of one of these metrics, measured over your chosen window. Cohorts group developers so the comparison is like for like."
        className="mb-0"
      />
      {cohortLabel && (
        <p className="mt-2 text-[11px] text-fg-2">
          <span className="text-fg-3">Cohort: </span>
          {cohortLabel}
        </p>
      )}
      {cohortDescription && (
        <p className="mt-0.5 text-[11px] text-fg-3">{cohortDescription}</p>
      )}
      <dl className="mt-3 flex flex-col gap-2.5">
        {metrics.map((m) => (
          <div
            key={m.id + "." + String(m.version)}
            className="border-t border-line-1 pt-2.5 first:border-t-0 first:pt-0"
          >
            <dt className="text-[12px] font-medium text-fg-1">
              {m.label}
              {m.unit && (
                <span className="ml-1.5 text-[10px] font-normal text-fg-3">
                  {m.unit}
                </span>
              )}
            </dt>
            <dd className="mt-0.5 text-[11px] text-fg-3">{m.description}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

// OwnBarLabel draws a small "You" tag above the one bar that is the
// developer's own band — recharts LabelList content renderer, so it only
// paints when the underlying datum's `isOwn` flag is true.
function OwnBarLabel(props: {
  x?: string | number;
  y?: string | number;
  width?: string | number;
  value?: unknown;
}) {
  const x = Number(props.x);
  const y = Number(props.y);
  const width = Number(props.width);
  if (!props.value || !Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(width)) {
    return null;
  }
  return (
    <text
      x={x + width / 2}
      y={y - 6}
      textAnchor="middle"
      fontSize={9}
      fontWeight={700}
      fill="var(--accent)"
    >
      You
    </text>
  );
}

export function Community() {
  // The catalog is fetched once (cached across visits). Metric and cohort
  // live in the URL, so a choice survives a reload and can be shared; the
  // cohort defaults to global and the metric to the first one offered.
  const metaQ = usePortalQuery<CommunityMetricsView>(
    "community:metrics",
    getCommunityMetrics,
  );
  const meta = metaQ.data;
  const metaError = metaQ.error && !meta ? metaQ.error : null;
  const [params, setParams] = useSearchParams();
  const urlMetric = params.get("metric");
  const metric =
    meta?.metrics.find((m) => m.id === urlMetric)?.id ?? meta?.metrics[0]?.id;
  const cohort = params.get("cohort") || "global";
  const setParam = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    next.set(k, v);
    setParams(next, { replace: true });
  };
  const setMetric = (v: string) => setParam("metric", v);
  const setCohort = (v: string) => setParam("cohort", v);

  // Version is resolved from the catalog for the selected metric so a v2
  // metric asks for v2 (the backend defaults to 1 otherwise); the window is
  // omitted so the server picks the most recent finalized one. A metric or
  // cohort switch keeps the previous distribution on screen, dimmed, until
  // the new one lands (the chart no longer unmounts).
  const version = meta?.metrics.find((m) => m.id === metric)?.version;
  const dataQ = usePortalQuery<CommunityView>(
    metric ? `community:${metric}:${version ?? ""}:${cohort}` : null,
    () => getCommunity({ metric, version, cohort }),
    [],
    { keepPrevious: true },
  );
  const data = dataQ.data;
  const dataError = dataQ.error && !data ? dataQ.error : null;
  const loading = metaQ.loading || dataQ.loading;

  if (metaError) {
    return (
      <ErrorPanel
        variant="page"
        what="community metrics"
        error={metaError}
        onRetry={metaQ.reload}
      />
    );
  }

  const metrics = meta?.metrics ?? [];
  const cohorts = meta?.cohorts ?? [];
  const selectedCohort = cohorts.find((c) => c.key === cohort);
  const edges = data?.band_edges ?? [];
  const bands = data?.bands ?? [];
  const own = data?.own;

  const chartData = bands.map((b) => ({
    band: b.band,
    label: bandLabel(b.band, edges),
    count: b.count,
    isOwn:
      own?.contributed === true &&
      own?.band !== undefined &&
      own.band === b.band,
  }));

  const ownPlacement =
    own?.contributed === true && own.value !== undefined ? (
      <Pill
        variant="accent"
        title={
          own.band !== undefined
            ? `band ${bandLabel(own.band, edges)}`
            : undefined
        }
      >
        You: {fmtValue(own.value, data?.metric_unit ?? "")}
      </Pill>
    ) : undefined;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Community"
        icon={routeIcon("/community")}
        sub="Where you sit in the private, opt-in developer community - a floored, aggregate band distribution with your own band highlighted. This is not a leaderboard: you never see another developer's number, and cohort cells below the minimum size are suppressed entirely."
      />

      {meta && metrics.length > 0 && (
        <div className="flex flex-wrap items-start gap-5 rounded-3 border border-line-2 bg-bg-2 p-4">
          <div className="flex flex-col gap-1.5">
            <span className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
              Metric
            </span>
            <SegmentedControl
              options={metrics.map((m) => ({ value: m.id, label: m.label }))}
              value={metric ?? ""}
              onChange={setMetric}
            />
          </div>
          {cohorts.length > 1 && (
            <div className="flex flex-col gap-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">
                Cohort
              </span>
              <SegmentedControl
                options={cohorts.map((c) => ({ value: c.key, label: c.label }))}
                value={cohort}
                onChange={setCohort}
              />
            </div>
          )}
        </div>
      )}

      {dataError && (
        <div className="rounded-3 border border-line-2 bg-bg-2">
          <ErrorPanel
            what="community bands"
            error={dataError}
            onRetry={dataQ.reload}
          />
        </div>
      )}

      {loading && !dataError && (
        <div className="flex flex-col gap-4" role="status" aria-label="Loading">
          {!meta && <HeaderSkeleton />}
          <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
            <ChartSkeleton height={240} />
          </div>
        </div>
      )}

      {!loading && !dataError && data && (
        <FadeIn className="flex flex-col gap-6">
          {own && !own.contributed && (
            <div className="rounded-3 border border-line-2 bg-bg-2 px-4 py-3 text-[12px] text-fg-2">
              You are not contributing this metric yet, so there is no band
              to highlight. Once your devices sync activity that covers this
              metric under your community grant, your own placement appears
              here. (Opting in to contribute is handled where you grant cloud
              data - not from this page.)
            </div>
          )}

          <ChartShell
            title={data.metric_label}
            icon={SECTION_ICONS.bands}
            sub={
              (data.cohort_size > 0
                ? `${fmtInt(data.cohort_size)} developers`
                : "cohort not sized") +
              (data.window_id ? ` · ${fmtYearMonth(data.window_id)}` : "") +
              (selectedCohort ? ` · ${selectedCohort.label}` : "")
            }
            right={
              <span className="flex items-center gap-2">
                <UpdatingBadge show={dataQ.isStale} />
                {ownPlacement}
              </span>
            }
            stale={dataQ.isStale}
          >
            {bands.length === 0 ? (
              <EmptyState
                variant="inline"
                illustration="cohort"
                illustrationSize={128}
                title="Not enough developers in this cohort yet"
                body="Community bands appear once at least 30 people opt in."
              />
            ) : (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart
                  data={chartData}
                  margin={{ top: 16, right: 12, left: 0, bottom: 0 }}
                >
                  <CartesianGrid {...CHART_GRID} />
                  <XAxis dataKey="label" {...CHART_AXIS} />
                  <YAxis
                    {...CHART_AXIS}
                    allowDecimals={false}
                    tickFormatter={fmtInt}
                  />
                  <Tooltip
                    cursor={{ fill: "var(--bg-3)" }}
                    content={
                      <ChartTooltip
                        formatItem={(_name, value) =>
                          `${fmtInt(value)} dev${value === 1 ? "" : "s"}`
                        }
                        extra={(row) => (row.isOwn ? "Your band" : null)}
                      />
                    }
                  />
                  <Bar
                    {...chartMotion()}
                    dataKey="count"
                    name="Developers"
                    fill="var(--fg-4)"
                    radius={[3, 3, 0, 0]}
                  >
                    {chartData.map((d) => (
                      <Cell
                        key={d.band}
                        // Non-own bands use fg-4 (3:1 on the card in both
                        // themes); bg-5 was ~1.4:1 and the distribution
                        // barely showed.
                        fill={d.isOwn ? "var(--accent)" : "var(--fg-4)"}
                      />
                    ))}
                    <LabelList dataKey="isOwn" content={OwnBarLabel} />
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </ChartShell>

          <Definitions
            metrics={metrics}
            cohortLabel={selectedCohort?.label}
            cohortDescription={selectedCohort?.description}
          />
        </FadeIn>
      )}
    </div>
  );
}
