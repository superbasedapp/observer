import { useEffect, useState } from "react";
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
import { fmtInt, fmtYearMonth } from "@shared/lib/format";

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
      <h3 className="text-[13px] font-semibold text-fg-0">
        Metric definitions
      </h3>
      <p className="mt-1 text-[11px] text-fg-3">
        Every band is a range of one of these metrics, measured over your
        chosen window. Cohorts group developers so the comparison is like for
        like.
      </p>
      {cohortLabel && (
        <p className="mt-2 text-[11px] text-fg-2">
          <span className="text-fg-3">Cohort: </span>
          {cohortLabel}
        </p>
      )}
      {cohortDescription && (
        <p className="mt-0.5 text-[11px] text-fg-4">{cohortDescription}</p>
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
                <span className="ml-1.5 text-[10px] font-normal text-fg-4">
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
  const [meta, setMeta] = useState<CommunityMetricsView | null>(null);
  const [metaError, setMetaError] = useState<string | null>(null);

  const [metric, setMetric] = useState<string | undefined>(undefined);
  const [cohort, setCohort] = useState<string>("global");

  const [data, setData] = useState<CommunityView | null>(null);
  const [dataError, setDataError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Load the catalogs once, then seed the metric selector with the first
  // metric the backend offers (the cohort selector defaults to global).
  useEffect(() => {
    let live = true;
    getCommunityMetrics()
      .then((m) => {
        if (!live) return;
        setMeta(m);
        if (m.metrics.length > 0) {
          setMetric(m.metrics[0].id);
        } else {
          // No metrics offered — nothing to load, so stop the spinner.
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (live) {
          setMetaError(err instanceof Error ? err.message : "failed to load");
          setLoading(false);
        }
      });
    return () => {
      live = false;
    };
  }, []);

  // Reload the distribution whenever the metric or cohort changes. Version is
  // resolved from the catalog for the selected metric so a v2 metric asks for
  // v2 (the backend defaults to 1 otherwise); the window is omitted so the
  // server picks the most recent finalized one.
  useEffect(() => {
    if (metric === undefined) {
      return;
    }
    let live = true;
    setLoading(true);
    const version = meta?.metrics.find((m) => m.id === metric)?.version;
    getCommunity({ metric, version, cohort })
      .then((d) => {
        if (!live) return;
        setDataError(null);
        setData(d);
      })
      .catch((err: unknown) => {
        if (live) {
          setDataError(err instanceof Error ? err.message : "failed to load");
        }
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [metric, cohort, meta]);

  if (metaError) {
    return (
      <div className="rounded-3 border border-danger/30 bg-bg-2 px-4 py-3 text-[13px] text-danger">
        Could not load community metrics: {metaError}
      </div>
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
      <div>
        <h1 className="text-[20px] font-semibold text-fg-0">Community</h1>
        <p className="mt-1 max-w-[640px] text-[11px] text-fg-3">
          Where you sit in the private, opt-in developer community - a
          floored, aggregate band distribution with your own band
          highlighted. This is not a leaderboard: you never see another
          developer&apos;s number, and cohort cells below the minimum size are
          suppressed entirely.
        </p>
      </div>

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
        <div className="rounded-3 border border-danger/30 bg-bg-2 px-4 py-3 text-[13px] text-danger">
          Could not load community bands: {dataError}
        </div>
      )}

      {loading && !dataError && (
        <div className="text-[13px] text-fg-3">
          Loading community bands...
        </div>
      )}

      {!loading && !dataError && data && (
        <>
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
            sub={
              (data.cohort_size > 0
                ? `${fmtInt(data.cohort_size)} developers`
                : "cohort not sized") +
              (data.window_id ? ` · ${fmtYearMonth(data.window_id)}` : "") +
              (selectedCohort ? ` · ${selectedCohort.label}` : "")
            }
            right={ownPlacement}
          >
            {bands.length === 0 ? (
              <div className="grid h-[220px] place-items-center text-center">
                <p className="max-w-[360px] text-[12px] text-fg-3">
                  Not enough developers in this cohort yet - community bands
                  appear once at least 30 people opt in.
                </p>
              </div>
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
                    content={({ active, payload }) => {
                      if (!active || !payload?.length) return null;
                      const p = payload[0].payload as (typeof chartData)[number];
                      return (
                        <div className="rounded-2 border border-line-3 bg-bg-3/95 px-3 py-2 text-[11px] shadow-2 backdrop-blur">
                          <div className="text-fg-1">{p.label}</div>
                          <div className="mt-0.5 text-fg-3">
                            {fmtInt(p.count)} dev{p.count === 1 ? "" : "s"}
                            {p.isOwn && (
                              <span className="ml-1 text-accent">
                                · your band
                              </span>
                            )}
                          </div>
                        </div>
                      );
                    }}
                  />
                  <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                    {chartData.map((d) => (
                      <Cell
                        key={d.band}
                        fill={d.isOwn ? "var(--accent)" : "var(--bg-5)"}
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
        </>
      )}
    </div>
  );
}
