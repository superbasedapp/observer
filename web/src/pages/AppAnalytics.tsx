import { Boxes, Bug, Layers, Server, Timer, Workflow } from "lucide-react";
import { Callout, Card, DataTable, HeroStat, PageHeader, Stagger, StatCard, TableSkeleton } from "@/components/primitives";
import { MetricIcon } from "@/components/MetricIcon";
import { DimCard, renderModelKey } from "@shared/components/planea/analytics";
import { KindChip } from "@shared/components/planea/chips";
import { usePlaneAMoney } from "@shared/components/planea/money";
import { TRACE_SOURCE } from "@shared/lib/obsVocab";
import { compact, ms, pct1 } from "@shared/lib/displayFormat";
import { useApi } from "@/lib/useApi";
import { navIcon } from "@/lib/nav";
import type { AppAnalyticsResult } from "@/lib/planeaApi";
import { APPS_HEADER_CLASS, AppsGate, ReadState, WindowPicker, useAppsWindow } from "@/components/apps/AppsChrome";
import { AppsCrossPlane } from "@/components/apps/AppsCrossPlane";
import { AppsMetricIcon } from "@/components/apps/AppsMetricIcon";

// Your apps > Analytics (Plane A lane B5, plan W2-5): totals, latency and the
// breakdowns of the window (GET /api/obs/analytics, contracts/node-routes.md),
// drawn with the shared DimCard the org Analytics page uses. The KPI band is
// the coding Overview's: the window's cost leads as a hero beside the
// operational tiles, each with its metric glyph.

export function AppAnalyticsPage() {
  const [days, setDays] = useAppsWindow();
  const money = usePlaneAMoney();
  const q = useApi<AppAnalyticsResult>("/api/obs/analytics", { days }, [days]);
  const a = q.data;
  const spark = (pick: (p: AppAnalyticsResult["by_day"][number]) => number) => (a ? a.by_day.map(pick) : undefined);
  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("app-analytics")}
        className={APPS_HEADER_CLASS}
        title="Analytics"
        sub="How your apps did in the window: volume, spend, errors and latency, broken down by model and service."
        right={<WindowPicker days={days} onChange={setDays} />}
      />
      <AppsGate>
        <ReadState error={q.error} onRetry={q.reload} feature="Analytics" />
        {!q.error && (
          <>
            <Stagger className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
              <HeroStat
                label="Cost"
                icon={<MetricIcon metric="spend" />}
                aurora
                sparkMode="wide"
                className="col-span-2 md:col-span-3 xl:col-span-2 xl:row-span-2"
                loading={q.loading}
                stale={q.isStale}
                value={a ? money.text({ usd: a.total_cost_usd, tokens: a.total_tokens }) : "-"}
                sub={
                  a && a.total_traces > 0
                    ? `${money.text({ usd: a.total_cost_usd / a.total_traces })} per trace on average`
                    : undefined
                }
                spark={spark((p) => p.cost_usd)}
              />
              <StatCard
                label="Traces"
                icon={<AppsMetricIcon metric="traces" />}
                loading={q.loading}
                value={a ? compact(a.total_traces) : "-"}
                sub={a ? `${compact(a.total_spans)} spans` : undefined}
                spark={spark((p) => p.traces)}
                stale={q.isStale}
              />
              <StatCard
                label="Tokens"
                icon={<MetricIcon metric="tokens" />}
                loading={q.loading}
                value={a ? compact(a.total_tokens) : "-"}
                sub={a ? `${compact(a.input_tokens)} in, ${compact(a.output_tokens)} out` : undefined}
                spark={spark((p) => p.tokens)}
                stale={q.isStale}
              />
              <StatCard
                label="Error rate"
                icon={<AppsMetricIcon metric="errorRate" />}
                loading={q.loading}
                value={a ? pct1(a.error_rate) : "-"}
                sub={a ? `${compact(a.error_traces)} traces` : undefined}
                warn={!!a && a.error_rate > 0}
                spark={spark((p) => p.error_traces)}
                stale={q.isStale}
              />
              <StatCard
                label="Latency p50"
                icon={<AppsMetricIcon metric="latency" />}
                loading={q.loading}
                value={a ? ms(a.latency_p50_ms) : "-"}
                sub={a ? `p95 ${ms(a.latency_p95_ms)}` : undefined}
                stale={q.isStale}
              />
              <StatCard label="Sessions" icon={<MetricIcon metric="sessions" />} loading={q.loading} value={a ? compact(a.sessions) : "-"} stale={q.isStale} />
              <StatCard label="End users" icon={<AppsMetricIcon metric="endUsers" />} loading={q.loading} value={a ? compact(a.end_users) : "-"} stale={q.isStale} />
            </Stagger>
            {a?.truncated && (
              <Callout title="Showing the newest 50,000 traces">This window holds more traces than one read covers.</Callout>
            )}
            {a && (
              <>
                <div className="grid gap-5 lg:grid-cols-2">
                  <DimCard title="By model" icon={Boxes} rows={a.by_model} keyHeader="Model" renderKey={renderModelKey} />
                  <DimCard title="By service" icon={Server} rows={a.by_service} keyHeader="Service" />
                  <DimCard title="By environment" icon={Layers} rows={a.by_environment} keyHeader="Environment" />
                  <DimCard title="By source" icon={Workflow} rows={a.by_source} keyHeader="Source" keyVocab={TRACE_SOURCE} />
                </div>
                <div className="grid gap-5 lg:grid-cols-2">
                  <Card title="Latency by span kind" icon={Timer}>
                    <DataTable
                      data={a.by_kind}
                      rowKey={(r) => r.kind}
                      zebra
                      minWidth={420}
                      columns={[
                        { accessorKey: "kind", header: "Kind", cell: (c) => <KindChip kind={c.row.original.kind} /> },
                        { accessorKey: "spans", header: "Spans", cell: (c) => compact(c.row.original.spans), meta: { align: "right" } },
                        { accessorKey: "p50_ms", header: "p50", cell: (c) => ms(c.row.original.p50_ms), meta: { align: "right" } },
                        { accessorKey: "p95_ms", header: "p95", cell: (c) => ms(c.row.original.p95_ms), meta: { align: "right" } },
                        { accessorKey: "avg_ms", header: "Average", cell: (c) => ms(c.row.original.avg_ms), meta: { align: "right" } },
                      ]}
                    />
                  </Card>
                  <DimCard title="Error causes" icon={Bug} rows={a.error_causes} keyHeader="Cause" />
                </div>
                {/* The cross-plane link (W4-3, lane C3). */}
                <AppsCrossPlane days={days} />
              </>
            )}
            {q.loading && !a && <TableSkeleton rows={6} />}
          </>
        )}
      </AppsGate>
    </div>
  );
}
