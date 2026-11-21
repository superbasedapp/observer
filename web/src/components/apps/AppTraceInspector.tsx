// AppTraceInspector - the machine's trace inspector: the shared
// TraceInspectorView (shared/components/planea/inspector) over
// GET /api/obs/trace/{id}, opened in place from the Traces and Sessions
// pages. The trace's scores come from lane B7's GET /api/obs/trace/{id}/scores
// when this daemon serves it; without it the view simply has no score chips.
// Content arrives with the detail (stored on this machine, D17), so there is
// no separate content load.

import { useMemo, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { Icon, SlideOver, StatCard, StatStrip, ErrorState, InlineLoading } from "@/components/primitives";
import { MetricIcon } from "@/components/MetricIcon";
import { AppsMetricIcon } from "@/components/apps/AppsMetricIcon";
import { AdmissionMarkPill } from "@/components/apps/AdmissionMarkPill";
import { GatedLink } from "@/components/GatedLink";
import { TraceInspectorView } from "@shared/components/planea/inspector";
import { PlaneATraceCostCell } from "@shared/components/planea/costCell";
import { compact, ms } from "@shared/lib/displayFormat";
import { useApi } from "@/lib/useApi";
import type { AppScoresResult, AppTraceDetail } from "@/lib/planeaApi";
import { contentBySpan, inspectorData } from "@/lib/planeaMap";

function InspectorBody({ traceId }: { traceId: string }) {
  const q = useApi<AppTraceDetail>(`/api/obs/trace/${encodeURIComponent(traceId)}`);
  const scores = useApi<AppScoresResult>(`/api/obs/trace/${encodeURIComponent(traceId)}/scores`);
  const [sel, setSel] = useState<string | null>(null);
  const data = useMemo(
    () => (q.data ? inspectorData(q.data, scores.data?.scores ?? []) : null),
    [q.data, scores.data],
  );
  const content = useMemo(() => (q.data ? contentBySpan(q.data) : null), [q.data]);
  if (q.error) return <ErrorState error={q.error} onRetry={q.reload} />;
  if (!data || !q.data) return <InlineLoading label="Loading the trace..." />;
  const t = q.data.trace;
  return (
    <TraceInspectorView
      traceKey={traceId}
      data={data}
      sel={sel}
      setSel={setSel}
      stats={
        <StatStrip cols={t.admission ? 5 : 4} ariaLabel="Trace summary" className="">
          <StatCard label="Spans" icon={<AppsMetricIcon metric="spans" />} value={compact(t.span_count)} />
          <StatCard label="Tokens" icon={<MetricIcon metric="tokens" />} value={compact(t.total_tokens)} />
          {/* The cost and its provenance as one pair (inspectorData: the
              TraceCost the server computed together, FR-M07), never the
              stored total beside the effective label. */}
          <StatCard label="Cost" icon={<MetricIcon metric="spend" />} value={<PlaneATraceCostCell usd={data.trace.cost_usd} tokens={t.total_tokens} provenance={data.cost_provenance} />} />
          <StatCard label="Duration" icon={<AppsMetricIcon metric="duration" />} value={ms(t.duration_ms)} />
          {t.admission && (
            <StatCard
              label="Admission"
              icon={<Icon icon={ShieldCheck} size="sm" />}
              value={<AdmissionMarkPill mark={t.admission} withCriterion />}
            />
          )}
        </StatStrip>
      }
      content={content}
      loadingContent={false}
      contentErr={null}
      loadContent={() => undefined}
      noContent={
        <>
          Either the app sent no prompt or response for this span, or storing app content is off on this machine.{" "}
          <GatedLink to="/settings?section=observability" className="text-accent hover:underline">
            Change it in Settings
          </GatedLink>
        </>
      }
    />
  );
}

/** AppTraceInspector is the slide-over; traceId null closes it. */
export function AppTraceInspector({ traceId, onClose }: { traceId: string | null; onClose: () => void }) {
  return (
    <SlideOver open={traceId !== null} onClose={onClose} width={960} bodyClassName="p-5" title="Trace" subtitle={traceId ?? undefined}>
      {traceId && <InspectorBody key={traceId} traceId={traceId} />}
    </SlideOver>
  );
}
