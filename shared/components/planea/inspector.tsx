import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  ChartGantt,
  Check,
  FileText,
  FlaskConical,
  LayoutDashboard,
  ListTree,
  Network,
  ShieldCheck,
  Spline,
  TextSearch,
  type LucideIcon,
} from "lucide-react";
import { ChartShell } from "../../primitives/ChartShell";
import { CardHeader } from "../../primitives/CardHeader";
import { HostMark } from "../../primitives/BrandGlyphs";
import { Icon } from "../../primitives/Icon";
import { InlineLoading } from "../../primitives/Spinner";
import { LiveDot } from "../../primitives/LiveDot";
import { ModelId } from "../../primitives/ModelId";
import { InlineEmpty as Empty, PanelCard as Card } from "../../primitives/Panel";
import { Pill } from "../../primitives/Pill";
import { SegmentedControl } from "../../primitives/SegmentedControl";
import { VocabDefPill as VocabPill } from "../../primitives/VocabDefPill";
import { compact, dateTime, ms } from "../../lib/displayFormat";
import { EVAL_VERDICT, evalLabelVerdict, TRACE_SOURCE, TRACE_STATUS } from "../../lib/obsVocab";
import { AgentGraphSvg, type AgentGraphEdgeInput, type AgentGraphNodeInput } from "./AgentGraphSvg";
import { KindChip } from "./chips";
import { usePlaneAMoney } from "./money";
import { PlaneACostBreakdown, PlaneACostCell, PlaneATraceCostCell } from "./costCell";
import type {
  PlaneAContentEntry,
  PlaneACostProvenance,
  PlaneAEvalChip,
  PlaneASpan,
  PlaneATraceHeader,
} from "./types";

// inspector - the pure body of the Plane A trace inspector (B5-0,
// 2026-11-19): header line, path strip, gantt timeline, span tree / agent
// graph and the span detail tabs (overview, content, evaluations). Promoted
// from web2/src/pages/obs/ObsInspectorPanel.tsx, which keeps the fetching
// (trace, content, annotations, admission) and the org-only slots and now
// renders <TraceInspectorView>; the node's Your apps trace page renders the
// same view over GET /api/obs/trace/{id}. No fetch, no router, no app state:
// data in, a span selection out, the org's extras through slots.

// INSPECTOR_SECTION_ICONS: one glyph per panel title in the inspector.
export const INSPECTOR_SECTION_ICONS = {
  timeline: ChartGantt,
  spanTree: ListTree,
  spanDetail: TextSearch,
  admission: ShieldCheck,
  sessionTraces: Spline,
} as const satisfies Record<string, LucideIcon>;

// INSPECTOR_VIEW_ICONS: the tree / graph toggle and the span-detail tabs.
export const INSPECTOR_VIEW_ICONS = {
  tree: ListTree,
  graph: Network,
  overview: LayoutDashboard,
  content: FileText,
  evaluations: FlaskConical,
} as const satisfies Record<string, LucideIcon>;

const SECTION_ICONS = INSPECTOR_SECTION_ICONS;
const VIEW_ICONS = INSPECTOR_VIEW_ICONS;

/** The trace the inspector view draws. */
export interface TraceInspectorData {
  trace: PlaneATraceHeader;
  spans: PlaneASpan[];
  trace_evals?: PlaneAEvalChip[];
  /** The trace's cost provenance at the top of the detail body (W4-2); the
   *  header line falls back to trace.cost_provenance. */
  cost_provenance?: PlaneACostProvenance | null;
}

/**
 * TraceInspectorView renders one trace (web2's TraceBody without its
 * fetches). The caller owns the content load (`content` null until loaded)
 * and passes its error as a rendered node; `annotations`, `stats` and
 * `footer` are slots (the org's annotation row, KPI strip and admission
 * panel; the node passes its own).
 */
export function TraceInspectorView({
  traceKey,
  data,
  sel,
  setSel,
  annotations,
  stats,
  footer,
  content,
  loadingContent,
  contentErr,
  loadContent,
  noContent,
}: {
  /** Changes when a different trace is shown (resets the default span). */
  traceKey: string;
  data: TraceInspectorData;
  sel: string | null;
  setSel: (id: string | null) => void;
  annotations?: ReactNode;
  stats?: ReactNode;
  footer?: ReactNode;
  content: Record<string, PlaneAContentEntry[]> | null;
  loadingContent: boolean;
  contentErr: ReactNode | null;
  loadContent: () => void;
  /** Why a span can have no content and where that is set (E-21): the
   *  app's sentence and link to its capture setting, shown under "No content
   *  captured for this span". Without it the view says only the generic
   *  reason (NO_CONTENT_REASON). */
  noContent?: ReactNode;
}) {
  const roots = useMemo(() => {
    const ids = new Set(data.spans.map((s) => s.span_id));
    return data.spans.filter((s) => !s.parent_span_id || !ids.has(s.parent_span_id));
  }, [data.spans]);
  const timeline = useMemo(() => buildTimeline(data.spans, roots), [data.spans, roots]);
  const selected = data.spans.find((s) => s.span_id === sel);
  const isFlat = data.spans.length > 1 && roots.length === data.spans.length;

  const [treeMode, setTreeMode] = useState<"tree" | "graph">("tree");
  const spanGraph = useMemo(() => buildSpanGraph(data.spans, roots), [data.spans, roots]);
  const selectedGroupId = useMemo(() => {
    if (!selected) return null;
    return spanGroupKey(selected);
  }, [selected]);

  const evalsBySpan = useMemo(() => {
    const m = new Map<string, PlaneAEvalChip[]>();
    for (const ev of data.trace_evals ?? []) {
      if (!ev.span_id) continue;
      const list = m.get(ev.span_id) ?? [];
      list.push(ev);
      m.set(ev.span_id, list);
    }
    return m;
  }, [data.trace_evals]);

  useEffect(() => {
    if (roots.length > 0 && !data.spans.some((s) => s.span_id === sel)) {
      setSel(roots[0].span_id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [traceKey, roots, data.spans]);

  return (
    <div className="space-y-5">
      <div>
        <TraceHeaderLine trace={{ ...data.trace, cost_provenance: data.cost_provenance ?? data.trace.cost_provenance }} />
        {annotations}
        {(data.trace_evals?.length ?? 0) > 0 && (
          <EvalChipRow evals={data.trace_evals ?? []} onJumpToSpan={setSel} />
        )}
      </div>

      {stats}

      <PathStrip rows={timeline.rows} sel={sel} setSel={setSel} isFlat={isFlat} />

      <ChartShell title="Timeline" icon={SECTION_ICONS.timeline}>
        <Timeline timeline={timeline} sel={sel} setSel={setSel} />
      </ChartShell>

      <div className="grid gap-5 lg:grid-cols-2">
        <ChartShell
          title="Span tree"
          icon={SECTION_ICONS.spanTree}
          right={
            <SegmentedControl<"tree" | "graph">
              options={[
                { value: "tree", label: "Tree", icon: VIEW_ICONS.tree },
                { value: "graph", label: "Graph", icon: VIEW_ICONS.graph },
              ]}
              value={treeMode}
              onChange={setTreeMode}
            />
          }
        >
          {treeMode === "tree" ? (
            <div className="space-y-0.5">
              {roots.map((r) => (
                <SpanNode
                  key={r.span_id}
                  span={r}
                  all={data.spans}
                  depth={0}
                  sel={sel}
                  setSel={setSel}
                  evalsBySpan={evalsBySpan}
                />
              ))}
            </div>
          ) : (
            <AgentGraphSvg
              nodes={spanGraph.nodes}
              edges={spanGraph.edges}
              selectedId={selectedGroupId}
              onNodeClick={(gid) => {
                const spanId = spanGraph.latestSpanIdByGroup.get(gid);
                if (spanId) setSel(spanId);
              }}
            />
          )}
        </ChartShell>

        <Card className="p-4">
          <CardHeader icon={SECTION_ICONS.spanDetail} title="Span detail" className="!mb-2" />
          {!selected ? (
            <p className="text-[13px] text-fg-3">Select a span.</p>
          ) : (
            <SpanDetailPanel
              span={selected}
              entries={content?.[selected.span_id]}
              evals={evalsBySpan.get(selected.span_id) ?? EMPTY_EVALS}
              contentLoaded={content !== null}
              loadingContent={loadingContent}
              contentErr={contentErr}
              loadContent={loadContent}
              noContent={noContent}
            />
          )}
        </Card>
      </div>

      {footer}
    </div>
  );
}

// --- helpers (ported from TraceDetail.tsx, then promoted here) ------------

const PATH_STRIP_CAP = 40;
function PathStrip({
  rows,
  sel,
  setSel,
  isFlat,
}: {
  rows: TimelineRow[];
  sel: string | null;
  setSel: (id: string | null) => void;
  isFlat: boolean;
}) {
  const capped = rows.slice(0, PATH_STRIP_CAP);
  const overflow = rows.length - capped.length;
  return (
    <div>
      <div className="flex flex-wrap items-center gap-1 text-[11px]">
        {capped.map((r, i) => (
          <span key={r.span.span_id} className="flex items-center gap-1">
            {i > 0 && <span className="text-fg-4">→</span>}
            <button
              type="button"
              onClick={() => setSel(r.span.span_id)}
              className={`rounded-1 border px-1.5 py-0.5 ${
                sel === r.span.span_id
                  ? "border-accent bg-accent-soft text-accent"
                  : "border-line-2 bg-bg-2 text-fg-2 hover:bg-bg-3"
              }`}
            >
              {r.span.kind}: {r.span.name || "(unnamed)"}
            </button>
          </span>
        ))}
        {overflow > 0 && <span className="text-fg-3">+{overflow} more</span>}
      </div>
      {isFlat && (
        <p className="mt-1 text-[11px] text-fg-3">
          Every span in this trace shares the same (missing) parent - this node/source may not be
          reporting parent_span_id, so the tree renders flat rather than nested.
        </p>
      )}
    </div>
  );
}

function spanGroupKey(s: PlaneASpan): string {
  return `${s.kind || "span"}:${s.name || "(unnamed)"}`;
}

type SpanGroup = {
  id: string;
  kind: string;
  name: string;
  count: number;
  errorCount: number;
  isRoot: boolean;
  latestSpanId: string;
  latestTime: number;
};

function buildSpanGraph(
  spans: PlaneASpan[],
  roots: PlaneASpan[],
): { nodes: AgentGraphNodeInput[]; edges: AgentGraphEdgeInput[]; latestSpanIdByGroup: Map<string, string> } {
  const rootIds = new Set(roots.map((r) => r.span_id));
  const groups = new Map<string, SpanGroup>();
  const spanGroup = new Map<string, string>();

  for (const s of spans) {
    const gid = spanGroupKey(s);
    spanGroup.set(s.span_id, gid);
    const t = epochMs(s.started_at);
    const existing = groups.get(gid);
    if (!existing) {
      groups.set(gid, {
        id: gid,
        kind: s.kind || "span",
        name: s.name || "(unnamed)",
        count: 1,
        errorCount: s.status === "error" ? 1 : 0,
        isRoot: rootIds.has(s.span_id),
        latestSpanId: s.span_id,
        latestTime: Number.isFinite(t) ? t : 0,
      });
    } else {
      existing.count += 1;
      if (s.status === "error") existing.errorCount += 1;
      if (rootIds.has(s.span_id)) existing.isRoot = true;
      if (Number.isFinite(t) && t >= existing.latestTime) {
        existing.latestTime = t;
        existing.latestSpanId = s.span_id;
      }
    }
  }

  const edgeMap = new Map<string, { from: string; to: string; count: number; errorCount: number }>();
  for (const s of spans) {
    if (!s.parent_span_id) continue;
    const parentGid = spanGroup.get(s.parent_span_id);
    if (!parentGid) continue;
    const childGid = spanGroup.get(s.span_id)!;
    const key = `${parentGid}->${childGid}`;
    const existing = edgeMap.get(key);
    if (!existing) {
      edgeMap.set(key, { from: parentGid, to: childGid, count: 1, errorCount: s.status === "error" ? 1 : 0 });
    } else {
      existing.count += 1;
      if (s.status === "error") existing.errorCount += 1;
    }
  }

  const nodes: AgentGraphNodeInput[] = Array.from(groups.values()).map((g) => ({
    id: g.id,
    kind: g.kind,
    name: g.name,
    count: g.count,
    errorCount: g.errorCount,
    isRoot: g.isRoot,
  }));
  const edges: AgentGraphEdgeInput[] = Array.from(edgeMap.values()).map((e) => ({
    from: e.from,
    to: e.to,
    count: e.count,
    errorCount: e.errorCount,
  }));
  const latestSpanIdByGroup = new Map<string, string>();
  for (const g of groups.values()) latestSpanIdByGroup.set(g.id, g.latestSpanId);

  return { nodes, edges, latestSpanIdByGroup };
}

const EMPTY_EVALS: PlaneAEvalChip[] = [];

// EVAL_BUTTON_CLASS colours an annotation chip button by its label's verdict
// (the same buckets as the EVAL_VERDICT pills).
const EVAL_BUTTON_CLASS: Record<ReturnType<typeof evalLabelVerdict>, string> = {
  pass: "border-success/30 bg-success-soft text-success",
  fail: "border-danger/30 bg-danger-soft text-danger",
  neutral: "border-line-2 bg-bg-2 text-fg-2",
};


function EvalChipRow({
  evals,
  onJumpToSpan,
}: {
  evals: PlaneAEvalChip[];
  onJumpToSpan: (spanId: string) => void;
}) {
  const [open, setOpen] = useState<number | null>(null);
  return (
    <div className="mt-2 flex flex-wrap items-center gap-1.5">
      {evals.map((ev, i) => (
        <span key={i} className="relative">
          <button
            type="button"
            onClick={() => setOpen(open === i ? null : i)}
            className={`rounded-pill border px-2 py-0.5 text-[11px] ${EVAL_BUTTON_CLASS[evalLabelVerdict(ev.label)]}`}
          >
            {ev.name}: {ev.label}
          </button>
          {open === i && <EvalChipPopover ev={ev} onJumpToSpan={onJumpToSpan} />}
        </span>
      ))}
    </div>
  );
}

function EvalChipPopover({ ev, onJumpToSpan }: { ev: PlaneAEvalChip; onJumpToSpan: (spanId: string) => void }) {
  useEffect(() => {
    function onDoc() {
      /* closed by parent re-render on outside click via row-level state is
         out of scope here; simplest safe behavior is click-to-toggle only */
    }
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);
  return (
    <div className="absolute left-0 top-full z-10 mt-1 w-56 rounded-2 border border-line-2 bg-bg-1 p-2 text-[11px] shadow-drawer">
      <div>
        <b>{ev.name}</b>
      </div>
      <div className="text-fg-3">
        {ev.label} · score {ev.score}
      </div>
      {ev.span_id && (
        <button
          type="button"
          onClick={() => onJumpToSpan(ev.span_id!)}
          className="mt-1 text-accent hover:underline"
        >
          Jump to span
        </button>
      )}
    </div>
  );
}

export function TraceHeaderLine({ trace }: { trace: PlaneATraceHeader }) {
  return (
    <div className="flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[12px] text-fg-2">
      <VocabPill of={TRACE_STATUS} value={trace.status} />
      <span className="text-fg-3">·</span>
      <span>{ms(trace.duration_ms)}</span>
      <span className="text-fg-3">·</span>
      <span>
        <PlaneATraceCostCell usd={trace.cost_usd} tokens={trace.total_tokens} provenance={trace.cost_provenance} />
      </span>
      <span className="text-fg-3">·</span>
      <span>{dateTime(trace.started_at)}</span>
      {trace.source && (
        <>
          <span className="text-fg-3">·</span>
          <VocabPill of={TRACE_SOURCE} value={trace.source} />
        </>
      )}
      {trace.email && (
        <>
          <span className="text-fg-3">·</span>
          <span>{trace.email}</span>
        </>
      )}
      {trace.session_id && (
        <>
          <span className="text-fg-3">·</span>
          <span className="text-fg-3">session {trace.session_id}</span>
        </>
      )}
    </div>
  );
}

function SpanNode({
  span,
  all,
  depth,
  sel,
  setSel,
  evalsBySpan,
}: {
  span: PlaneASpan;
  all: PlaneASpan[];
  depth: number;
  sel: string | null;
  setSel: (id: string | null) => void;
  evalsBySpan: Map<string, PlaneAEvalChip[]>;
}) {
  const children = all.filter((s) => s.parent_span_id === span.span_id);
  const evalCount = evalsBySpan.get(span.span_id)?.length ?? 0;
  return (
    <div>
      <button
        type="button"
        onClick={() => setSel(span.span_id)}
        style={{ paddingLeft: depth * 16 + 8 }}
        className={`flex w-full items-center gap-2 rounded-1 py-1 pr-2 text-left text-[12px] ${
          sel === span.span_id ? "bg-accent-soft text-accent" : "text-fg-2 hover:bg-bg-3"
        }`}
      >
        <KindChip kind={span.kind} />
        <StatusGlyph status={span.status} />
        <span className="min-w-0 flex-1 truncate">{span.name || "(unnamed)"}</span>
        {evalCount > 0 && <Pill variant="neutral">{evalCount} eval{evalCount === 1 ? "" : "s"}</Pill>}
        <span className="shrink-0 text-fg-3">{compact(span.total_tokens)}</span>
        <span className="shrink-0 text-fg-3">
          {/* A span with no model and no tokens (an agent or tool span) made
              no model call: a dash, never "Unpriced" beside a priced child
              (U-10). */}
          {!span.model && !span.total_tokens && span.cost_usd == null ? (
            <span title="No model call on this span">-</span>
          ) : (
            <PlaneACostCell usd={span.cost_usd} tokens={span.total_tokens} source={span.cost_source} />
          )}
        </span>
        <span className="shrink-0 text-fg-3">{ms(span.duration_ms)}</span>
      </button>
      {children.map((c) => (
        <SpanNode key={c.span_id} span={c} all={all} depth={depth + 1} sel={sel} setSel={setSel} evalsBySpan={evalsBySpan} />
      ))}
    </div>
  );
}


function StatusGlyph({ status }: { status: string }) {
  // web2 lib/liveSignals SPAN_STATUS_DOT has one row: error -> danger, still.
  if (status === "error") return <LiveDot tone="danger" still label="Span error" className="shrink-0" />;
  if (status === "ok") return <Icon icon={Check} size="xs" className="shrink-0 text-success" />;
  return null;
}

export function tokenSubLabel(data: { spans: PlaneASpan[] }): string {
  const proxyVerified = data.spans.some(
    (s) => s.enrichment?.found && (s.enrichment.input_tokens || s.enrichment.output_tokens),
  );
  return proxyVerified ? "proxy-verified" : "trace total";
}

/** NO_CONTENT_REASON is the generic reason under "No content captured for
 *  this span" when the app passes no noContent slot (E-21). */
export const NO_CONTENT_REASON =
  "Either the app sent no prompt or response for this span, or the capture setting that applies to it keeps metadata only.";

type SpanTab = "overview" | "content" | "evaluations";
function SpanDetailPanel({
  span,
  entries,
  evals,
  contentLoaded,
  loadingContent,
  contentErr,
  loadContent,
  noContent,
}: {
  span: PlaneASpan;
  entries?: PlaneAContentEntry[];
  evals: PlaneAEvalChip[];
  contentLoaded: boolean;
  loadingContent: boolean;
  contentErr: ReactNode | null;
  loadContent: () => void;
  noContent?: ReactNode;
}) {
  const [tab, setTab] = useState<SpanTab>("overview");
  useEffect(() => setTab("overview"), [span.span_id]);

  return (
    <div>
      <SegmentedControl<SpanTab>
        options={[
          { value: "overview", label: "Overview", icon: VIEW_ICONS.overview },
          { value: "content", label: "Content", icon: VIEW_ICONS.content },
          {
            value: "evaluations",
            label: `Evaluations${evals.length ? ` (${evals.length})` : ""}`,
            icon: VIEW_ICONS.evaluations,
          },
        ]}
        value={tab}
        onChange={setTab}
      />
      <div className="mt-3">
        {tab === "overview" && <SpanOverviewTab span={span} />}
        {tab === "content" && (
          <SpanContentTab
            entries={entries}
            contentLoaded={contentLoaded}
            loadingContent={loadingContent}
            contentErr={contentErr}
            loadContent={loadContent}
            noContent={noContent}
          />
        )}
        {tab === "evaluations" && <SpanEvaluationsTab evals={evals} />}
      </div>
    </div>
  );
}

function SpanOverviewTab({ span }: { span: PlaneASpan }) {
  const money = usePlaneAMoney().text;
  const hasWedge = span.input_tokens || span.output_tokens || span.cost_usd;
  return (
    <div className="space-y-3">
      <div>
        <h4 className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-fg-3">Overview</h4>
        <DetailRow label="Status" value={span.status} node={span.status ? <VocabPill of={TRACE_STATUS} value={span.status} /> : undefined} />
        <DetailRow label="Kind" value={span.kind} node={span.kind ? <KindChip kind={span.kind} /> : undefined} />
        <DetailRow label="Duration" value={ms(span.duration_ms)} />
        <DetailRow label="Started" value={dateTime(span.started_at)} />
        <DetailRow label="Ended" value={dateTime(span.ended_at)} />
        {span.model && (
          <DetailRow label="Model" value={span.model} node={<ModelId model={span.model} mono={false} />} />
        )}
        {span.provider && (
          <DetailRow
            label="Provider"
            value={span.provider}
            node={
              <span className="inline-flex items-center gap-1">
                <HostMark host={span.provider} size={12} className="text-fg-2" />
                {span.provider}
              </span>
            }
          />
        )}
      </div>
      <div>
        <h4 className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-fg-3">Attributes</h4>
        <DetailRow label="Span ID" value={span.span_id} mono />
        {span.parent_span_id && <DetailRow label="Parent span ID" value={span.parent_span_id} mono />}
        {span.request_id && <DetailRow label="Request ID" value={span.request_id} mono />}
      </div>
      <PlaneACostBreakdown span={span} />
      {Boolean(hasWedge) &&
        (span.enrichment?.found ? (
          <div className="rounded-2 border border-success/30 bg-success-soft/40 p-2.5 text-[12px]">
            <div className="mb-1 font-semibold text-success">Proxy-verified</div>
            <DetailRow label="Input" value={num0(span.enrichment.input_tokens)} />
            <DetailRow label="Output" value={num0(span.enrichment.output_tokens)} />
            <DetailRow label="Cache read" value={num0(span.enrichment.cache_read_tokens)} />
            <DetailRow label="Cache write" value={num0(span.enrichment.cache_creation_tokens)} />
            <DetailRow
              label="Cost"
              value={money({
                usd: span.enrichment.cost_usd,
                tokens: span.enrichment.input_tokens + span.enrichment.output_tokens,
              })}
            />
          </div>
        ) : (
          <div className="rounded-2 border border-line-2 bg-bg-2 p-2.5 text-[12px]">
            <div className="mb-1 font-semibold text-fg-2">Span tokens</div>
            <DetailRow label="Input" value={num0(span.input_tokens)} />
            <DetailRow label="Output" value={num0(span.output_tokens)} />
            <DetailRow label="Cache read" value={num0(span.cache_read_tokens)} />
            <DetailRow label="Cache write" value={num0(span.cache_write_tokens)} />
          </div>
        ))}
    </div>
  );
}

function SpanContentTab({
  entries,
  contentLoaded,
  loadingContent,
  contentErr,
  loadContent,
  noContent,
}: {
  entries?: PlaneAContentEntry[];
  contentLoaded: boolean;
  loadingContent: boolean;
  contentErr: ReactNode | null;
  loadContent: () => void;
  noContent?: ReactNode;
}) {
  // Opening the Content tab IS the intent to view content, so it loads
  // immediately (follow-up P2 ruling — no click-to-disclose gate on primary
  // content). The load is still audited server-side on every genuine fetch;
  // it only fires once this tab is actually rendered, never as a side effect
  // of merely opening the inspector.
  useEffect(() => {
    if (!contentLoaded && !loadingContent && !contentErr) loadContent();
  }, [contentLoaded, loadingContent, contentErr, loadContent]);
  if (!contentLoaded) {
    return (
      <div>
        {contentErr ? (
          contentErr
        ) : (
          <InlineLoading label="Loading content…" />
        )}
      </div>
    );
  }
  if (!entries || entries.length === 0) {
    return (
      <Empty
        icon={VIEW_ICONS.content}
        message="No content captured for this span."
        body={noContent ?? NO_CONTENT_REASON}
      />
    );
  }
  return (
    <div className="space-y-2">
      {entries.map((e, i) => (
        <ContentEntryBlock key={i} entry={e} />
      ))}
    </div>
  );
}

function ContentEntryBlock({ entry }: { entry: PlaneAContentEntry }) {
  const pretty = useMemo(() => {
    try {
      return JSON.stringify(JSON.parse(entry.content), null, 2);
    } catch {
      return null;
    }
  }, [entry.content]);
  const [mode, setMode] = useState<"pretty" | "raw">(pretty ? "pretty" : "raw");

  return (
    <div className="rounded-2 border border-line-2 bg-bg-2 p-2.5">
      <div className="mb-1.5 flex items-center justify-between">
        <span className="text-[11px] font-semibold text-fg-2">{contentLabel(entry.kind)}</span>
        {pretty && <PrettyRawToggle mode={mode} onChange={setMode} />}
      </div>
      {!entry.has_raw ? (
        <p className="text-[12px] text-fg-3">raw content disabled by the node - body hashed only</p>
      ) : (
        <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words text-[11px] text-fg-1">
          {mode === "pretty" && pretty ? pretty : entry.content}
        </pre>
      )}
    </div>
  );
}

function PrettyRawToggle({ mode, onChange }: { mode: "pretty" | "raw"; onChange: (m: "pretty" | "raw") => void }) {
  return (
    <div className="flex items-center gap-0.5 rounded-1 border border-line-2 bg-bg-1 p-0.5 text-[10px]">
      {(["pretty", "raw"] as const).map((m) => (
        <button
          key={m}
          type="button"
          onClick={() => onChange(m)}
          className={`rounded px-1.5 py-0.5 ${mode === m ? "bg-bg-4 text-fg-0" : "text-fg-3 hover:text-fg-1"}`}
        >
          {m}
        </button>
      ))}
    </div>
  );
}

function SpanEvaluationsTab({ evals }: { evals: PlaneAEvalChip[] }) {
  if (evals.length === 0) return <Empty icon={VIEW_ICONS.evaluations} message="No evaluations reference this span." />;
  return (
    <table className="w-full text-[12px]">
      <thead>
        <tr className="text-left text-fg-3">
          <th className="pb-1 font-medium">Name</th>
          <th className="pb-1 font-medium">Label</th>
          <th className="pb-1 font-medium">Score</th>
        </tr>
      </thead>
      <tbody>
        {evals.map((ev, i) => (
          <tr key={i} className="border-t border-line-1 transition-colors hover:bg-bg-3/60">
            <td className="py-1 pr-2">{ev.name}</td>
            <td className="py-1 pr-2">
              <VocabPill of={EVAL_VERDICT} value={evalLabelVerdict(ev.label)}>
                {ev.label}
              </VocabPill>
            </td>
            <td className="py-1">{ev.score}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// --- gantt timeline ----------------------------------------------------

type TimelineRow = { span: PlaneASpan; depth: number };
type TimelineModel = { rows: TimelineRow[]; lo: number; span: number; hasAxis: boolean; maxDur: number };

function epochMs(iso: string): number {
  return new Date(iso).getTime();
}

function buildTimeline(spans: PlaneASpan[], roots: PlaneASpan[]): TimelineModel {
  const childrenOf = new Map<string, PlaneASpan[]>();
  for (const s of spans) {
    if (!s.parent_span_id) continue;
    const list = childrenOf.get(s.parent_span_id) ?? [];
    list.push(s);
    childrenOf.set(s.parent_span_id, list);
  }
  const rows: TimelineRow[] = [];
  const seen = new Set<string>();
  function walk(span: PlaneASpan, depth: number) {
    if (seen.has(span.span_id)) return;
    seen.add(span.span_id);
    rows.push({ span, depth });
    for (const c of childrenOf.get(span.span_id) ?? []) walk(c, depth + 1);
  }
  for (const r of roots) walk(r, 0);
  for (const s of spans) {
    if (!seen.has(s.span_id)) {
      seen.add(s.span_id);
      rows.push({ span: s, depth: 0 });
    }
  }

  let lo = Infinity;
  let hi = -Infinity;
  let maxDur = 0;
  for (const s of spans) {
    const st = epochMs(s.started_at);
    const en = epochMs(s.ended_at);
    if (Number.isFinite(st)) lo = Math.min(lo, st);
    if (Number.isFinite(en)) hi = Math.max(hi, en);
    if (Number.isFinite(s.duration_ms)) maxDur = Math.max(maxDur, s.duration_ms);
  }
  const hasAxis = Number.isFinite(lo) && Number.isFinite(hi) && hi > lo;
  return { rows, lo: Number.isFinite(lo) ? lo : 0, span: hasAxis ? hi - lo : 0, hasAxis, maxDur };
}

function barGeom(s: PlaneASpan, t: TimelineModel): { left: number; width: number; faint: boolean } {
  if (t.hasAxis) {
    const st = epochMs(s.started_at);
    if (!Number.isFinite(st)) return { left: 0, width: 100, faint: true };
    const en = epochMs(s.ended_at);
    const left = ((st - t.lo) / t.span) * 100;
    const width = Number.isFinite(en) ? Math.max(((en - st) / t.span) * 100, 0.5) : 0.5;
    return { left: Math.min(Math.max(left, 0), 100), width: Math.min(width, 100 - left), faint: false };
  }
  if (t.maxDur > 0) {
    return { left: 0, width: Math.max((s.duration_ms / t.maxDur) * 100, 1), faint: false };
  }
  return { left: 0, width: 100, faint: true };
}

function Timeline({
  timeline,
  sel,
  setSel,
}: {
  timeline: TimelineModel;
  sel: string | null;
  setSel: (id: string | null) => void;
}) {
  if (timeline.rows.length === 0) return <Empty icon={SECTION_ICONS.timeline} message="No spans." />;
  return (
    <div className="space-y-0.5">
      {timeline.rows.map(({ span, depth }) => {
        const g = barGeom(span, timeline);
        const active = sel === span.span_id;
        return (
          <button
            key={span.span_id}
            type="button"
            onClick={() => setSel(span.span_id)}
            className="flex w-full items-center gap-2 rounded-1 py-1 pr-2 text-left hover:bg-bg-3"
          >
            <span
              style={{ paddingLeft: depth * 12 }}
              className="w-40 shrink-0 truncate text-[11px] text-fg-2"
              title={span.name}
            >
              {span.name || "(unnamed)"}
            </span>
            <span className="relative h-2.5 min-w-0 flex-1 rounded-full bg-fg-3/15">
              <span
                style={{ left: `${g.left}%`, width: `${g.width}%` }}
                className={`absolute inset-y-0 rounded-full ${
                  span.status === "error" ? "bg-danger" : "bg-accent"
                } ${active ? "ring-2 ring-accent-ring" : ""} ${g.faint ? "opacity-40" : ""}`}
              />
            </span>
            <span className="w-14 shrink-0 text-right text-[11px] text-fg-3">{ms(span.duration_ms)}</span>
          </button>
        );
      })}
    </div>
  );
}

// DetailRow renders one label / value line. `node` replaces the plain value
// text with a richer rendering (a model id with its family mark, a provider
// with its host mark); `value` still feeds the title.
function DetailRow({ label, value, mono, node }: { label: string; value: string; mono?: boolean; node?: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 py-0.5 text-[12px]">
      <span className="text-fg-3">{label}</span>
      <span className={`min-w-0 truncate text-right text-fg-1 ${mono ? "font-mono text-[11px]" : ""}`} title={value}>
        {node ?? (value || "-")}
      </span>
    </div>
  );
}

function num0(n: number): string {
  return compact(n);
}

function contentLabel(kind: string): string {
  if (kind === "prompt") return "Prompt";
  if (kind === "response") return "Response";
  if (kind === "tool_io") return "Tool I/O";
  return kind || "Content";
}

