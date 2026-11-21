import { useId, useMemo } from "react";
import { TONE_COLOR, vocabTone } from "../../lib/vocabDef";
import { SPAN_KIND } from "../../lib/obsVocab";

// AgentGraphSvg (promoted from web2/src/pages/obs/, B5-0; web2 keeps a
// re-export shim) — shared, hand-rolled, dependency-free SVG renderer for the
// Agent Graph feature (docs/plans/agent-graph-path-spec-2026-08-14.md §2.3).
// Pure presentational component: it does no fetching and no aggregation —
// callers (GraphTab.tsx for the window-aggregate graph, TraceDetail.tsx for
// the per-trace graph) hand it a plain {nodes, edges} shape and it lays out a
// layered DAG left-to-right by BFS depth from root nodes, with back-edges
// (cycles / repeat transitions) drawn as curved loops rather than hidden.
//
// Kept intentionally simple and deterministic — no force simulation, no
// external layout library (house rule: no new npm deps).

export type AgentGraphNodeInput = {
  id: string;
  kind: string;
  name: string;
  label?: string;
  count: number;
  errorCount: number;
  isRoot: boolean;
  sub?: string;
};
export type AgentGraphEdgeInput = {
  from: string;
  to: string;
  count: number;
  errorCount: number;
};

export function AgentGraphSvg({
  nodes,
  edges,
  selectedId,
  onNodeClick,
}: {
  nodes: AgentGraphNodeInput[];
  edges: AgentGraphEdgeInput[];
  selectedId?: string | null;
  onNodeClick?: (id: string) => void;
}) {
  const uid = useId().replace(/[^a-zA-Z0-9]/g, "");
  const layout = useMemo(() => computeLayout(nodes, edges), [nodes, edges]);

  if (nodes.length === 0) {
    return <p className="py-6 text-center text-[13px] text-fg-3">No steps to graph.</p>;
  }

  const incident = new Set<string>();
  if (selectedId) {
    for (const e of edges) {
      if (e.from === selectedId || e.to === selectedId) incident.add(edgeKey(e));
    }
  }

  return (
    <div className="overflow-x-auto overflow-y-hidden">
      <svg
        width={layout.width}
        height={layout.height}
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        className="block"
        role="img"
        aria-label="Agent graph"
      >
        <defs>
          <marker
            id={`ag-arrow-${uid}`}
            viewBox="0 0 10 10"
            refX="8.5"
            refY="5"
            markerWidth="9"
            markerHeight="9"
            markerUnits="userSpaceOnUse"
            orient="auto-start-reverse"
          >
            <path d="M0,0 L10,5 L0,10 z" fill="var(--fg-3)" />
          </marker>
          <marker
            id={`ag-arrow-err-${uid}`}
            viewBox="0 0 10 10"
            refX="8.5"
            refY="5"
            markerWidth="9"
            markerHeight="9"
            markerUnits="userSpaceOnUse"
            orient="auto-start-reverse"
          >
            <path d="M0,0 L10,5 L0,10 z" fill="var(--danger)" />
          </marker>
        </defs>

        {/* Edges first, under the nodes. */}
        {layout.edges.map((e) => {
          const highlighted = incident.has(e.key);
          const hasError = e.errorCount > 0;
          const stroke = hasError ? "var(--danger)" : highlighted ? "var(--accent)" : "var(--fg-4)";
          const width = Math.min(1 + Math.log2(1 + e.count), 6);
          const strokeWidth = highlighted ? width + 0.75 : width;
          // An edge that carried traffic in the window flows: a faint solid
          // track plus dashes walking in the edge's direction (sb-dash-flow;
          // still dashes under reduced motion). An edge with no recorded
          // transitions stays a plain static line.
          const flows = e.count > 0;
          return (
            <g key={e.key} opacity={selectedId && !highlighted ? 0.35 : 1}>
              <path
                d={e.path}
                fill="none"
                stroke={stroke}
                strokeOpacity={flows ? 0.4 : 1}
                strokeWidth={strokeWidth}
                markerEnd={`url(#${hasError ? `ag-arrow-err-${uid}` : `ag-arrow-${uid}`})`}
              />
              {flows && (
                <path
                  d={e.path}
                  fill="none"
                  stroke={stroke}
                  strokeWidth={strokeWidth}
                  strokeLinecap="round"
                  className="sb-dash-flow"
                  aria-hidden
                />
              )}
              <rect
                x={e.labelX - labelWidth(e.count) / 2}
                y={e.labelY - 8}
                width={labelWidth(e.count)}
                height={14}
                rx={7}
                fill="var(--bg-1)"
                stroke="var(--line-2)"
                strokeWidth={0.75}
              />
              <text
                x={e.labelX}
                y={e.labelY + 3.5}
                textAnchor="middle"
                fontSize={9.5}
                className="font-mono"
                fill={hasError ? "var(--danger)" : "var(--fg-3)"}
              >
                {e.count}
              </text>
            </g>
          );
        })}

        {/* Nodes on top of edges. */}
        {layout.nodes.map((n) => {
          const active = selectedId === n.id;
          const color = kindColor(n.kind);
          const label = truncateLabel(n.label ?? n.name, 20);
          return (
            <g
              key={n.id}
              transform={`translate(${n.x},${n.y})`}
              onClick={onNodeClick ? () => onNodeClick(n.id) : undefined}
              style={{ cursor: onNodeClick ? "pointer" : "default" }}
            >
              <title>
                {n.name || n.kind}
                {n.sub ? `, ${n.sub}` : ""}, {n.count}x, {n.errorCount} error{n.errorCount === 1 ? "" : "s"}
              </title>
              <rect
                width={NODE_WIDTH}
                height={NODE_HEIGHT}
                rx={9}
                fill="var(--bg-2)"
                stroke={active ? "var(--accent)" : n.errorCount > 0 ? "var(--danger)" : "var(--line-2)"}
                strokeWidth={active ? 2 : 1}
              />
              {active && (
                <rect
                  x={-3}
                  y={-3}
                  width={NODE_WIDTH + 6}
                  height={NODE_HEIGHT + 6}
                  rx={12}
                  fill="none"
                  stroke="var(--accent)"
                  strokeOpacity={0.35}
                  strokeWidth={4}
                />
              )}
              {/* kind accent stripe */}
              <rect x={0} y={0} width={4} height={NODE_HEIGHT} rx={2} fill={color} />
              <text x={14} y={20} fontSize={11.5} fontWeight={600} fill="var(--fg-0)">
                {label}
              </text>
              <text x={14} y={34} fontSize={9.5} fill="var(--fg-3)">
                {(n.kind || "span").toUpperCase()}
              </text>
              <text x={NODE_WIDTH - 10} y={20} textAnchor="end" fontSize={10} className="font-mono" fill="var(--fg-2)">
                {`×${compactCount(n.count)}`}
              </text>
              {n.sub && (
                <text x={NODE_WIDTH - 10} y={34} textAnchor="end" fontSize={9.5} fill="var(--fg-3)">
                  {n.sub}
                </text>
              )}
              {n.errorCount > 0 && (
                <g>
                  <circle cx={NODE_WIDTH - 8} cy={NODE_HEIGHT - 10} r={7} fill="var(--danger-soft)" stroke="var(--danger)" strokeWidth={1} />
                  <text
                    x={NODE_WIDTH - 8}
                    y={NODE_HEIGHT - 6.5}
                    textAnchor="middle"
                    fontSize={8.5}
                    fontWeight={700}
                    fill="var(--danger)"
                  >
                    {n.errorCount > 99 ? "99+" : n.errorCount}
                  </text>
                </g>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// ---- layout -----------------------------------------------------------

const NODE_WIDTH = 176;
const NODE_HEIGHT = 46;
const COL_GAP = 88;
const ROW_GAP = 18;
const PAD = 20;

type LaidOutNode = AgentGraphNodeInput & { x: number; y: number; depth: number };
type LaidOutEdge = { key: string; path: string; count: number; errorCount: number; labelX: number; labelY: number };
type Layout = { nodes: LaidOutNode[]; edges: LaidOutEdge[]; width: number; height: number };

function edgeKey(e: { from: string; to: string }): string {
  return `${e.from}=>${e.to}`;
}

function labelWidth(count: number): number {
  return Math.max(16, String(count).length * 7 + 8);
}

function compactCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}m`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

function truncateLabel(s: string, max: number): string {
  const t = (s || "").trim();
  if (!t) return "(unnamed)";
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

// kindColor is the span-kind pill's tone (lib/vocabs/obs.ts SPAN_KIND) as a
// raw CSS-variable string, since SVG presentation attributes here are set
// directly rather than through Tailwind classes (same pattern Sparkline.tsx
// uses for `stroke`).
function kindColor(kind: string): string {
  return TONE_COLOR[vocabTone(SPAN_KIND, kind)];
}

// computeLayout assigns every node a column (BFS depth from root nodes, or
// from indegree-0 nodes when no node is flagged isRoot) and a row within that
// column, then builds the deterministic node/edge geometry the SVG renders.
// Cycles cannot hang the BFS: every node gets a depth exactly once, and any
// edge whose target's depth is <= its source's depth is treated as a back
// edge and drawn as a curved loop rather than a straight forward connector.
function computeLayout(nodes: AgentGraphNodeInput[], edges: AgentGraphEdgeInput[]): Layout {
  const ids = nodes.map((n) => n.id);
  const idSet = new Set(ids);
  const validEdges = edges.filter((e) => idSet.has(e.from) && idSet.has(e.to));

  const outgoing = new Map<string, AgentGraphEdgeInput[]>();
  const incomingCount = new Map<string, number>();
  for (const id of ids) {
    outgoing.set(id, []);
    incomingCount.set(id, 0);
  }
  for (const e of validEdges) {
    outgoing.get(e.from)!.push(e);
    incomingCount.set(e.to, (incomingCount.get(e.to) ?? 0) + 1);
  }

  const depth = new Map<string, number>();
  const queue: string[] = [];
  const seed = (id: string, d: number) => {
    if (!depth.has(id)) {
      depth.set(id, d);
      queue.push(id);
    }
  };
  for (const n of nodes) if (n.isRoot) seed(n.id, 0);
  for (const n of nodes) if ((incomingCount.get(n.id) ?? 0) === 0) seed(n.id, 0);

  let qi = 0;
  // Outer loop handles disconnected components / pure cycles: after draining
  // the queue, seed any still-unreached node (preferring one with a visited
  // predecessor, so its depth follows that predecessor) and keep going. Each
  // pass seeds at least one node, so this always terminates.
  for (;;) {
    while (qi < queue.length) {
      const cur = queue[qi++];
      const d = depth.get(cur)!;
      for (const e of outgoing.get(cur) ?? []) {
        if (!depth.has(e.to)) seed(e.to, d + 1);
      }
    }
    const remaining = nodes.filter((n) => !depth.has(n.id));
    if (remaining.length === 0) break;
    const withVisitedParent = remaining.find((n) => validEdges.some((e) => e.to === n.id && depth.has(e.from)));
    if (withVisitedParent) {
      const parentEdge = validEdges.find((e) => e.to === withVisitedParent.id && depth.has(e.from))!;
      seed(withVisitedParent.id, depth.get(parentEdge.from)! + 1);
    } else {
      seed(remaining[0].id, 0);
    }
  }

  const maxDepth = Math.max(0, ...Array.from(depth.values()));
  const columns: string[][] = Array.from({ length: maxDepth + 1 }, () => []);
  for (const n of nodes) columns[depth.get(n.id) ?? 0].push(n.id);
  // Deterministic within-column order: busiest step first.
  const byId = new Map(nodes.map((n) => [n.id, n]));
  for (const col of columns) {
    col.sort((a, b) => byId.get(b)!.count - byId.get(a)!.count || a.localeCompare(b));
  }

  const colHeights = columns.map((col) => col.length * NODE_HEIGHT + Math.max(0, col.length - 1) * ROW_GAP);
  const maxColHeight = Math.max(0, ...colHeights);

  const positioned: LaidOutNode[] = [];
  const posById = new Map<string, { x: number; y: number }>();
  columns.forEach((col, d) => {
    const colHeight = colHeights[d];
    const top = PAD + (maxColHeight - colHeight) / 2;
    const x = PAD + d * (NODE_WIDTH + COL_GAP);
    col.forEach((id, i) => {
      const y = top + i * (NODE_HEIGHT + ROW_GAP);
      posById.set(id, { x, y: y + NODE_HEIGHT / 2 });
      const n = byId.get(id)!;
      positioned.push({ ...n, x, y, depth: d });
    });
  });

  const laidOutEdges: LaidOutEdge[] = validEdges.map((e, i) => {
    const from = posById.get(e.from)!;
    const to = posById.get(e.to)!;
    const isSelf = e.from === e.to;
    const isBack = !isSelf && (depth.get(e.to) ?? 0) <= (depth.get(e.from) ?? 0);
    const fromRight = from.x + NODE_WIDTH;
    const toLeft = to.x;

    let path: string;
    let labelX: number;
    let labelY: number;
    if (isSelf) {
      const cx = from.x + NODE_WIDTH;
      const cy = from.y;
      path = `M ${cx} ${cy - 8} C ${cx + 34} ${cy - 26}, ${cx + 34} ${cy + 26}, ${cx} ${cy + 8}`;
      labelX = cx + 30;
      labelY = cy;
    } else if (isBack) {
      const loopY = Math.max(from.y, to.y) + NODE_HEIGHT / 2 + 34;
      const x1 = fromRight - NODE_WIDTH / 2;
      const x2 = toLeft + NODE_WIDTH / 2;
      path = `M ${x1} ${from.y + NODE_HEIGHT / 2} C ${x1} ${loopY}, ${x2} ${loopY}, ${x2} ${to.y + NODE_HEIGHT / 2}`;
      labelX = (x1 + x2) / 2;
      labelY = loopY;
    } else {
      const y1 = from.y + NODE_HEIGHT / 2;
      const y2 = to.y + NODE_HEIGHT / 2;
      const dx = Math.max(30, (toLeft - fromRight) / 2);
      path = `M ${fromRight} ${y1} C ${fromRight + dx} ${y1}, ${toLeft - dx} ${y2}, ${toLeft} ${y2}`;
      labelX = (fromRight + toLeft) / 2;
      labelY = (y1 + y2) / 2 - 6;
    }
    return { key: `${edgeKey(e)}#${i}`, path, count: e.count, errorCount: e.errorCount, labelX, labelY };
  });

  const width = PAD * 2 + (maxDepth + 1) * NODE_WIDTH + maxDepth * COL_GAP + 40;
  const height = Math.max(PAD * 2 + maxColHeight, NODE_HEIGHT + PAD * 2) + 40;

  return { nodes: positioned, edges: laidOutEdges, width, height };
}
