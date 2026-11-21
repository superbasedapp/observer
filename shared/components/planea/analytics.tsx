import { useMemo, type ReactNode } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { UserRound, type LucideIcon } from "lucide-react";
import { Card } from "../../primitives/Card";
import { DataTable } from "../../primitives/DataTable";
import { ModelId } from "../../primitives/ModelId";
import { InlineEmpty as Empty } from "../../primitives/Panel";
import { Pill } from "../../primitives/Pill";
import { VocabDefPill as VocabPill } from "../../primitives/VocabDefPill";
import type { VocabDef } from "../../lib/vocabDef";
import { isUnattributed, UnattributedChip } from "../../primitives/Unattributed";
import { compact, num, pct1 } from "../../lib/displayFormat";
// Aggregate cells: a sum of priced spans, said so in the tooltip (W4-2).
import { PlaneAAggregateCost as Money } from "./costCell";

// analytics - the pure Plane A breakdown cards (B5-0, 2026-11-19): the
// per-dimension card of the Analytics page (DimCard, from
// web2/src/pages/obs/Analytics.tsx) and the per-end-user spend table
// (EndUserSpendCard, from web2/src/pages/obs/EndUsers.tsx). The org pages
// keep their fetching and render these; the node's Your apps pages render
// them over the node's /api/obs/analytics and /api/obs/end-users.

/** One dimension bucket (model, source, project, service, ...). */
export interface PlaneADimCount {
  key: string;
  traces: number;
  tokens: number;
  cost_usd: number;
}

/** One end user's spend in a window. */
export interface PlaneAEndUserBucket {
  end_user: string;
  cost_usd: number;
  traces: number;
  total_tokens: number;
  cost_share: number;
}

export function DimCard({
  title,
  icon,
  rows,
  keyHeader,
  mono,
  keyVocab,
  renderKey,
}: {
  title: string;
  icon: LucideIcon;
  rows: PlaneADimCount[];
  keyHeader: string;
  mono?: boolean;
  // keyVocab draws a closed-vocabulary key (a trace source) as its labelled
  // pill instead of the raw wire value.
  keyVocab?: VocabDef;
  // renderKey overrides the default key cell (a Pill / mono hash) - the
  // By model card passes renderModelKey so ids carry their family mark.
  renderKey?: (key: string) => ReactNode;
}) {
  const columns = useMemo<ColumnDef<PlaneADimCount, any>[]>(
    () => [
      {
        accessorKey: "key",
        header: keyHeader,
        cell: (c) => {
          if (isUnattributed(c.row.original.key)) return <UnattributedChip />;
          if (renderKey) return renderKey(c.row.original.key);
          if (keyVocab) return <VocabPill of={keyVocab} value={c.row.original.key} />;
          return mono ? (
            <span className="font-mono text-[12px] text-fg-2">{shortKey(c.row.original.key)}</span>
          ) : (
            <Pill variant="neutral">{c.row.original.key}</Pill>
          );
        },
      },
      {
        accessorKey: "traces",
        header: "Traces",
        cell: (c) => num(c.row.original.traces),
        meta: { align: "right" },
      },
      {
        accessorKey: "tokens",
        header: "Tokens",
        cell: (c) => compact(c.row.original.tokens),
        meta: { align: "right" },
      },
      {
        accessorKey: "cost_usd",
        header: "Cost",
        cell: (c) => <Money usd={c.row.original.cost_usd} tokens={c.row.original.tokens} />,
        meta: { align: "right", mono: true },
      },
    ],
    [keyHeader, mono, keyVocab, renderKey],
  );

  return (
    <Card icon={icon} title={title} className="min-w-0">
      {rows.length === 0 ? (
        <Empty icon={icon} message={`No ${keyHeader.toLowerCase()} data.`} />
      ) : (
        <DataTable
          data={rows}
          columns={columns}
          rowKey={(r) => r.key}
          initialSort={[{ id: "tokens", desc: true }]}
          zebra
          minWidth={420}
        />
      )}
    </Card>
  );
}

// renderModelKey renders a model-id dimension key with its family mark.
export function renderModelKey(key: string): ReactNode {
  return <ModelId model={key} className="max-w-[240px] text-[12px]" />;
}

// shortKey trims a project_hash to a readable prefix (it is a 64-char sha256).
function shortKey(k: string): string {
  if (k === "(none)") return k;
  return k.length > 14 ? k.slice(0, 14) + "…" : k;
}

// EndUserSpendCard: per-end-user spend, biggest first.
export function EndUserSpendCard({ rows, icon = UserRound }: { rows: PlaneAEndUserBucket[]; icon?: LucideIcon }) {
  const columns = useMemo<ColumnDef<PlaneAEndUserBucket, any>[]>(
    () => [
      {
        accessorKey: "end_user",
        header: "End user",
        cell: (c) => <span className="text-fg-1">{c.row.original.end_user}</span>,
      },
      {
        accessorKey: "cost_usd",
        header: "Cost",
        cell: (c) => (
          <Money usd={c.row.original.cost_usd} tokens={c.row.original.total_tokens} />
        ),
        meta: { align: "right", mono: true },
      },
      { accessorKey: "cost_share", header: "Share", cell: (c) => pct1(c.row.original.cost_share), meta: { align: "right" } },
      { accessorKey: "total_tokens", header: "Tokens", cell: (c) => compact(c.row.original.total_tokens), meta: { align: "right" } },
      { accessorKey: "traces", header: "Traces", cell: (c) => num(c.row.original.traces), meta: { align: "right" } },
    ],
    [],
  );
  return (
    <Card icon={icon} title="By end user" className="min-w-0">
      {rows.length === 0 ? (
        <Empty icon={icon} message="No end-user spend in this window." />
      ) : (
        <DataTable
          data={rows}
          columns={columns}
          rowKey={(r) => r.end_user}
          initialSort={[{ id: "cost_usd", desc: true }]}
          zebra
          minWidth={460}
        />
      )}
    </Card>
  );
}
