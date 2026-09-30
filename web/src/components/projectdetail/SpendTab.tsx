import { useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { IdLink, ModelId, SegmentedControl, Table, Tooltip } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { describeTruncation, TruncationBanner } from "@/components/projectdetail/TruncationBanner";
import { useApi } from "@/lib/useApi";
import { fmtInt, fmtShortId, fmtUSD } from "@/lib/format";
import type { ProjectCostBy, ProjectCostRowsResponse } from "@/lib/types";
import { CodeCommentSplit } from "@shared/primitives/CodeCommentSplit";

// SpendTab — cost by session / tool / model / day / task / commit, one
// SegmentedControl driving GET /api/project/<id>/cost?by= (plan §3.5
// SpendTab). The `/cost` rows are a plain {key,label,cost_usd,turns?,count?}
// shape regardless of grouping, so one table renders all six — no chart
// fits the frozen wire contract (CostAreaChart wants a bucket/input/output/
// cache-read/cache-write CostPoint, not a bare day+cost_usd pair), so this
// stays a table across every grouping rather than mixing a chart for `day`
// with a table for everything else.

const BY_OPTIONS: { value: ProjectCostBy; label: string }[] = [
  { value: "session", label: "Session" },
  { value: "tool", label: "Tool" },
  { value: "model", label: "Model" },
  { value: "day", label: "Day" },
  { value: "task", label: "Task" },
  { value: "commit", label: "Commit" },
];

// Non-session key cell per grouping, table-driven: a MODEL key renders
// through ModelId (family mark + id); every other grouping keeps plain mono
// text. (Session keys keep their IdLink branch below.)
const KEY_CELL_BY: Partial<Record<ProjectCostBy, (key: string) => ReactNode>> = {
  model: (key) => <ModelId model={key} className="min-w-0 text-[11px]" />,
};

export function SpendTab({ projectId, days }: { projectId: number; days: number }) {
  const [by, setBy] = useState<ProjectCostBy>("session");
  const navigate = useNavigate();

  const cost = useApi<ProjectCostRowsResponse>(
    `/api/project/${projectId}/cost`,
    { by, days },
    [projectId, by, days],
  );
  const rows = cost.data?.rows ?? [];
  const total = rows.reduce((a, r) => a + r.cost_usd, 0);
  const truncationNote = describeTruncation(cost.data, `spend by ${by}`);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <SegmentedControl options={BY_OPTIONS} value={by} onChange={setBy} size="sm" />
        <span className="font-mono text-[11px] text-fg-3">
          {fmtInt(rows.length)} rows · <span className="text-fg-1">{fmtUSD(total)}</span>
        </span>
      </div>

      {truncationNote && <TruncationBanner>{truncationNote}</TruncationBanner>}

      <ChartState
        loading={cost.loading && !cost.data}
        error={cost.error}
        denied={cost.denied}
        deniedPermission={cost.deniedPermission}
        empty={!cost.loading && rows.length === 0}
        emptyHint={`No spend by ${by} in this window.`}
        height={200}
      >
        <Table
          head={
            <tr>
              <th className="py-1.5 pl-1 font-medium">{by === "session" ? "Session" : "Key"}</th>
              <th className="py-1.5 text-right font-medium">Cost</th>
              <th className="py-1.5 text-right font-medium">Turns</th>
              <th className="py-1.5 pr-1 text-right font-medium">Count</th>
            </tr>
          }
        >
          {rows.map((r) => (
            <tr key={r.key} className="border-b border-line-1 last:border-0">
              <td className="py-1.5 pl-1">
                {by === "session" ? (
                  <>
                    <IdLink onClick={() => navigate(`/sessions?session=${encodeURIComponent(r.key)}`)}>
                      {fmtShortId(r.key, 10)}
                    </IdLink>
                    {r.label && <span className="ml-2 font-mono text-[10.5px] text-fg-3">{r.label}</span>}
                    {/* AI code-vs-comment split of this session's edits (by=session rows only). */}
                    {r.ai_split && (
                      <div className="mt-0.5">
                        <CodeCommentSplit split={r.ai_split} compact />
                      </div>
                    )}
                  </>
                ) : KEY_CELL_BY[by] ? (
                  KEY_CELL_BY[by]!(r.key)
                ) : (
                  <span className="font-mono text-[11px] text-fg-1">{r.label || r.key}</span>
                )}
              </td>
              <td className="py-1.5 text-right tabular-nums text-fg-1">
                <Tooltip content={r.unpriced_turns ? `${fmtInt(r.unpriced_turns)} unpriced turn(s) in this bucket (unknown model) - the cost is a floor, not an exact figure` : undefined}>
                  <span tabIndex={r.unpriced_turns ? 0 : undefined} className="focus:outline-none">
                    {fmtUSD(r.cost_usd)}
                    {r.unpriced_turns ? <span className="ml-0.5 text-warn">*</span> : null}
                  </span>
                </Tooltip>
              </td>
              <td className="py-1.5 text-right tabular-nums text-fg-3">
                {r.turns != null ? fmtInt(r.turns) : "-"}
              </td>
              <td className="py-1.5 pr-1 text-right tabular-nums text-fg-3">
                {r.count != null ? fmtInt(r.count) : "-"}
              </td>
            </tr>
          ))}
        </Table>
      </ChartState>
    </div>
  );
}
