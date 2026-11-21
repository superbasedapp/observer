import { useState } from "react";
import { Button } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import type { PlanUsageView } from "@/lib/plans";
import { usageBlock } from "@/lib/plansView";

// UsageByDay: an account's daily usage reconciliation on its card (the Codex
// app-server account today). Per UTC day: the vendor's account-wide total,
// what this machine captured, and what it did not ("not captured here",
// never "cloud usage"). Tokens only. It renders nothing until a reading has
// stored a daily total, so a card without one looks exactly as before. The
// wording lives in lib/plansView.ts (usageBlock), covered by its tests.

/** Rows shown before "Show all". */
const FIRST_ROWS = 7;

export function UsageByDay({ accountId }: { accountId: string }) {
  const res = useApi<PlanUsageView>(`/api/plans/accounts/${encodeURIComponent(accountId)}/usage`, { days: 30 });
  const [all, setAll] = useState(false);
  const b = usageBlock(res.data);
  if (!b) return null;
  const rows = all ? b.rows : b.rows.slice(0, FIRST_ROWS);
  return (
    <div className="min-w-0 space-y-2 border-t border-line-1 pt-3">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
        <h4 className="text-[12px] font-medium text-fg-1">{b.title}</h4>
        <span className="text-[11px] text-fg-3">{b.window}</span>
      </div>
      <dl className="grid grid-cols-3 gap-2">
        {b.totals.map((t) => (
          <div key={t.label} className="min-w-0">
            <dt className="text-[11px] leading-tight text-fg-3">{t.label}</dt>
            <dd className="text-[14px] font-semibold tabular-nums text-fg-0">{t.value}</dd>
          </div>
        ))}
      </dl>
      {b.empty ? (
        <p className="text-[12px] text-fg-2">{b.empty}</p>
      ) : (
        <table className="w-full table-fixed text-[11.5px] tabular-nums">
          <caption className="sr-only">{b.title}</caption>
          <thead>
            <tr className="text-fg-3">
              <th scope="col" className="w-[22%] py-1 text-left font-normal">Day</th>
              <th scope="col" className="py-1 text-right font-normal">{b.totals[0].label}</th>
              <th scope="col" className="py-1 text-right font-normal">Captured</th>
              <th scope="col" className="py-1 text-right font-normal">Not captured</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line-1">
            {rows.map((r) => (
              <tr key={r.day} title={r.share || undefined}>
                <th scope="row" className="py-1 text-left font-normal text-fg-2">{r.label}</th>
                <td className="py-1 text-right text-fg-1">{r.vendor}</td>
                <td className="py-1 text-right text-fg-1">{r.captured}</td>
                <td className="py-1 text-right text-fg-1">{r.uncaptured}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {b.rows.length > FIRST_ROWS && (
        <Button variant="ghost" size="sm" onClick={() => setAll((v) => !v)}>
          {all ? "Show fewer days" : `Show all ${b.rows.length} days`}
        </Button>
      )}
      <div className="space-y-0.5 text-[11px] text-fg-3">
        {b.notes.map((n) => (
          <p key={n}>{n}</p>
        ))}
      </div>
    </div>
  );
}
