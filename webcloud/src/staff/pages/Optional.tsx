// OptionalScreen renders a screen whose route another lane adds (the
// team-creation allow-list from w17/portal-guardrails, the deletion queue
// from w17/deletion-purge). The console shows it only when GET
// /staff/api/features says its route is mounted, and renders the read
// generically (a table of its rows, else the JSON) until that lane's own
// screen lands here. Writes, when the lane adds them, go through ChangeDialog
// like every other staff change.

import { ListChecks } from "lucide-react";
import { EmptyState } from "@shared/primitives/EmptyState";
import { ErrorState } from "@shared/primitives/ErrorState";
import { JsonPreview } from "@shared/primitives/JsonPreview";
import { PageHeader } from "@shared/primitives/PageHeader";
import { TableSkeleton } from "@shared/primitives/Skeleton";
import { Table } from "@shared/primitives/Table";
import { getOptional } from "../api";
import { useStaff, useStaffQuery } from "../session";

/** rowsOf finds the first array of objects in a response (e.g. {entries:
 *  [...]}) and the union of their keys, for a generic table. */
export function rowsOf(data: unknown): { rows: Record<string, unknown>[]; columns: string[] } | null {
  const arrays: unknown[] = Array.isArray(data) ? [data] : data && typeof data === "object" ? Object.values(data as object) : [];
  for (const a of arrays) {
    if (Array.isArray(a) && a.every((r) => r && typeof r === "object" && !Array.isArray(r))) {
      const rows = a as Record<string, unknown>[];
      const columns = [...new Set(rows.flatMap((r) => Object.keys(r)))];
      return { rows, columns };
    }
  }
  return null;
}

function cell(v: unknown): string {
  if (v === null || v === undefined) return "-";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

export function OptionalScreen({ feature, title, path }: { feature: string; title: string; path: string }) {
  const staff = useStaff();
  const on = staff.feature(feature);
  const q = useStaffQuery(on ? `staff:optional:${path}` : null, () => getOptional(path), [path]);
  const table = rowsOf(q.data);
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title={title} icon={ListChecks} />
      {!on ? (
        <EmptyState variant="inline" title={`${title} is not available on this console yet`} body="Its route is not mounted on this staff server." />
      ) : q.error && !q.data ? (
        <ErrorState variant="inline" title={`Could not load ${title.toLowerCase()}`} error={q.error} onRetry={q.reload} />
      ) : !q.data ? (
        <TableSkeleton />
      ) : table && table.rows.length > 0 ? (
        <Table
          padded
          head={
            <tr>
              {table.columns.map((c) => (
                <th key={c}>{c}</th>
              ))}
            </tr>
          }
        >
          {table.rows.map((r, i) => (
            <tr key={i}>
              {table.columns.map((c) => (
                <td key={c} className="max-w-[320px] truncate font-mono text-[11px]">
                  {cell(r[c])}
                </td>
              ))}
            </tr>
          ))}
        </Table>
      ) : table ? (
        <EmptyState variant="inline" title="Nothing here yet" />
      ) : (
        <JsonPreview value={q.data} maxHeight={480} copy />
      )}
    </div>
  );
}
