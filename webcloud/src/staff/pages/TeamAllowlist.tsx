// Team allow-list (staff console e2e finding SC-7; routes
// internal/cloudserver/api/portal_teamallowlist.go). While team creation is
// invitation-only, only an account on this list (by account id, or by the
// domain of its verified email) can create a team org; a personal org is
// never checked. Support reads the list; ops and admin add and remove
// entries through ChangeDialog. A removal keeps the row, stamped removed
// ("Show removed").

import { useState } from "react";
import { ListChecks, Plus, Trash2 } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Callout } from "@shared/primitives/Callout";
import { Card } from "@shared/primitives/Card";
import { EmptyState } from "@shared/primitives/EmptyState";
import { ErrorState } from "@shared/primitives/ErrorState";
import { PageHeader } from "@shared/primitives/PageHeader";
import { Pill } from "@shared/primitives/Pill";
import { RowActions } from "@shared/primitives/RowActions";
import { TableSkeleton } from "@shared/primitives/Skeleton";
import { Table } from "@shared/primitives/Table";
import { Toggle } from "@shared/primitives/Toggle";
import { listTeamAllowlist, type AllowlistEntry } from "../api";
import { AddAllowlistDialog, RemoveAllowlistDialog, refreshAllowlist } from "../components/AllowlistDialogs";
import { allowlistSummary, isActive, kindLabel } from "../lib/allowlist";
import { actorLabel, formatTime } from "../lib/model";
import { staffKeys, useStaff, useStaffQuery } from "../session";

export function TeamAllowlist() {
  const staff = useStaff();
  const on = staff.feature("team_allowlist");
  const [showRemoved, setShowRemoved] = useState(false);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<AllowlistEntry | null>(null);
  const q = useStaffQuery(on ? staffKeys.teamAllowlist(showRemoved) : null, () => listTeamAllowlist(showRemoved), [showRemoved]);
  const canWrite = staff.may("team_allowlist.write");
  const entries = q.data?.entries ?? [];
  const done = () => {
    setAdding(false);
    setRemoving(null);
    refreshAllowlist();
  };

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="Team allow-list"
        icon={ListChecks}
        sub="Who may create a team org while team creation is invitation-only. Personal orgs are never checked."
      />
      {!on ? (
        <EmptyState variant="inline" title="The team allow-list is not available on this console" body="Its route is not mounted on this staff server." />
      ) : (
        <>
          {!canWrite && (
            <Callout tone="info" title="Read only">
              Your role ({staff.me.role}) can read the list. ops and admin change it.
            </Callout>
          )}
          <Card
            title="Entries"
            sub={q.data ? allowlistSummary(entries) : undefined}
            actions={
              <span className="flex flex-wrap items-center gap-3">
                <Toggle on={showRemoved} onChange={setShowRemoved} label="Show removed" />
                {canWrite && (
                  <Button size="sm" variant="secondary" iconLeft={Plus} onClick={() => setAdding(true)}>
                    Add
                  </Button>
                )}
              </span>
            }
          >
            {q.error && !q.data ? (
              <ErrorState variant="inline" title="Could not load the allow-list" error={q.error} onRetry={q.reload} />
            ) : !q.data ? (
              <TableSkeleton />
            ) : entries.length === 0 ? (
              <EmptyState
                variant="inline"
                title="No one is on the allow-list"
                body={
                  canWrite
                    ? "Add an email domain or an account to let it create a team org."
                    : "ops or admin add an email domain or an account to let it create a team org."
                }
              >
                {canWrite && (
                  <Button size="sm" variant="primary" iconLeft={Plus} onClick={() => setAdding(true)}>
                    Add an entry
                  </Button>
                )}
              </EmptyState>
            ) : (
              <AllowlistTable entries={entries} showRemoved={showRemoved} canWrite={canWrite} self={staff.me.staff_id} onRemove={setRemoving} />
            )}
          </Card>
          <p className="text-[11.5px] text-fg-3">
            A person refused a team org reads their account reference: add it as an account entry, or add their company&apos;s email domain.
          </p>
        </>
      )}
      {adding && <AddAllowlistDialog open entries={entries} onClose={() => setAdding(false)} onDone={done} />}
      {removing && <RemoveAllowlistDialog entry={removing} onClose={() => setRemoving(null)} onDone={done} />}
    </div>
  );
}

/** AllowlistTable lists the entries (rendered by tests). */
export function AllowlistTable(p: {
  entries: AllowlistEntry[];
  showRemoved: boolean;
  canWrite: boolean;
  self?: string;
  onRemove: (e: AllowlistEntry) => void;
}) {
  return (
    <Table
      padded
      minWidth={p.showRemoved ? 900 : 720}
      head={
        <tr>
          <th>Kind</th>
          <th>Value</th>
          <th>Added</th>
          <th>Reason</th>
          {p.showRemoved && <th>Removed</th>}
          {p.canWrite && <th />}
        </tr>
      }
    >
      {p.entries.map((e) => {
        const active = isActive(e);
        return (
          <tr key={e.entry_id} className={active ? undefined : "text-fg-3"}>
            <td className="whitespace-nowrap">{kindLabel(e.kind)}</td>
            <td>
              <span className={active ? "break-all font-mono text-[11px] text-fg-1" : "break-all font-mono text-[11px]"}>{e.value}</span>
              {!active && (
                <span className="ml-2">
                  <Pill variant="neutral">removed</Pill>
                </span>
              )}
            </td>
            <td className="whitespace-nowrap">
              <div>{actorLabel(e.added_by, p.self)}</div>
              <div className="text-fg-3">{formatTime(e.added_at)}</div>
            </td>
            <td className="max-w-[280px] whitespace-pre-wrap text-fg-2">{e.added_reason}</td>
            {p.showRemoved && (
              <td className="max-w-[280px]">
                {active ? (
                  "-"
                ) : (
                  <>
                    <div className="whitespace-nowrap">
                      {actorLabel(e.removed_by ?? "", p.self)}, {formatTime(e.removed_at)}
                    </div>
                    {e.removed_reason && <div className="whitespace-pre-wrap text-fg-3">{e.removed_reason}</div>}
                  </>
                )}
              </td>
            )}
            {p.canWrite && (
              <td className="w-10 text-right">
                {active && (
                  <RowActions
                    menuLabel={`Actions for ${e.value}`}
                    actions={[{ id: "remove", label: "Remove", icon: Trash2, destructive: true, confirm: false, onSelect: () => p.onRemove(e) }]}
                  />
                )}
              </td>
            )}
          </tr>
        );
      })}
    </Table>
  );
}
