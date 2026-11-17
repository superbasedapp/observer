// Orgs: every org on the platform (GET /staff/api/orgs, cloud 0133): registry
// fields, members count, where its plan comes from, the latest usage day and
// the issued entitlements document's version. Registry and control-plane
// facts only; no tenant data. A row opens the org.

import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Building2 } from "lucide-react";
import { EmptyState } from "@shared/primitives/EmptyState";
import { ErrorState } from "@shared/primitives/ErrorState";
import { Input } from "@shared/primitives/Input";
import { PageHeader } from "@shared/primitives/PageHeader";
import { Pill } from "@shared/primitives/Pill";
import { Select } from "@shared/primitives/Select";
import { TableSkeleton } from "@shared/primitives/Skeleton";
import { Table } from "@shared/primitives/Table";
import { listOrgs, type StaffOrg } from "../api";
import { formatTime, matchesOrgQuery, orgStatusTone, planSummary } from "../lib/model";
import { useStaffQuery } from "../session";

const STATUSES = ["all", "provisioning", "active", "suspended", "pending_deletion", "purging", "purged"];

export function Orgs() {
  const q = useStaffQuery("staff:orgs", listOrgs);
  const [text, setText] = useState("");
  const [status, setStatus] = useState("all");
  const [kind, setKind] = useState("all");
  const orgs = useMemo(
    () => (q.data?.orgs ?? []).filter((o) => matchesOrgQuery(o, text) && (status === "all" || o.status === status) && (kind === "all" || o.kind === kind)),
    [q.data, text, status, kind],
  );
  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Orgs" icon={Building2} sub="Every org on the platform: registry, plan source, usage and the issued entitlements. No tenant data." />
      <div className="flex flex-wrap items-end gap-3">
        <Input label="Search" placeholder="Name, slug, id or host" value={text} onChange={(e) => setText(e.target.value)} className="w-64" />
        <Select label="Status" value={status} onChange={(e) => setStatus(e.target.value)} options={STATUSES} />
        <Select label="Kind" value={kind} onChange={(e) => setKind(e.target.value)} options={["all", "team", "personal"]} />
        {q.data && (
          <span className="pb-2 text-[11.5px] text-fg-3">
            {orgs.length} of {q.data.orgs.length}
          </span>
        )}
      </div>
      {q.error && !q.data ? (
        <ErrorState variant="inline" title="Could not load the orgs" error={q.error} onRetry={q.reload} />
      ) : !q.data ? (
        <TableSkeleton />
      ) : orgs.length === 0 ? (
        <EmptyState variant="inline" title={q.data.orgs.length === 0 ? "No orgs yet" : "No org matches"} />
      ) : (
        <OrgTable orgs={orgs} />
      )}
    </div>
  );
}

export function OrgTable({ orgs, now = new Date() }: { orgs: StaffOrg[]; now?: Date }) {
  const navigate = useNavigate();
  return (
    <Table
      padded
      minWidth={900}
      head={
        <tr>
          <th>Org</th>
          <th>Kind</th>
          <th>Status</th>
          <th className="text-right">Members</th>
          <th>Plan</th>
          <th>Latest usage</th>
          <th>Entitlements</th>
          <th>Created</th>
        </tr>
      }
    >
      {orgs.map((o) => {
        const plan = planSummary(o, now);
        return (
          <tr key={o.org_id} className="cursor-pointer hover:bg-bg-2" onClick={() => navigate(`/orgs/${o.org_id}`)}>
            <td>
              <Link to={`/orgs/${o.org_id}`} className="font-medium text-fg-1 hover:underline" onClick={(e) => e.stopPropagation()}>
                {o.display_name}
              </Link>
              <div className="font-mono text-[10.5px] text-fg-3">{o.slug}</div>
            </td>
            <td>{o.kind}</td>
            <td>
              <Pill variant={orgStatusTone(o.status)}>{o.status.replace("_", " ")}</Pill>
            </td>
            <td className="text-right tabular-nums">{o.members}</td>
            <td>
              <Pill variant={plan.tone} case="none">
                {plan.label}
              </Pill>
              <div className="text-[10.5px] text-fg-3">{plan.source}</div>
            </td>
            <td className="tabular-nums">{o.usage ? `${o.usage.seats} seats, ${o.usage.day}` : "-"}</td>
            <td className="tabular-nums">{o.entitlements ? `v${o.entitlements.version}` : "none issued"}</td>
            <td className="whitespace-nowrap text-fg-3">{formatTime(o.created_at)}</td>
          </tr>
        );
      })}
    </Table>
  );
}
