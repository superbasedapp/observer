// OrgDetail: one org (GET /staff/api/orgs/{id}, cloud 0133) - its registry
// row, where its plan comes from and the entitlements document in force, the
// plan grant history (with the operator's command to change it), its
// org_controls kill switches (editable by ops and admin), usage, lifecycle
// intents, deletion state, and the staff log rows about it. With the
// per-org component routes on, its component switches (Code security); with
// the issue route on, the changes not issued yet and this org's host's
// delivery (a switch reaches the host only once the envelope is issued).

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Building2, Pencil, Plus, Trash2 } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Callout } from "@shared/primitives/Callout";
import { Card } from "@shared/primitives/Card";
import { CopyOnClick } from "@shared/primitives/CopyOnClick";
import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { ErrorState } from "@shared/primitives/ErrorState";
import { JsonPreview } from "@shared/primitives/JsonPreview";
import { PageHeader } from "@shared/primitives/PageHeader";
import { Pill } from "@shared/primitives/Pill";
import { TableSkeleton } from "@shared/primitives/Skeleton";
import { Table } from "@shared/primitives/Table";
import { getOrg, listAvailability, listLog, postPlanGrant, type StaffOrgDetail } from "../api";
import { gatewayCell, gatewayMonthToDate, hasGatewayUsage, monthOf, type GatewayUsageDay } from "../lib/gatewayUsage";
import { ChangeDialog } from "../components/ChangeDialog";
import { GrantCommand } from "../components/GrantCommand";
import { InputEditorDialog, RemoveInputDialog } from "../components/InputEditor";
import { IssueCard } from "../components/IssueCard";
import { LogTable } from "../components/LogTable";
import { OrgComponentsCards } from "../components/OrgComponents";
import { PLATFORM_KEY, describeOrgControl, orgControlTone } from "../lib/envelope";
import { actorLabel, formatTime, grantInForce, isDeletionStatus, orgStatusTone, planSummary, relativeTime, subscriptionTone } from "../lib/model";
import { invalidateStaff, staffKeys, useStaff, useStaffQuery } from "../session";

export function OrgDetail() {
  const { id = "" } = useParams();
  const q = useStaffQuery(`staff:org:${id}`, () => getOrg(id), [id]);
  if (q.error && !q.data) {
    return (
      <div className="flex flex-col gap-4">
        <BackLink />
        <ErrorState variant="inline" title="Could not load the org" error={q.error} onRetry={q.reload} />
      </div>
    );
  }
  if (!q.data) return <TableSkeleton />;
  return <OrgDetailView d={q.data} reload={q.reload} />;
}

function BackLink() {
  return (
    <Link to="/orgs" className="inline-flex items-center gap-1 text-[12px] text-fg-3 hover:text-fg-1">
      <ArrowLeft size={13} aria-hidden="true" /> All orgs
    </Link>
  );
}

export function OrgDetailView({ d, reload, now = new Date() }: { d: StaffOrgDetail; reload: () => void; now?: Date }) {
  const staff = useStaff();
  const o = d.org;
  const plan = planSummary(o, now);
  const components = staff.feature("org_components");
  const issuable = staff.feature("availability_issue");
  return (
    <div className="flex flex-col gap-5">
      <BackLink />
      <PageHeader
        title={o.display_name}
        icon={Building2}
        sub={
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-mono">{o.slug}</span>
            <Pill variant={orgStatusTone(o.status)}>{o.status.replace("_", " ")}</Pill>
            <Pill variant="neutral">{o.kind}</Pill>
            <Pill variant={plan.tone} case="none">
              {plan.label}
            </Pill>
          </span>
        }
      />
      {(d.deletion || isDeletionStatus(o.status)) && <DeletionCard d={d} />}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card title="Registry" sub="The control plane's row for this org.">
          <DefinitionList>
            <DefinitionRow
              label="Org id"
              value={
                <CopyOnClick value={o.org_id}>
                  <span className="font-mono text-[11px]">{o.org_id}</span>
                </CopyOnClick>
              }
            />
            <DefinitionRow label="Kind" value={o.kind} />
            <DefinitionRow label="Tenancy" value={o.tenancy} />
            <DefinitionRow label="Status" value={o.status} />
            <DefinitionRow label="Host" value={o.host_id || "not placed"} />
            <DefinitionRow label="Platform sign-in rail" value={o.platform_rail_enabled ? "on" : "off"} />
            <DefinitionRow label="Lifecycle generation" value={o.lifecycle_gen} />
            <DefinitionRow label="Members" value={o.members} />
            <DefinitionRow label="Created" value={formatTime(o.created_at)} />
            <DefinitionRow label="Updated" value={formatTime(o.updated_at)} />
          </DefinitionList>
        </Card>
        <PlanCard d={d} now={now} />
      </div>
      <GrantsCard d={d} now={now} reload={reload} />
      {components ? (
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
          <OrgControlsCard orgId={o.org_id} />
          <OrgComponentsCards orgId={o.org_id} orgName={o.display_name} />
        </div>
      ) : (
        <OrgControlsCard orgId={o.org_id} />
      )}
      {issuable && <IssueCard orgId={o.org_id} hostId={o.host_id || null} names={new Map([[o.org_id, o.display_name]])} />}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <UsageCard d={d} />
        <IntentsCard d={d} now={now} />
      </div>
      <OrgLogCard orgId={o.org_id} />
    </div>
  );
}

function PlanCard({ d, now }: { d: StaffOrgDetail; now: Date }) {
  const o = d.org;
  const plan = planSummary(o, now);
  const body = (d.entitlements?.body ?? null) as {
    plan?: { name?: string; version?: number; label?: string };
    caps?: Record<string, number>;
    capabilities?: string[];
    not_after?: number;
  } | null;
  return (
    <Card title="Plan and entitlements" sub="Where the plan comes from, and the signed document hosts enforce.">
      <DefinitionList>
        <DefinitionRow label="Plan" value={plan.label} />
        <DefinitionRow label="Source" value={plan.source} />
        <DefinitionRow
          label="Subscription"
          value={
            o.subscription ? (
              <Pill variant={subscriptionTone(o.subscription.status)}>
                {o.subscription.status}
                {o.subscription.plan_name ? ` · ${o.subscription.plan_name}` : ""}
              </Pill>
            ) : (
              "none"
            )
          }
        />
        <DefinitionRow
          label="Operator grant"
          value={grantInForce(o.grant, now) ? `${o.grant?.plan_name} v${o.grant?.plan_version}` : o.grant ? `none (last: ${o.grant.action})` : "none"}
        />
        <DefinitionRow
          label="Issued document"
          value={d.entitlements ? `v${d.entitlements.version}, ${relativeTime(d.entitlements.issued_at, now)} by ${d.entitlements.issued_by}` : "none issued"}
        />
        {body?.plan && <DefinitionRow label="Document plan" value={`${body.plan.label ?? body.plan.name} (${body.plan.name} v${body.plan.version})`} />}
        {body?.not_after ? <DefinitionRow label="Document ends" value={formatTime(new Date(body.not_after * 1000).toISOString())} /> : null}
      </DefinitionList>
      {body?.caps && Object.keys(body.caps).length > 0 && (
        <div className="mt-3">
          <span className="text-[11.5px] font-medium text-fg-2">Caps in force</span>
          <DefinitionList>
            {Object.entries(body.caps)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([k, v]) => (
                <DefinitionRow key={k} label={<span className="font-mono text-[11px]">{k}</span>} value={v.toLocaleString()} />
              ))}
          </DefinitionList>
        </div>
      )}
      {body?.capabilities && body.capabilities.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1">
          {body.capabilities.map((c) => (
            <Pill key={c} variant="info" case="none">
              {c}
            </Pill>
          ))}
        </div>
      )}
      {d.entitlements && (
        <div className="mt-3">
          <JsonPreview label="Signed body" value={d.entitlements.body ?? `${d.entitlements.body_bytes} bytes (not JSON)`} maxHeight={200} copy />
        </div>
      )}
    </Card>
  );
}

function GrantsCard({ d, now, reload }: { d: StaffOrgDetail; now: Date; reload: () => void }) {
  const staff = useStaff();
  const [prepare, setPrepare] = useState(false);
  const [writing, setWriting] = useState<null | "grant" | "revoke">(null);
  const [plan, setPlan] = useState(d.org.kind === "team" ? "team" : "");
  const writable = staff.feature("plan_grant_write");
  return (
    <Card
      title="Plan grants"
      sub="Operator grants of a catalog plan to this org (cloud 0095). Append-only; the newest row decides; a live subscription still wins."
      actions={
        writable ? (
          <span className="flex gap-2">
            <Button size="sm" variant="secondary" iconLeft={Plus} onClick={() => setWriting("grant")}>
              Grant
            </Button>
            {grantInForce(d.org.grant, now) && (
              <Button size="sm" variant="ghost" iconLeft={Trash2} onClick={() => setWriting("revoke")}>
                Revoke
              </Button>
            )}
          </span>
        ) : (
          <Button size="sm" variant="secondary" onClick={() => setPrepare(!prepare)}>
            {prepare ? "Hide command" : "Prepare a grant command"}
          </Button>
        )
      }
    >
      {!writable && prepare && (
        <div className="mb-4">
          <Callout tone="info" title="Operator-only">
            Plan grants are written by the operator's CLI, not by the console (W15-D13). Prepare the command here; the row it writes appears below.
          </Callout>
          <div className="mt-3">
            <GrantCommand orgId={d.org.org_id} kind={d.org.kind} />
          </div>
        </div>
      )}
      {d.grants.length === 0 ? (
        <p className="text-[12px] text-fg-3">No plan grant has ever been written for this org.</p>
      ) : (
        <Table
          padded
          minWidth={700}
          head={
            <tr>
              <th>When</th>
              <th>Action</th>
              <th>Plan</th>
              <th>Ends</th>
              <th>By</th>
              <th>Reason</th>
            </tr>
          }
        >
          {d.grants.map((g) => (
            <tr key={g.seq}>
              <td className="whitespace-nowrap text-fg-3">{formatTime(g.at)}</td>
              <td>
                <Pill variant={g.action === "grant" ? "accent" : "neutral"}>{g.action}</Pill>
              </td>
              <td>{g.plan_name ? `${g.plan_name} v${g.plan_version}` : "-"}</td>
              <td className="whitespace-nowrap">{g.action === "grant" ? (g.effective_until ? formatTime(g.effective_until) : "no end") : "-"}</td>
              <td>{actorLabel(g.actor, staff.me.staff_id)}</td>
              <td className="max-w-[320px] whitespace-pre-wrap text-fg-2">{g.reason}</td>
            </tr>
          ))}
        </Table>
      )}
      {writing && (
        <ChangeDialog
          open
          title={writing === "grant" ? "Grant a plan" : "Revoke the plan grant"}
          destructive={writing === "revoke"}
          summary={
            writing === "grant" ? (
              <label className="flex flex-col gap-1 text-[12px]">
                Catalog plan of kind {d.org.kind}
                <input className="rounded-md border border-line-2 bg-bg-2 px-2 py-1 font-mono" value={plan} onChange={(e) => setPlan(e.target.value)} />
              </label>
            ) : (
              <span>End the operator grant in force. The org falls back to its subscription, launch window or floor at the next issuer pass.</span>
            )
          }
          blocking={writing === "grant" && !/^[a-z][a-z0-9_]{0,63}$/.test(plan.trim()) ? ["Name a catalog plan, e.g. team."] : []}
          confirmLabel={writing === "grant" ? "Grant" : "Revoke"}
          run={(reason) =>
            postPlanGrant(d.org.org_id, writing === "grant" ? { action: "grant", plan: plan.trim(), reason } : { action: "revoke", reason }).then(
              () => undefined,
            )
          }
          onClose={() => setWriting(null)}
          onDone={() => {
            setWriting(null);
            reload();
          }}
        />
      )}
    </Card>
  );
}

function OrgControlsCard({ orgId }: { orgId: string }) {
  const staff = useStaff();
  const inputs = useStaffQuery(staffKeys.inputs, listAvailability);
  const [editing, setEditing] = useState<null | "edit" | "remove">(null);
  const rows = (inputs.data?.inputs ?? []).filter((i) => i.section === "org_controls");
  const own = rows.find((i) => i.key === orgId);
  const platform = rows.find((i) => i.key === PLATFORM_KEY);
  const canWrite = staff.may("availability.write");
  const done = () => {
    setEditing(null);
    invalidateStaff(staffKeys.inputs);
    invalidateStaff(staffKeys.preview);
  };
  return (
    <Card
      title="Org controls"
      sub="This org's kill switches in the availability envelope: ingest pause or throttle, inference admission and dispatch."
      actions={
        canWrite ? (
          <span className="flex gap-2">
            <Button size="sm" variant="secondary" iconLeft={own ? Pencil : Plus} onClick={() => setEditing("edit")}>
              {own ? "Change" : "Add a control"}
            </Button>
            {own && (
              <Button size="sm" variant="ghost" iconLeft={Trash2} onClick={() => setEditing("remove")}>
                Remove
              </Button>
            )}
          </span>
        ) : undefined
      }
    >
      {inputs.error && !inputs.data ? (
        <ErrorState variant="inline" title="Could not load the controls" error={inputs.error} onRetry={inputs.reload} />
      ) : !inputs.data ? (
        <TableSkeleton />
      ) : (
        <div className="flex flex-col gap-3">
          <ControlLines label="This org" value={own?.value} reason={own?.reason} at={own?.updated_at} />
          <ControlLines label="Every org (platform-wide)" value={platform?.value} reason={platform?.reason} at={platform?.updated_at} />
          <p className="text-[11.5px] text-fg-3">For inference, the strictest of this org's row and the platform-wide row applies, route by route.</p>
        </div>
      )}
      {editing === "edit" && (
        <InputEditorDialog open section="org_controls" inputKey={orgId} before={own?.value} onClose={() => setEditing(null)} onDone={done} />
      )}
      {editing === "remove" && own && (
        <RemoveInputDialog open section="org_controls" inputKey={orgId} before={own.value} onClose={() => setEditing(null)} onDone={done} />
      )}
    </Card>
  );
}

function ControlLines({ label, value, reason, at }: { label: string; value?: unknown; reason?: string; at?: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-[11.5px] font-medium text-fg-2">{label}</span>
      {value === undefined ? (
        <span className="text-[12px] text-fg-3">No control.</span>
      ) : (
        <>
          <div className="flex flex-wrap gap-1">
            {describeOrgControl(value).map((l) => (
              <Pill key={l} variant={orgControlTone(value)} case="none">
                {l}
              </Pill>
            ))}
          </div>
          <span className="text-[11px] text-fg-3">
            {reason} · {formatTime(at)}
          </span>
        </>
      )}
    </div>
  );
}

// UsageDay is one daily usage report, plus the hosted AI gateway's
// forwarded requests that day (lane L4 adds `aigw_requests` to the host
// usage pull; an older host omits it). Typed here, additively, so the staff
// API types stay as they are until the field lands there.
type UsageDay = StaffOrgDetail["usage"][number] & GatewayUsageDay;

function UsageCard({ d }: { d: StaffOrgDetail }) {
  const rows: UsageDay[] = d.usage;
  const gateway = hasGatewayUsage(rows);
  const now = new Date();
  const mtd = gateway ? gatewayMonthToDate(rows, now) : null;
  return (
    <Card title="Usage" sub="Daily reports from the org's host (the last 30). Counts only.">
      {rows.length === 0 ? (
        <p className="text-[12px] text-fg-3">No usage report yet.</p>
      ) : (
        <>
          {gateway && (
            <p className="mb-2 text-[12px] text-fg-2">
              AI gateway requests in {monthOf(now)} (UTC):{" "}
              <span className="font-medium tabular-nums text-fg-1">{mtd === null ? "none reported" : mtd.toLocaleString("en-US")}</span>
            </p>
          )}
          <Table
            padded
            minWidth={gateway ? 520 : 420}
            maxHeight={320}
            stickyHead
            head={
              <tr>
                <th>Day</th>
                <th className="text-right">Seats</th>
                <th className="text-right">Members</th>
                <th className="text-right">Sessions</th>
                <th className="text-right">Machines</th>
                {gateway && <th className="text-right">Gateway requests</th>}
              </tr>
            }
          >
            {rows.map((u) => (
              <tr key={u.day}>
                <td className="whitespace-nowrap">{u.day}</td>
                <td className="text-right tabular-nums">{u.seats}</td>
                <td className="text-right tabular-nums">{u.members}</td>
                <td className="text-right tabular-nums">{u.sessions ?? 0}</td>
                <td className="text-right tabular-nums">{u.machine_identities ?? 0}</td>
                {gateway && <td className="text-right tabular-nums">{gatewayCell(u)}</td>}
              </tr>
            ))}
          </Table>
        </>
      )}
    </Card>
  );
}

function IntentsCard({ d, now }: { d: StaffOrgDetail; now: Date }) {
  return (
    <Card title="Lifecycle intents" sub="What the control plane asked the org's host to do (org_outbox), newest first.">
      {d.intents.length === 0 ? (
        <p className="text-[12px] text-fg-3">No intent.</p>
      ) : (
        <Table
          padded
          minWidth={460}
          maxHeight={320}
          stickyHead
          head={
            <tr>
              <th>Verb</th>
              <th>State</th>
              <th className="text-right">Attempts</th>
              <th>Created</th>
              <th>Next / done</th>
            </tr>
          }
        >
          {d.intents.map((i, n) => (
            <tr key={`${i.verb}-${i.created_at}-${n}`}>
              <td className="font-mono text-[11px]">{i.verb}</td>
              <td>
                <Pill variant={i.state === "acked" ? "success" : i.state === "failed" ? "danger" : "warn"}>{i.state}</Pill>
                {i.last_error_class && <div className="font-mono text-[10.5px] text-fg-3">{i.last_error_class}</div>}
              </td>
              <td className="text-right tabular-nums">{i.attempts}</td>
              <td className="whitespace-nowrap text-fg-3">{formatTime(i.created_at)}</td>
              <td className="whitespace-nowrap text-fg-3">{i.done_at ? formatTime(i.done_at) : relativeTime(i.next_attempt_at, now)}</td>
            </tr>
          ))}
        </Table>
      )}
    </Card>
  );
}

function DeletionCard({ d }: { d: StaffOrgDetail }) {
  const del = d.deletion;
  return (
    <Callout tone={del?.state === "blocked" ? "danger" : "warn"} title="Deletion">
      <div className="flex flex-col gap-1 text-[12px]">
        <span>
          Org status: <strong>{d.org.status.replace("_", " ")}</strong>
        </span>
        {del ? (
          <>
            <span>
              Request: <strong>{del.state.replace(/_/g, " ")}</strong>, opened {formatTime(del.created_at)}, updated {formatTime(del.updated_at)}
              {del.done_at ? `, done ${formatTime(del.done_at)}` : ""}
            </span>
            {del.blocked_reason && <span>Blocked: {del.blocked_reason}</span>}
          </>
        ) : (
          <span>No deletion request row.</span>
        )}
      </div>
    </Callout>
  );
}

function OrgLogCard({ orgId }: { orgId: string }) {
  const staff = useStaff();
  const q = useStaffQuery(`staff:log:org:${orgId}`, () => listLog({ org: orgId, limit: 50 }), [orgId]);
  return (
    <Card title="Staff actions on this org" sub="The staff log rows that name this org (support sign-ins and any change recorded against it).">
      {q.error && !q.data ? (
        <ErrorState variant="inline" title="Could not load the log" error={q.error} onRetry={q.reload} />
      ) : !q.data ? (
        <TableSkeleton />
      ) : q.data.actions.length === 0 ? (
        <p className="text-[12px] text-fg-3">No staff action names this org.</p>
      ) : (
        <LogTable actions={q.data.actions} self={staff.me.staff_id} showOrg={false} />
      )}
    </Card>
  );
}
