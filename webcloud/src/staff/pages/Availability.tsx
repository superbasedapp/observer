// Availability: the staff inputs of the availability envelope (plan 06
// 18.3.5) - the org_controls kill switches (ingest pause or throttle per org;
// inference admission and dispatch per org and platform-wide, by route), the
// per-component reach and the release flags - next to the envelope the
// control plane last signed from them. ops and admin change them; support
// reads. Every change goes through ChangeDialog (reason, tick, passkey).

import { useMemo, useState } from "react";
import { Gauge, Pencil, Plus, Trash2 } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Callout } from "@shared/primitives/Callout";
import { Card } from "@shared/primitives/Card";
import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { EmptyState } from "@shared/primitives/EmptyState";
import { ErrorState } from "@shared/primitives/ErrorState";
import { JsonPreview } from "@shared/primitives/JsonPreview";
import { PageHeader } from "@shared/primitives/PageHeader";
import { Pill } from "@shared/primitives/Pill";
import { TableSkeleton } from "@shared/primitives/Skeleton";
import { Table } from "@shared/primitives/Table";
import { TabPanel, TabStrip } from "@shared/primitives/Tabs";
import { getAvailabilityDocument, listAvailability, listOrgs, type AvailabilityInput, type SignedDoc } from "../api";
import { InputEditorDialog, RemoveInputDialog } from "../components/InputEditor";
import { PLATFORM_KEY, describeOrgControl, describeReach, orgControlTone, type Section } from "../lib/envelope";
import { actorLabel, envelopeBehind, formatTime } from "../lib/model";
import { invalidateStaff, useStaff, useStaffQuery } from "../session";

const TABS: { id: Section; label: string }[] = [
  { id: "org_controls", label: "Org controls" },
  { id: "components", label: "Components" },
  { id: "release_flags", label: "Release flags" },
];

type Editing = { kind: "edit"; section: Section; key: string; before?: unknown } | { kind: "remove"; section: Section; key: string; before: unknown } | null;

/** sortInputs puts the platform-wide org_controls row first, then by key. */
export function sortInputs(rows: AvailabilityInput[]): AvailabilityInput[] {
  return [...rows].sort((a, b) => (a.key === PLATFORM_KEY ? -1 : b.key === PLATFORM_KEY ? 1 : a.key.localeCompare(b.key)));
}

export function Availability() {
  const staff = useStaff();
  const inputs = useStaffQuery("staff:availability", listAvailability);
  const doc = useStaffQuery("staff:availability-doc", getAvailabilityDocument);
  const orgs = useStaffQuery(staff.feature("orgs") ? "staff:orgs" : null, listOrgs);
  const [tab, setTab] = useState<Section>("org_controls");
  const [editing, setEditing] = useState<Editing>(null);
  const canWrite = staff.may("availability.write");
  const names = useMemo(() => new Map((orgs.data?.orgs ?? []).map((o) => [o.org_id, o.display_name])), [orgs.data]);

  const done = () => {
    setEditing(null);
    invalidateStaff("staff:availability");
    invalidateStaff("staff:availability-doc");
  };

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="Availability"
        icon={Gauge}
        sub="The staff inputs the signed availability envelope is composed from: org kill switches, component reach and release flags."
      />
      <EnvelopeCard doc={doc.data?.document ?? null} error={doc.error} loading={!doc.data && !doc.error} />
      {!canWrite && (
        <Callout tone="info" title="Read only">
          Your role ({staff.me.role}) can read the inputs. ops and admin change them.
        </Callout>
      )}
      <TabStrip
        tabs={TABS.map((t) => ({ ...t, count: inputs.data?.inputs.filter((i) => i.section === t.id).length ?? null }))}
        value={tab}
        onChange={setTab}
        idPrefix="staff-avail"
        ariaLabel="Envelope sections"
      />
      {TABS.map((t) => (
        <TabPanel key={t.id} id={t.id} active={tab} idPrefix="staff-avail">
          {inputs.error && !inputs.data ? (
            <ErrorState variant="inline" title="Could not load the inputs" error={inputs.error} onRetry={inputs.reload} />
          ) : !inputs.data ? (
            <TableSkeleton />
          ) : (
            <InputTable
              section={t.id}
              rows={sortInputs(inputs.data.inputs.filter((i) => i.section === t.id))}
              issuedAt={doc.data?.document?.issued_at ?? null}
              names={names}
              self={staff.me.staff_id}
              canWrite={canWrite}
              onAdd={() => setEditing({ kind: "edit", section: t.id, key: "" })}
              onEdit={(r) => setEditing({ kind: "edit", section: t.id, key: r.key, before: r.value })}
              onRemove={(r) => setEditing({ kind: "remove", section: t.id, key: r.key, before: r.value })}
            />
          )}
        </TabPanel>
      ))}
      {editing?.kind === "edit" && (
        <InputEditorDialog open section={editing.section} inputKey={editing.key} before={editing.before} onClose={() => setEditing(null)} onDone={done} />
      )}
      {editing?.kind === "remove" && (
        <RemoveInputDialog open section={editing.section} inputKey={editing.key} before={editing.before} onClose={() => setEditing(null)} onDone={done} />
      )}
    </div>
  );
}

export function EnvelopeCard({ doc, error, loading }: { doc: SignedDoc | null; error: string | null; loading: boolean }) {
  return (
    <Card title="Issued envelope" sub="What hosts hold now: the newest signed sbo-availability-v1 document.">
      {loading ? (
        <TableSkeleton />
      ) : error ? (
        <ErrorState variant="inline" title="Could not load the issued envelope" error={error} />
      ) : !doc ? (
        <p className="text-[12px] text-fg-2">No envelope has been issued yet. Inputs below take effect once the control plane signs one.</p>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          <DefinitionList>
            <DefinitionRow label="Version" value={`v${doc.version}`} />
            <DefinitionRow label="Issued" value={formatTime(doc.issued_at)} />
            <DefinitionRow label="Issued by" value={doc.issued_by} />
            <DefinitionRow label="Signing key" value={<span className="font-mono text-[11px]">{doc.key_id.slice(0, 12)}</span>} />
          </DefinitionList>
          <JsonPreview label="Body" value={doc.body ?? `${doc.body_bytes} bytes (not JSON)`} maxHeight={200} copy />
        </div>
      )}
    </Card>
  );
}

export function InputTable(p: {
  section: Section;
  rows: AvailabilityInput[];
  issuedAt: string | null;
  names: Map<string, string>;
  self: string;
  canWrite: boolean;
  onAdd: () => void;
  onEdit: (r: AvailabilityInput) => void;
  onRemove: (r: AvailabilityInput) => void;
}) {
  const label = (r: AvailabilityInput) =>
    p.section === "org_controls" ? (r.key === PLATFORM_KEY ? "Every org (platform-wide)" : (p.names.get(r.key) ?? r.key)) : r.key;
  return (
    <div className="flex flex-col gap-3">
      {p.canWrite && (
        <div>
          <Button size="sm" variant="secondary" iconLeft={Plus} onClick={p.onAdd}>
            Add
          </Button>
        </div>
      )}
      {p.rows.length === 0 ? (
        <EmptyState variant="inline" title="No input in this section" body="Without an input the compiled stage default applies." />
      ) : (
        <Table
          padded
          minWidth={820}
          head={
            <tr>
              <th>{p.section === "org_controls" ? "Org" : "Id"}</th>
              <th>Setting</th>
              <th>Reason</th>
              <th>By</th>
              <th>Updated</th>
              <th>Envelope</th>
              {p.canWrite && <th />}
            </tr>
          }
        >
          {p.rows.map((r) => (
            <tr key={r.key}>
              <td>
                <div className="font-medium text-fg-1">{label(r)}</div>
                {p.section === "org_controls" && r.key !== PLATFORM_KEY && <div className="font-mono text-[10.5px] text-fg-3">{r.key}</div>}
              </td>
              <td>
                {p.section === "org_controls" ? (
                  <div className="flex flex-col gap-1">
                    {describeOrgControl(r.value).map((line) => (
                      <Pill key={line} variant={orgControlTone(r.value)} case="none">
                        {line}
                      </Pill>
                    ))}
                  </div>
                ) : (
                  describeReach(r.value)
                )}
              </td>
              <td className="max-w-[260px] whitespace-pre-wrap text-fg-2">{r.reason}</td>
              <td className="whitespace-nowrap">{actorLabel(r.author, p.self)}</td>
              <td className="whitespace-nowrap text-fg-3">{formatTime(r.updated_at)}</td>
              <td>
                {/* Order only: whether the composer carried a row into the
                    envelope is the envelope body's to say (shown above). */}
                {!p.issuedAt ? (
                  <Pill variant="warn">no envelope issued</Pill>
                ) : envelopeBehind(r.updated_at, p.issuedAt) ? (
                  <Pill variant="warn">newer than the envelope</Pill>
                ) : (
                  <Pill variant="neutral">older than the envelope</Pill>
                )}
              </td>
              {p.canWrite && (
                <td className="whitespace-nowrap text-right">
                  <Button size="sm" variant="ghost" iconLeft={Pencil} onClick={() => p.onEdit(r)}>
                    Edit
                  </Button>
                  <Button size="sm" variant="ghost" iconLeft={Trash2} onClick={() => p.onRemove(r)}>
                    Remove
                  </Button>
                </td>
              )}
            </tr>
          ))}
        </Table>
      )}
    </div>
  );
}
