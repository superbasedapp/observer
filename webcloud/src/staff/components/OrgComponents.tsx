// OrgComponents: the per-org component switches on Org detail (lane
// fix/sr-17-staff-control; today one row, Code security). Each card says
// whether the issued envelope offers the component to this org and whether
// the next one (the inputs now) would, and gives ops and admin one button
// that turns it on or off for this org through ChangeDialog. Off is the
// default: the component is offered only when staff turn it on. The button
// changes the INPUT only; the org's host changes once the envelope is issued
// (the IssueCard on the same page).

import { useState } from "react";
import { Link } from "react-router-dom";
import { Power } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Card } from "@shared/primitives/Card";
import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { ErrorState } from "@shared/primitives/ErrorState";
import { Pill } from "@shared/primitives/Pill";
import { TableSkeleton } from "@shared/primitives/Skeleton";
import { StaffApiError, getOrgComponents, needsPasskey, setOrgComponent, type OrgComponentRow } from "../api";
import { describeReach } from "../lib/envelope";
import { componentErrorText, componentView } from "../lib/issue";
import { invalidateStaff, staffKeys, useStaff, useStaffQuery } from "../session";
import { ChangeDialog } from "./ChangeDialog";
import { ISSUE_CARD_ID } from "./IssueCard";

export interface OrgComponentCardProps {
  row: OrgComponentRow;
  baseVersion: number;
  /** canWrite: this role changes availability inputs (ops, admin). */
  canWrite: boolean;
  /** issueHere: the issue card is on this page and this role can issue. */
  issueHere: boolean;
  onToggle: () => void;
}

/** OrgComponentCard is one component's card (rendered by tests). */
export function OrgComponentCard(p: OrgComponentCardProps) {
  const v = componentView(p.row, p.baseVersion);
  return (
    <Card
      title={p.row.title}
      sub="Off unless staff turn it on for this org."
      actions={
        p.canWrite ? (
          <Button
            size="sm"
            variant={p.row.toggle.on ? "primary" : "secondary"}
            iconLeft={Power}
            disabled={v.disabledReason !== null}
            onClick={p.onToggle}
          >
            {v.buttonLabel}
          </Button>
        ) : undefined
      }
    >
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Pill variant={v.headlineTone} case="none">
            {v.headline}
          </Pill>
          {v.differs && (
            <Pill variant="warn" case="none">
              not issued yet
            </Pill>
          )}
        </div>
        <DefinitionList>
          <DefinitionRow label={v.issuedLabel} value={v.issuedText} />
          <DefinitionRow label={v.nextLabel} value={v.nextText} />
          {p.row.input != null && <DefinitionRow label="Input" value={describeReach(p.row.input)} />}
        </DefinitionList>
        {v.differs && (
          <p className="text-[11.5px] text-fg-2">
            The org&apos;s host changes only after the envelope is issued.{" "}
            {p.issueHere ? (
              <button
                type="button"
                className="font-medium text-accent hover:underline"
                onClick={() => document.getElementById(ISSUE_CARD_ID)?.scrollIntoView({ behavior: "smooth", block: "start" })}
              >
                Review and issue
              </button>
            ) : (
              "ops or admin issue it."
            )}
          </p>
        )}
        {p.canWrite && v.disabledReason && (
          <p className="text-[11.5px] text-fg-3">
            {v.disabledReason}{" "}
            <Link to="/availability" className="font-medium text-accent hover:underline">
              Open Availability
            </Link>
          </p>
        )}
      </div>
    </Card>
  );
}

/** OrgComponentsCards reads one org's components and switches them. */
export function OrgComponentsCards({ orgId, orgName }: { orgId: string; orgName: string }) {
  const staff = useStaff();
  const q = useStaffQuery(staffKeys.orgComponents(orgId), () => getOrgComponents(orgId), [orgId]);
  const [toggling, setToggling] = useState<OrgComponentRow | null>(null);
  const canWrite = staff.may("availability.write");
  const issueHere = staff.feature("availability_issue") && staff.may("availability.issue");
  if (q.error && !q.data) {
    return (
      <Card title="Components for this org">
        <ErrorState variant="inline" title="Could not load the components" error={q.error} onRetry={q.reload} />
      </Card>
    );
  }
  if (!q.data) {
    return (
      <Card title="Components for this org">
        <TableSkeleton />
      </Card>
    );
  }
  const data = q.data;
  return (
    <>
      {data.components.map((row) => (
        <OrgComponentCard
          key={row.component}
          row={row}
          baseVersion={data.base_version}
          canWrite={canWrite}
          issueHere={issueHere}
          onToggle={() => setToggling(row)}
        />
      ))}
      {toggling && (
        <ToggleDialog
          orgId={orgId}
          orgName={orgName}
          row={toggling}
          onClose={() => setToggling(null)}
          onDone={() => {
            setToggling(null);
            invalidateStaff(staffKeys.orgComponents(orgId));
            invalidateStaff(staffKeys.preview);
            invalidateStaff(staffKeys.inputs);
          }}
        />
      )}
    </>
  );
}

function ToggleDialog({ orgId, orgName, row, onClose, onDone }: { orgId: string; orgName: string; row: OrgComponentRow; onClose: () => void; onDone: () => void }) {
  const on = row.toggle.on;
  const v = componentView(row, 0);
  return (
    <ChangeDialog
      open
      title={`${on ? "Turn on" : "Turn off"} ${row.title}`}
      destructive={!on}
      summary={
        <div className="flex flex-col gap-2">
          <p>
            {on ? "Offer" : "Stop offering"} {row.title} to <strong>{orgName}</strong>. {v.afterText}
          </p>
          <p className="text-[11.5px] text-fg-3">This changes the input only: the org&apos;s host changes after the envelope is issued.</p>
        </div>
      }
      before={row.input}
      after={row.toggle.value}
      blocking={v.disabledReason ? [v.disabledReason] : []}
      confirmLabel={on ? "Turn on" : "Turn off"}
      run={async (reason) => {
        try {
          await setOrgComponent(orgId, row.component, on, reason);
        } catch (e) {
          // A refusal other than the passkey's means the card is out of date
          // (e.g. a repeat switch, 409 no_change): read it again.
          if (e instanceof StaffApiError && !needsPasskey(e)) {
            invalidateStaff(staffKeys.orgComponents(orgId));
            invalidateStaff(staffKeys.preview);
            throw new StaffApiError(e.status, e.code, componentErrorText(e.code, e.message));
          }
          throw e;
        }
      }}
      onClose={onClose}
      onDone={onDone}
    />
  );
}
