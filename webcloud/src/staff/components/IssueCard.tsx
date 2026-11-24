// IssueCard: what the availability inputs would change if the envelope were
// issued now, and whether the last issue reached the hosts (lane
// fix/sr-17-staff-control). Staff writes change the inputs only; a host
// applies them only once ops or admin review the difference and issue a
// signed envelope here (IssueDialog). The card shows how many changes are
// not issued yet, the inputs that cannot be composed (issue is blocked until
// they are fixed or removed), the request waiting for the worker, the last
// request's outcome, and each host's delivery. While a request is pending it
// re-reads the preview every 2 s, and for a short while after, until every
// host holds the new envelope. Support reads it; ops and admin issue, and
// can withdraw a pending request the worker never picks up (it would refuse
// every later issue).

import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Send, XCircle } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Callout } from "@shared/primitives/Callout";
import { Card } from "@shared/primitives/Card";
import { ErrorState } from "@shared/primitives/ErrorState";
import { LiveDot, type LiveTone } from "@shared/primitives/LiveDot";
import { Pill } from "@shared/primitives/Pill";
import { TableSkeleton } from "@shared/primitives/Skeleton";
import { Table } from "@shared/primitives/Table";
import { getAvailabilityPreview, type AvailabilityPreview, type IssueRequest } from "../api";
import { SETTLE_MS, cancelGate, deliveryView, issueGate, issuePollMs, pendingSummary, requestView } from "../lib/issue";
import { actorLabel, relativeTime, type Tone } from "../lib/model";
import { invalidateStaff, staffKeys, useStaff, useStaffQuery } from "../session";
import { CancelIssueDialog, IssueDialog } from "./IssueDialog";

/** ISSUE_CARD_ID is the card's anchor (the component card scrolls to it). */
export const ISSUE_CARD_ID = "availability-issue";

const DOT_TONE: Record<Tone, LiveTone> = {
  neutral: "idle",
  success: "success",
  warn: "warn",
  danger: "danger",
  info: "info",
  accent: "accent",
};

export interface IssueCardViewProps {
  preview: AvailabilityPreview | null;
  error: string | null;
  onRetry?: () => void;
  /** mayIssue: this role can issue (ops, admin). */
  mayIssue: boolean;
  onReview: () => void;
  /** onCancelPending opens the withdraw dialog for the pending request
   *  (shown to ops and admin only). */
  onCancelPending?: (r: IssueRequest) => void;
  /** orgId counts the changes naming that org (Org detail). */
  orgId?: string;
  /** hostId narrows delivery to one host: undefined shows every host, null
   *  says the org is not placed on a host. */
  hostId?: string | null;
  /** problemsLink links the problem list to the Availability page. */
  problemsLink?: boolean;
  self?: string;
  now: Date;
}

/** IssueCardView is the card from its data (rendered by tests). */
export function IssueCardView(p: IssueCardViewProps) {
  return (
    <Card id={ISSUE_CARD_ID} title="Changes to issue" sub="Hosts apply input changes only once ops or admin issue a new signed envelope.">
      {p.error && !p.preview ? (
        <ErrorState variant="inline" title="Could not load the changes to issue" error={p.error} onRetry={p.onRetry} />
      ) : !p.preview ? (
        <TableSkeleton />
      ) : (
        <IssueBody {...p} preview={p.preview} />
      )}
    </Card>
  );
}

function IssueBody(p: IssueCardViewProps & { preview: AvailabilityPreview }) {
  const pv = p.preview;
  const summary = pendingSummary(pv, p.orgId);
  const gate = issueGate(pv, p.mayIssue);
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <span className="flex min-w-0 items-center gap-2 text-[13px] font-medium text-fg-1">
          <LiveDot tone={DOT_TONE[summary.tone]} still />
          {summary.text}
        </span>
        {gate.show ? (
          <div className="flex flex-col items-start gap-1 sm:items-end">
            <Button size="sm" variant="primary" iconLeft={Send} disabled={!gate.enabled} onClick={p.onReview}>
              Review and issue
            </Button>
            {gate.reason && <span className="text-[11px] text-fg-3">{gate.reason}</span>}
          </div>
        ) : pv.changes.length > 0 ? (
          <span className="text-[11.5px] text-fg-3">ops and admin issue the envelope.</span>
        ) : null}
      </div>
      {pv.problems.length > 0 && (
        <Callout
          tone="danger"
          title="Issue is blocked until these inputs are fixed or removed"
          action={
            p.problemsLink ? (
              <Link to="/availability" className="text-[11.5px] font-medium text-accent hover:underline">
                Open Availability
              </Link>
            ) : undefined
          }
        >
          <ul className="list-disc pl-4 font-mono text-[11px]">
            {pv.problems.map((x) => (
              <li key={x}>{x}</li>
            ))}
          </ul>
        </Callout>
      )}
      {pv.pending && (
        <RequestLine
          title="Issue request"
          r={pv.pending}
          live
          self={p.self}
          now={p.now}
          onCancel={cancelGate(pv.pending, p.mayIssue) && p.onCancelPending ? p.onCancelPending : undefined}
        />
      )}
      {pv.last_request && <RequestLine title="Last request" r={pv.last_request} self={p.self} now={p.now} />}
      <Deliveries preview={pv} hostId={p.hostId} now={p.now} />
    </div>
  );
}

function RequestLine({
  title,
  r,
  live,
  self,
  now,
  onCancel,
}: {
  title: string;
  r: IssueRequest;
  live?: boolean;
  self?: string;
  now: Date;
  /** onCancel shows the withdraw button (a pending request, ops and admin). */
  onCancel?: (r: IssueRequest) => void;
}) {
  const v = requestView(r);
  return (
    <div className="flex flex-col gap-1 rounded-2 border border-line-1 bg-bg-3 px-3 py-2">
      <div className="flex flex-wrap items-center gap-2 text-[12px]">
        <span className="font-medium text-fg-2">{title}</span>
        {live && <LiveDot tone="info" label="In progress" />}
        <Pill variant={v.tone}>{v.label}</Pill>
        <span className="text-fg-1">{v.text}</span>
        {onCancel && (
          <Button size="sm" variant="ghost" iconLeft={XCircle} className="ml-auto" onClick={() => onCancel(r)}>
            Withdraw request
          </Button>
        )}
      </div>
      <div className="text-[11px] text-fg-3">
        Requested by {actorLabel(r.requested_by, self)} {relativeTime(r.requested_at, now)}
        {r.done_at ? `, finished ${relativeTime(r.done_at, now)}` : ""}
      </div>
      {r.reason && <div className="whitespace-pre-wrap text-[11.5px] text-fg-2">Reason: {r.reason}</div>}
    </div>
  );
}

function Deliveries({ preview, hostId, now }: { preview: AvailabilityPreview; hostId?: string | null; now: Date }) {
  const rows = hostId === undefined ? preview.deliveries : preview.deliveries.filter((d) => d.host_id === hostId);
  const title = hostId === undefined ? "Delivery to hosts" : hostId ? `Delivery to this org's host (${hostId})` : "Delivery to this org's host";
  return (
    <div className="flex flex-col gap-2">
      <span className="text-[11.5px] font-medium text-fg-2">{title}</span>
      {hostId === null ? (
        <p className="text-[12px] text-fg-3">This org is not placed on a host yet.</p>
      ) : rows.length === 0 ? (
        <p className="text-[12px] text-fg-3">
          {preview.base_version === 0
            ? "No envelope has been issued, so no host holds one."
            : hostId
              ? "This host has not been reached yet."
              : "No host has been reached yet."}
        </p>
      ) : (
        <Table
          padded
          minWidth={560}
          head={
            <tr>
              <th>Host</th>
              <th>Envelope</th>
              <th>State</th>
              <th>Detail</th>
              <th>Updated</th>
            </tr>
          }
        >
          {rows.map((d) => {
            const v = deliveryView(d, preview.base_version);
            return (
              <tr key={d.host_id}>
                <td className="whitespace-nowrap font-mono text-[11px] text-fg-1">{d.host_id}</td>
                <td className="whitespace-nowrap">{v.version}</td>
                <td>
                  <Pill variant={v.tone}>{v.label}</Pill>
                </td>
                <td className="text-fg-2">{v.detail || "-"}</td>
                <td className="whitespace-nowrap text-fg-3">{relativeTime(d.updated_at, now)}</td>
              </tr>
            );
          })}
        </Table>
      )}
      {hostId === undefined && rows.length > 0 && <p className="text-[11px] text-fg-3">A host that is not listed has never been reached.</p>}
    </div>
  );
}

/** IssueCard reads the preview (polling while an issue is in flight) and
 *  opens the review dialog. */
export function IssueCard({ orgId, hostId, names }: { orgId?: string; hostId?: string | null; names?: Map<string, string> }) {
  const staff = useStaff();
  const [pollMs, setPollMs] = useState(0);
  const [settleUntil, setSettleUntil] = useState(0);
  const [reviewing, setReviewing] = useState(false);
  const [cancelling, setCancelling] = useState<IssueRequest | null>(null);
  const q = useStaffQuery(staffKeys.preview, getAvailabilityPreview, [], { refreshMs: pollMs });
  const settling = Date.now() < settleUntil;
  useEffect(() => {
    setPollMs(issuePollMs(q.data, settling));
  }, [q.data, settling]);

  // When the pending request finishes, the issued envelope changed: re-read
  // it, and keep watching the hosts take it for a short while.
  const pendingId = q.data?.pending?.request_id ?? null;
  const prevPending = useRef<string | null>(null);
  useEffect(() => {
    if (prevPending.current !== null && pendingId === null) {
      invalidateStaff(staffKeys.doc);
      if (orgId) invalidateStaff(staffKeys.orgComponents(orgId));
      setSettleUntil(Date.now() + SETTLE_MS);
    }
    prevPending.current = pendingId;
  }, [pendingId, orgId]);

  return (
    <>
      <IssueCardView
        preview={q.data}
        error={q.error}
        onRetry={q.reload}
        mayIssue={staff.may("availability.issue")}
        onReview={() => setReviewing(true)}
        onCancelPending={setCancelling}
        orgId={orgId}
        hostId={hostId}
        problemsLink={orgId !== undefined}
        self={staff.me.staff_id}
        now={new Date()}
      />
      {reviewing && q.data && (
        <IssueDialog
          open
          preview={q.data}
          names={names}
          onClose={() => setReviewing(false)}
          onDone={() => {
            setReviewing(false);
            invalidateStaff(staffKeys.preview);
            invalidateStaff(staffKeys.doc);
            setSettleUntil(Date.now() + SETTLE_MS);
          }}
        />
      )}
      {cancelling && (
        <CancelIssueDialog
          request={cancelling}
          self={staff.me.staff_id}
          onClose={() => setCancelling(null)}
          onDone={() => {
            setCancelling(null);
            invalidateStaff(staffKeys.preview);
          }}
        />
      )}
    </>
  );
}
