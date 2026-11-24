// IssueDialog: the reviewed step that turns the availability inputs into a
// signed envelope (lane fix/sr-17-staff-control). It shows the difference
// between the newest issued envelope and the next one as a table, with the
// full next body behind a disclosure, and goes through ChangeDialog like
// every staff write (reason, "I have checked", passkey). The request names
// the preview the staff member checked (its inputs digest and base
// version): when the inputs or the issued version moved since, the server
// refuses it, the preview is read again and the dialog shows the new
// difference, with the tick cleared so it is checked again.

import { InfoDisclosure } from "@shared/primitives/InfoDisclosure";
import { JsonPreview } from "@shared/primitives/JsonPreview";
import { Pill } from "@shared/primitives/Pill";
import { Table } from "@shared/primitives/Table";
import { StaffApiError, cancelAvailabilityIssue, issueAvailability, needsPasskey, type AvailabilityPreview, type IssueRequest } from "../api";
import { changeView, issueBlocking, issueErrorText, type ChangeView } from "../lib/issue";
import { actorLabel, formatTime } from "../lib/model";
import { invalidateStaff, staffKeys } from "../session";
import { ChangeDialog } from "./ChangeDialog";

function Lines({ lines, empty }: { lines: string[]; empty: string }) {
  if (lines.length === 0) return <span className="text-fg-4">{empty}</span>;
  return (
    <div className="flex flex-col gap-0.5">
      {lines.map((l, i) => (
        <span key={i}>{l}</span>
      ))}
    </div>
  );
}

/** ChangeTable is the difference between the issued and the next envelope. */
export function ChangeTable({ rows }: { rows: { key: string; view: ChangeView }[] }) {
  return (
    <Table
      padded
      minWidth={540}
      maxHeight={300}
      stickyHead
      head={
        <tr>
          <th>Item</th>
          <th>Change</th>
          <th>Issued now</th>
          <th>Next</th>
        </tr>
      }
    >
      {rows.map(({ key, view: r }) => (
        <tr key={key}>
          <td>
            <div className="text-[10.5px] text-fg-3">{r.sectionLabel}</div>
            <div className={r.item.mono ? "break-all font-mono text-[11px] text-fg-1" : "font-medium text-fg-1"}>{r.item.label}</div>
            {r.item.sub && <div className="break-all font-mono text-[10.5px] text-fg-3">{r.item.sub}</div>}
          </td>
          <td>
            <Pill variant={r.kindTone}>{r.kindLabel}</Pill>
          </td>
          <td className="text-fg-2">
            <Lines lines={r.before} empty="not in the envelope" />
          </td>
          <td className="text-fg-1">
            <Lines lines={r.after} empty="not in the envelope" />
            {r.note && <div className="mt-0.5 text-[11px] text-fg-3">{r.note}</div>}
            {r.reason && <div className="mt-0.5 whitespace-pre-wrap text-[11px] text-fg-3">Reason: {r.reason}</div>}
          </td>
        </tr>
      ))}
    </Table>
  );
}

/** IssueSummary is the dialog's body: what issuing does, the difference,
 *  and the full next body (rendered by tests without the modal). */
export function IssueSummary({ preview, names }: { preview: AvailabilityPreview; names?: Map<string, string> }) {
  const rows = preview.changes.map((c, i) => ({ key: `${c.section}/${c.key}/${i}`, view: changeView(c, names) }));
  return (
    <div className="flex flex-col gap-3">
      <p>
        Issuing signs a new envelope with every change below, for every org, and sends it to every host.{" "}
        {preview.base_version > 0 ? `It replaces v${preview.base_version}.` : "It is the first envelope."}
      </p>
      {rows.length === 0 ? <p className="text-fg-3">No change to issue.</p> : <ChangeTable rows={rows} />}
      {preview.body != null && (
        <InfoDisclosure summary="Show the full next envelope">
          <div className="mt-2">
            <JsonPreview label="Next body" value={preview.body} maxHeight={240} copy />
          </div>
        </InfoDisclosure>
      )}
    </div>
  );
}

export function IssueDialog({
  open,
  preview,
  names,
  onClose,
  onDone,
}: {
  open: boolean;
  preview: AvailabilityPreview;
  names?: Map<string, string>;
  onClose: () => void;
  onDone: () => void;
}) {
  return (
    <ChangeDialog
      open={open}
      title="Issue the availability envelope"
      summary={<IssueSummary preview={preview} names={names} />}
      blocking={issueBlocking(preview)}
      confirmLabel="Issue envelope"
      checkKey={`${preview.base_version}:${preview.inputs_digest}`}
      run={async (reason) => {
        try {
          await issueAvailability({ reason, inputs_digest: preview.inputs_digest, base_version: preview.base_version });
        } catch (e) {
          // ChangeDialog retries a stale passkey itself. Any other refusal
          // means the preview this dialog shows is not what the server holds
          // (inputs changed, nothing left, a request already pending): read
          // it again so the dialog shows the current difference.
          if (e instanceof StaffApiError && !needsPasskey(e)) {
            invalidateStaff(staffKeys.preview);
            throw new StaffApiError(e.status, e.code, issueErrorText(e.code, e.message));
          }
          throw e;
        }
      }}
      onClose={onClose}
      onDone={onDone}
    />
  );
}

/** CancelIssueDialog withdraws the pending issue request (ops, admin): it is
 *  marked cancelled and the worker never issues it. It is the way out when no
 *  worker picks requests up (its availability loops are off), since a
 *  pending request refuses every later issue. Reason and passkey as for
 *  every staff change; the input changes themselves stay. */
export function CancelIssueDialog({
  request,
  self,
  onClose,
  onDone,
}: {
  request: IssueRequest;
  self?: string;
  onClose: () => void;
  onDone: () => void;
}) {
  return (
    <ChangeDialog
      open
      title="Withdraw the issue request"
      destructive
      summary={
        <div className="flex flex-col gap-2">
          <span>
            Withdraw the request {actorLabel(request.requested_by, self)} made at {formatTime(request.requested_at)}. It is marked
            cancelled: nothing is signed or sent to any host, and the input changes stay as they are.
          </span>
          <span className="text-[11.5px] text-fg-3">
            Use this when the request has waited for minutes: the worker is not picking requests up (check its log for
            &quot;availability envelope issue and delivery OFF&quot;), and while one waits no other issue can be made.
          </span>
        </div>
      }
      confirmLabel="Withdraw request"
      run={async (reason) => {
        try {
          await cancelAvailabilityIssue(request.request_id, reason);
        } catch (e) {
          // The request may have finished meanwhile: read the preview again
          // so the card shows its outcome.
          if (e instanceof StaffApiError && !needsPasskey(e)) {
            invalidateStaff(staffKeys.preview);
            throw new StaffApiError(e.status, e.code, issueErrorText(e.code, e.message));
          }
          throw e;
        }
      }}
      onClose={onClose}
      onDone={onDone}
    />
  );
}
