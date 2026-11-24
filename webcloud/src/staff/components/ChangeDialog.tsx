// ChangeDialog is the ONE confirmation every staff write goes through: it
// shows what will change (and what it replaces), asks for the reason the
// server logs with it in staff_actions, asks the staff member to tick that
// they checked it, and verifies the passkey first when the last assertion is
// older than the server's 15-minute window (or this tab holds no CSRF
// token). The server is still the gate (role, freshness, CSRF, reason); this
// only makes the gate's demands visible before the request.

import { useEffect, useState, type ReactNode } from "react";
import { KeyRound } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Callout } from "@shared/primitives/Callout";
import { JsonPreview } from "@shared/primitives/JsonPreview";
import { Modal } from "@shared/primitives/Modal";
import { Textarea } from "@shared/primitives/Textarea";
import { StaffApiError, needsPasskey } from "../api";
import { changeFormView } from "../lib/model";
import { passkeyErrorText } from "../lib/webauthn";
import { useStaff } from "../session";

export interface ChangeFormProps {
  summary: ReactNode;
  before?: unknown;
  after?: unknown;
  /** blocking are the change's own validation errors. */
  blocking: string[];
  reason: string;
  onReason: (r: string) => void;
  confirmed: boolean;
  onConfirmed: (c: boolean) => void;
  ready: boolean;
  busy: boolean;
  error: string | null;
  destructive?: boolean;
  confirmLabel: string;
  maxReason?: number;
  onSubmit: () => void;
  onCancel: () => void;
}

/** ChangeForm is the dialog's body and buttons (rendered by tests without
 *  the modal portal). */
export function ChangeForm(p: ChangeFormProps) {
  const view = changeFormView({
    reason: p.reason,
    confirmed: p.confirmed,
    ready: p.ready,
    busy: p.busy,
    blocking: p.blocking,
    confirmLabel: p.confirmLabel,
    maxReason: p.maxReason,
  });
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        if (view.canSubmit) p.onSubmit();
      }}
    >
      <div className="text-[12.5px] text-fg-1">{p.summary}</div>
      {(p.before !== undefined || p.after !== undefined) && (
        <div className="grid gap-3 sm:grid-cols-2">
          <JsonPreview label="Now" value={p.before ?? null} emptyLabel="(not set)" maxHeight={180} />
          <JsonPreview label="After" value={p.after ?? null} emptyLabel="(removed)" maxHeight={180} />
        </div>
      )}
      {p.blocking.length > 0 && (
        <Callout tone="danger" title="This change cannot be applied">
          <ul className="list-disc pl-4">
            {p.blocking.map((b) => (
              <li key={b}>{b}</li>
            ))}
          </ul>
        </Callout>
      )}
      <Textarea
        label="Reason"
        help="Required. Kept with the change in the staff action log."
        value={p.reason}
        onChange={(e) => p.onReason(e.target.value)}
        error={view.reasonError ?? undefined}
        rows={3}
        maxLength={p.maxReason ?? 1000}
        name="reason"
      />
      <label className="flex items-start gap-2 text-[12px] text-fg-2">
        <input type="checkbox" name="confirmed" checked={p.confirmed} onChange={(e) => p.onConfirmed(e.target.checked)} className="mt-0.5" />
        <span>I have checked what this changes and who it affects.</span>
      </label>
      {!p.ready && (
        <p className="flex items-center gap-1.5 text-[11.5px] text-fg-3">
          <KeyRound size={13} aria-hidden="true" />
          Your passkey is asked for first: changes need a passkey check from the last 15 minutes.
        </p>
      )}
      {p.error && (
        <Callout tone="danger" title="Not applied">
          {p.error}
        </Callout>
      )}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={p.onCancel} disabled={p.busy}>
          Cancel
        </Button>
        <Button type="submit" variant={p.destructive ? "danger" : "primary"} disabled={!view.canSubmit} loading={p.busy}>
          {view.submitLabel}
        </Button>
      </div>
    </form>
  );
}

export interface ChangeDialogProps {
  open: boolean;
  title: string;
  summary: ReactNode;
  before?: unknown;
  after?: unknown;
  blocking?: string[];
  destructive?: boolean;
  confirmLabel?: string;
  /** checkKey names what the staff member is checking (e.g. the digest of
   *  the changes shown); when it changes while the dialog is open, the "I
   *  have checked" tick is cleared, so a new diff is checked again. */
  checkKey?: string;
  /** run sends the change with the reason; it throws on a refusal. */
  run: (reason: string) => Promise<void>;
  onClose: () => void;
  onDone: () => void;
}

export function ChangeDialog(p: ChangeDialogProps) {
  const staff = useStaff();
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setConfirmed(false);
  }, [p.checkKey]);

  function close() {
    if (busy) return;
    setReason("");
    setConfirmed(false);
    setError(null);
    p.onClose();
  }

  async function submit() {
    setBusy(true);
    setError(null);
    const r = reason.trim();
    try {
      if (!staff.ready) await staff.reverify();
      try {
        await p.run(r);
      } catch (e) {
        if (!needsPasskey(e)) throw e;
        await staff.reverify();
        await p.run(r);
      }
      setReason("");
      setConfirmed(false);
      p.onDone();
    } catch (e) {
      setError(e instanceof StaffApiError ? `${e.message} (${e.code})` : passkeyErrorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={p.open} onClose={close} title={p.title} width={620} dismissible={!busy}>
      <ChangeForm
        summary={p.summary}
        before={p.before}
        after={p.after}
        blocking={p.blocking ?? []}
        reason={reason}
        onReason={setReason}
        confirmed={confirmed}
        onConfirmed={setConfirmed}
        ready={staff.ready}
        busy={busy}
        error={error}
        destructive={p.destructive}
        confirmLabel={p.confirmLabel ?? "Apply"}
        maxReason={staff.features.max_reason_characters}
        onSubmit={() => void submit()}
        onCancel={close}
      />
    </Modal>
  );
}
