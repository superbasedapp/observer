import { useState, type FormEvent } from "react";
import { Trash2, Undo2 } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Callout } from "@shared/primitives/Callout";
import { Card } from "@shared/primitives/Card";
import { CopyOnClick } from "@shared/primitives/CopyOnClick";
import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { Input } from "@shared/primitives/Input";
import { Pill } from "@shared/primitives/Pill";
import { fmtInt, fmtShortId } from "@shared/lib/format";
import type {
  AuthMode,
  OrgDeletionPreview,
  OrgDeletionProof,
  OrgDeletionStatus,
  OrgDeletionView,
  PortalOrg,
} from "../../api";
import {
  ORG_DELETION_ORIGIN,
  blockedReasonText,
  keptText,
  orgDeletionControl,
  orgDeletionFormReady,
  orgDeletionProof,
  orgDeletionReauthMode,
  orgDeletionStateView,
  reauthNote,
  showCancel,
  stateDate,
  stepUpConfirmSlug,
  type OrgDeletionStepUpStash,
  type ReauthMode,
} from "../../lib/deletionModel";
import { dateWithRelative } from "../billing/util";

// OrgDeletionCard - the "Delete organization" danger zone on one org's page
// (plan 07 M6.9 / M7a.1). Every member sees where a deletion stands; only an
// owner sees the control: what deletion does (the cooling-off window, the
// purge, the canceled subscription, what is kept), the type-the-slug
// confirmation, and Cancel deletion while the server says it can still be
// canceled. Presentational: the page reads GET .../deletion and hands in
// onRequest / onCancel, which throw a worded Error on refusal. The request
// re-authenticates the person: a dev sign-in re-enters the developer
// subject; a WorkOS sign-in posts first without a step-up (a recent passkey
// use is enough), and the page starts the re-authentication when the server
// asks for it, coming back with stepUpId (and the stash it saved). The rules
// (who sees what, the slug match, which re-authentication, the state words)
// are deletionModel.ts's.

/** OrgDeletionRequestOutcome: "reauth" means the page is navigating away to
 * re-authenticate, so the card stays busy. */
export type OrgDeletionRequestOutcome = "requested" | "reauth";

export interface OrgDeletionCardProps {
  org: PortalOrg;
  view: OrgDeletionView;
  /** authMode is the session's sign-in, the fallback when the preview does
   * not say which re-authentication it needs. */
  authMode?: AuthMode | null;
  /** stepUpId is the one-use WorkOS authorization the page read from
   * ?step_up=, null when there is none. */
  stepUpId?: string | null;
  /** stepUpStash is what the page saved before re-authenticating. */
  stepUpStash?: OrgDeletionStepUpStash | null;
  onRequest: (confirmSlug: string, proof: OrgDeletionProof) => Promise<OrgDeletionRequestOutcome | void>;
  onCancel: () => Promise<void>;
}

/** OrgDeletionStatusPanel says where a deletion stands, for every member,
 * with Cancel deletion for an owner while it can still be canceled. */
export function OrgDeletionStatusPanel({
  org,
  deletion,
  onCancel,
}: {
  org: PortalOrg;
  deletion: OrgDeletionStatus;
  onCancel: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const v = orgDeletionStateView(deletion.state);
  const when = stateDate(deletion);
  async function cancel() {
    setBusy(true);
    setError(null);
    try {
      await onCancel();
    } catch (err) {
      setError(err instanceof Error ? err.message : "could not cancel the deletion");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="flex flex-col gap-3" data-testid="org-deletion-status">
      <div className="flex items-start gap-3">
        <Pill variant={v.tone}>{v.label}</Pill>
        <p className="text-[12px] leading-snug text-fg-2">{v.sentence(when ? dateWithRelative(when) : "")}</p>
      </div>
      <DefinitionList className="divide-y divide-line-1 text-[12px]">
        <DefinitionRow label="Requested" value={dateWithRelative(deletion.requested_at)} />
        <DefinitionRow label="Started by" value={ORG_DELETION_ORIGIN[deletion.origin] ?? deletion.origin} />
        {deletion.state === "cooling_off" && (
          <DefinitionRow label="Purge starts" value={dateWithRelative(deletion.purge_after)} />
        )}
        {deletion.state === "blocked" && deletion.blocked_reason && (
          <DefinitionRow label="Blocked because" value={blockedReasonText(deletion.blocked_reason)} />
        )}
        {(deletion.state === "purging" || deletion.state === "blocked") && deletion.step && (
          <DefinitionRow label="Step" value={<span className="font-mono">{deletion.step}</span>} />
        )}
        <DefinitionRow
          label="Request"
          value={
            <CopyOnClick value={deletion.request_id} className="font-mono">
              {fmtShortId(deletion.request_id)}
            </CopyOnClick>
          }
        />
      </DefinitionList>
      {error && (
        <p role="alert" className="text-[12px] text-danger">
          {error}
        </p>
      )}
      {showCancel(org, deletion) && (
        <div>
          <Button variant="secondary" size="sm" iconLeft={Undo2} loading={busy} onClick={() => void cancel()}>
            Cancel deletion
          </Button>
        </div>
      )}
    </div>
  );
}

/** OrgDeletionExplainer says, before the request, what deletion does. */
export function OrgDeletionExplainer({ org, preview }: { org: PortalOrg; preview: OrgDeletionPreview }) {
  const days = preview.cooling_off_days;
  const members = preview.members;
  return (
    <div className="flex flex-col gap-2 text-[12px] leading-snug text-fg-2">
      <p>
        {days > 0 ? (
          <>
            Deleting <strong className="text-fg-1">{org.display_name}</strong> starts a {fmtInt(days)}-day cooling-off
            window. Requested now, the purge starts on{" "}
            <strong className="text-fg-1">{dateWithRelative(preview.purge_after)}</strong>. Until then the team keeps
            working and any owner can cancel.
          </>
        ) : (
          <>
            Deleting <strong className="text-fg-1">{org.display_name}</strong> has no cooling-off window: the purge
            starts on <strong className="text-fg-1">{dateWithRelative(preview.purge_after)}</strong>.
          </>
        )}
      </p>
      <ul className="ml-4 list-disc space-y-1">
        <li>
          Every member loses access to the team
          {members > 0 ? ` (${fmtInt(members)} ${members === 1 ? "member" : "members"})` : ""}.
        </li>
        <li>
          The team's data on its host and in object storage is purged. Copies in backups expire within 30 days of the
          purge.
        </li>
        <li>
          The team's subscription is canceled
          {preview.live_subscription ? ": this team has a live subscription, and it stops renewing." : "."}
        </li>
      </ul>
      {preview.kept.length > 0 && (
        <>
          <p>What is kept:</p>
          <ul className="ml-4 list-disc space-y-1">
            {preview.kept.map((k) => (
              <li key={k}>{keptText(k)}</li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

/** OrgDeletionForm is the type-the-slug confirmation, controlled so the
 * button's state follows the typed text alone. A dev sign-in also re-enters
 * the developer subject; a deployment that cannot re-authenticate keeps the
 * button off and says why. */
export function OrgDeletionForm({
  slug,
  typed,
  onTyped,
  busy,
  error,
  onSubmit,
  mode = "step_up",
  subject = "",
  onSubject,
  steppedUp = false,
}: {
  slug: string;
  typed: string;
  onTyped: (v: string) => void;
  busy: boolean;
  error: string | null;
  onSubmit: () => void;
  mode?: ReauthMode;
  subject?: string;
  onSubject?: (v: string) => void;
  /** steppedUp: a WorkOS re-authentication came back and only the address
   * is missing. */
  steppedUp?: boolean;
}) {
  const ok = orgDeletionFormReady(mode, typed, slug, subject);
  const broker = mode === "broker_token";
  const note = reauthNote(mode, steppedUp);
  function submit(e: FormEvent) {
    e.preventDefault();
    if (ok && !busy) onSubmit();
  }
  return (
    <form className="flex max-w-[520px] flex-col gap-2" onSubmit={submit}>
      <Input
        label={
          <>
            Type <span className="font-mono text-fg-1">{slug}</span> to confirm
          </>
        }
        value={typed}
        onChange={(e) => onTyped(e.target.value)}
        disabled={busy || mode === "unavailable"}
        autoComplete="off"
        spellCheck={false}
        mono
        error={broker ? undefined : (error ?? undefined)}
      />
      {broker && (
        <Input
          label="Re-enter your developer subject to confirm"
          value={subject}
          onChange={(e) => onSubject?.(e.target.value)}
          disabled={busy}
          autoComplete="off"
          spellCheck={false}
          mono
          error={error ?? undefined}
        />
      )}
      {note && <p className="text-[12px] leading-snug text-fg-2">{note}</p>}
      <div>
        <Button type="submit" variant="danger" size="sm" iconLeft={Trash2} loading={busy} disabled={!ok}>
          Delete team
        </Button>
      </div>
    </form>
  );
}

/** OrgDeletionStepUpConfirm finishes a request after WorkOS
 * re-authentication, with the address the owner typed before leaving. */
export function OrgDeletionStepUpConfirm({
  org,
  busy,
  error,
  onConfirm,
}: {
  org: PortalOrg;
  busy: boolean;
  error: string | null;
  onConfirm: () => void;
}) {
  return (
    <div className="flex flex-col gap-2">
      {error && (
        <p role="alert" className="text-[12px] text-danger">
          {error}
        </p>
      )}
      <div>
        <Button variant="danger" size="sm" iconLeft={Trash2} loading={busy} onClick={onConfirm}>
          Re-authentication confirmed: delete {org.display_name}
        </Button>
      </div>
    </div>
  );
}

export function OrgDeletionCard({
  org,
  view,
  authMode = null,
  stepUpId = null,
  stepUpStash = null,
  onRequest,
  onCancel,
}: OrgDeletionCardProps) {
  const [typed, setTyped] = useState("");
  const [subject, setSubject] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { deletion, preview } = view;
  const control = orgDeletionControl(org, deletion, preview);
  // A non-owner with nothing in progress has nothing to see here.
  if (control.kind === "none" && deletion === null) return null;

  const mode = orgDeletionReauthMode(preview, authMode);
  const steppedUp = mode === "step_up" && stepUpId !== null;
  // After re-authenticating, the stashed address finishes the request; a
  // missing or foreign stash shows the form again.
  const stashedSlug = steppedUp ? stepUpConfirmSlug(stepUpStash, org) : null;

  async function request(confirmSlug: string) {
    setBusy(true);
    setError(null);
    let leaving = false;
    try {
      const out = await onRequest(confirmSlug, orgDeletionProof(mode, subject, stepUpId));
      if (out === "reauth") {
        leaving = true;
        return;
      }
      setTyped("");
      setSubject("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "could not request the deletion");
    } finally {
      if (!leaving) setBusy(false);
    }
  }

  return (
    <Card title="Delete team" icon={Trash2} tone="danger" id="delete-team">
      <div className="flex flex-col gap-4">
        {deletion !== null && <OrgDeletionStatusPanel org={org} deletion={deletion} onCancel={onCancel} />}
        {control.kind === "refused" && <Callout tone="info">{control.sentence}</Callout>}
        {control.kind === "form" && (
          <>
            <OrgDeletionExplainer org={org} preview={preview} />
            {stashedSlug !== null ? (
              <OrgDeletionStepUpConfirm
                org={org}
                busy={busy}
                error={error}
                onConfirm={() => void request(stashedSlug)}
              />
            ) : (
              <OrgDeletionForm
                slug={org.slug}
                typed={typed}
                onTyped={(v) => {
                  setTyped(v);
                  setError(null);
                }}
                busy={busy}
                error={error}
                onSubmit={() => void request(typed.trim())}
                mode={mode}
                subject={subject}
                onSubject={(v) => {
                  setSubject(v);
                  setError(null);
                }}
                steppedUp={steppedUp}
              />
            )}
          </>
        )}
      </div>
    </Card>
  );
}
