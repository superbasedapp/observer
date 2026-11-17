import { useState } from "react";
import { Laptop, KeyRound, ListRestart, Plus, Trash2 } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Callout } from "@shared/primitives/Callout";
import { Card } from "@shared/primitives/Card";
import { ConfirmButton } from "@shared/primitives/ConfirmButton";
import { Input } from "@shared/primitives/Input";
import { PageHeader } from "@shared/primitives/PageHeader";
import { Pill } from "@shared/primitives/Pill";
import { fmtDateTime } from "@shared/lib/format";
import {
  ApiError,
  approveDevice,
  beginPasskeyRegistration,
  finishPasskeyRegistration,
  getAuthMode,
  getMFA,
  newRecoveryCodes,
  removePasskey,
  type MFAStatus,
} from "../api";
import { CardSkeleton, ErrorPanel } from "../components/LoadState";
import { RecoveryCodes } from "../components/security/RecoveryCodes";
import { routeIcon } from "../lib/nav";
import { invalidatePortal, usePortalQuery } from "../lib/query";
import { createPasskey, passkeyErrorText, passkeysSupported } from "../lib/webauthn";

// Security - "Sign-in security" (C2; internal/cloudserver/api/portalmfa.go):
// the account's passkeys and recovery codes. Once an account has a passkey,
// every sign-in asks for it, and a team that requires a second factor lets
// the account in. Adding the FIRST passkey needs a fresh sign-in (the page
// sends the browser through one and back); removing a passkey or making new
// codes needs this session to have used its passkey or a recovery code.

/** MFA_REFUSAL_TEXT words the server's refusals for this page. */
const MFA_REFUSAL_TEXT: Readonly<Record<string, string>> = {
  second_factor_required: "Use your passkey (or a recovery code) in this session first: sign out and back in.",
  passkey_limit: "This account has as many passkeys as it can hold. Remove one first.",
  passkey_exists: "That passkey is already on this account.",
  passkey_signin_required: "Sign in with your passkey in this session to approve a machine.",
  reauth_required: "Sign in again to add your first passkey.",
};

function refusal(e: unknown): string {
  if (e instanceof ApiError && MFA_REFUSAL_TEXT[e.code]) return MFA_REFUSAL_TEXT[e.code];
  return e instanceof ApiError ? e.message : passkeyErrorText(e);
}

/** forcedSignInURL restarts sign-in with a fresh authentication and comes
 * back here (the first passkey needs it). */
const FORCED_SIGNIN = "/portal/auth/workos/start?reauth=1&return_to=" + encodeURIComponent("/portal/security");

export function Security() {
  const q = usePortalQuery<MFAStatus>("mfa", getMFA, []);
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [deviceId, setDeviceId] = useState("");
  const [approved, setApproved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);

  async function onAdd() {
    setBusy("add");
    setError(null);
    try {
      const start = await beginPasskeyRegistration(label.trim());
      const cred = await createPasskey(start.options);
      const done = await finishPasskeyRegistration(start.ceremony, cred);
      setLabel("");
      if (done.recovery_codes?.length) setCodes(done.recovery_codes);
      invalidatePortal("mfa");
    } catch (e) {
      if (e instanceof ApiError && e.code === "reauth_required" && getAuthMode() === "workos") {
        window.location.assign(FORCED_SIGNIN);
        return;
      }
      setError(refusal(e));
    } finally {
      setBusy(null);
    }
  }

  async function onRemove(id: string) {
    setBusy("remove:" + id);
    setError(null);
    try {
      await removePasskey(id);
      invalidatePortal("mfa");
    } catch (e) {
      setError(refusal(e));
    } finally {
      setBusy(null);
    }
  }

  async function onApproveDevice() {
    setBusy("device");
    setError(null);
    setApproved(false);
    try {
      await approveDevice(deviceId.trim());
      setApproved(true);
      setDeviceId("");
    } catch (e) {
      setError(refusal(e));
    } finally {
      setBusy(null);
    }
  }

  async function onNewCodes() {
    setBusy("codes");
    setError(null);
    try {
      const r = await newRecoveryCodes();
      setCodes(r.recovery_codes);
      invalidatePortal("mfa");
    } catch (e) {
      setError(refusal(e));
    } finally {
      setBusy(null);
    }
  }

  const header = (
    <PageHeader
      title="Sign-in security"
      icon={routeIcon("/security")}
      sub="A passkey is a second step when you sign in. Teams can require one."
    />
  );
  if (q.error && !q.data) {
    return (
      <div className="flex flex-col gap-6">
        {header}
        <ErrorPanel variant="page" what="your sign-in security" error={q.error} onRetry={q.reload} />
      </div>
    );
  }
  const st = q.data;
  const keys = st?.passkeys ?? [];
  return (
    <div className="flex flex-col gap-6">
      {header}
      {codes && <RecoveryCodes codes={codes} onDone={() => setCodes(null)} />}
      {error && <Callout tone="danger">{error}</Callout>}
      {st && !st.available && (
        <Callout tone="warn" title="Passkeys are not available">
          This server cannot check passkeys yet.
        </Callout>
      )}
      {st && !passkeysSupported() && (
        <Callout tone="warn" title="This browser cannot use passkeys">
          Open SuperBased in an up-to-date browser to add or use a passkey.
        </Callout>
      )}
      {!st ? (
        <CardSkeleton />
      ) : (
        <Card
          title="Passkeys"
          icon={KeyRound}
          sub={
            keys.length === 0
              ? "No passkey yet. Signing in uses only your SuperBased sign-in."
              : "Every sign-in asks for one of these."
          }
        >
          <div className="flex flex-col gap-4">
            {keys.length > 0 && (
              <ul className="flex flex-col divide-y divide-line-1">
                {keys.map((k) => (
                  <li key={k.id} className="flex flex-wrap items-center justify-between gap-3 py-2.5">
                    <div className="flex min-w-0 flex-col gap-0.5">
                      <span className="flex items-center gap-2 text-[12.5px] font-medium text-fg-0">
                        {k.label || "Passkey"}
                        <Pill variant={k.synced ? "info" : "neutral"} case="none">
                          {k.synced ? "Synced" : "Not synced"}
                        </Pill>
                      </span>
                      <span className="text-[11px] text-fg-3">
                        Added {fmtDateTime(k.created_at)}
                        {k.last_used_at ? `, last used ${fmtDateTime(k.last_used_at)}` : ", not used yet"}
                      </span>
                    </div>
                    <ConfirmButton
                      variant="danger-outline"
                      size="sm"
                      iconLeft={Trash2}
                      loading={busy === "remove:" + k.id}
                      confirmLabel="Remove passkey?"
                      armedNote={
                        keys.length === 1
                          ? "It is your only passkey: sign-ins stop asking for one, and your recovery codes are deleted."
                          : "It can no longer be used to sign in."
                      }
                      onConfirm={() => void onRemove(k.id)}
                    >
                      Remove
                    </ConfirmButton>
                  </li>
                ))}
              </ul>
            )}
            {st.available && (
              <form
                className="flex flex-wrap items-end gap-2"
                onSubmit={(ev) => {
                  ev.preventDefault();
                  void onAdd();
                }}
              >
                <Input
                  label="Name (optional)"
                  placeholder="Laptop, phone, security key"
                  maxLength={60}
                  value={label}
                  onChange={(ev) => setLabel(ev.target.value)}
                  className="w-64"
                />
                <Button type="submit" variant={keys.length === 0 ? "primary" : "secondary"} iconLeft={Plus} loading={busy === "add"}>
                  Add a passkey
                </Button>
              </form>
            )}
          </div>
        </Card>
      )}
      {st && keys.length > 0 && (
        <Card
          title="Recovery codes"
          icon={ListRestart}
          sub={`${st.recovery_codes_left} of 10 left. Each signs you in once if you lose your passkeys.`}
          actions={
            <ConfirmButton
              variant="secondary"
              size="sm"
              loading={busy === "codes"}
              confirmLabel="Replace your codes?"
              armedNote="Your current codes stop working."
              onConfirm={() => void onNewCodes()}
            >
              Make new codes
            </ConfirmButton>
          }
        >
          {st.recovery_codes_left <= 2 && (
            <Callout tone="warn">You are running out of recovery codes. Make new ones and save them.</Callout>
          )}
        </Card>
      )}
      {st && keys.length > 0 && (
        <Card
          title="Approve a machine"
          icon={Laptop}
          sub="Signing in to SuperBased from a new computer needs this step. Paste the machine id it showed you."
        >
          <form
            className="flex flex-wrap items-end gap-3"
            onSubmit={(ev) => {
              ev.preventDefault();
              void onApproveDevice();
            }}
          >
            <Input
              label="Machine id"
              maxLength={64}
              value={deviceId}
              onChange={(ev) => setDeviceId(ev.target.value)}
              className="w-80"
            />
            <Button type="submit" variant="secondary" loading={busy === "device"} disabled={deviceId.trim() === ""}>
              Approve
            </Button>
          </form>
          {approved && <Callout tone="success">Approved for 15 minutes. Sign in again on that computer.</Callout>}
        </Card>
      )}
    </div>
  );
}
