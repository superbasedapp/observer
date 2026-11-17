import type { FormEvent } from "react";
import { useEffect, useState } from "react";
import { KeyRound, LogOut } from "lucide-react";
import { AuthShell } from "@shared/components/auth/AuthShell";
import { Button } from "@shared/primitives/Button";
import { Callout } from "@shared/primitives/Callout";
import { Input } from "@shared/primitives/Input";
import { InlineLoading } from "@shared/primitives/Spinner";
import {
  ApiError,
  beginPasskeyAssertion,
  beginPasskeyRegistration,
  finishPasskeyAssertion,
  finishPasskeyRegistration,
  getAuthMode,
  getMFA,
  logout,
  redeemRecoveryCode,
  type MFAStatus,
} from "../api";
import { RecoveryCodes } from "../components/security/RecoveryCodes";
import { createPasskey, passkeyErrorText, passkeysSupported, safeNext, usePasskey } from "../lib/webauthn";

// SecondFactor - the portal's passkey step (C2; internal/cloudserver/api/
// portalmfa.go). Shown full screen, with no app shell, in two cases:
//
//   - the account has a passkey and this session has not used it yet (the
//     server refuses every other route until it does);
//   - the platform sign-in to a team that requires a second factor sent the
//     browser here (/second-factor?return_to=/oauth2/authorize?...): an
//     account with no passkey adds one here, then continues.
//
// After the passkey (or a recovery code) the page goes to the server's
// "next": the team sign-in it interrupted, or the portal.

/** returnToFromLocation reads ?return_to= of this page. */
function returnToFromLocation(): string {
  return new URLSearchParams(window.location.search).get("return_to") ?? "";
}

/** forcedSignInURL restarts sign-in with a fresh primary authentication and
 * comes back to this very page (the first passkey needs a fresh sign-in). */
function forcedSignInURL(): string {
  const here = window.location.pathname + window.location.search;
  return "/portal/auth/workos/start?reauth=1&return_to=" + encodeURIComponent(here);
}

export function SecondFactor() {
  const returnTo = returnToFromLocation();
  const [status, setStatus] = useState<MFAStatus | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showCode, setShowCode] = useState(false);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);

  useEffect(() => {
    getMFA()
      .then(setStatus)
      .catch((e: unknown) => setLoadError(e instanceof Error ? e.message : "could not load"));
  }, []);

  function go(next: string) {
    // A full navigation: the next page may be the team sign-in (a server
    // route), and the portal re-reads the session either way.
    window.location.assign(safeNext(next));
  }

  async function onUsePasskey() {
    setBusy(true);
    setError(null);
    try {
      const start = await beginPasskeyAssertion();
      const cred = await usePasskey(start.options);
      const { next } = await finishPasskeyAssertion(start.ceremony, cred, returnTo);
      go(next);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : passkeyErrorText(e));
      setBusy(false);
    }
  }

  async function onAddPasskey() {
    setBusy(true);
    setError(null);
    try {
      const start = await beginPasskeyRegistration("");
      const cred = await createPasskey(start.options);
      const done = await finishPasskeyRegistration(start.ceremony, cred);
      if (done.recovery_codes?.length) {
        setCodes(done.recovery_codes);
        setBusy(false);
        return;
      }
      go(returnTo);
    } catch (e) {
      if (e instanceof ApiError && e.code === "reauth_required" && getAuthMode() === "workos") {
        window.location.assign(forcedSignInURL());
        return;
      }
      setError(e instanceof ApiError ? e.message : passkeyErrorText(e));
      setBusy(false);
    }
  }

  async function onRecover(ev: FormEvent) {
    ev.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { next } = await redeemRecoveryCode(code, returnTo);
      go(next);
    } catch (e) {
      setError(e instanceof Error ? e.message : "that code did not work");
      setBusy(false);
    }
  }

  async function onSignOut() {
    try {
      await logout();
    } finally {
      window.location.assign("/portal/");
    }
  }

  if (codes) {
    return (
      <AuthShell title="Passkey added" intro="From now on, signing in asks for your passkey.">
        <RecoveryCodes codes={codes} onDone={() => go(returnTo)} />
      </AuthShell>
    );
  }

  const enrolled = status?.session.enrolled ?? false;
  const usedRecovery = status?.session.method === "recovery_code";
  const title = !status ? "Finish signing in" : enrolled ? "Use your passkey" : "Add a passkey";
  const intro = !status
    ? null
    : enrolled
      ? "Your account is protected by a passkey. Use it to finish signing in."
      : "Your team requires a second factor. Add a passkey to this account to continue: it takes a few seconds.";

  return (
    <AuthShell title={title} intro={intro}>
      <div className="flex flex-col gap-4">
        {loadError && <Callout tone="danger" title="Could not load">{loadError}</Callout>}
        {!status && !loadError && <InlineLoading label="Loading" />}
        {status && !status.available && (
          <Callout tone="warn" title="Passkeys are not available">
            This server cannot check passkeys right now. Try again later, or contact support.
          </Callout>
        )}
        {status && !passkeysSupported() && (
          <Callout tone="warn" title="This browser cannot use passkeys">
            Open SuperBased in an up-to-date browser that supports passkeys.
          </Callout>
        )}
        {usedRecovery && (
          <Callout tone="info" title="You signed in with a recovery code">
            This team asks for a passkey itself. Use one, or add a new one under Sign-in security.
          </Callout>
        )}
        {error && <Callout tone="danger">{error}</Callout>}
        {status?.available && enrolled && (
          <Button variant="primary" iconLeft={KeyRound} loading={busy} onClick={() => void onUsePasskey()}>
            Use your passkey
          </Button>
        )}
        {status?.available && !enrolled && (
          <Button variant="primary" iconLeft={KeyRound} loading={busy} onClick={() => void onAddPasskey()}>
            Add a passkey
          </Button>
        )}
        {status && enrolled && !usedRecovery && (
          showCode ? (
            <form className="flex flex-col gap-2" onSubmit={(ev) => void onRecover(ev)}>
              <Input
                label="Recovery code"
                help="One of the codes you saved when you added your passkey. Each works once."
                autoComplete="one-time-code"
                spellCheck={false}
                mono
                value={code}
                onChange={(ev) => setCode(ev.target.value)}
              />
              <Button type="submit" variant="secondary" loading={busy} disabled={code.trim() === ""}>
                Use this code
              </Button>
            </form>
          ) : (
            <Button variant="ghost" size="sm" onClick={() => setShowCode(true)}>
              Lost your passkey? Use a recovery code
            </Button>
          )
        )}
        <Button variant="ghost" size="sm" iconLeft={LogOut} onClick={() => void onSignOut()}>
          Sign out
        </Button>
      </div>
    </AuthShell>
  );
}
