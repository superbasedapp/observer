// The staff sign-in: a passkey assertion (WebAuthn, user verification
// required) is the only way a staff session starts. A first passkey is
// registered with a one-time code the operator mints (`observer-cloud staff
// enrol`); no web path creates a staff member.

import { useState } from "react";
import { KeyRound } from "lucide-react";
import { AuthShell } from "@shared/components/auth/AuthShell";
import { Button } from "@shared/primitives/Button";
import { Callout } from "@shared/primitives/Callout";
import { Input } from "@shared/primitives/Input";
import { StaffApiError, registerPasskey, signInWithPasskey } from "../api";
import { passkeyErrorText } from "../lib/webauthn";

function errorText(e: unknown): string {
  if (e instanceof StaffApiError) {
    if (e.code === "not_available") return "Passkey sign-in is not available on this server.";
    if (e.code === "webauthn_failed") return "That passkey did not verify. Use a passkey registered for this staff console.";
    return e.message;
  }
  return passkeyErrorText(e);
}

export function StaffSignIn({ onSignedIn }: { onSignedIn: () => Promise<void> | void }) {
  const [mode, setMode] = useState<"signin" | "register">("signin");
  const [code, setCode] = useState("");
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [registered, setRegistered] = useState(false);

  async function signIn() {
    setBusy(true);
    setError(null);
    try {
      await signInWithPasskey(navigator.credentials);
      await onSignedIn();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function register() {
    setBusy(true);
    setError(null);
    try {
      await registerPasskey(navigator.credentials, code.trim(), label.trim());
      setRegistered(true);
      setMode("signin");
      setCode("");
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      subtitle="Staff console"
      title={mode === "signin" ? "Sign in with your passkey" : "Register a passkey"}
      intro={
        mode === "signin"
          ? "Staff only. Every session starts with a passkey, and every change asks for it again after 15 minutes."
          : "Use the one-time enrolment code the operator gave you. It works once and expires in 30 minutes."
      }
    >
      <div className="flex flex-col gap-4">
        {registered && (
          <Callout tone="success" title="Passkey registered">
            Sign in with it now.
          </Callout>
        )}
        {error && (
          <Callout tone="danger" title="Not signed in">
            {error}
          </Callout>
        )}
        {mode === "signin" ? (
          <>
            <Button variant="primary" iconLeft={KeyRound} onClick={() => void signIn()} loading={busy}>
              Sign in with passkey
            </Button>
            <button type="button" className="text-[12px] text-accent underline-offset-2 hover:underline" onClick={() => setMode("register")}>
              I have an enrolment code
            </button>
          </>
        ) : (
          <form
            className="flex flex-col gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (code.trim() !== "") void register();
            }}
          >
            <Input label="Enrolment code" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" mono />
            <Input
              label="Passkey label"
              help="Optional, e.g. the device it lives on."
              value={label}
              maxLength={100}
              onChange={(e) => setLabel(e.target.value)}
            />
            <Button type="submit" variant="primary" iconLeft={KeyRound} loading={busy} disabled={code.trim() === ""}>
              Register passkey
            </Button>
            <button type="button" className="text-[12px] text-accent underline-offset-2 hover:underline" onClick={() => setMode("signin")}>
              Back to sign-in
            </button>
          </form>
        )}
      </div>
    </AuthShell>
  );
}
