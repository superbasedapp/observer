import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@shared/primitives/Button";
import { Input } from "@shared/primitives/Input";
import { ApiError, lookupConnectCode } from "../api";
import { AuthShell } from "../components/AuthShell";
import { CONNECT_CODE_KEY } from "../lib/connectModel";

// ConnectEntry - the verify_url page, /connect (Getting started v2): for a
// machine with no browser, `observer connect --no-browser` prints this
// address and a code; the person types the code here and lands on the
// machine's approval page. A ?code= in the link (or the one kept across
// sign-in) prefills the field. Code entry is attempt-limited on the server.

/** initialCode reads ?code= or the code kept across sign-in. */
function initialCode(): string {
  const fromLink = new URLSearchParams(window.location.search).get("code");
  if (fromLink) return fromLink;
  try {
    const kept = sessionStorage.getItem(CONNECT_CODE_KEY) ?? "";
    sessionStorage.removeItem(CONNECT_CODE_KEY);
    return kept;
  } catch {
    return "";
  }
}

const ERROR_TEXT: Readonly<Record<string, string>> = {
  code_invalid: "That is not a connect code. It looks like KTRW-4821.",
  code_not_found: "No machine is waiting with that code. Check it, or run observer connect again.",
  rate_limited: "Too many tries. Wait a few minutes and try again.",
};

export function ConnectEntry() {
  const navigate = useNavigate();
  const [code, setCode] = useState(initialCode);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { request_id } = await lookupConnectCode(code);
      navigate("/connect/" + encodeURIComponent(request_id));
    } catch (err) {
      const c = err instanceof ApiError ? err.code : "";
      setError(ERROR_TEXT[c] ?? (err instanceof Error ? err.message : "Something went wrong. Try again."));
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title="Connect a machine"
      intro={<p>Type the code your terminal shows after observer connect.</p>}
    >
      <form className="flex flex-col gap-3" onSubmit={onSubmit} noValidate>
        <Input
          label="Code"
          name="connect-code"
          mono
          autoComplete="off"
          spellCheck={false}
          placeholder="KTRW-4821"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          disabled={busy}
          error={error ?? undefined}
        />
        <Button type="submit" variant="primary" loading={busy} disabled={code.trim() === ""}>
          Continue
        </Button>
      </form>
    </AuthShell>
  );
}
