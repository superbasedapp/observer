// HostedUploadConsent.tsx is the New Terminal dialog's inline consent for a
// hosted row that uploads the launch folder (the live tree, or a copy),
// shown when Start was refused because the agreement is missing or no
// longer matches (the live-run report 2026-11-18: the upload scope changed
// and Start failed with the daemon's raw sentence). It reads the consent
// screen the Hosted sandboxes card reads (GET /api/terminal/sandbox/hosted
// for this folder and row), shows what changed and what the launch sends
// now, and Agree posts the card's own consent route with its confirm token;
// the dialog then starts the launch again. Decisions live in
// lib/hostedClone.ts.

import { useEffect, useState } from "react";
import type { HostedStatusResponse } from "@/components/SandboxHostedStatus";
import { HostedConsentAsk } from "@/components/sandboxHosted/HostedConsentAsk";
import { fetchJSON } from "@/lib/api";
import { cloneConsentState, type CloneConsentState, type HostedConsentProvider } from "@/lib/hostedClone";
import { errorNote } from "@/lib/needsSetting";
import type { SandboxBackendAvail } from "@/lib/types";

/**
 * uploadConsentQuery is the screen's query for one row and folder (no
 * repository: the upload of the folder), or null without a folder.
 */
export function uploadConsentQuery(provider: string, folder: string): Record<string, string> | null {
  return provider && folder ? { workspace: folder, provider } : null;
}

/** HostedUploadConsentView renders one answer; split out so a render test needs no fetch. */
export function HostedUploadConsentView({
  row,
  state,
  busy,
  canAgree,
  err,
  onAgree,
}: {
  row: Pick<SandboxBackendAvail, "label">;
  state: CloneConsentState;
  busy: boolean;
  canAgree: boolean;
  err: string | null;
  onAgree: () => void;
}) {
  if (state.kind === "error") return <p className="mt-2 text-[10.5px] leading-relaxed text-warn">{state.message}</p>;
  if (state.kind === "agreed") return <p className="mt-2 text-[10.5px] leading-relaxed text-fg-2">You have agreed to what this launch sends. Press Start again.</p>;
  if (state.kind !== "ask") return null;
  return (
    <div className="mt-2">
      <HostedConsentAsk
        state={state}
        providerName={row.label}
        repository=""
        cloneWhere=""
        busy={busy}
        canAgree={canAgree}
        err={err}
        onAgree={onAgree}
        testId="hosted-upload-consent"
      />
    </div>
  );
}

export function HostedUploadConsent({
  row,
  folder,
  refreshKey,
  onAgreed,
}: {
  row: SandboxBackendAvail;
  /** folder is the launch folder the agreement is recorded for. */
  folder: string;
  /** refreshKey asks again (a Start refused for the consent bumps it). */
  refreshKey: number;
  /** onAgreed runs once the agreement is recorded. */
  onAgreed: () => void;
}) {
  const query = uploadConsentQuery(row.id, folder);
  const queryKey = query ? JSON.stringify(query) : "";
  const [answer, setAnswer] = useState<HostedStatusResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (!queryKey) {
      setAnswer(null);
      return;
    }
    let cancelled = false;
    fetchJSON<HostedStatusResponse>("/api/terminal/sandbox/hosted", JSON.parse(queryKey) as Record<string, string>)
      .then((d) => {
        if (!cancelled) setAnswer(d);
      })
      .catch((e) => {
        if (!cancelled) {
          setAnswer(null);
          setErr(errorNote(e).text);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [queryKey, refreshKey]);
  const provider = (answer?.providers ?? []).find((p) => p.id === row.id) as HostedConsentProvider | undefined;

  async function agree() {
    if (!answer?.confirm_token || !query) return;
    setBusy(true);
    setErr(null);
    try {
      await fetchJSON("/api/terminal/sandbox/hosted/consent", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Observer-Confirm": answer.confirm_token },
        body: JSON.stringify({ provider: row.id, workspace: folder }),
      });
      onAgreed();
    } catch (e) {
      setErr(errorNote(e).text);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <HostedUploadConsentView row={row} state={cloneConsentState(provider)} busy={busy} canAgree={!!answer?.confirm_token} err={err} onAgree={() => void agree()} />
      {!provider && err && <p className="mt-2 text-[10.5px] leading-relaxed text-warn">{err}</p>}
    </>
  );
}
