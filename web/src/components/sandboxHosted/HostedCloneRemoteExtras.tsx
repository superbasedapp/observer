// HostedCloneRemoteExtras.tsx is the New Terminal dialog's clone-remote
// field area for a hosted row (lane CLONE2, decision SBXD-5 and the smaller
// item "Clone consent inline"): where the repository is cloned (a
// per-launch choice while the setting is Automatically), the daemon's one
// line about where this URL clones and why, and, when the launch would be
// refused for a missing or changed consent of that URL, the consent screen
// inline with an Agree button that posts the Hosted sandboxes card's own
// consent route (its confirm token), so Start needs no trip to Settings.
// Every decision is a pure helper in lib/hostedClone.ts.

import { useEffect, useState } from "react";
import { HelpTooltip } from "@shared/primitives/HelpTooltip";
import type { HostedStatusResponse } from "@/components/SandboxHostedStatus";
import { HostedConsentAsk } from "@/components/sandboxHosted/HostedConsentAsk";
import { fetchJSON } from "@/lib/api";
import { errorNote } from "@/lib/needsSetting";
import {
  cloneConsentBody,
  cloneConsentQuery,
  cloneConsentState,
  cloneWhereChoice,
  cloneWhereOptions,
  type CloneConsentState,
  type HostedConsentProvider,
} from "@/lib/hostedClone";
import type { SandboxBackendAvail } from "@/lib/types";

/** CONSENT_CHECK_DELAY_MS waits for typing to settle before the daemon is asked (each answer may list the repository). */
const CONSENT_CHECK_DELAY_MS = 700;

export function HostedCloneRemoteExtras({
  row,
  url,
  folder,
  picked,
  onPick,
  refreshKey,
  onAgreed,
  urlProblem = null,
}: {
  /** row is the chosen hosted row. */
  row: SandboxBackendAvail;
  /** url is the remote URL as typed. */
  url: string;
  /** folder is the launch folder the agreement is recorded for. */
  folder: string;
  /** picked is the person's clone location choice ("" for the setting). */
  picked: string;
  onPick: (v: string) => void;
  /** refreshKey asks again (a Start refused for the consent bumps it). */
  refreshKey: number;
  /** onAgreed runs once the agreement is recorded. */
  onAgreed: () => void;
  /**
   * urlProblem is the dialog's plain sentence for an address the launch
   * would refuse (lib/cloneURL.ts): the daemon is not asked for a screen
   * of such an address, so no raw refusal shows here.
   */
  urlProblem?: string | null;
}) {
  const view = row.clone_where;
  const options = cloneWhereOptions(view);
  const choice = cloneWhereChoice(view, picked);
  const [settledURL, setSettledURL] = useState(url.trim());
  useEffect(() => {
    const t = setTimeout(() => setSettledURL(url.trim()), CONSENT_CHECK_DELAY_MS);
    return () => clearTimeout(t);
  }, [url]);
  const query = urlProblem ? null : cloneConsentQuery({ provider: row.id, folder, url: settledURL, choice });
  const queryKey = query ? JSON.stringify(query) : "";
  const [answer, setAnswer] = useState<HostedStatusResponse | null>(null);
  const [reload, setReload] = useState(0);
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
      .catch(() => {
        // An older daemon or a hosted module that is off: nothing to say.
        if (!cancelled) setAnswer(null);
      });
    return () => {
      cancelled = true;
    };
  }, [queryKey, reload, refreshKey]);
  const provider = (answer?.providers ?? []).find((p) => p.id === row.id) as HostedConsentProvider | undefined;
  const state: CloneConsentState = settledURL === url.trim() ? cloneConsentState(provider) : { kind: "none" };

  async function agree() {
    if (!answer?.confirm_token) return;
    setBusy(true);
    setErr(null);
    try {
      await fetchJSON("/api/terminal/sandbox/hosted/consent", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Observer-Confirm": answer.confirm_token },
        body: JSON.stringify(cloneConsentBody({ provider: row.id, folder, url: settledURL, choice })),
      });
      setReload((n) => n + 1);
      onAgreed();
    } catch (e) {
      setErr(errorNote(e).text);
    } finally {
      setBusy(false);
    }
  }

  const screenWhere = provider?.screen?.clone_where ?? "";
  return (
    <div className="mt-2 space-y-1" data-testid="hosted-clone-remote">
      {options.length > 0 && (
        <>
          <label htmlFor="new-terminal-sandbox-clone-where" className="block text-[11px] font-medium text-fg-2">
            Where to clone it
            <HelpTooltip
              technical
              subject="the clone location"
              content={`[terminal.sandbox.hosted].clone_where = ${view?.setting ?? "auto"}; the launch sends workspace_clone_where when it chooses another`}
              className="ml-1 align-middle"
            />
          </label>
          <select
            id="new-terminal-sandbox-clone-where"
            value={choice}
            disabled={view?.fixed}
            onChange={(e) => onPick(e.target.value)}
            className="w-full rounded-2 border bg-bg-0 px-2 py-1.5 text-[12px] text-fg-1"
          >
            {options.map((o) => (
              <option key={o.value} value={o.value} disabled={o.disabled} title={o.note ?? o.label}>
                {o.label}
                {o.disabled ? " (not available)" : ""}
              </option>
            ))}
          </select>
          <p className="text-[10.5px] leading-relaxed text-fg-3">
            {view?.fixed ? "Set in Terminals > Settings > Hosted sandboxes. " : ""}
            {view?.rule}
          </p>
          {options.find((o) => o.value === "box" && o.disabled)?.note && (
            <p className="text-[10.5px] leading-relaxed text-fg-3">
              Inside the box is not available now: {options.find((o) => o.value === "box")?.note}
            </p>
          )}
        </>
      )}
      {state.kind === "error" && <p className="text-[10.5px] leading-relaxed text-warn">{state.message}</p>}
      {(state.kind === "agreed" || state.kind === "ask") && state.where && (
        <p className="text-[10.5px] leading-relaxed text-fg-2">This repository is {state.where}.</p>
      )}
      {state.kind === "ask" && (
        <HostedConsentAsk
          state={state}
          providerName={row.label}
          repository={settledURL}
          cloneWhere={screenWhere}
          busy={busy}
          canAgree={!!answer?.confirm_token}
          err={err}
          onAgree={() => void agree()}
        />
      )}
    </div>
  );
}
