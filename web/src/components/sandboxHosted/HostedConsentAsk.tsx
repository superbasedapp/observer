// HostedConsentAsk.tsx is the New Terminal dialog's inline hosted consent
// card: the consent screen's lines (what this launch sends, as the daemon
// computed it now), a heading that says when an earlier agreement no longer
// matches and what changed, and the Agree button. Pure presentation: the
// caller (HostedCloneRemoteExtras for a clone of a URL, HostedUploadConsent
// for an upload of the folder) reads the screen and posts the agreement.

import { ConfirmButton } from "@/components/primitives";
import { consentWording } from "@/components/SandboxHostedStatus";
import type { CloneConsentState } from "@/lib/hostedClone";

/** consentAskHeading is the card's first line for the state. */
export function consentAskHeading(state: Extract<CloneConsentState, { kind: "ask" }>): string {
  if (!state.again) return "Agree to what this launch sends before it starts:";
  return state.changed
    ? `What leaves this machine changed since you agreed (${state.changed}). Agree again to start:`
    : "What leaves this machine changed since you agreed. Agree again to start:";
}

export function HostedConsentAsk({
  state,
  providerName,
  repository,
  cloneWhere,
  busy,
  canAgree,
  err,
  onAgree,
  testId = "hosted-clone-consent",
}: {
  state: Extract<CloneConsentState, { kind: "ask" }>;
  /** providerName is the row's label (the confirm wording names it). */
  providerName: string;
  /** repository is the clone URL ("" for an upload of the folder). */
  repository: string;
  /** cloneWhere is where the screen says the clone runs ("" for none). */
  cloneWhere: string;
  busy: boolean;
  /** canAgree: the confirm token is in hand. */
  canAgree: boolean;
  err: string | null;
  onAgree: () => void;
  testId?: string;
}) {
  return (
    <div className="space-y-1 rounded-2 border border-line-2 bg-bg-1 p-2" data-testid={testId}>
      <p className="text-[11px] font-medium text-fg-1">{consentAskHeading(state)}</p>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-[10.5px]">
        {state.screen.lines.map((l) => (
          <div key={l.label} className="contents">
            <dt className="text-fg-3">{l.label}</dt>
            <dd className="text-fg-1">{l.value}</dd>
          </div>
        ))}
      </dl>
      <ConfirmButton
        size="sm"
        variant="soft"
        armedVariant="danger"
        requireConfirm
        disabled={busy || !canAgree}
        onConfirm={onAgree}
        {...consentWording(providerName, repository, cloneWhere)}
      >
        {busy ? "recording…" : "Agree"}
      </ConfirmButton>
      {err && <p className="text-[10.5px] text-bad">{err}</p>}
    </div>
  );
}
