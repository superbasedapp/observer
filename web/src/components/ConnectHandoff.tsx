import { useCallback, useState } from "react";
import { ExternalLink, Globe, Laptop } from "lucide-react";
import { Button, Callout, CopyOnClick, Icon, LiveDot } from "@/components/primitives";
import {
  HANDOFF_RETRY_COMMAND,
  HANDOFF_TEXT,
  handoffTeamLine,
  readNoteDismissed,
  twoDashboardsNote,
  writeNoteDismissed,
  type Handoff,
  type HandoffPhase,
} from "@/lib/connectHandoff";
import type { Account } from "@/lib/getStarted";

// ConnectHandoff renders the installer's hand-off (lib/connectHandoff.ts
// decides it): while the terminal's `observer connect` waits for approval,
// one card says where to approve and that this page updates by itself; when
// the wait ran out, how to try again. It stands in for the Get started panel
// on Overview, so the person sees one prompt, not two.
//
// TwoDashboardsNote is the short note shown once a machine is connected,
// until it is put away in this browser: this local dashboard holds
// everything on this computer, the online one what this machine shares.

export function HandoffCard({ phase, handoff }: { phase: HandoffPhase; handoff: Handoff | null }) {
  if (phase !== "waiting" && phase !== "expired") return null;
  const team = handoffTeamLine(handoff);
  if (phase === "expired") {
    const t = HANDOFF_TEXT.expired;
    return (
      <div data-testid="connect-handoff" data-phase={phase}>
        <Callout tone="warn" title={t.title}>
          <p>{t.line}</p>
          <CopyOnClick value={HANDOFF_RETRY_COMMAND} className="mt-1.5 inline-block">
            <code className="rounded-1 bg-bg-3 px-1.5 py-px font-mono text-[12px] font-semibold text-fg-0">
              {HANDOFF_RETRY_COMMAND}
            </code>
          </CopyOnClick>
        </Callout>
      </div>
    );
  }
  const t = HANDOFF_TEXT.waiting;
  return (
    <section
      role="status"
      aria-live="polite"
      data-testid="connect-handoff"
      data-phase={phase}
      className="rounded-3 border border-accent/30 bg-accent-soft px-4 py-3"
    >
      <div className="flex items-center gap-2">
        <LiveDot tone="accent" label="Connecting" />
        <h2 className="text-[14px] font-semibold text-fg-0">{t.title}</h2>
      </div>
      <p className="mt-1 text-[12.5px] leading-relaxed text-fg-1">{t.line}</p>
      {team && <p className="mt-1 text-[11.5px] text-fg-3">{team}</p>}
    </section>
  );
}

function readStoredDismissed(): boolean {
  try {
    return readNoteDismissed(globalThis.localStorage);
  } catch {
    return false;
  }
}

function storeDismissed(): void {
  try {
    writeNoteDismissed(globalThis.localStorage);
  } catch {
    // Storage unavailable: put away for this page view only.
  }
}

/** useTwoDashboardsNote is the note's put-away state for this browser. */
export function useTwoDashboardsNote(): { dismissed: boolean; dismiss: () => void } {
  const [dismissed, setDismissed] = useState(readStoredDismissed);
  const dismiss = useCallback(() => {
    setDismissed(true);
    storeDismissed();
  }, []);
  return { dismissed, dismiss };
}

export function TwoDashboardsNote({ account, onDismiss }: { account: Account; onDismiss: () => void }) {
  const n = twoDashboardsNote(account);
  return (
    <section
      aria-labelledby="sb-two-dashboards-title"
      data-testid="two-dashboards-note"
      className="rounded-3 border border-line-2 bg-bg-1 px-4 py-3"
    >
      <div className="flex items-start justify-between gap-2">
        <h2 id="sb-two-dashboards-title" className="text-[13px] font-semibold text-fg-0">
          {n.title}
        </h2>
        <Button size="sm" variant="ghost" onClick={onDismiss}>
          Got it
        </Button>
      </div>
      <div className="mt-2 grid gap-3 sm:grid-cols-2">
        <div className="flex min-w-0 gap-2">
          <Icon icon={Laptop} size="sm" className="mt-0.5 shrink-0 text-fg-3" />
          <div className="min-w-0">
            <div className="text-[12px] font-semibold text-fg-1">{n.local.label}</div>
            <p className="text-[11.5px] leading-relaxed text-fg-3">{n.local.role}</p>
          </div>
        </div>
        <div className="flex min-w-0 gap-2">
          <Icon icon={Globe} size="sm" className="mt-0.5 shrink-0 text-fg-3" />
          <div className="min-w-0">
            <div className="truncate text-[12px] font-semibold text-fg-1">{n.online.label}</div>
            <p className="text-[11.5px] leading-relaxed text-fg-3">{n.online.role}</p>
            {n.online.url && (
              <a
                href={n.online.url}
                target="_blank"
                rel="noreferrer noopener"
                data-testid="two-dashboards-open-online"
                className="mt-1 inline-flex items-center gap-1 text-[11.5px] font-medium text-accent hover:underline"
              >
                {n.online.button}
                <Icon icon={ExternalLink} size={11} />
              </a>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
