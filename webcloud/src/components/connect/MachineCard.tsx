import { ExternalLink, Laptop } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Card } from "@shared/primitives/Card";
import { LiveDot } from "@shared/primitives/LiveDot";
import { CONNECT_FIRST, type HomeMachineView, type InstallTabId } from "../../lib/connectModel";
import { InstallCommands } from "./InstallCommands";

// MachineCard - the account home's machine card (Getting started v2). With
// no machine yet it is "Connect your first machine": the commands and the
// live "Waiting for a machine..." line (the page polls). Once a machine
// connects it flips to "Connected: <machine>" with Open your dashboard. The
// decision is connectModel's homeMachineView; this file renders it.

export interface MachineCardProps {
  view: HomeMachineView;
  /** initialTab is the install tab this browser opens on. */
  initialTab: InstallTabId;
}

export function MachineCard({ view, initialTab }: MachineCardProps) {
  if (view.state === "loading") {
    return null;
  }
  if (view.showInstall) {
    return (
      <Card title={CONNECT_FIRST.title} icon={Laptop} sub={CONNECT_FIRST.lead}>
        <div className="flex max-w-[680px] flex-col gap-3">
          <InstallCommands initial={initialTab} />
          <p className="text-[12px] leading-snug text-fg-2">{CONNECT_FIRST.after}</p>
          <p role="status" aria-live="polite" className="inline-flex items-center gap-2 text-[12px] text-fg-3">
            <LiveDot />
            {view.headline}
          </p>
        </div>
      </Card>
    );
  }
  return (
    <Card title="Your machines" icon={Laptop}>
      <div className="flex flex-col gap-3">
        <p role="status" aria-live="polite" className="text-[13px] font-semibold text-fg-0">
          {view.headline}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          {view.openUrl && (
            <Button variant="primary" size="sm" iconRight={ExternalLink} href={view.openUrl} target="_blank" rel="noopener">
              Open your dashboard
            </Button>
          )}
        </div>
        <details className="text-[12px] text-fg-2">
          <summary className="cursor-pointer font-medium text-accent">Connect another machine</summary>
          <div className="mt-2 flex max-w-[680px] flex-col gap-2">
            <p>{CONNECT_FIRST.lead}</p>
            <InstallCommands initial={initialTab} />
          </div>
        </details>
      </div>
    </Card>
  );
}
