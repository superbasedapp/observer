import clsx from "clsx";
import { ExternalLink } from "lucide-react";
import { Button, Icon, LiveDot } from "@/components/primitives";
import { connectLine, safeOpenURL } from "@/lib/getStarted";
import type { ConnectFlow } from "@/lib/useConnectFlow";

// ConnectProgressBlock shows the connect flow in plain words (Getting
// started v2): "Waiting for approval in your browser... code KTRW-4821",
// with the approval page link for when the browser blocked the new tab,
// the code-entry address for a machine with no browser, and Stop. After
// the flow ends it shows how it ended, and the start or cancel request's
// own error (a refusal) when there is one. Renders nothing while idle.

const TONE_CLASS: Record<string, string> = {
  accent: "border-accent/30 bg-accent-soft text-fg-1",
  success: "border-success/30 bg-success-soft text-success",
  warn: "border-warn/40 bg-warn-soft text-warn",
  danger: "border-danger/30 bg-danger-soft text-danger",
  neutral: "border-line-2 bg-bg-2 text-fg-2",
};

export function ConnectProgressBlock({ flow, className }: { flow: ConnectFlow; className?: string }) {
  const p = flow.progress;
  const line = connectLine(p);
  const approveUrl = safeOpenURL(p?.approve_url);
  const verifyUrl = safeOpenURL(p?.verify_url);
  if (flow.error) {
    return (
      <div role="alert" className={clsx("rounded-2 border px-3 py-2 text-[11.5px]", TONE_CLASS.danger, className)}>
        {flow.error}
      </div>
    );
  }
  if (!p || !line.text) return null;
  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="connect-progress"
      data-state={p.state}
      className={clsx("space-y-1.5 rounded-2 border px-3 py-2 text-[11.5px]", TONE_CLASS[line.tone], className)}
    >
      <div className="flex flex-wrap items-center gap-2">
        {flow.active && <LiveDot tone="accent" label="Connecting" />}
        <span className="font-medium">{line.text}</span>
        {line.showCode && p.user_code && (
          <span className="text-fg-2">
            Code <code className="rounded-1 bg-bg-3 px-1.5 py-px font-mono text-[12px] font-semibold text-fg-0">{p.user_code}</code>
          </span>
        )}
      </div>
      {flow.active && (
        <div className="flex flex-wrap items-center gap-2 text-fg-3">
          {approveUrl && (
            <Button size="sm" variant="soft" iconLeft={ExternalLink} onClick={flow.openApproval}>
              Open approval page
            </Button>
          )}
          <Button size="sm" variant="ghost" onClick={() => void flow.cancel()} disabled={flow.busy}>
            Stop
          </Button>
          {verifyUrl && p.user_code && (
            <span className="text-[10.5px]">
              On another device, go to{" "}
              <a href={verifyUrl} target="_blank" rel="noreferrer noopener" className="text-accent hover:underline">
                the approval page
                <Icon icon={ExternalLink} size={10} className="ml-0.5 inline" />
              </a>{" "}
              and enter the code.
            </span>
          )}
        </div>
      )}
    </div>
  );
}
