import { useNavigate } from "react-router-dom";
import { Play } from "lucide-react";
import { Icon, LiveDot, Tooltip } from "@/components/primitives";
import { useOptionalLaunchDock } from "@/components/LaunchDock";
import { useMediaQuery } from "@/lib/useMediaQuery";
import { useRemoteTerminalGate } from "@/lib/remoteTerminal";
import { useConnectHandoff } from "@/lib/useConnectHandoff";
import { useAccount, useConnectFlow } from "@/lib/useConnectFlow";
import { RIBBON_TEXT, chipView, startToolFor, stripOpen } from "@/lib/ribbon";
import { useLiveRibbon, useRibbonMinimised } from "./useLiveRibbon";

// RibbonChip is the live ribbon's top-bar form (§8.2): "No agent running ·
// Start one" when nothing is live, "N live" when the strip is folded away or
// the screen is phone-width. lib/ribbon.ts CHIP_RULES decides; this renders.
// "Start one" opens New terminal (owner-local: a remote viewer without the
// terminal capability sees the words without the button).

/** The strip needs at least the sm breakpoint; below it the chip carries it. */
export const RIBBON_WIDE_QUERY = "(min-width: 640px)";

export function RibbonChip() {
  const ribbon = useLiveRibbon();
  const [minimised, setMinimised] = useRibbonMinimised();
  const wide = useMediaQuery(RIBBON_WIDE_QUERY);
  const flow = useConnectFlow();
  const { account } = useAccount(flow);
  const handoff = useConnectHandoff(account);
  const gate = useRemoteTerminalGate();
  const dock = useOptionalLaunchDock();
  const navigate = useNavigate();
  const canLaunch = !!dock && (!gate.isRemote || gate.allowTerminal === true);
  const view = chipView({
    off: ribbon.off,
    handoffWaiting: handoff.phase === "waiting",
    live: ribbon.live,
    stripOpen: stripOpen({ off: ribbon.off, live: ribbon.live, minimised, wide }),
    canLaunch,
  });
  if (view.kind === "hidden") return null;

  if (view.kind === "idle") {
    const start = () => {
      if (!dock) return;
      const tool = startToolFor(ribbon.perTool);
      if (tool) dock.openNewTerminalFor(tool);
      else dock.openNewTerminal();
    };
    return (
      <span
        data-testid="ribbon-chip"
        data-state="idle"
        className="flex h-6 shrink-0 items-center gap-1.5 rounded-pill border border-line-2 bg-bg-2 px-2 text-[10.5px] text-fg-3"
      >
        <LiveDot tone="idle" still size="sm" />
        <span className="hidden md:inline">{view.text}</span>
        {view.action && (
          <>
            <span aria-hidden className="hidden text-fg-4 md:inline">
              ·
            </span>
            <button
              type="button"
              onClick={start}
              data-testid="ribbon-start"
              aria-label={`${view.text}. ${view.action}`}
              className="inline-flex items-center gap-1 font-medium text-accent hover:text-accent-strong focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]"
            >
              <Icon icon={Play} size={10} />
              {view.action}
            </button>
          </>
        )}
      </span>
    );
  }

  // Live and folded: on a wide screen it unfolds the strip; on a phone the
  // strip cannot show, so it opens the Live page.
  const open = () => (wide ? setMinimised(false) : navigate("/live"));
  return (
    <Tooltip content={wide ? RIBBON_TEXT.expand : RIBBON_TEXT.openLive}>
      <button
        type="button"
        onClick={open}
        data-testid="ribbon-chip"
        data-state="live"
        className="flex h-6 shrink-0 items-center gap-1.5 rounded-pill border border-success/30 bg-success-soft px-2 text-[10.5px] font-medium text-success hover:bg-success/20 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]"
      >
        <LiveDot tone="success" size="sm" />
        {view.text}
      </button>
    </Tooltip>
  );
}
