// LaunchpadMeter: the live usage meter on the right of the launchpad's docked
// split (door A, docs/plans/local-dashboard-first-run-options-2026-11-18.md
// section 8, step 4). It reuses the session cockpit's link resolution (GET
// /api/terminal/session/<token>, 4 s while linking, 15 s once linked, never
// stopping, so a later authoritative correlation re-points it) and the
// session detail read, and shows tokens, cost (est.), model and actions
// ticking. While the terminal installs or starts it shows that state with no
// numbers; numbers appear only once real ones exist (lib/launchpad.ts
// meterPhase / meterShowsNumbers). "More vitals" is the cockpit itself
// (CockpitContent), and "Session details" opens the full detail modal.

import { useMemo, useRef } from "react";
import { AnimatedValue, Button, LiveDot, ToolDot, Tooltip } from "@/components/primitives";
import { CockpitContent } from "@/components/cockpit/CockpitContent";
import { useApi } from "@/lib/useApi";
import { fmtCompact, fmtInt, fmtUSD } from "@/lib/format";
import { toolMeta } from "@/lib/tools";
import { parseLinkError, terminalLinkPath, type TerminalSessionLink } from "@/lib/cockpit";
import {
  COST_BASIS_NOTE,
  METER_PHASE_TEXT,
  meterPhase,
  meterReading,
  meterShowsNumbers,
  type MeterPhase,
  type MeterSession,
  type SplitKind,
} from "@/lib/launchpad";

/** The dot and word each phase shows in the meter's header. */
const PHASE_HEAD: Record<MeterPhase, { word: string; tone: "info" | "success" | "idle"; still: boolean }> = {
  installing: { word: "installing", tone: "info", still: true },
  installed: { word: "installed", tone: "idle", still: true },
  starting: { word: "starting", tone: "info", still: true },
  waiting: { word: "waiting", tone: "info", still: true },
  live: { word: "live", tone: "success", still: false },
  ended: { word: "ended", tone: "idle", still: true },
};

type Props = {
  token: string;
  kind: SplitKind;
  /** The tool id the terminal runs (the install terminal's own label for an install). */
  tool: string;
  /** The terminal's connection status from the dock. */
  status: string | undefined;
  /** Opens the full session detail modal (TerminalSessionModal) for the token. */
  onOpenDetail: () => void;
};

export function LaunchpadMeter({ token, kind, tool, status, onOpenDetail }: Props) {
  const mountMs = useRef<number>(Date.now()).current;
  const isAgent = kind === "agent";
  const correlatedRef = useRef(false);
  const link = useApi<TerminalSessionLink>(isAgent ? terminalLinkPath(token) : null, undefined, [token], {
    refreshMs: correlatedRef.current ? 15000 : 4000,
  });
  const resolved = link.data ?? null;
  const sessionId = resolved?.correlated && resolved.session_id ? resolved.session_id : "";
  correlatedRef.current = sessionId !== "";
  const linkError = useMemo(() => parseLinkError(link.error), [link.error]);
  const session = useApi<MeterSession>(sessionId ? `/api/session/${sessionId}` : null, undefined, [sessionId], {
    refreshMs: 5000,
  });
  const reading = meterReading(session.data);
  const phase = meterPhase({ kind, status, correlated: sessionId !== "", hasActivity: reading.hasActivity });
  const head = PHASE_HEAD[phase];
  const toolId = isAgent ? resolved?.tool || tool : tool.replace(/ install$/, "");
  const label = toolMeta(toolId).label;

  return (
    <div className="flex h-full min-h-0 flex-col" data-testid="launchpad-meter">
      <div className="flex items-center gap-2 border-b border-line-1 px-3 py-2">
        <ToolDot tool={toolId} />
        <span className="min-w-0 truncate text-[12.5px] font-semibold text-fg-0">{isAgent ? "This session" : `${label} install`}</span>
        <span className="ml-auto inline-flex items-center gap-1.5 text-[11px] text-fg-3" data-testid="launchpad-meter-phase">
          <LiveDot tone={head.tone} still={head.still} size="sm" label={head.word} />
          {head.word}
        </span>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto px-3 py-3">
        {meterShowsNumbers(phase, reading.hasActivity) ? (
          <>
            <dl className="grid grid-cols-2 gap-x-3 gap-y-2.5 text-[11px]" data-testid="launchpad-meter-numbers">
              <div>
                <dt className="text-fg-3">Tokens</dt>
                <dd className="text-[16px] font-semibold tabular-nums text-fg-0">
                  <AnimatedValue value={fmtCompact(reading.tokens)} />
                </dd>
              </div>
              <div>
                <dt className="text-fg-3">Cost</dt>
                <dd className="text-[16px] font-semibold tabular-nums text-fg-0">
                  <AnimatedValue value={fmtUSD(reading.costUSD)} />{" "}
                  <Tooltip content={COST_BASIS_NOTE[reading.costBasis]}>
                    <span tabIndex={0} className="align-middle text-[10.5px] font-normal text-fg-3">
                      est.
                    </span>
                  </Tooltip>
                </dd>
              </div>
              <div className="min-w-0">
                <dt className="text-fg-3">Model</dt>
                <dd className="truncate font-mono text-[11.5px] text-fg-1" title={reading.model || undefined}>
                  {reading.model || "not recorded"}
                  {reading.extraModels > 0 && <span className="text-fg-3"> +{reading.extraModels}</span>}
                </dd>
              </div>
              <div>
                <dt className="text-fg-3">Actions</dt>
                <dd className="text-[16px] font-semibold tabular-nums text-fg-0">
                  <AnimatedValue value={fmtInt(reading.actions)} />
                </dd>
              </div>
            </dl>
            <p className="mt-2 text-[10.5px] leading-relaxed text-fg-4">
              The whole session so far. Updates every 5 s.
            </p>
            <div className="mt-2 flex flex-wrap gap-2">
              <Button variant="secondary" size="sm" onClick={onOpenDetail} data-testid="launchpad-meter-detail">
                Session details
              </Button>
            </div>
            <details className="mt-3">
              <summary className="cursor-pointer text-[11px] text-fg-2">More vitals</summary>
              <div className="mt-2">
                <CockpitContent
                  key={sessionId}
                  link={resolved}
                  linkError={linkError}
                  linkLoading={false}
                  mountMs={mountMs}
                />
              </div>
            </details>
          </>
        ) : (
          <p className="text-[12px] leading-relaxed text-fg-2" data-testid="launchpad-meter-waiting">
            {linkError?.code === "remote_view_disabled"
              ? "Per-terminal session view is off for remote viewers."
              : METER_PHASE_TEXT[phase]}
          </p>
        )}
      </div>
    </div>
  );
}
