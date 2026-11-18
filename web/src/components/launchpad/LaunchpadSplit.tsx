// LaunchpadSplit: the launchpad's docked split (door A, docs/plans/
// local-dashboard-first-run-options-2026-11-18.md section 8, step 4). A
// launch from "Start a coding agent" (useLaunchDock().openNewTerminalFor)
// opens here: the terminal docked on the left, the live usage meter on the
// right; on a narrow screen the meter stacks under the terminal.
//
// The terminal is NOT remounted: the dock stays the only owner of the live
// LaunchTerminal and moves its host element into the left pane through the
// same cell seam the Terminal Workspace grid uses (registerWorkspaceCell),
// so undocking hands the very same terminal back to the normal floating
// view. Default export for React.lazy (the meter pulls in the cockpit).

import { useEffect, useRef } from "react";
import { Maximize2, Minus } from "lucide-react";
import { Button } from "@/components/primitives";
import { LaunchpadMeter } from "@/components/launchpad/LaunchpadMeter";
import type { SplitKind } from "@/lib/launchpad";

type Props = {
  token: string;
  kind: SplitKind;
  tool: string;
  status: string | undefined;
  /** The dock's cell seam: the terminal's host moves into el (null hands it back). */
  registerCell: (token: string, el: HTMLElement | null) => void;
  /** Hand the terminal back to the normal floating terminal view. */
  onUndock: () => void;
  /** Park the terminal as a dock pill. */
  onMinimize: () => void;
  /** Open the full session detail modal for the token. */
  onOpenDetail: () => void;
};

export default function LaunchpadSplit({ token, kind, tool, status, registerCell, onUndock, onMinimize, onOpenDetail }: Props) {
  const cellRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const el = cellRef.current;
    if (el) registerCell(token, el);
    return () => registerCell(token, null);
  }, [token, registerCell]);

  return (
    <div
      className="fixed inset-0 z-[80] flex items-stretch justify-center bg-black/50 p-0 md:p-6"
      role="dialog"
      aria-modal="true"
      aria-label="Terminal and live usage"
      data-testid="launchpad-split"
    >
      <div className="flex h-full w-full max-w-[1500px] flex-col overflow-hidden border border-line-2 bg-bg-1 shadow-xl md:rounded-3">
        <div className="flex items-center gap-2 border-b border-line-1 px-3 py-1.5">
          <span className="text-[11.5px] text-fg-3">Terminal and live usage</span>
          <span className="ml-auto flex gap-1.5">
            <Button variant="ghost" size="sm" iconLeft={Maximize2} onClick={onUndock} data-testid="launchpad-undock">
              Undock
            </Button>
            <Button variant="ghost" size="sm" iconLeft={Minus} onClick={onMinimize} data-testid="launchpad-minimize">
              Minimize
            </Button>
          </span>
        </div>
        <div className="flex min-h-0 flex-1 flex-col md:flex-row">
          <div ref={cellRef} className="flex min-h-[55%] min-w-0 flex-1 flex-col md:min-h-0" data-testid="launchpad-terminal-cell" />
          <aside className="max-h-[45%] min-h-0 border-t border-line-1 md:max-h-none md:w-[340px] md:shrink-0 md:border-l md:border-t-0">
            <LaunchpadMeter token={token} kind={kind} tool={tool} status={status} onOpenDetail={onOpenDetail} />
          </aside>
        </div>
      </div>
    </div>
  );
}
