import { lazy, Suspense, useEffect, useState, useSyncExternalStore } from "react";
import { useApi } from "@/lib/useApi";
import {
  FIRST_RUN_PATH,
  closedThisVisit,
  decideFirstRun,
  firstRunSnapshot,
  shouldAutoOpen,
  subscribeFirstRun,
  type FirstRunResponse,
} from "@/lib/firstRun";
import { noteServerDismissals } from "@/lib/uiDismissals";

// FirstRunHost - the shell-resident half of the first-run capture view
// (T-922). It takes ONE brief read per page load (GET /api/firstrun?brief=1:
// the seen state and the totals, no per-tool probes), decides once whether
// the dialog opens by itself, and lazy-loads the dialog itself
// (FirstRunModal, its own chunk) only when it is open, the HelpDrawer /
// CommandPalette pattern. Once opened the dialog stays mounted so its exit
// transition plays.

const FirstRunModal = lazy(() =>
  import("@/components/FirstRunModal").then((m) => ({ default: m.FirstRunModal })),
);

/** If the brief read has not answered by then, stop holding the tour. */
const DECIDE_TIMEOUT_MS = 6000;

function visitStorage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.sessionStorage;
  } catch {
    return null;
  }
}

export function FirstRunHost() {
  const ui = useSyncExternalStore(subscribeFirstRun, firstRunSnapshot, firstRunSnapshot);
  const brief = useApi<FirstRunResponse>(ui.decided ? null : FIRST_RUN_PATH, { brief: "1" });

  // The auto-open decision, taken once from the first answer. A failed read
  // (a remote viewer, an older daemon) never opens anything.
  useEffect(() => {
    if (ui.decided) return;
    if (brief.data) {
      // Before the decision releases the tour: a tour the daemon reports
      // dismissed must not auto-start (WINNODE2 16b).
      noteServerDismissals(brief.data.dismissed, brief.data.confirm_token);
      decideFirstRun(shouldAutoOpen(brief.data, closedThisVisit(visitStorage())));
    } else if (brief.error) {
      decideFirstRun(false);
    }
  }, [ui.decided, brief.data, brief.error]);
  useEffect(() => {
    if (ui.decided) return;
    const t = window.setTimeout(() => decideFirstRun(false), DECIDE_TIMEOUT_MS);
    return () => window.clearTimeout(t);
  }, [ui.decided]);

  const [everOpened, setEverOpened] = useState(false);
  useEffect(() => {
    if (ui.open) setEverOpened(true);
  }, [ui.open]);

  if (!everOpened && !ui.open) return null;
  return (
    <Suspense fallback={null}>
      <FirstRunModal open={ui.open} />
    </Suspense>
  );
}
