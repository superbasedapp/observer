import { lazy, Suspense, useEffect, useState, useSyncExternalStore } from "react";
import { useApi } from "@/lib/useApi";
import {
  FIRST_RUN_PATH,
  decideFirstRun,
  firstRunSnapshot,
  subscribeFirstRun,
  type FirstRunResponse,
} from "@/lib/firstRun";
import { noteServerDismissals } from "@/lib/uiDismissals";

// FirstRunHost - the shell-resident half of the first-run capture view
// (T-922). It takes ONE brief read per page load (GET /api/firstrun?brief=1:
// the seen state and the totals, no per-tool probes) to learn the notices
// the owner dismissed on the daemon before the tour may start, and
// lazy-loads the dialog itself (FirstRunModal, its own chunk) only when it
// is open, the HelpDrawer / CommandPalette pattern. Once opened the dialog
// stays mounted so its exit transition plays.
//
// Getting started v2: the dialog no longer opens by itself. The Overview
// Get started panel (components/GetStarted.tsx) is the first-run surface;
// the dialog opens only on demand (Settings > Connected tools, the Tools
// coverage view and the command palette).

const FirstRunModal = lazy(() =>
  import("@/components/FirstRunModal").then((m) => ({ default: m.FirstRunModal })),
);

/** If the brief read has not answered by then, stop holding the tour. */
const DECIDE_TIMEOUT_MS = 6000;

export function FirstRunHost() {
  const ui = useSyncExternalStore(subscribeFirstRun, firstRunSnapshot, firstRunSnapshot);
  const brief = useApi<FirstRunResponse>(ui.decided ? null : FIRST_RUN_PATH, { brief: "1" });

  // The decision, taken once from the first answer, is always "closed"; it
  // only releases the tour. A failed read (a remote viewer, an older
  // daemon) releases it too.
  useEffect(() => {
    if (ui.decided) return;
    if (brief.data) {
      // Before the decision releases the tour: a tour the daemon reports
      // dismissed must not auto-start (WINNODE2 16b).
      noteServerDismissals(brief.data.dismissed, brief.data.confirm_token);
      decideFirstRun(false);
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
