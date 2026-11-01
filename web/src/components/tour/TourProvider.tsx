import { useCallback, useMemo, useSyncExternalStore, type ReactNode } from "react";
import { TourProvider as SharedTourProvider } from "@shared/components/tour/TourProvider";
import { TOUR_STEPS } from "@/lib/tour";
import { NAV_ITEMS } from "@/lib/nav";
import { useGovernanceVisibility } from "@/lib/governance";
import { hiddenNavIds, withoutHiddenPaths } from "@/lib/visibility";
import { firstRunSnapshot, subscribeFirstRun, tourHeld } from "@/lib/firstRun";
import { dismissalsSnapshot, isDismissed, subscribeDismissals } from "@/lib/uiDismissals";
import { useDismissNotice } from "@/lib/useDismissNotice";

// The node dashboard's tour adapter. The provider and overlay live in
// shared/components/tour (T-447, shared with the org dashboard); this file
// owns only what is the node's: its steps, filtered to the pages this
// machine's organization did not hide, and its completion key.
export { useTour, type TourContextValue } from "@shared/components/tour/TourProvider";

export function TourProvider({ children }: { children: ReactNode }) {
  // The tour never walks to a page this machine's organization hid (the
  // resolved visibility, lib/visibility.ts): its anchor would not exist and
  // the route would render the managed notice.
  // Fails closed until the posture is known (Sol A4-05).
  const { gov } = useGovernanceVisibility();
  const steps = useMemo(
    () => withoutHiddenPaths(TOUR_STEPS, (s) => s.path, hiddenNavIds(gov), NAV_ITEMS),
    [gov],
  );
  // The first-visit auto-start waits for the first-run capture view (T-922,
  // components/FirstRunModal.tsx): until it has decided whether to open, and
  // while it is open. The shared provider re-arms its auto-start when this
  // flips back, so a fresh install sees the capture view, then the tour.
  const firstRun = useSyncExternalStore(subscribeFirstRun, firstRunSnapshot, firstRunSnapshot);
  // A tour finished or skipped is also kept on the daemon, so it stays
  // dismissed where this browser's own storage does not persist (WINNODE2
  // 16b). The first-run read reports it before the auto-start is released.
  useSyncExternalStore(subscribeDismissals, dismissalsSnapshot, dismissalsSnapshot);
  const dismissNotice = useDismissNotice();
  const onComplete = useCallback(() => dismissNotice("tour"), [dismissNotice]);
  return (
    <SharedTourProvider
      steps={steps}
      storageKey="sb_tour_completed"
      autoStart={!tourHeld(firstRun) && !isDismissed("tour")}
      onComplete={onComplete}
    >
      {children}
    </SharedTourProvider>
  );
}
