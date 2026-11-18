import { useCallback, useMemo, useSyncExternalStore, type ReactNode } from "react";
import { TourProvider as SharedTourProvider } from "@shared/components/tour/TourProvider";
import { TOUR_STEPS } from "@/lib/tour";
import { NAV_ITEMS } from "@/lib/nav";
import { useGovernanceVisibility } from "@/lib/governance";
import { hiddenNavIds, withoutHiddenPaths } from "@/lib/visibility";
import { dismissalsSnapshot, subscribeDismissals } from "@/lib/uiDismissals";
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
  // The tour never starts by itself (local dashboard first-run design,
  // docs/plans/local-dashboard-first-run-options-2026-11-18.md section 5): the
  // Overview welcome band (components/firstrun/WelcomeBand.tsx), the Help
  // drawer and the command palette start it. A tour finished or skipped is
  // still kept on the daemon (WINNODE2 16b), so the welcome band can tell.
  useSyncExternalStore(subscribeDismissals, dismissalsSnapshot, dismissalsSnapshot);
  const dismissNotice = useDismissNotice();
  const onComplete = useCallback(() => dismissNotice("tour"), [dismissNotice]);
  return (
    <SharedTourProvider steps={steps} storageKey="sb_tour_completed" autoStart={false} onComplete={onComplete}>
      {children}
    </SharedTourProvider>
  );
}
