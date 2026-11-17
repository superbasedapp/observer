import { useMemo } from "react";
import { HelpDrawer as SharedHelpDrawer, type HelpDrawerCategory } from "@shared/components/help/HelpDrawer";
import { helpRegistry, type HelpCategory } from "@/lib/help";
import { useTour } from "@/components/tour/TourProvider";
import { isManaged, useGovernance, useGovernanceVisibility } from "@/lib/governance";
import { applyPostureView, helpPostureOf } from "@/lib/helpPostureView";
import { helpEntryHidden, hiddenNavIds, hiddenSettingsIds } from "@/lib/visibility";

// The node's help drawer: the shared chrome (shared/components/help/
// HelpDrawer.tsx) fed by the node registry. What stays here is CONTENT:
// which entries this machine may show and how they are worded.

const CATEGORY_LABEL: Record<HelpCategory, string> = {
  tab: "Tabs",
  tile: "KPI tiles",
  chart: "Charts",
  column: "Columns",
  filter: "Filters",
  metric: "Metrics",
  calc: "Calculations",
  glossary: "Glossary",
};

const CATEGORIES: readonly HelpDrawerCategory[] = (Object.keys(CATEGORY_LABEL) as HelpCategory[]).map((id) => ({
  id,
  label: CATEGORY_LABEL[id],
}));

// HELP_DRAWER_Z stacks the drawer above the overlays help can be opened
// from: the New Terminal dialog (85, whose sandbox setup steps carry help
// links), the terminal workspace's floating panels (90 to 110) and its
// expanded-terminal backdrop (80); below the guided tour (120 and 130),
// which the drawer's own Tour button closes it for. SlideOver's zIndex note
// names 112 as the level that clears that band.
export const HELP_DRAWER_Z = 112;

export function HelpDrawer({
  open,
  onClose,
  initialId,
}: {
  open: boolean;
  onClose: () => void;
  initialId?: string | null;
}) {
  const { startTour } = useTour();

  // Help about a page (or Settings section) hidden on this machine is not
  // offered: it would document a surface the developer cannot reach.
  // Fails closed until the posture is known (Sol A4-05): help about every
  // non-floor page and Settings section is withheld until then.
  const { gov, posture } = useGovernanceVisibility();
  // Wording that depends on the enrolment posture (T-470): on an
  // organization-managed machine the sharing help says what the org ships.
  // Read from the transparency read, not the fail-closed filter posture.
  const helpPosture = helpPostureOf(isManaged(useGovernance().data));
  const registry = useMemo(() => {
    const nav = hiddenNavIds(gov);
    const settings = hiddenSettingsIds(gov);
    const unresolved = posture !== "ready";
    const all = helpRegistry().map((e) => applyPostureView(e, helpPosture));
    if (nav.length === 0 && settings.length === 0 && !unresolved) return all;
    return all.filter((e) => !helpEntryHidden(e.id, nav, settings, unresolved));
  }, [gov, posture, helpPosture]);

  return (
    <SharedHelpDrawer
      open={open}
      onClose={onClose}
      initialId={initialId}
      entries={registry}
      categories={CATEGORIES}
      onTour={startTour}
      zIndex={HELP_DRAWER_Z}
    />
  );
}

// HelpInd lives in its own module so eager primitives (StatCard etc.) can
// import it without dragging the registry into the shell chunk.
// Re-exported here for callers that still want the HelpDrawer barrel.
export { HelpInd } from "@/components/HelpInd";
