import { createContext, useContext, type ReactNode } from "react";

// Injectable help-slot for the shared design system. StatCard/HeroStat/
// PageHeader render a help indicator without depending on any single app's
// help system: the app injects a renderer via HelpSlotProvider (the dashboard
// passes its <HelpInd id=... />), and surfaces with no help drawer (e.g. the
// cloud portal) provide none, so the default renderer draws nothing.
type HelpRenderer = (id: string) => ReactNode;

const HelpSlotContext = createContext<HelpRenderer | null>(null);

export const HelpSlotProvider = HelpSlotContext.Provider;

export function useHelpSlot(): HelpRenderer {
  return useContext(HelpSlotContext) ?? (() => null);
}
