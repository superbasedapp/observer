import { createContext, useContext, type ReactNode } from "react";
import { fmtCostFine } from "../../lib/format";

// money - the ONE cost seam of the Plane A components (B5-0, 2026-11-19).
//
// A Plane A cell renders a cost from its facts (dollars plus, when known,
// the tokens behind them). How a figure reads is the app's decision, so it
// is injected, the HelpSlotProvider pattern: the org dashboard installs its
// <Money> (admins always see dollars) and its `money(facts, mode)` string;
// the node dashboard installs nothing and gets the default below, the
// shared fmtCost, which already honours the developer cost display the
// node sets at boot (lib/format.ts setCostDisplayMode).

/** The facts one cost figure is drawn from. */
export type PlaneAMoneyFacts = { usd: number; tokens?: number };

/** PlaneAMoneySlot draws a cost as a node (a table cell) or a string (a
 *  composed label, a detail row). */
export type PlaneAMoneySlot = {
  node: (facts: PlaneAMoneyFacts) => ReactNode;
  text: (facts: PlaneAMoneyFacts) => string;
};

/** defaultMoneySlot is the node's rendering: the shared fmtCostFine (adaptive
 *  precision, so a real sub-cent cost never reads "$0.00"). */
export const defaultMoneySlot: PlaneAMoneySlot = {
  node: (f) => <span>{fmtCostFine(f.usd, f.tokens)}</span>,
  text: (f) => fmtCostFine(f.usd, f.tokens),
};

const MoneySlotContext = createContext<PlaneAMoneySlot>(defaultMoneySlot);

/** PlaneAMoneyProvider installs an app's cost rendering once, at its root. */
export function PlaneAMoneyProvider({ value, children }: { value: PlaneAMoneySlot; children: ReactNode }) {
  return <MoneySlotContext.Provider value={value}>{children}</MoneySlotContext.Provider>;
}

/** usePlaneAMoney returns the installed slot (the default when none). */
export function usePlaneAMoney(): PlaneAMoneySlot {
  return useContext(MoneySlotContext);
}

/** PlaneAMoney renders one cost figure through the installed slot. */
export function PlaneAMoney({ usd, tokens }: PlaneAMoneyFacts) {
  const slot = usePlaneAMoney();
  return <>{slot.node(tokens === undefined ? { usd } : { usd, tokens })}</>;
}
