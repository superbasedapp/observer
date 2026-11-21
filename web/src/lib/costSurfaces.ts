import { dollarsShown, fmtCost, fmtUSD } from "../../../shared/lib/format.ts";

// Node-dashboard surfaces whose cost wording is more than one figure, kept
// here so the developer cost display (shared/lib/format.ts, set by
// lib/costDisplay.tsx) decides them through the one formatter seam rather
// than each component building a dollar string itself (Sol A4-04). Pure,
// tested in costSurfaces.test.ts.

// arenaUsageLine is an Arena candidate's usage: the token split, plus the
// approximate dollar cost only while dollars are shown. In the token-usage
// view the split IS the figure, so nothing is appended.
export function arenaUsageLine(inputTokens: number, outputTokens: number, costUSD: number): string {
  const split = `${inputTokens.toLocaleString()} in / ${outputTokens.toLocaleString()} out`;
  if (!dollarsShown()) return split;
  return `${split} · ≈${fmtCost(costUSD, inputTokens + outputTokens, true)}`;
}

export interface SavedMilestoneCopy {
  chip: string;
  text: string;
  share: string;
}

// savedMilestoneCopy is the compression-savings milestone's wording, from the
// live all-time total. The milestone celebrates a dollar amount and has no
// token figure behind it, so in the token-usage view it does not exist
// (null): the card never shows it and never fires it.
export function savedMilestoneCopy(savedUSD: number): SavedMilestoneCopy | null {
  if (!dollarsShown()) return null;
  return {
    // no-bare-usd:allow (reached only after dollarsShown() returned true above)
    chip: `★ $${Math.floor(savedUSD).toLocaleString()} SAVED ★`,
    text: `Compression has paid for its config: ${fmtUSD(savedUSD)} saved so far.`,
    share: `superbased has saved me ${fmtUSD(savedUSD)} in AI coding costs so far - superbased.app`,
  };
}
