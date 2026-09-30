// shellWrap.ts - pure helpers for the Settings -> Terminal "Command wrapping"
// card (backlog item 7). No imports besides `import type`, so it runs under
// plain node:test.

import type { ShellWrapHonesty, ShellWrapStatus } from "./types.ts";

export type PillTone = "success" | "warn" | "neutral" | "info";

// Honesty -> Pill tone. The TEXT always comes from the server
// (honesty_text), so no surface re-words what wrapping buys.
export const HONESTY_TONE: Record<ShellWrapHonesty, PillTone> = {
  routed: "success",
  proof_owed: "warn",
  launch_only: "neutral",
};

// selectionKey identifies a (tools, shells) selection independent of order,
// so Apply is only offered for the exact selection that was previewed.
export function selectionKey(tools: string[], shells: string[]): string {
  return [...tools].sort().join(",") + "|" + [...shells].sort().join(",");
}

// stateLabel is the card's badge: an ordered table, first match wins.
const STATE_ROWS: { match: (s: ShellWrapStatus) => boolean; text: string; tone: PillTone }[] = [
  { match: (s) => s.enabled && s.in_sync, text: "on", tone: "success" },
  { match: (s) => s.enabled, text: "on - files differ, re-apply", tone: "warn" },
  { match: (s) => s.active, text: "off - leftovers installed", tone: "warn" },
  { match: () => true, text: "off", tone: "neutral" },
];

export function stateLabel(s: ShellWrapStatus): { text: string; tone: PillTone } {
  const row = STATE_ROWS.find((r) => r.match(s))!;
  return { text: row.text, tone: row.tone };
}
