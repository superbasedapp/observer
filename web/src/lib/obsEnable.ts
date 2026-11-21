// obsEnable - the pure half of the "Observability is off" empty state on the
// Egress and Policies pages (plan docs/plans/dashboard-cli-parity-plan-
// 2026-11-06.md, B-S1). Before it the empty state told the user to edit
// ~/.observer/config.toml and restart the daemon by hand.
//
// The button writes one or two plain config keys through the same
// PUT /api/config/keys path every schema-driven setting uses (dry run first,
// so the daemon validates the keys and values before anything is written),
// then raises the restart banner: the /api/obs routes register at daemon
// start. It never asks the user to run a command. The CodeIntelCard /
// codeIntelToggle pattern.

import type { ConfigKeyPatch } from "./configSchema.ts";

/** The dotted keys a page may need on. */
export const OBS_KEYS = {
  observability: "observability.enabled",
  admission: "observability.admission.enabled",
} as const;

export type ObsNeed = keyof typeof OBS_KEYS;

/** Each key's state, read from GET /api/config's `config` object; null when unknown. */
export type ObsEnableState = Record<ObsNeed, boolean | null>;

function boolAt(root: unknown, path: string[]): boolean | null {
  let cur: unknown = root;
  for (const p of path) {
    if (!cur || typeof cur !== "object") return null;
    cur = (cur as Record<string, unknown>)[p];
  }
  return typeof cur === "boolean" ? cur : null;
}

/** obsEnableState reads both switches; anything but a real boolean is unknown. */
export function obsEnableState(config: unknown): ObsEnableState {
  return {
    observability: boolAt(config, ["Observability", "Enabled"]),
    admission: boolAt(config, ["Observability", "Admission", "Enabled"]),
  };
}

/**
 * obsEnablePatches is the batch that turns on every needed switch still
 * off, or null when a needed switch's state is unknown (an older daemon, a
 * failed load: no switch, never a guess). An empty batch means everything is
 * already on in config.toml and only the restart is missing.
 */
export function obsEnablePatches(state: ObsEnableState, needs: readonly ObsNeed[]): ConfigKeyPatch[] | null {
  const out: ConfigKeyPatch[] = [];
  for (const n of needs) {
    const v = state[n];
    if (v === null) return null;
    if (!v) out.push({ key: OBS_KEYS[n], value: true, was: false });
  }
  return out;
}

const NEED_WORDS: Record<ObsNeed, string> = {
  observability: "observability",
  admission: "admission (the input-admission gate the policies run in)",
};

/** obsEnableLabel is the button's label. */
export function obsEnableLabel(needs: readonly ObsNeed[]): string {
  return needs.includes("admission") ? "Turn on observability and admission" : "Turn on observability";
}

/** obsEnableNote is the confirm note: the keys it sets and that a restart binds them. */
export function obsEnableNote(needs: readonly ObsNeed[]): string {
  const keys = needs.map((n) => `${OBS_KEYS[n]} = true`).join(" and ");
  return `Turns on ${needs.map((n) => NEED_WORDS[n]).join(" and ")}: sets ${keys} in config.toml (checked by the daemon before it is written). The page appears after the daemon restarts.`;
}

/** obsEnableDoneLine is the line after a save (or when only the restart is missing). */
export function obsEnableDoneLine(wrote: boolean): string {
  return wrote
    ? "Saved. Restart the daemon to load this page (the restart banner at the top has the button)."
    : "Already on in config.toml. Restart the daemon to load this page (the restart banner at the top has the button).";
}
