// updateAutoApply - the pure half of the "Update automatically" switch on
// Settings > Health > Updates (plan docs/plans/dashboard-cli-parity-plan-
// 2026-11-06.md, B-S7). Before it the card printed the daemon's reason, which
// ends "set [update].auto_apply = ... to ...", and the Org settings section
// showed the key read-only: it is three-state (unset means the managed-fleet
// default decides), which the generic editor cannot render.
//
// GET /api/update/auto-apply answers the value written in config.toml (null
// when unset) and the confirm token; PUT takes {"auto_apply": true|false|null}
// (null removes the explicit value), ?dry_run=1 first. [update] binds at
// daemon start, so a save needs a restart.

/** The route. */
export const UPDATE_AUTO_APPLY_PATH = "/api/update/auto-apply";

/** GET /api/update/auto-apply. */
export type UpdateAutoApplyView = {
  auto_apply: boolean | null;
  confirm_token?: string;
  config_etag?: string;
};

/** The three choices: follow the default, or set it on this node. */
export type AutoApplyChoice = "default" | "on" | "off";

/** autoApplyChoice is the choice the written value stands for. */
export function autoApplyChoice(explicit: boolean | null | undefined): AutoApplyChoice {
  if (explicit === true) return "on";
  if (explicit === false) return "off";
  return "default";
}

/** autoApplyBody is the PUT body for a choice. */
export function autoApplyBody(c: AutoApplyChoice): { auto_apply: boolean | null } {
  return { auto_apply: c === "on" ? true : c === "off" ? false : null };
}

/** autoApplyOptions are the three buttons; the default one says what the
 *  default is on this node (effective is the daemon's resolved value while
 *  nothing is written, so it is the default itself). */
export function autoApplyOptions(explicit: boolean | null | undefined, effective: boolean): { id: AutoApplyChoice; label: string }[] {
  // While a value is written, the default is not observable here: name it plainly.
  const def = explicit == null ? `Default (${effective ? "on" : "off"})` : "Default";
  return [
    { id: "default", label: def },
    { id: "on", label: "On" },
    { id: "off", label: "Off" },
  ];
}

// AUTO_APPLY_WORDS: what each state means, walked top-down.
const AUTO_APPLY_WORDS: readonly { when: (explicit: boolean | null | undefined, effective: boolean) => boolean; text: string }[] = [
  { when: (x) => x === true, text: "On, set on this node: it installs the update your organization offers by itself, inside the maintenance window." },
  { when: (x) => x === false, text: "Off, set on this node: it tells you about an update and waits for you." },
  { when: (_x, eff) => eff, text: "On by default: your organization manages this node, so it installs the update the organization offers by itself." },
  { when: () => true, text: "Off by default, as on every node no organization manages: it tells you about an update and waits for you." },
];

/** autoApplyWords says what the current state means. */
export function autoApplyWords(explicit: boolean | null | undefined, effective: boolean): string {
  for (const r of AUTO_APPLY_WORDS) if (r.when(explicit, effective)) return r.text;
  return "";
}
