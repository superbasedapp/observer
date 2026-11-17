import type { GuardRule } from "@/lib/types";

// orgLock: which rules the node's rule manager must not offer to disable or
// override, and how to say why. A rule the organization locks on this node
// (GuardRule.org_locked: an org-layer rule it did not mark overridable, or any
// rule its lock reaches here, every rule on a managed node) offers no local
// disable or override; the policy save gates refuse such an edit too
// (internal/intelligence/dashboard guardOrgLockedEdits). An org-layer row
// from an older daemon that sends no org_locked still counts, unless the org
// marked it overridable.
//
// Locked is not the same as set (2026-11-12 operator report: all 81 rules on
// a managed node read "Set by your organization" although its bundle named
// four). A rule the organization's bundle sets itself (GuardRule.org_named,
// or an org-layer row) reads "Set by your organization"; a rule that runs at
// its own built-in decision and is only locked reads "Locked by your
// organization".

/** ruleLockedByOrg reports whether any row of a rule id is locked by the
 *  organization on this node. */
export function ruleLockedByOrg(defs: readonly GuardRule[] | undefined): boolean {
  return (defs ?? []).some((d) => d.org_locked === true || (d.source === "org" && d.overridable !== true));
}

/** ruleSetByOrg reports whether the organization's bundle sets the rule
 *  itself (an override on it, or a rule it defines). */
export function ruleSetByOrg(defs: readonly GuardRule[] | undefined): boolean {
  return (defs ?? []).some((d) => d.org_named === true || d.source === "org");
}

/** orgUnlockedIds keeps the rule ids the page may offer a local disable or
 *  override for. */
export function orgUnlockedIds(ids: readonly string[], ruleDefs: ReadonlyMap<string, readonly GuardRule[]>): string[] {
  return ids.filter((id) => !ruleLockedByOrg(ruleDefs.get(id)));
}

/** OrgLockNote is the note shown in place of the controls: its text and the
 *  explanation behind it. */
export type OrgLockNote = { note: string; title: string };

/** ORG_SET is the note for a rule the organization's bundle sets. */
export const ORG_SET: OrgLockNote = {
  note: "Set by your organization",
  title:
    "Your organization's policy sets this rule's decision on this machine, so it cannot be disabled or overridden here. Ask for a time-limited exception on Requests.",
};

/** ORG_LOCKED is the note for a rule that runs at its built-in decision and
 *  that the organization only locks. */
export const ORG_LOCKED: OrgLockNote = {
  note: "Locked by your organization",
  title:
    "This rule runs at its built-in decision; your organization's policy does not change it. Your organization locks it on this machine (on a managed machine it locks every rule), so it cannot be disabled or overridden here. Ask for a time-limited exception on Requests.",
};

/** orgLockNote is the note for a locked rule id, or null when the page may
 *  offer the local controls. */
export function orgLockNote(defs: readonly GuardRule[] | undefined): OrgLockNote | null {
  if (!ruleLockedByOrg(defs)) return null;
  return ruleSetByOrg(defs) ? ORG_SET : ORG_LOCKED;
}
