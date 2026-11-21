import type { EntityMultiPickerOption } from "@/components/primitives";
import { type GuardOverrideRow, guardRuleInfo, isGuardIntegrityRuleId } from "@shared/lib/guardCatalog";

// integrityLock: the two weakening controls the local rule editor must not
// offer for a guard INTEGRITY rule (isGuardIntegrityRuleId, the TS mirror of
// internal/policy/engine.go::IsIntegrityRuleID). Audit CF2-A1 (F-021): the
// decision picker was already escalate-only for these, but the Enforce toggle
// could still write `enforce = false` (a cap the engine treats as a weakening)
// and the disable chip picker still listed the integrity ids. The server drops
// both with a load issue, so the floor held; the editor now stops offering
// them, so what the page shows is what the guard applies.

/**
 * withIntegrityEnforce returns the row with Enforce forced on when its rule is
 * an integrity rule, and the row unchanged otherwise. The editor applies it to
 * the initial row, on every rule change and on save, so an integrity override
 * can never carry `enforce = false`.
 */
export function withIntegrityEnforce(row: GuardOverrideRow): GuardOverrideRow {
  if (!isGuardIntegrityRuleId(row.rule) || row.enforce) return row;
  return { ...row, enforce: true };
}

/**
 * guardDisableOptions builds the disable chip picker's options from the
 * effective rule ids, leaving the integrity ids out: disabling one is a
 * weakening the policy engine refuses in every layer.
 */
export function guardDisableOptions(ids: readonly string[]): EntityMultiPickerOption[] {
  return ids
    .filter((id) => !isGuardIntegrityRuleId(id))
    .map((id) => ({ id, label: id, sublabel: guardRuleInfo(id)?.doc }));
}

/**
 * integrityDisables returns the ids in a disable list that are integrity
 * rules (a typed free id, or one an older config already carries), so the
 * page can say the guard ignores them.
 */
export function integrityDisables(ids: readonly string[]): string[] {
  return ids.filter((id) => isGuardIntegrityRuleId(id));
}

/**
 * canDisableRule reports whether the page may offer to disable a rule: never
 * for an integrity rule (fix round 1 of lane FU1: the Effective rules table's
 * per-row Disable button was the third weakening control).
 */
export function canDisableRule(id: string): boolean {
  return !isGuardIntegrityRuleId(id);
}

/**
 * withDisabledRule returns the disable list with id added once, or the list
 * unchanged when id is an integrity rule or already listed.
 */
export function withDisabledRule(list: readonly string[], id: string): string[] {
  if (!canDisableRule(id) || list.includes(id)) return [...list];
  return [...list, id];
}

/**
 * withIntegrityOverrides applies withIntegrityEnforce to every override row,
 * so the page's save never writes `enforce = false` for an integrity rule,
 * whatever row a file it loaded already carried.
 */
export function withIntegrityOverrides(rows: readonly GuardOverrideRow[]): GuardOverrideRow[] {
  return rows.map(withIntegrityEnforce);
}
