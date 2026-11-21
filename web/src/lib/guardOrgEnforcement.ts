// The organization's half of the Security page posture (FU-235). A rule the
// org policy layer authored or overrode follows the org layer's action
// whatever the local mode, so on an observe node an org-locked deny still
// blocks. Before this, the Guard posture tile read "observe", the Mode card
// "Running: observe" and the verdict tile "0 enforced" while a desktop toast
// said a rule had blocked a command. These helpers turn the daemon's
// /api/guard/summary fields into the words the tiles show. They hold no
// state and fetch nothing; the wording of the org line itself is the
// daemon's (guard.OrgOverridePosture.ModeLine, the same line `observer
// guard status` prints), so the page and the CLI never disagree.

export type GuardOrgPosture = {
  enforced_rules: string[] | null;
  locks_every_rule: boolean;
  unverifiable?: boolean;
  line: string;
};

export type GuardOrgCounts = {
  enforced: number;
  enforced_by_org?: number;
};

export type GuardChainState = {
  ok: boolean;
  checked: number;
  divergence_id?: number;
  actionless_rewritten?: number;
  /** Failing rows by class (store: "broken link", "re-pointed anchor", "rewritten row"). */
  breaks?: Record<string, number>;
  /** The daemon's repair line (store.GuardChainRepairHint), also printed by the CLI. */
  repair_hint?: string;
};

// guardPostureValue is the posture tile's headline: the local mode, marked
// "locally" when an org layer also decides some rules on this node.
export function guardPostureValue(sum: { enabled: boolean; mode: string; org?: GuardOrgPosture | null }): string {
  if (!sum.enabled) return "disabled";
  return sum.org ? `${sum.mode} locally` : sum.mode;
}

// guardOrgLine is the org line under the posture tile and on the Mode card,
// or null when no org layer reaches this node (an older daemon never sends
// it either, and then the page reads exactly as before).
export function guardOrgLine(org?: GuardOrgPosture | null): string | null {
  const line = org?.line?.trim();
  return line ? line : null;
}

// guardEnforcedSub is the verdict tile's second line: how many verdicts
// blocked or deferred, and how many of those the organization's policy
// produced.
export function guardEnforcedSub(c: GuardOrgCounts): string {
  const base = `${c.enforced} enforced (blocked or deferred)`;
  const byOrg = c.enforced_by_org ?? 0;
  return byOrg > 0 ? `${base}, ${byOrg} by your organization's policy` : base;
}

// guardChainSub is the audit-chain tile's second line (FU-236): where the
// chain first diverges and, when the walk found rows routine maintenance
// can explain, the dashboard's repair (B-G8: Repair audit chain on the
// Coverage tab runs the CLI's own repair) instead of a bare "BROKEN".
export function guardChainSub(chain: GuardChainState): string {
  if (chain.ok) return `${chain.checked} rows verified (tamper-evident, SHA-256 chained)`;
  const head = `first divergence at id ${chain.divergence_id ?? "?"}`;
  const n = chain.actionless_rewritten ?? 0;
  if (n > 0) {
    const rows = n === 1 ? "1 row lost its" : `${n} rows lost their`;
    return `${head}; ${rows} action id to routine maintenance, which Repair audit chain on the Coverage tab can prove and restore (dry run first)`;
  }
  if (chainRepairSteps(chain).length > 0) return `${head} - Repair audit chain on the Coverage tab shows what it can fix`;
  return `${head} - Verify audit chain on the Coverage tab walks it`;
}

/** The three audit chain repairs, each a dry run and an apply on /api/guard/jobs/chain. */
export type ChainRepairKind = "repair-anchors" | "dedup-events" | "relink-gaps";

export type ChainRepairStep = {
  kind: ChainRepairKind;
  /** The step's name on the card. */
  title: string;
  /** What the dry run looks for, one sentence. */
  finds: string;
  /** What the apply rewrites, for its confirm note. */
  rewrites: string;
};

// CHAIN_REPAIR_STEPS: the repairs in the order an operator runs them (the
// daemon's own hint order, store.guardChainHintRows). Each is the CLI verb of
// the same name; the apply is that verb with --apply.
export const CHAIN_REPAIR_STEPS: readonly ChainRepairStep[] = [
  {
    kind: "repair-anchors",
    title: "Restore pruned action ids",
    finds:
      "Finds rows whose action id routine maintenance cleared, and accepts an id only where the row's own stored hash proves it.",
    rewrites: "Writes the proven action ids into those guard audit rows. No hash changes; a row it cannot prove stays reported.",
  },
  {
    kind: "dedup-events",
    title: "Remove repeated rows",
    finds: "Finds guard rows a transcript re-parse wrote twice for the same action. Hook rows are never touched.",
    rewrites:
      "Deletes the repeated rows and re-hashes the chain from the first one on, in one transaction. It refuses if a row in that range already fails verification.",
  },
  {
    kind: "relink-gaps",
    title: "Re-link over deleted rows",
    finds: "Finds links that fail only because the row before them was deleted.",
    rewrites:
      "Recomputes every link from the first gap and adds a marker row recording the old tail hash. Any other kind of break refuses the whole run.",
  },
];

// chainRepairSteps picks the repairs that apply to what the walk found, in
// order: pruned action ids first, then the deleted-row pair. An intact chain
// needs none.
export function chainRepairSteps(chain: GuardChainState): ChainRepairStep[] {
  if (chain.ok) return [];
  const out: ChainRepairStep[] = [];
  if ((chain.actionless_rewritten ?? 0) > 0) out.push(CHAIN_REPAIR_STEPS[0]);
  if ((chain.breaks?.["broken link"] ?? 0) > 0) out.push(CHAIN_REPAIR_STEPS[1], CHAIN_REPAIR_STEPS[2]);
  return out;
}

/** A job of the shared registry, as the card tracks it. */
export type ChainRepairJob = { mode: string; status: string };

// chainApplyReady: a repair's apply is offered only after its dry run ran to
// completion in this view, so the person has seen what it would change.
export function chainApplyReady(kind: ChainRepairKind, dryRuns: Partial<Record<ChainRepairKind, ChainRepairJob>>): boolean {
  const j = dryRuns[kind];
  return !!j && j.mode === `guard:${kind}` && j.status === "done";
}

// chainApplyNote is an apply's confirm note: what it rewrites, and the
// backup to take first (Settings > Storage, Back up the database).
export function chainApplyNote(step: ChainRepairStep): string {
  return `${step.rewrites} This rewrites rows in observer.db: back up the database first (Settings > Storage, Back up now). Rows already pushed to an org server keep their old values there.`;
}
