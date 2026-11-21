import type { ProcessFinding } from "./types.ts";

// processFindings - the grouping behind the System tab's observe-only process
// findings list. A long session repeats one finding many times (every Go test
// binary run from a temp folder is one executable_from_tmp warning), so the
// list shows one row per rule, executable and detail with a count, worst
// severity first, and pages the rows.

/** FindingGroup is one row of the findings list: identical findings folded. */
export type FindingGroup = {
  key: string;
  rule_id: string;
  severity: string;
  exe_basename?: string;
  detail?: string;
  count: number;
  /** last is the newest occurrence's timestamp (ISO). */
  last: string;
  /** items are the occurrences, newest first. */
  items: ProcessFinding[];
};

/** SEVERITY_RANK orders the guard severity scale, strongest first. */
const SEVERITY_RANK: Record<string, number> = { high: 0, warn: 1, info: 2 };

function rank(sev: string): number {
  return SEVERITY_RANK[sev] ?? 3;
}

/** FINDING_GROUPS_PER_PAGE is how many grouped rows one page of the list shows. */
export const FINDING_GROUPS_PER_PAGE = 10;

/** MAX_OCCURRENCES_SHOWN caps the occurrences an expanded row lists. */
export const MAX_OCCURRENCES_SHOWN = 20;

/**
 * groupProcessFindings folds findings that share a rule, executable and
 * detail into one group, and orders the groups by severity (high first), then
 * count (largest first), then the newest occurrence, then the key.
 */
export function groupProcessFindings(findings: ProcessFinding[]): FindingGroup[] {
  const byKey = new Map<string, FindingGroup>();
  for (const f of findings) {
    const key = `${f.rule_id}\u0000${f.exe_basename ?? ""}\u0000${f.detail ?? ""}`;
    let g = byKey.get(key);
    if (!g) {
      g = {
        key,
        rule_id: f.rule_id,
        severity: f.severity,
        exe_basename: f.exe_basename,
        detail: f.detail,
        count: 0,
        last: f.timestamp,
        items: [],
      };
      byKey.set(key, g);
    }
    g.count++;
    g.items.push(f);
    if (rank(f.severity) < rank(g.severity)) g.severity = f.severity;
    if (f.timestamp > g.last) g.last = f.timestamp;
  }
  const out = [...byKey.values()];
  for (const g of out) g.items.sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0));
  out.sort(
    (a, b) =>
      rank(a.severity) - rank(b.severity) ||
      b.count - a.count ||
      (a.last < b.last ? 1 : a.last > b.last ? -1 : 0) ||
      (a.key < b.key ? -1 : a.key > b.key ? 1 : 0),
  );
  return out;
}
