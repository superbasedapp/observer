// scorers - the pure parse of an eval run's scorer list (design review
// 2026-11-21). The node's run row carries its scorers as the stored JSON
// string (`[{"name":"exact_match","version":"1"}]`), the org's as an array of
// names; both used to reach the page as raw text. Every shape resolves here
// to name + optional version, and ScorerChips (evals.tsx) draws them.

/** One scorer as a person reads it: its name and, when known, its version. */
export interface PlaneAScorerRef {
  name: string;
  version?: string;
}

function fromItem(item: unknown): PlaneAScorerRef | null {
  if (typeof item === "string") {
    const name = item.trim();
    return name ? { name } : null;
  }
  if (item && typeof item === "object") {
    const o = item as { name?: unknown; version?: unknown };
    const name = typeof o.name === "string" ? o.name.trim() : "";
    if (!name) return null;
    const v = typeof o.version === "string" || typeof o.version === "number" ? String(o.version).trim() : "";
    return v ? { name, version: v } : { name };
  }
  return null;
}

/** parseScorers resolves a run's scorers (a JSON string, a comma list, an
 *  array of names or of {name, version}) to a list; anything unreadable is
 *  an empty list, never the raw text. */
export function parseScorers(raw: unknown): PlaneAScorerRef[] {
  let list: unknown = raw;
  if (typeof raw === "string") {
    const s = raw.trim();
    if (!s) return [];
    if (s.startsWith("[") || s.startsWith("{")) {
      try {
        list = JSON.parse(s);
      } catch {
        return [];
      }
    } else {
      list = s.split(",");
    }
  }
  if (list && !Array.isArray(list) && typeof list === "object") list = [list];
  if (!Array.isArray(list)) return [];
  return list.map(fromItem).filter((r): r is PlaneAScorerRef => r !== null);
}

/** scorerLabel is one scorer's chip text: "exact_match v1". */
export function scorerLabel(s: PlaneAScorerRef): string {
  return s.version ? `${s.name} v${s.version}` : s.name;
}
