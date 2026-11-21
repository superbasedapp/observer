// adviseDigest: the Suggestions page's "Copy digest" (lane L5 B-R4), the
// dashboard twin of `observer advise --digest` (cmd/observer/advise.go
// printAdviseDigest). It builds the same markdown rollup (headline avoidable
// spend, savings by category, the top 10 suggestions with their nudges) from
// the GET /api/suggestions response the page already reads, so the digest
// follows the page's window and filters. Pure, with the money formatter
// injected (the page passes the one cost formatter seam), so the node test
// runner covers it.

/** DigestSuggestion is the part of a suggestion the digest prints. */
export type DigestSuggestion = { title: string; nudge: string; savings_usd?: number };

/** DigestInput is the part of GET /api/suggestions the digest reads. */
export type DigestInput = {
  window_days: number;
  total_savings_usd: number;
  total_count: number;
  sessions_scanned: number;
  by_category: Record<string, number>;
  /** The first page, in the report's order (highest savings first). */
  suggestions: DigestSuggestion[] | null;
};

/** DIGEST_TOP is how many suggestions the digest lists, as the CLI does. */
export const DIGEST_TOP = 10;

// The category order the CLI prints.
const CATEGORY_ORDER = ["cost", "latency", "quality", "hygiene"];

/** adviseDigest renders the markdown digest; money formats a USD amount. */
export function adviseDigest(r: DigestInput, money: (usd: number) => string): string {
  const out: string[] = [];
  const days = r.window_days;
  out.push(`# Observer advisor digest - last ${days} day(s)`, "");
  out.push(
    `**Avoidable spend: ${money(r.total_savings_usd)}** across ${r.total_count} suggestions (${r.sessions_scanned} sessions scanned).`,
    "",
  );
  for (const c of CATEGORY_ORDER) {
    const v = r.by_category[c] ?? 0;
    if (v > 0) out.push(`- ${c}: ${money(v)}`);
  }
  out.push("");
  const list = (r.suggestions ?? []).slice(0, DIGEST_TOP);
  list.forEach((s, i) => {
    out.push(`## ${i + 1}. ${s.title} (${money(s.savings_usd ?? 0)})`, "", s.nudge, "");
  });
  const more = r.total_count - list.length;
  if (more > 0) out.push(`…and ${more} more (the Suggestions page lists them all).`);
  return out.join("\n").replace(/\n+$/, "\n");
}
