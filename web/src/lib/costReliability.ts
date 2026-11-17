// costReliability - the pure model behind the Cost page's Total spend tile
// subtitle (pages/Cost.tsx). The tile used to print the summary's weakest
// reliability tag bare, so the first number a viewer saw read "$3,458.78 -
// unreliable" with nothing saying why (demo bug #7). The tag is the TOKEN
// source's trust level (cost.weakestReliability over every row): one
// "unreliable" row, typically a Claude Code transcript turn whose output count
// was recorded mid-stream, tags the whole total. The subtitle now says what
// the tag means and how much of the total it covers; the tooltip says why and
// what makes it exact. Ordered table (CLAUDE.md #5). Pure, so the test runs
// under `node --test`.

/** The part of a /api/cost row the note reads. */
export type CostReliabilityRow = { cost_usd: number; reliability: string };

export type CostReliabilityNote = { sub: string; tooltip: string };

/** pctOf is the cost share of rows matching `tags`, 0-100, rounded. */
function pctOf(rows: CostReliabilityRow[], tags: Set<string>): number {
  const total = rows.reduce((n, r) => n + (r.cost_usd > 0 ? r.cost_usd : 0), 0);
  if (total <= 0) return 0;
  const part = rows.reduce((n, r) => n + (tags.has(r.reliability) && r.cost_usd > 0 ? r.cost_usd : 0), 0);
  return Math.round((part / total) * 100);
}

const ESTIMATE = new Set(["unreliable"]);

const EXACT_HINT =
  "Turns that go through this machine's proxy carry the provider's own usage and are exact: route the tool through the proxy (Settings > Connected tools) or start it from a dashboard terminal.";

type Row = {
  when: (overall: string) => boolean;
  note: (rows: CostReliabilityRow[], unknownModels: number) => CostReliabilityNote;
};

const ROWS: Row[] = [
  {
    when: (r) => r === "unknown",
    note: (_rows, n) => ({
      sub: n > 0 ? `${n} model${n === 1 ? "" : "s"} without a rate ($0)` : "some models without a rate ($0)",
      tooltip:
        "At least one model in this window has no entry in the rate table, so its tokens are counted but its cost shows $0 and the total reads low. The per-model table below names it.",
    }),
  },
  {
    when: (r) => r === "unreliable",
    note: (rows) => {
      const pct = pctOf(rows, ESTIMATE);
      return {
        sub: pct > 0 ? `estimate: ${pct}% from transcript tokens` : "includes transcript estimates",
        tooltip:
          "Part of this total is priced from transcript token counts (for example Claude Code's session files), which are written while a reply is still streaming and can undercount output by around 10%. " +
          EXACT_HINT,
      };
    },
  },
  {
    when: (r) => r === "approximate",
    note: () => ({
      sub: "from transcripts, close to billed",
      tooltip: "Token counts come from the tools' own transcripts, which record the provider's usage intact. " + EXACT_HINT,
    }),
  },
  {
    when: (r) => r === "accurate",
    note: () => ({ sub: "provider-reported usage", tooltip: "Every turn in this window carries the provider's own usage, captured by the proxy." }),
  },
  { when: () => true, note: () => ({ sub: "-", tooltip: "" }) },
];

/** costReliabilityNote maps the summary's reliability onto the tile's subtitle. */
export function costReliabilityNote(overall: string | undefined, rows: CostReliabilityRow[], unknownModels = 0): CostReliabilityNote {
  const r = overall ?? "";
  for (const row of ROWS) {
    if (row.when(r)) return row.note(rows, unknownModels);
  }
  return { sub: "-", tooltip: "" };
}
